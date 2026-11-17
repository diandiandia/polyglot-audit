"""CLI --format human tests (DSR-074): dual JSON/human output format.

Contract under test:
- json stays the DEFAULT on every subcommand: the frozen envelope
  {"schema_version","ok","value"|"error"} and every automation consumer keep
  working unchanged (zero-diff hard constraint).
- --format human renders compact human-readable text: custom renderers for
  status/finalize/report/pause/run, a generic fallback (top-level scalars as
  `key: value`, nested dict/list as indented JSON) for the rest, and errors as
  `ERROR <code>: <message>` with indented details. Exit codes are
  format-independent.
- The mcp subcommand's wire format is fixed by JSON-RPC 2.0, so --format only
  accepts json there (human is rejected non-zero by argparse).

Tests that need a run directory seed events.db directly (same pattern as
tests/hosts) so status/pause/run coverage cannot be broken by in-flight
changes to AuditAppService.prepare in a parallel workstream; the finalize
lifecycle is isolated in its own class because it does exercise prepare.

Requirements: SWR-001(格式冻结) / DSR-074(json默认human可选)
"""

import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
AUDIT_PY = REPO_ROOT / "skill" / "scripts" / "audit.py"
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures"

FROZEN_SUBCOMMANDS = [
    "doctor", "prepare", "run", "next", "start", "submit", "status",
    "pause", "resume", "finalize", "report", "mcp", "guide",
]
ALL_SUBCOMMANDS = FROZEN_SUBCOMMANDS + ["host-fail"]


def run_cli(args, stdin_text=None, cwd=None):
    """Run audit.py in an isolated interpreter (-I) and return the process."""
    return subprocess.run(
        [sys.executable, "-I", str(AUDIT_PY)] + args,
        input=stdin_text,
        capture_output=True,
        text=True,
        cwd=str(cwd) if cwd else None,
        timeout=120,
    )


def parse_envelope(proc):
    """Parse a single JSON envelope from stdout."""
    lines = [ln for ln in proc.stdout.strip().splitlines() if ln.strip()]
    assert len(lines) == 1, f"expected exactly one envelope line, got: {proc.stdout!r}"
    return json.loads(lines[0])


def seed_run(run_dir: Path, state: str = "active") -> str:
    """Create a real run directory (events.db + one run row) without prepare."""
    from auditkit.ledger.db import get_db_connection, init_database

    run_dir.mkdir(parents=True, exist_ok=True)
    init_database(run_dir / "events.db")
    conn = get_db_connection(run_dir / "events.db")
    run_id = "run-" + run_dir.name
    conn.execute(
        """
        INSERT INTO runs (run_id, snapshot_id, state, schema_version, skill_version, knowledge_version, config_ref, revision, created_at, updated_at)
        VALUES (?, 'snp-01', ?, '1.0', '0.1.0', '1.0', 'cfg', 4, '2026-11-14T00:00:00Z', '2026-11-14T00:00:00Z')
        """,
        (run_id, state),
    )
    conn.commit()
    conn.close()
    return run_id


class TestHumanFormatBasics(unittest.TestCase):
    """Format surface: flag availability, json default, error rendering."""

    def test_format_flag_documented_on_every_subcommand(self):
        for sub in ALL_SUBCOMMANDS:
            with self.subTest(subcommand=sub):
                proc = run_cli([sub, "--help"])
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertIn("--format", proc.stdout + proc.stderr)

    def test_mcp_rejects_human_but_accepts_json(self):
        # The MCP wire protocol is fixed JSON-RPC 2.0: human is invalid there.
        # json is accepted on a run directory with a valid dossier ledger (the
        # server refuses to start without events.db — see
        # test_missing_run_dir.py), so this format test seeds a real dossier.
        proc = run_cli(["mcp", "--format", "human", "--run-dir", "/tmp/whatever"])
        self.assertNotEqual(proc.returncode, 0)
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run_fmt"
            seed_run(run_dir, state="ready")
            proc = run_cli(["mcp", "--format", "json", "--run-dir", str(run_dir)], stdin_text="")
            self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_json_is_still_the_default_envelope(self):
        proc = run_cli(
            ["guide", "--query", "how should I audit unsafe deserialization in python?"],
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        env = parse_envelope(proc)
        self.assertEqual(env["schema_version"], "1.0")
        self.assertTrue(env["ok"])
        self.assertIsInstance(env["value"], dict)
        self.assertNotIn("ERROR", proc.stdout)

    def test_format_json_is_an_explicit_noop(self):
        proc = run_cli(
            ["guide", "--query", "how should I audit unsafe deserialization in python?",
             "--format", "json"],
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        env = parse_envelope(proc)
        self.assertTrue(env["ok"])

    def test_error_renders_as_error_line_with_retryable(self):
        proc = run_cli(["report", "--run-dir", "/nonexistent/run-dir-xyz", "--format", "human"])
        self.assertNotEqual(proc.returncode, 0)
        lines = proc.stdout.strip().splitlines()
        self.assertTrue(lines[0].startswith("ERROR INVALID_INPUT: "), proc.stdout)
        self.assertIn("Report not found", lines[0])
        self.assertIn("retryable: false", proc.stdout)
        # human error output is NOT the json envelope
        self.assertNotIn("schema_version", proc.stdout)

    def test_error_renders_details_indented(self):
        long_reason = "x" * 300
        proc = run_cli(
            ["pause", "--run-dir", "/nonexistent/run-dir-xyz",
             "--reason", long_reason, "--format", "human"],
        )
        self.assertEqual(proc.returncode, 2, proc.stdout)
        self.assertTrue(proc.stdout.startswith("ERROR INVALID_INPUT: "), proc.stdout)
        self.assertIn("details:", proc.stdout)
        # nested dict values render as indented JSON under the error line
        self.assertIn('"length": 300', proc.stdout)
        self.assertIn('"limit": 256', proc.stdout)
        self.assertNotIn("schema_version", proc.stdout)

    def test_generic_fallback_on_guide_and_doctor(self):
        proc = run_cli(
            ["guide", "--query", "how should I audit unsafe deserialization in python?",
             "--format", "human"],
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        val = parse_envelope(run_cli(
            ["guide", "--query", "how should I audit unsafe deserialization in python?"]
        ))["value"]
        for key in val:
            self.assertIn(f"{key}:", proc.stdout)
        self.assertIn("mode:", proc.stdout)
        self.assertIn("guidance:", proc.stdout)

        proc = run_cli(["doctor", "--host", "session", "--format", "human"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("capabilities:", proc.stdout)


class TestHumanFormatRunObservation(unittest.TestCase):
    """status / pause / run human rendering on a real (seeded) run directory."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="human-format-")
        self.run_dir = Path(self.tmp) / "run_obs"
        self.run_id = seed_run(self.run_dir, state="ready")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_status_human_key_value_block(self):
        proc = run_cli(["status", "--run-dir", str(self.run_dir), "--format", "human"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = proc.stdout
        self.assertNotIn("schema_version", out)
        # aligned key: value block (renderer pads labels to _KV_WIDTH)
        self.assertIn("run_id:".ljust(24) + self.run_id, out)
        self.assertIn("snapshot_id:".ljust(24) + "snp-01", out)
        self.assertIn("state:", out)
        self.assertIn("revision:", out)
        self.assertIn("tasks:", out)
        self.assertIn("budgets:", out)

    def test_pause_human_summary_line_and_key_fields(self):
        proc = run_cli(["pause", "--run-dir", str(self.run_dir), "--format", "human"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        lines = proc.stdout.strip().splitlines()
        self.assertTrue(lines[0].startswith(f"paused {self.run_id} at revision "), proc.stdout)
        self.assertIn("in_flight:", lines[0])
        joined = proc.stdout
        self.assertIn("run_id:", joined)
        self.assertIn("state:", joined)
        self.assertIn("revision:", joined)
        self.assertIn("in_flight_tasks:", joined)
        self.assertIn("in_flight_attempt_ids:", joined)

    def test_run_human_session_summary(self):
        proc = run_cli(["run", "--run-dir", str(self.run_dir), "--format", "human"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = proc.stdout
        self.assertTrue(out.startswith(f"run {self.run_id} -> "), out)
        self.assertIn("state=active", out)
        self.assertIn("mode=session", out)
        self.assertIn("next_steps:", out)


class TestHumanFormatFinalizeReport(unittest.TestCase):
    """finalize / report human rendering through the full CLI lifecycle.

    This class is the only one riding on prepare/finalize (isolated so any
    in-flight churn in the parallel finalize-semantics workstream cannot mask
    failures in the classes above).
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="human-finalize-")
        self.target = FIXTURES_DIR / "pyapp"
        self.run_dir = Path(self.tmp) / "run_fin"
        self.config_path = Path(self.tmp) / "config.json"
        config = {
            "schema_version": "1.0",
            "target": str(self.target),
            "run_dir": str(self.run_dir),
            "report_language": "zh",
            "profile": "standard",
            "scope": {"include": ["*.py"], "exclude": ["tests/*"]},
            "budgets": [{
                "schema_version": "1.0", "dimension": "tasks", "mode": "enforced",
                "limit": 20, "settled": 0, "reserved": 0, "unit": "tasks",
                "availability": "exact",
            }],
            "safety_acceptance": {
                "allow_unverified_execution": False,
                "allow_unverified_network": False,
                "allow_unverified_write": False,
                "user_approved": True,
            },
        }
        self.config_path.write_text(json.dumps(config), encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def cli_ok(self, args, stdin_text=None):
        proc = run_cli(args, stdin_text=stdin_text)
        self.assertEqual(
            proc.returncode, 0,
            f"args={args}\nstdout={proc.stdout}\nstderr={proc.stderr}",
        )
        return proc

    def test_finalize_human_terminal_state_gates_and_reasons(self):
        self.cli_ok([
            "prepare", "--target", str(self.target),
            "--run-dir", str(self.run_dir), "--config", str(self.config_path),
        ])
        self.cli_ok(["run", "--run-dir", str(self.run_dir)])
        proc = self.cli_ok(["finalize", "--run-dir", str(self.run_dir), "--format", "human"])
        out = proc.stdout
        self.assertNotIn("schema_version", out)
        self.assertIn("run_id:", out)
        self.assertIn("final_state:", out)
        self.assertIn("generation_id:", out)
        self.assertIn("gates:", out)
        for gate in ("G1", "G2", "G3", "G4"):
            self.assertRegex(out, re.compile(rf"^\s+{gate}: \S+", re.MULTILINE))
        self.assertIn("incomplete_reasons:", out)

    def test_report_human_meta_plus_body(self):
        self.cli_ok([
            "prepare", "--target", str(self.target),
            "--run-dir", str(self.run_dir), "--config", str(self.config_path),
        ])
        self.cli_ok(["finalize", "--run-dir", str(self.run_dir)])
        report_text = (self.run_dir / "report" / "REPORT.md").read_text(encoding="utf-8")

        proc = self.cli_ok(["report", "--run-dir", str(self.run_dir), "--format", "human"])
        out = proc.stdout
        self.assertNotIn("schema_version", out)
        self.assertIn("generation_id:", out)
        self.assertIn("report_md_chars:", out)
        self.assertIn("report_md_lines:", out)
        self.assertIn("---", out)
        # the report body is emitted verbatim after the meta lines
        self.assertIn(report_text.rstrip("\n"), out)
        # and the json envelope for the same command still carries the fields
        env = parse_envelope(self.cli_ok(["report", "--run-dir", str(self.run_dir)]))
        self.assertEqual(env["value"]["report_md"], report_text)


if __name__ == "__main__":
    unittest.main()
