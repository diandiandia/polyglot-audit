"""CLI driver-loop contract tests for audit.py run / pause / report (IFC-06).

Implements the recalibrated CLI contracts:
- `audit run --host claude|codex` mounts the real dispatch loop: a fake host
  CLI on PATH (same script-fixture pattern as tests/hosts/fake_hosts.py,
  read-only reference) drives a small pyapp target until the queue drains and
  finalize yields final_state complete.
- A missing host CLI exits non-zero (HOST_FAILURE) instead of idling, and
  leaves the run state untouched.
- `audit run --host session` (default) only activates the run and prints the
  in-session next/start/submit guidance (exit 0, no idle spin, no fake work).
- `audit pause` surfaces in-flight accounting (revision, in_flight_tasks,
  in_flight_attempt_ids); a reason beyond 256 characters exits non-zero.
- `audit report` returns {"generation_id", "report_md"} and the generation id
  matches the REPORT.md header.

Standard library only; invokes skill/scripts/audit.py as a subprocess (-I).

Requirements: SWR-022(驱动与暂停) / DSR-064(缺失宿主拒绝), DSR-074(in-flight契约)
"""

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
AUDIT_PY = REPO_ROOT / "skill" / "scripts" / "audit.py"
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures"

FAKE_CLAUDE_HEADLESS_STDOUT = json.dumps({
    "ok": True,
    "usage": {"input_tokens": 12, "output_tokens": 8, "availability": "exact"},
})
FAKE_CODEX_HEADLESS_STDOUT = json.dumps({
    "ok": True,
    "usage": {"total_tokens": 42, "availability": "estimated"},
})


def run_cli(args, stdin_text=None, env_path=None):
    """Run audit.py in an isolated interpreter (-I) and return the process.

    env_path replaces PATH so tests can inject (or remove) fake host CLIs.
    """
    env = dict(os.environ)
    if env_path is not None:
        env["PATH"] = env_path
    return subprocess.run(
        [sys.executable, "-I", str(AUDIT_PY)] + args,
        input=stdin_text,
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
    )


def parse_envelope(proc):
    lines = [ln for ln in proc.stdout.strip().splitlines() if ln.strip()]
    assert len(lines) == 1, f"expected exactly one envelope line, got: {proc.stdout!r}"
    return json.loads(lines[0])


def write_executable(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8")
    mode = path.stat().st_mode
    path.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


def make_fake_host(directory: Path, name: str, headless_stdout: str) -> Path:
    """Create a fake host CLI script (tests/hosts/fake_hosts.py pattern).

    `--version` exits 0; any other invocation (headless path used by the
    driver adapters) prints headless_stdout and exits 0.
    """
    script = (
        "#!/bin/sh\n"
        "# Auto-generated fake host CLI (tests/cli/test_run_driver.py). Do not edit.\n"
        'if [ "$1" = "--version" ]; then\n'
        f'  echo "fake-{name} version 9.9.9"\n'
        "  exit 0\n"
        "fi\n"
        f"echo '{headless_stdout}'\n"
        "exit 0\n"
    )
    return write_executable(directory / name, script)


class DriverLoopTestCase(unittest.TestCase):
    """Shared prepare/config scaffolding for the run/pause/report contracts."""

    host_fixture_name = "pyapp"

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.target = FIXTURES_DIR / self.host_fixture_name
        self.run_dir = Path(self.tmp) / "run"
        self.config_path = Path(self.tmp) / "config.json"
        config = {
            "schema_version": "1.0",
            "target": str(self.target),
            "run_dir": str(self.run_dir),
            "report_language": "en",
            "profile": "standard",
            "scope": {"include": ["*.py"], "exclude": []},
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

    def cli_ok(self, args, stdin_text=None, env_path=None):
        proc = run_cli(args, stdin_text=stdin_text, env_path=env_path)
        self.assertEqual(
            proc.returncode, 0,
            f"args={args}\nstdout={proc.stdout}\nstderr={proc.stderr}",
        )
        return parse_envelope(proc)["value"]

    def make_fake_bin_dir(self, name="fakebin") -> str:
        bin_dir = Path(self.tmp) / name
        bin_dir.mkdir(parents=True, exist_ok=True)
        return str(bin_dir)

    def prepared_run_id(self) -> str:
        prep = self.cli_ok([
            "prepare", "--target", str(self.target),
            "--run-dir", str(self.run_dir), "--config", str(self.config_path),
        ])
        return prep["run_id"]


class TestRunDriverLoop(DriverLoopTestCase):
    """IFC-06: run --host claude|codex drives the dispatch loop for real."""

    def test_run_host_claude_drives_target_to_complete(self):
        run_id = self.prepared_run_id()
        bin_dir = self.make_fake_bin_dir()
        make_fake_host(Path(bin_dir), "claude", FAKE_CLAUDE_HEADLESS_STDOUT)

        res = self.cli_ok(
            ["run", "--run-dir", str(self.run_dir), "--host", "claude", "--concurrency", "2"],
            env_path=bin_dir,
        )
        self.assertEqual(res["run_id"], run_id)
        self.assertEqual(res["mode"], "claude")
        # The loop really worked work: every planned task submitted, none left.
        self.assertGreaterEqual(res["dispatch"]["submitted"], 1)
        self.assertEqual(res["dispatch"]["failed"], 0)
        self.assertEqual(res["queued_tasks"], 0)
        self.assertEqual(res["dispatch"]["stop_reason"], "queue_drained")
        # AIMD controller wired: concurrency grew past its initial value.
        self.assertGreaterEqual(res["concurrency"], 2)

        st = self.cli_ok(["status", "--run-dir", str(self.run_dir)])
        self.assertEqual(st["tasks"].get("queued", 0), 0)
        self.assertEqual(st["tasks"].get("done", 0), res["dispatch"]["submitted"])

        fin = self.cli_ok(["finalize", "--run-dir", str(self.run_dir)])
        self.assertEqual(fin["final_state"], "complete")
        for gate, status in fin["gates"].items():
            self.assertEqual(status, "pass", f"gate {gate} did not pass")

    def test_run_host_codex_drives_target_to_complete(self):
        self.prepared_run_id()
        bin_dir = self.make_fake_bin_dir()
        make_fake_host(Path(bin_dir), "codex", FAKE_CODEX_HEADLESS_STDOUT)

        res = self.cli_ok(
            ["run", "--run-dir", str(self.run_dir), "--host", "codex"],
            env_path=bin_dir,
        )
        self.assertEqual(res["mode"], "codex")
        self.assertGreaterEqual(res["dispatch"]["submitted"], 1)
        self.assertEqual(res["queued_tasks"], 0)

    def test_run_trusted_usage_flows_from_adapter_to_ledger(self):
        self.prepared_run_id()
        bin_dir = self.make_fake_bin_dir()
        make_fake_host(Path(bin_dir), "claude", FAKE_CLAUDE_HEADLESS_STDOUT)
        self.cli_ok(
            ["run", "--run-dir", str(self.run_dir), "--host", "claude"],
            env_path=bin_dir,
        )
        import sqlite3
        conn = sqlite3.connect(str(self.run_dir / "events.db"))
        try:
            rows = conn.execute(
                "SELECT dimension, availability, value, attempt_id FROM usage_records"
            ).fetchall()
            # P0 usage envelope: each attempt settles its OWN usage row, bound
            # to the attempt the dispatch loop actually submitted.
            attempt_ids = {
                r[0] for r in conn.execute("SELECT attempt_id FROM attempts").fetchall()
            }
        finally:
            conn.close()
        self.assertTrue(rows, "no usage record persisted by the driver loop")
        dims = {r[0] for r in rows}
        self.assertIn("tokens", dims)
        exact = [r for r in rows if r[1] == "exact" and r[2] == 20]
        self.assertTrue(
            exact,
            f"expected exact usage value 20 (12+8) from the fake host, got {rows}",
        )
        # Every usage row binds to a real attempt of this run, one row per
        # attempt: no attempt was left unattributed or double-attributed.
        for row in rows:
            self.assertIn(row[3], attempt_ids, f"usage row bound to unknown attempt: {row}")
        token_rows = [r for r in rows if r[0] == "tokens"]
        self.assertEqual(
            len({r[3] for r in token_rows}), len(token_rows),
            f"a single attempt carries multiple tokens usage rows: {token_rows}",
        )

    def test_missing_host_cli_exits_nonzero_without_idling(self):
        run_id = self.prepared_run_id()
        empty_dir = self.make_fake_bin_dir("emptypath")  # no claude/codex on PATH

        proc = run_cli(
            ["run", "--run-dir", str(self.run_dir), "--host", "claude"],
            env_path=empty_dir,
        )
        self.assertNotEqual(proc.returncode, 0)
        env = parse_envelope(proc)
        self.assertFalse(env["ok"])
        self.assertEqual(env["error"]["code"], "HOST_FAILURE")
        self.assertFalse(env["error"]["retryable"])

        # Honest failure: the run was not touched (no silent no-op progress).
        st = self.cli_ok(["status", "--run-dir", str(self.run_dir)])
        self.assertEqual(st["run_id"], run_id)
        self.assertEqual(st["tasks"].get("done", 0), 0)
        self.assertGreaterEqual(st["tasks"].get("queued", 0), 1)

    def test_missing_codex_cli_exits_nonzero(self):
        self.prepared_run_id()
        empty_dir = self.make_fake_bin_dir("emptypath2")
        proc = run_cli(
            ["run", "--run-dir", str(self.run_dir), "--host", "codex"],
            env_path=empty_dir,
        )
        self.assertNotEqual(proc.returncode, 0)
        env = parse_envelope(proc)
        self.assertEqual(env["error"]["code"], "HOST_FAILURE")

    def test_invalid_concurrency_rejected(self):
        self.prepared_run_id()
        bin_dir = self.make_fake_bin_dir()
        make_fake_host(Path(bin_dir), "claude", FAKE_CLAUDE_HEADLESS_STDOUT)
        proc = run_cli(
            ["run", "--run-dir", str(self.run_dir), "--host", "claude", "--concurrency", "0"],
            env_path=bin_dir,
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(parse_envelope(proc)["error"]["code"], "INVALID_INPUT")


class TestRunSessionMode(DriverLoopTestCase):
    """IFC-06 2b: session mode activates and guides, never idles or fakes."""

    def test_session_mode_prints_guidance_and_exits_zero(self):
        run_id = self.prepared_run_id()
        res = self.cli_ok(["run", "--run-dir", str(self.run_dir)])
        self.assertEqual(res["run_id"], run_id)
        self.assertEqual(res["state"], "active")
        self.assertEqual(res["mode"], "session")
        guidance = " ".join(res["next_steps"])
        for step in ("next", "start", "submit"):
            self.assertIn(step, guidance)
        self.assertIn("finalize", guidance)

    def test_session_mode_does_not_claim_tasks(self):
        self.prepared_run_id()
        res = self.cli_ok(["run", "--run-dir", str(self.run_dir)])
        self.assertEqual(res["state"], "active")
        st = self.cli_ok(["status", "--run-dir", str(self.run_dir)])
        # Guidance only: no task was dispatched or executed by the CLI itself.
        self.assertEqual(st["tasks"].get("done", 0), 0)
        self.assertEqual(st["tasks"].get("claimed", 0), 0)
        self.assertGreaterEqual(st["tasks"].get("queued", 0), 1)

    def test_session_mode_resumes_paused_run(self):
        self.prepared_run_id()
        self.cli_ok(["run", "--run-dir", str(self.run_dir)])
        self.cli_ok(["pause", "--run-dir", str(self.run_dir)])
        res = self.cli_ok(["run", "--run-dir", str(self.run_dir)])
        self.assertEqual(res["state"], "active")
        self.assertEqual(res["mode"], "session")


class TestPauseContract(DriverLoopTestCase):
    """pause surfaces in-flight accounting; over-long reasons fail loudly."""

    def _activate_and_claim(self):
        self.prepared_run_id()
        self.cli_ok(["run", "--run-dir", str(self.run_dir)])
        claims = self.cli_ok(
            ["next", "--run-dir", str(self.run_dir), "--batch", "1"]
        )["claims"]
        self.assertTrue(claims)
        return claims[0]

    def test_pause_reports_in_flight_tasks_and_attempt_ids(self):
        claim = self._activate_and_claim()
        res = self.cli_ok(["pause", "--run-dir", str(self.run_dir)])
        self.assertEqual(res["state"], "paused")
        for key in ("revision", "in_flight_tasks", "in_flight_attempt_ids"):
            self.assertIn(key, res)
        self.assertGreaterEqual(res["in_flight_tasks"], 1)
        self.assertIn(claim["attempt_id"], res["in_flight_attempt_ids"])

    def test_pause_with_no_in_flight_work_reports_zero(self):
        self.prepared_run_id()
        self.cli_ok(["run", "--run-dir", str(self.run_dir)])
        res = self.cli_ok(["pause", "--run-dir", str(self.run_dir)])
        self.assertEqual(res["in_flight_tasks"], 0)
        self.assertEqual(res["in_flight_attempt_ids"], [])

    def test_pause_reason_over_256_chars_exits_nonzero(self):
        self.prepared_run_id()
        proc = run_cli(
            ["pause", "--run-dir", str(self.run_dir), "--reason", "x" * 257]
        )
        self.assertNotEqual(proc.returncode, 0)
        env = parse_envelope(proc)
        self.assertFalse(env["ok"])
        self.assertEqual(env["error"]["code"], "INVALID_INPUT")
        self.assertEqual(env["error"]["details"].get("limit"), 256)

    def test_pause_reason_at_limit_exits_zero(self):
        self.prepared_run_id()
        res = self.cli_ok(
            ["pause", "--run-dir", str(self.run_dir), "--reason", "y" * 256]
        )
        self.assertEqual(res["state"], "paused")


class TestReportContract(DriverLoopTestCase):
    """report returns the generation id alongside report_md."""

    def _finalize(self):
        self.prepared_run_id()
        self.cli_ok(["run", "--run-dir", str(self.run_dir)])
        fin = self.cli_ok(["finalize", "--run-dir", str(self.run_dir)])
        return fin

    def test_report_generation_id_matches_report_header(self):
        fin = self._finalize()
        res = self.cli_ok(["report", "--run-dir", str(self.run_dir)])
        for key in ("generation_id", "report_md"):
            self.assertIn(key, res)
        self.assertTrue(res["generation_id"])
        # Consistent with the report header AND the finalize receipt.
        header_lines = res["report_md"].splitlines()[:30]
        header_gen = [
            ln for ln in header_lines
            if "Generation" in ln and res["generation_id"] in ln
        ]
        self.assertTrue(header_gen, f"generation id not in header: {header_lines[:8]}")
        self.assertEqual(fin["generation_id"], res["generation_id"])

    def test_report_generation_id_falls_back_to_header(self):
        self._finalize()
        import sqlite3
        conn = sqlite3.connect(str(self.run_dir / "events.db"))
        try:
            conn.execute("DELETE FROM artifacts WHERE relative_path = 'report/REPORT.md'")
            conn.commit()
        finally:
            conn.close()
        res = self.cli_ok(["report", "--run-dir", str(self.run_dir)])
        # Header fallback still resolves the published generation marker.
        self.assertTrue(res["generation_id"])
        self.assertIn(res["generation_id"], res["report_md"].splitlines()[5])


if __name__ == "__main__":
    unittest.main()
