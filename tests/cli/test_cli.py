"""CLI freeze tests for audit.py (DSR-074 / DSR-032 / SWR-001 / SWR-022 / SWR-023).

Implements DDS-07 / DSR-074:
- Invokes skill/scripts/audit.py as a subprocess (frozen public interface).
- Covers: every subcommand --help exits 0; unknown subcommand exits non-zero;
  invalid arguments exit non-zero; JSON envelope shape (schema_version/ok/value
  and error.code/message/retryable/details); submit never reads credentials
  from argv; guide/audit mode separation (guide creates no run directory).
- A minimal full lifecycle (prepare -> run -> next -> start -> host-fail ->
  next -> start -> submit -> finalize) is driven through the CLI on the shared
  tests/fixtures/pyapp target (same usage as tests/e2e, read-only reference).

Requirements: SWR-001(guide不建卷宗), SWR-022(共用CLI) / DSR-032(模糊不执行), DSR-052(入口说明), DSR-074(接口冻结)
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
AUDIT_PY = REPO_ROOT / "skill" / "scripts" / "audit.py"
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures"

# 13 frozen subcommands (DSR-074) + host-fail (DSR-065 wiring).
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


class TestCLIFreeze(unittest.TestCase):
    """DSR-074: frozen CLI surface."""

    def test_help_all_subcommands_exit_zero(self):
        for sub in ALL_SUBCOMMANDS:
            with self.subTest(subcommand=sub):
                proc = run_cli([sub, "--help"])
                self.assertEqual(proc.returncode, 0, proc.stderr)
                combined = (proc.stdout + proc.stderr).lower()
                self.assertIn("usage", combined)

    def test_top_level_help_exit_zero(self):
        proc = run_cli(["--help"])
        self.assertEqual(proc.returncode, 0)
        combined = proc.stdout + proc.stderr
        for sub in FROZEN_SUBCOMMANDS:
            self.assertIn(sub, combined, f"subcommand {sub} missing from help")

    def test_unknown_subcommand_nonzero_exit(self):
        proc = run_cli(["definitely-not-a-command"])
        self.assertNotEqual(proc.returncode, 0)

    def test_no_subcommand_nonzero_exit(self):
        proc = run_cli([])
        self.assertNotEqual(proc.returncode, 0)

    def test_invalid_argument_nonzero_exit(self):
        for args in (
            ["doctor", "--no-such-flag"],
            ["status", "--no-such-flag"],
            ["next", "--batch", "not-an-int"],
            ["pause", "--reason"],  # missing value
        ):
            with self.subTest(args=args):
                proc = run_cli(args)
                self.assertNotEqual(proc.returncode, 0)

    def test_missing_required_args_nonzero_exit(self):
        # DSR-032: audit mode without --target/--run-dir/--config must fail
        # loudly instead of running.
        for args in (
            ["prepare"],
            ["prepare", "--target", "."],
            ["prepare", "--target", ".", "--run-dir", "/tmp/x"],
            ["status"],
            ["submit"],
            ["finalize"],
        ):
            with self.subTest(args=args):
                proc = run_cli(args)
                self.assertNotEqual(proc.returncode, 0)

    # -- JSON envelope shape --------------------------------------------------

    def test_envelope_shape_success(self):
        proc = run_cli(["guide", "--query", "how to prevent unsafe deserialization in python"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        env = parse_envelope(proc)
        self.assertEqual(env["schema_version"], "1.0")
        self.assertTrue(env["ok"])
        self.assertIsInstance(env["value"], dict)
        self.assertNotIn("error", env)

    def test_envelope_shape_error(self):
        proc = run_cli(["report", "--run-dir", "/nonexistent/run-dir-xyz"])
        self.assertNotEqual(proc.returncode, 0)
        env = parse_envelope(proc)
        self.assertEqual(env["schema_version"], "1.0")
        self.assertFalse(env["ok"])
        self.assertNotIn("value", env)
        err = env["error"]
        for field in ("code", "message", "retryable", "details"):
            self.assertIn(field, err)
        self.assertIsInstance(err["details"], dict)

    # -- credentials never come from argv (DSR-074) ---------------------------

    def test_submit_does_not_read_credentials_from_argv(self):
        with tempfile.TemporaryDirectory() as tmp:
            token = "SECRET-CLAIM-TOKEN-do-not-leak"
            proc = run_cli(
                ["submit", "--run-dir", tmp, "--claim-token", token, "--claim", token],
                stdin_text="{}",
            )
            # argparse must reject unknown credential-bearing flags outright;
            # the token never reaches the JSON envelope on stdout and no
            # submit is processed (argv is not a credential channel, DSR-074).
            self.assertNotEqual(proc.returncode, 0)
            self.assertNotIn(token, proc.stdout)
            env_line = [ln for ln in proc.stdout.strip().splitlines() if ln.strip()]
            self.assertEqual(env_line, [])

    def test_start_reads_claim_from_stdin_not_argv(self):
        token = "SECRET-CLAIM-TOKEN-stdin-only"
        proc = run_cli(["start", "--run-dir", "/tmp/whatever", token])
        self.assertNotEqual(proc.returncode, 0)
        self.assertNotIn(token, proc.stdout)


class TestGuideAuditSeparation(unittest.TestCase):
    """SWR-001 / DSR-032: guide never creates run artifacts; ambiguous requests ask."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_guide_creates_no_run_directory_or_db(self):
        before = set(os.listdir(self.tmp))
        proc = run_cli(
            ["guide", "--query", "how should I audit unsafe deserialization in python?"],
            cwd=self.tmp,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        after = set(os.listdir(self.tmp))
        self.assertEqual(before, after, f"guide mode created files: {after - before}")

    def test_guide_rejects_run_dir_option(self):
        proc = run_cli(["guide", "--query", "how to prevent xss?", "--run-dir", self.tmp])
        self.assertNotEqual(proc.returncode, 0)

    def test_ambiguous_query_returns_clarification_not_execution(self):
        for query, reason in (
            ("", "empty_query"),
            ("帮个忙", "query_too_short"),
            ("这个项目挺有意思的", "no_request_verb"),
        ):
            with self.subTest(query=query):
                proc = run_cli(["guide", "--query", query], cwd=self.tmp)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                env = parse_envelope(proc)
                self.assertTrue(env["ok"])
                val = env["value"]
                self.assertEqual(val["mode"], "guide")
                self.assertEqual(val["status"], "ambiguous")
                self.assertEqual(val["ambiguity_reason"], reason)
                self.assertTrue(val["clarification_questions"])
                self.assertEqual(val["relevant_cards"], [])
                self.assertEqual(val["catalog_index"], [])

    def test_clear_query_executes_guide(self):
        proc = run_cli(
            ["guide", "--query", "请审计 python 反序列化风险，怎么检查？"],
            cwd=self.tmp,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        val = parse_envelope(proc)["value"]
        self.assertEqual(val["status"], "ok")
        self.assertIn("no run directory", val["guidance"])


class TestCLILifecycle(unittest.TestCase):
    """Minimal lifecycle over the CLI using the shared pyapp fixture (e2e usage)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.target = FIXTURES_DIR / "pyapp"
        self.run_dir = Path(self.tmp) / "run_cli"
        self.config_path = Path(self.tmp) / "config.json"
        config = {
            "schema_version": "1.0",
            "target": str(self.target),
            "run_dir": str(self.run_dir),
            "report_language": "zh",
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

    def cli_ok(self, args, stdin_text=None):
        proc = run_cli(args, stdin_text=stdin_text)
        self.assertEqual(proc.returncode, 0, f"args={args}\nstdout={proc.stdout}\nstderr={proc.stderr}")
        return parse_envelope(proc)["value"]

    def test_prepare_run_next_start_hostfail_submit_finalize(self):
        # prepare
        prep = self.cli_ok([
            "prepare", "--target", str(self.target),
            "--run-dir", str(self.run_dir), "--config", str(self.config_path),
        ])
        self.assertTrue(prep["run_id"].startswith("run-"))
        self.assertTrue((self.run_dir / "events.db").exists())

        # run (activate)
        run_res = self.cli_ok(["run", "--run-dir", str(self.run_dir)])
        self.assertEqual(run_res["state"], "active")

        # next (claim) -- batch 1 so no unused claim is left holding a lease
        claims = self.cli_ok(["next", "--run-dir", str(self.run_dir), "--batch", "1"])["claims"]
        self.assertTrue(claims)
        claim = claims[0]

        # start (claim from stdin)
        start_res = self.cli_ok(
            ["start", "--run-dir", str(self.run_dir)],
            stdin_text=json.dumps(claim),
        )
        self.assertEqual(start_res["status"], "running")

        # host-fail: retryable failure requeues the task (DSR-065 wiring)
        hf = self.cli_ok(
            ["host-fail", "--run-dir", str(self.run_dir), "--task", claim["task_id"], "--retryable"],
            stdin_text=json.dumps({"claim": claim, "reason": "host crashed mid-hunt"}),
        )
        self.assertIn(hf.get("action"), ("requeued", "quarantined"))

        # re-claim after failure
        claims2 = self.cli_ok(["next", "--run-dir", str(self.run_dir), "--batch", "1"])["claims"]
        self.assertTrue(claims2)
        claim2 = next(
            (c for c in claims2 if c["task_id"] == claim["task_id"]),
            claims2[0],
        )
        self.cli_ok(
            ["start", "--run-dir", str(self.run_dir)],
            stdin_text=json.dumps(claim2),
        )

        # submit (payload from stdin)
        result_kind = (claim2.get("spec") or {}).get("task_kind") or claim2.get("task_kind") or "hunt"
        worker_result = {
            "schema_version": "1.0",
            "task_id": claim2["task_id"],
            "attempt_id": claim2["attempt_id"],
            "kind": result_kind,
            "coverage": [{
                "schema_version": "1.0",
                "snapshot_id": prep["snapshot_id"],
                "unit_id": "u1",
                "dimension": "observed_read",
                "source": "worker",
                "ranges": [{"path": "app/handlers/upload.py", "line_start": 1, "line_end": 12}],
                "confidence": "exact",
            }],
            "records": [],
            "overflow": [],
        }
        sub = self.cli_ok(
            ["submit", "--run-dir", str(self.run_dir)],
            stdin_text=json.dumps({
                "claim": claim2,
                "result": worker_result,
                "result_digest": "digest-cli-01",
            }),
        )
        self.assertTrue(sub["ok"])

        # Drain remaining in-flight claims: finalize now enforces the terminal
        # state semantics (SD-06 §5.1 / DSR-076) and refuses to run while a
        # valid claim lease is held (INVALID_STATE).
        for _ in range(10):
            batch = self.cli_ok(["next", "--run-dir", str(self.run_dir), "--batch", "5"])["claims"]
            if not batch:
                break
            for c in batch:
                self.cli_ok(
                    ["start", "--run-dir", str(self.run_dir)],
                    stdin_text=json.dumps(c),
                )
                kind = (c.get("spec") or {}).get("task_kind") or c.get("task_kind") or "hunt"
                res = {
                    "schema_version": "1.0",
                    "task_id": c["task_id"],
                    "attempt_id": c["attempt_id"],
                    "kind": kind,
                    "coverage": [],
                    "records": [],
                    "overflow": [],
                }
                self.cli_ok(
                    ["submit", "--run-dir", str(self.run_dir)],
                    stdin_text=json.dumps({
                        "claim": c,
                        "result": res,
                        "result_digest": f"digest-drain-{c['task_id']}",
                    }),
                )

        # status
        st = self.cli_ok(["status", "--run-dir", str(self.run_dir)])
        self.assertEqual(st["run_id"], prep["run_id"])

        # finalize: transparently surfaces incomplete_reasons / coverage_gaps
        fin = self.cli_ok(["finalize", "--run-dir", str(self.run_dir)])
        for field in ("incomplete_reasons", "coverage_gaps", "gates", "final_state"):
            self.assertIn(field, fin)
        self.assertIn(fin["final_state"], ("complete", "incomplete"))

        # report
        rep = self.cli_ok(["report", "--run-dir", str(self.run_dir)])
        self.assertIn("report_md", rep)
        self.assertTrue((self.run_dir / "report" / "REPORT.md").exists())

    def test_host_fail_missing_run_dir_fails_cleanly(self):
        proc = run_cli(
            ["host-fail", "--run-dir", str(Path(self.tmp) / "missing")],
            stdin_text=json.dumps({"claim": {"task_id": "t"}}),
        )
        self.assertNotEqual(proc.returncode, 0)
        env = parse_envelope(proc)
        self.assertFalse(env["ok"])
        self.assertEqual(env["error"]["code"], "INVALID_INPUT")


if __name__ == "__main__":
    unittest.main()
