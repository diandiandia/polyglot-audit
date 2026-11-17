"""Contract-alignment tests: ledger-bound CLI commands refuse a run directory
without a valid dossier (no events.db) with the standard INVALID_INPUT
envelope (exit 2) — and never create events.db.

Why the no-side-effect assertion is the load-bearing one: sqlite3.connect
silently creates an (empty) database file when the path is missing. Before the
shared ``_require_events_db`` precheck in skill/scripts/audit.py, status /
next / pause / resume / finalize / run went straight to get_db_connection,
polluting the run directory and surfacing a non-standard INTERNAL_ERROR
("no such table: runs"). host-fail already carried the correct precheck; every
ledger-bound command now shares it, so each command is asserted against the
same contract as host-fail (exit 2, INVALID_INPUT, filesystem untouched).

Both variants of an invalid run directory are covered:
- the path does not exist at all (and must still not exist afterwards), and
- the directory exists but is empty (and must remain empty afterwards).

mcp refuses before the stdio loop starts: the standard CLI error envelope is
emitted (the JSON-RPC server never came up) with exit 2. A control test seeds
a real dossier (same pattern as tests/cli/test_human_format.seed_run) to pin
the positive direction: legal run-directory paths keep working unchanged.

Standard library only; invokes skill/scripts/audit.py as a subprocess (-I).

Requirements: SWR-001(缺条件不运行) / DSR-074(非法参数非零)
"""

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
AUDIT_PY = REPO_ROOT / "skill" / "scripts" / "audit.py"


def run_cli(args, stdin_text=None):
    """Run audit.py in an isolated interpreter (-I) and return the process."""
    return subprocess.run(
        [sys.executable, "-I", str(AUDIT_PY)] + args,
        input=stdin_text,
        capture_output=True,
        text=True,
        timeout=120,
    )


def parse_envelope(proc):
    """Parse a single JSON envelope from stdout."""
    lines = [ln for ln in proc.stdout.strip().splitlines() if ln.strip()]
    assert len(lines) == 1, f"expected exactly one envelope line, got: {proc.stdout!r}"
    return json.loads(lines[0])


# A well-formed claim/payload body. The events.db precheck fires before the
# stdin read, so the body never reaches the service — it only proves the
# command fails on the dossier check, not on payload parsing.
CLAIM = {
    "schema_version": "1.0",
    "run_id": "run-absent",
    "task_id": "task-1",
    "attempt_id": "att-1",
    "generation": 0,
    "claim_token": "token-1",
    "spec": {},
}

# The seven ledger-bound commands from the contract fix plus `run` (same
# connect-before-check bug class, same shared precheck).
LEDGER_BOUND_COMMANDS = [
    ("status", ["status"], None),
    ("next", ["next"], None),
    ("pause", ["pause"], None),
    ("resume", ["resume"], None),
    ("finalize", ["finalize"], None),
    ("run", ["run"], None),
    ("start", ["start"], json.dumps({"claim": CLAIM})),
    ("submit", ["submit"], json.dumps({"claim": CLAIM, "result": {}})),
]


def seed_run(run_dir: Path, state: str = "ready") -> str:
    """Create a real run directory (events.db + one run row) without prepare.

    Mirrors tests/cli/test_human_format.seed_run: seeds events.db directly so
    the positive control cannot be broken by in-flight changes to
    AuditAppService.prepare in a parallel workstream.
    """
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


class TestMissingRunDirInvalidInput(unittest.TestCase):
    """Every ledger-bound command: missing dossier -> INVALID_INPUT (exit 2),
    and the precheck strictly precedes any sqlite3.connect (no file created)."""

    def test_nonexistent_run_dir_invalid_input_no_files_created(self):
        for subcommand, argv, stdin_text in LEDGER_BOUND_COMMANDS:
            with self.subTest(subcommand=subcommand):
                tmp = tempfile.mkdtemp(prefix="missing-rundir-")
                try:
                    run_dir = Path(tmp) / "run_absent"
                    self.assertFalse(run_dir.exists())

                    proc = run_cli(argv + ["--run-dir", str(run_dir)], stdin_text=stdin_text)

                    # Standard error contract: exit 2 (INVALID_INPUT mapping),
                    # frozen error envelope, never INTERNAL_ERROR.
                    self.assertEqual(proc.returncode, 2, f"{subcommand}: {proc.stdout} {proc.stderr}")
                    env = parse_envelope(proc)
                    self.assertFalse(env["ok"])
                    self.assertNotIn("value", env)
                    err = env["error"]
                    self.assertEqual(err["code"], "INVALID_INPUT")
                    self.assertFalse(err["retryable"])
                    self.assertIn("run_dir", err["details"])
                    self.assertEqual(err["details"]["run_dir"], str(run_dir))
                    self.assertIn("events_db", err["details"])

                    # The load-bearing assertion: the precheck fired BEFORE any
                    # connect, so nothing was created under the run directory
                    # (sqlite3.connect would have silently created events.db).
                    self.assertFalse(
                        run_dir.exists(),
                        f"{subcommand} created the run directory (precheck ran after connect)",
                    )
                finally:
                    shutil.rmtree(tmp, ignore_errors=True)

    def test_empty_existing_run_dir_stays_empty(self):
        for subcommand, argv, stdin_text in LEDGER_BOUND_COMMANDS:
            with self.subTest(subcommand=subcommand):
                tmp = tempfile.mkdtemp(prefix="empty-rundir-")
                try:
                    run_dir = Path(tmp) / "run_empty"
                    run_dir.mkdir()
                    self.assertEqual(list(run_dir.iterdir()), [])

                    proc = run_cli(argv + ["--run-dir", str(run_dir)], stdin_text=stdin_text)

                    self.assertEqual(proc.returncode, 2, f"{subcommand}: {proc.stdout} {proc.stderr}")
                    env = parse_envelope(proc)
                    self.assertEqual(env["error"]["code"], "INVALID_INPUT")
                    # No events.db (and nothing else) may appear in the
                    # directory after the failed invocation.
                    self.assertEqual(
                        list(run_dir.iterdir()),
                        [],
                        f"{subcommand} created files in the empty run directory: "
                        f"{[p.name for p in run_dir.iterdir()]}",
                    )
                finally:
                    shutil.rmtree(tmp, ignore_errors=True)


class TestHostFailContractConsistency(unittest.TestCase):
    """host-fail is the reference behavior (it prechecked events.db first);
    the shared helper must keep its contract byte-for-byte."""

    def test_host_fail_missing_run_dir_same_contract(self):
        tmp = tempfile.mkdtemp(prefix="hostfail-rundir-")
        try:
            run_dir = Path(tmp) / "run_absent"
            proc = run_cli(
                ["host-fail", "--run-dir", str(run_dir)],
                stdin_text=json.dumps({"claim": {"task_id": "task-1"}}),
            )
            self.assertEqual(proc.returncode, 2, proc.stdout)
            env = parse_envelope(proc)
            self.assertFalse(env["ok"])
            self.assertEqual(env["error"]["code"], "INVALID_INPUT")
            self.assertFalse(env["error"]["retryable"])
            self.assertEqual(env["error"]["details"]["run_dir"], str(run_dir))
            self.assertFalse(run_dir.exists())
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestMCPRunDirPrecheck(unittest.TestCase):
    """mcp refuses to start the stdio server on a dossier-less run directory:
    standard CLI error envelope (exit 2), not a per-request JSON-RPC error."""

    def test_mcp_nonexistent_run_dir_refuses_to_start(self):
        tmp = tempfile.mkdtemp(prefix="mcp-rundir-")
        try:
            run_dir = Path(tmp) / "run_absent"
            request = json.dumps({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "status", "arguments": {}},
            })
            proc = run_cli(["mcp", "--run-dir", str(run_dir)], stdin_text=request)

            self.assertEqual(proc.returncode, 2, proc.stdout)
            env = parse_envelope(proc)
            self.assertFalse(env["ok"])
            self.assertEqual(env["error"]["code"], "INVALID_INPUT")
            self.assertEqual(env["error"]["details"]["run_dir"], str(run_dir))
            # The server never came up: no JSON-RPC response was produced.
            self.assertNotIn("jsonrpc", proc.stdout)
            self.assertFalse(run_dir.exists())
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestValidRunDirStillWorks(unittest.TestCase):
    """Positive control: a run directory WITH a valid dossier keeps working —
    the precheck must reject only dossier-less paths (legal-path behavior
    unchanged, zero-diff hard constraint)."""

    def test_status_on_seeded_dossier_exits_zero(self):
        tmp = tempfile.mkdtemp(prefix="valid-rundir-")
        try:
            run_dir = Path(tmp) / "run_ok"
            seed_run(run_dir, state="ready")
            proc = run_cli(["status", "--run-dir", str(run_dir)])
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            env = parse_envelope(proc)
            self.assertTrue(env["ok"])
            self.assertEqual(env["value"]["run_id"], "run-" + run_dir.name)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_mcp_on_seeded_dossier_starts_and_serves(self):
        tmp = tempfile.mkdtemp(prefix="valid-mcp-rundir-")
        try:
            run_dir = Path(tmp) / "run_ok"
            seed_run(run_dir, state="ready")
            request = json.dumps({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "status", "arguments": {}},
            })
            proc = run_cli(["mcp", "--run-dir", str(run_dir)], stdin_text=request)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            reply = json.loads(proc.stdout.strip().splitlines()[0])
            self.assertEqual(reply["jsonrpc"], "2.0")
            self.assertNotIn("error", reply)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
