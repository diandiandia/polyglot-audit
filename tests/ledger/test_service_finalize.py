"""Service-level tests for finalize gates, corrupt runs, stop sequence, and retries.

Implements coverage for DSR-076 (real gate inputs, corrupt defense, incomplete
terminal state), DSR-066 (stop sequence / budget exhaustion), and DSR-065
(retry consumption through the application service).
"""

import contextlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from auditkit.analysis.verifier import Verifier
from auditkit.app.service import AuditAppService
from auditkit.contracts.errors import CorruptRunError, HostFailureError, InvalidStateError
from auditkit.ledger.artifacts import ArtifactManager
from auditkit.ledger.db import get_db_connection

FIXTURES_DIR = Path("/root/polyglot-audit/tests/fixtures")
SKILL_DIR = Path("/root/polyglot-audit/skill")


class TestServiceFinalize(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.app = AuditAppService(SKILL_DIR)

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def _make_config(self, fixture: str, limit: int = 20) -> dict:
        run_dir = Path(self.temp_dir) / f"run_{fixture}_{limit}"
        return {
            "schema_version": "1.0",
            "target": str(FIXTURES_DIR / fixture),
            "run_dir": str(run_dir),
            "report_language": "zh",
            "profile": "standard",
            "scope": {"include": ["*"], "exclude": []},
            "budgets": [{"schema_version": "1.0", "dimension": "tasks", "mode": "enforced",
                         "limit": limit, "settled": 0, "reserved": 0, "unit": "tasks",
                         "availability": "exact"}],
            "safety_acceptance": {"allow_unverified_execution": False,
                                  "allow_unverified_network": False,
                                  "allow_unverified_write": False,
                                  "user_approved": True},
        }

    def _prepared_run(self, fixture: str = "pyapp", limit: int = 20):
        config = self._make_config(fixture, limit)
        prep = self.app.prepare(config["target"], config["run_dir"], config)
        self.app.activate(prep["run_id"], config["run_dir"])
        self._active_run_id = prep["run_id"]
        self._active_run_dir = Path(config["run_dir"])
        return prep, config

    def _recon_result(self, claim: dict) -> dict:
        return {
            "schema_version": "1.0",
            "task_id": claim["task_id"],
            "attempt_id": claim["attempt_id"],
            "kind": "recon",
            "coverage": [],
            "records": [],
            "overflow": [],
        }

    def _empty_hunt_result(self, claim: dict) -> dict:
        return {
            "schema_version": "1.0",
            "task_id": claim["task_id"],
            "attempt_id": claim["attempt_id"],
            "kind": "hunt",
            "coverage": [],
            "records": [],
            "overflow": [],
        }

    def _drain_all(self, snapshot_id: str = "", usage_value: int = 0):
        """Claim and submit every queued task until the queue is drained.

        Required by the SR-012/026 terminal-state semantics: finalize demands
        the plan scope (recon + every hunt, plus any verify fan-out) to be
        fully processed, so 'complete' fixtures must not leave queued work.
        """
        submitted = []
        while True:
            claims = self.app.next(
                self._active_run_id, self._active_run_dir, batch_size=20
            )
            if not claims:
                break
            for claim in claims:
                self.app.start(self._active_run_dir, claim)
                if (claim.get("spec") or {}).get("task_kind") == "recon":
                    result = self._recon_result(claim)
                else:
                    result = self._empty_hunt_result(claim)
                usage = None
                if usage_value:
                    usage = {
                        "schema_version": "1.0",
                        "attempt_id": claim["attempt_id"],
                        "dimension": "tasks",
                        "availability": "exact",
                        "value": usage_value,
                        "unit": "tasks",
                        "source": "host_cli_report",
                    }
                self.app.submit(
                    self._active_run_dir, claim, result, f"digest-{claim['attempt_id']}",
                    usage=usage,
                )
                submitted.append(claim)
        return submitted

    def _hunt_result(self, claim: dict, snapshot_id: str) -> dict:
        return {
            "schema_version": "1.0",
            "task_id": claim["task_id"],
            "attempt_id": claim["attempt_id"],
            "kind": "hunt",
            "coverage": [],
            "records": [{
                "schema_version": "1.0",
                "candidate_id": "cand-01",
                "issue": "py-01",
                "source": {"path": "caller.py", "line": 8, "symbol": "s", "kind": "param", "control": "c"},
                "sink": {"path": "callee.c", "line": 10, "symbol": "t", "kind": "deserialization", "effect": "e"},
                "steps": [
                    {"path": "caller.py", "line": 8, "role": "source", "note": "n1"},
                    {"path": "callee.c", "line": 10, "role": "sink", "note": "n2"},
                ],
                "guard_analysis": "none",
                "impact_claim": "RCE",
                "open_questions": [],
                "provenance": {"hunt_tasks": [claim["task_id"]]},
            }],
            "overflow": [],
        }

    # ------------------------------------------------------------------
    # DSR-076: corrupt run must never produce a report or forged terminal state
    # ------------------------------------------------------------------
    def test_finalize_corrupt_run_rejected_and_marked_corrupt(self):
        prep, config = self._prepared_run()
        run_id, run_dir = prep["run_id"], Path(config["run_dir"])

        with contextlib.closing(get_db_connection(run_dir / "events.db")) as conn:
            mgr = ArtifactManager(run_dir, conn)
            mgr.publish_artifact(run_id, "report", "report/notes.md", b"integrity check me")
            # Tamper with the published artifact
            (run_dir / "report" / "notes.md").write_bytes(b"tampered")

        with self.assertRaises(CorruptRunError):
            self.app.finalize(run_id, run_dir)

        with contextlib.closing(get_db_connection(run_dir / "events.db")) as conn:
            state = conn.execute("SELECT state FROM runs WHERE run_id = ?", (run_id,)).fetchone()["state"]
        self.assertEqual(state, "corrupt")
        # No report was produced
        self.assertFalse((run_dir / "report" / "REPORT.md").exists())

        # Terminal corrupt state refuses finalize
        with self.assertRaises(InvalidStateError):
            self.app.finalize(run_id, run_dir)

    # ------------------------------------------------------------------
    # DSR-076: incomplete terminal states from real gate data
    # ------------------------------------------------------------------
    def test_finalize_incomplete_when_result_lost(self):
        """A dispatched task whose lease expired without submission is a lost result."""
        prep, config = self._prepared_run()
        run_id, run_dir = prep["run_id"], Path(config["run_dir"])
        claims = self.app.next(run_id, run_dir, batch_size=5)
        self.app.start(run_dir, claims[0])

        # Expire the held lease without submitting, so the result is lost
        with contextlib.closing(get_db_connection(run_dir / "events.db")) as conn:
            conn.execute("UPDATE attempts SET expires_at = '2000-01-01T00:00:00+00:00'")

        fin = self.app.finalize(run_id, run_dir, findings=[])
        self.assertEqual(fin["final_state"], "incomplete")
        self.assertIn("G2", ",".join(fin["incomplete_reasons"]))
        with contextlib.closing(get_db_connection(run_dir / "events.db")) as conn:
            state = conn.execute("SELECT state FROM runs WHERE run_id = ?", (run_id,)).fetchone()["state"]
        self.assertEqual(state, "incomplete")

    def test_finalize_incomplete_on_budget_exhaustion(self):
        """Budget exhaustion is recorded and forces an incomplete run (DSR-066)."""
        # boundary fixture has 2 units; a limit of 1 exhausts the budget
        prep, config = self._prepared_run(fixture="boundary", limit=1)
        run_id, run_dir = prep["run_id"], Path(config["run_dir"])

        claims = self.app.next(run_id, run_dir, batch_size=1)
        self.assertEqual(len(claims), 1)
        self.app.start(run_dir, claims[0])
        self.app.submit(run_dir, claims[0], self._hunt_result(claims[0], prep["snapshot_id"]), "d1")

        # Second dispatch attempt hits the exhausted budget: nothing granted
        claims2 = self.app.next(run_id, run_dir, batch_size=1)
        self.assertEqual(claims2, [])

        fin = self.app.finalize(run_id, run_dir, findings=[])
        self.assertEqual(fin["final_state"], "incomplete")
        self.assertTrue(any("budget_exhausted" in r for r in fin["incomplete_reasons"]))

    def test_finalize_incomplete_after_quarantine(self):
        """Quarantined tasks are coverage gaps and yield an incomplete run (DSR-065)."""
        prep, config = self._prepared_run()
        run_id, run_dir = prep["run_id"], Path(config["run_dir"])
        claim = self.app.next(run_id, run_dir, batch_size=1)[0]
        self.app.start(run_dir, claim)

        res = self.app.report_host_failure(
            run_dir, claim, HostFailureError("host blew up", retryable=True), max_retries=0
        )
        self.assertEqual(res["action"], "quarantined")

        fin = self.app.finalize(run_id, run_dir, findings=[])
        self.assertEqual(fin["final_state"], "incomplete")
        self.assertTrue(any("coverage_gaps" in r for r in fin["incomplete_reasons"]))
        self.assertEqual(len(fin["coverage_gaps"]), 1)

    # ------------------------------------------------------------------
    # DSR-076: complete path with real gate inputs and usage (DSR-033)
    # ------------------------------------------------------------------
    def test_finalize_complete_with_usage(self):
        prep, config = self._prepared_run()
        run_id, run_dir = prep["run_id"], Path(config["run_dir"])

        # SR-012/026 terminal semantics: the plan scope (recon + all hunts)
        # must be processed before finalize, every attempt with exact usage.
        submitted = self._drain_all(usage_value=1)
        self.assertTrue(submitted)

        finding = Verifier().create_finding_from_candidate(
            {
                "schema_version": "1.0",
                "candidate_id": "cand-01",
                "issue": "py-01",
                "source": {"path": "caller.py", "line": 8, "symbol": "s", "kind": "param", "control": "c"},
                "sink": {"path": "callee.c", "line": 10, "symbol": "t", "kind": "deserialization", "effect": "e"},
                "steps": [
                    {"path": "caller.py", "line": 8, "role": "source", "note": "n1"},
                    {"path": "callee.c", "line": 10, "role": "sink", "note": "n2"},
                ],
                "guard_analysis": "none",
                "impact_claim": "RCE",
                "open_questions": [],
                "provenance": {"hunt_tasks": [submitted[0]["task_id"]]},
            },
            "confirmed", "t-verify-1",
            impact=4, exploitability=4,
            impact_why="RCE", exploitability_why="unauthenticated",
        )
        fin = self.app.finalize(run_id, run_dir, findings=[finding])
        self.assertEqual(fin["final_state"], "complete")
        self.assertEqual(set(fin["gates"].values()), {"pass"})
        self.assertEqual(fin["incomplete_reasons"], [])
        self.assertNotIn("unprocessed_units", fin["incomplete_reasons"])
        self.assertTrue((run_dir / "report" / "REPORT.md").exists())

        # Usage is reflected in budget status
        status = self.app.status(run_id, run_dir)
        tasks_budget = [b for b in status["budgets"] if b["dimension"] == "tasks"][0]
        self.assertEqual(tasks_budget["availability"], "exact")
        self.assertEqual(tasks_budget["source"], "host_cli_report")

    # ------------------------------------------------------------------
    # DSR-066: stop sequence — no dispatch after pause/finalize
    # ------------------------------------------------------------------
    def test_stop_sequence_blocks_dispatch_after_pause_and_finalize(self):
        prep, config = self._prepared_run()
        run_id, run_dir = prep["run_id"], Path(config["run_dir"])

        self.app.pause(run_id, run_dir)
        with self.assertRaises(InvalidStateError):
            self.app.next(run_id, run_dir, batch_size=1)

        self.app.activate(run_id, run_dir)
        self._drain_all()

        fin = self.app.finalize(run_id, run_dir, findings=[])
        self.assertEqual(fin["final_state"], "complete")
        self.assertNotIn("unprocessed_units", fin["incomplete_reasons"])
        with self.assertRaises(InvalidStateError):
            self.app.next(run_id, run_dir, batch_size=1)

    # ------------------------------------------------------------------
    # DSR-065: retryable host failures are consumed by the service
    # ------------------------------------------------------------------
    def test_report_host_failure_retries_with_new_generation(self):
        prep, config = self._prepared_run()
        run_id, run_dir = prep["run_id"], Path(config["run_dir"])

        claim = self.app.next(run_id, run_dir, batch_size=1)[0]
        self.app.start(run_dir, claim)

        res = self.app.report_host_failure(
            run_dir, claim, HostFailureError("transient host error", retryable=True), max_retries=2
        )
        self.assertEqual(res["action"], "requeued")

        # Next dispatch creates a new attempt with incremented generation
        claim2 = self.app.next(run_id, run_dir, batch_size=1)[0]
        self.assertEqual(claim2["generation"], 2)
        self.assertEqual(claim2["task_id"], claim["task_id"])

        # A non-retryable failure quarantines immediately
        res2 = self.app.report_host_failure(
            run_dir, claim2, HostFailureError("permanent host error", retryable=False), max_retries=2
        )
        self.assertEqual(res2["action"], "quarantined")

    def test_finalize_after_retries_then_success_is_complete(self):
        prep, config = self._prepared_run()
        run_id, run_dir = prep["run_id"], Path(config["run_dir"])

        claim = self.app.next(run_id, run_dir, batch_size=1)[0]
        self.app.report_host_failure(
            run_dir, claim, HostFailureError("transient", retryable=True), max_retries=2
        )
        claim2 = self.app.next(run_id, run_dir, batch_size=1)[0]
        self.assertEqual(claim2["task_id"], claim["task_id"])
        self.app.start(run_dir, claim2)
        self.app.submit(run_dir, claim2, self._recon_result(claim2), "digest-retry-ok")

        # Drain the remaining plan scope so finalize can reach 'complete'.
        self._drain_all()

        finding = Verifier().create_finding_from_candidate(
            self._hunt_result(claim2, prep["snapshot_id"])["records"][0],
            "confirmed", "t-verify-2",
            impact=2, exploitability=3,
            impact_why="x", exploitability_why="y",
        )
        fin = self.app.finalize(run_id, run_dir, findings=[finding])
        self.assertEqual(fin["final_state"], "complete")
        self.assertNotIn("unprocessed_units", fin["incomplete_reasons"])


if __name__ == "__main__":
    unittest.main()
