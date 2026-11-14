"""Cross-domain integration tests for the first-wave wiring (ANA/LED/SNP/INT/HST).

Covers the inter-module wiring that individual domain suites cannot see:
- ANA -> LED: hunt candidates produce verify tasks (Verifier.build_verify_task,
  enforce_attempt_gate=True); verify submissions are stamped with the current
  run_id and merged into finalize; verify completion is accounted.
- ANA -> LED: connector evaluations run a full reserve -> settle budget
  lifecycle; unresolved/incompatible/capped records become events.
- HST -> LED: adapter last_usage is converted into a trusted usage object
  (exact / estimated / unavailable + reason) and settles into the budget
  ledger; no submission is left without a usage object.
- SNP/INT -> service: T3/T4 units get no hunt tasks (disposition marker events
  instead); triage records and snapshot gaps are persisted as events and are
  surfaced through finalize coverage accounting.
- HST -> service: the AIMD dispatch loop adjusts concurrency and reports
  TerminationUncertainError as a retained budget (incomplete reason).
"""

import json
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path

from auditkit.analysis.verifier import Verifier
from auditkit.app.service import AuditAppService
from auditkit.contracts.errors import InvalidInputError
from auditkit.hosts.concurrency import ConcurrencyController
from auditkit.hosts.errors import TerminationUncertainError
from auditkit.ledger.db import get_db_connection
from auditkit.ledger.event_store import EventStore

FIXTURES_DIR = Path("/root/polyglot-audit/tests/fixtures")
SKILL_DIR = Path("/root/polyglot-audit/skill")


class _FakeAdapter:
    """Minimal stand-in for a host driver adapter (last_usage interface)."""

    def __init__(self, last_usage=None, max_retries=2, backoff_base=0.01, backoff_max=0.05):
        self.last_usage = last_usage
        self.max_retries = max_retries
        self.backoff_base = backoff_base
        self.backoff_max = backoff_max


class TestIntegrationWiring(unittest.TestCase):

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())
        self.app = AuditAppService(SKILL_DIR)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------
    def _make_config(self, target, budgets=None, profile="standard"):
        run_dir = self.temp_dir / f"run_{abs(hash(str(target))) % 10**8}"
        return {
            "schema_version": "1.0",
            "target": str(target),
            "run_dir": str(run_dir),
            "report_language": "zh",
            "profile": profile,
            "scope": {"include": ["*"], "exclude": []},
            "budgets": budgets
            or [
                {
                    "schema_version": "1.0",
                    "dimension": "tasks",
                    "mode": "enforced",
                    "limit": 20,
                    "settled": 0,
                    "reserved": 0,
                    "unit": "tasks",
                    "availability": "exact",
                }
            ],
            "safety_acceptance": {
                "allow_unverified_execution": False,
                "allow_unverified_network": False,
                "allow_unverified_write": False,
                "user_approved": True,
            },
        }

    def _prepared(self, config):
        prep = self.app.prepare(config["target"], config["run_dir"], config)
        self.app.activate(prep["run_id"], config["run_dir"])
        return prep

    def _hunt_result(self, claim, snapshot_id, records, overflow=None):
        return {
            "schema_version": "1.0",
            "task_id": claim["task_id"],
            "attempt_id": claim["attempt_id"],
            "kind": "hunt",
            "coverage": [],
            "records": records,
            "overflow": overflow or [],
        }

    def _candidate_record(self, claim):
        return {
            "schema_version": "1.0",
            "candidate_id": "cand-wired-01",
            "issue": "py-01",
            "source": {
                "path": "app/handlers/upload.py",
                "line": 8,
                "symbol": "handle_upload",
                "kind": "http_body",
                "control": "request_data['body']",
            },
            "sink": {
                "path": "app/storage/state.py",
                "line": 10,
                "symbol": "restore_state",
                "kind": "deserialization",
                "effect": "arbitrary object instantiation",
            },
            "steps": [
                {"path": "app/handlers/upload.py", "line": 8, "role": "source", "note": "n1"},
                {"path": "app/storage/state.py", "line": 10, "role": "sink", "note": "n2"},
            ],
            "guard_analysis": "none",
            "impact_claim": "RCE",
            "open_questions": [],
            "provenance": {"hunt_tasks": [claim["task_id"]]},
        }

    def _events(self, run_dir, event_type):
        conn = get_db_connection(Path(run_dir) / "events.db")
        try:
            rows = conn.execute(
                "SELECT revision, payload_json FROM events WHERE event_type = ? ORDER BY revision",
                (event_type,),
            ).fetchall()
            return [json.loads(r["payload_json"]) for r in rows]
        finally:
            conn.close()

    def _task_rows(self, run_dir):
        conn = get_db_connection(Path(run_dir) / "events.db")
        try:
            return conn.execute(
                "SELECT task_id, kind, state, priority FROM tasks ORDER BY priority DESC, task_id"
            ).fetchall()
        finally:
            conn.close()

    def _budget(self, run_id, run_dir, dimension):
        status = self.app.status(run_id, run_dir)
        for b in status["budgets"]:
            if b["dimension"] == dimension:
                return b
        return None

    # ------------------------------------------------------------------
    # 1. hunt -> verify full chain, ending complete
    # ------------------------------------------------------------------
    def test_hunt_to_verify_full_chain_finalizes_complete(self):
        config = self._make_config(
            FIXTURES_DIR / "pyapp",
            budgets=[
                {
                    "schema_version": "1.0",
                    "dimension": "tasks",
                    "mode": "enforced",
                    "limit": 10,
                    "settled": 0,
                    "reserved": 0,
                    "unit": "tasks",
                    "availability": "exact",
                },
                {
                    "schema_version": "1.0",
                    "dimension": "tokens",
                    "mode": "enforced",
                    "limit": 5000,
                    "settled": 0,
                    "reserved": 0,
                    "unit": "tokens",
                    "availability": "exact",
                },
            ],
        )
        prep = self._prepared(config)
        run_id, run_dir = prep["run_id"], Path(config["run_dir"])

        # --- hunt: candidate produced and submitted with adapter usage ---
        hunt_claim = self.app.next(run_id, run_dir, batch_size=5)[0]
        self.app.start(run_dir, hunt_claim)
        candidate = self._candidate_record(hunt_claim)
        adapter = _FakeAdapter({"total_tokens": 500})
        usage = self.app.build_usage(adapter, hunt_claim["attempt_id"])
        self.assertEqual(usage["availability"], "estimated")
        self.assertEqual(usage["value"], 500)
        self.assertEqual(usage["source"], "_FakeAdapter")
        self.app.submit(
            run_dir,
            hunt_claim,
            self._hunt_result(hunt_claim, prep["snapshot_id"], [candidate]),
            "digest-hunt-01",
            usage=usage,
        )

        # --- verify task was enqueued by the hunt wiring (ANA -> LED) ---
        verify_tasks = [t for t in self._task_rows(run_dir) if t["kind"] == "verify"]
        self.assertEqual(len(verify_tasks), 1)
        self.assertGreater(verify_tasks[0]["priority"], 20)  # dispatches before any hunt

        verify_claim = self.app.next(run_id, run_dir, batch_size=5)[0]
        self.assertEqual(verify_claim["task_id"], verify_tasks[0]["task_id"])
        self.assertEqual(verify_claim["spec"]["role"], "verify")
        self.assertEqual(verify_claim["spec"]["candidate_id"], "cand-wired-01")
        self.assertTrue(verify_claim["spec"]["requires_new_attempt"])
        self.app.start(run_dir, verify_claim)

        # The E2 gate is real: a confirmed verdict without a fresh attempt id
        # is rejected by the wired Verifier.
        verifier = Verifier(enforce_attempt_gate=True)
        with self.assertRaises(InvalidInputError):
            verifier.create_finding_from_candidate(
                candidate, "confirmed", "vt-01",
                impact=4, exploitability=4,
                verify_attempt_id="", hunt_attempt_id=hunt_claim["attempt_id"],
            )

        finding = verifier.create_finding_from_candidate(
            candidate, "confirmed", "vt-01",
            impact=4, exploitability=4,
            impact_why="RCE via pickle.loads",
            exploitability_why="unauthenticated request body",
            verify_attempt_id=verify_claim["attempt_id"],
            hunt_attempt_id=hunt_claim["attempt_id"],
        )
        verify_usage = self.app.build_usage(
            _FakeAdapter({"total_tokens": 300, "availability": "exact"}),
            verify_claim["attempt_id"],
        )
        self.assertEqual(verify_usage["availability"], "exact")
        self.app.submit(
            run_dir,
            verify_claim,
            self._hunt_result(verify_claim, prep["snapshot_id"],
                              [{"schema_version": "1.0", "verdict": "confirmed", "finding": finding}]),
            "digest-verify-01",
            usage=verify_usage,
        )

        # The stored finding carries the service-stamped run_id (item 6).
        stored_files = sorted(run_dir.glob("findings/verified-*.json"))
        self.assertEqual(len(stored_files), 1)
        stored = json.loads(stored_files[0].read_text(encoding="utf-8"))
        self.assertEqual(stored[0]["run_id"], run_id)
        self.assertEqual(stored[0]["finding_id"], finding["finding_id"])

        # --- finalize: stored findings merged, verify completion accounted ---
        fin = self.app.finalize(run_id, run_dir, findings=[])
        self.assertEqual(fin["final_state"], "complete")
        self.assertEqual(fin["verify"], {"enqueued": 1, "done": 1, "complete": True})
        self.assertEqual(set(fin["gates"].values()), {"pass"})
        # Usage settled across both attempts into the tokens dimension.
        tokens = self._budget(run_id, run_dir, "tokens")
        self.assertEqual(tokens["settled"], 800)
        self.assertEqual(tokens["availability"], "exact")
        tasks_budget = self._budget(run_id, run_dir, "tasks")
        self.assertEqual(tasks_budget["settled"], 2)

    # ------------------------------------------------------------------
    # 2. usage settlement: unavailable usage is recorded with a reason and
    #    keeps the reservation consumed
    # ------------------------------------------------------------------
    def test_usage_unavailable_keeps_reservation_consumed(self):
        config = self._make_config(FIXTURES_DIR / "pyapp")
        prep = self._prepared(config)
        run_id, run_dir = prep["run_id"], Path(config["run_dir"])

        claim = self.app.next(run_id, run_dir, batch_size=5)[0]
        self.app.start(run_dir, claim)
        adapter = _FakeAdapter(None)
        usage = self.app.build_usage(adapter, claim["attempt_id"], dimension="tasks", unit="tasks")
        self.assertEqual(usage["availability"], "unavailable")
        self.assertTrue(usage["reason"])
        self.assertNotIn("value", usage)
        self.app.submit(
            run_dir, claim,
            self._hunt_result(claim, prep["snapshot_id"], []),
            "digest-no-usage",
            usage=usage,
        )

        tasks_budget = self._budget(run_id, run_dir, "tasks")
        self.assertEqual(tasks_budget["availability"], "unavailable")
        self.assertEqual(tasks_budget["source"], "_FakeAdapter")
        # Unknown usage keeps the reserved amount settled, never freed.
        self.assertEqual(tasks_budget["settled"], 1)
        self.assertEqual(tasks_budget["reserved"], 0)

    # ------------------------------------------------------------------
    # 3. connector budget lifecycle (reserve -> settle) and unresolved events
    # ------------------------------------------------------------------
    def test_connector_budget_settled_and_unresolved_persisted(self):
        config = self._make_config(
            FIXTURES_DIR / "boundary",
            budgets=[
                {
                    "schema_version": "1.0",
                    "dimension": "tasks",
                    "mode": "enforced",
                    "limit": 10,
                    "settled": 0,
                    "reserved": 0,
                    "unit": "tasks",
                    "availability": "exact",
                },
                {
                    "schema_version": "1.0",
                    "dimension": "connector_evaluations",
                    "mode": "enforced",
                    "limit": 10,
                    "settled": 0,
                    "reserved": 0,
                    "unit": "evaluations",
                    "availability": "exact",
                },
            ],
        )
        prep = self._prepared(config)
        run_id, run_dir = prep["run_id"], Path(config["run_dir"])

        claim = self.app.next(run_id, run_dir, batch_size=5)[0]
        self.app.start(run_dir, claim)
        # Two frontiers, one probe: one pair matches, one frontier stays
        # unresolved, and 2 pairing evaluations are charged.
        records = [
            {
                "schema_version": "1.0",
                "frontier_id": "front-01",
                "source": {"path": "caller.py", "line": 8, "symbol": "dispatch_payload", "kind": "param"},
                "boundary": "libnative.so",
                "steps": [{"path": "caller.py", "line": 8, "role": "source", "note": "n"}],
                "open_questions": [],
                "provenance": {"hunt_tasks": [claim["task_id"]]},
            },
            {
                "schema_version": "1.0",
                "frontier_id": "front-02",
                "source": {"path": "caller.py", "line": 20, "symbol": "other_path", "kind": "param"},
                "boundary": "libother.so",
                "steps": [{"path": "caller.py", "line": 20, "role": "source", "note": "n"}],
                "open_questions": [],
                "provenance": {"hunt_tasks": [claim["task_id"]]},
            },
            {
                "schema_version": "1.0",
                "probe_id": "probe-01",
                "sink": {"path": "callee.c", "line": 10, "symbol": "system", "kind": "rce"},
                "boundary": "libnative.so",
                "steps": [{"path": "callee.c", "line": 10, "role": "sink", "note": "n"}],
                "guard_analysis": "unchecked buffer",
                "open_questions": [],
                "provenance": {"hunt_tasks": [claim["task_id"]]},
            },
        ]
        self.app.submit(
            run_dir, claim,
            self._hunt_result(claim, prep["snapshot_id"], records),
            "digest-connector",
        )

        # Budget lifecycle: reserved estimate settled down to the actual
        # evaluation count (ANA -> LED wiring).
        conn_budget = self._budget(run_id, run_dir, "connector_evaluations")
        self.assertEqual(conn_budget["settled"], 2)
        self.assertEqual(conn_budget["reserved"], 0)

        # Connector records are persisted as events, not silently dropped.
        unresolved = self._events(run_dir, "connector_unresolved")
        self.assertTrue(any(r.get("frontier_id") == "front-02" for r in unresolved))

        # The synthesized cross-boundary candidate got a verify task.
        verify_tasks = [t for t in self._task_rows(run_dir) if t["kind"] == "verify"]
        self.assertEqual(len(verify_tasks), 1)

        fin = self.app.finalize(run_id, run_dir, findings=[])
        self.assertEqual(fin["final_state"], "complete")
        self.assertTrue(fin["verify"]["enqueued"] >= 1)

    # ------------------------------------------------------------------
    # 4. T3/T4 units produce no hunt tasks (disposition markers instead)
    # ------------------------------------------------------------------
    def test_t3_t4_units_produce_no_hunt_tasks(self):
        target = self.temp_dir / "mixed_target"
        (target / "src").mkdir(parents=True)
        (target / "src" / "hot.py").write_text(
            "import os\nvalue = os.environ['X']\nexec(value)\n", encoding="utf-8"
        )
        (target / "src" / "guards.py").write_text(
            "@login_required\ndef guarded():\n    return True\n", encoding="utf-8"
        )
        (target / "src" / "clean.py").write_text("x = 1\n", encoding="utf-8")

        config = self._make_config(target, profile="deep")
        prep = self._prepared(config)
        run_id, run_dir = prep["run_id"], Path(config["run_dir"])

        plan = json.loads((run_dir / "plan.json").read_text(encoding="utf-8"))
        dispositions = plan["dispositions"]
        self.assertGreaterEqual(dispositions.get("triage_only", 0), 1)
        self.assertGreaterEqual(dispositions.get("inventory_only", 0), 1)
        self.assertEqual(plan["hunt_units"], dispositions.get("analyze", 0))

        # Only analyze-disposition units have tasks; all tasks are hunt tasks.
        tasks = self._task_rows(run_dir)
        self.assertTrue(tasks)
        self.assertEqual({t["kind"] for t in tasks}, {"hunt"})
        self.assertEqual(len(tasks), plan["hunt_units"])

        conn = get_db_connection(run_dir / "events.db")
        try:
            specs = [json.loads(r["spec_json"]) for r in conn.execute("SELECT spec_json FROM tasks")]
        finally:
            conn.close()
        analyze_unit_ids = {
            u["unit_id"] for u in plan["units"] if u["disposition"] == "analyze"
        }
        self.assertEqual({s["unit"]["unit_id"] for s in specs}, analyze_unit_ids)

        # T3/T4 markers are explicit events (never silently dropped).
        markers = self._events(run_dir, "unit_disposition")
        marked = {m["disposition"] for m in markers}
        self.assertIn("triage_only", marked)
        self.assertIn("inventory_only", marked)
        non_analyze_ids = {
            u["unit_id"] for u in plan["units"] if u["disposition"] != "analyze"
        }
        self.assertEqual({m["unit_id"] for m in markers}, non_analyze_ids)

    # ------------------------------------------------------------------
    # 5. triage records and hunter overflow persisted as events
    # ------------------------------------------------------------------
    def test_triage_records_and_overflow_persisted_as_events(self):
        config = self._make_config(FIXTURES_DIR / "pyapp")
        prep = self._prepared(config)
        run_id, run_dir = prep["run_id"], Path(config["run_dir"])

        triage_events = self._events(run_dir, "triage_recorded")
        self.assertEqual(len(triage_events), 1)
        payload = triage_events[0]
        self.assertTrue(payload["records"])
        for rec in payload["records"]:
            self.assertIn(rec["disposition"], ("candidate_created", "dismissed", "pending"))
        self.assertEqual(payload["stats"]["total_hits"], len(payload["records"]))

        # Hunter-reported overflow becomes an explicit event with the
        # standardized payload shape (dimension / estimated_count / reason).
        claim = self.app.next(run_id, run_dir, batch_size=5)[0]
        self.app.start(run_dir, claim)
        overflow = [{
            "dimension": "candidate",
            "estimated_count": 3,
            "reason": "Candidate cap reached in worker",
        }]
        self.app.submit(
            run_dir, claim,
            self._hunt_result(claim, prep["snapshot_id"], [], overflow=overflow),
            "digest-overflow",
        )
        overflow_events = self._events(run_dir, "hunter_overflow")
        self.assertTrue(overflow_events)
        self.assertEqual(overflow_events[-1]["dimension"], "candidate")
        self.assertEqual(overflow_events[-1]["estimated_count"], 3)

        # Both triage records and overflow are surfaced by finalize accounting.
        fin = self.app.finalize(run_id, run_dir, findings=[])
        gap_dimensions = {g.get("dimension") for g in fin["coverage_gaps"]}
        self.assertIn("candidate", gap_dimensions)

    # ------------------------------------------------------------------
    # 6. AIMD dispatch loop wiring + TerminationUncertainError budget retention
    # ------------------------------------------------------------------
    def test_dispatch_loop_aims_concurrency_and_settles_usage(self):
        config = self._make_config(
            FIXTURES_DIR / "pyapp",
            budgets=[
                {
                    "schema_version": "1.0",
                    "dimension": "tasks",
                    "mode": "enforced",
                    "limit": 10,
                    "settled": 0,
                    "reserved": 0,
                    "unit": "tasks",
                    "availability": "exact",
                },
                {
                    "schema_version": "1.0",
                    "dimension": "tokens",
                    "mode": "enforced",
                    "limit": 5000,
                    "settled": 0,
                    "reserved": 0,
                    "unit": "tokens",
                    "availability": "exact",
                },
            ],
        )
        prep = self._prepared(config)
        run_id, run_dir = prep["run_id"], Path(config["run_dir"])
        snapshot_id = prep["snapshot_id"]

        controller = ConcurrencyController(initial=1, maximum=4)
        adapter = _FakeAdapter({"total_tokens": 120, "availability": "exact"})

        def execute_fn(claim):
            return self._hunt_result(claim, snapshot_id, [])

        summary = self.app.run_dispatch_loop(
            run_id, run_dir, execute_fn, adapter=adapter, controller=controller,
            usage_dimension="tokens",
        )
        self.assertEqual(summary["submitted"], 1)
        self.assertEqual(summary["failed"], 0)
        self.assertEqual(summary["concurrency"], 2)  # AIMD additive increase

        tokens = self._budget(run_id, run_dir, "tokens")
        self.assertEqual(tokens["availability"], "exact")
        self.assertEqual(tokens["settled"], 120)

        fin = self.app.finalize(run_id, run_dir, findings=[])
        self.assertEqual(fin["final_state"], "complete")

    def test_termination_uncertain_retains_budget_and_forces_incomplete(self):
        config = self._make_config(FIXTURES_DIR / "boundary")
        prep = self._prepared(config)
        run_id, run_dir = prep["run_id"], Path(config["run_dir"])

        claim = self.app.next(run_id, run_dir, batch_size=1)[0]
        self.app.start(run_dir, claim)
        result = self.app.report_host_failure(
            run_dir, claim, TerminationUncertainError("killpg outcome unconfirmed")
        )
        self.assertEqual(result["action"], "retained")
        self.assertTrue(result["budget_retained"])

        # The reservation is NOT released (DSR-064).
        tasks_budget = self._budget(run_id, run_dir, "tasks")
        self.assertEqual(tasks_budget["reserved"], 1)

        # The retained task is not dispatched again; only the other (still
        # queued) hunt task of this run is granted.
        retained_task_id = result["task_id"]
        next_claims = self.app.next(run_id, run_dir, batch_size=5)
        self.assertNotIn(retained_task_id, {c["task_id"] for c in next_claims})
        self.assertEqual(self.app.next(run_id, run_dir, batch_size=5), [])

        fin = self.app.finalize(run_id, run_dir, findings=[])
        self.assertEqual(fin["final_state"], "incomplete")
        self.assertIn("termination_uncertain_budget_retained", fin["incomplete_reasons"])
        self.assertTrue(fin["budget_retained"])


if __name__ == "__main__":
    unittest.main()
