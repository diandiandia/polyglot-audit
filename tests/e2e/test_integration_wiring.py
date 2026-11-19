"""Cross-domain integration tests for the first-wave wiring (ANA/LED/SNP/INT/HST).

Covers the inter-module wiring that individual domain suites cannot see:
- ANA -> LED: hunt candidates produce verify tasks (Verifier.build_verify_task,
  enforce_attempt_gate=True); verify submissions are stamped with the current
  run_id and merged into finalize; verify completion is accounted.
- ANA -> LED: connector evaluations run a full reserve -> settle budget
  lifecycle; unresolved/incompatible/capped records become events.
- HST -> LED: the worker execution's per-attempt usage dict (the
  execute_worker envelope) is converted into a trusted usage object
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
    """Minimal stand-in for a host driver adapter (dispatch attributes only).

    Carries no usage state: under the per-task usage envelope the usage
    travels with each execution's return value, never on the adapter.
    """

    def __init__(self, max_retries=2, backoff_base=0.01, backoff_max=0.05):
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

    @staticmethod
    def _is_recon(claim):
        return (claim.get("spec") or {}).get("task_kind") == "recon"

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

    def _recon_result(self, claim, guards):
        return {
            "schema_version": "1.0",
            "task_id": claim["task_id"],
            "attempt_id": claim["attempt_id"],
            "kind": "recon",
            "coverage": [],
            "records": guards,
            "overflow": [],
        }

    def _recon_guard(self, guard_id="guard-mw", status="observed"):
        return {
            "schema_version": "1.0",
            "guard_id": guard_id,
            "status": status,
            "mechanism": "Framework middleware validates input bodies",
            "anchors": [{"path": "app/middleware.py", "line": 8}],
            "applicability": "app/handlers/",
            "exceptions": [],
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

        # --- recon first (DDS-05 S1): guard baseline reported by the worker ---
        all_claims = self.app.next(run_id, run_dir, batch_size=10)
        recon_claim = next(c for c in all_claims if self._is_recon(c))
        self.assertEqual(recon_claim["spec"]["task_kind"], "recon")
        self.assertTrue(recon_claim["spec"]["knowledge_hints"]["primary_language"])
        self.app.start(run_dir, recon_claim)
        self.app.submit(
            run_dir, recon_claim, self._recon_result(recon_claim, [self._recon_guard()]), "digest-recon-01",
        )

        # --- hunt: candidate produced and submitted with worker usage ---
        hunt_claim = next(c for c in all_claims if not self._is_recon(c))
        self.app.start(run_dir, hunt_claim)
        candidate = self._candidate_record(hunt_claim)
        usage = self.app.build_usage(
            {
                "schema_version": "1.0",
                "attempt_id": hunt_claim["attempt_id"],
                "dimension": "tokens",
                "availability": "estimated",
                "value": 500,
                "unit": "tokens",
                "source": "host_cli_report",
            },
            hunt_claim["attempt_id"],
        )
        self.assertEqual(usage["availability"], "estimated")
        self.assertEqual(usage["value"], 500)
        self.assertEqual(usage["source"], "host_cli_report")
        self.assertEqual(usage["attempt_id"], hunt_claim["attempt_id"])
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
            {
                "schema_version": "1.0",
                "attempt_id": verify_claim["attempt_id"],
                "dimension": "tokens",
                "availability": "exact",
                "value": 300,
                "unit": "tokens",
                "source": "host_cli_report",
            },
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

        # The confirmed Critical finding requires an independent second
        # opinion (DSR-061); its task dispatches above normal verify priority.
        so_rows = self._events(run_dir, "second_opinion_enqueued")
        self.assertEqual(len(so_rows), 1)
        second_opinion_claims = self.app.next(run_id, run_dir, batch_size=5)
        self.assertEqual(len(second_opinion_claims), 1)
        so_claim = second_opinion_claims[0]
        self.assertTrue(so_claim["spec"]["second_opinion"])
        self.assertEqual(so_claim["spec"]["target_finding_id"], finding["finding_id"])
        self.app.start(run_dir, so_claim)
        self.app.submit(
            run_dir,
            so_claim,
            self._hunt_result(so_claim, prep["snapshot_id"],
                              [{"schema_version": "1.0", "verdict": "confirmed",
                                "reason": "independent re-derivation reached the same trace"}]),
            "digest-second-opinion-01",
        )
        adjudicated_events = self._events(run_dir, "second_opinion_adjudicated")
        self.assertEqual(len(adjudicated_events), 1)
        self.assertEqual(adjudicated_events[0]["resolution"], "corroborated")

        # Submit any remaining hunt claims of the plan: SR-012/026 terminal
        # semantics require the full plan scope to be processed before
        # finalize (the pyapp fixture may plan a single hunt unit).
        for remaining in (
            c for c in all_claims
            if not self._is_recon(c) and c["task_id"] != hunt_claim["task_id"]
        ):
            self.app.start(run_dir, remaining)
            self.app.submit(
                run_dir, remaining,
                self._hunt_result(remaining, prep["snapshot_id"], []),
                "digest-hunt-02",
            )

        # --- finalize: stored findings merged, verify completion accounted ---
        fin = self.app.finalize(run_id, run_dir, findings=[])
        self.assertEqual(fin["final_state"], "complete")
        self.assertNotIn("unprocessed_units", fin["incomplete_reasons"])
        self.assertEqual(fin["verify"], {"enqueued": 2, "done": 2, "complete": True})
        self.assertEqual(fin["second_opinion_pending"], [])
        self.assertEqual(set(fin["gates"].values()), {"pass"})
        # Usage settled across all three submitted attempts into the tokens
        # dimension; the second hunt unit settled the tasks dimension without
        # a tokens usage record (unavailable usage, reservation consumed).
        tokens = self._budget(run_id, run_dir, "tokens")
        self.assertEqual(tokens["settled"], 800)
        self.assertEqual(tokens["availability"], "exact")
        tasks_budget = self._budget(run_id, run_dir, "tasks")
        # One settled task per claim: recon + hunts + verify + second opinion.
        self.assertEqual(tasks_budget["settled"], len(all_claims) + 2)

    # ------------------------------------------------------------------
    # 1b. verify worker semantics: the spec anchors the frozen snapshot and
    #     mandates rating factor reasons; semantic-input-only ratings survive
    #     the store; missing factor reasons demote with the E1 linkage.
    # ------------------------------------------------------------------
    def _drive_to_pending_verify(self, config):
        """Prepare a run and submit recon+hunt, leaving one candidate whose
        verify task is enqueued. Returns (prep, run_id, run_dir, claims,
        hunt_claim, candidate)."""
        prep = self._prepared(config)
        run_id, run_dir = prep["run_id"], Path(config["run_dir"])
        all_claims = self.app.next(run_id, run_dir, batch_size=10)
        recon_claim = next(c for c in all_claims if self._is_recon(c))
        self.app.start(run_dir, recon_claim)
        self.app.submit(
            run_dir, recon_claim, self._recon_result(recon_claim, [self._recon_guard()]),
            "digest-recon-r1",
        )
        hunt_claim = next(c for c in all_claims if not self._is_recon(c))
        self.app.start(run_dir, hunt_claim)
        candidate = self._candidate_record(hunt_claim)
        self.app.submit(
            run_dir, hunt_claim,
            self._hunt_result(hunt_claim, prep["snapshot_id"], [candidate]),
            "digest-hunt-r1",
        )
        return prep, run_id, run_dir, all_claims, hunt_claim, candidate

    def test_verify_spec_carries_snapshot_and_rating_contract(self):
        config = self._make_config(FIXTURES_DIR / "pyapp")
        prep, run_id, run_dir, _claims, _hunt, _cand = self._drive_to_pending_verify(config)
        verify_claim = self.app.next(run_id, run_dir, batch_size=5)[0]
        spec = verify_claim["spec"]
        # Snapshot anchor: the verify packet renders against the frozen
        # snapshot the hunt ran against -- never an empty header (the worker
        # would otherwise verify against nothing).
        self.assertEqual(spec.get("snapshot_id"), prep["snapshot_id"])
        # The output contract mandates the rating factor reasons for a
        # confirmed verdict, so a well-formed submission cannot be demoted
        # for fields it was never told to provide.
        self.assertIn("factor_reasons", spec["output_contract"])
        self.assertIn("impact_why", spec["output_contract"])
        self.assertIn("exploitability_why", spec["output_contract"])

    def test_verify_raw_record_semantic_rating_stays_confirmed(self):
        """A raw worker record supplies semantic inputs only (impact,
        exploitability, factor reasons) and no evidence_level: the program
        derives the severity fields (single authority: RatingEngine) and
        stamps the claim-strength evidence level, so the confirmed verdict
        survives the store without dying on bookkeeping fields the worker
        was never asked to compute."""
        config = self._make_config(FIXTURES_DIR / "pyapp")
        prep, run_id, run_dir, _claims, hunt_claim, candidate = (
            self._drive_to_pending_verify(config)
        )
        verify_claim = self.app.next(run_id, run_dir, batch_size=5)[0]
        self.app.start(run_dir, verify_claim)
        record = {
            "schema_version": "1.0",
            "verdict": "confirmed",
            "finding_id": "F-VERIFY-t1-0",
            "title": "Untrusted data reaches object restoration",
            "issue": "py-01",
            "languages": ["python"],
            "source": candidate["source"],
            "sink": candidate["sink"],
            "steps": candidate["steps"],
            "remediation": {"summary": "constrain types before restore"},
            "rating": {
                "impact": 4,
                "exploitability": 3,
                "factor_reasons": {
                    "impact_why": "restored object executes attacker-chosen code",
                    "exploitability_why": "endpoint accepts unauthenticated bodies",
                },
            },
            "provenance": {
                "candidates": ["cand-wired-01"],
                "hunt_tasks": [hunt_claim["task_id"]],
                "verify_tasks": [verify_claim["task_id"]],
                "verify_attempt_id": verify_claim["attempt_id"],
                "hunt_attempt_id": hunt_claim["attempt_id"],
            },
        }
        self.app.submit(
            run_dir, verify_claim,
            self._hunt_result(verify_claim, prep["snapshot_id"], [record]),
            "digest-verify-r1",
        )
        stored_files = sorted(run_dir.glob("findings/verified-*.json"))
        self.assertEqual(len(stored_files), 1)
        stored = json.loads(stored_files[0].read_text(encoding="utf-8"))[0]
        self.assertEqual(stored["verdict"], "confirmed")
        self.assertEqual(stored["evidence_level"], "E2")
        self.assertEqual(stored["rating"]["calculated_severity"], "High")
        self.assertEqual(
            stored["rating"]["final_severity"], stored["rating"]["calculated_severity"]
        )
        self.assertTrue(stored["rating"]["final_urgency"])
        self.assertEqual(
            stored["rating"]["factor_reasons"]["impact_why"],
            "restored object executes attacker-chosen code",
        )

    def test_verify_raw_record_missing_reasons_demotes_with_e1(self):
        """A confirmed claim whose rating lacks factor reasons is demoted on
        the store path with the linkage recorded: needs_validation, E1,
        demoted_from, and the concrete per-factor blockers."""
        config = self._make_config(FIXTURES_DIR / "pyapp")
        prep, run_id, run_dir, _claims, hunt_claim, candidate = (
            self._drive_to_pending_verify(config)
        )
        verify_claim = self.app.next(run_id, run_dir, batch_size=5)[0]
        self.app.start(run_dir, verify_claim)
        record = {
            "schema_version": "1.0",
            "verdict": "confirmed",
            "finding_id": "F-VERIFY-t2-0",
            "title": "Untrusted data reaches object restoration",
            "issue": "py-01",
            "languages": ["python"],
            "source": candidate["source"],
            "sink": candidate["sink"],
            "steps": candidate["steps"],
            "remediation": {"summary": "constrain types before restore"},
            "rating": {"impact": 4, "exploitability": 3},
            "provenance": {
                "candidates": ["cand-wired-01"],
                "hunt_tasks": [hunt_claim["task_id"]],
                "verify_tasks": [verify_claim["task_id"]],
                "verify_attempt_id": verify_claim["attempt_id"],
                "hunt_attempt_id": hunt_claim["attempt_id"],
            },
        }
        self.app.submit(
            run_dir, verify_claim,
            self._hunt_result(verify_claim, prep["snapshot_id"], [record]),
            "digest-verify-r2",
        )
        stored_files = sorted(run_dir.glob("findings/verified-*.json"))
        self.assertEqual(len(stored_files), 1)
        stored = json.loads(stored_files[0].read_text(encoding="utf-8"))[0]
        self.assertEqual(stored["verdict"], "needs_validation")
        self.assertEqual(stored["evidence_level"], "E1")
        self.assertEqual(stored["demoted_from"], "confirmed")
        self.assertIn("missing rating factor reason: impact_why", stored["blockers"])
        self.assertIn(
            "missing rating factor reason: exploitability_why", stored["blockers"]
        )

    # ------------------------------------------------------------------
    # 2. usage settlement: unavailable usage is recorded with a reason and
    #    keeps the reservation consumed
    # ------------------------------------------------------------------
    def test_usage_unavailable_keeps_reservation_consumed(self):
        config = self._make_config(FIXTURES_DIR / "pyapp")
        prep = self._prepared(config)
        run_id, run_dir = prep["run_id"], Path(config["run_dir"])

        claims = self.app.next(run_id, run_dir, batch_size=5)
        self.assertTrue(claims)
        self.assertTrue(self._is_recon(claims[0]))
        for claim in claims:
            self.app.start(run_dir, claim)
            # No usage block: the worker envelope carries None, and the
            # legacy adapter-shaped call yields the explicit unavailable
            # record too (the shared last_usage slot is no longer read).
            usage = self.app.build_usage(None, claim["attempt_id"], dimension="tasks", unit="tasks")
            self.assertEqual(usage["availability"], "unavailable")
            self.assertTrue(usage["reason"])
            self.assertNotIn("value", usage)
            self.assertEqual(usage["attempt_id"], claim["attempt_id"])
            result = (
                self._recon_result(claim, []) if self._is_recon(claim)
                else self._hunt_result(claim, prep["snapshot_id"], [])
            )
            self.app.submit(run_dir, claim, result, "digest-no-usage", usage=usage)

        tasks_budget = self._budget(run_id, run_dir, "tasks")
        self.assertEqual(tasks_budget["availability"], "unavailable")
        self.assertEqual(tasks_budget["source"], "service")
        # Unknown usage keeps the reserved amount settled, never freed.
        self.assertEqual(tasks_budget["settled"], len(claims))
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

        all_claims = self.app.next(run_id, run_dir, batch_size=5)
        recon_claim = next(c for c in all_claims if self._is_recon(c))
        self.app.start(run_dir, recon_claim)
        self.app.submit(
            run_dir, recon_claim, self._recon_result(recon_claim, [self._recon_guard()]), "digest-recon-c",
        )

        claim = next(c for c in all_claims if not self._is_recon(c))
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

        # Submit the remaining plan scope: the other hunt claim already held
        # from all_claims, plus the verify fan-out granted below, so finalize
        # can reach the complete terminal state.
        for held in (c for c in all_claims if not self._is_recon(c) and c["task_id"] != claim["task_id"]):
            self.app.start(run_dir, held)
            self.app.submit(
                run_dir, held,
                self._hunt_result(held, prep["snapshot_id"], []),
                f"digest-held-{held['attempt_id']}",
            )
        while True:
            open_claims = self.app.next(run_id, run_dir, batch_size=10)
            if not open_claims:
                break
            for open_claim in open_claims:
                self.app.start(run_dir, open_claim)
                task_kind = (open_claim.get("spec") or {}).get("task_kind") or "verify"
                self.app.submit(
                    run_dir, open_claim,
                    {
                        "schema_version": "1.0",
                        "task_id": open_claim["task_id"],
                        "attempt_id": open_claim["attempt_id"],
                        "kind": task_kind,
                        "coverage": [],
                        "records": [],
                        "overflow": [],
                    },
                    f"digest-drain-{open_claim['attempt_id']}",
                )

        fin = self.app.finalize(run_id, run_dir, findings=[])
        self.assertEqual(fin["final_state"], "complete")
        self.assertNotIn("unprocessed_units", fin["incomplete_reasons"])
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

        plan = json.loads((run_dir / "plan" / "plan.json").read_text(encoding="utf-8"))
        dispositions = plan["dispositions"]
        self.assertGreaterEqual(dispositions.get("triage_only", 0), 1)
        self.assertGreaterEqual(dispositions.get("inventory_only", 0), 1)
        self.assertEqual(plan["hunt_units"], dispositions.get("analyze", 0))

        # Only analyze-disposition units have hunt tasks; the single recon task
        # (DDS-05 S1) is the one non-hunt task in the plan.
        tasks = self._task_rows(run_dir)
        self.assertTrue(tasks)
        self.assertEqual({t["kind"] for t in tasks}, {"hunt", "recon"})
        self.assertEqual(
            len([t for t in tasks if t["kind"] == "hunt"]), plan["hunt_units"]
        )
        self.assertEqual(len([t for t in tasks if t["kind"] == "recon"]), 1)

        conn = get_db_connection(run_dir / "events.db")
        try:
            specs = [json.loads(r["spec_json"]) for r in conn.execute("SELECT spec_json FROM tasks")]
        finally:
            conn.close()
        analyze_unit_ids = {
            u["unit_id"] for u in plan["units"] if u["disposition"] == "analyze"
        }
        hunt_specs = [s for s in specs if s.get("task_kind") != "recon"]
        self.assertEqual({s["unit"]["unit_id"] for s in hunt_specs}, analyze_unit_ids)

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
        all_claims = self.app.next(run_id, run_dir, batch_size=5)
        recon_claim = next(c for c in all_claims if self._is_recon(c))
        self.app.start(run_dir, recon_claim)
        self.app.submit(
            run_dir, recon_claim, self._recon_result(recon_claim, [self._recon_guard()]), "digest-recon-t",
        )
        claim = next(c for c in all_claims if not self._is_recon(c))
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

        # Submit the remaining plan scope so finalize is allowed to run.
        while True:
            open_claims = self.app.next(run_id, run_dir, batch_size=10)
            if not open_claims:
                break
            for open_claim in open_claims:
                self.app.start(run_dir, open_claim)
                task_kind = (open_claim.get("spec") or {}).get("task_kind") or "verify"
                self.app.submit(
                    run_dir, open_claim,
                    {
                        "schema_version": "1.0",
                        "task_id": open_claim["task_id"],
                        "attempt_id": open_claim["attempt_id"],
                        "kind": task_kind,
                        "coverage": [],
                        "records": [],
                        "overflow": [],
                    },
                    f"digest-drain-{open_claim['attempt_id']}",
                )

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
        adapter = _FakeAdapter()

        recon_results = {"used": False}

        def execute_fn(claim):
            # The dispatch loop must answer recon claims with recon results and
            # hunt claims with hunt results (both flow through the same service);
            # each submission carries its own per-attempt usage envelope.
            if self._is_recon(claim) and not recon_results["used"]:
                recon_results["used"] = True
                return self._recon_result(claim, [self._recon_guard()]), {
                    "schema_version": "1.0",
                    "attempt_id": claim["attempt_id"],
                    "dimension": "tokens",
                    "availability": "exact",
                    "value": 120,
                    "unit": "tokens",
                    "source": "host_cli_report",
                }
            return self._hunt_result(claim, snapshot_id, []), {
                "schema_version": "1.0",
                "attempt_id": claim["attempt_id"],
                "dimension": "tokens",
                "availability": "exact",
                "value": 120,
                "unit": "tokens",
                "source": "host_cli_report",
            }

        summary = self.app.run_dispatch_loop(
            run_id, run_dir, execute_fn, adapter=adapter, controller=controller,
            usage_dimension="tokens",
        )
        self.assertGreaterEqual(summary["submitted"], 1)
        self.assertEqual(summary["failed"], 0)
        self.assertEqual(
            summary["concurrency"], min(1 + summary["submitted"], 4)
        )  # AIMD additive increase per submitted batch

        tokens = self._budget(run_id, run_dir, "tokens")
        self.assertEqual(tokens["availability"], "exact")
        self.assertEqual(tokens["settled"], 120 * summary["submitted"])

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

        # Submit the granted hunt claims so only the retained quarantine work
        # keeps the run from completing (SR-012/026 in-flight gate).
        for c in next_claims:
            self.app.start(run_dir, c)
            self.app.submit(
                run_dir, c,
                self._hunt_result(c, prep["snapshot_id"], []),
                f"digest-drain-{c['attempt_id']}",
            )

        fin = self.app.finalize(run_id, run_dir, findings=[])
        self.assertEqual(fin["final_state"], "incomplete")
        self.assertIn("termination_uncertain_budget_retained", fin["incomplete_reasons"])
        self.assertIn("unprocessed_units", fin["incomplete_reasons"])
        self.assertTrue(fin["budget_retained"])


class TestTaskSpecEnqueueGate(unittest.TestCase):
    """DSR-073: invalid task specs are rejected at the enqueue points."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())
        self.app = AuditAppService(SKILL_DIR)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_validated_task_spec_rejects_invalid_shapes(self):
        for bad in (
            {},
            {"schema_version": "1.0"},
            # The retired speculative shape (never produced by the service).
            {
                "schema_version": "1.0", "kind": "hunt", "unit_ids": ["u-1"],
                "packet_digest": "a" * 64, "priority": 10,
                "limits": {"max_candidates": 5, "timeout_seconds": 120},
            },
            # A hunt spec missing its unit cannot be served with a packet.
            {"schema_version": "1.0", "task_kind": "hunt", "snapshot_id": "snp"},
        ):
            with self.subTest(spec=bad):
                with self.assertRaises(InvalidInputError):
                    self.app._validated_task_spec(bad)

    def test_verify_fan_out_rejects_invalid_spec_with_event(self):
        from unittest import mock

        from auditkit.analysis.verifier import Verifier
        from auditkit.ledger.db import init_database

        run_dir = self.temp_dir / "run"
        run_dir.mkdir()
        init_database(run_dir / "events.db")
        conn = get_db_connection(run_dir / "events.db")
        try:
            conn.execute(
                """
                INSERT INTO runs (run_id, snapshot_id, state, schema_version, skill_version,
                                  knowledge_version, config_ref, revision, created_at, updated_at)
                VALUES ('run-spec', 'snp', 'active', '1.0', '0.1.0', '1.0', 'cfg', 1,
                        '2026-11-15T00:00:00Z', '2026-11-15T00:00:00Z')
                """
            )
            conn.commit() if hasattr(conn, "commit") else None

            with mock.patch.object(
                Verifier, "build_verify_task",
                return_value={"schema_version": "1.0", "task_kind": "verify"},
            ):
                enqueued = self.app._enqueue_verify_tasks(
                    conn, "run-spec",
                    [{"candidate_id": "cand-broken", "provenance": {"hunt_tasks": ["t"]}}],
                    "task-origin",
                )
            self.assertEqual(enqueued, [])

            rows = conn.execute(
                "SELECT payload_json FROM events WHERE event_type = 'verify_task_spec_rejected'"
            ).fetchall()
            self.assertEqual(len(rows), 1)
            payload = json.loads(rows[0]["payload_json"])
            self.assertEqual(payload["candidate_id"], "cand-broken")
            self.assertIn("Schema validation failed", payload["reason"])

            # Nothing was enqueued under the candidate's task key.
            remaining = conn.execute(
                "SELECT count(*) AS cnt FROM tasks WHERE task_key LIKE 'verify:task-origin:%'"
            ).fetchone()["cnt"]
            self.assertEqual(remaining, 0)
        finally:
            conn.close()


class TestVerifyUnitEndpointShapes(unittest.TestCase):
    """Packet-context synthesis from real worker endpoint shapes (SR-008).

    Workers name locations in several shapes; a verify packet that fails to
    resolve them renders an empty 'Target Code under Review' section and the
    worker verifies blind. Resolution stays snapshot-anchored: names that do
    not resolve contribute NO range (honest absence, never a guess)."""

    def test_file_lines_shapes_resolve_to_packet_ranges(self):
        spec = {
            "schema_version": "1.0",
            "task_kind": "verify",
            "input": {
                "candidate": {
                    "candidate_id": "cand-shape-1",
                    "source": {
                        "description": "untrusted header parsed in src/example_app/handlers.py",
                        "file": "src/example_app/handlers.py",
                        "lines": "261-265, 307, 360",
                    },
                    "sink": {
                        "file": "src/example_app/upstream.py",
                        "line": "615",
                    },
                }
            },
        }
        snapshot_paths = ["src/example_app/handlers.py", "src/example_app/upstream.py"]
        unit = AuditAppService._verify_unit_from_spec(spec, snapshot_paths=snapshot_paths)
        ranges = unit["ranges"]
        by_path = {}
        for r in ranges:
            by_path.setdefault(r["path"], []).append(r)
        # Both endpoints resolved; nothing was silently dropped.
        self.assertIn("src/example_app/handlers.py", by_path)
        self.assertIn("src/example_app/upstream.py", by_path)
        # Multi-segment 'lines' yields one range per segment (windowed).
        handler_ranges = by_path["src/example_app/handlers.py"]

        def covers(rs, line):
            return any(r["line_start"] <= line <= r["line_end"] for r in rs)

        for line in (261, 265, 307, 360):
            self.assertTrue(covers(handler_ranges, line), f"range missing line {line}")
        # String 'line' values parse; the sink range covers its line.
        self.assertTrue(covers(by_path["src/example_app/upstream.py"], 615))

    def test_unresolvable_endpoint_names_contribute_no_range(self):
        spec = {
            "schema_version": "1.0",
            "task_kind": "verify",
            "input": {
                "candidate": {
                    "candidate_id": "cand-shape-2",
                    "source": {"file": "not_in_manifest/example.py", "line": 3},
                    "sink": {"file": "also_missing/example.py", "lines": "10-20"},
                }
            },
        }
        snapshot_paths = ["real/example.py"]
        unit = AuditAppService._verify_unit_from_spec(spec, snapshot_paths=snapshot_paths)
        paths = {r["path"] for r in unit["ranges"]}
        self.assertNotIn("not_in_manifest/example.py", paths)
        self.assertNotIn("also_missing/example.py", paths)
        # No fabricated ranges for names outside the frozen manifest.
        self.assertEqual(
            [r for r in unit["ranges"] if r["path"].endswith("example.py")], []
        )


if __name__ == "__main__":
    unittest.main()
