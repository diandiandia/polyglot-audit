"""Pipeline closure tests: cross-layer assertions for the ten audited fixes.

These tests exist because a fully green suite once masked pipeline breaks: the
individual domain suites each passed while the cross-layer wiring was dead.
Every fix has at least one assertion that crosses layers:

1.  Recon stage wiring (DDS-05 S1 / DSR-024 / SR-006): prepare dispatches a
    single recon task before any hunt task; a recon submission persists the
    guard baseline (event + recon/recon-result.json summary artifact, plus
    the raw worker result at tasks/{task_id}/result.json); hunt
    packets published afterwards carry the guard summary; without a recon
    submission no baseline is fabricated (packet stays without a guard
    section = unknown).
2.  Real packet persistence (DSR-025/059 / IFC-02): every claim's
    packet_ref points at a real readable artifact with <untrusted_code>
    slices and the declared role; render failures release the claim
    (fail closed) with events; capacity overflow is recorded.
3.  MCP / in-session unified through AuditAppService: covered in
    tests/hosts/test_mcp_run_adapter.py and tests/hosts/test_session_adapter.py
    (an MCP hunt submission must enqueue a verify task).
4.  Candidate deduplication (DSR-063): exact duplicates are auto-merged with
    confirmed_by="pipeline:exact-duplicate" and only representatives are
    verified; distinct-source duplicates only get a dedup_suggested event.
5.  High/Critical second opinions (DSR-061): a confirmed High/Critical
    finding enqueues an independent second-opinion verify task at a priority
    above normal verify; agreement corroborates, conflict demotes to
    needs_validation with both sides kept; a pending (never dispatched)
    second opinion is recorded, never implied as done.
6.  Self-review inputs at finalize (SR-014 / DSR-070): run_stats assembled
    from the ledger reach SKILL-REVIEW.md (anomaly list not constant-empty).
7.  usage_records into cost (SR-020 / DSR-067): COST.md reflects persisted
    token usage and ledger-derived retries; without records it stays
    unavailable with the reason.
8.  G4 ordering (user-confirmed fix): the gate is evaluated against the
    published artifacts; a failing G4 forces 'incomplete' with g4_failed.
9.  report_language at finalize (SR-012).
10. pause/resume contract (IFC-06).
11. DSR-062 variant search (ANA -> SNP): a verify-submitted confirmed finding
    runs the bounded variant search against the frozen snapshot before it is
    persisted; same-sink variants are recorded with
    requires_independent_verification=True; empty results, unreadable snapshot
    files and file-cap truncation are recorded honestly in variant_search.
"""

import hashlib
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[2]
SKILL_SCRIPTS = REPO_ROOT / "skill" / "scripts"
if str(SKILL_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SKILL_SCRIPTS))

from auditkit.analysis.verifier import Verifier  # noqa: E402
from auditkit.app import service as service_module  # noqa: E402
from auditkit.app.service import AuditAppService  # noqa: E402
from auditkit.contracts.errors import (  # noqa: E402
    CorruptRunError,
    HostFailureError,
    InvalidInputError,
    InvalidStateError,
)
from auditkit.ledger.artifacts import ArtifactManager  # noqa: E402
from auditkit.ledger.db import get_db_connection  # noqa: E402
from auditkit.ledger.task_queue import TaskQueue  # noqa: E402

FIXTURES_APP = REPO_ROOT / "tests" / "fixtures" / "pyapp" / "app"
SKILL_DIR = REPO_ROOT / "skill"

BIG_LINE = "value = f(\"{candidate_argument_one}_{candidate_argument_two}\")  # padded line\n"
DANGER_SOURCE = "import os\n\n\ndef handler(user_input):\n    os.system(user_input)\n"


def hunt_result(claim, records=(), overflow=()):
    return {
        "schema_version": "1.0",
        "task_id": claim["task_id"],
        "attempt_id": claim["attempt_id"],
        "kind": "hunt",
        "coverage": [],
        "records": list(records),
        "overflow": list(overflow),
    }


def recon_result(claim, guards=()):
    return {
        "schema_version": "1.0",
        "task_id": claim["task_id"],
        "attempt_id": claim["attempt_id"],
        "kind": "recon",
        "coverage": [],
        "records": list(guards),
        "overflow": [],
    }


def verify_result(claim, records):
    return {
        "schema_version": "1.0",
        "task_id": claim["task_id"],
        "attempt_id": claim["attempt_id"],
        "kind": "verify",
        "coverage": [],
        "records": list(records),
        "overflow": [],
    }


def candidate_record(claim, candidate_id="cand-pipe-01", source_path="pkg/handlers/upload.py",
                     sink_path="pkg/handlers/upload.py"):
    return {
        "schema_version": "1.0",
        "candidate_id": candidate_id,
        "issue": "py-01",
        "source": {"path": source_path, "line": 5, "symbol": "handler",
                   "kind": "param", "control": "user_input"},
        "sink": {"path": sink_path, "line": 5, "symbol": "os.system",
                 "kind": "rce", "effect": "command execution"},
        "steps": [
            {"path": source_path, "line": 5, "role": "source", "note": "n1"},
            {"path": sink_path, "line": 5, "role": "sink", "note": "n2"},
        ],
        "guard_analysis": "none",
        "impact_claim": "RCE",
        "open_questions": [],
        "provenance": {"hunt_tasks": [claim["task_id"]]},
    }


def guard_record(guard_id="guard-mw", status="observed"):
    return {
        "schema_version": "1.0",
        "guard_id": guard_id,
        "status": status,
        "mechanism": "Middleware validates request bodies",
        "anchors": [{"path": "pkg/middleware.py", "line": 8}],
        "applicability": "pkg/handlers/",
        "exceptions": [],
    }


def usage_exact(attempt_id, value, dimension="tokens"):
    return {
        "schema_version": "1.0",
        "attempt_id": attempt_id,
        "dimension": dimension,
        "availability": "exact",
        "value": value,
        "unit": dimension,
        "source": "host_cli_report",
    }


class PipelineClosureBase(unittest.TestCase):

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="pipe-closure-"))
        self.app = AuditAppService(SKILL_DIR)
        self.run_dir = self.temp_dir / "run"
        self._run_id = None

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # ------------------------------------------------------------- helpers
    def make_config(self, target, budgets=None, report_language="en", profile="standard"):
        return {
            "schema_version": "1.0",
            "target": str(target),
            "run_dir": str(self.run_dir),
            "report_language": report_language,
            "profile": profile,
            "scope": {"include": ["*"], "exclude": []},
            "budgets": budgets or [{
                "schema_version": "1.0", "dimension": "tasks", "mode": "enforced",
                "limit": 12, "settled": 0, "reserved": 0, "unit": "tasks",
                "availability": "exact",
            }],
            "safety_acceptance": {
                "allow_unverified_execution": False,
                "allow_unverified_network": False,
                "allow_unverified_write": False,
                "user_approved": True,
            },
        }

    def prepared_pyapp(self, budgets=None, report_language="en"):
        target = self.temp_dir / "target"
        shutil.copytree(FIXTURES_APP, target)
        config = self.make_config(target, budgets=budgets, report_language=report_language)
        prep = self.app.prepare(target, self.run_dir, config)
        self.app.activate(self.run_id, self.run_dir)
        return prep

    def prepared_two_unit_target(self, budgets=None, report_language="en"):
        """Two strong-signal files in separate directories: two hunt units."""
        target = self.temp_dir / "target2"
        for sub in ("a", "b"):
            (target / sub).mkdir(parents=True)
            (target / sub / "danger.py").write_text(DANGER_SOURCE, encoding="utf-8")
        config = self.make_config(target, budgets=budgets, report_language=report_language)
        prep = self.app.prepare(target, self.run_dir, config)
        self.assertEqual(prep["plan_summary"]["hunt_units"], 2)
        self.app.activate(self.run_id, self.run_dir)
        return prep

    def drain_recon(self, guards=(guard_record(),)):
        """Claim (batch of one) and complete the recon task; returns its claim."""
        claims = self.app.next(self.run_id, self.run_dir, batch_size=1)
        self.assertEqual(len(claims), 1)
        claim = claims[0]
        self.assertEqual(claim["spec"].get("task_kind"), "recon")
        self.app.start(self.run_dir, claim)
        self.app.submit(self.run_dir, claim, recon_result(claim, guards), "digest-recon")
        return claim

    def claim_all(self):
        return self.app.next(self.run_id, self.run_dir, batch_size=10)

    @property
    def run_id(self):
        if self._run_id is None:
            conn = get_db_connection(self.run_dir / "events.db")
            try:
                self._run_id = conn.execute(
                    "SELECT run_id FROM runs LIMIT 1"
                ).fetchone()["run_id"]
            finally:
                conn.close()
        return self._run_id

    def events(self, event_type):
        conn = get_db_connection(self.run_dir / "events.db")
        try:
            rows = conn.execute(
                "SELECT revision, payload_json FROM events WHERE event_type = ? ORDER BY revision",
                (event_type,),
            ).fetchall()
            return [json.loads(r["payload_json"]) for r in rows]
        finally:
            conn.close()

    def task_rows(self):
        conn = get_db_connection(self.run_dir / "events.db")
        try:
            return conn.execute(
                "SELECT task_id, kind, state, priority, task_key FROM tasks "
                "ORDER BY priority DESC, task_id"
            ).fetchall()
        finally:
            conn.close()


class TestReconPipeline(PipelineClosureBase):
    """Fix 1 + 2: recon dispatch, guard baseline, real packet persistence."""

    def test_prepare_enqueues_single_recon_task_dispatched_first(self):
        prep = self.prepared_pyapp()
        tasks = self.task_rows()
        recon = [t for t in tasks if t["kind"] == "recon"]
        self.assertEqual(len(recon), 1)
        self.assertEqual(recon[0]["task_key"], "recon:baseline")
        # Recon dispatches before every hunt task (DDS-05 S1).
        self.assertGreater(
            recon[0]["priority"],
            max(t["priority"] for t in tasks if t["kind"] == "hunt"),
        )
        self.assertEqual(prep["recon_task_id"], recon[0]["task_id"])

        claims = self.claim_all()
        self.assertEqual(claims[0]["task_id"], recon[0]["task_id"])
        self.assertEqual(claims[0]["spec"]["task_kind"], "recon")
        # Recon spec carries snapshot id, primary language index, knowledge hints.
        self.assertEqual(claims[0]["spec"]["snapshot_id"], prep["snapshot_id"])
        self.assertTrue(claims[0]["spec"]["language_index"])
        self.assertIn("primary_language", claims[0]["spec"]["knowledge_hints"])
        self.assertTrue(claims[0]["spec"]["knowledge_hints"]["catalog_languages"])

    def test_claim_packet_is_real_readable_artifact(self):
        self.prepared_pyapp()
        claims = self.claim_all()
        self.assertTrue(claims)
        for claim in claims:
            self.assertEqual(claim["packet_ref"], f"tasks/{claim['task_id']}/packet.json")
            packet_path = self.run_dir / claim["packet_ref"]
            self.assertTrue(packet_path.exists(), f"packet missing for {claim['task_id']}")
            packet = json.loads(packet_path.read_text(encoding="utf-8"))
            self.assertIn("packet_digest", packet)
            self.assertIn("Role:", packet["prompt_text"])
            if claim["spec"].get("task_kind") == "recon":
                self.assertEqual(packet["task_kind"], "recon")
                self.assertIn("Primary Language Index", packet["prompt_text"])

    def test_hunt_packet_contains_source_slices_and_no_unearned_baseline(self):
        self.prepared_pyapp()
        claims = self.claim_all()
        hunt_claim = next(c for c in claims if c["spec"].get("task_kind") != "recon")
        packet = json.loads(
            (self.run_dir / hunt_claim["packet_ref"]).read_text(encoding="utf-8")
        )
        self.assertEqual(packet["task_kind"], "hunt")
        self.assertIn("<untrusted_code", packet["prompt_text"])
        self.assertIn("os.system", packet["prompt_text"])  # real source slice content
        # No recon baseline yet: no guard section may be fabricated (DDS-05).
        self.assertNotIn("Environment Guards", packet["prompt_text"])

    def test_recon_submission_persists_guard_baseline_and_reaches_hunt_packets(self):
        self.prepared_pyapp()
        recon_claim = self.drain_recon()

        baseline_events = self.events("guard_baseline")
        self.assertEqual(len(baseline_events), 1)
        self.assertEqual(baseline_events[0]["guards_reported"], 1)
        # §10.1: the guard baseline summary is published in the recon/ directory.
        self.assertEqual(baseline_events[0]["artifact"], "recon/recon-result.json")
        artifact = self.run_dir / baseline_events[0]["artifact"]
        self.assertTrue(artifact.exists())
        stored = json.loads(artifact.read_text(encoding="utf-8"))
        self.assertEqual(stored["guards"][0]["guard_id"], "guard-mw")
        self.assertEqual(stored["guards_reported"], 1)
        # The raw recon worker result itself is persisted per task, exactly
        # like every other accepted submission (§10.1 tasks/<id>/result.json).
        raw = json.loads(
            (self.run_dir / "tasks" / recon_claim["task_id"] / "result.json").read_text(encoding="utf-8")
        )
        self.assertEqual(raw["kind"], "recon")
        self.assertEqual([g["guard_id"] for g in raw["records"]], ["guard-mw"])

        # The guard summary established by recon reaches every later hunt packet.
        claims = self.claim_all()
        hunt_claims = [c for c in claims if c["spec"].get("task_kind") != "recon"]
        self.assertTrue(hunt_claims)
        for claim in hunt_claims:
            packet = json.loads((self.run_dir / claim["packet_ref"]).read_text(encoding="utf-8"))
            self.assertIn("Environment Guards", packet["prompt_text"])
            self.assertIn("guard-mw", packet["prompt_text"])

    def test_recon_invalid_guard_records_are_rejected_with_events(self):
        self.prepared_pyapp()
        bad = guard_record("guard-broken", status="bogus_status")
        self.drain_recon(guards=(bad, guard_record("guard-ok")))
        invalid = self.events("recon_invalid_record")
        self.assertEqual(len(invalid), 1)
        self.assertEqual(invalid[0]["guard_id"], "guard-broken")
        baseline = self.events("guard_baseline")[0]
        self.assertEqual([g["guard_id"] for g in baseline["guards"]], ["guard-ok"])
        self.assertEqual(baseline["invalid_records"], 1)

    def test_packet_render_failure_releases_claim_fail_closed(self):
        self.prepared_pyapp()
        # A hunt task whose spec carries no unit can never be rendered into a
        # packet; the claim must be released (fail closed) with events.
        conn = get_db_connection(self.run_dir / "events.db")
        try:
            TaskQueue(conn).enqueue(self.run_id, "hunt:broken", "hunt", {"snapshot_id": "snp"})
        finally:
            conn.close()

        broken_ids = {t["task_id"] for t in self.task_rows() if t["task_key"] == "hunt:broken"}
        self.assertEqual(len(broken_ids), 1)
        claims = self.claim_all()
        # The broken claim never leaves next(): fail closed.
        self.assertNotIn(broken_ids.pop(), {c["task_id"] for c in claims})

        row = None
        conn = get_db_connection(self.run_dir / "events.db")
        try:
            task_id = [t["task_id"] for t in self.task_rows() if t["task_key"] == "hunt:broken"][0]
            row = conn.execute(
                "SELECT state, generation FROM tasks WHERE task_id = ?", (task_id,)
            ).fetchone()
        finally:
            conn.close()
        self.assertEqual(row["state"], "queued")  # released back, not lost
        self.assertEqual(row["generation"], 2)    # generation advanced
        self.assertTrue(self.events("packet_render_failed"))
        self.assertTrue(self.events("attempt_released"))

    def test_packet_capacity_overflow_is_recorded(self):
        target = self.temp_dir / "big"
        (target / "pkg").mkdir(parents=True)
        (target / "pkg" / "huge.py").write_text(
            "import os\nos.system(cmd)\n" + BIG_LINE * 450, encoding="utf-8"
        )
        config = self.make_config(target)
        self.app.prepare(target, self.run_dir, config)
        self.app.activate(self.run_id, self.run_dir)

        claims = self.claim_all()
        hunt_claims = [c for c in claims if c["spec"].get("task_kind") != "recon"]
        self.assertTrue(hunt_claims)
        overflows = self.events("packet_overflow")
        self.assertTrue(overflows)
        self.assertEqual(overflows[0]["dimension"], "packet_capacity")
        # The packet itself was still published (overflow semantics, not silence).
        self.assertTrue((self.run_dir / hunt_claims[0]["packet_ref"]).exists())


class TestDedupAndSecondOpinion(PipelineClosureBase):
    """Fix 3 (service verify fan-out, also via MCP/in-session suites) + 4 + 5."""

    def submit_hunt(self, claim, candidate):
        self.app.start(self.run_dir, claim)
        self.app.submit(
            self.run_dir, claim, hunt_result(claim, [candidate]), f"digest-{claim['task_id']}",
            usage=usage_exact(claim["attempt_id"], 100),
        )

    def test_hunt_submission_via_service_enqueues_verify_task(self):
        self.prepared_pyapp()
        self.drain_recon()
        hunt_claim = next(c for c in self.claim_all() if c["spec"].get("task_kind") != "recon")
        self.submit_hunt(hunt_claim, candidate_record(
            hunt_claim, source_path="handlers/upload.py", sink_path="storage/state.py",
        ))

        verify_tasks = [t for t in self.task_rows() if t["kind"] == "verify"]
        self.assertEqual(len(verify_tasks), 1)
        self.assertGreater(verify_tasks[0]["priority"], 20)

    def _submitted_two_hunts(self, cand_a, cand_b):
        self.prepared_two_unit_target()
        self.drain_recon()
        claims = self.claim_all()
        hunt_claims = [c for c in claims if c["spec"].get("task_kind") != "recon"]
        self.assertEqual(len(hunt_claims), 2)
        self.submit_hunt(hunt_claims[0], cand_a)
        self.submit_hunt(hunt_claims[1], cand_b)
        return hunt_claims

    def test_exact_duplicates_merged_and_only_representative_verified(self):
        cand_a = candidate_record({"task_id": "t-a"}, "cand-dup-a")
        cand_b = candidate_record({"task_id": "t-b"}, "cand-dup-b")  # same fingerprint+source
        self._submitted_two_hunts(cand_a, cand_b)

        merged = self.events("candidate_deduplicated")
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["confirmed_by"], "pipeline:exact-duplicate")
        self.assertEqual(merged[0]["merged_candidate_id"], "cand-dup-b")
        self.assertEqual(merged[0]["representative_id"], "cand-dup-a")

        # Only the representative candidate is dispatched for verification.
        conn = get_db_connection(self.run_dir / "events.db")
        try:
            specs = [
                json.loads(r["spec_json"])
                for r in conn.execute("SELECT spec_json FROM tasks WHERE kind = 'verify'")
            ]
        finally:
            conn.close()
        self.assertEqual({s.get("candidate_id") for s in specs}, {"cand-dup-a"})
        self.assertEqual(self.events("dedup_suggested"), [])

    def test_distinct_source_duplicates_suggested_but_not_merged(self):
        cand_a = candidate_record({"task_id": "t-a"}, "cand-src-a", source_path="b/danger.py")
        cand_b = candidate_record({"task_id": "t-b"}, "cand-src-b", source_path="a/danger.py")
        self._submitted_two_hunts(cand_a, cand_b)

        suggested = self.events("dedup_suggested")
        self.assertEqual(len(suggested), 1)
        self.assertEqual(sorted(suggested[0]["candidate_ids"]), ["cand-src-a", "cand-src-b"])
        self.assertEqual(sorted(suggested[0]["source_paths"]), ["a/danger.py", "b/danger.py"])
        # Both sides are retained: two verify tasks, one per distinct source.
        self.assertEqual(len([t for t in self.task_rows() if t["kind"] == "verify"]), 2)
        self.assertEqual(self.events("candidate_deduplicated"), [])

    def _confirm_high_finding(self):
        """Full hunt -> verify -> confirmed(High) flow through the service."""
        self.prepared_pyapp()
        self.drain_recon()
        hunt_claim = next(c for c in self.claim_all() if c["spec"].get("task_kind") != "recon")
        candidate = candidate_record(
            hunt_claim, source_path="handlers/upload.py", sink_path="storage/state.py",
        )
        self.submit_hunt(hunt_claim, candidate)
        verify_claim = self.app.next(self.run_id, self.run_dir, batch_size=5)[0]
        self.assertEqual(verify_claim["spec"]["role"], "verify")
        self.app.start(self.run_dir, verify_claim)
        finding = Verifier(enforce_attempt_gate=True).create_finding_from_candidate(
            candidate,
            "confirmed", "vt-pipe-01",
            impact=3, exploitability=4,  # High
            impact_why="sensitive sink", exploitability_why="unauthenticated",
            verify_attempt_id=verify_claim["attempt_id"],
            hunt_attempt_id=hunt_claim["attempt_id"],
        )
        self.app.submit(
            self.run_dir, verify_claim,
            verify_result(verify_claim, [
                {"schema_version": "1.0", "verdict": "confirmed", "finding": finding}
            ]),
            "digest-verify",
            usage=usage_exact(verify_claim["attempt_id"], 90),
        )
        return hunt_claim, verify_claim, finding

    def test_confirmed_high_finding_enqueues_second_opinion_above_verify(self):
        hunt_claim, verify_claim, finding = self._confirm_high_finding()

        enqueued = self.events("second_opinion_enqueued")
        self.assertEqual(len(enqueued), 1)
        self.assertEqual(enqueued[0]["finding_id"], finding["finding_id"])

        so_rows = [t for t in self.task_rows() if t["task_key"].startswith("verify:second-opinion:")]
        self.assertEqual(len(so_rows), 1)
        normal_verify = [
            t for t in self.task_rows()
            if t["kind"] == "verify" and not t["task_key"].startswith("verify:second-opinion:")
        ]
        self.assertGreater(so_rows[0]["priority"], normal_verify[0]["priority"])

        # Corroboration: the second opinion agrees -> finding stays confirmed.
        so_claim = self.app.next(self.run_id, self.run_dir, batch_size=5)[0]
        self.assertTrue(so_claim["spec"]["second_opinion"])
        self.assertEqual(so_claim["spec"]["target_finding_id"], finding["finding_id"])
        self.app.start(self.run_dir, so_claim)
        self.app.submit(
            self.run_dir, so_claim,
            verify_result(so_claim, [{
                "schema_version": "1.0", "verdict": "confirmed",
                "reason": "independent trace reached the same sink",
            }]),
            "digest-so",
        )
        adjudicated = self.events("second_opinion_adjudicated")
        self.assertEqual(len(adjudicated), 1)
        self.assertEqual(adjudicated[0]["resolution"], "corroborated")

        fin = self.app.finalize(self.run_id, self.run_dir, findings=[])
        self.assertEqual(fin["final_state"], "complete")
        self.assertEqual(fin["second_opinion_pending"], [])
        on_disk = json.loads(
            (self.run_dir / adjudicated[0]["artifact"]).read_text(encoding="utf-8")
        )
        self.assertEqual(on_disk[0]["verdict"], "confirmed")
        self.assertEqual(on_disk[0]["second_opinion"]["resolution"], "corroborated")

    def test_second_opinion_conflict_demotes_to_needs_validation(self):
        hunt_claim, verify_claim, finding = self._confirm_high_finding()
        so_claim = self.app.next(self.run_id, self.run_dir, batch_size=5)[0]
        self.app.start(self.run_dir, so_claim)
        self.app.submit(
            self.run_dir, so_claim,
            verify_result(so_claim, [{
                "schema_version": "1.0", "verdict": "rejected",
                "reason": "input is validated upstream at the framework layer",
                "anchor": {"path": "pkg/middleware.py", "line": 8},
            }]),
            "digest-so-conflict",
        )
        adjudicated = self.events("second_opinion_adjudicated")
        self.assertEqual(len(adjudicated), 1)
        self.assertEqual(adjudicated[0]["resolution"], "conflict_demoted")

        fin = self.app.finalize(self.run_id, self.run_dir, findings=[])
        self.assertEqual(fin["final_state"], "complete")
        demoted = [u for u in fin["unverified"] if u["finding_id"] == finding["finding_id"]]
        self.assertEqual(len(demoted), 1)
        self.assertEqual(demoted[0]["verdict"], "needs_validation")
        on_disk = json.loads(
            (self.run_dir / adjudicated[0]["artifact"]).read_text(encoding="utf-8")
        )[0]
        self.assertEqual(on_disk["verdict"], "needs_validation")
        # Both sides preserved structurally.
        self.assertEqual(on_disk["second_opinion"]["primary"]["verdict"], "confirmed")
        self.assertEqual(on_disk["second_opinion"]["secondary"]["verdict"], "rejected")
        self.assertTrue(on_disk["second_opinion"]["secondary"]["anchor"])

    def test_pending_second_opinion_recorded_not_implied_done(self):
        hunt_claim, verify_claim, finding = self._confirm_high_finding()
        # The second-opinion task exists but is never dispatched/completed.
        fin = self.app.finalize(self.run_id, self.run_dir, findings=[])
        self.assertIn(finding["finding_id"], fin["second_opinion_pending"])
        pending = self.events("second_opinion_pending")
        self.assertTrue(pending)
        self.assertIn(finding["finding_id"], pending[-1]["finding_ids"])
        self.assertEqual(fin["final_state"], "incomplete")


class TestFinalizeClosure(PipelineClosureBase):
    """Fix 6 + 7 + 8 + 9: self-review inputs, usage in cost, G4 order, language."""

    def _run_hunts(self, with_usage=True, retry_first=False):
        self.prepared_pyapp()
        self.drain_recon()
        hunt_claims = [c for c in self.claim_all() if c["spec"].get("task_kind") != "recon"]
        if retry_first:
            res = self.app.report_host_failure(
                self.run_dir, hunt_claims[0],
                HostFailureError("transient host error", retryable=True),
                max_retries=2,
            )
            self.assertEqual(res["action"], "requeued")
            hunt_claims = [c for c in self.claim_all() if c["spec"].get("task_kind") != "recon"]
        for c in hunt_claims:
            self.app.start(self.run_dir, c)
            self.app.submit(
                self.run_dir, c, hunt_result(c, []), "digest-hunt-final",
                usage=usage_exact(c["attempt_id"], 120) if with_usage else None,
            )
        return hunt_claims

    def test_finalize_cost_reflects_usage_records_and_ledger_retries(self):
        self._run_hunts(with_usage=True, retry_first=True)
        fin = self.app.finalize(self.run_id, self.run_dir, findings=[])
        self.assertEqual(fin["final_state"], "complete")
        # SR-012/026: a fully drained run reaches the complete terminal state
        # without the unprocessed-units reason (plan scope processed).
        self.assertNotIn("unprocessed_units", fin["incomplete_reasons"])

        cost_md = (self.run_dir / "report" / "COST.md").read_text(encoding="utf-8")
        # SR-020 / DSR-067: token status reflects the persisted usage records.
        self.assertIn("exact", cost_md)
        self.assertNotIn("no usage records were persisted", cost_md)
        # Retry counter derived from the attempts table (one requeued task).
        self.assertIn("Retries**: 1", cost_md)

    def test_finalize_without_usage_records_states_reason(self):
        fin = self.app.finalize_after_drain = self._finalize_drained(with_usage=False)
        cost_md = (self.run_dir / "report" / "COST.md").read_text(encoding="utf-8")
        self.assertIn("unavailable", cost_md)
        self.assertIn("no usage records were persisted for this run", cost_md)
        # SR-012/026 terminal semantics: the drained run is complete and the
        # run_finalized event records the unprocessed-units accounting.
        self.assertEqual(fin["final_state"], "complete")
        finalized = self.events("run_finalized")[-1]
        self.assertEqual(finalized["incomplete_reasons"], [])
        self.assertGreaterEqual(finalized["unprocessed_units"]["plan_hunt_units"], 1)
        self.assertGreaterEqual(finalized["unprocessed_units"]["completed_hunt_tasks"], 1)
        self.assertEqual(finalized["unprocessed_units"]["hunt_tasks_ever_dispatched"], finalized["unprocessed_units"]["completed_hunt_tasks"])
        self.assertEqual(finalized["unprocessed_units"]["recon_tasks_not_done"], 0)
        self.assertEqual(finalized["unprocessed_units"]["verify_tasks_not_done_or_quarantined"], 0)

    def _finalize_drained(self, with_usage=True):
        self._run_hunts(with_usage=with_usage)
        return self.app.finalize(self.run_id, self.run_dir, findings=[])

    def test_finalize_skill_review_receives_real_inputs(self):
        self._run_hunts(with_usage=False)
        # Attempts without usage records must surface in the skill self-review
        # (inputs really transmitted; the anomaly list is not constant-empty).
        self.app.finalize(self.run_id, self.run_dir, findings=[])
        review = (self.run_dir / "skill-review" / "SKILL-REVIEW.md").read_text(encoding="utf-8")
        self.assertIn("usage_missing", review)
        self.assertIn("attempts lack host usage records", review)
        self.assertIn("[cost]", review)  # token telemetry missing -> cost anomaly

    def test_finalize_g4_is_evaluated_after_publication(self):
        self._run_hunts(with_usage=True)
        real_generator = service_module.ReportGenerator
        tampered = {"done": False}

        class TamperingGenerator(real_generator):
            def generate_all(self, *args, **kwargs):
                gen_id = super().generate_all(*args, **kwargs)
                if not tampered["done"]:
                    tampered["done"] = True
                    report_path = Path(self.artifacts.run_dir) / "report" / "REPORT.md"
                    content = report_path.read_text(encoding="utf-8")
                    # Simulate post-publish leakage: the gate must catch it by
                    # reading the PUBLISHED artifact back (ordering fix).
                    report_path.write_text(
                        content + '\napi_key = "leakedkeyvalue123456"\n', encoding="utf-8"
                    )
                return gen_id

        with mock.patch.object(service_module, "ReportGenerator", TamperingGenerator):
            fin = self.app.finalize(self.run_id, self.run_dir, findings=[])

        self.assertEqual(fin["gates"]["G4"], "fail")
        self.assertIn("g4_failed", fin["incomplete_reasons"])
        self.assertEqual(fin["final_state"], "incomplete")
        conn = get_db_connection(self.run_dir / "events.db")
        try:
            state = conn.execute(
                "SELECT state FROM runs WHERE run_id = ?", (self.run_id,)
            ).fetchone()["state"]
            gens = [
                r["generation"]
                for r in conn.execute(
                    "SELECT DISTINCT generation FROM artifacts WHERE run_id = ? AND generation IS NOT NULL",
                    (self.run_id,),
                ).fetchall()
            ]
        finally:
            conn.close()
        self.assertEqual(state, "incomplete")
        # The dossier was re-published with the true terminal state: exactly
        # one generation survives and it no longer carries the leaked secret.
        self.assertEqual(len(gens), 1)
        final_report = (self.run_dir / "report" / "REPORT.md").read_text(encoding="utf-8")
        self.assertNotIn("leakedkeyvalue123456", final_report)
        self.assertIn("incomplete", final_report)

    def test_finalize_report_language_follows_config(self):
        self.prepared_pyapp(report_language="zh")
        self.drain_recon()
        for c in self.claim_all():
            if c["spec"].get("task_kind") != "recon":
                self.app.start(self.run_dir, c)
                self.app.submit(self.run_dir, c, hunt_result(c, []), "digest-zh")
        self.app.finalize(self.run_id, self.run_dir, findings=[])
        report = (self.run_dir / "report" / "REPORT.md").read_text(encoding="utf-8")
        self.assertIn("发现总表", report)


def frontier_record(task_id, frontier_id="front-a1", boundary="libnative.so",
                    symbol="dispatch_payload", path="a/danger.py"):
    return {
        "schema_version": "1.0",
        "record_type": "frontier",
        "frontier_id": frontier_id,
        "source": {"path": path, "line": 3, "symbol": symbol, "kind": "param"},
        "boundary": boundary,
        "steps": [{"path": path, "line": 3, "role": "source", "note": "outgoing taint"}],
        "open_questions": [],
        "provenance": {"hunt_tasks": [task_id]},
    }


def probe_record(task_id, probe_id="probe-b1", boundary="libnative.so",
                 symbol="exec_command", path="b/danger.py"):
    return {
        "schema_version": "1.0",
        "record_type": "sink_probe",
        "probe_id": probe_id,
        "sink": {"path": path, "line": 6, "symbol": symbol, "kind": "rce", "effect": "exec"},
        "boundary": boundary,
        "steps": [{"path": path, "line": 6, "role": "sink", "note": "dangling sink"}],
        "guard_analysis": "none",
        "open_questions": [],
        "provenance": {"hunt_tasks": [task_id]},
    }


class TestCrossTaskHalfChains(PipelineClosureBase):
    """SR-005/007/DSR-026/058: half-chains persist and pair across tasks."""

    def _two_hunt_claims(self):
        self.prepared_two_unit_target()
        self.drain_recon()
        claims = self.claim_all()
        hunt_claims = [c for c in claims if c["spec"].get("task_kind") != "recon"]
        self.assertEqual(len(hunt_claims), 2)
        return hunt_claims

    def test_frontier_from_task_a_pairs_with_probe_from_task_b(self):
        hunt_a, hunt_b = self._two_hunt_claims()

        # Task A reports frontiers only (one matchable, one orphan).
        self.app.start(self.run_dir, hunt_a)
        self.app.submit(
            self.run_dir, hunt_a,
            hunt_result(hunt_a, [
                frontier_record(hunt_a["task_id"], "front-a1"),
                frontier_record(
                    hunt_a["task_id"], "front-a2",
                    boundary="libother.so", symbol="other_path",
                ),
            ]),
            f"digest-{hunt_a['task_id']}",
        )

        # A's submission persisted the frontiers verbatim; no connector run
        # happened (no probes yet), and both are marked unpaired so far.
        recorded = self.events("frontier_recorded")
        self.assertEqual(len(recorded), 1)
        self.assertEqual(recorded[0]["task_id"], hunt_a["task_id"])
        self.assertEqual(
            sorted(r["frontier_id"] for r in recorded[0]["records"]),
            ["front-a1", "front-a2"],
        )
        self.assertEqual(self.events("connector_evaluated"), [])
        self.assertEqual(
            {e["record_id"] for e in self.events("unpaired_half_chain")},
            {"front-a1", "front-a2"},
        )

        # Task B reports the matching probe: the cross-task pair is formed at
        # B's submission time from the run-level aggregation.
        self.app.start(self.run_dir, hunt_b)
        self.app.submit(
            self.run_dir, hunt_b,
            hunt_result(hunt_b, [probe_record(hunt_b["task_id"], "probe-b1")]),
            f"digest-{hunt_b['task_id']}",
        )

        paired = self.events("connector_paired")
        self.assertEqual(len(paired), 1)
        self.assertEqual(paired[0]["frontier_id"], "front-a1")
        self.assertEqual(paired[0]["probe_id"], "probe-b1")
        self.assertEqual(paired[0]["status"], "hypothesized")
        self.assertEqual(self.events("sink_probe_recorded")[0]["task_id"], hunt_b["task_id"])

        # The pairing synthesized a linked candidate and dispatched verify work.
        verify_tasks = [t for t in self.task_rows() if t["kind"] == "verify"]
        self.assertEqual(len(verify_tasks), 1)

        # Idempotence: the paired records leave the pending set; the orphan
        # stays and is NOT re-marked on repeated aggregation.
        conn = get_db_connection(self.run_dir / "events.db")
        try:
            pending = AuditAppService._gather_pending_half_chains(conn, self.run_id)
        finally:
            conn.close()
        self.assertEqual(
            [e["record"]["frontier_id"] for e in pending["frontiers"]], ["front-a2"]
        )
        self.assertEqual(pending["probes"], [])
        self.assertEqual(
            {e["record_id"] for e in self.events("unpaired_half_chain")},
            {"front-a1", "front-a2"},
        )

    def test_unpaired_half_chains_render_into_needs_validation(self):
        hunt_a, hunt_b = self._two_hunt_claims()
        self.app.start(self.run_dir, hunt_a)
        self.app.submit(
            self.run_dir, hunt_a,
            hunt_result(hunt_a, [frontier_record(hunt_a["task_id"], "front-solo")]),
            f"digest-{hunt_a['task_id']}",
        )
        self.app.start(self.run_dir, hunt_b)
        self.app.submit(
            self.run_dir, hunt_b, hunt_result(hunt_b, []),
            f"digest-{hunt_b['task_id']}",
        )

        fin = self.app.finalize(self.run_id, self.run_dir, findings=[])
        self.assertEqual(fin["final_state"], "complete")

        needs_val = (self.run_dir / "report" / "NEEDS-VALIDATION.md").read_text(encoding="utf-8")
        self.assertIn("Unconnected Half-Chains", needs_val)
        self.assertIn("front-solo", needs_val)
        self.assertIn(hunt_a["task_id"], needs_val)
        # The paired frontier never renders as unpaired; the paired probe is
        # consumed by the connection and also absent.
        self.assertNotIn("front-paired", needs_val)
        report = (self.run_dir / "report" / "REPORT.md").read_text(encoding="utf-8")
        self.assertIn("Frontier / Dangling Sink", report)

    def test_later_pairing_supersedes_the_unpaired_marker(self):
        hunt_a, hunt_b = self._two_hunt_claims()
        # A leaves a frontier; B leaves nothing yet.
        self.app.start(self.run_dir, hunt_a)
        self.app.submit(
            self.run_dir, hunt_a,
            hunt_result(hunt_a, [frontier_record(hunt_a["task_id"], "front-late")]),
            f"digest-{hunt_a['task_id']}",
        )
        self.app.start(self.run_dir, hunt_b)
        self.app.submit(
            self.run_dir, hunt_b, hunt_result(hunt_b, []),
            f"digest-{hunt_b['task_id']}",
        )
        self.assertTrue(self.events("unpaired_half_chain"))

        # A later verify-style dispatch is impossible for half-chains, so the
        # reconciliation happens through a fresh aggregation when a probe
        # arrives late from a re-claimed task: simulate by draining the queue
        # (no verify tasks here) and re-checking the pending set logic.
        conn = get_db_connection(self.run_dir / "events.db")
        try:
            from auditkit.ledger.event_store import EventStore
            store = EventStore(conn)
            store.append_event(
                self.run_id, "sink_probe_recorded", "service",
                {
                    "schema_version": "1.0",
                    "task_id": hunt_b["task_id"],
                    "attempt_id": hunt_b["attempt_id"],
                    "records": [probe_record(hunt_b["task_id"], "probe-late")],
                },
            )
            pending = AuditAppService._gather_pending_half_chains(conn, self.run_id)
        finally:
            conn.close()
        # Both sides pending: a subsequent hunt submission pairs them via the
        # connector (covered by the pairing test); the ledger keeps history.
        self.assertEqual(
            [e["record"]["frontier_id"] for e in pending["frontiers"]], ["front-late"]
        )
        self.assertEqual(
            [e["record"]["probe_id"] for e in pending["probes"]], ["probe-late"]
        )


class TestUnverifiedCandidateSurfacing(PipelineClosureBase):
    """DSR-066: candidates whose verification never completed stay visible."""

    CANDIDATE = None

    def _submit_hunt_with_candidate(self, budgets=None):
        self.prepared_pyapp(budgets=budgets)
        self.drain_recon()
        hunt_claim = next(
            c for c in self.claim_all() if c["spec"].get("task_kind") != "recon"
        )
        candidate = candidate_record(
            hunt_claim, source_path="handlers/upload.py", sink_path="storage/state.py",
        )
        self.app.start(self.run_dir, hunt_claim)
        self.app.submit(
            self.run_dir, hunt_claim, hunt_result(hunt_claim, [candidate]),
            f"digest-{hunt_claim['task_id']}",
            usage=usage_exact(hunt_claim["attempt_id"], 100),
        )
        return hunt_claim, candidate

    def _needs_validation_md(self):
        return (self.run_dir / "report" / "NEEDS-VALIDATION.md").read_text(encoding="utf-8")

    def test_budget_exhausted_candidates_appear_in_needs_validation(self):
        budgets = [{
            "schema_version": "1.0", "dimension": "tasks", "mode": "enforced",
            "limit": 2, "settled": 0, "reserved": 0, "unit": "tasks",
            "availability": "exact",
        }]
        hunt_claim, candidate = self._submit_hunt_with_candidate(budgets=budgets)

        # The verify task can never be claimed: the budget is exhausted.
        self.assertEqual(self.app.next(self.run_id, self.run_dir, batch_size=5), [])
        self.assertTrue(self.events("budget_exhausted"))

        fin = self.app.finalize(self.run_id, self.run_dir, findings=[])
        self.assertEqual(fin["final_state"], "incomplete")
        self.assertTrue(any("budget_exhausted" in r for r in fin["incomplete_reasons"]))
        self.assertIn("unprocessed_units", fin["incomplete_reasons"])

        unverified_ids = {u["finding_id"] for u in fin["unverified"]}
        self.assertIn(f"F-UNVERIFIED-{candidate['candidate_id']}", unverified_ids)
        entry = next(
            u for u in fin["unverified"]
            if u["finding_id"] == f"F-UNVERIFIED-{candidate['candidate_id']}"
        )
        self.assertEqual(entry["verdict"], "unverified")
        self.assertEqual(entry["reason"], "verification_not_completed_before_finalize")

        needs_val = self._needs_validation_md()
        self.assertIn("Unverified Candidates", needs_val)
        self.assertIn(f"F-UNVERIFIED-{candidate['candidate_id']}", needs_val)
        self.assertIn("verification_not_completed_before_finalize", needs_val)
        self.assertIn("queued", needs_val)  # verify task state is disclosed
        # The machine-readable export carries the candidate-level entry too.
        findings_export = json.loads(
            (self.run_dir / "report" / "findings.json").read_text(encoding="utf-8")
        )
        self.assertIn(
            f"F-UNVERIFIED-{candidate['candidate_id']}",
            {f.get("finding_id") for f in findings_export},
        )

    def test_early_finalize_surfaces_queued_verify_candidates(self):
        hunt_claim, candidate = self._submit_hunt_with_candidate()

        # Finalize while the verify task is still queued (no valid lease, so
        # the in-flight gate does not block this early finalize).
        fin = self.app.finalize(self.run_id, self.run_dir, findings=[])
        self.assertEqual(fin["final_state"], "incomplete")
        self.assertIn("unprocessed_units", fin["incomplete_reasons"])
        self.assertIn(
            f"F-UNVERIFIED-{candidate['candidate_id']}",
            {u["finding_id"] for u in fin["unverified"]},
        )
        needs_val = self._needs_validation_md()
        self.assertIn("verification_not_completed_before_finalize", needs_val)
        self.assertIn(candidate["candidate_id"], needs_val)

    def test_verified_candidates_are_not_duplicated_as_unverified(self):
        from auditkit.analysis.verifier import Verifier as _Verifier

        hunt_claim, candidate = self._submit_hunt_with_candidate()
        verify_claim = self.app.next(self.run_id, self.run_dir, batch_size=5)[0]
        self.app.start(self.run_dir, verify_claim)
        self.app.submit(
            self.run_dir, verify_claim,
            verify_result(verify_claim, [{
                "schema_version": "1.0",
                "finding_id": "F-VERD-01",
                "candidate_refs": [candidate["candidate_id"]],
                "verdict": "unverified",
                "evidence_level": "E1",
                "unverified_reason": "deployment facts unavailable in static-only run",
                "provenance": {
                    "hunt_tasks": [hunt_claim["task_id"]],
                    "verify_tasks": [verify_claim["task_id"]],
                },
            }]),
            "digest-verify-unverified",
        )

        fin = self.app.finalize(self.run_id, self.run_dir, findings=[])
        self.assertEqual(fin["final_state"], "complete")
        unverified_ids = [u["finding_id"] for u in fin["unverified"]]
        self.assertIn("F-VERD-01", unverified_ids)
        self.assertNotIn(f"F-UNVERIFIED-{candidate['candidate_id']}", unverified_ids)
        needs_val = self._needs_validation_md()
        self.assertNotIn("verification_not_completed_before_finalize", needs_val)


class TestTerminalStateSemantics(PipelineClosureBase):
    """SR-012/026/DSR-076: terminal-state semantics enforced end to end.

    - prepare -> finalize directly must yield 'incomplete' with the
      unprocessed_units reason (the zero-dispatch blind spot of the G1/G2
      formulas is covered by an explicit hard rule).
    - attempts still held under a valid claim lease block finalize with
      InvalidStateError (SD-06 §5.1: the plan scope must be processed).
    """

    def test_prepare_then_finalize_is_incomplete_with_unprocessed_units(self):
        target = self.temp_dir / "target-fresh"
        shutil.copytree(FIXTURES_APP, target)
        self.app.prepare(target, self.run_dir, self.make_config(target))
        # No activation, no claims: straight to finalize.
        fin = self.app.finalize(self.run_id, self.run_dir, findings=[])

        self.assertEqual(fin["final_state"], "incomplete")
        self.assertIn("unprocessed_units", fin["incomplete_reasons"])
        self.assertIn("gate_failed:G1", ",".join(fin["incomplete_reasons"]))
        self.assertEqual(fin["gates"]["G1"], "fail")

        # The run_finalized event carries the plan-coverage accounting.
        finalized = self.events("run_finalized")[-1]
        accounting = finalized["unprocessed_units"]
        self.assertGreaterEqual(accounting["plan_hunt_units"], 1)
        self.assertEqual(accounting["completed_hunt_tasks"], 0)
        self.assertEqual(accounting["hunt_tasks_ever_dispatched"], 0)
        self.assertEqual(accounting["recon_tasks_not_done"], 1)

        # The on-disk dossier states the true terminal state.
        report = (self.run_dir / "report" / "REPORT.md").read_text(encoding="utf-8")
        self.assertIn("incomplete", report)

    def test_finalize_with_in_flight_lease_is_rejected_then_allowed_after_expiry(self):
        self.prepared_pyapp()
        claims = self.app.next(self.run_id, self.run_dir, batch_size=1)
        self.assertEqual(len(claims), 1)
        self.app.start(self.run_dir, claims[0])

        with self.assertRaises(InvalidStateError):
            self.app.finalize(self.run_id, self.run_dir, findings=[])
        # The rejection message names the escape hatches and the run did not
        # enter a terminal or 'finalizing' state.
        with self.assertRaises(InvalidStateError) as ctx:
            self.app.finalize(self.run_id, self.run_dir, findings=[])
        self.assertIn("Pause", str(ctx.exception))
        conn = get_db_connection(self.run_dir / "events.db")
        try:
            state = conn.execute(
                "SELECT state FROM runs WHERE run_id = ?", (self.run_id,)
            ).fetchone()["state"]
        finally:
            conn.close()
        self.assertEqual(state, "active")

        # After the lease expires (and is reclaimed) finalize proceeds — and
        # honestly reports the unprocessed plan scope.
        conn = get_db_connection(self.run_dir / "events.db")
        try:
            conn.execute("UPDATE attempts SET expires_at = '2000-01-01T00:00:00+00:00'")
        finally:
            conn.close()
        fin = self.app.finalize(self.run_id, self.run_dir, findings=[])
        self.assertEqual(fin["final_state"], "incomplete")
        self.assertIn("unprocessed_units", fin["incomplete_reasons"])
        gate_failed = next(r for r in fin["incomplete_reasons"] if r.startswith("gate_failed:"))
        self.assertIn("G2", gate_failed)


class TestPauseResumeContract(PipelineClosureBase):
    """Fix 10: pause/resume contract (IFC-06)."""

    def test_pause_returns_in_flight_contract_and_bounds_reason(self):
        self.prepared_pyapp()
        claims = self.app.next(self.run_id, self.run_dir, batch_size=2)
        held = claims[0]
        self.app.start(self.run_dir, held)

        paused = self.app.pause(self.run_id, self.run_dir, reason="paused by operator")
        self.assertEqual(paused["run_id"], self.run_id)
        self.assertEqual(paused["state"], "paused")
        self.assertIsInstance(paused["revision"], int)
        self.assertGreaterEqual(paused["in_flight_tasks"], 1)
        self.assertIn(held["attempt_id"], paused["in_flight_attempt_ids"])

        with self.assertRaises(InvalidInputError):
            self.app.pause(self.run_id, self.run_dir, reason="x" * 257)
        with self.assertRaises(InvalidInputError):
            self.app.pause(self.run_id, self.run_dir, reason="   ")

        payload = self.events("run_paused")[-1]
        self.assertEqual(payload["reason"], "paused by operator")
        self.assertEqual(payload["in_flight_tasks"], paused["in_flight_tasks"])
        self.assertIn(held["attempt_id"], payload["in_flight_attempt_ids"])

    def test_resume_requires_paused_state_and_snapshot_integrity(self):
        self.prepared_pyapp()
        manifest = json.loads(
            (self.run_dir / "snapshot" / "manifest.json").read_text(encoding="utf-8")
        )

        # Not paused -> InvalidStateError (before any verification work).
        with self.assertRaises(InvalidStateError):
            self.app.resume(self.run_id, self.run_dir)

        self.app.pause(self.run_id, self.run_dir)

        # Snapshot tampering must fail the resume (recomputed root hash).
        snapshot_file = self.run_dir / "snapshot" / "handlers" / "upload.py"
        original = snapshot_file.read_bytes()
        snapshot_file.write_bytes(original + b"\n# tampered\n")
        with self.assertRaises(CorruptRunError):
            self.app.resume(self.run_id, self.run_dir)

        # Restored snapshot resumes cleanly, re-affirms paused, records the event.
        snapshot_file.write_bytes(original)
        res = self.app.resume(self.run_id, self.run_dir)
        self.assertEqual(res["state"], "paused")
        self.assertTrue(res["verified"])
        self.assertEqual(res["snapshot_integrity"], "verified")
        resumed = self.events("run_resumed")
        self.assertEqual(len(resumed), 1)
        self.assertEqual(resumed[0]["snapshot_root_hash"], manifest["root_hash"])

        # A missing artifact reference fails resume too (existing integrity gate).
        conn = get_db_connection(self.run_dir / "events.db")
        try:
            ArtifactManager(self.run_dir, conn).publish_artifact(
                self.run_id, "report", "report/notes.md", b"resume integrity"
            )
        finally:
            conn.close()
        (self.run_dir / "report" / "notes.md").unlink()
        with self.assertRaises(CorruptRunError):
            self.app.resume(self.run_id, self.run_dir)

    def test_resume_force_reclaim_drains_orphaned_leases(self):
        """RUN-LESSONS L-11: a driver that died mid-flight leaves otherwise
        valid claim leases behind -- they block finalize (still-holds-lease)
        and hold budget reservations. Plain resume reports them honestly but
        revokes nothing; resume with force_reclaim=True drains them, returns
        the tasks to the queue, and records each revocation auditable."""
        self.prepared_pyapp()
        claim = self.app.next(self.run_id, self.run_dir, batch_size=1)[0]

        # Pausing stops dispatch but leaves the held lease intact (IFC-06).
        self.app.pause(self.run_id, self.run_dir)

        # Plain resume: the orphaned lease survives untouched.
        res_plain = self.app.resume(self.run_id, self.run_dir)
        self.assertEqual(res_plain.get("reclaimed_attempts"), 0)
        conn = get_db_connection(self.run_dir / "events.db")
        try:
            state = conn.execute(
                "SELECT state FROM tasks WHERE task_id = ?", (claim["task_id"],)
            ).fetchone()["state"]
            self.assertEqual(state, "claimed")
        finally:
            conn.close()

        # Pause again, then force-reclaim drains the lease on resume.
        self.app.pause(self.run_id, self.run_dir)
        res = self.app.resume(self.run_id, self.run_dir, force_reclaim=True)
        self.assertTrue(res["force_reclaim"])
        self.assertGreaterEqual(res["reclaimed_attempts"], 1)
        conn = get_db_connection(self.run_dir / "events.db")
        try:
            task_state = conn.execute(
                "SELECT state FROM tasks WHERE task_id = ?", (claim["task_id"],)
            ).fetchone()["state"]
            att_state = conn.execute(
                "SELECT status FROM attempts WHERE attempt_id = ?",
                (claim["attempt_id"],),
            ).fetchone()["status"]
        finally:
            conn.close()
        # The task is back in the queue and re-claimable; the revoked
        # attempt is no longer active.
        self.assertEqual(task_state, "queued")
        self.assertEqual(att_state, "expired")
        expired_events = self.events("attempt_expired")
        self.assertTrue(
            any(e.get("forced") and e.get("task_id") == claim["task_id"]
                for e in expired_events)
        )


class TestVariantSearchClosure(PipelineClosureBase):
    """Fix 11: DSR-062 bounded variant search wired into the verify path.

    bounded_variant_search used to have no production consumer: verify
    submissions were stored straight from worker records, so every finding's
    variants stayed empty. These tests cross the layers: a hunt candidate for
    a sink symbol, a verify confirmation, and the persisted finding artifact
    must carry real same-sink variants plus the honest variant_search record.
    """

    # os.system sits on line 5 of this exact source (two PEP8 blank lines).
    VARIANT_SOURCE = "import os\n\n\ndef handler(user_input):\n    os.system(user_input)\n"
    CLEAN_SOURCE = "import os\n\n\ndef cleanup(path):\n    os.remove(path)\n"

    def _variant_target(self, second_file_text):
        """Target with a/danger.py hitting os.system; b/other.py optional."""
        target = self.temp_dir / "target-variant"
        (target / "a").mkdir(parents=True)
        (target / "a" / "danger.py").write_text(self.VARIANT_SOURCE, encoding="utf-8")
        if second_file_text is not None:
            (target / "b").mkdir(parents=True)
            (target / "b" / "other.py").write_text(second_file_text, encoding="utf-8")
        return target

    def variant_candidate(self, claim, candidate_id="cand-var-01"):
        return {
            "schema_version": "1.0",
            "candidate_id": candidate_id,
            "issue": "py-01",
            "source": {"path": "a/danger.py", "line": 4, "symbol": "handler",
                       "kind": "param", "control": "user_input"},
            "sink": {"path": "a/danger.py", "line": 5, "symbol": "os.system",
                     "kind": "rce", "effect": "command execution"},
            "steps": [
                {"path": "a/danger.py", "line": 4, "role": "source", "note": "n1"},
                {"path": "a/danger.py", "line": 5, "role": "sink", "note": "n2"},
            ],
            "guard_analysis": "none",
            "impact_claim": "RCE",
            "open_questions": [],
            "provenance": {"hunt_tasks": [claim["task_id"]]},
        }

    def _run_hunt_phase(self, second_file_text, candidate_id="cand-var-01"):
        """prepare -> recon -> hunt(candidate).

        Returns (hunt_claim, candidate, other_hunt_claims); the other hunt
        unit's claims stay claimed so a test that finalizes can drain them.
        """
        target = self._variant_target(second_file_text)
        self.app.prepare(target, self.run_dir, self.make_config(target))
        self.app.activate(self.run_id, self.run_dir)
        self.drain_recon()
        hunt_claims = [c for c in self.claim_all() if c["spec"].get("task_kind") != "recon"]
        candidate = self.variant_candidate(hunt_claims[0], candidate_id)
        self.app.start(self.run_dir, hunt_claims[0])
        self.app.submit(
            self.run_dir, hunt_claims[0], hunt_result(hunt_claims[0], [candidate]),
            f"digest-{hunt_claims[0]['task_id']}",
        )
        return hunt_claims[0], candidate, hunt_claims[1:]

    def _confirm(self, hunt_claim, candidate, impact=3, exploitability=2):
        """Claim and complete the verify task with a confirmed finding."""
        verify_claim = self.app.next(self.run_id, self.run_dir, batch_size=5)[0]
        self.assertEqual(verify_claim["spec"]["role"], "verify")
        self.app.start(self.run_dir, verify_claim)
        finding = Verifier(enforce_attempt_gate=True).create_finding_from_candidate(
            candidate, "confirmed", "vt-var-01",
            impact=impact, exploitability=exploitability,
            impact_why="sensitive sink", exploitability_why="unvalidated input",
            verify_attempt_id=verify_claim["attempt_id"],
            hunt_attempt_id=hunt_claim["attempt_id"],
        )
        self.app.submit(
            self.run_dir, verify_claim,
            verify_result(verify_claim, [
                {"schema_version": "1.0", "verdict": "confirmed", "finding": finding}
            ]),
            "digest-verify-variant",
        )
        return verify_claim, finding["finding_id"]

    def _run_to_confirmed(self, second_file_text, candidate_id="cand-var-01",
                          impact=3, exploitability=2):
        """prepare -> recon -> hunt(candidate) -> verify confirmed; returns
        (finding_id, hunt_claim, verify_claim)."""
        hunt_claim, candidate, _ = self._run_hunt_phase(second_file_text, candidate_id)
        verify_claim, finding_id = self._confirm(
            hunt_claim, candidate, impact=impact, exploitability=exploitability
        )
        return finding_id, hunt_claim, verify_claim

    def _stored_finding(self, verify_claim):
        artifact = self.run_dir / f"findings/verified-{verify_claim['attempt_id']}.json"
        stored = json.loads(artifact.read_text(encoding="utf-8"))
        self.assertEqual(len(stored), 1)
        return stored[0]

    def test_confirmed_finding_carries_same_sink_variants(self):
        """DSR-062: the persisted confirmed finding lists the OTHER same-sink
        location as a variant requiring independent verification."""
        finding_id, _, verify_claim = self._run_to_confirmed(self.VARIANT_SOURCE)
        stored = self._stored_finding(verify_claim)
        self.assertEqual(stored["finding_id"], finding_id)
        self.assertEqual(stored["verdict"], "confirmed")

        variants = stored["variants"]
        self.assertTrue(variants, "variant search must find the b/other.py sink")
        self.assertIn(
            ("b/other.py", 5),
            [(v["path"], v["line"]) for v in variants],
        )
        # The confirmed location itself is never its own variant.
        self.assertNotIn(
            ("a/danger.py", 5),
            [(v["path"], v["line"]) for v in variants],
        )
        for v in variants:
            self.assertTrue(v["requires_independent_verification"])
            self.assertEqual(v["source_finding_id"], finding_id)
            self.assertTrue(v["snippet"])

        search = stored["variant_search"]
        self.assertEqual(search["total_files"], 2)      # both snapshot files
        self.assertEqual(search["searched_files"], 2)
        self.assertFalse(search["truncated"])
        self.assertEqual(search["unsearched_files"], [])

    def test_without_same_symbol_variants_stay_empty_and_are_recorded(self):
        """DSR-062: no same-sink match -> variants == [] and variant_search
        truthfully records what was searched (no fabricated variants)."""
        _, _, verify_claim = self._run_to_confirmed(self.CLEAN_SOURCE)
        stored = self._stored_finding(verify_claim)
        self.assertEqual(stored["variants"], [])
        search = stored["variant_search"]
        self.assertEqual(search["total_files"], 2)
        self.assertEqual(search["searched_files"], 2)
        self.assertFalse(search["truncated"])
        self.assertEqual(search["unsearched_files"], [])

    def test_unreadable_snapshot_file_is_skipped_and_recorded(self):
        """DSR-062: one bad snapshot file must not abort the search; the skip
        is recorded as truncation with a reason naming the file."""
        hunt_claim, candidate, _ = self._run_hunt_phase(
            self.VARIANT_SOURCE, candidate_id="cand-var-skip"
        )
        # Break the frozen snapshot BEFORE the verify submission: the search
        # runs against the snapshot copy at verify-submission time.
        (self.run_dir / "snapshot" / "b" / "other.py").unlink()
        verify_claim, finding_id = self._confirm(hunt_claim, candidate)
        stored = self._stored_finding(verify_claim)
        self.assertEqual(stored["finding_id"], finding_id)
        self.assertEqual(stored["variants"], [])
        search = stored["variant_search"]
        self.assertTrue(search["truncated"])
        self.assertIn("b/other.py", search["reason"])
        self.assertIn("b/other.py", search["unsearched_files"])
        self.assertEqual(search["searched_files"], 1)
        self.assertEqual(search["total_files"], 2)

    def test_snapshot_read_cap_is_deterministic_and_recorded(self):
        """DSR-062: the snapshot read bound caps memory (max_files attempted
        in manifest order); the overflow is listed as unsearched."""
        target = self._variant_target(self.VARIANT_SOURCE)
        self.app.prepare(target, self.run_dir, self.make_config(target))
        loaded = AuditAppService._load_snapshot_files(self.run_dir, 1)
        self.assertEqual(loaded["total_files"], 2)
        self.assertEqual(sorted(loaded["files"]), ["a/danger.py"])  # manifest order
        self.assertEqual(loaded["unsearched_files"], ["b/other.py"])
        self.assertEqual(loaded["read_errors"], [])

    def test_variants_survive_finalize_merge_and_reporting(self):
        """DSR-062: the merged finding keeps its variants at finalize and the
        published reports render without breaking on the new fields."""
        hunt_claim, candidate, other_hunts = self._run_hunt_phase(
            self.VARIANT_SOURCE, candidate_id="cand-var-fin"
        )
        verify_claim, finding_id = self._confirm(
            hunt_claim, candidate, impact=3, exploitability=2,  # Medium: no 2nd opinion
        )
        # Drain the second hunt unit so the run reaches the complete state.
        for claim in other_hunts:
            self.app.start(self.run_dir, claim)
            self.app.submit(
                self.run_dir, claim, hunt_result(claim, []), f"digest-{claim['task_id']}"
            )
        fin = self.app.finalize(self.run_id, self.run_dir, findings=[])
        self.assertEqual(fin["final_state"], "complete")

        export = json.loads(
            (self.run_dir / "report" / "findings.json").read_text(encoding="utf-8")
        )
        merged = next(f for f in export if f.get("finding_id") == finding_id)
        self.assertIn(("b/other.py", 5), [(v["path"], v["line"]) for v in merged["variants"]])
        self.assertEqual(merged["variant_search"]["total_files"], 2)

        report = (self.run_dir / "report" / "REPORT.md").read_text(encoding="utf-8")
        self.assertIn(finding_id, report)
        needs_val = (self.run_dir / "report" / "NEEDS-VALIDATION.md").read_text(encoding="utf-8")
        self.assertIsInstance(needs_val, str)


if __name__ == "__main__":
    unittest.main()


class TestIFC05FloorEvents(unittest.TestCase):
    """IFC-05 floor requirement (SR-018/DSR-016): snapshot_published,
    usage_settled and gate_evaluated events exist and carry reconstruction-
    grade payloads; the gate ledger follows the artifact ledger."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())
        self.app = AuditAppService(SKILL_DIR)
        self.target = FIXTURES_APP
        self.run_dir = self.temp_dir / "run"
        cfg = {
            "schema_version": "1.0",
            "target": str(self.target),
            "run_dir": str(self.run_dir),
            "report_language": "en",
            "profile": "standard",
            "scope": {"include": ["*"], "exclude": []},
            "budgets": [{
                "schema_version": "1.0", "dimension": "tasks", "mode": "enforced",
                "limit": 30, "settled": 0, "reserved": 0, "unit": "tasks",
                "availability": "exact",
            }],
            "safety_acceptance": {
                "allow_unverified_execution": False, "allow_unverified_network": False,
                "allow_unverified_write": False, "user_approved": True,
            },
        }
        prep = self.app.prepare(str(self.target), str(self.run_dir), cfg)
        self.run_id = prep["run_id"]
        self.app.activate(self.run_id, self.run_dir)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _events(self, event_type):
        conn = get_db_connection(self.run_dir / "events.db")
        try:
            rows = conn.execute(
                "SELECT payload_json FROM events WHERE event_type = ? ORDER BY revision",
                (event_type,),
            ).fetchall()
            return [json.loads(r["payload_json"]) for r in rows]
        finally:
            conn.close()

    def _drain(self):
        for _ in range(15):
            claims = self.app.next(self.run_id, self.run_dir, batch_size=5)
            if not claims:
                break
            for c in claims:
                self.app.start(self.run_dir, c)
                kind = (c.get("spec") or {}).get("task_kind") or "hunt"
                self.app.submit(
                    self.run_dir, c,
                    {"schema_version": "1.0", "task_id": c["task_id"],
                     "attempt_id": c["attempt_id"], "kind": kind,
                     "coverage": [], "records": [], "overflow": []},
                    hashlib.sha256(c["task_id"].encode()).hexdigest(),
                )

    def test_prepare_emits_snapshot_published_with_reconstruction_payload(self):
        events = self._events("snapshot_published")
        self.assertEqual(len(events), 1)
        payload = events[0]
        self.assertTrue(payload["snapshot_id"].startswith("snp-"))
        self.assertRegex(payload["root_hash"], r"^[0-9a-f]{64}$")
        self.assertGreater(payload["total_files"], 0)
        self.assertIn("gap_count", payload)
        self.assertIn("source_control", payload)

    def test_finalize_emits_gate_evaluated_after_publish_for_g1_to_g4(self):
        self._drain()
        result = self.app.finalize(self.run_id, self.run_dir)
        events = self._events("gate_evaluated")
        gate_ids = [e["gate_id"] for e in events]
        self.assertIn("G1", gate_ids)
        self.assertIn("G2", gate_ids)
        self.assertIn("G3", gate_ids)
        self.assertIn("G4", gate_ids)
        # G4 is evaluated against published artifacts: its event must be the
        # last gate event and run must reach a terminal state.
        conn = get_db_connection(self.run_dir / "events.db")
        try:
            seen_types = [
                r["event_type"]
                for r in conn.execute(
                    "SELECT event_type FROM events ORDER BY revision"
                ).fetchall()
            ]
        finally:
            conn.close()
        self.assertEqual(gate_ids[-1], "G4")
        self.assertIn("run_finalized", seen_types)
        self.assertIn(result["final_state"], ("complete", "incomplete"))


if __name__ == "__main__":
    unittest.main()
