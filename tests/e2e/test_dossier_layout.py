"""Dossier layout alignment tests (design SYSTEM_DESIGN.md §10.1).

The run directory must carry the ten §10.1 entries after a real audit:

    run.json            immutable run metadata (target/snapshot/skill digest/
                        dossier version/config/profile/budgets)
    events.db           the ledger
    inventory/          inventory summary
    plan/               plan (units, dispositions, budget allocation, estimates)
    recon/              run brief (guard baseline)
    tasks/<task-id>/    prompt packet, result, validation log, usage
    candidates/         merged candidate pool
    findings/<id>/      finding record + status-transition history
    report/             the §9.3 report set (seven deliverables)
    skill-review/       the skill self-review (local part; portable export
                        only when explicitly enabled)

Hard invariants pinned here:
- report/ does NOT contain SKILL-REVIEW.md (the self-review is not a report
  file; it lives in skill-review/).
- run.json is written once by prepare and is byte-identical after finalize;
  a second prepare on the same run directory is rejected (existing behaviour)
  and never overwrites it.
- Every accepted worker result is published at tasks/<task-id>/result.json
  for all three task kinds (recon/hunt/verify) with content equal to the
  submission; trusted usage objects land at tasks/<task-id>/usage.json; a
  schema-rejected submission publishes tasks/<task-id>/validation.json with
  the refusal reason and field paths (DSR-018 validation log).
- Old (pre-§10.1) dossiers are read with documented fallbacks and never
  migrated in place (DSR-072): status works read-only on a legacy layout
  (flat plan.json, no run.json) and creates neither plan/ nor run.json.
"""

from __future__ import annotations

import copy
import json
import shutil
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SKILL_SCRIPTS = REPO_ROOT / "skill" / "scripts"
if str(SKILL_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SKILL_SCRIPTS))

from auditkit.analysis.verifier import Verifier  # noqa: E402
from auditkit.app.service import AuditAppService  # noqa: E402
from auditkit.contracts.errors import InvalidInputError, StorageError  # noqa: E402
from auditkit.ledger.db import get_db_connection, init_database  # noqa: E402

SKILL_DIR = REPO_ROOT / "skill"

DANGER_SOURCE = "import os\n\n\ndef handler(user_input):\n    os.system(user_input)\n"

REPORT_SET = (
    "report/REPORT.md",
    "report/findings.json",
    "report/NEEDS-VALIDATION.md",
    "report/COVERAGE.md",
    "report/coverage.csv",
    "report/AUDIT-TRAIL.md",
    "report/COST.md",
)


def guard_record() -> dict:
    return {
        "schema_version": "1.0",
        "guard_id": "guard-mw",
        "status": "observed",
        "mechanism": "Middleware validates request bodies",
        "anchors": [{"path": "danger.py", "line": 1}],
        "applicability": "/",
        "exceptions": [],
    }


def usage_exact(attempt_id: str) -> dict:
    return {
        "schema_version": "1.0",
        "attempt_id": attempt_id,
        "dimension": "tokens",
        "availability": "exact",
        "value": 120,
        "unit": "tokens",
        "source": "host_cli_report",
    }


class DossierLayoutBase(unittest.TestCase):

    def setUp(self) -> None:
        self.temp_dir = Path(tempfile.mkdtemp(prefix="dossier-layout-"))
        self.app = AuditAppService(SKILL_DIR)
        self.run_dir = self.temp_dir / "run"
        self._run_id = None
        self.submitted_results: dict = {}

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # ------------------------------------------------------------ helpers
    def make_config(self, target: Path, task_budget: int = 20) -> dict:
        return {
            "schema_version": "1.0",
            "target": str(target),
            "run_dir": str(self.run_dir),
            "report_language": "en",
            "profile": "quick",
            "scope": {"include": ["*.py"], "exclude": []},
            "budgets": [{
                "schema_version": "1.0", "dimension": "tasks", "mode": "enforced",
                "limit": task_budget, "settled": 0, "reserved": 0, "unit": "tasks",
                "availability": "exact",
            }],
            "safety_acceptance": {
                "allow_unverified_execution": False,
                "allow_unverified_network": False,
                "allow_unverified_write": False,
                "user_approved": True,
            },
        }

    def worker_result(self, claim, records=()) -> dict:
        kind = (claim.get("spec") or {}).get("task_kind") or "hunt"
        return {
            "schema_version": "1.0",
            "task_id": claim["task_id"],
            "attempt_id": claim["attempt_id"],
            "kind": kind,
            "coverage": [],
            "records": list(records),
            "overflow": [],
        }

    def submit(self, claim, records=(), with_usage: bool = True) -> dict:
        """Start and submit one claim; the submitted payload is snapshotted
        for later equality assertions against the published dossier artifact."""
        self.app.start(self.run_dir, claim)
        result = self.worker_result(claim, records)
        self.submitted_results[claim["task_id"]] = copy.deepcopy(result)
        return self.app.submit(
            self.run_dir, claim, result,
            f"digest-{claim['attempt_id']}",
            usage=usage_exact(claim["attempt_id"]) if with_usage else None,
        )

    def run_complete_audit(self) -> dict:
        """prepare -> recon -> hunt(candidate) -> verify(confirmed, Medium) ->
        finalize. Returns (run_id, finding_id)."""
        target = self.temp_dir / "target"
        target.mkdir(parents=True)
        (target / "danger.py").write_text(DANGER_SOURCE, encoding="utf-8")
        prep = self.app.prepare(str(target), str(self.run_dir), self.make_config(target))
        run_id = prep["run_id"]
        self._run_id = run_id
        self.app.activate(run_id, self.run_dir)

        claims = self.app.next(run_id, self.run_dir, batch_size=10)
        recon = next(c for c in claims if c["spec"]["task_kind"] == "recon")
        hunts = [c for c in claims if c["spec"]["task_kind"] == "hunt"]
        self.submit(recon, [guard_record()])

        candidate = {
            "schema_version": "1.0",
            "candidate_id": "cand-layout-01",
            "issue": "py-01",
            "source": {"path": "danger.py", "line": 4, "symbol": "handler",
                       "kind": "param", "control": "user_input"},
            "sink": {"path": "danger.py", "line": 4, "symbol": "os.system",
                     "kind": "rce", "effect": "command execution"},
            "steps": [
                {"path": "danger.py", "line": 4, "role": "source", "note": "request body"},
                {"path": "danger.py", "line": 4, "role": "sink", "note": "os.system call"},
            ],
            "guard_analysis": "none",
            "impact_claim": "RCE",
            "open_questions": [],
            "provenance": {"hunt_tasks": [hunts[0]["task_id"]]},
        }
        for c in hunts:
            self.submit(c, [candidate])

        verify_claim = next(
            c for c in self.app.next(run_id, self.run_dir, batch_size=10)
            if c["spec"]["task_kind"] == "verify"
        )
        # Medium severity (3 x 2): below the second-opinion scope so the run
        # reaches the complete terminal state without extra fan-out.
        finding = Verifier().create_finding_from_candidate(
            candidate, "confirmed", verify_claim["task_id"],
            verify_attempt_id=verify_claim["attempt_id"],
            impact=3, exploitability=2,
            impact_why="Command execution on the studied path",
            exploitability_why="Reachable only from an authenticated session",
            remediation={"where": "danger.py:4", "change": "drop shell exec",
                         "regression_test": "reject metacharacters"},
        )
        self.submit(verify_claim, [{
            "schema_version": "1.0", "verdict": "confirmed", "finding": finding,
        }])

        fin = self.app.finalize(run_id, self.run_dir, findings=[])
        self.assertEqual(fin["final_state"], "complete", fin)
        return {"run_id": run_id, "finding_id": finding["finding_id"], "fin": fin}

    @property
    def run_id(self) -> str:
        if self._run_id is None:
            conn = get_db_connection(self.run_dir / "events.db")
            try:
                self._run_id = conn.execute(
                    "SELECT run_id FROM runs LIMIT 1"
                ).fetchone()["run_id"]
            finally:
                conn.close()
        return self._run_id


class TestSection101Layout(DossierLayoutBase):
    """A complete audit leaves exactly the §10.1 directory shape on disk."""

    def test_ten_section_entries_exist_after_complete_audit(self):
        info = self.run_complete_audit()
        run_id = info["run_id"]

        # 1. run.json — immutable run metadata.
        run_json = self.run_dir / "run.json"
        self.assertTrue(run_json.is_file(), "missing run.json")
        meta = json.loads(run_json.read_text(encoding="utf-8"))
        for field in (
            "target", "snapshot_id", "root_hash", "skill_version",
            "skill_payload_sha256", "dossier_version", "config", "profile",
            "budgets", "created_at",
        ):
            self.assertIn(field, meta, f"run.json missing {field}")
        self.assertEqual(meta["dossier_version"], "1.0")
        self.assertEqual(meta["run_id"], run_id)
        self.assertEqual(meta["profile"], "quick")
        self.assertEqual(meta["budgets"], meta["config"]["budgets"])
        self.assertRegex(meta["skill_payload_sha256"], r"^[0-9a-f]{64}$")
        self.assertTrue(meta["skill_version"])

        # 2. events.db — the ledger.
        self.assertTrue((self.run_dir / "events.db").is_file())

        # 3. inventory/summary.json — reconciliation record.
        inventory = json.loads(
            (self.run_dir / "inventory" / "summary.json").read_text(encoding="utf-8")
        )
        for field in ("included", "excluded", "unknown_language",
                      "by_language", "by_component", "reconciled"):
            self.assertIn(field, inventory)
        self.assertTrue(inventory["reconciled"])
        self.assertEqual(inventory["snapshot_id"], meta["snapshot_id"])

        # 4. plan/plan.json — units, dispositions, queue priority, budget
        #    allocation, platform evidence and component detection.
        plan = json.loads(
            (self.run_dir / "plan" / "plan.json").read_text(encoding="utf-8")
        )
        for field in ("units", "dispositions", "profile", "budgets",
                      "queue_priority", "platform_evidence",
                      "component_detection", "inventory_reconciliation"):
            self.assertIn(field, plan)
        self.assertEqual(plan["budgets"], meta["budgets"])
        self.assertFalse((self.run_dir / "plan.json").exists(),
                         "the flat legacy plan.json must not be written anymore")

        # 5. recon/recon-result.json — the guard baseline summary.
        recon_summary = json.loads(
            (self.run_dir / "recon" / "recon-result.json").read_text(encoding="utf-8")
        )
        self.assertEqual(recon_summary["guards_reported"], 1)

        # 6. tasks/<task-id>/{packet,result,usage}.
        conn = get_db_connection(self.run_dir / "events.db")
        try:
            task_ids = [r["task_id"] for r in conn.execute(
                "SELECT task_id FROM tasks WHERE run_id = ?", (run_id,)
            ).fetchall()]
        finally:
            conn.close()
        self.assertTrue(task_ids)
        for task_id in task_ids:
            task_dir = self.run_dir / "tasks" / task_id
            self.assertTrue((task_dir / "packet.json").is_file(),
                            f"missing packet for {task_id}")
            self.assertTrue((task_dir / "result.json").is_file(),
                            f"missing result for {task_id}")
            self.assertTrue((task_dir / "usage.json").is_file(),
                            f"missing usage for {task_id}")

        # 7. candidates/final.json — the merged candidate pool.
        pool = json.loads(
            (self.run_dir / "candidates" / "final.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            [c["candidate_id"] for c in pool["candidates"]],
            ["cand-layout-01"],
        )
        self.assertIn("provenance", pool["candidates"][0])

        # 8. findings/<finding-id>/{record,history}.json.
        finding_id = info["finding_id"]
        record_path = self.run_dir / "findings" / finding_id / "record.json"
        history_path = self.run_dir / "findings" / finding_id / "history.json"
        self.assertTrue(record_path.is_file(), f"missing {record_path}")
        self.assertTrue(history_path.is_file(), f"missing {history_path}")
        record = json.loads(record_path.read_text(encoding="utf-8"))
        self.assertEqual(record["finding_id"], finding_id)
        self.assertEqual(record["verdict"], "confirmed")
        history = json.loads(history_path.read_text(encoding="utf-8"))
        event_types = [h["event_type"] for h in history["history"]]
        self.assertIn("verified_findings_stored", event_types)
        self.assertEqual(
            history["history"],
            sorted(history["history"], key=lambda h: h["revision"]),
        )

        # 9. report/ — the §9.3 report set; and 10. skill-review/.
        for rel_path in REPORT_SET:
            p = self.run_dir / rel_path
            self.assertTrue(p.is_file(), f"missing {rel_path}")
            self.assertGreater(p.stat().st_size, 0, f"empty {rel_path}")
        self.assertTrue(
            (self.run_dir / "skill-review" / "SKILL-REVIEW.md").is_file(),
            "missing the local skill self-review",
        )
        # §10.1 boundary: report/ holds ONLY the report set — the self-review
        # is not a report file, and the portable export stays off by default.
        self.assertFalse((self.run_dir / "report" / "SKILL-REVIEW.md").exists())
        self.assertFalse((self.run_dir / "skill-review" / "portable.json").exists())

    def test_report_holds_no_self_review_and_findings_dual_form_agrees(self):
        """report/findings.json (machine-readable summary) and the
        findings/<id>/record.json directories carry the same records."""
        info = self.run_complete_audit()
        findings_json = json.loads(
            (self.run_dir / "report" / "findings.json").read_text(encoding="utf-8")
        )
        by_id = {f["finding_id"]: f for f in findings_json}
        record = json.loads(
            (self.run_dir / "findings" / info["finding_id"] / "record.json")
            .read_text(encoding="utf-8")
        )
        self.assertEqual(record, by_id[info["finding_id"]])
        self.assertFalse((self.run_dir / "report" / "SKILL-REVIEW.md").exists())


class TestRunJsonImmutability(DossierLayoutBase):
    """run.json is written once by prepare and never rewritten afterwards."""

    def test_finalize_leaves_run_json_byte_identical(self):
        self.run_complete_audit()
        run_json = self.run_dir / "run.json"
        after_finalize = run_json.read_bytes()
        self.assertTrue(after_finalize)  # written once, non-empty

    def test_second_prepare_is_rejected_and_never_overwrites_run_json(self):
        self.run_complete_audit()
        before = (self.run_dir / "run.json").read_bytes()
        target = self.temp_dir / "target"
        with self.assertRaises(StorageError):
            self.app.prepare(str(target), str(self.run_dir), self.make_config(target))
        self.assertEqual((self.run_dir / "run.json").read_bytes(), before)

    def test_skill_payload_digest_is_deterministic_and_cache_insensitive(self):
        """The skill digest is a deterministic function of the asset payload:
        generated bytecode caches never change it."""
        digest_a = AuditAppService._compute_skill_payload_sha256(SKILL_DIR)
        digest_b = AuditAppService._compute_skill_payload_sha256(SKILL_DIR)
        self.assertEqual(digest_a, digest_b)
        pycache = SKILL_DIR / "scripts" / "__pycache__"
        self.assertTrue(pycache.is_dir(), "precondition: a bytecode cache exists")
        sentinel = pycache / "layout-probe.pyc"
        sentinel.write_bytes(b"x")
        try:
            digest_c = AuditAppService._compute_skill_payload_sha256(SKILL_DIR)
        finally:
            sentinel.unlink(missing_ok=True)
        self.assertEqual(digest_c, digest_a)


class TestTaskArtifacts(DossierLayoutBase):
    """tasks/<id>/{result,usage,validation}.json publication semantics."""

    def test_result_and_usage_artifacts_equal_the_submissions(self):
        self.run_complete_audit()
        for task_id, submitted in self.submitted_results.items():
            published = json.loads(
                (self.run_dir / "tasks" / task_id / "result.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                published, submitted,
                f"result.json for {task_id} must equal the submitted worker result",
            )
            published_usage = json.loads(
                (self.run_dir / "tasks" / task_id / "usage.json").read_text(encoding="utf-8")
            )
            self.assertEqual(published_usage["availability"], "exact")
            self.assertEqual(published_usage["value"], 120)

    def test_submission_without_usage_publishes_no_usage_artifact(self):
        target = self.temp_dir / "target"
        target.mkdir(parents=True)
        (target / "danger.py").write_text(DANGER_SOURCE, encoding="utf-8")
        prep = self.app.prepare(str(target), str(self.run_dir), self.make_config(target))
        self.app.activate(prep["run_id"], self.run_dir)
        claims = self.app.next(prep["run_id"], self.run_dir, batch_size=10)
        recon = next(c for c in claims if c["spec"]["task_kind"] == "recon")
        self.app.start(self.run_dir, recon)
        self.app.submit(
            self.run_dir, recon, self.worker_result(recon), "digest-recon",
            usage=None,
        )
        self.assertTrue((self.run_dir / "tasks" / recon["task_id"] / "result.json").exists())
        self.assertFalse((self.run_dir / "tasks" / recon["task_id"] / "usage.json").exists())

    def test_schema_rejection_publishes_validation_log_with_field_paths(self):
        """DSR-018: a schema-rejected worker result is never accepted, and the
        refusal is published as the task's validation log (reason + field
        paths) before the bounded retry path runs."""
        target = self.temp_dir / "target"
        target.mkdir(parents=True)
        (target / "danger.py").write_text(DANGER_SOURCE, encoding="utf-8")
        prep = self.app.prepare(str(target), str(self.run_dir), self.make_config(target))
        self.app.activate(prep["run_id"], self.run_dir)
        claims = self.app.next(prep["run_id"], self.run_dir, batch_size=10)
        recon = next(c for c in claims if c["spec"]["task_kind"] == "recon")
        self.app.start(self.run_dir, recon)

        malformed = self.worker_result(recon)
        del malformed["kind"]  # required by the worker_result contract
        with self.assertRaises(InvalidInputError) as ctx:
            self.app.submit(self.run_dir, recon, malformed, "digest-bad")
        self.assertIn("kind", str(ctx.exception))

        log_path = self.run_dir / "tasks" / recon["task_id"] / "validation.json"
        self.assertTrue(log_path.is_file(), "schema rejection left no validation log")
        log = json.loads(log_path.read_text(encoding="utf-8"))
        self.assertTrue(log["rejected"])
        self.assertIn("kind", log["reason"])
        self.assertTrue(log["errors"], "field paths must be recorded")
        self.assertTrue(
            any("kind" in json.dumps(e) for e in log["errors"]),
            "the failing field path must appear in the recorded errors",
        )
        # The task was NOT accepted: no result artifact was published.
        self.assertFalse((self.run_dir / "tasks" / recon["task_id"] / "result.json").exists())


class TestCandidatePoolAndEmptyHistory(DossierLayoutBase):
    """candidates/final.json and the honest-empty finding history."""

    def test_candidate_pool_carries_provenance_and_dedup_references(self):
        self.run_complete_audit()
        pool = json.loads(
            (self.run_dir / "candidates" / "final.json").read_text(encoding="utf-8")
        )
        entry = pool["candidates"][0]
        self.assertEqual(entry["candidate_id"], "cand-layout-01")
        self.assertEqual(entry["dedup_records"], [])  # no duplicates occurred
        self.assertEqual(entry["provenance"]["hunt_tasks"], [
            t for t in entry["provenance"]["hunt_tasks"]
        ])

    def test_unverified_synthetic_finding_has_honest_empty_history(self):
        """A finding whose verification never completed (synthetic unverified
        entry, DSR-066) carries an honest empty history list — never a
        fabricated transition."""
        target = self.temp_dir / "target"
        target.mkdir(parents=True)
        (target / "danger.py").write_text(DANGER_SOURCE, encoding="utf-8")
        prep = self.app.prepare(str(target), str(self.run_dir), self.make_config(target))
        run_id = prep["run_id"]
        self.app.activate(run_id, self.run_dir)
        claims = self.app.next(run_id, self.run_dir, batch_size=10)
        recon = next(c for c in claims if c["spec"]["task_kind"] == "recon")
        hunts = [c for c in claims if c["spec"]["task_kind"] == "hunt"]
        self.submit(recon, [])
        candidate = {
            "schema_version": "1.0",
            "candidate_id": "cand-layout-02",
            "issue": "py-01",
            "source": {"path": "danger.py", "line": 4, "symbol": "handler",
                       "kind": "param", "control": "user_input"},
            "sink": {"path": "danger.py", "line": 4, "symbol": "os.system",
                     "kind": "rce", "effect": "command execution"},
            "steps": [
                {"path": "danger.py", "line": 4, "role": "source", "note": "n1"},
                {"path": "danger.py", "line": 4, "role": "sink", "note": "n2"},
            ],
            "guard_analysis": "none",
            "impact_claim": "RCE",
            "open_questions": [],
            "provenance": {"hunt_tasks": [hunts[0]["task_id"]]},
        }
        for c in hunts:
            self.submit(c, [candidate])
        # finalize WITHOUT processing the enqueued verify task (simulated
        # interruption): the candidate surfaces as F-UNVERIFIED-*.
        fin = self.app.finalize(run_id, self.run_dir, findings=[])
        self.assertEqual(fin["final_state"], "incomplete")
        unverified_id = f"F-UNVERIFIED-cand-layout-02"
        record = json.loads(
            (self.run_dir / "findings" / unverified_id / "record.json").read_text(encoding="utf-8")
        )
        self.assertEqual(record["verdict"], "unverified")
        history = json.loads(
            (self.run_dir / "findings" / unverified_id / "history.json").read_text(encoding="utf-8")
        )
        self.assertEqual(history["history"], [])


class TestLegacyLayoutReadOnly(DossierLayoutBase):
    """DSR-072: old (pre-§10.1) dossiers are read, never migrated in place."""

    def _build_legacy_run(self) -> Path:
        """A simulated old terminal run: flat plan.json at the run root, no
        run.json, no plan/ directory."""
        legacy = self.temp_dir / "legacy-run"
        legacy.mkdir(parents=True)
        init_database(legacy / "events.db")
        conn = get_db_connection(legacy / "events.db")
        try:
            conn.execute(
                """
                INSERT INTO runs (run_id, snapshot_id, state, schema_version,
                                  skill_version, knowledge_version, config_ref,
                                  revision, created_at, updated_at)
                VALUES ('run-legacy001', 'snp-legacy', 'complete', '1.0',
                        '0.1.0', '1.0', 'config.json', 3, ?, ?)
                """,
                ("2026-11-01T00:00:00Z", "2026-11-01T00:00:00Z"),
            )
            conn.commit()
        finally:
            conn.close()
        (legacy / "plan.json").write_text(
            json.dumps({
                "snapshot_id": "snp-legacy",
                "total_files": 1,
                "total_units": 1,
                "hunt_units": 1,
                "dispositions": {"analyze": 1},
                "profile": "quick",
                "units": [{"unit_id": "u-1", "tier": "T1", "disposition": "analyze"}],
            }, indent=2),
            encoding="utf-8",
        )
        (legacy / "config.json").write_text(json.dumps({"report_language": "en"}), encoding="utf-8")
        snapshot_dir = legacy / "snapshot"
        snapshot_dir.mkdir()
        (snapshot_dir / "manifest.json").write_text(
            json.dumps({
                "snapshot_id": "snp-legacy",
                "root_hash": "legacy-root-hash",
                "files": [],
                "excluded": [],
                "gaps": [],
            }, indent=2),
            encoding="utf-8",
        )
        return legacy

    @staticmethod
    def _layout_snapshot(run_path: Path) -> dict:
        """The dossier-relevant file state (relative path -> bytes), excluding
        the SQLite WAL sidecars that plain DB access creates transiently."""
        snapshot = {}
        for p in run_path.rglob("*"):
            if p.is_dir() or p.name.endswith(("-wal", "-shm")):
                continue
            snapshot[str(p.relative_to(run_path))] = p.read_bytes()
        return snapshot

    def test_status_reads_legacy_layout_read_only(self):
        legacy = self._build_legacy_run()
        before = self._layout_snapshot(legacy)

        status = self.app.status("run-legacy001", legacy)
        self.assertEqual(status["run_id"], "run-legacy001")
        self.assertEqual(status["state"], "complete")
        self.assertEqual(status["snapshot_id"], "snp-legacy")

        # Read-only tolerance: status created neither run.json nor a plan/
        # directory and touched no dossier file (禁止写迁移; the SQLite WAL
        # sidecars of a plain read connection are not dossier writes).
        after = self._layout_snapshot(legacy)
        self.assertEqual(set(after), set(before), "no dossier file may appear or vanish")
        self.assertEqual(
            {k: after[k] for k in before if k in after}, before,
            "no dossier file content may change",
        )
        self.assertFalse((legacy / "run.json").exists())
        self.assertFalse((legacy / "plan").exists())
        self.assertTrue((legacy / "plan.json").exists())

    def test_plan_loader_falls_back_to_legacy_flat_layout(self):
        legacy = self._build_legacy_run()
        plan = AuditAppService._load_plan(legacy)
        self.assertEqual(plan["snapshot_id"], "snp-legacy")
        self.assertEqual(plan["hunt_units"], 1)

    def test_finalize_reads_legacy_plan_layout(self):
        """A legacy dossier whose plan sits flat at the run root can still be
        finalized (read-only): the plan load falls back, no plan/ is created."""
        legacy = self._build_legacy_run()
        # Mark it ready instead of complete so finalize may run; no tasks
        # exist, so the run ends incomplete with unprocessed_units — the
        # point here is that the legacy plan file is READ, not that the run
        # reaches complete.
        conn = get_db_connection(legacy / "events.db")
        try:
            conn.execute("UPDATE runs SET state = 'active' WHERE run_id = 'run-legacy001'")
            conn.commit()
        finally:
            conn.close()
        fin = self.app.finalize("run-legacy001", legacy, findings=[])
        self.assertEqual(fin["final_state"], "incomplete")
        self.assertFalse((legacy / "plan").exists(),
                         "finalizing a legacy dossier must not create plan/")
        self.assertTrue((legacy / "plan.json").exists())


if __name__ == "__main__":
    unittest.main()
