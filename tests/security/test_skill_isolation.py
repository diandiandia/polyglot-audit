"""Skill isolation tests (DSR-046 / SWR-016).

Three adversarial-isolation scenarios over the full audit lifecycle:
1. 运行数据不回写 skill：a complete prepare/run/submit/finalize lifecycle must
   not add or modify any file inside the skill payload directory.
2. 新 run 不读旧 run：a fresh run over the same target must not reference the
   previous run's id, directories, or artifacts anywhere in its own dossier.
3. 导出失败关闭：a write failure during the opt-in portable skill-review
   export must raise and leave no half-written files, and the export
   whitelist must reject non-whitelisted statistics fail-closed.

Standard library only (DSR-024). The skill payload directory is copied into a
tempdir so the real repo skill tree can never be mutated by these tests.
"""

import json
import os
import shutil
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SKILL_SCRIPTS = Path(__file__).resolve().parents[2] / "skill" / "scripts"
if str(SKILL_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SKILL_SCRIPTS))

from auditkit.app.service import AuditAppService
from auditkit.contracts.errors import InvalidInputError, StorageError
from auditkit.ledger.artifacts import ArtifactManager
from auditkit.ledger.db import get_db_connection, init_database
from auditkit.reporting.generator import ReportGenerator

REPO_ROOT = Path(__file__).resolve().parents[2]
REPO_SKILL_DIR = REPO_ROOT / "skill"

# Bytecode caches are an interpreter artifact, not audit run data.
EXCLUDED_DIR_NAMES = {"__pycache__"}
EXCLUDED_SUFFIXES = {".pyc"}


def dir_snapshot(root: Path) -> dict:
    """Map relpath -> sha256 for every regular file under root."""
    import hashlib

    snapshot = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIR_NAMES]
        for name in filenames:
            if os.path.splitext(name)[1] in EXCLUDED_SUFFIXES:
                continue
            p = Path(dirpath) / name
            rel = str(p.relative_to(root))
            snapshot[rel] = hashlib.sha256(p.read_bytes()).hexdigest()
    return snapshot


def file_set(root: Path) -> set:
    """Relative path set of all regular files under root."""
    return set(dir_snapshot(root).keys())


class SkillIsolationTestBase(unittest.TestCase):

    def setUp(self):
        os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
        self.temp_dir = Path(tempfile.mkdtemp(prefix="skill-iso-"))
        # Copy the skill payload into the tempdir: audit runs touch the copy,
        # never the real repo skill tree.
        self.skill_dir = self.temp_dir / "skill"
        shutil.copytree(REPO_SKILL_DIR, self.skill_dir)

        # Minimal synthetic target: a couple of small fixture files that carry
        # real source/sink signals so the plan produces hunt units.
        fixture_app = REPO_ROOT / "tests" / "fixtures" / "pyapp" / "app"
        self.target_dir = self.temp_dir / "target" / "app"
        shutil.copytree(fixture_app, self.target_dir)

    def tearDown(self):
        os.environ.pop("PYTHONDONTWRITEBYTECODE", None)
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # ------------------------------------------------------------ lifecycle
    def make_config(self, run_dir: Path) -> dict:
        return {
            "schema_version": "1.0",
            "target": str(self.target_dir),
            "run_dir": str(run_dir),
            "report_language": "en",
            "profile": "standard",
            "scope": {"include": ["*.py"], "exclude": []},
            "budgets": [{
                "schema_version": "1.0",
                "dimension": "tasks",
                "mode": "enforced",
                "limit": 20,
                "settled": 0,
                "reserved": 0,
                "unit": "tasks",
                "availability": "exact",
            }],
            "safety_acceptance": {
                "allow_unverified_execution": False,
                "allow_unverified_network": False,
                "allow_unverified_write": False,
                "user_approved": True,
            },
        }

    def run_full_lifecycle(self, run_dir: Path) -> dict:
        """Full audit lifecycle against the copied skill; returns run facts."""
        app = AuditAppService(self.skill_dir)
        config = self.make_config(run_dir)
        prep = app.prepare(str(self.target_dir), str(run_dir), config)
        run_id = prep["run_id"]
        app.activate(run_id, run_dir)

        # --- hunt pass -----------------------------------------------------
        claims = app.next(run_id, run_dir, batch_size=50)
        self.assertTrue(claims)
        hunt_task_ids = []
        for claim in claims:
            hunt_task_ids.append(claim["task_id"])
            app.start(run_dir, claim)
            worker_result = {
                "schema_version": "1.0",
                "task_id": claim["task_id"],
                "attempt_id": claim["attempt_id"],
                "kind": "hunt",
                "coverage": [{
                    "schema_version": "1.0",
                    "snapshot_id": prep["snapshot_id"],
                    "unit_id": claim["spec"]["unit"]["unit_id"],
                    "dimension": "observed_read",
                    "source": "worker",
                    "ranges": [{"path": "app/handlers/upload.py", "line_start": 1, "line_end": 3}],
                    "confidence": "exact",
                }],
                "records": [{
                    "schema_version": "1.0",
                    "candidate_id": "cand-iso-01",
                    "issue": "iso-01",
                    "source": {"path": "app/handlers/upload.py", "line": 2, "symbol": "handle", "kind": "request_body", "control": "request['body']"},
                    "sink": {"path": "app/storage/state.py", "line": 2, "symbol": "persist", "kind": "sink", "effect": "unvalidated payload persisted"},
                    "steps": [
                        {"path": "app/handlers/upload.py", "line": 2, "role": "source", "note": "raw request body"},
                        {"path": "app/storage/state.py", "line": 2, "role": "sink", "note": "persist without validation"},
                    ],
                    "guard_analysis": "No validation on the upload path",
                    "impact_claim": "Unvalidated payload persistence",
                    "open_questions": [],
                    "provenance": {"hunt_tasks": [claim["task_id"]]},
                }],
                "overflow": [],
            }
            app.submit(run_dir, claim, worker_result, "digest-iso-hunt")

        # --- verify pass (verify tasks were enqueued by the hunt submit) ---
        while True:
            claims = app.next(run_id, run_dir, batch_size=50)
            if not claims:
                break
            for claim in claims:
                app.start(run_dir, claim)
                worker_result = {
                    "schema_version": "1.0",
                    "task_id": claim["task_id"],
                    "attempt_id": claim["attempt_id"],
                    "kind": "verify",
                    "coverage": [],
                    "records": [{
                        "schema_version": "1.0",
                        "finding_id": "F-ISO-001",
                        "candidate_refs": ["cand-iso-01"],
                        "verdict": "unverified",
                        "evidence_level": "E1",
                        "unverified_reason": "deployment facts unavailable in static-only run",
                        "provenance": {
                            "hunt_tasks": list(hunt_task_ids),
                            "verify_tasks": [claim["task_id"]],
                        },
                    }],
                    "overflow": [],
                }
                app.submit(run_dir, claim, worker_result, "digest-iso-verify")

        fin = app.finalize(run_id, run_dir)
        return {
            "run_id": run_id,
            "snapshot_id": prep["snapshot_id"],
            "finalize": fin,
            "app": app,
        }


class TestRunDataNotWrittenToSkill(SkillIsolationTestBase):
    """Scenario 1 (DSR-046 / SWR-016): run data never written back to skill."""

    def test_full_lifecycle_leaves_skill_payload_untouched(self):
        baseline_snapshot = dir_snapshot(self.skill_dir)
        baseline_files = set(baseline_snapshot.keys())
        run_dir = self.temp_dir / "run"
        run_id = self.run_full_lifecycle(run_dir)["run_id"]
        self.assertTrue(run_id.startswith("run-"))

        after_snapshot = dir_snapshot(self.skill_dir)
        self.assertEqual(
            baseline_files,
            set(after_snapshot.keys()),
            "skill payload directory gained or lost files during the audit run",
        )
        changed = [p for p in baseline_files if baseline_snapshot[p] != after_snapshot[p]]
        self.assertEqual(
            changed, [],
            f"skill payload files were modified during the audit run: {changed}",
        )

        # No run identifier or run dossier path may appear inside the skill
        # payload either (not even inside an unchanged file).
        for rel in sorted(baseline_files):
            p = self.skill_dir / rel
            try:
                text = p.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue  # binary asset; covered by the hash check above
            self.assertNotIn(run_id, text, f"run_id leaked into skill file {rel}")
            self.assertNotIn(str(run_dir), text, f"run directory path leaked into skill file {rel}")


class TestNewRunDoesNotReadOldRun(SkillIsolationTestBase):
    """Scenario 2 (DSR-046 / SWR-016): a fresh run never references a prior run."""

    def test_run_b_is_independent_of_run_a(self):
        run_dir_a = self.temp_dir / "run_a"
        facts_a = self.run_full_lifecycle(run_dir_a)
        run_id_a = facts_a["run_id"]

        run_dir_b = self.temp_dir / "run_b"
        facts_b = self.run_full_lifecycle(run_dir_b)
        run_id_b = facts_b["run_id"]
        self.assertNotEqual(run_id_a, run_id_b)

        # 1. No event (or any other row) in B's ledger references run A.
        db_b = sqlite3.connect(f"file:{run_dir_b / 'events.db'}?mode=ro", uri=True)
        try:
            db_b.row_factory = sqlite3.Row
            tables = [r[0] for r in db_b.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()]
            hits = []
            for table in tables:
                for row in db_b.execute(f"SELECT * FROM [{table}]").fetchall():
                    serialized = json.dumps(
                        [dict(row).get(k) for k in row.keys()], default=str, ensure_ascii=False
                    )
                    if run_id_a in serialized:
                        hits.append(table)
            self.assertEqual(
                hits, [],
                f"run B ledger references the previous run's id in tables: {sorted(set(hits))}",
            )
            # B's own run id must of course be present (sanity check that the
            # scan above is actually reading rows).
            runs_rows = db_b.execute("SELECT run_id FROM runs").fetchall()
            self.assertEqual([r["run_id"] for r in runs_rows], [run_id_b])
        finally:
            db_b.close()

        # 2. B's snapshot manifest is derived from B's own snapshot, not copied
        #    from A: the snapshot_id must be the content hash of B's own
        #    manifest root_hash, independently recomputed.
        manifest_b = json.loads((run_dir_b / "snapshot" / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest_b["snapshot_id"], "snp-" + manifest_b["root_hash"][:12])
        self.assertTrue(manifest_b["root_hash"])
        # Manifest paths are target-relative; no absolute dossier reference.
        self.assertNotIn(str(run_dir_a), json.dumps(manifest_b))

        # 3. No handle from B into A: every file in B's dossier resolves inside
        #    B (no symlinks escaping into the previous run), and B's file
        #    manifest is mutually exclusive with A's dossier contents.
        for p in run_dir_b.rglob("*"):
            if p.is_symlink():
                self.fail(f"run B contains a symlink: {p}")
            if p.is_file():
                self.assertTrue(
                    str(p.resolve()).startswith(str(run_dir_b.resolve())),
                    f"run B file resolves outside its own dossier: {p}",
                )
        b_relpaths = file_set(run_dir_b)
        self.assertNotIn(str(run_dir_a), repr(sorted(b_relpaths)))
        # Content-level check: no file inside B mentions A's dossier path.
        for rel in sorted(b_relpaths):
            p = run_dir_b / rel
            try:
                text = p.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            self.assertNotIn(str(run_dir_a), text, f"stale reference to run A found in {rel}")


class TestExportFailureClosed(SkillIsolationTestBase):
    """Scenario 3 (DSR-046 / SWR-016 / DSR-045): export failures fail closed."""

    def _make_generator(self, run_dir: Path) -> ReportGenerator:
        db_path = run_dir / "events.db"
        init_database(db_path)
        conn = get_db_connection(db_path)
        run_id = "run-export-test"
        conn.execute(
            """
            INSERT INTO runs (run_id, snapshot_id, state, schema_version, skill_version, knowledge_version, config_ref, revision, created_at, updated_at)
            VALUES (?, 'snp-01', 'finalizing', '1.0', '0.1.0', '1.0', 'config.json', 1, '2026-11-14T00:00:00Z', '2026-11-14T00:00:00Z')
            """,
            (run_id,),
        )
        art_mgr = ArtifactManager(run_dir, conn)
        self.addCleanup(conn.close)
        return ReportGenerator(run_id, "snp-01", "complete", art_mgr)

    def _assert_no_residuals(self, run_dir: Path):
        report_dir = run_dir / "report"
        if report_dir.exists():
            leftovers = sorted(p.name for p in report_dir.iterdir())
            self.assertEqual(
                leftovers, [],
                f"half-written report artifacts left behind: {leftovers}",
            )
        self.assertFalse((report_dir / "skill-review.json").exists())

    def test_export_write_failure_raises_and_leaves_no_half_files(self):
        run_dir = self.temp_dir / "run_export_fail"
        run_dir.mkdir()
        generator = self._make_generator(run_dir)

        def failing_fsync(fd):
            raise OSError("simulated disk failure during export")

        with mock.patch("auditkit.reporting.generator.os.fsync", side_effect=failing_fsync):
            with self.assertRaises(StorageError):
                generator.generate_all(
                    [], {"total_files": 0}, {"total_tasks": 0, "retries": 0}, [],
                    export_skill_review=True,
                )

        # No staged temp file and no published export survived the failure.
        self._assert_no_residuals(run_dir)

    def test_export_whitelist_rejects_foreign_stats_and_writes_nothing(self):
        run_dir = self.temp_dir / "run_export_reject"
        run_dir.mkdir()
        self._make_generator(run_dir)

        # run_stats carries keys outside the DSR-045/SWR-016 export whitelist;
        # the whitelist must reject them fail-closed before anything reaches disk.
        foreign_export = {
            "schema_version": "1.0",
            "run_stats": {"total_tasks": 3, "finding_titles": ["t"]},
        }
        with self.assertRaises(InvalidInputError) as ctx:
            ReportGenerator._enforce_export_whitelist(foreign_export)
        self.assertIn("run_stats", str(ctx.exception))

        # Nested and non-scalar violations are rejected as well.
        with self.assertRaises(InvalidInputError):
            ReportGenerator._enforce_export_whitelist({
                "schema_version": "1.0",
                "run_summary": {"run_state": "complete", "finding_paths": ["a.py"]},
            })
        with self.assertRaises(InvalidInputError):
            ReportGenerator._enforce_export_whitelist({
                "schema_version": "1.0",
                "run_summary": {"run_state": {"nested": "object"}},
            })

        self._assert_no_residuals(run_dir)

    def test_export_injected_foreign_run_stats_fail_closed(self):
        """run_stats carrying a non-whitelisted key must abort before staging."""
        run_dir = self.temp_dir / "run_export_inject"
        run_dir.mkdir()
        generator = self._make_generator(run_dir)

        real_enforce = ReportGenerator._enforce_export_whitelist

        def tampered_enforce(export):
            # Simulate the self-review stats feeding a non-whitelisted key
            # into the portable export before the whitelist runs.
            export["run_stats"] = {"total_tasks": 3, "finding_titles": ["t"]}
            return real_enforce(export)

        with mock.patch.object(
            ReportGenerator, "_enforce_export_whitelist", staticmethod(tampered_enforce)
        ):
            with self.assertRaises(InvalidInputError) as ctx:
                generator.generate_all(
                    [], {"total_files": 0}, {"total_tasks": 0, "retries": 0}, [],
                    export_skill_review=True,
                )
        self.assertIn("run_stats", str(ctx.exception))
        self._assert_no_residuals(run_dir)


if __name__ == "__main__":
    unittest.main()
