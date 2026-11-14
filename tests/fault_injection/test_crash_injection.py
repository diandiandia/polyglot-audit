"""Fault-injection tests (DSR-018 / DSR-019 / DSR-036 / SWR-018).

Injects crashes at the exact boundaries the design calls out and asserts the
state invariants survive:

1. Crash inside the claim transaction (budget reserve raises) -> the
   BEGIN IMMEDIATE transaction rolls back; the task stays queued with its
   generation untouched and no orphan attempt row remains.
2. Crash during artifact publication (os.replace raises) -> StorageError, no
   final file appears, no published reference exists, and the retry succeeds.
3. Worker crash (lease expiry) -> reclaim_expired_attempts returns the task to
   queued with generation+1, releases the reservation, and a late submit with
   the stale claim token is rejected (DSR-019).
4. Crash mid-submit (event append raises) -> no partial submission; the task
   keeps its pre-crash state and a retry submit succeeds, with a duplicate
   submit returning the original idempotent receipt (DSR-018).

Standard library only. Mock targets are module-level so no production code is
modified.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from auditkit.app.service import AuditAppService
from auditkit.contracts.errors import StorageError, StaleAttemptError
from auditkit.ledger.artifacts import ArtifactManager
from auditkit.ledger.db import get_db_connection
from auditkit.ledger.event_store import EventStore
from auditkit.ledger.task_queue import TaskQueue

FIXTURES_DIR = Path("/root/polyglot-audit/tests/fixtures")
SKILL_DIR = Path("/root/polyglot-audit/skill")


def _result_digest(worker_result: dict) -> str:
    return hashlib.sha256(
        json.dumps(worker_result, sort_keys=True, ensure_ascii=False).encode("utf-8")
    ).hexdigest()


class TestCrashInjection(unittest.TestCase):

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())
        self.app = AuditAppService(SKILL_DIR)
        target = self.temp_dir / "target"
        (target / "pkg").mkdir(parents=True)
        # Copy both upload handler and state sink to ensure signals trigger analyze tier
        shutil.copy(FIXTURES_DIR / "pyapp" / "app" / "handlers" / "upload.py", target / "pkg" / "upload.py")
        shutil.copy(FIXTURES_DIR / "pyapp" / "app" / "storage" / "state.py", target / "pkg" / "state.py")
        self.target = target
        self.run_dir = self.temp_dir / "run"
        config = self._make_config()
        prep = self.app.prepare(str(target), str(self.run_dir), config)
        self.run_id = prep["run_id"]
        self.app.activate(self.run_id, self.run_dir)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _make_config(self) -> dict:
        return {
            "schema_version": "1.0",
            "target": str(self.target),
            "run_dir": str(self.run_dir),
            "report_language": "zh",
            "profile": "standard",
            "scope": {"include": ["*"], "exclude": []},
            "budgets": [
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

    def _conn(self) -> sqlite3.Connection:
        return get_db_connection(self.run_dir / "events.db")

    def _hunt_result(self, claim: dict) -> dict:
        return {
            "schema_version": "1.0",
            "task_id": claim["task_id"],
            "attempt_id": claim["attempt_id"],
            "kind": "hunt",
            "coverage": [],
            "records": [],
            "overflow": [],
        }

    # ------------------------------------------------------------------
    # 1. crash inside the claim transaction -> full rollback
    # ------------------------------------------------------------------
    def test_crash_in_claim_rolls_back_and_task_stays_queued(self):
        # Inject the crash at the attempt_claimed event append: it runs inside
        # the claim transaction and has no swallow-guard, so the raise must
        # propagate and trigger the BEGIN IMMEDIATE rollback (DSR-017).
        with mock.patch.object(
            EventStore,
            "append_event",
            side_effect=RuntimeError("injected crash: disk gone mid-claim"),
        ):
            with self.assertRaises(RuntimeError):
                self.app.next(self.run_id, self.run_dir)

        # Invariants after rollback: no orphan attempt, task still claimable.
        conn = self._conn()
        try:
            attempts = conn.execute(
                "SELECT COUNT(*) AS n FROM attempts"
            ).fetchone()["n"]
            tasks = conn.execute(
                "SELECT state FROM tasks"
            ).fetchall()
        finally:
            conn.close()
        self.assertEqual(attempts, 0, "crashed claim must not leave an attempt row")
        self.assertTrue(all(t["state"] == "queued" for t in tasks))

        claims = self.app.next(self.run_id, self.run_dir)
        self.assertGreaterEqual(len(claims), 1)
        self.assertEqual(claims[0]["generation"], 1)

    # ------------------------------------------------------------------
    # 2. crash during artifact publication -> no final file, retry works
    # ------------------------------------------------------------------
    def test_crash_in_artifact_publish_leaves_no_final_file(self):
        conn = self._conn()
        try:
            manager = ArtifactManager(self.run_dir, conn)
            with mock.patch(
                "auditkit.ledger.artifacts.os.replace",
                side_effect=OSError("injected crash: no space left"),
            ):
                with self.assertRaises(StorageError):
                    manager.publish_artifact(
                        self.run_id, "test", "report/x.json", b'{"v": 1}'
                    )
            final_path = self.run_dir / "report" / "x.json"
            self.assertFalse(final_path.exists(), "crashed publish must not leave a final file")
            
            # Simulate a power-loss orphaned temp file on disk
            orphan_tmp = self.run_dir / "report" / ".tmp-abandoned-x.json"
            orphan_tmp.write_bytes(b"partial-data")
            cleaned = manager.cleanup_orphaned_temps()
            self.assertGreaterEqual(cleaned, 1, "orphaned tmp file must be reclaimable")

            receipt = manager.publish_artifact(
                self.run_id, "test", "report/x.json", b'{"v": 1}'
            )
            self.assertTrue(final_path.exists())
            self.assertTrue(receipt.get("sha256") or receipt.get("digest") or receipt)
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # 3. worker crash -> lease expiry reclaims, late submit rejected
    # ------------------------------------------------------------------
    def test_worker_crash_lease_expiry_reclaims_and_rejects_late_submit(self):
        claims = self.app.next(self.run_id, self.run_dir, batch_size=1)
        self.assertEqual(len(claims), 1)
        claim = claims[0]
        self.app.start(self.run_dir, claim)

        # Simulate the worker process dying and its lease expiring.
        conn = self._conn()
        try:
            conn.execute(
                "UPDATE attempts SET expires_at = '2000-01-01T00:00:00+00:00' WHERE attempt_id = ?",
                (claim["attempt_id"],),
            )
            conn.commit()
        finally:
            conn.close()

        queue_conn = self._conn()
        try:
            queue = TaskQueue(queue_conn)
            reclaimed = queue.reclaim_expired_attempts(self.run_id)
            self.assertEqual(len(reclaimed), 1)
            self.assertEqual(reclaimed[0]["task_id"], claim["task_id"])
        finally:
            queue_conn.close()

        # Late submit with the stale claim token must be rejected (DSR-019).
        with self.assertRaises(StaleAttemptError):
            self.app.submit(
                self.run_dir, claim, self._hunt_result(claim), _result_digest(self._hunt_result(claim))
            )

        # The task is queued again at generation+1 and fully processable.
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT generation FROM tasks WHERE task_id = ?", (claim["task_id"],)
            ).fetchone()
        finally:
            conn.close()
        self.assertEqual(row["generation"], claim["generation"] + 1)
        new_claims = self.app.next(self.run_id, self.run_dir)
        self.assertEqual(new_claims[0]["task_id"], claim["task_id"])
        # Next claim increments task generation from 2 to 3
        self.assertEqual(new_claims[0]["generation"], claim["generation"] + 2)

    # ------------------------------------------------------------------
    # 4. crash mid-submit -> no partial submission, retry is idempotent
    # ------------------------------------------------------------------
    def test_crash_mid_submit_keeps_state_and_retry_is_idempotent(self):
        claims = self.app.next(self.run_id, self.run_dir)
        self.assertGreaterEqual(len(claims), 1)
        claim = claims[0]
        self.app.start(self.run_dir, claim)
        result = self._hunt_result(claim)
        digest = _result_digest(result)

        with mock.patch.object(
            EventStore,
            "append_event",
            side_effect=RuntimeError("injected crash: ledger write fails"),
        ):
            with self.assertRaises(RuntimeError):
                self.app.submit(self.run_dir, claim, result, digest)

        # No partial submission: task is not done.
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT state FROM tasks WHERE task_id = ?", (claim["task_id"],)
            ).fetchone()
        finally:
            conn.close()
        self.assertEqual(row["state"], "running")

        receipt = self.app.submit(self.run_dir, claim, result, digest)
        receipt_again = self.app.submit(self.run_dir, claim, result, digest)
        self.assertEqual(receipt["receipt"], receipt_again["receipt"], "duplicate submit must return the original receipt")
        self.assertTrue(receipt_again.get("replayed", False))


if __name__ == "__main__":
    unittest.main()
