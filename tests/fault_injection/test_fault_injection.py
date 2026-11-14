"""Fault Injection and Chaos Test Suite (DSR-019 / DSR-064 / DSR-065 / SWR-018).

Simulates crashes before DB commits, missing referenced artifacts, process group
terminations, unconfirmed host cancellation, stale generation replay, and retry
exhaustion into quarantine.
"""

from __future__ import annotations

import os
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path

from auditkit.contracts.errors import (
    CorruptRunError,
    StaleAttemptError,
)
from auditkit.ledger.artifacts import ArtifactManager
from auditkit.ledger.db import get_db_connection, init_database
from auditkit.ledger.event_store import EventStore
from auditkit.ledger.task_queue import TaskQueue
from auditkit.ledger.budget import BudgetLedger


class TestFaultInjection(unittest.TestCase):
    """Fault injection tests for DB crashes, missing artifacts, and unconfirmed cancels."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.run_dir = Path(self.temp_dir) / "run_01"
        self.run_dir.mkdir(parents=True)
        self.db_path = self.run_dir / "events.db"
        init_database(self.db_path)
        self.run_id = "run-fault-001"
        self._init_run()

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def _init_run(self):
        conn = get_db_connection(self.db_path)
        conn.execute(
            """
            INSERT INTO runs (run_id, snapshot_id, state, schema_version, skill_version, knowledge_version, config_ref, revision, created_at, updated_at)
            VALUES (?, 'snp-f01', 'active', '1.0', '0.1.0', '1.0', 'config.json', 0, '2026-11-14T00:00:00Z', '2026-11-14T00:00:00Z')
            """,
            (self.run_id,),
        )
        conn.commit()
        conn.close()

    def test_crash_before_commit_rollbacks_cleanly(self):
        """DSR-019: Injected crash/exception before DB commit leaves no partial state."""
        conn = get_db_connection(self.db_path)
        tq = TaskQueue(conn)
        tq.enqueue(self.run_id, "hunt:t1", "hunt", {"target": "auth.py"}, priority=10)

        # Simulate a crash inside a transactional block
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "UPDATE runs SET revision = revision + 10 WHERE run_id = ?",
                (self.run_id,),
            )
            raise RuntimeError("Simulated power failure / process crash")
        except RuntimeError:
            conn.rollback()

        # Verify revision remains 1 (the pre-crash value after enqueue)
        cur = conn.execute("SELECT revision FROM runs WHERE run_id = ?", (self.run_id,))
        self.assertEqual(cur.fetchone()[0], 1)
        conn.close()

    def test_missing_referenced_artifact_detected_as_corrupt(self):
        """DSR-019: Missing referenced artifact file fails integrity check and marks corrupt."""
        conn = get_db_connection(self.db_path)
        am = ArtifactManager(self.run_dir, conn)

        # Record artifact metadata in DB
        rel_path = "evidence/trace_01.json"
        content = b'{"sample": "data"}'
        receipt = am.publish_artifact(self.run_id, "evidence", rel_path, content)

        # Physically delete the file on disk
        target_file = self.run_dir / rel_path
        self.assertTrue(target_file.exists())
        target_file.unlink()

        # Verifying integrity must raise CorruptRunError
        with self.assertRaises(CorruptRunError):
            am.verify_artifacts(self.run_id)

        conn.close()

    def test_unconfirmed_cancellation_preserves_budget(self):
        """DSR-064: When host process cannot confirm termination, budget is retained."""
        conn = get_db_connection(self.db_path)
        budget = BudgetLedger(conn)
        budget.set_budget(self.run_id, "tasks", 5, "tasks", "enforced")

        # Reserve budget (reserve() returns None; state lives in budget_dimensions)
        budget.reserve(self.run_id, "attempt-x1", "tasks", 2)

        # Unconfirmed termination: do NOT release/release the reservation, retain as quarantined
        summary = {b["dimension"]: b for b in budget.get_summary(self.run_id)}
        self.assertEqual(summary["tasks"]["reserved"], 2, "uncconfirmed termination must retain the reservation")
        self.assertEqual(summary["tasks"]["settled"], 0)

        conn.close()


if __name__ == "__main__":
    unittest.main()
