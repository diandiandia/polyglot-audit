"""Concurrency tests for atomic claim and budget reservation (DSR-017 / DSR-020).

Each worker uses its own SQLite connection against the same WAL database and
races for the same task / last budget unit. BEGIN IMMEDIATE transactions must
guarantee that at most one claim and at most one reservation of the final unit
succeed.
"""

import shutil
import tempfile
import threading
import unittest
from pathlib import Path

from auditkit.contracts.errors import BudgetExhaustedError
from auditkit.ledger.budget import BudgetLedger
from auditkit.ledger.db import get_db_connection, init_database
from auditkit.ledger.task_queue import TaskQueue

NUM_WORKERS = 8


class TestAtomicClaimAndReserve(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "events.db"
        init_database(self.db_path)
        conn = get_db_connection(self.db_path)
        self.run_id = "run-race-1"
        conn.execute(
            """
            INSERT INTO runs (run_id, snapshot_id, state, schema_version, skill_version, knowledge_version, config_ref, revision, created_at, updated_at)
            VALUES (?, 'snp-001', 'active', '1.0', '0.1.0', '1.0', 'config.json', 0, '2026-11-14T00:00:00Z', '2026-11-14T00:00:00Z')
            """,
            (self.run_id,),
        )
        conn.commit()
        conn.close()

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def _run_workers(self, worker_fn):
        """Run worker_fn(worker_index) concurrently in NUM_WORKERS threads."""
        barrier = threading.Barrier(NUM_WORKERS)
        results = [None] * NUM_WORKERS
        errors = [None] * NUM_WORKERS

        def wrapper(idx: int) -> None:
            conn = get_db_connection(self.db_path)
            try:
                barrier.wait(timeout=10)
                results[idx] = worker_fn(conn, idx)
            except Exception as e:  # noqa: BLE001 - collected for assertions
                errors[idx] = e
            finally:
                conn.close()

        threads = [threading.Thread(target=wrapper, args=(i,)) for i in range(NUM_WORKERS)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        return results, errors

    def test_concurrent_claim_same_task_single_winner(self):
        """Multiple workers racing for one queued task: at most one claim succeeds."""
        setup_conn = get_db_connection(self.db_path)
        queue = TaskQueue(setup_conn)
        queue.enqueue(self.run_id, "hunt:unit1", "hunt", {"unit": "u1"})
        setup_conn.close()

        def worker(conn, idx):
            q = TaskQueue(conn)
            return q.claim(self.run_id, batch_size=1, worker_id=f"worker-{idx}")

        results, errors = self._run_workers(worker)

        # No unexpected errors (e.g. database lock timeouts)
        for i, e in enumerate(errors):
            self.assertIsNone(e, f"worker {i} raised unexpected error: {e}")

        claimed_counts = [len(r) for r in results]
        self.assertEqual(sum(claimed_counts), 1, f"exactly one claim must win, got {claimed_counts}")

        # Database holds exactly one attempt and the task is claimed exactly once
        conn = get_db_connection(self.db_path)
        attempts = conn.execute("SELECT count(*) AS c FROM attempts").fetchone()["c"]
        tasks = conn.execute("SELECT count(*) AS c FROM tasks WHERE state = 'claimed'").fetchone()["c"]
        conn.close()
        self.assertEqual(attempts, 1)
        self.assertEqual(tasks, 1)

    def test_concurrent_reserve_last_unit_single_winner(self):
        """Multiple workers racing for the last budget unit: at most one reserve succeeds."""
        setup_conn = get_db_connection(self.db_path)
        budget = BudgetLedger(setup_conn)
        budget.set_budget(self.run_id, "tasks", limit_val=1, unit="tasks", mode="enforced")
        setup_conn.close()

        def worker(conn, idx):
            b = BudgetLedger(conn)
            b.reserve(self.run_id, f"att-{idx}", "tasks", 1)
            return True

        results, errors = self._run_workers(worker)

        successes = sum(1 for r in results if r)
        exhausted = sum(1 for e in errors if isinstance(e, BudgetExhaustedError))
        self.assertEqual(successes, 1, f"exactly one reserve must win, got {successes}")
        self.assertEqual(exhausted, NUM_WORKERS - 1)

        # Other error types are unacceptable
        for i, e in enumerate(errors):
            if e is not None:
                self.assertIsInstance(e, BudgetExhaustedError, f"worker {i} raised unexpected error: {e}")

        conn = get_db_connection(self.db_path)
        reserved = conn.execute(
            "SELECT reserved FROM budget_dimensions WHERE run_id = ? AND dimension = 'tasks'",
            (self.run_id,),
        ).fetchone()["reserved"]
        reservations = conn.execute("SELECT count(*) AS c FROM reservations").fetchone()["c"]
        conn.close()
        self.assertEqual(reserved, 1)
        self.assertEqual(reservations, 1)


if __name__ == "__main__":
    unittest.main()
