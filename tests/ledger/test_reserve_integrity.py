"""Reserve-integrity regression tests (SWR-018 / SWR-019).

Two honesty gaps in the claim/reserve path, each pinned here:

- TaskQueue.claim swallowed non-budget reservation exceptions silently
  (no event, no report, loop just stopped). The failure must be recorded
  as a ``reserve_failed`` event with its reason and attempt context, and
  the task must stay queued (SWR-018 invariant).
- BudgetLedger.reserve skipped dimensions with no budget row silently
  (no reservation, no tracking, no degradation record). SWR-019 requires
  a dimension that cannot be constrained to be EXPLICITLY degraded: the
  first reserve on it now creates a mode='unavailable' row, later
  reserves stay no-ops against it, and get_summary reports the
  dimension honestly instead of omitting it.

Standard library only; runnable from unittest discovery.
"""

import json
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from auditkit.ledger.budget import BudgetLedger
from auditkit.ledger.db import get_db_connection, init_database
from auditkit.ledger.task_queue import TaskQueue


class ReserveIntegrityBase(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="reserve-integrity-")
        self.db_path = Path(self.temp_dir) / "events.db"
        init_database(self.db_path)
        self.conn = get_db_connection(self.db_path)
        self.run_id = "run-reserve-integrity"
        self.conn.execute(
            """
            INSERT INTO runs (run_id, snapshot_id, state, schema_version, skill_version, knowledge_version, config_ref, revision, created_at, updated_at)
            VALUES (?, 'snp-001', 'active', '1.0', '0.1.0', '1.0', 'config.json', 0, '2026-11-14T00:00:00Z', '2026-11-14T00:00:00Z')
            """,
            (self.run_id,),
        )
        self.conn.commit()

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.temp_dir, ignore_errors=True)


class TestClaimRecordsReserveFailure(ReserveIntegrityBase):
    """SWR-018: a non-budget reserve failure is recorded, never swallowed."""

    def test_non_budget_reserve_error_appends_reserve_failed_event(self):
        queue = TaskQueue(self.conn)
        queue.enqueue(self.run_id, "hunt:unit1", "hunt", {"unit": "u1"})

        def broken_reserve(*args, **kwargs):
            raise RuntimeError("ledger storage unavailable")

        with mock.patch.object(queue.budget_ledger, "reserve", broken_reserve):
            claims = queue.claim(self.run_id, batch_size=3, worker_id="worker-7")

        # The loop stayed alive and handed out nothing.
        self.assertEqual(claims, [])

        # The task is untouched: still queued, no attempt row exists.
        task = self.conn.execute(
            "SELECT task_id, state, generation FROM tasks WHERE task_key = 'hunt:unit1'"
        ).fetchone()
        self.assertEqual(task["state"], "queued")
        attempts = self.conn.execute("SELECT COUNT(*) AS c FROM attempts").fetchone()["c"]
        self.assertEqual(attempts, 0)

        # The failure is on the record with its reason and attempt context.
        events = queue.event_store.get_events(self.run_id)
        failures = [e for e in events if e["event_type"] == "reserve_failed"]
        self.assertEqual(len(failures), 1, f"expected one reserve_failed event: {events}")
        recorded = failures[0]
        self.assertEqual(recorded["actor"], "worker-7")
        payload = recorded["payload"]
        self.assertEqual(payload["dimension"], "tasks")
        self.assertIn("ledger storage unavailable", payload["reason"])
        self.assertEqual(payload["error"], "RuntimeError")
        self.assertEqual(payload["blocked_task_id"], task["task_id"])
        self.assertTrue(str(payload["attempt_id"]).startswith("att-"))

    def test_reserve_failed_does_not_poison_later_claims(self):
        """After the recorded failure the queue still works: a healthy
        reserve lets the same task be claimed normally."""
        queue = TaskQueue(self.conn)
        queue.enqueue(self.run_id, "hunt:unit1", "hunt", {"unit": "u1"})

        def broken_reserve(*args, **kwargs):
            raise RuntimeError("transient ledger fault")

        with mock.patch.object(queue.budget_ledger, "reserve", broken_reserve):
            queue.claim(self.run_id, batch_size=1)

        claim = queue.claim(self.run_id, batch_size=1)
        self.assertEqual(len(claim), 1)
        self.assertEqual(claim[0]["task_id"], queue.conn.execute(
            "SELECT task_id FROM tasks WHERE task_key = 'hunt:unit1'"
        ).fetchone()["task_id"])


class TestUnbudgetedDimensionExplicitDegradation(ReserveIntegrityBase):
    """SWR-019: an unconstrained dimension is explicitly degraded, not skipped."""

    def test_reserve_without_budget_row_creates_unavailable_degradation(self):
        budget = BudgetLedger(self.conn)
        # No set_budget for 'tokens' anywhere.
        budget.reserve(self.run_id, "att-degraded", "tokens", 3)

        row = self.conn.execute(
            "SELECT mode, limit_val, settled, reserved, unit FROM budget_dimensions "
            "WHERE run_id = ? AND dimension = 'tokens'",
            (self.run_id,),
        ).fetchone()
        self.assertIsNotNone(row, "degradation row must exist")
        self.assertEqual(row["mode"], "unavailable")
        self.assertEqual(row["limit_val"], 0)
        self.assertEqual(row["reserved"], 0)
        self.assertEqual(row["settled"], 0)

        # A no-op reserve records no reservation against the dimension.
        reservations = self.conn.execute(
            "SELECT COUNT(*) AS c FROM reservations WHERE attempt_id = 'att-degraded'"
        ).fetchone()["c"]
        self.assertEqual(reservations, 0)

    def test_later_reserves_stay_noop_against_degraded_dimension(self):
        budget = BudgetLedger(self.conn)
        budget.reserve(self.run_id, "att-1", "tokens", 3)
        budget.reserve(self.run_id, "att-2", "tokens", 2)

        row = self.conn.execute(
            "SELECT mode, reserved FROM budget_dimensions "
            "WHERE run_id = ? AND dimension = 'tokens'",
            (self.run_id,),
        ).fetchone()
        self.assertEqual(row["mode"], "unavailable")
        self.assertEqual(row["reserved"], 0, "unavailable dimension must stay a no-op")

    def test_summary_reports_degraded_dimension(self):
        budget = BudgetLedger(self.conn)
        budget.reserve(self.run_id, "att-1", "tokens", 3)
        summary = {b["dimension"]: b for b in budget.get_summary(self.run_id)}
        self.assertIn("tokens", summary, "degraded dimension must not vanish from the summary")
        entry = summary["tokens"]
        self.assertEqual(entry["mode"], "unavailable")
        self.assertEqual(entry["availability"], "unavailable")
        self.assertEqual(entry["limit"], 0)
        self.assertIsNone(entry["value"])

    def test_claim_without_budget_config_degrades_tasks_dimension(self):
        """Integration: a run with no budget config claims tasks normally,
        and the tasks dimension lands in the summary as unavailable."""
        queue = TaskQueue(self.conn)
        queue.enqueue(self.run_id, "hunt:unit1", "hunt", {"unit": "u1"})
        claim = queue.claim(self.run_id, batch_size=1)
        self.assertEqual(len(claim), 1, "unbudgeted tasks dimension must not block dispatch")

        summary = {
            b["dimension"]: b for b in queue.budget_ledger.get_summary(self.run_id)
        }
        self.assertIn("tasks", summary)
        self.assertEqual(summary["tasks"]["mode"], "unavailable")

    def test_enforced_dimension_still_refuses_and_tracks(self):
        """The degradation path must not weaken enforcement: an enforced
        dimension keeps refusing when the limit is breached."""
        budget = BudgetLedger(self.conn)
        from auditkit.contracts.errors import BudgetExhaustedError

        budget.set_budget(self.run_id, "tasks", limit_val=1, unit="tasks", mode="enforced")
        budget.reserve(self.run_id, "att-a", "tasks", 1)
        with self.assertRaises(BudgetExhaustedError):
            budget.reserve(self.run_id, "att-b", "tasks", 1)
        row = self.conn.execute(
            "SELECT mode, reserved FROM budget_dimensions "
            "WHERE run_id = ? AND dimension = 'tasks'",
            (self.run_id,),
        ).fetchone()
        self.assertEqual(row["mode"], "enforced")
        self.assertEqual(row["reserved"], 1)


if __name__ == "__main__":
    unittest.main()
