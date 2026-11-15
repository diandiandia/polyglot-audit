"""Tests for SQLite ledger, task queue, attempts, idempotency, and budget."""

import shutil
import tempfile
import unittest
from pathlib import Path

from auditkit.contracts.errors import (
    BudgetExhaustedError,
    CorruptRunError,
    HostFailureError,
    IdempotencyConflictError,
    InvalidStateError,
    StaleAttemptError,
    UnsupportedSchemaError,
)
from auditkit.ledger.artifacts import ArtifactManager
from auditkit.ledger.budget import BudgetLedger
from auditkit.ledger.db import check_version_compatibility, get_db_connection, init_database
from auditkit.ledger.event_store import EventStore
from auditkit.ledger.task_queue import TaskQueue
from auditkit.ledger.usage import parse_usage


class TestLedger(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "events.db"
        init_database(self.db_path)
        self.conn = get_db_connection(self.db_path)

        # Seed run
        self.run_id = "run-test-1"
        self.conn.execute(
            """
            INSERT INTO runs (run_id, snapshot_id, state, schema_version, skill_version, knowledge_version, config_ref, revision, created_at, updated_at)
            VALUES (?, 'snp-001', 'active', '1.0', '0.1.0', '1.0', 'config.json', 0, '2026-11-14T00:00:00Z', '2026-11-14T00:00:00Z')
            """,
            (self.run_id,),
        )

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.temp_dir)

    def test_event_store_monotone_revision(self):
        store = EventStore(self.conn)
        rev1 = store.append_event(self.run_id, "test_event_1", "actor", {"k": 1})
        rev2 = store.append_event(self.run_id, "test_event_2", "actor", {"k": 2})

        self.assertEqual(rev1, 1)
        self.assertEqual(rev2, 2)

        events = store.get_events(self.run_id)
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["revision"], 1)
        self.assertEqual(events[1]["revision"], 2)

    def test_task_queue_claim_token_security(self):
        queue = TaskQueue(self.conn)
        t_id = queue.enqueue(self.run_id, "hunt:unit1", "hunt", {"unit": "u1"})

        claims = queue.claim(self.run_id, batch_size=1)
        self.assertEqual(len(claims), 1)
        raw_token = claims[0]["claim_token"]
        att_id = claims[0]["attempt_id"]

        # Check that plain token is NOT stored in the database!
        row = self.conn.execute(
            "SELECT token_digest FROM attempts WHERE attempt_id = ?",
            (att_id,),
        ).fetchone()
        self.assertNotEqual(row["token_digest"], raw_token)
        self.assertEqual(len(row["token_digest"]), 64)

    def test_task_queue_submit_idempotency_and_conflict(self):
        queue = TaskQueue(self.conn)
        queue.enqueue(self.run_id, "hunt:unit1", "hunt", {"unit": "u1"})
        claim = queue.claim(self.run_id, batch_size=1)[0]

        # First submission succeeds
        res1 = queue.submit(
            run_id=self.run_id,
            task_id=claim["task_id"],
            attempt_id=claim["attempt_id"],
            generation=claim["generation"],
            claim_token=claim["claim_token"],
            worker_result={"records": []},
            result_digest="digest-abc",
        )
        self.assertTrue(res1["ok"])
        self.assertFalse(res1["replayed"])

        # Replay with same digest returns existing receipt
        res2 = queue.submit(
            run_id=self.run_id,
            task_id=claim["task_id"],
            attempt_id=claim["attempt_id"],
            generation=claim["generation"],
            claim_token=claim["claim_token"],
            worker_result={"records": []},
            result_digest="digest-abc",
        )
        self.assertTrue(res2["ok"])
        self.assertTrue(res2["replayed"])
        self.assertEqual(res1["receipt"], res2["receipt"])

        # Replay with different digest raises IdempotencyConflictError
        with self.assertRaises(IdempotencyConflictError):
            queue.submit(
                run_id=self.run_id,
                task_id=claim["task_id"],
                attempt_id=claim["attempt_id"],
                generation=claim["generation"],
                claim_token=claim["claim_token"],
                worker_result={"records": []},
                result_digest="digest-DIFFERENT",
            )

    def test_budget_reservation_and_exhaustion(self):
        budget = BudgetLedger(self.conn)
        budget.set_budget(self.run_id, "tasks", limit_val=2, unit="tasks", mode="enforced")

        # Reserve 1
        budget.reserve(self.run_id, "att-1", "tasks", 1)
        # Reserve 1
        budget.reserve(self.run_id, "att-2", "tasks", 1)

        # Third reserve exceeds limit and raises BudgetExhaustedError
        with self.assertRaises(BudgetExhaustedError):
            budget.reserve(self.run_id, "att-3", "tasks", 1)

    def test_artifact_publishing_and_corruption_detection(self):
        mgr = ArtifactManager(self.temp_dir, self.conn)
        art = mgr.publish_artifact(self.run_id, "report", "report.md", b"# Report")
        self.assertTrue((Path(self.temp_dir) / "report.md").exists())

        # Verification passes
        mgr.verify_artifacts(self.run_id)

        # Delete artifact to simulate storage corruption
        (Path(self.temp_dir) / "report.md").unlink()
        with self.assertRaises(CorruptRunError):
            mgr.verify_artifacts(self.run_id)

    # ------------------------------------------------------------------
    # DSR-066: dispatch priority ordering
    # ------------------------------------------------------------------
    def test_claim_respects_priority_order(self):
        queue = TaskQueue(self.conn)
        low = queue.enqueue(self.run_id, "hunt:low", "hunt", {"unit": "low"}, priority=10)
        high = queue.enqueue(self.run_id, "hunt:high", "hunt", {"unit": "high"}, priority=20)

        claims = queue.claim(self.run_id, batch_size=2)
        self.assertEqual(len(claims), 2)
        # Higher numeric priority (T1) is dispatched first
        self.assertEqual(claims[0]["task_id"], high)
        self.assertEqual(claims[1]["task_id"], low)

    # ------------------------------------------------------------------
    # DSR-066: stop sequence — dispatch only while the run is active
    # ------------------------------------------------------------------
    def test_claim_blocked_when_run_not_active(self):
        queue = TaskQueue(self.conn)
        queue.enqueue(self.run_id, "hunt:u1", "hunt", {"unit": "u1"})

        self.conn.execute("UPDATE runs SET state = 'paused' WHERE run_id = ?", (self.run_id,))
        with self.assertRaises(InvalidStateError):
            queue.claim(self.run_id, batch_size=1)

        self.conn.execute("UPDATE runs SET state = 'complete' WHERE run_id = ?", (self.run_id,))
        with self.assertRaises(InvalidStateError):
            queue.claim(self.run_id, batch_size=1)

    # ------------------------------------------------------------------
    # DSR-033: usage collection and usage-based settlement
    # ------------------------------------------------------------------
    def test_usage_validation_rejections(self):
        with self.assertRaises(UnsupportedSchemaError):
            parse_usage({"schema_version": "9.9", "attempt_id": "a", "dimension": "tasks",
                         "availability": "exact", "value": 1, "unit": "tasks", "source": "cli"})
        with self.assertRaises(Exception) as ctx:
            parse_usage({"attempt_id": "a", "dimension": "tasks", "availability": "exact",
                         "value": 1, "unit": "tasks", "source": "cli"})
        self.assertIn("schema_version", str(ctx.exception))
        # Missing required field
        with self.assertRaises(Exception):
            parse_usage({"schema_version": "1.0", "attempt_id": "a", "dimension": "tasks",
                         "availability": "exact", "value": 1, "unit": "tasks"})
        # Unknown field
        with self.assertRaises(Exception):
            parse_usage({"schema_version": "1.0", "attempt_id": "a", "dimension": "tasks",
                         "availability": "exact", "value": 1, "unit": "tasks", "source": "s",
                         "extra": 1})
        # exact without value
        with self.assertRaises(Exception):
            parse_usage({"schema_version": "1.0", "attempt_id": "a", "dimension": "tasks",
                         "availability": "exact", "unit": "tasks", "source": "s"})
        # unavailable with a value is invalid
        with self.assertRaises(Exception):
            parse_usage({"schema_version": "1.0", "attempt_id": "a", "dimension": "tasks",
                         "availability": "unavailable", "value": 3, "unit": "tasks",
                         "source": "s", "reason": "lost"})
        # valid unavailable usage
        rec = parse_usage({"schema_version": "1.0", "attempt_id": "a", "dimension": "tasks",
                           "availability": "unavailable", "unit": "tasks", "source": "s",
                           "reason": "process lost"})
        self.assertIsNone(rec.value)

    def test_submit_with_usage_settles_real_amount(self):
        budget = BudgetLedger(self.conn)
        budget.set_budget(self.run_id, "tasks", limit_val=5, unit="tasks", mode="enforced")
        queue = TaskQueue(self.conn)
        queue.enqueue(self.run_id, "hunt:u1", "hunt", {"unit": "u1"})
        claim = queue.claim(self.run_id, batch_size=1)[0]

        res = queue.submit(
            run_id=self.run_id,
            task_id=claim["task_id"],
            attempt_id=claim["attempt_id"],
            generation=claim["generation"],
            claim_token=claim["claim_token"],
            worker_result={"records": []},
            result_digest="digest-usage",
            usage={
                "schema_version": "1.0",
                "attempt_id": claim["attempt_id"],
                "dimension": "tasks",
                "availability": "exact",
                "value": 1,
                "unit": "tasks",
                "source": "host_cli_report",
            },
        )
        self.assertTrue(res["ok"])

        summary = {b["dimension"]: b for b in budget.get_summary(self.run_id)}["tasks"]
        self.assertEqual(summary["settled"], 1)
        self.assertEqual(summary["reserved"], 0)
        # DSR-033: exact availability with recorded source
        self.assertEqual(summary["availability"], "exact")
        self.assertEqual(summary["source"], "host_cli_report")
        self.assertEqual(summary["value"], 1)

    def test_submit_without_usage_settles_unknown_not_one(self):
        budget = BudgetLedger(self.conn)
        budget.set_budget(self.run_id, "tasks", limit_val=2, unit="tasks", mode="enforced")
        queue = TaskQueue(self.conn)
        queue.enqueue(self.run_id, "hunt:u1", "hunt", {"unit": "u1"})
        claim = queue.claim(self.run_id, batch_size=1)[0]
        queue.submit(
            run_id=self.run_id,
            task_id=claim["task_id"],
            attempt_id=claim["attempt_id"],
            generation=claim["generation"],
            claim_token=claim["claim_token"],
            worker_result={"records": []},
            result_digest="digest-nousage",
        )
        summary = {b["dimension"]: b for b in budget.get_summary(self.run_id)}["tasks"]
        # Unknown usage is settled at the reserved amount, availability unavailable
        self.assertEqual(summary["settled"], 1)
        self.assertEqual(summary["reserved"], 0)
        self.assertEqual(summary["availability"], "unavailable")
        self.assertIsNone(summary["source"])
        self.assertIsNone(summary["value"])

    def test_submit_usage_unavailable_retains_consumption(self):
        budget = BudgetLedger(self.conn)
        budget.set_budget(self.run_id, "tokens", limit_val=10, unit="tokens", mode="enforced")
        queue = TaskQueue(self.conn)
        queue.enqueue(self.run_id, "hunt:u1", "hunt", {"unit": "u1"})
        claim = queue.claim(self.run_id, batch_size=1)[0]
        queue.submit(
            run_id=self.run_id,
            task_id=claim["task_id"],
            attempt_id=claim["attempt_id"],
            generation=claim["generation"],
            claim_token=claim["claim_token"],
            worker_result={"records": []},
            result_digest="digest-unavail",
            usage={
                "schema_version": "1.0",
                "attempt_id": claim["attempt_id"],
                "dimension": "tokens",
                "availability": "unavailable",
                "unit": "tokens",
                "source": "host_cli_report",
                "reason": "worker process lost",
            },
        )
        summary = {b["dimension"]: b for b in budget.get_summary(self.run_id)}["tokens"]
        self.assertEqual(summary["availability"], "unavailable")
        self.assertEqual(summary["source"], "host_cli_report")
        # DSR-033: missing value stays null, never defaulted
        self.assertIsNone(summary["value"])

    def test_submit_usage_attempt_id_mismatch_rejected(self):
        queue = TaskQueue(self.conn)
        queue.enqueue(self.run_id, "hunt:u1", "hunt", {"unit": "u1"})
        claim = queue.claim(self.run_id, batch_size=1)[0]
        with self.assertRaises(Exception) as ctx:
            queue.submit(
                run_id=self.run_id,
                task_id=claim["task_id"],
                attempt_id=claim["attempt_id"],
                generation=claim["generation"],
                claim_token=claim["claim_token"],
                worker_result={"records": []},
                result_digest="digest-x",
                usage={"schema_version": "1.0", "attempt_id": "att-other", "dimension": "tasks",
                       "availability": "exact", "value": 1, "unit": "tasks", "source": "s"},
            )
        self.assertIn("attempt", str(ctx.exception))
        # The failed submission must not settle or complete the task
        state = self.conn.execute("SELECT state FROM tasks WHERE task_id = ?", (claim["task_id"],)).fetchone()
        self.assertEqual(state["state"], "claimed")

    # ------------------------------------------------------------------
    # DSR-019: lease reclamation
    # ------------------------------------------------------------------
    def test_reclaim_expired_attempts(self):
        budget = BudgetLedger(self.conn)
        budget.set_budget(self.run_id, "tasks", limit_val=1, unit="tasks", mode="enforced")
        queue = TaskQueue(self.conn)
        task_id = queue.enqueue(self.run_id, "hunt:u1", "hunt", {"unit": "u1"})
        claim = queue.claim(self.run_id, batch_size=1)[0]

        # Budget fully reserved; any further claim would fail
        with self.assertRaises(BudgetExhaustedError):
            budget.reserve(self.run_id, "att-other", "tasks", 1)

        # Expire the lease
        self.conn.execute("UPDATE attempts SET expires_at = '2000-01-01T00:00:00+00:00' WHERE attempt_id = ?",
                          (claim["attempt_id"],))

        reclaimed = queue.reclaim_expired_attempts(self.run_id)
        self.assertEqual(len(reclaimed), 1)
        self.assertEqual(reclaimed[0]["task_id"], task_id)
        self.assertEqual(reclaimed[0]["reservations_released"], 1)

        # Task is queued again with generation+1; old attempt expired
        row = self.conn.execute("SELECT state, generation FROM tasks WHERE task_id = ?", (task_id,)).fetchone()
        self.assertEqual(row["state"], "queued")
        self.assertEqual(row["generation"], 2)
        att = self.conn.execute("SELECT status FROM attempts WHERE attempt_id = ?", (claim["attempt_id"],)).fetchone()
        self.assertEqual(att["status"], "expired")

        # Reservation released: the budget is available again
        summary = {b["dimension"]: b for b in budget.get_summary(self.run_id)}["tasks"]
        self.assertEqual(summary["reserved"], 0)

        # Late submission of the expired attempt is rejected
        with self.assertRaises(StaleAttemptError):
            queue.submit(
                run_id=self.run_id,
                task_id=task_id,
                attempt_id=claim["attempt_id"],
                generation=claim["generation"],
                claim_token=claim["claim_token"],
                worker_result={"records": []},
                result_digest="digest-late",
            )

        # Re-claim succeeds with a fresh generation and reservation
        claim2 = queue.claim(self.run_id, batch_size=1)[0]
        self.assertEqual(claim2["generation"], 3)

    def test_reclaim_ignores_unexpired_attempts(self):
        queue = TaskQueue(self.conn)
        queue.enqueue(self.run_id, "hunt:u1", "hunt", {"unit": "u1"})
        queue.claim(self.run_id, batch_size=1)
        self.assertEqual(queue.reclaim_expired_attempts(self.run_id), [])

    # ------------------------------------------------------------------
    # DSR-065: bounded retry and quarantine
    # ------------------------------------------------------------------
    def test_fail_attempt_retry_then_quarantine(self):
        budget = BudgetLedger(self.conn)
        budget.set_budget(self.run_id, "tasks", limit_val=10, unit="tasks", mode="enforced")
        queue = TaskQueue(self.conn)
        task_id = queue.enqueue(self.run_id, "hunt:u1", "hunt", {"unit": "u1"})

        # Attempt 1: retryable failure -> requeued
        claim = queue.claim(self.run_id, batch_size=1)[0]
        res = queue.fail_attempt(
            run_id=self.run_id, task_id=task_id, attempt_id=claim["attempt_id"],
            generation=claim["generation"], claim_token=claim["claim_token"],
            reason="host timeout", retryable=True, max_retries=2,
        )
        self.assertEqual(res["action"], "requeued")
        # Reservation of the failed attempt is released
        summary = {b["dimension"]: b for b in budget.get_summary(self.run_id)}["tasks"]
        self.assertEqual(summary["reserved"], 0)

        # Attempt 2: retryable failure -> still requeued (generation increments per claim)
        claim = queue.claim(self.run_id, batch_size=1)[0]
        self.assertEqual(claim["generation"], 2)
        res = queue.fail_attempt(
            run_id=self.run_id, task_id=task_id, attempt_id=claim["attempt_id"],
            generation=claim["generation"], claim_token=claim["claim_token"],
            reason="host timeout again", retryable=True, max_retries=2,
        )
        self.assertEqual(res["action"], "requeued")

        # Attempt 3: retries exhausted -> quarantined with coverage gap
        claim = queue.claim(self.run_id, batch_size=1)[0]
        self.assertEqual(claim["generation"], 3)
        res = queue.fail_attempt(
            run_id=self.run_id, task_id=task_id, attempt_id=claim["attempt_id"],
            generation=claim["generation"], claim_token=claim["claim_token"],
            reason="still failing", retryable=True, max_retries=2,
        )
        self.assertEqual(res["action"], "quarantined")

        row = self.conn.execute("SELECT state FROM tasks WHERE task_id = ?", (task_id,)).fetchone()
        self.assertEqual(row["state"], "quarantined")

        gaps = self.conn.execute(
            "SELECT count(*) AS c FROM events WHERE run_id = ? AND event_type = 'coverage_gap'",
            (self.run_id,),
        ).fetchone()["c"]
        self.assertEqual(gaps, 1)

    def test_fail_attempt_non_retryable_quarantines_immediately(self):
        queue = TaskQueue(self.conn)
        task_id = queue.enqueue(self.run_id, "hunt:u1", "hunt", {"unit": "u1"})
        claim = queue.claim(self.run_id, batch_size=1)[0]
        res = queue.fail_attempt(
            run_id=self.run_id, task_id=task_id, attempt_id=claim["attempt_id"],
            generation=claim["generation"], claim_token=claim["claim_token"],
            reason="malformed result", retryable=False, max_retries=2,
        )
        self.assertEqual(res["action"], "quarantined")
        row = self.conn.execute("SELECT state FROM tasks WHERE task_id = ?", (task_id,)).fetchone()
        self.assertEqual(row["state"], "quarantined")

    # ------------------------------------------------------------------
    # DSR-016: event replay and payload version validation
    # ------------------------------------------------------------------
    def test_append_event_rejects_unknown_payload_version(self):
        store = EventStore(self.conn)
        with self.assertRaises(UnsupportedSchemaError):
            store.append_event(self.run_id, "future_event", "actor", {"k": 1}, payload_version="2.0")

    def test_replay_events_projection(self):
        queue = TaskQueue(self.conn)
        store = EventStore(self.conn)
        store.append_event(self.run_id, "run_activated", "service", {})
        t1 = queue.enqueue(self.run_id, "hunt:u1", "hunt", {"unit": "u1"})
        t2 = queue.enqueue(self.run_id, "hunt:u2", "hunt", {"unit": "u2"})
        c1 = queue.claim(self.run_id, batch_size=1)[0]
        queue.submit(
            run_id=self.run_id, task_id=c1["task_id"], attempt_id=c1["attempt_id"],
            generation=c1["generation"], claim_token=c1["claim_token"],
            worker_result={"records": []}, result_digest="d1",
        )

        store = EventStore(self.conn)
        projection = store.replay_events(self.run_id)
        self.assertEqual(projection["tasks_enqueued"], 2)
        self.assertEqual(projection["claims"], 1)
        self.assertEqual(projection["submissions"], 1)
        self.assertEqual(projection["run_state"], "active")  # seeded run state is irrelevant; events decide
        self.assertTrue(projection["revision_consistent"])

        # Ledger tampering is detected by replay
        self.conn.execute("UPDATE runs SET revision = 99 WHERE run_id = ?", (self.run_id,))
        projection2 = store.replay_events(self.run_id)
        self.assertFalse(projection2["revision_consistent"])

    # ------------------------------------------------------------------
    # DSR-072: version compatibility check
    # ------------------------------------------------------------------
    def test_version_compatibility(self):
        # Supported format passes and returns version info
        info = check_version_compatibility(self.conn)
        self.assertEqual(info["schema_version"], "1.0")

        # Older format rejected
        self.conn.execute("UPDATE runs SET schema_version = '0.9' WHERE run_id = ?", (self.run_id,))
        with self.assertRaises(UnsupportedSchemaError):
            check_version_compatibility(self.conn)

        # Future format rejected
        self.conn.execute("UPDATE runs SET schema_version = '2.0' WHERE run_id = ?", (self.run_id,))
        with self.assertRaises(UnsupportedSchemaError):
            check_version_compatibility(self.conn)

        # Future skill major rejected
        self.conn.execute("UPDATE runs SET schema_version = '1.0', skill_version = '1.5.0' WHERE run_id = ?", (self.run_id,))
        with self.assertRaises(UnsupportedSchemaError):
            check_version_compatibility(self.conn)

        # No automatic migration happened
        row = self.conn.execute("SELECT schema_version, skill_version FROM runs WHERE run_id = ?", (self.run_id,)).fetchone()
        self.assertEqual(row["schema_version"], "1.0")
        self.assertEqual(row["skill_version"], "1.5.0")

    def test_version_compatibility_future_schema_rejected_on_claim(self):
        queue = TaskQueue(self.conn)
        queue.enqueue(self.run_id, "hunt:u1", "hunt", {"unit": "u1"})
        self.conn.execute("UPDATE runs SET schema_version = '2.0' WHERE run_id = ?", (self.run_id,))
        with self.assertRaises(UnsupportedSchemaError):
            queue.claim(self.run_id, batch_size=1)


if __name__ == "__main__":
    unittest.main()

    def test_submit_emits_usage_settled_event_ifc05(self):
        """IFC-05 floor requirement: every settlement emits a usage_settled event
        with availability and settled value/reason -- including unknown paths."""
        budget = BudgetLedger(self.conn)
        budget.set_budget(self.run_id, "tasks", limit_val=5, unit="tasks", mode="enforced")
        queue = TaskQueue(self.conn)
        queue.enqueue(self.run_id, "hunt:u1", "hunt", {"unit": "u1"})
        claim = queue.claim(self.run_id, batch_size=1)[0]
        queue.submit(
            run_id=self.run_id,
            task_id=claim["task_id"],
            attempt_id=claim["attempt_id"],
            generation=claim["generation"],
            claim_token=claim["claim_token"],
            worker_result={"records": []},
            result_digest="digest-ifc05-exact",
            usage={
                "schema_version": "1.0",
                "attempt_id": claim["attempt_id"],
                "dimension": "tasks",
                "availability": "exact",
                "value": 2,
                "unit": "tasks",
                "source": "host_cli_report",
            },
        )

        events = self.conn.execute(
            "SELECT payload_json FROM events WHERE event_type = 'usage_settled' ORDER BY revision"
        ).fetchall()
        self.assertEqual(len(events), 1)
        payload = json.loads(events[0]["payload_json"])
        self.assertEqual(payload["attempt_id"], claim["attempt_id"])
        self.assertEqual(payload["dimension"], "tasks")
        self.assertEqual(payload["availability"], "exact")
        self.assertEqual(payload["settled_value"], 2)
        self.assertIsNone(payload["reason"])
        self.assertEqual(payload["source"], "host_cli_report")

        # Unknown-settlement path (no usage supplied) also emits the event
        # with availability=unavailable and an explicit reason -- never zero.
        queue.enqueue(self.run_id, "hunt:u2", "hunt", {"unit": "u2"})
        claim2 = queue.claim(self.run_id, batch_size=1)[0]
        queue.submit(
            run_id=self.run_id,
            task_id=claim2["task_id"],
            attempt_id=claim2["attempt_id"],
            generation=claim2["generation"],
            claim_token=claim2["claim_token"],
            worker_result={"records": []},
            result_digest="digest-ifc05-unknown",
        )
        events = self.conn.execute(
            "SELECT payload_json FROM events WHERE event_type = 'usage_settled' ORDER BY revision"
        ).fetchall()
        self.assertEqual(len(events), 2)
        payload2 = json.loads(events[1]["payload_json"])
        self.assertEqual(payload2["availability"], "unavailable")
        self.assertIsNone(payload2["settled_value"])
        self.assertTrue(payload2["reason"])
