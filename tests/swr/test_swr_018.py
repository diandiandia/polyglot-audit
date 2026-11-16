"""SWR-018 acceptance tests: event store, atomic claim, generation, expiry, dedup, recovery.

验收准则原文 (docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2):
| SWR-018 | SR-018 -> SD-06 | P1 / SWR-025 | 实现事件库、原子 claim、generation、过期、去重与恢复；
  并发重复领取、崩溃、提交重放和迟到结果测试均保持不变量。 |

上游系统需求 (SYSTEM_REQUIREMENTS.md §2):
| SR-018 | 在中断、重复提交、并发领取、延迟提交、驱动切换及进程崩溃后保持状态一致，
  不重复接受同一任务的有效结果。验收：故障注入和并发测试证明原子状态变迁、过期尝试被拒绝、
  恢复后可审计对账。 |

绑定实现: ledger/task_queue.py (DSR-017/018/019), ledger/event_store.py (DSR-016),
ledger/db.py (DSR-016)。
"""

import shutil
import sys
import tempfile
import threading
import unittest
from pathlib import Path

_SKILL_SCRIPTS = Path(__file__).resolve().parents[2] / "skill" / "scripts"
if str(_SKILL_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SKILL_SCRIPTS))

from auditkit.contracts.errors import (  # noqa: E402
    IdempotencyConflictError,
    StaleAttemptError,
)
from auditkit.ledger.budget import BudgetLedger  # noqa: E402
from auditkit.ledger.db import get_db_connection, init_database  # noqa: E402
from auditkit.ledger.event_store import EventStore  # noqa: E402
from auditkit.ledger.task_queue import TaskQueue  # noqa: E402

NUM_RACERS = 8

_RUN_INSERT = """
INSERT INTO runs (run_id, snapshot_id, state, schema_version, skill_version,
                  knowledge_version, config_ref, revision, created_at, updated_at)
VALUES (?, 'snp-018', 'active', '1.0', '0.1.0', '1.0', 'config.json', 0,
        '2026-11-14T00:00:00Z', '2026-11-14T00:00:00Z')
"""


class TestSWR018(unittest.TestCase):
    """并发重复领取、崩溃恢复、提交重放、迟到结果与 generation 单调不变量。"""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="swr-018-"))
        self.db_path = self.temp_dir / "events.db"
        init_database(self.db_path)
        conn = get_db_connection(self.db_path)
        self.run_id = "run-swr-018"
        conn.execute(_RUN_INSERT, (self.run_id,))
        # A constrained tasks dimension so every claim carries a real
        # reservation (released again on expiry/reclaim).
        BudgetLedger(conn).set_budget(self.run_id, "tasks", limit_val=20, unit="tasks")
        conn.commit()
        conn.close()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # ------------------------------------------------------------ helpers
    def _connect(self):
        return get_db_connection(self.db_path)

    def _race(self, worker_fn, n=NUM_RACERS):
        """Run worker_fn(conn, idx) concurrently in n threads, one connection each."""
        barrier = threading.Barrier(n)
        results = [None] * n
        errors = [None] * n

        def wrapper(idx):
            conn = self._connect()
            try:
                barrier.wait(timeout=15)
                results[idx] = worker_fn(conn, idx)
            except Exception as e:  # noqa: BLE001 - collected for assertions
                errors[idx] = e
            finally:
                conn.close()

        threads = [threading.Thread(target=wrapper, args=(i,)) for i in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)
        return results, errors

    def _events(self, conn, event_type):
        rows = conn.execute(
            "SELECT revision, payload_json FROM events WHERE event_type = ? AND run_id = ? "
            "ORDER BY revision",
            (event_type, self.run_id),
        ).fetchall()
        import json

        return [(r["revision"], json.loads(r["payload_json"])) for r in rows]

    # ------------------------------------------------- 并发重复领取不变量
    def test_concurrent_duplicate_claim_single_winner_invariants(self):
        """8 个 worker 各持独立连接争抢同一任务：至多一次领取成功，且事件投影、
        attempts 表与 generation 全部自洽（原子状态变迁）。"""
        setup = self._connect()
        queue = TaskQueue(setup)
        task_id = queue.enqueue(self.run_id, "hunt:unit-1", "hunt", {"unit_id": "unit-1"})
        setup.commit()
        setup.close()

        results, errors = self._race(
            lambda conn, idx: TaskQueue(conn).claim(
                self.run_id, batch_size=1, worker_id=f"racer-{idx}"
            )
        )

        for i, e in enumerate(errors):
            self.assertIsNone(e, f"racer {i} raised unexpected error: {e}")
        winners = [r for r in results if r]
        self.assertEqual(len(winners), 1, f"exactly one claim may win, got {len(winners)}")

        conn = self._connect()
        try:
            # Invariant 1: exactly one attempt row, task claimed exactly once.
            self.assertEqual(
                conn.execute("SELECT count(*) c FROM attempts").fetchone()["c"], 1
            )
            row = conn.execute(
                "SELECT state, generation FROM tasks WHERE task_id = ?", (task_id,)
            ).fetchone()
            self.assertEqual(row["state"], "claimed")
            self.assertEqual(row["generation"], 1)

            # Invariant 2: exactly one attempt_claimed event in the audit log.
            claimed_events = self._events(conn, "attempt_claimed")
            self.assertEqual(len(claimed_events), 1)
            self.assertEqual(claimed_events[0][1]["task_id"], task_id)
            self.assertEqual(claimed_events[0][1]["generation"], 1)

            # Invariant 3: event-store projection reconciles with the ledger.
            projection = EventStore(conn).replay_events(self.run_id)
            self.assertEqual(projection["claims"], 1)
            self.assertEqual(projection["tasks_enqueued"], 1)
            self.assertEqual(projection["submissions"], 0)
            self.assertTrue(projection["revision_consistent"])
        finally:
            conn.close()

    # ----------------------------------------------------- 崩溃后恢复对账
    def test_crash_recovery_reclaim_reconciles_and_rejects_late_result(self):
        """进程崩溃（租约过期后重开连接恢复）：reclaim 把任务归队并 generation+1、
        释放预留；旧 attempt 的迟到提交被拒绝；恢复后事件投影可审计对账。"""
        # Phase 1: claim on one connection, then "crash" (close without submit).
        setup = self._connect()
        queue = TaskQueue(setup)
        task_id = queue.enqueue(self.run_id, "hunt:unit-2", "hunt", {"unit_id": "unit-2"})
        setup.commit()
        claim = queue.claim(self.run_id, batch_size=1)[0]
        setup.commit()
        setup.close()  # crash: the lease and its worker vanish

        # Phase 2: recovery opens a fresh connection; the lease is expired.
        conn = self._connect()
        try:
            conn.execute(
                "UPDATE attempts SET expires_at = '2000-01-01T00:00:00+00:00' "
                "WHERE attempt_id = ?",
                (claim["attempt_id"],),
            )
            conn.commit()

            queue2 = TaskQueue(conn)
            reclaimed = queue2.reclaim_expired_attempts(self.run_id)
            self.assertEqual(len(reclaimed), 1)
            rec = reclaimed[0]
            self.assertEqual(rec["task_id"], task_id)
            self.assertEqual(rec["generation"], claim["generation"] + 1)
            self.assertEqual(rec["reservations_released"], 1)

            # Late result from the crashed worker must be rejected.
            with self.assertRaises(StaleAttemptError):
                queue2.submit(
                    run_id=self.run_id,
                    task_id=task_id,
                    attempt_id=claim["attempt_id"],
                    generation=claim["generation"],
                    claim_token=claim["claim_token"],
                    worker_result={"records": []},
                    result_digest="late-digest",
                )

            # The rejected late result left no trace: no result digest, not done.
            att = conn.execute(
                "SELECT status, result_digest FROM attempts WHERE attempt_id = ?",
                (claim["attempt_id"],),
            ).fetchone()
            self.assertEqual(att["status"], "expired")
            self.assertIsNone(att["result_digest"])
            task = conn.execute(
                "SELECT state, generation FROM tasks WHERE task_id = ?", (task_id,)
            ).fetchone()
            self.assertEqual(task["state"], "queued")
            self.assertEqual(task["generation"], claim["generation"] + 1)

            # Recovery reconciles: projection consistent, claims counted once.
            projection = EventStore(conn).replay_events(self.run_id)
            self.assertEqual(projection["claims"], 1)
            self.assertEqual(projection["submissions"], 0)
            self.assertTrue(projection["revision_consistent"])

            # Phase 3: the task is re-dispatchable at a strictly higher
            # generation (reclaim bumped the task once, this claim bumps again).
            claims2 = queue2.claim(self.run_id, batch_size=1)
            self.assertEqual(len(claims2), 1)
            self.assertGreater(claims2[0]["generation"], claim["generation"])
            self.assertEqual(claims2[0]["generation"], rec["generation"] + 1)
            self.assertNotEqual(claims2[0]["attempt_id"], claim["attempt_id"])

            # A second reclaim with no expired leases is a no-op.
            self.assertEqual(queue2.reclaim_expired_attempts(self.run_id), [])
        finally:
            conn.close()

    # ------------------------------------------------------- 提交重放不变量
    def test_submit_replay_returns_original_receipt_without_double_settlement(self):
        """同代同 digest 的重放返回原回执；事件、用量记录与预算结算都只计一次。"""
        conn = self._connect()
        try:
            queue = TaskQueue(conn)
            task_id = queue.enqueue(self.run_id, "hunt:unit-3", "hunt", {"unit_id": "unit-3"})
            conn.commit()
            claim = queue.claim(self.run_id, batch_size=1)[0]
            conn.commit()

            usage = {
                "schema_version": "1.0",
                "attempt_id": claim["attempt_id"],
                "dimension": "tasks",
                "availability": "exact",
                "value": 7,
                "unit": "tasks",
                "source": "host_cli_report",
            }
            first = queue.submit(
                run_id=self.run_id,
                task_id=task_id,
                attempt_id=claim["attempt_id"],
                generation=claim["generation"],
                claim_token=claim["claim_token"],
                worker_result={"records": []},
                result_digest="digest-replay-1",
                usage=usage,
            )
            conn.commit()
            self.assertTrue(first["ok"])
            self.assertFalse(first["replayed"])

            replay = queue.submit(
                run_id=self.run_id,
                task_id=task_id,
                attempt_id=claim["attempt_id"],
                generation=claim["generation"],
                claim_token=claim["claim_token"],
                worker_result={"records": []},
                result_digest="digest-replay-1",
                usage=usage,
            )
            conn.commit()
            self.assertTrue(replay["ok"])
            self.assertTrue(replay["replayed"])
            self.assertEqual(replay["receipt"], first["receipt"])

            # Same generation + different digest must conflict, not overwrite.
            with self.assertRaises(IdempotencyConflictError):
                queue.submit(
                    run_id=self.run_id,
                    task_id=task_id,
                    attempt_id=claim["attempt_id"],
                    generation=claim["generation"],
                    claim_token=claim["claim_token"],
                    worker_result={"records": []},
                    result_digest="digest-replay-2",
                )

            # Exactly one submission event, one usage record, one settlement.
            submitted = self._events(conn, "attempt_submitted")
            self.assertEqual(len(submitted), 1)
            settled = self._events(conn, "usage_settled")
            self.assertEqual(len(settled), 1)
            self.assertEqual(conn.execute("SELECT count(*) c FROM usage_records").fetchone()["c"], 1)
            budget_row = conn.execute(
                "SELECT settled, reserved FROM budget_dimensions WHERE run_id = ? AND dimension = 'tasks'",
                (self.run_id,),
            ).fetchone()
            self.assertEqual(budget_row["settled"], 7, "settlement must be counted exactly once")
            self.assertEqual(budget_row["reserved"], 0)

            # The receipt reference stored in the ledger is the original one.
            att = conn.execute(
                "SELECT receipt_ref, result_digest FROM attempts WHERE attempt_id = ?",
                (claim["attempt_id"],),
            ).fetchone()
            self.assertEqual(att["receipt_ref"], first["receipt"])
            self.assertEqual(att["result_digest"], "digest-replay-1")
        finally:
            conn.close()

    # ------------------------------------------------------- 迟到结果拒绝
    def test_late_result_rejected_for_wrong_token_and_stale_generation(self):
        """过期/被替换的凭据不能产生结果：错 token、旧 generation、旧 attempt
        全部拒绝，且 ledger 中无 result、任务未完成（不重复接受同一任务的结果）。"""
        conn = self._connect()
        try:
            queue = TaskQueue(conn)
            task_id = queue.enqueue(self.run_id, "hunt:unit-4", "hunt", {"unit_id": "unit-4"})
            conn.commit()
            claim = queue.claim(self.run_id, batch_size=1)[0]
            conn.commit()

            # a) Wrong token.
            with self.assertRaises(StaleAttemptError):
                queue.submit(
                    run_id=self.run_id,
                    task_id=task_id,
                    attempt_id=claim["attempt_id"],
                    generation=claim["generation"],
                    claim_token="forged-token",
                    worker_result={"records": []},
                    result_digest="digest-bad",
                )

            # b) Stale generation: task re-queued via release, then a new claim
            #    happens; the old generation can never submit.
            queue.release_claim(
                run_id=self.run_id,
                task_id=task_id,
                attempt_id=claim["attempt_id"],
                generation=claim["generation"],
                claim_token=claim["claim_token"],
                reason="packet unavailable",
            )
            conn.commit()
            new_claim = queue.claim(self.run_id, batch_size=1)[0]
            self.assertGreater(new_claim["generation"], claim["generation"])
            with self.assertRaises(StaleAttemptError):
                queue.submit(
                    run_id=self.run_id,
                    task_id=task_id,
                    attempt_id=claim["attempt_id"],
                    generation=claim["generation"],
                    claim_token=claim["claim_token"],
                    worker_result={"records": []},
                    result_digest="digest-stale",
                )

            # Invariant: no result was recorded for either rejected submission.
            rows = conn.execute(
                "SELECT count(*) c FROM attempts WHERE result_digest IS NOT NULL"
            ).fetchone()
            self.assertEqual(rows["c"], 0)
            task = conn.execute(
                "SELECT state FROM tasks WHERE task_id = ?", (task_id,)
            ).fetchone()
            self.assertEqual(task["state"], "claimed")  # held by the live new claim
            projection = EventStore(conn).replay_events(self.run_id)
            self.assertEqual(projection["submissions"], 0)
        finally:
            conn.close()

    # ------------------------------------------------------ generation 单调
    def test_generation_strictly_monotonic_across_recovery_cycles(self):
        """三次崩溃-恢复循环：generation 严格单调递增，(task_id, generation) 唯一，
        任务行上的 generation 与 attempt 最大代一致。"""
        conn = self._connect()
        try:
            queue = TaskQueue(conn)
            task_id = queue.enqueue(self.run_id, "hunt:unit-5", "hunt", {"unit_id": "unit-5"})
            conn.commit()
            seen_generations = []
            previous_token = None

            for cycle in range(3):
                claim = queue.claim(self.run_id, batch_size=1)[0]
                conn.commit()
                seen_generations.append(claim["generation"])
                if previous_token is not None:
                    self.assertNotEqual(
                        claim["claim_token"], previous_token,
                        "each attempt must carry a fresh claim token",
                    )
                previous_token = claim["claim_token"]

                # Crash: expire the lease, recover on the same connection.
                conn.execute(
                    "UPDATE attempts SET expires_at = '2000-01-01T00:00:00+00:00' "
                    "WHERE attempt_id = ?",
                    (claim["attempt_id"],),
                )
                conn.commit()
                reclaimed = queue.reclaim_expired_attempts(self.run_id)
                self.assertEqual(len(reclaimed), 1)
                self.assertEqual(reclaimed[0]["generation"], claim["generation"] + 1)

            self.assertEqual(seen_generations, [1, 3, 5], "generation must increase strictly")
            for older, newer in zip(seen_generations, seen_generations[1:]):
                self.assertGreater(newer, older, "generation must never repeat or decrease")

            gens = [
                r["generation"]
                for r in conn.execute(
                    "SELECT generation FROM attempts WHERE task_id = ? ORDER BY generation",
                    (task_id,),
                ).fetchall()
            ]
            self.assertEqual(gens, [1, 3, 5])
            task_gen = conn.execute(
                "SELECT generation FROM tasks WHERE task_id = ?", (task_id,)
            ).fetchone()["generation"]
            # The task row always sits above every dispatched attempt: after a
            # reclaim it names the next generation to hand out.
            self.assertEqual(task_gen, max(gens) + 1)
            # Every attempt of this task used a distinct token digest.
            digests = conn.execute(
                "SELECT count(DISTINCT token_digest) c FROM attempts WHERE task_id = ?",
                (task_id,),
            ).fetchone()["c"]
            self.assertEqual(digests, 3)
        finally:
            conn.close()

    # ---------------------------------------------------------- 入队去重
    def test_enqueue_dedup_same_spec_and_conflict_on_different_spec(self):
        """同 key 同 spec 幂等返回同一 task_id（不产生重复任务）；同 key 不同 spec
        显式冲突；已完成任务再次入队不产生第二个可领取任务。"""
        conn = self._connect()
        try:
            queue = TaskQueue(conn)
            spec = {"unit_id": "unit-6"}
            t1 = queue.enqueue(self.run_id, "hunt:unit-6", "hunt", dict(spec))
            t2 = queue.enqueue(self.run_id, "hunt:unit-6", "hunt", dict(spec))
            self.assertEqual(t1, t2)
            self.assertEqual(
                conn.execute("SELECT count(*) c FROM tasks WHERE run_id = ?", (self.run_id,)).fetchone()["c"],
                1,
            )
            with self.assertRaises(IdempotencyConflictError):
                queue.enqueue(self.run_id, "hunt:unit-6", "hunt", {"unit_id": "unit-6-different"})

            # Complete the task; re-enqueueing the same spec stays idempotent
            # and never yields a second dispatchable task.
            claim = queue.claim(self.run_id, batch_size=1)[0]
            conn.commit()
            queue.submit(
                run_id=self.run_id,
                task_id=claim["task_id"],
                attempt_id=claim["attempt_id"],
                generation=claim["generation"],
                claim_token=claim["claim_token"],
                worker_result={"records": []},
                result_digest="digest-done",
            )
            conn.commit()
            t3 = queue.enqueue(self.run_id, "hunt:unit-6", "hunt", dict(spec))
            self.assertEqual(t3, t1)
            conn.commit()
            self.assertEqual(queue.claim(self.run_id, batch_size=5), [])
        finally:
            conn.close()

    # ------------------------------------------------------ 事件库不变量
    def test_event_store_replay_projection_after_full_lifecycle(self):
        """完整生命周期（入队/领取/启动/提交）后：重放投影与持久化账本一致
        （revision_consistent），计数逐一可复算。"""
        conn = self._connect()
        try:
            queue = TaskQueue(conn)
            queue.enqueue(self.run_id, "hunt:unit-7", "hunt", {"unit_id": "unit-7"})
            conn.commit()
            claim = queue.claim(self.run_id, batch_size=1)[0]
            conn.commit()
            queue.start(self.run_id, claim["task_id"], claim["attempt_id"],
                        claim["generation"], claim["claim_token"])
            conn.commit()
            queue.submit(
                run_id=self.run_id,
                task_id=claim["task_id"],
                attempt_id=claim["attempt_id"],
                generation=claim["generation"],
                claim_token=claim["claim_token"],
                worker_result={"records": []},
                result_digest="digest-full",
            )
            conn.commit()

            projection = EventStore(conn).replay_events(self.run_id)
            self.assertEqual(projection["tasks_enqueued"], 1)
            self.assertEqual(projection["claims"], 1)
            self.assertEqual(projection["submissions"], 1)
            self.assertTrue(projection["revision_consistent"])
            self.assertEqual(projection["highest_revision"], projection["persisted_revision"])
            self.assertGreaterEqual(projection["events_replayed"], 4)

            # Events are append-only: revisions have no gaps and are unique.
            revisions = [
                r["revision"]
                for r in conn.execute(
                    "SELECT revision FROM events WHERE run_id = ? ORDER BY revision",
                    (self.run_id,),
                ).fetchall()
            ]
            self.assertEqual(revisions, list(range(1, len(revisions) + 1)))
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
