"""SWR-019 acceptance tests: budget modes, transactional reservation, and settlement.

验收准则原文 (docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2):
| SWR-019 | SR-019 -> SD-07 | P1 / SWR-018、SWR-023 | 实现预算模式、事务预留与结算；
  模拟并发、重试、失联及缺失用量，无法约束的维度禁止硬模式或明确降级。 |

上游系统需求 (SYSTEM_REQUIREMENTS.md §2):
| SR-019 | 预算须可在派发前预留，并对不可度量或不可强制的预算维度诚实降级。验收：
  多并发及重试下可强制预算不超上限；无可靠用量/限额时不能称 token 或费用为硬上限，
  需阻止该模式或经同意切换到可执行的任务/时间限额。 |

绑定实现: ledger/budget.py (DSR-020/033/066), ledger/task_queue.py (DSR-020/064/065),
hosts/probes.py:probe_single_call_budget (DSR-005)。
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

from auditkit.contracts.errors import BudgetExhaustedError  # noqa: E402
from auditkit.hosts import probes  # noqa: E402
from auditkit.ledger.budget import BudgetLedger  # noqa: E402
from auditkit.ledger.db import get_db_connection, init_database  # noqa: E402
from auditkit.ledger.task_queue import TaskQueue  # noqa: E402

NUM_RACERS = 8

_RUN_INSERT = """
INSERT INTO runs (run_id, snapshot_id, state, schema_version, skill_version,
                  knowledge_version, config_ref, revision, created_at, updated_at)
VALUES (?, 'snp-019', 'active', '1.0', '0.1.0', '1.0', 'config.json', 0,
        '2026-11-14T00:00:00Z', '2026-11-14T00:00:00Z')
"""


class TestSWR019(unittest.TestCase):
    """并发预留、重试预留、失联保留、缺失用量与诚实降级矩阵。"""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="swr-019-"))
        self.db_path = self.temp_dir / "events.db"
        init_database(self.db_path)
        conn = get_db_connection(self.db_path)
        self.run_id = "run-swr-019"
        conn.execute(_RUN_INSERT, (self.run_id,))
        conn.commit()
        conn.close()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _connect(self):
        return get_db_connection(self.db_path)

    def _budget_row(self, conn, dimension):
        return conn.execute(
            "SELECT mode, limit_val, settled, reserved FROM budget_dimensions "
            "WHERE run_id = ? AND dimension = ?",
            (self.run_id, dimension),
        ).fetchone()

    def _usage(self, attempt_id, availability, value=None, dimension="tasks", source="host_cli_report"):
        data = {
            "schema_version": "1.0",
            "attempt_id": attempt_id,
            "dimension": dimension,
            "availability": availability,
            "unit": dimension,
            "source": source,
        }
        if value is not None:
            data["value"] = value
        if availability == "unavailable":
            data["reason"] = "host process lost before usage was reported"
        return data

    def _claim_one(self, queue, key):
        task_id = queue.enqueue(self.run_id, key, "hunt", {"unit_id": key})
        claim = queue.claim(self.run_id, batch_size=1)[0]
        return task_id, claim

    # ------------------------------------------------- 并发预留竞争
    def test_concurrent_reserve_last_unit_exactly_one_winner(self):
        """8 个并发 reserver 争抢最后 1 个额度：恰一成功，其余 BudgetExhausted；
        事后账本满足 settled+reserved ≤ limit 的硬不变量。"""
        conn = self._connect()
        BudgetLedger(conn).set_budget(self.run_id, "tasks", limit_val=1, unit="tasks")
        conn.commit()
        conn.close()

        barrier = threading.Barrier(NUM_RACERS)
        results = [None] * NUM_RACERS
        errors = [None] * NUM_RACERS

        def worker(idx):
            c = self._connect()
            try:
                barrier.wait(timeout=15)
                BudgetLedger(c).reserve(self.run_id, f"att-race-{idx}", "tasks", 1)
                results[idx] = True
            except Exception as e:  # noqa: BLE001 - collected for assertions
                errors[idx] = e
            finally:
                c.close()

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(NUM_RACERS)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)

        successes = sum(1 for r in results if r)
        exhausted = sum(1 for e in errors if isinstance(e, BudgetExhaustedError))
        self.assertEqual(successes, 1, "exactly one reserver may win the last unit")
        self.assertEqual(exhausted, NUM_RACERS - 1)
        for i, e in enumerate(errors):
            if e is not None:
                self.assertIsInstance(e, BudgetExhaustedError)

        conn = self._connect()
        try:
            row = self._budget_row(conn, "tasks")
            self.assertLessEqual(row["settled"] + row["reserved"], row["limit_val"])
            self.assertEqual(row["reserved"], 1)
            # Exactly one reservation row in the reserved state.
            self.assertEqual(
                conn.execute(
                    "SELECT count(*) c FROM reservations WHERE state = 'reserved'"
                ).fetchone()["c"],
                1,
            )
        finally:
            conn.close()

    # ------------------------------------------------------- 重试再次预留
    def test_retryable_failure_requeues_with_fresh_reservation_within_limit(self):
        """可重试失败释放旧预留并归队；重新领取以新 attempt 新预留再次占用；
        全程 reserved+settled 不超上限；超限重试隔离并记录 coverage gap。"""
        conn = self._connect()
        try:
            ledger = BudgetLedger(conn)
            ledger.set_budget(self.run_id, "tasks", limit_val=2, unit="tasks")
            queue = TaskQueue(conn)
            conn.commit()

            _, c1 = self._claim_one(queue, "hunt:r1")
            _, c2 = self._claim_one(queue, "hunt:r2")
            conn.commit()
            self.assertEqual(self._budget_row(conn, "tasks")["reserved"], 2)

            # First retryable failure: the reservation is released, task requeued.
            res = queue.fail_attempt(
                run_id=self.run_id,
                task_id=c1["task_id"],
                attempt_id=c1["attempt_id"],
                generation=c1["generation"],
                claim_token=c1["claim_token"],
                reason="transient host error",
                retryable=True,
                max_retries=2,
            )
            conn.commit()
            self.assertEqual(res["action"], "requeued")
            row = self._budget_row(conn, "tasks")
            self.assertEqual(row["reserved"], 1, "failed attempt must release its reservation")

            # Re-claim: a NEW attempt with a fresh reservation, still within limit.
            claims = queue.claim(self.run_id, batch_size=1)
            conn.commit()
            self.assertEqual(len(claims), 1)
            self.assertEqual(claims[0]["task_id"], c1["task_id"])
            self.assertNotEqual(claims[0]["attempt_id"], c1["attempt_id"])
            row = self._budget_row(conn, "tasks")
            self.assertLessEqual(row["settled"] + row["reserved"], row["limit_val"])
            self.assertEqual(row["reserved"], 2)

            # Burn the remaining retries of the re-queued attempt: quarantine.
            c3 = claims[0]
            queue.fail_attempt(self.run_id, c3["task_id"], c3["attempt_id"],
                               c3["generation"], c3["claim_token"], "still failing",
                               retryable=True, max_retries=2)
            conn.commit()
            c4 = queue.claim(self.run_id, batch_size=1)[0]
            conn.commit()
            res2 = queue.fail_attempt(self.run_id, c4["task_id"], c4["attempt_id"],
                                      c4["generation"], c4["claim_token"], "still failing",
                                      retryable=True, max_retries=2)
            conn.commit()
            self.assertEqual(res2["action"], "quarantined")

            gaps = conn.execute(
                "SELECT payload_json FROM events WHERE event_type = 'coverage_gap' AND run_id = ?",
                (self.run_id,),
            ).fetchall()
            self.assertGreaterEqual(len(gaps), 1, "quarantine must record a coverage gap")
            # The task never normalized into a done result.
            state = conn.execute(
                "SELECT state FROM tasks WHERE task_id = ?", (c1["task_id"],)
            ).fetchone()["state"]
            self.assertEqual(state, "quarantined")
        finally:
            conn.close()

    # --------------------------------------------------------- 失联保留
    def test_unavailable_usage_settlement_keeps_reserved_amount(self):
        """失联（usage=unavailable）结算不得释放预留：保留量转入 settled，
        可得性如实标 unavailable，值保持 null。"""
        conn = self._connect()
        try:
            ledger = BudgetLedger(conn)
            ledger.set_budget(self.run_id, "tasks", limit_val=5, unit="tasks")
            queue = TaskQueue(conn)
            conn.commit()

            _, claim = self._claim_one(queue, "hunt:lost")
            conn.commit()
            row = self._budget_row(conn, "tasks")
            self.assertEqual(row["reserved"], 1)

            queue.submit(
                run_id=self.run_id,
                task_id=claim["task_id"],
                attempt_id=claim["attempt_id"],
                generation=claim["generation"],
                claim_token=claim["claim_token"],
                worker_result={"records": []},
                result_digest="digest-lost",
                usage=self._usage(claim["attempt_id"], "unavailable"),
            )
            conn.commit()

            row = self._budget_row(conn, "tasks")
            self.assertEqual(row["reserved"], 0)
            self.assertEqual(
                row["settled"], 1,
                "unavailable usage must settle the reserved amount, never release it",
            )

            summary = {s["dimension"]: s for s in ledger.get_summary(self.run_id)}
            self.assertEqual(summary["tasks"]["availability"], "unavailable")
            self.assertIsNone(summary["tasks"]["value"], "missing usage must stay null")
            self.assertEqual(summary["tasks"]["source"], "host_cli_report")

            stored = conn.execute(
                "SELECT value, availability, reason FROM usage_records WHERE attempt_id = ?",
                (claim["attempt_id"],),
            ).fetchone()
            self.assertIsNotNone(stored)
            self.assertIsNone(stored["value"])
            self.assertEqual(stored["availability"], "unavailable")
            self.assertTrue(stored["reason"])

            # Losing the worker still consumed capacity: only 4 units remain.
            with self.assertRaises(BudgetExhaustedError):
                for i in range(5):
                    ledger.reserve(self.run_id, f"att-after-lost-{i}", "tasks", 1)
        finally:
            conn.close()

    # ------------------------------------------------------- 缺失用量不当零
    def test_missing_usage_never_treated_as_zero(self):
        """提交不带任何用量对象：结算额为保留量（unknown），不写零、不造 '1'，
        usage_settled 事件带显式 unknown 原因，usage_records 无伪造行。"""
        conn = self._connect()
        try:
            ledger = BudgetLedger(conn)
            ledger.set_budget(self.run_id, "tasks", limit_val=5, unit="tasks")
            queue = TaskQueue(conn)
            conn.commit()

            _, claim = self._claim_one(queue, "hunt:nousage")
            conn.commit()
            queue.submit(
                run_id=self.run_id,
                task_id=claim["task_id"],
                attempt_id=claim["attempt_id"],
                generation=claim["generation"],
                claim_token=claim["claim_token"],
                worker_result={"records": []},
                result_digest="digest-nousage",
                usage=None,
            )
            conn.commit()

            row = self._budget_row(conn, "tasks")
            self.assertEqual(
                row["settled"], 1,
                "unknown usage must settle the reserved amount (not 0, not a fabricated value)",
            )
            self.assertEqual(row["reserved"], 0)

            summary = {s["dimension"]: s for s in ledger.get_summary(self.run_id)}
            self.assertEqual(summary["tasks"]["availability"], "unavailable")
            self.assertIsNone(summary["tasks"]["value"])
            self.assertIsNone(summary["tasks"]["source"], "no usage record: source stays null")

            # No usage row may be fabricated for a submission without usage.
            self.assertEqual(
                conn.execute("SELECT count(*) c FROM usage_records").fetchone()["c"], 0
            )

            settled_events = conn.execute(
                "SELECT payload_json FROM events WHERE event_type = 'usage_settled' AND run_id = ?",
                (self.run_id,),
            ).fetchall()
            self.assertEqual(len(settled_events), 1)
            import json

            payload = json.loads(settled_events[0]["payload_json"])
            self.assertIsNone(payload["settled_value"])
            self.assertEqual(payload["availability"], "unavailable")
            self.assertEqual(payload["reason"], "no host usage supplied with submission")
        finally:
            conn.close()

    # --------------------------------------------------- 真实超额触发停止
    def test_real_overrun_settles_actual_and_blocks_further_dispatch(self):
        """真实用量超过预留：按真实值入账（reserved 清零），随后派发被预算
        停止序列拦截并记录 budget_exhausted 事件（真实超额触发暂停）。"""
        conn = self._connect()
        try:
            ledger = BudgetLedger(conn)
            ledger.set_budget(self.run_id, "tasks", limit_val=2, unit="tasks")
            queue = TaskQueue(conn)
            conn.commit()

            _, claim = self._claim_one(queue, "hunt:overrun")
            conn.commit()

            # The host reports far more than the reserved 1 unit.
            queue.submit(
                run_id=self.run_id,
                task_id=claim["task_id"],
                attempt_id=claim["attempt_id"],
                generation=claim["generation"],
                claim_token=claim["claim_token"],
                worker_result={"records": []},
                result_digest="digest-overrun",
                usage=self._usage(claim["attempt_id"], "exact", value=5),
            )
            conn.commit()
            row = self._budget_row(conn, "tasks")
            self.assertEqual(row["settled"], 5, "actual usage must be booked in full")
            self.assertEqual(row["reserved"], 0)

            # Dispatch is now over budget: the claim refuses and records why.
            queue.enqueue(self.run_id, "hunt:blocked", "hunt", {"unit_id": "blocked"})
            conn.commit()
            claims = queue.claim(self.run_id, batch_size=1)
            conn.commit()
            self.assertEqual(claims, [])
            events = conn.execute(
                "SELECT payload_json FROM events WHERE event_type = 'budget_exhausted' AND run_id = ?",
                (self.run_id,),
            ).fetchall()
            self.assertGreaterEqual(len(events), 1)
            import json

            payload = json.loads(events[-1]["payload_json"])
            self.assertEqual(payload["dimension"], "tasks")
            self.assertTrue(payload["blocked_task_id"])
            # The blocked task stayed queued (not lost, not silently dispatched).
            state = conn.execute(
                "SELECT state FROM tasks WHERE task_key = 'hunt:blocked'"
            ).fetchone()["state"]
            self.assertEqual(state, "queued")
        finally:
            conn.close()

    # --------------------------------- 无法约束维度不得称硬上限（降级矩阵）
    def test_enforcement_matrix_tasks_hard_vs_unmeasurable_dimensions_soft(self):
        """可数维度（tasks）enforced 模式硬约束；无可靠用量的维度（tokens）
        只能 observed/unavailable 模式（软）——超限不拒且如实披露模式；
        无实测证据时 token 硬上限探测保持 UNKNOWN，绝不宣称可硬控。"""
        conn = self._connect()
        try:
            ledger = BudgetLedger(conn)
            ledger.set_budget(self.run_id, "tasks", limit_val=1, unit="tasks", mode="enforced")
            ledger.set_budget(self.run_id, "tokens", limit_val=1, unit="tokens", mode="observed")
            conn.commit()

            # Hard dimension: the last unit is protected; the second fails.
            ledger.reserve(self.run_id, "att-t1", "tasks", 1)
            with self.assertRaises(BudgetExhaustedError):
                ledger.reserve(self.run_id, "att-t2", "tasks", 1)

            # Soft dimension: no upstream enforcement exists, so exceeding the
            # nominal limit must NOT be claimed as impossible — it is observed.
            ledger.reserve(self.run_id, "att-k1", "tokens", 5)
            ledger.reserve(self.run_id, "att-k2", "tokens", 5)

            summary = {s["dimension"]: s for s in ledger.get_summary(self.run_id)}
            self.assertEqual(summary["tasks"]["mode"], "enforced")
            self.assertEqual(summary["tokens"]["mode"], "observed")
            self.assertEqual(summary["tokens"]["reserved"], 10)
        finally:
            conn.close()

        # Unmeasured token hard-limit capability stays UNKNOWN (DSR-005): the
        # probe that could prove hard enforcement never ran, so nothing may
        # claim token/cost as a hard ceiling.
        budget_feature = probes.probe_single_call_budget(None, probe_level="aggressive")
        self.assertEqual(budget_feature["state"], "unknown")
        self.assertIn("not executed", budget_feature["reason"])

        from auditkit.hosts.doctor import Doctor

        caps = Doctor().probe(probe_cli=False)
        for cap in caps:
            if cap["adapter"] in ("claude_cli", "codex_cli"):
                hard = cap["features"]["hard_token_budget"]
                self.assertEqual(hard["state"], "unknown")
                self.assertNotIn("evidence", hard)
                self.assertIn("method", hard)

        # Mode "unavailable" is the explicit honest-degradation label.
        conn2 = self._connect()
        try:
            ledger2 = BudgetLedger(conn2)
            ledger2.set_budget(self.run_id, "cost", limit_val=0, unit="usd", mode="unavailable")
            conn2.commit()
            summary = {s["dimension"]: s for s in ledger2.get_summary(self.run_id)}
            self.assertEqual(summary["cost"]["mode"], "unavailable")
            # Nothing enforces, nothing is silently upgraded to enforced.
            ledger2.reserve(self.run_id, "att-cost-1", "cost", 3)
            conn2.commit()
            summary = {s["dimension"]: s for s in ledger2.get_summary(self.run_id)}
            self.assertEqual(summary["cost"]["mode"], "unavailable")
        finally:
            conn2.close()

    # ------------------------------------------- 验证预留保护（hunt 不侵占）
    def test_hunt_claim_cannot_consume_protected_verify_budget(self):
        """DSR-020 验证预算保护：hunt 领取不得占用受保护的 verify 配额，
        保护部分对 hunt 不可见但普通预留仍可用。"""
        conn = self._connect()
        try:
            ledger = BudgetLedger(conn)
            # limit 4; 30% protected for verify -> hunt may use at most ceil(4*0.7)
            # available minus the protected floor.
            ledger.set_budget(self.run_id, "tasks", limit_val=4, unit="tasks")
            queue = TaskQueue(conn)
            conn.commit()

            # Three hunt claims fill the pool down to the protected floor
            # (limit 4, protected = int(4 * 0.3) = 1 -> hunts may use 3).
            for i in range(3):
                queue.enqueue(self.run_id, f"hunt:p{i}", "hunt", {"unit_id": f"p{i}"})
            got = queue.claim(self.run_id, batch_size=3)
            conn.commit()
            self.assertEqual(len(got), 3)

            # The remaining pool is below the verify-protected floor for hunts.
            queue.enqueue(self.run_id, "hunt:p3", "hunt", {"unit_id": "p3"})
            got = queue.claim(self.run_id, batch_size=1)
            conn.commit()
            self.assertEqual(got, [], "hunt dispatch must stop at the verify-protected floor")
            events = conn.execute(
                "SELECT payload_json FROM events WHERE event_type = 'budget_exhausted' AND run_id = ?",
                (self.run_id,),
            ).fetchall()
            self.assertTrue(events, "blocked hunt dispatch must record budget_exhausted")
            import json

            self.assertIn("protected for verify", json.loads(events[-1]["payload_json"])["reason"])

            # A direct (non-hunt) reservation of the protected floor still works.
            ledger.reserve(self.run_id, "att-verify-1", "tasks", 1)
            conn.commit()
            row = self._budget_row(conn, "tasks")
            self.assertEqual(row["reserved"], 4)
            self.assertLessEqual(row["settled"] + row["reserved"], row["limit_val"])
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
