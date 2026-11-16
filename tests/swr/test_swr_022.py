"""SWR-022 acceptance tests: driver and in-session are equally supported work modes.

验收准则原文 (docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2):
| SWR-022 | SR-022 -> SD-01、SD-09 | P2 / SWR-018、SWR-023 | 实现 driver 和 in-session 共用调度、
  领取、提交及暂停切换；同一合成案例状态/报告等价，不支持委派时如实降级。 |

上游系统需求 (SYSTEM_REQUIREMENTS.md §2):
| SR-022 | driver 与 in-session 为同等支持的工作方式，共用审计语义和持久记录，运行前探测宿主能力。
  验收：同一合成案例分别完成相同状态与报告契约；宿主不支持委派或隔离时显式说明降级，
  不能把设想当作已验证。 |

绑定实现: hosts/session_adapter.py:InSessionAdapter (DSR-030/075),
app/service.py:run_dispatch_loop (driver 路径, DSR-064), hosts/doctor.py (能力披露)。
"""

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

_SKILL_SCRIPTS = Path(__file__).resolve().parents[2] / "skill" / "scripts"
if str(_SKILL_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SKILL_SCRIPTS))

from auditkit.app.service import AuditAppService  # noqa: E402
from auditkit.contracts.errors import InvalidStateError  # noqa: E402
from auditkit.hosts.concurrency import ConcurrencyController  # noqa: E402
from auditkit.hosts.doctor import Doctor  # noqa: E402
from auditkit.hosts.session_adapter import InSessionAdapter  # noqa: E402
from auditkit.ledger.db import get_db_connection  # noqa: E402
from auditkit.ledger.event_store import EventStore  # noqa: E402
from auditkit.ledger.task_queue import sha256_text  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
SKILL_DIR = REPO_ROOT / "skill"

DANGER_SOURCE = "import os\n\n\ndef handler(user_input):\n    os.system(user_input)\n"


def _attempt_usage(claim, value=20):
    """Per-attempt usage dict, as the worker execution envelope returns it."""
    return {
        "schema_version": "1.0",
        "attempt_id": claim["attempt_id"],
        "dimension": "tokens",
        "availability": "exact",
        "value": value,
        "unit": "tokens",
        "source": "host_cli_report",
    }


class _FakeAdapter:
    """Minimal host driver adapter stand-in (dispatch attributes only).

    Carries no usage state: under the per-task usage envelope the usage
    travels with each execution's return value, never on the adapter.
    """

    def __init__(self):
        self.max_retries = 2
        self.backoff_base = 0.01
        self.backoff_max = 0.05


class TestSWR022(unittest.TestCase):
    """同一合成案例 driver 与 in-session 终态/记录等价；缺委派如实降级；
    暂停后切换引擎状态保持。"""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="swr-022-"))
        self.app = AuditAppService(SKILL_DIR)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # ------------------------------------------------------------ helpers
    def _make_config(self, target, run_dir):
        return {
            "schema_version": "1.0",
            "target": str(target),
            "run_dir": str(run_dir),
            "report_language": "en",
            "profile": "standard",
            "scope": {"include": ["*"], "exclude": []},
            "budgets": [
                {"schema_version": "1.0", "dimension": "tasks", "mode": "enforced",
                 "limit": 12, "settled": 0, "reserved": 0, "unit": "tasks",
                 "availability": "exact"},
                {"schema_version": "1.0", "dimension": "tokens", "mode": "enforced",
                 "limit": 100000, "settled": 0, "reserved": 0, "unit": "tokens",
                 "availability": "exact"},
            ],
            "safety_acceptance": {
                "allow_unverified_execution": False,
                "allow_unverified_network": False,
                "allow_unverified_write": False,
                "user_approved": True,
            },
        }

    def _prepare(self, name):
        """Same synthetic case: two files, each a T1 hunt unit, plus recon."""
        target = self.temp_dir / f"target-{name}"
        (target / "src").mkdir(parents=True)
        (target / "src" / "mod_a.py").write_text(DANGER_SOURCE, encoding="utf-8")
        (target / "src" / "mod_b.py").write_text(DANGER_SOURCE, encoding="utf-8")
        run_dir = self.temp_dir / f"run-{name}"
        config = self._make_config(target, run_dir)
        prep = self.app.prepare(target, run_dir, config)
        self.app.activate(prep["run_id"], run_dir)
        return prep["run_id"], run_dir

    @staticmethod
    def _worker_result(claim):
        """Deterministic synthetic worker output, shared by BOTH engines."""
        kind = (claim.get("spec") or {}).get("task_kind") or "hunt"
        records = []
        if kind == "recon":
            records = [{
                "schema_version": "1.0",
                "guard_id": "guard-shared",
                "status": "observed",
                "mechanism": "shared synthetic guard",
                "anchors": [],
                "applicability": "",
                "exceptions": [],
            }]
        return {
            "schema_version": "1.0",
            "task_id": claim["task_id"],
            "attempt_id": claim["attempt_id"],
            "kind": kind,
            "coverage": [],
            "records": records,
            "overflow": [],
        }

    def _db_counts(self, run_dir):
        conn = get_db_connection(Path(run_dir) / "events.db")
        try:
            tasks = {
                r["state"]: r["c"]
                for r in conn.execute(
                    "SELECT state, count(*) c FROM tasks GROUP BY state"
                ).fetchall()
            }
            attempts = conn.execute("SELECT count(*) c FROM attempts").fetchone()["c"]
            receipts = conn.execute(
                "SELECT count(*) c FROM attempts WHERE result_digest IS NOT NULL"
            ).fetchone()["c"]
            usage = conn.execute(
                "SELECT dimension, availability, value, count(*) c FROM usage_records "
                "GROUP BY dimension, availability, value"
            ).fetchall()
            return {
                "tasks": tasks,
                "attempts": attempts,
                "results": receipts,
                "usage": [dict(r) for r in usage],
            }
        finally:
            conn.close()

    def _projection(self, run_dir):
        conn = get_db_connection(Path(run_dir) / "events.db")
        try:
            run_id = conn.execute("SELECT run_id FROM runs LIMIT 1").fetchone()["run_id"]
            return EventStore(conn).replay_events(run_id)
        finally:
            conn.close()

    def _budget_summary(self, run_dir, run_id):
        conn = get_db_connection(Path(run_dir) / "events.db")
        try:
            from auditkit.ledger.budget import BudgetLedger

            return {
                s["dimension"]: {
                    k: s[k] for k in ("mode", "limit", "settled", "reserved",
                                      "availability", "value")
                }
                for s in BudgetLedger(conn).get_summary(run_id)
            }
        finally:
            conn.close()

    # --------------------------------- 同一合成案例两路径等价
    def test_same_synthetic_case_driver_and_in_session_equivalent(self):
        """同一合成案例分别经 driver（run_dispatch_loop + 假宿主 execute_fn）与
        in-session（InSessionAdapter next/start/submit）完成：终态、任务分布、
        预算汇总、事件投影与用量记录全部等价（共用调度/领取/提交语义）。"""
        facts = {}
        for mode in ("driver", "in_session"):
            run_id, run_dir = self._prepare(mode)
            adapter = _FakeAdapter()

            if mode == "driver":
                def execute_fn(claim):
                    # Per-task usage envelope: the usage dict is returned by
                    # the same call that produced the result.
                    return self._worker_result(claim), _attempt_usage(claim)

                summary = self.app.run_dispatch_loop(
                    run_id, run_dir,
                    execute_fn,
                    adapter=adapter,
                    controller=ConcurrencyController(initial=2, maximum=2),
                )
                self.assertEqual(summary["stop_reason"], "queue_drained")
                self.assertEqual(summary["failed"], 0)
            else:
                session = InSessionAdapter(self.app, run_dir)
                while True:
                    claims = session.next_task(run_id, batch_size=10)
                    if not claims:
                        break
                    for claim in claims:
                        session.start_task(claim)
                        result = self._worker_result(claim)
                        usage = self.app.build_usage(
                            _attempt_usage(claim), claim["attempt_id"]
                        )
                        session.submit_task(claim, result, sha256_text(
                            json.dumps(result, sort_keys=True, ensure_ascii=False)
                        ), usage=usage)

            fin = self.app.finalize(run_id, run_dir, findings=[])
            facts[mode] = {
                "final_state": fin["final_state"],
                "gates": fin["gates"],
                "incomplete_reasons": fin["incomplete_reasons"],
                "status": self.app.status(run_id, run_dir),
                "counts": self._db_counts(run_dir),
                "projection": self._projection(run_dir),
                "budgets": self._budget_summary(run_dir, run_id),
            }

        driver, in_session = facts["driver"], facts["in_session"]

        # 1. Same terminal contract.
        self.assertEqual(driver["final_state"], "complete")
        self.assertEqual(in_session["final_state"], driver["final_state"])
        self.assertEqual(driver["status"]["state"], "complete")
        self.assertEqual(in_session["status"]["state"], driver["status"]["state"])
        self.assertEqual(driver["gates"], in_session["gates"])
        self.assertEqual(driver["incomplete_reasons"], in_session["incomplete_reasons"])

        # 2. Same task-state distribution (recon + 2 hunts all done).
        self.assertEqual(driver["counts"]["tasks"], in_session["counts"]["tasks"])
        self.assertEqual(driver["counts"]["tasks"].get("done"), 3)
        # One result per task — no path double-accepted a result.
        self.assertEqual(driver["counts"]["results"], 3)
        self.assertEqual(in_session["counts"]["results"], driver["counts"]["results"])

        # 3. Same event-log projection: shared claim/submit semantics.
        for key in ("tasks_enqueued", "claims", "submissions", "run_state",
                    "revision_consistent"):
            self.assertEqual(driver["projection"][key], in_session["projection"][key],
                             f"projection key {key} differs across engines")
        self.assertEqual(driver["projection"]["claims"], 3)
        self.assertEqual(driver["projection"]["submissions"], 3)

        # 4. Same budget accounting and trusted-usage records.
        self.assertEqual(driver["budgets"], in_session["budgets"])
        self.assertEqual(driver["counts"]["usage"], in_session["counts"]["usage"])
        tokens = driver["budgets"]["tokens"]
        self.assertEqual(tokens["availability"], "exact")
        self.assertEqual(tokens["settled"], 60, "3 attempts x 20 tokens each")

    # ------------------------------- 缺委派如实标 sequential_fallback
    def test_missing_delegation_honestly_labeled_sequential_fallback(self):
        """未测/无委派：adapter 模式如实为 sequential_fallback，doctor 能力矩阵
        按真实模式披露；未执行委派试探时保持 UNKNOWN，绝不静默升级为 enforced。"""
        run_id, run_dir = self._prepare("fallback")
        adapter = InSessionAdapter(self.app, run_dir)  # delegation unmeasured
        self.assertEqual(adapter.mode, "sequential_fallback")
        self.assertIsNone(adapter.supports_subagents)

        # A failed delegation trial keeps the honest fallback label.
        def reject(_prompt):
            raise RuntimeError("host cannot spawn sub-agents")

        feature = adapter.probe_delegation(reject, probe_level="aggressive")
        self.assertEqual(feature["state"], "unknown")
        self.assertEqual(adapter.mode, "sequential_fallback")
        self.assertFalse(adapter.supports_subagents)

        # The doctor reports the REAL session shape with per-feature evidence.
        caps = Doctor().probe(probe_cli=False, session_mode=adapter.mode)
        session_cap = next(c for c in caps if c["adapter"] == "in_session")
        fallback = session_cap["features"]["sequential_session_fallback"]
        self.assertEqual(fallback["state"], "enforced")
        self.assertEqual(fallback["method"], "InSessionAdapter mode introspection")
        self.assertIn("sequential", fallback["evidence"])

        delegation = session_cap["features"]["subagent_delegation"]
        self.assertEqual(delegation["state"], "unknown")
        self.assertIn("method", delegation)
        self.assertNotIn("evidence", delegation)

        # Unmeasured session mode stays UNKNOWN, never promoted.
        caps = Doctor().probe(probe_cli=False, session_mode=None)
        session_cap = next(c for c in caps if c["adapter"] == "in_session")
        self.assertEqual(
            session_cap["features"]["sequential_session_fallback"]["state"], "unknown"
        )

        # The measured subagent mode is also disclosed as such.
        caps = Doctor().probe(probe_cli=False, session_mode="subagent")
        session_cap = next(c for c in caps if c["adapter"] == "in_session")
        self.assertEqual(
            session_cap["features"]["sequential_session_fallback"]["state"], "enforced"
        )
        self.assertIn("sub-agent", session_cap["features"]["sequential_session_fallback"]["evidence"])

    # ----------------------------- 暂停后切换引擎状态保持
    def test_pause_then_engine_switch_preserves_state_and_record(self):
        """driver 派发 1 个任务后暂停：两条路径都如实拒绝新派发（stop sequence），
        resume+activate 后 in-session 接续完成，终态 complete，账本无重复结果。"""
        run_id, run_dir = self._prepare("switch")
        adapter = _FakeAdapter()

        # Driver path: dispatch exactly one task, then stop on the caller cap.
        summary = self.app.run_dispatch_loop(
            run_id, run_dir,
            lambda claim: self._worker_result(claim),
            adapter=adapter,
            controller=ConcurrencyController(initial=1, maximum=1),
            max_batches=1,
        )
        self.assertEqual(summary["batches"], 1)
        self.assertEqual(summary["submitted"], 1)
        self.assertIsNone(summary["stop_reason"], "caller-cap stop, not a queue/state stop")

        conn = get_db_connection(run_dir / "events.db")
        try:
            receipt_before = conn.execute(
                "SELECT attempt_id, receipt_ref FROM attempts WHERE result_digest IS NOT NULL"
            ).fetchall()
        finally:
            conn.close()
        self.assertEqual(len(receipt_before), 1)

        # Pause: dispatch stops for BOTH engines; in-flight leases are reported.
        paused = self.app.pause(run_id, run_dir, reason="engine switch under test")
        self.assertEqual(paused["state"], "paused")
        self.assertEqual(paused["in_flight_tasks"], 0)

        # Driver path refuses new dispatch with the honest stop reason.
        summary = self.app.run_dispatch_loop(
            run_id, run_dir, lambda claim: self._worker_result(claim), adapter=adapter
        )
        self.assertEqual(summary["batches"], 0)
        self.assertEqual(summary["stop_reason"], "paused_or_blocked")

        # In-session path is refused through the same stop sequence.
        session = InSessionAdapter(self.app, run_dir)
        with self.assertRaises(InvalidStateError):
            session.next_task(run_id)

        # Resume verifies integrity, activate re-opens dispatch; the in-session
        # engine continues on the SAME persistent record.
        resumed = self.app.resume(run_id, run_dir)
        self.assertTrue(resumed["verified"])
        self.app.activate(run_id, run_dir)

        dispatched = 0
        while True:
            claims = session.next_task(run_id, batch_size=10)
            if not claims:
                break
            for claim in claims:
                session.start_task(claim)
                result = self._worker_result(claim)
                usage = self.app.build_usage(_attempt_usage(claim), claim["attempt_id"])
                session.submit_task(claim, result, sha256_text(
                    json.dumps(result, sort_keys=True, ensure_ascii=False)
                ), usage=usage)
                dispatched += 1
        self.assertEqual(dispatched, 2, "the remaining two tasks are done in-session")

        fin = self.app.finalize(run_id, run_dir, findings=[])
        self.assertEqual(fin["final_state"], "complete")

        conn = get_db_connection(run_dir / "events.db")
        try:
            receipts = conn.execute(
                "SELECT attempt_id, receipt_ref, task_id FROM attempts "
                "WHERE result_digest IS NOT NULL ORDER BY attempt_id"
            ).fetchall()
            tasks_by_state = {
                r["state"]: r["c"]
                for r in conn.execute("SELECT state, count(*) c FROM tasks GROUP BY state").fetchall()
            }
            task_ids_with_results = [r["task_id"] for r in receipts]
        finally:
            conn.close()
        # State survived the engine switch: 3 tasks, 3 results, no duplicates.
        self.assertEqual(tasks_by_state.get("done"), 3)
        self.assertEqual(len(receipts), 3)
        self.assertEqual(len(set(task_ids_with_results)), 3)
        self.assertEqual(
            {r["attempt_id"]: r["receipt_ref"] for r in receipts}[receipt_before[0]["attempt_id"]],
            receipt_before[0]["receipt_ref"],
            "the driver-phase receipt must survive the engine switch untouched",
        )
        # The run_state projection reconciles across the switch.
        projection = self._projection(run_dir)
        self.assertEqual(projection["run_state"], "complete")
        self.assertTrue(projection["revision_consistent"])


if __name__ == "__main__":
    unittest.main()
