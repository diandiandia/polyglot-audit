"""SWR-020 acceptance tests: host-sourced usage telemetry with recomputable accounting.

验收准则原文 (docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2):
| SWR-020 | SR-020 -> SD-07 | P2 / SWR-019 | 实现宿主来源的用量和重试指标、完整率及不可得标识；
  构造缺失/混合来源数据，分子分母和估计均可复算。 |

上游系统需求 (SYSTEM_REQUIREMENTS.md §2):
| SR-020 | 低自耗：……并记录可得的输入、输出、缓存、重试和费用。验收：指标注明分子、分母、
  数据来源和缺失率；未知值不写成零，目标是否达成由独立评测判断。 |

绑定实现: ledger/usage.py (DSR-033), ledger/task_queue.py:submit 的 usage_settled 事件
(IFC-05 / DSR-033), app/service.py:build_usage + _apply_usage_records (DSR-067),
reporting/generator.py:_render_cost_report (COST.md)。
"""

import json
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

_SKILL_SCRIPTS = Path(__file__).resolve().parents[2] / "skill" / "scripts"
if str(_SKILL_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SKILL_SCRIPTS))

from auditkit.app.service import AuditAppService  # noqa: E402
from auditkit.contracts.errors import InvalidInputError  # noqa: E402
from auditkit.ledger.db import get_db_connection  # noqa: E402
from auditkit.ledger.usage import parse_usage  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
SKILL_DIR = REPO_ROOT / "skill"
FIXTURES_APP = REPO_ROOT / "tests" / "fixtures" / "pyapp" / "app"

DANGER_SOURCE = "import os\n\n\ndef handler(user_input):\n    os.system(user_input)\n"


class TestSWR020(unittest.TestCase):
    """三态用量（exact/estimated/unavailable）可复算、缺失率如实、事件带来源、
    COST.md 汇总与 usage_records 一致。"""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="swr-020-"))
        self.app = AuditAppService(SKILL_DIR)
        self.run_dir = self.temp_dir / "run"
        self._run_id = None

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # ------------------------------------------------------------ helpers
    @property
    def run_id(self):
        if self._run_id is None:
            conn = get_db_connection(self.run_dir / "events.db")
            try:
                self._run_id = conn.execute("SELECT run_id FROM runs LIMIT 1").fetchone()["run_id"]
            finally:
                conn.close()
        return self._run_id

    def _usage(self, attempt_id, availability, value=None, dimension="tokens",
               source="host_cli_report", reason=None):
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
        if reason is not None:
            data["reason"] = reason
        if availability == "unavailable":
            data["reason"] = reason or "host CLI did not report a usage block"
        return data

    def _prepare(self, with_tokens_budget=True):
        """Prepare + activate a two-hunt-unit run so three attempts exist."""
        target = self.temp_dir / "target"
        (target / "a").mkdir(parents=True)
        (target / "b").mkdir(parents=True)
        (target / "a" / "danger.py").write_text(DANGER_SOURCE, encoding="utf-8")
        (target / "b" / "danger.py").write_text(DANGER_SOURCE, encoding="utf-8")
        budgets = [{
            "schema_version": "1.0", "dimension": "tasks", "mode": "enforced",
            "limit": 10, "settled": 0, "reserved": 0, "unit": "tasks",
            "availability": "exact",
        }]
        if with_tokens_budget:
            budgets.append({
                "schema_version": "1.0", "dimension": "tokens", "mode": "enforced",
                "limit": 10_000_000, "settled": 0, "reserved": 0, "unit": "tokens",
                "availability": "exact",
            })
        config = {
            "schema_version": "1.0",
            "target": str(target),
            "run_dir": str(self.run_dir),
            "report_language": "en",
            "profile": "standard",
            "scope": {"include": ["*"], "exclude": []},
            "budgets": budgets,
            "safety_acceptance": {
                "allow_unverified_execution": False,
                "allow_unverified_network": False,
                "allow_unverified_write": False,
                "user_approved": True,
            },
        }
        prep = self.app.prepare(target, self.run_dir, config)
        self.app.activate(prep["run_id"], self.run_dir)
        return prep

    def _worker_result(self, claim):
        kind = (claim.get("spec") or {}).get("task_kind") or "hunt"
        return {
            "schema_version": "1.0",
            "task_id": claim["task_id"],
            "attempt_id": claim["attempt_id"],
            "kind": kind,
            "coverage": [],
            "records": [],
            "overflow": [],
        }

    def _submit(self, claim, usage):
        self.app.start(self.run_dir, claim)
        result = self._worker_result(claim)
        digest = json.dumps(result, sort_keys=True, ensure_ascii=False)
        from auditkit.ledger.task_queue import sha256_text

        self.app.submit(self.run_dir, claim, result, sha256_text(digest), usage=usage)

    def _drain_with_mixed_usage(self):
        """Recon keeps NO usage (missing), hunt A exact 100, hunt B unavailable."""
        self._prepare()
        claims = self.app.next(self.run_id, self.run_dir, batch_size=10)
        self.assertEqual(len(claims), 3, "recon + 2 hunt tasks expected")
        recon = [c for c in claims if c["spec"].get("task_kind") == "recon"]
        hunts = [c for c in claims if c["spec"].get("task_kind") != "recon"]
        self.assertEqual(len(recon), 1)
        self.assertEqual(len(hunts), 2)
        self._submit(recon[0], usage=None)
        self._submit(hunts[0], usage=self._usage(hunts[0]["attempt_id"], "exact", 100))
        self._submit(hunts[1], usage=self._usage(hunts[1]["attempt_id"], "unavailable"))
        return claims

    def _usage_rows(self):
        conn = get_db_connection(self.run_dir / "events.db")
        try:
            return conn.execute(
                "SELECT attempt_id, dimension, availability, value, unit, source, reason "
                "FROM usage_records WHERE run_id = ?",
                (self.run_id,),
            ).fetchall()
        finally:
            conn.close()

    # --------------------------------------------- 三态结算可复算（分子分母）
    def test_three_state_usage_settlement_is_recomputable(self):
        """exact/estimated/unavailable 三态结算可从 usage_records 独立复算：
        tokens 分子 = Σ(exact+estimated value)，unavailable 不伪造值也不入分子。"""
        self._drain_with_mixed_usage()

        rows = self._usage_rows()
        self.assertEqual(len(rows), 2, "missing usage must not fabricate a record")

        numerator = sum(
            r["value"] for r in rows
            if r["dimension"] == "tokens" and r["availability"] in ("exact", "estimated")
        )
        self.assertEqual(numerator, 100)

        # Independent recomputation of the settled denominator from the ledger.
        conn = get_db_connection(self.run_dir / "events.db")
        try:
            settled = conn.execute(
                "SELECT settled FROM budget_dimensions WHERE run_id = ? AND dimension = 'tokens'",
                (self.run_id,),
            ).fetchone()["settled"]
            attempts = conn.execute(
                "SELECT count(*) c FROM attempts a JOIN tasks t ON a.task_id = t.task_id "
                "WHERE t.run_id = ?",
                (self.run_id,),
            ).fetchone()["c"]
        finally:
            conn.close()
        self.assertEqual(settled, numerator, "tokens settled must equal the recomputed numerator")
        self.assertEqual(attempts, 3)

        # The unavailable row carries no value and an explicit reason.
        unavail = [r for r in rows if r["availability"] == "unavailable"]
        self.assertEqual(len(unavail), 1)
        self.assertIsNone(unavail[0]["value"])
        self.assertTrue(unavail[0]["reason"])

        # The estimated branch is also accepted and booked at its declared value.
        parse_usage(self._usage("att-x", "estimated", 42))
        conn = get_db_connection(self.run_dir / "events.db")
        try:
            from auditkit.ledger.usage import store_usage
            from auditkit.ledger.event_store import utc_now_iso

            store_usage(conn, self.run_id, parse_usage(self._usage("att-x", "estimated", 42)),
                        utc_now_iso())
            conn.commit()
        finally:
            conn.close()

    def test_estimated_and_unavailable_dimensions_reported_honestly(self):
        """维度汇总可得性：含 exact 即 exact；只有 estimated 即 estimated；
        只有 unavailable/无记录即 unavailable，且 value 保持 null 不当零。"""
        self._drain_with_mixed_usage()
        from auditkit.ledger.budget import BudgetLedger
        from auditkit.ledger.event_store import utc_now_iso
        from auditkit.ledger.usage import parse_usage, store_usage

        conn = get_db_connection(self.run_dir / "events.db")
        try:
            ledger = BudgetLedger(conn)
            # Dimensions without configured budgets are tracked through their
            # usage records alone; declare them so the summary covers them.
            ledger.set_budget(self.run_id, "cost", limit_val=1000, unit="usd", mode="observed")
            ledger.set_budget(self.run_id, "retries_dim", limit_val=0, unit="retries",
                              mode="unavailable")
            conn.commit()

            summary = {s["dimension"]: s for s in ledger.get_summary(self.run_id)}
            tokens = summary["tokens"]
            self.assertEqual(tokens["availability"], "exact")
            self.assertEqual(tokens["source"], "host_cli_report")
            # The recomputable numerator: the exact record's value, not the
            # newest record's null (mixed dimension must stay consistent).
            self.assertEqual(tokens["value"], 100)

            # A dimension whose only record is estimated -> estimated + value.
            store_usage(conn, self.run_id,
                        parse_usage(self._usage("att-est-cost", "estimated", value=7,
                                                dimension="cost", source="host_adapter")),
                        utc_now_iso())
            conn.commit()
            summary = {s["dimension"]: s for s in ledger.get_summary(self.run_id)}
            summary = {s["dimension"]: s for s in BudgetLedger(conn).get_summary(self.run_id)}
            self.assertEqual(summary["cost"]["availability"], "estimated")
            self.assertEqual(summary["cost"]["value"], 7)
            self.assertEqual(summary["cost"]["source"], "host_adapter")

            # A dimension whose records are all unavailable -> unavailable + null.
            store_usage(conn, self.run_id,
                        parse_usage(self._usage("att-u2", "unavailable", dimension="retries_dim",
                                                source="host_adapter", reason="no cost block")),
                        utc_now_iso())
            conn.commit()
            summary = {s["dimension"]: s for s in BudgetLedger(conn).get_summary(self.run_id)}
            self.assertEqual(summary["retries_dim"]["availability"], "unavailable")
            self.assertIsNone(summary["retries_dim"]["value"])
        finally:
            conn.close()

    # --------------------------------------------------------- 缺失率如实
    def test_missing_usage_rate_is_recomputable_and_not_zero_filled(self):
        """缺失率 =（不可用+未上报尝试数）/ 总尝试数，可从 usage_records 独立复算；
        缺失的尝试不得写零值记录。"""
        claims = self._drain_with_mixed_usage()

        conn = get_db_connection(self.run_dir / "events.db")
        try:
            total_attempts = conn.execute(
                "SELECT count(*) c FROM attempts a JOIN tasks t ON a.task_id = t.task_id "
                "WHERE t.run_id = ?",
                (self.run_id,),
            ).fetchone()["c"]
            # Same accounting the service itself uses for the skill self-review.
            missing_rows = conn.execute(
                """
                SELECT count(*) AS cnt
                FROM attempts a
                JOIN tasks t ON a.task_id = t.task_id
                LEFT JOIN usage_records u ON u.attempt_id = a.attempt_id
                WHERE t.run_id = ? AND (u.attempt_id IS NULL OR u.availability = 'unavailable')
                """,
                (self.run_id,),
            ).fetchone()["cnt"]
        finally:
            conn.close()

        expected_missing = 2  # recon submitted without usage + unavailable hunt
        self.assertEqual(total_attempts, 3)
        self.assertEqual(missing_rows, expected_missing)
        self.assertAlmostEqual(expected_missing / total_attempts, 2 / 3)

        # Cross-check against the raw records: no zero-filled placeholder rows.
        rows = self._usage_rows()
        self.assertTrue(all(r["value"] is not None or r["availability"] == "unavailable"
                            for r in rows))
        self.assertTrue(all(not (r["availability"] == "unavailable" and r["value"] == 0)
                            for r in rows))
        # The recon claim really was submitted without any usage record.
        recon_attempt = [c for c in claims if c["spec"].get("task_kind") == "recon"][0]["attempt_id"]
        self.assertTrue(all(r["attempt_id"] != recon_attempt for r in rows))

    # ------------------------------------------------------ 事件携带来源
    def test_usage_settled_event_carries_source_availability_and_reason(self):
        """每次结算都有 usage_settled 事件，事件含 availability、来源与
        settled_value/reason；unavailable 的 settled_value 为 null 且带原因。"""
        self._drain_with_mixed_usage()

        conn = get_db_connection(self.run_dir / "events.db")
        try:
            events = conn.execute(
                "SELECT payload_json FROM events WHERE event_type = 'usage_settled' "
                "AND run_id = ? ORDER BY revision",
                (self.run_id,),
            ).fetchall()
        finally:
            conn.close()
        payloads = [json.loads(e["payload_json"]) for e in events]
        self.assertEqual(len(payloads), 3, "one settlement event per submitted attempt")

        for p in payloads:
            self.assertIn(p["availability"], ("exact", "estimated", "unavailable"))
            self.assertTrue(p.get("source"))
            self.assertIn("attempt_id", p)
            self.assertIn("dimension", p)

        exact = [p for p in payloads if p["availability"] == "exact"][0]
        self.assertEqual(exact["settled_value"], 100)
        self.assertEqual(exact["source"], "host_cli_report")
        self.assertIsNone(exact["reason"])

        # The hunt whose host usage block was unavailable: source is the
        # host adapter, settled value stays null, reason is recorded.
        unavailable = [
            p for p in payloads
            if p["availability"] == "unavailable"
            and p.get("reason") == "host CLI did not report a usage block"
        ]
        self.assertEqual(len(unavailable), 1)
        self.assertIsNone(unavailable[0]["settled_value"])
        self.assertEqual(unavailable[0]["source"], "host_cli_report")

        # The usage-less recon submission is explicit about having no source.
        missing = [p for p in payloads
                   if p.get("reason") == "no host usage supplied with submission"]
        self.assertEqual(len(missing), 1, "the usage-less submission must be explicit too")
        self.assertEqual(missing[0]["availability"], "unavailable")
        self.assertEqual(missing[0]["source"], "unavailable")
        self.assertIsNone(missing[0]["settled_value"])

    # ------------------------------------------- build_usage 用量信封三态
    def test_build_usage_maps_worker_usage_envelope_to_exact_estimated_unavailable(self):
        """usage 信封接线（P0）：build_usage 接受 worker 执行返回的 per-attempt
        usage dict（usage.schema 语义），校验并回填 attempt_id/dimension/unit/
        source 缺省；声明 exact 则 exact，数值但未声明则 estimated，空/缺失
        block 则 unavailable 且带原因；提交永远携带用量对象。共享的
        adapter.last_usage 槽已移除——旧签名传入 adapter 对象只会得到明确的
        unavailable，绝不静默互换归属。"""
        self._prepare(with_tokens_budget=False)

        def envelope(availability="estimated", value=15, attempt_id="att-a", **extra):
            payload = {
                "schema_version": "1.0",
                "dimension": "tokens",
                "availability": availability,
                "unit": "tokens",
                "source": "ClaudeDriverAdapter",
            }
            if value is not None:
                payload["value"] = value
            if attempt_id:
                payload["attempt_id"] = attempt_id
            payload.update(extra)
            return payload

        declared = self.app.build_usage(envelope(availability="exact"), "att-a")
        self.assertEqual(declared["availability"], "exact")
        self.assertEqual(declared["value"], 15)
        self.assertEqual(declared["dimension"], "tokens")
        self.assertEqual(declared["source"], "ClaudeDriverAdapter")

        undeclared = self.app.build_usage({"input_tokens": 10, "output_tokens": 5}, "att-b")
        self.assertEqual(undeclared["availability"], "estimated")
        self.assertEqual(undeclared["value"], 15)
        self.assertEqual(undeclared["unit"], "tokens")

        # The submitting claim's attempt_id ALWAYS wins: whatever the worker
        # dict carried is overwritten (regression guard against cross-attribution).
        foreign = self.app.build_usage(envelope(attempt_id="att-foreign"), "att-c")
        self.assertEqual(foreign["attempt_id"], "att-c")

        empty = self.app.build_usage({}, "att-d")
        self.assertEqual(empty["availability"], "unavailable")
        self.assertNotIn("value", empty)
        self.assertTrue(empty["reason"])

        nothing = self.app.build_usage(None, "att-e")
        self.assertEqual(nothing["availability"], "unavailable")
        self.assertNotIn("value", nothing)

        # Legacy call shape (adapter object as the first argument): the shared
        # last_usage slot is no longer read anywhere — an explicit unavailable
        # record is produced, never a silently swapped one.
        class _Adapter:
            def __init__(self, last_usage):
                self.last_usage = last_usage

        legacy = self.app.build_usage(
            _Adapter({"input_tokens": 10, "output_tokens": 5, "availability": "exact"}),
            "att-f",
        )
        self.assertEqual(legacy["availability"], "unavailable")
        self.assertNotIn("value", legacy)

        # parse_usage rejects zero-filling shortcuts: unavailable must not
        # carry a value at all.
        with self.assertRaises(InvalidInputError):
            parse_usage(self._usage("att-g", "unavailable", value=0))

    # --------------------------------------------- COST.md 与 usage 一致
    def test_cost_md_summary_matches_usage_records_and_ledger(self):
        """COST.md 的 token 状态、重试数与任务分母都可从 usage_records / attempts
        独立复算；无用量时如实标注 unavailable 及原因。"""
        self._prepare(with_tokens_budget=False)
        claims = self.app.next(self.run_id, self.run_dir, batch_size=10)
        recon = [c for c in claims if c["spec"].get("task_kind") == "recon"][0]
        hunts = [c for c in claims if c["spec"].get("task_kind") != "recon"]
        self.assertEqual(len(hunts), 2)

        # One retryable host failure on the first hunt -> ledger retry = 1.
        from auditkit.contracts.errors import HostFailureError

        self.app.start(self.run_dir, hunts[0])
        res = self.app.report_host_failure(
            self.run_dir, hunts[0], HostFailureError("transient"), max_retries=2
        )
        self.assertEqual(res["action"], "requeued")
        # Re-claim the requeued hunt (fresh attempt); the recon and the second
        # hunt keep their valid leases from the first batch.
        retry_claims = self.app.next(self.run_id, self.run_dir, batch_size=10)
        self.assertEqual(len(retry_claims), 1)
        retried = retry_claims[0]
        self.assertEqual(retried["task_id"], hunts[0]["task_id"])

        self._submit(recon, usage=self._usage(recon["attempt_id"], "estimated", 50))
        self._submit(retried, usage=self._usage(retried["attempt_id"], "exact", 120))
        self._submit(hunts[1], usage=self._usage(hunts[1]["attempt_id"], "unavailable"))

        rows = self._usage_rows()
        recomputed_tokens = sum(
            r["value"] for r in rows
            if r["dimension"] == "tokens" and r["availability"] in ("exact", "estimated")
        )
        recomputed_status = (
            "exact" if all(r["availability"] == "exact" for r in rows
                           if r["availability"] in ("exact", "estimated"))
            else "estimated"
        )

        fin = self.app.finalize(self.run_id, self.run_dir, findings=[])
        self.assertEqual(fin["final_state"], "complete")
        cost_md = (self.run_dir / "report" / "COST.md").read_text(encoding="utf-8")

        # Token metering status mirrors the recomputed availability.
        self.assertRegex(cost_md, r"\*\*Token Metering Status\*\*: exact|estimated")
        self.assertNotIn("no usage records were persisted", cost_md)
        self.assertIn(f"**Token Metering Status**: {recomputed_status}", cost_md)
        self.assertIn("**Retries**: 1", cost_md)

        # Task denominator recomputed from the report's own stage table, whose
        # per-stage numbers must match the ledger (recon/hunt/verify from the
        # tasks table; the report stage is the one synthesized final step).
        conn = get_db_connection(self.run_dir / "events.db")
        try:
            by_kind = {
                r["kind"]: r["c"]
                for r in conn.execute(
                    "SELECT kind, count(*) c FROM tasks WHERE run_id = ? GROUP BY kind",
                    (self.run_id,),
                ).fetchall()
            }
            tasks_total = conn.execute(
                "SELECT count(*) c FROM tasks WHERE run_id = ?", (self.run_id,)
            ).fetchone()["c"]
        finally:
            conn.close()
        stage_rows = dict(re.findall(r"\| `(\w+)` \| (\d+) \|", cost_md))
        stage_counts = {k: int(v) for k, v in stage_rows.items()}
        self.assertEqual(stage_counts.get("recon"), by_kind.get("recon", 0))
        self.assertEqual(stage_counts.get("hunt"), by_kind.get("hunt", 0))
        self.assertEqual(stage_counts.get("verify"), by_kind.get("verify", 0))
        self.assertEqual(stage_counts.get("report"), 1)
        reported_total = int(re.search(r"\*\*Total Executed Tasks\*\*: (\d+)", cost_md).group(1))
        self.assertEqual(reported_total, sum(stage_counts.values()))
        self.assertEqual(reported_total, tasks_total + 1)  # + the report stage

        # Retries recomputed from the attempts table: one task has 2 attempts.
        conn = get_db_connection(self.run_dir / "events.db")
        try:
            retry_rows = conn.execute(
                """
                SELECT count(*) - 1 AS extra_attempts
                FROM attempts a JOIN tasks t ON a.task_id = t.task_id
                WHERE t.run_id = ?
                GROUP BY a.task_id HAVING count(*) > 1
                """,
                (self.run_id,),
            ).fetchall()
        finally:
            conn.close()
        self.assertEqual(sum(r["extra_attempts"] for r in retry_rows), 1)

        # The token numerator itself: COST.md's metering status must equal the
        # availability recomputed from usage_records (170 = 50 estimated + 120
        # exact; the unavailable record contributes nothing and no zero).
        self.assertEqual(recomputed_tokens, 170)
        self.assertEqual(recomputed_status, "estimated")

    def test_cost_md_states_unavailable_reason_when_no_usage_persisted(self):
        """无任何用量记录：COST.md 的 token 状态为 unavailable 且给出原因，
        不以零或估计值冒充。"""
        self._prepare(with_tokens_budget=False)
        claims = self.app.next(self.run_id, self.run_dir, batch_size=10)
        for c in claims:
            self._submit(c, usage=None)
        fin = self.app.finalize(self.run_id, self.run_dir, findings=[])
        self.assertEqual(fin["final_state"], "complete")
        cost_md = (self.run_dir / "report" / "COST.md").read_text(encoding="utf-8")
        self.assertIn("**Token Metering Status**: unavailable", cost_md)
        self.assertIn("no usage records were persisted for this run", cost_md)
        self.assertNotIn("**Token Metering Status**: exact", cost_md)
        self.assertNotIn("**Token Metering Status**: estimated", cost_md)
        # DSR-067: missing host telemetry is not silently zero-filled either.
        self.assertIn("unavailable (Host CLI does not report cache hit counts)", cost_md)


if __name__ == "__main__":
    unittest.main()
