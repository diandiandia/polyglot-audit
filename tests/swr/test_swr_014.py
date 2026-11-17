"""SWR-014 acceptance tests (逐编号验收).

验收原文 (docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2):
    SWR-014 | SR-014 → SD-11 | P3／SWR-012、SWR-020 |
    实现本地 Skill 自审及缺失数据说明；
    测试 complete、incomplete 与写失败，无数据不得当零处理。

上游系统需求 (SYSTEM_REQUIREMENTS.md §2):
    SR-014: 每次可结束运行生成本地 Skill 自审，说明缺失数据和改进建议；
    不将缺失数据当作零处理。
    验收：complete、incomplete 与写失败三种场景的自审行为可复现。

Acceptance coverage
-------------------
1. 正常 (complete) 与不完整 (incomplete) 运行均生成本地 SKILL-REVIEW.md,
   且异常清单来自真实运行统计数据 (usage 缺失 → usage_missing 异常,
   token 遥测不可得 → cost 异常), 不是恒空清单。
2. 八类检测器 (flow/coverage/cost/verification/knowledge/adaptation/error/
   usage_missing) 在输入数据整体缺失或字段缺失时逐类标 unknown (含
   unknown_note), 不当零处理; 而真实的零测量 (total_tasks=0) 是数据驱动的
   异常, 与 unknown 语义区分。
3. 写失败: 阶段写入失败显式抛 StorageError 且失败信息包含出错的报告工件
   路径 (故障路径可见); 已发布的上一代自审保持不变 (不留下半成品);
   finalize 路径的存储失败同样显式报错并给出路径, 运行不得伪称 complete。
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SKILL_SCRIPTS = Path(__file__).resolve().parents[2] / "skill" / "scripts"
if str(SKILL_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SKILL_SCRIPTS))

from auditkit.app.service import AuditAppService  # noqa: E402
from auditkit.contracts.errors import StorageError  # noqa: E402
from auditkit.ledger.db import get_db_connection  # noqa: E402
from auditkit.reporting.generator import ReportGenerator  # noqa: E402
from auditkit.reporting.self_review import CATEGORIES, SelfReviewCollector  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
SKILL_DIR = REPO_ROOT / "skill"

DANGER_SOURCE = "import os\n\n\ndef handler(user_input):\n    os.system(user_input)\n"


class SWR014FinalizeBase(unittest.TestCase):
    """Drives the real finalize path (SKILL-REVIEW.md comes from run stats)."""

    def setUp(self) -> None:
        self.temp_dir = Path(tempfile.mkdtemp(prefix="swr014-"))
        self.app = AuditAppService(SKILL_DIR)
        self.run_dir = self.temp_dir / "run"
        self._run_id = None

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def prepare_run(self, task_budget: int = 10) -> None:
        target = self.temp_dir / "target"
        target.mkdir(parents=True)
        (target / "danger.py").write_text(DANGER_SOURCE, encoding="utf-8")
        config = {
            "schema_version": "1.0",
            "target": str(target),
            "run_dir": str(self.run_dir),
            "report_language": "en",
            "profile": "quick",
            "scope": {"include": ["*.py"], "exclude": []},
            "budgets": [{
                "schema_version": "1.0", "dimension": "tasks", "mode": "enforced",
                "limit": task_budget, "settled": 0, "reserved": 0, "unit": "tasks",
                "availability": "exact",
            }],
            "safety_acceptance": {
                "allow_unverified_execution": False,
                "allow_unverified_network": False,
                "allow_unverified_write": False,
                "user_approved": True,
            },
        }
        prep = self.app.prepare(str(target), str(self.run_dir), config)
        self.app.activate(prep["run_id"], self.run_dir)
        self._run_id = prep["run_id"]

    def worker_result(self, claim, records=()):
        kind = (claim.get("spec") or {}).get("task_kind") or "hunt"
        return {
            "schema_version": "1.0",
            "task_id": claim["task_id"],
            "attempt_id": claim["attempt_id"],
            "kind": kind,
            "coverage": [],
            "records": list(records),
            "overflow": [],
        }

    def drain(self) -> None:
        while True:
            claims = self.app.next(self.run_id, self.run_dir, batch_size=10)
            if not claims:
                break
            for claim in claims:
                self.app.start(self.run_dir, claim)
                self.app.submit(
                    self.run_dir, claim, self.worker_result(claim),
                    f"digest-{claim['attempt_id']}",
                )

    @property
    def run_id(self) -> str:
        if self._run_id is None:
            conn = get_db_connection(self.run_dir / "events.db")
            try:
                self._run_id = conn.execute("SELECT run_id FROM runs LIMIT 1").fetchone()["run_id"]
            finally:
                conn.close()
        return self._run_id

    def run_state(self) -> str:
        conn = get_db_connection(self.run_dir / "events.db")
        try:
            return conn.execute(
                "SELECT state FROM runs WHERE run_id = ?", (self.run_id,)
            ).fetchone()["state"]
        finally:
            conn.close()


class TestSWR014GeneratedPerRun(SWR014FinalizeBase):
    """每次可结束运行均生成自审, 异常来自真实统计数据。"""

    def test_complete_run_self_review_uses_real_run_statistics(self):
        self.prepare_run()
        self.drain()
        fin = self.app.finalize(self.run_id, self.run_dir, findings=[])
        self.assertEqual(fin["final_state"], "complete")

        review_path = self.run_dir / "skill-review" / "SKILL-REVIEW.md"
        self.assertTrue(review_path.exists(), "complete run must produce SKILL-REVIEW.md")
        review = review_path.read_text(encoding="utf-8")
        self.assertIn("# Skill Self-Review", review)
        self.assertIn(self.run_id, review)
        self.assertIn(fin["generation_id"], review)

        # Data-driven anomalies (no usage records were submitted; token
        # telemetry absent): the review reflects them instead of a constant
        # empty list (DSR-070 wiring through finalize).
        self.assertIn("[usage_missing]", review)
        self.assertIn("attempts lack host usage records", review)
        self.assertIn("[cost]", review)
        # Categories whose inputs WERE supplied are not marked unknown:
        # flow statistics exist, so no "input data unavailable" for flow.
        self.assertNotIn("input data unavailable: total_tasks / stage_tasks", review)
        self.assertNotIn("input data unavailable: coverage_summary", review)

    def test_incomplete_run_also_produces_self_review(self):
        """A finishable but incomplete run (budget exhausted) still gets its
        local self-review."""
        self.prepare_run(task_budget=1)
        claims = self.app.next(self.run_id, self.run_dir, batch_size=10)
        self.assertEqual(claims[0]["spec"]["task_kind"], "recon")
        for claim in claims:
            self.app.start(self.run_dir, claim)
            self.app.submit(
                self.run_dir, claim, self.worker_result(claim),
                f"digest-{claim['attempt_id']}",
            )
        fin = self.app.finalize(self.run_id, self.run_dir, findings=[])
        self.assertEqual(fin["final_state"], "incomplete")

        review_path = self.run_dir / "skill-review" / "SKILL-REVIEW.md"
        self.assertTrue(review_path.exists(), "incomplete run must also produce SKILL-REVIEW.md")
        review = review_path.read_text(encoding="utf-8")
        self.assertIn(self.run_id, review)
        self.assertIn("[usage_missing]", review)


class TestSWR014UnknownNotZero(unittest.TestCase):
    """数据不可得逐类标 unknown, 不当零处理。"""

    def test_no_input_yields_one_unknown_per_category(self):
        anomalies = SelfReviewCollector(None).collect()
        self.assertEqual(
            [a["category"] for a in anomalies], list(CATEGORIES),
            "with no input, every detector must emit exactly one unknown anomaly",
        )
        for a in anomalies:
            self.assertIn("input data unavailable", a["evidence"], a["category"])
            self.assertIn("unknown, not zero", a["impact"], a["category"])
            self.assertTrue(a["unknown_note"], a["category"])
            self.assertTrue(a["recommendation"], a["category"])

    def test_unknown_anomalies_never_claim_a_zero_measurement(self):
        """Missing data must not be reported AS a measured zero: the evidence
        records unavailability, not a '0' count."""
        for a in SelfReviewCollector(None).collect():
            self.assertNotIn(
                "recorded zero", a["evidence"],
                f"{a['category']} treated missing data as a measured zero",
            )

    def test_partially_supplied_stats_mark_only_missing_categories_unknown(self):
        stats = {
            "total_tasks": 4,
            "stage_tasks": {"hunt": 3, "report": 1},
        }
        anomalies = SelfReviewCollector(stats).collect()
        unknown_categories = sorted(a["category"] for a in anomalies if a["unknown_note"])
        self.assertEqual(
            unknown_categories,
            sorted(set(CATEGORIES) - {"flow"}),
            "only categories without inputs may be marked unknown",
        )
        self.assertFalse(
            [a for a in anomalies if a["category"] == "flow"],
            "flow had complete inputs; it must not be marked unknown",
        )

    def test_single_missing_field_marks_its_category_unknown(self):
        # cost_stats supplied but token/kloc fields missing → cost evaluated on
        # its fields, every other category unknown.
        stats = {"cost_metrics": {"token_availability": "exact", "tasks_per_kloc": 3.2}}
        anomalies = SelfReviewCollector(stats).collect()
        self.assertEqual(
            sorted(a["category"] for a in anomalies if a["unknown_note"]),
            sorted({"flow", "coverage", "verification", "knowledge",
                    "adaptation", "error", "usage_missing"}),
        )
        self.assertFalse([a for a in anomalies if a["category"] == "cost"])

    def test_measured_zero_is_data_not_unknown(self):
        """A REAL zero measurement is an evaluated finding, not an unknown:
        total_tasks=0 with complete stage data is a recorded flow anomaly and
        stays distinct from the unknown semantics."""
        stats = {
            "total_tasks": 0,
            "stage_tasks": {"hunt": 0},
            "coverage_summary": {"total_files": 1},
            "cost_metrics": {"token_availability": "exact", "tasks_per_kloc": 0.0},
            "verdict_distribution": {"confirmed": 0},
            "knowledge_gaps": [], "knowledge_version": "1.0",
            "detected_languages": ["python"], "uncovered_languages": [],
            "error_events": 0, "usage_missing_count": 0,
        }
        anomalies = SelfReviewCollector(stats).collect()
        self.assertFalse(
            [a for a in anomalies if a["unknown_note"]],
            "fully supplied statistics must not produce unknown anomalies",
        )
        flow_anomalies = [a for a in anomalies if a["category"] == "flow"]
        self.assertTrue(flow_anomalies, "a recorded zero task count is a flow anomaly")
        # "recorded zero tasks" is the measured-finding wording (in the impact
        # field); its evidence cites the actual measured value, not absence.
        zero_anomaly = next(
            (a for a in flow_anomalies if "recorded zero tasks" in a["impact"]), None
        )
        self.assertIsNotNone(zero_anomaly, "measured-zero flow finding missing")
        self.assertIn("total_tasks=0", zero_anomaly["evidence"])
        # The zero anomaly is a measured finding: no unknown note is attached.
        self.assertIsNone(zero_anomaly["unknown_note"])


class TestSWR014WriteFailure(unittest.TestCase):
    """写失败: 显式报错 + 故障路径可见 + 已发布内容保持不变。"""

    def setUp(self) -> None:
        self.temp_dir = Path(tempfile.mkdtemp(prefix="swr014w-"))
        db_path = self.temp_dir / "events.db"
        from auditkit.ledger.artifacts import ArtifactManager
        from auditkit.ledger.db import init_database
        import sqlite3
        init_database(db_path)
        self.conn = sqlite3.connect(str(db_path))
        self.conn.row_factory = sqlite3.Row
        self.conn.execute(
            """
            INSERT INTO runs (run_id, snapshot_id, state, schema_version, skill_version,
                              knowledge_version, config_ref, revision, created_at, updated_at)
            VALUES ('run-swr014', 'snp-01', 'finalizing', '1.0', '0.1.0', '1.0', 'cfg',
                    1, '2026-11-16T00:00:00Z', '2026-11-16T00:00:00Z')
            """
        )
        self.art_mgr = ArtifactManager(self.temp_dir, self.conn)
        self.generator = ReportGenerator(
            "run-swr014", "snp-01", "complete", self.art_mgr, report_language="en"
        )

    def tearDown(self) -> None:
        self.conn.close()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_stage_write_failure_raises_storage_error_naming_the_artifact(self):
        real_fsync = __import__("os").fsync

        def failing_fsync(fd):
            raise OSError("simulated artifacts write failure")

        with mock.patch("auditkit.reporting.generator.os.fsync", side_effect=failing_fsync):
            with self.assertRaises(StorageError) as ctx:
                self.generator.generate_all(
                    [], {}, {}, events=[], anomalies=[],
                )
        # The fault path is part of the error: the failing report artifact and
        # the underlying OS error are both named.
        message = str(ctx.exception)
        self.assertIn("Failed to stage report artifact", message)
        self.assertIn("report/", message, "error must name the failing report artifact")
        self.assertIn("simulated artifacts write failure", message)
        # Nothing was published: no SKILL-REVIEW.md, no staged leftovers.
        self.assertFalse((self.temp_dir / "skill-review" / "SKILL-REVIEW.md").exists())

    def test_self_review_without_any_input_is_not_rendered_as_all_clear(self):
        """SWR-014 无数据不得当零: rendering a self-review with neither
        statistics nor an explicit anomaly list produces unknown anomalies,
        not an empty 'no anomalies' report."""
        self.generator.generate_all([], {}, {}, events=[])  # no inputs at all
        review = (self.temp_dir / "skill-review" / "SKILL-REVIEW.md").read_text(encoding="utf-8")
        self.assertNotIn("No significant process or contract anomalies detected", review)
        for category in CATEGORIES:
            self.assertIn(f"[{category}]", review, f"missing unknown anomaly for {category}")
        self.assertIn("input data unavailable", review)


class TestSWR014FinalizeWriteFailure(SWR014FinalizeBase):
    """finalize 路径的存储失败: 显式报错, 不伪称 complete。"""

    def test_finalize_storage_failure_is_explicit_and_non_terminal(self):
        self.prepare_run()
        self.drain()
        # Block the publish destination: `report` exists as a file.
        (self.run_dir / "report").write_text("not a directory\n", encoding="utf-8")

        with self.assertRaises(StorageError) as ctx:
            self.app.finalize(self.run_id, self.run_dir, findings=[])
        self.assertIn("report", str(ctx.exception))
        # The run never claims a terminal complete state and no review exists.
        self.assertNotEqual(self.run_state(), "complete")
        self.assertFalse((self.run_dir / "skill-review" / "SKILL-REVIEW.md").exists())


if __name__ == "__main__":
    unittest.main()
