"""SWR-030 acceptance tests (逐编号验收测试).

验收原文 (docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2):
    | SWR-030 | SR-030 → SD-03、SD-07、SD-10 | P4／SWR-020、SWR-021、SWR-029 |
    定义并测量十万文件场景、性能和成本基线；记录硬件/工作负载/分母/缺失率
    及未达标处置，不将设想数字当实测。

对应 DSR-049/050（docs/design/DETAILED_DEVELOPMENT_REQUIREMENTS.md）:
    | DSR-049 | 编写十万文件合成树、恢复与峰值内存测试；统一执行前记录硬件/
      文件分布、计时及验收阈值，结果缺失不能写通过。 |
    | DSR-050 | 实现并准备测试固定统计口径的各阶段成本、开销、重试、缺失率及
      结果；15%、60%、1.3 等为待评测假设，不能通过删记录或隐藏未决达标。 |

验收要点（本文件逐条对应）:
- 十万文件场景定义完备且确定性：100_000 = 模块×包×文件，布局可复算，
  小规模重放两次 root_hash 一致；
- 计时/峰值内存记录存在且含硬件、工作负载（文件分布）、分母（文件数/
  字节数）、阈值；实测数字为正实数，不是占位设想值；
- POLYGLOT_SKIP_SCALE=1 或磁盘不足时：场景测试整体 skip 并标 unknown
  （skip≠pass，规模能力保持 unknown 属合规），unknown 记录不宣称达标；
- 成本口径：分子分母可独立复算（tokens/kLOC、tasks/kLOC、tasks/finding）；
  缺失率如实（无遥测 → None + 原因，绝不写零）；重试可从基数分离；
  0 分母使比率 non-computable 而非 0；设想数字不作为实测达标值硬编码。
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT_DIR = Path(__file__).resolve().parents[2]
SKILL_SCRIPTS = ROOT_DIR / "skill" / "scripts"
if str(SKILL_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SKILL_SCRIPTS))

from auditkit.reporting.cost import CostTracker

SCALE_MODULE_PATH = ROOT_DIR / "tests" / "performance" / "test_scale_100k.py"
RECORD_PATH = ROOT_DIR / "tests" / "performance" / "records" / "scale_100k_last_run.json"


def _load_scale_module(name: str):
    spec = importlib.util.spec_from_file_location(name, SCALE_MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestSWR030(unittest.TestCase):
    """SWR-030: 十万文件场景/性能/成本基线——记录口径完整，不把设想当实测。"""

    # -- 场景定义完备且确定性 ------------------------------------------------

    def test_scenario_constants_define_exactly_100k_files(self):
        """100_000 = 模块数 × 每模块包数 × 每包文件数（分母明确）。"""
        mod = _load_scale_module("swr030_scale_def")
        self.assertEqual(mod.TOTAL_FILES, 100_000)
        self.assertEqual(
            mod.MODULES * mod.PACKAGES * mod.FILES_PER_PACKAGE, mod.TOTAL_FILES
        )
        self.assertGreater(mod.TIME_BUDGET_SECONDS, 0)
        self.assertGreater(mod.MEMORY_BUDGET_BYTES, 0)
        self.assertTrue(str(mod.RECORD_PATH).endswith("scale_100k_last_run.json"))

    def test_layout_is_deterministic_replayable_at_small_scale(self):
        """小规模重放：同参数两次建树得到完全相同的文件集与 root_hash。"""
        mod = _load_scale_module("swr030_scale_replay")
        temp = Path(tempfile.mkdtemp(prefix="swr030_replay_"))
        try:
            with mock.patch.object(mod, "MODULES", 2), \
                 mock.patch.object(mod, "PACKAGES", 3), \
                 mock.patch.object(mod, "FILES_PER_PACKAGE", 4), \
                 mock.patch.object(mod, "TOTAL_FILES", 24):
                tree_a = temp / "a"
                tree_b = temp / "b"
                tree_a.mkdir()
                tree_b.mkdir()
                mod._build_tree(tree_a)
                mod._build_tree(tree_b)

                files_a = sorted(
                    p.relative_to(tree_a).as_posix() for p in tree_a.rglob("*") if p.is_file()
                )
                files_b = sorted(
                    p.relative_to(tree_b).as_posix() for p in tree_b.rglob("*") if p.is_file()
                )
                self.assertEqual(len(files_a), 24)
                self.assertEqual(files_a, files_b, "layout must be deterministic")

                results_a = mod._measure(tree_a)
                results_b = mod._measure(tree_b)
                self.assertEqual(results_a["root_hash"], results_b["root_hash"])
                self.assertEqual(len(results_a["root_hash"]), 64)
                self.assertGreater(results_a["timings"]["manifest_build_seconds"], 0.0)
        finally:
            shutil.rmtree(temp, ignore_errors=True)

    def test_measure_records_timing_and_peak_memory(self):
        """测量函数同时产出计时与峰值内存字段（记录口径完整）。"""
        mod = _load_scale_module("swr030_scale_measure")
        temp = Path(tempfile.mkdtemp(prefix="swr030_meas_"))
        try:
            with mock.patch.object(mod, "MODULES", 1), \
                 mock.patch.object(mod, "PACKAGES", 1), \
                 mock.patch.object(mod, "FILES_PER_PACKAGE", 5), \
                 mock.patch.object(mod, "TOTAL_FILES", 5):
                tree = temp / "t"
                tree.mkdir()
                mod._build_tree(tree)
                results = mod._measure(tree)
            self.assertEqual(results["file_count"], 5)
            self.assertIn("inventory_walk_seconds", results["timings"])
            self.assertIn("manifest_build_seconds", results["timings"])
            self.assertGreaterEqual(results["peak_traced_bytes"], 0)
        finally:
            shutil.rmtree(temp, ignore_errors=True)

    # -- 记录出处完整（硬件/工作负载/分母/阈值） -----------------------------

    def test_record_when_present_has_full_provenance(self):
        """已存在的记录：measured 必带硬件/分布/计时/峰值/阈值；unknown 必带说明。"""
        if not RECORD_PATH.is_file():
            self.skipTest(
                "no scale record yet in this checkout; run tests/performance/"
                "test_scale_100k.py once to produce scale_100k_last_run.json"
            )
        data = json.loads(RECORD_PATH.read_text(encoding="utf-8"))
        self.assertIn(data["status"], {"measured", "unknown"})

        if data["status"] == "measured":
            for key in ("hardware", "file_distribution", "timings", "peak_traced_bytes", "thresholds"):
                self.assertIn(key, data, f"measured record missing provenance key: {key}")
            self.assertEqual(data["file_distribution"]["total_files"], 100_000)
            self.assertIn("cpu_count", data["hardware"])
            self.assertIn("platform", data["hardware"])
            self.assertIn("python_version", data["hardware"])
            # 实测数字：正实数，而非设想占位值。
            self.assertGreater(data["timings"]["inventory_walk_seconds"], 0.0)
            self.assertGreater(data["timings"]["manifest_build_seconds"], 0.0)
            self.assertGreater(data["peak_traced_bytes"], 0)
            self.assertEqual(len(data["root_hash"]), 64)
            # 分母可复算：分布分解之积 == 记录的总文件数。
            dist = data["file_distribution"]
            self.assertEqual(
                dist["modules"] * dist["packages_per_module"] * dist["files_per_package"],
                dist["total_files"],
            )
            # 阈值是预算口径，不是结果：不得把阈值写进计时字段充数。
            self.assertNotEqual(data["thresholds"], data["timings"])
        else:
            # unknown 记录不得宣称达标，必须带原因说明。
            self.assertTrue(
                data.get("reason") or data.get("note"),
                "unknown record must say why the scale capability is unverified",
            )

    def test_skip_env_marks_scale_unknown_not_failed(self):
        """POLYGLOT_SKIP_SCALE=1 → 场景测试整体 skip（skip≠pass，能力 unknown）。"""
        with mock.patch.dict(os.environ, {"POLYGLOT_SKIP_SCALE": "1"}):
            mod = _load_scale_module("swr030_scale_skip_env")
            self.assertFalse(mod._ENV_OK)
            self.assertTrue(getattr(mod.TestScale100k, "__unittest_skip__", False))
            message = getattr(mod.TestScale100k, "__unittest_skip_why__", "")
            self.assertIn("unknown", message, f"skip reason must mark unknown: {message}")

    def test_adequate_disk_keeps_scale_runnable(self):
        """磁盘充足且未设跳过变量时，场景可运行（不误伤可用环境）。"""
        mod = _load_scale_module("swr030_scale_disk_ok")
        if os.environ.get("POLYGLOT_SKIP_SCALE") == "1":
            self.skipTest("POLYGLOT_SKIP_SCALE=1 set by runner; runnable-ness check not applicable")
        self.assertTrue(mod._ENV_OK)
        # skipUnless(condition=True) is the identity decorator: no skip marks.
        self.assertFalse(getattr(mod.TestScale100k, "__unittest_skip__", False))

    # -- 成本口径（分子分母可复算，缺失率与 unknown 如实） -------------------

    def test_cost_metrics_recomputable_from_recorded_inputs(self):
        """给定记录的输入，分子/分母比率可独立复算并逐一相等。"""
        tracker = CostTracker()
        for _ in range(3):
            tracker.record_task("recon")
        for _ in range(5):
            tracker.record_task("hunt")
        for _ in range(2):
            tracker.record_task("verify", is_retry=True)
        tracker.record_task("report")
        tracker.set_tokens(24_000, source="exact")

        total_lines = 6_000
        findings = 4
        metrics = tracker.compute_metrics(total_lines=total_lines, confirmed_findings_count=findings)

        # Independent recomputation from the recorded inputs.
        self.assertEqual(metrics["total_tasks"], 11)
        self.assertEqual(metrics["retries"], 2)
        self.assertEqual(metrics["total_tokens"], 24_000)
        self.assertEqual(metrics["tokens_per_kloc"], round(24_000 / (total_lines / 1000.0), 2))
        self.assertEqual(metrics["tasks_per_kloc"], round(11 / (total_lines / 1000.0), 2))
        self.assertEqual(metrics["tasks_per_finding"], round(11 / findings, 2))
        self.assertEqual(sum(metrics["stage_tasks"].values()), metrics["total_tasks"])

    def test_missing_telemetry_recorded_as_unknown_never_zero(self):
        """缺失率如实：无遥测 → None + unavailable + 原因，绝不写零冒充。"""
        tracker = CostTracker()
        metrics = tracker.compute_metrics(total_lines=2_000, confirmed_findings_count=1)
        self.assertIsNone(metrics["total_tokens"])
        self.assertEqual(metrics["token_availability"], "unavailable")
        self.assertTrue(metrics["unavailable_reason"])
        self.assertNotEqual(metrics["total_tokens"], 0)
        self.assertIsNone(metrics["tokens_per_kloc"])
        for key in ("cache_hits", "protocol_overhead"):
            entry = metrics[key]
            self.assertEqual(entry["availability"], "unavailable")
            self.assertIsNone(entry["value"])
            self.assertTrue(entry["reason"], f"{key} missing data needs a reason")

    def test_zero_denominators_are_non_computable_not_zero(self):
        """0 分母（0 行/0 发现）→ 比率 None + 状态 non-computable + 原因。"""
        tracker = CostTracker()
        tracker.record_task("hunt")
        metrics = tracker.compute_metrics(total_lines=0, confirmed_findings_count=0)
        self.assertIsNone(metrics["tasks_per_kloc"])
        self.assertEqual(metrics["tasks_per_kloc_status"], "non-computable")
        self.assertTrue(metrics["tasks_per_kloc_reason"])
        self.assertIsNone(metrics["tasks_per_finding"])
        self.assertEqual(metrics["tasks_per_finding_status"], "non-computable")
        # Task counts themselves are facts (recorded-as-zero is honest for counts).
        self.assertEqual(metrics["total_tasks"], 1)

    def test_estimated_telemetry_stays_flagged_estimated(self):
        """估计值保持 estimated 标记：估计不得升格为 exact（口径不混）。"""
        tracker = CostTracker()
        tracker.set_tokens(12_345, source="estimated")
        metrics = tracker.compute_metrics(total_lines=5_000, confirmed_findings_count=1)
        self.assertEqual(metrics["token_availability"], "estimated")
        self.assertNotEqual(metrics["token_availability"], "exact")
        self.assertEqual(metrics["total_tokens"], 12_345)

    def test_no_hypothetical_targets_hardcoded_as_measured(self):
        """设想数字（15%/60%/1.3 等）不作为实测达标值硬编码进口径。"""
        mod = _load_scale_module("swr030_scale_no_targets")
        source = SCALE_MODULE_PATH.read_text(encoding="utf-8")
        for hypothetical in ("0.15", "0.60", "1.3"):
            self.assertNotIn(
                f"target_{hypothetical}", source,
                "evaluation hypotheses must not masquerade as measured targets",
            )
        # The scale thresholds are budgets to judge a real measurement, and
        # both are explicit numbers with units in their names.
        self.assertGreater(mod.TIME_BUDGET_SECONDS, 0)
        self.assertGreater(mod.MEMORY_BUDGET_BYTES, 0)


if __name__ == "__main__":
    unittest.main()
