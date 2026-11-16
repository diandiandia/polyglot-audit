"""SWR-021 acceptance tests (逐编号验收测试).

验收原文 (docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2):
    | SWR-021 | SR-021 → SD-08 | P2／SWR-004、SWR-018 |
    实现行区间覆盖与来源分层；测试读取片段、重复块、排除、日志缺失时
    无整文件覆盖虚报。

对应 DSR-034（docs/design/DETAILED_DEVELOPMENT_REQUIREMENTS.md）:
    | DSR-034 | 实现覆盖区间并集和来源分层；局部读取不等于完整文件，
      重叠只计一次，缺日志为 unknown。 |

验收要点（本文件逐条对应）:
- 读取片段不虚增：片段区间的覆盖行数等于片段行数，绝不折算整文件；
- 重复块只计一次：重复记录与重叠记录经区间并集去重；
- 排除文件不进分母：被排除文件不出现在覆盖分解、不占清单行数；
- 日志缺失为 unknown：observed_read 无任何区间记录时按维度披露
  dimension_unknown（缺数据 ≠ 实测零覆盖），不写零；
- 五维来源分层口径正确：inventoried / signal_scanned / context_supplied /
  observed_read / review_claimed 各自独立按并集统计，逐层收窄不串层。
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

SKILL_SCRIPTS = Path(__file__).resolve().parents[2] / "skill" / "scripts"
if str(SKILL_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SKILL_SCRIPTS))

from auditkit.reporting.coverage import (
    CoverageCalculator,
    compute_interval_union,
    count_covered_lines,
)

DIMENSIONS = (
    "inventoried",
    "signal_scanned",
    "context_supplied",
    "observed_read",
    "review_claimed",
)


class TestSWR021(unittest.TestCase):
    """SWR-021: 行区间覆盖与来源分层——片段/重复/排除/缺日志均不虚报。"""

    @staticmethod
    def _manifest(files):
        return [dict({"language": "python", "line_count": 100}, **f) for f in files]

    # -- 读取片段不虚增 ------------------------------------------------------

    def test_partial_read_counts_only_fragment_lines(self):
        """100 行文件读 5–10 行：observed_read == 6，不是 100。"""
        calc = CoverageCalculator(self._manifest([{"path": "big.py"}]))
        calc.record_interval("big.py", "observed_read", 5, 10)
        summary = calc.get_summary()

        self.assertEqual(summary["dimension_covered_lines"]["observed_read"], 6)
        self.assertLess(
            summary["dimension_percentages"]["observed_read"], 7.0,
            "a 6-line read of a 100-line file must not read as full coverage",
        )
        row = next(r for r in summary["file_breakdown"] if r["path"] == "big.py")
        self.assertEqual(row["coverage_lines"]["observed_read"], 6)
        self.assertEqual(row["total_lines"], 100)

    def test_fragment_never_promotes_to_full_file(self):
        """任何片段覆盖都严格小于全文件行数（无整文件虚报）。"""
        calc = CoverageCalculator(self._manifest([{"path": "f.py"}]))
        for start, end in ((1, 3), (40, 55), (98, 100)):
            calc.record_interval("f.py", "observed_read", start, end)
        summary = calc.get_summary()
        observed = summary["dimension_covered_lines"]["observed_read"]
        self.assertEqual(observed, 22)  # 3 + 16 + 3, disjoint fragments
        self.assertLess(observed, 100)

    # -- 重复块只计一次 ------------------------------------------------------

    def test_repeated_identical_block_counted_once(self):
        """同一区间记录两次：覆盖只算一次。"""
        calc = CoverageCalculator(self._manifest([{"path": "dup.py"}]))
        calc.record_interval("dup.py", "observed_read", 10, 20)
        calc.record_interval("dup.py", "observed_read", 10, 20)
        self.assertEqual(calc.get_summary()["dimension_covered_lines"]["observed_read"], 11)

    def test_overlapping_blocks_merged_by_union(self):
        """重叠区间 (1,50)+(30,80) → 80 行，而不是 130。"""
        calc = CoverageCalculator(self._manifest([{"path": "ov.py"}]))
        calc.record_interval("ov.py", "context_supplied", 1, 50)
        calc.record_interval("ov.py", "context_supplied", 30, 80)
        self.assertEqual(calc.get_summary()["dimension_covered_lines"]["context_supplied"], 80)

    def test_adjacent_blocks_merge_without_gap_inflation(self):
        """相邻 (1,10)+(11,20) 折叠为 (1,20)：20 行，无重复无缺口。"""
        self.assertEqual(compute_interval_union([(1, 10), (11, 20)]), [(1, 20)])
        calc = CoverageCalculator(self._manifest([{"path": "adj.py"}]))
        calc.record_interval("adj.py", "observed_read", 1, 10)
        calc.record_interval("adj.py", "observed_read", 11, 20)
        self.assertEqual(calc.get_summary()["dimension_covered_lines"]["observed_read"], 20)

    def test_duplicate_unit_windows_across_units_do_not_double_count(self):
        """分块窗口回退造成的重复块（模拟多单元重复供给）只计一次。"""
        calc = CoverageCalculator(self._manifest([{"path": "chunked.py"}]))
        # Two units with a 30-line rollback overlap.
        calc.record_interval("chunked.py", "context_supplied", 1, 400)
        calc.record_interval("chunked.py", "context_supplied", 371, 800)
        summary = calc.get_summary()
        self.assertEqual(summary["dimension_covered_lines"]["context_supplied"], 800)
        # Cross-check against the interval-union primitive.
        self.assertEqual(count_covered_lines([(1, 400), (371, 800)]), 800)

    # -- 排除文件不进分母 ----------------------------------------------------

    def test_excluded_file_absent_from_breakdown_and_totals(self):
        """被排除文件不在清单 → 不出现在 file_breakdown、不占 total 行数。"""
        included = self._manifest([{"path": "kept.py"}])
        calc = CoverageCalculator(included)
        calc.record_interval("kept.py", "observed_read", 1, 10)
        summary = calc.get_summary()

        self.assertNotIn("vendor/dep.js", [r["path"] for r in summary["file_breakdown"]])
        self.assertNotIn("tests/test_app.py", [r["path"] for r in summary["file_breakdown"]])
        self.assertEqual(summary["total_files"], 1)
        self.assertEqual(summary["total_inventoried_lines"], 100)

        # A request for an excluded path must not silently create coverage:
        # the calculator only accounts files present in the frozen manifest.
        excluded_probe = CoverageCalculator(included)
        excluded_probe.record_interval("vendor/dep.js", "observed_read", 1, 500)
        probe_summary = excluded_probe.get_summary()
        self.assertNotIn("vendor/dep.js", [r["path"] for r in probe_summary["file_breakdown"]])
        self.assertEqual(probe_summary["total_inventoried_lines"], 100)
        self.assertEqual(
            probe_summary["dimension_covered_lines"]["observed_read"], 0,
            "coverage of an excluded file must not leak into the included denominator",
        )

    def test_unknown_files_included_in_denominator_not_in_coverage_claims(self):
        """未知语言纳入文件占分母；无记录维度不虚报（见 dimension_unknown）。"""
        files = [
            {"path": "a.py", "language": "python", "line_count": 50},
            {"path": "blob.xyz", "language": "unknown", "line_count": 30},
        ]
        summary = CoverageCalculator(files).get_summary()
        self.assertEqual(summary["total_inventoried_lines"], 80)
        self.assertEqual(len(summary["file_breakdown"]), 2)
        self.assertTrue(summary["dimension_unknown"]["observed_read"])

    # -- 日志缺失为 unknown，不写零 ------------------------------------------

    def test_missing_worker_logs_disclosed_as_dimension_unknown(self):
        """有清单无日志：observed_read 维度披露 unknown（缺数据≠零覆盖）。"""
        calc = CoverageCalculator(self._manifest([{"path": "a.py"}]))
        summary = calc.get_summary()

        self.assertTrue(summary["dimension_unknown"]["observed_read"])
        self.assertTrue(summary["dimension_unknown"]["review_claimed"])
        self.assertIn("observed_read", summary.get("dimension_unknown_reason", {}))
        self.assertIn("unknown", summary["dimension_unknown_reason"]["observed_read"])
        # The numeric row stays for aggregation, but the flag disambiguates:
        # it must be read as "no data", never as "measured 0% coverage".
        self.assertEqual(summary["dimension_covered_lines"]["observed_read"], 0)

    def test_dimensions_with_data_are_not_flagged_unknown(self):
        """有区间记录的维度不为 unknown（inventoried 恒有数据）。"""
        calc = CoverageCalculator(self._manifest([{"path": "a.py"}]))
        calc.record_interval("a.py", "observed_read", 1, 5)
        summary = calc.get_summary()
        self.assertFalse(summary["dimension_unknown"]["observed_read"])
        self.assertFalse(summary["dimension_unknown"]["inventoried"])
        self.assertTrue(summary["dimension_unknown"]["review_claimed"])

    def test_top_level_unknown_when_no_data_at_all(self):
        """空清单/零行清单 → 顶层 unknown=True 且带原因（不静默写零）。"""
        empty = CoverageCalculator([]).get_summary()
        self.assertTrue(empty["unknown"])
        self.assertTrue(empty["unknown_reason"])

        zero_line = CoverageCalculator(
            [{"path": "e.py", "language": "python", "line_count": 0}]
        ).get_summary()
        self.assertTrue(zero_line["unknown"])
        self.assertIn("zero", zero_line["unknown_reason"])

    def test_missing_logs_scenario_reported_unknown_not_zero_claim(self):
        """端到端口径：清单在、扫描/供给/读日志全缺 → 各维度如实 unknown。"""
        summary = CoverageCalculator(
            self._manifest([{"path": "a.py"}, {"path": "b.py"}])
        ).get_summary()
        self.assertFalse(summary["unknown"], "manifest has lines: totals exist")
        for dim in ("signal_scanned", "context_supplied", "observed_read", "review_claimed"):
            self.assertTrue(
                summary["dimension_unknown"][dim],
                f"missing logs for {dim} must surface as unknown",
            )

    # -- 五维来源分层口径 ----------------------------------------------------

    def test_five_dimensions_present_and_independently_counted(self):
        """五个维度齐备，各自按并集统计、互不串层。"""
        calc = CoverageCalculator(self._manifest([{"path": "layered.py"}]))
        calc.record_interval("layered.py", "signal_scanned", 1, 100)
        calc.record_interval("layered.py", "context_supplied", 1, 80)
        calc.record_interval("layered.py", "observed_read", 1, 40)
        calc.record_interval("layered.py", "review_claimed", 10, 20)
        summary = calc.get_summary()

        self.assertEqual(sorted(summary["dimension_covered_lines"].keys()), sorted(DIMENSIONS))
        totals = summary["dimension_covered_lines"]
        self.assertEqual(totals["inventoried"], 100)
        self.assertEqual(totals["signal_scanned"], 100)
        self.assertEqual(totals["context_supplied"], 80)
        self.assertEqual(totals["observed_read"], 40)
        self.assertEqual(totals["review_claimed"], 11)
        # Percentages follow the same union accounting against the denominator.
        self.assertEqual(summary["dimension_percentages"]["review_claimed"], 11.0)

    def test_layering_narrows_monotonically_for_nested_evidence(self):
        """逐层收窄的证据（nested）保持 inventoried ≥ … ≥ review_claimed。"""
        calc = CoverageCalculator(self._manifest([{"path": "nest.py"}]))
        calc.record_interval("nest.py", "signal_scanned", 1, 90)
        calc.record_interval("nest.py", "context_supplied", 1, 70)
        calc.record_interval("nest.py", "observed_read", 5, 50)
        calc.record_interval("nest.py", "review_claimed", 10, 30)
        totals = calc.get_summary()["dimension_covered_lines"]
        values = [totals[dim] for dim in DIMENSIONS]
        self.assertEqual(values, sorted(values, reverse=True), f"layering not narrowing: {values}")

    def test_higher_layer_record_does_not_leak_into_lower_layer(self):
        """下层（更窄来源）不被上层记录污染：维度间严格独立。"""
        calc = CoverageCalculator(self._manifest([{"path": "iso.py"}]))
        calc.record_interval("iso.py", "review_claimed", 1, 100)
        summary = calc.get_summary()
        self.assertEqual(summary["dimension_covered_lines"]["review_claimed"], 100)
        self.assertEqual(summary["dimension_covered_lines"]["observed_read"], 0)
        self.assertEqual(summary["dimension_covered_lines"]["context_supplied"], 0)

    def test_per_file_union_across_files_summed_in_totals(self):
        """跨文件各自并集后求和；文件间不跨文件合并区间。"""
        calc = CoverageCalculator(self._manifest([
            {"path": "x.py", "line_count": 50},
            {"path": "y.py", "line_count": 30},
        ]))
        calc.record_interval("x.py", "observed_read", 1, 20)
        calc.record_interval("x.py", "observed_read", 15, 30)   # overlap inside x
        calc.record_interval("y.py", "observed_read", 1, 10)
        summary = calc.get_summary()
        self.assertEqual(summary["dimension_covered_lines"]["observed_read"], 40)


if __name__ == "__main__":
    unittest.main()
