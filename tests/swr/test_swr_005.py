"""SWR-005 acceptance tests (逐编号验收测试).

验收原文 (docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2):
    | SWR-005 | SR-005 → SD-03、SD-04 | P2／SWR-004、SWR-007 |
    实现启发式分块、回退与半链关联；测试每个纳入区间并集完整、
    重叠去重、跨单元和多语言未解链保留。

验收要点（本文件逐条对应）:
- 分块（含窗口回退与固定窗口回退）覆盖所有纳入行区间的并集完整无缺口：
  union(slice(ranges)) == [(1, line_count)]，对 0/1/小/大/重叠过大回退均成立；
- 重叠只计一次：逐块行数之和大于文件行数，但去重并集行数等于行数；
- 跨单元/跨语言 fixture 产出可追踪待验证连接（hypothesized，绝不升级为
  verified；候选带 provenance 追溯到 frontier_id/probe_id）；
- 未连接条目（无匹配 frontier/probe）与超额条目（连接上限/预算耗尽）
  均有明确状态：unresolved / gaps，绝不静默丢弃。
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

SKILL_SCRIPTS = Path(__file__).resolve().parents[2] / "skill" / "scripts"
if str(SKILL_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SKILL_SCRIPTS))

from auditkit.analysis.connector import HypothesisConnector
from auditkit.inventory.slicer import slice_file_ranges
from auditkit.reporting.coverage import compute_interval_union, count_covered_lines


def _line_set(ranges):
    out = set()
    for s, e in ranges:
        out.update(range(s, e + 1))
    return out


class TestSWR005(unittest.TestCase):
    """SWR-005: 分块并集完整、重叠去重、跨单元/多语言半链与未解链保留。"""

    @classmethod
    def setUpClass(cls):
        # Cross-unit, cross-language fixture: a Python frontier (outgoing call
        # across a ctypes boundary, planned in unit A) and a C sink probe
        # (callee implementation, planned in unit B).
        cls.python_frontier = {
            "schema_version": "1.0",
            "frontier_id": "front-py-001",
            "boundary": "ctypes_ffi",
            "source": {
                "path": "web/bridge.py",
                "line": 7,
                "symbol": "lib.encrypt",
                "params": ["data", "key"],
            },
            "steps": [
                {"seq": 1, "path": "web/bridge.py", "line": 7,
                 "note": "passes attacker-controlled data over FFI"},
            ],
            "provenance": {"hunt_tasks": ["hunt-unit-A"]},
        }
        cls.c_probe = {
            "schema_version": "1.0",
            "probe_id": "probe-c-001",
            "boundary": "ctypes_ffi",
            "sink": {
                "path": "native/crypto.c",
                "line": 42,
                "symbol": "encrypt",
                "params": ["data", "key"],
            },
            "steps": [
                {"seq": 1, "path": "native/crypto.c", "line": 42,
                 "note": "encrypt() writes into stack buffer without bounds check"},
            ],
            "provenance": {"hunt_tasks": ["hunt-unit-B"]},
        }

    # -- 分块并集完整与重叠去重 ---------------------------------------------

    def test_union_of_chunks_covers_all_included_lines(self):
        """各规模文件的分块并集 == [(1, line_count)]，无缺口、无越界。"""
        for line_count in (0, 1, 2, 399, 400, 401, 430, 830, 1200, 5000):
            ranges = slice_file_ranges(line_count, chunk_size=400, overlap=30)
            if line_count == 0:
                self.assertEqual(ranges, [], f"line_count={line_count}")
                continue
            union = compute_interval_union(ranges)
            self.assertEqual(
                union, [(1, line_count)],
                f"line_count={line_count}: union {union} is not complete 1..{line_count}",
            )
            self.assertEqual(count_covered_lines(ranges), line_count)
            for s, e in ranges:
                self.assertGreaterEqual(s, 1)
                self.assertLessEqual(e, line_count)
                self.assertLessEqual(s, e)

    def test_overlaps_deduplicated_counted_once(self):
        """重叠只计一次：逐块行数之和虚高，去重后恰为文件行数。"""
        line_count = 1000
        ranges = slice_file_ranges(line_count, chunk_size=400, overlap=30)
        raw_sum = sum(e - s + 1 for s, e in ranges)
        self.assertGreater(raw_sum, line_count, "windows must overlap (rollback in effect)")
        self.assertEqual(count_covered_lines(ranges), line_count)
        self.assertEqual(len(compute_interval_union(ranges)), 1)

    def test_fallback_fixed_window_terminates_and_covers(self):
        """回退（固定窗口）路径：chunk_size<=overlap 时仍终止且并集完整。"""
        ranges = slice_file_ranges(10, chunk_size=2, overlap=5)
        self.assertEqual(compute_interval_union(ranges), [(1, 10)])
        # Degenerate single-line and tiny files fall back to one window.
        self.assertEqual(slice_file_ranges(1, chunk_size=400, overlap=30), [(1, 1)])
        self.assertEqual(
            slice_file_ranges(5, chunk_size=2, overlap=1),
            [(1, 2), (2, 3), (3, 4), (4, 5)],
        )

    def test_cross_chunk_symbol_reachable_within_union(self):
        """跨块符号（落在窗口回退区）仍在并集覆盖内，不因分块丢失。"""
        ranges = slice_file_ranges(830, chunk_size=400, overlap=30)
        covered = _line_set(ranges)
        for probe_line in (1, 399, 400, 401, 429, 430, 800, 830):
            self.assertIn(probe_line, covered, f"line {probe_line} uncovered")

    # -- 跨单元/跨语言半链关联 ----------------------------------------------

    def test_cross_unit_cross_language_half_chain_linked_as_hypothesis(self):
        """跨单元/跨语言半链产出可追踪、待验证的连接假设（非 verified）。"""
        connector = HypothesisConnector()
        result = connector.connect_ex([self.python_frontier], [self.c_probe])

        self.assertEqual(len(result["connections"]), 1)
        conn = result["connections"][0]
        self.assertEqual(conn["status"], "hypothesized")
        self.assertNotEqual(conn["status"], "verified")
        self.assertEqual(conn["frontier_id"], "front-py-001")
        self.assertEqual(conn["probe_id"], "probe-c-001")
        self.assertTrue(conn["matching_factors"])

        # The synthesized candidate is traceable back to both half chains.
        self.assertEqual(len(result["candidates"]), 1)
        cand = result["candidates"][0]
        self.assertEqual(
            sorted(cand["provenance"]["candidates"]),
            ["front-py-001", "probe-c-001"],
        )
        self.assertEqual(cand["source"]["path"], "web/bridge.py")
        self.assertEqual(cand["sink"]["path"], "native/crypto.c")
        self.assertTrue(cand["open_questions"], "unverified link must carry open questions")
        self.assertIn("hunt-unit-A", cand["provenance"]["hunt_tasks"])
        self.assertIn("hunt-unit-B", cand["provenance"]["hunt_tasks"])

    def test_hypothesis_never_reports_verified_evidence(self):
        """启发式连接不得自称已验证（无反证/逐跳证据保持待验证）。"""
        result = HypothesisConnector().connect_ex(
            [self.python_frontier], [self.c_probe]
        )
        for conn in result["connections"]:
            self.assertEqual(conn["status"], "hypothesized")
        for cand in result["candidates"]:
            self.assertIn("Hypothesized", cand["impact_claim"])
            self.assertIn("unverified", cand["guard_analysis"].lower())

    # -- 未解链与超额条目的明确状态 -----------------------------------------

    def test_unconnected_entries_keep_explicit_unresolved_status(self):
        """跨单元未解链：无匹配的 frontier 与 probe 均保留 unresolved 记录。"""
        lonely_frontier = dict(self.python_frontier, frontier_id="front-py-002",
                               boundary="java_jni")
        lonely_frontier = dict(lonely_frontier, source=dict(
            self.python_frontier["source"], symbol="load_remote_config"))
        lonely_probe = dict(self.c_probe, probe_id="probe-c-002", boundary="dotnet_pinvoke")
        lonely_probe = dict(lonely_probe, sink=dict(
            self.c_probe["sink"], symbol="write_audit_log"))
        result = HypothesisConnector().connect_ex([lonely_frontier], [lonely_probe])

        self.assertEqual(result["connections"], [])
        kinds = {(u["kind"], u.get("frontier_id") or u.get("probe_id"))
                 for u in result["unresolved"]}
        self.assertIn(("frontier", "front-py-002"), kinds)
        self.assertIn(("probe", "probe-c-002"), kinds)
        for u in result["unresolved"]:
            self.assertTrue(u["reason"], "unresolved record must say why")
        self.assertEqual(result["stats"]["unresolved"], 2)

    def test_incompatible_signature_prevents_pairing_and_is_recorded(self):
        """同名但参数不兼容的半链不成对，且记录 incompatible 状态。"""
        probe_1arg = dict(self.c_probe, probe_id="probe-c-003")
        probe_1arg["sink"] = dict(self.c_probe["sink"], params=["data"])
        result = HypothesisConnector().connect_ex([self.python_frontier], [probe_1arg])

        self.assertEqual(result["connections"], [])
        self.assertEqual(len(result["incompatible"]), 1)
        inc = result["incompatible"][0]
        self.assertEqual(inc["frontier_id"], "front-py-001")
        self.assertEqual(inc["probe_id"], "probe-c-003")
        self.assertIn("mismatch", inc["reason"].lower())

    def test_excess_entries_beyond_cap_have_explicit_status(self):
        """超额条目：连接上限与预算耗尽均产生 gap 记录（数量下界），不静默。"""
        frontiers = [
            dict(self.python_frontier, frontier_id=f"front-py-{i:03d}",
                 boundary="ctypes_ffi")
            for i in range(5)
        ]
        probes = [
            dict(self.c_probe, probe_id=f"probe-c-{i:03d}", boundary="ctypes_ffi")
            for i in range(5)
        ]

        capped = HypothesisConnector().connect_ex(
            frontiers, probes, max_connections=2
        )
        self.assertEqual(len(capped["connections"]), 2)
        gap_dims = [g["dimension"] for g in capped["gaps"]]
        self.assertIn("connections", gap_dims)
        gap = next(g for g in capped["gaps"] if g["dimension"] == "connections")
        self.assertGreaterEqual(gap["estimated_count"], 1)
        self.assertTrue(gap["reason"])
        # Unscheduled frontiers are accounted in the gap, not dropped silently:
        # every frontier is either covered by a connection or counted in the
        # gap's estimated_count lower bound.
        matched_frontiers = {c["frontier_id"] for c in capped["connections"]}
        self.assertEqual(
            capped["stats"]["frontiers"] - len(matched_frontiers),
            gap["estimated_count"],
        )

        budgeted = HypothesisConnector().connect_ex(frontiers, probes, budget=0)
        self.assertEqual(budgeted["connections"], [])
        budget_dims = [g["dimension"] for g in budgeted["gaps"]]
        self.assertIn("connection_budget", budget_dims)
        bgap = next(g for g in budgeted["gaps"] if g["dimension"] == "connection_budget")
        self.assertGreaterEqual(bgap["estimated_count"], len(frontiers))
        self.assertTrue(bgap["reason"])

    def test_stats_are_internally_consistent(self):
        """stats 与明细一致（连接/unresolved 记账可对账，条目不重不漏）。"""
        result = HypothesisConnector().connect_ex(
            [self.python_frontier], [self.c_probe], max_connections=50
        )
        stats = result["stats"]
        self.assertEqual(stats["frontiers"], 1)
        self.assertEqual(stats["probes"], 1)
        self.assertEqual(stats["evaluations"], stats["frontiers"] * stats["probes"])
        # Every frontier is either connected or unresolved; likewise probes.
        conn_frontiers = {c["frontier_id"] for c in result["connections"]}
        conn_probes = {c["probe_id"] for c in result["connections"]}
        unres_frontiers = {u["frontier_id"] for u in result["unresolved"] if u["kind"] == "frontier"}
        unres_probes = {u["probe_id"] for u in result["unresolved"] if u["kind"] == "probe"}
        self.assertEqual(conn_frontiers | unres_frontiers, {self.python_frontier["frontier_id"]})
        self.assertEqual(conn_probes | unres_probes, {self.c_probe["probe_id"]})
        self.assertFalse(conn_frontiers & unres_frontiers)
        self.assertFalse(conn_probes & unres_probes)


if __name__ == "__main__":
    unittest.main()
