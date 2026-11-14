"""Interval coverage accounting and multi-dimensional coverage calculation.

Implements DSR-034 / SD-08 / SR-021:
- Five distinct coverage dimensions:
  1. inventoried: files and line intervals included in snapshot
  2. signal_scanned: scanned for source/sink/guard patterns
  3. context_supplied: packaged into worker prompt packets
  4. observed_read: documented read operations from worker logs
  5. review_claimed: lines explicitly evaluated in candidate/verdict trace
- Interval union algorithm prevents double-counting of overlapping chunks.
- Partial reads never erroneously inflate to full-file coverage.
"""

# 需求追踪 (Requirement Traceability)
# ---------------------------------------------------------------------------
# 上层需求: docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2
# 设计依据: docs/design/SOFTWARE_DESIGN.md
# SWR-021  行区间覆盖与来源分层；读取片段、重复块、排除、日志缺失不得虚增覆盖
#   绑定实现: DSR-034
# 状态以统一测试结论为准；未实测能力保持 unknown（设计原则 8：能观测的不靠声明）。
#

from __future__ import annotations
from typing import Any, Dict, List, Optional, Set, Tuple


def compute_interval_union(intervals: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    """Compute minimal disjoint sorted intervals covering the union of inputs."""
    if not intervals:
        return []

    sorted_ints = sorted(intervals, key=lambda x: (x[0], x[1]))
    merged: List[Tuple[int, int]] = []

    curr_start, curr_end = sorted_ints[0]
    for s, e in sorted_ints[1:]:
        if s <= curr_end + 1:
            # Overlapping or adjacent
            curr_end = max(curr_end, e)
        else:
            merged.append((curr_start, curr_end))
            curr_start, curr_end = s, e
    merged.append((curr_start, curr_end))
    return merged


def count_covered_lines(intervals: List[Tuple[int, int]]) -> int:
    """Return total unique covered lines from disjoint intervals."""
    union_ints = compute_interval_union(intervals)
    return sum(e - s + 1 for s, e in union_ints if e >= s)


class CoverageCalculator:
    """Aggregates multi-dimensional coverage across files in a run."""

    def __init__(self, manifest_files: List[Dict[str, Any]]) -> None:
        self.manifest_files = manifest_files
        self._total_inventoried_lines = sum(f.get("line_count", 0) for f in manifest_files)
        # Store intervals per file per dimension: {file: {dimension: [(start, end)]}}
        self._intervals: Dict[str, Dict[str, List[Tuple[int, int]]]] = {}

        for f in manifest_files:
            path = f["path"]
            lc = f.get("line_count", 0)
            self._intervals[path] = {
                "inventoried": [(1, lc)] if lc > 0 else [],
                "signal_scanned": [],
                "context_supplied": [],
                "observed_read": [],
                "review_claimed": [],
            }

    def record_interval(
        self,
        path: str,
        dimension: str,
        start_line: int,
        end_line: int,
    ) -> None:
        """Record a covered interval for a file and dimension."""
        if path not in self._intervals:
            self._intervals[path] = {
                "inventoried": [],
                "signal_scanned": [],
                "context_supplied": [],
                "observed_read": [],
                "review_claimed": [],
            }
        self._intervals[path].setdefault(dimension, []).append((start_line, end_line))

    def get_summary(self) -> Dict[str, Any]:
        """Compute aggregated coverage percentages and line totals."""
        dimensions = ["inventoried", "signal_scanned", "context_supplied", "observed_read", "review_claimed"]
        totals: Dict[str, int] = {dim: 0 for dim in dimensions}
        file_breakdown: List[Dict[str, Any]] = []

        for f in self.manifest_files:
            path = f["path"]
            total_file_lines = f.get("line_count", 0)
            file_dims: Dict[str, int] = {}

            for dim in dimensions:
                ints = self._intervals.get(path, {}).get(dim, [])
                covered = count_covered_lines(ints)
                totals[dim] += covered
                file_dims[dim] = covered

            file_breakdown.append({
                "path": path,
                "language": f.get("language", "unknown"),
                "total_lines": total_file_lines,
                "coverage_lines": file_dims,
            })

        total_lines = self._total_inventoried_lines or 1

        summary: Dict[str, Any] = {
            "total_files": len(self.manifest_files),
            "total_inventoried_lines": self._total_inventoried_lines,
            "dimension_covered_lines": totals,
            "dimension_percentages": {
                dim: round((totals[dim] / total_lines) * 100, 2)
                for dim in dimensions
            },
            "file_breakdown": file_breakdown,
        }

        # DSR-034 / SWR-021: when no interval was ever recorded (empty
        # manifest and/or zero-line files) the all-zero rows above are not
        # evidence of "nothing covered" — they are the absence of data. Flag
        # the summary as unknown instead of letting it read as a silent zero.
        # Backward compatible: only new keys are added.
        if not any(
            self._intervals.get(path, {}).get(dim)
            for path in list(self._intervals.keys())
            for dim in dimensions
        ):
            summary["unknown"] = True
            if not self.manifest_files:
                summary["unknown_reason"] = "no manifest files and no recorded intervals; coverage accounting produced no data"
            else:
                summary["unknown_reason"] = "manifest present but all inventoried line counts are zero; no intervals exist"
        else:
            summary["unknown"] = False

        return summary
