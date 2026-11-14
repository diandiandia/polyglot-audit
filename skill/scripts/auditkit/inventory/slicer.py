"""Risk-based slicing, T1-T4 prioritization, and interval union planning.

Implements DSR-015 / DSR-056 / SD-03 / SR-004 / SR-005:
- Deterministic unit planning from snapshot and signal analysis.
- Risk Tiers:
  - T1: High density source/sink combinations or boundaries
  - T2: Present source or sink signals
  - T3: Guard, config, or sparse signals (triage only)
  - T4: Clean / no signal files (inventory only)
- Profiles (DSR-056): quick plans T1+T2; standard additionally keeps T3 as
  triage-only markers; deep keeps everything, with T4 as inventory-only
  markers. Each unit carries ``tier`` and ``disposition``
  (analyze / triage_only / inventory_only). Identical snapshot + config
  yields byte-identical unit lists.
- Slicing with window rollback (e.g., 20-line overlap).
- Interval union guarantee: union of all unit chunks covers 1..line_count
  exactly once when overlaps are merged.
"""

# 需求追踪 (Requirement Traceability)
# ---------------------------------------------------------------------------
# 上层需求: docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2
# 设计依据: docs/design/SOFTWARE_DESIGN.md
# SWR-005  大文件分块：区间并集证明无漏行、重叠只算一次
#   绑定实现: DSR-015, DSR-056
# SWR-030  按可解释风险和预算计划审读（T1~T4、quick/standard/deep）
#   绑定实现: DSR-056
# 状态以统一测试结论为准；未实测能力保持 unknown（设计原则 8：能观测的不靠声明）。
#

from __future__ import annotations
import hashlib
from typing import Any, Dict, List, Optional, Tuple


def calculate_risk_tier(signal_hits: List[Dict[str, Any]], has_boundary: bool) -> Tuple[str, List[str]]:
    """Determine risk tier T1..T4 and list risk factor reasons."""
    factors: List[str] = []
    has_sink = any(s["kind"] == "sink" for s in signal_hits)
    has_source = any(s["kind"] == "source" for s in signal_hits)
    high_strength_count = sum(1 for s in signal_hits if s.get("strength", 0) >= 3)

    if has_boundary:
        factors.append("Cross-language boundary detected")
    if has_source and has_sink:
        factors.append("Contains both source and sink signals")
    if high_strength_count > 0:
        factors.append(f"{high_strength_count} high-severity (strength 3) signals")

    if (has_source and has_sink) or has_boundary or high_strength_count >= 2:
        return "T1", factors or ["High risk density"]
    elif has_source or has_sink:
        factors.append("Contains unverified source or sink")
        return "T2", factors
    elif signal_hits:
        factors.append(f"{len(signal_hits)} low-priority signals")
        return "T3", factors
    else:
        return "T4", ["No security signals identified"]


def slice_file_ranges(
    line_count: int,
    chunk_size: int = 400,
    overlap: int = 30,
) -> List[Tuple[int, int]]:
    """Generate 1-based closed intervals covering 1..line_count with overlap.

    Guarantees that:
    1. If line_count == 0, returns []
    2. Intervals cover [1, line_count] completely without gaps
    3. Overlaps are bounded
    """
    if line_count <= 0:
        return []

    if line_count <= chunk_size:
        return [(1, line_count)]

    ranges: List[Tuple[int, int]] = []
    start = 1
    while start <= line_count:
        end = min(start + chunk_size - 1, line_count)
        ranges.append((start, end))
        if end >= line_count:
            break
        # Advance with overlap
        start = max(end - overlap + 1, start + 1)

    return ranges


class UnitPlanner:
    """Plans units from files and signal scans."""

    # DSR-056: profile -> which dispositions produce active hunt units.
    # - quick:    T1 + T2 only (disposition "analyze")
    # - standard: T1 + T2 analyzed, T3 kept as triage-only markers
    # - deep:     everything; T4 kept as inventory-only markers
    PROFILE_DISPOSITIONS = {
        "quick": {"analyze"},
        "standard": {"analyze", "triage_only"},
        "deep": {"analyze", "triage_only", "inventory_only"},
    }

    def __init__(self, snapshot_id: str, profile: str = "standard") -> None:
        if profile not in self.PROFILE_DISPOSITIONS:
            raise ValueError(f"Unknown profile: {profile!r}")
        self.snapshot_id = snapshot_id
        self.profile = profile

    def create_units(
        self,
        files: List[Dict[str, Any]],
        file_signals: Dict[str, List[Dict[str, Any]]],
        boundaries: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Create deterministic units for a snapshot.

        Every unit carries its ``tier`` (T1..T4) and a ``disposition``
        (DSR-056): ``analyze`` (T1/T2), ``triage_only`` (T3) or
        ``inventory_only`` (T4). Profiles control which dispositions yield
        units; the profile never changes the evidence standard, only which
        tiers get active hunt units.
        """
        units: List[Dict[str, Any]] = []
        boundary_files = {b["path"] for b in boundaries}

        # Deterministic sorting
        sorted_files = sorted(files, key=lambda f: f["path"])

        for f in sorted_files:
            path = f["path"]
            line_count = f.get("line_count", 0)
            lang = f.get("language", "unknown")
            comp = f.get("component", "default")
            signals = file_signals.get(path, [])
            has_b = path in boundary_files

            tier, factors = calculate_risk_tier(signals, has_b)

            # DSR-056 disposition mapping
            if tier in ("T1", "T2"):
                disposition = "analyze"
            elif tier == "T3":
                disposition = "triage_only"
            else:
                disposition = "inventory_only"

            # Skip unit creation for dispositions this profile does not plan
            if disposition not in self.PROFILE_DISPOSITIONS[self.profile]:
                continue

            ranges = slice_file_ranges(line_count)
            if not ranges:
                continue

            for idx, (r_start, r_end) in enumerate(ranges):
                uid_hash = hashlib.sha256(f"{path}:{r_start}:{r_end}".encode("utf-8")).hexdigest()[:8]
                unit_id = f"unit-{uid_hash}"

                anchor = {
                    "schema_version": "1.0",
                    "snapshot_id": self.snapshot_id,
                    "path": path,
                    "line_start": r_start,
                    "line_end": r_end,
                    "file_sha256": f["sha256"],
                }

                units.append({
                    "schema_version": "1.0",
                    "unit_id": unit_id,
                    "snapshot_id": self.snapshot_id,
                    "component": comp,
                    "language": lang,
                    "ranges": [anchor],
                    "risk_factors": factors + [f"Tier: {tier}"],
                    "tier": tier,
                    "disposition": disposition,
                })

        return units
