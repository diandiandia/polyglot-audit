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
    """Determine risk tier T1..T4 and list risk factor reasons.

    Requirements: SWR-005(风险分级T1~T4) / DSR-056(风险因子与排序).
    """
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

    Requirements: SWR-005(区间并集完整+回退) / DSR-015(切块与窗口回退).
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

    # DA-10 (owner decision): audit is FULL coverage -- the profile no longer
    # gates which dispositions produce hunt work; every planned unit is
    # analyzed and the tier orders dispatch priority. The mapping is kept as
    # a validated constant so existing configs stay accepted; all profiles
    # plan the full unit set.
    PROFILE_DISPOSITIONS = {
        "quick": {"analyze"},
        "standard": {"analyze"},
        "deep": {"analyze"},
    }

    def __init__(self, snapshot_id: str, profile: str = "standard") -> None:
        """Validate and store the planning profile for this snapshot.

        Requirements: SWR-005(计划策略校验) / DSR-056 (support).
        """
        if profile not in self.PROFILE_DISPOSITIONS:
            raise ValueError(f"Unknown profile: {profile!r}")
        self.snapshot_id = snapshot_id
        self.profile = profile
        self.binary_files_skipped = 0

    @staticmethod
    def _is_test_path(path: str) -> bool:
        """Generic test-file detection across language families.

        Matches common naming conventions only: a test marker segment in the
        basename (``test_foo.py``, ``test_main.rs``, ``foo_test.go``,
        ``foo.test.js``, ``foo.spec.ts`` ...). Never inspects file content or
        target-specific directory layout (SR-003/SR-016: no target-derived
        knowledge in the planner).
        """
        import re as _re

        basename = path.rsplit("/", 1)[-1]
        return bool(
            _re.match(r"^test[-_.]", basename)
            or _re.search(r"[-_.](?:test|spec)\.[A-Za-z]", basename)
            or basename.endswith("_test.go")
        )

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

        Requirements: SWR-005(确定性单元计划), SWR-004(无命中保留资格)
        / DSR-056(tier+disposition策略), DSR-015(分块区间).
        """
        units: List[Dict[str, Any]] = []
        boundary_files = {b["path"] for b in boundaries}
        self.binary_files_skipped = 0

        # Deterministic sorting
        sorted_files = sorted(files, key=lambda f: f["path"])

        for f in sorted_files:
            path = f["path"]
            # RUN-LESSONS: two real-target run series inventoried compiled
            # binaries as plan units (every run ~200 decode-failure files);
            # one binary even exhausted a signal-scan cap on its own. Binary
            # payloads are never hunt units -- they stay in the manifest
            # (honest inventory) but plan no work.
            if f.get("encoding") == "binary":
                self.binary_files_skipped += 1
                continue
            line_count = f.get("line_count", 0)
            lang = f.get("language", "unknown")
            comp = f.get("component", "default")
            signals = file_signals.get(path, [])
            has_b = path in boundary_files

            tier, factors = calculate_risk_tier(signals, has_b)

            # RUN-LESSONS: test files reached T1 on their own signal hits and
            # consumed top-priority hunt slots in a budget-starved real run
            # (one slot yielded a test-only hygiene finding). Test files cap
            # at T2: they are real scope (unpinned behavior is evidence) but
            # never outrank production source when the budget cannot cover
            # everything.
            if tier == "T1" and self._is_test_path(path):
                tier = "T2"
                factors.append("Test file (tier capped from T1)")

            # DA-10 (owner decision, supersedes DSR-056 disposition gating):
            # audit means FULL coverage -- every planned unit is analyzed
            # regardless of tier. The tier remains as the dispatch-priority
            # ordering (T1 first); it no longer gates whether a unit is
            # hunted. Low-signal units still carry their tier honestly, so
            # the queue drains highest-risk work first and the tail is
            # covered as budget allows.
            disposition = "analyze"

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
                    "surface_class": self._derive_surface_class(signals),
                })

        return units

    @staticmethod
    def _derive_surface_class(hits: List[Dict[str, Any]]) -> str:
        """Attack-surface class from the unit's entry-signal ids (DA-11).

        ``remote``: at least one ``src_http*`` (network entry) hit;
        ``local``: any other ``src_*`` (CLI/env/file) hit; ``internal``: no
        entry-signal hits. The signal ids are the toolkit's own cross-language
        taxonomy -- no language-specific rules (SR-003). Surface class orders
        dispatch within a tier and labels the dossier's attack-surface view;
        it never filters coverage (DA-10: audit is full coverage).
        """
        saw_local = False
        for h in hits or []:
            sid = str(h.get("signal_id") or "")
            if sid.startswith("src_http"):
                return "remote"
            if sid.startswith("src_"):
                saw_local = True
        return "local" if saw_local else "internal"
