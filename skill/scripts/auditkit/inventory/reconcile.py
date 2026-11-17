"""Inventory reconciliation counts (DSR-014).

Provides ``reconcile(manifest)``: a single honest accounting that
- counts included, excluded and unknown-language files,
- aggregates by language and by component,
- asserts the reconciliation invariant
  ``known_language + excluded + unknown_language == total_files``.

No silent double counting: unknown-language files are inventoried (they are
part of ``included``) and reported separately so the three-way sum with
``excluded`` reconstructs the discovered total exactly.
"""

# 需求追踪 (Requirement Traceability)
# ---------------------------------------------------------------------------
# 上层需求: docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2
# 设计依据: docs/design/SOFTWARE_DESIGN.md
# SWR-004  清点分母对账：纳入+排除+未知 == 总数；无信号不等于安全
#   绑定实现: DSR-014
# 状态以统一测试结论为准；未实测能力保持 unknown（设计原则 8：能观测的不靠声明）。
#

from __future__ import annotations
from typing import Any, Dict, Optional

from auditkit.contracts.errors import InvalidInputError


def reconcile(manifest: Any, discovered_total: Optional[int] = None, strict: bool = False) -> Dict[str, Any]:
    """Reconcile inventory counts for a snapshot manifest (DSR-014).

    - ``manifest``: a :class:`auditkit.snapshot.manifest.SnapshotManifest`
      (or any object with ``files`` and ``excluded`` lists).
    - ``discovered_total``: total files discovered in the source tree. When
      omitted, it is derived as ``included + excluded``.
    - ``strict``: when True, raises InvalidInputError if the counts do not
      reconcile (instead of just reporting ``reconciled: False``).

    Returns a dict with ``included``, ``known_language``, ``unknown_language``,
    ``excluded``, ``total_files``, ``by_language``, ``by_component``,
    ``included_plus_excluded_plus_unknown`` and ``reconciled``.

    Requirements: SWR-004(分母三路对账) / DSR-014(对账不变量).
    """
    files = list(getattr(manifest, "files", []) or [])
    excluded = list(getattr(manifest, "excluded", []) or [])

    included = len(files)
    excluded_count = len(excluded)
    unknown_files = [f for f in files if f.get("language", "unknown") == "unknown"]
    unknown_count = len(unknown_files)
    known_count = included - unknown_count

    by_language: Dict[str, int] = {}
    by_component: Dict[str, int] = {}
    for f in files:
        lang = f.get("language", "unknown")
        comp = f.get("component", "default")
        by_language[lang] = by_language.get(lang, 0) + 1
        by_component[comp] = by_component.get(comp, 0) + 1

    total = discovered_total if discovered_total is not None else included + excluded_count
    three_way_total = known_count + excluded_count + unknown_count
    reconciled = (
        known_count + unknown_count == included
        and sum(by_language.values()) == included
        and three_way_total == total
    )

    summary: Dict[str, Any] = {
        "included": included,
        "known_language": known_count,
        "unknown_language": unknown_count,
        "excluded": excluded_count,
        "total_files": total,
        "by_language": dict(sorted(by_language.items())),
        "by_component": dict(sorted(by_component.items())),
        "included_plus_excluded_plus_unknown": three_way_total,
        "reconciled": reconciled,
    }

    if strict and not reconciled:
        raise InvalidInputError(
            "Inventory reconciliation failed: "
            f"known({known_count}) + excluded({excluded_count}) + "
            f"unknown_language({unknown_count}) = {three_way_total} != total_files({total})"
        )

    return summary
