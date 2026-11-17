"""Strong-signal triage records and disposition state machine.

Implements DSR-060 / SD-04 / SR-007:
- Consumes strong signal hits plus a capacity limit and produces sparse triage
  records with explicit dispositions (candidate_created / dismissed / pending).
- Hits beyond the single-output capacity produce an overflow record
  (dimension + estimated_count + reason), mirroring the hunter overflow
  pattern; nothing is truncated silently.
- Records the state machine: a strong signal whose disposition is still
  ``pending`` (undispositioned) can never be marked reviewed, and pending
  records are excluded from the reviewed count.
"""

# 需求追踪 (Requirement Traceability)
# ---------------------------------------------------------------------------
# 上层需求: docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2
# 设计依据: docs/design/SOFTWARE_DESIGN.md
# SWR-007  强信号分诊：稀疏记录、容量溢出、未处置不得计为已审查
#   绑定实现: DSR-060
# 状态以统一测试结论为准；未实测能力保持 unknown（设计原则 8：能观测的不靠声明）。
#

from __future__ import annotations
from typing import Any, Dict, List, Optional

from auditkit.contracts.errors import InvalidInputError

TRIAGE_DISPOSITIONS = ("candidate_created", "dismissed", "pending")


def _signal_key(hit: Dict[str, Any]) -> str:
    """Stable key used to look up a caller-supplied disposition for a hit.

    Requirements: SWR-007(support) / DSR-060(信号键,support)
    """
    signal_id = hit.get("signal_id")
    if signal_id:
        return str(signal_id)
    return f"{hit.get('path', '')}:{hit.get('line', '')}"


class StrongSignalTriage:
    """Produces sparse triage dispositions for strong signal hits.

    Requirements: SWR-007(强信号分诊) / DSR-060(稀疏记录+溢出)
    """

    def __init__(self, max_records: int = 50) -> None:
        """Validate the single-output capacity bound (>= 1).

        Requirements: SWR-007(容量上限,support) / DSR-060(support)
        """
        if max_records < 1:
            raise InvalidInputError(f"max_records must be >= 1, got {max_records}")
        self.max_records = max_records

    def triage_signals(
        self,
        hits: List[Dict[str, Any]],
        dispositions: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Triage strong signal hits into sparse disposition records.

        ``hits`` are strong-signal hit dicts (path, line, kind, strength,
        signal_id). ``dispositions`` optionally maps a signal key (signal_id,
        or "path:line" when no signal_id exists) to candidate_created /
        dismissed; anything else stays ``pending``.

        Returns: {"schema_version", "records", "overflow", "stats"}

        Requirements: SWR-007(稀疏记录,显式溢出) / DSR-060(容量溢出可计数)
        """
        records: List[Dict[str, Any]] = []
        overflow: List[Dict[str, Any]] = []

        for idx, hit in enumerate(hits):
            if not isinstance(hit, dict):
                raise InvalidInputError(
                    f"hit at index {idx} must be a dict, got {type(hit).__name__}"
                )
            if len(records) >= self.max_records:
                overflow.append({
                    "dimension": "triage",
                    "estimated_count": len(hits) - len(records),
                    "reason": (
                        f"Triage cap {self.max_records} reached; remaining strong "
                        f"signals were not dispositioned in this output."
                    ),
                })
                break

            key = _signal_key(hit)
            disposition = (dispositions or {}).get(key, "pending")
            if disposition not in TRIAGE_DISPOSITIONS:
                raise InvalidInputError(
                    f"Invalid disposition '{disposition}' for signal '{key}'; "
                    f"expected one of {TRIAGE_DISPOSITIONS}"
                )

            records.append({
                "schema_version": "1.0",
                "triage_id": f"tri-{len(records) + 1:04d}",
                "signal_ref": key,
                "path": hit.get("path", ""),
                "line": hit.get("line"),
                "signal_kind": hit.get("kind", ""),
                "strength": hit.get("strength"),
                "disposition": disposition,
                "reviewed": False,
                "reason": hit.get("reason", ""),
            })

        stats = self.compute_stats(records)
        stats["total_hits"] = len(hits)
        stats["overflowed"] = len(hits) - len(records)

        return {
            "schema_version": "1.0",
            "records": records,
            "overflow": overflow,
            "stats": stats,
        }

    def set_disposition(self, record: Dict[str, Any], disposition: str) -> Dict[str, Any]:
        """Move a triage record to candidate_created / dismissed / pending.

        Requirements: SWR-007(三态处置状态机) / DSR-060(重处置回未审)
        """
        if disposition not in TRIAGE_DISPOSITIONS:
            raise InvalidInputError(
                f"Invalid disposition '{disposition}'; expected one of {TRIAGE_DISPOSITIONS}"
            )
        record["disposition"] = disposition
        # A (re)dispositioned signal is un-reviewed until explicitly reviewed
        # again; pending records can never be reviewed.
        record["reviewed"] = False
        return record

    def mark_reviewed(self, record: Dict[str, Any], reviewed_by: str = "") -> Dict[str, Any]:
        """Mark a triage record reviewed (state machine gate).

        A record whose disposition is still ``pending`` — i.e. the strong
        signal was never dispositioned — can never be marked reviewed; doing
        so raises InvalidInputError.

        Requirements: SWR-007(未处置不得记已审) / DSR-060(pending门禁)
        """
        if record.get("disposition") == "pending":
            raise InvalidInputError(
                f"Strong signal '{record.get('signal_ref', '')}' has no disposition "
                f"(pending); it cannot be marked reviewed."
            )
        if record.get("disposition") not in TRIAGE_DISPOSITIONS:
            raise InvalidInputError(
                f"Triage record has invalid disposition '{record.get('disposition')}'"
            )
        record["reviewed"] = True
        if reviewed_by:
            record["reviewed_by"] = reviewed_by
        return record

    @staticmethod
    def compute_stats(records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Aggregate triage stats.

        ``reviewed`` counts only records whose disposition is decided
        (candidate_created / dismissed); pending records are excluded because
        an undispositioned strong signal can never count as reviewed.

        Requirements: SWR-007(未处置不计已审) / DSR-060(统计口径)
        """
        stats: Dict[str, Any] = {
            "candidate_created": 0,
            "dismissed": 0,
            "pending": 0,
            "reviewed": 0,
        }
        for rec in records:
            disposition = rec.get("disposition")
            if disposition not in TRIAGE_DISPOSITIONS:
                raise InvalidInputError(
                    f"Triage record '{rec.get('triage_id', '')}' has invalid "
                    f"disposition '{disposition}'"
                )
            stats[disposition] += 1
            if disposition != "pending" and rec.get("reviewed"):
                stats["reviewed"] += 1
        return stats


def triage_strong_signals(
    hits: List[Dict[str, Any]],
    max_records: int = 50,
    dispositions: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Module-level convenience wrapper around StrongSignalTriage.triage_signals.

    Returns: {"schema_version", "records", "overflow", "stats"}

    Requirements: SWR-007(support) / DSR-060(便捷封装,support)
    """
    return StrongSignalTriage(max_records=max_records).triage_signals(hits, dispositions)
