"""Guard baseline extraction and management.

Implements DSR-024 / SD-04 / SR-006:
- Records guards with id, status (observed, not_found, unknown), mechanism, anchors, applicability, exceptions.
- Ensures registered guards do not grant automatic blanket exemptions.
- Validates that observed guards have verifiable anchors.
"""

# 需求追踪 (Requirement Traceability)
# ---------------------------------------------------------------------------
# 上层需求: docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2
# 设计依据: docs/design/SOFTWARE_DESIGN.md
# SWR-006  守卫/例外/未知三态保留；未经路径适用性核验不得据此驳回（不构成自动豁免）
#   绑定实现: DSR-024
# 状态以统一测试结论为准；未实测能力保持 unknown（设计原则 8：能观测的不靠声明）。
#

from __future__ import annotations
from typing import Any, Dict, List, Optional

from auditkit.contracts.errors import InvalidInputError


class GuardRecord:
    """Represents an environment defense or input sanitizer."""

    def __init__(
        self,
        guard_id: str,
        status: str,  # observed, not_found, unknown
        mechanism: str,
        anchors: Optional[List[Dict[str, Any]]] = None,
        applicability: str = "",
        exceptions: Optional[List[str]] = None,
    ) -> None:
        self.guard_id = guard_id
        self.status = status
        self.mechanism = mechanism
        self.anchors = anchors or []
        self.applicability = applicability
        self.exceptions = exceptions or []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": "1.0",
            "guard_id": self.guard_id,
            "status": self.status,
            "mechanism": self.mechanism,
            "anchors": self.anchors,
            "applicability": self.applicability,
            "exceptions": self.exceptions,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> GuardRecord:
        return cls(
            guard_id=data["guard_id"],
            status=data["status"],
            mechanism=data["mechanism"],
            anchors=data.get("anchors", []),
            applicability=data.get("applicability", ""),
            exceptions=data.get("exceptions", []),
        )


class GuardManager:
    """Manages collection of guards in a run."""

    def __init__(self) -> None:
        self.guards: Dict[str, GuardRecord] = {}

    def add_guard(self, guard: GuardRecord) -> None:
        self.guards[guard.guard_id] = guard

    def get_summary(self) -> List[Dict[str, Any]]:
        return [g.to_dict() for g in self.guards.values()]

    def render_prompt_summary(self, max_tokens: int = 300) -> str:
        """Render concise guard summary for prompt packet."""
        if not self.guards:
            return "No environment guards established yet."

        lines = ["Environment Defense Baseline:"]
        for g in list(self.guards.values())[:8]:
            anchors_str = f" ({len(g.anchors)} anchors)" if g.anchors else ""
            lines.append(f"- [{g.status.upper()}] {g.guard_id}: {g.mechanism}{anchors_str}")
            if g.exceptions:
                lines.append(f"  Exceptions: {', '.join(g.exceptions)}")

        return "\n".join(lines)


VALID_GUARD_STATUSES = ("observed", "not_found", "unknown")


def _candidate_paths(candidate: Dict[str, Any]) -> List[str]:
    """Collect every path anchored by a candidate (source, sink, and steps)."""
    paths: List[str] = []
    for endpoint in (candidate.get("source") or {}, candidate.get("sink") or {}):
        path = endpoint.get("path", "")
        if path:
            paths.append(path)
    for step in candidate.get("steps") or []:
        path = step.get("path", "")
        if path:
            paths.append(path)
    return paths


def _covers_path(pattern: str, paths: List[str]) -> Optional[str]:
    """Return the first candidate path covered by ``pattern`` (substring match).

    Empty patterns never match: an empty applicability/exception entry must not
    be treated as a blanket (global) match.
    """
    if not pattern:
        return None
    for path in paths:
        if pattern in path or path in pattern:
            return path
    return None


def _normalize_guard_record(record: Any) -> GuardRecord:
    """Accept GuardRecord instances or their dict serialization."""
    if isinstance(record, GuardRecord):
        return record
    if isinstance(record, dict):
        return GuardRecord.from_dict(record)
    raise InvalidInputError(
        f"Guard records must be GuardRecord instances or dicts, got {type(record).__name__}"
    )


def evaluate_guards(candidate: Dict[str, Any], guard_records: List[Any]) -> Dict[str, Any]:
    """Evaluate a candidate against guard records and decide exemption (DSR-024).

    Three scenarios must never be conflated into a global effect:

    1. A registered (``observed``) guard whose applicability covers the
       candidate but whose conditions are unmet (no verifiable anchors, or no
       explicit exception for the path) does NOT exempt the candidate; the
       reason is preserved.
    2. An explicit exception (``applicability``/``exceptions`` entry covering
       the candidate path) grants exemption and preserves the evidence.
    3. A guard with ``unknown`` status never grants exemption and the overall
       decision status stays ``unknown``.

    ``not_found`` guards have no effect. No guard is ever promoted to a
    blanket/global exemption: only path-specific evidence counts.

    Returns a decision dict:
    {
        "schema_version", "exempt", "status" ("exempt" | "not_exempt" | "unknown"),
        "reasons": [...], "evidence": [...], "evaluated_guards": [...],
    }
    """
    if not isinstance(candidate, dict):
        raise InvalidInputError("candidate must be a dict")

    paths = _candidate_paths(candidate)
    reasons: List[str] = []
    evidence: List[Dict[str, Any]] = []
    evaluated: List[str] = []
    has_unknown = False
    has_explicit_exception = False

    if not guard_records:
        reasons.append(
            "No guards registered for this run; no guard-based exemption is available."
        )

    for raw in guard_records:
        guard = _normalize_guard_record(raw)
        if guard.status not in VALID_GUARD_STATUSES:
            raise InvalidInputError(
                f"Guard '{guard.guard_id}' has invalid status '{guard.status}'; "
                f"expected one of {VALID_GUARD_STATUSES}"
            )
        evaluated.append(guard.guard_id)

        if guard.status == "not_found":
            reasons.append(
                f"Guard '{guard.guard_id}' is not present in the environment (not_found); no effect."
            )
            continue

        if guard.status == "unknown":
            has_unknown = True
            reasons.append(
                f"Guard '{guard.guard_id}' status is unknown; exemption cannot be granted "
                f"and the decision stays unknown."
            )
            continue

        # status == "observed"
        covered_path = _covers_path(guard.applicability, paths)
        matched_exc: Optional[str] = None
        exception_path: Optional[str] = None
        for exc in guard.exceptions:
            exception_path = _covers_path(exc, paths)
            if exception_path:
                matched_exc = exc
                break

        if exception_path:
            has_explicit_exception = True
            evidence.append({
                "guard_id": guard.guard_id,
                "type": "explicit_exception",
                "exception": matched_exc,
                "covered_path": exception_path,
                "mechanism": guard.mechanism,
            })
            reasons.append(
                f"Guard '{guard.guard_id}' explicitly declares an exception covering "
                f"'{exception_path}'; exemption granted with recorded evidence."
            )
        elif covered_path:
            if not guard.anchors:
                reasons.append(
                    f"Guard '{guard.guard_id}' is registered and applies to '{covered_path}' "
                    f"but its conditions are unmet: no verifiable anchors; no exemption."
                )
            else:
                reasons.append(
                    f"Guard '{guard.guard_id}' is active and applies to '{covered_path}' "
                    f"without an explicit exception for this path; no exemption."
                )
        else:
            reasons.append(
                f"Guard '{guard.guard_id}' applicability does not cover this candidate; "
                f"recorded without granting any global exemption."
            )

    if has_unknown:
        # Scenario 3 dominates: an unknown guard can never yield an exemption.
        status = "unknown"
        exempt = False
    elif has_explicit_exception:
        status = "exempt"
        exempt = True
    else:
        status = "not_exempt"
        exempt = False

    return {
        "schema_version": "1.0",
        "exempt": exempt,
        "status": status,
        "reasons": reasons,
        "evidence": evidence,
        "evaluated_guards": evaluated,
    }
