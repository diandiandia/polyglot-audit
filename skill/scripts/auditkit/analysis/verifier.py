"""Independent verification engine, 4-way verdicts, and second-opinion adjudication.

Implements DSR-027 / DSR-061 / DSR-062 / SD-05 / SR-008 / SR-009:
- Four formal verdicts: confirmed, needs_validation, rejected, unverified.
- Static proof yields E2; absence of E3 strictly enforced.
- Independent second opinion adjudication for High/Critical findings.
- Bounded variant search across the snapshot.
"""

# 需求追踪 (Requirement Traceability)
# ---------------------------------------------------------------------------
# 上层需求: docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2
# 设计依据: docs/design/SOFTWARE_DESIGN.md
# SWR-008  独立验证：证伪与证据推理，区分 confirmed/needs_validation/rejected/unverified
#   绑定实现: DSR-027, DSR-061, DSR-062
# SWR-009  E1/E2 裁决校验：E2 需新 attempt 与逐跳证据；首版禁用 E3 声称
#   绑定实现: DSR-027
# 状态以统一测试结论为准；未实测能力保持 unknown（设计原则 8：能观测的不靠声明）。
#

from __future__ import annotations
import uuid
from typing import Any, Dict, List, Optional, Tuple

from auditkit.analysis.rating import RatingEngine
from auditkit.contracts.errors import InvalidInputError
from auditkit.contracts.semantic_validator import (
    SemanticValidator,
    calculate_validation_priority,
)
from auditkit.inventory.languages import detect_language

SECOND_OPINION_SEVERITIES = ("High", "Critical")


def derive_languages(candidate: Dict[str, Any]) -> List[str]:
    """Derive the finding languages from observable candidate facts (P-04).

    No field may carry a fabricated default: the previous hard-coded
    ``"python"`` fallback mislabelled every non-Python candidate whose source
    omitted ``lang`` (e.g. a JS/TS finding rendered as Python). Explicit
    ``source.lang`` wins; otherwise the language is detected from the source
    and sink path extensions so cross-language chains list both sides. When
    nothing is observable the honest value is ``"unknown"``.
    """
    source = candidate.get("source") or {}
    sink = candidate.get("sink") or {}
    langs: List[str] = []
    explicit = source.get("lang")
    if explicit:
        langs.append(str(explicit))
    for endpoint in (source, sink):
        detected = detect_language(endpoint.get("path", ""))
        if detected != "unknown" and detected not in langs:
            langs.append(detected)
    return langs or ["unknown"]


def bounded_variant_search(
    snapshot_files: Dict[str, Any],
    confirmed_finding: Dict[str, Any],
    max_variants: int = 5,
    max_files: int = 20,
) -> Dict[str, Any]:
    """Bounded variant search for a confirmed finding (DSR-062).

    Searches snapshot files for other occurrences of the confirmed finding's
    sink pattern (sink symbol call sites), excluding the confirmed location
    itself. Search scope is capped by ``max_files`` and result count by
    ``max_variants``; unsearched areas and truncation reasons are recorded
    explicitly. Every variant carries
    ``requires_independent_verification: True``: sharing the same sink never
    counts as independent confirmation.

    ``snapshot_files`` maps relative path -> file content (str or list of lines).

    Returns:
    {
        "schema_version", "variants": [...],
        "searched_files": int, "total_files": int,
        "truncated": bool, "reason": str, "unsearched_files": [...],
    }
    """
    if not isinstance(snapshot_files, dict):
        raise InvalidInputError("snapshot_files must be a dict of path -> content")
    if max_variants < 1:
        raise InvalidInputError(f"max_variants must be >= 1, got {max_variants}")
    if max_files < 1:
        raise InvalidInputError(f"max_files must be >= 1, got {max_files}")

    sink = confirmed_finding.get("sink") or {}
    symbol = (sink.get("symbol") or "").strip()
    sink_path = sink.get("path", "")
    sink_line = sink.get("line")

    paths = sorted(snapshot_files.keys())
    total_files = len(paths)
    searched_paths = paths[:max_files]
    unsearched_files = paths[max_files:]

    variants: List[Dict[str, Any]] = []
    truncated_reasons: List[str] = []

    if not symbol:
        truncated_reasons.append(
            "Confirmed finding declares no sink symbol; no searchable pattern available."
        )

    variant_cap_hit = False
    for path in searched_paths:
        if variant_cap_hit:
            unsearched_files.append(path)
            continue
        content = snapshot_files[path]
        lines = content if isinstance(content, list) else str(content).splitlines()
        for line_no, line in enumerate(lines, start=1):
            if path == sink_path and sink_line is not None and line_no == sink_line:
                continue
            if symbol and symbol.lower() in line.lower():
                if len(variants) >= max_variants:
                    variant_cap_hit = True
                    truncated_reasons.append(
                        f"Variant cap {max_variants} reached; remaining matches in "
                        f"'{path}' and later files were not enumerated."
                    )
                    break
                variants.append({
                    "schema_version": "1.0",
                    "variant_id": f"var-{len(variants) + 1:03d}",
                    "path": path,
                    "line": line_no,
                    "snippet": line.strip()[:200],
                    "pattern": f"sink symbol '{symbol}'",
                    "source_finding_id": confirmed_finding.get("finding_id", ""),
                    "requires_independent_verification": True,
                    "evidence_requirements": (
                        "An independent source-to-sink trace with its own anchors and "
                        "provenance is required; sharing the same sink does not "
                        "constitute independent confirmation."
                    ),
                })

    if len(searched_paths) < total_files:
        truncated_reasons.append(
            f"File cap {max_files} reached: searched {len(searched_paths)} of "
            f"{total_files} snapshot files."
        )

    truncated = bool(truncated_reasons)
    return {
        "schema_version": "1.0",
        "variants": variants,
        "searched_files": len(searched_paths),
        "total_files": total_files,
        "truncated": truncated,
        "reason": "; ".join(truncated_reasons) if truncated else "",
        "unsearched_files": unsearched_files,
    }


class Verifier:
    """Evaluates candidates independently and produces verified Findings."""

    def __init__(
        self,
        semantic_validator: Optional[SemanticValidator] = None,
        enforce_attempt_gate: bool = False,
    ) -> None:
        """Create a verifier.

        ``enforce_attempt_gate`` enables the DSR-027 E2 gate that requires a
        fresh ``verify_attempt_id`` distinct from the hunt attempt on every
        ``confirmed`` finding. It defaults to False only so legacy in-process
        callers keep working; the production pipeline constructs the Verifier
        with the gate enabled (``AuditAppService._enqueue_verify_tasks``).
        """
        self.validator = semantic_validator or SemanticValidator()
        self.enforce_attempt_gate = enforce_attempt_gate

    def build_verify_task(self, candidate: Dict[str, Any]) -> Dict[str, Any]:
        """Build a verify-kind task specification for a candidate (DSR-027).

        The returned spec is enqueued through the LED task queue by
        ``AuditAppService._enqueue_verify_tasks`` (validated against the
        task_spec contract before enqueue). The spec declares role ``verify``,
        its output contract, and requires a
        fresh ``verify_attempt_id`` distinct from the hunt attempt for an E2
        verdict.
        """
        if not isinstance(candidate, dict):
            raise InvalidInputError("candidate must be a dict")
        cand_id = candidate.get("candidate_id", "")
        if not cand_id:
            raise InvalidInputError("candidate is missing candidate_id")
        hunt_tasks = candidate.get("provenance", {}).get("hunt_tasks", [])

        return {
            "schema_version": "1.0",
            "task_kind": "verify",
            "role": "verify",
            "verify_task_id": f"vt-{uuid.uuid4().hex[:8]}",
            "candidate_id": cand_id,
            "output_contract": (
                "Return a verdict object (confirmed | needs_validation | rejected | "
                "unverified) with evidence anchors and provenance; a confirmed verdict "
                "requires a verify_attempt_id distinct from the hunt attempt."
            ),
            "requires_new_attempt": True,
            "input": {
                "candidate": candidate,
                "hunt_tasks": list(hunt_tasks),
            },
        }

    def create_finding_from_candidate(
        self,
        candidate: Dict[str, Any],
        verdict: str,
        verify_task_id: str,
        *,
        impact: int = 3,
        exploitability: int = 3,
        impact_why: str = "",
        exploitability_why: str = "",
        remediation: Optional[Dict[str, Any]] = None,
        blockers: Optional[List[str]] = None,
        validation_plan: str = "",
        counter_evidence: Optional[Dict[str, Any]] = None,
        unverified_reason: str = "",
        adjustment: Optional[Dict[str, Any]] = None,
        verify_attempt_id: str = "",
        hunt_attempt_id: str = "",
        snapshot_files: Optional[Dict[str, Any]] = None,
        max_variants: int = 5,
        max_files: int = 20,
    ) -> Dict[str, Any]:
        """Construct structured Finding object complying with IFC-02."""
        finding_id = f"F-{uuid.uuid4().hex[:6].upper()}"
        cand_id = candidate.get("candidate_id", "")
        hunt_tasks = candidate.get("provenance", {}).get("hunt_tasks", [])

        finding: Dict[str, Any] = {
            "schema_version": "1.0",
            "finding_id": finding_id,
            "candidate_refs": [cand_id] if cand_id else [],
            "verdict": verdict,
            "evidence_level": "E2" if verdict == "confirmed" else "E1",
            "provenance": {
                "candidates": [cand_id] if cand_id else [],
                "hunt_tasks": list(hunt_tasks),
                "verify_tasks": [verify_task_id],
            },
        }

        # The rating matrix, its bounded adjustment and the urgency
        # recalculation have one authority (RatingEngine, DSR-028): the
        # verifier delegates instead of duplicating the matrix here, so an
        # explicitly declared adjustment can never be silently ignored.
        rating_dict: Dict[str, Any] = RatingEngine.compute_rating(
            impact=impact,
            exploitability=exploitability,
            impact_why=impact_why or "Demonstrated sensitive sink reachability",
            exploitability_why=exploitability_why or "Attacker input unchecked",
            adjustment=adjustment,
        )
        if verdict != "confirmed":
            # SR-011 / DSR-028: only confirmed findings carry a repair
            # urgency; pending findings are restricted to the validation
            # priority (see the needs_validation branch below).
            rating_dict.pop("calculated_urgency", None)
            rating_dict.pop("final_urgency", None)

        if verdict == "confirmed":
            # DSR-027: an E2 (confirmed) verdict must come from a fresh
            # verification attempt, distinct from the hunt attempt.
            hunt_attempt = hunt_attempt_id or candidate.get("provenance", {}).get(
                "hunt_attempt_id", ""
            )
            if self.enforce_attempt_gate:
                if not verify_attempt_id:
                    raise InvalidInputError(
                        "Confirmed (E2) verdict requires a non-empty "
                        "provenance.verify_attempt_id (a fresh verification attempt)"
                    )
                if hunt_attempt and verify_attempt_id == hunt_attempt:
                    raise InvalidInputError(
                        "Confirmed (E2) verdict requires a new verification attempt: "
                        f"verify_attempt_id '{verify_attempt_id}' must differ from the "
                        f"hunt attempt '{hunt_attempt}'"
                    )
            elif verify_attempt_id and hunt_attempt and verify_attempt_id == hunt_attempt:
                raise InvalidInputError(
                    "Confirmed (E2) verdict requires a new verification attempt: "
                    f"verify_attempt_id '{verify_attempt_id}' must differ from the "
                    f"hunt attempt '{hunt_attempt}'"
                )
            if verify_attempt_id:
                finding["provenance"]["verify_attempt_id"] = verify_attempt_id

            source = candidate.get("source", {})
            sink = candidate.get("sink", {})
            steps = candidate.get("steps", [])

            # Ensure steps begin with source and end with sink
            if not steps:
                steps = [
                    {"path": source.get("path", ""), "line": source.get("line", 1), "role": "source", "note": "Input entry"},
                    {"path": sink.get("path", ""), "line": sink.get("line", 1), "role": "sink", "note": "Sensitive sink execution"},
                ]

            finding.update({
                "title": f"Confirmed vulnerability in {sink.get('path', 'unknown')}",
                "issue": candidate.get("issue", "general"),
                "languages": derive_languages(candidate),
                "source": source,
                "sink": sink,
                "steps": steps,
                "guards": [],
                "attacker": "remote_unauth",
                "preconditions": ["Default configuration"],
                "rating": rating_dict,
                "remediation": remediation or {
                    "where": f"{sink.get('path')}:{sink.get('line', 1)}",
                    "change": "Enforce strict input validation and safe APIs",
                    "regression_test": "Verify invalid input payload is safely rejected",
                },
                "variants": [],
            })

            # DSR-062: bounded variant search produces real variants when a
            # snapshot is available; coverage and truncation are recorded.
            if snapshot_files is not None:
                variant_result = bounded_variant_search(
                    snapshot_files,
                    finding,
                    max_variants=max_variants,
                    max_files=max_files,
                )
                finding["variants"] = variant_result["variants"]
                finding["variant_search"] = {
                    "searched_files": variant_result["searched_files"],
                    "total_files": variant_result["total_files"],
                    "truncated": variant_result["truncated"],
                    "reason": variant_result["reason"],
                    "unsearched_files": variant_result["unsearched_files"],
                }

        elif verdict == "needs_validation":
            # SR-008 / DSR-027: the pending disposition must carry the REAL
            # open question — a canned blocker or plan would fabricate the
            # reason the finding could not be resolved.
            if not blockers or not isinstance(blockers, list):
                raise InvalidInputError(
                    "needs_validation verdict requires the actual open "
                    "'blockers' (non-empty list); a canned blocker would "
                    "fabricate the unresolved condition (SR-008)"
                )
            if not (validation_plan or "").strip():
                raise InvalidInputError(
                    "needs_validation verdict requires a concrete "
                    "'validation_plan' stating how the blocker is resolved"
                )
            rating_dict["validation_priority"] = calculate_validation_priority(impact, exploitability)
            finding.update({
                "title": f"Potential issue needing validation in {candidate.get('sink', {}).get('path', 'unknown')}",
                "issue": candidate.get("issue", "general"),
                "languages": derive_languages(candidate),
                "blockers": list(blockers),
                "validation_plan": validation_plan,
                "rating": rating_dict,
            })

        elif verdict == "rejected":
            # SR-008 / DSR-027: a rejection without observed counter evidence
            # is forbidden — a canned rationale would fabricate the refutation.
            if not isinstance(counter_evidence, dict) or not (
                counter_evidence.get("rationale") or ""
            ).strip():
                raise InvalidInputError(
                    "Rejected verdict requires observed counter evidence with a "
                    "non-empty 'rationale'; rejecting without counter evidence "
                    "is prohibited (SR-008)"
                )
            finding.update({"counter_evidence": counter_evidence})

        elif verdict == "unverified":
            # SR-008: unverified is a queue disposition, not a verdict — it
            # must state its own real reason instead of a fabricated default.
            if not (unverified_reason or "").strip():
                raise InvalidInputError(
                    "Unverified disposition requires a non-empty "
                    "'unverified_reason' stating why verification did not happen"
                )
            finding.update({"unverified_reason": unverified_reason})

        # Run semantic validation to ensure contract compliance
        self.validator.validate_finding(finding)
        return finding

    def adjudicate_second_opinion(
        self,
        finding: Dict[str, Any],
        second_opinion_verdict: str,
        second_opinion_reason: str,
        second_opinion_anchor: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Adjudicate an independent second opinion (DSR-061).

        Only High/Critical severity findings are in scope: findings of any
        other final severity raise InvalidInputError. On agreement the finding
        is corroborated; on conflict both sides are preserved structurally
        (primary/secondary verdict + evidence + anchor) and the finding is
        conservatively demoted to needs_validation.

        ``second_opinion_anchor`` optionally records where the secondary
        evidence was observed (e.g. {"path": ..., "line": ...}).
        """
        rating = finding.get("rating") or {}
        severity = rating.get("final_severity") or rating.get("calculated_severity")
        if severity not in SECOND_OPINION_SEVERITIES:
            raise InvalidInputError(
                f"Independent second opinion is required only for High/Critical "
                f"findings; finding severity is '{severity or 'unknown'}'"
            )

        primary_anchor = {
            "path": (finding.get("sink") or {}).get("path", ""),
            "line": (finding.get("sink") or {}).get("line"),
        }
        primary_evidence = (
            finding.get("counter_evidence")
            or {
                "rationale": "Primary verifier trace from source to sink",
                "anchors": finding.get("steps", []),
            }
        )

        first_verdict = finding["verdict"]
        if first_verdict == second_opinion_verdict:
            # Second opinion corroborates the primary verdict.
            finding.setdefault("provenance", {}).setdefault("verify_tasks", []).append(
                "second_opinion_corroborated"
            )
            finding["second_opinion"] = {
                "schema_version": "1.0",
                "resolution": "corroborated",
                "primary": {
                    "verdict": first_verdict,
                    "evidence": primary_evidence,
                    "anchor": primary_anchor,
                },
                "secondary": {
                    "verdict": second_opinion_verdict,
                    "evidence": {"rationale": second_opinion_reason},
                    "anchor": second_opinion_anchor or {},
                },
            }
            return finding

        # Conflict detected! Preserve both sides structurally and demote to
        # needs_validation (conservative resolution).
        finding["second_opinion"] = {
            "schema_version": "1.0",
            "resolution": "conflict_demoted",
            "primary": {
                "verdict": first_verdict,
                "evidence": primary_evidence,
                "anchor": primary_anchor,
            },
            "secondary": {
                "verdict": second_opinion_verdict,
                "evidence": {"rationale": second_opinion_reason},
                "anchor": second_opinion_anchor or {},
            },
        }
        finding["verdict"] = "needs_validation"
        finding["evidence_level"] = "E1"
        finding["blockers"] = [
            f"Conflicting verifier opinions: Primary found {first_verdict}, secondary found {second_opinion_verdict} ({second_opinion_reason})"
        ]
        finding["validation_plan"] = "Resolve conflict via dynamic execution or manual inspection"
        if "rating" in finding:
            impact = finding["rating"]["impact"]
            exploitability = finding["rating"]["exploitability"]
            # SR-011 / DSR-028: a pending finding carries the validation
            # priority only — the pre-demotion repair urgency is removed, not
            # kept as a stale claim.
            finding["rating"].pop("calculated_urgency", None)
            finding["rating"].pop("final_urgency", None)
            finding["rating"]["validation_priority"] = calculate_validation_priority(impact, exploitability)
        return finding
