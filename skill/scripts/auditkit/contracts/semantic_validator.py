"""Semantic validation engine for polyglot-audit exchange objects.

Implements DSR-010 / SD-05 / IFC-02:
- Anchor verification against snapshot manifest and line bounds
- Verdict and evidence level rules (E3 disallowance, E2 requirements)
- Rating matrix calculation and adjustment verification
- Order of steps in traces (must start with source, end with sink)
- Provenance checks
"""

# 需求追踪 (Requirement Traceability)
# ---------------------------------------------------------------------------
# 上层需求: docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2
# 设计依据: docs/design/SOFTWARE_DESIGN.md
# SWR-009  E1/E2 静态确认条件、E3 禁用；缺逐跳证据保持未决
#   绑定实现: DSR-010, DSR-027
# SWR-011  定级矩阵 16 组合、调整 ±1 档校验、缺理由拒绝
#   绑定实现: DSR-028
# SWR-025  跨 run 引用拒绝；无效输入可定位
#   绑定实现: DSR-010
# 状态以统一测试结论为准；未实测能力保持 unknown（设计原则 8：能观测的不靠声明）。
#

from __future__ import annotations
from typing import Any, Dict, List, Optional, Set, Tuple

from auditkit.contracts.errors import InvalidInputError


SEVERITY_ORDER = ["Info", "Low", "Medium", "High", "Critical"]
URGENCY_ORDER = ["P3", "P2", "P1", "P0"]


def calculate_severity(impact: int, exploitability: int) -> str:
    """Calculate severity from impact (1-4) and exploitability (1-4)."""
    if impact == 4:
        if exploitability == 4:
            return "Critical"
        elif exploitability in (2, 3):
            return "High"
        else:
            return "Medium"
    elif impact == 3:
        if exploitability in (3, 4):
            return "High"
        elif exploitability == 2:
            return "Medium"
        else:
            return "Low"
    elif impact == 2:
        if exploitability in (3, 4):
            return "Medium"
        else:
            return "Low"
    elif impact == 1:
        if exploitability in (2, 3, 4):
            return "Low"
        else:
            return "Info"
    raise ValueError(f"Invalid impact {impact} or exploitability {exploitability}")


def calculate_urgency(severity: str, exploitability: int) -> str:
    """Calculate urgency P0-P3 from severity and exploitability."""
    if severity == "Critical" or (severity == "High" and exploitability == 4):
        return "P0"
    if severity == "High" or (severity == "Medium" and exploitability == 4):
        return "P1"
    if severity == "Medium" or (severity == "Low" and exploitability >= 3):
        return "P2"
    return "P3"


def calculate_validation_priority(impact: int, exploitability: int) -> str:
    """Map impact and exploitability to validation priority V1-V3 for needs_validation."""
    sev = calculate_severity(impact, exploitability)
    if sev in ("Critical", "High"):
        return "V1"
    elif sev == "Medium":
        return "V2"
    else:
        return "V3"


class SemanticValidator:
    """Validates domain semantics of audit objects."""

    def __init__(
        self,
        manifest: Optional[Dict[str, Any]] = None,
        current_run_id: Optional[str] = None,
    ) -> None:
        self.manifest = manifest
        self.current_run_id = current_run_id
        self._manifest_files: Dict[str, Dict[str, Any]] = {}
        if manifest and "files" in manifest:
            for f in manifest["files"]:
                self._manifest_files[f["path"]] = f

    def validate_run_references(self, obj: Any, current_run_id: Optional[str] = None, path: str = "obj") -> None:
        """Validate cross-run references (DSR-010).

        Every run_id referenced anywhere inside the object (top level, provenance,
        nested records) must equal the current run id; references to any other
        run are rejected with their field path.
        """
        target_run = current_run_id if current_run_id is not None else self.current_run_id
        if target_run is None:
            return
        if isinstance(obj, dict):
            for key, val in obj.items():
                if key == "run_id":
                    if val != target_run:
                        raise InvalidInputError(
                            f"{path}.run_id references run '{val}' which is not the current run '{target_run}'",
                            details={"path": f"{path}.run_id", "referenced": val, "current": target_run},
                        )
                else:
                    self.validate_run_references(val, target_run, f"{path}.{key}")
        elif isinstance(obj, list):
            for idx, item in enumerate(obj):
                self.validate_run_references(item, target_run, f"{path}/{idx}")

    def validate_anchor(self, anchor: Dict[str, Any], path_prefix: str = "anchor") -> None:
        """Validate an anchor's line bounds and existence in manifest."""
        line_start = anchor.get("line_start", 0)
        line_end = anchor.get("line_end", 0)
        file_path = anchor.get("path", "")
        file_sha256 = anchor.get("file_sha256", "")

        if line_start < 1:
            raise InvalidInputError(f"{path_prefix}.line_start must be >= 1, got {line_start}")
        if line_end < line_start:
            raise InvalidInputError(
                f"{path_prefix}.line_end ({line_end}) cannot be less than line_start ({line_start})"
            )

        if self.manifest:
            if file_path not in self._manifest_files:
                raise InvalidInputError(
                    f"{path_prefix}: file '{file_path}' does not exist in snapshot manifest",
                    details={"path": file_path},
                )
            mf = self._manifest_files[file_path]
            if file_sha256 and mf["sha256"] != file_sha256:
                raise InvalidInputError(
                    f"{path_prefix}: file_sha256 mismatch for '{file_path}'",
                    details={"expected": mf["sha256"], "actual": file_sha256},
                )
            line_count = mf.get("line_count", 0)
            if line_count > 0 and line_end > line_count:
                raise InvalidInputError(
                    f"{path_prefix}: line_end ({line_end}) exceeds file line count ({line_count}) for '{file_path}'",
                    details={"path": file_path, "line_end": line_end, "line_count": line_count},
                )

    def validate_rating(self, rating: Dict[str, Any], is_confirmed: bool) -> None:
        """Validate rating calculation, bounds, and adjustment."""
        impact = rating.get("impact")
        exploitability = rating.get("exploitability")
        if not isinstance(impact, int) or impact < 1 or impact > 4:
            raise InvalidInputError(f"rating.impact must be integer 1..4, got {impact}")
        if not isinstance(exploitability, int) or exploitability < 1 or exploitability > 4:
            raise InvalidInputError(f"rating.exploitability must be integer 1..4, got {exploitability}")

        expected_sev = calculate_severity(impact, exploitability)
        calc_sev = rating.get("calculated_severity")
        if calc_sev != expected_sev:
            raise InvalidInputError(
                f"rating.calculated_severity mismatch: expected '{expected_sev}', got '{calc_sev}'"
            )

        expected_urg = calculate_urgency(expected_sev, exploitability)
        final_sev = rating.get("final_severity")
        final_urg = rating.get("final_urgency")
        adjustment = rating.get("adjustment")

        if not is_confirmed:
            # SR-011 / DSR-028: pending findings carry a validation priority,
            # never a repair urgency — the two must not be conflated.
            if "calculated_urgency" in rating or "final_urgency" in rating:
                raise InvalidInputError(
                    "needs_validation rating must not carry a remediation urgency "
                    "('calculated_urgency'/'final_urgency'); pending findings are "
                    "restricted to the validation priority (SR-011)"
                )
        else:
            calc_urg = rating.get("calculated_urgency")
            if calc_urg != expected_urg:
                raise InvalidInputError(
                    f"rating.calculated_urgency mismatch: expected '{expected_urg}', got '{calc_urg}'"
                )

        if adjustment:
            if not isinstance(adjustment, dict):
                raise InvalidInputError("rating.adjustment must be an object if present")
            operator = adjustment.get("operator")
            reason = adjustment.get("reason")
            direction = adjustment.get("direction")
            if not operator or not reason:
                raise InvalidInputError("rating.adjustment requires operator and reason")

            # Must adjust by at most 1 grade
            idx_calc = SEVERITY_ORDER.index(expected_sev)
            idx_final = SEVERITY_ORDER.index(final_sev) if final_sev in SEVERITY_ORDER else -1
            if idx_final == -1:
                raise InvalidInputError(f"Invalid final_severity '{final_sev}'")

            diff = idx_final - idx_calc
            if direction == "up" and diff != 1:
                raise InvalidInputError(f"Adjustment direction 'up' must adjust exactly 1 grade, got diff {diff}")
            elif direction == "down" and diff != -1:
                raise InvalidInputError(f"Adjustment direction 'down' must adjust exactly 1 grade, got diff {diff}")
            elif direction not in ("up", "down"):
                raise InvalidInputError(f"Invalid adjustment direction '{direction}'")

            # Final urgency must be recomputed from final_severity and exploitability
            if is_confirmed:
                expected_final_urg = calculate_urgency(final_sev, exploitability)
                if final_urg != expected_final_urg:
                    raise InvalidInputError(
                        f"rating.final_urgency must be recalculated from final_severity: expected '{expected_final_urg}', got '{final_urg}'"
                    )
        else:
            if final_sev != expected_sev:
                raise InvalidInputError(
                    f"Without adjustment, final_severity '{final_sev}' must match calculated_severity '{expected_sev}'"
                )
            if is_confirmed and final_urg != expected_urg:
                raise InvalidInputError(
                    f"Without adjustment, final_urgency '{final_urg}' must match calculated_urgency '{expected_urg}'"
                )

        if not is_confirmed:
            # needs_validation must have validation_priority
            val_prio = rating.get("validation_priority")
            expected_vp = calculate_validation_priority(impact, exploitability)
            if val_prio != expected_vp:
                raise InvalidInputError(
                    f"needs_validation rating requires validation_priority: expected '{expected_vp}', got '{val_prio}'"
                )

    def validate_finding(self, finding: Dict[str, Any]) -> None:
        """Validate Finding object semantics (verdict, evidence_level, conditions).

        When a current run id is known, any cross-run reference inside the
        finding is rejected (DSR-010).
        """
        # Cross-run reference check (DSR-010)
        self.validate_run_references(finding, path="finding")

        verdict = finding.get("verdict")
        evidence_level = finding.get("evidence_level")

        # Disallow E3 strictly
        if evidence_level == "E3":
            raise InvalidInputError("evidence_level 'E3' is prohibited in polyglot-audit v1")
        if evidence_level not in ("E1", "E2"):
            raise InvalidInputError(f"Invalid evidence_level '{evidence_level}', must be E1 or E2")

        if verdict == "confirmed":
            # Must satisfy confirmed preconditions
            for req in ("title", "issue", "languages", "source", "sink", "steps", "remediation", "rating"):
                if req not in finding or not finding[req]:
                    raise InvalidInputError(f"Confirmed finding requires non-empty '{req}'")

            # Validate steps order: starts with source, ends with sink
            steps = finding.get("steps", [])
            if len(steps) < 2:
                raise InvalidInputError("Confirmed finding trace must have at least 2 steps (source and sink)")
            if steps[0].get("role") != "source":
                raise InvalidInputError("Finding trace must start with a step having role 'source'")
            if steps[-1].get("role") != "sink":
                raise InvalidInputError("Finding trace must end with a step having role 'sink'")

            self.validate_rating(finding["rating"], is_confirmed=True)

        elif verdict == "needs_validation":
            blockers = finding.get("blockers")
            if not blockers or not isinstance(blockers, list) or len(blockers) == 0:
                raise InvalidInputError("needs_validation finding requires non-empty 'blockers'")
            validation_plan = finding.get("validation_plan")
            if not validation_plan or not isinstance(validation_plan, str):
                raise InvalidInputError("needs_validation finding requires 'validation_plan'")
            if "rating" in finding and finding["rating"]:
                self.validate_rating(finding["rating"], is_confirmed=False)

        elif verdict == "rejected":
            counter_evidence = finding.get("counter_evidence")
            if not counter_evidence or not isinstance(counter_evidence, dict):
                raise InvalidInputError("rejected finding requires 'counter_evidence' object with rationale")
            if not counter_evidence.get("rationale"):
                raise InvalidInputError("rejected finding requires 'counter_evidence.rationale'")

        elif verdict == "unverified":
            unverified_reason = finding.get("unverified_reason")
            if not unverified_reason:
                raise InvalidInputError("unverified finding requires 'unverified_reason'")
        else:
            raise InvalidInputError(f"Invalid verdict '{verdict}'")

        # Check provenance acyclicity
        provenance = finding.get("provenance", {})
        candidates = provenance.get("candidates", [])
        finding_id = finding.get("finding_id", "")
        if finding_id in candidates:
            raise InvalidInputError(f"Cycle detected in provenance: {finding_id} references itself")
