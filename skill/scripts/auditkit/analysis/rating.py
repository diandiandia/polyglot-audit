"""Rating calculation matrix and bounded adjustment logic.

Implements DSR-028 / SD-05 / IFC-02:
- 4x4 matrix mapping (Impact 1-4 x Exploitability 1-4) to Severity (Critical, High, Medium, Low, Info).
- Urgency mapping (P0, P1, P2, P3).
- Manual adjustment: bounded to strictly +/- 1 grade, requiring operator and reason.
- Recalculates final urgency upon adjustment.
"""

# 需求追踪 (Requirement Traceability)
# ---------------------------------------------------------------------------
# 上层需求: docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2
# 设计依据: docs/design/SOFTWARE_DESIGN.md
# SWR-011  定级矩阵与受约束人工调整（最多一档、留理由）；待验证项仅给验证优先级
#   绑定实现: DSR-028
# 状态以统一测试结论为准；未实测能力保持 unknown（设计原则 8：能观测的不靠声明）。
#

from __future__ import annotations
from typing import Any, Dict, Optional, Tuple

from auditkit.contracts.errors import InvalidInputError
from auditkit.contracts.semantic_validator import (
    SEVERITY_ORDER,
    URGENCY_ORDER,
    calculate_severity,
    calculate_urgency,
    calculate_validation_priority,
)


class RatingEngine:
    """Computes and adjusts security finding ratings.

    Requirements: SWR-011(定级唯一权威) / DSR-028(矩阵与调整)
    """

    @staticmethod
    def compute_rating(
        impact: int,
        exploitability: int,
        impact_why: str,
        exploitability_why: str,
        adjustment: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Compute rating dictionary adhering strictly to IFC-02 / DSR-028.

        Requirements: SWR-011(缺理由拒级,受控调整) / DSR-028(穷举矩阵,两端越界,紧迫度重算)
        """
        if not (1 <= impact <= 4):
            raise InvalidInputError(f"Impact must be in 1..4, got {impact}")
        if not (1 <= exploitability <= 4):
            raise InvalidInputError(f"Exploitability must be in 1..4, got {exploitability}")
        if not impact_why:
            raise InvalidInputError("impact_why is required")
        if not exploitability_why:
            raise InvalidInputError("exploitability_why is required")

        calc_sev = calculate_severity(impact, exploitability)
        calc_urg = calculate_urgency(calc_sev, exploitability)

        final_sev = calc_sev
        final_urg = calc_urg

        if adjustment is not None:
            # An explicitly supplied adjustment (even an empty object) is a
            # declared operator action: it must carry operator, reason and a
            # valid direction — silently ignoring it would fabricate an
            # unadjusted grade (SR-011).
            if not isinstance(adjustment, dict):
                raise InvalidInputError("adjustment must be an object when present")
            operator = adjustment.get("operator")
            reason = adjustment.get("reason")
            direction = adjustment.get("direction")

            if not operator or not reason:
                raise InvalidInputError("Manual adjustment requires operator and reason")

            idx = SEVERITY_ORDER.index(calc_sev)
            if direction == "up":
                if idx < len(SEVERITY_ORDER) - 1:
                    final_sev = SEVERITY_ORDER[idx + 1]
                else:
                    raise InvalidInputError("Cannot adjust Critical severity upwards")
            elif direction == "down":
                if idx > 0:
                    final_sev = SEVERITY_ORDER[idx - 1]
                else:
                    raise InvalidInputError("Cannot adjust Info severity downwards")
            else:
                raise InvalidInputError(f"Invalid adjustment direction: {direction}")

            # Recompute urgency from final severity
            final_urg = calculate_urgency(final_sev, exploitability)

        return {
            "schema_version": "1.0",
            "impact": impact,
            "exploitability": exploitability,
            "factor_reasons": {
                "impact_why": impact_why,
                "exploitability_why": exploitability_why,
            },
            "calculated_severity": calc_sev,
            "calculated_urgency": calc_urg,
            "final_severity": final_sev,
            "final_urgency": final_urg,
            "adjustment": adjustment,
        }
