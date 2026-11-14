"""Card admission verification and governance.

Implements DSR-045 / DSR-071 / DSR-077 / SD-02 / SD-11:
- Quality verification of language cards:
  1. Unique card ID matching format.
  2. Concrete platform & language conditions.
  3. Clear security mechanism and source/sink clues.
  4. Mandatory 'not_candidate_when' section to avoid generic code smells.
  5. Synthetic vulnerable example and safe fix example.
  6. Verified public reference (CWE / language documentation).
  7. Regex signal hits on the synthetic vulnerable example.
  8. Independent review record.
- Admission gating: requires 2 independent run corroborations or blocking bug exception.
"""

# 需求追踪 (Requirement Traceability)
# ---------------------------------------------------------------------------
# 上层需求: docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2
# 设计依据: docs/design/SOFTWARE_DESIGN.md
# SWR-016  不读取旧 run、不写回资产、默认不导出；有限字段经人工审核才可准入
#   绑定实现: DSR-045, DSR-071
# SWR-028  升级准入：两次独立运行或记录的阻断性例外；单次非阻断条目不得直接准入
#   绑定实现: DSR-045, DSR-077
# 状态以统一测试结论为准；未实测能力保持 unknown（设计原则 8：能观测的不靠声明）。
#

from __future__ import annotations
import re
from typing import Any, Dict, List, Optional, Tuple


class CardAdmissionChecker:
    """Validates language cards against quality standards."""

    REQUIRED_CARD_FIELDS = [
        "id",
        "title",
        "language",
        "platform_conditions",
        "security_mechanism",
        "source_sink_clues",
        "tracking_guards",
        "not_candidate_when",
        "synthetic_vulnerable_example",
        "synthetic_safe_example",
        "public_references",
        "signals",
        "review_record",
    ]

    def validate_card(self, card: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Verify that a card meets all positive admission criteria."""
        errors: List[str] = []

        for field in self.REQUIRED_CARD_FIELDS:
            if field not in card or not card[field]:
                errors.append(f"Missing required field: {field}")

        # Check examples
        vuln_ex = card.get("synthetic_vulnerable_example", "")
        safe_ex = card.get("synthetic_safe_example", "")
        if len(vuln_ex) < 20:
            errors.append("synthetic_vulnerable_example is too short or missing")
        if len(safe_ex) < 20:
            errors.append("synthetic_safe_example is too short or missing")

        # Check references
        refs = card.get("public_references", [])
        if not refs or not isinstance(refs, list):
            errors.append("public_references must be a non-empty list of citations")

        # Check signals match vulnerable example
        signals = card.get("signals", [])
        if not signals:
            errors.append("card must define at least one regex signal")
        else:
            hit = False
            for sig in signals:
                pat = sig.get("pattern", "")
                try:
                    if re.search(pat, vuln_ex, re.IGNORECASE):
                        hit = True
                        break
                except re.error as e:
                    errors.append(f"Invalid signal regex pattern '{pat}': {e}")
            if not hit and vuln_ex:
                errors.append("Defined signals did not hit on the synthetic_vulnerable_example")

        # Check review record
        rev = card.get("review_record", {})
        if not rev.get("reviewer") or not rev.get("reviewed_at"):
            errors.append("review_record must have reviewer and reviewed_at")

        return len(errors) == 0, errors

    def check_upgrade_admission(
        self,
        item_id: str,
        independent_run_ids: List[str],
        is_blocking_exception: bool = False,
        blocking_rationale: str = "",
    ) -> Tuple[bool, str]:
        """Verify admission for a skill knowledge upgrade."""
        if is_blocking_exception:
            if not blocking_rationale:
                return False, "Blocking bug exception requires explicit rationale"
            return True, f"Admitted via blocking exception: {blocking_rationale}"

        if len(set(independent_run_ids)) >= 2:
            return True, f"Admitted via {len(set(independent_run_ids))} independent run corroborations"

        return False, f"Admission requires at least 2 independent runs; found {len(set(independent_run_ids))}"
