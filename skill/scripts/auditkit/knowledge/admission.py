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
import json
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

    # ------------------------------------------------------------------
    # DSR-071 / SR-016: 受控导入 (controlled import of portable review data)
    # ------------------------------------------------------------------
    # 与 reporting.generator 的导出白名单保持同步（同 artifacts.py 与 ledger/db.py
    # 列结构的同步约定）；本类是导入侧的准入权威，不允许自由文本进入。
    PORTABLE_REVIEW_ALLOWED_ROOT_KEYS = frozenset(
        {"schema_version", "generation_id", "run_id", "run_summary", "anomaly_categories"}
    )
    PORTABLE_REVIEW_ALLOWED_RUN_SUMMARY_KEYS = frozenset(
        {
            "run_state",
            "total_files_audited",
            "total_lines_audited",
            "total_confirmed_findings",
            "total_needs_validation",
            "total_tasks_executed",
            "retries",
            "language",
        }
    )
    PORTABLE_REVIEW_SCALAR_TYPES = (str, int, float, bool)
    PORTABLE_REVIEW_MAX_STRING_LENGTH = 64
    SELF_REVIEW_ANOMALY_CATEGORIES = frozenset(
        {"flow", "coverage", "cost", "verification", "knowledge", "adaptation", "error", "usage_missing"}
    )

    def admit_portable_review(
        self,
        payload: Dict[str, Any],
        independent_run_ids: List[str],
        is_blocking_exception: bool = False,
        blocking_rationale: str = "",
    ) -> Dict[str, Any]:
        """Controlled import of a portable skill-review payload (DSR-071 / SR-016).

        Default-deny gate: a payload is importable only when it
          1. matches the export whitelist exactly (root keys, run_summary keys,
             scalar values — the mirror of reporting.generator's export),
          2. contains no free text, paths, or target identifiers (string values
             are capped and anomaly categories must come from the fixed enum),
          3. carries upgrade evidence: two independent runs, or a recorded
             blocking exception with explicit rationale (SWR-028 semantics).

        Returns an admission record dict; it never raises on policy rejection
        (rejections carry machine-readable reasons). Structural violations of
        the whitelist raise InvalidInputError, mirroring the export side.
        """
        import hashlib
        from datetime import datetime, timezone

        from auditkit.contracts.errors import InvalidInputError

        reasons: List[str] = []

        # 1) whitelist mirror (export-side parity)
        if not isinstance(payload, dict):
            raise InvalidInputError("controlled import rejected: payload must be an object")
        for key, value in payload.items():
            if key not in self.PORTABLE_REVIEW_ALLOWED_ROOT_KEYS:
                raise InvalidInputError(
                    f"controlled import rejected: non-whitelisted root key '{key}'",
                    details={"key": key},
                )
            if key == "run_summary":
                if not isinstance(value, dict):
                    raise InvalidInputError("controlled import rejected: run_summary must be an object")
                for sub_key, sub_value in value.items():
                    if sub_key not in self.PORTABLE_REVIEW_ALLOWED_RUN_SUMMARY_KEYS:
                        raise InvalidInputError(
                            f"controlled import rejected: non-whitelisted run_summary key '{sub_key}'",
                            details={"key": sub_key},
                        )
                    if sub_value is not None and not isinstance(sub_value, self.PORTABLE_REVIEW_SCALAR_TYPES):
                        raise InvalidInputError(
                            f"controlled import rejected: run_summary '{sub_key}' is not scalar",
                            details={"key": sub_key},
                        )
            elif key == "anomaly_categories":
                if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
                    raise InvalidInputError(
                        "controlled import rejected: anomaly_categories must be a list of strings"
                    )
                unknown = [v for v in value if v not in self.SELF_REVIEW_ANOMALY_CATEGORIES]
                if unknown:
                    raise InvalidInputError(
                        "controlled import rejected: anomaly_categories outside fixed enum",
                        details={"unknown": unknown},
                    )

        # 2) free-text / path / identifier guard over every string value
        def _scan_strings(node: Any) -> None:
            if isinstance(node, str):
                if len(node) > self.PORTABLE_REVIEW_MAX_STRING_LENGTH:
                    reasons.append(f"string value exceeds {self.PORTABLE_REVIEW_MAX_STRING_LENGTH} chars (free text)")
                if any(marker in node for marker in ("/", "\\", "..", "\x00")):
                    reasons.append("string value contains path-like characters")
            elif isinstance(node, dict):
                for k, v in node.items():
                    _scan_strings(k)
                    _scan_strings(v)
            elif isinstance(node, list):
                for v in node:
                    _scan_strings(v)

        _scan_strings(payload)

        # 3) upgrade evidence (SWR-028 semantics, same as check_upgrade_admission)
        evidence_ok, evidence_reason = self.check_upgrade_admission(
            item_id="portable_skill_review",
            independent_run_ids=independent_run_ids,
            is_blocking_exception=is_blocking_exception,
            blocking_rationale=blocking_rationale,
        )
        if not evidence_ok:
            reasons.append(evidence_reason)

        admitted = not reasons
        # Canonical JSON digest (sort_keys): semantically identical payloads
        # must produce identical admission records regardless of key insertion
        # order -- repr() of nested dicts preserves insertion order and would
        # break the reproducibility of admission audits (SWR-016/028).
        payload_digest = hashlib.sha256(
            json.dumps(payload, sort_keys=True, ensure_ascii=False,
                       separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        return {
            "admitted": admitted,
            "reasons": reasons,
            "evidence": evidence_reason,
            "payload_digest": payload_digest,
            "admission_record": {
                "decided_at": datetime.now(timezone.utc).isoformat(),
                "decision": "admitted" if admitted else "rejected",
                "is_blocking_exception": bool(is_blocking_exception),
                "payload_digest": payload_digest,
                "independent_run_ids": sorted(set(independent_run_ids)),
            },
        }
