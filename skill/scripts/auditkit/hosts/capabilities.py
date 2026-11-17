"""Capability representation, feature matrix, and safety policy enforcement.

Implements DSR-001 / DSR-005 / DSR-021 / SD-09 / IFC-02:
- Tracks capabilities per adapter: enforced, not_enforced, unknown.
- Explicit reasoning when feature is unknown or not enforced.
- Requires user safety acceptance before allowing execution if sandboxing is not enforced.
- Never falsely claims token/cost hard limits or MCP OS sandboxing.
"""

# 需求追踪 (Requirement Traceability)
# ---------------------------------------------------------------------------
# 上层需求: docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2
# 设计依据: docs/design/SOFTWARE_DESIGN.md
# SWR-015  无法强制的权限在启动前披露并需用户明确接受，禁止静默降级
#   绑定实现: DSR-021
# 状态以统一测试结论为准；未实测能力保持 unknown（设计原则 8：能观测的不靠声明）。
#

from __future__ import annotations
import datetime
from typing import Any, Dict, List, Optional

from auditkit.contracts.errors import (
    CapabilityUnavailableError,
    SafetyApprovalRequiredError,
)


class FeatureState:
    ENFORCED = "enforced"
    NOT_ENFORCED = "not_enforced"
    UNKNOWN = "unknown"


class Capability:
    """Represents detected environment and host adapter capability."""

    def __init__(
        self,
        adapter: str,
        adapter_version: str,
        features: Optional[Dict[str, Dict[str, Any]]] = None,
        checked_at: Optional[str] = None,
    ) -> None:
        """Build a capability with conservative default disclosures.

        Requirements: SWR-015(support) / DSR-021(能力披露)
        """
        self.adapter = adapter
        self.adapter_version = adapter_version
        self.checked_at = checked_at or datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.features = features or {
            "structured_output": {"state": FeatureState.UNKNOWN, "reason": "Not probed in offline test"},
            "headless_cli": {"state": FeatureState.UNKNOWN, "reason": "Requires active probe"},
            "filesystem_isolation": {"state": FeatureState.NOT_ENFORCED, "reason": "MCP and host prompts do not enforce OS sandbox"},
            "network_isolation": {"state": FeatureState.UNKNOWN, "reason": "Host network policy unprobed"},
            "execution_isolation": {"state": FeatureState.NOT_ENFORCED, "reason": "Target execution prohibited by default"},
            "hard_token_budget": {"state": FeatureState.UNKNOWN, "reason": "Upstream token hard limits not provable"},
        }

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the capability report.

        Requirements: SWR-023(support) / DSR-001(能力报告)
        """
        return {
            "schema_version": "1.0",
            "adapter": self.adapter,
            "adapter_version": self.adapter_version,
            "checked_at": self.checked_at,
            "features": self.features,
        }

    def verify_safety_policy(self, safety_acceptance: Dict[str, Any]) -> None:
        """Verify that user has explicitly approved running with unverified or un-enforced isolation. Requirements: SWR-015(批准门禁) / DSR-021(未批禁启)"""
        user_approved = safety_acceptance.get("user_approved", False)

        fs_state = self.features.get("filesystem_isolation", {}).get("state")
        exec_state = self.features.get("execution_isolation", {}).get("state")
        net_state = self.features.get("network_isolation", {}).get("state")

        requires_approval = (
            fs_state != FeatureState.ENFORCED
            or exec_state != FeatureState.ENFORCED
            or net_state != FeatureState.ENFORCED
        )

        if requires_approval and not user_approved:
            raise SafetyApprovalRequiredError(
                "Host environment does not enforce OS-level sandbox isolation (filesystem, execution, network). "
                "Explicit user approval is required in safety_acceptance.user_approved to proceed.",
                details={
                    "filesystem_isolation": fs_state,
                    "execution_isolation": exec_state,
                    "network_isolation": net_state,
                },
            )
