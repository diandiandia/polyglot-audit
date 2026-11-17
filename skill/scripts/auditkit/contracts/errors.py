"""Error types and exit code mapping for polyglot-audit.

Adheres strictly to IFC-03 §3.1 and IFC-06 error classifications.
"""

# 需求追踪 (Requirement Traceability)
# ---------------------------------------------------------------------------
# 上层需求: docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2
# 设计依据: docs/design/SOFTWARE_DESIGN.md
# SWR-025  无效输入可定位、不可静默修复成有效结论（错误类型与退出码契约）
#   绑定实现: DSR-006, DSR-074
# 状态以统一测试结论为准；未实测能力保持 unknown（设计原则 8：能观测的不靠声明）。
#
# ==============================================================================
# 软件需求追踪与实现规范 (Software Requirements Traceability)
# ==============================================================================
# 上层需求: docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md
# 设计依据: docs/design/SOFTWARE_DESIGN.md；系统需求: docs/design/SYSTEM_REQUIREMENTS.md
# --- 需求编号: SWR-025 / DSR-006 / DSR-074 ---
# 需求描述: 定义版本化 schema 及标准库子集校验器、语义规则；无效输入可定位、
#   不可静默修复成有效结论；CLI 退出码契约（错误码 → 退出码映射）。
#   └─ 对应系统需求 SR-025: 结构化输入严格验证类型、限制、条件字段、语义和跨记录关系；
#      无效输入可定位、不可静默修复成有效结论。
# ==============================================================================

from __future__ import annotations
from typing import Any, Dict, Optional


class AuditError(Exception):
    """Base class for all domain errors in auditkit.

    Requirements: SWR-025(错误可定位,不静默修复) / DSR-006(错误码), DSR-074(退出码)
    """

    def __init__(
        self,
        code: str,
        message: str,
        *,
        retryable: bool = False,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Store code/message/retryable/details for contract serialization.

        Requirements: SWR-025(错误对象,support) / DSR-006(support)
        """
        super().__init__(f"[{code}] {message}")
        self.code = code
        self.message = message
        self.retryable = retryable
        self.details = details or {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert error to contract error representation (IFC-02).

        Requirements: SWR-025(错误信封可定位) / DSR-006(support)
        """
        return {
            "code": self.code,
            "message": self.message,
            "retryable": self.retryable,
            "details": self.details,
        }

    @property
    def exit_code(self) -> int:
        """Map this error's code to its contract CLI exit code (IFC-03).

        Requirements: SWR-025(退出码映射) / DSR-074(退出码契约)
        """
        return ERROR_CODE_TO_EXIT_CODE.get(self.code, 1)


# IFC-03 §3.1 defined error codes
ERROR_CODE_TO_EXIT_CODE: Dict[str, int] = {
    # Exit Code 2: Input / schema / limits
    "INVALID_INPUT": 2,
    "UNSUPPORTED_SCHEMA": 2,
    "PATH_UNSAFE": 2,
    "LIMIT_EXCEEDED": 2,
    # Exit Code 3: State / concurrency conflicts
    "INVALID_STATE": 3,
    "STALE_ATTEMPT": 3,
    "IDEMPOTENCY_CONFLICT": 3,
    # Exit Code 4: Budget / capability
    "BUDGET_EXHAUSTED": 4,
    "CAPABILITY_UNAVAILABLE": 4,
    "SAFETY_APPROVAL_REQUIRED": 4,
    "USAGE_UNKNOWN": 4,
    # Exit Code 5: Host failure
    "HOST_FAILURE": 5,
    # Exit Code 6: Storage / corruption / snapshot inconsistency
    "STORAGE_ERROR": 6,
    "CORRUPT_RUN": 6,
    "SNAPSHOT_INCONSISTENT": 6,
    # Exit Code 7: Gate failure
    "GATE_FAILED": 7,
}


class InvalidInputError(AuditError):
    """Invalid input detected; exit code 2.

    Requirements: SWR-025(无效输入退出2) / DSR-006(错误码), DSR-074(退出码)
    """

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        """Map to INVALID_INPUT / exit 2. Requirements: SWR-025 / DSR-006(错误码映射,support)"""
        super().__init__("INVALID_INPUT", message, retryable=False, details=details)


class UnsupportedSchemaError(AuditError):
    """Unsupported schema keyword or version; exit code 2.

    Requirements: SWR-025(未支持schema退出2) / DSR-007(未支持即拒绝), DSR-074(退出码)
    """

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        """Map to UNSUPPORTED_SCHEMA / exit 2. Requirements: SWR-025 / DSR-007(错误码映射,support)"""
        super().__init__("UNSUPPORTED_SCHEMA", message, retryable=False, details=details)


class PathUnsafeError(AuditError):
    """Unsafe target/path access; exit code 2.

    Requirements: SWR-025(路径不安全退出2) / DSR-006(错误码), DSR-074(退出码)
    """

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        """Map to PATH_UNSAFE / exit 2. Requirements: SWR-025 / DSR-006(错误码映射,support)"""
        super().__init__("PATH_UNSAFE", message, retryable=False, details=details)


class LimitExceededError(AuditError):
    """Configured limit exceeded; exit code 2.

    Requirements: SWR-025(超限退出2) / DSR-006(错误码), DSR-074(退出码)
    """

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        """Map to LIMIT_EXCEEDED / exit 2. Requirements: SWR-025 / DSR-006(错误码映射,support)"""
        super().__init__("LIMIT_EXCEEDED", message, retryable=False, details=details)


class InvalidStateError(AuditError):
    """Invalid state transition or precondition; exit code 3.

    Requirements: SWR-025(状态冲突退出3) / DSR-006(错误码), DSR-074(退出码)
    """

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        """Map to INVALID_STATE / exit 3. Requirements: SWR-025 / DSR-006(错误码映射,support)"""
        super().__init__("INVALID_STATE", message, retryable=False, details=details)


class StaleAttemptError(AuditError):
    """Expired or superseded attempt (stale claim/generation); exit code 3.

    Requirements: SWR-025(过期attempt退出3) / DSR-006(错误码), DSR-074(退出码)
    """

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        """Map to STALE_ATTEMPT / exit 3. Requirements: SWR-025 / DSR-006(错误码映射,support)"""
        super().__init__("STALE_ATTEMPT", message, retryable=False, details=details)


class IdempotencyConflictError(AuditError):
    """Conflicting duplicate submission for the same key; exit code 3.

    Requirements: SWR-025(幂等冲突退出3) / DSR-006(错误码), DSR-074(退出码)
    """

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        """Map to IDEMPOTENCY_CONFLICT / exit 3. Requirements: SWR-025 / DSR-006(错误码映射,support)"""
        super().__init__("IDEMPOTENCY_CONFLICT", message, retryable=False, details=details)


class BudgetExhaustedError(AuditError):
    """Budget reserve/settlement exhausted; exit code 4.

    Requirements: SWR-025(预算耗尽退出4) / DSR-006(错误码), DSR-074(退出码)
    """

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        """Map to BUDGET_EXHAUSTED / exit 4. Requirements: SWR-025 / DSR-006(错误码映射,support)"""
        super().__init__("BUDGET_EXHAUSTED", message, retryable=False, details=details)


class CapabilityUnavailableError(AuditError):
    """Required host capability missing or unproven; exit code 4.

    Requirements: SWR-025(能力缺失退出4) / DSR-006(错误码), DSR-074(退出码)
    """

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        """Map to CAPABILITY_UNAVAILABLE / exit 4. Requirements: SWR-025 / DSR-006(错误码映射,support)"""
        super().__init__("CAPABILITY_UNAVAILABLE", message, retryable=False, details=details)


class SafetyApprovalRequiredError(AuditError):
    """Unapproved safety-relevant action requested; exit code 4.

    Requirements: SWR-025(需安全批准退出4) / DSR-006(错误码), DSR-074(退出码)
    """

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        """Map to SAFETY_APPROVAL_REQUIRED / exit 4. Requirements: SWR-025 / DSR-006(错误码映射,support)"""
        super().__init__("SAFETY_APPROVAL_REQUIRED", message, retryable=False, details=details)


class UsageUnknownError(AuditError):
    """Usage data unavailable or not constrainable; exit code 4.

    Requirements: SWR-025(用量未知退出4) / DSR-006(错误码), DSR-074(退出码)
    """

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        """Map to USAGE_UNKNOWN / exit 4. Requirements: SWR-025 / DSR-006(错误码映射,support)"""
        super().__init__("USAGE_UNKNOWN", message, retryable=False, details=details)


class HostFailureError(AuditError):
    """Host adapter or process failure; exit code 5.

    Requirements: SWR-025(宿主失败退出5) / DSR-006(错误码), DSR-074(退出码)
    """

    def __init__(self, message: str, retryable: bool = True, details: Optional[Dict[str, Any]] = None) -> None:
        """Map to HOST_FAILURE / exit 5. Requirements: SWR-025 / DSR-006(错误码映射,support)"""
        super().__init__("HOST_FAILURE", message, retryable=retryable, details=details)


class StorageError(AuditError):
    """Persistence or storage failure; exit code 6.

    Requirements: SWR-025(存储失败退出6) / DSR-006(错误码), DSR-074(退出码)
    """

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        """Map to STORAGE_ERROR / exit 6. Requirements: SWR-025 / DSR-006(错误码映射,support)"""
        super().__init__("STORAGE_ERROR", message, retryable=False, details=details)


class CorruptRunError(AuditError):
    """Referenced run state/artifact is corrupt or missing; exit code 6.

    Requirements: SWR-025(run损坏退出6) / DSR-006(错误码), DSR-074(退出码)
    """

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        """Map to CORRUPT_RUN / exit 6. Requirements: SWR-025 / DSR-006(错误码映射,support)"""
        super().__init__("CORRUPT_RUN", message, retryable=False, details=details)


class SnapshotInconsistentError(AuditError):
    """Snapshot drift or inconsistency detected; exit code 6.

    Requirements: SWR-025(快照不一致退出6) / DSR-006(错误码), DSR-074(退出码)
    """

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        """Map to SNAPSHOT_INCONSISTENT / exit 6. Requirements: SWR-025 / DSR-006(错误码映射,support)"""
        super().__init__("SNAPSHOT_INCONSISTENT", message, retryable=False, details=details)


class GateFailedError(AuditError):
    """A programmatic gate check failed; exit code 7.

    Requirements: SWR-025(门禁失败退出7) / DSR-006(错误码), DSR-074(退出码)
    """

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        """Map to GATE_FAILED / exit 7. Requirements: SWR-025 / DSR-006(错误码映射,support)"""
        super().__init__("GATE_FAILED", message, retryable=False, details=details)
