"""Host-layer error types that extend the shared contracts error system.

Implements DSR-031 / DSR-075 / DSR-064:
- RunMismatchError: cross-run access against a run-bound adapter (DSR-031/075).
- TerminationUncertainError: process termination could not be confirmed after
  killpg, so the LED domain must treat the attempt's budget as retained
  (DSR-064).

These classes live in the hosts layer because contracts/errors.py is a frozen
shared contract and must not gain host-specific exceptions. RunMismatchError
deliberately subclasses InvalidInputError so existing exit-code mapping
(INVALID_INPUT -> 2) keeps working without touching contracts.
"""

# 需求追踪 (Requirement Traceability)
# ---------------------------------------------------------------------------
# 上层需求: docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2
# 设计依据: docs/design/SOFTWARE_DESIGN.md
# SWR-019  终止不可确认时保留预算（TerminationUncertainError.retains_budget）
#   绑定实现: DSR-064
# 状态以统一测试结论为准；未实测能力保持 unknown（设计原则 8：能观测的不靠声明）。
#

from __future__ import annotations
from typing import Any, Dict, Optional

from auditkit.contracts.errors import HostFailureError, InvalidInputError


class RunMismatchError(InvalidInputError):
    """Raised when a caller supplies a run_id different from the bound run."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message, details=details)


class TerminationUncertainError(HostFailureError):
    """Raised when process-group termination could not be confirmed.

    `retains_budget=True` signals the LED domain that the attempt's budget
    reservation must stay outstanding until the termination state is resolved.
    """

    def __init__(
        self,
        message: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, retryable=True, details=details)
        self.retains_budget = True
