"""Concurrency adjustment controller (AIMD) for host worker dispatch.

Implements DSR-064:
- Successes increase the effective concurrency by one, up to a maximum.
- Failures halve the effective concurrency, down to a minimum of 1.

This class is provided at the hosts layer so the service layer (app/service.py)
and the run loop (audit.py) can wire it in later without touching frozen
modules. It is a pure in-process controller: no I/O, no threads.
"""

# 需求追踪 (Requirement Traceability)
# ---------------------------------------------------------------------------
# 上层需求: docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2
# 设计依据: docs/design/SOFTWARE_DESIGN.md
# SWR-022  driver 并发调度：AIMD 并发调整，失败驱动降速
#   绑定实现: DSR-064
# 状态以统一测试结论为准；未实测能力保持 unknown（设计原则 8：能观测的不靠声明）。
#

from __future__ import annotations


class ConcurrencyController:
    """Additive-increase / multiplicative-decrease concurrency governor."""

    def __init__(self, initial: int = 1, maximum: int = 8, minimum: int = 1) -> None:
        """Validate and clamp concurrency bounds.

        Requirements: SWR-022(support) / DSR-064(并发边界)
        """
        if minimum < 1:
            raise ValueError("minimum concurrency must be >= 1")
        if maximum < minimum:
            raise ValueError("maximum concurrency must be >= minimum")
        if initial < minimum:
            initial = minimum
        if initial > maximum:
            initial = maximum
        self.maximum = maximum
        self.minimum = minimum
        self._current = initial

    @property
    def current(self) -> int:
        """Current effective concurrency level. Requirements: SWR-022(support) / DSR-064(当前并发)"""
        return self._current

    def on_success(self) -> int:
        """AIMD additive increase: +1 on success, capped at maximum. Requirements: SWR-022(加性增) / DSR-064(成功升速)"""
        if self._current < self.maximum:
            self._current += 1
        return self._current

    def on_failure(self) -> int:
        """AIMD multiplicative decrease: halve on failure, floored at minimum. Requirements: SWR-022(乘性减) / DSR-064(失败降速)"""
        self._current = max(self._current // 2, self.minimum)
        return self._current
