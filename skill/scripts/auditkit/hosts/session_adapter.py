"""In-session execution adapter and task dispatch.

Implements DSR-004 / DSR-030 / SD-09 / IFC-04 / DDS-01 / SR-022:
- Coordinates next -> start -> submit cycle within the active LLM session.
- Routes every operation through the AuditAppService (DDS-01 / SR-022): the
  in-session path is the same state-mutation entry point as the MCP and CLI
  transports, so schema validation, coverage recording and the hunt -> verify
  fan-out apply identically.
- Supports sub-agent delegation if available, falls back gracefully to
  sequential execution; the active mode is disclosed via the `mode` attribute
  ("subagent" or "sequential_fallback") so the doctor / capability matrix can
  report the real session shape instead of assuming one (DSR-030).
- Validates tokens and handles delayed submissions safely.
"""

# 需求追踪 (Requirement Traceability)
# ---------------------------------------------------------------------------
# 上层需求: docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2
# 设计依据: docs/design/SOFTWARE_DESIGN.md
# SWR-022  in-session 与 driver 同等支持：共用 claim 协议；缺委派如实标 sequential_fallback 降级
#   绑定实现: DSR-030, DSR-075
# 状态以统一测试结论为准；未实测能力保持 unknown（设计原则 8：能观测的不靠声明）。
#

from __future__ import annotations
from typing import Any, Callable, Dict, List, Optional

from auditkit.app.service import AuditAppService
from auditkit.hosts.probes import (
    PROBE_LEVEL_AGGRESSIVE,
    probe_subagent_delegation,
)

MODE_SUBAGENT = "subagent"
MODE_SEQUENTIAL_FALLBACK = "sequential_fallback"


class InSessionAdapter:
    """Coordinates in-session task execution through the AuditAppService."""

    def __init__(
        self,
        service: AuditAppService,
        run_dir: str,
        supports_subagents: Optional[bool] = None,
    ) -> None:
        """Create the adapter.

        service: the application service every operation routes through
        (DDS-01: the single state-mutation entry point).
        run_dir: the run directory this adapter operates on.
        supports_subagents: None (default) means delegation capability has not
        been measured -> the adapter starts in the bounded sequential fallback
        mode and the delegation probe stays UNKNOWN (DSR-004/030: unmeasured
        capabilities are never assumed). True/False record a measured result.
        Requirements: SWR-022(模式披露) / DSR-030(未测降级), DSR-004(委派未知)
        """
        self.service = service
        self.run_dir = run_dir
        if supports_subagents is None:
            self._supports_subagents: Optional[bool] = None
            self._mode = MODE_SEQUENTIAL_FALLBACK
        elif supports_subagents:
            self._supports_subagents = True
            self._mode = MODE_SUBAGENT
        else:
            self._supports_subagents = False
            self._mode = MODE_SEQUENTIAL_FALLBACK

    @property
    def mode(self) -> str:
        """Current execution mode: "subagent" or "sequential_fallback". Requirements: SWR-022(support) / DSR-030(模式读取)"""
        return self._mode

    @property
    def supports_subagents(self) -> Optional[bool]:
        """Measured delegation capability: True / False / None (unmeasured). Requirements: SWR-022(support) / DSR-004(委派状态)"""
        return self._supports_subagents

    def probe_delegation(
        self,
        delegate_fn: Optional[Callable[[str], Any]] = None,
        probe_level: str = "conservative",
    ) -> Dict[str, Any]:
        """DSR-004/030: measure sub-agent delegation and update `mode`.

        Only executes the trial at the aggressive level with a delegate
        callback; otherwise returns UNKNOWN with the probe plan described
        (conservative default). When the trial confirms delegation, the mode
        switches to "subagent".
        Requirements: SWR-022(委派探测) / DSR-004(实测切换), DSR-030(如实降级)
        """
        feature = probe_subagent_delegation(delegate_fn, probe_level=probe_level)
        if (
            probe_level == PROBE_LEVEL_AGGRESSIVE
            and delegate_fn is not None
            and feature.get("state") == "enforced"
        ):
            self._supports_subagents = True
            self._mode = MODE_SUBAGENT
        elif probe_level == PROBE_LEVEL_AGGRESSIVE and delegate_fn is not None:
            self._supports_subagents = False
            self._mode = MODE_SEQUENTIAL_FALLBACK
        return feature

    def next_task(self, run_id: str, batch_size: int = 1) -> List[Dict[str, Any]]:
        """Fetch next batch of claims (with published prompt packets). Requirements: SWR-022(共用领取) / DSR-030(next流程)"""
        return self.service.next(
            run_id, self.run_dir, batch_size=batch_size, worker_id="in_session"
        )

    def start_task(self, claim: Dict[str, Any]) -> Dict[str, Any]:
        """Mark claimed attempt as active. Requirements: SWR-022(共用开始) / DSR-030(start流程)"""
        return self.service.start(self.run_dir, claim)

    def submit_task(
        self,
        claim: Dict[str, Any],
        worker_result: Dict[str, Any],
        result_digest: str,
        usage: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Submit completed task result. Requirements: SWR-022(共用提交) / DSR-030(submit流程), DSR-075(令牌校验)"""
        return self.service.submit(
            self.run_dir,
            claim,
            worker_result,
            result_digest,
            usage=usage,
        )
