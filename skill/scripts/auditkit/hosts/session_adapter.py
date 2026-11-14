"""In-session execution adapter and task dispatch.

Implements DSR-004 / DSR-030 / SD-09 / IFC-04:
- Coordinates next -> start -> submit cycle within the active LLM session.
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
import json
from typing import Any, Callable, Dict, List, Optional

from auditkit.contracts.errors import InvalidStateError
from auditkit.ledger.task_queue import TaskQueue
from auditkit.hosts.probes import (
    PROBE_LEVEL_AGGRESSIVE,
    probe_subagent_delegation,
)

MODE_SUBAGENT = "subagent"
MODE_SEQUENTIAL_FALLBACK = "sequential_fallback"


class InSessionAdapter:
    """Coordinates in-session task execution against the TaskQueue."""

    def __init__(
        self,
        task_queue: TaskQueue,
        supports_subagents: Optional[bool] = None,
    ) -> None:
        """Create the adapter.

        supports_subagents: None (default) means delegation capability has not
        been measured -> the adapter starts in the bounded sequential fallback
        mode and the delegation probe stays UNKNOWN (DSR-004/030: unmeasured
        capabilities are never assumed). True/False record a measured result.
        """
        self.queue = task_queue
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
        """Current execution mode: "subagent" or "sequential_fallback"."""
        return self._mode

    @property
    def supports_subagents(self) -> Optional[bool]:
        """Measured delegation capability: True / False / None (unmeasured)."""
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
        """Fetch next batch of claims."""
        return self.queue.claim(run_id, batch_size=batch_size, worker_id="in_session")

    def start_task(self, claim: Dict[str, Any]) -> Dict[str, Any]:
        """Mark claimed attempt as active."""
        return self.queue.start(
            run_id=claim["run_id"],
            task_id=claim["task_id"],
            attempt_id=claim["attempt_id"],
            generation=claim["generation"],
            claim_token=claim["claim_token"],
        )

    def submit_task(
        self,
        claim: Dict[str, Any],
        worker_result: Dict[str, Any],
        result_digest: str,
        usage: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Submit completed task result."""
        return self.queue.submit(
            run_id=claim["run_id"],
            task_id=claim["task_id"],
            attempt_id=claim["attempt_id"],
            generation=claim["generation"],
            claim_token=claim["claim_token"],
            worker_result=worker_result,
            result_digest=result_digest,
            usage=usage,
        )
