"""Cost and resource telemetry calculation.

Implements DSR-067 / SD-07 / SR-020 / SWR-020:
- Tracks stage usage, retries, cache hits, and protocol overhead.
- Computes cost per kLOC and cost per confirmed finding; a zero/missing
  denominator is marked ``non-computable`` with an explicit reason instead of
  being silently replaced by a fabricated ``1.0`` fallback.
- Cache-hit and protocol-overhead counters are only reported when the host
  supplies them; missing data is marked ``unavailable`` with a reason and is
  never defaulted to zero.
- Retry counts can be supplied by the caller (host/WIRE wiring) via
  ``set_retries``; the internal ``record_task(is_retry=True)`` path is kept.
- Standard library only.
"""

# 需求追踪 (Requirement Traceability)
# ---------------------------------------------------------------------------
# 上层需求: docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2
# 设计依据: docs/design/SOFTWARE_DESIGN.md
# SWR-020  宿主来源用量与重试指标、完整率及不可得标识；分子分母和估计可复算，未知不写零
#   绑定实现: DSR-033, DSR-067
# 状态以统一测试结论为准；未实测能力保持 unknown（设计原则 8：能观测的不靠声明）。
#

from __future__ import annotations
from typing import Any, Dict, Optional

DEFAULT_CACHE_UNAVAILABLE_REASON = "Host CLI does not report cache hit counts"
DEFAULT_PROTOCOL_OVERHEAD_UNAVAILABLE_REASON = "Host CLI does not report protocol overhead"
DEFAULT_TOKEN_UNAVAILABLE_REASON = "Host CLI does not report verified token counts"


class CostTracker:
    """Computes cost metrics and telemetry summaries."""

    def __init__(self) -> None:
        self.stage_tasks: Dict[str, int] = {"recon": 0, "hunt": 0, "verify": 0, "report": 0}
        self.retries: int = 0
        # DSR-067: caller-supplied retry counter (host wiring); when set it
        # overrides the locally observed count.
        self.retries_override: Optional[int] = None
        self.retries_source: str = "observed"
        self.total_tokens: Optional[int] = None
        self.token_source: str = "unavailable"
        self.unavailable_reason: Optional[str] = DEFAULT_TOKEN_UNAVAILABLE_REASON
        # DSR-067: cache hit / protocol overhead telemetry (None = unavailable).
        self.cache_hits: Optional[int] = None
        self.cache_hits_source: str = "unavailable"
        self.cache_hits_reason: Optional[str] = DEFAULT_CACHE_UNAVAILABLE_REASON
        self.protocol_overhead: Optional[int] = None
        self.protocol_overhead_source: str = "unavailable"
        self.protocol_overhead_reason: Optional[str] = DEFAULT_PROTOCOL_OVERHEAD_UNAVAILABLE_REASON

    def record_task(self, kind: str, is_retry: bool = False) -> None:
        if kind in self.stage_tasks:
            self.stage_tasks[kind] += 1
        if is_retry:
            self.retries += 1

    def set_retries(self, count: int, source: str = "host") -> None:
        """Accept a caller-supplied retry counter (WIRE wiring point)."""
        self.retries_override = int(count)
        self.retries_source = source

    def set_tokens(self, tokens: int, source: str = "exact") -> None:
        self.total_tokens = tokens
        self.token_source = source
        self.unavailable_reason = None

    def set_cache_hits(self, count: int, source: str = "exact") -> None:
        self.cache_hits = int(count)
        self.cache_hits_source = source
        self.cache_hits_reason = None

    def set_protocol_overhead(self, overhead: int, source: str = "exact") -> None:
        self.protocol_overhead = int(overhead)
        self.protocol_overhead_source = source
        self.protocol_overhead_reason = None

    @staticmethod
    def _optional_metric(value: Optional[int], source: str, reason: Optional[str]) -> Dict[str, Any]:
        if value is None:
            return {
                "availability": "unavailable",
                "source": source,
                "value": None,
                "reason": reason or "not supplied",
            }
        return {"availability": source, "source": source, "value": value, "reason": None}

    def compute_metrics(
        self,
        total_lines: int,
        confirmed_findings_count: int,
    ) -> Dict[str, Any]:
        """Compute cost and efficiency indicators."""
        total_tasks = sum(self.stage_tasks.values())

        # DSR-067: retry counter resolution — caller-supplied value wins.
        if self.retries_override is not None:
            retries = self.retries_override
            retries_source = self.retries_source
        else:
            retries = self.retries
            retries_source = "observed"

        # DSR-067: a zero/missing line denominator makes the normalized rate
        # non-computable; it is reported as such with a reason, never via a
        # fabricated 1.0 kLOC fallback.
        if total_lines and total_lines > 0:
            kloc = total_lines / 1000.0
            tasks_per_kloc: Optional[float] = round(total_tasks / kloc, 2)
            tasks_per_kloc_status = "computed"
            tasks_per_kloc_reason: Optional[str] = None
        else:
            tasks_per_kloc = None
            tasks_per_kloc_status = "non-computable"
            tasks_per_kloc_reason = "total_lines is 0 or missing; kLOC denominator does not exist"

        if confirmed_findings_count > 0:
            tasks_per_finding: Optional[float] = round(total_tasks / confirmed_findings_count, 2)
            tasks_per_finding_status = "computed"
            tasks_per_finding_reason: Optional[str] = None
        else:
            tasks_per_finding = None
            tasks_per_finding_status = "non-computable"
            tasks_per_finding_reason = "no confirmed findings; per-finding rate undefined"

        tokens_per_kloc = None
        if self.total_tokens is not None and total_lines and total_lines > 0:
            tokens_per_kloc = round(self.total_tokens / kloc, 2)

        return {
            "stage_tasks": self.stage_tasks,
            "total_tasks": total_tasks,
            "retries": retries,
            "retries_source": retries_source,
            "total_tokens": self.total_tokens,
            "token_availability": self.token_source,
            "unavailable_reason": self.unavailable_reason,
            "tasks_per_kloc": tasks_per_kloc,
            "tasks_per_kloc_status": tasks_per_kloc_status,
            "tasks_per_kloc_reason": tasks_per_kloc_reason,
            "tasks_per_finding": tasks_per_finding,
            "tasks_per_finding_status": tasks_per_finding_status,
            "tasks_per_finding_reason": tasks_per_finding_reason,
            "tokens_per_kloc": tokens_per_kloc,
            "cache_hits": self._optional_metric(self.cache_hits, self.cache_hits_source, self.cache_hits_reason),
            "protocol_overhead": self._optional_metric(
                self.protocol_overhead, self.protocol_overhead_source, self.protocol_overhead_reason
            ),
        }
