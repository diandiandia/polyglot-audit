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
- Task counts are reported in two explicit denominators (O-03, run lessons):
  ``total_enqueued`` counts every task created for the run, while
  ``total_executed`` counts only the tasks actually processed (settled done,
  quarantined, or failed). The normalized rates (tasks/kLOC, tasks/finding)
  use the EXECUTED count as their denominator and say so in their reason
  strings, so a run that planned 4464 units but processed 7 can never dress
  the plan up as executed work. When a caller never records executed counts
  (legacy trackers), the rates fall back to the enqueued total and the
  reason string states that fallback explicitly.
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

# Denominator provenance labels for the normalized rates (O-03): the rates
# are computed over EXECUTED tasks when the caller recorded them, and over
# the enqueued total only as an explicit, documented legacy fallback.
DENOMINATOR_EXECUTED = "executed"
DENOMINATOR_ENQUEUED_FALLBACK = "enqueued_fallback"
EXECUTED_DENOMINATOR_NOTE = "denominator: executed tasks (done/quarantined/failed)"
ENQUEUED_FALLBACK_DENOMINATOR_NOTE = (
    "denominator: enqueued tasks (executed counts were not recorded by this caller)"
)


class CostTracker:
    """Computes cost metrics and telemetry summaries."""

    def __init__(self) -> None:
        """Initialize counters with every optional metric marked unavailable.

        Requirements: SWR-020(缺省不可得) / DSR-067(遥测初始化), DSR-033(来源保留)
        """
        self.candidate_count: Optional[int] = None
        self.usage_covered: Optional[int] = None
        self.usage_total: Optional[int] = None
        self.stage_tasks: Dict[str, int] = {"recon": 0, "hunt": 0, "verify": 0, "report": 0}
        # O-03: executed tasks per stage (settled done / quarantined / failed
        # work actually processed), recorded by the LED wiring. Empty until a
        # caller records them; only then do the rates use the executed
        # denominator.
        self.stage_tasks_executed: Dict[str, int] = {}
        self.executed_recorded: bool = False
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
        """Record an ENQUEUED task (plan scope), not executed work (O-03).

        Requirements: SWR-020(入队计数) / DSR-067(阶段分子), DSR-033(重试观察)
        """
        if kind in self.stage_tasks:
            self.stage_tasks[kind] += 1
        if is_retry:
            self.retries += 1

    def record_executed_task(self, kind: str) -> None:
        """Record one task that was actually processed (O-03).

        Executed means the task reached a processed terminal state: settled
        done, quarantined, or failed. Only these count toward the executed
        denominator of the normalized rates; enqueued-but-never-dispatched
        tasks stay visible in ``stage_tasks`` / ``total_enqueued`` only.

        Requirements: SWR-020(执行分母) / DSR-067(实做计数)
        """
        self.stage_tasks_executed[kind] = self.stage_tasks_executed.get(kind, 0) + 1
        self.executed_recorded = True

    def set_executed_tasks(self, counts: Dict[str, int]) -> None:
        """Accept caller-supplied executed counts per stage (LED wiring point).

        ``counts`` maps task kind -> number of tasks that reached a processed
        terminal state (settled done / quarantined / failed). Calling this
        with an empty dict is meaningful: it records that the caller tracked
        executions and observed ZERO of them, so the rates use a real
        executed denominator of 0 instead of the enqueued fallback.

        Requirements: SWR-020(执行分母) / DSR-067(LED接线)
        """
        for kind, count in (counts or {}).items():
            count = int(count)
            if count:
                self.stage_tasks_executed[kind] = count
        self.executed_recorded = True

    def set_retries(self, count: int, source: str = "host") -> None:
        """Accept a caller-supplied retry counter (WIRE wiring point).

        Requirements: SWR-020(重试指标) / DSR-067(宿主来源)
        """
        self.retries_override = int(count)
        self.retries_source = source

    def set_tokens(self, tokens: int, source: str = "exact") -> None:
        """Record the verified token total with its availability source.

        Requirements: SWR-020(用量来源) / DSR-033(exact保留)
        """
        self.total_tokens = tokens
        self.token_source = source
        self.unavailable_reason = None

    def set_cache_hits(self, count: int, source: str = "exact") -> None:
        """Record caller-supplied cache-hit telemetry (missing stays unavailable).

        Requirements: SWR-020(缓存遥测) / DSR-067(缺失不写零)
        """
        self.cache_hits = int(count)
        self.cache_hits_source = source
        self.cache_hits_reason = None

    def set_candidate_count(self, count: int) -> None:
        """Caller-supplied confirmed-candidate count for §6.10 rates."""
        self.candidate_count = count

    def set_usage_coverage(self, covered: int, total: int) -> None:
        """Caller-supplied usage telemetry coverage (G-2 §6.10: 带 token 用量的任务比例)."""
        self.usage_covered = covered
        self.usage_total = total

    def set_protocol_overhead(self, overhead: int, source: str = "exact") -> None:
        """Record caller-supplied protocol-overhead telemetry (never defaulted).

        Requirements: SWR-020(协议开销) / DSR-067(可观测开销)
        """
        self.protocol_overhead = int(overhead)
        self.protocol_overhead_source = source
        self.protocol_overhead_reason = None

    @staticmethod
    def _optional_metric(value: Optional[int], source: str, reason: Optional[str]) -> Dict[str, Any]:
        """Render an optional metric as available or unavailable-with-reason.

        Requirements: SWR-020(不可得标识) / DSR-067(缺失留原因)
        """
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
        """Compute cost and efficiency indicators.

        The normalized rates (tasks/kLOC, tasks/finding) divide by the
        EXECUTED task count when executed counts were recorded (O-03), and by
        the enqueued total only for legacy callers that never recorded them —
        in that case the rate reason strings say the denominator is the
        enqueued fallback, so a plan is never presented as executed work.

        Requirements: SWR-020(比率可复算) / DSR-067(不可计算标注), DSR-033(来源标注)
        """
        total_enqueued = sum(self.stage_tasks.values())
        total_executed: Optional[int] = (
            sum(self.stage_tasks_executed.values()) if self.executed_recorded else None
        )

        # Rate denominator resolution (O-03): executed when recorded, with an
        # explicit documented fallback for legacy callers.
        if total_executed is not None:
            rate_denominator = total_executed
            denominator_source = DENOMINATOR_EXECUTED
            denominator_note = EXECUTED_DENOMINATOR_NOTE
        else:
            rate_denominator = total_enqueued
            denominator_source = DENOMINATOR_ENQUEUED_FALLBACK
            denominator_note = ENQUEUED_FALLBACK_DENOMINATOR_NOTE

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
            tasks_per_kloc: Optional[float] = round(rate_denominator / kloc, 2)
            tasks_per_kloc_status = "computed"
            tasks_per_kloc_reason: Optional[str] = denominator_note
        else:
            tasks_per_kloc = None
            tasks_per_kloc_status = "non-computable"
            tasks_per_kloc_reason = "total_lines is 0 or missing; kLOC denominator does not exist"

        if confirmed_findings_count > 0:
            tasks_per_finding: Optional[float] = round(rate_denominator / confirmed_findings_count, 2)
            tasks_per_finding_status = "computed"
            tasks_per_finding_reason: Optional[str] = denominator_note
        else:
            tasks_per_finding = None
            tasks_per_finding_status = "non-computable"
            tasks_per_finding_reason = "no confirmed findings; per-finding rate undefined"

        tokens_per_kloc = None
        if self.total_tokens is not None and total_lines and total_lines > 0:
            tokens_per_kloc = round(self.total_tokens / kloc, 2)

        return {
            "stage_tasks": self.stage_tasks,
            "stage_tasks_executed": dict(self.stage_tasks_executed),
            "total_tasks": total_enqueued,
            "total_enqueued": total_enqueued,
            "total_executed": total_executed,
            "rates_denominator": denominator_source,
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
        out["six_ten_metrics"] = self._six_ten_metrics(out)
        return out

    def _six_ten_metrics(self, out: Dict[str, Any]) -> Dict[str, Any]:
        """SYSTEM_DESIGN §6.10 metric table (M4: 可自动产出) -- honest
        computed/unknown statuses, never fabricated numbers."""
        executed = out.get("total_executed")
        stage_executed = out.get("stage_tasks_executed") or {}
        hunt_exec = stage_executed.get("hunt", 0)
        hunt_share = round(hunt_exec / executed, 4) if executed else None

        verify_exec = stage_executed.get("verify", 0)
        cand = self.candidate_count
        verify_per_candidate = (
            round(verify_exec / cand, 3) if cand and cand > 0 else None
        )

        quarantined = stage_executed.get("quarantined", 0)
        failed = stage_executed.get("failed", 0)
        invalid_ratio = (
            round((quarantined + failed) / executed, 4) if executed else None
        )

        if self.usage_covered is not None and self.usage_total:
            usage_ratio = round(self.usage_covered / self.usage_total, 4)
        else:
            usage_ratio = None

        def _m(value, status, reason=None):
            return {"value": value, "status": status, **({"reason": reason} if reason else {})}

        return {
            "hunt_share_of_executed": (
                _m(hunt_share, "computed") if hunt_share is not None
                else _m(None, "unknown", "no executed tasks")
            ),
            "verify_tasks_per_candidate": (
                _m(verify_per_candidate, "computed") if verify_per_candidate is not None
                else _m(None, "unknown", "no confirmed candidates or executed verify tasks")
            ),
            "invalid_task_ratio": (
                _m(invalid_ratio, "computed") if invalid_ratio is not None
                else _m(None, "unknown", "no executed tasks")
            ),
            "usage_task_coverage_ratio": (
                _m(usage_ratio, "computed") if usage_ratio is not None
                else _m(None, "unknown", "usage coverage not supplied by the ledger wiring")
            ),
        }
