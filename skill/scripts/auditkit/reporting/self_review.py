"""Skill self-review anomaly detection across eight mandatory categories.

Implements DSR-070 / SWR-014:
- Every finishable run must produce a local skill self-review.
- Eight detector categories: flow / coverage / cost / verification / knowledge /
  adaptation / error / usage_missing.
- Input is an optional run-statistics dictionary (task counts, gaps, cost
  summary, verdict distribution, unhandled units, ...). When input data is
  missing entirely, each detector emits an ``unknown`` anomaly carrying an
  explicit ``unknown_note`` — missing data is never silently treated as zero
  (design principle 8: observe, don't declare).
- Standard library only.
"""

# 需求追踪 (Requirement Traceability)
# ---------------------------------------------------------------------------
# 上层需求: docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2
# 设计依据: docs/design/SOFTWARE_DESIGN.md
# SWR-014  每次可结束运行生成本地 Skill 自审；数据不可得标明原因，不得当零处理
#   绑定实现: DSR-044, DSR-070, DSR-071
# 状态以统一测试结论为准；未实测能力保持 unknown（设计原则 8：能观测的不靠声明）。
#

from __future__ import annotations
from typing import Any, Callable, Dict, List, Optional

CATEGORIES = (
    "flow",
    "coverage",
    "cost",
    "verification",
    "knowledge",
    "adaptation",
    "error",
    "usage_missing",
)


class SelfReviewCollector:
    """Collects self-review anomalies for one finished run."""

    def __init__(self, run_stats: Optional[Dict[str, Any]] = None) -> None:
        """Accept optional run statistics; detectors cope with partial input.

        Requirements: SWR-014(缺失容忍) / DSR-070(输入可缺)
        """
        # run_stats may be None or partially filled; every detector must cope.
        self.run_stats = run_stats

    # ------------------------------------------------------------------ API
    def collect(self) -> List[Dict[str, Any]]:
        """Run all eight detectors and return the anomaly list.

        Requirements: SWR-014(自审采集) / DSR-070(八类检测)
        """
        stats = self.run_stats
        anomalies: List[Dict[str, Any]] = []
        detectors: List[Callable[[Optional[Dict[str, Any]]], List[Dict[str, Any]]]] = [
            self.detect_flow,
            self.detect_coverage,
            self.detect_cost,
            self.detect_verification,
            self.detect_knowledge,
            self.detect_adaptation,
            self.detect_error,
            self.detect_usage_missing,
        ]
        for detector in detectors:
            anomalies.extend(detector(stats))
        return anomalies

    # -------------------------------------------------------------- helpers
    @staticmethod
    def _anomaly(
        category: str,
        evidence: str,
        impact: str,
        recommendation: str,
        unknown_note: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Shape one anomaly: category/evidence/impact/recommendation/unknown.

        Requirements: SWR-014(结构化异常) / DSR-070(依据影响建议)
        """
        return {
            "category": category,
            "evidence": evidence,
            "impact": impact,
            "recommendation": recommendation,
            "unknown_note": unknown_note,
        }

    @classmethod
    def _unknown(cls, category: str, missing: str) -> Dict[str, Any]:
        """Emit the explicit unknown anomaly for missing input data.

        Requirements: SWR-014(缺失不当零) / DSR-070(unknown说明)
        """
        return cls._anomaly(
            category=category,
            evidence=f"input data unavailable: {missing}",
            impact="self-review for this category cannot be evaluated; result is unknown, not zero",
            recommendation="record the missing statistic at its source so the next run can be reviewed",
            unknown_note=f"{missing} was not supplied to the self-review collector",
        )

    # ------------------------------------------------------------ detectors
    def detect_flow(self, stats: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect flow anomalies: stage/report task accounting.

        Requirements: SWR-014(流程检测) / DSR-070(流程类)
        """
        if stats is None:
            return [self._unknown("flow", "run flow statistics (task counts / stage tasks)")]
        out: List[Dict[str, Any]] = []
        if "total_tasks" not in stats or "stage_tasks" not in stats:
            out.append(self._unknown("flow", "total_tasks / stage_tasks"))
            return out
        stage_tasks = stats.get("stage_tasks") or {}
        if not stage_tasks.get("report"):
            out.append(self._anomaly(
                "flow",
                f"stage_tasks={stage_tasks}",
                "report stage produced no recorded tasks; deliverables may be stale or untracked",
                "ensure the report stage records its tasks in the ledger",
            ))
        if stats.get("total_tasks", 0) <= 0:
            out.append(self._anomaly(
                "flow",
                f"total_tasks={stats.get('total_tasks')}",
                "a finished run recorded zero tasks; the flow accounting is suspect",
                "audit the task claim/settle loop for dropped records",
            ))
        return out

    def detect_coverage(self, stats: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect coverage anomalies: unknown summaries and recorded gaps.

        Requirements: SWR-014(覆盖检测) / DSR-070(覆盖类)
        """
        cov = (stats or {}).get("coverage_summary") if stats else None
        if stats is None or cov is None:
            return [self._unknown("coverage", "coverage_summary")]
        out: List[Dict[str, Any]] = []
        if cov.get("unknown"):
            out.append(self._anomaly(
                "coverage",
                f"coverage summary flagged unknown: {cov.get('unknown_reason')}",
                "coverage claims cannot be substantiated for this run",
                "fix snapshot/interval accounting so coverage is computable",
            ))
        gaps = cov.get("coverage_gaps") or stats.get("coverage_gaps") or []
        if gaps:
            out.append(self._anomaly(
                "coverage",
                f"{len(gaps)} coverage gaps recorded",
                "parts of the inventory were never covered by any dimension",
                "plan follow-up units for the gap regions before declaring completion",
            ))
        return out

    def detect_cost(self, stats: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect cost anomalies: unavailable telemetry and missing rates.

        Requirements: SWR-014(成本检测) / DSR-070(成本类)
        """
        cost = (stats or {}).get("cost_metrics") if stats else None
        if stats is None or cost is None:
            return [self._unknown("cost", "cost_metrics")]
        out: List[Dict[str, Any]] = []
        if cost.get("token_availability") != "exact":
            out.append(self._anomaly(
                "cost",
                f"token_availability={cost.get('token_availability')} reason={cost.get('unavailable_reason')}",
                "cost-per-work metrics are unavailable; budget discipline cannot be reviewed",
                "wire host-supplied token usage into the usage ledger",
                unknown_note=cost.get("unavailable_reason"),
            ))
        if cost.get("tasks_per_kloc") is None:
            out.append(self._anomaly(
                "cost",
                "tasks_per_kloc is non-computable",
                "normalized cost rate missing",
                "record audited line totals so the kLOC denominator exists",
                unknown_note=str(cost.get("tasks_per_kloc_reason") or "no denominator"),
            ))
        return out

    def detect_verification(self, stats: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect a verdict distribution dominated by unverified findings.

        Requirements: SWR-014(验证检测) / DSR-070(验证类)
        """
        verdicts = (stats or {}).get("verdict_distribution") if stats else None
        if stats is None or verdicts is None:
            return [self._unknown("verification", "verdict_distribution")]
        out: List[Dict[str, Any]] = []
        unverified = verdicts.get("needs_validation", 0) + verdicts.get("unverified", 0)
        total = sum(verdicts.values())
        if total > 0 and unverified / total > 0.3:
            out.append(self._anomaly(
                "verification",
                f"{unverified}/{total} findings lack a final verdict",
                "large unverified share weakens the evidence profile of the report",
                "schedule verification rounds or document blockers per finding",
            ))
        return out

    def detect_knowledge(self, stats: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect knowledge-catalog gaps disclosed during the run.

        Requirements: SWR-014(知识检测) / DSR-070(知识类)
        """
        if stats is None:
            return [self._unknown("knowledge", "knowledge statistics (version / gaps)")]
        gaps = stats.get("knowledge_gaps")
        version = stats.get("knowledge_version")
        if gaps is None or version is None:
            return [self._unknown("knowledge", "knowledge_gaps / knowledge_version")]
        out: List[Dict[str, Any]] = []
        if gaps:
            out.append(self._anomaly(
                "knowledge",
                f"knowledge gaps reported: {gaps}",
                "detector coverage for some issue classes is known-incomplete",
                "extend the knowledge catalog for the gap classes",
            ))
        return out

    def detect_adaptation(self, stats: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect detected-but-unadapted languages.

        Requirements: SWR-014(适配检测) / DSR-070(适配类)
        """
        if stats is None:
            return [self._unknown("adaptation", "language adaptation statistics")]
        uncovered = stats.get("uncovered_languages")
        detected = stats.get("detected_languages")
        if uncovered is None or detected is None:
            return [self._unknown("adaptation", "uncovered_languages / detected_languages")]
        out: List[Dict[str, Any]] = []
        if uncovered:
            out.append(self._anomaly(
                "adaptation",
                f"detected={detected} uncovered={uncovered}",
                "some project languages had no adapted detector roster",
                "register language adapters before the next run",
            ))
        return out

    def detect_error(self, stats: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect recorded error events that may hide dropped work.

        Requirements: SWR-014(错误检测) / DSR-070(错误类)
        """
        if stats is None:
            return [self._unknown("error", "error event statistics")]
        errors = stats.get("error_events")
        if errors is None:
            return [self._unknown("error", "error_events")]
        out: List[Dict[str, Any]] = []
        if errors:
            out.append(self._anomaly(
                "error",
                f"{errors} error events recorded during the run",
                "host/storage failures may have silently dropped work units",
                "review error events and reconcile task coverage",
            ))
        return out

    def detect_usage_missing(self, stats: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect attempts without usable host usage records.

        Requirements: SWR-014(用量缺失) / DSR-070(用量类)
        """
        if stats is None:
            return [self._unknown("usage_missing", "host usage statistics")]
        missing_usage = stats.get("usage_missing_count")
        if missing_usage is None:
            return [self._unknown("usage_missing", "usage_missing_count")]
        out: List[Dict[str, Any]] = []
        if missing_usage:
            out.append(self._anomaly(
                "usage_missing",
                f"{missing_usage} attempts lack host usage records",
                "telemetry completeness below 100%; cost review is partial",
                "enable host usage capture for all attempt kinds",
            ))
        return out
