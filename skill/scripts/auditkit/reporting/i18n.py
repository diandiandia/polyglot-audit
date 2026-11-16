"""Minimal report i18n: zh/en label dictionaries with fallback.

Implements DSR-068 / SWR-012:
- ``ReportGenerator`` stores ``report_language``; without this module all
  headings and status copy were hard-coded Chinese regardless of the setting.
- ``en`` is the default report language; an unknown language falls back to
  ``zh`` and the fallback is both logged and surfaced in the report header.
- Standard library only.
"""

# 需求追踪 (Requirement Traceability)
# ---------------------------------------------------------------------------
# 上层需求: docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2
# 设计依据: docs/design/SOFTWARE_DESIGN.md
# SWR-012  主报告、结果、未决、覆盖、轨迹、成本与终态渲染；中断/预算耗尽输出不完整报告
#   绑定实现: DSR-068
# 状态以统一测试结论为准；未实测能力保持 unknown（设计原则 8：能观测的不靠声明）。
#

from __future__ import annotations
import logging
from typing import Dict, List

_logger = logging.getLogger("auditkit.reporting.i18n")

SUPPORTED_LANGUAGES = ("en", "zh")
DEFAULT_LANGUAGE = "en"
FALLBACK_LANGUAGE = "zh"

# Terminal run state copy (DSR-068: status text must follow report_language).
STATE_LABELS: Dict[str, Dict[str, str]] = {
    "en": {
        "complete": "complete",
        "incomplete": "incomplete (run interrupted or budget exhausted)",
        "finalizing": "finalizing",
        "unknown": "unknown state",
    },
    "zh": {
        "complete": "complete",
        "incomplete": "incomplete (run interrupted or budget exhausted)",
        "finalizing": "finalizing",
        "unknown": "unknown state",
    },
}

LABELS: Dict[str, Dict[str, str]] = {
    "en": {
        "report_title": "# Source Code Security Audit Report",
        "run_id": "Run ID",
        "snapshot_id": "Snapshot ID",
        "status": "Status",
        "generation": "Generation",
        "language_note": "Language",
        "confirmed_findings": "Confirmed Findings",
        "needs_validation": "Needs Validation",
        "unverified_count": "Unverified Candidates",
        "findings_summary": "## 1. Findings Summary",
        "col_id": "ID",
        "col_urgency": "Urgency",
        "col_severity": "Severity",
        "col_issue": "Issue Class",
        "col_title": "Title",
        "col_location": "Location",
        "no_confirmed": "No confirmed high-risk security findings.",
        "detailed_findings": "## 2. Detailed Findings",
        "verdict": "Verdict",
        "evidence_level": "Evidence Level",
        "severity": "Severity",
        "taint_path": "**Taint Path:**",
        "guards": "Guards",
        "guards_none": "none recorded on the studied path (guard absence is NOT claimed)",
        "attacker": "Attacker",
        "preconditions": "Attack Preconditions",
        "preconditions_none": "none recorded",
        "exploitability": "Exploitability",
        "remediation": "**Remediation**",
        "regression_test": "- **Regression Test**",
        "limitations": "## 3. Limitations & Scope",
        "limitation_static": "- This audit is based on pure static semantic analysis (E2 evidence level); no dynamic reproduction was performed.",
        "limitation_env": "- External environment variables and cloud-specific deployment topology may change actual path reachability.",
        "limitation_secrets": "- Secret redaction covers only known credential patterns (API keys, bearer tokens, passwords, private keys). Secrets in unrecognized formats may remain in this report; manually review before distribution. Unrecognized-secret risk is explicitly acknowledged.",
        "needs_val_title": "# Needs Validation Items",
        "total_items": "Total items",
        "no_needs_val": "No pending external validation items.",
        "priority": "Priority",
        "blockers": "**Blockers**",
        "validation_plan": "**Validation Plan**",
        "unverified_items": "Unverified Candidates",
        "half_chain_section": "## Unconnected Half-Chains (Frontier / Dangling Sink)",
        "half_chain_none": "No unconnected half-chain records.",
        "half_chain_note": "Records below were reported by hunt workers but never paired by the run-level connector; they are hypotheses, not findings (DSR-058).",
        "col_record_kind": "Kind",
        "col_record_id": "Record ID",
        "col_boundary": "Boundary",
        "col_symbol": "Symbol",
        "col_source_task": "Source Task",
        "unverified_section": "## Unverified Candidates",
        "unverified_none": "No unverified candidates.",
        "unverified_reason_label": "**Unverified reason**",
        "verify_task_state": "Verify task state",
        "coverage_title": "# Audit Coverage Report",
        "total_files": "Total Files",
        "inventoried_lines": "Inventoried Lines",
        "dim_coverage": "## Multi-Dimensional Coverage",
        "col_dimension": "Dimension",
        "col_covered": "Covered Lines",
        "col_pct": "Coverage",
        "trail_title": "# Audit Trail",
        "total_events": "Total events",
        "timeline": "## 1. State Event Timeline",
        "col_rev": "Rev",
        "col_time": "Time",
        "col_actor": "Actor",
        "col_event": "Event Type",
        "provenance": "## 2. Finding Provenance",
        "prov_hunt": "Hunt Tasks",
        "prov_verify": "Verify Tasks",
        "cost_title": "# Cost & Telemetry Report",
        "total_tasks": "Total Executed Tasks",
        "retries": "Retries",
        "tasks_per_kloc": "Tasks/kLOC",
        "tasks_per_finding": "Tasks per Confirmed Finding",
        "token_status": "Token Metering Status",
        "unavailable_reason": "Unavailable Reason",
        "cache_section": "## Cache & Protocol Overhead",
        "cache_hits": "Cache Hits",
        "protocol_overhead": "Protocol Overhead (tasks)",
        "non_computable": "non-computable",
        "unavailable": "unavailable",
        "stage_breakdown": "## Stage Breakdown",
        "col_stage": "Stage",
        "col_tasks": "Tasks",
        "review_title": "# Skill Self-Review",
        "total_anomalies": "Total Anomalies Detected",
        "anomaly_list": "## Anomalies & Gaps",
        "no_anomalies": "No significant process or contract anomalies detected.",
        "impact": "Impact",
        "recommendation": "Recommendation",
        "unknown_note": "Unknown note",
        "local_dossier_note": "- This local self-review may reference the run dossier; the portable JSON export is whitelist-only and is not written unless explicitly enabled.",
    },
    "zh": {
        "report_title": "# 源代码安全审计报告 (Source Code Security Audit Report)",
        "run_id": "Run ID",
        "snapshot_id": "Snapshot ID",
        "status": "状态 (Status)",
        "generation": "代次 (Generation)",
        "language_note": "报告语言 (Language)",
        "confirmed_findings": "已确认发现 (Confirmed Findings)",
        "needs_validation": "待验证 (Needs Validation)",
        "unverified_count": "未验证候选 (Unverified)",
        "findings_summary": "\n## 1. 发现总表 (Findings Summary)\n",
        "col_id": "ID",
        "col_urgency": "紧迫度",
        "col_severity": "严重度",
        "col_issue": "问题类",
        "col_title": "标题",
        "col_location": "位置",
        "no_confirmed": "未发现已确认的高危安全漏洞",
        "detailed_findings": "\n## 2. 详细发现明细 (Detailed Findings)\n",
        "verdict": "裁决 (Verdict)",
        "evidence_level": "证据等级",
        "severity": "严重度",
        "taint_path": "\n**数据流追踪 (Taint Path):**",
        "guards": "守卫 (Guards)",
        "guards_none": "研究路径上未记录守卫（不声称守卫不存在）",
        "attacker": "攻击者 (Attacker)",
        "preconditions": "攻击前提 (Attack Preconditions)",
        "preconditions_none": "未记录前提条件",
        "exploitability": "可利用性 (Exploitability)",
        "remediation": "**修复建议 (Remediation)**",
        "regression_test": "- **回归检验**",
        "limitations": "\n## 3. 审计局限与范围说明 (Limitations & Scope)",
        "limitation_static": "- 本次审计依据纯静态代码语义分析（E2 等级），未经动态运行复现。",
        "limitation_env": "- 外部环境变量、云端特定部署架构可能改变路径实际可达性。",
        "limitation_secrets": "- 秘密脱敏仅覆盖已知凭据模式（API key、Bearer token、密码、私钥等）；无法识别格式的秘密可能残留在报告中，存在泄露风险，分发前需人工复核。无法识别的秘密风险在此显式声明。",
        "needs_val_title": "# 待外部验证清单 (Needs Validation Items)",
        "total_items": "总条目",
        "no_needs_val": "当前无待外部验证事项。",
        "priority": "优先级",
        "blockers": "**阻断原因 (Blockers)**",
        "validation_plan": "**验证方案 (Validation Plan)**",
        "unverified_items": "未验证候选 (Unverified Candidates)",
        "half_chain_section": "\n## 未连接半链 (Unconnected Half-Chains: Frontier / Dangling Sink)\n",
        "half_chain_none": "当前无未连接半链记录。",
        "half_chain_note": "以下记录由 hunt worker 报告，但经 run 级汇聚后仍未被连接器配对；它们只是假设线索，不是发现 (DSR-058)。",
        "col_record_kind": "类型",
        "col_record_id": "记录 ID",
        "col_boundary": "边界",
        "col_symbol": "符号",
        "col_source_task": "来源任务",
        "unverified_section": "\n## 未验证候选 (Unverified Candidates)\n",
        "unverified_none": "当前无未验证候选。",
        "unverified_reason_label": "**未验证原因 (Unverified reason)**",
        "verify_task_state": "验证任务状态 (Verify task state)",
        "coverage_title": "# 审计覆盖率报告 (Coverage Report)",
        "total_files": "总文件数",
        "inventoried_lines": "纳入行数 (Inventoried Lines)",
        "dim_coverage": "\n## 各维度覆盖率 (Multi-Dimensional Coverage)\n",
        "col_dimension": "维度",
        "col_covered": "覆盖行数",
        "col_pct": "覆盖比例",
        "trail_title": "# 审计轨迹记录 (Audit Trail)",
        "total_events": "总事件数",
        "timeline": "\n## 1. 状态事件时间线 (Event Timeline)\n",
        "col_rev": "Rev",
        "col_time": "时间",
        "col_actor": "Actor",
        "col_event": "事件类型",
        "provenance": "\n## 2. 发现溯源映射 (Finding Provenance)\n",
        "prov_hunt": "Hunt 任务",
        "prov_verify": "Verify 任务",
        "cost_title": "# 资源消耗与成本报告 (Cost & Telemetry Report)",
        "total_tasks": "总执行任务数",
        "retries": "重试次数 (Retries)",
        "tasks_per_kloc": "每千行任务数 (Tasks/kLOC)",
        "tasks_per_finding": "每确认发现任务数",
        "token_status": "Token 计量状态",
        "unavailable_reason": "不可用原因",
        "cache_section": "\n## 缓存与协议开销 (Cache & Protocol Overhead)\n",
        "cache_hits": "缓存命中 (Cache Hits)",
        "protocol_overhead": "协议开销任务数 (Protocol Overhead)",
        "non_computable": "不可计算 (non-computable)",
        "unavailable": "不可得 (unavailable)",
        "stage_breakdown": "\n## 阶段任务明细 (Stage Breakdown)\n",
        "col_stage": "阶段",
        "col_tasks": "任务数",
        "review_title": "# 本地 Skill 自审报告 (Skill Self-Review)",
        "total_anomalies": "检测到异常总数",
        "anomaly_list": "\n## 异常与改进清单 (Anomalies & Gaps)\n",
        "no_anomalies": "未发现显著流程或契约异常。",
        "impact": "影响",
        "recommendation": "建议",
        "unknown_note": "数据缺失说明",
        "local_dossier_note": "- 本地自审报告可引用运行卷宗；可移植 JSON 导出仅含白名单字段，未显式开启时不写出。",
    },
}


class ReportLanguage:
    """Resolved report language with explicit unknown-language fallback."""

    def __init__(self, requested: str) -> None:
        self.requested = requested
        if requested in SUPPORTED_LANGUAGES:
            self.language = requested
            self.fallback_applied = False
        else:
            # DSR-068: unknown language falls back to zh and must be recorded.
            self.language = FALLBACK_LANGUAGE
            self.fallback_applied = True
            _logger.warning(
                "Unknown report_language %r; falling back to %r", requested, FALLBACK_LANGUAGE
            )

    @property
    def fallback_note(self) -> str:
        if not self.fallback_applied:
            return ""
        return (
            f"- **Language note**: requested report_language `{self.requested}` is not "
            f"supported; fell back to `{FALLBACK_LANGUAGE}` (supported: "
            f"{', '.join(SUPPORTED_LANGUAGES)})."
        )

    def t(self, key: str) -> str:
        table = LABELS[self.language]
        return table.get(key, LABELS[FALLBACK_LANGUAGE].get(key, key))

    def state(self, state: str) -> str:
        return STATE_LABELS[self.language].get(state, STATE_LABELS[self.language]["unknown"])
