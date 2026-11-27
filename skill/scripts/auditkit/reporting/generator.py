"""Multi-report atomic generator and Skill self-review renderer.

Implements DSR-034 / DSR-035 / DSR-036 / DSR-044 / DSR-045 / DSR-067 / DSR-068 /
DSR-069 / DSR-070 / DSR-071 / SD-08 / SD-11 / SWR-010 / SWR-012 / SWR-014 / SWR-016:
- Atomic publishing under a single report_generation_id: every payload is
  rendered and staged to a temporary file first; only after ALL stage writes
  succeed and every staged file is verified to carry the generation id are the
  final names replaced. The replacement tail is replace-only and kept short,
  so an interrupted generation can never publish a mixed half-new/half-old
  report directory (DSR-036).
- Every output medium (Markdown, JSON, CSV) passes through the secret masker
  before it touches disk (DSR-069 / SWR-010).
- Findings-first presentation in REPORT.md with per-finding provenance and
  audit-trail traceability down to candidate/attempt anchors (DSR-035).
- NEEDS-VALIDATION.md renders three kinds of pending work: needs_validation /
  unverified findings (DSR-066), unconnected half-chains reconciled from the
  event ledger (SR-005 / DSR-058), and unverified candidates with their
  reasons.
- Minimal i18n: zh/en label tables, ``en`` default, unknown language falls
  back to ``zh`` and the fallback is recorded (DSR-068 / SWR-012).
- The portable skill-review JSON export (skill-review/portable.json) is
  opt-in and strictly whitelist-only (DSR-045 / SWR-016); the local
  skill-review/SKILL-REVIEW.md is always written. Design §10.1 keeps the
  skill self-review in its own dossier directory — report/ holds only the
  §9.3 report set.
- Standard library only.
"""

# 需求追踪 (Requirement Traceability)
# ---------------------------------------------------------------------------
# 上层需求: docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2
# 设计依据: docs/design/SOFTWARE_DESIGN.md
# SWR-010  确认发现报告呈现 source/sink/证据链/修复建议；凭据值不得出现在报告
#   绑定实现: DSR-035, DSR-069
# SWR-012  主报告、结果、未决、覆盖、轨迹、成本与终态渲染；中断/预算耗尽输出不完整报告
#   绑定实现: DSR-035, DSR-036, DSR-068
# SWR-013  卷宗保留到任务、提示、结果、快照摘要的追溯关系；报告双向可追踪
#   绑定实现: DSR-035, DSR-036
# SWR-014  每次可结束运行生成本地 Skill 自审；数据不可得标明原因，不得当零处理
#   绑定实现: DSR-044, DSR-070, DSR-071
# SWR-016  可移植自审导出仅含白名单枚举/统计字段，默认关闭
#   绑定实现: DSR-045
# 状态以统一测试结论为准；未实测能力保持 unknown（设计原则 8：能观测的不靠声明）。
#

from __future__ import annotations
import csv
import hashlib
import io
import json
import logging
import os
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from auditkit.contracts.errors import InvalidInputError, StorageError
from auditkit.contracts.semantic_validator import URGENCY_ORDER
from auditkit.ledger.artifacts import ArtifactManager
from auditkit.reporting.i18n import DEFAULT_LANGUAGE, ReportLanguage
from auditkit.reporting.secret_masker import mask_csv_text, mask_json_text, mask_secrets, mask_tree
from auditkit.reporting.self_review import SelfReviewCollector

_logger = logging.getLogger("auditkit.reporting.generator")

# DSR-045 / SWR-016: whitelist for the portable skill-review JSON export.
# Anything outside these key sets must be rejected, never silently exported.
SKILL_REVIEW_EXPORT_ALLOWED_ROOT_KEYS = {"schema_version", "generation_id", "run_id", "run_summary", "anomaly_categories"}
SKILL_REVIEW_EXPORT_ALLOWED_RUN_SUMMARY_KEYS = {
    "run_state",
    "total_files_audited",
    "total_lines_audited",
    "total_confirmed_findings",
    "total_needs_validation",
    "total_tasks_executed",
    "retries",
    "language",
}
SKILL_REVIEW_EXPORT_SCALAR_TYPES = (str, int, float, bool)


class ReportGenerator:
    """Renders and atomically publishes all audit deliverables."""

    def __init__(
        self,
        run_id: str,
        snapshot_id: str,
        run_state: str,
        artifact_manager: ArtifactManager,
        report_language: str = DEFAULT_LANGUAGE,
    ) -> None:
        """Bind one generation to a run state and resolved report language.

        Requirements: SWR-012(终态与语言) / DSR-068(语言解析)
        """
        self.run_id = run_id
        self.snapshot_id = snapshot_id
        self.run_state = run_state
        self.artifacts = artifact_manager
        # DSR-068: language resolution with recorded fallback.
        self.report_language = report_language
        self._lang = ReportLanguage(report_language)
        self.language_fallback_applied = self._lang.fallback_applied

    # ------------------------------------------------------------------ API
    def generate_all(
        self,
        findings: List[Dict[str, Any]],
        coverage_summary: Dict[str, Any],
        cost_metrics: Dict[str, Any],
        events: List[Dict[str, Any]],
        anomalies: Optional[List[Dict[str, Any]]] = None,
        export_skill_review: bool = False,
        self_review_inputs: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Render all reports atomically and return generation ID.

        DSR-045: ``skill-review/portable.json`` (portable whitelist-only
        export) is only written when ``export_skill_review`` is True;
        ``skill-review/SKILL-REVIEW.md`` (local, may reference the run
        dossier) is always written.
        DSR-070: when ``anomalies`` is not supplied but ``self_review_inputs``
        is, the SelfReviewCollector produces the anomaly list.

        Requirements: SWR-012(报告集生成), SWR-014(自审渲染) / DSR-036(原子发布), DSR-045(默认不导出), DSR-070(异常采集)
        """
        generation_id = f"gen-{uuid.uuid4().hex[:8]}"

        if anomalies is None and self_review_inputs is not None:
            anomalies = SelfReviewCollector(self_review_inputs).collect()
        elif anomalies is None and self_review_inputs is None:
            # DSR-070 / SWR-014: no statistics and no explicit anomaly list —
            # the honest self-review states per-category unknown anomalies; it
            # must never render an empty list that reads as "nothing wrong".
            anomalies = SelfReviewCollector(None).collect()

        payloads = self._build_payloads(
            findings, coverage_summary, cost_metrics, events,
            anomalies or [], generation_id, export_skill_review,
        )

        self._stage_and_publish(payloads, generation_id)
        return generation_id

    # ------------------------------------------------------- payload build
    def _build_payloads(
        self,
        findings: List[Dict[str, Any]],
        coverage_summary: Dict[str, Any],
        cost_metrics: Dict[str, Any],
        events: List[Dict[str, Any]],
        anomalies: List[Dict[str, Any]],
        generation_id: str,
        export_skill_review: bool,
    ) -> List[Tuple[str, str, bool, bytes]]:
        """Return (kind, rel_path, carries_generation_marker, content) tuples.

        Requirements: SWR-010(逐介质脱敏), SWR-012(报告集构建) / DSR-035(固定记录), DSR-069(凭据掩蔽)
        """
        payloads: List[Tuple[str, str, bool, bytes]] = []

        # SR-005/DSR-058/DSR-066: unconnected half-chains are reconciled from
        # the event ledger (events are already a generate_all input), and
        # unverified candidates from the findings themselves — no extra
        # parameters or caller changes are required.
        half_chains = self._collect_unpaired_half_chains(events)
        unverified_candidates = [f for f in findings if f.get("verdict") == "unverified"]

        # 1. findings.json — DSR-069: JSON media masked by value recursion.
        findings_payload = mask_tree(findings)
        findings_json_bytes = json.dumps(findings_payload, indent=2, ensure_ascii=False).encode("utf-8")
        payloads.append(("report_json", "report/findings.json", False, findings_json_bytes))

        # 2. REPORT.md
        report_md = self._render_main_report(findings, coverage_summary, generation_id, half_chains)
        payloads.append(("report_md", "report/REPORT.md", True, mask_secrets(report_md).encode("utf-8")))

        # 3. NEEDS-VALIDATION.md (DSR-068: generation id in header)
        needs_val_md = self._render_needs_validation(
            findings, generation_id, half_chains=half_chains,
            unverified_candidates=unverified_candidates,
        )
        payloads.append(("report_needs_validation", "report/NEEDS-VALIDATION.md", True, mask_secrets(needs_val_md).encode("utf-8")))

        # 4. COVERAGE.md & coverage.csv
        cov_md = self._render_coverage_md(coverage_summary, generation_id)
        payloads.append(("report_coverage_md", "report/COVERAGE.md", True, mask_secrets(cov_md).encode("utf-8")))

        cov_csv = self._render_coverage_csv(coverage_summary.get("file_breakdown", []), generation_id)
        payloads.append(("report_coverage_csv", "report/coverage.csv", True, mask_csv_text(cov_csv).encode("utf-8")))

        # 5. AUDIT-TRAIL.md
        trail_md = self._render_audit_trail(events, findings, generation_id)
        payloads.append(("report_trail", "report/AUDIT-TRAIL.md", True, mask_secrets(trail_md).encode("utf-8")))

        # 6. COST.md
        cost_md = self._render_cost_report(cost_metrics, generation_id)
        payloads.append(("report_cost", "report/COST.md", True, mask_secrets(cost_md).encode("utf-8")))

        # 7. SKILL-REVIEW.md (always, local dossier-aware) and portable.json
        #    (opt-in whitelist-only portable export, DSR-045/SWR-016). Design
        #    §10.1 puts the skill self-review in its own dossier directory
        #    (skill-review/) — report/ holds only the report set of §9.3.
        review_md = self._render_skill_review_md(anomalies, generation_id)
        payloads.append(("skill_review_md", "skill-review/SKILL-REVIEW.md", True, mask_secrets(review_md).encode("utf-8")))

        if export_skill_review:
            review_json = self._build_portable_skill_review(anomalies, coverage_summary, cost_metrics, findings, generation_id)
            # DSR-069: JSON export is built from whitelisted scalars only, but
            # still pass through the masker for defense in depth.
            payloads.append((
                "skill_review_json",
                "skill-review/portable.json",
                True,
                mask_json_text(json.dumps(review_json, indent=2, ensure_ascii=False)).encode("utf-8"),
            ))

        return payloads

    # -------------------------------------------------- staged publication
    def _stage_and_publish(
        self,
        payloads: List[Tuple[str, str, bool, bytes]],
        generation_id: str,
    ) -> None:
        """Two-phase publication (DSR-036 / SWR-012).

        Phase A (fail-safe): render + write every payload to a ``.tmp-stage-*``
        file inside the target directory and fsync it. Any failure here leaves
        the previous generation untouched.
        Phase B (verify): read every staged file back and require its
        generation marker before anything is published.
        Phase C (commit): replace-only tail — every risky operation already
        happened, so the mixed-generation window is limited to the
        uninterruptible ``os.replace`` calls themselves.

        Requirements: SWR-012(中断不混合) / DSR-036(两阶段发布)
        """
        run_dir = self.artifacts.run_dir
        staged: List[Tuple[Path, Path, str, str, bool, bytes]] = []

        # ---- Phase A: stage all temp writes before any replace.
        current_tmp: Optional[Path] = None
        try:
            for kind, rel_path, has_marker, content in payloads:
                final_path = run_dir / rel_path
                final_path.parent.mkdir(parents=True, exist_ok=True)
                current_tmp = final_path.parent / f".tmp-stage-{generation_id}-{final_path.name}"
                with open(current_tmp, "wb") as f:
                    f.write(content)
                    f.flush()
                    os.fsync(f.fileno())
                staged.append((current_tmp, final_path, kind, rel_path, has_marker, content))
                current_tmp = None
        except OSError as e:
            # Also remove the tmp file whose write itself failed.
            self._cleanup_staged(list(tmp for tmp, _, _, _, _, _ in staged) + ([current_tmp] if current_tmp else []))
            # SWR-012/SWR-014: the fault path is part of the failure report —
            # name the artifact that could not be staged.
            raise StorageError(f"Failed to stage report artifact {rel_path}: {e}")

        # ---- Phase B: verify staged generation markers.
        try:
            for tmp_path, _, _, rel_path, has_marker, _ in staged:
                written = tmp_path.read_bytes()
                if has_marker and generation_id.encode("utf-8") not in written:
                    raise StorageError(
                        f"Staged artifact {rel_path} does not carry generation {generation_id}; aborting publish"
                    )
        except StorageError:
            self._cleanup_staged(tmp for tmp, _, _, _, _, _ in staged)
            raise

        # ---- Phase C: replace-only commit tail (kept deliberately short).
        for tmp_path, final_path, kind, rel_path, _, content in staged:
            os.replace(tmp_path, final_path)
            self._register_artifact(kind, rel_path, content, generation_id)

    @staticmethod
    def _cleanup_staged(tmp_paths) -> None:
        """Remove staged temp files best-effort (publication stays fail-safe).

        Requirements: SWR-012(半成品清理) / DSR-036(support)
        """
        for tmp_path in tmp_paths:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass

    def _register_artifact(self, kind: str, rel_path: str, content: bytes, generation_id: str) -> None:
        """Register a committed report artifact in the artifacts table.

        DSR-036 note: the ledger's publish_artifact interleaves its own temp
        write with the replace, which would re-open the mixed-generation
        window; therefore the generator commits the already-staged file
        itself and only registers the row here. Keep the column list in sync
        with ledger/db.py (artifacts table).

        Requirements: SWR-013(工件登记) / DSR-036(同代登记)
        """
        hasher = hashlib.sha256()
        hasher.update(content)
        artifact_id = f"art-{uuid.uuid4().hex[:12]}"
        self.artifacts.conn.execute(
            """
            INSERT INTO artifacts (artifact_id, run_id, kind, relative_path, sha256, size_bytes, generation)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (artifact_id, self.run_id, kind, rel_path, hasher.hexdigest(), len(content), generation_id),
        )

    # ------------------------------------------------------------ renderers
    @staticmethod
    def _collect_unpaired_half_chains(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Reconcile the CURRENT unconnected half-chains from the event ledger.

        ``unpaired_half_chain`` events mark records that were unpaired at the
        time they were recorded; a record that a LATER submission paired
        carries a ``connector_paired`` event and is excluded here, so the
        rendered section always reflects the run's final pairing state.

        Requirements: SWR-005(半链对账) / DSR-058(未配对渲染)
        """
        paired_ids = {
            str(e.get("payload", {}).get("frontier_id") or "")
            for e in events
            if e.get("event_type") == "connector_paired"
        } | {
            str(e.get("payload", {}).get("probe_id") or "")
            for e in events
            if e.get("event_type") == "connector_paired"
        }
        paired_ids.discard("")
        unpaired: List[Dict[str, Any]] = []
        for e in events:
            if e.get("event_type") != "unpaired_half_chain":
                continue
            payload = e.get("payload", {}) or {}
            if str(payload.get("record_id") or "") in paired_ids:
                continue
            unpaired.append(payload)
        return unpaired

    def _render_main_report(
        self,
        findings: List[Dict[str, Any]],
        coverage_summary: Dict[str, Any],
        generation_id: str,
        half_chains: Optional[List[Dict[str, Any]]] = None,
    ) -> str:
        """Render REPORT.md: summary table, per-finding details, limitations.

        Requirements: SWR-010(逐字段呈现), SWR-012(主报告) / DSR-035(溯源呈现), DSR-069(风险声明)
        """
        t = self._lang.t
        confirmed = [f for f in findings if f.get("verdict") == "confirmed"]
        needs_val = [f for f in findings if f.get("verdict") == "needs_validation"]
        unverified = [f for f in findings if f.get("verdict") == "unverified"]

        # Sort confirmed by urgency P0 -> P1 -> P2 -> P3
        def urgency_key(f: Dict[str, Any]) -> int:
            """Sort key: confirmed findings by final urgency P0..P3.

            Requirements: SWR-011(紧迫度排序) / DSR-028(重算呈现)+(support)
            """
            _rating = f.get("rating")
            urg = _rating.get("final_urgency", "P3") if isinstance(_rating, dict) else "P3"
            return URGENCY_ORDER.index(urg) if urg in URGENCY_ORDER else -1

        sorted_confirmed = sorted(confirmed, key=urgency_key, reverse=True)

        lines = [
            t("report_title"),
            "",
            f"- **{t('run_id')}**: `{self.run_id}`",
            f"- **{t('snapshot_id')}**: `{self.snapshot_id}`",
            f"- **{t('status')}**: `{self._state_label()}`",
            f"- **{t('generation')}**: `{generation_id}`",
            f"- **{t('confirmed_findings')}**: {len(confirmed)}",
            f"- **{t('needs_validation')}**: {len(needs_val)}",
            f"- **{t('unverified_count')}**: {len(unverified)}",
        ]
        if half_chains:
            lines.append(f"- **{t('half_chain_section').strip('# ').strip()}**: {len(half_chains)}")
        if self._lang.fallback_applied:
            lines.append(self._lang.fallback_note)
        lines.append(t("findings_summary"))
        lines.append("")
        lines.append(f"| {t('col_id')} | {t('col_urgency')} | {t('col_severity')} | {t('col_issue')} | {t('col_title')} | {t('col_location')} |")
        lines.append("|---|---|---|---|---|---|")

        if not sorted_confirmed:
            lines.append(f"| — | — | — | — | {t('no_confirmed')} | — |")
        else:
            for f in sorted_confirmed:
                fid = f.get("finding_id")
                _rating = f.get("rating")
                urg = _rating.get("final_urgency", "P3") if isinstance(_rating, dict) else "P3"
                sev = _rating.get("final_severity", "Info") if isinstance(_rating, dict) else "Info"
                issue = f.get("issue", "general")
                title = f.get("title", "")
                sink = f.get("sink", {})
                loc = f"`{sink.get('path', '?')}:{sink.get('line', '?')}`"
                lines.append(f"| {fid} | **{urg}** | {sev} | `{issue}` | {title} | {loc} |")

        lines.append(t("detailed_findings"))
        lines.append("")
        for f in sorted_confirmed:
            fid = f.get("finding_id")
            _rating = f.get("rating")
            urg = _rating.get("final_urgency", "P3") if isinstance(_rating, dict) else "P3"
            sev = _rating.get("final_severity", "Info") if isinstance(_rating, dict) else "Info"
            title = f.get("title", "")
            source = f.get("source", {})
            sink = f.get("sink", {})
            steps = f.get("steps", [])
            remediation = f.get("remediation", {})

            lines.append(f"### {fid} [{urg}] {title}")
            lines.append("")
            lines.append(f"- **{t('verdict')}**: `{f.get('verdict')}` | **{t('evidence_level')}**: `{f.get('evidence_level')}` | **{t('severity')}**: `{sev}`")
            lines.append(f"- **Source**: `{source.get('path')}:{source.get('line')}` ({source.get('kind', 'input')})")
            lines.append(f"- **Sink**: `{sink.get('path')}:{sink.get('line')}` ({sink.get('kind', 'sensitive_op')})")
            lines.append(t("taint_path"))
            for idx, s in enumerate(steps, start=1):
                # Real worker shapes (RUN-LESSONS real-shape family): steps
                # arrive as {path, line, role, note} objects OR as the
                # contract's literal "path:LINE explanation" strings. Render
                # either honestly -- a report must never crash on a recorded
                # evidence shape (SR-025: records are rendered as recorded).
                if isinstance(s, dict):
                    lines.append(f"  {idx}. `{s.get('path')}:{s.get('line')}` - [{s.get('role')}] {s.get('note')}")
                else:
                    lines.append(f"  {idx}. {s}")

            # SR-010 / SWR-010: guards, attack preconditions, impact and
            # exploitability belong to the confirmed-finding presentation.
            # Each is rendered on its own labelled line so every acceptance
            # field traces back to its record; a missing value is stated as
            # such, never invented.
            guards = f.get("guards", []) or []
            lines.append(f"- **{t('guards')}**:")
            if guards:
                for g in guards:
                    lines.append(
                        f"  - `{g.get('guard_id', '')}` [{g.get('status', 'unknown')}] "
                        f"{g.get('mechanism', '')} "
                        f"(applicability: {g.get('applicability', 'N/A')})"
                    )
            else:
                lines.append(f"  - {t('guards_none')}")
            lines.append(f"- **{t('attacker')}**: `{f.get('attacker', 'unknown')}`")
            preconds = f.get("preconditions", []) or []
            if preconds:
                for p in preconds:
                    lines.append(f"- **{t('preconditions')}**: {p}")
            else:
                lines.append(f"- **{t('preconditions')}**: {t('preconditions_none')}")
            rating = f.get("rating", {}) or {}
            factors = rating.get("factor_reasons", {}) or {}
            lines.append(
                f"- **{t('impact')}**: {rating.get('impact', 'N/A')} — "
                f"{factors.get('impact_why', 'N/A')}"
            )
            lines.append(
                f"- **{t('exploitability')}**: {rating.get('exploitability', 'N/A')} — "
                f"{factors.get('exploitability_why', 'N/A')}"
            )

            lines.append("")
            lines.append(f"{t('remediation')}: {remediation.get('change', 'N/A')}")
            lines.append(f"{t('regression_test')}: {remediation.get('regression_test', 'N/A')}")
            lines.append("")

        lines.append(t("limitations"))
        lines.append("")
        lines.append(t("limitation_static"))
        lines.append(t("limitation_env"))
        # DSR-069 / SWR-010: explicit unrecognized-secret risk clause.
        lines.append(t("limitation_secrets"))

        return "\n".join(lines)

    def _state_label(self) -> str:
        """Render the terminal-state label in the resolved report language.

        Requirements: SWR-012(终态呈现) / DSR-068(状态本地化)
        """
        label = self._lang.state(self.run_state)
        return f"{label} (`{self.run_state}`)"

    def _render_needs_validation(
        self,
        findings: List[Dict[str, Any]],
        generation_id: str,
        half_chains: Optional[List[Dict[str, Any]]] = None,
        unverified_candidates: Optional[List[Dict[str, Any]]] = None,
    ) -> str:
        """Render the pending-work report (DSR-066 / SR-005 / SR-007).

        - Pending items: verdicts ``needs_validation`` AND ``unverified``
          (DSR-066: candidates whose verification never completed stay visible).
        - Unconnected half-chains (frontier / dangling sink) that remained
          unpaired after run-level aggregation (DSR-058 / SR-005).
        - Unverified candidates with their reason, at candidate granularity.

        Requirements: SWR-012(未决渲染) / DSR-066(未验证保留), DSR-058(半链呈现)
        """
        t = self._lang.t
        needs_val = [
            f for f in findings if f.get("verdict") in ("needs_validation", "unverified")
        ]
        half_chains = half_chains or []
        unverified_candidates = unverified_candidates or []

        lines = [
            t("needs_val_title"),
            f"{t('run_id')}: `{self.run_id}` | {t('generation')}: `{generation_id}` | {t('total_items')}: {len(needs_val)}",
            "",
        ]

        if not needs_val:
            lines.append(t("no_needs_val"))
        for f in needs_val:
            fid = f.get("finding_id")
            _rating = f.get("rating")
            prio = _rating.get("validation_priority", "V2") if isinstance(_rating, dict) else "V2"
            title = f.get("title", "")
            blockers = f.get("blockers", [])
            plan = f.get("validation_plan", "")

            lines.append(f"### {fid} [{t('priority')}: {prio}] {title}")
            if f.get("verdict") == "unverified":
                lines.append(f"- {t('unverified_reason_label')} {f.get('unverified_reason', '')}")
                if f.get("verify_task_id"):
                    lines.append(
                        f"- {t('verify_task_state')}: `{f.get('verify_task_id')}` "
                        f"({f.get('verify_task_state', 'unknown')})"
                    )
                source = f.get("source", {}) or {}
                sink = f.get("sink", {}) or {}
                if source.get("path") or sink.get("path"):
                    lines.append(
                        f"- Source: `{source.get('path', '?')}:{source.get('line', '?')}` -> "
                        f"Sink: `{sink.get('path', '?')}:{sink.get('line', '?')}`"
                    )
            if blockers:
                lines.append(f"- {t('blockers')}:")
                for b in blockers:
                    lines.append(f"  - {b}")
            if plan:
                lines.append(f"- {t('validation_plan')}: {plan}")
            lines.append("")

        # --- Unconnected half-chains (SR-005 / DSR-058) ---------------------
        lines.append(t("half_chain_section"))
        lines.append("")
        lines.append(t("half_chain_note"))
        lines.append("")
        if not half_chains:
            lines.append(t("half_chain_none"))
        else:
            lines.append(
                f"| {t('col_record_kind')} | {t('col_record_id')} | {t('col_boundary')} "
                f"| {t('col_symbol')} | {t('col_source_task')} |"
            )
            lines.append("|---|---|---|---|---|")
            for hc in half_chains:
                lines.append(
                    f"| `{hc.get('record_kind', '')}` | `{hc.get('record_id', '')}` "
                    f"| {hc.get('boundary', '')} | `{hc.get('symbol', '')}` "
                    f"| `{hc.get('source_task_id', '')}` |"
                )
        lines.append("")

        # --- Unverified candidates (DSR-066) --------------------------------
        lines.append(t("unverified_section"))
        lines.append("")
        if not unverified_candidates:
            lines.append(t("unverified_none"))
        else:
            for cand in unverified_candidates:
                cand_ids = ", ".join(cand.get("candidate_refs", []) or ["—"])
                lines.append(
                    f"### {cand.get('finding_id')} — candidate `{cand_ids}` "
                    f"[{t('verify_task_state')}: {cand.get('verify_task_state', 'unknown')}]"
                )
                lines.append(
                    f"- {t('unverified_reason_label')} {cand.get('unverified_reason', '')}"
                )
                source = cand.get("source", {}) or {}
                sink = cand.get("sink", {}) or {}
                if source.get("path") or sink.get("path"):
                    lines.append(
                        f"- Source: `{source.get('path', '?')}:{source.get('line', '?')}` -> "
                        f"Sink: `{sink.get('path', '?')}:{sink.get('line', '?')}`"
                    )
                lines.append("")
        return "\n".join(lines)

    def _render_coverage_md(self, coverage_summary: Dict[str, Any], generation_id: str) -> str:
        """Render COVERAGE.md with per-dimension coverage and unknown flags.

        Requirements: SWR-021(覆盖报告) / DSR-034(维度分层)
        """
        t = self._lang.t
        lines = [
            t("coverage_title"),
            "",
            f"- **{t('run_id')}**: `{self.run_id}`",
            f"- **{t('generation')}**: `{generation_id}`",
            f"- **{t('total_files')}**: {coverage_summary.get('total_files', 0)}",
            f"- **{t('inventoried_lines')}**: {coverage_summary.get('total_inventoried_lines', 0)}",
        ]
        if coverage_summary.get("unknown"):
            lines.append(
                f"- **unknown**: true ({coverage_summary.get('unknown_reason', 'coverage data unavailable')})"
            )
        lines.append(t("dim_coverage"))
        lines.append("")
        lines.append(f"| {t('col_dimension')} | {t('col_covered')} | {t('col_pct')} |")
        lines.append("|---|---|---|")
        pcts = coverage_summary.get("dimension_percentages", {})
        totals = coverage_summary.get("dimension_covered_lines", {})
        for dim, pct in pcts.items():
            lines.append(f"| `{dim}` | {totals.get(dim, 0)} | {pct}% |")

        return "\n".join(lines)

    def _render_coverage_csv(self, file_breakdown: List[Dict[str, Any]], generation_id: str) -> str:
        """Render the per-file coverage CSV carrying the generation marker.

        Requirements: SWR-021(逐文件覆盖) / DSR-034(CSV分层), DSR-036(代次标记)
        """
        output = io.StringIO()
        writer = csv.writer(output)
        # DSR-036: leading meta comment carries the generation id so staged
        # files can be verified before publish. CSV consumers should skip
        # leading lines beginning with '#'.
        writer.writerow([f"# generation_id: {generation_id}"])
        writer.writerow(["path", "language", "total_lines", "inventoried", "signal_scanned", "context_supplied", "observed_read", "review_claimed"])

        for f in file_breakdown:
            cov = f.get("coverage_lines", {})
            writer.writerow([
                f.get("path"),
                f.get("language"),
                f.get("total_lines"),
                cov.get("inventoried", 0),
                cov.get("signal_scanned", 0),
                cov.get("context_supplied", 0),
                cov.get("observed_read", 0),
                cov.get("review_claimed", 0),
            ])
        return output.getvalue()

    def _render_audit_trail(self, events: List[Dict[str, Any]], findings: List[Dict[str, Any]], generation_id: str) -> str:
        """Render AUDIT-TRAIL.md: event timeline plus finding provenance.

        Requirements: SWR-013(轨迹可追溯) / DSR-035(溯源映射)
        """
        t = self._lang.t
        lines = [
            t("trail_title"),
            f"{t('run_id')}: `{self.run_id}` | {t('generation')}: `{generation_id}` | {t('total_events')}: {len(events)}",
            t("timeline"),
            "",
            f"| {t('col_rev')} | {t('col_time')} | {t('col_actor')} | {t('col_event')} |",
            "|---|---|---|---|",
        ]
        for e in events:
            lines.append(f"| {e.get('revision')} | {e.get('occurred_at')} | {e.get('actor')} | `{e.get('event_type')}` |")

        # DSR-035 / SWR-013: every finding must be traceable to its producing
        # hunt/verify tasks and candidate/attempt anchors. All keys present in
        # the finding's provenance block are rendered verbatim.
        lines.append(t("provenance"))
        lines.append("")
        if not findings:
            lines.append("- —")
        for f in findings:
            prov = f.get("provenance", {}) or {}
            prov_parts = " | ".join(f"{k}: `{json.dumps(v, ensure_ascii=False)}`" for k, v in prov.items())
            lines.append(f"- **{f.get('finding_id')}**: {prov_parts}")

        return "\n".join(lines)

    def _render_cost_report(self, cost_metrics: Dict[str, Any], generation_id: str) -> str:
        """Render COST.md with explicit denominators and unavailable metrics.

        Requirements: SWR-020(成本报告) / DSR-067(不可计算标注)
        """
        t = self._lang.t
        non_computable = t("non_computable")
        tasks_per_kloc = cost_metrics.get("tasks_per_kloc")
        if tasks_per_kloc is None:
            tasks_per_kloc = f"{non_computable} ({cost_metrics.get('tasks_per_kloc_reason', 'denominator unavailable')})"
        elif cost_metrics.get("tasks_per_kloc_reason"):
            # O-03: every rate line states its denominator (executed tasks,
            # or the documented legacy enqueued fallback) so the report's
            # numbers stay recomputable by the reader.
            tasks_per_kloc = f"{tasks_per_kloc} ({cost_metrics['tasks_per_kloc_reason']})"

        # O-03: the enqueued plan scope and the work actually processed are
        # two different numbers and are rendered as two separate labelled
        # lines — a run that planned 4464 units but processed 7 must not be
        # able to present the plan as executed work.
        total_enqueued = cost_metrics.get(
            "total_enqueued", cost_metrics.get("total_tasks", 0)
        )
        total_executed = cost_metrics.get("total_executed")
        if total_executed is None:
            executed_line = (
                f"{total_enqueued} ({t('executed_not_recorded')})"
            )
        else:
            executed_line = str(total_executed)

        tasks_per_finding = cost_metrics.get("tasks_per_finding")
        if tasks_per_finding is None:
            tasks_per_finding = (
                f"{non_computable} ({cost_metrics.get('tasks_per_finding_reason', 'denominator unavailable')})"
            )
        elif cost_metrics.get("tasks_per_finding_reason"):
            tasks_per_finding = (
                f"{tasks_per_finding} ({cost_metrics['tasks_per_finding_reason']})"
            )

        lines = [
            t("cost_title"),
            "",
            f"- **{t('run_id')}**: `{self.run_id}`",
            f"- **{t('generation')}**: `{generation_id}`",
            f"- **{t('total_tasks')}**: {total_enqueued}",
            f"- **{t('total_tasks_executed')}**: {executed_line}",
            f"- **{t('retries')}**: {cost_metrics.get('retries', 0)}",
            f"- **{t('tasks_per_kloc')}**: {tasks_per_kloc}",
            f"- **{t('tasks_per_finding')}**: {tasks_per_finding}",
            f"- **{t('token_status')}**: {cost_metrics.get('token_availability')}",
        ]
        if cost_metrics.get("unavailable_reason"):
            lines.append(f"- **{t('unavailable_reason')}**: {cost_metrics.get('unavailable_reason')}")

        # DSR-067: cache hits and protocol overhead are surfaced explicitly;
        # missing host data is marked unavailable with its reason, never zero.
        lines.append(t("cache_section"))
        cache = cost_metrics.get("cache_hits") or {}
        if isinstance(cache, dict) and cache.get("value") is None:
            lines.append(f"- **{t('cache_hits')}**: {t('unavailable')} ({cache.get('reason', 'host data not supplied')})")
        else:
            lines.append(f"- **{t('cache_hits')}**: {cache.get('value') if isinstance(cache, dict) else cache}")
        overhead = cost_metrics.get("protocol_overhead") or {}
        if isinstance(overhead, dict) and overhead.get("value") is None:
            lines.append(f"- **{t('protocol_overhead')}**: {t('unavailable')} ({overhead.get('reason', 'host data not supplied')})")
        else:
            lines.append(f"- **{t('protocol_overhead')}**: {overhead.get('value') if isinstance(overhead, dict) else overhead}")

        lines.append(t("stage_breakdown"))
        lines.append("")
        lines.append(f"| {t('col_stage')} | {t('col_tasks')} |")
        lines.append("|---|---|")
        for stg, cnt in cost_metrics.get("stage_tasks", {}).items():
            lines.append(f"| `{stg}` | {cnt} |")

        return "\n".join(lines)

    def _render_skill_review_md(self, anomalies: List[Dict[str, Any]], generation_id: str) -> str:
        """Render the local SKILL-REVIEW.md (dossier-aware, always written).

        Requirements: SWR-014(本地自审) / DSR-044(三场景), DSR-070(异常呈现)
        """
        t = self._lang.t
        lines = [
            t("review_title"),
            "",
            f"- **{t('run_id')}**: `{self.run_id}`",
            f"- **{t('generation')}**: `{generation_id}`",
            f"- **{t('total_anomalies')}**: {len(anomalies)}",
            t("anomaly_list"),
        ]
        if not anomalies:
            lines.append(t("no_anomalies"))
        else:
            for a in anomalies:
                lines.append(
                    f"- **[{a.get('category')}]** {a.get('evidence')} "
                    f"({t('impact')}: {a.get('impact')}; {t('recommendation')}: {a.get('recommendation')})"
                )
                if a.get("unknown_note"):
                    lines.append(f"  - {t('unknown_note')}: {a.get('unknown_note')}")
        lines.append("")
        lines.append(t("local_dossier_note"))
        return "\n".join(lines)

    # ------------------------------------------------- portable export (opt-in)
    def _build_portable_skill_review(
        self,
        anomalies: List[Dict[str, Any]],
        coverage_summary: Dict[str, Any],
        cost_metrics: Dict[str, Any],
        findings: List[Dict[str, Any]],
        generation_id: str,
    ) -> Dict[str, Any]:
        """Build the opt-in portable skill-review export (whitelist-only).

        Requirements: SWR-016(白名单导出) / DSR-045(仅枚举统计), DSR-071(允许列表)
        """
        portable_export = {
            "schema_version": "1.0",
            "generation_id": generation_id,
            "run_id": self.run_id,
            "run_summary": {
                "run_state": self.run_state,
                "language": self._lang.language,
                "total_files_audited": coverage_summary.get("total_files", 0),
                "total_lines_audited": coverage_summary.get("total_inventoried_lines", 0),
                "total_confirmed_findings": len([f for f in findings if f.get("verdict") == "confirmed"]),
                "total_needs_validation": len([f for f in findings if f.get("verdict") == "needs_validation"]),
                "total_tasks_executed": cost_metrics.get(
                    "total_executed", cost_metrics.get("total_tasks", 0)
                ),
                "retries": cost_metrics.get("retries", 0),
            },
            "anomaly_categories": [a.get("category", "GENERAL") for a in anomalies],
        }
        self._enforce_export_whitelist(portable_export)
        return portable_export

    @staticmethod
    def _enforce_export_whitelist(export: Dict[str, Any]) -> None:
        """DSR-045 / SWR-016: reject any non-whitelisted key before export.

        Requirements: SWR-016(非白名单拒绝) / DSR-045(失败关闭), DSR-071(受控导出)
        """
        for key, value in export.items():
            if key not in SKILL_REVIEW_EXPORT_ALLOWED_ROOT_KEYS:
                raise InvalidInputError(
                    f"skill-review export rejected: non-whitelisted root key '{key}'",
                    details={"key": key},
                )
            if key == "run_summary":
                if not isinstance(value, dict):
                    raise InvalidInputError("skill-review export rejected: run_summary must be an object")
                for sub_key, sub_value in value.items():
                    if sub_key not in SKILL_REVIEW_EXPORT_ALLOWED_RUN_SUMMARY_KEYS:
                        raise InvalidInputError(
                            f"skill-review export rejected: non-whitelisted run_summary key '{sub_key}'",
                            details={"key": sub_key},
                        )
                    if sub_value is not None and not isinstance(sub_value, SKILL_REVIEW_EXPORT_SCALAR_TYPES):
                        raise InvalidInputError(
                            f"skill-review export rejected: run_summary '{sub_key}' is not a scalar",
                            details={"key": sub_key, "type": type(sub_value).__name__},
                        )
            elif key == "anomaly_categories":
                if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
                    raise InvalidInputError("skill-review export rejected: anomaly_categories must be a list of strings")
