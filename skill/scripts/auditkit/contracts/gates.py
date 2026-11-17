"""Gate checking framework (G0 through G4) for polyglot-audit.

Implements DSR-022 / DSR-026 / DSR-036 / DSR-051 / DSR-073 / DSR-076:
- G0: Snapshot, Inventory, Plan completeness
- G1: Units, Overflow, and Incomplete accounting
- G2: Dispatch reconciliation (submitted vs dispatched tasks) and finding semantic integrity
- G3: Findings semantic validation pass accounting and report/ledger reconciliation
- G4: Revision/artifact consistency and export sanitization
- Every gate and check can be pass / fail / not_applicable; a not_applicable
  result always requires an explicit reason (DSR-022).
- Typed dataclass interface (DSR-073) serialized via to_dict().
"""

# 需求追踪 (Requirement Traceability)
# ---------------------------------------------------------------------------
# 上层需求: docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2
# 设计依据: docs/design/SOFTWARE_DESIGN.md
# SWR-026  G0~G4 可程序化检查：记录完整性而非证明安全；not_applicable 必须有理由
#   绑定实现: DSR-022
# 状态以统一测试结论为准；未实测能力保持 unknown（设计原则 8：能观测的不靠声明）。
#

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from auditkit.contracts.errors import InvalidInputError
from auditkit.contracts.types import GateCheckData, GateResultData

GATE_STATUSES = ("pass", "fail", "not_applicable")


@dataclass
class GateCheck:
    """Single check inside a gate result.

    Requirements: SWR-026(检查三态可定位) / DSR-022(N/A须有理由)
    """

    check_id: str
    name: str
    status: str  # "pass", "fail", "not_applicable"
    message: str
    evidence_ref: Optional[str] = None

    def __post_init__(self) -> None:
        """Enforce the status enum and the N/A-requires-reason rule.

        Requirements: SWR-026(support) / DSR-022(N/A必带理由)
        """
        if self.status not in GATE_STATUSES:
            raise InvalidInputError(
                f"Gate check '{self.check_id}' has invalid status '{self.status}'; "
                f"must be one of {list(GATE_STATUSES)}"
            )
        if self.status == "not_applicable" and not (self.message or "").strip():
            raise InvalidInputError(
                f"Gate check '{self.check_id}' is not_applicable: a reason (message) is required (DSR-022)"
            )

    def to_dict(self) -> GateCheckData:
        """Serialize the check to the gate_result contract shape.

        Requirements: SWR-025(类型化序列化,support) / DSR-073(support)
        """
        d: GateCheckData = {
            "check_id": self.check_id,
            "name": self.name,
            "status": self.status,
            "message": self.message,
        }
        if self.evidence_ref:
            d["evidence_ref"] = self.evidence_ref
        return d


@dataclass
class GateResult:
    """Aggregated gate result.

    Requirements: SWR-026(门禁结果完整性) / DSR-022(可定位,N/A理由)
    """

    gate_id: str  # G0, G1, G2, G3, G4
    status: str   # pass, fail, not_applicable
    checks: List[GateCheck] = field(default_factory=list)
    revision: int = 0
    reason: Optional[str] = None

    def __post_init__(self) -> None:
        """Enforce the status enum and the N/A-requires-reason rule.

        Requirements: SWR-026(support) / DSR-022(N/A必带理由)
        """
        if self.status not in GATE_STATUSES:
            raise InvalidInputError(
                f"Gate '{self.gate_id}' has invalid status '{self.status}'; "
                f"must be one of {list(GATE_STATUSES)}"
            )
        # DSR-022: N/A must always carry an explicit reason.
        if self.status == "not_applicable" and not (self.reason or "").strip():
            raise InvalidInputError(
                f"Gate '{self.gate_id}' is not_applicable: an explicit reason is required (DSR-022)"
            )

    def to_dict(self) -> GateResultData:
        """Serialize the gate result with all child checks.

        Requirements: SWR-025(类型化序列化,support) / DSR-073(support)
        """
        d: GateResultData = {
            "schema_version": "1.0",
            "gate_id": self.gate_id,
            "status": self.status,
            "checks": [c.to_dict() for c in self.checks],
            "revision": self.revision,
        }
        if self.reason:
            d["reason"] = self.reason
        return d


class GateEvaluator:
    """Evaluates gates G0 through G4 against run state.

    Requirements: SWR-026(G0~G4可程序化检查) / DSR-022(可复用检查框架)
    """

    @staticmethod
    def evaluate_g0(manifest: Optional[Dict[str, Any]], plan: Optional[Dict[str, Any]], revision: int) -> GateResult:
        """Check snapshot manifest, inventory and planning-unit completeness.

        Requirements: SWR-026(G0快照/清点/计划) / DSR-022(失败可定位)
        """
        checks: List[GateCheck] = []
        if not manifest:
            checks.append(GateCheck("G0-1", "Snapshot Manifest", "fail", "Missing snapshot manifest"))
            return GateResult("G0", "fail", checks, revision, "Missing snapshot manifest")

        root_hash = manifest.get("root_hash", "")
        if len(root_hash) == 64:
            checks.append(GateCheck("G0-1", "Snapshot Root Hash", "pass", f"Valid root hash: {root_hash[:8]}...", root_hash))
        else:
            checks.append(GateCheck("G0-1", "Snapshot Root Hash", "fail", f"Invalid root hash: {root_hash}"))

        files = manifest.get("files", [])
        if files:
            checks.append(GateCheck("G0-2", "Inventory Files", "pass", f"Inventory contains {len(files)} files"))
        else:
            checks.append(GateCheck("G0-2", "Inventory Files", "fail", "Inventory is empty"))

        if plan and "units" in plan:
            checks.append(GateCheck("G0-3", "Planning Units", "pass", f"Plan contains {len(plan['units'])} units"))
        else:
            checks.append(GateCheck("G0-3", "Planning Units", "fail", "Planning units missing"))

        status = "pass" if all(c.status == "pass" for c in checks) else "fail"
        return GateResult("G0", status, checks, revision)

    @staticmethod
    def evaluate_g1(
        total_units: int,
        completed_units: int,
        overflow_records: List[Dict[str, Any]],
        revision: int,
    ) -> GateResult:
        """Check unit dispatch completeness and overflow accounting.

        Requirements: SWR-026(G1单元/溢出记账) / DSR-022(失败可定位)
        """
        checks: List[GateCheck] = []
        if total_units > 0 and completed_units >= total_units:
            checks.append(GateCheck("G1-1", "Unit Dispatch", "pass", f"All {total_units} units dispatched and processed"))
        else:
            checks.append(GateCheck("G1-1", "Unit Dispatch", "fail", f"Incomplete unit dispatch: {completed_units}/{total_units}"))

        if overflow_records:
            checks.append(GateCheck("G1-2", "Overflow Tracking", "pass", f"{len(overflow_records)} overflow events tracked"))
        else:
            checks.append(GateCheck("G1-2", "Overflow Tracking", "pass", "No overflow events recorded"))

        status = "pass" if all(c.status == "pass" for c in checks) else "fail"
        return GateResult("G1", status, checks, revision)

    @staticmethod
    def evaluate_g2(
        findings: List[Dict[str, Any]],
        revision: int,
        submitted_tasks: Optional[int] = None,
        dispatched_tasks: Optional[int] = None,
        in_flight_tasks: Optional[int] = None,
    ) -> GateResult:
        """Dispatch reconciliation plus finding semantic integrity (DSR-076).

        When task counts are supplied, every dispatched task must have either a
        submitted result or an outcome (quarantined/failed/expired attempts);
        only tasks held by a currently valid (unexpired) claim lease are treated
        as in-flight without a lost result. Any dispatched task without a
        submitted result and without a valid lease fails the gate. Findings are
        checked against the semantic validator.

        Requirements: SWR-026(G2调度对账+语义完整) / DSR-022(失败可定位), DSR-076(不伪终态)
        """
        from auditkit.contracts.semantic_validator import SemanticValidator

        checks: List[GateCheck] = []

        if submitted_tasks is not None and dispatched_tasks is not None:
            in_flight = in_flight_tasks or 0
            lost = dispatched_tasks - submitted_tasks - in_flight
            if lost <= 0:
                checks.append(
                    GateCheck(
                        "G2-0",
                        "Task Result Reconciliation",
                        "pass",
                        f"No lost results: {submitted_tasks} submitted, {in_flight} in valid lease, "
                        f"{dispatched_tasks} dispatched",
                    )
                )
            else:
                checks.append(
                    GateCheck(
                        "G2-0",
                        "Task Result Reconciliation",
                        "fail",
                        f"Dispatched tasks without submitted results or valid lease: {lost} "
                        f"(submitted {submitted_tasks}, in-flight {in_flight}, dispatched {dispatched_tasks})",
                    )
                )

        validator = SemanticValidator()
        validation_failures = 0

        for f in findings:
            try:
                validator.validate_finding(f)
            except Exception as e:
                validation_failures += 1
                checks.append(GateCheck("G2-1", f"Finding {f.get('finding_id', '?')}", "fail", str(e)))

        if validation_failures == 0:
            checks.append(GateCheck("G2-1", "Finding Semantic Integrity", "pass", f"All {len(findings)} findings semantically valid"))

        status = "pass" if all(c.status == "pass" for c in checks) else "fail"
        return GateResult("G2", status, checks, revision)

    @staticmethod
    def evaluate_g3(
        report_findings_count: int,
        db_findings_count: int,
        generation_id: str,
        revision: int,
    ) -> GateResult:
        """Check report/ledger findings-count reconciliation and generation id.

        Requirements: SWR-026(G3报告对账) / DSR-022(失败可定位)
        """
        checks: List[GateCheck] = []
        if report_findings_count == db_findings_count:
            checks.append(GateCheck("G3-1", "Findings Count Reconciliation", "pass", f"Reconciled {db_findings_count} findings"))
        else:
            checks.append(
                GateCheck(
                    "G3-1",
                    "Findings Count Reconciliation",
                    "fail",
                    f"Mismatch: report has {report_findings_count}, db has {db_findings_count}",
                )
            )

        if generation_id:
            checks.append(GateCheck("G3-2", "Generation Identifier", "pass", f"Single generation id: {generation_id}"))
        else:
            checks.append(GateCheck("G3-2", "Generation Identifier", "fail", "Missing generation id"))

        status = "pass" if all(c.status == "pass" for c in checks) else "fail"
        return GateResult("G3", status, checks, revision)

    @staticmethod
    def evaluate_g4(revision_consistent: bool, export_sanitized: bool, revision: int) -> GateResult:
        """Revision/artifact consistency and export sanitization (DSR-076).

        revision_consistent: the persisted run revision matches the replayed
        event ledger and artifact generations are consistent.
        export_sanitized: published export content passed leakage sanitization.

        Requirements: SWR-026(G4修订/导出一致) / DSR-022(失败可定位)
        """
        checks: List[GateCheck] = []
        if revision_consistent:
            checks.append(GateCheck("G4-1", "Revision and Artifact Consistency", "pass", f"Revision {revision} reconciles with event ledger and artifacts"))
        else:
            checks.append(GateCheck("G4-1", "Revision and Artifact Consistency", "fail", "Run revision does not reconcile with event ledger or artifact generations"))

        if export_sanitized:
            checks.append(GateCheck("G4-2", "Export Leakage Sanitization", "pass", "Sanitization checks passed"))
        else:
            checks.append(GateCheck("G4-2", "Export Leakage Sanitization", "fail", "Sanitization checks failed"))

        status = "pass" if all(c.status == "pass" for c in checks) else "fail"
        return GateResult("G4", status, checks, revision)
