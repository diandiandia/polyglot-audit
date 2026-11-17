"""Application service coordinating the complete audit lifecycle.

Implements IFC-03 / DDS-01 / DDS-03 / DDS-04 / SWR-001 / SWR-022 / SWR-026:
- Implements: doctor, prepare, activate, next, start, submit, status, pause, resume, finalize, report.
- Strictly single entry point for all state mutations.
- Enforces G0..G4 gates during progression.
- Preserves transactional consistency and atomic publishing.

Cross-domain wiring owned here (ANA/LED, SNP/INT, HST/LED):
- prepare dispatches one recon task per run (DDS-05 S1 / DSR-024 / SR-006)
  before every hunt task; its spec carries the snapshot id, the primary
  language index and knowledge catalog clues;
- next() serves every claim with a real prompt packet published at
  tasks/{task_id}/packet.json (DSR-025/059 / IFC-02); render failures release
  the claim fail-closed with events, capacity overflow is recorded;
- recon submissions persist the guard baseline (guard_baseline event +
  tasks/{task_id}/result.json artifact); hunt packets built afterwards carry
  the guard summary; with no recon worker no baseline is fabricated;
- hunt submissions deduplicate candidates (DSR-063: exact duplicates merged
  with confirmed_by="pipeline:exact-duplicate", distinct-source duplicates
  only suggested) and enqueue verify-kind tasks (Verifier with
  enforce_attempt_gate=True); connector evaluations run a full
  reserve -> settle budget lifecycle;
- verified High/Critical findings enqueue an independent second-opinion
  verify task (DSR-061); its submission adjudicates the finding (conflict
  demotes to needs_validation with both sides preserved); a pending second
  opinion is recorded and forces an incomplete run;
- hunt submissions persist EVERY frontier and sink probe as ledger events
  (SR-005/007/DSR-026/058) BEFORE connection; the connector evaluates the
  run-level PENDING half-chain set (history + this submission, already-paired
  records excluded via connector_paired events), so task A's frontier can pair
  with task B's probe; records still unpaired after aggregation are marked
  unpaired_half_chain and rendered into NEEDS-VALIDATION;
- verify submissions are stamped with the current run_id and merged at
  finalize (adjudicated findings override verified ones), making the semantic
  validator's cross-run check real; every confirmed finding additionally runs
  the DSR-062 bounded variant search against the frozen snapshot before it is
  persisted (bounded read, bounded result list, honest truncation accounting,
  variants marked requires_independent_verification);
- every task spec is validated against the task_spec contract at its enqueue
  point (DSR-073); invalid specs are rejected with InvalidInputError and never
  enqueued;
- finalize blocks on in-flight claim leases (InvalidStateError), enforces the
  plan-coverage invariant via the unprocessed_units hard rule, synthesizes
  unverified entries for candidates whose verify task never completed
  (DSR-066), and feeds the report stage with real self-review inputs
  (SR-014 / DSR-070); it aggregates usage_records and ledger retries into cost
  telemetry (SR-020 / DSR-067), reads report_language from the run config
  (SR-012), and evaluates G4 AFTER the reports are published, against the
  published artifacts (user-confirmed ordering fix);
- the run dossier follows the design §10.1 directory layout: prepare
  publishes the immutable run metadata (run.json: target, snapshot, skill
  version + payload digest, dossier version, frozen config, profile,
  budgets), the plan (plan/plan.json) and the inventory summary
  (inventory/summary.json); every accepted worker result is persisted at
  tasks/{task_id}/result.json (all three task kinds), schema rejections
  publish tasks/{task_id}/validation.json (DSR-018 validation log) and
  trusted usage objects land at tasks/{task_id}/usage.json; recon
  submissions additionally publish the guard baseline summary at
  recon/recon-result.json; finalize publishes the deduplicated
  representative candidate pool (candidates/final.json) and, per finding,
  the full record plus its status-transition history
  (findings/<finding_id>/{record,history}.json). All read points prefer the
  §10.1 layout and fall back read-only to the legacy flat files (plan.json
  at the run root); old dossiers are never migrated in place (DSR-072);
- prepare detects JVM build evidence in the snapshot (SR-003 / SD-02) and
  threads the three-state platform result into both platform-conditional
  catalog call sites (recon enqueue and hunt packet rendering); without
  evidence Kotlin/Scala targets do NOT inherit the Java base index and the
  packet discloses the unknown platform;
- prepare identifies build components from build manifests (DSR-055) right
  after collection: every file is assigned its nearest enclosing
  build-manifest root (inventory/components.py, shared manifest discovery
  with the JVM evidence scan per DA-03); components land in the frozen
  manifest.json and drive reconciliation by_component and every sliced unit;
- run_dispatch_loop drives tasks with real parallel dispatch: each task is
  claimed immediately before its own execution (no batch pre-claiming), the
  in-flight cap follows the AIMD ConcurrencyController's current value on a
  thread pool, ledger mutations are lock-serialized, and adapter retry/backoff
  parameters, trusted usage objects, and TerminationUncertainError budget
  retention are preserved; pause returns the in-flight attempt contract and
  resume verifies version/artifact/snapshot integrity before a paused run may
  continue (IFC-06).
"""

# 需求追踪 (Requirement Traceability)
# ---------------------------------------------------------------------------
# 上层需求: docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2
# 设计依据: docs/design/SOFTWARE_DESIGN.md
# SWR-001  audit 流程：显式范围与预算、安全确认；预算与降级不用静默默认值
#   绑定实现: DSR-032, DSR-053
# SWR-012  终态渲染与对账：complete 只表示流程完整不表示安全；中断输出不完整报告
#   绑定实现: DSR-036, DSR-076
# SWR-018  claim 协议、预算记账、恢复校验快照与已发布产物
#   绑定实现: DSR-017, DSR-019
# SWR-026  G0~G4 门禁与 incomplete 分支：corrupt 不得伪造成 complete
#   绑定实现: DSR-022, DSR-051, DSR-076
# SWR-027  版本兼容检查接入所有打开点
#   绑定实现: DSR-072
# 状态以统一测试结论为准；未实测能力保持 unknown（设计原则 8：能观测的不靠声明）。
#

from __future__ import annotations
import concurrent.futures
import hashlib
import json
import os
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from auditkit.analysis.connector import HypothesisConnector
from auditkit.analysis.dedup import CandidateDeduplicator, compute_fingerprint
from auditkit.analysis.guards import VALID_GUARD_STATUSES, GuardManager, GuardRecord
from auditkit.analysis.hunter import HuntResultParser
from auditkit.analysis.packets import PacketBuilder
from auditkit.analysis.triage import StrongSignalTriage
from auditkit.analysis.verifier import (
    SECOND_OPINION_SEVERITIES,
    Verifier,
    bounded_variant_search,
)
import re
from auditkit.contracts.errors import (
    AuditError,
    CorruptRunError,
    GateFailedError,
    HostFailureError,
    InvalidInputError,
    InvalidStateError,
    StaleAttemptError,
    StorageError,
)
from auditkit.contracts.gates import GateEvaluator
from auditkit.contracts.schema_validator import SchemaValidator
from auditkit.contracts.semantic_validator import SemanticValidator
from auditkit.hosts.capabilities import Capability
from auditkit.hosts.concurrency import ConcurrencyController
from auditkit.hosts.doctor import Doctor
from auditkit.hosts.errors import TerminationUncertainError
from auditkit.hosts.retry import compute_backoff_delay
from auditkit.inventory.boundaries import BoundaryScanner
from auditkit.inventory.components import (
    DEFAULT_COMPONENT,
    component_roots,
    detect_components,
    find_build_manifest_paths,
)
from auditkit.inventory.languages import detect_language
from auditkit.inventory.reconcile import reconcile as reconcile_inventory
from auditkit.inventory.rules import ExclusionRules
from auditkit.inventory.signals import SignalScanner, scan_snapshot_files
from auditkit.inventory.slicer import UnitPlanner
from auditkit.knowledge.catalog import KnowledgeCatalog
from auditkit.ledger.artifacts import ArtifactManager
from auditkit.ledger.budget import BudgetLedger
from auditkit.ledger.db import check_version_compatibility, get_db_connection, init_database
from auditkit.ledger.event_store import EventStore, utc_now_iso
from auditkit.ledger.task_queue import DISPATCHED_TASK_STATES, TaskQueue, sha256_text
from auditkit.reporting.cost import CostTracker
from auditkit.reporting.coverage import CoverageCalculator
from auditkit.reporting.generator import ReportGenerator
from auditkit.reporting.secret_masker import mask_secrets
from auditkit.snapshot.collector import SnapshotCollector
from auditkit.snapshot.manifest import compute_root_hash
from auditkit.snapshot.paths import validate_three_roots


# --- Cross-domain wiring constants (ANA -> LED, SNP -> INT, HST -> LED) ----
# Dispatch priority ordering (lower numeric value dispatched later): the recon
# baseline runs first (DDS-05 S1), then independent second opinions (DSR-061),
# then normal verify work, then T1 hunts (20) and the remaining hunts (10).
RECON_TASK_PRIORITY = 40
SECOND_OPINION_TASK_PRIORITY = 35
VERIFY_TASK_PRIORITY = 30
# Recon is one task per run, dispatched before any hunt task (DSR-024/SR-006).
RECON_TASK_KEY = "recon:baseline"
# Recon packet sampling cap: ranges copied into the recon unit before the
# PacketBuilder capacity semantics take over (overflow recorded, never silent).
RECON_UNIT_MAX_RANGES = 8
# Second-opinion task keys carry an explicit marker (DSR-061).
SECOND_OPINION_TASK_KEY_PREFIX = "verify:second-opinion:"
# Connector evaluation budget dimension and upper estimate cap (ANA -> LED).
CONNECTOR_BUDGET_DIMENSION = "connector_evaluations"
CONNECTOR_EVALUATION_CAP = 200
# Strong-signal triage thresholds (ANA -> INT).
TRIAGE_STRONG_KINDS = ("source", "sink")
TRIAGE_STRONG_MIN_STRENGTH = 3
TRIAGE_MAX_RECORDS = 50
# Event types that account for coverage blind spots and capped work. They are
# surfaced through finalize's coverage_gaps; only "coverage_gap" (lost or
# quarantined dispatched work) forces an incomplete terminal state, keeping
# the existing stop-sequence contract unchanged.
GAP_EVENT_TYPES = ("coverage_gap", "analysis_gap", "snapshot_gap")
OVERFLOW_EVENT_TYPES = ("hunter_overflow", "signal_overflow", "packet_overflow")
CONNECTOR_RECORD_EVENT_TYPES = ("connector_unresolved", "connector_incompatible")
COVERAGE_ACCOUNTING_EVENT_TYPES = GAP_EVENT_TYPES + OVERFLOW_EVENT_TYPES + CONNECTOR_RECORD_EVENT_TYPES
# Host termination could not be confirmed: attempt budget stays reserved.
TERMINATION_UNCERTAIN_EVENT_TYPE = "attempt_termination_uncertain"
# Verified findings produced by verify-task submissions are persisted here.
FINDINGS_ARTIFACT_KIND = "verified_findings"
VERIFIED_FINDING_VERDICTS = ("confirmed", "needs_validation", "rejected", "unverified")
# DSR-062 wiring (ANA -> SNP/ANA): every confirmed finding runs the bounded
# variant search against the FROZEN snapshot before it is persisted. The read
# cap mirrors bounded_variant_search's own max_files bound so a large snapshot
# never enters memory whole and the variant list stays reviewable.
VARIANT_SEARCH_MAX_VARIANTS = 5
VARIANT_SEARCH_MAX_FILES = 20
# IFC-06: pause reasons are bounded so the ledger stays a ledger, not a log.
PAUSE_REASON_MAX_LENGTH = 256
# Error-family events counted by finalize's self-review input (DSR-070).
ERROR_EVENT_TYPES = (
    "attempt_failed_retriable",
    "attempt_expired",
    "attempt_released",
    "attempt_termination_uncertain",
    "coverage_gap",
    "packet_render_failed",
    "recon_invalid_record",
)
# Self-review flow accounting treats the report stage as executed work.
REPORT_STAGE_TASKS = 1
# O-03 (run lessons): the cost report separates the ENQUEUED plan scope from
# the work actually processed. These are the processed terminal task states
# (settled done, quarantined, failed) that form the executed denominator of
# the normalized cost rates; enqueued-but-never-dispatched tasks stay out of
# it and remain visible as the enqueued total.
EXECUTED_TASK_STATES = ("done", "failed", "quarantined")
# SR-012/SR-026/DSR-076: finalize enforces the plan-coverage invariant that
# DDS-06's G1/G2 formulas miss (zero-dispatch blind spot): planned work that
# was never dispatched, and recon/verify tasks that never reached a terminal
# or quarantine state, force the 'incomplete' terminal state.
UNPROCESSED_UNITS_REASON = "unprocessed_units"
# SR-005/SR-007/DSR-026/DSR-058: every frontier and sink probe of a hunt
# submission is persisted as an event BEFORE any connection attempt, so
# one-sided half-chains survive and can be paired later by another task's
# submission. connector_paired marks the records a connection consumed
# (idempotent re-connection guard); unpaired_half_chain records the records
# still unpaired after run-level aggregation.
FRONTIER_RECORDED_EVENT = "frontier_recorded"
SINK_PROBE_RECORDED_EVENT = "sink_probe_recorded"
CONNECTOR_PAIRED_EVENT = "connector_paired"
UNPAIRED_HALF_CHAIN_EVENT = "unpaired_half_chain"
HALF_CHAIN_EVENT_TYPES = (FRONTIER_RECORDED_EVENT, SINK_PROBE_RECORDED_EVENT)
# DSR-066: synthetic verdict stamped onto candidates whose verify task never
# completed before finalize; they surface in NEEDS-VALIDATION instead of
# silently disappearing.
UNVERIFIED_SYNTHETIC_REASON = "verification_not_completed_before_finalize"
# SR-003 / SD-02 (platform conditioning): JVM build-evidence markers scanned
# from the snapshot manifest. Kotlin/Scala targets without any of these
# markers are NOT assumed to be JVM targets (honest unknown instead).
JVM_BUILD_FILE_MARKERS = (
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "settings.gradle",
    "settings.gradle.kts",
)
JVM_BUILD_SUFFIX_MARKERS = (".sbt",)
JVM_BUILD_PATH_PREFIX_MARKERS = (".mvn/",)
JVM_CONDITIONAL_LANGUAGES = ("kotlin", "scala")
# --- Design §10.1 dossier layout (path-B alignment) -------------------------
# dossier_version marks the on-disk layout recorded in run.json so a future
# layout change can be detected read-only (DSR-072: old layouts are read with
# documented fallbacks, never migrated in place).
DOSSIER_VERSION = "1.0"
RUN_METADATA_ARTIFACT_KIND = "run_metadata"
PLAN_ARTIFACT_KIND = "plan"
INVENTORY_SUMMARY_ARTIFACT_KIND = "inventory_summary"
RECON_SUMMARY_ARTIFACT_KIND = "recon_summary"
WORKER_RESULT_ARTIFACT_KIND = "worker_result"
USAGE_ARTIFACT_KIND = "usage"
VALIDATION_LOG_ARTIFACT_KIND = "validation_log"
CANDIDATE_POOL_ARTIFACT_KIND = "candidate_pool"
FINDING_RECORD_ARTIFACT_KIND = "finding_record"
FINDING_HISTORY_ARTIFACT_KIND = "finding_history"
# Event types that record a finding's status transitions; they feed the
# per-finding history.json in the dossier (§10.1 findings/<id>/). A finding
# with none of these events gets an honest empty history list.
FINDING_TRANSITION_EVENT_TYPES = (
    "verified_findings_stored",
    "second_opinion_enqueued",
    "second_opinion_adjudicated",
    "second_opinion_pending",
    "second_opinion_target_missing",
    "second_opinion_not_applicable",
)


def detect_jvm_build_evidence_files(paths: List[str]) -> List[str]:
    """Return the snapshot paths that carry a JVM build marker (SR-003 / SD-02).

    Markers: pom.xml, Gradle build/settings scripts, .sbt build files and the
    .mvn/ directory. An empty result means NO JVM build evidence was found —
    the caller must then keep the platform unknown for Kotlin/Scala targets
    instead of assuming JVM.

    The build-manifest scan is shared with component detection (DA-03):
    ``find_build_manifest_paths`` discovers pom/gradle-family manifests once
    and this filter keeps only the JVM-relevant subset plus the .sbt/.mvn
    markers that are not manifest files.
    """
    build_manifests = set(find_build_manifest_paths(paths))
    evidence: List[str] = []
    for p in sorted(set(paths)):
        normalized = p[2:] if p.startswith("./") else p
        name = normalized.rsplit("/", 1)[-1]
        if normalized in build_manifests and name in JVM_BUILD_FILE_MARKERS:
            evidence.append(p)
        elif normalized.startswith(JVM_BUILD_PATH_PREFIX_MARKERS):
            evidence.append(p)
        elif name.endswith(JVM_BUILD_SUFFIX_MARKERS):
            evidence.append(p)
    return sorted(evidence)


class AuditAppService:
    """Core domain application service."""

    def __init__(self, skill_dir: str | Path) -> None:
        self.skill_dir = Path(os.path.realpath(os.path.abspath(skill_dir)))
        self.schemas_dir = self.skill_dir / "schemas"
        self.knowledge_dir = self.skill_dir / "knowledge"
        self._task_spec_validator: Optional[SchemaValidator] = None

    # ------------------------------------------------------------------
    # DSR-073: task_spec contract enforcement at every enqueue point.
    # ------------------------------------------------------------------
    def _validated_task_spec(self, spec: Dict[str, Any]) -> Dict[str, Any]:
        """Validate a task spec against the real task_spec contract (DSR-073).

        The schema is the single source of truth for the actual hunt/recon/
        verify spec shapes built by this service; an invalid spec raises
        InvalidInputError and is never enqueued.
        """
        if self._task_spec_validator is None:
            with open(self.schemas_dir / "task_spec.schema.json", "r", encoding="utf-8") as f:
                self._task_spec_validator = SchemaValidator(json.load(f))
        self._task_spec_validator.validate_or_raise(spec)
        return spec

    def _open_run_db(self, run_dir: str | Path) -> Any:
        """Open a run database and verify its recorded versions (DSR-072).

        Unsupported old or future formats fail closed with UnsupportedSchemaError;
        no automatic migration is ever attempted.
        """
        conn = get_db_connection(Path(run_dir) / "events.db")
        check_version_compatibility(conn)
        return conn

    def doctor(self, probe_cli: bool = False) -> List[Dict[str, Any]]:
        """Run non-destructive diagnostic probe."""
        return Doctor().probe(probe_cli=probe_cli)

    def prepare(
        self,
        target_dir: str,
        run_dir: str,
        config: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Initialize new audit run with frozen snapshot and deterministic plan."""
        # 1. Validate three roots
        target_path, skill_path, run_path = validate_three_roots(target_dir, str(self.skill_dir), run_dir)

        # Check existing run directory
        if run_path.exists() and any(run_path.iterdir()):
            raise StorageError(f"Run directory already exists and is non-empty: {run_path}")
        run_path.mkdir(parents=True, exist_ok=True)

        # 2. Validate RunConfig schema
        with open(self.schemas_dir / "run_config.schema.json", "r", encoding="utf-8") as f:
            cfg_schema = json.load(f)
        SchemaValidator(cfg_schema).validate_or_raise(config)

        # 3. Check safety acceptance
        cap = Capability("safety_check", "1.0")
        cap.verify_safety_policy(config.get("safety_acceptance", {}))

        # 4. Initialize Database
        db_path = run_path / "events.db"
        init_database(db_path)
        conn = get_db_connection(db_path)

        run_id = f"run-{uuid.uuid4().hex[:8]}"
        now = utc_now_iso()

        # Initialize run entry
        conn.execute(
            """
            INSERT INTO runs (run_id, snapshot_id, state, schema_version, skill_version, knowledge_version, config_ref, revision, created_at, updated_at)
            VALUES (?, 'pending', 'preparing', '1.0', '0.1.0', '1.0', 'config.json', 0, ?, ?)
            """,
            (run_id, now, now),
        )

        event_store = EventStore(conn)
        budget_ledger = BudgetLedger(conn)
        task_queue = TaskQueue(conn)

        # Save config
        with open(run_path / "config.json", "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)

        # Configure budgets
        for b in config.get("budgets", []):
            budget_ledger.set_budget(
                run_id=run_id,
                dimension=b["dimension"],
                limit_val=b["limit"],
                unit=b["unit"],
                mode=b.get("mode", "enforced"),
            )

        # 5. Collect Snapshot (knowledge_dir wiring: language knowledge gaps are
        # disclosed in the manifest assumptions instead of silently assumed).
        exclusion_rules = ExclusionRules(
            user_includes=config.get("scope", {}).get("include"),
            user_excludes=config.get("scope", {}).get("exclude"),
        )
        snapshot_dest = run_path / "snapshot"
        collector = SnapshotCollector(
            target_dir=target_path,
            snapshot_dest_dir=snapshot_dest,
            is_excluded_fn=exclusion_rules.evaluate,
            language_detector_fn=lambda p, b: (detect_language(p, b), "default"),
            knowledge_dir=self.knowledge_dir,
        )
        manifest = collector.collect()
        snapshot_id = manifest.snapshot_id

        # 5b. DSR-055: build-manifest component identification. Components are
        # injected BEFORE any consumer runs (inventory reconciliation, unit
        # slicing, plan accounting), so by_component and every unit's
        # component field reflect real build components. Injection point: the
        # collector freezes the snapshot inside collect(), so the persisted
        # manifest.json is rewritten in place with the detected component
        # fields. Snapshot identity is unaffected — the content-addressed
        # root_hash/snapshot_id encode only path/file_type/bytes/sha256 and
        # never the component field, so integrity verification (which
        # recomputes the root hash from file contents) still matches.
        component_labels = detect_components(manifest.files, snapshot_dest)
        for entry in manifest.files:
            entry["component"] = component_labels.get(entry["path"], DEFAULT_COMPONENT)
        manifest.save_json(str(snapshot_dest / "manifest.json"))
        component_root_records = component_roots([f["path"] for f in manifest.files])
        default_component_files = sum(
            1 for e in manifest.files if e.get("component") == DEFAULT_COMPONENT
        )

        # 6. Inventory, Signals, Boundaries, Slicing.
        # Signal scanning consumes the knowledge_dir (DSR-057) and the honest
        # scan_snapshot_files accounting: read failures and hit-cap overflows
        # are recorded as events, never silently swallowed.
        signal_scanner = SignalScanner(knowledge_dir=self.knowledge_dir)
        boundary_scanner = BoundaryScanner()

        scan_result = scan_snapshot_files(signal_scanner, manifest.files, snapshot_dest)
        file_signals: Dict[str, List[Dict[str, Any]]] = scan_result["file_signals"]
        all_boundaries: List[Dict[str, Any]] = []

        # Boundary scanning re-reads files with explicit failure accounting;
        # files already reported unreadable by the signal scan are not re-read.
        signal_scan_failed = {g["path"] for g in scan_result["gaps"]}
        boundary_gaps: List[Dict[str, Any]] = []
        for f in manifest.files:
            p = f["path"]
            if p in signal_scan_failed:
                lines: List[str] = []
            else:
                try:
                    with open(snapshot_dest / p, "r", encoding="utf-8", errors="replace") as sf:
                        lines = list(sf.read().splitlines())
                except OSError as e:
                    boundary_gaps.append({"path": p, "reason": "read_failure", "detail": str(e)})
                    lines = []

            b_hits = boundary_scanner.scan_file(p, lines, f.get("language", "unknown"))
            all_boundaries.extend(b_hits)

        matched_boundaries = boundary_scanner.match_boundaries(
            all_boundaries, [f["path"] for f in manifest.files]
        )

        # Snapshot gap / overflow accounting as events (SNP -> INT wiring).
        snapshot_gaps: List[Dict[str, Any]] = list(manifest.gaps)
        for g in snapshot_gaps:
            event_store.append_event(
                run_id, "snapshot_gap", "service", dict(g, source="collector")
            )
        for g in scan_result["gaps"]:
            event_store.append_event(run_id, "snapshot_gap", "service", dict(g, source="signal_scan"))
            snapshot_gaps.append(dict(g, source="signal_scan"))
        for g in boundary_gaps:
            event_store.append_event(run_id, "snapshot_gap", "service", dict(g, source="boundary_scan"))
            snapshot_gaps.append(dict(g, source="boundary_scan"))
        for ov in scan_result["overflows"]:
            event_store.append_event(
                run_id,
                "signal_overflow",
                "service",
                {
                    "path": ov.get("path", ""),
                    "dimension": ov.get("dimension", "signals"),
                    "estimated_count": ov.get("estimated_count", 0),
                    "reason": ov.get("reason", ""),
                },
            )
        for lang, err in sorted(signal_scanner.language_load_errors.items()):
            event_store.append_event(
                run_id,
                "snapshot_gap",
                "service",
                {"path": f"knowledge/languages/{lang}/signals.json", "reason": "load_failure", "detail": err, "source": "knowledge"},
            )

        # Strong-signal triage records persisted as events (ANA -> INT wiring).
        strong_hits: List[Dict[str, Any]] = []
        for p in sorted(file_signals.keys()):
            for h in file_signals[p]:
                if (
                    h.get("kind") in TRIAGE_STRONG_KINDS
                    and h.get("strength", 0) >= TRIAGE_STRONG_MIN_STRENGTH
                ):
                    strong_hits.append(h)
        triage_result = StrongSignalTriage(max_records=TRIAGE_MAX_RECORDS).triage_signals(strong_hits)
        event_store.append_event(
            run_id,
            "triage_recorded",
            "service",
            {"records": triage_result["records"], "stats": triage_result["stats"]},
        )
        for ov in triage_result["overflow"]:
            event_store.append_event(
                run_id,
                "analysis_gap",
                "service",
                {
                    "dimension": ov.get("dimension", "triage"),
                    "estimated_count": ov.get("estimated_count", 0),
                    "reason": ov.get("reason", ""),
                    "source": "triage",
                },
            )

        # Inventory reconciliation (DSR-014) recorded in the plan and events.
        inventory_reconciliation = reconcile_inventory(
            manifest,
            discovered_total=len(manifest.files) + len(manifest.excluded),
        )
        event_store.append_event(
            run_id,
            "inventory_reconciled",
            "service",
            inventory_reconciliation,
        )

        # Unit Planning
        profile = config.get("profile", "standard")
        planner = UnitPlanner(snapshot_id, profile=profile)
        units = planner.create_units(manifest.files, file_signals, matched_boundaries)

        dispositions: Dict[str, int] = {}
        for u in units:
            d = u.get("disposition", "analyze")
            dispositions[d] = dispositions.get(d, 0) + 1
        analyze_units = [u for u in units if u.get("disposition", "analyze") == "analyze"]

        # SR-003 / SD-02: JVM platform evidence is detected once, recorded in
        # the plan, and reused for every platform-conditional index decision.
        jvm_evidence_files = detect_jvm_build_evidence_files(
            [f["path"] for f in manifest.files]
        )
        platform_is_jvm: Optional[bool] = True if jvm_evidence_files else None

        # Save plan artifact
        plan_summary = {
            "snapshot_id": snapshot_id,
            "total_files": len(manifest.files),
            "total_units": len(units),
            "hunt_units": len(analyze_units),
            "dispositions": dispositions,
            "profile": profile,
            # §10.1 plan/: the budget allocation the queue is planned against
            # (dispatch priority ordering: recon > second opinion > verify >
            # T1 hunts > remaining hunts).
            "budgets": config.get("budgets", []),
            "queue_priority": {
                "recon": RECON_TASK_PRIORITY,
                "second_opinion": SECOND_OPINION_TASK_PRIORITY,
                "verify": VERIFY_TASK_PRIORITY,
                "hunt_t1": 20,
                "hunt_remaining": 10,
            },
            "units": units,
            "source_control": manifest.source_control,
            "snapshot_gaps": snapshot_gaps,
            "drift_detected": manifest.drift_detected,
            "inventory_reconciliation": inventory_reconciliation,
            "platform_evidence": {
                "is_jvm": platform_is_jvm,
                "build_marker_files": jvm_evidence_files,
                "basis": (
                    "JVM build markers found in the snapshot manifest"
                    if jvm_evidence_files
                    else "no JVM build markers found; platform stays unknown for "
                    "Kotlin/Scala targets (SD-02: state uncertainty when unknown)"
                ),
            },
            # DSR-055: the component roots found by build-manifest detection
            # and the accounting that falls outside every root (default).
            "component_detection": {
                "roots": component_root_records,
                "default_component_files": default_component_files,
            },
        }
        # Save the plan artifact at its §10.1 location (plan/plan.json), hashed
        # into the artifact ledger. finalize reads it back with a read-only
        # fallback to the legacy flat plan.json for old dossiers (DSR-072: old
        # layouts are read, never migrated).
        ArtifactManager(run_path, conn).publish_artifact(
            run_id,
            PLAN_ARTIFACT_KIND,
            "plan/plan.json",
            json.dumps(plan_summary, indent=2).encode("utf-8"),
        )

        # §10.1 inventory/summary.json: the reconciliation record as published
        # data (included/excluded/unknown-language accounting, per-language and
        # per-component counts, and the reconciled flag).
        inventory_summary = dict(inventory_reconciliation)
        inventory_summary["snapshot_id"] = snapshot_id
        ArtifactManager(run_path, conn).publish_artifact(
            run_id,
            INVENTORY_SUMMARY_ARTIFACT_KIND,
            "inventory/summary.json",
            json.dumps(inventory_summary, indent=2, sort_keys=True).encode("utf-8"),
        )

        # Evaluate G0 against the full manifest (gaps + source_control included)
        g0_res = GateEvaluator.evaluate_g0(manifest.to_dict(), plan_summary, 0)
        if g0_res.status != "pass":
            raise GateFailedError(f"Gate G0 failed: {g0_res.reason or 'Snapshot/Plan criteria unsatisfied'}")

        # Enqueue tasks per unit disposition (DSR-056): only analyze-disposition
        # units get hunt tasks. triage_only (T3) / inventory_only (T4) units are
        # recorded as explicit disposition marker events, never silently dropped
        # and never dispatched as hunt work.
        for u in units:
            disposition = u.get("disposition", "analyze")
            if disposition != "analyze":
                event_store.append_event(
                    run_id,
                    "unit_disposition",
                    "service",
                    {
                        "unit_id": u["unit_id"],
                        "tier": u.get("tier", ""),
                        "disposition": disposition,
                        "snapshot_id": snapshot_id,
                        "reason": "No hunt task dispatched for this disposition (DSR-056)",
                    },
                )
                continue
            task_queue.enqueue(
                run_id=run_id,
                task_key=f"hunt:{u['unit_id']}",
                kind="hunt",
                spec=self._validated_task_spec({
                    "schema_version": "1.0",
                    "task_kind": "hunt",
                    "snapshot_id": snapshot_id,
                    "unit": u,
                }),
                priority=20 if "T1" in u.get("tier", "") else 10,
            )

        # Recon stage wiring (DDS-05 S1 / DSR-024 / SR-006): exactly one recon
        # task per run, dispatched before any hunt task. Its spec carries the
        # snapshot id, the primary language index and knowledge catalog clues
        # so the worker can establish the guard baseline. The task_key is
        # idempotent (unique per run) and the sampled recon unit is derived
        # deterministically from the plan.
        recon_unit = self._build_recon_unit(units, snapshot_id)
        catalog = KnowledgeCatalog(self.knowledge_dir)
        # SR-003 / SD-02 (platform conditioning): the Java base index is only
        # applicable to JVM targets. Evidence comes from JVM build markers in
        # the frozen snapshot; a Kotlin/Scala target without any marker stays
        # honestly unknown (is_jvm=None) — the base index is not expanded and
        # the packet says so.
        recon_primary_index, recon_base_index = catalog.get_applicable_indices(
            recon_unit.get("language", "unknown"), is_jvm=platform_is_jvm
        )
        catalog_languages = self._catalog_languages()
        recon_task_id = task_queue.enqueue(
            run_id=run_id,
            task_key=RECON_TASK_KEY,
            kind="recon",
            spec=self._validated_task_spec({
                "schema_version": "1.0",
                "task_kind": "recon",
                "role": "hunt",  # recon packets declare the hunt output contract (DSR-059)
                "snapshot_id": snapshot_id,
                "unit": recon_unit,
                "language_index": recon_primary_index,
                "base_language_index": recon_base_index,
                "knowledge_hints": {
                    "primary_language": recon_unit.get("language", "unknown"),
                    "languages_in_scope": sorted(
                        {u.get("language", "unknown") for u in units}
                    ),
                    "catalog_languages": catalog_languages,
                },
            }),
            priority=RECON_TASK_PRIORITY,
        )

        # Update run to ready state
        conn.execute(
            "UPDATE runs SET snapshot_id = ?, state = 'ready' WHERE run_id = ?",
            (snapshot_id, run_id),
        )
        # IFC-05 floor requirement: the frozen snapshot view is announced as an
        # explicit event so replay/reconstruction can key evidence to it.
        event_store.append_event(
            run_id,
            "snapshot_published",
            "service",
            {
                "snapshot_id": manifest.snapshot_id,
                "root_hash": manifest.root_hash,
                "total_files": len(manifest.files),
                "excluded_files": len(manifest.excluded),
                "gap_count": len(getattr(manifest, "gaps", []) or []),
                "source_control": getattr(manifest, "source_control", None),
                "drift_detected": bool(getattr(manifest, "drift_detected", False)),
            },
        )
        event_store.append_event(
            run_id,
            "run_prepared",
            "service",
            {
                "snapshot_id": snapshot_id,
                "total_units": len(units),
                "hunt_units": len(analyze_units),
                "dispositions": dispositions,
                "recon_task_id": recon_task_id,
            },
        )

        # §10.1 run.json: the immutable run metadata. It is written exactly
        # once here and never rewritten by any later stage (finalize must not
        # overwrite it); the prepare entry point rejects any run directory
        # that already holds content, so the file cannot be silently replaced.
        # skill_payload_sha256 is a deterministic digest over the skill asset
        # tree (sorted relative paths, per-file content digests; generated
        # __pycache__/.pyc entries excluded) so the exact audited skill payload
        # stays verifiable for the lifetime of the dossier.
        run_metadata = {
            "schema_version": "1.0",
            "dossier_version": DOSSIER_VERSION,
            "run_id": run_id,
            "target": config.get("target"),
            "snapshot_id": snapshot_id,
            "root_hash": manifest.root_hash,
            "skill_version": self._read_skill_version(),
            "skill_payload_sha256": self._compute_skill_payload_sha256(self.skill_dir),
            "config": config,
            "profile": profile,
            "budgets": config.get("budgets", []),
            "created_at": now,
        }
        ArtifactManager(run_path, conn).publish_artifact(
            run_id,
            RUN_METADATA_ARTIFACT_KIND,
            "run.json",
            json.dumps(run_metadata, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8"),
        )

        return {
            "schema_version": "1.0",
            "run_id": run_id,
            "snapshot_id": snapshot_id,
            "recon_task_id": recon_task_id,
            "plan_summary": {
                "total_files": len(manifest.files),
                "total_units": len(units),
                "hunt_units": len(analyze_units),
                "dispositions": dispositions,
                "profile": profile,
            },
            "source_control": manifest.source_control,
            "snapshot_gaps_count": len(snapshot_gaps),
            "inventory_reconciliation": inventory_reconciliation,
            "triage_stats": triage_result["stats"],
        }

    def _catalog_languages(self) -> List[str]:
        """List the languages the knowledge catalog actually covers."""
        langs_dir = self.knowledge_dir / "languages"
        if not langs_dir.is_dir():
            return []
        return sorted(
            d.name for d in langs_dir.iterdir()
            if (d / "index.json").is_file()
        )

    def _read_skill_version(self) -> str:
        """The skill version string from the skill VERSION file."""
        try:
            return (self.skill_dir / "VERSION").read_text(encoding="utf-8").strip()
        except OSError:
            return "unknown"

    @staticmethod
    def _compute_skill_payload_sha256(skill_dir: str | Path) -> str:
        """Deterministic digest over the skill asset tree (run.json metadata).

        Every file under ``skill_dir`` is visited in sorted relative-path order
        (UTF-8 byte order) and its content SHA-256 is folded into the digest
        together with its path. Generated bytecode caches (``__pycache__``
        directories, ``*.pyc``/``*.pyo`` files) are excluded so the digest
        identifies the published asset payload, not the host's import cache.
        """
        root = Path(skill_dir)
        relative_paths: List[str] = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = sorted(d for d in dirnames if d != "__pycache__")
            for fname in filenames:
                if fname.endswith((".pyc", ".pyo")):
                    continue
                relative_paths.append(
                    (Path(dirpath) / fname).relative_to(root).as_posix()
                )
        hasher = hashlib.sha256()
        for rel in sorted(relative_paths, key=lambda s: s.encode("utf-8")):
            with open(root / rel, "rb") as f:
                hasher.update(rel.encode("utf-8"))
                hasher.update(b"\x00")
                hasher.update(hashlib.sha256(f.read()).digest())
        return hasher.hexdigest()

    @staticmethod
    def _load_plan(run_path: str | Path) -> Dict[str, Any]:
        """Load the run plan, preferring the §10.1 location (DSR-072).

        New dossiers carry the plan at ``plan/plan.json``; legacy dossiers kept
        it flat at the run root. Both are read transparently — an old dossier
        is never migrated in place (read-only tolerance for terminal runs).
        """
        primary = Path(run_path) / "plan" / "plan.json"
        try:
            with open(primary, "r", encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            pass
        # Legacy flat layout fallback (read-only).
        with open(Path(run_path) / "plan.json", "r", encoding="utf-8") as f:
            return json.load(f)

    @staticmethod
    def _build_recon_unit(units: List[Dict[str, Any]], snapshot_id: str) -> Dict[str, Any]:
        """Build the deterministic per-run recon unit (DDS-05 S1 / DSR-024).

        The recon unit samples line ranges from the planned analyze units
        (T1 first, then deterministic unit-id order), capped at
        RECON_UNIT_MAX_RANGES; packet capacity semantics take over from there
        (overflow is recorded, never silent). The unit language is the dominant
        language of the sampled ranges so the knowledge catalog can select the
        primary language index.
        """
        analyze_units = [u for u in units if u.get("disposition", "analyze") == "analyze"]
        pool = analyze_units or list(units)
        sorted_pool = sorted(
            pool,
            key=lambda u: (0 if "T1" in u.get("tier", "") else 1, u.get("unit_id", "")),
        )

        ranges: List[Dict[str, Any]] = []
        languages: List[str] = []
        for u in sorted_pool:
            for r in u.get("ranges", []):
                ranges.append({
                    "path": r["path"],
                    "line_start": r["line_start"],
                    "line_end": r["line_end"],
                })
                languages.append(u.get("language", "unknown"))
            if len(ranges) >= RECON_UNIT_MAX_RANGES:
                break
        ranges = ranges[:RECON_UNIT_MAX_RANGES]

        dominant_language = "unknown"
        if languages:
            counts: Dict[str, int] = {}
            for lang in languages:
                counts[lang] = counts.get(lang, 0) + 1
            dominant_language = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]

        unit_id = "recon-" + hashlib.sha256(snapshot_id.encode("utf-8")).hexdigest()[:8]
        return {
            "schema_version": "1.0",
            "unit_id": unit_id,
            "snapshot_id": snapshot_id,
            "tier": "recon",
            "disposition": "recon",
            "language": dominant_language,
            "ranges": ranges,
        }

    def activate(self, run_id: str, run_dir: str | Path) -> int:
        """Activate ready or paused run."""
        conn = self._open_run_db(run_dir)
        row = conn.execute("SELECT state FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        if not row:
            raise InvalidInputError(f"Run {run_id} not found")
        if row["state"] not in ("ready", "paused"):
            raise InvalidStateError(f"Cannot activate run in state '{row['state']}'")

        conn.execute("UPDATE runs SET state = 'active' WHERE run_id = ?", (run_id,))
        store = EventStore(conn)
        return store.append_event(run_id, "run_activated", "service", {})

    def next(
        self,
        run_id: str,
        run_dir: str | Path,
        batch_size: int = 1,
        lease_seconds: int = 300,
        worker_id: str = "worker",
    ) -> List[Dict[str, Any]]:
        """Claim next batch of tasks with their prompt packets published (IFC-02).

        Every returned claim carries a real, readable packet artifact at
        ``tasks/{task_id}/packet.json`` rendered by the PacketBuilder for the
        task kind (hunt / verify / recon roles, ``<untrusted_code>`` source
        slices, language index and guard summary). If a packet cannot be
        rendered or published, the claim is released back to the queue
        (fail closed): no claim leaves this method without its packet, and the
        failure is recorded as an event — never silently swallowed.
        """
        conn = self._open_run_db(run_dir)
        queue = TaskQueue(conn)
        claims = queue.claim(
            run_id, batch_size=batch_size, lease_seconds=lease_seconds, worker_id=worker_id
        )

        run_path = Path(run_dir)
        catalog = KnowledgeCatalog(self.knowledge_dir)
        builder = PacketBuilder()
        published: List[Dict[str, Any]] = []
        for claim in claims:
            try:
                self._publish_claim_packet(conn, run_path, catalog, builder, claim)
            except Exception as e:  # fail closed: release the claim, record the reason
                reason = f"packet rendering failed: {type(e).__name__}: {e}"
                # Render-failure circuit breaker (RUN-LESSONS O-01/O-11): a
                # task that fails to render 3 times is permanently unrenderable
                # (e.g. an unresolvable path) -- release-then-reclaim would
                # loop forever. Quarantine it with an explicit coverage gap so
                # the remaining queue keeps flowing.
                prior = 0
                try:
                    prior = conn.execute(
                        "SELECT count(*) AS cnt FROM events "
                        "WHERE event_type = 'packet_render_failed' AND payload_json LIKE ?",
                        (f'%"{claim["task_id"]}"%',),
                    ).fetchone()[0]
                except Exception:
                    prior = 0
                try:
                    EventStore(conn).append_event(
                        run_id,
                        "packet_render_failed",
                        "service",
                        {
                            "task_id": claim["task_id"],
                            "attempt_id": claim["attempt_id"],
                            "reason": reason,
                            "prior_failures": prior,
                        },
                    )
                finally:
                    if prior >= 2:
                        # Third failure: quarantine instead of releasing.
                        try:
                            self.report_host_failure(
                                run_dir,
                                claim,
                                HostFailureError(
                                    f"packet rendering failed 3 times: {reason}",
                                    retryable=False,
                                ),
                                max_retries=0,
                            )
                            EventStore(conn).append_event(
                                run_id,
                                "coverage_gap",
                                "service",
                                {
                                    "task_id": claim["task_id"],
                                    "attempt_id": claim["attempt_id"],
                                    "reason": "packet render unrenderable after 3 attempts",
                                },
                            )
                        except Exception as qe:  # noqa: BLE001
                            EventStore(conn).append_event(
                                run_id,
                                "packet_render_failed",
                                "service",
                                {
                                    "task_id": claim["task_id"],
                                    "quarantine_error": str(qe),
                                    "reason": reason,
                                },
                            )
                    else:
                        queue.release_claim(
                            run_id=claim["run_id"],
                            task_id=claim["task_id"],
                            attempt_id=claim["attempt_id"],
                            generation=claim["generation"],
                            claim_token=claim["claim_token"],
                            reason=reason,
                        )
                continue
            published.append(claim)
        return published

    # ------------------------------------------------------------------
    # IFC-02 wiring: real prompt packet publication per claim.
    # ------------------------------------------------------------------
    def _publish_claim_packet(
        self,
        conn: Any,
        run_path: Path,
        catalog: KnowledgeCatalog,
        builder: PacketBuilder,
        claim: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Render and publish the prompt packet for one claim (DSR-025/059).

        Returns the publish receipt. Raises on any failure so the caller can
        release the claim (fail closed).
        """
        run_id = claim["run_id"]
        task_id = claim["task_id"]
        spec = claim.get("spec") or {}
        task_row = conn.execute(
            "SELECT kind FROM tasks WHERE task_id = ?", (task_id,)
        ).fetchone()
        kind = task_row["kind"] if task_row else str(spec.get("task_kind", ""))
        snapshot_id = spec.get("snapshot_id", "")

        unit = spec.get("unit")
        if unit is None:
            if kind == "verify":
                unit = self._verify_unit_from_spec(
                    spec, snapshot_paths=self._snapshot_paths(run_path)
                )
            else:
                raise InvalidInputError(
                    f"Task '{task_id}' spec carries no unit; packet cannot be rendered"
                )

        file_contents = self._read_packet_files(run_path, unit)
        guard_summary = self._load_guard_summary(conn, run_id)

        if kind == "recon":
            packet, _digest, overflow = builder.build_recon_packet(
                snapshot_id,
                unit,
                file_contents,
                guard_summary=guard_summary,
                language_index=spec.get("language_index"),
                base_language_index=spec.get("base_language_index"),
            )
        elif kind == "verify":
            packet, _digest, overflow = builder.build_packet(
                "verify",
                snapshot_id,
                unit,
                file_contents,
                guard_summary=guard_summary,
            )
        else:
            primary_index, base_index = catalog.get_applicable_indices(
                unit.get("language", "unknown"),
                is_jvm=self._snapshot_platform_is_jvm(run_path),
            )
            packet, _digest, overflow = builder.build_hunt_packet(
                snapshot_id,
                unit,
                file_contents,
                guard_summary=guard_summary,
                language_index=primary_index,
                base_language_index=base_index,
            )

        payload = json.dumps(packet, sort_keys=True, ensure_ascii=False).encode("utf-8")
        receipt = ArtifactManager(run_path, conn).publish_artifact(
            run_id, "packet", f"tasks/{task_id}/packet.json", payload
        )

        if overflow:
            EventStore(conn).append_event(
                run_id,
                "packet_overflow",
                "service",
                {
                    "task_id": task_id,
                    "attempt_id": claim["attempt_id"],
                    "dimension": overflow.get("dimension", "packet_capacity"),
                    "estimated_count": overflow.get("estimated_count", 0),
                    "reason": overflow.get("reason", ""),
                },
            )

        # Coverage wiring: the ranges supplied in the packet are recorded in the
        # context_supplied dimension (DSR-034), sourced from the packet itself.
        for anchor in unit.get("ranges", []):
            conn.execute(
                """
                INSERT INTO coverage_intervals (run_id, snapshot_id, unit_id, path, dimension, start_line, end_line, attempt_id, source, confidence)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    snapshot_id or "default",
                    unit.get("unit_id", "default"),
                    anchor["path"],
                    "context_supplied",
                    anchor["line_start"],
                    anchor["line_end"],
                    claim["attempt_id"],
                    "packet_builder",
                    "exact",
                ),
            )
        return receipt

    @staticmethod
    @staticmethod
    def _snapshot_paths(run_path: Path) -> List[str]:
        """Snapshot-relative paths from the frozen manifest (program-owned)."""
        try:
            manifest = json.loads(
                (Path(run_path) / "snapshot" / "manifest.json").read_text(encoding="utf-8")
            )
            return [f.get("path", "") for f in manifest.get("files", [])]
        except (OSError, json.JSONDecodeError):
            return []

    @staticmethod
    def _resolve_snapshot_path(path: str, snapshot_paths: List[str]) -> str:
        """Resolve an abbreviated model path against the frozen manifest.

        Real workers cite shortened paths (relative names like "dir/name.ext"); the
        manifest is program-owned ground truth. Unique suffix match wins;
        ambiguous or unmatched paths keep the raw value and render as a
        degraded/unavailable block -- never guessed (SR-025).
        """
        if not path or path in snapshot_paths:
            return path
        matches = [p for p in snapshot_paths if p.endswith("/" + path) or p.endswith(path)]
        if len(matches) == 1:
            return matches[0]
        return path

    @staticmethod
    def _verify_unit_from_spec(spec: Dict[str, Any], snapshot_paths: Optional[List[str]] = None) -> Dict[str, Any]:
        """Synthesize a packet unit for a verify task from its candidate/finding."""
        snapshot_paths = snapshot_paths or []
        payload = (spec.get("input") or {})
        target = payload.get("candidate") or payload.get("finding") or {}
        ranges: List[Dict[str, Any]] = []
        seen: set = set()

        def _add_range(endpoint: Any, window: int = 5) -> None:
            """Extract a snapshot-resolvable location from an endpoint.

            Real workers emit endpoints as dicts whose location lives in free
            text (artifact/validation/...), or as prose strings. Tokens that
            resolve against the frozen manifest (exact, then unique suffix)
            become packet context ranges -- resolution-aware, no guessing
            (SR-025); unresolvable endpoints contribute no range (honest).
            """
            texts: List[str] = []
            if isinstance(endpoint, dict):
                explicit_path = endpoint.get("path") or ""
                explicit_line = endpoint.get("line")
                if explicit_path and explicit_path in snapshot_paths:
                    line = int(explicit_line or 1)
                    rng = {"path": explicit_path,
                           "line_start": max(1, line - window),
                           "line_end": line + window}
                    key = (rng["path"], rng["line_start"], rng["line_end"])
                    if key not in seen:
                        seen.add(key)
                        ranges.append(rng)
                    return
                for field in ("path", "artifact", "validation", "location", "symbol"):
                    v = endpoint.get(field)
                    if isinstance(v, str) and v:
                        texts.append(v)
            elif isinstance(endpoint, str):
                texts.append(endpoint)
            else:
                return

            import re as _re
            tokens = [
                (m.group(1), m.group(2))
                for m in _re.finditer(
                    r"([A-Za-z0-9_./\-]+\.[A-Za-z][A-Za-z0-9]{1,8})(?::(\d+))?",
                    " ".join(texts),
                )
            ]
            for token_path, token_line in tokens:
                resolved = AuditAppService._resolve_snapshot_path(token_path, snapshot_paths)
                if resolved == token_path and token_path not in snapshot_paths:
                    continue  # unresolvable guess: honestly skipped
                line = int(token_line or 1)
                rng = {"path": resolved,
                       "line_start": max(1, line - window),
                       "line_end": line + window}
                key = (rng["path"], rng["line_start"], rng["line_end"])
                if key not in seen:
                    seen.add(key)
                    ranges.append(rng)
                return  # first resolvable location wins

        def _resolve(rng: Dict[str, Any]) -> Dict[str, Any]:
            resolved = dict(rng)
            resolved["path"] = AuditAppService._resolve_snapshot_path(rng["path"], snapshot_paths)
            return resolved

        _add_range(target.get("source"))
        _add_range(target.get("sink"))
        for step in target.get("steps") or []:
            _add_range(step, window=2)
        ranges = [_resolve(r) for r in ranges]

        candidate_id = target.get("candidate_id") or spec.get("candidate_id") or "unknown"
        return {
            "schema_version": "1.0",
            "unit_id": f"verify-{candidate_id}",
            "language": (target.get("source") or {}).get("lang", "unknown"),
            "ranges": ranges,
        }

    @staticmethod
    def _read_packet_files(run_path: Path, unit: Dict[str, Any]) -> Dict[str, str]:
        """Read the snapshot files referenced by a unit's ranges."""
        snapshot_dest = run_path / "snapshot"
        contents: Dict[str, str] = {}
        for anchor in unit.get("ranges", []):
            path = anchor["path"]
            if path in contents:
                continue
            with open(snapshot_dest / path, "r", encoding="utf-8", errors="replace") as sf:
                contents[path] = sf.read()
        return contents

    @staticmethod
    def _snapshot_platform_is_jvm(run_path: Path) -> Optional[bool]:
        """Resolve JVM platform evidence from the frozen snapshot (SR-003/SD-02).

        True when JVM build markers exist in the snapshot manifest; None
        (honest unknown) when they do not. The value only changes behavior for
        platform-conditional base languages (Kotlin/Scala -> Java).
        """
        manifest_path = run_path / "snapshot" / "manifest.json"
        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                files = json.load(f).get("files", [])
        except (OSError, ValueError):
            return None
        if detect_jvm_build_evidence_files([f.get("path", "") for f in files if isinstance(f, dict)]):
            return True
        return None

    def _load_guard_summary(self, conn: Any, run_id: str) -> str:
        """Read the guard baseline summary from the ledger (DDS-05).

        Returns "" when no recon-established baseline exists: the hunt packet
        then carries no guard section at all, i.e. the guard baseline stays
        unknown instead of being fabricated.
        """
        row = conn.execute(
            """
            SELECT payload_json FROM events
            WHERE run_id = ? AND event_type = 'guard_baseline'
            ORDER BY revision DESC LIMIT 1
            """,
            (run_id,),
        ).fetchone()
        if not row:
            return ""
        try:
            guards = json.loads(row["payload_json"]).get("guards", [])
        except ValueError:
            return ""
        if not guards:
            return ""
        manager = GuardManager()
        for g in guards:
            try:
                manager.add_guard(GuardRecord.from_dict(g))
            except (KeyError, InvalidInputError):
                continue
        return manager.render_prompt_summary()

    def start(self, run_dir: str | Path, claim: Dict[str, Any]) -> Dict[str, Any]:
        """Mark task attempt as started."""
        conn = self._open_run_db(run_dir)
        queue = TaskQueue(conn)
        return queue.start(
            run_id=claim["run_id"],
            task_id=claim["task_id"],
            attempt_id=claim["attempt_id"],
            generation=claim["generation"],
            claim_token=claim["claim_token"],
        )

    def submit(
        self,
        run_dir: str | Path,
        claim: Dict[str, Any],
        worker_result: Dict[str, Any],
        digest: str,
        usage: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Submit completed worker result."""
        # Validate worker_result schema. A rejection is published as the
        # task's validation log (tasks/{task_id}/validation.json, DSR-018)
        # before the bounded format-correction retry path runs, so the refusal
        # reason and the exact field paths stay auditable in the dossier.
        with open(self.schemas_dir / "worker_result.schema.json", "r", encoding="utf-8") as f:
            res_schema = json.load(f)
        try:
            SchemaValidator(res_schema).validate_or_raise(worker_result)
        except InvalidInputError as e:
            self._publish_validation_log(run_dir, claim, e)
            raise

        conn = self._open_run_db(run_dir)
        queue = TaskQueue(conn)
        receipt = queue.submit(
            run_id=claim["run_id"],
            task_id=claim["task_id"],
            attempt_id=claim["attempt_id"],
            generation=claim["generation"],
            claim_token=claim["claim_token"],
            worker_result=worker_result,
            result_digest=digest,
            usage=usage,
        )

        # Record coverage intervals
        for cov in worker_result.get("coverage", []):
            dim = cov.get("dimension", "observed_read")
            for rng in cov.get("ranges", []):
                conn.execute(
                    """
                    INSERT INTO coverage_intervals (run_id, snapshot_id, unit_id, path, dimension, start_line, end_line, attempt_id, source, confidence)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        claim["run_id"],
                        cov.get("snapshot_id", "default"),
                        cov.get("unit_id", "default"),
                        rng["path"],
                        dim,
                        rng["line_start"],
                        rng["line_end"],
                        claim["attempt_id"],
                        cov.get("source", "worker"),
                        cov.get("confidence", "exact"),
                    ),
                )

        # Cross-domain wiring only runs once per attempt: idempotent replays of
        # the same submission return the original receipt and must not enqueue
        # duplicate verify tasks, re-run connector budget accounting, or
        # re-publish the per-task dossier artifacts.
        if not receipt.get("replayed", False):
            run_path = Path(run_dir)
            art_mgr = ArtifactManager(run_path, conn)
            # §10.1 tasks/<task-id>/: every accepted worker result is published
            # at tasks/{task_id}/result.json for all three task kinds (hunt,
            # recon, verify), and the trusted usage object lands at
            # tasks/{task_id}/usage.json when the submission carried one.
            # Both are hashed into the artifact ledger (traceability).
            art_mgr.publish_artifact(
                claim["run_id"],
                WORKER_RESULT_ARTIFACT_KIND,
                f"tasks/{claim['task_id']}/result.json",
                json.dumps(worker_result, sort_keys=True, ensure_ascii=False).encode("utf-8"),
            )
            if usage is not None:
                art_mgr.publish_artifact(
                    claim["run_id"],
                    USAGE_ARTIFACT_KIND,
                    f"tasks/{claim['task_id']}/usage.json",
                    json.dumps(usage, sort_keys=True, ensure_ascii=False).encode("utf-8"),
                )
            self._on_result_accepted(conn, run_path, claim, worker_result)

        return receipt

    def _publish_validation_log(
        self,
        run_dir: str | Path,
        claim: Dict[str, Any],
        error: InvalidInputError,
    ) -> None:
        """Publish tasks/{task_id}/validation.json for a schema-rejected result.

        The validation log records the rejection reason plus the exact field
        paths (DSR-018 校验日志), so a bounded format-correction retry is
        auditable from the dossier even though the malformed output itself is
        never accepted (SR-025). If the log itself cannot be persisted, the
        fact is raised as StorageError chained onto the original rejection —
        the dispatch loop's failure handling is identical for both error
        families, and the original reason is never lost.
        """
        details = getattr(error, "details", None) or {}
        payload = json.dumps(
            {
                "schema_version": "1.0",
                "task_id": claim.get("task_id", ""),
                "attempt_id": claim.get("attempt_id", ""),
                "rejected": True,
                "reason": str(getattr(error, "message", error)),
                "errors": details.get("errors", []),
            },
            sort_keys=True,
            ensure_ascii=False,
        ).encode("utf-8")
        try:
            conn = self._open_run_db(run_dir)
            ArtifactManager(Path(run_dir), conn).publish_artifact(
                claim["run_id"],
                VALIDATION_LOG_ARTIFACT_KIND,
                f"tasks/{claim['task_id']}/validation.json",
                payload,
            )
        except AuditError as log_error:
            raise StorageError(
                f"Failed to publish validation log for task "
                f"{claim.get('task_id', '')}: {log_error}"
            ) from error

    # ------------------------------------------------------------------
    # ANA -> LED wiring: verify task enqueue, connector budget accounting,
    # triage/gap/unresolved event persistence, verified finding stamping.
    # ------------------------------------------------------------------
    def _on_result_accepted(
        self,
        conn: Any,
        run_path: Path,
        claim: Dict[str, Any],
        worker_result: Dict[str, Any],
    ) -> None:
        """Fan a freshly accepted worker result out to the wired domains."""
        run_id = claim["run_id"]
        task_row = conn.execute(
            "SELECT kind FROM tasks WHERE task_id = ?",
            (claim["task_id"],),
        ).fetchone()
        kind = task_row["kind"] if task_row else str(worker_result.get("kind", ""))
        store = EventStore(conn)

        # Worker-reported overflow records are persisted as explicit events.
        overflow_type = "hunter_overflow" if kind == "hunt" else "analysis_gap"
        for ov in worker_result.get("overflow", []) or []:
            # RUN-LESSONS O-01: real models may emit overflow entries as bare
            # strings -- skip non-dict entries honestly (counted via the
            # trailing diagnostics), never crash the accept path.
            if not isinstance(ov, dict):
                store.append_event(
                    run_id,
                    overflow_type,
                    "worker",
                    {
                        "task_id": claim["task_id"],
                        "attempt_id": claim["attempt_id"],
                        "dimension": "unknown",
                        "estimated_count": 0,
                        "reason": f"non-dict overflow entry: {str(ov)[:120]}",
                    },
                )
                continue
            store.append_event(
                run_id,
                overflow_type,
                "worker",
                {
                    "task_id": claim["task_id"],
                    "attempt_id": claim["attempt_id"],
                    "dimension": ov.get("dimension", "unknown"),
                    "estimated_count": ov.get("estimated_count", 0),
                    "reason": ov.get("reason", ""),
                },
            )

        if kind == "recon":
            self._on_recon_result(conn, run_path, run_id, claim, worker_result, store)
        elif kind == "hunt":
            candidates, frontiers, probes, parser_overflows = HuntResultParser().parse_worker_payload(
                worker_result, claim["task_id"]
            )
            for ov in parser_overflows:
                store.append_event(
                    run_id,
                    "hunter_overflow",
                    "service",
                    {
                        "task_id": claim["task_id"],
                        "attempt_id": claim["attempt_id"],
                        "dimension": ov.get("dimension", "unknown"),
                        "estimated_count": ov.get("estimated_count", 0),
                        "reason": ov.get("reason", ""),
                    },
                )
            # SR-005/SR-007/DSR-026/DSR-058: persist EVERY frontier and sink
            # probe of this submission as a ledger event BEFORE any connection
            # attempt — including one-sided submissions. A half-chain without a
            # counterpart yet is recorded data, never silently dropped input.
            if frontiers:
                store.append_event(
                    run_id,
                    FRONTIER_RECORDED_EVENT,
                    "service",
                    {
                        "schema_version": "1.0",
                        "task_id": claim["task_id"],
                        "attempt_id": claim["attempt_id"],
                        "records": frontiers,
                    },
                )
            if probes:
                store.append_event(
                    run_id,
                    SINK_PROBE_RECORDED_EVENT,
                    "service",
                    {
                        "schema_version": "1.0",
                        "task_id": claim["task_id"],
                        "attempt_id": claim["attempt_id"],
                        "records": probes,
                    },
                )
            # DSR-063: duplicate candidates are reconciled before any verify
            # work is dispatched; only deduplicated representatives continue.
            candidates = self._deduplicate_candidates(conn, run_id, candidates, store)
            self._enqueue_verify_tasks(conn, run_id, candidates, claim["task_id"])
            # Cross-task connection (SR-005/DSR-026): aggregate this run's
            # half-chains from the event ledger (history + this submission)
            # before evaluating pairings, so a frontier reported by task A can
            # pair with a probe reported by task B at B's submission time.
            pending = self._gather_pending_half_chains(conn, run_id)
            if (frontiers or probes) and pending["frontiers"] and pending["probes"]:
                result = self._run_connector(
                    conn, run_id, claim,
                    [e["record"] for e in pending["frontiers"]],
                    [e["record"] for e in pending["probes"]],
                    store,
                )
            else:
                result = {"connections": []}
            self._record_unpaired_half_chains(run_id, pending, result, store)
        elif kind == "verify":
            spec = self._task_spec(conn, claim)
            if spec.get("second_opinion"):
                self._adjudicate_second_opinion(conn, run_path, run_id, claim, worker_result, store)
            else:
                self._store_verified_findings(conn, run_path, run_id, claim, worker_result, store)

    @staticmethod
    def _task_spec(conn: Any, claim: Dict[str, Any]) -> Dict[str, Any]:
        """Resolve a claim's task spec (from the claim itself or the ledger)."""
        spec = claim.get("spec")
        if isinstance(spec, dict) and spec:
            return spec
        row = conn.execute(
            "SELECT spec_json FROM tasks WHERE task_id = ?", (claim["task_id"],)
        ).fetchone()
        if row:
            try:
                return json.loads(row["spec_json"])
            except ValueError:
                return {}
        return {}

    # ------------------------------------------------------------------
    # SR-005/SR-007/DSR-026/DSR-058 wiring: run-level half-chain ledger.
    # ------------------------------------------------------------------
    @staticmethod
    def _gather_pending_half_chains(conn: Any, run_id: str) -> Dict[str, Any]:
        """Aggregate a run's recorded half-chains from the event ledger.

        Returns the pending (not yet paired) frontier and sink-probe records
        with the task id that reported them, plus the record ids already
        covered by an earlier ``unpaired_half_chain`` event (so the marker is
        written once per record, not once per submission).
        """
        frontiers: Dict[str, Dict[str, Any]] = {}
        probes: Dict[str, Dict[str, Any]] = {}
        paired_frontier_ids: set = set()
        paired_probe_ids: set = set()
        marked_unpaired: set = set()

        placeholders = ",".join("?" * 3)
        for row in conn.execute(
            f"""
            SELECT event_type, payload_json FROM events
            WHERE run_id = ? AND event_type IN ({placeholders})
            ORDER BY revision
            """,
            (run_id, FRONTIER_RECORDED_EVENT, SINK_PROBE_RECORDED_EVENT, CONNECTOR_PAIRED_EVENT),
        ).fetchall():
            try:
                payload = json.loads(row["payload_json"])
            except ValueError:
                continue
            if not isinstance(payload, dict):
                continue
            event_type = row["event_type"]
            if event_type == CONNECTOR_PAIRED_EVENT:
                if payload.get("frontier_id"):
                    paired_frontier_ids.add(payload["frontier_id"])
                if payload.get("probe_id"):
                    paired_probe_ids.add(payload["probe_id"])
                continue
            source_task_id = str(payload.get("task_id", ""))
            bucket = frontiers if event_type == FRONTIER_RECORDED_EVENT else probes
            for rec in payload.get("records", []) or []:
                if not isinstance(rec, dict):
                    continue
                record_id = str(rec.get("frontier_id") or rec.get("probe_id") or "")
                if not record_id or record_id in bucket:
                    continue  # first occurrence wins (idempotent re-reporting)
                bucket[record_id] = {"record": rec, "task_id": source_task_id}

        for row in conn.execute(
            "SELECT payload_json FROM events WHERE run_id = ? AND event_type = ? ORDER BY revision",
            (run_id, UNPAIRED_HALF_CHAIN_EVENT),
        ).fetchall():
            try:
                payload = json.loads(row["payload_json"])
            except ValueError:
                continue
            if isinstance(payload, dict) and payload.get("record_id"):
                marked_unpaired.add(str(payload["record_id"]))

        pending_frontiers = [
            frontiers[fid] for fid in sorted(frontiers) if fid not in paired_frontier_ids
        ]
        pending_probes = [
            probes[pid] for pid in sorted(probes) if pid not in paired_probe_ids
        ]
        return {
            "frontiers": pending_frontiers,
            "probes": pending_probes,
            "marked_unpaired": marked_unpaired,
        }

    @staticmethod
    def _record_unpaired_half_chains(
        run_id: str,
        pending: Dict[str, Any],
        connector_result: Dict[str, Any],
        store: EventStore,
    ) -> List[str]:
        """Persist ``unpaired_half_chain`` events for still-unpaired records.

        Called after the run-level aggregation/connection step: records that
        the connector did not pair (either side missing, capped, unresolved or
        incompatible) get an explicit marker event with their provenance so
        the NEEDS-VALIDATION report can render them. Records already marked
        and still pending are not re-marked; a record paired LATER supersedes
        its marker through the connector_paired event the renderer reconciles.
        """
        newly_paired_frontiers = {
            c.get("frontier_id", "") for c in connector_result.get("connections", [])
        }
        newly_paired_probes = {
            c.get("probe_id", "") for c in connector_result.get("connections", [])
        }
        marked = pending.get("marked_unpaired") or set()
        recorded: List[str] = []

        entries: List[tuple] = [
            ("frontier", e["record"], e["task_id"]) for e in pending.get("frontiers", [])
        ] + [("sink_probe", e["record"], e["task_id"]) for e in pending.get("probes", [])]

        for record_kind, rec, source_task_id in entries:
            record_id = str(rec.get("frontier_id") or rec.get("probe_id") or "")
            if not record_id or record_id in marked:
                continue
            if record_kind == "frontier" and record_id in newly_paired_frontiers:
                continue
            if record_kind == "sink_probe" and record_id in newly_paired_probes:
                continue
            endpoint = rec.get("source") if record_kind == "frontier" else rec.get("sink")
            endpoint = endpoint if isinstance(endpoint, dict) else {}
            store.append_event(
                run_id,
                UNPAIRED_HALF_CHAIN_EVENT,
                "service",
                {
                    "schema_version": "1.0",
                    "record_kind": record_kind,
                    "record_id": record_id,
                    "boundary": rec.get("boundary", ""),
                    "symbol": endpoint.get("symbol", ""),
                    "path": endpoint.get("path", ""),
                    "line": endpoint.get("line"),
                    "source_task_id": source_task_id,
                    "reason": (
                        "run-level aggregation found no compatible counterpart "
                        "for this half-chain (DSR-058: unmatched records are "
                        "never silently dropped)"
                    ),
                },
            )
            recorded.append(record_id)
        return recorded

    # ------------------------------------------------------------------
    # DDS-05 S1 / DSR-024 / SR-006 wiring: recon results establish the
    # guard baseline (events + artifact). No recon worker means no
    # fabricated baseline: hunt packets simply keep the unknown default.
    # ------------------------------------------------------------------
    def _on_recon_result(
        self,
        conn: Any,
        run_path: Path,
        run_id: str,
        claim: Dict[str, Any],
        worker_result: Dict[str, Any],
        store: EventStore,
    ) -> None:
        """Persist a recon worker's guard baseline as an event + artifact."""
        guards: List[Dict[str, Any]] = []
        invalid_records: List[Dict[str, Any]] = []
        unrecognized = 0
        for rec in worker_result.get("records", []) or []:
            if not isinstance(rec, dict):
                unrecognized += 1
                continue
            if "guard_id" not in rec:
                unrecognized += 1
                continue
            status = rec.get("status")
            if status not in VALID_GUARD_STATUSES or not rec.get("mechanism"):
                invalid_records.append(rec)
                continue
            guards.append(GuardRecord.from_dict(rec).to_dict())

        # §10.1: the guard baseline summary is published at recon/recon-result.json
        # (the recon/ directory of the dossier). The raw recon worker result
        # itself is persisted at tasks/{task_id}/result.json by submit(), which
        # publishes that artifact uniformly for every task kind.
        rel_path = "recon/recon-result.json"
        payload = json.dumps(
            {
                "schema_version": "1.0",
                "task_id": claim["task_id"],
                "attempt_id": claim["attempt_id"],
                "guards": guards,
                "guards_reported": len(guards),
                "unrecognized_records": unrecognized,
                "invalid_records": len(invalid_records),
            },
            sort_keys=True,
            ensure_ascii=False,
        ).encode("utf-8")
        ArtifactManager(run_path, conn).publish_artifact(
            run_id, RECON_SUMMARY_ARTIFACT_KIND, rel_path, payload
        )
        store.append_event(
            run_id,
            "guard_baseline",
            "service",
            {
                "task_id": claim["task_id"],
                "attempt_id": claim["attempt_id"],
                "guards": guards,
                "guards_reported": len(guards),
                "unrecognized_records": unrecognized,
                "invalid_records": len(invalid_records),
                "artifact": rel_path,
            },
        )
        for rec in invalid_records:
            store.append_event(
                run_id,
                "recon_invalid_record",
                "service",
                {
                    "task_id": claim["task_id"],
                    "attempt_id": claim["attempt_id"],
                    "guard_id": rec.get("guard_id", ""),
                    "reason": "guard record carried an invalid status or no mechanism",
                },
            )

    # ------------------------------------------------------------------
    # DSR-063 wiring: candidate deduplication before verify dispatch.
    # ------------------------------------------------------------------
    def _prior_verified_candidates(self, conn: Any, run_id: str) -> List[Dict[str, Any]]:
        """Candidates already dispatched for verification in this run (DSR-063).

        The ledger is the cross-submission memory: every verify task's spec
        carries the candidate it was built from, so duplicates arriving in a
        LATER hunt submission are still reconciled against the candidate that
        already represents them.
        """
        prior: List[Dict[str, Any]] = []
        for row in conn.execute(
            "SELECT spec_json FROM tasks WHERE run_id = ? AND kind = 'verify'",
            (run_id,),
        ).fetchall():
            try:
                spec = json.loads(row["spec_json"])
            except ValueError:
                continue
            cand = (spec.get("input") or {}).get("candidate")
            if isinstance(cand, dict) and cand.get("candidate_id"):
                prior.append(cand)
        return prior

    def _deduplicate_candidates(
        self,
        conn: Any,
        run_id: str,
        candidates: List[Dict[str, Any]],
        store: EventStore,
    ) -> List[Dict[str, Any]]:
        """Reconcile duplicate candidates and return verify-eligible representatives.

        Exact duplicates (same fingerprint AND same source origin) are merged
        automatically with confirmed_by="pipeline:exact-duplicate" and recorded
        as candidate_deduplicated events; the pool includes candidates already
        dispatched for verification in earlier submissions, so a duplicate that
        arrives later is merged into the existing representative instead of
        producing a second verify task. Same-fingerprint candidates with
        DIFFERENT sources are never merged (DSR-063: distinct sources are
        preserved); they are only recorded as dedup_suggested events.
        """
        if not candidates:
            return candidates
        # SR-025 defense in depth: a candidate whose endpoints are not the
        # contract shape (a bare string "source", etc.) must not reach the
        # fingerprint math -- it is rejected with an explicit analysis_gap
        # event (located, never silently dropped, never crashing the audit).
        well_formed = []
        for cand in candidates:
            src_obj = cand.get("source")
            sink_obj = cand.get("sink")
            if isinstance(src_obj, dict) and isinstance(sink_obj, dict):
                well_formed.append(cand)
            else:
                store.append_event(
                    run_id,
                    "analysis_gap",
                    "service",
                    {
                        "reason": "candidate rejected: non-contract endpoint shape",
                        "candidate_id": cand.get("candidate_id", ""),
                        "source_type": type(src_obj).__name__,
                        "sink_type": type(sink_obj).__name__,
                    },
                )
        candidates = well_formed
        if not candidates:
            return candidates
        deduplicator = CandidateDeduplicator()
        prior = self._prior_verified_candidates(conn, run_id)
        new_ids = {c.get("candidate_id", "") for c in candidates}
        pool = prior + candidates

        merged_ids: set = set()
        for suggestion in deduplicator.propose_deduplication(pool):
            if suggestion["merged_candidate_id"] not in new_ids:
                # Historical pair: both sides were reconciled in an earlier
                # submission; re-confirming would duplicate events.
                continue
            merge = deduplicator.confirm_merge(
                dict(suggestion), confirmed_by="pipeline:exact-duplicate"
            )
            merged_ids.add(merge["merged_candidate_id"])
            store.append_event(
                run_id,
                "candidate_deduplicated",
                "service",
                {
                    "suggestion_id": merge["suggestion_id"],
                    "fingerprint": suggestion.get("fingerprint", ""),
                    "merged_candidate_id": merge["merged_candidate_id"],
                    "representative_id": merge["representative_id"],
                    "confirmed_by": merge["confirmed_by"],
                    "reason": merge["reason"],
                },
            )

        by_fingerprint: Dict[str, List[Dict[str, Any]]] = {}
        for cand in pool:
            fp = compute_fingerprint(cand)
            by_fingerprint.setdefault(fp, []).append(cand)
        for fp, group in sorted(by_fingerprint.items()):
            source_paths = sorted({c.get("source", {}).get("path", "") for c in group})
            involves_new = any(c.get("candidate_id", "") in new_ids for c in group)
            if len(source_paths) > 1 and involves_new:
                store.append_event(
                    run_id,
                    "dedup_suggested",
                    "service",
                    {
                        "fingerprint": fp,
                        "candidate_ids": [c.get("candidate_id", "") for c in group],
                        "source_paths": source_paths,
                        "reason": (
                            "Same fingerprint with distinct source origins; both "
                            "candidates are retained (DSR-063 forbids the merge)"
                        ),
                    },
                )

        return [c for c in candidates if c.get("candidate_id", "") not in merged_ids]

    def _enqueue_verify_tasks(
        self,
        conn: Any,
        run_id: str,
        candidates: List[Dict[str, Any]],
        origin_task_id: str = "",
    ) -> List[Dict[str, Any]]:
        """Enqueue verify-kind tasks for hunt candidates (DSR-027 wiring).

        The Verifier is constructed with enforce_attempt_gate=True so the E2
        new-attempt gate is real: submissions claiming a confirmed verdict must
        carry a verify_attempt_id distinct from the hunt attempt.

        Task keys are scoped by the producing hunt task, so identical
        worker-supplied candidate ids from different hunt tasks never collide.

        DSR-073: every spec is validated against the task_spec contract before
        enqueue; a spec that does not match the real contract is rejected with
        InvalidInputError and recorded as an explicit event instead of being
        enqueued (fail visible, never silently enqueued).
        """
        verifier = Verifier(enforce_attempt_gate=True)
        queue = TaskQueue(conn)
        store = EventStore(conn)
        enqueued: List[Dict[str, Any]] = []
        for cand in candidates:
            cand_id = cand.get("candidate_id", "")
            if not cand_id:
                continue
            try:
                spec = self._validated_task_spec(verifier.build_verify_task(cand))
            except InvalidInputError as e:
                store.append_event(
                    run_id,
                    "verify_task_spec_rejected",
                    "service",
                    {
                        "candidate_id": cand_id,
                        "origin_task_id": origin_task_id,
                        "reason": str(getattr(e, "message", e)),
                    },
                )
                continue
            task_id = queue.enqueue(
                run_id=run_id,
                task_key=f"verify:{origin_task_id}:{cand_id}",
                kind="verify",
                spec=spec,
                priority=VERIFY_TASK_PRIORITY,
            )
            enqueued.append(
                {"task_id": task_id, "candidate_id": cand_id, "verify_task_id": spec["verify_task_id"]}
            )
        return enqueued

    def _run_connector(
        self,
        conn: Any,
        run_id: str,
        claim: Dict[str, Any],
        frontiers: List[Dict[str, Any]],
        probes: List[Dict[str, Any]],
        store: EventStore,
    ) -> Dict[str, Any]:
        """Run hypothesis connection with a full LED budget lifecycle (ANA -> LED).

        ``frontiers``/``probes`` are the run-level PENDING half-chain sets
        (history + current submission, already-paired records excluded), so a
        frontier reported by one task can pair with a probe reported by
        another. reserve -> settle (actual pairing evaluations) on success,
        reserve -> release on failure. Every formed connection is recorded as
        a ``connector_paired`` event — the idempotence guard that keeps
        repeated submissions from re-pairing the same records. Unresolved /
        incompatible / capped records are persisted as events and never
        silently dropped (DSR-058).
        """
        ledger = BudgetLedger(conn)
        connector = HypothesisConnector()
        # Reservations are keyed per hunt attempt and connector dimension, so
        # replays of the same attempt cannot double-charge the budget.
        reservation_key = f"{claim['attempt_id']}:connector"
        estimate = min(len(frontiers) * len(probes), CONNECTOR_EVALUATION_CAP)

        ledger.reserve(run_id, reservation_key, CONNECTOR_BUDGET_DIMENSION, estimate)
        try:
            result = connector.connect_ex(frontiers, probes, budget=estimate)
        except BaseException:
            ledger.release(reservation_key, run_id=run_id)
            raise
        ledger.settle(
            reservation_key,
            CONNECTOR_BUDGET_DIMENSION,
            result["stats"]["evaluations"],
            run_id=run_id,
        )
        store.append_event(
            run_id,
            "connector_evaluated",
            "service",
            {
                "attempt_id": claim["attempt_id"],
                "budget_dimension": CONNECTOR_BUDGET_DIMENSION,
                "estimated_evaluations": estimate,
                "actual_evaluations": result["stats"]["evaluations"],
                "connections": result["stats"]["connections"],
                "candidates": result["stats"]["candidates"],
            },
        )

        # SR-005/DSR-026: mark the records each connection consumed. The
        # pending-set gathering excludes ids present in these events, which is
        # what makes cross-task connection idempotent across submissions.
        for conn_rec in result["connections"]:
            store.append_event(
                run_id,
                CONNECTOR_PAIRED_EVENT,
                "service",
                {
                    "schema_version": "1.0",
                    "connection_id": conn_rec.get("connection_id", ""),
                    "frontier_id": conn_rec.get("frontier_id", ""),
                    "probe_id": conn_rec.get("probe_id", ""),
                    "status": conn_rec.get("status", ""),
                    "task_id": claim["task_id"],
                    "attempt_id": claim["attempt_id"],
                },
            )

        for rec in result["unresolved"]:
            payload = {k: v for k, v in rec.items() if k != "record"}
            store.append_event(run_id, "connector_unresolved", "service", payload)
        for rec in result["incompatible"]:
            store.append_event(run_id, "connector_incompatible", "service", rec)
        for g in result["gaps"]:
            store.append_event(
                run_id,
                "analysis_gap",
                "service",
                {
                    "dimension": g.get("dimension", "connector"),
                    "estimated_count": g.get("estimated_count", 0),
                    "reason": g.get("reason", ""),
                    "source": "connector",
                },
            )

        connector_candidates = self._deduplicate_candidates(conn, run_id, result["candidates"], store)
        self._enqueue_verify_tasks(conn, run_id, connector_candidates, claim["task_id"])
        return result

    def _extract_findings(self, records: List[Dict[str, Any]], claim_hint: str = "x") -> List[Dict[str, Any]]:
        """Extract draft finding objects from verify-task result records."""
        findings: List[Dict[str, Any]] = []
        for n, rec in enumerate(records or []):
            if not isinstance(rec, dict) or rec.get("verdict") not in VERIFIED_FINDING_VERDICTS:
                continue
            finding = rec.get("finding") if isinstance(rec.get("finding"), dict) else rec
            if not finding.get("finding_id"):
                # Program-owned record identity (not evidence): models omit
                # the id even when the verdict payload is well-formed
                # (RUN-LESSONS real-shape series, run-009b/010).
                finding["finding_id"] = f"F-VERIFY-{claim_hint}-{n}"
            findings.append(finding)
        return findings

    def _store_verified_findings(
        self,
        conn: Any,
        run_path: Path,
        run_id: str,
        claim: Dict[str, Any],
        worker_result: Dict[str, Any],
        store: EventStore,
    ) -> List[Dict[str, Any]]:
        """Stamp run_id on verified findings and persist them atomically (DSR-010).

        Every finding from a verify submission is stamped with the current
        run_id before storage, so the semantic validator's cross-run reference
        check is real at finalize time. Each attempt publishes its own artifact
        file (no in-place rewrite), keeping artifact integrity verification sound.

        DSR-062: every confirmed finding additionally runs the bounded variant
        search against the frozen snapshot (bounded read, bounded result list)
        before it is persisted, so same-sink variants are surfaced as explicit
        requires_independent_verification entries instead of staying empty.
        """
        findings = self._extract_findings(worker_result.get("records", []), claim.get("attempt_id", "x"))
        if not findings:
            return []
        # Bind verified findings to their candidate dossier metadata (title/
        # issue/source/sink/steps) when the worker verdict payload omits them:
        # the verify spec's candidate record is program-owned dossier data
        # (RUN-LESSONS real-shape series, real run-011).
        spec = self._task_spec(conn, claim)
        cand = ((spec.get("input") or {}).get("candidate")) or {}
        for finding in findings:
            for field in ("title", "issue", "category", "impact_claim"):
                if not finding.get(field) and cand.get(field):
                    finding[field] = cand[field]
            for field in ("source", "sink"):
                cur = finding.get(field)
                if (not isinstance(cur, dict) or not cur) and isinstance(cand.get(field), dict):
                    finding[field] = cand[field]
            if not finding.get("steps") and cand.get("steps"):
                finding["steps"] = cand["steps"]
        stamped: List[Dict[str, Any]] = []
        snapshot_data: Optional[Dict[str, Any]] = None
        for f in findings:
            f["run_id"] = run_id
            if f.get("verdict") == "confirmed":
                # SR-008/SR-011 (H′ demotion semantics on the service store
                # path): a confirmed finding requires rating factor reasons.
                # rating.schema nests them under factor_reasons (RatingEngine
                # output); a flat shape is tolerated defensively. Both shapes
                # are read -- a nested reason must never be misread as
                # missing (RUN-LESSONS real run-011 false-demotion fix).
                rating = f.get("rating") or {}
                nested = rating.get("factor_reasons") if isinstance(rating.get("factor_reasons"), dict) else {}
                reasons_missing = [
                    k for k in ("impact_why", "exploitability_why")
                    if not str(nested.get(k) or rating.get(k) or "").strip()
                ]
                if reasons_missing:
                    f["verdict"] = "needs_validation"
                    f["demoted_from"] = "confirmed"
                    f.setdefault("blockers", []).extend(
                        f"missing rating factor reason: {k}" for k in reasons_missing
                    )
                    if rating:
                        f.setdefault("blockers", []).append(
                            "neutral pending rating applied (worker supplied no "
                            "usable rating for this verdict)"
                        )
                    f["validation_plan"] = (
                        "re-rate with impact/exploitability factor reasons and "
                        "re-submit through an independent verification attempt"
                    )
                    # Verifier._pending_rating: schema-valid pending rating
                    # (observed numbers; neutral 3 only when truly absent,
                    # disclosed via the blocker above).
                    f["rating"] = Verifier._pending_rating(
                        int(rating.get("impact") or 3),
                        int(rating.get("exploitability") or 3),
                    )
            if f.get("verdict") == "confirmed":
                # DSR-062 is a fixed action for confirmed findings: no config
                # switch. The snapshot is read lazily and at most once per
                # submission, capped at VARIANT_SEARCH_MAX_FILES files.
                if snapshot_data is None:
                    snapshot_data = self._load_snapshot_files(run_path, VARIANT_SEARCH_MAX_FILES)
                self._attach_variant_search(f, snapshot_data)
            stamped.append(f)
        payload = json.dumps(stamped, sort_keys=True, ensure_ascii=False).encode("utf-8")
        rel_path = f"findings/verified-{claim['attempt_id']}.json"
        ArtifactManager(run_path, conn).publish_artifact(
            run_id, FINDINGS_ARTIFACT_KIND, rel_path, payload
        )
        store.append_event(
            run_id,
            "verified_findings_stored",
            "service",
            {
                "attempt_id": claim["attempt_id"],
                "artifact": rel_path,
                "finding_ids": [f.get("finding_id") for f in stamped],
            },
        )
        self._enqueue_second_opinion_tasks(conn, run_id, stamped, store)
        return stamped

    # ------------------------------------------------------------------
    # DSR-062 wiring: bounded variant search against the frozen snapshot.
    # ------------------------------------------------------------------
    @staticmethod
    def _load_snapshot_files(run_path: Path, max_files: int) -> Dict[str, Any]:
        """Read the frozen snapshot for the variant search (DSR-062).

        Files are attempted in manifest-path order (UTF-8 bytes, the same
        deterministic order as the root hash) and the number of attempted
        files is capped at ``max_files`` — the bounded_variant_search read
        bound, so a large snapshot never enters memory whole. A single
        unreadable file is skipped and recorded, never allowed to abort the
        search. An unreadable manifest is recorded the same way.

        Returns:
        {
            "files": {relative path -> content} (successfully read only),
            "total_files": manifest file count,
            "unsearched_files": paths not searched (cap overflow + skips),
            "read_errors": ["path: error" or manifest failure strings],
        }
        """
        snapshot_dest = run_path / "snapshot"
        manifest_path = snapshot_dest / "manifest.json"
        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                paths = [
                    entry.get("path", "")
                    for entry in json.load(f).get("files", [])
                    if isinstance(entry, dict) and entry.get("path")
                ]
        except (OSError, ValueError) as exc:
            return {
                "files": {},
                "total_files": 0,
                "unsearched_files": [],
                "read_errors": [
                    f"snapshot manifest unreadable ({exc.__class__.__name__}); "
                    "no snapshot file was searched"
                ],
            }
        paths = sorted(paths, key=lambda p: p.encode("utf-8"))
        files: Dict[str, str] = {}
        read_errors: List[str] = []
        unsearched: List[str] = list(paths[max_files:])
        for rel_path in paths[:max_files]:
            try:
                with open(snapshot_dest / rel_path, "r", encoding="utf-8", errors="replace") as sf:
                    files[rel_path] = sf.read()
            except OSError as exc:
                read_errors.append(f"{rel_path}: {exc.__class__.__name__}")
                unsearched.append(rel_path)
        return {
            "files": files,
            "total_files": len(paths),
            "unsearched_files": sorted(unsearched),
            "read_errors": read_errors,
        }

    @staticmethod
    def _attach_variant_search(
        finding: Dict[str, Any],
        snapshot_data: Dict[str, Any],
    ) -> None:
        """Run the bounded variant search and record it on the finding (DSR-062).

        Writes ``variants`` plus the honest ``variant_search`` coverage record:
        snapshot paths beyond the read cap and unreadable files are recorded
        as truncation with reasons instead of being silently dropped, and every
        variant carries requires_independent_verification=True (sharing the
        same sink never counts as independent confirmation).
        """
        search = bounded_variant_search(
            snapshot_data["files"],
            finding,
            max_variants=VARIANT_SEARCH_MAX_VARIANTS,
            max_files=VARIANT_SEARCH_MAX_FILES,
        )
        reasons = [search["reason"]] if search["reason"] else []
        unsearched = list(search["unsearched_files"])
        if snapshot_data["unsearched_files"]:
            unsearched.extend(snapshot_data["unsearched_files"])
            reasons.append(
                f"Snapshot read cap {VARIANT_SEARCH_MAX_FILES}: read "
                f"{len(snapshot_data['files'])} of {snapshot_data['total_files']} "
                "manifest files; the remaining paths were not searched."
            )
        if snapshot_data["read_errors"]:
            reasons.append(
                f"{len(snapshot_data['read_errors'])} snapshot file(s) skipped "
                "because they could not be read: "
                + "; ".join(snapshot_data["read_errors"])
            )
        truncated = bool(
            search["truncated"] or snapshot_data["unsearched_files"] or snapshot_data["read_errors"]
        )
        finding["variants"] = search["variants"]
        finding["variant_search"] = {
            "schema_version": "1.0",
            "searched_files": search["searched_files"],
            "total_files": snapshot_data["total_files"],
            "truncated": truncated,
            "reason": "; ".join(reasons),
            "unsearched_files": unsearched,
        }

    # ------------------------------------------------------------------
    # DSR-061 wiring: independent second opinion for High/Critical findings.
    # ------------------------------------------------------------------
    def _enqueue_second_opinion_tasks(
        self,
        conn: Any,
        run_id: str,
        findings: List[Dict[str, Any]],
        store: EventStore,
    ) -> List[str]:
        """Enqueue an independent second-opinion verify task per High/Critical confirmation.

        The task key carries the second-opinion marker and its priority is
        higher than normal verify work. If the task cannot be enqueued —
        including a spec that fails the task_spec contract (DSR-073) — the
        fact is recorded as a second_opinion_pending event: the run never
        pretends a finding was double-reviewed when it was not.
        """
        enqueued: List[str] = []
        for f in findings:
            if f.get("verdict") != "confirmed":
                continue
            severity = (f.get("rating") or {}).get("final_severity")
            if severity not in SECOND_OPINION_SEVERITIES:
                continue
            finding_id = f.get("finding_id", "")
            try:
                spec = self._validated_task_spec({
                    "schema_version": "1.0",
                    "task_kind": "verify",
                    "role": "verify",
                    "verify_task_id": f"vt-{uuid.uuid4().hex[:8]}",
                    "candidate_id": (f.get("candidate_refs") or [""])[0],
                    "second_opinion": True,
                    "target_finding_id": finding_id,
                    "target_severity": severity,
                    "output_contract": (
                        "Independently re-derive a verdict (confirmed | needs_validation | "
                        "rejected | unverified) for the target finding; agreement corroborates, "
                        "conflict demotes the finding to needs_validation with both sides kept."
                    ),
                    "requires_new_attempt": True,
                    "input": {"finding": f},
                })
                queue = TaskQueue(conn)
                task_id = queue.enqueue(
                    run_id=run_id,
                    task_key=f"{SECOND_OPINION_TASK_KEY_PREFIX}{finding_id}",
                    kind="verify",
                    spec=spec,
                    priority=SECOND_OPINION_TASK_PRIORITY,
                )
            except Exception as e:
                store.append_event(
                    run_id,
                    "second_opinion_pending",
                    "service",
                    {
                        "finding_id": finding_id,
                        "reason": f"second-opinion task could not be enqueued: {e}",
                    },
                )
                continue
            enqueued.append(finding_id)
            store.append_event(
                run_id,
                "second_opinion_enqueued",
                "service",
                {
                    "finding_id": finding_id,
                    "task_id": task_id,
                    "priority": SECOND_OPINION_TASK_PRIORITY,
                },
            )
        return enqueued

    # ------------------------------------------------------------------
    # §10.1 dossier alignment: candidates/ and findings/<id>/ publication.
    # ------------------------------------------------------------------
    def _publish_dossier_records(
        self,
        art_mgr: ArtifactManager,
        run_id: str,
        findings: List[Dict[str, Any]],
        events: List[Dict[str, Any]],
    ) -> None:
        """Publish the candidate pool and per-finding record/history artifacts.

        - ``candidates/final.json``: the deduplicated representative candidate
          pool — exactly the candidates verify tasks were built from — each
          entry carrying its provenance and the dedup ledger records that
          reference it (exact-duplicate merges and distinct-source
          suggestions alike). An empty pool is published as an empty list:
          absent candidates are stated, never implied.
        - ``findings/<finding_id>/record.json``: the merged finding record
          (the same records findings.json summarizes, in full).
        - ``findings/<finding_id>/history.json``: the finding's recorded
          status transitions (verified-findings storage, second-opinion
          enqueue/adjudication, pending or missing-target markers) in ledger
          order. A finding with no recorded transition carries an honest
          empty history list.
        """
        candidates = self._collect_final_candidates(art_mgr.conn, run_id)
        art_mgr.publish_artifact(
            run_id,
            CANDIDATE_POOL_ARTIFACT_KIND,
            "candidates/final.json",
            json.dumps(
                {"schema_version": "1.0", "candidates": candidates},
                indent=2, sort_keys=True, ensure_ascii=False,
            ).encode("utf-8"),
        )

        history_events = [
            e for e in events if e.get("event_type") in FINDING_TRANSITION_EVENT_TYPES
        ]
        used_dirs: Dict[str, str] = {}
        for finding in findings:
            finding_id = str(finding.get("finding_id") or "")
            dir_name = self._safe_dossier_dir_name(finding_id, used_dirs)
            art_mgr.publish_artifact(
                run_id,
                FINDING_RECORD_ARTIFACT_KIND,
                f"findings/{dir_name}/record.json",
                json.dumps(finding, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8"),
            )
            history = [
                {
                    "revision": e.get("revision"),
                    "occurred_at": e.get("occurred_at"),
                    "event_type": e.get("event_type"),
                    "payload": e.get("payload") or {},
                }
                for e in history_events
                if self._event_mentions_finding(e, finding_id)
            ]
            art_mgr.publish_artifact(
                run_id,
                FINDING_HISTORY_ARTIFACT_KIND,
                f"findings/{dir_name}/history.json",
                json.dumps(
                    {
                        "schema_version": "1.0",
                        "finding_id": finding_id,
                        "history": history,
                    },
                    indent=2, sort_keys=True, ensure_ascii=False,
                ).encode("utf-8"),
            )

    def _collect_final_candidates(self, conn: Any, run_id: str) -> List[Dict[str, Any]]:
        """Reconstruct the deduplicated representative candidate pool.

        The candidates are read from the verify tasks' persisted specs (the
        deduplication wiring only ever enqueues verify work for
        representatives, DSR-063); second-opinion specs carry a finding, not a
        candidate, and are skipped. Each entry is annotated with the dedup
        ledger records that reference it so provenance stays queryable from
        the dossier without replaying the event store.
        """
        dedup_records: List[Dict[str, Any]] = []
        for row in conn.execute(
            """
            SELECT event_type, payload_json FROM events
            WHERE run_id = ? AND event_type IN ('candidate_deduplicated', 'dedup_suggested')
            ORDER BY revision
            """,
            (run_id,),
        ).fetchall():
            try:
                payload = json.loads(row["payload_json"])
            except ValueError:
                continue
            if isinstance(payload, dict):
                dedup_records.append(dict(payload, event_type=row["event_type"]))

        pool: Dict[str, Dict[str, Any]] = {}
        for row in conn.execute(
            "SELECT spec_json FROM tasks WHERE run_id = ? AND kind = 'verify' ORDER BY task_id",
            (run_id,),
        ).fetchall():
            try:
                spec = json.loads(row["spec_json"])
            except ValueError:
                continue
            if not isinstance(spec, dict) or spec.get("second_opinion"):
                continue
            spec_input = spec.get("input") if isinstance(spec.get("input"), dict) else {}
            cand = spec_input.get("candidate")
            if not isinstance(cand, dict) or not cand.get("candidate_id"):
                continue
            cand_id = str(cand["candidate_id"])
            if cand_id in pool:
                continue  # the same representative; verify specs are idempotent
            entry = json.loads(json.dumps(cand, ensure_ascii=False))
            entry["dedup_records"] = [
                rec for rec in dedup_records
                if cand_id in (rec.get("candidate_ids") or [])
                or rec.get("representative_id") == cand_id
                or rec.get("merged_candidate_id") == cand_id
            ]
            pool[cand_id] = entry
        return [pool[cid] for cid in sorted(pool)]

    @staticmethod
    def _event_mentions_finding(event: Dict[str, Any], finding_id: str) -> bool:
        """True when a ledger event records a transition of this finding."""
        if not finding_id:
            return False
        payload = event.get("payload") or {}
        if payload.get("finding_id") == finding_id:
            return True
        ids = payload.get("finding_ids")
        return isinstance(ids, list) and finding_id in ids

    @staticmethod
    def _safe_dossier_dir_name(finding_id: str, used: Dict[str, str]) -> str:
        """Map a finding id to a filesystem-safe dossier directory name.

        Finding ids are worker- or program-supplied identifiers, never trusted
        path data: characters outside ``[A-Za-z0-9._-]`` are replaced, the
        name is length-capped, and a deterministic short-hash suffix resolves
        collisions so two distinct finding ids can never silently share one
        record directory.
        """
        base = re.sub(r"[^A-Za-z0-9._-]", "_", str(finding_id)).strip("._") or "finding"
        base = base[:72]
        if used.get(base, finding_id) != finding_id:
            suffix = hashlib.sha256(finding_id.encode("utf-8")).hexdigest()[:8]
            base = f"{base[:63]}-{suffix}"
        used[base] = finding_id
        return base

    def _load_run_findings(self, run_path: Path) -> Dict[str, Dict[str, Any]]:
        """Load stored findings (verified + adjudicated) keyed by finding_id."""
        stored: Dict[str, Dict[str, Any]] = {}
        for pattern in ("findings/verified-*.json", "findings/adjudicated-*.json"):
            for path in sorted(run_path.glob(pattern)):
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        records = json.load(f)
                except (OSError, ValueError):
                    continue
                for rec in records if isinstance(records, list) else []:
                    fid = rec.get("finding_id") if isinstance(rec, dict) else None
                    if fid:
                        stored[fid] = rec  # adjudicated files are read last and win
        return stored

    def _adjudicate_second_opinion(
        self,
        conn: Any,
        run_path: Path,
        run_id: str,
        claim: Dict[str, Any],
        worker_result: Dict[str, Any],
        store: EventStore,
    ) -> Optional[Dict[str, Any]]:
        """Adjudicate an independent second-opinion verify submission (DSR-061).

        Agreement corroborates the primary finding; a conflict demotes it to
        needs_validation while preserving both sides structurally. The
        adjudicated finding is published as its own artifact (adjudicated
        findings override the verified ones at finalize merge time).
        """
        spec = self._task_spec(conn, claim)
        target_id = spec.get("target_finding_id", "")
        records = worker_result.get("records", []) or []
        first = records[0] if records and isinstance(records[0], dict) else {}
        verdict = str(first.get("verdict", ""))
        reason = str(
            first.get("reason")
            or first.get("note")
            or (first.get("finding") or {}).get("title")
            or "second-opinion verdict submitted without an explicit reason"
        )
        anchor = first.get("anchor") if isinstance(first.get("anchor"), dict) else None

        primary = self._load_run_findings(run_path).get(target_id)
        if primary is None:
            store.append_event(
                run_id,
                "second_opinion_target_missing",
                "service",
                {"finding_id": target_id, "attempt_id": claim["attempt_id"]},
            )
            return None

        severity = (primary.get("rating") or {}).get("final_severity")
        if severity not in SECOND_OPINION_SEVERITIES:
            store.append_event(
                run_id,
                "second_opinion_not_applicable",
                "service",
                {"finding_id": target_id, "severity": severity or "unknown"},
            )
            return None

        adjudicated = json.loads(json.dumps(primary, ensure_ascii=False))
        try:
            adjudicated = Verifier(enforce_attempt_gate=True).adjudicate_second_opinion(
                adjudicated, verdict, reason, anchor
            )
        except InvalidInputError as e:
            store.append_event(
                run_id,
                "second_opinion_not_applicable",
                "service",
                {"finding_id": target_id, "reason": str(getattr(e, "message", e))},
            )
            return None

        adjudicated["run_id"] = run_id
        rel_path = f"findings/adjudicated-{claim['attempt_id']}.json"
        ArtifactManager(run_path, conn).publish_artifact(
            run_id, FINDINGS_ARTIFACT_KIND, rel_path,
            json.dumps([adjudicated], sort_keys=True, ensure_ascii=False).encode("utf-8"),
        )
        store.append_event(
            run_id,
            "second_opinion_adjudicated",
            "service",
            {
                "finding_id": target_id,
                "attempt_id": claim["attempt_id"],
                "resolution": (adjudicated.get("second_opinion") or {}).get("resolution", ""),
                "primary_verdict": (adjudicated.get("second_opinion") or {}).get("primary", {}).get("verdict", ""),
                "secondary_verdict": (adjudicated.get("second_opinion") or {}).get("secondary", {}).get("verdict", ""),
                "artifact": rel_path,
            },
        )
        return adjudicated

    # ------------------------------------------------------------------
    # HST -> LED/service wiring: trusted usage objects from host adapters.
    # ------------------------------------------------------------------
    def build_usage(
        self,
        usage: Optional[Dict[str, Any]] = None,
        attempt_id: Optional[str] = None,
        dimension: str = "tokens",
        unit: str = "tokens",
        source: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Build a trusted per-attempt usage object (DSR-033 wiring).

        Usage envelope contract (P0 fix): ``usage`` is the per-attempt usage
        dict the worker execution itself returned (the second element of the
        ``execute_worker`` tuple), captured from the same invocation that
        produced the result — so concurrent workers can never cross-attribute
        usage through a shared adapter slot. The submitting claim's
        ``attempt_id`` (this method's argument) ALWAYS wins: whatever
        attempt_id the worker dict carried is overwritten, so the returned
        record is bound to the attempt actually being submitted.

        Back-compat shim: the previous ``build_usage(adapter, attempt_id,
        ...)`` call shape still works — a non-dict first argument (an adapter
        object) is IGNORED and treated as "no usage supplied". The shared
        ``adapter.last_usage`` slot is no longer read anywhere (it
        cross-attributed attempts under real concurrency), so the shim yields
        an explicit ``unavailable`` record, never a silently swapped one.

        Host-reported numbers map to availability "exact" only when the host
        explicitly declared it, otherwise "estimated"; a missing or
        non-numeric usage block maps to "unavailable" with an explicit reason.
        Usage is never omitted: a submission always carries a usage object.
        """
        if usage is not None and not isinstance(usage, dict):
            # Legacy positional shape: the first argument was the adapter.
            usage = None
        if usage is not None and not attempt_id:
            attempt_id = usage.get("attempt_id") or None
        if not attempt_id:
            raise InvalidInputError("usage.attempt_id is required")

        record: Dict[str, Any] = {
            "schema_version": "1.0",
            "attempt_id": attempt_id,
            "dimension": dimension,
            "unit": unit,
            "source": source or (usage or {}).get("source") or "service",
        }
        if usage is None:
            record["availability"] = "unavailable"
            record["reason"] = "worker execution returned no usage block"
            return record

        availability = usage.get("availability")
        value = usage.get("value")
        if not isinstance(value, int) or isinstance(value, bool):
            # Schema-shaped dicts carry "value"; raw host usage blocks carry
            # typed counter fields instead — sum the numeric ones.
            numerics = [
                v for v in usage.values() if isinstance(v, int) and not isinstance(v, bool)
            ]
            value = sum(numerics) if numerics else None
        if availability == "unavailable" or value is None:
            record["availability"] = "unavailable"
            record["reason"] = (
                usage.get("reason")
                or (
                    "host reported no usable usage values"
                    if availability == "unavailable"
                    else "host usage block contained no numeric values"
                )
            )
            return record
        record["availability"] = availability if availability in ("exact", "estimated") else "estimated"
        record["value"] = value
        return record

    # ------------------------------------------------------------------
    # HST -> service wiring: AIMD-driven dispatch loop.
    # ------------------------------------------------------------------

    @staticmethod
    def conn_query_count(run_dir: str | Path, sql: str, params: tuple = ()) -> int:
        """One-shot read-only scalar query with a fresh connection."""
        conn = get_db_connection(Path(run_dir) / "events.db")
        try:
            return conn.execute(sql, params).fetchone()[0]
        finally:
            conn.close()

    def run_dispatch_loop(
        self,
        run_id: str,
        run_dir: str | Path,
        execute_fn: Callable[[Dict[str, Any]], Any],
        adapter: Any = None,
        controller: Optional[ConcurrencyController] = None,
        max_batches: Optional[int] = None,
        lease_seconds: int = 300,
        usage_dimension: str = "tokens",
        usage_unit: str = "tokens",
        usage_source: Optional[str] = None,
        sleep_fn: Callable[[float], None] = time.sleep,
    ) -> Dict[str, Any]:
        """Drive claim -> start -> execute -> submit with AIMD concurrency (DSR-064).

        Concurrency model (real parallel dispatch):
        - Every task has an independent lifecycle: ``next(batch_size=1)`` runs
          immediately before that task's execution, so no attempt ever holds a
          lease while queued behind other work (no whole-batch pre-claiming).
        - The in-flight cap follows the ConcurrencyController's CURRENT value
          (``controller.current``); tasks run on a
          ``concurrent.futures.ThreadPoolExecutor`` worker pool. AIMD maps
          per task: success -> ``on_success()`` (+1), failure -> ``on_failure()``
          (halve). Retry/backoff semantics are unchanged: TerminationUncertainError
          retains the attempt budget (no release) and retryable failures requeue
          within ``adapter.max_retries`` (quarantine + coverage gap beyond it).
        - Ledger mutations (claim/start/submit/fail) are serialized with an
          in-process ``threading.Lock``; BEGIN IMMEDIATE already serializes
          writers at the SQLite layer, the lock only avoids useless busy-timeout
          contention between this loop's own worker threads. ``execute_fn`` runs
          OUTSIDE the lock (it is the slow host call).

        Return contract (unchanged for CLI consumers):
        - ``stop_reason``: ``"queue_drained"`` when the task queue is empty;
          ``"budget_exhausted"`` when dispatch stopped against remaining queued
          tasks with a budget_exhausted ledger event;
          ``"verification_reserve_exhausted"`` when that event records the
          hunt claims being refused by the verification reserve floor
          (DSR-020) while non-hunt room remained (O-04: the budget-class
          stop that a real run mislabeled as blocked);
          ``"paused_or_blocked"`` when the run is not active (stop sequence)
          or no cause is recorded. ``None`` means the loop stopped on the
          caller-supplied task cap.
        - ``max_batches`` now caps TASK DISPATCH ROUNDS (one claimed task per
          round), not whole-batch claim rounds: once that many tasks have been
          claimed, no further tasks are claimed, in-flight tasks complete, and
          ``stop_reason`` is ``None``.
        - ``batches`` counts dispatched tasks (one claim round per task).
        - ``adapter``: host driver adapter; its ``max_retries`` bounds queue
          retries and its ``backoff_base``/``backoff_max`` bound the backoff
          sleep after retryable failures (slept by the failing worker only).
          ``execute_fn``'s usage envelope feeds the trusted usage object
          submitted for every attempt (built via ``build_usage``): the new
          contract returns ``(worker_result, usage_dict_or_None)`` from the
          SAME execution, so per-attempt usage can never be cross-attributed
          through shared adapter state (the former shared ``last_usage`` slot
          swapped attribution when two workers finished within each other's
          execute_fn tail — removed). A bare ``worker_result`` return is still
          accepted for backward compatibility; its usage then falls back to
          the legacy ``build_usage(adapter, ...)`` path, which now yields an
          explicit ``unavailable`` record instead of reading the shared slot.
        - ``sleep_fn`` stays injectable (used for the post-failure backoff).
        - TerminationUncertainError retains the attempt budget (no release) and
          is converted into an incomplete candidate reason at finalize.
        """
        # Claims, starts and submits all flow through the service entry points
        # (next/start/submit), which open and version-check their own handles.
        ctrl = controller or ConcurrencyController()
        max_retries = int(getattr(adapter, "max_retries", 2) or 2)
        backoff_base = float(getattr(adapter, "backoff_base", 0.5))
        backoff_max = float(getattr(adapter, "backoff_max", 30.0))

        db_lock = threading.Lock()
        ctrl_lock = threading.Lock()
        counters = {
            "dispatched": 0,
            "submitted": 0,
            "failed": 0,
            "budget_retained": 0,
        }
        # Set when the caller-supplied task cap is reached: worker slots then
        # finish their current task and stop claiming new ones.
        stop_claiming = threading.Event()

        def execute_one_task(_slot: int) -> tuple:
            """Claim ONE task and drive it through the full pipeline.

            Returns an (outcome, task_id) tuple; outcomes:
            submitted / failed / retained / empty / blocked / stopped.
            """
            if stop_claiming.is_set():
                return ("stopped", None)
            # Claims flow through service.next so every dispatched attempt is
            # served with its published prompt packet (IFC-02); claims whose
            # packet cannot be rendered are released back to the queue inside
            # next() and never reach execute_fn. batch_size=1 keeps the claim
            # immediately adjacent to this task's own execution.
            with db_lock:
                # The caller cap is enforced inside the claim critical section,
                # so a task is never claimed past max_batches even when slots
                # were already queued on the pool.
                if stop_claiming.is_set() or (
                    max_batches is not None and counters["dispatched"] >= max_batches
                ):
                    return ("stopped", None)
                try:
                    claims = self.next(
                        run_id,
                        run_dir,
                        batch_size=1,
                        lease_seconds=lease_seconds,
                        worker_id="service_loop",
                    )
                except InvalidStateError:
                    # Stop sequence (DSR-066): dispatch is only granted to
                    # active runs; report honestly via the stop reason.
                    return ("blocked", None)
                if claims:
                    # Dispatch accounting stays inside the claim critical
                    # section so the cap is exact under concurrency.
                    counters["dispatched"] += 1
            if not claims:
                # DA-06 dimension-aware stop: an empty claim usually means the
                # hunt budget hit its verification-reserve floor. Verify and
                # second-opinion tasks live behind that protected floor and
                # MUST still be dispatched (DSR-066/DSR-020) -- otherwise a
                # budget-first audit ends with every candidate unverified.
                # Check first (cheap, no latency); sleep only when queued
                # verification work actually exists.
                for _ in range(2):
                    pending_verify = self.conn_query_count(
                        run_dir,
                        "SELECT count(*) AS cnt FROM tasks WHERE run_id = ? "
                        "AND kind IN ('verify') AND state = 'queued'",
                        (run_id,),
                    )
                    if not pending_verify:
                        return ("empty", None)
                    sleep_fn(1.0)
                    claims = self.next(
                        run_id,
                        run_dir,
                        batch_size=1,
                        lease_seconds=lease_seconds,
                        worker_id="service_loop",
                    )
                    if claims:
                        counters["dispatched"] += 1
                        break
                if not claims:
                    return ("empty", None)
            claim = claims[0]
            with db_lock:
                self.start(run_dir, claim)
            try:
                outcome = execute_fn(claim)
            except TerminationUncertainError as e:
                # Budget is retained, never released (DSR-064).
                with db_lock:
                    self.report_host_failure(run_dir, claim, e, max_retries=max_retries)
                with ctrl_lock:
                    ctrl.on_failure()
                    counters["budget_retained"] += 1
                    counters["failed"] += 1
                return ("retained", claim["task_id"])
            except AuditError as e:
                with db_lock:
                    self.report_host_failure(run_dir, claim, e, max_retries=max_retries)
                with ctrl_lock:
                    ctrl.on_failure()
                    counters["failed"] += 1
                    failures = counters["failed"]
                # The failing worker backs off; other in-flight tasks are not
                # delayed by this host failure.
                sleep_fn(compute_backoff_delay(failures, backoff_base, backoff_max))
                return ("failed", claim["task_id"])
            except Exception as e:  # noqa: BLE001 -- per-task isolation
                # SR-019/DSR-066: a single malformed worker output or an
                # unexpected internal error must fail THAT task honestly and
                # never take down the whole audit -- the remaining queued
                # units stay visible as explicit incomplete coverage.
                with db_lock:
                    self.report_host_failure(
                        run_dir,
                        claim,
                        HostFailureError(
                            f"internal error while processing task: {type(e).__name__}: {e}",
                            retryable=True,
                        ),
                        max_retries=max_retries,
                    )
                with ctrl_lock:
                    ctrl.on_failure()
                    counters["failed"] += 1
                    failures = counters["failed"]
                sleep_fn(compute_backoff_delay(failures, backoff_base, backoff_max))
                return ("failed", claim["task_id"])

            # Usage envelope contract (P0 fix): the new execute_fn shape
            # returns (worker_result, usage_dict_or_None) — the usage captured
            # by the SAME execution that produced the result, so two workers
            # overlapping through each other's submit tail each settle their
            # OWN usage. A bare worker_result (pre-envelope consumers) is
            # still accepted: its usage falls back to the legacy
            # build_usage(adapter, ...) path, which no longer reads the shared
            # adapter slot and therefore yields an explicit unavailable
            # record, never a cross-attributed one.
            if isinstance(outcome, tuple) and len(outcome) == 2:
                result, captured_usage = outcome
                usage = self.build_usage(
                    captured_usage,
                    claim["attempt_id"],
                    dimension=usage_dimension,
                    unit=usage_unit,
                    source=usage_source,
                )
            else:
                result = outcome
                usage = self.build_usage(
                    adapter,
                    claim["attempt_id"],
                    dimension=usage_dimension,
                    unit=usage_unit,
                    source=usage_source,
                )
            digest = sha256_text(json.dumps(result, sort_keys=True, ensure_ascii=False))
            try:
                with db_lock:
                    self.submit(run_dir, claim, result, digest, usage=usage)
            except InvalidInputError as e:
                # DSR-018 bounded format correction: a schema/semantic
                # rejection keeps the task (not the attempt) eligible for a
                # bounded retry with a fresh attempt and reservation; after
                # max_retries the task is quarantined with an explicit
                # coverage gap. The malformed output is never normalized
                # into a success (SR-025).
                with db_lock:
                    self.report_host_failure(
                        run_dir,
                        claim,
                        HostFailureError(
                            f"worker output rejected by contract: {e.message}",
                            retryable=True,
                        ),
                        max_retries=max_retries,
                    )
                with ctrl_lock:
                    ctrl.on_failure()
                    counters["failed"] += 1
                    failures = counters["failed"]
                sleep_fn(compute_backoff_delay(failures, backoff_base, backoff_max))
                return ("failed", claim["task_id"])
            except StaleAttemptError as e:
                # Real workers can exceed the claim lease (e.g. an LLM call
                # longer than lease_seconds). DDS-06: the late result is
                # rejected and the task is atomically requeued with a fresh
                # generation -- surface that as a task-level retryable
                # failure instead of crashing the whole driver loop.
                with db_lock:
                    self.report_host_failure(
                        run_dir,
                        claim,
                        HostFailureError(
                            f"claim lease expired before submit: {e.message}",
                            retryable=True,
                        ),
                        max_retries=max_retries,
                    )
                with ctrl_lock:
                    ctrl.on_failure()
                    counters["failed"] += 1
                    failures = counters["failed"]
                sleep_fn(compute_backoff_delay(failures, backoff_base, backoff_max))
                return ("failed", claim["task_id"])
            with ctrl_lock:
                ctrl.on_success()
                counters["submitted"] += 1
            return ("submitted", claim["task_id"])

        stop_reason: Optional[str] = None
        drain_seen = False
        blocked_seen = False
        # Pool sizing: the controller's maximum bounds the in-flight cap, so a
        # pool of that size can always satisfy the current AIMD level.
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=max(1, ctrl.maximum), thread_name_prefix="dispatch"
        ) as pool:
            in_flight: set = set()
            while True:
                # 1. Reap finished slots (counters/AIMD already updated inside).
                for fut in [f for f in in_flight if f.done()]:
                    in_flight.discard(fut)
                    outcome, _task_id = fut.result()
                    if outcome in ("empty", "stopped"):
                        drain_seen = True
                    elif outcome == "blocked":
                        blocked_seen = True
                    else:
                        # Work completed: its submission may have enqueued
                        # follow-up tasks, so an earlier empty claim no longer
                        # proves the queue is drained — re-probe with a fresh
                        # claim before deciding to stop.
                        drain_seen = False
                        blocked_seen = False

                # 2. Caller cap: no further tasks are claimed once the
                # dispatched count reaches max_batches.
                if max_batches is not None and counters["dispatched"] >= max_batches:
                    stop_claiming.set()

                # 3. Stop decisions BEFORE refilling, so fresh probe slots can
                # never keep the loop alive after the pipeline is empty.
                if stop_claiming.is_set() and not in_flight:
                    # Stopped by the caller-supplied task cap: neither the
                    # queue nor the run state caused the stop.
                    stop_reason = None
                    break
                if (drain_seen or blocked_seen) and not in_flight:
                    stop_reason = self._dispatch_stop_reason(run_id, run_dir)
                    break

                # 4. Fill the pipeline up to the CURRENT AIMD in-flight cap.
                # An observed empty claim suppresses probing while other slots
                # are still running: they may enqueue follow-up work, and their
                # completion resets the drain observation, so a fresh claim is
                # only submitted after real work finished (no probe storm).
                if not stop_claiming.is_set() and not drain_seen and not blocked_seen:
                    with ctrl_lock:
                        target = ctrl.current
                    while len(in_flight) < target:
                        in_flight.add(pool.submit(execute_one_task, len(in_flight)))

                # 5. Nothing new to submit: wait for a slot to finish (a hunt
                # submission may enqueue verify work, so drain is only decided
                # once the pipeline is empty).
                if in_flight:
                    concurrent.futures.wait(
                        list(in_flight), timeout=0.05,
                        return_when=concurrent.futures.FIRST_COMPLETED,
                    )

        return {
            "batches": counters["dispatched"],
            "submitted": counters["submitted"],
            "failed": counters["failed"],
            "budget_retained": counters["budget_retained"],
            "concurrency": ctrl.current,
            "stop_reason": stop_reason,
        }

    def _dispatch_stop_reason(self, run_id: str, run_dir: str | Path) -> str:
        """Disambiguate an empty-claim stop honestly (state contract).

        - ``"paused_or_blocked"``: the run is not active (stop sequence) or no
          cause event is recorded;
        - ``"verification_reserve_exhausted"``: queued tasks remain and a
          budget_exhausted event shows a HUNT claim was refused by the
          verification reserve floor (DSR-020) while non-hunt budget room
          still existed — the dispatch stop was caused by the verify
          protection, not by a fully spent budget (O-04, run lessons);
        - ``"budget_exhausted"``: queued tasks remain and a budget_exhausted
          event explains why they were not dispatched;
        - ``"queue_drained"``: the queue is empty.
        """
        conn = self._open_run_db(run_dir)
        try:
            row = conn.execute(
                "SELECT state FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            if row is None or row["state"] != "active":
                return "paused_or_blocked"
            queued = conn.execute(
                "SELECT count(*) AS cnt FROM tasks WHERE run_id = ? AND state = 'queued'",
                (run_id,),
            ).fetchone()["cnt"]
            if queued == 0:
                return "queue_drained"
            budget_events = conn.execute(
                "SELECT payload_json FROM events "
                "WHERE run_id = ? AND event_type = 'budget_exhausted'",
                (run_id,),
            ).fetchall()
            if not budget_events:
                return "paused_or_blocked"
            if self._is_verification_reserve_stop(conn, run_id, budget_events):
                return "verification_reserve_exhausted"
            return "budget_exhausted"
        finally:
            conn.close()

    @staticmethod
    def _is_verification_reserve_stop(
        conn: Any,
        run_id: str,
        budget_event_payloads: List[Any],
    ) -> bool:
        """True when the recorded claim refusals are the verify-floor case.

        The claim path's BudgetExhaustedError event payload already carries
        the dimension and the ledger's own refusal reason (O-04: consume it
        instead of re-deriving). A hunt refusal whose reason names the
        verify protection (``protected for verify``, BudgetLedger wording)
        is the floor case — but only while the tasks dimension still had
        room for a non-hunt claim; once available is 0 the stop is a plain
        budget exhaustion, whatever the refused claim's kind was.
        """
        floor_refusal_seen = False
        for row in budget_event_payloads:
            try:
                payload = json.loads(row["payload_json"])
            except (KeyError, TypeError, ValueError):
                continue
            reason = str(payload.get("reason", ""))
            if "protected for verify" in reason:
                floor_refusal_seen = True
                break
        if not floor_refusal_seen:
            return False
        dim_row = conn.execute(
            "SELECT limit_val, settled, reserved FROM budget_dimensions "
            "WHERE run_id = ? AND dimension = 'tasks'",
            (run_id,),
        ).fetchone()
        if dim_row is None:
            return False
        available = dim_row["limit_val"] - (dim_row["settled"] + dim_row["reserved"])
        return available > 0

    def status(self, run_id: str, run_dir: str | Path) -> Dict[str, Any]:
        """Retrieve current run status."""
        conn = self._open_run_db(run_dir)
        run_row = conn.execute("SELECT state, revision, snapshot_id FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        if not run_row:
            raise InvalidInputError(f"Run {run_id} not found")

        tasks_summary = {}
        for r in conn.execute("SELECT state, count(*) as cnt FROM tasks WHERE run_id = ? GROUP BY state", (run_id,)).fetchall():
            tasks_summary[r["state"]] = r["cnt"]

        budgets = BudgetLedger(conn).get_summary(run_id)

        return {
            "run_id": run_id,
            "snapshot_id": run_row["snapshot_id"],
            "state": run_row["state"],
            "revision": run_row["revision"],
            "tasks": tasks_summary,
            "budgets": budgets,
        }

    def pause(self, run_id: str, run_dir: str | Path, reason: str = "user_requested") -> Dict[str, Any]:
        """Pause run dispatch and report the in-flight attempt state (IFC-06).

        Returns a dict contract (not a bare revision): run_id, state, revision,
        reason, in_flight_tasks and in_flight_attempt_ids for the attempts
        currently held under a valid claim lease. In-flight leases are reported
        honestly — pausing stops NEW dispatch (stop sequence) but does not
        silently revoke leases that workers already hold.
        """
        if not isinstance(reason, str) or not reason.strip():
            raise InvalidInputError("pause requires a non-empty reason")
        if len(reason) > PAUSE_REASON_MAX_LENGTH:
            raise InvalidInputError(
                f"pause reason exceeds {PAUSE_REASON_MAX_LENGTH} characters",
                details={"length": len(reason)},
            )
        conn = self._open_run_db(run_dir)
        row = conn.execute(
            "SELECT state FROM runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        if not row:
            raise InvalidInputError(f"Run {run_id} not found")

        in_flight_rows = conn.execute(
            """
            SELECT a.attempt_id
            FROM attempts a
            JOIN tasks t ON a.task_id = t.task_id
            WHERE t.run_id = ? AND a.status IN ('claimed', 'running') AND a.expires_at >= ?
            ORDER BY a.attempt_id
            """,
            (run_id, utc_now_iso()),
        ).fetchall()
        in_flight_attempt_ids = [r["attempt_id"] for r in in_flight_rows]

        conn.execute("UPDATE runs SET state = 'paused' WHERE run_id = ?", (run_id,))
        revision = EventStore(conn).append_event(
            run_id,
            "run_paused",
            "service",
            {
                "reason": reason,
                "in_flight_tasks": len(in_flight_attempt_ids),
                "in_flight_attempt_ids": in_flight_attempt_ids,
            },
        )
        return {
            "run_id": run_id,
            "state": "paused",
            "revision": revision,
            "reason": reason,
            "in_flight_tasks": len(in_flight_attempt_ids),
            "in_flight_attempt_ids": in_flight_attempt_ids,
        }

    def report_host_failure(
        self,
        run_dir: str | Path,
        claim: Dict[str, Any],
        error: AuditError,
        max_retries: int = 2,
    ) -> Dict[str, Any]:
        """Consume a host/worker failure reported for a claimed attempt (DSR-065).

        Retryable errors requeue the task while retries remain (each retry gets a
        new attempt and a fresh reservation with an incremented generation);
        non-retryable errors, or retryable errors beyond max_retries, quarantine
        the task and record a coverage gap. The error is never normalized into a
        successful result.

        Errors carrying ``retains_budget=True`` (TerminationUncertainError,
        DSR-064) quarantine the attempt WITHOUT releasing its budget
        reservation, record the uncertainty as an event, and become an
        incomplete candidate reason at finalize.
        """
        conn = self._open_run_db(run_dir)
        queue = TaskQueue(conn)
        if getattr(error, "retains_budget", False):
            return queue.retain_attempt_budget(
                run_id=claim["run_id"],
                task_id=claim["task_id"],
                attempt_id=claim["attempt_id"],
                generation=claim["generation"],
                claim_token=claim["claim_token"],
                reason=str(getattr(error, "message", error)),
            )
        return queue.fail_attempt(
            run_id=claim["run_id"],
            task_id=claim["task_id"],
            attempt_id=claim["attempt_id"],
            generation=claim["generation"],
            claim_token=claim["claim_token"],
            reason=str(getattr(error, "message", error)),
            retryable=bool(getattr(error, "retryable", False)),
            max_retries=max_retries,
        )

    def resume(self, run_id: str, run_dir: str | Path) -> Dict[str, Any]:
        """Verify integrity and resume a paused run (IFC-06 / DSR-072 / DSR-019).

        The full gate before a paused run may continue:
        1. version compatibility check (DSR-072, via _open_run_db);
        2. the persisted run state must be 'paused' (InvalidStateError otherwise);
        3. artifact integrity (missing/tampered references raise CorruptRunError);
        4. snapshot integrity: every snapshot file's content SHA-256 is
           recomputed and the manifest root hash rebuilt with the snapshot
           module's own capability; any drift raises CorruptRunError.
        Only after all checks pass is the paused state explicitly re-affirmed
        and the run_resumed event appended. Activation back to 'active' stays
        with activate().
        """
        run_path = Path(run_dir)
        conn = self._open_run_db(run_path)

        run_row = conn.execute("SELECT state FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        if not run_row:
            raise InvalidInputError(f"Run {run_id} not found")
        if run_row["state"] != "paused":
            raise InvalidStateError(
                f"Run {run_id} is in state '{run_row['state']}'; only paused runs can be resumed"
            )

        ArtifactManager(run_path, conn).verify_artifacts(run_id)
        root_hash = self._verify_snapshot_integrity(run_path)

        conn.execute("UPDATE runs SET state = 'paused' WHERE run_id = ?", (run_id,))
        EventStore(conn).append_event(
            run_id,
            "run_resumed",
            "service",
            {
                "snapshot_root_hash": root_hash,
                "snapshot_integrity": "verified",
                "artifact_integrity": "verified",
            },
        )
        return {
            "run_id": run_id,
            "state": "paused",
            "verified": True,
            "snapshot_integrity": "verified",
        }

    def _verify_snapshot_integrity(self, run_path: Path) -> str:
        """Recompute snapshot content hashes against the manifest root hash.

        Uses the snapshot module's own root-hash capability (manifest.compute_root_hash)
        over freshly read file contents; any missing file or hash drift raises
        CorruptRunError (fail closed, DSR-019).
        """
        with open(run_path / "snapshot" / "manifest.json", "r", encoding="utf-8") as f:
            manifest = json.load(f)
        recomputed_files: List[Dict[str, Any]] = []
        for entry in manifest.get("files", []):
            path = entry["path"]
            file_path = run_path / "snapshot" / path
            try:
                data = file_path.read_bytes()
            except OSError as e:
                raise CorruptRunError(
                    f"Snapshot file missing or unreadable during resume: {path}",
                    details={"path": path, "detail": str(e)},
                )
            recomputed_files.append({
                "path": path,
                "file_type": entry.get("file_type", "regular"),
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            })
        recomputed_root = compute_root_hash(recomputed_files)
        if recomputed_root != manifest.get("root_hash"):
            raise CorruptRunError(
                "Snapshot integrity verification failed: recomputed root hash "
                "does not match the manifest root hash",
                details={
                    "recomputed": recomputed_root,
                    "manifest": manifest.get("root_hash", ""),
                },
            )
        return recomputed_root

    def finalize(
        self,
        run_id: str,
        run_dir: str | Path,
        findings: Optional[List[Dict[str, Any]]] = None,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Finalize run, evaluate gates against real data, and publish reports (DSR-076).

        Artifact integrity is verified before anything else: a corrupt run is
        moved to state 'corrupt' and refuses to produce any report. Attempts
        still held under a valid claim lease block finalize outright
        (InvalidStateError): SD-06 §5.1 requires the planned scope to be fully
        processed before a terminal state is reached. G1..G3 are fed with real
        run data (plan vs COMPLETED hunt tasks, dispatched vs submitted task
        reconciliation, semantic validation pass accounting); a planned scope
        that was never dispatched (or whose recon/verify work never finished)
        additionally forces the 'unprocessed_units' incomplete reason.
        G4 (user-confirmed ordering fix) is evaluated AFTER the report stage
        published its artifacts: the gate reads back the published REPORT.md
        (generation marker + sanitization spot check) and reconciles the
        artifacts table generation. A failing G4 forces the terminal state to
        'incomplete' (incomplete_reasons gains 'g4_failed') and the reports
        are re-published so the on-disk dossier states the true terminal
        state. Runs with gate failures, budget exhaustion, unverified
        candidates, or unprocessed plan scope end 'incomplete', never
        'complete'.
        """
        run_path = Path(run_dir)
        conn = self._open_run_db(run_path)
        art_mgr = ArtifactManager(run_dir, conn)

        run_row = conn.execute("SELECT state FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        if not run_row:
            raise InvalidInputError(f"Run {run_id} not found")
        if run_row["state"] in ("complete", "corrupt"):
            raise InvalidStateError(f"Run {run_id} already reached terminal state '{run_row['state']}'")

        # SD-06 §5.1 / SR-012: the 'complete' terminal state means the planned
        # scope finished processing. Attempts still held under a valid claim
        # lease may still produce results, so finalizing over them would
        # silently discard in-flight work — fail closed instead.
        in_flight_claims = conn.execute(
            """
            SELECT count(*) AS cnt
            FROM attempts a
            JOIN tasks t ON a.task_id = t.task_id
            WHERE t.run_id = ? AND a.status IN ('claimed', 'running') AND a.expires_at >= ?
            """,
            (run_id, utc_now_iso()),
        ).fetchone()["cnt"]
        if in_flight_claims:
            raise InvalidStateError(
                f"Run {run_id} still holds {in_flight_claims} attempt(s) under a valid "
                "claim lease; finalize requires the plan scope to be fully processed. "
                "Pause the run first, or wait for the leases to expire and reclaim "
                "the attempts, then finalize."
            )

        conn.execute("UPDATE runs SET state = 'finalizing' WHERE run_id = ?", (run_id,))

        # DSR-076: verify artifact integrity before any report generation.
        # Corrupt runs must never yield a report or a forged terminal state.
        try:
            art_mgr.verify_artifacts(run_id)
        except CorruptRunError:
            conn.execute("UPDATE runs SET state = 'corrupt' WHERE run_id = ?", (run_id,))
            EventStore(conn).append_event(
                run_id,
                "run_corrupted",
                "service",
                {"reason": "artifact verification failed during finalize"},
            )
            raise

        # Load snapshot manifest and plan. The plan is read from its §10.1
        # location with a read-only fallback to the legacy flat plan.json, so
        # a pre-§10.1 dossier can still be finalized/read (DSR-072) without
        # any in-place migration.
        with open(run_path / "snapshot" / "manifest.json", "r", encoding="utf-8") as f:
            manifest_dict = json.load(f)
        plan_dict = self._load_plan(run_path)

        # Merge caller-supplied findings with findings persisted by verify-task
        # submissions (ANA -> LED wiring). Verified findings are loaded first,
        # then second-opinion adjudications override them by finding_id (a
        # conflict demotes the stored finding to needs_validation). Caller
        # findings get the run_id stamp here, so every finding evaluated below
        # is bound to this run.
        merged_findings: Dict[str, Dict[str, Any]] = {}
        for f in findings or []:
            if isinstance(f, dict):
                merged_findings[f.get("finding_id") or f"anon-{len(merged_findings)}"] = f
        for pattern in ("findings/verified-*.json", "findings/adjudicated-*.json"):
            for vf_path in sorted(run_path.glob(pattern)):
                try:
                    with open(vf_path, "r", encoding="utf-8") as f:
                        stored = json.load(f)
                except (OSError, ValueError) as e:
                    raise CorruptRunError(
                        f"Verified findings artifact unreadable: {vf_path.name}",
                        details={"detail": str(e)},
                    )
                for f in stored if isinstance(stored, list) else []:
                    merged_findings[f.get("finding_id") or f"anon-{len(merged_findings)}"] = f
        # SR-011 at the merge point (reports derive from records): a stored
        # confirmed finding without rating factor reasons cannot be presented
        # as a rated confirmed finding in the report -- demote honestly to
        # needs_validation, preserving all verified evidence (RUN-LESSONS
        # real run-011: verified findings lacked rating factors).
        for f in merged_findings.values():
            if f.get("verdict") != "confirmed":
                continue
            rating = f.get("rating") or {}
            nested = rating.get("factor_reasons") if isinstance(rating.get("factor_reasons"), dict) else {}
            missing = [
                k for k in ("impact_why", "exploitability_why")
                if not str(nested.get(k) or rating.get(k) or "").strip()
            ]
            if missing:
                f["verdict"] = "needs_validation"
                f["demoted_from"] = "confirmed"
                f.setdefault("blockers", []).extend(
                    f"missing rating factor reason: {k}" for k in missing
                )
                f["validation_plan"] = (
                    "re-rate with impact/exploitability factor reasons and "
                    "re-submit through an independent verification attempt"
                )
                f["rating"] = Verifier._pending_rating(
                    int(rating.get("impact") or 3),
                    int(rating.get("exploitability") or 3),
                )

        all_findings = list(merged_findings.values())

        # DSR-066: candidates whose verify task never completed before finalize
        # are surfaced as explicit unverified findings instead of silently
        # disappearing with the queued/failed verify work. Candidates that
        # already carry a verified/adjudicated result are not duplicated.
        verified_candidate_ids = {
            cid
            for f in all_findings
            for cid in (f.get("candidate_refs") or [])
            if isinstance(cid, str) and cid
        }
        for row in conn.execute(
            """
            SELECT task_id, state, spec_json FROM tasks
            WHERE run_id = ? AND kind = 'verify' AND state NOT IN ('done', 'quarantined')
            ORDER BY task_id
            """,
            (run_id,),
        ).fetchall():
            try:
                spec = json.loads(row["spec_json"])
            except ValueError:
                continue
            spec_input = spec.get("input") if isinstance(spec.get("input"), dict) else {}
            cand = spec_input.get("candidate")
            if not isinstance(cand, dict):
                # Second-opinion tasks are accounted via second_opinion_pending.
                continue
            cand_id = str(cand.get("candidate_id") or spec.get("candidate_id") or "")
            if not cand_id or cand_id in verified_candidate_ids:
                continue
            verified_candidate_ids.add(cand_id)
            verify_task_id = str(spec.get("verify_task_id", ""))
            all_findings.append({
                "schema_version": "1.0",
                "finding_id": f"F-UNVERIFIED-{cand_id}",
                "candidate_refs": [cand_id],
                "verdict": "unverified",
                "evidence_level": "E1",
                "unverified_reason": (
                    UNVERIFIED_SYNTHETIC_REASON
                    if row["state"] != "quarantined"
                    else "verification_task_quarantined_after_retries"
                ),
                "issue": cand.get("issue", "unknown"),
                "source": cand.get("source", {}),
                "sink": cand.get("sink", {}),
                "verify_task_id": verify_task_id,
                "verify_task_state": row["state"],
                "provenance": {
                    "candidates": [cand_id],
                    "hunt_tasks": list((cand.get("provenance") or {}).get("hunt_tasks", [])),
                    "verify_tasks": [verify_task_id],
                },
            })

        for f in all_findings:
            f.setdefault("run_id", run_id)

        # Calculate coverage
        cov_calc = CoverageCalculator(manifest_dict.get("files", []))
        for row in conn.execute("SELECT path, dimension, start_line, end_line FROM coverage_intervals WHERE run_id = ?", (run_id,)).fetchall():
            cov_calc.record_interval(row["path"], row["dimension"], row["start_line"], row["end_line"])
        coverage_summary = cov_calc.get_summary()

        store = EventStore(conn)
        events = store.get_events(run_id)
        current_rev = conn.execute("SELECT revision FROM runs WHERE run_id = ?", (run_id,)).fetchone()["revision"]

        # §10.1 dossier alignment: publish the merged candidate pool
        # (candidates/final.json) and, per finding, the full record plus its
        # status-transition history (findings/<finding_id>/{record,history}.json).
        # These dossier artifacts carry no report generation id, so they do not
        # interfere with the G4 generation reconciliation below; they are
        # hashed into the artifact ledger like every published artifact.
        self._publish_dossier_records(art_mgr, run_id, all_findings, events)

        # SR-020 / DSR-067: cost telemetry from real ledger data — stage task
        # counts, the executed report stage, usage_records aggregation and the
        # retry count derived from the attempts table.
        cost_tracker = CostTracker()
        for r in conn.execute("SELECT kind, count(*) as cnt FROM tasks WHERE run_id = ? GROUP BY kind", (run_id,)).fetchall():
            for _ in range(r["cnt"]):
                cost_tracker.record_task(r["kind"])
        for _ in range(REPORT_STAGE_TASKS):
            cost_tracker.record_task("report")
        # O-03: the executed denominator comes from the ledger's processed
        # terminal states (settled done / quarantined / failed) — never from
        # the enqueued plan scope, which the two COST.md totals report
        # separately. The synthesized report stage is the one stage finalize
        # itself executes.
        executed_counts = {
            r["kind"]: r["cnt"]
            for r in conn.execute(
                f"SELECT kind, count(*) AS cnt FROM tasks WHERE run_id = ? "
                f"AND state IN ({','.join('?' * len(EXECUTED_TASK_STATES))}) GROUP BY kind",
                (run_id, *EXECUTED_TASK_STATES),
            ).fetchall()
        }
        executed_counts["report"] = executed_counts.get("report", 0) + REPORT_STAGE_TASKS
        cost_tracker.set_executed_tasks(executed_counts)
        self._apply_usage_records(conn, run_id, cost_tracker)
        cost_metrics = cost_tracker.compute_metrics(
            coverage_summary.get("total_inventoried_lines", 0),
            len([f for f in all_findings if f.get("verdict") == "confirmed"]),
        )

        # --- Real gate inputs (DSR-076) -------------------------------------
        # G1: plan/report unit inventory vs DB COMPLETED hunt task inventory.
        # Only analyze-disposition units are planned as hunt work (DSR-056);
        # older plans without the hunt_units field fall back to the full unit
        # count. Counting only state='done' tasks closes the zero-dispatch
        # blind spot: enqueued-but-never-processed units no longer reconcile.
        plan_units = plan_dict.get("hunt_units", len(plan_dict.get("units", [])))
        db_hunt_tasks = conn.execute(
            "SELECT count(*) AS cnt FROM tasks WHERE run_id = ? AND kind = 'hunt' AND state = 'done'",
            (run_id,),
        ).fetchone()["cnt"]
        g1_res = GateEvaluator.evaluate_g1(plan_units, db_hunt_tasks, [], current_rev)

        # SR-012/SR-026/DSR-076 (plan-coverage invariant): planned hunt work
        # with no attempt record at all was never dispatched; recon/verify
        # tasks that never reached done (verify: or an explicit quarantine)
        # mean the plan scope was not fully processed. Either way the run
        # cannot claim the 'complete' terminal state.
        hunt_attempt_count = conn.execute(
            """
            SELECT count(*) AS cnt
            FROM attempts a JOIN tasks t ON a.task_id = t.task_id
            WHERE t.run_id = ? AND t.kind = 'hunt'
            """,
            (run_id,),
        ).fetchone()["cnt"]
        recon_unprocessed = conn.execute(
            "SELECT count(*) AS cnt FROM tasks WHERE run_id = ? AND kind = 'recon' AND state != 'done'",
            (run_id,),
        ).fetchone()["cnt"]
        verify_unprocessed = conn.execute(
            """
            SELECT count(*) AS cnt FROM tasks
            WHERE run_id = ? AND kind = 'verify' AND state NOT IN ('done', 'quarantined')
            """,
            (run_id,),
        ).fetchone()["cnt"]

        # G2: submitted vs dispatched task reconciliation + finding integrity.
        dispatched_count = conn.execute(
            f"SELECT count(*) AS cnt FROM tasks WHERE run_id = ? AND state IN ({','.join('?' * len(DISPATCHED_TASK_STATES))})",
            (run_id, *DISPATCHED_TASK_STATES),
        ).fetchone()["cnt"]
        done_count = conn.execute(
            "SELECT count(*) AS cnt FROM tasks WHERE run_id = ? AND state = 'done'",
            (run_id,),
        ).fetchone()["cnt"]
        in_flight_count = conn.execute(
            """
            SELECT count(*) AS cnt
            FROM attempts a
            JOIN tasks t ON a.task_id = t.task_id
            WHERE t.run_id = ? AND a.status IN ('claimed', 'running') AND a.expires_at >= ?
            """,
            (run_id, utc_now_iso()),
        ).fetchone()["cnt"]
        g2_res = GateEvaluator.evaluate_g2(
            all_findings,
            current_rev,
            submitted_tasks=done_count,
            dispatched_tasks=dispatched_count,
            in_flight_tasks=in_flight_count,
        )

        # G3: findings that all pass semantic validation vs total findings.
        # The validator is bound to this run's id and manifest, so cross-run
        # provenance references and stale anchors fail the gate for real
        # (DSR-010 wiring: findings carry the service-stamped run_id).
        semantic_validator = SemanticValidator(manifest=manifest_dict, current_run_id=run_id)
        validated_count = 0
        for f in all_findings:
            try:
                semantic_validator.validate_finding(f)
                validated_count += 1
            except AuditError:
                validated_count += 0
        g3_res = GateEvaluator.evaluate_g3(len(all_findings), validated_count, "gen-final", current_rev)

        # Verify-task completion accounting (ANA -> LED wiring): verify tasks
        # reconcile into G2 through the dispatched/submitted counts above; the
        # completion ratio is reported explicitly alongside them.
        verify_rows = conn.execute(
            "SELECT state, count(*) AS cnt FROM tasks WHERE run_id = ? AND kind = 'verify' GROUP BY state",
            (run_id,),
        ).fetchall()
        verify_states = {r["state"]: r["cnt"] for r in verify_rows}
        verify_enqueued = sum(verify_states.values())
        verify_done = verify_states.get("done", 0)
        verify_stats = {
            "enqueued": verify_enqueued,
            "done": verify_done,
            "complete": bool(verify_enqueued) and verify_done == verify_enqueued,
        }

        # DSR-061: second opinions that were required but never completed are
        # recorded explicitly — the run must not imply a double review that
        # did not happen (no budget / not dispatched / not submitted).
        second_opinion_pending: List[str] = []
        for r in conn.execute(
            """
            SELECT task_id, state, spec_json FROM tasks
            WHERE run_id = ? AND task_key LIKE ?
            """,
            (run_id, SECOND_OPINION_TASK_KEY_PREFIX + "%"),
        ).fetchall():
            if r["state"] == "done":
                continue
            try:
                target = json.loads(r["spec_json"]).get("target_finding_id", "")
            except ValueError:
                target = ""
            second_opinion_pending.append(target)
        if second_opinion_pending:
            store.append_event(
                run_id,
                "second_opinion_pending",
                "service",
                {
                    "finding_ids": second_opinion_pending,
                    "reason": "second-opinion tasks were enqueued but not completed before finalize",
                },
            )
        # ---------------------------------------------------------------------

        # IFC-05 floor requirement: every gate evaluation is recorded as an
        # explicit event (gate_id/status/failed checks) so replay can rebuild
        # the gate ledger without trusting the final projection alone.
        for _gate in (g1_res, g2_res, g3_res):
            store.append_event(
                run_id,
                "gate_evaluated",
                "service",
                {
                    "gate_id": _gate.gate_id,
                    "status": _gate.status,
                    "failed_checks": [
                        {"check_id": c.check_id, "message": c.message}
                        for c in getattr(_gate, "checks", [])
                        if getattr(c, "status", "") != "pass"
                    ],
                },
            )

        # Provisional terminal state from G1..G3 and the stop sequence; G4 is
        # evaluated below against the artifacts this call is about to publish.
        pre_gates_passed = (
            g1_res.status == "pass"
            and g2_res.status == "pass"
            and g3_res.status == "pass"
        )

        # Stop-sequence reconciliation (DSR-066): budget exhaustion and
        # unverified candidates force an incomplete terminal state.
        incomplete_reasons: List[str] = []
        if not pre_gates_passed:
            failed_gates = [
                g.gate_id
                for g in (g1_res, g2_res, g3_res)
                if g.status != "pass"
            ]
            incomplete_reasons.append("gate_failed:" + ",".join(failed_gates))

        # Zero-dispatch / unprocessed plan scope (double guard with G1 above):
        # the gate formula alone cannot see "planned but never dispatched".
        if (
            (plan_units > 0 and hunt_attempt_count == 0)
            or recon_unprocessed
            or verify_unprocessed
        ):
            incomplete_reasons.append(UNPROCESSED_UNITS_REASON)

        has_budget_exhausted = any(e["event_type"] == "budget_exhausted" for e in events)
        if has_budget_exhausted:
            incomplete_reasons.append("budget_exhausted")

        # Unverified candidates are recorded with their reasons (DSR-066). They
        # do not by themselves force an incomplete run (a complete audit may
        # legitimately report needs_validation findings); they do when the stop
        # sequence fired due to budget exhaustion, which is handled above.
        unverified = []
        for f in all_findings:
            if f.get("verdict") in ("needs_validation", "unverified"):
                unverified.append({
                    "finding_id": f.get("finding_id"),
                    "verdict": f.get("verdict"),
                    "reason": f.get("unverified_reason") or "; ".join(f.get("blockers", [])) or None,
                })

        coverage_gap_events = [e for e in events if e["event_type"] == "coverage_gap"]
        if coverage_gap_events:
            incomplete_reasons.append("coverage_gaps_present")

        # Host termination could not be confirmed (DSR-064): the attempt's
        # budget reservation is retained, so the run ends incomplete with an
        # explicit candidate reason instead of silently ignoring the attempt.
        budget_retained_events = [
            e for e in events if e["event_type"] == TERMINATION_UNCERTAIN_EVENT_TYPE
        ]
        if budget_retained_events:
            incomplete_reasons.append("termination_uncertain_budget_retained")

        # DSR-061: a mandated second opinion that never ran must not be
        # papered over by a 'complete' terminal state — the High/Critical
        # finding stands un-corroborated and the run says so.
        if second_opinion_pending:
            incomplete_reasons.append("second_opinion_pending")

        provisional_state = (
            "complete" if pre_gates_passed and not incomplete_reasons else "incomplete"
        )

        # Coverage accounting (triage overflow, connector unresolved/incompatible,
        # hunter/signal overflow, packet overflow, snapshot gaps, quarantined
        # work): all of these are surfaced as finalize coverage gaps; only
        # "coverage_gap" events force an incomplete state above.
        accounting_events = [
            e for e in events if e["event_type"] in COVERAGE_ACCOUNTING_EVENT_TYPES
        ]

        # SR-014 / DSR-070: assemble the real run statistics and hand them to
        # the report generator as self-review inputs. Every input below is
        # derived from the ledger / plan / findings — no fabricated defaults.
        run_stats = self._build_run_stats(
            conn, run_id, events, plan_dict, manifest_dict,
            coverage_summary, cost_metrics, all_findings,
        )

        # SR-012: the report language recorded at prepare time governs the
        # dossier rendering; missing config falls back to 'en'.
        report_language = "en"
        try:
            with open(run_path / "config.json", "r", encoding="utf-8") as f:
                report_language = json.load(f).get("report_language", "en") or "en"
        except (OSError, ValueError):
            pass

        # --- Report stage: publish first, then gate on the artifacts --------
        def _publish_reports(state: str) -> str:
            generator = ReportGenerator(
                run_id, manifest_dict["snapshot_id"], state, art_mgr,
                report_language=report_language,
            )
            return generator.generate_all(
                all_findings, coverage_summary, cost_metrics, events,
                self_review_inputs=run_stats,
            )

        gen_id = _publish_reports(provisional_state)

        # G4 (ordering fix): evaluated on the PUBLISHED artifacts. Reads the
        # report back from disk for the generation marker and a sanitization
        # spot check, and reconciles the artifacts-table generation.
        post_events = store.get_events(run_id)
        post_rev = conn.execute(
            "SELECT revision FROM runs WHERE run_id = ?", (run_id,)
        ).fetchone()["revision"]
        revision_consistent = len(post_events) == post_rev
        generation_rows = [
            r["generation"]
            for r in conn.execute(
                "SELECT DISTINCT generation FROM artifacts WHERE run_id = ? AND generation IS NOT NULL",
                (run_id,),
            ).fetchall()
        ]
        generation_consistent = set(generation_rows) == {gen_id}
        findings_export = json.dumps(all_findings, sort_keys=True, ensure_ascii=False)
        export_sanitized = mask_secrets(findings_export) == findings_export

        g4_detail = "published reports absent"
        try:
            report_text = (run_path / "report" / "REPORT.md").read_text(encoding="utf-8")
            if gen_id not in report_text:
                g4_detail = f"published REPORT.md does not carry generation {gen_id}"
            elif mask_secrets(report_text) != report_text:
                g4_detail = "published REPORT.md failed the sanitization spot check"
            else:
                g4_detail = "published reports verified"
        except OSError:
            report_text = ""
        if not generation_consistent:
            g4_detail = "artifacts table carries more than one report generation"

        g4_res = GateEvaluator.evaluate_g4(
            revision_consistent and generation_consistent,
            export_sanitized and g4_detail == "published reports verified",
            post_rev,
        )
        if g4_res.status != "pass":
            g4_res.reason = g4_detail
            incomplete_reasons.append("g4_failed")
        # IFC-05 floor requirement: G4 is evaluated against the published
        # artifacts, so its event lands after the reports exist (ordering
        # matters for replay: gate ledger follows the artifact ledger).
        store.append_event(
            run_id,
            "gate_evaluated",
            "service",
            {
                "gate_id": g4_res.gate_id,
                "status": g4_res.status,
                "reason": g4_res.reason,
                "failed_checks": [
                    {"check_id": c.check_id, "message": c.message}
                    for c in getattr(g4_res, "checks", [])
                    if getattr(c, "status", "") != "pass"
                ],
            },
        )
        final_state = (
            "complete"
            if pre_gates_passed and not incomplete_reasons
            else "incomplete"
        )

        if final_state != provisional_state:
            # The provisional dossier declared the wrong terminal state; drop
            # its artifact references and re-publish with the real one so the
            # on-disk report never claims a complete run that did not happen.
            conn.execute(
                "DELETE FROM artifacts WHERE run_id = ? AND generation = ?",
                (run_id, gen_id),
            )
            gen_id = _publish_reports(final_state)

        # Update run terminal state
        conn.execute("UPDATE runs SET state = ? WHERE run_id = ?", (final_state, run_id))
        EventStore(conn).append_event(
            run_id,
            "run_finalized",
            "service",
            {
                "final_state": final_state,
                "generation_id": gen_id,
                "reason": reason,
                "incomplete_reasons": incomplete_reasons,
                "unprocessed_units": {
                    "plan_hunt_units": plan_units,
                    "completed_hunt_tasks": db_hunt_tasks,
                    "hunt_tasks_ever_dispatched": hunt_attempt_count,
                    "recon_tasks_not_done": recon_unprocessed,
                    "verify_tasks_not_done_or_quarantined": verify_unprocessed,
                },
                "verify": verify_stats,
                "second_opinion_pending": second_opinion_pending,
                "g4_evaluation": g4_detail,
            },
        )

        return {
            "run_id": run_id,
            "final_state": final_state,
            "generation_id": gen_id,
            "gates": {
                "G1": g1_res.status,
                "G2": g2_res.status,
                "G3": g3_res.status,
                "G4": g4_res.status,
            },
            "incomplete_reasons": incomplete_reasons,
            "unverified": unverified,
            "verify": verify_stats,
            "second_opinion_pending": second_opinion_pending,
            "coverage_gaps": [e["payload"] for e in accounting_events],
            "budget_retained": [e["payload"] for e in budget_retained_events],
        }

    # ------------------------------------------------------------------
    # SR-020 / DSR-067 wiring: usage_records + retry accounting into cost.
    # ------------------------------------------------------------------
    @staticmethod
    def _apply_usage_records(conn: Any, run_id: str, tracker: CostTracker) -> None:
        """Aggregate the run's persisted usage_records into the CostTracker.

        Token-dimension records with exact/estimated availability are summed
        into set_tokens with their real availability; a run with usage records
        but no token values, or with none at all, keeps the token metric
        unavailable with the reason that states which case happened. Retry
        counts come from the attempts table (tasks dispatched more than once).
        """
        rows = conn.execute(
            """
            SELECT dimension, availability, value, unit, source
            FROM usage_records WHERE run_id = ?
            """,
            (run_id,),
        ).fetchall()

        token_rows = [
            r for r in rows
            if r["dimension"] == "tokens" and r["availability"] in ("exact", "estimated")
            and r["value"] is not None
        ]
        if token_rows:
            tracker.set_tokens(
                sum(int(r["value"]) for r in token_rows),
                source="exact" if all(r["availability"] == "exact" for r in token_rows) else "estimated",
            )
        elif rows:
            tracker.unavailable_reason = (
                "usage records were persisted but none carried a token-dimension value"
            )
        else:
            tracker.unavailable_reason = "no usage records were persisted for this run"

        retry_rows = conn.execute(
            """
            SELECT count(*) - 1 AS extra_attempts
            FROM attempts a
            JOIN tasks t ON a.task_id = t.task_id
            WHERE t.run_id = ?
            GROUP BY a.task_id
            HAVING count(*) > 1
            """,
            (run_id,),
        ).fetchall()
        retries = sum(r["extra_attempts"] for r in retry_rows)
        if retries:
            tracker.set_retries(int(retries), source="ledger")

    # ------------------------------------------------------------------
    # SR-014 / DSR-070 wiring: real run statistics for the skill self-review.
    # ------------------------------------------------------------------
    def _build_run_stats(
        self,
        conn: Any,
        run_id: str,
        events: List[Dict[str, Any]],
        plan_dict: Dict[str, Any],
        manifest_dict: Dict[str, Any],
        coverage_summary: Dict[str, Any],
        cost_metrics: Dict[str, Any],
        all_findings: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Assemble the self-review inputs from real ledger/plan/finding data."""
        stage_tasks: Dict[str, int] = {}
        total_tasks = 0
        for r in conn.execute(
            "SELECT kind, count(*) AS cnt FROM tasks WHERE run_id = ? GROUP BY kind",
            (run_id,),
        ).fetchall():
            stage_tasks[r["kind"]] = r["cnt"]
            total_tasks += r["cnt"]
        stage_tasks["report"] = REPORT_STAGE_TASKS
        total_tasks += REPORT_STAGE_TASKS

        verdict_distribution: Dict[str, int] = {}
        for f in all_findings:
            v = f.get("verdict", "unknown")
            verdict_distribution[v] = verdict_distribution.get(v, 0) + 1

        knowledge_gaps = [
            e["payload"]
            for e in events
            if e["event_type"] == "snapshot_gap"
            and (e["payload"].get("source") == "knowledge")
        ]

        detected_languages = sorted({
            f.get("language", "unknown")
            for f in manifest_dict.get("files", [])
            if f.get("language")
        })
        catalog = KnowledgeCatalog(self.knowledge_dir)
        uncovered_languages = [
            lang for lang in detected_languages
            if lang != "unknown" and not catalog.get_language_index(lang)
        ]

        usage_missing_rows = conn.execute(
            """
            SELECT count(*) AS cnt
            FROM attempts a
            JOIN tasks t ON a.task_id = t.task_id
            LEFT JOIN usage_records u ON u.attempt_id = a.attempt_id
            WHERE t.run_id = ? AND (u.attempt_id IS NULL OR u.availability = 'unavailable')
            """,
            (run_id,),
        ).fetchone()["cnt"]

        error_events = sum(1 for e in events if e["event_type"] in ERROR_EVENT_TYPES)

        return {
            "total_tasks": total_tasks,
            "stage_tasks": stage_tasks,
            "coverage_summary": dict(
                coverage_summary,
                coverage_gaps=[
                    e["payload"] for e in events
                    if e["event_type"] in COVERAGE_ACCOUNTING_EVENT_TYPES
                ],
            ),
            "cost_metrics": cost_metrics,
            "verdict_distribution": verdict_distribution,
            "knowledge_gaps": knowledge_gaps,
            "knowledge_version": conn.execute(
                "SELECT knowledge_version FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone()["knowledge_version"],
            "detected_languages": detected_languages,
            "uncovered_languages": uncovered_languages,
            "error_events": error_events,
            "usage_missing_count": int(usage_missing_rows),
            "plan_hunt_units": plan_dict.get("hunt_units"),
            "total_inventoried_files": len(manifest_dict.get("files", [])),
        }
