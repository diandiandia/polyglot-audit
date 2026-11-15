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
- verify submissions are stamped with the current run_id and merged at
  finalize (adjudicated findings override verified ones), making the semantic
  validator's cross-run check real;
- finalize feeds the report stage with real self-review inputs (SR-014 /
  DSR-070), aggregates usage_records and ledger retries into cost telemetry
  (SR-020 / DSR-067), reads report_language from the run config (SR-012), and
  evaluates G4 AFTER the reports are published, against the published
  artifacts (user-confirmed ordering fix);
- run_dispatch_loop drives claims with AIMD concurrency, adapter retry/backoff
  parameters, trusted usage objects, and TerminationUncertainError budget
  retention; pause returns the in-flight attempt contract and resume verifies
  version/artifact/snapshot integrity before a paused run may continue
  (IFC-06).
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
import hashlib
import json
import os
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
from auditkit.analysis.verifier import SECOND_OPINION_SEVERITIES, Verifier
from auditkit.contracts.errors import (
    AuditError,
    CorruptRunError,
    GateFailedError,
    InvalidInputError,
    InvalidStateError,
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


class AuditAppService:
    """Core domain application service."""

    def __init__(self, skill_dir: str | Path) -> None:
        self.skill_dir = Path(os.path.realpath(os.path.abspath(skill_dir)))
        self.schemas_dir = self.skill_dir / "schemas"
        self.knowledge_dir = self.skill_dir / "knowledge"

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

        # Save plan artifact
        plan_summary = {
            "snapshot_id": snapshot_id,
            "total_files": len(manifest.files),
            "total_units": len(units),
            "hunt_units": len(analyze_units),
            "dispositions": dispositions,
            "profile": profile,
            "units": units,
            "source_control": manifest.source_control,
            "snapshot_gaps": snapshot_gaps,
            "drift_detected": manifest.drift_detected,
            "inventory_reconciliation": inventory_reconciliation,
        }
        with open(run_path / "plan.json", "w", encoding="utf-8") as f:
            json.dump(plan_summary, f, indent=2)

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
                spec={"unit": u, "snapshot_id": snapshot_id},
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
        recon_primary_index, recon_base_index = catalog.get_applicable_indices(
            recon_unit.get("language", "unknown")
        )
        catalog_languages = self._catalog_languages()
        recon_task_id = task_queue.enqueue(
            run_id=run_id,
            task_key=RECON_TASK_KEY,
            kind="recon",
            spec={
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
            },
            priority=RECON_TASK_PRIORITY,
        )

        # Update run to ready state
        conn.execute(
            "UPDATE runs SET snapshot_id = ?, state = 'ready' WHERE run_id = ?",
            (snapshot_id, run_id),
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
                try:
                    EventStore(conn).append_event(
                        run_id,
                        "packet_render_failed",
                        "service",
                        {
                            "task_id": claim["task_id"],
                            "attempt_id": claim["attempt_id"],
                            "reason": reason,
                        },
                    )
                finally:
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
                unit = self._verify_unit_from_spec(spec)
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
                unit.get("language", "unknown")
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
    def _verify_unit_from_spec(spec: Dict[str, Any]) -> Dict[str, Any]:
        """Synthesize a packet unit for a verify task from its candidate/finding."""
        payload = (spec.get("input") or {})
        target = payload.get("candidate") or payload.get("finding") or {}
        ranges: List[Dict[str, Any]] = []
        seen: set = set()

        def _add_range(endpoint: Any, window: int = 5) -> None:
            path = (endpoint or {}).get("path", "")
            if not path:
                return
            line = (endpoint or {}).get("line") or 1
            rng = (path, max(1, int(line) - window), int(line) + window)
            if rng not in seen:
                seen.add(rng)
                ranges.append({"path": rng[0], "line_start": rng[1], "line_end": rng[2]})

        _add_range(target.get("source"))
        _add_range(target.get("sink"))
        for step in target.get("steps") or []:
            _add_range(step, window=2)

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
        # Validate worker_result schema
        with open(self.schemas_dir / "worker_result.schema.json", "r", encoding="utf-8") as f:
            res_schema = json.load(f)
        SchemaValidator(res_schema).validate_or_raise(worker_result)

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
        # duplicate verify tasks or re-run connector budget accounting.
        if not receipt.get("replayed", False):
            self._on_result_accepted(conn, Path(run_dir), claim, worker_result)

        return receipt

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
            # DSR-063: duplicate candidates are reconciled before any verify
            # work is dispatched; only deduplicated representatives continue.
            candidates = self._deduplicate_candidates(conn, run_id, candidates, store)
            self._enqueue_verify_tasks(conn, run_id, candidates, claim["task_id"])
            if frontiers and probes:
                self._run_connector(conn, run_id, claim, frontiers, probes, store)
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

        rel_path = f"tasks/{claim['task_id']}/result.json"
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
            run_id, "guard_baseline", rel_path, payload
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
        """
        verifier = Verifier(enforce_attempt_gate=True)
        queue = TaskQueue(conn)
        enqueued: List[Dict[str, Any]] = []
        for cand in candidates:
            cand_id = cand.get("candidate_id", "")
            if not cand_id:
                continue
            spec = verifier.build_verify_task(cand)
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

        reserve -> settle (actual pairing evaluations) on success, reserve ->
        release on failure. Unresolved / incompatible / capped records are
        persisted as events and never silently dropped (DSR-058).
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

    def _extract_findings(self, records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract draft finding objects from verify-task result records."""
        findings: List[Dict[str, Any]] = []
        for rec in records or []:
            if not isinstance(rec, dict) or rec.get("verdict") not in VERIFIED_FINDING_VERDICTS:
                continue
            finding = rec.get("finding") if isinstance(rec.get("finding"), dict) else rec
            if finding.get("finding_id"):
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
        """
        findings = self._extract_findings(worker_result.get("records", []))
        if not findings:
            return []
        stamped: List[Dict[str, Any]] = []
        for f in findings:
            f["run_id"] = run_id
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
        higher than normal verify work. If the task cannot be enqueued, the
        fact is recorded as a second_opinion_pending event — the run never
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
            spec = {
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
            }
            try:
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
        adapter: Any,
        attempt_id: str,
        dimension: str = "tokens",
        unit: str = "tokens",
        source: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Build a trusted usage object from a host adapter (DSR-033 wiring).

        Reads the adapter's ``last_usage`` (populated by ``extract_usage``).
        Host-reported numbers map to availability "exact" only when the host
        explicitly declared it, otherwise "estimated"; a missing or non-numeric
        usage block maps to "unavailable" with an explicit reason. Usage is
        never omitted: a submission always carries a usage object.
        """
        raw = getattr(adapter, "last_usage", None)
        usage: Dict[str, Any] = {
            "schema_version": "1.0",
            "attempt_id": attempt_id,
            "dimension": dimension,
            "unit": unit,
            "source": source or (type(adapter).__name__ if adapter is not None else "service"),
        }
        if isinstance(raw, dict):
            numeric = [
                v for v in raw.values() if isinstance(v, int) and not isinstance(v, bool)
            ]
            if numeric:
                declared = raw.get("availability")
                usage["availability"] = declared if declared in ("exact", "estimated") else "estimated"
                usage["value"] = sum(numeric)
                return usage
            usage["availability"] = "unavailable"
            usage["reason"] = "host adapter usage block contained no numeric values"
            return usage
        usage["availability"] = "unavailable"
        usage["reason"] = "host adapter reported no usage block"
        return usage

    # ------------------------------------------------------------------
    # HST -> service wiring: AIMD-driven dispatch loop.
    # ------------------------------------------------------------------
    def run_dispatch_loop(
        self,
        run_id: str,
        run_dir: str | Path,
        execute_fn: Callable[[Dict[str, Any]], Dict[str, Any]],
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

        - ``controller``: ConcurrencyController; batch size follows AIMD
          (success +1, failure halve). Defaults to a fresh controller.
        - ``adapter``: host driver adapter; its ``max_retries`` bounds queue
          retries and its ``backoff_base``/``backoff_max`` bound the inter-batch
          backoff sleep after retryable failures. ``last_usage`` feeds the
          trusted usage object submitted for every attempt.
        - TerminationUncertainError retains the attempt budget (no release) and
          is converted into an incomplete candidate reason at finalize.
        """
        # Claims, starts and submits all flow through the service entry points
        # (next/start/submit), which open and version-check their own handles.
        ctrl = controller or ConcurrencyController()
        max_retries = int(getattr(adapter, "max_retries", 2) or 2)
        backoff_base = float(getattr(adapter, "backoff_base", 0.5))
        backoff_max = float(getattr(adapter, "backoff_max", 30.0))

        batches = 0
        submitted = 0
        failed = 0
        retained = 0
        stop_reason = None

        while max_batches is None or batches < max_batches:
            # Claims flow through service.next so every dispatched attempt is
            # served with its published prompt packet (IFC-02); claims whose
            # packet cannot be rendered are released back to the queue inside
            # next() and never reach execute_fn.
            claims = self.next(
                run_id,
                run_dir,
                batch_size=ctrl.current,
                lease_seconds=lease_seconds,
                worker_id="service_loop",
            )
            if not claims:
                stop_reason = "queue_drained"
                break
            batches += 1

            for claim in claims:
                self.start(run_dir, claim)
                try:
                    result = execute_fn(claim)
                except TerminationUncertainError as e:
                    # Budget is retained, never released (DSR-064).
                    self.report_host_failure(run_dir, claim, e, max_retries=max_retries)
                    ctrl.on_failure()
                    retained += 1
                    failed += 1
                    continue
                except AuditError as e:
                    self.report_host_failure(run_dir, claim, e, max_retries=max_retries)
                    ctrl.on_failure()
                    failed += 1
                    sleep_fn(compute_backoff_delay(failed, backoff_base, backoff_max))
                    continue

                usage = self.build_usage(
                    adapter,
                    claim["attempt_id"],
                    dimension=usage_dimension,
                    unit=usage_unit,
                    source=usage_source,
                )
                digest = sha256_text(json.dumps(result, sort_keys=True, ensure_ascii=False))
                self.submit(run_dir, claim, result, digest, usage=usage)
                ctrl.on_success()
                submitted += 1

        return {
            "batches": batches,
            "submitted": submitted,
            "failed": failed,
            "budget_retained": retained,
            "concurrency": ctrl.current,
            "stop_reason": stop_reason,
        }

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
        moved to state 'corrupt' and refuses to produce any report. G1..G3 are
        fed with real run data (plan/DB unit reconciliation, dispatched vs
        submitted task reconciliation, semantic validation pass accounting).
        G4 (user-confirmed ordering fix) is evaluated AFTER the report stage
        published its artifacts: the gate reads back the published REPORT.md
        (generation marker + sanitization spot check) and reconciles the
        artifacts table generation. A failing G4 forces the terminal state to
        'incomplete' (incomplete_reasons gains 'g4_failed') and the reports
        are re-published so the on-disk dossier states the true terminal
        state. Runs with gate failures, budget exhaustion, or unverified
        candidates end 'incomplete', never 'complete'.
        """
        run_path = Path(run_dir)
        conn = self._open_run_db(run_path)
        art_mgr = ArtifactManager(run_dir, conn)

        run_row = conn.execute("SELECT state FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        if not run_row:
            raise InvalidInputError(f"Run {run_id} not found")
        if run_row["state"] in ("complete", "corrupt"):
            raise InvalidStateError(f"Run {run_id} already reached terminal state '{run_row['state']}'")

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

        # Load snapshot manifest and plan
        with open(run_path / "snapshot" / "manifest.json", "r", encoding="utf-8") as f:
            manifest_dict = json.load(f)
        with open(run_path / "plan.json", "r", encoding="utf-8") as f:
            plan_dict = json.load(f)

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
        all_findings = list(merged_findings.values())
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

        # SR-020 / DSR-067: cost telemetry from real ledger data — stage task
        # counts, the executed report stage, usage_records aggregation and the
        # retry count derived from the attempts table.
        cost_tracker = CostTracker()
        for r in conn.execute("SELECT kind, count(*) as cnt FROM tasks WHERE run_id = ? GROUP BY kind", (run_id,)).fetchall():
            for _ in range(r["cnt"]):
                cost_tracker.record_task(r["kind"])
        for _ in range(REPORT_STAGE_TASKS):
            cost_tracker.record_task("report")
        self._apply_usage_records(conn, run_id, cost_tracker)
        cost_metrics = cost_tracker.compute_metrics(
            coverage_summary.get("total_inventoried_lines", 0),
            len([f for f in all_findings if f.get("verdict") == "confirmed"]),
        )

        # --- Real gate inputs (DSR-076) -------------------------------------
        # G1: plan/report unit inventory vs DB enqueued task inventory. Only
        # analyze-disposition units are planned as hunt work (DSR-056); older
        # plans without the hunt_units field fall back to the full unit count.
        plan_units = plan_dict.get("hunt_units", len(plan_dict.get("units", [])))
        db_hunt_tasks = conn.execute(
            "SELECT count(*) AS cnt FROM tasks WHERE run_id = ? AND kind = 'hunt'",
            (run_id,),
        ).fetchone()["cnt"]
        g1_res = GateEvaluator.evaluate_g1(plan_units, db_hunt_tasks, [], current_rev)

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
