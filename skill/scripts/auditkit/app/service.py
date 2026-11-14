"""Application service coordinating the complete audit lifecycle.

Implements IFC-03 / DDS-01 / DDS-03 / DDS-04 / SWR-001 / SWR-022 / SWR-026:
- Implements: doctor, prepare, activate, next, start, submit, status, pause, resume, finalize, report.
- Strictly single entry point for all state mutations.
- Enforces G0..G4 gates during progression.
- Preserves transactional consistency and atomic publishing.

Cross-domain wiring owned here (ANA/LED, SNP/INT, HST/LED):
- hunt submissions enqueue verify-kind tasks (Verifier(enforce_attempt_gate=True))
  and run connector evaluations under a full reserve -> settle budget lifecycle;
- triage records, snapshot gaps, hunter/signal overflow, connector
  unresolved/incompatible records are persisted as events and surfaced through
  finalize's coverage accounting;
- verify submissions are stamped with the current run_id and merged at finalize,
  making the semantic validator's cross-run check real;
- prepare consumes snapshot capabilities (knowledge_dir, scan gap/overflow
  accounting, inventory reconciliation, unit dispositions: only analyze units
  get hunt tasks);
- run_dispatch_loop drives claims with AIMD concurrency, adapter retry/backoff
  parameters, trusted usage objects, and TerminationUncertainError budget
  retention.
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
import shutil
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from auditkit.analysis.connector import HypothesisConnector
from auditkit.analysis.hunter import HuntResultParser
from auditkit.analysis.triage import StrongSignalTriage
from auditkit.analysis.verifier import Verifier
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
from auditkit.snapshot.manifest import SnapshotManifest
from auditkit.snapshot.paths import validate_three_roots


# --- Cross-domain wiring constants (ANA -> LED, SNP -> INT, HST -> LED) ----
# Verify tasks dispatch before any hunt task (T1 hunt priority is 20).
VERIFY_TASK_PRIORITY = 30
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
OVERFLOW_EVENT_TYPES = ("hunter_overflow", "signal_overflow")
CONNECTOR_RECORD_EVENT_TYPES = ("connector_unresolved", "connector_incompatible")
COVERAGE_ACCOUNTING_EVENT_TYPES = GAP_EVENT_TYPES + OVERFLOW_EVENT_TYPES + CONNECTOR_RECORD_EVENT_TYPES
# Host termination could not be confirmed: attempt budget stays reserved.
TERMINATION_UNCERTAIN_EVENT_TYPE = "attempt_termination_uncertain"
# Verified findings produced by verify-task submissions are persisted here.
FINDINGS_ARTIFACT_KIND = "verified_findings"
VERIFIED_FINDING_VERDICTS = ("confirmed", "needs_validation", "rejected", "unverified")


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
            },
        )

        return {
            "schema_version": "1.0",
            "run_id": run_id,
            "snapshot_id": snapshot_id,
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

    def next(self, run_id: str, run_dir: str | Path, batch_size: int = 1) -> List[Dict[str, Any]]:
        """Claim next batch of tasks."""
        conn = self._open_run_db(run_dir)
        queue = TaskQueue(conn)
        return queue.claim(run_id, batch_size=batch_size)

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

        if kind == "hunt":
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
            self._enqueue_verify_tasks(conn, run_id, candidates, claim["task_id"])
            if frontiers and probes:
                self._run_connector(conn, run_id, claim, frontiers, probes, store)
        elif kind == "verify":
            self._store_verified_findings(conn, run_path, run_id, claim, worker_result, store)

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

        self._enqueue_verify_tasks(conn, run_id, result["candidates"], claim["task_id"])
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
        return stamped

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
        conn = self._open_run_db(run_dir)
        queue = TaskQueue(conn)
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
            claims = queue.claim(
                run_id,
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

    def pause(self, run_id: str, run_dir: str | Path, reason: str = "user_requested") -> int:
        """Pause run dispatch."""
        conn = self._open_run_db(run_dir)
        conn.execute("UPDATE runs SET state = 'paused' WHERE run_id = ?", (run_id,))
        store = EventStore(conn)
        return store.append_event(run_id, "run_paused", "service", {"reason": reason})

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
        """Verify integrity and resume paused run."""
        conn = self._open_run_db(run_dir)
        art_mgr = ArtifactManager(run_dir, conn)
        art_mgr.verify_artifacts(run_id)

        run_row = conn.execute("SELECT state FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        if not run_row:
            raise InvalidInputError(f"Run {run_id} not found")

        return {"run_id": run_id, "state": run_row["state"], "verified": True}

    def finalize(
        self,
        run_id: str,
        run_dir: str | Path,
        findings: Optional[List[Dict[str, Any]]] = None,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Finalize run, evaluate gates against real data, and publish reports (DSR-076).

        Artifact integrity is verified before anything else: a corrupt run is
        moved to state 'corrupt' and refuses to produce any report. G1..G4 are
        fed with real run data (plan/DB unit reconciliation, dispatched vs
        submitted task reconciliation, semantic validation pass accounting,
        revision/artifact consistency, and export sanitization). Runs with gate
        failures, budget exhaustion, or unverified candidates end 'incomplete',
        never 'complete'.
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

        # Merge caller-supplied findings with verified findings persisted by
        # verify-task submissions (ANA -> LED wiring). Stored findings already
        # carry the run_id stamp; caller findings get it here, so every finding
        # evaluated below is bound to this run.
        merged_findings: Dict[str, Dict[str, Any]] = {}
        for f in findings or []:
            if isinstance(f, dict):
                merged_findings[f.get("finding_id") or f"anon-{len(merged_findings)}"] = f
        for vf_path in sorted(run_path.glob("findings/verified-*.json")):
            try:
                with open(vf_path, "r", encoding="utf-8") as f:
                    stored = json.load(f)
            except (OSError, ValueError) as e:
                raise CorruptRunError(
                    f"Verified findings artifact unreadable: {vf_path.name}",
                    details={"detail": str(e)},
                )
            for f in stored if isinstance(stored, list) else []:
                merged_findings.setdefault(f.get("finding_id") or f"anon-{len(merged_findings)}", f)
        all_findings = list(merged_findings.values())
        for f in all_findings:
            f.setdefault("run_id", run_id)

        # Calculate coverage
        cov_calc = CoverageCalculator(manifest_dict.get("files", []))
        for row in conn.execute("SELECT path, dimension, start_line, end_line FROM coverage_intervals WHERE run_id = ?", (run_id,)).fetchall():
            cov_calc.record_interval(row["path"], row["dimension"], row["start_line"], row["end_line"])
        coverage_summary = cov_calc.get_summary()

        # Build cost tracker
        cost_tracker = CostTracker()
        for r in conn.execute("SELECT kind, count(*) as cnt FROM tasks WHERE run_id = ? GROUP BY kind", (run_id,)).fetchall():
            for _ in range(r["cnt"]):
                cost_tracker.record_task(r["kind"])
        cost_metrics = cost_tracker.compute_metrics(
            coverage_summary.get("total_inventoried_lines", 0),
            len([f for f in (findings or []) if f.get("verdict") == "confirmed"]),
        )

        store = EventStore(conn)
        events = store.get_events(run_id)
        current_rev = conn.execute("SELECT revision FROM runs WHERE run_id = ?", (run_id,)).fetchone()["revision"]

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

        # G4: revision/event ledger/artifact consistency + export sanitization.
        revision_consistent = len(events) == current_rev
        generation_rows = conn.execute(
            "SELECT DISTINCT generation FROM artifacts WHERE run_id = ? AND generation IS NOT NULL",
            (run_id,),
        ).fetchall()
        if len(generation_rows) > 1:
            revision_consistent = False
        findings_export = json.dumps(all_findings, sort_keys=True, ensure_ascii=False)
        export_sanitized = mask_secrets(findings_export) == findings_export
        g4_res = GateEvaluator.evaluate_g4(revision_consistent, export_sanitized, current_rev)
        # ---------------------------------------------------------------------

        all_passed = (
            g1_res.status == "pass"
            and g2_res.status == "pass"
            and g3_res.status == "pass"
            and g4_res.status == "pass"
        )

        # Stop-sequence reconciliation (DSR-066): budget exhaustion and
        # unverified candidates force an incomplete terminal state.
        incomplete_reasons: List[str] = []
        if not all_passed:
            failed_gates = [
                g.gate_id
                for g in (g1_res, g2_res, g3_res, g4_res)
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

        final_state = "complete" if all_passed and not incomplete_reasons else "incomplete"

        # Coverage accounting (triage overflow, connector unresolved/incompatible,
        # hunter/signal overflow, snapshot gaps, quarantined work): all of these
        # are surfaced as finalize coverage gaps; only "coverage_gap" events
        # (lost/quarantined dispatched work) force an incomplete state above.
        accounting_events = [
            e for e in events if e["event_type"] in COVERAGE_ACCOUNTING_EVENT_TYPES
        ]

        # Generate reports
        rep_gen = ReportGenerator(run_id, manifest_dict["snapshot_id"], final_state, art_mgr)
        gen_id = rep_gen.generate_all(all_findings, coverage_summary, cost_metrics, events)

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
            "coverage_gaps": [e["payload"] for e in accounting_events],
            "budget_retained": [e["payload"] for e in budget_retained_events],
        }
