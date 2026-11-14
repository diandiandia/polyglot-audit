"""Atomic task queue with lease management, generation tracking, and idempotent submission.

Implements DSR-017 / DSR-018 / DSR-019 / DSR-020 / DSR-033 / DSR-065 / DSR-066 / DDS-04 / IFC-02:
- Atomic enqueue, claim, start, submit, expire.
- Claim and budget reservation run inside BEGIN IMMEDIATE ... COMMIT, so under
  multi-process contention a given task is claimed at most once and the last
  budget unit is reserved at most once.
- Secure random claim token (only digest stored in DB, never exposed in logs).
- Idempotent submit replay (same digest returns receipt, different digest conflicts).
- Stale attempt and generation mismatch rejection.
- Lease reclamation: expired claimed/running attempts are expired, tasks return
  to the queue with generation+1 and their reservations are released (DSR-019).
- Bounded task retry: retryable host failures requeue the task (a new attempt
  with a new reservation and incremented generation is created on the next
  claim); exceeding max_retries quarantines the task and records a coverage gap.
  Error outputs are never normalized into successful results (DSR-065).
- Dispatch priority ordering and the stop sequence: claims are only granted
  while the run is active (DSR-066).
"""

# 需求追踪 (Requirement Traceability)
# ---------------------------------------------------------------------------
# 上层需求: docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2
# 设计依据: docs/design/SOFTWARE_DESIGN.md
# SWR-018  任务生命周期 queued→claimed→running→done/failed/quarantined；BEGIN IMMEDIATE 原子 claim、token 摘要、幂等回执、迟到拒绝、租约回收
#   绑定实现: DSR-017, DSR-018, DSR-019, DSR-065, DSR-066
# 状态以统一测试结论为准；未实测能力保持 unknown（设计原则 8：能观测的不靠声明）。
#

from __future__ import annotations
import datetime
import hashlib
import json
import secrets
import sqlite3
import uuid
from typing import Any, Dict, List, Optional

from auditkit.contracts.errors import (
    BudgetExhaustedError,
    IdempotencyConflictError,
    InvalidInputError,
    InvalidStateError,
    StaleAttemptError,
    StorageError,
)
from auditkit.ledger.budget import BudgetLedger
from auditkit.ledger.db import check_version_compatibility
from auditkit.ledger.event_store import EventStore, utc_now_iso
from auditkit.ledger.usage import parse_usage, store_usage

# Default dispatch priorities (lower value = dispatched later). The service
# assigns T1 (highest risk) units a higher numeric priority.
DEFAULT_PRIORITY = 10
# Task states that represent dispatched (in-flight or finished) work.
DISPATCHED_TASK_STATES = ("claimed", "running", "done", "failed", "quarantined")


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class TaskQueue:
    """Manages transactional task scheduling and execution attempts."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn
        self.event_store = EventStore(conn)
        self.budget_ledger = BudgetLedger(conn)

    def enqueue(
        self,
        run_id: str,
        task_key: str,
        kind: str,
        spec: Dict[str, Any],
        priority: int = DEFAULT_PRIORITY,
    ) -> str:
        """Enqueue a task deterministically.

        Same task_key + same spec returns existing task_id.
        Same task_key + different spec raises IdempotencyConflictError.
        """
        spec_str = json.dumps(spec, sort_keys=True, ensure_ascii=False)
        spec_digest = sha256_text(spec_str)

        row = self.conn.execute(
            "SELECT task_id, spec_digest FROM tasks WHERE run_id = ? AND task_key = ?",
            (run_id, task_key),
        ).fetchone()

        if row:
            if row["spec_digest"] == spec_digest:
                return row["task_id"]
            else:
                raise IdempotencyConflictError(
                    f"Task key conflict for '{task_key}': spec digest differs"
                )

        task_id = f"task-{uuid.uuid4().hex[:12]}"
        self.conn.execute(
            """
            INSERT INTO tasks (task_id, run_id, task_key, kind, state, priority, generation, spec_digest, spec_json)
            VALUES (?, ?, ?, ?, 'queued', ?, 0, ?, ?)
            """,
            (task_id, run_id, task_key, kind, priority, spec_digest, spec_str),
        )

        self.event_store.append_event(
            run_id,
            "task_enqueued",
            "task_queue",
            {"task_id": task_id, "task_key": task_key, "kind": kind, "priority": priority},
        )
        return task_id

    def _check_dispatch_allowed(self, run_id: str) -> None:
        """Enforce the stop sequence: tasks are only dispatched while run is active (DSR-066)."""
        row = self.conn.execute("SELECT state FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        if not row:
            raise InvalidInputError(f"Run '{run_id}' not found")
        if row["state"] != "active":
            raise InvalidStateError(
                f"Dispatch is not allowed while run '{run_id}' is in state '{row['state']}' "
                "(stop sequence: new tasks are only granted to active runs)"
            )

    def claim(
        self,
        run_id: str,
        batch_size: int = 1,
        lease_seconds: int = 300,
        worker_id: str = "worker",
    ) -> List[Dict[str, Any]]:
        """Atomically claim up to batch_size queued tasks using BEGIN IMMEDIATE (DSR-017).

        The candidate selection, budget reservation, and state transition all run
        inside one immediate transaction, so competing workers can never claim the
        same task twice nor race for the last budget unit. Tasks are selected by
        descending priority (higher numeric priority dispatched first), then by
        task_id for determinism.
        """
        self._check_dispatch_allowed(run_id)
        # DSR-072: fail closed on unsupported persisted formats before dispatch.
        check_version_compatibility(self.conn, run_id)

        now = datetime.datetime.now(datetime.timezone.utc)
        expires_at = (now + datetime.timedelta(seconds=lease_seconds)).isoformat()
        claims: List[Dict[str, Any]] = []

        self.conn.execute("BEGIN IMMEDIATE")
        try:
            # Find candidate queued tasks in dispatch priority order
            rows = self.conn.execute(
                """
                SELECT task_id, kind, generation, priority, spec_json
                FROM tasks
                WHERE run_id = ? AND state = 'queued'
                ORDER BY priority DESC, task_id ASC
                LIMIT ?
                """,
                (run_id, batch_size),
            ).fetchall()

            for r in rows:
                task_id = r["task_id"]
                kind = r["kind"]
                new_gen = r["generation"] + 1
                attempt_id = f"att-{uuid.uuid4().hex[:12]}"
                claim_token = secrets.token_hex(16)
                token_digest = sha256_text(claim_token)

                # Try budget reservation (1 task) inside the same transaction
                is_hunt = (kind == "hunt")
                try:
                    self.budget_ledger.reserve(run_id, attempt_id, "tasks", 1, is_hunt_task=is_hunt)
                except BudgetExhaustedError as e:
                    # Stop sequence (DSR-066): budget exhausted, record reason and stop dispatch
                    self.event_store.append_event(
                        run_id,
                        "budget_exhausted",
                        worker_id,
                        {
                            "dimension": "tasks",
                            "reason": str(e),
                            "blocked_task_id": task_id,
                        },
                    )
                    break
                except Exception:
                    # Non-budget failure while reserving: stop claiming more
                    break

                # Update task state and insert attempt
                self.conn.execute(
                    "UPDATE tasks SET state = 'claimed', generation = ? WHERE task_id = ?",
                    (new_gen, task_id),
                )
                self.conn.execute(
                    """
                    INSERT INTO attempts (attempt_id, task_id, generation, status, token_digest, expires_at)
                    VALUES (?, ?, ?, 'claimed', ?, ?)
                    """,
                    (attempt_id, task_id, new_gen, token_digest, expires_at),
                )

                self.event_store.append_event(
                    run_id,
                    "attempt_claimed",
                    worker_id,
                    {"task_id": task_id, "attempt_id": attempt_id, "generation": new_gen, "expires_at": expires_at},
                )

                claims.append({
                    "schema_version": "1.0",
                    "run_id": run_id,
                    "task_id": task_id,
                    "attempt_id": attempt_id,
                    "generation": new_gen,
                    "claim_token": claim_token,
                    "expires_at": expires_at,
                    "packet_ref": f"tasks/{task_id}/packet.json",
                    "spec": json.loads(r["spec_json"]),
                })
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise

        self.conn.execute("COMMIT")
        return claims

    def reclaim_expired_attempts(self, run_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Expire stale claimed/running attempts and return their tasks to the queue (DSR-019).

        Each expired attempt: status -> 'expired', task state -> 'queued' with
        generation+1 (so late submissions are rejected as stale), and its budget
        reservation is released back to the available pool. Returns the list of
        reclamation records.
        """
        now_iso = utc_now_iso()
        reclaimed: List[Dict[str, Any]] = []

        self.conn.execute("BEGIN IMMEDIATE")
        try:
            sql = """
                SELECT a.attempt_id, a.task_id, t.run_id, t.generation
                FROM attempts a
                JOIN tasks t ON a.task_id = t.task_id
                WHERE a.status IN ('claimed', 'running') AND a.expires_at < ?
            """
            params: List[Any] = [now_iso]
            if run_id is not None:
                sql += " AND t.run_id = ?"
                params.append(run_id)

            rows = self.conn.execute(sql, params).fetchall()
            for r in rows:
                new_gen = r["generation"] + 1
                self.conn.execute(
                    "UPDATE attempts SET status = 'expired' WHERE attempt_id = ?",
                    (r["attempt_id"],),
                )
                self.conn.execute(
                    "UPDATE tasks SET state = 'queued', generation = ? WHERE task_id = ?",
                    (new_gen, r["task_id"]),
                )
                released = self.budget_ledger.release(r["attempt_id"])
                self.event_store.append_event(
                    r["run_id"],
                    "attempt_expired",
                    "task_queue",
                    {
                        "task_id": r["task_id"],
                        "attempt_id": r["attempt_id"],
                        "generation": new_gen,
                        "reservations_released": released,
                    },
                )
                reclaimed.append({
                    "task_id": r["task_id"],
                    "attempt_id": r["attempt_id"],
                    "run_id": r["run_id"],
                    "generation": new_gen,
                    "reservations_released": released,
                })
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise

        self.conn.execute("COMMIT")
        return reclaimed

    def start(
        self,
        run_id: str,
        task_id: str,
        attempt_id: str,
        generation: int,
        claim_token: str,
    ) -> Dict[str, Any]:
        """Mark attempt as running."""
        att = self._verify_attempt_token(task_id, attempt_id, generation, claim_token)

        if att["status"] in ("running", "done"):
            return {"status": att["status"], "attempt_id": attempt_id}

        self.conn.execute("UPDATE attempts SET status = 'running' WHERE attempt_id = ?", (attempt_id,))
        self.conn.execute("UPDATE tasks SET state = 'running' WHERE task_id = ?", (task_id,))

        self.event_store.append_event(
            run_id,
            "attempt_started",
            "worker",
            {"task_id": task_id, "attempt_id": attempt_id, "generation": generation},
        )
        return {"status": "running", "attempt_id": attempt_id}

    def submit(
        self,
        run_id: str,
        task_id: str,
        attempt_id: str,
        generation: int,
        claim_token: str,
        worker_result: Dict[str, Any],
        result_digest: str,
        usage: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Submit worker result atomically (DSR-018 / DSR-033).

        Replays of same attempt with same digest return existing receipt.
        Replays with different digest trigger IdempotencyConflictError.
        Stale attempts or token mismatches trigger StaleAttemptError.

        The trusted usage object (exact / estimated / unavailable) is validated,
        persisted, and used for settlement: unknown usage keeps the reserved
        amount consumed rather than silently settling a fixed "1 task".
        """
        att = self._verify_attempt_token(task_id, attempt_id, generation, claim_token, allow_finished=True)

        if att["status"] == "done":
            existing_digest = att["result_digest"]
            if existing_digest == result_digest:
                # Idempotent replay
                return {
                    "ok": True,
                    "receipt": att["receipt_ref"] or f"receipt-{attempt_id}",
                    "replayed": True,
                }
            else:
                raise IdempotencyConflictError(
                    f"Submission conflict for attempt {attempt_id}: digest differs from already submitted result"
                )

        receipt = f"receipt-{attempt_id}-{uuid.uuid4().hex[:6]}"

        # Validate and persist usage before mutating state (fail-closed on bad usage)
        usage_record = None
        if usage is not None:
            usage_record = parse_usage(usage)
            if usage_record.attempt_id != attempt_id:
                raise InvalidInputError(
                    f"usage.attempt_id '{usage_record.attempt_id}' does not match submitted attempt '{attempt_id}'"
                )

        self.conn.execute("BEGIN IMMEDIATE")
        try:
            if usage_record is not None:
                store_usage(self.conn, run_id, usage_record, utc_now_iso())
                # Settle the usage dimension with the real value; unavailable
                # usage keeps the reservation consumed (never freed, DSR-033).
                actual = usage_record.value if usage_record.availability in ("exact", "estimated") else None
                self.budget_ledger.settle(attempt_id, usage_record.dimension, actual)
                if usage_record.dimension != "tasks":
                    # The dispatch slot reservation itself settles as unknown usage.
                    self.budget_ledger.settle(attempt_id, "tasks", None)
            else:
                # No usage provided: settlement amount is unknown (not "1").
                self.budget_ledger.settle(attempt_id, "tasks", None)

            # Mark attempt and task done
            self.conn.execute(
                """
                UPDATE attempts
                SET status = 'done', result_digest = ?, receipt_ref = ?
                WHERE attempt_id = ?
                """,
                (result_digest, receipt, attempt_id),
            )
            self.conn.execute("UPDATE tasks SET state = 'done' WHERE task_id = ?", (task_id,))

            self.event_store.append_event(
                run_id,
                "attempt_submitted",
                "worker",
                {
                    "task_id": task_id,
                    "attempt_id": attempt_id,
                    "generation": generation,
                    "result_digest": result_digest,
                    "receipt": receipt,
                    "usage_availability": usage_record.availability if usage_record else "unavailable",
                },
            )
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise

        self.conn.execute("COMMIT")

        return {"ok": True, "receipt": receipt, "replayed": False}

    def fail_attempt(
        self,
        run_id: str,
        task_id: str,
        attempt_id: str,
        generation: int,
        claim_token: str,
        reason: str,
        retryable: bool = True,
        max_retries: int = 2,
    ) -> Dict[str, Any]:
        """Handle a worker/host failure for an attempt (DSR-065).

        - Retryable failures requeue the task while retries remain: the next
          claim creates a new attempt (generation+1) with a fresh reservation.
          The failed attempt's reservation is released.
        - Non-retryable failures, or retryable failures beyond max_retries,
          quarantine the task and record a coverage gap. The failure is never
          normalized into a successful result.

        Returns {"action": "requeued", ...} or {"action": "quarantined", ...}.
        """
        self._verify_attempt_token(task_id, attempt_id, generation, claim_token)

        attempts_used = self.conn.execute(
            "SELECT COUNT(*) AS cnt FROM attempts WHERE task_id = ?",
            (task_id,),
        ).fetchone()["cnt"]
        retries_used = max(0, attempts_used - 1)

        self.conn.execute("BEGIN IMMEDIATE")
        try:
            self.budget_ledger.release(attempt_id)
            if retryable and retries_used < max_retries:
                self.conn.execute(
                    "UPDATE attempts SET status = 'failed' WHERE attempt_id = ?",
                    (attempt_id,),
                )
                self.conn.execute(
                    "UPDATE tasks SET state = 'queued' WHERE task_id = ?",
                    (task_id,),
                )
                self.event_store.append_event(
                    run_id,
                    "attempt_failed_retriable",
                    "worker",
                    {
                        "task_id": task_id,
                        "attempt_id": attempt_id,
                        "generation": generation,
                        "reason": reason,
                        "retries_used": retries_used,
                        "max_retries": max_retries,
                    },
                )
                result = {
                    "action": "requeued",
                    "task_id": task_id,
                    "attempt_id": attempt_id,
                    "retries_used": retries_used,
                    "retries_remaining": max_retries - retries_used,
                }
            else:
                self.conn.execute(
                    "UPDATE attempts SET status = 'quarantined' WHERE attempt_id = ?",
                    (attempt_id,),
                )
                self.conn.execute(
                    "UPDATE tasks SET state = 'quarantined' WHERE task_id = ?",
                    (task_id,),
                )
                # Coverage gap: quarantined work is never silently dropped (DSR-065).
                self.event_store.append_event(
                    run_id,
                    "coverage_gap",
                    "worker",
                    {
                        "task_id": task_id,
                        "attempt_id": attempt_id,
                        "reason": reason,
                        "retryable": retryable,
                        "retries_used": retries_used,
                        "max_retries": max_retries,
                    },
                )
                result = {
                    "action": "quarantined",
                    "task_id": task_id,
                    "attempt_id": attempt_id,
                    "retries_used": retries_used,
                }
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise

        self.conn.execute("COMMIT")
        return result

    def retain_attempt_budget(
        self,
        run_id: str,
        task_id: str,
        attempt_id: str,
        generation: int,
        claim_token: str,
        reason: str,
    ) -> Dict[str, Any]:
        """Quarantine an attempt while keeping its budget reservation (DSR-064).

        Used when a host reports TerminationUncertainError (process-group
        termination could not be confirmed): the attempt can never produce a
        result, so the task is quarantined and a coverage gap is recorded — but
        the budget reservation is deliberately NOT released, because the worker
        process may still be consuming host resources. The reservation stays
        outstanding until the termination state is resolved out of band.

        Returns {"action": "retained", ...}.
        """
        self._verify_attempt_token(task_id, attempt_id, generation, claim_token)

        self.conn.execute("BEGIN IMMEDIATE")
        try:
            self.conn.execute(
                "UPDATE attempts SET status = 'quarantined' WHERE attempt_id = ?",
                (attempt_id,),
            )
            self.conn.execute(
                "UPDATE tasks SET state = 'quarantined' WHERE task_id = ?",
                (task_id,),
            )
            self.event_store.append_event(
                run_id,
                "attempt_termination_uncertain",
                "task_queue",
                {
                    "task_id": task_id,
                    "attempt_id": attempt_id,
                    "generation": generation,
                    "reason": reason,
                    "budget_retained": True,
                },
            )
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise

        self.conn.execute("COMMIT")
        return {
            "action": "retained",
            "task_id": task_id,
            "attempt_id": attempt_id,
            "budget_retained": True,
        }

    def _verify_attempt_token(
        self,
        task_id: str,
        attempt_id: str,
        generation: int,
        claim_token: str,
        allow_finished: bool = False,
    ) -> sqlite3.Row:
        row = self.conn.execute(
            """
            SELECT a.attempt_id, a.task_id, a.generation, a.status, a.token_digest, a.expires_at, a.result_digest, a.receipt_ref,
                   t.generation as task_current_generation
            FROM attempts a
            JOIN tasks t ON a.task_id = t.task_id
            WHERE a.attempt_id = ? AND a.task_id = ?
            """,
            (attempt_id, task_id),
        ).fetchone()

        if not row:
            raise StaleAttemptError(f"Attempt '{attempt_id}' for task '{task_id}' not found")

        # Check generation
        if row["generation"] != generation:
            raise StaleAttemptError(
                f"Generation mismatch for attempt {attempt_id}: attempt is gen {row['generation']}, provided {generation}"
            )

        # Check token digest
        expected_digest = row["token_digest"]
        actual_digest = sha256_text(claim_token)
        if expected_digest != actual_digest:
            raise StaleAttemptError(f"Invalid claim token for attempt {attempt_id}")

        if not allow_finished and row["status"] == "done":
            raise InvalidStateError(f"Attempt {attempt_id} is already completed")

        # Terminal failed/expired/quarantined attempts can never produce a result
        if row["status"] in ("expired", "quarantined", "failed"):
            raise StaleAttemptError(
                f"Attempt {attempt_id} is no longer active (status '{row['status']}')"
            )

        # Expiration check (if not yet submitted)
        if row["status"] != "done":
            now_iso = utc_now_iso()
            if row["expires_at"] < now_iso:
                raise StaleAttemptError(f"Attempt {attempt_id} has expired at {row['expires_at']}")

        return row
