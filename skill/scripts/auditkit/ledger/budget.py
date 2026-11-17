"""Multi-dimensional budget ledger and reservation management.

Implements DSR-019 / DSR-020 / DSR-033 / DSR-066 / SD-07:
- Integer units and explicit currency/units.
- Atomic reservation in enforced mode before claim dispatch.
- Verification budget protection (hunt tasks cannot consume verification reservation).
- Safe settlement: u <= r releases (r - u); u > r freezes dispatch.
"""

# 需求追踪 (Requirement Traceability)
# ---------------------------------------------------------------------------
# 上层需求: docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2
# 设计依据: docs/design/SOFTWARE_DESIGN.md
# SWR-019  预算事务预留与结算：已结算+保留+新预留 ≤ 上限；不可度量维度诚实降级（unavailable）
#   绑定实现: DSR-020, DSR-033, DSR-066
# 状态以统一测试结论为准；未实测能力保持 unknown（设计原则 8：能观测的不靠声明）。
#

from __future__ import annotations
import sqlite3
from typing import Any, Dict, List, Optional, Tuple

from auditkit.contracts.errors import BudgetExhaustedError, StorageError


class BudgetLedger:
    """Manages multi-dimensional budgets and atomic reservations."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        """Bind the ledger connection for budget accounting.

        Requirements: SWR-019(support) / DSR-020(账本装配)
        """
        self.conn = conn

    def set_budget(
        self,
        run_id: str,
        dimension: str,
        limit_val: int,
        unit: str,
        mode: str = "enforced",
    ) -> None:
        """Initialize or update a budget dimension. Requirements: SWR-019(分维模式) / DSR-020(预算设定)"""
        self.conn.execute(
            """
            INSERT INTO budget_dimensions (run_id, dimension, mode, limit_val, settled, reserved, unit)
            VALUES (?, ?, ?, ?, 0, 0, ?)
            ON CONFLICT(run_id, dimension) DO UPDATE SET
                mode = excluded.mode,
                limit_val = excluded.limit_val,
                unit = excluded.unit
            """,
            (run_id, dimension, mode, limit_val, unit),
        )

    def reserve(
        self,
        run_id: str,
        attempt_id: str,
        dimension: str,
        amount: int,
        is_hunt_task: bool = False,
        verify_reserve_ratio: float = 0.3,
    ) -> None:
        """Reserve budget for an attempt atomically (DSR-020).

        The read-check-update sequence runs inside BEGIN IMMEDIATE ... COMMIT when
        no transaction is already active on the connection, so two concurrent
        reservers competing for the last unit cannot both succeed. Raises
        BudgetExhaustedError if an enforced limit would be breached. Enforces
        verification budget protection if is_hunt_task is True.
        Requirements: SWR-019(原子预留) / DSR-020(并发唯一), DSR-066(验证保护)
        """
        own_tx = not self.conn.in_transaction
        if own_tx:
            self.conn.execute("BEGIN IMMEDIATE")
        try:
            self._apply_reserve(run_id, attempt_id, dimension, amount, is_hunt_task, verify_reserve_ratio)
        except BaseException:
            if own_tx:
                self.conn.execute("ROLLBACK")
            raise
        if own_tx:
            self.conn.execute("COMMIT")

    def _apply_reserve(
        self,
        run_id: str,
        attempt_id: str,
        dimension: str,
        amount: int,
        is_hunt_task: bool,
        verify_reserve_ratio: float,
    ) -> None:
        """Reservation body executed inside the caller's transaction. Requirements: SWR-019(support) / DSR-020(预留体), DSR-066(验证保留)"""
        row = self.conn.execute(
            "SELECT mode, limit_val, settled, reserved FROM budget_dimensions WHERE run_id = ? AND dimension = ?",
            (run_id, dimension),
        ).fetchone()

        if not row:
            # Dimension not constrained
            return

        mode = row["mode"]
        limit_val = row["limit_val"]
        settled = row["settled"]
        reserved = row["reserved"]

        if mode == "enforced":
            available = limit_val - (settled + reserved)

            # Verification protection: if hunt task, protect verify_reserve_ratio of total limit
            if is_hunt_task:
                protected_for_verify = int(limit_val * verify_reserve_ratio)
                max_hunt_available = max(0, available - protected_for_verify)
                if amount > max_hunt_available:
                    raise BudgetExhaustedError(
                        f"Budget limit reached for hunt on dimension '{dimension}' "
                        f"(available: {max_hunt_available}, requested: {amount}, protected for verify: {protected_for_verify})"
                    )

            if amount > available:
                raise BudgetExhaustedError(
                    f"Budget exhausted for dimension '{dimension}' "
                    f"(limit: {limit_val}, settled: {settled}, reserved: {reserved}, requested: {amount})"
                )

        # Reservation accounting applies to EVERY mode: only `enforced` may
        # refuse (hard limit), but observed/unavailable dimensions still track
        # their outstanding reservations honestly — a reservation that is not
        # reflected in `reserved` would under-report the committed budget
        # (DSR-020 / SR-019: degraded dimensions stay honest, never unaccounted).
        self.conn.execute(
            """
            UPDATE budget_dimensions
            SET reserved = reserved + ?
            WHERE run_id = ? AND dimension = ?
            """,
            (amount, run_id, dimension),
        )

        self.conn.execute(
            """
            INSERT INTO reservations (attempt_id, dimension, reserved_val, settled_val, state)
            VALUES (?, ?, ?, NULL, 'reserved')
            ON CONFLICT(attempt_id, dimension) DO UPDATE SET
                reserved_val = excluded.reserved_val,
                state = 'reserved'
            """,
            (attempt_id, dimension, amount),
        )

    def release(self, attempt_id: str, run_id: Optional[str] = None) -> int:
        """Release all outstanding reservations of an attempt (DSR-019 / DSR-065).

        Returns the number of reservation rows released. Released amounts are
        returned to the available pool (reserved is decreased). Settled or
        already released reservations are left untouched.

        ``run_id``: when given, the reservations are attributed to this run
        directly. This supports in-process reservations whose key is not a
        dispatch attempt row (e.g. connector evaluation budgets); without it,
        the run is resolved through the attempt -> task join, and reservations
        without a matching attempt row are left untouched.
        Requirements: SWR-019(释放回池) / DSR-019(恢复释放), DSR-020(预留释放), DSR-065(重试释放)
        """
        own_tx = not self.conn.in_transaction
        if own_tx:
            self.conn.execute("BEGIN IMMEDIATE")
        try:
            released = self._apply_release(attempt_id, run_id)
        except BaseException:
            if own_tx:
                self.conn.execute("ROLLBACK")
            raise
        if own_tx:
            self.conn.execute("COMMIT")
        return released

    def _apply_release(self, attempt_id: str, run_id: Optional[str] = None) -> int:
        """Release body executed inside the caller's transaction. Requirements: SWR-019(support) / DSR-020(释放体)"""
        res_rows = self.conn.execute(
            "SELECT dimension, reserved_val FROM reservations WHERE attempt_id = ? AND state = 'reserved'",
            (attempt_id,),
        ).fetchall()
        released = 0
        for r in res_rows:
            resolved_run_id = run_id
            if resolved_run_id is None:
                task_row = self.conn.execute(
                    """
                    SELECT t.run_id
                    FROM attempts a
                    JOIN tasks t ON a.task_id = t.task_id
                    WHERE a.attempt_id = ?
                    """,
                    (attempt_id,),
                ).fetchone()
                if not task_row:
                    continue
                resolved_run_id = task_row["run_id"]
            self.conn.execute(
                """
                UPDATE budget_dimensions
                SET reserved = max(0, reserved - ?)
                WHERE run_id = ? AND dimension = ?
                """,
                (r["reserved_val"], resolved_run_id, r["dimension"]),
            )
            self.conn.execute(
                "UPDATE reservations SET state = 'released' WHERE attempt_id = ? AND dimension = ?",
                (attempt_id, r["dimension"]),
            )
            released += 1
        return released

    def settle(
        self,
        attempt_id: str,
        dimension: str,
        actual_used: Optional[int],
        run_id: Optional[str] = None,
    ) -> None:
        """Settle reserved budget against actual usage (DSR-020 / DSR-033).

        actual_used=None records unknown usage: the reserved amount is moved to
        settled (never released back to the available pool). Runs atomically via
        BEGIN IMMEDIATE when no transaction is active on the connection.

        ``run_id``: when given, the settlement is attributed to this run
        directly (used for in-process reservations such as connector evaluation
        budgets whose key is not a dispatch attempt row).
        Requirements: SWR-019(事务结算), SWR-020 / DSR-020(结算原子), DSR-033(未知保留)
        """
        own_tx = not self.conn.in_transaction
        if own_tx:
            self.conn.execute("BEGIN IMMEDIATE")
        try:
            self._apply_settle(attempt_id, dimension, actual_used, run_id)
        except BaseException:
            if own_tx:
                self.conn.execute("ROLLBACK")
            raise
        if own_tx:
            self.conn.execute("COMMIT")

    def _apply_settle(
        self,
        attempt_id: str,
        dimension: str,
        actual_used: Optional[int],
        run_id: Optional[str] = None,
    ) -> None:
        """Settlement body executed inside the caller's transaction. Requirements: SWR-019(support) / DSR-020(结算体), DSR-033(未知保留)"""
        # Find run_id (caller-supplied value wins; otherwise resolve through
        # the attempt -> task join).
        if run_id is None:
            task_row = self.conn.execute(
                """
                SELECT t.run_id
                FROM attempts a
                JOIN tasks t ON a.task_id = t.task_id
                WHERE a.attempt_id = ?
                """,
                (attempt_id,),
            ).fetchone()
            if not task_row:
                return
            run_id = task_row["run_id"]

        res_row = self.conn.execute(
            "SELECT reserved_val, state FROM reservations WHERE attempt_id = ? AND dimension = ?",
            (attempt_id, dimension),
        ).fetchone()

        if res_row is None:
            # No reservation exists for this attempt/dimension (e.g. usage
            # reported for a dimension that was never reserved at claim time).
            # A known value is still accounted post hoc so reported usage is
            # never silently dropped; unknown usage has nothing to settle.
            if actual_used is None:
                return
            self.conn.execute(
                "UPDATE budget_dimensions SET settled = settled + ? WHERE run_id = ? AND dimension = ?",
                (actual_used, run_id, dimension),
            )
            self.conn.execute(
                """
                INSERT INTO reservations (attempt_id, dimension, reserved_val, settled_val, state)
                VALUES (?, ?, 0, ?, 'settled')
                """,
                (attempt_id, dimension, actual_used),
            )
            return

        if res_row["state"] == "settled":
            return

        reserved_val = res_row["reserved_val"]

        if actual_used is None:
            # Usage unknown: keep reservation settled at reserved_val
            settled_amount = reserved_val
            delta_reserved = -reserved_val
            delta_settled = reserved_val
        else:
            settled_amount = actual_used
            delta_reserved = -reserved_val
            delta_settled = actual_used

        self.conn.execute(
            """
            UPDATE budget_dimensions
            SET reserved = max(0, reserved + ?),
                settled = settled + ?
            WHERE run_id = ? AND dimension = ?
            """,
            (delta_reserved, delta_settled, run_id, dimension),
        )

        self.conn.execute(
            """
            UPDATE reservations
            SET settled_val = ?, state = 'settled'
            WHERE attempt_id = ? AND dimension = ?
            """,
            (settled_amount, attempt_id, dimension),
        )

    def get_summary(self, run_id: str) -> List[Dict[str, Any]]:
        """Return list of budget statuses including usage availability and source (DSR-033).

        availability reflects the recorded trusted usage for the dimension:
        - "exact": at least one exact usage record exists.
        - "estimated": usage records exist but none is exact.
        - "unavailable": no usage data at all, or only unavailable records.
        value is the recomputable numerator for the dimension: the sum of the
        exact/estimated record values when any is known (matching how
        settlement books the dimension), None otherwise. source is the source
        of the most recent usage record, or None when data is missing; missing
        values stay null and are never defaulted to zero.
        Requirements: SWR-019(预算汇总), SWR-020 / DSR-033(可用性溯源)
        """
        rows = self.conn.execute(
            "SELECT dimension, mode, limit_val, settled, reserved, unit FROM budget_dimensions WHERE run_id = ?",
            (run_id,),
        ).fetchall()

        summaries: List[Dict[str, Any]] = []
        for r in rows:
            usage_rows = self.conn.execute(
                """
                SELECT availability, source, value, recorded_at
                FROM usage_records
                WHERE run_id = ? AND dimension = ?
                ORDER BY recorded_at DESC
                """,
                (run_id, r["dimension"]),
            ).fetchall()

            if usage_rows:
                availabilities = [u["availability"] for u in usage_rows]
                known_values = [
                    u["value"] for u in usage_rows
                    if u["availability"] in ("exact", "estimated") and u["value"] is not None
                ]
                if "exact" in availabilities:
                    availability = "exact"
                elif all(a == "unavailable" for a in availabilities):
                    availability = "unavailable"
                else:
                    availability = "estimated"
                source = usage_rows[0]["source"]
                # The reported value must be consistent with the availability
                # label and recomputable (SR-020): when the dimension carries
                # any known value it is the sum of the exact/estimated records
                # — the same numerator settlement books — never just the newest
                # record's value (a mixed dimension with an unavailable latest
                # record would otherwise report availability "exact" and a
                # null numerator).
                value = sum(known_values) if known_values else None
            else:
                availability = "unavailable"
                source = None
                value = None

            summaries.append(
                {
                    "schema_version": "1.0",
                    "dimension": r["dimension"],
                    "mode": r["mode"],
                    "limit": r["limit_val"],
                    "settled": r["settled"],
                    "reserved": r["reserved"],
                    "unit": r["unit"],
                    "availability": availability,
                    "source": source,
                    "value": value,
                }
            )
        return summaries
