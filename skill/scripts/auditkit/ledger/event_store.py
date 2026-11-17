"""Append-only event store and revision tracking.

Implements IFC-05 / DSR-016 / DDS-04:
- Monotone revisions per run (unique constraint on run_id, revision).
- Append-only event ledger.
- Reducer and state reconstruction capabilities.
"""

# 需求追踪 (Requirement Traceability)
# ---------------------------------------------------------------------------
# 上层需求: docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2
# 设计依据: docs/design/SOFTWARE_DESIGN.md
# SWR-018  事件只追加、状态视图可重建（replay_events 投影）；未知 payload_version 拒绝
#   绑定实现: DSR-016
# 状态以统一测试结论为准；未实测能力保持 unknown（设计原则 8：能观测的不靠声明）。
#

from __future__ import annotations
import datetime
import json
import sqlite3
import uuid
from typing import Any, Dict, List, Optional

from auditkit.contracts.errors import StorageError, CorruptRunError, UnsupportedSchemaError

# DSR-016: event payload versions this build can read or write. Unknown versions
# are rejected on append and on replay (fail closed, no silent reinterpretation).
SUPPORTED_EVENT_PAYLOAD_VERSIONS = {"1.0"}

# Event types that drive the run-state projection in replay_events.
STATE_EVENT_TYPES = {
    "run_prepared": "ready",
    "run_activated": "active",
    "run_paused": "paused",
}


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO 8601 format. Requirements: SWR-018(support) / DSR-016(UTC时间戳)"""
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


class EventStore:
    """Manages append-only events for runs."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        """Bind the store to a ledger connection.

        Requirements: SWR-018(support) / DSR-016(连接绑定)
        """
        self.conn = conn

    def append_event(
        self,
        run_id: str,
        event_type: str,
        actor: str,
        payload: Dict[str, Any],
        payload_version: str = "1.0",
    ) -> int:
        """Atomically append an event and advance run revision.

        Must be called within an active transaction or with BEGIN IMMEDIATE.
        Unknown payload versions are rejected with UnsupportedSchemaError (DSR-016).
        Returns the new revision number.
        Requirements: SWR-018(原子追加) / DSR-016(修订推进), DSR-017(claim支撑)
        """
        if payload_version not in SUPPORTED_EVENT_PAYLOAD_VERSIONS:
            raise UnsupportedSchemaError(
                f"Unsupported event payload_version '{payload_version}'; "
                f"supported versions are {sorted(SUPPORTED_EVENT_PAYLOAD_VERSIONS)}",
                details={"event_type": event_type, "payload_version": payload_version},
            )

        event_id = f"evt-{uuid.uuid4().hex[:12]}"
        now = utc_now_iso()

        payload_str = json.dumps(payload, sort_keys=True, ensure_ascii=False)

        # IFC-05 / SR-018: revision must be read and advanced inside one
        # BEGIN IMMEDIATE critical section. Real concurrent drivers append
        # events from multiple worker threads (separate connections); a
        # bare SELECT-then-INSERT races on the same revision and trips the
        # (run_id, revision) UNIQUE constraint (RUN-LESSONS, real run-009b).
        own_tx = not self.conn.in_transaction
        if own_tx:
            self.conn.execute("BEGIN IMMEDIATE")
        try:
            row = self.conn.execute(
                "SELECT revision FROM runs WHERE run_id = ?",
                (run_id,),
            ).fetchone()
            if not row:
                raise StorageError(f"Run '{run_id}' not found")

            new_rev = row["revision"] + 1

            self.conn.execute(
                """
                INSERT INTO events (event_id, run_id, revision, event_type, occurred_at, actor, payload_version, payload_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (event_id, run_id, new_rev, event_type, now, actor, payload_version, payload_str),
            )
            self.conn.execute(
                "UPDATE runs SET revision = ?, updated_at = ? WHERE run_id = ?",
                (new_rev, now, run_id),
            )
        except sqlite3.IntegrityError as e:
            if own_tx:
                self.conn.execute("ROLLBACK")
            raise StorageError(f"Failed to append event to run {run_id}: {e}")
        except BaseException:
            if own_tx:
                self.conn.execute("ROLLBACK")
            raise
        if own_tx:
            self.conn.execute("COMMIT")

        return new_rev

    def get_events(self, run_id: str, from_rev: int = 1) -> List[Dict[str, Any]]:
        """Retrieve events ordered by revision. Requirements: SWR-018(support) / DSR-016(事件读取)"""
        cursor = self.conn.execute(
            """
            SELECT event_id, run_id, revision, event_type, occurred_at, actor, payload_version, payload_json
            FROM events
            WHERE run_id = ? AND revision >= ?
            ORDER BY revision ASC
            """,
            (run_id, from_rev),
        )
        events = []
        for row in cursor.fetchall():
            events.append({
                "event_id": row["event_id"],
                "run_id": row["run_id"],
                "revision": row["revision"],
                "event_type": row["event_type"],
                "occurred_at": row["occurred_at"],
                "actor": row["actor"],
                "payload_version": row["payload_version"],
                "payload": json.loads(row["payload_json"]),
            })
        return events

    def replay_events(self, run_id: str) -> Dict[str, Any]:
        """Replay the event log and rebuild the projected run state (DSR-016).

        Unknown payload versions are rejected with UnsupportedSchemaError. The
        projection counts enqueued/claimed/submitted work, derives the run state
        from lifecycle events, and compares the highest replayed revision against
        the persisted runs.revision to detect ledger inconsistency.
        Requirements: SWR-018(重放投影) / DSR-016(投影一致)
        """
        projection: Dict[str, Any] = {
            "run_id": run_id,
            "events_replayed": 0,
            "highest_revision": 0,
            "tasks_enqueued": 0,
            "claims": 0,
            "submissions": 0,
            "run_state": "unknown",
            "revision_consistent": False,
        }

        for event in self.get_events(run_id):
            if event["payload_version"] not in SUPPORTED_EVENT_PAYLOAD_VERSIONS:
                raise UnsupportedSchemaError(
                    f"Cannot replay event {event['event_id']} with unsupported "
                    f"payload_version '{event['payload_version']}'",
                    details={"event_id": event["event_id"], "payload_version": event["payload_version"]},
                )

            projection["events_replayed"] += 1
            projection["highest_revision"] = max(projection["highest_revision"], event["revision"])

            etype = event["event_type"]
            payload = event["payload"]
            if etype == "task_enqueued":
                projection["tasks_enqueued"] += 1
            elif etype == "attempt_claimed":
                projection["claims"] += 1
            elif etype == "attempt_submitted":
                projection["submissions"] += 1
            elif etype in STATE_EVENT_TYPES:
                projection["run_state"] = STATE_EVENT_TYPES[etype]
            elif etype == "run_finalized":
                projection["run_state"] = payload.get("final_state", "unknown")

        row = self.conn.execute("SELECT revision FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        if not row:
            raise StorageError(f"Run '{run_id}' not found")

        persisted_rev = row["revision"]
        projection["persisted_revision"] = persisted_rev
        projection["revision_consistent"] = persisted_rev == projection["highest_revision"]
        return projection
