"""SQLite database initialization, WAL configuration, and schema management.

Implements IFC-07 / DSR-016 / DSR-033 / DSR-072 / DDS-04:
- Enables WAL mode and busy_timeout=5000ms.
- Strict schema definition for runs, events, tasks, attempts, budgets, artifacts, coverage, usage.
- BEGIN IMMEDIATE transactions for multi-process safety.
- Version compatibility reading (DSR-072): unsupported old or future formats are
  rejected with UnsupportedSchemaError; automatic migration is prohibited.
"""

# 需求追踪 (Requirement Traceability)
# ---------------------------------------------------------------------------
# 上层需求: docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2
# 设计依据: docs/design/SOFTWARE_DESIGN.md
# SWR-018  事件库、原子 claim、generation、过期、去重与恢复；并发/崩溃/迟到保持不变量
#   绑定实现: DSR-016, DSR-017
# SWR-027  版本声明、旧格式只读、不自动迁移活动 run；不支持的版本显式拒绝
#   绑定实现: DSR-072
# 状态以统一测试结论为准；未实测能力保持 unknown（设计原则 8：能观测的不靠声明）。
#

from __future__ import annotations
import sqlite3
from pathlib import Path
from typing import Any, Dict, Optional

from auditkit.contracts.errors import UnsupportedSchemaError

# DSR-072: supported formats. Automatic migration of active runs is prohibited;
# encountering any other version must fail closed.
SUPPORTED_SCHEMA_VERSIONS = {"1.0"}
SKILL_VERSION = "0.1.0"
SUPPORTED_KNOWLEDGE_VERSION_MAJOR = "1"


SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    snapshot_id TEXT NOT NULL,
    state TEXT NOT NULL,
    schema_version TEXT NOT NULL,
    skill_version TEXT NOT NULL,
    knowledge_version TEXT NOT NULL,
    config_ref TEXT NOT NULL,
    revision INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    revision INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    actor TEXT NOT NULL,
    payload_version TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    UNIQUE(run_id, revision)
);

CREATE TABLE IF NOT EXISTS tasks (
    task_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    task_key TEXT NOT NULL,
    kind TEXT NOT NULL,
    state TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 10,
    generation INTEGER NOT NULL DEFAULT 0,
    spec_digest TEXT NOT NULL,
    spec_json TEXT NOT NULL,
    UNIQUE(run_id, task_key)
);

CREATE TABLE IF NOT EXISTS attempts (
    attempt_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(task_id),
    generation INTEGER NOT NULL,
    status TEXT NOT NULL,
    token_digest TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    result_digest TEXT,
    receipt_ref TEXT,
    UNIQUE(task_id, generation)
);

CREATE TABLE IF NOT EXISTS budget_dimensions (
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    dimension TEXT NOT NULL,
    mode TEXT NOT NULL,
    limit_val INTEGER NOT NULL,
    settled INTEGER NOT NULL DEFAULT 0,
    reserved INTEGER NOT NULL DEFAULT 0,
    unit TEXT NOT NULL,
    PRIMARY KEY(run_id, dimension)
);

CREATE TABLE IF NOT EXISTS reservations (
    attempt_id TEXT NOT NULL,
    dimension TEXT NOT NULL,
    reserved_val INTEGER NOT NULL,
    settled_val INTEGER,
    state TEXT NOT NULL,
    PRIMARY KEY(attempt_id, dimension)
);

CREATE TABLE IF NOT EXISTS artifacts (
    artifact_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    kind TEXT NOT NULL,
    relative_path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    generation TEXT
);

CREATE TABLE IF NOT EXISTS usage_records (
    attempt_id TEXT NOT NULL,
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    dimension TEXT NOT NULL,
    availability TEXT NOT NULL,
    value INTEGER,
    unit TEXT NOT NULL,
    source TEXT NOT NULL,
    reason TEXT,
    schema_version TEXT NOT NULL DEFAULT '1.0',
    recorded_at TEXT NOT NULL,
    PRIMARY KEY(attempt_id, dimension)
);

CREATE TABLE IF NOT EXISTS coverage_intervals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    snapshot_id TEXT NOT NULL,
    unit_id TEXT NOT NULL,
    path TEXT NOT NULL,
    dimension TEXT NOT NULL,
    start_line INTEGER NOT NULL,
    end_line INTEGER NOT NULL,
    attempt_id TEXT,
    source TEXT NOT NULL,
    confidence TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tasks_run_state ON tasks(run_id, state);
CREATE INDEX IF NOT EXISTS idx_usage_run_dim ON usage_records(run_id, dimension);
CREATE INDEX IF NOT EXISTS idx_attempts_task_gen ON attempts(task_id, generation);
CREATE INDEX IF NOT EXISTS idx_events_run_rev ON events(run_id, revision);
"""


def get_db_connection(db_path: str | Path) -> sqlite3.Connection:
    """Open SQLite connection configured with WAL and busy timeout.

    ``check_same_thread=False``: the driver loop's worker threads read the
    ledger through connections opened by the caller's thread (e.g. audit.py's
    shared run handle used by its execute_fn). SQLite is compiled in serialized
    mode (sqlite3.threadsafety == 3), so statement-level access to one
    connection from several threads is serialized by SQLite itself; write
    transactions stay serialized via BEGIN IMMEDIATE (and the dispatch loop's
    own in-process lock). Cross-process safety is unchanged.
    """
    conn = sqlite3.connect(str(db_path), timeout=5.0, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Configure WAL mode and busy timeout
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA busy_timeout = 5000;")
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_database(db_path: str | Path) -> None:
    """Initialize SQLite database with core tables."""
    conn = get_db_connection(db_path)
    try:
        conn.executescript(SCHEMA_SQL)
    finally:
        conn.close()


def _check_semver_major(version: str, expected_major: str, label: str) -> None:
    """Validate that a dotted version string has the expected major segment."""
    major = version.split(".", 1)[0]
    if major != expected_major:
        raise UnsupportedSchemaError(
            f"Unsupported {label} version '{version}' (expected major version "
            f"'{expected_major}'); automatic migration of existing runs is prohibited",
            details={"version": version, "expected_major": expected_major, "field": label},
        )


def check_version_compatibility(conn: sqlite3.Connection, run_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Read recorded run/schema/skill/knowledge versions and reject unsupported formats.

    Implements DSR-072: opens read the persisted version columns and fail closed on
    unsupported old or future formats. No migration is ever attempted and no record
    is modified. Returns the version info of the (single) inspected run, or None
    when the database contains no matching run.
    """
    if run_id is not None:
        rows = conn.execute(
            "SELECT run_id, schema_version, skill_version, knowledge_version FROM runs WHERE run_id = ?",
            (run_id,),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT run_id, schema_version, skill_version, knowledge_version FROM runs"
        ).fetchall()

    if not rows:
        return None

    skill_major = SKILL_VERSION.split(".", 1)[0]
    info: Dict[str, Any] = {}
    for r in rows:
        if r["schema_version"] not in SUPPORTED_SCHEMA_VERSIONS:
            raise UnsupportedSchemaError(
                f"Run '{r['run_id']}' uses unsupported schema_version '{r['schema_version']}'; "
                f"supported versions are {sorted(SUPPORTED_SCHEMA_VERSIONS)}. Automatic "
                f"migration of existing runs is prohibited",
                details={"run_id": r["run_id"], "schema_version": r["schema_version"]},
            )
        _check_semver_major(r["skill_version"], skill_major, "skill_version")
        _check_semver_major(r["knowledge_version"], SUPPORTED_KNOWLEDGE_VERSION_MAJOR, "knowledge_version")
        info = {
            "run_id": r["run_id"],
            "schema_version": r["schema_version"],
            "skill_version": r["skill_version"],
            "knowledge_version": r["knowledge_version"],
        }
    return info
