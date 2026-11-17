"""Trusted host usage collection, validation, and settlement.

Implements DSR-033 / DSR-020:
- Loads and validates usage objects following usage.schema.json
  (exact / estimated / unavailable availability, with mandatory source).
- Missing values are stored as NULL (never coerced to zero or to a fixed
  "1 task" placeholder).
- Reservations for attempts whose usage is unavailable are never released back
  to the available pool (a lost worker's reserved amount is settled, not freed).
"""

# 需求追踪 (Requirement Traceability)
# ---------------------------------------------------------------------------
# 上层需求: docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2
# 设计依据: docs/design/SOFTWARE_DESIGN.md
# SWR-020  宿主来源用量：exact/estimated/unavailable + 来源；缺数据为 null 不得当零
#   绑定实现: DSR-033
# 状态以统一测试结论为准；未实测能力保持 unknown（设计原则 8：能观测的不靠声明）。
#

from __future__ import annotations
import sqlite3
from dataclasses import dataclass
from typing import Any, Dict, Optional

from auditkit.contracts.errors import InvalidInputError, UnsupportedSchemaError
from auditkit.contracts.types import Usage

SUPPORTED_USAGE_SCHEMA_VERSIONS = {"1.0"}
SUPPORTED_AVAILABILITY = ("exact", "estimated", "unavailable")


@dataclass
class UsageRecord:
    """Validated usage record tied to a single attempt and dimension."""

    attempt_id: str
    dimension: str
    availability: str
    unit: str
    source: str
    value: Optional[int] = None
    reason: Optional[str] = None
    schema_version: str = "1.0"

    def to_storage_tuple(self, run_id: str, recorded_at: str) -> tuple:
        """Return the tuple used to persist this record into usage_records. Requirements: SWR-020(support) / DSR-033(落库元组)"""
        return (
            self.attempt_id,
            run_id,
            self.dimension,
            self.availability,
            self.value,
            self.unit,
            self.source,
            self.reason,
            self.schema_version,
            recorded_at,
        )

    def to_dict(self) -> Usage:
        """Return the plain-dict usage representation (usage.schema.json). Requirements: SWR-020(support) / DSR-033(字典表示)"""
        d: Usage = {
            "schema_version": self.schema_version,
            "attempt_id": self.attempt_id,
            "dimension": self.dimension,
            "availability": self.availability,
            "unit": self.unit,
            "source": self.source,
        }
        if self.value is not None:
            d["value"] = self.value
        if self.reason is not None:
            d["reason"] = self.reason
        return d


def parse_usage(data: Any) -> UsageRecord:
    """Validate a usage object and return a UsageRecord.

    Raises UnsupportedSchemaError for unknown schema versions and
    InvalidInputError for missing/unknown fields or invalid values.
    Requirements: SWR-020(用量校验) / DSR-033(缺失为null)
    """
    if not isinstance(data, dict):
        raise InvalidInputError("usage must be an object")

    version = data.get("schema_version")
    if version is None:
        raise InvalidInputError("usage.schema_version is required")
    if version not in SUPPORTED_USAGE_SCHEMA_VERSIONS:
        raise UnsupportedSchemaError(
            f"Unsupported usage schema_version '{version}'; "
            f"supported versions are {sorted(SUPPORTED_USAGE_SCHEMA_VERSIONS)}"
        )

    allowed = {
        "schema_version",
        "attempt_id",
        "dimension",
        "availability",
        "value",
        "unit",
        "source",
        "reason",
    }
    unknown = sorted(set(data.keys()) - allowed)
    if unknown:
        raise InvalidInputError(
            f"usage has unknown field(s): {', '.join(unknown)}",
            details={"unknown_fields": unknown},
        )

    for req in ("attempt_id", "dimension", "availability", "unit", "source"):
        v = data.get(req)
        if not isinstance(v, str) or not v:
            raise InvalidInputError(f"usage.{req} is required and must be a non-empty string")

    availability = data["availability"]
    if availability not in SUPPORTED_AVAILABILITY:
        raise InvalidInputError(
            f"usage.availability must be one of {list(SUPPORTED_AVAILABILITY)}, got '{availability}'"
        )

    value = data.get("value")
    if availability in ("exact", "estimated"):
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise InvalidInputError(
                f"usage with availability '{availability}' requires integer value >= 0, got {value!r}"
            )
    else:  # unavailable
        if value is not None:
            raise InvalidInputError(
                "usage with availability 'unavailable' must not carry a value (value must be null)"
            )

    reason = data.get("reason")
    if reason is not None and not isinstance(reason, str):
        raise InvalidInputError("usage.reason must be a string when present")
    if availability == "unavailable" and not reason:
        raise InvalidInputError("usage with availability 'unavailable' requires a non-empty reason")

    return UsageRecord(
        attempt_id=data["attempt_id"],
        dimension=data["dimension"],
        availability=availability,
        unit=data["unit"],
        source=data["source"],
        value=value,
        reason=reason,
        schema_version=version,
    )


def store_usage(conn: sqlite3.Connection, run_id: str, record: UsageRecord, recorded_at: str) -> None:
    """Persist a validated usage record into the usage_records table (DSR-033). Requirements: SWR-020(support) / DSR-033(用量落库)"""
    conn.execute(
        """
        INSERT INTO usage_records (attempt_id, run_id, dimension, availability, value, unit, source, reason, schema_version, recorded_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(attempt_id, dimension) DO UPDATE SET
            availability = excluded.availability,
            value = excluded.value,
            unit = excluded.unit,
            source = excluded.source,
            reason = excluded.reason,
            schema_version = excluded.schema_version,
            recorded_at = excluded.recorded_at
        """,
        record.to_storage_tuple(run_id, recorded_at),
    )


def get_attempt_usage(conn: sqlite3.Connection, attempt_id: str) -> Dict[str, UsageRecord]:
    """Return stored usage records for an attempt, keyed by dimension. Requirements: SWR-020(support) / DSR-033(按维读取)"""
    rows = conn.execute(
        "SELECT attempt_id, dimension, availability, value, unit, source, reason, schema_version "
        "FROM usage_records WHERE attempt_id = ?",
        (attempt_id,),
    ).fetchall()
    out: Dict[str, UsageRecord] = {}
    for r in rows:
        out[r["dimension"]] = UsageRecord(
            attempt_id=r["attempt_id"],
            dimension=r["dimension"],
            availability=r["availability"],
            unit=r["unit"],
            source=r["source"],
            value=r["value"],
            reason=r["reason"],
            schema_version=r["schema_version"],
        )
    return out
