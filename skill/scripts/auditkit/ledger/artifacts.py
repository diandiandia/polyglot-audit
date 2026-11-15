"""Atomic artifact publishing protocol and integrity checks.

Implements DSR-019 / DDS-04 / IFC-05 / REV-12:
- Two-phase artifact publishing:
  1. Write to temporary file in target directory
  2. Flush and fsync
  3. Atomic rename/replace to final path
  4. Record in database artifacts table
- Integrity audit: verifies that all published artifacts exist and hashes match.
- Missing referenced artifacts trigger CorruptRunError.
- Safely cleans up orphan unreferenced temporary artifacts.
"""

# 需求追踪 (Requirement Traceability)
# ---------------------------------------------------------------------------
# 上层需求: docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2
# 设计依据: docs/design/SOFTWARE_DESIGN.md
# SWR-013  卷宗持久化：tmp+fsync+原子重命名；引用缺失转 corrupt，不删用户文件
#   绑定实现: DSR-019, DSR-036
# 状态以统一测试结论为准；未实测能力保持 unknown（设计原则 8：能观测的不靠声明）。
#

from __future__ import annotations
import hashlib
import os
import sqlite3
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from auditkit.contracts.errors import CorruptRunError, StorageError


class ArtifactManager:
    """Manages file artifacts tied to a run."""

    def __init__(self, run_dir: str | Path, conn: sqlite3.Connection) -> None:
        self.run_dir = Path(os.path.realpath(os.path.abspath(run_dir)))
        self.conn = conn

    def publish_artifact(
        self,
        run_id: str,
        kind: str,
        rel_path: str,
        content_bytes: bytes,
        generation: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Atomically write and register an artifact."""
        final_path = self.run_dir / rel_path
        final_path.parent.mkdir(parents=True, exist_ok=True)

        temp_name = f".tmp-{uuid.uuid4().hex[:8]}-{final_path.name}"
        temp_path = final_path.parent / temp_name

        hasher = hashlib.sha256()
        hasher.update(content_bytes)
        sha256_digest = hasher.hexdigest()
        size_bytes = len(content_bytes)

        try:
            with open(temp_path, "wb") as f:
                f.write(content_bytes)
                f.flush()
                os.fsync(f.fileno())

            # Atomic replace
            os.replace(temp_path, final_path)
        except OSError as e:
            if temp_path.exists():
                temp_path.unlink(missing_ok=True)
            raise StorageError(f"Failed to publish artifact {rel_path}: {e}")

        artifact_id = f"art-{uuid.uuid4().hex[:12]}"

        # Republishing the same path replaces the prior reference: integrity
        # verification hashes the current file, so a stale row for a previous
        # version of the same relative path would report a false corruption.
        self.conn.execute(
            "DELETE FROM artifacts WHERE run_id = ? AND relative_path = ?",
            (run_id, rel_path),
        )

        # Record in DB
        self.conn.execute(
            """
            INSERT INTO artifacts (artifact_id, run_id, kind, relative_path, sha256, size_bytes, generation)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (artifact_id, run_id, kind, rel_path, sha256_digest, size_bytes, generation),
        )

        return {
            "artifact_id": artifact_id,
            "kind": kind,
            "relative_path": rel_path,
            "sha256": sha256_digest,
            "size_bytes": size_bytes,
        }

    def verify_artifacts(self, run_id: str) -> None:
        """Verify all referenced artifacts exist and match digests."""
        rows = self.conn.execute(
            "SELECT artifact_id, kind, relative_path, sha256, size_bytes FROM artifacts WHERE run_id = ?",
            (run_id,),
        ).fetchall()

        for r in rows:
            path = self.run_dir / r["relative_path"]
            if not path.exists():
                raise CorruptRunError(
                    f"Referenced artifact missing from disk: {r['relative_path']}",
                    details={"artifact_id": r["artifact_id"], "path": r["relative_path"]},
                )
            # Check sha256
            hasher = hashlib.sha256()
            with open(path, "rb") as f:
                while chunk := f.read(65536):
                    hasher.update(chunk)
            if hasher.hexdigest() != r["sha256"]:
                raise CorruptRunError(
                    f"Artifact content hash corrupted: {r['relative_path']}",
                    details={"artifact_id": r["artifact_id"], "expected": r["sha256"], "actual": hasher.hexdigest()},
                )

    def cleanup_orphaned_temps(self) -> int:
        """Remove leftover .tmp files in run_dir."""
        removed = 0
        for root, _, files in os.walk(self.run_dir):
            for fname in files:
                if fname.startswith(".tmp-"):
                    try:
                        (Path(root) / fname).unlink(missing_ok=True)
                        removed += 1
                    except OSError:
                        pass
        return removed
