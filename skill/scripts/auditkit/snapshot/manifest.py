"""Snapshot manifest representation and root hash computation.

Implements DDS-03 §3.1 / IFC-02 / DSR-012:
- Content-addressed root hash calculated over UTF-8 sorted canonical entries.
- Unambiguous length-prefixed encoding (does NOT include mtime or absolute paths).
- Complete file and exclusion records.
"""

# 需求追踪 (Requirement Traceability)
# ---------------------------------------------------------------------------
# 上层需求: docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2
# 设计依据: docs/design/SOFTWARE_DESIGN.md
# SWR-017  快照清单与内容摘要；gaps/source_control/drift_detected 如实记录
#   绑定实现: DSR-012, DSR-013
# 状态以统一测试结论为准；未实测能力保持 unknown（设计原则 8：能观测的不靠声明）。
#

from __future__ import annotations
import hashlib
import json
from typing import Any, Dict, List, Optional


def compute_root_hash(files: List[Dict[str, Any]]) -> str:
    """Compute deterministic root hash over sorted file entries.

    Entries sorted by path UTF-8 bytes.
    Each entry encoded as:
      {len(path)}:{path}:{len(file_type)}:{file_type}:{bytes}:{sha256}\n
    """
    sorted_files = sorted(files, key=lambda f: f["path"].encode("utf-8"))
    hasher = hashlib.sha256()

    for f in sorted_files:
        p = f["path"]
        t = f.get("file_type", "regular")
        b = str(f["bytes"])
        s = f["sha256"]
        entry_str = f"{len(p.encode('utf-8'))}:{p}:{len(t.encode('utf-8'))}:{t}:{b}:{s}\n"
        hasher.update(entry_str.encode("utf-8"))

    return hasher.hexdigest()


class SnapshotManifest:
    """In-memory representation of a frozen snapshot manifest."""

    def __init__(
        self,
        snapshot_id: str,
        files: List[Dict[str, Any]],
        excluded: List[Dict[str, Any]],
        collection_assumptions: Optional[List[str]] = None,
        root_hash: Optional[str] = None,
        gaps: Optional[List[Dict[str, Any]]] = None,
        source_control: Optional[Dict[str, Any]] = None,
        drift_detected: bool = False,
    ) -> None:
        self.snapshot_id = snapshot_id
        self.files = files
        self.excluded = excluded
        # DSR-013: explicit coverage-gap records {path, reason, detail?}.
        # Reasons: decode_failure / read_failure / symlink_excluded /
        # drift_detected. Empty gaps mean no known coverage blind spots.
        self.gaps = gaps or []
        # DSR-012: honest Git state metadata (clean/dirty/non_git/unknown).
        self.source_control = source_control or {"status": "unknown", "reason": "not probed"}
        self.drift_detected = drift_detected
        self.collection_assumptions = collection_assumptions or [
            "Source tree remained stable during collection window",
            "Symlinks not traversed outside target root",
        ]
        self.hash_algorithm = "sha256"
        self.root_hash = root_hash or compute_root_hash(self.files)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": "1.0",
            "snapshot_id": self.snapshot_id,
            "hash_algorithm": self.hash_algorithm,
            "root_hash": self.root_hash,
            "files": self.files,
            "excluded": self.excluded,
            "gaps": self.gaps,
            "source_control": self.source_control,
            "drift_detected": self.drift_detected,
            "collection_assumptions": self.collection_assumptions,
        }

    def save_json(self, output_path: str) -> None:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)
            f.write("\n")

    @classmethod
    def load_json(cls, input_path: str) -> SnapshotManifest:
        with open(input_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls(
            snapshot_id=data["snapshot_id"],
            files=data["files"],
            excluded=data["excluded"],
            collection_assumptions=data.get("collection_assumptions"),
            root_hash=data.get("root_hash"),
            gaps=data.get("gaps"),
            source_control=data.get("source_control"),
            drift_detected=bool(data.get("drift_detected", False)),
        )
