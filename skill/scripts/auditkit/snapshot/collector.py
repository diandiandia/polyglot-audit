"""Deterministic snapshot collector and drift detection.

Implements DSR-011 / DSR-012 / DSR-013 / DDS-03 §3.1:
- Content-addressed file copying into private snapshot folder.
- SHA-256 digest computation.
- 1-based closed interval line counting with CRLF normalization.
- Pre/post collection re-check for drift detection, including content-level
  SHA-256 re-verification (same-size/same-mtime rewrites MUST be detected;
  mtime/size alone is never treated as proof of stability).
- Dirty Git worktree detection (via `git status --porcelain`; non-Git and
  missing-git cases are recorded honestly, never guessed).
- Handles decode failures, read failures and symlinks safely: symlinks are
  excluded (with gap records), opened files use O_NOFOLLOW plus post-open
  realpath re-verification to defend against TOCTOU escapes.
"""

# 需求追踪 (Requirement Traceability)
# ---------------------------------------------------------------------------
# 上层需求: docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2
# 设计依据: docs/design/SOFTWARE_DESIGN.md
# SWR-017  内容寻址只读快照、采集复查、漂移检出（禁止仅用 mtime）、dirty Git 与失败处理
#   绑定实现: DSR-012, DSR-013
# SWR-015  目标代码只读：symlink 不跟随、O_NOFOLLOW 防 TOCTOU
#   绑定实现: DSR-011, DSR-008
# 状态以统一测试结论为准；未实测能力保持 unknown（设计原则 8：能观测的不靠声明）。
#

from __future__ import annotations
import hashlib
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from auditkit.contracts.errors import (
    PathUnsafeError,
    SnapshotInconsistentError,
    StorageError,
)
from auditkit.snapshot.manifest import SnapshotManifest, compute_root_hash
from auditkit.snapshot.paths import check_symlink_safety, validate_canonical_relpath

# Gap reason codes recorded in the manifest `gaps` list (DSR-013).
GAP_DECODE_FAILURE = "decode_failure"
GAP_DRIFT_DETECTED = "drift_detected"
GAP_READ_FAILURE = "read_failure"
GAP_SYMLINK_EXCLUDED = "symlink_excluded"

# Number of bytes re-read at the head of each file for language detection.
LANGUAGE_SNIFF_BYTES = 4096

# Linux/BSD hardening flag; absent on platforms without it (e.g. some CI FS).
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


def check_git_status(target_dir: str | Path) -> Dict[str, str]:
    """Detect the Git state of the target directory without mutating anything.

    Returns a dict with at least a ``status`` key:
    - ``clean``   : inside a Git repository with no uncommitted changes.
    - ``dirty``   : inside a Git repository with uncommitted changes
                    (``details`` carries a truncated ``git status --porcelain``).
    - ``non_git`` : Git is available but the target is not inside a repository.
    - ``unknown`` : the git binary is missing or the probe timed out; this is
                    recorded honestly and never blocks collection by itself.

    Git metadata is supplementary only (SR-017 / REV-01): content digests,
    not Git state, decide snapshot consistency.

    Requirements: SWR-017(dirty/non_git/unknown如实) / DSR-012(Git状态仅辅助).
    """
    try:
        proc = subprocess.run(
            ["git", "-C", str(target_dir), "status", "--porcelain"],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except FileNotFoundError:
        return {"status": "unknown", "reason": "git binary not available"}
    except subprocess.TimeoutExpired:
        return {"status": "unknown", "reason": "git status probe timed out"}
    except OSError as e:
        return {"status": "unknown", "reason": f"git probe failed: {e}"}

    if proc.returncode != 0:
        return {
            "status": "non_git",
            "reason": (proc.stderr or "not a git repository").strip()[:200],
        }
    if proc.stdout.strip():
        return {"status": "dirty", "details": proc.stdout.strip()[:500]}
    return {"status": "clean"}


def count_lines(content_bytes: bytes) -> Tuple[int, str]:
    """Count lines under 1-based closed interval convention and detect encoding.

    Rules:
    - Empty file: 0 lines
    - CRLF counts as 1 line ending
    - Trailing newline at EOF does not create an extra line
    - Content that is not valid UTF-8 and contains NUL bytes is classified
      as ``binary`` (decode failure recorded upstream as a gap).

    Requirements: SWR-017(行数/编码/二进制判定) / DSR-012(行数字段), DSR-013(解码失败缺口).
    """
    if len(content_bytes) == 0:
        return 0, "utf-8"

    # Attempt utf-8 decoding first
    encoding = "utf-8"
    try:
        text = content_bytes.decode("utf-8")
    except UnicodeDecodeError:
        if b"\x00" in content_bytes:
            # NUL bytes with broken UTF-8: treat as binary payload (DSR-013).
            return 0, "binary"
        try:
            text = content_bytes.decode("latin1")
            encoding = "latin1"
        except UnicodeDecodeError:
            return 0, "binary"

    # Split lines preserving standard line semantics
    # splitlines() splits on \r, \n, \r\n without trailing empty strings
    lines = text.splitlines()
    return len(lines), encoding


class SnapshotCollector:
    """Collects and freezes a snapshot of the target directory."""

    def __init__(
        self,
        target_dir: str | Path,
        snapshot_dest_dir: str | Path,
        is_excluded_fn: Optional[Callable[[str], Tuple[bool, str]]] = None,
        language_detector_fn: Optional[Callable[[str, bytes], Tuple[str, str]]] = None,
        reject_dirty_git: bool = False,
        on_drift: str = "raise",
        knowledge_dir: Optional[str | Path] = None,
    ) -> None:
        """Create a collector.

        - ``reject_dirty_git``: when True, a dirty Git worktree aborts
          collection before any file is copied (DSR-012). When False (default)
          the dirty state is recorded honestly in ``manifest.source_control``.
        - ``on_drift``: ``raise`` (default) aborts on content drift detected
          during the collection window; ``record`` instead records
          ``drift_detected`` gap entries and flags the manifest.
        - ``knowledge_dir``: the skill knowledge root. When set, the collector
          records which collected languages have no knowledge signal
          definitions (``knowledge/languages/<lang>/signals.json`` missing) as
          explicit collection assumptions, so the absence of knowledge backing
          is disclosed instead of discovered later (DSR-013/DSR-038).

        Requirements: SWR-017(漂移策略与dirty拒绝) / DSR-012, DSR-013 (support).
        """
        if on_drift not in ("raise", "record"):
            raise StorageError(f"Unsupported on_drift policy: {on_drift!r}")
        self.target_dir = Path(os.path.realpath(os.path.abspath(target_dir)))
        self.snapshot_dest_dir = Path(os.path.realpath(os.path.abspath(snapshot_dest_dir)))
        self.is_excluded_fn = is_excluded_fn or (lambda p: (False, ""))
        self.language_detector_fn = language_detector_fn or (lambda p, b: ("unknown", "default"))
        self.reject_dirty_git = reject_dirty_git
        self.on_drift = on_drift
        self.knowledge_dir = (
            Path(os.path.realpath(os.path.abspath(knowledge_dir))) if knowledge_dir else None
        )

    def collect(self) -> SnapshotManifest:
        """Execute full snapshot collection with pre/post drift checking.

        Requirements: SWR-017(只读快照+采集复查), SWR-015(不跟随链接)
        / DSR-012(复制与内容摘要), DSR-013(复查失败处理), DSR-011(TOCTOU防护).
        """
        if not self.target_dir.exists() or not self.target_dir.is_dir():
            raise StorageError(f"Target directory does not exist: {self.target_dir}")

        temp_dest = self.snapshot_dest_dir.parent / f"{self.snapshot_dest_dir.name}.tmp"
        if temp_dest.exists():
            shutil.rmtree(temp_dest)
        temp_dest.mkdir(parents=True, exist_ok=True)

        try:
            # 0. Source control state (DSR-012): dirty Git is supplementary
            # metadata, never a substitute for content digests.
            git_status = check_git_status(self.target_dir)
            if git_status["status"] == "dirty" and self.reject_dirty_git:
                raise SnapshotInconsistentError(
                    "Source Git worktree is dirty; refusing to freeze a snapshot",
                    details={"source_control": git_status},
                )

            # 1. Pre-collection scan
            pre_inventory = self._scan_source_tree()

            collected_files: List[Dict[str, Any]] = []
            excluded_files: List[Dict[str, Any]] = []
            gaps: List[Dict[str, Any]] = []
            collected_hashes: Dict[str, str] = {}

            # 2. Copy and hash files
            for relpath, stat_info in pre_inventory.items():
                src_path = self.target_dir / relpath
                dest_path = temp_dest / relpath

                # Check symlinks: never traverse; record whether the link
                # would have escaped the target root (DSR-011 / DSR-013).
                if src_path.is_symlink():
                    escaped = not check_symlink_safety(self.target_dir, src_path)
                    detail = (
                        "symlink target escapes target root"
                        if escaped
                        else "symlinks are not traversed by default"
                    )
                    excluded_files.append({
                        "path": relpath,
                        "reason": f"symlink_excluded: {detail}",
                    })
                    gaps.append({"path": relpath, "reason": GAP_SYMLINK_EXCLUDED, "detail": detail})
                    continue

                if not src_path.is_file():
                    continue

                # Check exclusion rules
                is_excl, reason = self.is_excluded_fn(relpath)
                if is_excl:
                    excluded_files.append({
                        "path": relpath,
                        "reason": reason or "Excluded by rule",
                    })
                    continue

                # Read and hash file with TOCTOU defenses (DSR-011):
                # O_NOFOLLOW open plus post-open realpath containment check.
                try:
                    content = self._read_file_nofollow(src_path)
                except OSError as e:
                    # Read failures are recorded as coverage gaps instead of
                    # being silently swallowed (DSR-013).
                    gaps.append({
                        "path": relpath,
                        "reason": GAP_READ_FAILURE,
                        "detail": str(e),
                    })
                    continue

                if not self._resolved_within_target(src_path):
                    gaps.append({
                        "path": relpath,
                        "reason": GAP_READ_FAILURE,
                        "detail": "resolved path escaped target root after open",
                    })
                    continue

                sha256 = hashlib.sha256(content).hexdigest()
                collected_hashes[relpath] = sha256
                file_size = len(content)
                line_count, encoding = count_lines(content)
                if encoding == "binary":
                    gaps.append({
                        "path": relpath,
                        "reason": GAP_DECODE_FAILURE,
                        "detail": "content is binary (NUL bytes, not valid UTF-8)",
                    })
                language, component = self.language_detector_fn(relpath, content[:LANGUAGE_SNIFF_BYTES])

                # Copy to temp dest
                dest_path.parent.mkdir(parents=True, exist_ok=True)
                with open(dest_path, "wb") as f:
                    f.write(content)

                collected_files.append({
                    "path": relpath,
                    "sha256": sha256,
                    "bytes": file_size,
                    "line_count": line_count,
                    "encoding": encoding,
                    "component": component,
                    "language": language,
                    "file_type": "regular",
                })

            # 3. Post-collection scan (drift check)
            post_inventory = self._scan_source_tree()
            self._verify_drift(pre_inventory, post_inventory)
            content_drift = self._verify_content_hashes(collected_hashes)
            drift_detected = bool(content_drift)
            if drift_detected and self.on_drift == "raise":
                raise SnapshotInconsistentError(
                    f"Source file contents changed during snapshot collection: {len(content_drift)} files",
                    details={"modified": content_drift[:10]},
                )
            for drifted_path in content_drift:
                gaps.append({
                    "path": drifted_path,
                    "reason": GAP_DRIFT_DETECTED,
                    "detail": "content digest changed during collection window",
                })

            # 4. Generate manifest
            root_hash = compute_root_hash(collected_files)
            snapshot_id = f"snp-{root_hash[:12]}"
            assumptions = self._knowledge_assumptions(collected_files)
            manifest = SnapshotManifest(
                snapshot_id=snapshot_id,
                files=collected_files,
                excluded=excluded_files,
                collection_assumptions=assumptions,
                gaps=gaps,
                source_control=git_status,
                drift_detected=drift_detected,
                root_hash=root_hash,
            )

            # Save manifest inside snapshot dir
            manifest.save_json(str(temp_dest / "manifest.json"))

            # 5. Atomic rename to destination
            if self.snapshot_dest_dir.exists():
                raise StorageError(f"Snapshot destination directory already exists: {self.snapshot_dest_dir}")
            temp_dest.rename(self.snapshot_dest_dir)

            return manifest

        except Exception:
            if temp_dest.exists():
                shutil.rmtree(temp_dest, ignore_errors=True)
            raise

    def _knowledge_assumptions(self, collected_files: List[Dict[str, Any]]) -> List[str]:
        """Build deterministic collection assumptions, disclosing knowledge gaps.

        When a knowledge_dir was supplied, every collected language without a
        knowledge signal definition produces an explicit assumption line;
        unmeasured knowledge backing is disclosed, never silently assumed.

        Requirements: SWR-017(知识缺口披露) / DSR-013(假设如实记录) (support).
        """
        assumptions = [
            "Source tree remained stable during collection window",
            "Symlinks not traversed outside target root",
        ]
        if self.knowledge_dir is None:
            return assumptions

        languages = sorted({f.get("language", "unknown") for f in collected_files})
        uncovered = [
            lang
            for lang in languages
            if not (self.knowledge_dir / "languages" / lang / "signals.json").exists()
        ]
        if uncovered:
            assumptions.append(
                "No knowledge signal definitions for collected languages: "
                + ", ".join(uncovered)
            )
        return assumptions

    def _read_file_nofollow(self, path: Path) -> bytes:
        """Read a file's bytes with symlink-following hardening.

        Opens via ``os.open`` with ``O_NOFOLLOW`` where the platform supports
        it, so a symlink swapped in after the walk (TOCTOU) fails instead of
        leaking out-of-root content (DSR-011).

        Requirements: SWR-015(O_NOFOLLOW防TOCTOU) / DSR-011(链接安全访问).
        """
        fd = os.open(path, os.O_RDONLY | _NOFOLLOW)
        try:
            chunks: List[bytes] = []
            while True:
                chunk = os.read(fd, 1 << 20)
                if not chunk:
                    break
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            os.close(fd)

    def _resolved_within_target(self, path: Path) -> bool:
        """Re-verify that the fully resolved path is still inside target root.

        Requirements: SWR-015(打开后逃逸复验) / DSR-011 (support).
        """
        resolved = Path(os.path.realpath(path))
        try:
            resolved.relative_to(self.target_dir)
            return True
        except ValueError:
            return False

    def _scan_source_tree(self) -> Dict[str, Tuple[int, float]]:
        """Return dict of canonical relative paths to (size, mtime).

        Requirements: SWR-017(采集前后树扫描) / DSR-013 (support).
        """
        entries: Dict[str, Tuple[int, float]] = {}
        for root, dirs, files in os.walk(self.target_dir):
            for fname in files:
                full_path = Path(root) / fname
                try:
                    rel_path = full_path.relative_to(self.target_dir).as_posix()
                    canonical = validate_canonical_relpath(rel_path)
                    st = full_path.stat()
                    entries[canonical] = (st.st_size, st.st_mtime)
                except (OSError, PathUnsafeError):
                    continue
        return entries

    def _verify_drift(
        self,
        pre_scan: Dict[str, Tuple[int, float]],
        post_scan: Dict[str, Tuple[int, float]],
    ) -> None:
        """Verify that source file metadata did not change between scans.

        Size/mtime differences here are a fast-fail signal only; content-level
        equality is proven separately by :meth:`_verify_content_hashes`
        (SR-017 forbids relying on mtime alone).

        Requirements: SWR-017(采集中变化快失败) / DSR-013(采集复查).
        """
        pre_keys = set(pre_scan.keys())
        post_keys = set(post_scan.keys())

        added = post_keys - pre_keys
        removed = pre_keys - post_keys
        if added or removed:
            raise SnapshotInconsistentError(
                f"Source tree modified during snapshot collection: added {len(added)}, removed {len(removed)} files",
                details={"added": list(added)[:10], "removed": list(removed)[:10]},
            )

        modified = []
        for p in pre_keys:
            if pre_scan[p] != post_scan[p]:
                modified.append(p)

        if modified:
            raise SnapshotInconsistentError(
                f"Source files modified during snapshot collection: {len(modified)} files altered",
                details={"modified": modified[:10]},
            )

    def _verify_content_hashes(self, collected_hashes: Dict[str, str]) -> List[str]:
        """Recompute SHA-256 of collected files and compare to capture digests.

        This is the authoritative drift check (DSR-012): a rewrite that keeps
        size and mtime identical is still detected. Returns the sorted list of
        drifted paths; empty means content verified stable. Unreadable files
        (deleted, permission-escaped or symlink-swapped mid-collection) count
        as drifted.

        Requirements: SWR-017(同大小同mtime改写必检出) / DSR-012(内容摘要权威复查).
        """
        drift: List[str] = []
        for relpath in sorted(collected_hashes.keys()):
            try:
                content = self._read_file_nofollow(self.target_dir / relpath)
                if not self._resolved_within_target(self.target_dir / relpath):
                    drift.append(relpath)
                    continue
                actual = hashlib.sha256(content).hexdigest()
            except OSError:
                drift.append(relpath)
                continue
            if actual != collected_hashes[relpath]:
                drift.append(relpath)
        return drift
