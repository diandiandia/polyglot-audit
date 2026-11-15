"""Build-manifest component detection for the frozen snapshot (DSR-055).

Provides ``detect_components(manifest_files, snapshot_root)``: deterministic
assignment of every snapshot file to its build component.

- Build manifests recognized: pom.xml, package.json, build.gradle,
  build.gradle.kts, settings.gradle, settings.gradle.kts, go.mod, Cargo.toml.
  Discovery runs over the FROZEN manifest's own file list — no second
  filesystem scan of the snapshot (DA-03: JVM build-evidence detection reuses
  the same discovery helper instead of rescanning).
- Every manifest file's directory is a component root.
- Each file belongs to its NEAREST enclosing component root (the deepest root
  that is a path prefix of the file's directory; nested roots therefore win).
- Component label (documented choice): the component root's snapshot-relative
  directory path; when the root IS the snapshot top level the label is the
  manifest file's own name (e.g. "pom.xml", "package.json"). Labels are
  deterministic and stably sortable.
- Files not covered by any component root map to ``default``.
"""

# 需求追踪 (Requirement Traceability)
# ---------------------------------------------------------------------------
# 上层需求: docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2
# 设计依据: docs/design/SOFTWARE_DESIGN.md
# SWR-004  清点分母对账：by_component 反映真实构建组件而非恒定 default
#   绑定实现: DSR-055
# 状态以统一测试结论为准；未实测能力保持 unknown（设计原则 8：能观测的不靠声明）。
#

from __future__ import annotations
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Union

# Build manifest file names that mark a component root (DSR-055).
BUILD_MANIFEST_FILE_NAMES = (
    "pom.xml",
    "package.json",
    "build.gradle",
    "build.gradle.kts",
    "settings.gradle",
    "settings.gradle.kts",
    "go.mod",
    "Cargo.toml",
)

# Files whose directory is not covered by any component root.
DEFAULT_COMPONENT = "default"

_Entry = Union[str, Dict[str, Any]]


def _normalize_relpath(raw: str, snapshot_root: Optional[str | Path]) -> Optional[str]:
    """Normalize a manifest entry path to a snapshot-relative POSIX path.

    Returns None when the path cannot be expressed inside the snapshot root
    (absolute paths escaping it, or relative paths climbing out with "..").
    """
    p = raw[2:] if raw.startswith("./") else raw
    p = p.replace("\\", "/")
    if snapshot_root is not None and Path(p).is_absolute():
        try:
            p = Path(p).resolve().relative_to(Path(snapshot_root).resolve()).as_posix()
        except (ValueError, OSError):
            return None
    if p.startswith("../"):
        return None
    return p


def find_build_manifest_paths(paths: Iterable[str]) -> List[str]:
    """Return the sorted snapshot-relative paths that are build manifests.

    Pure path-list helper shared by component detection (DSR-055) and JVM
    build-evidence detection (DA-03 / SR-003) so the manifest scan happens
    exactly once per run.
    """
    manifests: List[str] = []
    for raw in set(paths):
        normalized = _normalize_relpath(raw, None)
        if normalized is None:
            continue
        name = normalized.rsplit("/", 1)[-1]
        if name in BUILD_MANIFEST_FILE_NAMES:
            manifests.append(normalized)
    return sorted(set(manifests))


def component_roots(manifest_paths: Iterable[str]) -> List[Dict[str, str]]:
    """Derive the component roots from build manifest paths (DSR-055).

    Returns one record per root, sorted deepest-first (longest root path,
    then label as a deterministic tie-break for two manifests sharing one
    directory): ``{"root": <snapshot-relative dir or "">, "manifest":
    <manifest path>, "label": <component label>}``. The top-level root
    carries ``root: ""`` and is labelled with the manifest file's own name.
    """
    records: List[Dict[str, str]] = []
    for manifest_path in find_build_manifest_paths(manifest_paths):
        root_dir = manifest_path.rsplit("/", 1)[0] if "/" in manifest_path else ""
        label = root_dir if root_dir else manifest_path.rsplit("/", 1)[-1]
        records.append({"root": root_dir, "manifest": manifest_path, "label": label})
    # Deepest roots first, so the first enclosing match is the nearest root.
    return sorted(records, key=lambda r: (-len(r["root"]), r["label"], r["root"]))


def _nearest_root_label(directory: str, records: List[Dict[str, str]]) -> Optional[str]:
    """Label of the nearest enclosing component root, or None for no cover.

    A root covers a directory when it is the directory itself or an ancestor
    of it; the top-level root (``root == ""``) covers the whole tree.
    """
    for record in records:
        root_dir = record["root"]
        if root_dir == "" or directory == root_dir or directory.startswith(root_dir + "/"):
            return record["label"]
    return None


def detect_components(
    manifest_files: Iterable[_Entry],
    snapshot_root: Optional[str | Path] = None,
) -> Dict[str, str]:
    """Assign every snapshot file its build component (DSR-055).

    - ``manifest_files``: the frozen snapshot manifest's ``files`` entries
      (dicts carrying ``path``) or plain snapshot-relative path strings.
    - ``snapshot_root``: the frozen snapshot directory the entries are
      relative to. Discovery intentionally does NOT rescan this tree (the
      manifest is authoritative and DA-03 forbids a second scan); it is used
      only to normalize absolute entry paths.

    Returns ``{entry_path: component}``. Components follow the nearest
    enclosing component root (deepest build-manifest directory that contains
    the file); files outside every root map to ``default``. The result is
    deterministic for a given manifest.
    """
    entries: List[str] = []
    seen_keys: Dict[str, str] = {}
    for entry in manifest_files:
        raw = entry.get("path") if isinstance(entry, dict) else entry
        if not isinstance(raw, str) or not raw:
            continue
        normalized = _normalize_relpath(raw, snapshot_root)
        if normalized is None:
            # Unplaceable path: no component root can enclose it.
            seen_keys[raw] = DEFAULT_COMPONENT
            continue
        entries.append(normalized)
        seen_keys.setdefault(raw, normalized)

    roots = component_roots(entries)

    assignment: Dict[str, str] = {}
    for raw_key, rel_path in seen_keys.items():
        directory = rel_path.rsplit("/", 1)[0] if "/" in rel_path else ""
        label = _nearest_root_label(directory, roots)
        assignment[raw_key] = label if label is not None else DEFAULT_COMPONENT
    return assignment
