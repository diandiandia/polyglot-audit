"""Three-root path validation and filesystem security checks.

Implements DSR-011 / SR-015 / SD-03 / IFC-01:
- Validates three roots: target_dir, skill_dir, run_dir are non-overlapping.
- Resolves real paths to prevent symlink traversal and alias escapes.
- Enforces canonical relative path rules: no '..', no leading '/', no null bytes.
"""

# 需求追踪 (Requirement Traceability)
# ---------------------------------------------------------------------------
# 上层需求: docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2
# 设计依据: docs/design/SOFTWARE_DESIGN.md
# SWR-015  载荷、源码、运行目录三根分离；符号链接与路径别名攻击拒绝
#   绑定实现: DSR-011
# 状态以统一测试结论为准；未实测能力保持 unknown（设计原则 8：能观测的不靠声明）。
#

from __future__ import annotations
import os
from pathlib import Path
from typing import Tuple

from auditkit.contracts.errors import PathUnsafeError, InvalidInputError


def validate_canonical_relpath(relpath: str) -> str:
    """Validate and return canonical relative path.

    Rules:
    - '/' delimited
    - No empty segments, no '.' or '..'
    - No leading or trailing '/'
    - No null bytes or backslashes
    """
    if not relpath or not isinstance(relpath, str):
        raise PathUnsafeError("Path must be a non-empty string")
    if "\0" in relpath:
        raise PathUnsafeError("Null bytes prohibited in path")
    if "\\" in relpath:
        raise PathUnsafeError("Backslashes prohibited in canonical relative paths")
    if relpath.startswith("/"):
        raise PathUnsafeError("Absolute paths prohibited in canonical relative paths")

    parts = relpath.split("/")
    for p in parts:
        if not p or p == "." or p == "..":
            raise PathUnsafeError(f"Path contains forbidden traversal segment: {p!r} in {relpath!r}")

    return "/".join(parts)


def validate_three_roots(target: str, skill_dir: str, run_dir: str) -> Tuple[Path, Path, Path]:
    """Validate that target, skill_dir, and run_dir are separate and non-overlapping.

    Raises PathUnsafeError if any overlap exists or if paths are invalid.
    """
    target_path = Path(os.path.realpath(os.path.abspath(target)))
    skill_path = Path(os.path.realpath(os.path.abspath(skill_dir)))
    run_path = Path(os.path.realpath(os.path.abspath(run_dir)))

    # Check existence of target
    if not target_path.exists() or not target_path.is_dir():
        raise PathUnsafeError(f"Target directory does not exist or is not a directory: {target}")

    # Check that roots are distinct
    roots = [("target", target_path), ("skill_dir", skill_path), ("run_dir", run_path)]
    for i in range(len(roots)):
        for j in range(i + 1, len(roots)):
            name_a, path_a = roots[i]
            name_b, path_b = roots[j]

            if path_a == path_b:
                raise PathUnsafeError(
                    f"Path separation violation: {name_a} and {name_b} point to the same directory ({path_a})"
                )

            # Check if one is a subpath of another
            try:
                path_a.relative_to(path_b)
                raise PathUnsafeError(
                    f"Path separation violation: {name_a} ({path_a}) is inside {name_b} ({path_b})"
                )
            except ValueError:
                pass

            try:
                path_b.relative_to(path_a)
                raise PathUnsafeError(
                    f"Path separation violation: {name_b} ({path_b}) is inside {name_a} ({path_a})"
                )
            except ValueError:
                pass

    return target_path, skill_path, run_path


def check_symlink_safety(target_root: Path, file_path: Path) -> bool:
    """Verify that a path does not escape target_root via symlinks."""
    try:
        resolved = file_path.resolve(strict=False)
        resolved.relative_to(target_root.resolve())
        return True
    except (ValueError, RuntimeError):
        return False
