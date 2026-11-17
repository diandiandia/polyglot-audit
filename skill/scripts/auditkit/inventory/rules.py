"""File inclusion, default exclusion rules, and user overrides.

Implements DSR-014 / DSR-054 / SD-03 / SR-004:
- Default exclusions: vcs, dependencies, build outputs, binaries, test suites.
- User overrides with documented reasons.
- Never falsely counts excluded files as security-reviewed.
"""

# 需求追踪 (Requirement Traceability)
# ---------------------------------------------------------------------------
# 上层需求: docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2
# 设计依据: docs/design/SOFTWARE_DESIGN.md
# SWR-004  纳入/排除规则与原因记录；错误排除不得计入安全覆盖
#   绑定实现: DSR-054
# 状态以统一测试结论为准；未实测能力保持 unknown（设计原则 8：能观测的不靠声明）。
#

from __future__ import annotations
import fnmatch
import os
from typing import Any, Dict, List, Optional, Tuple

DEFAULT_EXCLUDED_DIRS = {
    ".git",
    ".svn",
    ".hg",
    "node_modules",
    "vendor",
    "third_party",
    "extern",
    "bower_components",
    "dist",
    "build",
    "out",
    "target",
    "bin",
    "obj",
    "__pycache__",
    ".pytest_cache",
    ".idea",
    ".vscode",
}

# Directory names that indicate generated/vendor build output (DSR-054
# classification "generated", as opposed to generic "directory_rule").
GENERATED_DIRS = {
    "node_modules",
    "vendor",
    "third_party",
    "extern",
    "bower_components",
    "dist",
    "build",
    "out",
    "target",
    "bin",
    "obj",
}

# Archive extensions (DSR-054 classification "archive").
ARCHIVE_EXTENSIONS = {
    ".zip",
    ".tar",
    ".gz",
    ".bz2",
    ".xz",
    ".7z",
    ".tgz",
}

DEFAULT_EXCLUDED_EXTENSIONS = {
    # Binaries & compiled
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".bin",
    ".class",
    ".jar",
    ".war",
    ".pyc",
    ".pyo",
    ".o",
    ".a",
    ".whl",
    # Media & docs
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    # Lockfiles & minified
    ".min.js",
    ".min.css",
}


class ExclusionRules:
    """Manages file exclusion decisions."""

    def __init__(
        self,
        user_includes: Optional[List[str]] = None,
        user_excludes: Optional[List[str]] = None,
        include_tests: bool = False,
    ) -> None:
        """Store user overrides and the test-inclusion switch.

        Requirements: SWR-004(用户覆盖与开关) / DSR-054 (support).
        """
        self.user_includes = user_includes or []
        self.user_excludes = user_excludes or []
        self.include_tests = include_tests

    def evaluate(self, relpath: str) -> Tuple[bool, str]:
        """Determine if a file should be excluded and provide the reason.

        Returns: (is_excluded, reason)

        Requirements: SWR-004(纳入/排除带原因) / DSR-054(默认排除规则).
        """
        # 1. User include override takes precedence
        for pattern in self.user_includes:
            if fnmatch.fnmatch(relpath, pattern) or fnmatch.fnmatch(os.path.basename(relpath), pattern):
                return False, "Matched user include rule"

        # 2. User exclude rule
        for pattern in self.user_excludes:
            if fnmatch.fnmatch(relpath, pattern) or fnmatch.fnmatch(os.path.basename(relpath), pattern):
                return True, f"Matched user exclude pattern: {pattern}"

        # 3. Directory check
        parts = relpath.split("/")
        for part in parts[:-1]:
            if part in DEFAULT_EXCLUDED_DIRS:
                return True, f"Inside excluded directory: {part}"

        # 4. Extension check (archives classified separately, DSR-054)
        basename = parts[-1]
        _, ext = os.path.splitext(basename)
        ext_lower = ext.lower()
        if ext_lower in ARCHIVE_EXTENSIONS:
            return True, f"Excluded archive extension: {ext}"
        if ext_lower in DEFAULT_EXCLUDED_EXTENSIONS:
            return True, f"Excluded binary/media extension: {ext}"

        # 5. Minified file check
        if basename.endswith(".min.js") or basename.endswith(".min.css"):
            return True, "Excluded minified bundle"

        # 6. Test directory/file check (if tests not explicitly included)
        if not self.include_tests:
            for part in parts[:-1]:
                if part.lower() in ("test", "tests", "spec", "specs"):
                    return True, f"Default excluded test directory: {part}"
            if (
                basename.startswith("test_")
                or basename.endswith("_test.go")
                or basename.endswith(".test.js")
                or basename.endswith(".test.ts")
                or basename.endswith(".spec.js")
                or basename.endswith(".spec.ts")
            ):
                return True, f"Default excluded test file: {basename}"

        return False, ""


def classify_exclusion_reason(reason: str) -> str:
    """Map an exclusion reason string to a DSR-054 category.

    Categories: directory_rule / generated / test / binary / archive /
    user_rule / symlink / other.

    Requirements: SWR-004(排除原因归类) / DSR-054(分类清点结果).
    """
    reason_lower = (reason or "").lower()
    if "archive extension" in reason_lower:
        return "archive"
    if "binary/media extension" in reason_lower:
        return "binary"
    if "minified bundle" in reason_lower:
        return "generated"
    if "test" in reason_lower:
        return "test"
    if "inside excluded directory" in reason_lower:
        dir_name = reason.rsplit(":", 1)[-1].strip()
        if dir_name in GENERATED_DIRS:
            return "generated"
        return "directory_rule"
    if "user exclude" in reason_lower:
        return "user_rule"
    if "symlink" in reason_lower:
        return "symlink"
    return "other"


def inclusion_summary(manifest: Any) -> Dict[str, int]:
    """Aggregate inventory counts by inclusion/exclusion category (DSR-054).

    Buckets every manifest file into one of:
    - ``included``          : inventoried with a recognized language
    - ``unknown_extension`` : inventoried but language unknown
    and every excluded file into: directory_rule / generated / test /
    binary / archive / user_rule / symlink / other.

    Never counts excluded files as security-reviewed coverage.

    Requirements: SWR-004(排除不计安全覆盖) / DSR-054(分类汇总对账).
    """
    summary: Dict[str, int] = {
        "included": 0,
        "unknown_extension": 0,
        "excluded_total": 0,
        "directory_rule": 0,
        "generated": 0,
        "test": 0,
        "binary": 0,
        "archive": 0,
        "user_rule": 0,
        "symlink": 0,
        "other": 0,
    }
    for f in manifest.files:
        if f.get("language", "unknown") == "unknown":
            summary["unknown_extension"] += 1
        else:
            summary["included"] += 1
    for e in manifest.excluded:
        summary["excluded_total"] += 1
        summary[classify_exclusion_reason(e.get("reason", ""))] += 1
    return summary
