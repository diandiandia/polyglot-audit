"""Multi-language boundary scanning and boundary unit generation.

Implements DSR-055 / SD-03 / SR-003 / SR-005:
- Detects FFI, subprocess calls, and inter-language bindings.
- Identifies declaration side and implementation side.
- Records explicit gaps when interface endpoints lack matched implementation.
"""

# 需求追踪 (Requirement Traceability)
# ---------------------------------------------------------------------------
# 上层需求: docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2
# 设计依据: docs/design/SOFTWARE_DESIGN.md
# SWR-003  混合语言边界扫描：FFI/脚本调用；声明/实现未匹配留明确缺口
#   绑定实现: DSR-055
# 状态以统一测试结论为准；未实测能力保持 unknown（设计原则 8：能观测的不靠声明）。
#

from __future__ import annotations
import os
import re
from typing import Any, Dict, List, Optional, Tuple


class BoundaryScanner:
    """Scans for cross-language boundaries across files."""

    FFI_PATTERNS = [
        (re.compile(r"ctypes\.CDLL\s*\(\s*['\"]([^'\"]+)['\"]"), "ctypes_ffi"),
        (re.compile(r"#include\s+<([a-zA-Z0-9_\-\.]+)\.h>"), "c_header_include"),
        (re.compile(r"extern\s+\"C\""), "extern_c_boundary"),
        (re.compile(r"import\s+\"C\""), "cgo_boundary"),
        (re.compile(r"\[DllImport\s*\(\s*['\"]([^'\"]+)['\"]"), "p_invoke_boundary"),
    ]

    SUBPROCESS_PATTERNS = [
        (re.compile(r"subprocess\.(Popen|run|call)\s*\(\s*\[?['\"]([^'\"]+)['\"]"), "subprocess_call"),
        (re.compile(r"exec\.Command\s*\(\s*['\"]([^'\"]+)['\"]"), "go_exec_command"),
        (re.compile(r"child_process\.(exec|spawn)\s*\(\s*['\"]([^'\"]+)['\"]"), "node_subprocess"),
        # DSR-055: script invocation coverage beyond subprocess-style calls.
        (re.compile(r"\bos\.system\s*\(\s*['\"]([^'\"]+)['\"]"), "os_system_call"),
        (re.compile(r"(?<![A-Za-z0-9_])popen\s*\(\s*['\"]([^'\"]+)['\"]"), "popen_call"),
    ]

    def scan_file(self, relpath: str, lines: List[str], lang: str) -> List[Dict[str, Any]]:
        """Identify boundaries in a file.

        Requirements: SWR-003(跨语言边界检出), SWR-005(未解链保留)
        / DSR-055(FFI/脚本调用扫描).
        """
        boundaries: List[Dict[str, Any]] = []

        for line_idx, line in enumerate(lines, start=1):
            # Check FFI
            for pattern, b_type in self.FFI_PATTERNS:
                m = pattern.search(line)
                if m:
                    target = m.group(1) if m.groups() else ""
                    boundaries.append({
                        "path": relpath,
                        "line": line_idx,
                        "boundary_type": b_type,
                        "source_lang": lang,
                        "target_ref": target,
                        "matched_implementation": None,
                        "is_gap": True,  # default until matched
                    })

            # Check Subprocess
            for pattern, b_type in self.SUBPROCESS_PATTERNS:
                m = pattern.search(line)
                if m:
                    cmd = m.group(2) if len(m.groups()) >= 2 else (m.group(1) if m.groups() else "")
                    boundaries.append({
                        "path": relpath,
                        "line": line_idx,
                        "boundary_type": b_type,
                        "source_lang": lang,
                        "target_ref": cmd,
                        "matched_implementation": None,
                        "is_gap": True,
                    })

        return boundaries

    # DSR-055: extension families that may implement one another. A
    # declaration referencing ``util.h`` may be implemented by ``util.c`` /
    # ``util.cpp``, a ``native.dll`` import by native C#/C++ sources, etc.
    EXTENSION_FAMILIES = [
        {".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".hxx", ".hh"},
        {".py", ".pyw"},
        {".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".tsx"},
        {".go"},
        {".java", ".kt", ".scala"},
        {".rs"},
        {".cs"},
        {".sh", ".bash", ".zsh", ".ksh"},
        {".rb"},
        {".php"},
    ]

    @classmethod
    def _family_of(cls, ext: str) -> Optional[frozenset]:
        """Return the extension family containing ``ext`` (lowercase), if any.

        Requirements: SWR-005(扩展名族匹配) / DSR-055 (support).
        """
        for family in cls.EXTENSION_FAMILIES:
            if ext in family:
                return frozenset(family)
        return None

    def match_boundaries(
        self,
        boundaries: List[Dict[str, Any]],
        all_files: List[str],
    ) -> List[Dict[str, Any]]:
        """Attempt to match declaration side with implementation side in repo files.

        Matching is deliberately strict (DSR-055) to avoid the historical
        substring false positives (e.g. ``libc`` matching any path that
        contains the string):

        1. exact basename equality between the reference and a repo file, or
        2. equal stem plus an extension within the same extension family.

        Anything unmatched keeps ``matched_implementation`` None and
        ``is_gap`` True — an explicit coverage gap, never a guessed match.

        Requirements: SWR-005(声明/实现匹配留缺口) / DSR-055(未匹配明确缺口).
        """
        by_basename: Dict[str, List[str]] = {}
        by_stem: Dict[str, List[Tuple[str, str]]] = {}
        for f in all_files:
            base = os.path.basename(f)
            by_basename.setdefault(base, []).append(f)
            stem, ext = os.path.splitext(base)
            by_stem.setdefault(stem, []).append((f, ext.lower()))

        matched = []
        for b in boundaries:
            ref = b.get("target_ref", "")
            found_target = None
            if ref:
                ref_normalized = ref.replace("\\", "/")
                ref_base = os.path.basename(ref_normalized)
                ref_stem, ref_ext = os.path.splitext(ref_base)
                ref_ext_lower = ref_ext.lower()

                # 1. Exact basename match (deterministically sorted).
                exact_hits = sorted(by_basename.get(ref_base, []))
                if exact_hits:
                    found_target = exact_hits[0]
                elif ref_stem:
                    # 2. Same stem within the same extension family. A
                    # reference without an extension (e.g. C ``#include
                    # <util.h>`` headers captured as ``util``, or bare script
                    # invocations) may match any known code-family extension.
                    if ref_ext_lower:
                        family = self._family_of(ref_ext_lower)
                        allowed_exts = frozenset(family) if family else frozenset()
                    else:
                        allowed_exts = frozenset().union(*self.EXTENSION_FAMILIES)
                    family_hits = sorted(
                        p for p, e in by_stem.get(ref_stem, []) if e in allowed_exts
                    )
                    if family_hits:
                        found_target = family_hits[0]

            if found_target:
                b["matched_implementation"] = found_target
                b["is_gap"] = False
            matched.append(b)
        return matched
