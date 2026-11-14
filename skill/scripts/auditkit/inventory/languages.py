"""Language detection and base-language relationships.

Implements DSR-014 / DSR-038 / SD-02 / SR-003:
- Supports 15 core catalog languages + unknown language handling.
- Maps base language associations:
  - TypeScript -> JavaScript
  - Kotlin -> Java (when on JVM)
  - Scala -> Java
  - C++ -> C
- Recognizes extensions, filenames, and shebang lines.
"""

# 需求追踪 (Requirement Traceability)
# ---------------------------------------------------------------------------
# 上层需求: docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2
# 设计依据: docs/design/SOFTWARE_DESIGN.md
# SWR-004  语言/组件识别；未知语言单列并可采用通用方法
#   绑定实现: DSR-014
# 状态以统一测试结论为准；未实测能力保持 unknown（设计原则 8：能观测的不靠声明）。
#

from __future__ import annotations
import os
from typing import Dict, List, Optional, Set, Tuple

CATALOG_LANGUAGES: Set[str] = {
    "c",
    "cpp",
    "csharp",
    "go",
    "java",
    "rust",
    "python",
    "javascript",
    "typescript",
    "kotlin",
    "scala",
    "php",
    "ruby",
    "swift",
    "shell",
}

EXTENSION_MAP: Dict[str, str] = {
    # C
    ".c": "c",
    ".h": "c",
    # C++
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".hxx": "cpp",
    ".hh": "cpp",
    # C#
    ".cs": "csharp",
    # Go
    ".go": "go",
    # Java
    ".java": "java",
    # Rust
    ".rs": "rust",
    # Python
    ".py": "python",
    ".pyw": "python",
    ".wsgi": "python",
    # JavaScript
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    # TypeScript
    ".ts": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    ".tsx": "typescript",
    # Kotlin
    ".kt": "kotlin",
    ".kts": "kotlin",
    # Scala
    ".scala": "scala",
    ".sc": "scala",
    # PHP
    ".php": "php",
    ".phtml": "php",
    # Ruby
    ".rb": "ruby",
    ".rake": "ruby",
    # Swift
    ".swift": "swift",
    # Shell
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".ksh": "shell",
}

EXACT_FILENAME_MAP: Dict[str, str] = {
    "Gemfile": "ruby",
    "Rakefile": "ruby",
    "Dockerfile": "shell",
}

BASE_LANGUAGE_MAP: Dict[str, str] = {
    "typescript": "javascript",
    "kotlin": "java",
    "scala": "java",
    "cpp": "c",
}


def detect_language(path: str, header_bytes: bytes = b"") -> str:
    """Detect language from path and optional header bytes (shebang)."""
    basename = os.path.basename(path)
    if basename in EXACT_FILENAME_MAP:
        return EXACT_FILENAME_MAP[basename]

    _, ext = os.path.splitext(basename)
    ext_lower = ext.lower()
    if ext_lower in EXTENSION_MAP:
        return EXTENSION_MAP[ext_lower]

    # Shebang check
    if header_bytes.startswith(b"#!"):
        first_line = header_bytes.splitlines()[0].decode("utf-8", errors="ignore").lower()
        if "python" in first_line:
            return "python"
        elif "node" in first_line:
            return "javascript"
        elif "ruby" in first_line:
            return "ruby"
        elif "php" in first_line:
            return "php"
        elif any(sh in first_line for sh in ("bash", "sh", "zsh", "ksh")):
            return "shell"

    return "unknown"


def get_base_languages(language: str, platform_is_jvm: bool = True) -> List[str]:
    """Return applicable base languages for a given language.

    - TypeScript always includes JavaScript.
    - C++ always includes C.
    - Kotlin and Scala only include Java when platform is JVM.
    """
    if language == "typescript":
        return ["javascript"]
    elif language == "cpp":
        return ["c"]
    elif language in ("kotlin", "scala"):
        return ["java"] if platform_is_jvm else []
    return []
