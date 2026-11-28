"""Signal scanning across source code files.

Implements DSR-015 / DSR-057 / SD-03 / SR-004:
- Line-by-line regex scanning for source, sink, guard, boundary, and config signals.
- Assigns signal strength (1-3).
- Records anchors and enforces overflow caps per file to prevent unbounded expansion.
- Hits are deterministically ordered by (line ascending, strength descending).
- Per-language signal definitions are loaded from
  ``knowledge/languages/<lang>/signals.json`` and merged into the scan config.
- File-level scan errors (OSError while reading) are counted and returned as
  coverage gaps instead of being silently swallowed.
"""

# 需求追踪 (Requirement Traceability)
# ---------------------------------------------------------------------------
# 上层需求: docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2
# 设计依据: docs/design/SOFTWARE_DESIGN.md
# SWR-004  扫描信号排序（行号升序、强度降序）；按语言可配置，扫描失败计数不静默
#   绑定实现: DSR-057
# 状态以统一测试结论为准；未实测能力保持 unknown（设计原则 8：能观测的不靠声明）。
#

from __future__ import annotations
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from auditkit.contracts.errors import InvalidInputError


# Core common signal regexes per category
COMMON_SIGNALS = [
    # Source signals
    ("src_http_input", "source", 3, r"(request\.(form|args|json|body|data)|req\.(body|query|params)|http\.Request|r\.URL\.Query|getParameter|\$_GET|\$_POST)"),
    ("src_cli_env", "source", 2, r"(os\.environ|process\.env|System\.getenv|os\.Getenv|\$argv|\$_SERVER|sys\.argv)"),
    ("src_file_read", "source", 1, r"(open\(|readFile|ioutil\.ReadFile|FileInputStream|File\.read)"),

    # Sink signals
    ("sink_rce", "sink", 3, r"(exec\(|eval\(|system\(|popen\(|subprocess\.(Popen|run|call)|child_process\.exec|Runtime\.getRuntime\(\)\.exec|ProcessBuilder|os/exec)"),
    ("sink_sqli", "sink", 3, r"(execute\(|rawQuery\(|createQuery\(|query\()(?=.*(\%s|\{\}|\+|format|concat))"),
    ("sink_deser", "sink", 3, r"(pickle\.loads?|yaml\.load(?!\s*,\s*Loader=SafeLoader)|readObject\(|unserialize\(|Marshal\.load|BinaryFormatter)"),
    ("sink_path_traversal", "sink", 2, r"(os\.path\.join|path\.join|filepath\.Join|new File\()"),
    ("sink_dom_xss", "sink", 2, r"(innerHTML|outerHTML|document\.write|dangerouslySetInnerHTML|Html\.Raw)"),

    # Guard signals
    ("guard_auth", "guard", 3, r"(@login_required|@authenticated|isAuthenticated|check_permission|authorize\(|verify_token)"),
    ("guard_sanitize", "guard", 2, r"(escape\(|sanitize\(|whitelist|allowed_hosts|validate_input|int\(|Number\()"),
    ("guard_csrf", "guard", 2, r"(csrf_protect|validate_csrf|CsrfToken)"),

    # Boundary signals
    ("boundary_ffi", "boundary", 3, r"(extern\s+\"C\"|cgo|ctypes|P/Invoke|NativeMethods|JNIEXPORT)"),
    ("boundary_subprocess", "boundary", 2, r"(subprocess|child_process|exec\.Command)"),

    # Config signals
    ("config_debug", "config", 2, r"(DEBUG\s*=\s*True|allow_all|insecure|skip_verify|TrustAll)"),
]


def compile_signals(raw_signals: List[Tuple[str, str, int, str]]) -> List[Tuple[str, str, int, Any]]:
    """Compile raw signal tuples into (id, kind, strength, pattern) rules.

    Invalid regexes are skipped rather than aborting the scan; deterministic
    input order yields deterministic rule order.

    Requirements: SWR-004(信号规则确定编译) / DSR-057 (support).
    """
    rules: List[Tuple[str, str, int, Any]] = []
    for sig_id, kind, strength, pattern_str in raw_signals:
        try:
            compiled = re.compile(pattern_str, re.IGNORECASE)
            rules.append((sig_id, kind, strength, compiled))
        except re.error:
            continue
    return rules


def load_language_signals(knowledge_dir: str | os.PathLike, language: str) -> List[Tuple[str, str, int, str]]:
    """Load per-language signal definitions for one language (DSR-057).

    Reads ``<knowledge_dir>/languages/<language>/signals.json``. Each entry
    must carry ``pattern_id``, ``pattern``; ``kind`` (default ``sink``) and
    ``strength`` (default 3) are optional. Returns an empty list when the
    file does not exist; raises InvalidInputError on unreadable or malformed
    JSON so the failure is visible instead of silently dropping signals.

    Requirements: SWR-004(按语言可配置信号) / DSR-057(加载失败可见).
    """
    if not language or language == "unknown":
        return []
    signals_path = Path(knowledge_dir) / "languages" / language / "signals.json"
    if not signals_path.exists():
        return []
    try:
        with open(signals_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except OSError as e:
        raise InvalidInputError(f"Cannot read language signals file {signals_path}: {e}")
    except ValueError as e:
        raise InvalidInputError(f"Malformed language signals JSON in {signals_path}: {e}")

    if not isinstance(data, list):
        raise InvalidInputError(f"Language signals file must contain a list: {signals_path}")

    raw: List[Tuple[str, str, int, str]] = []
    for idx, entry in enumerate(data):
        if not isinstance(entry, dict) or not entry.get("pattern"):
            raise InvalidInputError(f"Invalid signal entry #{idx} in {signals_path}")
        sig_id = entry.get("pattern_id") or f"{language}_{idx}"
        kind = entry.get("kind", "sink")
        strength = int(entry.get("strength", 3))
        raw.append((sig_id, kind, strength, entry["pattern"]))
    return raw


class SignalScanner:
    """Scans code lines for security signals."""

    def __init__(
        self,
        custom_signals: Optional[List[Tuple[str, str, int, str]]] = None,
        knowledge_dir: Optional[str | os.PathLike] = None,
    ) -> None:
        """Create a scanner.

        - ``custom_signals``: replacement global signal set (defaults to
          COMMON_SIGNALS).
        - ``knowledge_dir``: when set, per-language signals are lazily loaded
          from ``knowledge/languages/<lang>/signals.json`` and merged into the
          rules used for files of that language (DSR-057). Load failures are
          counted in ``language_load_errors``.

        Requirements: SWR-004(信号扫描配置) / DSR-057 (support).
        """
        self.knowledge_dir = knowledge_dir
        self.rules = compile_signals(custom_signals or COMMON_SIGNALS)
        self.language_rules: Dict[str, List[Tuple[str, str, int, Any]]] = {}
        self.language_load_errors: Dict[str, str] = {}
        self.language_hit_cap_counts: Dict[str, int] = {}

    def _rules_for_language(self, language: Optional[str]) -> List[Tuple[str, str, int, Any]]:
        """Return common rules merged with the language-specific rules.

        Requirements: SWR-004(语言规则合并) / DSR-057 (support).
        """
        if not language or language == "unknown" or self.knowledge_dir is None:
            return self.rules
        if language not in self.language_rules:
            try:
                raw = load_language_signals(self.knowledge_dir, language)
                self.language_rules[language] = compile_signals(raw)
            except InvalidInputError as e:
                self.language_load_errors[language] = str(e)
                self.language_rules[language] = []
        return self.rules + self.language_rules[language]

    def scan_file(
        self,
        relpath: str,
        lines: List[str],
        max_hits: int = 200,
        language: Optional[str] = None,
    ) -> Tuple[List[Dict[str, Any]], Optional[Dict[str, Any]]]:
        """Scan file lines for signals.

        Hits are deterministically ordered by (line ascending, strength
        descending); ties keep scan order. When the per-file cap is reached,
        an overflow record is returned and counted via
        ``language_hit_cap_counts`` for the file's language.

        Returns: (hits, overflow_record_if_any)

        Requirements: SWR-004(信号排序与上限) / DSR-015(行升序强度降序), DSR-057(命中上限计数).
        """
        rules = self._rules_for_language(language)
        hits: List[Dict[str, Any]] = []
        overflow: Optional[Dict[str, Any]] = None

        for line_idx, line in enumerate(lines, start=1):
            if len(hits) >= max_hits:
                overflow = {
                    "path": relpath,
                    "dimension": "signals",
                    "estimated_count": len(lines) - line_idx + max_hits,
                    "reason": f"Hit cap of {max_hits} signals reached in {relpath}",
                }
                self.language_hit_cap_counts[language or "unknown"] = (
                    self.language_hit_cap_counts.get(language or "unknown", 0) + 1
                )
                break

            for sig_id, kind, strength, regex in rules:
                match = regex.search(line)
                if match:
                    hits.append({
                        "path": relpath,
                        "line": line_idx,
                        "signal_id": sig_id,
                        "kind": kind,
                        "strength": strength,
                        "match_text": match.group(0)[:60],
                    })
                    if len(hits) >= max_hits:
                        break

        # DSR-015: deterministic order — by line, then strongest signal first.
        hits.sort(key=lambda h: (h["line"], -h["strength"]))
        return hits, overflow


def scan_snapshot_files(
    scanner: SignalScanner,
    files: List[Dict[str, Any]],
    snapshot_root: str | os.PathLike,
    max_hits: int = 200,
) -> Dict[str, Any]:
    """Scan snapshot files with honest error accounting (DSR-057 / DSR-013).

    Reads each inventoried file from ``snapshot_root`` and scans it with the
    language-appropriate rules. Read failures (OSError) are NOT silently
    swallowed: they are returned as gap records with reason ``read_failure``.

    Returns a dict with:
    - ``file_signals``: {path: [hit, ...]} (unreadable files map to [])
    - ``gaps``: [{path, reason, detail}, ...] read-failure gap records
    - ``overflows`` / ``overflow_count``: hit-cap overflow records
    - ``scan_error_count``: number of files that could not be read

    Requirements: SWR-004(扫描失败计数与缺口) / DSR-057(失败不静默), DSR-013(读失败缺口).
    """
    file_signals: Dict[str, List[Dict[str, Any]]] = {}
    gaps: List[Dict[str, Any]] = []
    overflows: List[Dict[str, Any]] = []

    for f in files:
        p = f["path"]
        language = f.get("language")
        src_file = Path(snapshot_root) / p
        try:
            with open(src_file, "r", encoding="utf-8", errors="replace") as sf:
                lines = sf.read().splitlines()
        except OSError as e:
            gaps.append({"path": p, "reason": "read_failure", "detail": str(e)})
            file_signals[p] = []
            continue

        hits, overflow = scanner.scan_file(p, lines, max_hits=max_hits, language=language)
        file_signals[p] = hits
        if overflow:
            overflows.append(overflow)

    return {
        "file_signals": file_signals,
        "gaps": gaps,
        "overflows": overflows,
        "overflow_count": len(overflows),
        "scan_error_count": len(gaps),
    }
