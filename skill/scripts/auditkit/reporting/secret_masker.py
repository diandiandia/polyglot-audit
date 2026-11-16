"""Secret and credential masking in audit reports and logs.

Implements DSR-069 / SD-08 / SR-010:
- Detects API keys, tokens, passwords, private keys, and claim tokens.
- Replaces raw secret bytes with redaction placeholders.
- Preserves file paths and line anchors while masking credential contents.
"""

# 需求追踪 (Requirement Traceability)
# ---------------------------------------------------------------------------
# 上层需求: docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2
# 设计依据: docs/design/SOFTWARE_DESIGN.md
# SWR-010  凭据/密钥值不得出现在报告（日志、JSON、Markdown 介质的脱敏）
#   绑定实现: DSR-069
# 状态以统一测试结论为准；未实测能力保持 unknown（设计原则 8：能观测的不靠声明）。
#

from __future__ import annotations
import csv
import io
import json
import re
from typing import Any


SECRET_PATTERNS = [
    # API keys / Bearer tokens / claim tokens
    (re.compile(r"(?i)(bearer\s+[a-zA-Z0-9_\-\.]{16,})"), "[REDACTED_BEARER_TOKEN]"),
    # DSR-069 / SWR-010: quoted AND unquoted (env/header style) key=value
    # forms of the declared credential families are both masked — a value
    # inside a declared pattern family must not survive because it happened
    # to be unquoted.
    (re.compile(r"(?i)(api[_-]?key\s*[:=]\s*['\"]?)[a-zA-Z0-9_\-\.]{12,}(['\"]?)"), r"\1[REDACTED_API_KEY]\2"),
    (re.compile(r"(?i)(secret[_-]?key\s*[:=]\s*['\"]?)[a-zA-Z0-9_\-\.]{12,}(['\"]?)"), r"\1[REDACTED_SECRET]\2"),
    (re.compile(r"(?i)(password\s*[:=]\s*['\"]?)[^'\"]{4,}(['\"]?)"), r"\1[REDACTED_PASSWORD]\2"),
    (re.compile(r"(?i)(claim_token\s*[:=]\s*['\"]?)[a-zA-Z0-9]{16,}(['\"]?)"), r"\1[REDACTED_TOKEN]\2"),
    (re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+ PRIVATE KEY-----"), "[REDACTED_PRIVATE_KEY]"),
]


def mask_secrets(text: str) -> str:
    """Mask known credential patterns in text."""
    if not text:
        return text

    sanitized = text
    for regex, repl in SECRET_PATTERNS:
        sanitized = regex.sub(repl, sanitized)
    return sanitized


def mask_tree(obj: Any) -> Any:
    """Recursively mask every string value inside a JSON-serializable structure.

    DSR-069 / SWR-010: JSON report media (findings.json, skill-review.json) must
    not leak credential values stored in nested dicts/lists. Keys are preserved
    (they carry schema meaning); only string values are masked.
    """
    if isinstance(obj, str):
        return mask_secrets(obj)
    if isinstance(obj, dict):
        return {k: mask_tree(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [mask_tree(v) for v in obj]
    if isinstance(obj, tuple):
        return [mask_tree(v) for v in obj]
    return obj


def mask_json_text(json_text: str) -> str:
    """Parse a JSON document, mask all string values, and re-serialize.

    Falls back to plain textual masking if the payload is not valid JSON so
    sanitization never silently degrades to a no-op.
    """
    if not json_text:
        return json_text
    try:
        parsed = json.loads(json_text)
    except (ValueError, TypeError):
        return mask_secrets(json_text)
    return json.dumps(mask_tree(parsed), indent=2, ensure_ascii=False)


def mask_csv_text(csv_text: str) -> str:
    """Mask every cell of a CSV document (DSR-069 / SWR-010).

    The document is parsed with the stdlib csv module so quoted multi-line
    cells are handled correctly; each cell value is passed through the same
    secret pattern substitution used for Markdown media. Comment/meta lines
    starting with '#' are preserved verbatim (still passed through masking).
    """
    if not csv_text:
        return csv_text

    output = io.StringIO()
    writer = csv.writer(output)
    for row in csv.reader(io.StringIO(csv_text)):
        writer.writerow([mask_secrets(cell) for cell in row])
    return output.getvalue()
