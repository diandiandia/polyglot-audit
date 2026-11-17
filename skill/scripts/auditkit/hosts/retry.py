"""Retry primitives shared by host driver adapters.

Implements DSR-029 / DSR-064:
- compute_backoff_delay: pure exponential backoff function with cap.
- classify_exit_failure: maps exit code + stderr onto failure categories
  (rate_limit / auth_error / timeout / other) with retryability.
- extract_usage / locate_usage_block: pull a usage block out of a structured
  worker result. The search is generalized (O-02, run lessons): real host
  CLIs report token telemetry at different places in their JSON output — a
  top-level ``usage`` object, a ``meta``/``telemetry`` envelope, or another
  nested object — so the block is located ANYWHERE in the payload, matched
  case-insensitively against a table of common token-counter field aliases
  (input/prompt/completion/output/total/cache/reasoning tokens). A block is
  never fabricated: a payload without usage-shaped data yields None and the
  caller reports usage as unavailable with that honest reason (SR-020).
- build_usage_envelope: maps the located block onto the usage.schema
  semantics (schema_version / attempt_id / dimension / availability / value
  / unit / source) shared by both driver adapters.

Adapters never retry infinitely: they call compute_backoff_delay with the
attempt number and bound the retry count explicitly (max_retries default 2).
"""

# 需求追踪 (Requirement Traceability)
# ---------------------------------------------------------------------------
# 上层需求: docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2
# 设计依据: docs/design/SOFTWARE_DESIGN.md
# SWR-019  预算/重试约束：限流退避可配置、有限重试，不可控维度诚实降级
#   绑定实现: DSR-064
# 状态以统一测试结论为准；未实测能力保持 unknown（设计原则 8：能观测的不靠声明）。
#

from __future__ import annotations
from typing import Any, Dict, List, Optional, Tuple

# Failure categories produced by classify_exit_failure (DSR-029).
CATEGORY_RATE_LIMIT = "rate_limit"
CATEGORY_AUTH_ERROR = "auth_error"
CATEGORY_TIMEOUT = "timeout"
CATEGORY_OTHER = "other"

# stderr (lowercased) substrings treated as rate limiting / auth failure.
_RATE_LIMIT_PATTERNS = ("rate limit", "rate_limit", "ratelimit", "429", "too many requests", "quota")
_AUTH_PATTERNS = ("auth", "unauthorized", "401", "403", "api key", "login", "credential")


def compute_backoff_delay(attempt: int, base: float = 0.5, max_delay: float = 30.0) -> float:
    """Return the exponential backoff delay in seconds for a retry attempt.

    attempt is 1-based (first retry uses base * 2**0). The result is capped at
    max_delay. Pure function: no I/O, no clock, no state.
    Requirements: SWR-019(有限退避) / DSR-064(限流退避)
    """
    if attempt < 1:
        attempt = 1
    delay = base * (2 ** (attempt - 1))
    if delay > max_delay:
        delay = max_delay
    return delay


def classify_exit_failure(stderr: str, return_code: int) -> Tuple[str, bool]:
    """Classify a non-zero CLI exit into (category, retryable).

    Categories follow DSR-029: rate_limit and timeout are retryable,
    auth_error is not, other is not retryable by default.
    Requirements: SWR-023(support) / DSR-029(退出分类), DSR-064(类别互异)
    """
    lowered = (stderr or "").lower()
    if any(p in lowered for p in _RATE_LIMIT_PATTERNS):
        return CATEGORY_RATE_LIMIT, True
    if any(p in lowered for p in _AUTH_PATTERNS):
        return CATEGORY_AUTH_ERROR, False
    # Non-zero exit codes conventionally used by rate limiting.
    if return_code in (429,):
        return CATEGORY_RATE_LIMIT, True
    return CATEGORY_OTHER, False


# Recognized token-counter field names inside a usage block. Matching is
# case-insensitive and covers the common host CLI spellings: Anthropic-style
# input/output tokens, OpenAI-style prompt/completion tokens, provider
# totals, and cache/reasoning counters.
TOKEN_FIELD_ALIASES: frozenset = frozenset({
    "input_tokens", "inputtokens",
    "prompt_tokens", "prompttokens",
    "output_tokens", "outputtokens",
    "completion_tokens", "completiontokens",
    "total_tokens", "totaltokens",
    "cache_creation_input_tokens", "cache_read_input_tokens",
    "cache_creation_tokens", "cache_read_tokens",
    "cached_tokens", "cache_write_tokens",
    "reasoning_tokens", "thinking_tokens",
})

# Field names that carry a host-declared grand total. When one is present it
# is the authoritative value: summing it together with its parts would
# double-count (input + output + total != total).
_TOTAL_FIELD_ALIASES: frozenset = frozenset({"total_tokens", "totaltokens"})

# Container key names under which hosts are known to REPORT a usage block
# (matched case-insensitively). A block reached through one of these keys is
# host-declared usage telemetry; a block that merely looks like usage is an
# inferred one and is mapped conservatively (see build_usage_envelope).
USAGE_CONTAINER_NAMES: frozenset = frozenset({
    "usage", "token_usage", "tokenusage", "tokens", "usage_report",
})

# Search bound: usage telemetry sits in the envelope around the result, not
# arbitrarily deep in it. The cap keeps pathological payloads bounded.
_USAGE_SEARCH_MAX_DEPTH = 8


def _as_number(value: Any) -> Optional[int]:
    """Return the value as an integer token count when it is a plain number.

    bools are excluded (True is not a count); integral floats are accepted
    because some hosts serialize counts as ``123.0``. Everything else is not
    a usable count and is never coerced into one (no invented numbers).
    Requirements: SWR-020(support) / DSR-033(不造假数)
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return None


def _is_usage_shaped(obj: Any) -> bool:
    """True when the dict carries at least one numeric token-counter field. Requirements: SWR-020(support) / DSR-033(形状识别)"""
    if not isinstance(obj, dict):
        return False
    for key, value in obj.items():
        if str(key).lower() in TOKEN_FIELD_ALIASES and _as_number(value) is not None:
            return True
    return False


def _token_numerics(block: Dict[str, Any]) -> Tuple[int, Optional[int]]:
    """Return (sum_of_parts, declared_total) from a usage block.

    Only recognized token-counter fields contribute (an unrelated numeric
    such as ``num_turns`` must not inflate the token count); ``declared_total``
    is set when the host supplies a total field, in which case it wins over
    the summed parts.
    Requirements: SWR-020(support) / DSR-033(计数汇总)
    """
    parts: List[int] = []
    declared_total: Optional[int] = None
    for key, value in block.items():
        lowered = str(key).lower()
        if lowered not in TOKEN_FIELD_ALIASES:
            continue
        number = _as_number(value)
        if number is None:
            continue
        if lowered in _TOTAL_FIELD_ALIASES:
            # A grand total never also counts as a part; the first one wins.
            if declared_total is None:
                declared_total = number
        else:
            parts.append(number)
    return sum(parts), declared_total


def locate_usage_block(result: Any) -> Optional[Tuple[Dict[str, Any], str]]:
    """Locate the host usage block anywhere in a parsed JSON payload (O-02).

    Returns ``(block, origin)`` where ``origin`` is:

    - ``"named"``: the block was reached through a usage-like container key
      ("usage" / "token_usage" / "tokens", any case) — the HOST declares the
      object as its usage telemetry;
    - ``"shape"``: no usage-named container exists, but an object carries the
      recognizable token-counter fields — the block is inferred, and the
      caller must not promote it above "estimated".

    The conventional top-level ``usage`` key wins (back-compat), then
    usage-named containers in breadth-first (shallowest first) order, then
    usage-shaped objects in the same order. ``None`` when no part of the
    payload carries usage data: absence is reported as absence, never
    invented (SR-020 / design principle 8).
    Requirements: SWR-020(用量定位) / DSR-033(缺则None)
    """
    if not isinstance(result, dict):
        return None

    # Back-compat fast path: the conventional top-level block, taken as
    # host-declared regardless of its inner field names (an explicitly
    # emitted "usage" object without numbers is an explicit unavailable).
    top_level = result.get("usage")
    if isinstance(top_level, dict):
        return top_level, "named"

    named: Optional[Tuple[Dict[str, Any], str]] = None
    shaped: Optional[Tuple[Dict[str, Any], str]] = None
    frontier: List[Any] = [result]
    depth = 0
    while frontier and depth < _USAGE_SEARCH_MAX_DEPTH:
        next_frontier: List[Any] = []
        for node in frontier:
            if isinstance(node, dict):
                for key, value in node.items():
                    if not isinstance(value, dict):
                        continue
                    if str(key).lower() in USAGE_CONTAINER_NAMES and named is None:
                        named = (value, "named")
                    if shaped is None and _is_usage_shaped(value):
                        shaped = (value, "shape")
                    next_frontier.append(value)
            elif isinstance(node, list):
                next_frontier.extend(item for item in node if isinstance(item, (dict, list)))
        if named is not None:
            return named
        frontier = next_frontier
        depth += 1
    return shaped


def extract_usage(result: Any) -> Optional[Dict[str, Any]]:
    """Extract the usage block from a parsed structured worker result.

    Returns the usage dict when present (located anywhere in the payload,
    see locate_usage_block), otherwise None (LED domain treats this as
    USAGE_UNKNOWN and must not invent token counts).
    Requirements: SWR-020(support) / DSR-033(块提取)
    """
    found = locate_usage_block(result)
    return found[0] if found else None


def build_usage_envelope(
    parsed: Any,
    attempt_id: Optional[str],
    source: str,
) -> Optional[Dict[str, Any]]:
    """Map the located host usage block onto usage.schema semantics (DSR-033).

    Availability ladder (SWR-020 / O-02 — honest labeling, never invented):
    - a block the host DECLARED exact/estimated keeps that declaration;
    - a block the host declared unavailable stays unavailable with that
      reason, even when it carries numbers;
    - a host-NAMED usage block (usage/token_usage/... key) is the host's own
      telemetry and maps to "exact";
    - a block recognized only by its field shape maps conservatively to
      "estimated";
    - a block without any usable token number maps to "unavailable" with an
      explicit reason.

    The value is the host's declared total when it supplies one, otherwise
    the sum of the recognized token-counter fields. A payload without any
    usage block yields None; ``attempt_id`` is stamped from the claim this
    execution served (the service backfills its own authoritative claim
    attempt_id when unknown here).
    Requirements: SWR-020(可用性阶梯) / DSR-033(exact映射)
    """
    found = locate_usage_block(parsed)
    if found is None:
        return None
    block, origin = found

    usage: Dict[str, Any] = {
        "schema_version": "1.0",
        "dimension": "tokens",
        "unit": "tokens",
        "source": source,
    }
    if attempt_id:
        usage["attempt_id"] = attempt_id

    declared = block.get("availability")
    if declared == "unavailable":
        usage["availability"] = "unavailable"
        usage["reason"] = "host declared its usage block unavailable"
        return usage

    parts_sum, declared_total = _token_numerics(block)
    if declared_total is None and not parts_sum:
        usage["availability"] = "unavailable"
        usage["reason"] = "host usage block contained no numeric token values"
        return usage

    if declared in ("exact", "estimated"):
        availability = declared
    else:
        availability = "exact" if origin == "named" else "estimated"
    usage["availability"] = availability
    usage["value"] = declared_total if declared_total is not None else parts_sum
    return usage
