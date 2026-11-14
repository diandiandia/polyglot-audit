"""Retry primitives shared by host driver adapters.

Implements DSR-029 / DSR-064:
- compute_backoff_delay: pure exponential backoff function with cap.
- classify_exit_failure: maps exit code + stderr onto failure categories
  (rate_limit / auth_error / timeout / other) with retryability.
- extract_usage: pulls a usage block out of a structured worker result.

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
from typing import Any, Dict, Optional, Tuple

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


def extract_usage(result: Any) -> Optional[Dict[str, Any]]:
    """Extract the usage block from a parsed structured worker result.

    Returns the usage dict when present, otherwise None (LED domain treats
    this as USAGE_UNKNOWN and must not invent token counts).
    """
    if not isinstance(result, dict):
        return None
    usage = result.get("usage")
    if isinstance(usage, dict):
        return usage
    # Some hosts nest usage under meta/telemetry blocks.
    for key in ("meta", "telemetry", "_meta"):
        nested = result.get(key)
        if isinstance(nested, dict) and isinstance(nested.get("usage"), dict):
            return nested["usage"]
    return None
