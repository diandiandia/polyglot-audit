"""Driver adapter for Claude Code CLI worker execution.

Implements DSR-029 / DSR-064 / SD-09:
- Launches Claude CLI in headless mode.
- Enforces execution timeouts and kills process tree on cancellation.
- Categorizes process failures: auth, rate limit, timeout, format errors.
- Circuit breaker to halt dispatch after repeated consecutive host failures.
- Bounded rate-limit backoff: at most max_retries retries with exponential
  backoff (compute_backoff_delay); the adapter never retries unboundedly.
- Per-task usage envelope: execute_worker returns (worker_result, usage) with
  the usage dict captured from the SAME invocation (usage.schema semantics) —
  never a shared adapter slot, which cross-attributed attempts when two
  workers finished within each other's execute tail under real concurrency.
- When process-group termination cannot be confirmed after killpg, raises
  TerminationUncertainError with retains_budget=True so the LED domain keeps
  the attempt budget outstanding (DSR-064).
"""

# 需求追踪 (Requirement Traceability)
# ---------------------------------------------------------------------------
# 上层需求: docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2
# 设计依据: docs/design/SOFTWARE_DESIGN.md
# SWR-023  Claude CLI 适配：认证、结构化输出提取、退出分类
#   绑定实现: DSR-029, DSR-064
# 状态以统一测试结论为准；未实测能力保持 unknown（设计原则 8：能观测的不靠声明）。
#

from __future__ import annotations
import json
import os
import signal
import subprocess
import time
from typing import Any, Dict, Optional, Tuple

from auditkit.contracts.errors import HostFailureError
from auditkit.hosts.errors import TerminationUncertainError
from auditkit.hosts.retry import (
    CATEGORY_FORMAT,
    CATEGORY_TIMEOUT,
    backoff_delay_for_failure,
    build_usage_envelope,
    classify_exit_failure,
    extract_usage,
)


def _usage_from_block(
    parsed: Any,
    attempt_id: Optional[str],
    source: str,
) -> Optional[Dict[str, Any]]:
    """Map this invocation's host usage block onto usage.schema semantics.

    Per-attempt usage envelope (P0 fix): the usage dict is built from the
    SAME parsed payload that produced the returned worker_result and is
    returned together with it — it is never parked on shared adapter state,
    so concurrent workers on one adapter cannot cross-attribute per-attempt
    usage. Mapping follows SWR-020 / DSR-033 with the generalized real-host
    search (O-02): the usage block is located anywhere in the CLI's JSON
    output (top-level, meta/telemetry envelope, or another nested object)
    against a case-insensitive alias table of common token-counter field
    names; a host-named block maps to "exact", a shape-only match to
    "estimated", a block without usable numbers to an explicit
    "unavailable" with a reason. The host is never inventable data: a
    payload without any usage block yields None. ``attempt_id`` is stamped
    from the claim this execution served (the service backfills its own
    authoritative claim attempt_id when unknown here).
    Requirements: SWR-020(用量映射) / DSR-033(逐次归属)
    """
    return build_usage_envelope(parsed, attempt_id, source)


class ClaudeDriverAdapter:
    """Invokes Claude CLI as external worker."""

    def __init__(
        self,
        claude_binary: str = "claude",
        timeout_seconds: int = 120,
        max_consecutive_failures: int = 3,
        max_retries: int = 2,
        backoff_base: float = 0.5,
        backoff_max: float = 30.0,
        rate_backoff_base: float = 30.0,
        rate_backoff_max: float = 120.0,
    ) -> None:
        """Configure timeouts, retries, breaker, and backoff.

        rate_backoff_* applies to rate-limit-categorized retries only:
        provider windows are minute-scale, so those retries use a
        minute-scale schedule instead of the generic one.

        Requirements: SWR-023(support) / DSR-064(熔断退避)
        """
        self.claude_binary = claude_binary
        self.timeout_seconds = timeout_seconds
        self.max_consecutive_failures = max_consecutive_failures
        self.consecutive_failures = 0
        self.max_retries = max_retries
        self.backoff_base = backoff_base
        self.backoff_max = backoff_max
        self.rate_backoff_base = rate_backoff_base
        self.rate_backoff_max = rate_backoff_max
        # NOTE: the former shared ``last_usage`` slot was removed (P0 fix).
        # Usage is returned per execution by execute_worker; a shared slot
        # cross-attributed per-attempt usage when two workers finished within
        # each other's execute tail under real concurrency.

    def execute_worker(
        self,
        prompt: str,
        task_id: str,
        timeout: Optional[int] = None,
        attempt_id: Optional[str] = None,
    ) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]]]:
        """Execute headless Claude worker and return (worker_result, usage).

        Returns a per-execution tuple: the parsed JSON result plus the usage
        dict captured from THIS invocation (usage.schema semantics:
        schema_version / attempt_id / dimension / availability / value / unit
        / source), or None when the host reported no usage block — absence is
        reported as None, never invented. Usage travels with the result it
        belongs to, so concurrent workers sharing this adapter each receive
        their own usage (the removed ``last_usage`` slot swapped attribution
        when completions interleaved).

        Retryable failures (rate limit / timeout) are retried at most
        max_retries times with exponential backoff; non-retryable failures
        (auth, format, circuit breaker) propagate immediately.

        ``attempt_id``, when supplied (the claim this call executes), is
        stamped into the returned usage dict.
        Requirements: SWR-023(无头执行) / DSR-029(退出分类), DSR-064(退避熔断), DSR-033(逐次用量)
        """
        if self.consecutive_failures >= self.max_consecutive_failures:
            raise HostFailureError(
                f"Circuit breaker tripped: {self.consecutive_failures} consecutive Claude host failures",
                retryable=False,
            )

        attempt = 0
        while True:
            try:
                return self._execute_once(
                    prompt, task_id, attempt_id, timeout or self.timeout_seconds
                )
            except TerminationUncertainError:
                raise
            except HostFailureError as exc:
                if not exc.retryable or attempt >= self.max_retries:
                    raise
                attempt += 1
                # Rate-limit failures back off on a minute-scale schedule:
                # provider windows are minute-scale, and the generic fast
                # schedule would spend every retry inside the window.
                delay = backoff_delay_for_failure(
                    attempt,
                    getattr(exc, "category", None),
                    self.backoff_base,
                    self.backoff_max,
                    self.rate_backoff_base,
                    self.rate_backoff_max,
                )
                if delay > 0:
                    time.sleep(delay)

    def _execute_once(
        self,
        prompt: str,
        task_id: str,
        attempt_id: Optional[str],
        effective_timeout: int,
    ) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]]]:
        """Run one Claude headless invocation and classify its outcome. Requirements: SWR-023(support) / DSR-029(单次分类), DSR-064(超时终止)"""
        # Stream contract (IFC-04 / DA-05): the worker process must never
        # inherit the runner's interactive stdin. stdin=PIPE binds a
        # runner-owned pipe instead: the prompt is written once and the pipe
        # closed (claude --print reads it), so the runner's own stdin is
        # untouched -- no blocking, no swallowed input. Prompt-via-pipe also
        # removes the OS single-argument length ceiling that large review
        # packets would otherwise hit on the argv path.
        cmd = [self.claude_binary, "--print"]

        proc = None
        try:
            # Start process in new process group to allow reliable cancellation.
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                preexec_fn=os.setsid if hasattr(os, "setsid") else None,
            )

            stdout, stderr = proc.communicate(input=prompt, timeout=effective_timeout)
            ret_code = proc.returncode

            if ret_code != 0:
                self.consecutive_failures += 1
                # Both streams are classification evidence: real hosts print
                # API errors on either stderr or stdout, and the failure
                # reason must keep enough of both to stay diagnosable when
                # one of them is empty.
                category, retryable = classify_exit_failure(stderr, ret_code, stdout=stdout)
                if category == "rate_limit":
                    exc = HostFailureError(
                        f"Claude rate limited: stderr={stderr[:200]!r} stdout_tail={stdout[-200:]!r}",
                        retryable=True,
                    )
                elif category == "auth_error":
                    exc = HostFailureError(
                        f"Claude authentication failure: stderr={stderr[:200]!r} stdout_tail={stdout[-200:]!r}",
                        retryable=False,
                    )
                else:
                    exc = HostFailureError(
                        f"Claude process exited with code {ret_code}: "
                        f"stderr={stderr[:200]!r} stdout_tail={stdout[-200:]!r}",
                        retryable=retryable,
                    )
                exc.category = category  # consumer: rate-aware retry backoff
                raise exc

            # Reset consecutive failures on success
            self.consecutive_failures = 0

            # Attempt to parse output JSON. Real models wrap JSON in prose
            # ("All verification complete. ...") or markdown fences; both are
            # accepted, with the raw error preserved for honest retryables.
            try:
                clean_stdout = stdout.strip()
                if "```json" in clean_stdout:
                    clean_stdout = clean_stdout.split("```json")[1].split("```")[0].strip()
                elif "```" in clean_stdout:
                    clean_stdout = clean_stdout.split("```")[1].split("```")[0].strip()
                try:
                    parsed = json.loads(clean_stdout)
                except json.JSONDecodeError:
                    # Fallback: outermost braces scan (prose-wrapped raw JSON)
                    start, end = clean_stdout.find("{"), clean_stdout.rfind("}")
                    if start == -1 or end <= start:
                        raise
                    parsed = json.loads(clean_stdout[start:end + 1])
            except json.JSONDecodeError as e:
                # Bounded format retry (DA-13): real workers occasionally
                # emit prose-only or malformed/truncated JSON. One fresh
                # execution usually produces contract output, so this failure
                # is retryable; the attempt/generation caps still quarantine
                # a genuinely unformattable unit after the bounded retries.
                exc = HostFailureError(
                    f"Failed to parse worker JSON output: {e}\nRaw output: {stdout[:200]}",
                    retryable=True,
                )
                exc.category = CATEGORY_FORMAT
                raise exc

            return parsed, _usage_from_block(
                parsed, attempt_id, source=type(self).__name__
            )

        except subprocess.TimeoutExpired:
            self.consecutive_failures += 1
            if proc:
                confirmed = self._kill_process_group(proc)
            else:
                confirmed = False
            if not confirmed:
                raise TerminationUncertainError(
                    f"Claude execution timed out after {effective_timeout}s and "
                    "process-group termination could not be confirmed; attempt "
                    "budget must be retained pending resolution"
                )
            timeout_exc = HostFailureError(
                f"Claude execution timed out after {effective_timeout}s", retryable=True
            )
            timeout_exc.category = CATEGORY_TIMEOUT  # consumer: retry backoff
            raise timeout_exc

        except Exception:
            if proc and proc.poll() is None:
                self._kill_process_group(proc)
            raise

    def extract_usage(self, result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Extract the usage block from a structured worker result (or None). Requirements: SWR-020(support) / DSR-033(用量提取)"""
        return extract_usage(result)

    def _kill_process_group(self, proc: subprocess.Popen) -> bool:
        """Kill entire process group; return True only if termination confirmed. Requirements: SWR-023(support) / DSR-064(进程组终止)"""
        try:
            if hasattr(os, "killpg") and hasattr(os, "getpgid"):
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            else:
                proc.kill()
        except OSError:
            # Could not deliver the signal at all — termination unconfirmed.
            return False
        try:
            proc.wait(timeout=5)
            return True
        except subprocess.TimeoutExpired:
            return False
