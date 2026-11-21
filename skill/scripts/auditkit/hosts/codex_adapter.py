"""Driver adapter for Codex CLI worker execution.

Implements DSR-003 / DSR-029 / DSR-064 / SD-09:
- Launches Codex CLI in headless mode.
- Isolates process execution and enforces process killing on timeout/cancellation.
- Validates that target repo configs are not executed during audit invocation.
- Classifies process exits into rate_limit / auth_error / timeout / other
  (DSR-029), with per-category retryability.
- Circuit breaker symmetric with the Claude adapter (DSR-064).
- Bounded exponential backoff for retryable failures (max_retries default 2).
- Per-task usage envelope: execute_worker returns (worker_result, usage) with
  the usage dict captured from the SAME invocation (usage.schema semantics) —
  never a shared adapter slot, which cross-attributed attempts when two
  workers finished within each other's execute tail under real concurrency.
- TerminationUncertainError with retains_budget=True when killpg outcome is
  unconfirmed (DSR-064).
"""

# 需求追踪 (Requirement Traceability)
# ---------------------------------------------------------------------------
# 上层需求: docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2
# 设计依据: docs/design/SOFTWARE_DESIGN.md
# SWR-023  Codex CLI 独立适配：与 Claude 等价的分类/用量/熔断，不互相推断
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

    Per-attempt usage envelope (P0 fix), symmetric with the Claude adapter:
    the usage dict is built from the SAME parsed payload that produced the
    returned worker_result and is returned together with it — it is never
    parked on shared adapter state, so concurrent workers on one adapter
    cannot cross-attribute per-attempt usage. Mapping follows SWR-020 /
    DSR-033 with the generalized real-host search (O-02): the usage block is
    located anywhere in the CLI's JSON output against a case-insensitive
    alias table of common token-counter field names; a host-named block maps
    to "exact", a shape-only match to "estimated", and a block without
    usable numbers to an explicit "unavailable" with a reason. The host is
    never inventable data: a payload without any usage block yields None.
    ``attempt_id`` is stamped from the claim this execution served (the
    service backfills its own authoritative claim attempt_id when unknown
    here).
    Requirements: SWR-020(用量映射) / DSR-033(逐次归属)
    """
    return build_usage_envelope(parsed, attempt_id, source)


class CodexDriverAdapter:
    """Invokes Codex CLI as external worker."""

    def __init__(
        self,
        codex_binary: str = "codex",
        timeout_seconds: int = 120,
        max_consecutive_failures: int = 3,
        max_retries: int = 2,
        backoff_base: float = 0.5,
        backoff_max: float = 30.0,
        rate_backoff_base: float = 30.0,
        rate_backoff_max: float = 120.0,
    ) -> None:
        """Configure timeouts, retries, breaker, and backoff.

        Requirements: SWR-023(support) / DSR-064(熔断退避)
        """
        self.codex_binary = codex_binary
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
        """Execute headless Codex worker and return (worker_result, usage).

        Returns a per-execution tuple: the parsed JSON result plus the usage
        dict captured from THIS invocation (usage.schema semantics:
        schema_version / attempt_id / dimension / availability / value / unit
        / source), or None when the host reported no usage block — absence is
        reported as None, never invented. Usage travels with the result it
        belongs to, so concurrent workers sharing this adapter each receive
        their own usage (the removed ``last_usage`` slot swapped attribution
        when completions interleaved).

        Retryable failures are retried at most max_retries times with
        exponential backoff; the circuit breaker halts dispatch after
        max_consecutive_failures consecutive host failures.

        ``attempt_id``, when supplied (the claim this call executes), is
        stamped into the returned usage dict.
        Requirements: SWR-023(无头执行) / DSR-029(退出分类), DSR-064(退避熔断), DSR-033(逐次用量)
        """
        if self.consecutive_failures >= self.max_consecutive_failures:
            raise HostFailureError(
                f"Circuit breaker tripped: {self.consecutive_failures} consecutive Codex host failures",
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
        """Run one Codex headless invocation and classify its outcome. Requirements: SWR-023(support) / DSR-003(独立适配), DSR-029(单次分类), DSR-064(超时终止)"""
        # Invocation contract (P0-1, verified against codex-cli 0.167.0):
        # - the prompt is a POSITIONAL argument of `codex exec [OPTIONS] [PROMPT]`;
        #   the real CLI rejects `--prompt` with "error: unexpected argument
        #   '--prompt' found" (the fake host in tests/hosts/fake_hosts.py
        #   enforces this so the defect class cannot hide behind a permissive fake);
        # - `--skip-git-repo-check` deterministically disables codex's own git
        #   trust gate ("Not inside a trusted directory and --skip-git-repo-check
        #   was not specified."). SR-017 explicitly supports non-Git targets:
        #   this audit's isolation comes from the frozen snapshot plus the
        #   user's safety acceptance (SR-015), not from codex's interactive
        #   trust convenience, so the gate is disabled to keep non-Git targets
        #   equally auditable.
        # Stream contract (IFC-04 / DA-05): the worker process must never
        # inherit the runner's interactive stdin. stdin=PIPE binds a
        # runner-owned pipe instead: the prompt is written once and the pipe
        # closed, so codex exec (which reads its prompt from stdin when no
        # positional prompt is given) receives exactly this payload and the
        # runner's own stdin is untouched -- no blocking, no swallowed input.
        # Prompt-via-pipe also removes the OS single-argument length ceiling
        # that large review packets would otherwise hit on the argv path
        # (probes keep the positional form: their prompts are tiny).
        cmd = [
            self.codex_binary,
            "exec",
            "--skip-git-repo-check",
        ]

        proc = None
        try:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                preexec_fn=os.setsid if hasattr(os, "setsid") else None,
            )

            stdout, stderr = proc.communicate(input=prompt + '\n', timeout=effective_timeout)
            if proc.returncode != 0:
                self.consecutive_failures += 1
                # Both streams are classification evidence (see retry.py):
                # hosts print API errors on either stderr or stdout, and the
                # failure reason must stay diagnosable when one is empty.
                category, retryable = classify_exit_failure(stderr, proc.returncode, stdout=stdout)
                if category == "rate_limit":
                    exc = HostFailureError(
                        f"Codex rate limited: stderr={stderr[:200]!r} stdout_tail={stdout[-200:]!r}",
                        retryable=True,
                    )
                elif category == "auth_error":
                    exc = HostFailureError(
                        f"Codex authentication failure: stderr={stderr[:200]!r} stdout_tail={stdout[-200:]!r}",
                        retryable=False,
                    )
                else:
                    exc = HostFailureError(
                        f"Codex process exited with code {proc.returncode}: "
                        f"stderr={stderr[:200]!r} stdout_tail={stdout[-200:]!r}",
                        retryable=retryable,
                    )
                exc.category = category  # consumer: rate-aware retry backoff
                raise exc

            # Reset consecutive failures on success
            self.consecutive_failures = 0

            clean = stdout.strip()
            if "```json" in clean:
                clean = clean.split("```json")[1].split("```")[0].strip()
            elif "```" in clean:
                clean = clean.split("```")[1].split("```")[0].strip()

            parsed = json.loads(clean)
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
                    f"Codex worker timed out after {effective_timeout}s and "
                    "process-group termination could not be confirmed; attempt "
                    "budget must be retained pending resolution"
                )
            raise HostFailureError(f"Codex worker timed out after {effective_timeout}s", retryable=True)

        except json.JSONDecodeError as e:
            # Bounded format retry (DA-13): see claude_adapter — real workers
            # occasionally emit prose-only or malformed/truncated JSON; one
            # fresh execution usually produces contract output, so this is
            # retryable within the existing attempt/generation caps.
            exc = HostFailureError(
                f"Failed to parse Codex JSON output: {e}\nRaw output: {stdout[:200]}",
                retryable=True,
            )
            exc.category = CATEGORY_FORMAT
            raise exc

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
            return False
        try:
            proc.wait(timeout=5)
            return True
        except subprocess.TimeoutExpired:
            return False
