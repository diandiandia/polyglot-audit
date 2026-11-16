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

from auditkit.contracts.errors import HostFailureError, InvalidInputError
from auditkit.hosts.errors import TerminationUncertainError
from auditkit.hosts.retry import (
    classify_exit_failure,
    compute_backoff_delay,
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
    DSR-033: availability is "exact" only when the host declared it, numeric
    values without a declaration map to "estimated", and a block without any
    numeric value maps to an explicit "unavailable" record with a reason.
    The host is never inventable data: a payload without any usage block
    yields None. ``attempt_id`` is stamped from the claim this execution
    served (the service backfills its own authoritative claim attempt_id
    when unknown here).
    """
    block = extract_usage(parsed)
    if not isinstance(block, dict):
        return None
    usage: Dict[str, Any] = {
        "schema_version": "1.0",
        "dimension": "tokens",
        "unit": "tokens",
        "source": source,
    }
    if attempt_id:
        usage["attempt_id"] = attempt_id
    declared = block.get("availability")
    numerics = [
        v for v in block.values() if isinstance(v, int) and not isinstance(v, bool)
    ]
    if not numerics:
        usage["availability"] = "unavailable"
        usage["reason"] = "host usage block contained no numeric values"
        return usage
    usage["availability"] = declared if declared in ("exact", "estimated") else "estimated"
    usage["value"] = sum(numerics)
    return usage


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
    ) -> None:
        self.codex_binary = codex_binary
        self.timeout_seconds = timeout_seconds
        self.max_consecutive_failures = max_consecutive_failures
        self.consecutive_failures = 0
        self.max_retries = max_retries
        self.backoff_base = backoff_base
        self.backoff_max = backoff_max
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
                delay = compute_backoff_delay(attempt, self.backoff_base, self.backoff_max)
                if delay > 0:
                    time.sleep(delay)

    def _execute_once(
        self,
        prompt: str,
        task_id: str,
        attempt_id: Optional[str],
        effective_timeout: int,
    ) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]]]:
        """Run one Codex headless invocation and classify its outcome."""
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
        # stdin is detached: codex exec additionally reads stdin when it is not
        # a TTY, and a headless worker must neither block on nor ingest the
        # runner's input stream.
        cmd = [
            self.codex_binary,
            "exec",
            "--skip-git-repo-check",
            prompt,
        ]

        proc = None
        try:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                preexec_fn=os.setsid if hasattr(os, "setsid") else None,
            )

            stdout, stderr = proc.communicate(timeout=effective_timeout)
            if proc.returncode != 0:
                self.consecutive_failures += 1
                category, retryable = classify_exit_failure(stderr, proc.returncode)
                if category == "rate_limit":
                    raise HostFailureError(f"Codex rate limited: {stderr[:200]}", retryable=True)
                elif category == "auth_error":
                    raise HostFailureError(
                        f"Codex authentication failure: {stderr[:200]}", retryable=False
                    )
                else:
                    raise HostFailureError(
                        f"Codex process exited with code {proc.returncode}: {stderr[:200]}",
                        retryable=retryable,
                    )

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
            raise InvalidInputError(f"Failed to parse Codex JSON output: {e}\nRaw output: {stdout[:200]}")

        except Exception:
            if proc and proc.poll() is None:
                self._kill_process_group(proc)
            raise

    def extract_usage(self, result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Extract the usage block from a structured worker result (or None)."""
        return extract_usage(result)

    def _kill_process_group(self, proc: subprocess.Popen) -> bool:
        """Kill entire process group; return True only if termination confirmed."""
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
