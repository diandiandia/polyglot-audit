"""Driver adapter for Claude Code CLI worker execution.

Implements DSR-029 / DSR-064 / SD-09:
- Launches Claude CLI in headless mode.
- Enforces execution timeouts and kills process tree on cancellation.
- Categorizes process failures: auth, rate limit, timeout, format errors.
- Circuit breaker to halt dispatch after repeated consecutive host failures.
- Bounded rate-limit backoff: at most max_retries retries with exponential
  backoff (compute_backoff_delay); the adapter never retries unboundedly.
- Usage extraction from structured output for the LED domain.
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
from typing import Any, Dict, Optional

from auditkit.contracts.errors import HostFailureError, InvalidInputError
from auditkit.hosts.errors import TerminationUncertainError
from auditkit.hosts.retry import (
    classify_exit_failure,
    compute_backoff_delay,
    extract_usage,
)


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
    ) -> None:
        self.claude_binary = claude_binary
        self.timeout_seconds = timeout_seconds
        self.max_consecutive_failures = max_consecutive_failures
        self.consecutive_failures = 0
        self.max_retries = max_retries
        self.backoff_base = backoff_base
        self.backoff_max = backoff_max
        self.last_usage: Optional[Dict[str, Any]] = None

    def execute_worker(
        self,
        prompt: str,
        task_id: str,
        timeout: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Execute headless Claude worker and return parsed JSON result.

        Retryable failures (rate limit / timeout) are retried at most
        max_retries times with exponential backoff; non-retryable failures
        (auth, format, circuit breaker) propagate immediately. The usage block
        of the successful structured output, when present, is exposed via
        last_usage / extract_usage; absence is reported as None, never
        invented.
        """
        if self.consecutive_failures >= self.max_consecutive_failures:
            raise HostFailureError(
                f"Circuit breaker tripped: {self.consecutive_failures} consecutive Claude host failures",
                retryable=False,
            )

        attempt = 0
        while True:
            try:
                return self._execute_once(prompt, task_id, timeout or self.timeout_seconds)
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
        effective_timeout: int,
    ) -> Dict[str, Any]:
        """Run one Claude headless invocation and classify its outcome."""
        cmd = [self.claude_binary, "--print", prompt]

        proc = None
        try:
            # Start process in new process group to allow reliable cancellation.
            # stdin is bound to DEVNULL: a headless worker must neither block
            # on nor ingest the runner's input stream (same contract as the
            # Codex adapter; IFC-04 / DA-05).
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                preexec_fn=os.setsid if hasattr(os, "setsid") else None,
            )

            stdout, stderr = proc.communicate(timeout=effective_timeout)
            ret_code = proc.returncode

            if ret_code != 0:
                self.consecutive_failures += 1
                category, retryable = classify_exit_failure(stderr, ret_code)
                if category == "rate_limit":
                    raise HostFailureError(f"Claude rate limited: {stderr[:200]}", retryable=True)
                elif category == "auth_error":
                    raise HostFailureError(
                        f"Claude authentication failure: {stderr[:200]}", retryable=False
                    )
                else:
                    raise HostFailureError(
                        f"Claude process exited with code {ret_code}: {stderr[:200]}",
                        retryable=retryable,
                    )

            # Reset consecutive failures on success
            self.consecutive_failures = 0

            # Attempt to parse output JSON
            try:
                # Find JSON block in stdout if markdown fenced
                clean_stdout = stdout.strip()
                if "```json" in clean_stdout:
                    clean_stdout = clean_stdout.split("```json")[1].split("```")[0].strip()
                elif "```" in clean_stdout:
                    clean_stdout = clean_stdout.split("```")[1].split("```")[0].strip()
                parsed = json.loads(clean_stdout)
            except json.JSONDecodeError as e:
                raise InvalidInputError(f"Failed to parse worker JSON output: {e}\nRaw output: {stdout[:200]}")

            self.last_usage = extract_usage(parsed)
            return parsed

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
            raise HostFailureError(f"Claude execution timed out after {effective_timeout}s", retryable=True)

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
            # Could not deliver the signal at all — termination unconfirmed.
            return False
        try:
            proc.wait(timeout=5)
            return True
        except subprocess.TimeoutExpired:
            return False
