"""Tests for driver adapters: exit classification (DSR-029), rate-limit
backoff, circuit breakers, the per-task usage envelope and termination-
uncertain budget retention (DSR-064). All host CLIs are fakes from
fake_hosts.py."""

import json
import os
import shutil
import subprocess
import tempfile
import threading
import unittest
from unittest import mock

from auditkit.contracts.errors import HostFailureError, InvalidInputError
from auditkit.hosts.claude_adapter import ClaudeDriverAdapter
from auditkit.hosts.codex_adapter import CodexDriverAdapter
from auditkit.hosts.errors import TerminationUncertainError
from auditkit.hosts.retry import compute_backoff_delay, extract_usage

import fake_hosts


class RetryTestMixin:
    """Configure adapters for fast tests: no retries and no sleep unless asked."""

    def make_claude(self, binary, **kwargs):
        kwargs.setdefault("max_retries", 0)
        kwargs.setdefault("backoff_base", 0.0)
        return ClaudeDriverAdapter(claude_binary=binary, **kwargs)

    def make_codex(self, binary, **kwargs):
        kwargs.setdefault("max_retries", 0)
        kwargs.setdefault("backoff_base", 0.0)
        return CodexDriverAdapter(codex_binary=binary, **kwargs)


class TestExitClassification(unittest.TestCase, RetryTestMixin):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="adapter-test-")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_claude_rate_limit_classified_retryable(self):
        binary = fake_hosts.create_fake_host(
            self.temp_dir, "claude", headless_exit=1, headless_stderr="rate limit exceeded"
        )
        adapter = self.make_claude(binary)
        with self.assertRaises(HostFailureError) as ctx:
            adapter.execute_worker("prompt", "t1")
        self.assertIn("rate limited", str(ctx.exception))
        self.assertTrue(ctx.exception.retryable)
        self.assertEqual(adapter.consecutive_failures, 1)

    def test_claude_auth_failure_not_retryable(self):
        binary = fake_hosts.create_fake_host(
            self.temp_dir, "claude", headless_exit=1, headless_stderr="unauthorized: bad api key"
        )
        adapter = self.make_claude(binary)
        with self.assertRaises(HostFailureError) as ctx:
            adapter.execute_worker("prompt", "t1")
        self.assertIn("authentication failure", str(ctx.exception))
        self.assertFalse(ctx.exception.retryable)

    def test_codex_rate_limit_classified(self):
        """DSR-029: Codex no longer maps every exit to a generic failure."""
        binary = fake_hosts.create_fake_host(
            self.temp_dir, "codex", headless_exit=1, headless_stderr="429 rate limit exceeded"
        )
        adapter = self.make_codex(binary)
        with self.assertRaises(HostFailureError) as ctx:
            adapter.execute_worker("prompt", "t1")
        self.assertIn("rate limited", str(ctx.exception))
        self.assertTrue(ctx.exception.retryable)

    def test_codex_auth_failure_not_retryable(self):
        binary = fake_hosts.create_fake_host(
            self.temp_dir, "codex", headless_exit=1, headless_stderr="authentication required: run codex login"
        )
        adapter = self.make_codex(binary)
        with self.assertRaises(HostFailureError) as ctx:
            adapter.execute_worker("prompt", "t1")
        self.assertIn("authentication failure", str(ctx.exception))
        self.assertFalse(ctx.exception.retryable)

    def test_codex_generic_exit_other_category(self):
        binary = fake_hosts.create_fake_host(
            self.temp_dir, "codex", headless_exit=7, headless_stderr="something broke"
        )
        adapter = self.make_codex(binary)
        with self.assertRaises(HostFailureError) as ctx:
            adapter.execute_worker("prompt", "t1")
        self.assertIn("exited with code 7", str(ctx.exception))
        self.assertFalse(ctx.exception.retryable)

    def test_codex_prompt_is_positional_argument(self):
        """P0-1: the prompt is passed as a POSITIONAL argument of
        `codex exec [OPTIONS] [PROMPT]` — never as a `--prompt` flag, which the
        real CLI rejects with the clap error and exit code 2. The real
        `--skip-git-repo-check` option is passed so non-Git targets work."""
        binary = fake_hosts.create_fake_host(
            self.temp_dir, "codex", headless_stdout='{"ok": true}'
        )
        adapter = self.make_codex(binary)
        result, _usage = adapter.execute_worker("reply with OK", "t1")
        self.assertEqual(result["ok"], True)
        invoked = fake_hosts.last_invoked_args(self.temp_dir, "codex")
        self.assertEqual(invoked, ["exec", "--skip-git-repo-check", "reply with OK"])

    def test_codex_non_git_target_is_usable(self):
        """P0-1 (SR-017): the adapter must not depend on codex's git trust
        gate — non-Git targets are auditable. The fake reproduces the real
        gate (refusal without --skip-git-repo-check, success with it), so a
        dropped option cannot pass silently."""
        binary = fake_hosts.create_fake_host(
            self.temp_dir, "codex", headless_stdout='{"ok": true}'
        )
        adapter = self.make_codex(binary)
        result, _usage = adapter.execute_worker("reply with OK", "t1")
        self.assertEqual(result["ok"], True)
        invoked = fake_hosts.last_invoked_args(self.temp_dir, "codex")
        self.assertIn("--skip-git-repo-check", invoked)
        # Without the option the real CLI refuses; the fake must too.
        proc = subprocess.run(
            [binary, "exec", "reply with OK"],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(proc.returncode, 1)
        self.assertIn(
            "Not inside a trusted directory and --skip-git-repo-check was not specified.",
            proc.stderr,
        )

    def test_codex_fake_rejects_prompt_flag_like_real_cli(self):
        """P0-1 anti-masking: the fake codex reproduces the real clap
        rejection, so a regression to `--prompt` cannot silently pass."""
        binary = fake_hosts.create_fake_host(self.temp_dir, "codex", headless_stdout="OK")
        proc = subprocess.run(
            [binary, "exec", "--prompt", "reply with OK"],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertIn("error: unexpected argument '--prompt' found", proc.stderr)
        self.assertIn("Usage: codex exec [OPTIONS] [PROMPT]", proc.stderr)
        self.assertEqual(proc.stdout.strip(), "")

    def test_timeout_classification(self):
        binary = fake_hosts.create_fake_host(self.temp_dir, "claude", sleep_seconds=30)
        adapter = self.make_claude(binary, timeout_seconds=1)
        with self.assertRaises(HostFailureError) as ctx:
            adapter.execute_worker("prompt", "t1")
        self.assertIn("timed out", str(ctx.exception))
        self.assertTrue(ctx.exception.retryable)


class TestBackoffAndRetry(unittest.TestCase, RetryTestMixin):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="backoff-test-")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_compute_backoff_delay_sequence(self):
        """DSR-064: exponential backoff sequence with cap; pure function."""
        self.assertEqual(compute_backoff_delay(1, base=0.5, max_delay=30.0), 0.5)
        self.assertEqual(compute_backoff_delay(2, base=0.5, max_delay=30.0), 1.0)
        self.assertEqual(compute_backoff_delay(3, base=0.5, max_delay=30.0), 2.0)
        self.assertEqual(compute_backoff_delay(10, base=0.5, max_delay=30.0), 30.0)
        self.assertEqual(compute_backoff_delay(0, base=2.0, max_delay=30.0), 2.0)

    def test_retryable_failure_backs_off_then_succeeds(self):
        binary = fake_hosts.create_rate_limited_fake_host(self.temp_dir, "claude", fail_first=2)
        adapter = self.make_claude(binary, max_retries=2, backoff_base=0.0)
        result, _usage = adapter.execute_worker("prompt", "t1")
        self.assertEqual(result["ok"], True)
        counter = os.path.join(self.temp_dir, "claude.attempt_counter")
        with open(counter, encoding="utf-8") as f:
            attempts = len(f.read().split())
        self.assertEqual(attempts, 3)
        self.assertEqual(adapter.consecutive_failures, 0)

    def test_codex_retries_bounded(self):
        binary = fake_hosts.create_rate_limited_fake_host(self.temp_dir, "codex", fail_first=5)
        adapter = self.make_codex(binary, max_retries=2, backoff_base=0.0)
        with self.assertRaises(HostFailureError):
            adapter.execute_worker("prompt", "t1")
        counter = os.path.join(self.temp_dir, "codex.attempt_counter")
        with open(counter, encoding="utf-8") as f:
            attempts = len(f.read().split())
        # initial call + max_retries retries, never unbounded retrying
        self.assertEqual(attempts, 3)

    def test_non_retryable_failure_not_retried(self):
        binary = fake_hosts.create_fake_host(
            self.temp_dir, "claude", headless_exit=1, headless_stderr="unauthorized"
        )
        adapter = self.make_claude(binary, max_retries=2, backoff_base=0.0)
        with self.assertRaises(HostFailureError):
            adapter.execute_worker("prompt", "t1")
        counter = os.path.join(self.temp_dir, "claude.attempt_counter")
        self.assertFalse(os.path.exists(counter))


class TestCircuitBreaker(unittest.TestCase, RetryTestMixin):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="breaker-test-")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_codex_circuit_breaker_trips(self):
        """DSR-064: Codex gets the same consecutive-failure breaker as Claude."""
        binary = fake_hosts.create_fake_host(
            self.temp_dir, "codex", headless_exit=1, headless_stderr="generic failure"
        )
        adapter = self.make_codex(binary)
        for _ in range(3):
            with self.assertRaises(HostFailureError):
                adapter.execute_worker("prompt", "t1")
        with self.assertRaises(HostFailureError) as ctx:
            adapter.execute_worker("prompt", "t1")
        self.assertIn("Circuit breaker", str(ctx.exception))
        self.assertFalse(ctx.exception.retryable)

    def test_claude_circuit_breaker_resets_on_success(self):
        binary = fake_hosts.create_rate_limited_fake_host(self.temp_dir, "claude", fail_first=2)
        adapter = self.make_claude(binary, max_retries=1, backoff_base=0.0)
        with self.assertRaises(HostFailureError):
            adapter.execute_worker("prompt", "t1")
        self.assertEqual(adapter.consecutive_failures, 2)
        adapter.execute_worker("prompt", "t2")  # succeeds, resets counter
        self.assertEqual(adapter.consecutive_failures, 0)


class TestUsageExtraction(unittest.TestCase, RetryTestMixin):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="usage-test-")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_claude_usage_envelope_captured_when_present(self):
        """P0 usage envelope: execute_worker returns (result, usage) with the
        usage dict bound to THIS execution's attempt (usage.schema semantics).
        The shared last_usage slot is gone: concurrent workers on one adapter
        can no longer cross-attribute per-attempt usage."""
        payload = {"ok": True, "usage": {"input_tokens": 10, "output_tokens": 5}}
        binary = fake_hosts.create_fake_host(
            self.temp_dir, "claude", headless_stdout=json.dumps(payload)
        )
        adapter = self.make_claude(binary)
        result, usage = adapter.execute_worker("prompt", "t1", attempt_id="att-1")
        self.assertEqual(result["ok"], True)
        self.assertEqual(usage, {
            "schema_version": "1.0",
            "attempt_id": "att-1",
            "dimension": "tokens",
            "availability": "estimated",
            "value": 15,
            "unit": "tokens",
            "source": "ClaudeDriverAdapter",
        })
        self.assertFalse(
            hasattr(adapter, "last_usage"),
            "the shared last_usage slot must be gone from the execution path",
        )
        self.assertEqual(
            adapter.extract_usage(payload), {"input_tokens": 10, "output_tokens": 5}
        )

    def test_codex_usage_envelope_declared_exact(self):
        payload = {"ok": True, "usage": {"total_tokens": 42, "availability": "exact"}}
        binary = fake_hosts.create_fake_host(
            self.temp_dir, "codex", headless_stdout=json.dumps(payload)
        )
        adapter = self.make_codex(binary)
        result, usage = adapter.execute_worker("prompt", "t1", attempt_id="att-2")
        self.assertEqual(result["ok"], True)
        self.assertEqual(usage, {
            "schema_version": "1.0",
            "attempt_id": "att-2",
            "dimension": "tokens",
            "availability": "exact",
            "value": 42,
            "unit": "tokens",
            "source": "CodexDriverAdapter",
        })

    def test_usage_envelope_unavailable_when_block_has_no_numbers(self):
        """A usage block without numeric values maps to an explicit
        unavailable record with a reason, never an invented value."""
        payload = {"ok": True, "usage": {"note": "metering disabled"}}
        binary = fake_hosts.create_fake_host(
            self.temp_dir, "claude", headless_stdout=json.dumps(payload)
        )
        adapter = self.make_claude(binary)
        _result, usage = adapter.execute_worker("prompt", "t1", attempt_id="att-3")
        self.assertEqual(usage["availability"], "unavailable")
        self.assertTrue(usage["reason"])
        self.assertNotIn("value", usage)
        self.assertEqual(usage["attempt_id"], "att-3")

    def test_usage_none_when_absent(self):
        """DSR-029: missing usage is reported as None, never invented."""
        binary = fake_hosts.create_fake_host(
            self.temp_dir, "codex", headless_stdout='{"ok": true}'
        )
        adapter = self.make_codex(binary)
        result, usage = adapter.execute_worker("prompt", "t1")
        self.assertEqual(result["ok"], True)
        self.assertIsNone(usage)
        self.assertIsNone(extract_usage({"ok": True}))
        self.assertIsNone(extract_usage("not a dict"))

    def test_concurrent_executions_bind_usage_to_their_own_attempt(self):
        """P0 regression (real concurrency): two threads driving the SAME
        adapter on different overlapping tasks must each receive the usage
        captured for their OWN invocation. Under the removed shared
        last_usage slot, overlapping completions swapped attribution; with
        the per-task envelope each return carries its own task's values."""
        # The fake host inspects the prompt (argv[2]) for the task marker and
        # emits the matching payload, so ONE shared adapter serves both tasks
        # with distinct usage through genuinely concurrent invocations.
        script = (
            "#!/bin/sh\n"
            "if [ \"$1\" = \"--version\" ]; then echo 'fake-host version 9.9.9'; exit 0; fi\n"
            "sleep 0.2\n"
            "case \"$2\" in\n"
            "  *TASK-A*) echo '{\"ok\": true, \"task\": \"TASK-A\", "
            "\"usage\": {\"total_tokens\": 150, \"availability\": \"exact\"}}';;\n"
            "  *TASK-B*) echo '{\"ok\": true, \"task\": \"TASK-B\", "
            "\"usage\": {\"total_tokens\": 700, \"availability\": \"exact\"}}';;\n"
            "esac\n"
            "exit 0\n"
        )
        binary = fake_hosts._write_executable(
            os.path.join(self.temp_dir, "claude"), script
        )
        adapter = self.make_claude(binary, timeout_seconds=30)
        start = threading.Barrier(2, timeout=30)
        collected = {}
        errors = []

        def run(marker, tokens):
            try:
                for round_no in range(3):
                    start.wait()
                    _result, usage = adapter.execute_worker(
                        f"work {marker}", f"task-{marker}-{round_no}",
                        attempt_id=f"att-{marker}-{round_no}",
                    )
                    collected[(marker, round_no)] = (usage or {}).get("value")
            except Exception as exc:  # surfaced below, never silently dropped
                errors.append(exc)

        threads = [
            threading.Thread(target=run, args=("TASK-A", 150)),
            threading.Thread(target=run, args=("TASK-B", 700)),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)
        self.assertEqual(errors, [], f"worker threads raised: {errors}")
        self.assertEqual(len(collected), 6)
        for (marker, _round), value in collected.items():
            self.assertEqual(
                value, 150 if marker == "TASK-A" else 700,
                f"usage cross-attributed for {marker}: got {value}",
            )


class TestTerminationUncertain(unittest.TestCase, RetryTestMixin):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="kill-test-")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_claude_unconfirmed_kill_retains_budget(self):
        """DSR-064: unconfirmable termination raises an exception flagged
        retains_budget and is not retried."""
        binary = fake_hosts.create_fake_host(self.temp_dir, "claude", sleep_seconds=30)
        adapter = self.make_claude(binary, timeout_seconds=1, max_retries=3)
        calls = {"n": 0}
        original = adapter._kill_process_group

        def flaky_kill(proc):
            calls["n"] += 1
            original(proc)
            return False  # pretend the killpg outcome cannot be confirmed

        adapter._kill_process_group = flaky_kill
        with self.assertRaises(TerminationUncertainError) as ctx:
            adapter.execute_worker("prompt", "t1")
        self.assertTrue(ctx.exception.retains_budget)
        self.assertTrue(ctx.exception.retryable)
        # Not retried despite retryable=True: budget state must be resolved first
        self.assertEqual(calls["n"], 1)

    def test_codex_unconfirmed_kill_retains_budget(self):
        binary = fake_hosts.create_fake_host(self.temp_dir, "codex", sleep_seconds=30)
        adapter = self.make_codex(binary, timeout_seconds=1, max_retries=3)
        with mock.patch.object(adapter, "_kill_process_group", return_value=False):
            with self.assertRaises(TerminationUncertainError) as ctx:
                adapter.execute_worker("prompt", "t1")
        self.assertTrue(ctx.exception.retains_budget)

    def test_confirmed_kill_raises_plain_timeout(self):
        binary = fake_hosts.create_fake_host(self.temp_dir, "codex", sleep_seconds=30)
        adapter = self.make_codex(binary, timeout_seconds=1, max_retries=0)
        with self.assertRaises(HostFailureError) as ctx:
            adapter.execute_worker("prompt", "t1")
        self.assertNotIsInstance(ctx.exception, TerminationUncertainError)


class TestFormatError(unittest.TestCase, RetryTestMixin):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="format-test-")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_invalid_json_raises_invalid_input(self):
        binary = fake_hosts.create_fake_host(self.temp_dir, "codex", headless_stdout="not json")
        adapter = self.make_codex(binary)
        with self.assertRaises(InvalidInputError):
            adapter.execute_worker("prompt", "t1")


if __name__ == "__main__":
    unittest.main()
