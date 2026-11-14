"""Tests for driver adapters: exit classification (DSR-029), rate-limit
backoff, circuit breakers, usage extraction and termination-uncertain budget
retention (DSR-064). All host CLIs are fakes from fake_hosts.py."""

import json
import os
import shutil
import tempfile
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
        result = adapter.execute_worker("prompt", "t1")
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

    def test_usage_captured_when_present(self):
        payload = {"ok": True, "usage": {"input_tokens": 10, "output_tokens": 5}}
        binary = fake_hosts.create_fake_host(
            self.temp_dir, "claude", headless_stdout=json.dumps(payload)
        )
        adapter = self.make_claude(binary)
        adapter.execute_worker("prompt", "t1")
        self.assertEqual(adapter.last_usage, {"input_tokens": 10, "output_tokens": 5})
        self.assertEqual(
            adapter.extract_usage(payload), {"input_tokens": 10, "output_tokens": 5}
        )

    def test_usage_none_when_absent(self):
        """DSR-029: missing usage is reported as None, never invented."""
        binary = fake_hosts.create_fake_host(
            self.temp_dir, "codex", headless_stdout='{"ok": true}'
        )
        adapter = self.make_codex(binary)
        adapter.execute_worker("prompt", "t1")
        self.assertIsNone(adapter.last_usage)
        self.assertIsNone(extract_usage({"ok": True}))
        self.assertIsNone(extract_usage("not a dict"))


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
