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

from auditkit.contracts.errors import HostFailureError
from auditkit.hosts.claude_adapter import ClaudeDriverAdapter
from auditkit.hosts.codex_adapter import CodexDriverAdapter
from auditkit.hosts.errors import TerminationUncertainError
from auditkit.hosts.retry import backoff_delay_for_failure, compute_backoff_delay, extract_usage

import fake_hosts


class RetryTestMixin:
    """Configure adapters for fast tests: no retries and no sleep unless asked."""

    def make_claude(self, binary, **kwargs):
        kwargs.setdefault("max_retries", 0)
        kwargs.setdefault("backoff_base", 0.0)
        kwargs.setdefault("rate_backoff_base", 0.0)
        return ClaudeDriverAdapter(claude_binary=binary, **kwargs)

    def make_codex(self, binary, **kwargs):
        kwargs.setdefault("max_retries", 0)
        kwargs.setdefault("backoff_base", 0.0)
        kwargs.setdefault("rate_backoff_base", 0.0)
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

    def test_codex_prompt_is_delivered_on_stdin(self):
        """P0-1 (revised for large-payload delivery): the prompt reaches the
        CLI without touching argv, so payload size is bounded by the pipe and
        not by the OS single-argument length limit. The fake's grammar stays
        strict: argv carries only the subcommand and real options (never a
        `--prompt` flag, which the real CLI rejects with the clap error and
        exit code 2), the real `--skip-git-repo-check` option is passed so
        non-Git targets work, and the prompt itself arrives complete on the
        runner-owned stdin pipe (IFC-04/DA-05: the worker never inherits the
        runner's interactive stdin)."""
        binary = fake_hosts.create_fake_host(
            self.temp_dir, "codex", headless_stdout='{"ok": true}'
        )
        adapter = self.make_codex(binary)
        result, _usage = adapter.execute_worker("reply with OK", "t1")
        self.assertEqual(result["ok"], True)
        invoked = fake_hosts.last_invoked_args(self.temp_dir, "codex")
        self.assertEqual(invoked, ["exec", "--skip-git-repo-check"])
        self.assertNotIn("reply with OK", invoked)
        stdin_text = fake_hosts.last_stdin(self.temp_dir, "codex")
        self.assertIn("reply with OK", stdin_text)

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

    def test_evidence_free_exit_defaults_retryable(self):
        """Exit with no diagnostic signature on either stream defaults to
        retryable: a non-retryable verdict permanently quarantines an audit
        unit while a retry costs minutes. The failure reason keeps a stdout
        tail so evidence-free stays diagnosable."""
        binary = fake_hosts.create_fake_host(
            self.temp_dir, "claude", headless_exit=1, headless_stderr="", headless_stdout=""
        )
        adapter = self.make_claude(binary)
        with self.assertRaises(HostFailureError) as ctx:
            adapter.execute_worker("prompt", "t1")
        self.assertTrue(ctx.exception.retryable)
        self.assertIn("exited with code 1", str(ctx.exception))
        self.assertIn("stdout_tail", str(ctx.exception))

    def test_stdout_only_rate_limit_signature_is_retryable(self):
        """A rate-limit signature printed on stdout (not stderr) classifies
        as retryable rate_limit: both streams are classification evidence."""
        binary = fake_hosts.create_fake_host(
            self.temp_dir, "claude", headless_exit=1,
            headless_stderr="", headless_stdout="APIError: Request rejected (429), retry later",
        )
        adapter = self.make_claude(binary)
        with self.assertRaises(HostFailureError) as ctx:
            adapter.execute_worker("prompt", "t1")
        self.assertIn("rate limited", str(ctx.exception))
        self.assertTrue(ctx.exception.retryable)

    def test_codex_evidence_free_exit_defaults_retryable(self):
        binary = fake_hosts.create_fake_host(
            self.temp_dir, "codex", headless_exit=1, headless_stderr="", headless_stdout=""
        )
        adapter = self.make_codex(binary)
        with self.assertRaises(HostFailureError) as ctx:
            adapter.execute_worker("prompt", "t1")
        self.assertTrue(ctx.exception.retryable)

    def test_prose_output_is_retryable_format_failure(self):
        """DA-13 bounded format retry: a successful exit whose output is
        prose-only (no JSON anywhere) is a retryable format failure, not a
        permanent quarantine -- one fresh execution usually produces
        contract output."""
        binary = fake_hosts.create_fake_host(
            self.temp_dir, "claude", headless_exit=0,
            headless_stdout="All checks done. No issues found in this unit.",
        )
        adapter = self.make_claude(binary)
        with self.assertRaises(HostFailureError) as ctx:
            adapter.execute_worker("prompt", "t1")
        self.assertTrue(ctx.exception.retryable)
        self.assertEqual(getattr(ctx.exception, "category", None), "format")

    def test_malformed_json_is_retryable_format_failure(self):
        """DA-13: truncated/malformed JSON (valid contract shape at the
        start, syntax error mid-stream) is retryable the same way."""
        binary = fake_hosts.create_fake_host(
            self.temp_dir, "claude", headless_exit=0,
            headless_stdout='{"schema_version": "1.0", "task_id": "t", "candid',
        )
        adapter = self.make_claude(binary)
        with self.assertRaises(HostFailureError) as ctx:
            adapter.execute_worker("prompt", "t1")
        self.assertTrue(ctx.exception.retryable)
        self.assertEqual(getattr(ctx.exception, "category", None), "format")

    def test_codex_prose_output_is_retryable_format_failure(self):
        binary = fake_hosts.create_fake_host(
            self.temp_dir, "codex", headless_exit=0,
            headless_stdout="Verification complete, no findings.",
        )
        adapter = self.make_codex(binary)
        with self.assertRaises(HostFailureError) as ctx:
            adapter.execute_worker("prompt", "t1")
        self.assertTrue(ctx.exception.retryable)
        self.assertEqual(getattr(ctx.exception, "category", None), "format")


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

    def test_compute_backoff_delay_bounded_under_cumulative_counter(self):
        """A cumulative failure counter (thousands) passed as the attempt
        index must not overflow float conversion -- the exponent is clamped
        and the schedule stays capped at max_delay."""
        self.assertEqual(compute_backoff_delay(1000, base=0.5, max_delay=30.0), 30.0)
        self.assertEqual(compute_backoff_delay(10**9, base=30.0, max_delay=120.0), 120.0)

    def test_backoff_rate_limit_uses_minute_scale_schedule(self):
        """Rate-limit retries use a minute-scale schedule (provider windows
        are minute-scale; the generic schedule spends every retry inside the
        window); other categories keep the generic schedule."""
        self.assertEqual(backoff_delay_for_failure(1, "rate_limit"), 30.0)
        self.assertEqual(backoff_delay_for_failure(2, "rate_limit"), 60.0)
        self.assertEqual(backoff_delay_for_failure(3, "rate_limit"), 120.0)
        self.assertEqual(backoff_delay_for_failure(9, "rate_limit"), 120.0)
        self.assertEqual(backoff_delay_for_failure(1, "other"), 0.5)
        self.assertEqual(backoff_delay_for_failure(2, None), 1.0)
        # Constructor overrides flow through for both schedules.
        self.assertEqual(
            backoff_delay_for_failure(1, "rate_limit", 0.5, 30.0, 0.1, 0.2), 0.1
        )

    def test_rate_limited_retries_apply_rate_schedule_and_recover(self):
        """Rate-limit-failing host recovers within retries using the
        rate schedule (wired via the failure category, fast params)."""
        binary = fake_hosts.create_rate_limited_fake_host(self.temp_dir, "claude", fail_first=2)
        adapter = self.make_claude(
            binary, max_retries=2, backoff_base=0.0, rate_backoff_base=0.01, rate_backoff_max=0.02
        )
        result, _usage = adapter.execute_worker("prompt", "t1")
        self.assertEqual(result["ok"], True)
        self.assertEqual(adapter.consecutive_failures, 0)

    def test_cli_json_envelope_usage_extracted_as_exact(self):
        """O-T03: with --output-format json the CLI wraps the worker text in
        an envelope carrying the host's token telemetry. The envelope's
        usage block is host-declared telemetry and maps to "exact"; the
        worker's own JSON is recovered from envelope.result."""
        worker_json = json.dumps({"ok": True, "candidates": []})
        envelope = json.dumps({
            "type": "result",
            "subtype": "success",
            "result": worker_json,
            "usage": {"input_tokens": 100, "output_tokens": 50},
        })
        binary = fake_hosts.create_fake_host(
            self.temp_dir, "claude", headless_exit=0, headless_stdout=envelope
        )
        adapter = self.make_claude(binary)
        result, usage = adapter.execute_worker("prompt", "t1", attempt_id="att-x1")
        self.assertEqual(result["ok"], True)
        self.assertIsNotNone(usage)
        self.assertEqual(usage["availability"], "exact")
        self.assertEqual(usage["value"], 150)
        self.assertEqual(usage["attempt_id"], "att-x1")

    def test_cli_json_envelope_without_usage_yields_none(self):
        """An envelope without a usage block yields None (never invented);
        the worker result still parses from envelope.result."""
        worker_json = json.dumps({"ok": True})
        envelope = json.dumps({
            "type": "result",
            "subtype": "success",
            "result": worker_json,
        })
        binary = fake_hosts.create_fake_host(
            self.temp_dir, "claude", headless_exit=0, headless_stdout=envelope
        )
        adapter = self.make_claude(binary)
        result, usage = adapter.execute_worker("prompt", "t1")
        self.assertEqual(result["ok"], True)
        self.assertIsNone(usage)

    def test_legacy_plain_worker_output_still_parses(self):
        """Regression: plain (non-envelope) worker output keeps parsing via
        the legacy path when the CLI ignores --output-format json."""
        binary = fake_hosts.create_fake_host(self.temp_dir, "claude")
        adapter = self.make_claude(binary)
        result, _usage = adapter.execute_worker("prompt", "t1")
        self.assertEqual(result["ok"], True)

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
        # Fail-safe pause marker: the dispatch layer pauses the run on this
        # error instead of cascading non-retryable quarantine (L-02).
        self.assertTrue(getattr(ctx.exception, "breaker_tripped", False))

    def test_claude_circuit_breaker_trips_marked_for_fail_safe_pause(self):
        binary = fake_hosts.create_fake_host(
            self.temp_dir, "claude", headless_exit=1, headless_stderr="generic failure"
        )
        adapter = self.make_claude(binary)
        for _ in range(3):
            with self.assertRaises(HostFailureError):
                adapter.execute_worker("prompt", "t1")
        with self.assertRaises(HostFailureError) as ctx:
            adapter.execute_worker("prompt", "t1")
        self.assertIn("Circuit breaker", str(ctx.exception))
        self.assertTrue(getattr(ctx.exception, "breaker_tripped", False))

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
        can no longer cross-attribute per-attempt usage. A host-NAMED usage
        block is the host's own telemetry and maps to "exact" (O-02: real
        host cost must be observable, never understated by a guess)."""
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
            "availability": "exact",
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

    # ------------------------------------------------- O-02 real-host usage
    def test_usage_found_in_nested_meta_envelope(self):
        """O-02: hosts that nest usage under a meta/telemetry envelope are
        observable. The block sits anywhere in the JSON output; a host-named
        container maps to exact with the declared value."""
        payload = {
            "ok": True,
            "result": {"records": []},
            "meta": {
                "session": "s-1",
                "usage": {"input_tokens": 120, "output_tokens": 80},
            },
        }
        binary = fake_hosts.create_fake_host(
            self.temp_dir, "claude", headless_stdout=json.dumps(payload)
        )
        adapter = self.make_claude(binary)
        _result, usage = adapter.execute_worker("prompt", "t1", attempt_id="att-meta")
        self.assertEqual(usage["availability"], "exact")
        self.assertEqual(usage["value"], 200)
        self.assertEqual(usage["attempt_id"], "att-meta")

    def test_usage_found_by_shape_only_maps_to_estimated(self):
        """O-02: an object that merely carries token-counter fields (no
        usage-like container name) is an INFERRED block — mapped
        conservatively to estimated, never promoted to exact."""
        payload = {
            "ok": True,
            "metrics": {"model": "synthetic", "prompt_tokens": 90, "completion_tokens": 30},
        }
        binary = fake_hosts.create_fake_host(
            self.temp_dir, "claude", headless_stdout=json.dumps(payload)
        )
        adapter = self.make_claude(binary)
        _result, usage = adapter.execute_worker("prompt", "t1", attempt_id="att-shape")
        self.assertEqual(usage["availability"], "estimated")
        self.assertEqual(usage["value"], 120)

    def test_usage_aliases_are_case_insensitive_and_camel_case(self):
        """O-02: the alias table matches case-insensitively, including
        camelCase host spellings like ``inputTokens`` / ``totalTokens``."""
        self.assertEqual(
            extract_usage({"ok": True, "Usage": {"InputTokens": 7, "OutputTokens": 3}}),
            {"InputTokens": 7, "OutputTokens": 3},
        )
        payload = {"ok": True, "usage": {"inputTokens": 7, "outputTokens": 3}}
        binary = fake_hosts.create_fake_host(
            self.temp_dir, "claude", headless_stdout=json.dumps(payload)
        )
        adapter = self.make_claude(binary)
        _result, usage = adapter.execute_worker("prompt", "t1", attempt_id="att-camel")
        self.assertEqual(usage["availability"], "exact")
        self.assertEqual(usage["value"], 10)

    def test_usage_declared_total_wins_over_part_sums(self):
        """O-02: when the host declares a grand total it is authoritative —
        input + output + total must not be summed into a double count."""
        payload = {
            "ok": True,
            "usage": {"input_tokens": 12, "output_tokens": 8, "total_tokens": 20},
        }
        binary = fake_hosts.create_fake_host(
            self.temp_dir, "claude", headless_stdout=json.dumps(payload)
        )
        adapter = self.make_claude(binary)
        _result, usage = adapter.execute_worker("prompt", "t1", attempt_id="att-total")
        self.assertEqual(usage["value"], 20)

    def test_usage_unrelated_numbers_do_not_inflate_token_count(self):
        """O-02: only recognized token-counter fields contribute; unrelated
        numeric envelope fields (turns, durations, ids) never inflate the
        token count and no number is ever invented."""
        payload = {
            "ok": True,
            "usage": {"input_tokens": 10, "num_turns": 4, "duration_ms": 1500},
        }
        binary = fake_hosts.create_fake_host(
            self.temp_dir, "claude", headless_stdout=json.dumps(payload)
        )
        adapter = self.make_claude(binary)
        _result, usage = adapter.execute_worker("prompt", "t1", attempt_id="att-noise")
        self.assertEqual(usage["value"], 10)

    def test_usage_host_declared_unavailable_is_honored(self):
        """O-02: a host that declares its own usage block unavailable keeps
        the honest unavailable record even when the block carries numbers."""
        payload = {
            "ok": True,
            "usage": {"input_tokens": 10, "availability": "unavailable"},
        }
        binary = fake_hosts.create_fake_host(
            self.temp_dir, "claude", headless_stdout=json.dumps(payload)
        )
        adapter = self.make_claude(binary)
        _result, usage = adapter.execute_worker("prompt", "t1", attempt_id="att-unavail")
        self.assertEqual(usage["availability"], "unavailable")
        self.assertTrue(usage["reason"])
        self.assertNotIn("value", usage)

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
        # The fake host inspects the prompt (delivered on stdin, matching the
        # adapters' stream contract) for the task marker and emits the
        # matching payload, so ONE shared adapter serves both tasks with
        # distinct usage through genuinely concurrent invocations.
        script = (
            "#!/bin/sh\n"
            "if [ \"$1\" = \"--version\" ]; then echo 'fake-host version 9.9.9'; exit 0; fi\n"
            "sleep 0.2\n"
            "prompt=$(cat)\n"
            "case \"$prompt\" in\n"
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
        """DA-13 (revised contract): unparseable worker output is a bounded-
        retryable format failure (HostFailureError, category=format), not a
        non-retryable InvalidInputError -- one fresh execution usually
        produces contract output; the attempt/generation caps still bound a
        genuinely unformattable unit."""
        binary = fake_hosts.create_fake_host(self.temp_dir, "codex", headless_stdout="not json")
        adapter = self.make_codex(binary)
        with self.assertRaises(HostFailureError) as ctx:
            adapter.execute_worker("prompt", "t1")
        self.assertTrue(ctx.exception.retryable)
        self.assertEqual(getattr(ctx.exception, "category", None), "format")


if __name__ == "__main__":
    unittest.main()
