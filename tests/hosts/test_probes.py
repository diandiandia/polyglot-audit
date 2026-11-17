"""Tests for the probe_host_capabilities framework (DSR-002/003/004/005).

Uses fake host CLIs built into a tempdir injected via PATH so no real host is
required. Verifies: level gating, honest UNKNOWN on headless failure,
independent Claude/Codex probing, and conservative defaults for the
delegation / budget / timeout probe plans.
"""

import os
import re
import shutil
import sys
import tempfile
import unittest
from unittest import mock

from auditkit.hosts import probes
from auditkit.hosts.capabilities import FeatureState

import fake_hosts


class TestProbeHostCapabilities(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="probe-test-")
        self.empty_dir = tempfile.mkdtemp(prefix="probe-empty-")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        shutil.rmtree(self.empty_dir, ignore_errors=True)

    def _probe(self, binary, host, level):
        with mock.patch.dict(os.environ, {"PATH": self.temp_dir}):
            return probes.probe_host_capabilities(binary, host, probe_level=level)

    def test_conservative_level_does_not_execute_headless(self):
        """DSR-002: default conservative level never runs the host CLI beyond
        --version; headless stays UNKNOWN with the plan described."""
        fake_hosts.create_fake_host(self.temp_dir, "claude")
        report = self._probe("claude", "claude", probes.PROBE_LEVEL_CONSERVATIVE)
        self.assertIsNotNone(report["binary"])
        headless = report["features"]["headless_cli"]
        self.assertEqual(headless["state"], FeatureState.UNKNOWN)
        self.assertIn("conservative", headless["reason"])
        version = report["features"]["version"]
        self.assertEqual(version["state"], FeatureState.ENFORCED)
        self.assertIn("--version", version["method"])

    def test_headless_level_success_is_enforced(self):
        fake_hosts.create_fake_host(self.temp_dir, "claude", headless_stdout="OK")
        report = self._probe("claude", "claude", probes.PROBE_LEVEL_HEADLESS)
        self.assertEqual(report["features"]["headless_cli"]["state"], FeatureState.ENFORCED)

    def test_headless_failure_stays_unknown(self):
        """DSR-002: failed headless invocation keeps UNKNOWN + probe error."""
        fake_hosts.create_fake_host(
            self.temp_dir, "claude", headless_exit=2, headless_stderr="exploded"
        )
        report = self._probe("claude", "claude", probes.PROBE_LEVEL_HEADLESS)
        headless = report["features"]["headless_cli"]
        self.assertEqual(headless["state"], FeatureState.UNKNOWN)
        self.assertIn("exploded", headless["reason"])

    def test_counterexample_layer_not_executed_below_aggressive(self):
        """Aggressive-layer probes stay UNKNOWN + plan unless requested."""
        fake_hosts.create_fake_host(self.temp_dir, "codex")
        report = self._probe("codex", "codex", probes.PROBE_LEVEL_HEADLESS)
        for feature in ("filesystem_isolation", "network_isolation", "execution_isolation"):
            self.assertEqual(report["features"][feature]["state"], FeatureState.UNKNOWN)
            self.assertIn("counterexample", report["features"][feature]["method"])

    def test_codex_headless_probe_passes_prompt_positionally(self):
        """P0-1: the codex probe shape matches the real CLI contract — the
        prompt is positional after `exec --skip-git-repo-check`; `--prompt`
        never appears in the transmitted command."""
        fake_hosts.create_fake_host(self.temp_dir, "codex", headless_stdout="OK")
        report = self._probe("codex", "codex", probes.PROBE_LEVEL_HEADLESS)
        headless = report["features"]["headless_cli"]
        self.assertEqual(headless["state"], FeatureState.ENFORCED)
        self.assertNotIn("--prompt", headless["method"])
        self.assertIn("--skip-git-repo-check", headless["method"])
        self.assertEqual(
            fake_hosts.last_invoked_args(self.temp_dir, "codex"),
            ["exec", "--skip-git-repo-check", "reply with OK"],
        )

    def test_codex_counterexample_probe_transmits_its_own_prompt(self):
        """P0-1 adjacent fix: the execution counterexample previously reused
        the fixed headless prompt table entry, so codex was asked to 'reply
        with OK' instead of writing the marker file. The probe's own prompt
        must be the one transmitted."""
        workdir = tempfile.mkdtemp(prefix="codex-counterexample-")
        try:
            fake_hosts.create_fake_host(self.temp_dir, "codex", headless_stdout="OK")
            probes.probe_execution_counterexample(
                fake_hosts.create_fake_host(self.temp_dir, "codex", headless_stdout="OK"),
                "codex",
                workdir,
                timeout=10,
            )
            invoked = fake_hosts.last_invoked_args(self.temp_dir, "codex")
            self.assertEqual(invoked[0], "exec")
            self.assertIn("--skip-git-repo-check", invoked)
            self.assertNotIn("--prompt", invoked)
            # The transmitted prompt is the marker-file instruction, not the
            # generic headless probe prompt.
            self.assertIn("auditkit_exec_probe_marker.txt", invoked[-1])
            self.assertNotIn("reply with OK", invoked[-1])
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

    def test_invalid_probe_level_rejected(self):
        with self.assertRaises(ValueError):
            probes.probe_host_capabilities("claude", "claude", probe_level="yolo")

    def test_missing_cli_independent_of_other_host(self):
        """DSR-003: Codex is never inferred from Claude's presence."""
        fake_hosts.create_fake_host(self.temp_dir, "claude")
        with mock.patch.dict(os.environ, {"PATH": self.temp_dir}):
            claude_report = probes.probe_host_capabilities(
                "claude", "claude", probe_level=probes.PROBE_LEVEL_CONSERVATIVE
            )
            codex_report = probes.probe_host_capabilities(
                "codex", "codex", probe_level=probes.PROBE_LEVEL_CONSERVATIVE
            )
        self.assertEqual(
            claude_report["features"]["installed"]["state"], FeatureState.ENFORCED
        )
        self.assertEqual(codex_report["binary"], None)
        self.assertEqual(
            codex_report["features"]["installed"]["state"], FeatureState.NOT_ENFORCED
        )
        self.assertIn("codex", codex_report["features"]["installed"]["reason"])


class TestProbePlanDefaults(unittest.TestCase):

    def test_subagent_delegation_default_unknown(self):
        """DSR-004: delegation probe is UNKNOWN unless aggressively executed."""
        feature = probes.probe_subagent_delegation()
        self.assertEqual(feature["state"], FeatureState.UNKNOWN)
        self.assertIn("plan", feature["reason"].lower() or feature["method"])

    def test_subagent_delegation_aggressive_success(self):
        feature = probes.probe_subagent_delegation(
            lambda prompt: "OK", probe_level=probes.PROBE_LEVEL_AGGRESSIVE
        )
        self.assertEqual(feature["state"], FeatureState.ENFORCED)

    def test_subagent_delegation_aggressive_failure_unknown(self):
        def bad_delegate(prompt):
            raise RuntimeError("no subagents available")

        feature = probes.probe_subagent_delegation(
            bad_delegate, probe_level=probes.PROBE_LEVEL_AGGRESSIVE
        )
        self.assertEqual(feature["state"], FeatureState.UNKNOWN)
        self.assertIn("no subagents", feature["reason"])

    def test_budget_probe_default_unknown(self):
        """DSR-005: hard budget limits stay UNKNOWN without measured usage."""
        feature = probes.probe_single_call_budget()
        self.assertEqual(feature["state"], FeatureState.UNKNOWN)

    def test_budget_probe_with_usage_evidence(self):
        feature = probes.probe_single_call_budget(
            lambda: {"usage": {"input_tokens": 1}}, probe_level=probes.PROBE_LEVEL_AGGRESSIVE
        )
        self.assertEqual(feature["state"], FeatureState.ENFORCED)

    def test_timeout_probe_default_unknown(self):
        feature = probes.probe_timeout_cancellation()
        self.assertEqual(feature["state"], FeatureState.UNKNOWN)


class TestNetworkCounterexampleProbe(unittest.TestCase):
    """DSR-002/003: the network counterexample measures the HOST process.

    The earlier revision connected from the audit process itself, so it
    judged the local environment and wrote that verdict into the host's
    network_isolation. These tests pin the corrected contract: only a
    connection made by the host CLI process is evidence, and an
    unmeasurable host stays UNKNOWN (never mislabelled NOT_ENFORCED).
    """

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="net-probe-")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_connecting_host_reports_not_enforced(self):
        """A host whose CLI process connects to the listener is observed
        using the network: NOT_ENFORCED with the executed command recorded."""
        fake = fake_hosts.create_network_fake_host(
            self.temp_dir, "claude", behaviour="connect"
        )
        feature = probes.probe_network_counterexample(
            fake, "claude", timeout=15, listen_seconds=3
        )
        self.assertEqual(feature["state"], FeatureState.NOT_ENFORCED)
        self.assertIn("host CLI process", feature["evidence"])
        # DSR-001: the method carries the exact command that was executed.
        self.assertIn(fake, feature["method"])

    def test_refusing_host_stays_unknown_not_mislabeled(self):
        """The fix for the DSR-002 deviation: a sandboxed host whose CLI
        fails its headless call must stay UNKNOWN. The audit machine itself
        can always reach loopback, so the old environment-level probe would
        have returned NOT_ENFORCED here."""
        fake = fake_hosts.create_network_fake_host(
            self.temp_dir, "claude", behaviour="refuse"
        )
        feature = probes.probe_network_counterexample(
            fake, "claude", timeout=15, listen_seconds=1
        )
        self.assertEqual(feature["state"], FeatureState.UNKNOWN)
        self.assertNotIn("evidence", feature)
        self.assertIn("host exited 7", feature["reason"])

    def test_hanging_host_times_out_to_unknown(self):
        """Conservative default: a host slower than the probe window is
        UNKNOWN with the timed-out reason, never a fabricated verdict."""
        fake = fake_hosts.create_network_fake_host(
            self.temp_dir, "claude", behaviour="hang", hang_seconds=30
        )
        feature = probes.probe_network_counterexample(
            fake, "claude", timeout=2, listen_seconds=1
        )
        self.assertEqual(feature["state"], FeatureState.UNKNOWN)
        self.assertIn("timed out", feature["reason"])
        self.assertNotIn("evidence", feature)

    def test_prompt_instructs_the_host_with_the_bound_port(self):
        """The transmitted prompt is the connection instruction carrying the
        listener's own port, and the evidence names that same port — the
        local socket work is preparation only, the host process connects."""
        captured = {}
        real_run = probes.subprocess.run

        def spy_run(cmd, **kwargs):
            captured["cmd"] = cmd
            return real_run(cmd, **kwargs)

        fake = fake_hosts.create_network_fake_host(
            self.temp_dir, "claude", behaviour="connect"
        )
        with mock.patch.object(probes.subprocess, "run", spy_run):
            feature = probes.probe_network_counterexample(
                fake, "claude", timeout=15, listen_seconds=3
            )
        self.assertEqual(feature["state"], FeatureState.NOT_ENFORCED)
        prompt = captured["cmd"][-1]
        match = re.search(r"127\.0\.0\.1 port (\d+)", prompt)
        self.assertIsNotNone(match, "prompt must name the loopback port")
        self.assertIn(f"127.0.0.1:{match.group(1)}", feature["evidence"])
        self.assertEqual(fake, captured["cmd"][0])

    def test_aggressive_report_writes_host_outcome_not_local_environment(self):
        """Integration through probe_host_capabilities (aggressive level): a
        refusing host lands UNKNOWN in network_isolation even though the
        runner's own environment permits loopback connections."""
        fake_hosts.create_network_fake_host(self.temp_dir, "claude", behaviour="refuse")
        with mock.patch.dict(os.environ, {"PATH": self.temp_dir}):
            report = probes.probe_host_capabilities(
                "claude", "claude", probe_level=probes.PROBE_LEVEL_AGGRESSIVE,
                timeout=10,
            )
        net = report["features"]["network_isolation"]
        self.assertEqual(net["state"], FeatureState.UNKNOWN)
        self.assertNotIn("evidence", net)
        self.assertIn("loopback socket counterexample", net["method"])


class TestMcpHandshakeProbe(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="mcp-probe-")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_handshake_success_enforced(self):
        server = fake_hosts.create_mcp_stdio_fake_server(self.temp_dir)
        feature = probes.probe_mcp_stdio_handshake([sys.executable, server])
        self.assertEqual(feature["state"], FeatureState.ENFORCED)
        self.assertIn("initialize", feature["method"])

    def test_spawn_failure_unknown(self):
        feature = probes.probe_mcp_stdio_handshake(
            ["/nonexistent/mcp-server-binary-path"], timeout=5
        )
        self.assertEqual(feature["state"], FeatureState.UNKNOWN)
        self.assertIn("reason", feature)


if __name__ == "__main__":
    unittest.main()
