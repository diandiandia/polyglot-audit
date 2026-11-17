"""Tests for DSR-001 probe honesty in the Doctor capability report."""

import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

from auditkit.hosts.capabilities import FeatureState
from auditkit.hosts.doctor import Doctor
from auditkit.hosts import probes

import fake_hosts


class TestDoctorProbeHonesty(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="doctor-test-")
        self.empty_dir = tempfile.mkdtemp(prefix="doctor-empty-")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        shutil.rmtree(self.empty_dir, ignore_errors=True)

    def test_stdlib_offline_probe_records_evidence_and_method(self):
        """DSR-001: stdlib claim is backed by a real import enumeration."""
        caps = Doctor().probe(probe_cli=False)
        core = next(c for c in caps if c["adapter"] == "python_core")
        feature = core["features"]["stdlib_offline"]
        self.assertEqual(feature["state"], FeatureState.ENFORCED)
        self.assertIn("method", feature)
        # Evidence must carry the module list, not a hard-coded assertion.
        for mod in probes.DEFAULT_STDLIB_PROBE_MODULES:
            self.assertIn(mod, feature["evidence"])

    def test_stdlib_probe_unknown_on_import_failure(self):
        """DSR-001: an import failure leaves the claim UNKNOWN with reason."""
        feature = probes.probe_stdlib_modules(["json", "no_such_module_xyz"])
        self.assertEqual(feature["state"], FeatureState.UNKNOWN)
        self.assertIn("no_such_module_xyz", feature["reason"])
        self.assertIn("method", feature)

    def test_version_probe_failure_is_unknown_with_reason(self):
        """DSR-001: --version failure is recorded as UNKNOWN + reason, never
        silently swallowed into an ENFORCED or empty version."""
        fake = fake_hosts.create_fake_host(
            self.temp_dir, "claude", version_exit=3, version_output=""
        )
        with mock.patch.dict(os.environ, {"PATH": self.temp_dir}):
            caps = Doctor().probe(probe_cli=False)
        claude = next(c for c in caps if c["adapter"] == "claude_cli")
        self.assertEqual(claude["adapter_version"], "unknown")
        version = claude["features"]["version"]
        self.assertEqual(version["state"], FeatureState.UNKNOWN)
        self.assertIn("3", version["reason"])
        self.assertIn("--version", version["method"])

    def test_missing_cli_scenario_reports_not_enforced(self):
        """DSR-001: PATH pointing at an empty directory yields a not_enforced
        installed feature and no fabricated version."""
        with mock.patch.dict(os.environ, {"PATH": self.empty_dir}):
            caps = Doctor().probe(probe_cli=False)
        claude = next(c for c in caps if c["adapter"] == "claude_cli")
        self.assertEqual(claude["adapter_version"], "not_installed")
        self.assertEqual(
            claude["features"]["installed"]["state"], FeatureState.NOT_ENFORCED
        )
        self.assertIn("PATH", claude["features"]["installed"]["method"])
        codex = next(c for c in caps if c["adapter"] == "codex_cli")
        self.assertEqual(codex["adapter_version"], "not_installed")

    def test_python_core_execution_isolation_never_claimed_without_probe(self):
        """DSR-002 discipline: 'runtime policy review' is not a falsifiable
        probe, so python_core.execution_isolation must stay UNKNOWN with the
        honest reason — matching the honest NOT_ENFORCED treatment of the
        filesystem/network rows on the same adapter."""
        caps = Doctor().probe(probe_cli=False)
        core = next(c for c in caps if c["adapter"] == "python_core")
        feature = core["features"]["execution_isolation"]
        self.assertEqual(feature["state"], FeatureState.UNKNOWN)
        self.assertNotIn("evidence", feature)
        self.assertIn("not a falsifiable probe", feature["method"])
        self.assertIn("runtime policy review is not a falsifiable probe", feature["reason"])

    def test_every_feature_records_method(self):
        """DSR-001: capability report is evidence-with-command; each feature
        must disclose the probe method used."""
        fake_hosts.create_fake_host(self.temp_dir, "claude")
        with mock.patch.dict(os.environ, {"PATH": self.temp_dir}):
            caps = Doctor().probe(probe_cli=False)
        for cap in caps:
            for name, feature in cap["features"].items():
                self.assertIn(
                    "method", feature, f"{cap['adapter']}.{name} missing method"
                )

    def test_probe_cli_false_keeps_headless_unknown(self):
        """probe_cli=False must never promote headless_cli to ENFORCED."""
        fake_hosts.create_fake_host(self.temp_dir, "claude")
        with mock.patch.dict(os.environ, {"PATH": self.temp_dir}):
            caps = Doctor().probe(probe_cli=False)
        claude = next(c for c in caps if c["adapter"] == "claude_cli")
        self.assertEqual(claude["features"]["headless_cli"]["state"], FeatureState.UNKNOWN)

    def test_probe_cli_true_with_working_headless_enforced(self):
        """probe_cli=True performs a real headless call; success -> ENFORCED."""
        fake_hosts.create_fake_host(
            self.temp_dir, "claude", headless_stdout="OK"
        )
        with mock.patch.dict(os.environ, {"PATH": self.temp_dir}):
            caps = Doctor().probe(probe_cli=True)
        claude = next(c for c in caps if c["adapter"] == "claude_cli")
        self.assertEqual(claude["features"]["headless_cli"]["state"], FeatureState.ENFORCED)
        self.assertIn("claude --print", claude["features"]["headless_cli"]["method"])

    def test_probe_cli_true_with_failing_headless_stays_unknown(self):
        """DSR-002: a failing headless call must NOT be turned into ENFORCED
        (the old --version-only fake probe)."""
        fake_hosts.create_fake_host(
            self.temp_dir, "claude", headless_exit=1, headless_stderr="boom"
        )
        with mock.patch.dict(os.environ, {"PATH": self.temp_dir}):
            caps = Doctor().probe(probe_cli=True)
        claude = next(c for c in caps if c["adapter"] == "claude_cli")
        headless = claude["features"]["headless_cli"]
        self.assertEqual(headless["state"], FeatureState.UNKNOWN)
        self.assertIn("boom", headless["reason"])

    def test_mcp_stdio_transport_unknown_without_probe(self):
        """DSR-004: transport stays UNKNOWN until a real handshake runs."""
        caps = Doctor().probe(probe_cli=False)
        session = next(c for c in caps if c["adapter"] == "in_session")
        feature = session["features"]["mcp_stdio_transport"]
        self.assertEqual(feature["state"], FeatureState.UNKNOWN)
        self.assertIn("handshake", feature["method"])

    def test_mcp_stdio_transport_enforced_after_real_handshake(self):
        """DSR-004: ENFORCED only when a stdio initialize handshake succeeds."""
        server = fake_hosts.create_mcp_stdio_fake_server(self.temp_dir)
        caps = Doctor().probe(probe_cli=False, mcp_server_cmd=[sys.executable, server])
        session = next(c for c in caps if c["adapter"] == "in_session")
        feature = session["features"]["mcp_stdio_transport"]
        self.assertEqual(feature["state"], FeatureState.ENFORCED)
        self.assertIn("initialize", feature["evidence"])

    def test_sequential_fallback_follows_session_mode(self):
        """DSR-030: sequential_session_fallback is reported from the real mode."""
        caps = Doctor().probe(probe_cli=False, session_mode="sequential_fallback")
        session = next(c for c in caps if c["adapter"] == "in_session")
        self.assertEqual(
            session["features"]["sequential_session_fallback"]["state"],
            FeatureState.ENFORCED,
        )
        self.assertIn("sequential", session["features"]["sequential_session_fallback"]["evidence"])

        caps = Doctor().probe(probe_cli=False)
        session = next(c for c in caps if c["adapter"] == "in_session")
        self.assertEqual(
            session["features"]["sequential_session_fallback"]["state"], FeatureState.UNKNOWN
        )


if __name__ == "__main__":
    unittest.main()
