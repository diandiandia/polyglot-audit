"""Per-host probe timeout regression (P1 deviation 4, DSR-002).

实测偏差: a real codex reasoning-model round trip routinely exceeds 30s, so
the previous uniform 30s headless-probe cap returned fabricated "unknown"
verdicts for working codex installs. The cap is now per host (claude 30s,
codex 90s) with explicit arguments still overriding.

tests/hosts/** is owned by a parallel workstream, so these regression tests
live under tests/tools/. They assert only what the deviation requires: the
EFFECTIVE timeout value applied to the real CLI call, and an honest reason
when a host still exceeds its window — never that a slow host is declared
working.

A real-CLI test runs when codex is present on PATH; it passes either way
(ENFORCED, or UNKNOWN with the honest "timed out after 90s" reason), failing
only if the probe silently used the old 30s cap or lied about its reason.
"""

from __future__ import annotations
import shutil
import subprocess
import unittest
from unittest import mock

from auditkit.hosts import probes
from auditkit.hosts.capabilities import FeatureState

CODEX_BIN = shutil.which("codex")
CLAUDE_BIN = shutil.which("claude")


def _completed_process(stdout: str = "OK") -> mock.MagicMock:
    proc = mock.MagicMock()
    proc.returncode = 0
    proc.stdout = stdout
    proc.stderr = ""
    return proc


class TestResolveProbeTimeout(unittest.TestCase):

    def test_per_host_defaults(self):
        self.assertEqual(probes.resolve_probe_timeout("claude"), 30)
        self.assertEqual(probes.resolve_probe_timeout("codex"), 90)

    def test_unknown_host_uses_conservative_fallback(self):
        self.assertEqual(probes.resolve_probe_timeout("mysteryhost"), 30)

    def test_explicit_timeout_overrides_host_default(self):
        self.assertEqual(probes.resolve_probe_timeout("codex", timeout=5), 5)
        self.assertEqual(probes.resolve_probe_timeout("claude", timeout=120), 120)

    def test_non_positive_timeout_rejected(self):
        for bad in (0, -3):
            with self.assertRaises(ValueError):
                probes.resolve_probe_timeout("codex", timeout=bad)

    def test_default_table_is_honest_about_codex_being_slower(self):
        """P1 deviation guard: codex must keep its wider window."""
        self.assertGreater(
            probes.DEFAULT_PROBE_TIMEOUTS["codex"],
            probes.DEFAULT_PROBE_TIMEOUTS["claude"],
        )


class TestHeadlessProbeAppliesHostTimeout(unittest.TestCase):

    def _run_probe(self, host, **kwargs):
        with mock.patch.object(probes.subprocess, "run") as run_mock:
            run_mock.return_value = _completed_process()
            feature = probes.probe_headless_invocation("/usr/bin/fake", host, **kwargs)
        return feature, run_mock

    def test_codex_probe_waits_90s_not_30s(self):
        feature, run_mock = self._run_probe("codex")
        self.assertEqual(feature["state"], FeatureState.ENFORCED)
        self.assertEqual(run_mock.call_args.kwargs["timeout"], 90)

    def test_claude_probe_keeps_30s(self):
        feature, run_mock = self._run_probe("claude")
        self.assertEqual(run_mock.call_args.kwargs["timeout"], 30)

    def test_explicit_timeout_still_overrides(self):
        _, run_mock = self._run_probe("codex", timeout=7)
        self.assertEqual(run_mock.call_args.kwargs["timeout"], 7)

    def test_timeout_reason_records_effective_value(self):
        """A host slower than its window stays UNKNOWN — with the honest
        reason carrying the timeout that actually applied."""
        with mock.patch.object(probes.subprocess, "run") as run_mock:
            run_mock.side_effect = subprocess.TimeoutExpired(cmd="codex", timeout=90)
            feature = probes.probe_headless_invocation("/usr/bin/fake", "codex")
        self.assertEqual(feature["state"], FeatureState.UNKNOWN)
        self.assertEqual(feature["reason"], "headless probe timed out after 90s")

    def test_capability_probe_passes_host_default_to_headless_call(self):
        with mock.patch.dict("os.environ", {"PATH": "/nonexistent-auditkit-probe"}):
            with mock.patch.object(probes, "shutil") as shutil_mock:
                shutil_mock.which.return_value = "/usr/bin/fake"
                with mock.patch.object(probes.subprocess, "run") as run_mock:
                    run_mock.return_value = _completed_process(stdout="1.0.0")
                    report = probes.probe_host_capabilities(
                        "codex", "codex", probe_level=probes.PROBE_LEVEL_HEADLESS
                    )
        timeouts = [c.kwargs["timeout"] for c in run_mock.call_args_list]
        # --version probe (10s) followed by the headless probe on the
        # per-host codex default.
        self.assertEqual(report["features"]["headless_cli"]["state"], FeatureState.ENFORCED)
        self.assertIn(90, timeouts)
        self.assertNotIn(30, timeouts)


@unittest.skipUnless(CODEX_BIN, "real codex CLI not available on PATH")
class TestRealCodexProbeTimeout(unittest.TestCase):
    """真实 CLI 回归: the codex probe must not fail on OUR 30s budget.

    Passes either way: ENFORCED when the real round trip fits the 90s window,
    UNKNOWN with the honest per-window reason when the model is slower than
    90s. It fails only if the effective cap regresses to 30s or the reason
    misreports the window.
    """

    def test_real_codex_headless_probe_not_capped_at_30s(self):
        feature = probes.probe_headless_invocation(CODEX_BIN, "codex")
        self.assertIn(feature["state"], (FeatureState.ENFORCED, FeatureState.UNKNOWN))
        if feature["state"] == FeatureState.UNKNOWN:
            reason = str(feature.get("reason", ""))
            if "timed out" in reason:
                # The recorded window must be the codex default, not the old
                # uniform 30s cap.
                self.assertIn("timed out after 90s", reason)
        # P0-1 guard: the probe must invoke the documented codex shape.
        self.assertNotIn("--prompt", str(feature.get("method", "")))

    @unittest.skipUnless(CLAUDE_BIN, "real claude CLI not available on PATH")
    def test_real_claude_probe_keeps_its_own_window(self):
        """DSR-003: hosts are probed independently — claude's default stays 30s."""
        with mock.patch.object(probes.subprocess, "run", wraps=subprocess.run) as run_mock:
            feature = probes.probe_headless_invocation(CLAUDE_BIN, "claude")
        self.assertEqual(run_mock.call_args.kwargs["timeout"], 30)
        self.assertIn(feature["state"], (FeatureState.ENFORCED, FeatureState.UNKNOWN))


if __name__ == "__main__":
    unittest.main()
