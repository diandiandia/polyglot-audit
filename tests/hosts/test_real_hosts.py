"""Real-host tests (DSR-048).

These tests run only when a real claude / codex CLI is present on PATH
(detected with shutil.which). Otherwise they are SKIPPED — a skip is never
counted as a pass. They cover the minimal real invocation scenarios:
permission probing, config injection, and authentication failure.
"""

from __future__ import annotations
import os
import shutil
import subprocess
import unittest

from auditkit.hosts.capabilities import FeatureState
from auditkit.hosts.probes import (
    PROBE_LEVEL_HEADLESS,
    probe_cli_version,
    probe_headless_invocation,
)

CLAUDE_BIN = shutil.which("claude")
CODEX_BIN = shutil.which("codex")

# P0-1 regression guard: an argument-rejection or trust-gate message in a
# probe result means OUR code invoked the host CLI wrongly (invalid flag, or
# missing --skip-git-repo-check on a non-Git target) — that is a code defect
# and must fail the test, never pass as a legitimate host unknown.
# Missing binaries, auth failures and rate limits remain legitimate unknowns.
_FORBIDDEN_ARG_ERROR = "unexpected argument"
_FORBIDDEN_TRUST_GATE = "Not inside a trusted directory"


def _assert_no_cli_argument_rejection(feature, msg: str) -> None:
    """Fail when a probe result carries a caller-defect host rejection."""
    haystack = " | ".join(
        str(feature.get(field, "")) for field in ("method", "evidence", "reason")
    )
    # The recorded probe method itself must not contain the invalid flag.
    if "--prompt" in haystack:
        raise AssertionError(
            "probe invoked the host with the rejected '--prompt' flag "
            f"(code defect, P0-1): {haystack[:300]}"
        )
    for marker, why in (
        (_FORBIDDEN_ARG_ERROR, "invalid CLI argument"),
        (_FORBIDDEN_TRUST_GATE, "codex git trust gate (missing --skip-git-repo-check)"),
    ):
        if marker in haystack:
            raise AssertionError(
                f"{msg}: host rejected our invocation ({why}); this is a code "
                f"defect, not a legitimate host unknown: {haystack[:300]}"
            )


@unittest.skipUnless(CLAUDE_BIN, "real claude CLI not available on PATH")
class TestRealClaudeHost(unittest.TestCase):

    def test_version_probe(self):
        """DSR-048: real Claude CLI answers --version with evidence."""
        feature = probe_cli_version(CLAUDE_BIN, timeout=30)
        self.assertEqual(feature["state"], FeatureState.ENFORCED)
        self.assertIn("method", feature)
        self.assertTrue(feature["evidence"])

    def test_headless_probe(self):
        """DSR-002: real headless invocation; honest status either way.

        P0-1 guard: a CLI argument rejection in the result is a CODE defect
        (we invoked the host wrong) and fails here; capability gaps, auth and
        rate-limit failures stay legitimate UNKNOWNs.
        """
        feature = probe_headless_invocation(CLAUDE_BIN, "claude", timeout=120)
        # Only ENFORCED is a positive claim; any failure must stay UNKNOWN.
        self.assertIn(feature["state"], (FeatureState.ENFORCED, FeatureState.UNKNOWN))
        if feature["state"] == FeatureState.UNKNOWN:
            self.assertIn("reason", feature)
        _assert_no_cli_argument_rejection(
            feature,
            "claude headless probe transmitted an invalid CLI argument",
        )

    def test_auth_failure_classification(self):
        """DSR-048: authentication failure surfaces as a classified,
        non-retryable host failure. Strips credential env vars to force the
        unauthenticated path where the host honours them."""
        env = dict(os.environ)
        for key in list(env):
            if "ANTHROPIC" in key.upper() or "CLAUDE" in key.upper():
                env.pop(key, None)
        proc = subprocess.run(
            [CLAUDE_BIN, "--print", "reply with OK"],
            capture_output=True,
            text=True,
            timeout=120,
            env=env,
        )
        if proc.returncode == 0:
            # Host may be authenticated via stored credentials; record it.
            self.assertTrue(proc.stdout.strip())
        else:
            from auditkit.hosts.retry import classify_exit_failure

            category, retryable = classify_exit_failure(proc.stderr, proc.returncode)
            self.assertIn(category, ("auth_error", "rate_limit", "other", "timeout"))
            if category == "auth_error":
                self.assertFalse(retryable)

    def test_permission_probe_read_only(self):
        """DSR-048: minimal read-only call must not modify the working tree;
        the host must not gain unprobed write powers."""
        workdir = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".real_probe_tmp")
        os.makedirs(workdir, exist_ok=True)
        marker = os.path.join(workdir, "marker_should_not_exist.txt")
        if os.path.exists(marker):
            os.unlink(marker)
        try:
            proc = subprocess.run(
                [CLAUDE_BIN, "--print", "reply with OK"],
                capture_output=True,
                text=True,
                timeout=120,
                cwd=workdir,
            )
            # Regardless of host cooperation, a read-only prompt must not have
            # created files on its own.
            self.assertFalse(
                os.path.exists(marker),
                "host created an unrequested file; permission probe evidence",
            )
            self.assertIsInstance(proc.returncode, int)
        finally:
            shutil.rmtree(workdir, ignore_errors=True)


@unittest.skipUnless(CODEX_BIN, "real codex CLI not available on PATH")
class TestRealCodexHost(unittest.TestCase):

    def test_version_probe(self):
        """DSR-048: real Codex CLI answers --version with evidence."""
        feature = probe_cli_version(CODEX_BIN, timeout=30)
        self.assertEqual(feature["state"], FeatureState.ENFORCED)
        self.assertTrue(feature["evidence"])

    def test_headless_probe(self):
        """DSR-003: Codex probed independently with one real headless call.

        P0-1 guard: the real CLI takes the prompt as a POSITIONAL argument of
        `codex exec [OPTIONS] [PROMPT]`; an "unexpected argument" rejection in
        the evidence means our invocation is wrong and must fail. Unauthenticated
        or otherwise degraded hosts stay legitimate UNKNOWNs.
        """
        feature = probe_headless_invocation(CODEX_BIN, "codex", timeout=120)
        self.assertIn(feature["state"], (FeatureState.ENFORCED, FeatureState.UNKNOWN))
        if feature["state"] == FeatureState.UNKNOWN:
            self.assertIn("reason", feature)
        # The probe method must carry the prompt positionally after `exec`
        # together with the real --skip-git-repo-check option.
        self.assertIn(" exec ", f" {feature.get('method', '')} ")
        self.assertIn("--skip-git-repo-check", feature.get("method", ""))
        _assert_no_cli_argument_rejection(
            feature,
            "codex headless probe transmitted an invalid CLI argument",
        )

    def test_auth_failure_classification(self):
        """DSR-048: Codex auth failure classification on a real exit."""
        env = dict(os.environ)
        for key in list(env):
            if "OPENAI" in key.upper() or "CODEX" in key.upper():
                env.pop(key, None)
        proc = subprocess.run(
            [CODEX_BIN, "exec", "reply with OK"],
            capture_output=True,
            text=True,
            timeout=120,
            env=env,
        )
        if proc.returncode == 0:
            self.assertTrue(proc.stdout.strip())
        else:
            # P0-1 guard: an argument or trust-gate rejection is our defect,
            # not an auth outcome.
            self.assertNotIn(_FORBIDDEN_ARG_ERROR, proc.stderr)
            self.assertNotIn(_FORBIDDEN_TRUST_GATE, proc.stderr)
            from auditkit.hosts.retry import classify_exit_failure

            category, retryable = classify_exit_failure(proc.stderr, proc.returncode)
            self.assertIn(category, ("auth_error", "rate_limit", "other", "timeout"))


if __name__ == "__main__":
    unittest.main()
