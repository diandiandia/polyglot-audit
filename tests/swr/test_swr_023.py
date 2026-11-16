"""SWR-023 acceptance tests: capability matrix probing for accepted host versions.

验收准则原文 (docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2):
| SWR-023 | SR-023 -> SD-01、SD-09 | P0 / — | 探测并实现已验收宿主版本的认证、结构化输出、工具和
  配置加载适配；真实 CLI 加目标注入夹具验证，未知不能静默降级。 |

上游系统需求 (SYSTEM_REQUIREMENTS.md §2):
| SR-023 | 适配 Claude Code CLI 和 Codex CLI 的已验收版本，明确能力矩阵、认证、结构化输出及
  不加载目标指令的条件。验收：真实 CLI 集成测试和不可信目标指令反例通过，不能做到的能力标为
  不支持；不得自动降低隔离级别。 |

绑定实现: hosts/doctor.py (DSR-001/002/003/004), hosts/probes.py（分层探测,
Claude/Codex 独立探测互不推断）。
"""

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

_SKILL_SCRIPTS = Path(__file__).resolve().parents[2] / "skill" / "scripts"
_HOSTS_TESTS = Path(__file__).resolve().parents[1] / "hosts"
for p in (str(_SKILL_SCRIPTS), str(_HOSTS_TESTS)):
    if p not in sys.path:
        sys.path.insert(0, p)

import fake_hosts  # noqa: E402
from auditkit.hosts.capabilities import FeatureState  # noqa: E402
from auditkit.hosts.doctor import Doctor  # noqa: E402
from auditkit.hosts.probes import probe_mcp_stdio_handshake  # noqa: E402

ENFORCED, UNKNOWN, NOT_ENFORCED = (
    FeatureState.ENFORCED,
    FeatureState.UNKNOWN,
    FeatureState.NOT_ENFORCED,
)

# Distinct version fingerprints so cross-host contamination is detectable.
CLAUDE_VERSION = "fake-claude 1.2.3 (auditkit-test)"
CODEX_VERSION = "fake-codex-cli 9.8.7 (auditkit-test)"


class TestSWR023(unittest.TestCase):
    """能力矩阵逐 feature 带 method 证据；Claude/Codex 独立探测互不推断；
    未知不静默降级；本机真实 CLI 保守探测通过。"""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="swr-023-"))
        self.empty_path = tempfile.mkdtemp(prefix="swr-023-empty-")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        shutil.rmtree(self.empty_path, ignore_errors=True)

    # ------------------------------------------------- 能力矩阵带证据
    def test_capability_matrix_every_feature_carries_method_and_evidence(self):
        """DSR-001: 能力报告的每个 feature 都带探测 method；enforced 必附 evidence；
        unknown/not_enforced 必附 reason——没有无证据的断言。"""
        caps = Doctor().probe(probe_cli=False)
        self.assertGreaterEqual(len(caps), 4)

        checked = 0
        for cap in caps:
            self.assertIn("adapter", cap)
            self.assertIn("adapter_version", cap)
            self.assertIn("features", cap)
            for name, feature in cap["features"].items():
                self.assertIn("state", feature, f"{cap['adapter']}.{name} missing state")
                self.assertIn("method", feature, f"{cap['adapter']}.{name} missing method")
                self.assertTrue(feature["method"].strip(), f"{cap['adapter']}.{name} empty method")
                state = feature["state"]
                if state == ENFORCED:
                    self.assertTrue(
                        feature.get("evidence"),
                        f"enforced claim without evidence: {cap['adapter']}.{name}",
                    )
                if state in (UNKNOWN, NOT_ENFORCED):
                    self.assertTrue(
                        feature.get("reason"),
                        f"{state} feature without a reason: {cap['adapter']}.{name}",
                    )
                checked += 1
        self.assertGreaterEqual(checked, 20, "capability matrix unexpectedly small")

        # Core claims carry concrete evidence: stdlib enumeration and SQLite.
        core = next(c for c in caps if c["adapter"] == "python_core")
        self.assertEqual(core["features"]["stdlib_offline"]["state"], ENFORCED)
        self.assertIn("sqlite3", core["features"]["stdlib_offline"]["evidence"])
        self.assertIn("sqlite3.sqlite_version", core["features"]["sqlite_wal"]["method"])

    # --------------------------------- Claude / Codex 独立探测互不推断
    def test_claude_and_codex_probed_independently_no_cross_inference(self):
        """DSR-003: 只装其一时报 not_installed；两者都装且版本指纹不同时，
        各自的版本证据只能来自自身（Claude 的结果不得推断给 Codex，反之亦然）。"""
        # Scenario A: only a claude fake exists -> codex must be not_installed.
        self.bin_a = str(self.temp_dir / "a")
        os.mkdir(self.bin_a)
        fake_hosts.create_fake_host(self.bin_a, "claude", version_output=CLAUDE_VERSION)
        with mock.patch.dict(os.environ, {"PATH": self.bin_a}):
            caps = Doctor().probe(probe_cli=False)
        by_adapter = {c["adapter"]: c for c in caps}
        self.assertEqual(by_adapter["claude_cli"]["adapter_version"], CLAUDE_VERSION)
        codex = by_adapter["codex_cli"]
        self.assertEqual(codex["adapter_version"], "not_installed")
        installed = codex["features"]["installed"]
        self.assertEqual(installed["state"], NOT_ENFORCED)
        self.assertEqual(installed["method"], "shutil.which('codex') against PATH")
        self.assertIn("not found in PATH", installed["reason"])
        version = codex["features"]["version"]
        self.assertEqual(version["state"], UNKNOWN)
        self.assertIn("not installed", version["reason"])

        # Scenario B: only a codex fake exists -> claude must be not_installed
        # with its OWN independent evidence (no inference from Scenario A/B).
        self.bin_b = str(self.temp_dir / "b")
        os.mkdir(self.bin_b)
        fake_hosts.create_fake_host(self.bin_b, "codex", version_output=CODEX_VERSION)
        with mock.patch.dict(os.environ, {"PATH": self.bin_b}):
            caps = Doctor().probe(probe_cli=False)
        by_adapter = {c["adapter"]: c for c in caps}
        claude = by_adapter["claude_cli"]
        self.assertEqual(claude["adapter_version"], "not_installed")
        self.assertEqual(claude["features"]["installed"]["state"], NOT_ENFORCED)
        self.assertEqual(by_adapter["codex_cli"]["adapter_version"], CODEX_VERSION)

        # Scenario C: both installed with distinct version fingerprints; each
        # adapter's evidence must be exactly its own CLI's output.
        self.bin_c = str(self.temp_dir / "c")
        os.mkdir(self.bin_c)
        fake_hosts.create_fake_host(self.bin_c, "claude", version_output=CLAUDE_VERSION)
        fake_hosts.create_fake_host(self.bin_c, "codex", version_output=CODEX_VERSION)
        with mock.patch.dict(os.environ, {"PATH": self.bin_c}):
            caps = Doctor().probe(probe_cli=False)
        by_adapter = {c["adapter"]: c for c in caps}
        claude_v = by_adapter["claude_cli"]["features"]["version"]
        codex_v = by_adapter["codex_cli"]["features"]["version"]
        self.assertEqual(claude_v["state"], ENFORCED)
        self.assertEqual(codex_v["state"], ENFORCED)
        self.assertEqual(claude_v["evidence"], CLAUDE_VERSION)
        self.assertEqual(codex_v["evidence"], CODEX_VERSION)
        self.assertNotEqual(claude_v["evidence"], codex_v["evidence"])
        # Independent probing left separate method records (--version per CLI).
        self.assertIn("claude", claude_v["method"])
        self.assertIn("codex", codex_v["method"])

    # ------------------------------------- 未知不得静默降级/升级
    def test_unknown_never_silently_promoted_or_degraded(self):
        """未执行的探针（反例/结构化输出/token 硬限额）保持 UNKNOWN 并说明探测计划；
        全矩阵不存在无证据的 enforced；未验证能力不得标 enforced，也不得把
        未测项悄悄写成 not_enforced 了事。"""
        self.bin = str(self.temp_dir / "bin")
        os.mkdir(self.bin)
        fake_hosts.create_fake_host(self.bin, "claude", version_output=CLAUDE_VERSION)
        fake_hosts.create_fake_host(self.bin, "codex", version_output=CODEX_VERSION)
        with mock.patch.dict(os.environ, {"PATH": self.bin}):
            caps = Doctor().probe(probe_cli=False)

        by_adapter = {c["adapter"]: c for c in caps}
        never_claimed_without_probe = (
            "structured_output",
            "hard_token_budget",
            "filesystem_isolation",
            "network_isolation",
            "execution_isolation",
        )
        for adapter in ("claude_cli", "codex_cli"):
            for name in never_claimed_without_probe:
                feature = by_adapter[adapter]["features"].get(name)
                if feature is None:
                    continue
                self.assertEqual(
                    feature["state"], UNKNOWN,
                    f"{adapter}.{name} must stay unverified at conservative level",
                )
                self.assertNotIn("evidence", feature, f"{adapter}.{name} fabricated evidence")
                self.assertIn("method", feature)

        # A NOT_ENFORCED claim must carry its review evidence too: MCP is a
        # transport adapter, never an OS sandbox (DSR-004).
        in_session = by_adapter["in_session"]["features"]
        self.assertEqual(in_session["mcp_os_sandbox"]["state"], NOT_ENFORCED)
        self.assertTrue(in_session["mcp_os_sandbox"]["reason"])
        # And the unexecuted MCP handshake stays UNKNOWN with its probe plan.
        self.assertEqual(in_session["mcp_stdio_transport"]["state"], UNKNOWN)
        self.assertIn("handshake not executed", in_session["mcp_stdio_transport"]["reason"])

        # Conversely: a real measured handshake IS promoted — with evidence.
        server = fake_hosts.create_mcp_stdio_fake_server(str(self.temp_dir))
        handshake = probe_mcp_stdio_handshake([sys.executable, server])
        self.assertEqual(handshake["state"], ENFORCED)
        self.assertTrue(handshake["evidence"])
        self.assertIn("initialize", handshake["method"])

    def test_probe_failure_recorded_not_swallowed(self):
        """探测失败（版本退出码非零 / headless 无输出）如实记录 UNKNOWN + 原因，
        绝不吞错升级为 enforced。"""
        self.bin = str(self.temp_dir / "bin")
        os.mkdir(self.bin)
        fake_hosts.create_fake_host(
            self.bin, "claude", version_exit=3, version_output="",
            headless_exit=1, headless_stdout="",
        )
        with mock.patch.dict(os.environ, {"PATH": self.bin}):
            report = Doctor().probe(probe_cli=True)  # upgrades to headless level

        claude = next(c for c in report if c["adapter"] == "claude_cli")
        version = claude["features"]["version"]
        self.assertEqual(version["state"], UNKNOWN)
        self.assertIn("3", version["reason"])
        self.assertIn("--version", version["method"])
        headless = claude["features"]["headless_cli"]
        self.assertEqual(headless["state"], UNKNOWN)
        self.assertTrue(headless["reason"])
        # A failed headless probe must not unlock any downstream claim.
        for name in ("structured_output", "hard_token_budget"):
            self.assertEqual(claude["features"][name]["state"], UNKNOWN)

    # ----------------------------------------- 真实 CLI 存在时的真实探测
    @unittest.skipUnless(
        shutil.which("claude") and shutil.which("codex"),
        "real claude/codex CLI not on PATH",
    )
    def test_real_cli_probe_reports_installed_versions(self):
        """本机装有真实 claude/codex：保守探测（仅 --version，不发起 headless 调用，
        非破坏性）必须给出各自真实的版本证据；未实测能力保持 UNKNOWN。"""
        caps = Doctor().probe(probe_cli=False)
        by_adapter = {c["adapter"]: c for c in caps}

        for adapter, binary in (("claude_cli", "claude"), ("codex_cli", "codex")):
            cap = by_adapter[adapter]
            installed = cap["features"]["installed"]
            self.assertEqual(installed["state"], ENFORCED, f"{binary} is installed")
            self.assertEqual(installed["evidence"], shutil.which(binary))
            version = cap["features"]["version"]
            self.assertEqual(version["state"], ENFORCED)
            self.assertIn("--version", version["method"])
            self.assertGreaterEqual(len(version["evidence"]), 1)
            self.assertTrue(any(ch.isdigit() for ch in version["evidence"]),
                            f"{binary} version evidence must carry a version string")
            # Conservative level: counterexample layers were NOT executed, so
            # isolation claims stay UNKNOWN — the real probe does not silently
            # downgrade or upgrade anything.
            for name in ("filesystem_isolation", "network_isolation", "execution_isolation",
                         "hard_token_budget", "structured_output"):
                feature = cap["features"].get(name)
                if feature is not None:
                    self.assertEqual(feature["state"], UNKNOWN, f"{adapter}.{name}")
                    self.assertIn("method", feature)


if __name__ == "__main__":
    unittest.main()
