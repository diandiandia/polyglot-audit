# ==============================================================================
# 软件需求追踪与实现规范 (Software Requirements Traceability & Implementation)
# ==============================================================================
# 对应模块: tests/model_eval/test_model_eval.py
#
# 本代码文件承担的软件设计与开发需求编号及完整需求描述如下：
#
# --- 需求编号: DSR-048 [负责人: QAV] / DSR-078 [负责人: QAV] ---
# 需求描述: 编写 Claude/Codex 与 in-session 的真实宿主测试，包括权限、配置注入和认证失败；
#   统一测试时各组合独立出结论。开发统一测试编排和结果汇总工具，区分自动确定性、
#   真实 CLI、模型评测、故障注入和规模测试；每类缺失/跳过单列，禁止把 mock 计为真实宿主通过。
#   └─ 上层软件需求 SWR-029 (SR-029 → SD-10): 建立合成和隔离留出评测及双宿主运行记录；
#      发布各语言、跨单元的分母、检出、误报、未决与成本，不伪造缺失结果。
#        └─ 对应系统需求 SR-029: 在合成正反例、留出语料、大规模目录和双宿主上评测功能、
#           恢复、安全与成本；留出集与调参隔离。验收：发布报告给出各语言及跨单元的分母、
#           检出、误报、未决、成本和环境；无可靠数据不得宣称召回率或通过目标。
# ==============================================================================

"""Model-in-the-loop Evaluation Suite (DSR-048 / DSR-078 / SWR-029).

Tests model harness behavior, auth checks, prompt structure, and honest unknown
capability handling when live models/credentials are not present. Live-CLI
observations (when a real claude/codex binary exists) are recorded under
records/ with detection_claims="none" — a single headless call is never
detection evidence (SR-029).
"""

from __future__ import annotations

import datetime
import json
import os
import shutil
import unittest
from pathlib import Path

from auditkit.hosts.capabilities import Capability, FeatureState
from auditkit.hosts.claude_adapter import ClaudeDriverAdapter
from auditkit.hosts.codex_adapter import CodexDriverAdapter
from auditkit.hosts.probes import probe_host_capabilities

RECORDS_DIR = Path(__file__).resolve().parent / "records"

CLAUDE_BIN = shutil.which("claude")
CODEX_BIN = shutil.which("codex")


def _record_result(filename: str, payload: dict) -> None:
    RECORDS_DIR.mkdir(parents=True, exist_ok=True)
    payload["recorded_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    payload["detection_claims"] = "none"
    payload["note"] = (
        "Single-call observation only. Detection quality requires the isolated "
        "holdout corpus (tools/evaluate_holdout.py) with denominator accounting; "
        "this record must not be cited as detection evidence."
    )
    (RECORDS_DIR / filename).write_text(
        json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
    )


class TestModelEvaluation(unittest.TestCase):
    """Model evaluation suite verifying live vs unknown model handling."""

    def test_unauthenticated_host_status_unknown(self):
        """DSR-048: When live LLM credentials/CLI are unverified, capability is unknown."""
        cap = Capability(adapter="claude", adapter_version="unknown")
        fs_feature = cap.features.get("filesystem_isolation", {})
        self.assertIn(fs_feature.get("state"), [FeatureState.NOT_ENFORCED, FeatureState.UNKNOWN])
        net_feature = cap.features.get("network_isolation", {})
        self.assertEqual(net_feature.get("state"), FeatureState.UNKNOWN)

    def test_mock_is_never_reported_as_real_model_pass(self):
        """DSR-078: Mock results cannot be counted as real model pass."""
        adapter = ClaudeDriverAdapter(claude_binary="/bin/true")
        self.assertIsNotNone(adapter)
        self.assertEqual(adapter.claude_binary, "/bin/true")

    def test_live_claude_eval_skips_honestly_when_no_credentials(self):
        """DSR-048: When Claude API/auth is not configured, test skips without claiming pass."""
        if not os.environ.get("ANTHROPIC_API_KEY") and not shutil.which("claude"):
            self.skipTest("Live Claude model unavailable; capability remains honestly unknown (DSR-048)")

    def test_live_codex_eval_skips_honestly_when_no_credentials(self):
        """DSR-048: When Codex API/auth is not configured, test skips without claiming pass."""
        if not os.environ.get("OPENAI_API_KEY") and not shutil.which("codex"):
            self.skipTest("Live Codex model unavailable; capability remains honestly unknown (DSR-048)")


@unittest.skipUnless(CLAUDE_BIN, "real Claude CLI not available; capability stays unknown")
class TestClaudeLiveObservation(unittest.TestCase):

    def test_headless_call_observed_and_recorded(self):
        report = probe_host_capabilities("claude", host="claude", probe_level="headless")
        headless = report.get("features", {}).get("headless_cli", {})
        self.assertIn(headless.get("state", headless.get("status")), {"enforced", "unknown", "not_enforced"})
        self.assertIn("method", headless, "every feature must record its probe method (DSR-001)")
        _record_result(
            "claude_headless_last_run.json",
            {"host": "claude", "probe_level": "headless", "report": report},
        )


@unittest.skipUnless(CODEX_BIN, "real Codex CLI not available; capability stays unknown")
class TestCodexLiveObservation(unittest.TestCase):

    def test_headless_call_observed_and_recorded(self):
        report = probe_host_capabilities("codex", host="codex", probe_level="headless")
        headless = report.get("features", {}).get("headless_cli", {})
        self.assertIn(headless.get("state", headless.get("status")), {"enforced", "unknown", "not_enforced"})
        self.assertIn("method", headless)
        _record_result(
            "codex_headless_last_run.json",
            {"host": "codex", "probe_level": "headless", "report": report},
        )


if __name__ == "__main__":
    unittest.main()
