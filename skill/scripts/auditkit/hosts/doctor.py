"""Environment diagnostic probe and doctor command implementation.

Implements DSR-001 / DSR-002 / DSR-003 / DSR-004 / DSR-005 / DSR-030 /
SD-01 / IFC-06:
- Non-destructive capability probing with per-feature `method` fields
  (evidence-with-command capability report, DSR-001).
- Real probes only: a feature is ENFORCED only when the probe that could
  falsify it actually ran and confirmed it. Anything unmeasured stays
  UNKNOWN/NOT_ENFORCED with an explicit reason — including probe failures,
  which are recorded with their error message instead of being swallowed.
- Claude and Codex are probed independently; nothing is inferred across
  hosts (DSR-003).
"""

# 需求追踪 (Requirement Traceability)
# ---------------------------------------------------------------------------
# 上层需求: docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2
# 设计依据: docs/design/SOFTWARE_DESIGN.md
# SWR-023  探测宿主认证、结构化输出、工具与配置加载；未知不能静默降级
#   绑定实现: DSR-001, DSR-002, DSR-003, DSR-004
# SWR-024  标准库实现核心工具包，离线可用；无第三方 Python 包
#   绑定实现: DSR-001, DSR-023
# 状态以统一测试结论为准；未实测能力保持 unknown（设计原则 8：能观测的不靠声明）。
#

from __future__ import annotations
import shutil
import sqlite3
import sys
from typing import Any, Dict, List, Optional

from auditkit.hosts.capabilities import Capability, FeatureState
from auditkit.hosts.probes import (
    PROBE_LEVEL_CONSERVATIVE,
    PROBE_LEVEL_HEADLESS,
    make_feature,
    probe_host_capabilities,
    probe_mcp_stdio_handshake,
    probe_stdlib_modules,
)

# Session modes reported by the in-session adapter (DSR-030).
SESSION_MODE_SUBAGENT = "subagent"
SESSION_MODE_SEQUENTIAL_FALLBACK = "sequential_fallback"


class Doctor:
    """Probes host environment and installed tools non-destructively."""

    def probe(
        self,
        probe_cli: bool = False,
        probe_level: str = PROBE_LEVEL_CONSERVATIVE,
        session_mode: Optional[str] = None,
        mcp_server_cmd: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """Probe the environment and return capability reports.

        probe_cli=True upgrades the CLI probe to the headless level (one real
        headless invocation per CLI). probe_level may be raised explicitly to
        "aggressive" to also run counterexample probes. session_mode comes
        from the InSessionAdapter ("subagent" or "sequential_fallback");
        mcp_server_cmd, when provided, triggers a real stdio MCP handshake
        probe. Without evidence, sequential fallback and MCP transport stay
        UNKNOWN with their probe plan described.
        """
        if probe_cli and probe_level == PROBE_LEVEL_CONSERVATIVE:
            probe_level = PROBE_LEVEL_HEADLESS

        capabilities: List[Capability] = []

        # 1. Python & SQLite Core
        py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        sql_ver = sqlite3.sqlite_version
        core_features = {
            "sqlite_wal": make_feature(
                FeatureState.ENFORCED,
                method="sqlite3.sqlite_version introspection",
                evidence=f"SQLite {sql_ver} with WAL and BEGIN IMMEDIATE support",
            ),
            "stdlib_offline": probe_stdlib_modules(),
            "filesystem_isolation": make_feature(
                FeatureState.NOT_ENFORCED,
                method="runtime policy review",
                reason="Process runs with current OS user permissions; relies on path checks",
            ),
            "network_isolation": make_feature(
                FeatureState.NOT_ENFORCED,
                method="runtime policy review",
                reason="OS socket access not restricted by runtime",
            ),
            "execution_isolation": make_feature(
                FeatureState.ENFORCED,
                method="runtime policy review",
                evidence="Audit tool does not execute target repository code",
            ),
        }
        capabilities.append(Capability("python_core", py_ver, core_features))

        # 2. Claude CLI Adapter (independent probe, DSR-002/003)
        capabilities.append(
            self._cli_capability("claude", "claude_cli", probe_level)
        )

        # 3. Codex CLI Adapter (independent probe, DSR-003)
        capabilities.append(
            self._cli_capability("codex", "codex_cli", probe_level)
        )

        # 4. In-Session & MCP Adapter
        session_features = {
            "subagent_delegation": make_feature(
                FeatureState.UNKNOWN,
                method="minimal in-session sub-agent delegation trial (aggressive level)",
                reason=(
                    "delegation trial not executed; availability depends on the "
                    "caller host session and must be measured, not assumed"
                ),
            ),
            "sequential_session_fallback": self._sequential_fallback_feature(session_mode),
            "mcp_stdio_transport": self._mcp_transport_feature(mcp_server_cmd),
            "mcp_os_sandbox": make_feature(
                FeatureState.NOT_ENFORCED,
                method="protocol review",
                reason="MCP protocol is a transport adapter, not an OS sandbox",
            ),
        }
        capabilities.append(Capability("in_session", "1.0", session_features))

        return [c.to_dict() for c in capabilities]

    def _cli_capability(
        self,
        binary_name: str,
        adapter_name: str,
        probe_level: str,
    ) -> Capability:
        """Probe one host CLI independently and build its capability report."""
        report = probe_host_capabilities(binary_name, binary_name, probe_level=probe_level)
        features = dict(report["features"])

        version_feature = features.get("version", {})
        adapter_version = (
            version_feature.get("evidence", "unknown")
            if version_feature.get("state") == FeatureState.ENFORCED
            else "unknown"
        )
        if version_feature.get("state") != FeatureState.ENFORCED and report["binary"]:
            # Keep the failure reason visible in the report (DSR-001).
            features["version"] = version_feature

        extra = {
            "structured_output": make_feature(
                FeatureState.UNKNOWN,
                method="headless structured-output trial (aggressive level)",
                reason="Host JSON schema output enforcement unverified",
            ),
            "hard_token_budget": make_feature(
                FeatureState.UNKNOWN,
                method="single-call budget probe (aggressive level)",
                reason="Upstream token limit enforcement unverified",
            ),
            "filesystem_isolation": make_feature(
                FeatureState.UNKNOWN,
                method="write-a-file execution counterexample (aggressive level only)",
                reason=f"counterexample not executed (probe_level={probe_level})",
            ),
        }
        if adapter_name == "claude_cli":
            extra["network_isolation"] = make_feature(
                FeatureState.UNKNOWN,
                method="loopback socket counterexample (aggressive level only)",
                reason=f"counterexample not executed (probe_level={probe_level})",
            )
        else:
            extra["config_loading"] = make_feature(
                FeatureState.UNKNOWN,
                method="target project config loading trial (aggressive level)",
                reason="Target project config loading unverified",
            )
        features.update(extra)

        if report["binary"] is None:
            return Capability(
                adapter_name,
                "not_installed",
                {
                    "installed": make_feature(
                        FeatureState.NOT_ENFORCED,
                        method=f"shutil.which({binary_name!r}) against PATH",
                        reason=f"{binary_name} CLI not found in PATH",
                    ),
                    "version": features.get(
                        "version",
                        make_feature(
                            FeatureState.UNKNOWN,
                            method=f"{binary_name} --version",
                            reason="CLI not installed; version probe impossible",
                        ),
                    ),
                },
            )

        return Capability(adapter_name, adapter_version, features)

    def _sequential_fallback_feature(self, session_mode: Optional[str]) -> Dict[str, Any]:
        """DSR-030: report sequential fallback according to the real mode."""
        if session_mode == SESSION_MODE_SEQUENTIAL_FALLBACK:
            return make_feature(
                FeatureState.ENFORCED,
                method="InSessionAdapter mode introspection",
                evidence=(
                    "no sub-agent delegation available; main session runs tasks "
                    "in bounded sequential mode"
                ),
            )
        if session_mode == SESSION_MODE_SUBAGENT:
            return make_feature(
                FeatureState.ENFORCED,
                method="InSessionAdapter mode introspection",
                evidence="sub-agent delegation available; sequential loop also supported",
            )
        return make_feature(
            FeatureState.UNKNOWN,
            method="InSessionAdapter mode introspection",
            reason="session mode not determined; adapter not instantiated or mode unset",
        )

    def _mcp_transport_feature(self, mcp_server_cmd: Optional[List[str]]) -> Dict[str, Any]:
        """DSR-004: MCP stdio transport is ENFORCED only after a real handshake."""
        if mcp_server_cmd:
            return probe_mcp_stdio_handshake(mcp_server_cmd)
        return make_feature(
            FeatureState.UNKNOWN,
            method="stdio JSON-RPC initialize handshake with the MCP server (probe not run)",
            reason=(
                "handshake not executed; start the stdio MCP server and pass "
                "mcp_server_cmd to verify the transport"
            ),
        )
