"""Standard MCP protocol tests (DSR-031 / SR-022 / SR-023 / DDS-01 / IFC-04).

The MCP transport must implement the standard JSON-RPC 2.0 method surface so a
standard MCP client can actually complete the handshake (initialize ->
notifications/initialized -> tools/list -> tools/call) — the previous custom
transport (method IS the tool name) was unreachable by standard clients.

Covered here:
- MCPServer.handle_protocol in-process:
  * initialize: protocolVersion echo (or default), capabilities.tools,
    serverInfo {name, version from skill/VERSION}.
  * notifications/initialized (and unknown notifications): empty ack, never
    an error.
  * tools/list: exactly the four audit tools, each with name/description and
    a concise inputSchema matching handle_call's actual arguments.
  * tools/call: result wrapped as {content:[{type:"text",text:JSON}],isError};
    tool-level errors (unknown tool / unknown run) become isError=true
    content instead of crashing the transport.
  * Legacy compatibility: a slash-free method naming one of the four tools
    keeps the historic direct-dispatch semantics (raw tool result).
  * Unknown method -> MCPMethodNotFoundError (JSON-RPC -32601).
- End-to-end over the real stdio loop (audit.py mcp --run-dir as a
  subprocess, isolated interpreter): a standard client session plus the
  legacy direct call; id-less notifications get NO response line, unknown
  methods get -32601, malformed JSON gets -32700.
"""

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SKILL_DIR = REPO_ROOT / "skill"
AUDIT_PY = SKILL_DIR / "scripts" / "audit.py"

from auditkit.app.service import AuditAppService
from auditkit.hosts.mcp_adapter import (
    MCP_DEFAULT_PROTOCOL_VERSION,
    MCP_SERVER_NAME,
    MCP_TOOL_DEFINITIONS,
    MCPServer,
    MCPMethodNotFoundError,
    read_skill_version,
)
from auditkit.ledger.db import get_db_connection, init_database


def _seed_run(run_dir: Path) -> str:
    """Create a real run directory (events.db + active run row).

    Same construction pattern as tests/hosts/test_hosts.py: a real run
    directory with a real ledger so MCPServer/AuditAppService execute the
    genuine status path. Protocol coverage deliberately does not ride on
    AuditAppService.prepare (its task_spec contract is being tightened in a
    parallel workstream); every assertion here still goes through the real
    service against the real run directory — no mocks.
    """
    run_dir.mkdir(parents=True, exist_ok=True)
    init_database(run_dir / "events.db")
    conn = get_db_connection(run_dir / "events.db")
    run_id = "run-" + run_dir.name
    conn.execute(
        """
        INSERT INTO runs (run_id, snapshot_id, state, schema_version, skill_version, knowledge_version, config_ref, revision, created_at, updated_at)
        VALUES (?, 'snp-01', 'active', '1.0', '0.1.0', '1.0', 'cfg', 0, '2026-11-14T00:00:00Z', '2026-11-14T00:00:00Z')
        """,
        (run_id,),
    )
    conn.commit()
    conn.close()
    return run_id


class TestMCPServerProtocol(unittest.TestCase):
    """handle_protocol method layer over the unchanged handle_call."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="mcp-protocol-")
        cls.run_dir = Path(cls.tmp) / "run_proto"
        cls.run_id = _seed_run(cls.run_dir)
        cls.app = AuditAppService(SKILL_DIR)
        cls.server = MCPServer(cls.run_dir, cls.app)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    # -- initialize ---------------------------------------------------------

    def test_initialize_echoes_client_protocol_version(self):
        res = self.server.handle_protocol(
            "initialize", {"protocolVersion": "2025-06-18"}
        )
        self.assertEqual(res["protocolVersion"], "2025-06-18")
        self.assertEqual(res["capabilities"], {"tools": {}})
        self.assertEqual(res["serverInfo"]["name"], MCP_SERVER_NAME)
        self.assertEqual(res["serverInfo"]["version"], read_skill_version())

    def test_initialize_defaults_protocol_version(self):
        res = self.server.handle_protocol("initialize", {})
        self.assertEqual(res["protocolVersion"], MCP_DEFAULT_PROTOCOL_VERSION)
        self.assertEqual(res["serverInfo"]["version"], read_skill_version())

    def test_skill_version_read_from_version_file(self):
        version_file = SKILL_DIR / "VERSION"
        self.assertEqual(read_skill_version(), version_file.read_text(encoding="utf-8").strip())

    # -- notifications ------------------------------------------------------

    def test_notifications_initialized_is_an_empty_ack(self):
        self.assertEqual(self.server.handle_protocol("notifications/initialized", {}), {})

    def test_unknown_notifications_ack_silently_never_error(self):
        self.assertEqual(self.server.handle_protocol("notifications/other", {}), {})

    # -- tools/list ---------------------------------------------------------

    def test_tools_list_exposes_exactly_the_four_audit_tools(self):
        res = self.server.handle_protocol("tools/list", {})
        tools = res["tools"]
        self.assertEqual(
            [t["name"] for t in tools],
            ["next", "submit", "status", "read_artifact"],
        )
        for tool in tools:
            self.assertIsInstance(tool["description"], str)
            self.assertTrue(tool["description"].strip())
            schema = tool["inputSchema"]
            self.assertEqual(schema["type"], "object")
            self.assertIn("run_id", schema["properties"])
            self.assertIn("run_id", schema["required"])

    def test_tool_input_schemas_match_handle_call_arguments(self):
        schemas = {t["name"]: t["inputSchema"] for t in MCP_TOOL_DEFINITIONS}
        self.assertEqual(
            set(schemas["next"]["properties"]),
            {"run_id", "batch_size"},
        )
        self.assertEqual(
            set(schemas["submit"]["properties"]),
            {"run_id", "task_id", "attempt_id", "generation", "claim_token", "result"},
        )
        self.assertEqual(schemas["submit"]["properties"]["result"]["type"], "object")
        self.assertEqual(
            set(schemas["status"]["properties"]), {"run_id"}
        )
        self.assertEqual(
            set(schemas["read_artifact"]["properties"]),
            {"run_id", "relative_path"},
        )

    # -- tools/call ---------------------------------------------------------

    def test_tools_call_status_succeeds_on_a_real_run(self):
        res = self.server.handle_protocol(
            "tools/call",
            {"name": "status", "arguments": {"run_id": self.run_id}},
        )
        self.assertFalse(res["isError"])
        self.assertEqual(len(res["content"]), 1)
        self.assertEqual(res["content"][0]["type"], "text")
        payload = json.loads(res["content"][0]["text"])
        self.assertEqual(payload["run_id"], self.run_id)
        self.assertIn("state", payload)

    def test_tools_call_unknown_tool_is_error_not_crash(self):
        res = self.server.handle_protocol(
            "tools/call", {"name": "no_such_tool", "arguments": {}}
        )
        self.assertTrue(res["isError"])
        text = json.loads(res["content"][0]["text"])
        self.assertEqual(text["code"], "INVALID_INPUT")
        self.assertIn("no_such_tool", text["message"])

    def test_tools_call_unknown_run_is_error_not_crash(self):
        res = self.server.handle_protocol(
            "tools/call",
            {"name": "status", "arguments": {"run_id": "ghost-run"}},
        )
        self.assertTrue(res["isError"])
        self.assertEqual(json.loads(res["content"][0]["text"])["code"], "INVALID_INPUT")

    def test_tools_call_missing_arguments_is_error_not_crash(self):
        res = self.server.handle_protocol("tools/call", {"name": "status"})
        self.assertTrue(res["isError"])

    # -- legacy direct transport ---------------------------------------------

    def test_legacy_method_status_returns_raw_tool_result(self):
        res = self.server.handle_protocol("status", {"run_id": self.run_id})
        # Raw service payload, NOT wrapped as MCP tool content.
        self.assertEqual(res["run_id"], self.run_id)
        self.assertNotIn("content", res)
        self.assertNotIn("isError", res)

    def test_legacy_method_next_is_routed_to_the_tool(self):
        res = self.server.handle_protocol(
            "next", {"run_id": self.run_id, "batch_size": 1}
        )
        self.assertIn("claims", res)

    # -- unknown methods ------------------------------------------------------

    def test_unknown_method_raises_jsonrpc_32601(self):
        with self.assertRaises(MCPMethodNotFoundError) as ctx:
            self.server.handle_protocol("some/other/method", {})
        self.assertEqual(ctx.exception.JSONRPC_CODE, -32601)

    def test_non_string_method_raises_jsonrpc_32601(self):
        with self.assertRaises(MCPMethodNotFoundError):
            self.server.handle_protocol(None, {})


class TestMCPStdioProtocol(unittest.TestCase):
    """End-to-end: standard client session over audit.py mcp stdio (subprocess)."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="mcp-stdio-")
        cls.run_dir = Path(cls.tmp) / "run_stdio"
        cls.run_id = _seed_run(cls.run_dir)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _send(self, requests):
        """Pipe raw JSON-RPC lines through audit.py mcp and return responses."""
        payload = "\n".join(requests) + "\n"
        proc = subprocess.run(
            [sys.executable, "-I", str(AUDIT_PY), "mcp", "--run-dir", str(self.run_dir)],
            input=payload,
            capture_output=True,
            text=True,
            timeout=120,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
        return proc, [json.loads(ln) for ln in lines]

    def test_standard_client_session_over_stdio(self):
        requests = [
            json.dumps({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-06-18"},
            }),
            # Standard post-initialize notification: carries NO id and must
            # produce NO response line on the stream.
            json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
            json.dumps({
                "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": {"name": "status", "arguments": {"run_id": self.run_id}},
            }),
            # Legacy custom transport stays compatible on the same stream.
            json.dumps({
                "jsonrpc": "2.0", "id": 4, "method": "status",
                "params": {"run_id": self.run_id},
            }),
            json.dumps({"jsonrpc": "2.0", "id": 5, "method": "no/such/thing"}),
            "not json at all",
        ]
        proc, responses = self._send(requests)
        # 6 responses: ids 1..5 plus the parse error. The notification is
        # answered with silence (JSON-RPC notification semantics).
        self.assertEqual(len(responses), 6, proc.stdout)
        by_id = {}
        for resp in responses:
            self.assertEqual(resp["jsonrpc"], "2.0")
            by_id[resp.get("id")] = resp

        # 1: initialize handshake
        init = by_id[1]["result"]
        self.assertEqual(init["protocolVersion"], "2025-06-18")
        self.assertEqual(init["serverInfo"]["name"], MCP_SERVER_NAME)

        # 2: tools/list
        tools = by_id[2]["result"]["tools"]
        self.assertEqual(
            sorted(t["name"] for t in tools),
            ["next", "read_artifact", "status", "submit"],
        )

        # 3: tools/call status (standard client path)
        call = by_id[3]["result"]
        self.assertFalse(call["isError"])
        self.assertEqual(json.loads(call["content"][0]["text"])["run_id"], self.run_id)

        # 4: legacy direct tool call
        self.assertEqual(by_id[4]["result"]["run_id"], self.run_id)

        # 5: unknown method -> -32601
        self.assertEqual(by_id[5]["error"]["code"], -32601)

        # malformed line -> -32700 with null id
        self.assertEqual(by_id[None]["error"]["code"], -32700)

    def test_tools_call_unknown_tool_over_stdio_is_error_result(self):
        proc, responses = self._send([
            json.dumps({
                "jsonrpc": "2.0", "id": 7, "method": "tools/call",
                "params": {"name": "bogus_tool", "arguments": {}},
            }),
        ])
        self.assertEqual(len(responses), 1, proc.stdout)
        result = responses[0]["result"]
        self.assertTrue(result["isError"])
        self.assertEqual(json.loads(result["content"][0]["text"])["code"], "INVALID_INPUT")
        # The server must stay alive for subsequent calls on the same stream:
        self.assertEqual(proc.returncode, 0)


if __name__ == "__main__":
    unittest.main()
