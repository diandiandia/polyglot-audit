"""Model Context Protocol (MCP) stdio candidate transport server.

Implements DSR-004 / DSR-031 / DSR-075 / DR-011 / IFC-04 / DDS-01 / SR-022:
- Exposes exactly four strictly scoped tools:
  1. 'next': Claim tasks (with their published prompt packets)
  2. 'submit': Submit results with claim token
  3. 'status': Read run state and budget metrics
  4. 'read_artifact': Safely retrieve published artifacts strictly within run directory
- Speaks the standard MCP JSON-RPC 2.0 method surface (DSR-031 "adapt to the
  host transport", SR-022/023 host acceptance): initialize handshake with
  protocolVersion + serverInfo, notifications/initialized acknowledgement,
  tools/list with name/description/inputSchema, and tools/call with results
  wrapped as {content, isError}. The legacy custom transport (JSON-RPC method
  IS the tool name) stays compatible: a slash-free method naming one of the
  four tools keeps its historic direct-dispatch semantics.
- Routes every tool call through the AuditAppService (DDS-01 / SR-022): MCP is
  a transport, never a second state-mutation path. Submissions therefore go
  through the same schema validation, coverage recording and hunt -> verify
  fan-out as every other channel.
- Enforces payload size limits, run binding, and artifact path constraints.
- Discloses that MCP is a transport protocol, not an OS sandbox.
"""

# 需求追踪 (Requirement Traceability)
# ---------------------------------------------------------------------------
# 上层需求: docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2
# 设计依据: docs/design/SOFTWARE_DESIGN.md
# SWR-015  MCP 是传输适配不是安全沙箱：run 绑定、大小限制、路径规范化、任务所有权
#   绑定实现: DSR-031, DSR-075
# 状态以统一测试结论为准；未实测能力保持 unknown（设计原则 8：能观测的不靠声明）。
#

from __future__ import annotations
import hashlib
import json
from pathlib import Path
from typing import Any, Dict

from auditkit.contracts.errors import (
    AuditError,
    InvalidInputError,
    LimitExceededError,
    PathUnsafeError,
)
from auditkit.app.service import AuditAppService
from auditkit.hosts.errors import RunMismatchError


MAX_MCP_PAYLOAD_BYTES = 5 * 1024 * 1024  # 5 MB

# Standard MCP protocol layer (DSR-031 / SR-022 / SR-023): the server side of
# the standard handshake so standard MCP clients can initialize, list tools
# and call tools over the same stdio JSON-RPC channel.
MCP_DEFAULT_PROTOCOL_VERSION = "2024-11-05"
MCP_SERVER_NAME = "polyglot-audit-mcp"

# Legacy custom transport: the JSON-RPC method IS the tool name. Kept for
# backward compatibility with existing consumers and tests.
LEGACY_TOOL_METHODS = ("next", "submit", "status", "read_artifact")


def read_skill_version() -> str:
    """Return the skill version from skill/VERSION ('unknown' when unreadable)."""
    try:
        version_file = Path(__file__).resolve().parents[3] / "VERSION"
        text = version_file.read_text(encoding="utf-8").strip()
        return text or "unknown"
    except OSError:
        return "unknown"


def _object_schema(properties: Dict[str, Any], required: list) -> Dict[str, Any]:
    """Build a concise JSON-Schema object schema for one MCP tool."""
    return {"type": "object", "properties": properties, "required": required}


# tools/list payload: concise handwritten inputSchemas mirroring exactly the
# arguments MCPServer.handle_call consumes for each tool.
MCP_TOOL_DEFINITIONS = [
    {
        "name": "next",
        "description": (
            "Claim the next batch of audit tasks; returns claims with claim "
            "tokens and prompt packet references under the run directory."
        ),
        "inputSchema": _object_schema(
            {
                "run_id": {"type": "string", "description": "Run identifier to claim tasks from"},
                "batch_size": {"type": "integer", "description": "Maximum tasks to claim (default 1)"},
            },
            ["run_id"],
        ),
    },
    {
        "name": "submit",
        "description": (
            "Submit a worker result for a claimed attempt; validated and "
            "coverage-recorded through AuditAppService (hunt -> verify fan-out)."
        ),
        "inputSchema": _object_schema(
            {
                "run_id": {"type": "string"},
                "task_id": {"type": "string"},
                "attempt_id": {"type": "string"},
                "generation": {"type": "integer", "description": "Claim lease generation"},
                "claim_token": {"type": "string"},
                "result": {
                    "type": "object",
                    "description": (
                        "worker_result object: schema_version/task_id/attempt_id/"
                        "kind/coverage/records/overflow"
                    ),
                },
            },
            ["run_id", "task_id", "attempt_id", "generation", "claim_token", "result"],
        ),
    },
    {
        "name": "status",
        "description": "Read run state, revision, task counters and budget summary.",
        "inputSchema": _object_schema(
            {"run_id": {"type": "string"}},
            ["run_id"],
        ),
    },
    {
        "name": "read_artifact",
        "description": (
            "Read a published artifact by run-directory-relative path "
            "(traversal-safe; capped at 1MB of text)."
        ),
        "inputSchema": _object_schema(
            {
                "run_id": {"type": "string"},
                "relative_path": {"type": "string"},
            },
            ["run_id", "relative_path"],
        ),
    },
]


class MCPMethodNotFoundError(Exception):
    """JSON-RPC protocol error: the method is neither a standard MCP method,
    a notification, nor a legacy direct tool name (-> -32601)."""

    JSONRPC_CODE = -32601

    def __init__(self, method: object) -> None:
        super().__init__(f"Method not found: {method}")
        self.method = method


class MCPServer:
    """Stdio JSON-RPC transport exposing the 4 audit tools via AuditAppService."""

    def __init__(self, run_dir: str | Path, service: AuditAppService) -> None:
        self.run_dir = Path(run_dir)
        self.service = service

    def handle_protocol(self, method: object, params: object) -> Any:
        """Standard MCP JSON-RPC method layer (DSR-031 / SR-022 / SR-023).

        Sits above handle_call (which stays unchanged): maps the standard
        methods initialize / notifications/initialized / tools/list /
        tools/call onto the four audit tools, keeps the legacy direct
        transport (method = tool name) compatible, and raises
        MCPMethodNotFoundError (JSON-RPC -32601) for anything else.

        Returns the JSON-RPC `result` payload. Domain errors raised inside
        tools/call are converted into isError=true tool content (a tool
        execution failure is a tool result in MCP semantics, never a stdio
        loop crash); legacy direct tool calls keep propagating AuditError to
        the transport loop's historic -32000 mapping.
        """
        if not isinstance(method, str):
            raise MCPMethodNotFoundError(method)
        if not isinstance(params, dict):
            params = {}

        if method == "initialize":
            client_version = params.get("protocolVersion")
            protocol_version = (
                client_version
                if isinstance(client_version, str) and client_version
                else MCP_DEFAULT_PROTOCOL_VERSION
            )
            return {
                "protocolVersion": protocol_version,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": MCP_SERVER_NAME, "version": read_skill_version()},
            }

        if method == "notifications/initialized":
            # Standard post-initialize notification. JSON-RPC notifications
            # carry no id and get no response; an empty ack is returned so an
            # id-bearing variant still receives a valid response object.
            return {}

        if method.startswith("notifications/"):
            # Unknown notifications must never error (JSON-RPC notification
            # semantics): acknowledge silently.
            return {}

        if method == "tools/list":
            return {"tools": [dict(tool) for tool in MCP_TOOL_DEFINITIONS]}

        if method == "tools/call":
            return self._handle_tools_call(params)

        if method in LEGACY_TOOL_METHODS:
            # Backward-compatible legacy transport: a slash-free method naming
            # one of the four tools keeps the historic direct-dispatch
            # semantics (raw tool result; domain errors surface as JSON-RPC
            # errors from the transport loop, not isError content).
            return self.handle_call(method, params)

        raise MCPMethodNotFoundError(method)

    def _handle_tools_call(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Unpack params.name + params.arguments, route to handle_call, and
        wrap the outcome as an MCP tool result {content, isError}."""
        name = params.get("name")
        arguments = params.get("arguments")
        if not isinstance(arguments, dict):
            arguments = {}
        try:
            result = self.handle_call(name if isinstance(name, str) else "", arguments)
        except AuditError as tool_error:
            # Tool execution failure (invalid input, unknown tool, path
            # unsafe, ...) becomes isError=true content so the stdio loop
            # keeps running for subsequent requests.
            return {
                "content": [
                    {"type": "text", "text": json.dumps(tool_error.to_dict(), ensure_ascii=False)}
                ],
                "isError": True,
            }
        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(result, ensure_ascii=False, sort_keys=True),
                }
            ],
            "isError": False,
        }

    def handle_call(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatch tool call through the application service."""
        if tool_name == "next":
            run_id = arguments.get("run_id", "")
            batch = int(arguments.get("batch_size", 1))
            claims = self.service.next(
                run_id, self.run_dir, batch_size=batch, worker_id="mcp_worker"
            )
            return {"claims": claims}

        elif tool_name == "submit":
            run_id = arguments.get("run_id", "")
            task_id = arguments.get("task_id", "")
            attempt_id = arguments.get("attempt_id", "")
            generation = int(arguments.get("generation", 0))
            token = arguments.get("claim_token", "")
            result = arguments.get("result", {})

            result_bytes = json.dumps(result, sort_keys=True).encode("utf-8")
            if len(result_bytes) > MAX_MCP_PAYLOAD_BYTES:
                raise LimitExceededError("Submitted result exceeds maximum MCP payload limit of 5MB")

            digest = hashlib.sha256(result_bytes).hexdigest()
            claim = {
                "run_id": run_id,
                "task_id": task_id,
                "attempt_id": attempt_id,
                "generation": generation,
                "claim_token": token,
            }
            receipt = self.service.submit(self.run_dir, claim, result, digest)
            return receipt

        elif tool_name == "status":
            run_id = arguments.get("run_id", "")
            # Unknown runs raise InvalidInputError from the service (validated,
            # not ignored — DSR-031/075).
            return self.service.status(run_id, self.run_dir)

        elif tool_name == "read_artifact":
            run_id = arguments.get("run_id", "")
            rel_path = arguments.get("relative_path", "")
            # DSR-031/075: the run_id is validated, not ignored — unknown runs
            # cannot read artifacts.
            try:
                self.service.status(run_id, self.run_dir)
            except InvalidInputError:
                raise InvalidInputError(f"Run '{run_id}' not found")
            if not rel_path or ".." in rel_path or rel_path.startswith("/"):
                raise PathUnsafeError("Prohibited artifact path traversal")

            full_path = (self.run_dir / rel_path).resolve()
            if not full_path.is_relative_to(self.run_dir.resolve()):
                raise PathUnsafeError("Path escapes run directory")

            if not full_path.exists() or not full_path.is_file():
                raise InvalidInputError(f"Artifact not found: {rel_path}")

            with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read(1024 * 1024)
            return {"relative_path": rel_path, "content": content}

        else:
            raise InvalidInputError(f"Unknown MCP tool: {tool_name}")


class McpRunAdapter:
    """Run-bound MCP tool adapter enforcing cross-run isolation (DSR-031/075).

    Binds a single run_id at construction; every tool call must supply the
    same run_id or RunMismatchError is raised (cross-run access is rejected
    before any service or filesystem interaction). Also enforces the 5MB
    submit payload limit and artifact path safety on the bound adapter level.
    """

    def __init__(self, run_dir: str | Path, service: AuditAppService, run_id: str) -> None:
        self.server = MCPServer(run_dir, service)
        self.run_id = run_id

    def _require_run(self, run_id: str) -> None:
        """Reject calls whose run_id does not match the bound run."""
        if run_id != self.run_id:
            raise RunMismatchError(
                f"run_id '{run_id}' does not match the adapter-bound run '{self.run_id}'",
                details={"provided_run_id": run_id, "bound_run_id": self.run_id},
            )

    def next(self, run_id: str, batch_size: int = 1) -> Dict[str, Any]:
        """Claim tasks, strictly within the bound run."""
        self._require_run(run_id)
        return self.server.handle_call("next", {"run_id": run_id, "batch_size": batch_size})

    def submit(
        self,
        run_id: str,
        task_id: str,
        attempt_id: str,
        generation: int,
        claim_token: str,
        result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Submit a result; cross-run submissions are rejected."""
        self._require_run(run_id)
        return self.server.handle_call(
            "submit",
            {
                "run_id": run_id,
                "task_id": task_id,
                "attempt_id": attempt_id,
                "generation": generation,
                "claim_token": claim_token,
                "result": result,
            },
        )

    def status(self, run_id: str) -> Dict[str, Any]:
        """Read run state, strictly for the bound run."""
        self._require_run(run_id)
        return self.server.handle_call("status", {"run_id": run_id})

    def read_artifact(self, run_id: str, relative_path: str) -> Dict[str, Any]:
        """Read a published artifact, strictly for the bound run."""
        self._require_run(run_id)
        return self.server.handle_call(
            "read_artifact", {"run_id": run_id, "relative_path": relative_path}
        )