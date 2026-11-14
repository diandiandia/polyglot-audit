"""Model Context Protocol (MCP) stdio candidate transport server.

Implements DSR-004 / DSR-031 / DSR-075 / DR-011 / IFC-04:
- Exposes exactly four strictly scoped tools:
  1. 'next': Claim tasks
  2. 'submit': Submit results with claim token
  3. 'status': Read run state and budget metrics
  4. 'read_artifact': Safely retrieve published artifacts strictly within run directory
- Enforces payload size limits, token validation, and cross-run isolation.
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
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from auditkit.contracts.errors import (
    AuditError,
    InvalidInputError,
    LimitExceededError,
    PathUnsafeError,
)
from auditkit.hosts.errors import RunMismatchError
from auditkit.ledger.task_queue import TaskQueue


MAX_MCP_PAYLOAD_BYTES = 5 * 1024 * 1024  # 5 MB


class MCPServer:
    """Stdio JSON-RPC transport exposing the 4 audit tools."""

    def __init__(self, run_dir: str | Path, queue: TaskQueue) -> None:
        self.run_dir = Path(run_dir)
        self.queue = queue

    def handle_call(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatch tool call."""
        if tool_name == "next":
            run_id = arguments.get("run_id", "")
            batch = int(arguments.get("batch_size", 1))
            claims = self.queue.claim(run_id, batch_size=batch, worker_id="mcp_worker")
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
            receipt = self.queue.submit(
                run_id=run_id,
                task_id=task_id,
                attempt_id=attempt_id,
                generation=generation,
                claim_token=token,
                worker_result=result,
                result_digest=digest,
            )
            return receipt

        elif tool_name == "status":
            run_id = arguments.get("run_id", "")
            row = self.queue.conn.execute("SELECT state, revision FROM runs WHERE run_id = ?", (run_id,)).fetchone()
            if not row:
                raise InvalidInputError(f"Run '{run_id}' not found")
            return {"run_id": run_id, "state": row["state"], "revision": row["revision"]}

        elif tool_name == "read_artifact":
            run_id = arguments.get("run_id", "")
            rel_path = arguments.get("relative_path", "")
            # DSR-031/075: the run_id is validated, not ignored — unknown runs
            # cannot read artifacts.
            row = self.queue.conn.execute(
                "SELECT run_id FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            if not row:
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
    before any queue or filesystem interaction). Also enforces the 5MB submit
    payload limit and artifact path safety on the bound adapter level.
    """

    def __init__(self, run_dir: str | Path, queue: TaskQueue, run_id: str) -> None:
        self.server = MCPServer(run_dir, queue)
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
