"""Tests for host capability detection, doctor, safety acceptance, and MCP tools."""
# ==============================================================================
# 软件需求追踪与实现规范 (Software Requirements Traceability)
# ==============================================================================
# --- 需求编号: DSR-021/030/031 [负责人: HST] / SWR-015 / SWR-022 ---
# 需求描述: 能力矩阵安全策略门禁、in-session next/start/submit、MCP 四工具候选适配；
#   未批准禁止启动，未经证实不得标 enforced。
#   └─ 对应系统需求 SR-015（无法强制的权限启动前披露并需用户接受）与 SR-022（双引擎同语义）。
# ==============================================================================

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from auditkit.app.service import AuditAppService
from auditkit.contracts.errors import (
    PathUnsafeError,
    SafetyApprovalRequiredError,
)
from auditkit.hosts.capabilities import Capability, FeatureState
from auditkit.hosts.doctor import Doctor
from auditkit.hosts.mcp_adapter import MCPServer
from auditkit.ledger.db import get_db_connection, init_database
from auditkit.ledger.task_queue import TaskQueue

SKILL_DIR = Path("/root/polyglot-audit/skill")


class TestHosts(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "events.db"
        init_database(self.db_path)
        self.conn = get_db_connection(self.db_path)

        self.run_id = "run-mcp-test"
        self.conn.execute(
            """
            INSERT INTO runs (run_id, snapshot_id, state, schema_version, skill_version, knowledge_version, config_ref, revision, created_at, updated_at)
            VALUES (?, 'snp-01', 'active', '1.0', '0.1.0', '1.0', 'cfg', 0, '2026-11-14T00:00:00Z', '2026-11-14T00:00:00Z')
            """,
            (self.run_id,),
        )

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.temp_dir)

    def test_doctor_probe(self):
        doc = Doctor()
        caps = doc.probe(probe_cli=False)
        self.assertTrue(len(caps) >= 3)
        adapters = [c["adapter"] for c in caps]
        self.assertIn("python_core", adapters)
        self.assertIn("claude_cli", adapters)
        self.assertIn("codex_cli", adapters)

    def test_safety_acceptance_enforcement(self):
        cap = Capability("test_host", "1.0")
        # When isolation not enforced and user_approved is False -> raises SafetyApprovalRequiredError
        with self.assertRaises(SafetyApprovalRequiredError):
            cap.verify_safety_policy({"user_approved": False})

        # With user_approved True -> succeeds
        cap.verify_safety_policy({"user_approved": True})

    def test_mcp_four_tools(self):
        queue = TaskQueue(self.conn)
        queue.enqueue(self.run_id, "hunt:u1", "hunt", {"unit": {"unit_id": "u1"}})

        server = MCPServer(self.temp_dir, AuditAppService(SKILL_DIR))

        # Tool 1: next
        res_next = server.handle_call("next", {"run_id": self.run_id, "batch_size": 1})
        self.assertEqual(len(res_next["claims"]), 1)
        claim = res_next["claims"][0]

        # Tool 2: submit
        res_submit = server.handle_call("submit", {
            "run_id": self.run_id,
            "task_id": claim["task_id"],
            "attempt_id": claim["attempt_id"],
            "generation": claim["generation"],
            "claim_token": claim["claim_token"],
            "result": {"schema_version": "1.0", "task_id": claim["task_id"], "attempt_id": claim["attempt_id"], "kind": "hunt", "records": [], "overflow": [], "coverage": []},
        })
        self.assertTrue(res_submit["ok"])

        # Tool 3: status
        res_status = server.handle_call("status", {"run_id": self.run_id})
        self.assertEqual(res_status["state"], "active")

        # Tool 4: read_artifact
        art_path = Path(self.temp_dir) / "report.txt"
        art_path.write_text("Audit summary", encoding="utf-8")
        res_art = server.handle_call("read_artifact", {"run_id": self.run_id, "relative_path": "report.txt"})
        self.assertEqual(res_art["content"], "Audit summary")

        # Prohibit path traversal in read_artifact
        with self.assertRaises(PathUnsafeError):
            server.handle_call("read_artifact", {"run_id": self.run_id, "relative_path": "../outside.txt"})


if __name__ == "__main__":
    unittest.main()
