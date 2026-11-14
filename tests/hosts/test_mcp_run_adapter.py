"""Tests for the run-bound MCP adapter (DSR-031/075): run binding, cross-run
rejection, payload limits, and artifact path validation."""

import shutil
import tempfile
import unittest
from pathlib import Path

from auditkit.contracts.errors import InvalidInputError, LimitExceededError, PathUnsafeError
from auditkit.hosts.errors import RunMismatchError
from auditkit.hosts.mcp_adapter import MCPServer, McpRunAdapter
from auditkit.ledger.db import get_db_connection, init_database
from auditkit.ledger.task_queue import TaskQueue

_RESULT_TEMPLATE = {
    "schema_version": "1.0",
    "kind": "hunt",
    "records": [],
    "overflow": [],
    "coverage": [],
}


class TestMcpRunAdapter(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="mcp-run-test-")
        self.db_path = Path(self.temp_dir) / "events.db"
        init_database(self.db_path)
        self.conn = get_db_connection(self.db_path)
        for run_id in ("run-a", "run-b"):
            self.conn.execute(
                """
                INSERT INTO runs (run_id, snapshot_id, state, schema_version, skill_version, knowledge_version, config_ref, revision, created_at, updated_at)
                VALUES (?, 'snp-01', 'active', '1.0', '0.1.0', '1.0', 'cfg', 0, '2026-11-14T00:00:00Z', '2026-11-14T00:00:00Z')
                """,
                (run_id,),
            )
        self.queue = TaskQueue(self.conn)
        self.adapter = McpRunAdapter(self.temp_dir, self.queue, "run-a")

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.temp_dir)

    def _enqueue_one(self):
        self.queue.enqueue("run-a", "hunt:u1", "hunt", {"unit": "u1"})
        return self.adapter.next("run-a")["claims"][0]

    def test_full_cycle_within_bound_run(self):
        claim = self._enqueue_one()
        result = dict(_RESULT_TEMPLATE, task_id=claim["task_id"], attempt_id=claim["attempt_id"])
        receipt = self.adapter.submit(
            "run-a",
            claim["task_id"],
            claim["attempt_id"],
            claim["generation"],
            claim["claim_token"],
            result,
        )
        self.assertTrue(receipt["ok"])
        status = self.adapter.status("run-a")
        self.assertEqual(status["state"], "active")

    def test_cross_run_next_rejected(self):
        """DSR-031: next with a foreign run_id raises RunMismatchError."""
        self.queue.enqueue("run-b", "hunt:u2", "hunt", {"unit": "u2"})
        with self.assertRaises(RunMismatchError):
            self.adapter.next("run-b")

    def test_cross_run_status_rejected(self):
        with self.assertRaises(RunMismatchError):
            self.adapter.status("run-b")

    def test_cross_run_submit_rejected(self):
        """DSR-075: cross-run submission is rejected before touching the queue."""
        claim = self._enqueue_one()
        result = dict(_RESULT_TEMPLATE, task_id=claim["task_id"], attempt_id=claim["attempt_id"])
        with self.assertRaises(RunMismatchError):
            self.adapter.submit(
                "run-b",
                claim["task_id"],
                claim["attempt_id"],
                claim["generation"],
                claim["claim_token"],
                result,
            )

    def test_cross_run_read_artifact_rejected(self):
        art = Path(self.temp_dir) / "report.txt"
        art.write_text("x", encoding="utf-8")
        with self.assertRaises(RunMismatchError):
            self.adapter.read_artifact("run-b", "report.txt")

    def test_oversized_submit_rejected(self):
        """DSR-031: requests above 5MB raise LimitExceededError."""
        claim = self._enqueue_one()
        big = {"records": [{"data": "x" * (5 * 1024 * 1024 + 100)}]}
        result = dict(_RESULT_TEMPLATE, task_id=claim["task_id"], attempt_id=claim["attempt_id"], records=big["records"])
        with self.assertRaises(LimitExceededError):
            self.adapter.submit(
                "run-a",
                claim["task_id"],
                claim["attempt_id"],
                claim["generation"],
                claim["claim_token"],
                result,
            )

    def test_read_artifact_happy_path_and_missing_file(self):
        claim = self._enqueue_one()
        result = dict(_RESULT_TEMPLATE, task_id=claim["task_id"], attempt_id=claim["attempt_id"])
        self.adapter.submit(
            "run-a", claim["task_id"], claim["attempt_id"], claim["generation"], claim["claim_token"], result
        )
        art = Path(self.temp_dir) / "report.txt"
        art.write_text("Audit summary", encoding="utf-8")
        self.assertEqual(self.adapter.read_artifact("run-a", "report.txt")["content"], "Audit summary")

        # Nonexistent artifact
        with self.assertRaises(InvalidInputError):
            self.adapter.read_artifact("run-a", "nope.txt")
        # Illegal path traversal
        with self.assertRaises(PathUnsafeError):
            self.adapter.read_artifact("run-a", "../outside.txt")
        # Absolute path
        with self.assertRaises(PathUnsafeError):
            self.adapter.read_artifact("run-a", "/etc/passwd")

    def test_transport_server_read_artifact_unknown_run(self):
        """DSR-031/075: MCPServer-level read_artifact validates the run too."""
        self.queue.enqueue("run-a", "hunt:u3", "hunt", {"unit": "u3"})
        art = Path(self.temp_dir) / "report.txt"
        art.write_text("Audit summary", encoding="utf-8")
        server = MCPServer(self.temp_dir, self.queue)
        with self.assertRaises(InvalidInputError):
            server.handle_call("read_artifact", {"run_id": "ghost-run", "relative_path": "report.txt"})


if __name__ == "__main__":
    unittest.main()
