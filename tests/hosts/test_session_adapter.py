"""Tests for the in-session adapter modes (DSR-030) and the AIMD concurrency
controller (DSR-064). The adapter routes through AuditAppService (DDS-01):
submitting a hunt candidate in-session must enqueue a verify task."""

import shutil
import tempfile
import unittest
from pathlib import Path

from auditkit.app.service import AuditAppService
from auditkit.hosts.capabilities import FeatureState
from auditkit.hosts.concurrency import ConcurrencyController
from auditkit.hosts.session_adapter import InSessionAdapter
from auditkit.ledger.db import get_db_connection, init_database
from auditkit.ledger.task_queue import TaskQueue

SKILL_DIR = Path("/root/polyglot-audit/skill")


class TestInSessionAdapterModes(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="session-test-")
        self.db_path = Path(self.temp_dir) / "events.db"
        init_database(self.db_path)
        self.conn = get_db_connection(self.db_path)
        self.conn.execute(
            """
            INSERT INTO runs (run_id, snapshot_id, state, schema_version, skill_version, knowledge_version, config_ref, revision, created_at, updated_at)
            VALUES ('run-s', 'snp-01', 'active', '1.0', '0.1.0', '1.0', 'cfg', 0, '2026-11-14T00:00:00Z', '2026-11-14T00:00:00Z')
            """
        )
        self.queue = TaskQueue(self.conn)
        self.app = AuditAppService(SKILL_DIR)
        self.adapter = InSessionAdapter(self.app, self.temp_dir)

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.temp_dir)

    def test_unmeasured_delegation_defaults_to_sequential_fallback(self):
        """DSR-030/004: without a measured delegation capability the adapter
        starts in the bounded sequential fallback mode."""
        self.assertEqual(self.adapter.mode, "sequential_fallback")
        self.assertIsNone(self.adapter.supports_subagents)

    def test_explicit_modes(self):
        self.assertEqual(
            InSessionAdapter(self.app, self.temp_dir, supports_subagents=True).mode, "subagent"
        )
        self.assertEqual(
            InSessionAdapter(self.app, self.temp_dir, supports_subagents=False).mode,
            "sequential_fallback",
        )

    def test_delegation_probe_conservative_keeps_unknown(self):
        feature = self.adapter.probe_delegation()
        self.assertEqual(feature["state"], FeatureState.UNKNOWN)
        self.assertEqual(self.adapter.mode, "sequential_fallback")

    def test_delegation_probe_updates_mode_on_success(self):
        feature = self.adapter.probe_delegation(
            lambda prompt: "OK", probe_level="aggressive"
        )
        self.assertEqual(feature["state"], FeatureState.ENFORCED)
        self.assertEqual(self.adapter.mode, "subagent")
        self.assertTrue(self.adapter.supports_subagents)

    def test_delegation_probe_failure_keeps_sequential(self):
        def bad_delegate(prompt):
            raise RuntimeError("delegation rejected")

        feature = self.adapter.probe_delegation(bad_delegate, probe_level="aggressive")
        self.assertEqual(feature["state"], FeatureState.UNKNOWN)
        self.assertEqual(self.adapter.mode, "sequential_fallback")
        self.assertFalse(self.adapter.supports_subagents)

    def test_next_start_submit_cycle(self):
        self.queue.enqueue("run-s", "hunt:u1", "hunt", {"unit": {"unit_id": "u1"}})
        claims = self.adapter.next_task("run-s")
        self.assertEqual(len(claims), 1)
        adapter = self.adapter
        adapter.start_task(claims[0])
        receipt = adapter.submit_task(
            claims[0],
            {"schema_version": "1.0", "task_id": claims[0]["task_id"], "attempt_id": claims[0]["attempt_id"], "kind": "hunt", "records": [], "overflow": [], "coverage": []},
            "deadbeef",
            usage={
                "schema_version": "1.0",
                "attempt_id": claims[0]["attempt_id"],
                "dimension": "tokens",
                "availability": "exact",
                "unit": "tokens",
                "source": "worker_output",
                "value": 3,
            },
        )
        self.assertTrue(receipt["ok"])

    def test_in_session_submit_enqueues_verify_task_via_service(self):
        """DDS-01 / SR-022: the in-session path is not a bypass — a hunt result
        carrying a candidate must produce a verify task through the service."""
        (Path(self.temp_dir) / "snapshot").mkdir()
        (Path(self.temp_dir) / "snapshot" / "app.py").write_text(
            "import os\nos.system(cmd)\n", encoding="utf-8"
        )
        self.queue.enqueue(
            "run-s",
            "hunt:u1",
            "hunt",
            {"snapshot_id": "snp-01", "unit": {"unit_id": "u1", "language": "python",
             "ranges": [{"path": "app.py", "line_start": 1, "line_end": 2}]}},
        )
        claims = self.adapter.next_task("run-s")
        claim = claims[0]
        self.adapter.start_task(claim)
        candidate = {
            "schema_version": "1.0",
            "candidate_id": "cand-in-session-01",
            "issue": "py-01",
            "source": {"path": "app.py", "line": 2, "symbol": "run", "kind": "param", "control": "c"},
            "sink": {"path": "app.py", "line": 2, "symbol": "os.system", "kind": "rce", "effect": "e"},
            "steps": [
                {"path": "app.py", "line": 2, "role": "source", "note": "n1"},
                {"path": "app.py", "line": 2, "role": "sink", "note": "n2"},
            ],
            "guard_analysis": "none",
            "impact_claim": "RCE",
            "open_questions": [],
            "provenance": {"hunt_tasks": [claim["task_id"]]},
        }
        receipt = self.adapter.submit_task(
            claim,
            {"schema_version": "1.0", "task_id": claim["task_id"],
             "attempt_id": claim["attempt_id"], "kind": "hunt", "records": [candidate],
             "overflow": [], "coverage": []},
            "digest-in-session-01",
        )
        self.assertTrue(receipt["ok"])
        verify_rows = self.conn.execute(
            "SELECT task_id, kind, priority FROM tasks WHERE kind = 'verify'"
        ).fetchall()
        self.assertEqual(len(verify_rows), 1)
        self.assertGreater(verify_rows[0]["priority"], 20)


class TestConcurrencyController(unittest.TestCase):

    def test_aimd_increase_on_success(self):
        """DSR-064: success +1 up to maximum."""
        ctrl = ConcurrencyController(initial=1, maximum=4)
        self.assertEqual(ctrl.on_success(), 2)
        self.assertEqual(ctrl.on_success(), 3)
        self.assertEqual(ctrl.on_success(), 4)
        self.assertEqual(ctrl.on_success(), 4)  # capped

    def test_aimd_halve_on_failure_floored_at_one(self):
        ctrl = ConcurrencyController(initial=8, maximum=8)
        self.assertEqual(ctrl.on_failure(), 4)
        self.assertEqual(ctrl.on_failure(), 2)
        self.assertEqual(ctrl.on_failure(), 1)
        self.assertEqual(ctrl.on_failure(), 1)  # floored

    def test_bounds_clamped(self):
        ctrl = ConcurrencyController(initial=100, maximum=8, minimum=1)
        self.assertEqual(ctrl.current, 8)
        ctrl = ConcurrencyController(initial=0, maximum=8, minimum=1)
        self.assertEqual(ctrl.current, 1)

    def test_invalid_bounds_rejected(self):
        with self.assertRaises(ValueError):
            ConcurrencyController(maximum=0)
        with self.assertRaises(ValueError):
            ConcurrencyController(initial=5, maximum=2, minimum=4)


if __name__ == "__main__":
    unittest.main()
