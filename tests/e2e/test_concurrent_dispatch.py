"""Real-concurrency contract tests for run_dispatch_loop (DSR-064 / HST -> LED).

Covers the parallel dispatch model that the serial batch loop could not have:
- Per-task lifecycle: the claim(batch_size=1) happens immediately before each
  task's own execution, so no attempt ever holds a lease while queued behind
  other work; even executions that outlive the lease never go stale.
- Parallel execution: independent tasks run concurrently on the worker pool
  under the in-flight cap taken from the ConcurrencyController's CURRENT value.
- AIMD mapping per task: success -> on_success (+1), failure -> on_failure
  (halve); retryable host failures requeue the task within adapter.max_retries.
- Stop contract (CLI consumers): stop_reason is queue_drained /
  budget_exhausted / paused_or_blocked; max_batches caps dispatched task rounds
  and reports stop_reason None (the caller cap, not a queue/budget/state stop).
- run/CLI-level behavior contracts are unchanged: every dispatched attempt is
  submitted with a trusted usage object and the drained run finalizes complete.
"""

import json
import shutil
import tempfile
import threading
import time
import unittest
from pathlib import Path

from auditkit.app.service import AuditAppService
from auditkit.contracts.errors import HostFailureError
from auditkit.hosts.concurrency import ConcurrencyController
from auditkit.ledger.db import get_db_connection

FIXTURES_DIR = Path("/root/polyglot-audit/tests/fixtures")
SKILL_DIR = Path("/root/polyglot-audit/skill")

# Two strength-3 sink signals per file: high_strength_count >= 2 yields T1
# units, so every file becomes an analyze-disposition hunt task (DSR-056).
SIGNAL_FILE_TEMPLATE = (
    "import pickle\n\n\n"
    "def handle_payload_{i}(untrusted_payload):\n"
    "    obj = pickle.loads(untrusted_payload)\n"
    "    eval(user_expression)\n"
    "    return obj\n"
)


class _FakeAdapter:
    """Minimal stand-in for a host driver adapter (last_usage interface)."""

    def __init__(self, last_usage=None, max_retries=2, backoff_base=0.01, backoff_max=0.05):
        self.last_usage = last_usage
        self.max_retries = max_retries
        self.backoff_base = backoff_base
        self.backoff_max = backoff_max


class TestConcurrentDispatch(unittest.TestCase):
    """run_dispatch_loop: real parallel dispatch with per-task claims."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())
        self.app = AuditAppService(SKILL_DIR)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------
    def _signal_target(self, n_files: int) -> Path:
        """Create a target whose n_files each become a T1 hunt unit."""
        target = self.temp_dir / "target"
        (target / "src").mkdir(parents=True)
        for i in range(n_files):
            (target / "src" / f"mod_{i}.py").write_text(
                SIGNAL_FILE_TEMPLATE.format(i=i), encoding="utf-8"
            )
        return target

    def _make_config(self, target, tasks_limit=30):
        return {
            "schema_version": "1.0",
            "target": str(target),
            "run_dir": str(self.temp_dir / "run"),
            "report_language": "en",
            "profile": "standard",
            "scope": {"include": ["*"], "exclude": []},
            "budgets": [
                {
                    "schema_version": "1.0",
                    "dimension": "tasks",
                    "mode": "enforced",
                    "limit": tasks_limit,
                    "settled": 0,
                    "reserved": 0,
                    "unit": "tasks",
                    "availability": "exact",
                },
                {
                    "schema_version": "1.0",
                    "dimension": "tokens",
                    "mode": "enforced",
                    "limit": 100000,
                    "settled": 0,
                    "reserved": 0,
                    "unit": "tokens",
                    "availability": "exact",
                },
            ],
            "safety_acceptance": {
                "allow_unverified_execution": False,
                "allow_unverified_network": False,
                "allow_unverified_write": False,
                "user_approved": True,
            },
        }

    def _prepared(self, config):
        prep = self.app.prepare(config["target"], config["run_dir"], config)
        self.app.activate(prep["run_id"], config["run_dir"])
        return prep

    def _worker_result(self, claim):
        kind = (claim.get("spec") or {}).get("task_kind") or "hunt"
        return {
            "schema_version": "1.0",
            "task_id": claim["task_id"],
            "attempt_id": claim["attempt_id"],
            "kind": kind,
            "coverage": [],
            "records": [],
            "overflow": [],
        }

    def _db(self, run_dir):
        return get_db_connection(Path(run_dir) / "events.db")

    # ------------------------------------------------------------------
    # a. parallel execution under the in-flight cap
    # ------------------------------------------------------------------
    def test_tasks_execute_in_parallel_under_in_flight_cap(self):
        target = self._signal_target(4)
        config = self._make_config(target)
        prep = self._prepared(config)
        run_id, run_dir = prep["run_id"], Path(config["run_dir"])

        controller = ConcurrencyController(initial=4, maximum=4)
        lock = threading.Lock()
        live = {"now": 0, "max": 0}

        def execute_fn(claim):
            with lock:
                live["now"] += 1
                live["max"] = max(live["max"], live["now"])
            time.sleep(0.4)
            with lock:
                live["now"] -= 1
            return self._worker_result(claim)

        adapter = _FakeAdapter({"total_tokens": 20, "availability": "exact"})
        t0 = time.monotonic()
        summary = self.app.run_dispatch_loop(
            run_id, run_dir, execute_fn, adapter=adapter, controller=controller
        )
        elapsed = time.monotonic() - t0

        # 5 tasks total (recon + 4 hunts): serial execution would need ~2.0s
        # of pure worker sleep; the parallel cap 4 must land far below it.
        # The threshold is generous to stay stable on loaded CI machines.
        self.assertLess(elapsed, 1.2, f"dispatch was not parallel: {elapsed:.2f}s")
        self.assertGreaterEqual(live["max"], 3, f"max observed concurrency {live['max']}")
        self.assertEqual(summary["stop_reason"], "queue_drained")
        self.assertEqual(summary["failed"], 0)
        # recon + 4 hunts all submitted
        self.assertEqual(summary["submitted"], 5)

        # Unchanged run-level contract: usage is settled for every attempt.
        conn = self._db(run_dir)
        try:
            usage_rows = conn.execute(
                "SELECT dimension, availability, value FROM usage_records"
            ).fetchall()
            done_rows = conn.execute(
                "SELECT count(*) AS cnt FROM tasks WHERE state = 'done'"
            ).fetchone()["cnt"]
        finally:
            conn.close()
        self.assertEqual(done_rows, 5)
        self.assertEqual(len(usage_rows), 5)
        self.assertTrue(all(r["availability"] == "exact" and r["value"] == 20 for r in usage_rows))

        fin = self.app.finalize(run_id, run_dir, findings=[])
        self.assertEqual(fin["final_state"], "complete")

    # ------------------------------------------------------------------
    # b. claim precedes execution: no stale lease errors
    # ------------------------------------------------------------------
    def test_claim_precedes_execution_so_long_tasks_never_go_stale(self):
        target = self._signal_target(4)
        config = self._make_config(target)
        prep = self._prepared(config)
        run_id, run_dir = prep["run_id"], Path(config["run_dir"])

        controller = ConcurrencyController(initial=4, maximum=4)

        def execute_fn(claim):
            # Each execution outlives the remaining lease of a hypothetical
            # batch-queued claim (lease_seconds=1 < 4 x 0.2s serial would have
            # expired); with per-task claims this must never surface as a
            # StaleAttemptError.
            time.sleep(0.2)
            return self._worker_result(claim)

        summary = self.app.run_dispatch_loop(
            run_id, run_dir, execute_fn,
            adapter=_FakeAdapter(), controller=controller, lease_seconds=1,
        )
        self.assertEqual(summary["stop_reason"], "queue_drained")
        self.assertEqual(summary["submitted"], 5)
        self.assertEqual(summary["failed"], 0)
        self.assertEqual(summary["budget_retained"], 0)

        conn = self._db(run_dir)
        try:
            attempts = conn.execute(
                "SELECT attempt_id, generation, status FROM attempts"
            ).fetchall()
            expired_events = conn.execute(
                "SELECT count(*) AS cnt FROM events WHERE event_type = 'attempt_expired'"
            ).fetchone()["cnt"]
            done_rows = conn.execute(
                "SELECT count(*) AS cnt FROM tasks WHERE state = 'done'"
            ).fetchone()["cnt"]
        finally:
            conn.close()
        # Every task was claimed exactly once, executed, and submitted: no
        # lease was reclaimed and no attempt was retried or went stale.
        self.assertEqual(done_rows, 5)
        self.assertEqual(len(attempts), 5)
        self.assertTrue(all(a["status"] == "done" and a["generation"] == 1 for a in attempts))
        self.assertEqual(expired_events, 0)

    # ------------------------------------------------------------------
    # c. AIMD: failures halve the cap, later successes raise it back
    # ------------------------------------------------------------------
    def test_failures_halve_in_flight_cap_and_successes_recover_it(self):
        target = self._signal_target(4)
        config = self._make_config(target)
        prep = self._prepared(config)
        run_id, run_dir = prep["run_id"], Path(config["run_dir"])

        class RecordingController(ConcurrencyController):
            """Records every AIMD level change for direct value assertions."""

            def __init__(self, **kwargs):
                super().__init__(**kwargs)
                self.history = [self.current]

            def on_success(self):
                value = super().on_success()
                self.history.append(value)
                return value

            def on_failure(self):
                value = super().on_failure()
                self.history.append(value)
                return value

        controller = RecordingController(initial=4, maximum=8)
        lock = threading.Lock()
        state = {"failures_left": 2}

        def execute_fn(claim):
            with lock:
                if state["failures_left"] > 0:
                    state["failures_left"] -= 1
                    fail = True
                else:
                    fail = False
            if fail:
                # Retryable host failure: the task requeues (adapter budget)
                # and a later attempt succeeds.
                raise HostFailureError("worker host died mid-task", retryable=True)
            time.sleep(0.01)
            return self._worker_result(claim)

        summary = self.app.run_dispatch_loop(
            run_id, run_dir, execute_fn,
            adapter=_FakeAdapter(), controller=controller,
        )
        # Both injected failures were reported and requeued; every task still
        # completed on a retry.
        self.assertEqual(summary["failed"], 2)
        self.assertEqual(summary["submitted"], 5)
        self.assertEqual(summary["stop_reason"], "queue_drained")

        # AIMD was mapped per task: the in-flight cap dropped from 4 to <= 2
        # (multiplicative decrease on each failure) and rose again afterwards
        # (additive increase on each later success).
        history = controller.history
        self.assertIn(4, history, f"cap never observed its initial level: {history}")
        self.assertLessEqual(min(history), 2, f"no halving observed: {history}")
        self.assertGreater(max(history), min(history), f"no recovery observed: {history}")
        self.assertEqual(summary["concurrency"], controller.current)
        self.assertGreaterEqual(summary["concurrency"], 3)

        conn = self._db(run_dir)
        try:
            retriable_events = conn.execute(
                "SELECT count(*) AS cnt FROM events WHERE event_type = 'attempt_failed_retriable'"
            ).fetchone()["cnt"]
            done_rows = conn.execute(
                "SELECT count(*) AS cnt FROM tasks WHERE state = 'done'"
            ).fetchone()["cnt"]
        finally:
            conn.close()
        self.assertEqual(retriable_events, 2)
        self.assertEqual(done_rows, 5)

    # ------------------------------------------------------------------
    # d. stop contract: three stop reasons + task cap
    # ------------------------------------------------------------------
    def test_stop_reason_queue_drained_on_empty_queue(self):
        target = self._signal_target(2)
        config = self._make_config(target)
        prep = self._prepared(config)
        summary = self.app.run_dispatch_loop(
            prep["run_id"], Path(config["run_dir"]), self._worker_result,
            adapter=_FakeAdapter(),
        )
        self.assertEqual(summary["stop_reason"], "queue_drained")
        self.assertEqual(summary["submitted"], 3)  # recon + 2 hunts

    def test_stop_reason_budget_exhausted_with_tasks_remaining(self):
        target = self._signal_target(4)
        # Budget of one task: after the recon consumes it, the queued hunts
        # can never be dispatched.
        config = self._make_config(target, tasks_limit=1)
        prep = self._prepared(config)
        run_id, run_dir = prep["run_id"], Path(config["run_dir"])

        summary = self.app.run_dispatch_loop(
            run_id, run_dir, self._worker_result, adapter=_FakeAdapter()
        )
        self.assertEqual(summary["stop_reason"], "budget_exhausted")
        self.assertEqual(summary["submitted"], 1)

        conn = self._db(run_dir)
        try:
            queued = conn.execute(
                "SELECT count(*) AS cnt FROM tasks WHERE state = 'queued'"
            ).fetchone()["cnt"]
            budget_events = conn.execute(
                "SELECT count(*) AS cnt FROM events WHERE event_type = 'budget_exhausted'"
            ).fetchone()["cnt"]
        finally:
            conn.close()
        self.assertGreater(queued, 0)
        self.assertGreaterEqual(budget_events, 1)

    def test_stop_reason_paused_or_blocked_when_run_is_not_active(self):
        target = self._signal_target(2)
        config = self._make_config(target)
        prep = self._prepared(config)
        run_id, run_dir = prep["run_id"], Path(config["run_dir"])

        self.app.pause(run_id, run_dir, "concurrency-test")
        summary = self.app.run_dispatch_loop(
            run_id, run_dir, self._worker_result, adapter=_FakeAdapter()
        )
        self.assertEqual(summary["stop_reason"], "paused_or_blocked")
        self.assertEqual(summary["submitted"], 0)
        self.assertEqual(summary["batches"], 0)

    def test_max_batches_caps_dispatched_task_rounds(self):
        target = self._signal_target(4)
        config = self._make_config(target)
        prep = self._prepared(config)
        run_id, run_dir = prep["run_id"], Path(config["run_dir"])

        summary = self.app.run_dispatch_loop(
            run_id, run_dir, self._worker_result,
            adapter=_FakeAdapter(), max_batches=2,
        )
        # The cap counts dispatched tasks (one claim round per task); the loop
        # stops claiming once it is reached and reports the caller cap as
        # stop_reason None (not a queue/budget/state stop).
        self.assertEqual(summary["batches"], 2)
        self.assertIsNone(summary["stop_reason"])
        self.assertGreaterEqual(summary["submitted"], 1)

        conn = self._db(run_dir)
        try:
            queued = conn.execute(
                "SELECT count(*) AS cnt FROM tasks WHERE state = 'queued'"
            ).fetchone()["cnt"]
        finally:
            conn.close()
        self.assertGreater(queued, 0, "task cap did not leave planned work queued")

    def test_summary_contract_keys_are_stable_for_cli_consumers(self):
        target = self._signal_target(1)
        config = self._make_config(target)
        prep = self._prepared(config)
        summary = self.app.run_dispatch_loop(
            prep["run_id"], Path(config["run_dir"]), self._worker_result,
            adapter=_FakeAdapter({"total_tokens": 7, "availability": "exact"}),
        )
        # The dispatch summary embedded by `audit run` keeps its documented key
        # set; consumers read submitted/failed/budget_retained/concurrency/
        # stop_reason/batches.
        self.assertEqual(
            sorted(summary.keys()),
            ["batches", "budget_retained", "concurrency", "failed",
             "stop_reason", "submitted"],
        )
        self.assertIsInstance(summary["concurrency"], int)
        self.assertIsInstance(json.dumps(summary), str)


if __name__ == "__main__":
    unittest.main()
