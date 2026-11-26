"""Real-concurrency contract tests for run_dispatch_loop (DSR-064 / HST -> LED).

Covers the parallel dispatch model that the serial batch loop could not have:
- Per-task lifecycle: the claim(batch_size=1) happens immediately before each
  task's own execution, so no attempt ever holds a lease while queued behind
  other work; even executions that outlive the lease never go stale.
- Parallel execution: independent tasks run concurrently on the worker pool
  under the in-flight cap taken from the ConcurrencyController's CURRENT value.
- Per-attempt usage attribution (P0 regression core): execute_fn returns the
  (worker_result, usage) envelope — the usage captured by the SAME execution
  — so two tasks overlapping through each other's completion tail each settle
  their OWN usage row; the removed shared adapter slot swapped attribution.
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
from unittest import mock

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


def _usage_for(claim, value=20, availability="exact"):
    """Per-attempt usage dict, as the worker execution envelope returns it."""
    return {
        "schema_version": "1.0",
        "attempt_id": claim["attempt_id"],
        "dimension": "tokens",
        "availability": availability,
        "value": value,
        "unit": "tokens",
        "source": "host_cli_report",
    }


class _FakeAdapter:
    """Minimal stand-in for a host driver adapter (dispatch attributes only).

    Carries no usage state: under the per-task usage envelope the usage
    travels with each execution's return value, never on the adapter.
    """

    def __init__(self, max_retries=2, backoff_base=0.01, backoff_max=0.05):
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
            return self._worker_result(claim), _usage_for(claim)

        adapter = _FakeAdapter()
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
    # b2. P0 regression core: overlapping completions keep their own usage
    # ------------------------------------------------------------------
    def test_overlapping_completions_bind_usage_to_their_own_attempt(self):
        """P0 usage-attribution regression: tasks whose executions overlap
        through each other's completion tail must each settle the usage
        captured for THEIR OWN task. The per-task (result, usage) envelope
        replaced the shared adapter slot, which cross-attributed attempts
        whenever two workers finished within each other's execute_fn tail;
        the ledger must show each attempt carrying its own value."""
        target = self._signal_target(2)
        config = self._make_config(target)
        prep = self._prepared(config)
        run_id, run_dir = prep["run_id"], Path(config["run_dir"])

        controller = ConcurrencyController(initial=4, maximum=4)
        # Per-task usage values are asymmetric so any attribution swap is
        # loud: the first-seen task settles 17, the second 27, the third 37.
        expected: dict = {}
        values_lock = threading.Lock()
        hunts_arrived = threading.Barrier(2, timeout=10)
        live = {"now": 0, "max": 0}
        live_lock = threading.Lock()

        def execute_fn(claim):
            with live_lock:
                live["now"] += 1
                live["max"] = max(live["max"], live["now"])
            with values_lock:
                if claim["task_id"] not in expected:
                    expected[claim["task_id"]] = 10 * (len(expected) + 1) + 7
            kind = (claim.get("spec") or {}).get("task_kind") or "hunt"
            if kind != "recon":
                # Hold BOTH hunts open until they are executing at the same
                # time, then release them together: their completions (and
                # submit tails) interleave — the exact interleaving that used
                # to swap usage through the shared adapter slot.
                try:
                    hunts_arrived.wait()
                except threading.BrokenBarrierError:
                    pass
            with live_lock:
                live["now"] -= 1
            return self._worker_result(claim), _usage_for(
                claim, value=expected[claim["task_id"]]
            )

        summary = self.app.run_dispatch_loop(
            run_id, run_dir, execute_fn, adapter=_FakeAdapter(), controller=controller
        )
        self.assertEqual(summary["stop_reason"], "queue_drained")
        self.assertEqual(summary["submitted"], 3)
        self.assertEqual(summary["failed"], 0)
        # The overlap actually happened (the test cannot pass vacuously).
        self.assertGreaterEqual(live["max"], 2, f"tasks did not overlap: {live}")
        self.assertEqual(len(expected), 3)
        self.assertEqual(sorted(expected.values()), [17, 27, 37])

        conn = self._db(run_dir)
        try:
            rows = conn.execute(
                "SELECT u.attempt_id, u.value, u.availability, a.task_id "
                "FROM usage_records u "
                "JOIN attempts a ON a.attempt_id = u.attempt_id"
            ).fetchall()
        finally:
            conn.close()
        # One tokens row per attempt, bound to the attempt that executed the
        # task, carrying THAT task's value — never a swapped one.
        self.assertEqual(len(rows), 3)
        by_task = {r["task_id"]: (r["value"], r["availability"]) for r in rows}
        self.assertEqual(
            by_task,
            {task_id: (value, "exact") for task_id, value in expected.items()},
            f"usage attribution swapped across overlapping attempts: {by_task}",
        )

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
        # Budget of one pinned task (budget_autosize=False: fault-injection
        # escape hatch, DA-10): after the recon consumes it, the queued hunts
        # can never be dispatched.
        config = self._make_config(target, tasks_limit=1)
        config["budget_autosize"] = False
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

    def _plan_target_with_candidates(self, n_files=4):
        """Target + worker fn whose hunt submissions each produce one
        distinct candidate, so the ANA->LED wiring enqueues verify tasks
        mid-loop and the DA-06 decision-3 verification exemption is
        exercised against real queued verification work."""
        target = self._signal_target(n_files)

        def execute_fn(claim):
            kind = (claim.get("spec") or {}).get("task_kind") or "hunt"
            if kind == "hunt":
                unit_path = (
                    (((claim.get("spec") or {}).get("unit") or {}).get("ranges") or [{}])[0]
                    .get("path", "src/unknown.py")
                )
                cand = {
                    "schema_version": "1.0",
                    "candidate_id": f"cand-{claim['task_id'][-6:]}",
                    "issue": "py-01",
                    "source": {"path": unit_path, "line": 3, "symbol": "handle", "kind": "http"},
                    "sink": {"path": unit_path, "line": 5, "symbol": "restore", "kind": "deserialization"},
                    "steps": [
                        {"path": unit_path, "line": 3, "role": "source", "note": "n1"},
                        {"path": unit_path, "line": 5, "role": "sink", "note": "n2"},
                    ],
                    "guard_analysis": "none",
                    "impact_claim": "RCE",
                    "open_questions": [],
                }
                return {
                    "schema_version": "1.0",
                    "task_id": claim["task_id"],
                    "attempt_id": claim["attempt_id"],
                    "kind": "hunt",
                    "coverage": [],
                    "records": [cand],
                    "overflow": [],
                }
            return {
                "schema_version": "1.0",
                "task_id": claim["task_id"],
                "attempt_id": claim["attempt_id"],
                "kind": kind,
                "coverage": [],
                "records": [],
                "overflow": [],
            }

        return target, execute_fn

    def test_verify_dispatch_continues_after_plan_cap(self):
        """DA-06 decision 3: the caller plan cap (max_batches) bounds
        hunt/recon only. Once it is reached, queued verification still
        dispatches to completion (RUN-LESSONS: a shared counter ended
        budget-first real runs with every candidate unverified)."""
        target, execute_fn = self._plan_target_with_candidates(4)
        config = self._make_config(target)
        prep = self._prepared(config)
        run_id, run_dir = prep["run_id"], Path(config["run_dir"])

        summary = self.app.run_dispatch_loop(
            run_id, run_dir, execute_fn,
            adapter=_FakeAdapter(), max_batches=3,
        )
        self.assertEqual(summary["dispatched_plan"], 3)
        self.assertGreaterEqual(summary["dispatched_verify"], 1)
        self.assertEqual(
            summary["batches"],
            summary["dispatched_plan"] + summary["dispatched_verify"],
        )
        self.assertIsNone(summary["stop_reason"])
        conn = self._db(run_dir)
        try:
            queued = conn.execute(
                "SELECT count(*) AS cnt FROM tasks WHERE state = 'queued'"
            ).fetchone()["cnt"]
        finally:
            conn.close()
        self.assertGreater(queued, 0, "plan cap must leave planned hunt work queued")

    def test_max_verify_batches_caps_verification_family(self):
        """DA-06 open question 2: verification is boundable through its own
        caller cap; reaching it stops verification dispatch the same way the
        plan cap stops plan-scope work, with the remainder queued and the
        stop attributed to the cap (stop_reason None)."""
        target, execute_fn = self._plan_target_with_candidates(4)
        config = self._make_config(target)
        prep = self._prepared(config)
        run_id, run_dir = prep["run_id"], Path(config["run_dir"])

        summary = self.app.run_dispatch_loop(
            run_id, run_dir, execute_fn,
            adapter=_FakeAdapter(), max_batches=None, max_verify_batches=1,
        )
        self.assertEqual(summary["dispatched_verify"], 1)
        self.assertIsNone(summary["stop_reason"])
        conn = self._db(run_dir)
        try:
            queued_verify = conn.execute(
                "SELECT count(*) AS cnt FROM tasks WHERE state = 'queued' AND kind = 'verify'"
            ).fetchone()["cnt"]
        finally:
            conn.close()
        self.assertGreater(queued_verify, 0, "verify cap must leave verification queued")

    def test_summary_contract_keys_are_stable_for_cli_consumers(self):
        target = self._signal_target(1)
        config = self._make_config(target)
        prep = self._prepared(config)
        summary = self.app.run_dispatch_loop(
            prep["run_id"], Path(config["run_dir"]), self._worker_result,
            adapter=_FakeAdapter(),
        )
        # The dispatch summary embedded by `audit run` keeps its documented key
        # set; consumers read submitted/failed/budget_retained/concurrency/
        # stop_reason/batches, plus the DA-06 decision-3 family split
        # (dispatched_plan / dispatched_verify) that makes the verification
        # exemption auditable.
        self.assertEqual(
            sorted(summary.keys()),
            ["batches", "budget_retained", "concurrency", "dispatched_plan",
             "dispatched_verify", "failed", "stop_reason", "submitted"],
        )
        self.assertEqual(summary["batches"],
                         summary["dispatched_plan"] + summary["dispatched_verify"])
        self.assertIsInstance(summary["concurrency"], int)
        self.assertIsInstance(json.dumps(summary), str)

    # ------------------------------------------------------------------
    # g. unexpected submit failures are task-scoped, never loop-fatal
    # ------------------------------------------------------------------
    def test_unexpected_submit_exception_is_task_scoped_not_loop_fatal(self):
        """RUN-LESSONS L-06 discipline extended to the whole submit /
        verify-enqueue path: an unexpected exception while accepting a
        result (e.g. a real-world candidate shape an enqueue helper did not
        expect) degrades to a task-scoped retryable failure. It must never
        escape the worker future and kill the dispatch loop; the task is
        requeued with a fresh generation and completes."""
        target = self._signal_target(2)
        config = self._make_config(target)
        prep = self._prepared(config)
        run_id, run_dir = prep["run_id"], Path(config["run_dir"])

        real_submit = AuditAppService.submit
        state = {"crashed": False}

        def submit_crashing_once(self, run_dir, claim, worker_result, digest, usage=None):
            if not state["crashed"]:
                state["crashed"] = True
                raise RuntimeError("unexpected real-world candidate shape")
            return real_submit(self, run_dir, claim, worker_result, digest, usage=usage)

        def execute_fn(claim):
            return self._worker_result(claim), _usage_for(claim)

        with mock.patch.object(AuditAppService, "submit", submit_crashing_once):
            summary = self.app.run_dispatch_loop(
                run_id, run_dir, execute_fn,
                adapter=_FakeAdapter(), controller=ConcurrencyController(initial=1),
            )

        # The loop survived and drained: the crashed attempt's task was
        # requeued with a fresh generation and completed on its next try.
        self.assertEqual(summary["stop_reason"], "queue_drained")
        self.assertGreaterEqual(summary["failed"], 1)
        conn = self._db(run_dir)
        try:
            done_rows = conn.execute(
                "SELECT count(*) AS cnt FROM tasks WHERE state = 'done'"
            ).fetchone()["cnt"]
            quarantined = conn.execute(
                "SELECT count(*) AS cnt FROM tasks WHERE state = 'quarantined'"
            ).fetchone()["cnt"]
        finally:
            conn.close()
        # recon + 2 hunts, including the task that survived its crash.
        self.assertEqual(done_rows, 3)
        self.assertEqual(quarantined, 0)

    # ------------------------------------------------------------------
    # h. circuit-breaker trips pause the run fail-safe, never cascade
    # ------------------------------------------------------------------
    def test_breaker_trip_pauses_run_and_requeues_task_without_quarantine(self):
        """RUN-LESSONS L-02, realized twice in one bounded real run: a
        wedged adapter instance can never reset (it raises before
        attempting), so reporting its breaker errors as non-retryable
        mass-quarantined every task it touched during a transient host
        outage. The breaker contract is failure-driven slowdown: a trip
        must pause the run fail-safe and requeue the touched task, never
        quarantine it."""
        target = self._signal_target(2)
        config = self._make_config(target)
        prep = self._prepared(config)
        run_id, run_dir = prep["run_id"], Path(config["run_dir"])

        def execute_fn(claim):
            exc = HostFailureError(
                "Circuit breaker tripped: 3 consecutive Claude host failures",
                retryable=False,
            )
            exc.breaker_tripped = True
            raise exc

        summary = self.app.run_dispatch_loop(
            run_id, run_dir, execute_fn,
            adapter=_FakeAdapter(), controller=ConcurrencyController(initial=1),
        )

        # The loop stopped on the pause (fail-safe), not on a queue drain.
        self.assertEqual(summary["stop_reason"], "paused_or_blocked")

        conn = self._db(run_dir)
        try:
            state = conn.execute(
                "SELECT state FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone()["state"]
            task_states = dict(conn.execute(
                "SELECT state, count(*) FROM tasks GROUP BY state"
            ).fetchall())
            gens = dict(conn.execute(
                "SELECT generation, count(*) FROM tasks WHERE state='queued' GROUP BY generation"
            ).fetchall())
            reasons = [r[0] for r in conn.execute(
                "SELECT payload_json FROM events WHERE event_type='run_paused'"
            ).fetchall()]
        finally:
            conn.close()

        self.assertEqual(state, "paused")
        # Every task survived: requeued, nothing quarantined.
        self.assertEqual(task_states.get("quarantined", 0), 0)
        self.assertGreater(task_states.get("queued", 0), 0)
        # The tripped task was requeued with a bumped generation (tasks
        # start at generation 0; one fail-safe requeue lands on 1).
        self.assertIn(1, gens)
        # The pause reason names the fail-safe breaker path.
        self.assertTrue(any("fail-safe pause" in r for r in reasons))


if __name__ == "__main__":
    unittest.main()
