"""Stop-reason disambiguation for budget stops (O-04, run lessons).

A real run stopped dispatch while queued tasks remained and the driver
labeled the stop ``paused_or_blocked`` ("no cause recorded") even though the
cause WAS recorded: the tasks budget refused a HUNT claim because the
verification reserve floor (DSR-020 ``verify_reserve_ratio``) protected the
remaining units for verify work — the hunt-visible pool was empty while the
dimension as a whole still had room. The stop reason must say which budget
mechanism stopped dispatch:

- ``verification_reserve_exhausted``: a budget_exhausted event whose ledger
  reason names the verify protection, while the tasks dimension still has
  room for a non-hunt claim (the floor case, O-04);
- ``budget_exhausted``: the plain case — the refusal fired at available == 0,
  whatever the refused claim's kind was;
- ``paused_or_blocked``: stays reserved for stops with no recorded cause.

The disambiguation consumes the claim path's own budget_exhausted event
payload (dimension + reason, already recorded by task_queue.claim) plus the
budget summary — it never re-derives the refusal.
"""

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

_SKILL_SCRIPTS = Path(__file__).resolve().parents[2] / "skill" / "scripts"
if str(_SKILL_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SKILL_SCRIPTS))

from auditkit.app.service import AuditAppService  # noqa: E402
from auditkit.hosts.concurrency import ConcurrencyController  # noqa: E402
from auditkit.ledger.db import get_db_connection  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
SKILL_DIR = REPO_ROOT / "skill"

# Each file carries two strong sink signals, so every file becomes a T1
# analyze-disposition hunt unit (DSR-056) and the queue is hunt-dominated —
# the shape that exposes the verify-reserve floor.
SIGNAL_FILE_TEMPLATE = (
    "import pickle\n\n\n"
    "def handle_payload_{i}(untrusted_payload):\n"
    "    obj = pickle.loads(untrusted_payload)\n"
    "    eval(user_expression)\n"
    "    return obj\n"
)


class _FakeAdapter:
    """Minimal host driver adapter stand-in (dispatch attributes only)."""

    max_retries = 2
    backoff_base = 0.01
    backoff_max = 0.05


class TestBudgetStopReason(unittest.TestCase):
    """Hunt claims refused by the verification reserve floor stop dispatch
    with an honest budget-class stop reason, not paused_or_blocked."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="budget-stop-"))
        self.app = AuditAppService(SKILL_DIR)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # ------------------------------------------------------------- helpers
    def _target(self, n_files: int) -> Path:
        target = self.temp_dir / "target"
        (target / "src").mkdir(parents=True)
        for i in range(n_files):
            (target / "src" / f"mod_{i}.py").write_text(
                SIGNAL_FILE_TEMPLATE.format(i=i), encoding="utf-8"
            )
        return target

    def _config(self, target: Path, tasks_limit: int, autosize: bool = True) -> dict:
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
            ],
            "budget_autosize": autosize,
            "safety_acceptance": {
                "allow_unverified_execution": False,
                "allow_unverified_network": False,
                "allow_unverified_write": False,
                "user_approved": True,
            },
        }

    @staticmethod
    def _worker_result(claim):
        """Synthetic worker output that submits every claim successfully."""
        kind = (claim.get("spec") or {}).get("task_kind") or "hunt"
        records = []
        if kind == "recon":
            records = [{
                "schema_version": "1.0",
                "guard_id": "guard-shared",
                "status": "observed",
                "mechanism": "shared synthetic guard",
                "anchors": [],
                "applicability": "",
                "exceptions": [],
            }]
        return {
            "schema_version": "1.0",
            "task_id": claim["task_id"],
            "attempt_id": claim["attempt_id"],
            "kind": kind,
            "coverage": [],
            "records": records,
            "overflow": [],
        }

    def _budget_exhausted_payloads(self, run_dir):
        conn = get_db_connection(Path(run_dir) / "events.db")
        try:
            rows = conn.execute(
                "SELECT payload_json FROM events WHERE event_type = 'budget_exhausted'"
            ).fetchall()
        finally:
            conn.close()
        return [json.loads(r["payload_json"]) for r in rows]

    def _budget_summary_row(self, run_dir):
        conn = get_db_connection(Path(run_dir) / "events.db")
        try:
            row = conn.execute(
                "SELECT limit_val, settled, reserved FROM budget_dimensions "
                "WHERE dimension = 'tasks'"
            ).fetchone()
        finally:
            conn.close()
        return dict(row)

    # ------------------------------------------------ the O-04 floor case
    def test_hunt_verify_reserve_floor_reports_budget_class_stop(self):
        """Dispatch stopped by the verification reserve floor (hunt claims
        refused while the dimension still had room) is labeled
        verification_reserve_exhausted — never paused_or_blocked."""
        # limit 4, floor int(4 * 0.3) = 1: recon + 2 hunts settle (3), the
        # hunt-visible pool then empties while 1 unit stays reserved for
        # verify — dispatch stops with hunts still queued.
        target = self._target(6)
        config = self._config(target, tasks_limit=4, autosize=False)
        prep = self.app.prepare(target, Path(config["run_dir"]), config)
        run_id, run_dir = prep["run_id"], Path(config["run_dir"])
        self.app.activate(run_id, run_dir)

        summary = self.app.run_dispatch_loop(
            run_id, run_dir, self._worker_result,
            adapter=_FakeAdapter(),
            controller=ConcurrencyController(initial=2, maximum=2),
        )

        queued = self._queued_count(run_dir)
        self.assertGreater(queued, 0, "scenario must stop with hunt work remaining")
        payloads = self._budget_exhausted_payloads(run_dir)
        self.assertTrue(payloads, "the claim path must record its refusal")
        self.assertTrue(
            any("protected for verify" in str(p.get("reason", "")) for p in payloads),
            "the recorded refusal must be the verify-floor refusal",
        )
        summary_row = self._budget_summary_row(run_dir)
        available = summary_row["limit_val"] - (summary_row["settled"] + summary_row["reserved"])
        self.assertGreater(
            available, 0,
            "scenario must leave non-hunt room so the floor (not a spent budget) caused the stop",
        )
        self.assertEqual(
            summary["stop_reason"], "verification_reserve_exhausted",
            f"floor stop must not be mislabeled; summary={summary}",
        )

    # ------------------------------------------------ the plain case
    def test_spent_budget_still_reports_budget_exhausted(self):
        """A refusal at available == 0 stays the plain budget_exhausted stop,
        even when the refused claim was a hunt whose reason text mentions
        the (zero-sized) protection."""
        target = self._target(4)
        config = self._config(target, tasks_limit=1, autosize=False)
        prep = self.app.prepare(target, Path(config["run_dir"]), config)
        run_id, run_dir = prep["run_id"], Path(config["run_dir"])
        self.app.activate(run_id, run_dir)

        summary = self.app.run_dispatch_loop(
            run_id, run_dir, self._worker_result, adapter=_FakeAdapter(),
        )

        payloads = self._budget_exhausted_payloads(run_dir)
        self.assertTrue(payloads, "the claim path must record its refusal")
        summary_row = self._budget_summary_row(run_dir)
        available = summary_row["limit_val"] - (summary_row["settled"] + summary_row["reserved"])
        self.assertEqual(available, 0, "scenario must spend the whole budget")
        self.assertEqual(summary["stop_reason"], "budget_exhausted")

    # ------------------------------------------------ the no-cause case
    def test_pause_stop_without_budget_events_stays_paused_or_blocked(self):
        """Without a recorded cause (paused run), the stop reason stays
        paused_or_blocked — the new floor label must not over-reach."""
        target = self._target(2)
        config = self._config(target, tasks_limit=30)
        prep = self.app.prepare(target, Path(config["run_dir"]), config)
        run_id, run_dir = prep["run_id"], Path(config["run_dir"])
        self.app.activate(run_id, run_dir)
        self.app.pause(run_id, run_dir, reason="stop-reason disambiguation test")

        summary = self.app.run_dispatch_loop(
            run_id, run_dir, self._worker_result, adapter=_FakeAdapter(),
        )
        self.assertEqual(summary["batches"], 0)
        self.assertEqual(summary["stop_reason"], "paused_or_blocked")
        self.assertEqual(self._budget_exhausted_payloads(run_dir), [])

    def _queued_count(self, run_dir) -> int:
        conn = get_db_connection(Path(run_dir) / "events.db")
        try:
            return conn.execute(
                "SELECT count(*) AS c FROM tasks WHERE state = 'queued'"
            ).fetchone()["c"]
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
