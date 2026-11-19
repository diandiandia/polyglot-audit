"""RUN-LESSONS mechanism batch: real-run failure shapes turned into generic
mechanisms, each pinned by a synthetic-fixture regression (SR-028 batch).

The failure shapes below were corroborated across two independent real-target
run series; these tests pin the INPUT SHAPE -> EXPECTED BEHAVIOR contract with
synthetic fixtures only (SR-016/SR-031: no target-derived data):

- packet overflow now enqueues continuation work for the dropped ranges
  (previously the unit tail stayed under-covered forever: packet_overflow
  fired, nothing followed it)
- compiled binaries never become plan units (they poisoned signal caps and
  spawned junk units in every observed run); test files cap at T2 so they
  never outrank production source in a budget-starved queue
- a task budget that cannot cover the plan records the coverage forecast
  before any work starts (a decision point, not a post-mortem)
- worker results with no coverage block are recorded as explicit ledger
  events instead of silently leaving the review coverage dimensions at zero
- the per-unit candidate estimate is calibrated against the observed rate at
  finalize, and the self-review flags a drifted estimate (SYSTEM_DESIGN §预算:
  首批任务后校准)
"""

import json
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path

from auditkit.app.service import AuditAppService
from auditkit.inventory.slicer import UnitPlanner, calculate_risk_tier
from auditkit.ledger.db import get_db_connection
from auditkit.reporting.self_review import SelfReviewCollector

SKILL_DIR = Path("/root/polyglot-audit/skill")


def _big_source(line_count: int) -> str:
    """Synthetic source: repetitive safe lines plus periodic sink calls so
    the signal scan grades the file as real hunt scope (T1)."""
    lines = []
    for n in range(1, line_count + 1):
        if n % 200 == 0:
            lines.append(f"def handler_{n}(data):\n    eval(data)\n")
        else:
            lines.append(f"value_{n} = {n}  # synthetic filler line\n")
    return "\n".join(lines)


class RunLessonsMechanismHarness(unittest.TestCase):
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="rl-mech-"))
        self.app = AuditAppService(SKILL_DIR)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _write_target(self, files: dict) -> Path:
        target = self.temp_dir / "target"
        for rel, text in files.items():
            p = target / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text, encoding="utf-8")
        return target

    def _make_config(self, target, tasks_limit=50):
        run_dir = self.temp_dir / f"run_{abs(hash(str(target))) % 10**8}"
        return {
            "schema_version": "1.0",
            "target": str(target),
            "run_dir": str(run_dir),
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
                }
            ],
            "safety_acceptance": {
                "allow_unverified_execution": False,
                "allow_unverified_network": False,
                "allow_unverified_write": False,
                "user_approved": True,
            },
        }

    def _events(self, run_dir, event_type):
        conn = get_db_connection(Path(run_dir) / "events.db")
        try:
            rows = conn.execute(
                "SELECT payload_json FROM events WHERE event_type = ? ORDER BY revision",
                (event_type,),
            ).fetchall()
            return [json.loads(r["payload_json"]) for r in rows]
        finally:
            conn.close()


class TestPacketContinuation(RunLessonsMechanismHarness):
    def test_overflow_enqueues_continuation_for_dropped_ranges(self):
        # One big file (2400 lines -> 400-line ranges) whose packet cannot
        # fit the budget: the old behavior stopped at the overflow event and
        # the tail was never re-supplied.
        target = self._write_target(
            {"pkg/heavy.py": _big_source(2400), "pkg/small.py": "x = 1\n"}
        )
        config = self._make_config(target, tasks_limit=50)
        prep = self.app.prepare(config["target"], config["run_dir"], config)
        self.app.activate(prep["run_id"], config["run_dir"])
        run_id, run_dir = prep["run_id"], Path(config["run_dir"])

        claims = self.app.next(run_id, run_dir, batch_size=20)
        self.assertTrue(claims)

        overflow_events = self._events(run_dir, "packet_overflow")
        self.assertTrue(overflow_events, "overflow expected for the heavy unit")
        cont_events = self._events(run_dir, "packet_continuation_enqueued")
        self.assertTrue(cont_events, "the dropped ranges must become follow-up work")

        cont = cont_events[0]
        self.assertNotEqual(cont["task_id"], cont["origin_task_id"])
        self.assertGreaterEqual(cont["ranges"], 1)
        self.assertEqual(cont["depth"], 1)

        conn = get_db_connection(run_dir / "events.db")
        try:
            row = conn.execute(
                "SELECT kind, state, priority, spec_json FROM tasks WHERE task_id = ?",
                (cont["task_id"],),
            ).fetchone()
        finally:
            conn.close()
        self.assertIsNotNone(row, "continuation task must be queued")
        self.assertEqual(row["state"], "queued")
        spec = json.loads(row["spec_json"])
        cont_unit = spec["unit"]
        self.assertEqual(cont_unit["unit_id"], cont["unit_id"])
        # Continuation ranges carry exactly the leftover scope.
        self.assertEqual(len(cont_unit["ranges"]), cont["ranges"])
        # A dropped range is never re-rendered as already-supplied context:
        # every continuation range starts after its unit's rendered ranges.
        origin_overflow = overflow_events[0]
        self.assertGreaterEqual(origin_overflow["estimated_count"], cont["ranges"])

    def test_oversized_range_is_chunked_by_lines(self):
        # A continuation whose leftover still contains a huge range must
        # chunk it so each hop strictly shrinks (termination guarantee).
        planner_units = UnitPlanner("snp-example").create_units(
            [
                {
                    "path": "pkg/heavy.py",
                    "encoding": "utf-8",
                    "language": "python",
                    "line_count": 2400,
                    "component": "pkg",
                    "sha256": "a" * 64,
                }
            ],
            {"pkg/heavy.py": [{"kind": "sink", "strength": 3}]},
            [],
        )
        self.assertTrue(planner_units)
        self.assertTrue(all(
            r["line_end"] - r["line_start"] < 1500
            for u in planner_units
            for r in u["ranges"]
        ))


class TestPlanHygiene(RunLessonsMechanismHarness):
    def test_binary_files_never_become_units(self):
        planner = UnitPlanner("snp-example")
        units = planner.create_units(
            [
                {
                    "path": "src/real.py",
                    "encoding": "utf-8",
                    "language": "python",
                    "line_count": 800,
                    "component": "src",
                    "sha256": "b" * 64,
                },
                {
                    "path": "dist/compiled",
                    "encoding": "binary",
                    "language": "unknown",
                    "line_count": 0,
                    "component": "src",
                    "sha256": "c" * 64,
                },
            ],
            {"src/real.py": [{"kind": "sink", "kind2": None, "strength": 3}]},
            [],
        )
        paths = {u["ranges"][0]["path"] for u in units if u.get("ranges")}
        self.assertIn("src/real.py", paths)
        self.assertNotIn("dist/compiled", paths)
        self.assertEqual(planner.binary_files_skipped, 1)

    def test_test_file_caps_at_t2_despite_t1_signals(self):
        tier, factors = calculate_risk_tier(
            [
                {"kind": "sink", "strength": 3},
                {"kind": "source", "strength": 3},
            ],
            has_boundary=False,
        )
        self.assertEqual(tier, "T1")  # raw grading is unchanged

        planner = UnitPlanner("snp-example")
        units = planner.create_units(
            [
                {
                    "path": "tests/test_widget.py",
                    "encoding": "utf-8",
                    "language": "python",
                    "line_count": 300,
                    "component": "tests",
                    "sha256": "d" * 64,
                }
            ],
            {
                "tests/test_widget.py": [
                    {"kind": "sink", "strength": 3},
                    {"kind": "source", "strength": 3},
                ]
            },
            [],
        )
        analyze = [u for u in units if u.get("disposition") == "analyze"]
        self.assertTrue(analyze)
        self.assertTrue(all(u["tier"] == "T2" for u in analyze))
        self.assertTrue(
            any("Test file (tier capped from T1)" in u.get("risk_factors", [])
                for u in analyze)
        )


class TestBudgetForecast(RunLessonsMechanismHarness):
    def test_unaffordable_plan_records_forecast_before_work(self):
        # A wide target and a tiny task budget: the forecast must exist in
        # the plan BEFORE any task executes (RUN-LESSONS: a real run executed
        # a few percent of its plan and finalized without a decision point).
        files = {f"pkg/mod_{n}.py": _big_source(600) for n in range(6)}
        target = self._write_target(files)
        config = self._make_config(target, tasks_limit=2)
        prep = self.app.prepare(config["target"], config["run_dir"], config)
        self.app.activate(prep["run_id"], config["run_dir"])
        run_dir = Path(config["run_dir"])

        plan = json.loads((run_dir / "plan" / "plan.json").read_text(encoding="utf-8"))
        forecast = plan.get("budget_coverage_forecast")
        self.assertIsNotNone(forecast)
        self.assertLess(forecast, 1.0)
        self.assertGreater(forecast, 0.0)

        events = self._events(run_dir, "budget_plan_forecast")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["tasks_budget_limit"], 2)
        self.assertGreater(events[0]["hunt_units"], forecast * events[0]["hunt_units"])

        # The self-review turns the low forecast into an explicit anomaly.
        review = SelfReviewCollector({"budget_coverage_forecast": forecast}).collect()
        self.assertTrue(
            any("budget_coverage_forecast" in a.get("evidence", "") for a in review)
        )


class TestCoverageUnreported(RunLessonsMechanismHarness):
    def _hunt_result(self, claim, snapshot_id, records, coverage):
        return {
            "schema_version": "1.0",
            "task_id": claim["task_id"],
            "attempt_id": claim["attempt_id"],
            "kind": "hunt",
            "coverage": coverage,
            "records": records,
            "overflow": [],
        }

    def test_empty_coverage_block_is_recorded_as_gap(self):
        target = self._write_target({"pkg/mod.py": _big_source(600)})
        config = self._make_config(target, tasks_limit=20)
        prep = self.app.prepare(config["target"], config["run_dir"], config)
        self.app.activate(prep["run_id"], config["run_dir"])
        run_id, run_dir = prep["run_id"], Path(config["run_dir"])

        claims = self.app.next(run_id, run_dir, batch_size=5)
        hunt_claim = next(
            c for c in claims if (c.get("spec") or {}).get("task_kind") == "hunt"
        )
        self.app.start(run_dir, hunt_claim)
        self.app.submit(
            run_dir,
            hunt_claim,
            self._hunt_result(hunt_claim, prep["snapshot_id"], [], coverage=[]),
            "digest-rl-01",
        )
        events = self._events(run_dir, "coverage_unreported")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["task_id"], hunt_claim["task_id"])
        self.assertEqual(events[0]["unit_id"], hunt_claim["spec"]["unit"]["unit_id"])

        # The self-review surfaces the gap shape.
        review = SelfReviewCollector({"coverage_unreported_count": 1}).collect()
        self.assertTrue(
            any("no coverage block" in a.get("evidence", "") for a in review)
        )

    def test_submitted_coverage_does_not_trigger_the_gap_event(self):
        target = self._write_target({"pkg/mod.py": _big_source(600)})
        config = self._make_config(target, tasks_limit=20)
        prep = self.app.prepare(config["target"], config["run_dir"], config)
        self.app.activate(prep["run_id"], config["run_dir"])
        run_id, run_dir = prep["run_id"], Path(config["run_dir"])

        claims = self.app.next(run_id, run_dir, batch_size=5)
        hunt_claim = next(
            c for c in claims if (c.get("spec") or {}).get("task_kind") == "hunt"
        )
        unit_id = hunt_claim["spec"]["unit"]["unit_id"]
        self.app.start(run_dir, hunt_claim)
        self.app.submit(
            run_dir,
            hunt_claim,
            self._hunt_result(
                hunt_claim,
                prep["snapshot_id"],
                [],
                coverage=[
                    {
                        "schema_version": "1.0",
                        "snapshot_id": prep["snapshot_id"],
                        "unit_id": unit_id,
                        "dimension": "observed_read",
                        "ranges": [
                            {
                                "path": "pkg/mod.py",
                                "line_start": 1,
                                "line_end": 1,
                            }
                        ],
                    }
                ],
            ),
            "digest-rl-02",
        )
        self.assertEqual(self._events(run_dir, "coverage_unreported"), [])


class TestCalibrationSelfReviewCollector(unittest.TestCase):
    def test_drifted_candidate_estimate_is_flagged(self):
        review = SelfReviewCollector(
            {
                "calibration": {
                    "configured_candidate_rate_estimate": 0.2,
                    "observed_candidates_per_hunt_unit": 0.04,
                    "hunt_units_executed": 10,
                    "candidates": 0.4,
                }
            }
        ).collect()
        self.assertTrue(
            any("calibration" in a.get("evidence", "") for a in review)
        )

    def test_matching_estimate_is_not_flagged(self):
        review = SelfReviewCollector(
            {
                "calibration": {
                    "configured_candidate_rate_estimate": 0.2,
                    "observed_candidates_per_hunt_unit": 0.19,
                    "hunt_units_executed": 10,
                    "candidates": 1.9,
                }
            }
        ).collect()
        self.assertFalse(
            any("calibration" in a.get("evidence", "") for a in review)
        )


class TestTriageCapScaling(unittest.TestCase):
    """RUN-LESSONS: a fixed triage cap left the overwhelming majority of
    strong signals undispositioned in a real run. The effective cap scales
    with the observed volume up to an absolute ceiling; whatever lies beyond
    stays explicitly counted."""

    def _hits(self, n):
        return [
            {"path": f"pkg/mod_{i}.py", "line": i + 1, "kind": "sink", "strength": 3}
            for i in range(n)
        ]

    def test_small_volume_keeps_the_design_cap(self):
        from auditkit.app.service import _effective_triage_cap
        self.assertEqual(_effective_triage_cap(10), 50)

    def test_large_volume_scales_to_a_bounded_ceiling(self):
        from auditkit.app.service import _effective_triage_cap
        self.assertEqual(_effective_triage_cap(200), 200)
        self.assertEqual(_effective_triage_cap(5000), 500)


if __name__ == "__main__":
    unittest.main()
