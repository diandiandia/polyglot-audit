"""Cost accounting semantics tests (DSR-050 / SWR-020).

Validates the fixed statistical口径 of CostTracker:

- exact / estimated / unavailable token telemetry is attributed explicitly
  and never defaulted to zero;
- numerators and denominators are independently recomputable from the
  recorded inputs (15% / 60% / 1.3 style constants remain hypotheses under
  evaluation — nothing here hard-codes them as targets);
- missing-rate scenarios surface as None + reason, not fabricated numbers;
- a zero denominator makes a ratio non-computable (None), never 0.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
SKILL_SCRIPTS = ROOT_DIR / "skill" / "scripts"
if str(SKILL_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SKILL_SCRIPTS))

from auditkit.reporting.cost import CostTracker  # noqa: E402


class TestExactTelemetry(unittest.TestCase):

    def test_exact_tokens_are_recomputable(self):
        tracker = CostTracker()
        tracker.set_tokens(24_000, source="exact")
        metrics = tracker.compute_metrics(total_lines=6_000, confirmed_findings_count=4)

        # Numerator/denominator recomputation: tokens_per_kloc == tokens / (lines/1000)
        self.assertEqual(metrics["total_tokens"], 24_000)
        self.assertEqual(metrics["token_availability"], "exact")
        self.assertIsNone(metrics["unavailable_reason"])
        expected = round(24_000 / (6_000 / 1000.0), 2)
        self.assertEqual(metrics["tokens_per_kloc"], expected)

    def test_task_counts_recomputable(self):
        tracker = CostTracker()
        for _ in range(3):
            tracker.record_task("recon")
        for _ in range(5):
            tracker.record_task("hunt")
        for _ in range(2):
            tracker.record_task("verify", is_retry=True)
        tracker.record_task("report")
        metrics = tracker.compute_metrics(total_lines=10_000, confirmed_findings_count=2)

        self.assertEqual(metrics["total_tasks"], 11)
        self.assertEqual(metrics["retries"], 2)
        self.assertEqual(metrics["stage_tasks"], {"recon": 3, "hunt": 5, "verify": 2, "report": 1})
        # sum of stage tasks == total_tasks (internal consistency)
        self.assertEqual(sum(metrics["stage_tasks"].values()), metrics["total_tasks"])
        self.assertEqual(metrics["tasks_per_kloc"], round(11 / 10.0, 2))
        self.assertEqual(metrics["tasks_per_finding"], round(11 / 2, 2))


class TestEstimatedTelemetry(unittest.TestCase):

    def test_estimated_tokens_are_flagged_as_estimated(self):
        tracker = CostTracker()
        tracker.set_tokens(12_345, source="estimated")
        metrics = tracker.compute_metrics(total_lines=5_000, confirmed_findings_count=1)
        self.assertEqual(metrics["token_availability"], "estimated")
        # The estimate is still attributable (not silently promoted to exact)
        self.assertEqual(metrics["total_tokens"], 12_345)
        self.assertEqual(metrics["tokens_per_kloc"], round(12_345 / 5.0, 2))

    def test_estimated_is_not_reported_as_exact(self):
        tracker = CostTracker()
        tracker.set_tokens(999, source="estimated")
        metrics = tracker.compute_metrics(total_lines=1_000, confirmed_findings_count=1)
        self.assertNotEqual(metrics["token_availability"], "exact")


class TestUnavailableTelemetry(unittest.TestCase):

    def test_missing_tokens_stay_none_with_reason(self):
        tracker = CostTracker()  # never given token data
        metrics = tracker.compute_metrics(total_lines=2_000, confirmed_findings_count=1)
        self.assertIsNone(metrics["total_tokens"], "unknown token count must not default to 0")
        self.assertEqual(metrics["token_availability"], "unavailable")
        self.assertTrue(metrics["unavailable_reason"], "missing data needs a recorded reason")
        self.assertIsNone(metrics["tokens_per_kloc"])

    def test_missing_tokens_never_writen_as_zero(self):
        tracker = CostTracker()
        metrics = tracker.compute_metrics(total_lines=1_000, confirmed_findings_count=1)
        self.assertNotEqual(metrics.get("total_tokens"), 0)
        self.assertNotEqual(metrics.get("tokens_per_kloc"), 0)


class TestZeroDenominators(unittest.TestCase):

    def test_zero_findings_makes_per_finding_non_computable(self):
        tracker = CostTracker()
        tracker.record_task("hunt")
        metrics = tracker.compute_metrics(total_lines=1_000, confirmed_findings_count=0)
        self.assertIsNone(
            metrics["tasks_per_finding"],
            "0 findings is a zero denominator: ratio must be None, not 0",
        )

    def test_zero_lines_scenario_does_not_fabricate_findings_ratio(self):
        tracker = CostTracker()
        tracker.record_task("recon")
        metrics = tracker.compute_metrics(total_lines=0, confirmed_findings_count=0)
        self.assertIsNone(metrics["tasks_per_finding"])
        self.assertIsNone(metrics["tokens_per_kloc"])
        # Task accounting itself stays honest even with no corpus lines.
        self.assertEqual(metrics["total_tasks"], 1)


class TestMissingRateScenarios(unittest.TestCase):

    def test_partial_stage_data_is_visible(self):
        """A run that only recorded some stages must not look complete."""
        tracker = CostTracker()
        tracker.record_task("hunt")
        metrics = tracker.compute_metrics(total_lines=1_000, confirmed_findings_count=1)
        zero_stages = [s for s, n in metrics["stage_tasks"].items() if n == 0]
        # The unrecorded stages remain visible as zeros (recorded-as-zero is
        # honest here: absence of a recorded task IS a zero count of tasks),
        # while token absence (unobservable value) stays None.
        self.assertEqual(len(zero_stages), 3)
        self.assertIsNone(metrics["total_tokens"])

    def test_retry_numerator_separable_from_base_count(self):
        tracker = CostTracker()
        tracker.record_task("verify", is_retry=True)
        tracker.record_task("verify", is_retry=True)
        tracker.record_task("verify")
        metrics = tracker.compute_metrics(total_lines=500, confirmed_findings_count=1)
        self.assertEqual(metrics["retries"], 2)
        self.assertEqual(metrics["total_tasks"], 3)
        # retries are part of the numerator, never hidden
        self.assertEqual(sum(metrics["stage_tasks"].values()), 3)


if __name__ == "__main__":
    unittest.main()
