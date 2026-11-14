"""Tests for the eight-category skill self-review collector (DSR-070 / SWR-014)."""

import unittest

from auditkit.reporting.self_review import CATEGORIES, SelfReviewCollector


def complete_run_stats():
    return {
        "total_tasks": 12,
        "stage_tasks": {"recon": 2, "hunt": 6, "verify": 3, "report": 1},
        "coverage_summary": {"unknown": False, "coverage_gaps": []},
        "cost_metrics": {"token_availability": "exact", "tasks_per_kloc": 4.5},
        "verdict_distribution": {"confirmed": 9, "needs_validation": 1, "unverified": 0},
        "knowledge_gaps": [],
        "knowledge_version": "1.0",
        "detected_languages": ["python", "go"],
        "uncovered_languages": [],
        "error_events": 0,
        "usage_missing_count": 0,
    }


def incomplete_run_stats():
    return {
        "total_tasks": 5,
        "stage_tasks": {"recon": 1, "hunt": 4, "verify": 0, "report": 0},
        "coverage_summary": {"unknown": False, "coverage_gaps": [{"path": "x.py", "lines": [1, 200]}]},
        "cost_metrics": {"token_availability": "unavailable", "unavailable_reason": "no host telemetry", "tasks_per_kloc": None},
        "verdict_distribution": {"confirmed": 1, "needs_validation": 4, "unverified": 2},
        "knowledge_gaps": ["ts-js-sinks"],
        "knowledge_version": "1.0",
        "detected_languages": ["typescript"],
        "uncovered_languages": ["ruby"],
        "error_events": 2,
        "usage_missing_count": 3,
    }


class TestSelfReview(unittest.TestCase):

    def assert_well_formed(self, anomalies):
        for a in anomalies:
            self.assertIn(a["category"], CATEGORIES)
            for field in ("category", "evidence", "impact", "recommendation", "unknown_note"):
                self.assertIn(field, a, f"anomaly missing field {field}: {a}")

    # ---------------------------------------------------------- complete run
    def test_complete_run_yields_no_anomalies(self):
        anomalies = SelfReviewCollector(complete_run_stats()).collect()
        self.assert_well_formed(anomalies)
        self.assertEqual(anomalies, [])

    # -------------------------------------------------------- incomplete run
    def test_incomplete_run_flags_expected_categories(self):
        anomalies = SelfReviewCollector(incomplete_run_stats()).collect()
        self.assert_well_formed(anomalies)
        categories = {a["category"] for a in anomalies}
        expected = {"flow", "coverage", "cost", "verification", "knowledge", "adaptation", "error", "usage_missing"}
        self.assertTrue(expected.issubset(categories), f"missing categories: {expected - categories}")
        # An unknown_note is allowed only where a sub-metric was genuinely
        # unavailable (host token telemetry here), never for wholesale
        # missing input.
        for a in anomalies:
            if a["unknown_note"] is not None:
                self.assertTrue(
                    "unavailable" in a["evidence"] or "non-computable" in a["evidence"],
                    f"unexpected unknown_note on anomaly with available data: {a}",
                )
        # Specific assertions on key detectors.
        by_cat = {a["category"]: a for a in anomalies}
        self.assertIn("coverage gaps", by_cat["coverage"]["evidence"])
        cost_evidence = " | ".join(a["evidence"] for a in anomalies if a["category"] == "cost")
        self.assertIn("unavailable", cost_evidence)
        self.assertIn("non-computable", cost_evidence)
        self.assertIn("'report': 0", by_cat["flow"]["evidence"])

    # ----------------------------------------------------- missing input data
    def test_missing_input_yields_unknown_anomalies_per_category(self):
        anomalies = SelfReviewCollector(None).collect()
        self.assert_well_formed(anomalies)
        self.assertEqual({a["category"] for a in anomalies}, set(CATEGORIES))
        for a in anomalies:
            self.assertTrue(a["unknown_note"], f"missing-data anomaly must carry unknown_note: {a}")
            self.assertIn("unavailable", a["evidence"])

    def test_partial_input_marks_only_missing_categories_unknown(self):
        stats = complete_run_stats()
        del stats["cost_metrics"]
        anomalies = SelfReviewCollector(stats).collect()
        self.assert_well_formed(anomalies)
        by_cat = {a["category"]: a for a in anomalies}
        self.assertIn("unknown_note", by_cat["cost"])
        self.assertTrue(by_cat["cost"]["unknown_note"])
        # Other categories evaluated normally: flow data was complete.
        self.assertNotIn("flow", by_cat)

    def test_each_detector_missing_subfield_yields_unknown(self):
        # Stats dict exists but lacks the keys each detector needs.
        stats = {"coverage_summary": None, "verdict_distribution": None}
        anomalies = SelfReviewCollector(stats).collect()
        self.assert_well_formed(anomalies)
        categories = {a["category"] for a in anomalies}
        for expected in ("flow", "coverage", "cost", "verification", "knowledge", "adaptation", "error", "usage_missing"):
            self.assertIn(expected, categories)

    def test_high_unverified_ratio_flags_verification(self):
        stats = complete_run_stats()
        stats["verdict_distribution"] = {"confirmed": 1, "needs_validation": 5, "unverified": 4}
        anomalies = SelfReviewCollector(stats).collect()
        by_cat = {a["category"]: a for a in anomalies}
        self.assertIn("verification", by_cat)
        self.assertIn("9/10", by_cat["verification"]["evidence"])


if __name__ == "__main__":
    unittest.main()
