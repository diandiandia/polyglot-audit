"""DSR-024: guard evaluation must never conflate the three guard scenarios."""

import unittest

from auditkit.analysis.guards import GuardRecord, evaluate_guards
from auditkit.contracts.errors import InvalidInputError


def _candidate(sink_path: str = "app/db.py") -> dict:
    return {
        "candidate_id": "cand-1",
        "source": {"path": "app/web.py", "line": 1, "kind": "http"},
        "sink": {"path": sink_path, "line": 20, "symbol": "query"},
        "steps": [
            {"path": "app/web.py", "line": 1, "role": "source"},
            {"path": sink_path, "line": 20, "role": "sink"},
        ],
    }


class TestGuardEvaluation(unittest.TestCase):

    def test_registered_guard_conditions_unmet_does_not_exempt(self):
        """Scenario 1: observed guard applies but conditions unmet -> not exempt."""
        guard = GuardRecord(
            guard_id="g-input-filter",
            status="observed",
            mechanism="Global input filter",
            anchors=[],  # no verifiable anchors -> conditions unmet
            applicability="app/db.py",
            exceptions=[],
        )
        decision = evaluate_guards(_candidate(), [guard])
        self.assertFalse(decision["exempt"])
        self.assertEqual(decision["status"], "not_exempt")
        self.assertTrue(
            any("conditions are unmet" in r for r in decision["reasons"]),
            decision["reasons"],
        )

    def test_explicit_exception_grants_exemption_with_evidence(self):
        """Scenario 2: applicability/exceptions covering the path -> exempt + evidence."""
        guard = GuardRecord(
            guard_id="g-sanitizer",
            status="observed",
            mechanism="Parameterized-query-only wrapper",
            anchors=[{"path": "app/db.py", "line_start": 10, "line_end": 12}],
            applicability="app/db.py",
            exceptions=["app/db.py"],  # explicit exception covering this path
        )
        decision = evaluate_guards(_candidate(), [guard])
        self.assertTrue(decision["exempt"])
        self.assertEqual(decision["status"], "exempt")
        self.assertEqual(len(decision["evidence"]), 1)
        self.assertEqual(decision["evidence"][0]["guard_id"], "g-sanitizer")
        self.assertEqual(decision["evidence"][0]["type"], "explicit_exception")
        self.assertEqual(decision["evidence"][0]["covered_path"], "app/db.py")

    def test_unknown_guard_stays_unknown_and_does_not_exempt(self):
        """Scenario 3: unknown status -> not exempt, status stays unknown."""
        guard = GuardRecord(
            guard_id="g-waf",
            status="unknown",
            mechanism="Possibly a WAF",
            applicability="app/db.py",
        )
        decision = evaluate_guards(_candidate(), [guard])
        self.assertFalse(decision["exempt"])
        self.assertEqual(decision["status"], "unknown")
        self.assertTrue(any("unknown" in r for r in decision["reasons"]))

    def test_unknown_dominates_even_when_exception_exists(self):
        """An unknown guard must never be promoted to a global exemption."""
        exc_guard = GuardRecord(
            guard_id="g-sanitizer",
            status="observed",
            mechanism="Sanitizer",
            anchors=[{"path": "app/db.py", "line_start": 1, "line_end": 2}],
            applicability="app/db.py",
            exceptions=["app/db.py"],
        )
        unknown_guard = GuardRecord(
            guard_id="g-waf",
            status="unknown",
            mechanism="Possibly a WAF",
            applicability="app/db.py",
        )
        decision = evaluate_guards(_candidate(), [exc_guard, unknown_guard])
        self.assertFalse(decision["exempt"])
        self.assertEqual(decision["status"], "unknown")

    def test_not_found_guard_has_no_effect(self):
        guard = GuardRecord(
            guard_id="g-absent",
            status="not_found",
            mechanism="Searched, not present",
        )
        decision = evaluate_guards(_candidate(), [guard])
        self.assertFalse(decision["exempt"])
        self.assertEqual(decision["status"], "not_exempt")

    def test_applicability_not_covering_never_grants_blanket_exemption(self):
        """A guard whose applicability misses the candidate grants nothing global."""
        guard = GuardRecord(
            guard_id="g-elsewhere",
            status="observed",
            mechanism="Sanitizer for other modules",
            anchors=[{"path": "other.py", "line_start": 1, "line_end": 2}],
            applicability="other_module/",
            exceptions=["other_module/safe.py"],
        )
        decision = evaluate_guards(_candidate(), [guard])
        self.assertFalse(decision["exempt"])
        self.assertEqual(decision["status"], "not_exempt")
        self.assertTrue(
            any("does not cover" in r for r in decision["reasons"]),
            decision["reasons"],
        )

    def test_accepts_dict_records_and_rejects_invalid_status(self):
        as_dict = {
            "guard_id": "g-dict",
            "status": "observed",
            "mechanism": "Filter",
            "applicability": "app/db.py",
        }
        decision = evaluate_guards(_candidate(), [as_dict])
        self.assertEqual(decision["evaluated_guards"], ["g-dict"])

        bad = {"guard_id": "g-bad", "status": "assumed", "mechanism": "x"}
        with self.assertRaises(InvalidInputError):
            evaluate_guards(_candidate(), [bad])

    def test_no_guards_registered(self):
        decision = evaluate_guards(_candidate(), [])
        self.assertFalse(decision["exempt"])
        self.assertEqual(decision["status"], "not_exempt")
        self.assertTrue(any("No guards registered" in r for r in decision["reasons"]))


if __name__ == "__main__":
    unittest.main()
