"""DSR-027 / DSR-061 / DSR-062: verify task API, E2 attempt gate, second-opinion
tightening, and bounded variant search."""

import unittest

from auditkit.analysis.verifier import Verifier, bounded_variant_search
from auditkit.contracts.errors import InvalidInputError


def _candidate(sev: str = "critical") -> dict:
    impact, exploitability = (4, 4) if sev == "critical" else (1, 1)
    return {
        "candidate_id": "cand-1",
        "source": {"path": "app.py", "line": 10, "symbol": "get_input", "kind": "http"},
        "sink": {"path": "db.py", "line": 40, "symbol": "query", "kind": "sqli"},
        "steps": [
            {"path": "app.py", "line": 10, "role": "source", "note": "read"},
            {"path": "db.py", "line": 40, "role": "sink", "note": "exec"},
        ],
        "provenance": {"hunt_tasks": ["t1"], "hunt_attempt_id": "attempt-hunt-1"},
    }


class TestVerifyTask(unittest.TestCase):

    def test_build_verify_task_produces_verify_kind_spec(self):
        verifier = Verifier()
        spec = verifier.build_verify_task(_candidate())
        self.assertEqual(spec["task_kind"], "verify")
        self.assertEqual(spec["role"], "verify")
        self.assertEqual(spec["candidate_id"], "cand-1")
        self.assertTrue(spec["requires_new_attempt"])
        self.assertIn("verify_attempt_id", spec["output_contract"])
        self.assertEqual(spec["input"]["hunt_tasks"], ["t1"])

    def test_build_verify_task_requires_candidate_id(self):
        with self.assertRaises(InvalidInputError):
            Verifier().build_verify_task({"source": {}})


class TestE2AttemptGate(unittest.TestCase):

    def test_confirmed_requires_verify_attempt_when_gate_enforced(self):
        verifier = Verifier(enforce_attempt_gate=True)
        with self.assertRaises(InvalidInputError):
            verifier.create_finding_from_candidate(
                _candidate(), "confirmed", "t-v1", impact=4, exploitability=4
            )

    def test_confirmed_rejects_reused_hunt_attempt(self):
        verifier = Verifier(enforce_attempt_gate=True)
        with self.assertRaises(InvalidInputError):
            verifier.create_finding_from_candidate(
                _candidate(),
                "confirmed",
                "t-v1",
                impact=4,
                exploitability=4,
                verify_attempt_id="attempt-hunt-1",
            )

    def test_confirmed_with_fresh_attempt_succeeds(self):
        verifier = Verifier(enforce_attempt_gate=True)
        finding = verifier.create_finding_from_candidate(
            _candidate(),
            "confirmed",
            "t-v1",
            impact=4,
            exploitability=4,
            verify_attempt_id="attempt-verify-1",
        )
        self.assertEqual(finding["verdict"], "confirmed")
        self.assertEqual(finding["evidence_level"], "E2")
        self.assertEqual(
            finding["provenance"]["verify_attempt_id"], "attempt-verify-1"
        )

    def test_legacy_callers_without_gate_still_work(self):
        """Back-compat: without the gate, missing attempt id is still accepted
        until app/service.py wiring lands (documented TODO)."""
        verifier = Verifier()
        finding = verifier.create_finding_from_candidate(
            _candidate(), "confirmed", "t-v1", impact=4, exploitability=4
        )
        self.assertEqual(finding["verdict"], "confirmed")


class TestSecondOpinionGate(unittest.TestCase):

    def _confirmed_finding(self, verifier: Verifier, severity: str) -> dict:
        cand = _candidate(severity)
        kwargs = dict(impact=4, exploitability=4)
        if severity != "critical":
            kwargs = dict(impact=1, exploitability=1)
        return verifier.create_finding_from_candidate(
            cand, "confirmed", "t-v1", verify_attempt_id="att-v1", **kwargs
        )

    def test_only_high_or_critical_accepted(self):
        verifier = Verifier()
        finding = self._confirmed_finding(verifier, "low")  # severity Info
        with self.assertRaises(InvalidInputError):
            verifier.adjudicate_second_opinion(finding, "confirmed", "Looks fine")

    def test_agreement_corroborates_and_preserves_both_sides(self):
        verifier = Verifier()
        finding = self._confirmed_finding(verifier, "critical")
        out = verifier.adjudicate_second_opinion(finding, "confirmed", "Trace reproduced")
        self.assertEqual(out["verdict"], "confirmed")
        so = out["second_opinion"]
        self.assertEqual(so["resolution"], "corroborated")
        self.assertEqual(so["primary"]["verdict"], "confirmed")
        self.assertEqual(so["secondary"]["verdict"], "confirmed")
        self.assertEqual(so["secondary"]["anchor"], {})
        self.assertEqual(so["primary"]["anchor"]["path"], "db.py")

    def test_conflict_structured_and_demoted(self):
        verifier = Verifier()
        finding = self._confirmed_finding(verifier, "critical")
        out = verifier.adjudicate_second_opinion(
            finding,
            "rejected",
            "Sanitizer observed on line 25",
            second_opinion_anchor={"path": "db.py", "line": 25},
        )
        self.assertEqual(out["verdict"], "needs_validation")
        self.assertEqual(out["evidence_level"], "E1")
        so = out["second_opinion"]
        self.assertEqual(so["resolution"], "conflict_demoted")
        # Both sides preserved structurally with verdict + evidence + anchor
        self.assertEqual(so["primary"]["verdict"], "confirmed")
        self.assertEqual(so["primary"]["anchor"], {"path": "db.py", "line": 40})
        self.assertTrue(so["primary"]["evidence"])
        self.assertEqual(so["secondary"]["verdict"], "rejected")
        self.assertEqual(
            so["secondary"]["evidence"]["rationale"], "Sanitizer observed on line 25"
        )
        self.assertEqual(so["secondary"]["anchor"], {"path": "db.py", "line": 25})


class TestBoundedVariantSearch(unittest.TestCase):

    SNAPSHOT = {
        "db.py": "def query(sql):\n    query(sql)\n",
        "other1.py": "query(user_input)\n",
        "other2.py": "query(more)\n",
        "other3.py": "no match here\n",
    }

    def _confirmed(self) -> dict:
        verifier = Verifier()
        cand = _candidate()
        cand["sink"]["line"] = 2  # db.py:2 is the confirmed sink occurrence
        return verifier.create_finding_from_candidate(
            cand,
            "confirmed",
            "t-v1",
            impact=4,
            exploitability=4,
            verify_attempt_id="att-v1",
        )

    def test_finds_variants_excluding_confirmed_location(self):
        finding = self._confirmed()
        result = bounded_variant_search(self.SNAPSHOT, finding)
        paths_lines = [(v["path"], v["line"]) for v in result["variants"]]
        # db.py:2 is the confirmed sink location itself and must be excluded
        self.assertNotIn(("db.py", 2), paths_lines)
        self.assertIn(("db.py", 1), paths_lines)
        self.assertIn(("other1.py", 1), paths_lines)
        self.assertIn(("other2.py", 1), paths_lines)
        self.assertNotIn(("other3.py", 1), paths_lines)
        self.assertEqual(result["searched_files"], 4)
        self.assertEqual(result["total_files"], 4)
        self.assertFalse(result["truncated"])
        for v in result["variants"]:
            self.assertTrue(v["requires_independent_verification"])
            self.assertIn("same sink", v["evidence_requirements"])

    def test_variant_cap_records_truncation_reason(self):
        finding = self._confirmed()
        result = bounded_variant_search(self.SNAPSHOT, finding, max_variants=2)
        self.assertEqual(len(result["variants"]), 2)
        self.assertTrue(result["truncated"])
        self.assertIn("Variant cap 2", result["reason"])

    def test_file_cap_records_unsearched_files(self):
        finding = self._confirmed()
        result = bounded_variant_search(self.SNAPSHOT, finding, max_files=2)
        self.assertEqual(result["searched_files"], 2)
        self.assertEqual(result["total_files"], 4)
        self.assertTrue(result["truncated"])
        self.assertEqual(result["unsearched_files"], ["other2.py", "other3.py"])
        self.assertIn("File cap 2", result["reason"])

    def test_wired_into_confirmed_finding(self):
        verifier = Verifier()
        finding = verifier.create_finding_from_candidate(
            _candidate(),
            "confirmed",
            "t-v1",
            impact=4,
            exploitability=4,
            verify_attempt_id="att-v1",
            snapshot_files=self.SNAPSHOT,
        )
        self.assertTrue(finding["variants"])
        coverage = finding["variant_search"]
        self.assertEqual(coverage["searched_files"], 4)
        self.assertEqual(coverage["total_files"], 4)
        self.assertFalse(coverage["truncated"])

    def test_without_snapshot_variants_stay_empty(self):
        verifier = Verifier()
        finding = verifier.create_finding_from_candidate(
            _candidate(), "confirmed", "t-v1", impact=4, exploitability=4
        )
        self.assertEqual(finding["variants"], [])

    def test_invalid_arguments(self):
        with self.assertRaises(InvalidInputError):
            bounded_variant_search("not-a-dict", {"sink": {"symbol": "x"}})
        with self.assertRaises(InvalidInputError):
            bounded_variant_search(self.SNAPSHOT, {"sink": {"symbol": "x"}}, max_variants=0)


if __name__ == "__main__":
    unittest.main()
