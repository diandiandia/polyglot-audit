"""SWR-011 acceptance tests: rating matrix, bounded manual adjustment,
final urgency recalculation, and pending-item validation priority.

验收原文 (docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2, SWR-011):
    "实现定级矩阵、单档人工调整及最终紧迫度重算；穷举因子、调整边界、缺理由
    与未决分级反例。"

细化依据: DSR-028: "实现影响×可利用性矩阵及调整；穷举 16 个组合、两端越界、
缺理由和调整后紧迫度，待验证无修复紧迫度。" SYSTEM_DESIGN 9.2 gives the
documented 4x4 matrix and urgency rules; "verifier 可以上调或下调至多一档并
写明理由"; "needs_validation 不给紧迫度，只给验证优先级 V1–V3"。

Covered here:
- All 16 (impact x exploitability) combinations computed reproducibly and
  equal to the documented matrix / urgency rules.
- Manual adjustment moves exactly one grade with operator and reason kept,
  and final urgency is recalculated from the final severity.
- Adjustment without operator/reason is rejected; more than one grade or a
  bogus direction is rejected; both ends (Critical/Info) are bounded.
- A needs_validation finding carries only the validation priority (no
  remediation urgency, no remediation field); factor bounds reject 0/5.
"""

import unittest

from auditkit.analysis.rating import RatingEngine
from auditkit.analysis.verifier import Verifier
from auditkit.contracts.errors import InvalidInputError
from auditkit.contracts.semantic_validator import (
    SemanticValidator,
    calculate_severity,
    calculate_urgency,
    calculate_validation_priority,
)

# Documented matrix (SYSTEM_DESIGN.md §9.2): rows are impact 4..1, columns
# exploitability 4..1.
DOCUMENTED_SEVERITY = {
    (4, 4): "Critical", (4, 3): "High", (4, 2): "High", (4, 1): "Medium",
    (3, 4): "High", (3, 3): "High", (3, 2): "Medium", (3, 1): "Low",
    (2, 4): "Medium", (2, 3): "Medium", (2, 2): "Low", (2, 1): "Low",
    (1, 4): "Low", (1, 3): "Low", (1, 2): "Low", (1, 1): "Info",
}


def _documented_urgency(severity: str, exploitability: int) -> str:
    """Urgency rules from SYSTEM_DESIGN 9.2 (highest satisfied tier wins)."""
    if severity == "Critical" or (severity == "High" and exploitability == 4):
        return "P0"
    if severity == "High" or (severity == "Medium" and exploitability == 4):
        return "P1"
    if severity == "Medium" or (severity == "Low" and exploitability >= 3):
        return "P2"
    return "P3"


class TestSWR011(unittest.TestCase):

    def setUp(self):
        self.validator = SemanticValidator()

    # -- exhaustive 16 combinations, reproducible ----------------------------
    def test_all_16_factor_combinations_match_documented_matrix(self):
        for impact in range(1, 5):
            for exploitability in range(1, 5):
                expected_sev = DOCUMENTED_SEVERITY[(impact, exploitability)]
                expected_urg = _documented_urgency(expected_sev, exploitability)

                self.assertEqual(
                    calculate_severity(impact, exploitability), expected_sev,
                    f"severity matrix mismatch at I={impact},X={exploitability}",
                )
                self.assertEqual(
                    calculate_urgency(expected_sev, exploitability), expected_urg,
                    f"urgency rule mismatch at I={impact},X={exploitability}",
                )

                first = RatingEngine.compute_rating(
                    impact=impact, exploitability=exploitability,
                    impact_why=f"impact reason I{impact}",
                    exploitability_why=f"exploitability reason X{exploitability}",
                )
                second = RatingEngine.compute_rating(
                    impact=impact, exploitability=exploitability,
                    impact_why=f"impact reason I{impact}",
                    exploitability_why=f"exploitability reason X{exploitability}",
                )
                self.assertEqual(first, second, "rating computation must be reproducible")
                self.assertEqual(first["calculated_severity"], expected_sev)
                self.assertEqual(first["calculated_urgency"], expected_urg)
                self.assertEqual(first["final_severity"], expected_sev)
                self.assertEqual(first["final_urgency"], expected_urg)
                # The program-computed rating passes semantic validation.
                self.validator.validate_rating(first, is_confirmed=True)

    # -- single-grade adjustment keeps operator and reason -------------------
    def test_adjustment_single_grade_up_and_down(self):
        # I=3, X=3 -> High/P1; up one grade -> Critical (urgency recomputed).
        up = RatingEngine.compute_rating(
            impact=3, exploitability=3,
            impact_why="authenticated bypass", exploitability_why="low-priv session",
            adjustment={
                "operator": "operator-1",
                "reason": "affected asset is key material",
                "direction": "up",
            },
        )
        self.assertEqual(up["calculated_severity"], "High")
        self.assertEqual(up["final_severity"], "Critical")
        self.assertEqual(up["final_urgency"], "P0")
        self.assertEqual(up["adjustment"]["operator"], "operator-1")
        self.assertEqual(up["adjustment"]["reason"], "affected asset is key material")
        self.validator.validate_rating(up, is_confirmed=True)

        # I=3, X=3 -> High/P1; down one grade -> Medium; urgency recomputed to
        # P2 (Medium stays P2 regardless of X=3).
        down = RatingEngine.compute_rating(
            impact=3, exploitability=3,
            impact_why="authenticated bypass", exploitability_why="low-priv session",
            adjustment={
                "operator": "operator-2",
                "reason": "compensating control verified on the default config",
                "direction": "down",
            },
        )
        self.assertEqual(down["calculated_severity"], "High")
        self.assertEqual(down["final_severity"], "Medium")
        self.assertEqual(down["final_urgency"], "P2")
        self.validator.validate_rating(down, is_confirmed=True)

    def test_adjustment_without_operator_or_reason_rejected(self):
        engine = RatingEngine
        for bad in (
            {"operator": "", "reason": "r", "direction": "up"},
            {"operator": "op", "reason": "", "direction": "up"},
            {"operator": None, "reason": "r", "direction": "up"},
            {"operator": "op", "reason": "r", "direction": None},
            {},
        ):
            with self.assertRaises(InvalidInputError, msg=str(bad)):
                engine.compute_rating(
                    impact=3, exploitability=3,
                    impact_why="i", exploitability_why="e",
                    adjustment=bad,
                )
            # The semantic validator rejects the same shapes.
            rating = {
                "impact": 3, "exploitability": 3,
                "factor_reasons": {"impact_why": "i", "exploitability_why": "e"},
                "calculated_severity": "High", "calculated_urgency": "P1",
                "final_severity": "Critical", "final_urgency": "P0",
                "adjustment": bad,
            }
            with self.assertRaises(InvalidInputError, msg=str(bad)):
                self.validator.validate_rating(rating, is_confirmed=True)

    def test_adjustment_beyond_one_grade_rejected(self):
        """Direction must move exactly one grade — two grades fail validation."""
        rating = {
            "impact": 3, "exploitability": 3,
            "factor_reasons": {"impact_why": "i", "exploitability_why": "e"},
            "calculated_severity": "High", "calculated_urgency": "P1",
            "final_severity": "Low",  # two grades down
            "final_urgency": "P3",
            "adjustment": {"operator": "op", "reason": "r", "direction": "down"},
        }
        with self.assertRaises(InvalidInputError) as ctx:
            self.validator.validate_rating(rating, is_confirmed=True)
        self.assertIn("exactly 1 grade", str(ctx.exception))

        wrong_direction = dict(rating)
        wrong_direction["final_severity"] = "Low"
        wrong_direction["adjustment"] = {
            "operator": "op", "reason": "r", "direction": "up"
        }
        with self.assertRaises(InvalidInputError):
            self.validator.validate_rating(wrong_direction, is_confirmed=True)

        bogus_direction = dict(rating)
        bogus_direction["final_severity"] = "Critical"
        bogus_direction["final_urgency"] = "P0"
        bogus_direction["adjustment"] = {
            "operator": "op", "reason": "r", "direction": "sideways"
        }
        with self.assertRaises(InvalidInputError):
            self.validator.validate_rating(bogus_direction, is_confirmed=True)

    def test_adjustment_bounds_at_both_ends(self):
        """Critical cannot go up; Info cannot go down (DSR-028 two-end cases)."""
        with self.assertRaises(InvalidInputError):
            RatingEngine.compute_rating(
                impact=4, exploitability=4,
                impact_why="i", exploitability_why="e",
                adjustment={"operator": "op", "reason": "r", "direction": "up"},
            )
        with self.assertRaises(InvalidInputError):
            RatingEngine.compute_rating(
                impact=1, exploitability=1,
                impact_why="i", exploitability_why="e",
                adjustment={"operator": "op", "reason": "r", "direction": "down"},
            )

    def test_urgency_recalculated_after_adjustment(self):
        """The final urgency must follow the final severity, not the original.

        I=2,X=4 -> Medium/P1; down -> Low with urgency recomputed to P2
        (Low with X>=3), NOT the original P1.
        """
        rating = RatingEngine.compute_rating(
            impact=2, exploitability=4,
            impact_why="limited overwrite", exploitability_why="unauthenticated remote",
            adjustment={"operator": "op", "reason": "sandboxed deployment", "direction": "down"},
        )
        self.assertEqual(rating["calculated_severity"], "Medium")
        self.assertEqual(rating["calculated_urgency"], "P1")
        self.assertEqual(rating["final_severity"], "Low")
        self.assertEqual(rating["final_urgency"], "P2")
        self.validator.validate_rating(rating, is_confirmed=True)

    # -- factor bounds --------------------------------------------------------
    def test_factor_values_outside_1_to_4_rejected(self):
        for bad in (0, 5, -1):
            with self.assertRaises(InvalidInputError):
                RatingEngine.compute_rating(
                    impact=bad, exploitability=3,
                    impact_why="i", exploitability_why="e",
                )
            with self.assertRaises(InvalidInputError):
                RatingEngine.compute_rating(
                    impact=3, exploitability=bad,
                    impact_why="i", exploitability_why="e",
                )
            rating = {
                "impact": bad, "exploitability": 3,
                "factor_reasons": {"impact_why": "i", "exploitability_why": "e"},
                "calculated_severity": "High", "calculated_urgency": "P1",
                "final_severity": "High", "final_urgency": "P1",
            }
            with self.assertRaises(InvalidInputError):
                self.validator.validate_rating(rating, is_confirmed=True)

    def test_missing_factor_reasons_rejected(self):
        with self.assertRaises(InvalidInputError):
            RatingEngine.compute_rating(
                impact=3, exploitability=3,
                impact_why="", exploitability_why="e",
            )
        with self.assertRaises(InvalidInputError):
            RatingEngine.compute_rating(
                impact=3, exploitability=3,
                impact_why="i", exploitability_why="",
            )

    # -- pending findings carry validation priority only ----------------------
    def test_needs_validation_has_validation_priority_only(self):
        """待验证无修复紧迫度: pending items get V1-V3, not a repair urgency."""
        verifier = Verifier()
        candidate = {
            "candidate_id": "cand-r-1",
            "issue": "py-02",
            "source": {"path": "app/a.py", "line": 1, "kind": "http", "lang": "python"},
            "sink": {"path": "app/b.py", "line": 2, "kind": "sql"},
            "provenance": {"hunt_tasks": ["t1"]},
        }
        # I=4, X=4 would be Critical -> validation priority V1.
        pending = verifier.create_finding_from_candidate(
            candidate, "needs_validation", "vt-r1",
            impact=4, exploitability=4,
            blockers=["runtime deployment unknown"],
            validation_plan="probe the deployment",
        )
        rating = pending["rating"]
        self.assertEqual(rating["validation_priority"], "V1")
        self.assertEqual(
            rating["validation_priority"],
            calculate_validation_priority(4, 4),
        )
        # No remediation urgency on pending items.
        self.assertNotIn("calculated_urgency", rating)
        self.assertNotIn("final_urgency", rating)
        # And no remediation field on the finding itself.
        self.assertNotIn("remediation", pending)

        # I=1, X=1 would be Info -> V3.
        low = verifier.create_finding_from_candidate(
            candidate, "needs_validation", "vt-r2",
            impact=1, exploitability=1,
            blockers=["runtime deployment unknown"],
            validation_plan="probe the deployment",
        )
        self.assertEqual(low["rating"]["validation_priority"], "V3")

        # I=4, X=1 is Medium per the matrix -> V2.
        mid = verifier.create_finding_from_candidate(
            candidate, "needs_validation", "vt-r3",
            impact=4, exploitability=1,
            blockers=["runtime deployment unknown"],
            validation_plan="probe the deployment",
        )
        self.assertEqual(mid["rating"]["validation_priority"], "V2")

        # I=2, X=2 is Low per the matrix -> V3.
        low2 = verifier.create_finding_from_candidate(
            candidate, "needs_validation", "vt-r3b",
            impact=2, exploitability=2,
            blockers=["runtime deployment unknown"],
            validation_plan="probe the deployment",
        )
        self.assertEqual(low2["rating"]["validation_priority"], "V3")

    def test_needs_validation_rating_passes_semantic_validation(self):
        verifier = Verifier()
        candidate = {
            "candidate_id": "cand-r-9",
            "issue": "py-02",
            "source": {"path": "app/a.py", "line": 1, "kind": "http", "lang": "python"},
            "sink": {"path": "app/b.py", "line": 2, "kind": "sql"},
            "provenance": {"hunt_tasks": ["t1"]},
        }
        pending = verifier.create_finding_from_candidate(
            candidate, "needs_validation", "vt-r9",
            impact=3, exploitability=1,
            blockers=["unknown"],
            validation_plan="plan",
        )
        # I=3, X=1 -> Low severity per the matrix -> validation priority V3.
        self.assertEqual(pending["rating"]["validation_priority"], "V3")
        self.validator.validate_finding(pending)

    def test_confirmed_findings_keep_matrix_urgency(self):
        verifier = Verifier(enforce_attempt_gate=True)
        candidate = {
            "candidate_id": "cand-r-2",
            "issue": "py-01",
            "source": {"path": "app/a.py", "line": 1, "kind": "http", "lang": "python"},
            "sink": {"path": "app/b.py", "line": 2, "kind": "rce"},
            "steps": [
                {"path": "app/a.py", "line": 1, "role": "source"},
                {"path": "app/b.py", "line": 2, "role": "sink"},
            ],
            "provenance": {"hunt_tasks": ["t1"]},
        }
        confirmed = verifier.create_finding_from_candidate(
            candidate, "confirmed", "vt-r4",
            verify_attempt_id="att-v", hunt_attempt_id="att-h",
            impact=4, exploitability=4,
        )
        self.assertEqual(confirmed["rating"]["calculated_severity"], "Critical")
        self.assertEqual(confirmed["rating"]["final_urgency"], "P0")
        self.assertIn("remediation", confirmed)


if __name__ == "__main__":
    unittest.main()
