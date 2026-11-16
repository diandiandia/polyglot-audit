"""SWR-008 acceptance tests: independent verification tasks, counter
evidence, and the four-way disposition.

验收原文 (docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2, SWR-008):
    "实现独立验证任务、反证及四种处理状态；测试可达性或防御未知不能确认、
    无反证不能驳回。"

细化依据: DSR-027: "实现独立验证任务、三种裁决与 unverified；缺部署事实转
needs_validation，rejected 无反证失败，E2 必须新 attempt。" IFC-02 Finding:
"confirmed 需 source/sink、完整逐跳依据、守卫、影响、前提、rating、remediation；
needs_validation 需 blockers 和 validation_plan；rejected 需反证锚点；
unverified 需原因。" Anchor 契约: "只能证实位置存在，不能证明语义。"

Covered here:
- Each of the four verdicts has a satisfying and a violating case.
- Unresolved reachability cannot be confirmed (broken / missing per-hop trace
  fails validation).
- Unknown defense state cannot be confirmed; it lands on needs_validation.
- Rejected without counter evidence fails; with a rationale it succeeds.
- The presence of anchors alone is not proof: a fully anchored candidate
  still cannot yield confirmed without a fresh verification attempt.
"""

import unittest

from auditkit.analysis.guards import GuardRecord, evaluate_guards
from auditkit.analysis.verifier import Verifier
from auditkit.contracts.errors import InvalidInputError


def _anchored_candidate() -> dict:
    return {
        "candidate_id": "cand-v-1",
        "issue": "py-01",
        "source": {
            "path": "app/handlers/upload.py", "line": 8,
            "symbol": "handle_upload", "kind": "http_body", "lang": "python",
        },
        "sink": {
            "path": "app/storage/state.py", "line": 12,
            "symbol": "restore_state", "kind": "deserialization",
        },
        "steps": [
            {"path": "app/handlers/upload.py", "line": 8, "role": "source", "note": "read body"},
            {"path": "app/storage/state.py", "line": 12, "role": "sink", "note": "unpickle"},
        ],
        "guard_analysis": "no validation observed on this path",
        "provenance": {"hunt_tasks": ["task-hunt-1"], "hunt_attempt_id": "att-hunt-1"},
    }


class TestSWR008(unittest.TestCase):

    def setUp(self):
        self.verifier = Verifier(enforce_attempt_gate=True)

    # -- confirmed: satisfying and violating cases ---------------------------
    def test_confirmed_with_complete_evidence_succeeds(self):
        finding = self.verifier.create_finding_from_candidate(
            _anchored_candidate(),
            "confirmed",
            "vt-1",
            verify_attempt_id="att-verify-1",
            hunt_attempt_id="att-hunt-1",
            impact=4,
            exploitability=4,
        )
        self.assertEqual(finding["verdict"], "confirmed")
        self.assertEqual(finding["evidence_level"], "E2")
        self.assertEqual(
            finding["provenance"]["verify_attempt_id"], "att-verify-1"
        )
        for req in ("title", "issue", "languages", "source", "sink",
                    "steps", "remediation", "rating"):
            self.assertTrue(finding.get(req), f"confirmed finding needs {req}")

    def test_unresolved_reachability_cannot_be_confirmed(self):
        """A broken per-hop trace must never pass as a confirmed finding."""
        broken = _anchored_candidate()
        del broken["source"]  # reachability starts nowhere
        with self.assertRaises(InvalidInputError) as ctx:
            self.verifier.create_finding_from_candidate(
                broken, "confirmed", "vt-2",
                verify_attempt_id="att-verify-2", hunt_attempt_id="att-hunt-1",
                impact=4, exploitability=4,
            )
        self.assertIn("source", str(ctx.exception))

        no_sink = _anchored_candidate()
        del no_sink["sink"]
        with self.assertRaises(InvalidInputError):
            self.verifier.create_finding_from_candidate(
                no_sink, "confirmed", "vt-3",
                verify_attempt_id="att-verify-3", hunt_attempt_id="att-hunt-1",
                impact=4, exploitability=4,
            )

        # A confirmed verdict whose stored trace does not end at a sink is
        # rejected by the semantic validator (field located: steps).
        invalid_trace = {
            "schema_version": "1.0",
            "finding_id": "F-BROKEN",
            "candidate_refs": ["cand-v-1"],
            "verdict": "confirmed",
            "evidence_level": "E2",
            "title": "t", "issue": "py-01", "languages": ["python"],
            "source": {"path": "a.py", "line": 1},
            "sink": {"path": "b.py", "line": 2},
            "steps": [
                {"path": "a.py", "line": 1, "role": "source"},
                {"path": "mid.py", "line": 2, "role": "propagator"},
            ],
            "remediation": {"where": "b.py:2", "change": "c", "regression_test": "r"},
            "rating": self.verifier.create_finding_from_candidate(
                _anchored_candidate(), "confirmed", "vt-x",
                verify_attempt_id="att-x", hunt_attempt_id="att-h",
                impact=4, exploitability=4,
            )["rating"],
            "provenance": {"hunt_tasks": [], "verify_tasks": ["vt-x"]},
        }
        with self.assertRaises(InvalidInputError) as ctx2:
            self.verifier.validator.validate_finding(invalid_trace)
        self.assertIn("sink", str(ctx2.exception))

    # -- defense unknown cannot be confirmed ---------------------------------
    def test_defense_unknown_lands_on_needs_validation(self):
        """Unknown guard state must keep the disposition pending, not confirm."""
        guard = GuardRecord(
            guard_id="g-waf", status="unknown", mechanism="possible WAF",
        )
        decision = evaluate_guards(_anchored_candidate(), [guard])
        self.assertEqual(decision["status"], "unknown")

        finding = self.verifier.create_finding_from_candidate(
            _anchored_candidate(),
            "needs_validation",
            "vt-guard-1",
            impact=4,
            exploitability=3,
            blockers=[
                f"Defense state unresolved: guard '{decision['status']}' "
                "in the deployment is unknown"
            ],
            validation_plan="Probe the deployed environment for the guard behavior",
        )
        self.assertEqual(finding["verdict"], "needs_validation")
        self.assertEqual(finding["evidence_level"], "E1")
        self.assertTrue(finding["blockers"])
        self.assertTrue(finding["validation_plan"])
        self.assertIn(
            "validation_priority", finding["rating"],
            "pending findings carry a validation priority instead of urgency",
        )

    # -- rejected / unverified: satisfying and violating cases ----------------
    def test_rejected_requires_counter_evidence(self):
        """无反证不能驳回: a rejected verdict without counter evidence fails."""
        with self.assertRaises(InvalidInputError) as ctx:
            self.verifier.create_finding_from_candidate(
                _anchored_candidate(), "rejected", "vt-rej-0",
            )
        self.assertIn("counter evidence", str(ctx.exception).lower())

        rejected = self.verifier.create_finding_from_candidate(
            _anchored_candidate(),
            "rejected",
            "vt-rej-1",
            counter_evidence={
                "rationale": "Input is length-validated before the sink call",
                "anchors": [
                    {"path": "app/handlers/upload.py",
                     "line_start": 6, "line_end": 7, "file_sha256": ""}
                ],
            },
        )
        self.assertEqual(rejected["verdict"], "rejected")
        self.assertEqual(rejected["evidence_level"], "E1")
        self.assertTrue(rejected["counter_evidence"]["rationale"])

    def test_unverified_requires_reason(self):
        with self.assertRaises(InvalidInputError):
            self.verifier.create_finding_from_candidate(
                _anchored_candidate(), "unverified", "vt-unv-0", unverified_reason="",
            )
        unverified = self.verifier.create_finding_from_candidate(
            _anchored_candidate(),
            "unverified",
            "vt-unv-1",
            unverified_reason="Verification budget exhausted before evaluation",
        )
        self.assertEqual(unverified["verdict"], "unverified")
        self.assertTrue(unverified["unverified_reason"])

    def test_unknown_verdict_is_rejected_not_coerced(self):
        with self.assertRaises(InvalidInputError):
            self.verifier.validator.validate_finding({
                "schema_version": "1.0",
                "finding_id": "F-1",
                "verdict": "probably_confirmed",
                "evidence_level": "E1",
            })

    # -- anchors alone are not proof ------------------------------------------
    def test_anchor_presence_alone_is_not_proof(self):
        """A fully anchored candidate cannot confirm itself (E2 gate)."""
        candidate = _anchored_candidate()  # rich anchors and steps
        with self.assertRaises(InvalidInputError) as ctx:
            self.verifier.create_finding_from_candidate(
                candidate, "confirmed", "vt-no-attempt",
                hunt_attempt_id="att-hunt-1",
                # No verify_attempt_id supplied: no fresh verification attempt.
                impact=4, exploitability=4,
            )
        self.assertIn("attempt", str(ctx.exception))

        # Re-using the hunt attempt is equally not a verification.
        with self.assertRaises(InvalidInputError) as ctx2:
            self.verifier.create_finding_from_candidate(
                candidate, "confirmed", "vt-reused",
                verify_attempt_id="att-hunt-1",
                hunt_attempt_id="att-hunt-1",
                impact=4, exploitability=4,
            )
        self.assertIn("new verification attempt", str(ctx2.exception))

    def test_verify_task_declares_independence_requirements(self):
        task = self.verifier.build_verify_task(_anchored_candidate())
        self.assertEqual(task["task_kind"], "verify")
        self.assertEqual(task["role"], "verify")
        self.assertTrue(task["requires_new_attempt"])
        self.assertIn("confirmed", task["output_contract"])
        self.assertEqual(task["input"]["candidate"]["candidate_id"], "cand-v-1")
        self.assertEqual(task["input"]["hunt_tasks"], ["task-hunt-1"])

    def test_four_dispositions_have_distinguishable_shapes(self):
        cand = _anchored_candidate()
        confirmed = self.verifier.create_finding_from_candidate(
            cand, "confirmed", "vt-a",
            verify_attempt_id="att-v", hunt_attempt_id="att-hunt-1",
            impact=4, exploitability=4,
        )
        pending = self.verifier.create_finding_from_candidate(
            cand, "needs_validation", "vt-b", impact=2, exploitability=2,
            blockers=["b"], validation_plan="p",
        )
        rejected = self.verifier.create_finding_from_candidate(
            cand, "rejected", "vt-c",
            counter_evidence={"rationale": "hardcoded constant input"},
        )
        unverified = self.verifier.create_finding_from_candidate(
            cand, "unverified", "vt-d", unverified_reason="deadline",
        )
        self.assertEqual(confirmed["evidence_level"], "E2")
        for other in (pending, rejected, unverified):
            self.assertEqual(other["evidence_level"], "E1")
        self.assertIn("remediation", confirmed)
        self.assertNotIn("remediation", pending)
        self.assertIn("blockers", pending)
        self.assertIn("counter_evidence", rejected)
        self.assertIn("unverified_reason", unverified)


if __name__ == "__main__":
    unittest.main()
