"""SWR-009 acceptance tests: E1/E2 adjudication validation and E3 ban.

验收原文 (docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2, SWR-009):
    "实现 E1/E2 与静态确认条件的裁决校验；缺逐跳证据或必要前提时保持未决，
    首版禁用 E3 声称。"

细化依据: IFC-02: "E2 仅适用于符合静态独立验证条件的 confirmed，E1 表示不完整
的静态证据……首版不接受 E3。" DDS-05: "每个验证必须创建与 hunter 不同的
attempt 和新上下文"。SYSTEM_DESIGN 9.1: "校验器强制：证据链以 source 开始、
以 sink 结束；每个锚点在快照中存在"。

Covered here:
- E2 (confirmed) requires a fresh verification attempt distinct from the hunt
  attempt: missing or reused attempts fail the gate.
- E2 requires a per-hop trace: source-first, sink-last, at least two steps;
  incomplete traces stay unconfirmed.
- E3 is strictly prohibited in the first version; other unknown levels fail.
- Missing necessary preconditions (deployment facts, rating, verdict shape)
  fall back to needs_validation instead of being confirmed.
- Non-confirmed verdicts stay at E1.
"""

import unittest

from auditkit.analysis.verifier import Verifier
from auditkit.contracts.errors import InvalidInputError
from auditkit.contracts.semantic_validator import SemanticValidator


def _candidate() -> dict:
    return {
        "candidate_id": "cand-e2-1",
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
            {"path": "app/handlers/upload.py", "line": 8, "role": "source", "note": "read"},
            {"path": "app/storage/state.py", "line": 12, "role": "sink", "note": "unpickle"},
        ],
        "guard_analysis": "none on path",
        "provenance": {"hunt_tasks": ["task-h1"], "hunt_attempt_id": "att-hunt"},
    }


class TestSWR009(unittest.TestCase):

    def setUp(self):
        self.verifier = Verifier(enforce_attempt_gate=True)
        self.validator = SemanticValidator()

    # -- E2 requires a fresh verification attempt (gate) ---------------------
    def test_e2_gate_requires_new_attempt(self):
        """E2 needs verify_attempt_id distinct from the hunt attempt."""
        with self.assertRaises(InvalidInputError) as missing:
            self.verifier.create_finding_from_candidate(
                _candidate(), "confirmed", "vt-1",
                hunt_attempt_id="att-hunt", impact=4, exploitability=4,
                impact_why="Attacker body reaches unpickle without validation",
            exploitability_why="Upload endpoint needs no authentication",
            )
        self.assertIn("attempt", str(missing.exception))

        with self.assertRaises(InvalidInputError) as reused:
            self.verifier.create_finding_from_candidate(
                _candidate(), "confirmed", "vt-2",
                verify_attempt_id="att-hunt",  # equals the hunt attempt
                hunt_attempt_id="att-hunt", impact=4, exploitability=4,
                impact_why="Attacker body reaches unpickle without validation",
            exploitability_why="Upload endpoint needs no authentication",
            )
        self.assertIn("must differ", str(reused.exception))

        finding = self.verifier.create_finding_from_candidate(
            _candidate(), "confirmed", "vt-3",
            verify_attempt_id="att-verify",
            hunt_attempt_id="att-hunt", impact=4, exploitability=4,
            impact_why="Attacker body reaches unpickle without validation",
            exploitability_why="Upload endpoint needs no authentication",
        )
        self.assertEqual(finding["evidence_level"], "E2")
        self.assertEqual(finding["provenance"]["verify_attempt_id"], "att-verify")

    def test_e2_gate_active_for_legacy_callers_when_hunt_attempt_known(self):
        """Even without the gate flag, a reused hunt attempt is rejected."""
        legacy = Verifier(enforce_attempt_gate=False)
        with self.assertRaises(InvalidInputError):
            legacy.create_finding_from_candidate(
                _candidate(), "confirmed", "vt-4",
                verify_attempt_id="att-hunt", hunt_attempt_id="att-hunt",
                impact=4, exploitability=4,
                impact_why="Attacker body reaches unpickle without validation",
            exploitability_why="Upload endpoint needs no authentication",
            )

    # -- E2 requires per-hop evidence ----------------------------------------
    def test_e2_requires_per_hop_trace(self):
        """Confirmed without a source->sink trace stays unconfirmed."""
        base = self.verifier.create_finding_from_candidate(
            _candidate(), "confirmed", "vt-5",
            verify_attempt_id="att-verify", hunt_attempt_id="att-hunt",
            impact=4, exploitability=4,
            impact_why="Attacker body reaches unpickle without validation",
            exploitability_why="Upload endpoint needs no authentication",
        )

        one_step = dict(base)
        one_step["steps"] = [{"path": "b.py", "line": 12, "role": "sink"}]
        with self.assertRaises(InvalidInputError) as ctx1:
            self.validator.validate_finding(one_step)
        self.assertIn("2 steps", str(ctx1.exception))

        starts_mid = dict(base)
        starts_mid["steps"] = [
            {"path": "mid.py", "line": 1, "role": "propagator"},
            {"path": "b.py", "line": 12, "role": "sink"},
        ]
        with self.assertRaises(InvalidInputError) as ctx2:
            self.validator.validate_finding(starts_mid)
        self.assertIn("source", str(ctx2.exception))

        ends_mid = dict(base)
        ends_mid["steps"] = [
            {"path": "a.py", "line": 8, "role": "source"},
            {"path": "mid.py", "line": 2, "role": "propagator"},
        ]
        with self.assertRaises(InvalidInputError) as ctx3:
            self.validator.validate_finding(ends_mid)
        self.assertIn("sink", str(ctx3.exception))

        empty_steps = dict(base)
        empty_steps["steps"] = []
        with self.assertRaises(InvalidInputError):
            self.validator.validate_finding(empty_steps)

    # -- E3 prohibited in the first version ----------------------------------
    def test_e3_claim_is_prohibited(self):
        base = self.verifier.create_finding_from_candidate(
            _candidate(), "confirmed", "vt-6",
            verify_attempt_id="att-verify", hunt_attempt_id="att-hunt",
            impact=4, exploitability=4,
            impact_why="Attacker body reaches unpickle without validation",
            exploitability_why="Upload endpoint needs no authentication",
        )
        e3 = dict(base)
        e3["evidence_level"] = "E3"
        with self.assertRaises(InvalidInputError) as ctx:
            self.validator.validate_finding(e3)
        self.assertIn("E3", str(ctx.exception))
        self.assertIn("prohibited", str(ctx.exception))

    def test_unknown_evidence_levels_fail(self):
        base = {
            "schema_version": "1.0",
            "finding_id": "F-LVL",
            "verdict": "rejected",
            "evidence_level": "E9",
            "counter_evidence": {"rationale": "constant input"},
        }
        with self.assertRaises(InvalidInputError) as ctx:
            self.validator.validate_finding(base)
        self.assertIn("E1 or E2", str(ctx.exception))

    def test_e1_default_for_every_non_confirmed_verdict(self):
        cand = _candidate()
        pending = self.verifier.create_finding_from_candidate(
            cand, "needs_validation", "vt-7", impact=2, exploitability=2,
            blockers=["deployment facts unknown"],
            validation_plan="probe the deployment",
        )
        rejected = self.verifier.create_finding_from_candidate(
            cand, "rejected", "vt-8",
            counter_evidence={"rationale": "constant input"},
        )
        unverified = self.verifier.create_finding_from_candidate(
            cand, "unverified", "vt-9", unverified_reason="budget exhausted",
        )
        for finding in (pending, rejected, unverified):
            self.assertEqual(finding["evidence_level"], "E1", finding["verdict"])

    # -- missing preconditions fall back to needs_validation -----------------
    def test_missing_deployment_preconditions_stay_pending(self):
        """When a necessary premise is missing, the verdict stays unconfirmed."""
        finding = self.verifier.create_finding_from_candidate(
            _candidate(),
            "needs_validation",
            "vt-10",
            impact=4,
            exploitability=3,
            blockers=[
                "Deployment uses a runtime WAF whose state is unknown; "
                "reachability cannot be proven statically"
            ],
            validation_plan="Replay the request path in the deployed environment",
        )
        self.assertEqual(finding["verdict"], "needs_validation")
        self.assertEqual(finding["evidence_level"], "E1")
        self.assertTrue(finding["blockers"])
        self.assertTrue(finding["validation_plan"])

    def test_confirmed_missing_required_field_is_refused(self):
        """A confirmed claim missing a necessary premise cannot be validated."""
        base = self.verifier.create_finding_from_candidate(
            _candidate(), "confirmed", "vt-11",
            verify_attempt_id="att-verify", hunt_attempt_id="att-hunt",
            impact=4, exploitability=4,
            impact_why="Attacker body reaches unpickle without validation",
            exploitability_why="Upload endpoint needs no authentication",
        )
        for drop in ("remediation", "rating", "languages", "title"):
            broken = dict(base)
            broken.pop(drop)
            with self.assertRaises(InvalidInputError) as ctx:
                self.validator.validate_finding(broken)
            self.assertIn(drop, str(ctx.exception))

    def test_invalid_verdict_shape_is_refused(self):
        with self.assertRaises(InvalidInputError) as ctx:
            self.validator.validate_finding({
                "schema_version": "1.0",
                "finding_id": "F-X",
                "verdict": "confirmed_likely",
                "evidence_level": "E2",
            })
        self.assertIn("Invalid verdict", str(ctx.exception))

    def test_provenance_cycle_refused(self):
        base = self.verifier.create_finding_from_candidate(
            _candidate(), "confirmed", "vt-12",
            verify_attempt_id="att-verify", hunt_attempt_id="att-hunt",
            impact=3, exploitability=3,
            impact_why="Attacker body reaches unpickle without validation",
            exploitability_why="Upload endpoint needs no authentication",
        )
        cyclic = dict(base)
        cyclic["finding_id"] = "cand-e2-1"
        cyclic["provenance"] = dict(base["provenance"], candidates=["cand-e2-1"])
        with self.assertRaises(InvalidInputError) as ctx:
            self.validator.validate_finding(cyclic)
        self.assertIn("Cycle", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
