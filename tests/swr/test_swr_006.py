"""SWR-006 acceptance tests: recon structure, guard records, and prompt packets.

验收原文 (docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2, SWR-006):
    "建立 Recon 与守卫结构和提示包；测试条件启用、例外和未知，单靠注册锚点
    不得驳回候选。"

细化依据: DSR-024: "实现 Recon 包和 Guard 记录；已注册但条件未满足、明确例外
和 unknown 三种场景不能被错误视作全局生效。" SYSTEM_DESIGN: "status 为
observed/not_found/unknown；observed 要有锚点，unknown 要有原因；模型声明不
自动构成实际保护。"

Covered here:
- Guard records keep the three states (observed / not_found / unknown) through
  serialization and in the prompt summary; unknown is never promoted.
- evaluate_guards three scenarios: conditional enablement by applicability,
  explicit exception grants exemption with evidence, unknown keeps the
  decision unknown.
- A registered guard with verifiable anchors but no path exception neither
  exempts nor REJECTS the candidate: the candidate stays in the flow.
- No guard baseline is fabricated: with no recon-established baseline the
  hunt packet carries no guard section at all (baseline stays unknown), and
  the empty summary says so instead of inventing defenses.
"""

import unittest

from auditkit.analysis.guards import (
    GuardManager,
    GuardRecord,
    evaluate_guards,
)
from auditkit.analysis.packets import PacketBuilder
from auditkit.contracts.errors import InvalidInputError


def _candidate(sink_path: str = "app/db.py") -> dict:
    return {
        "candidate_id": "cand-guard-1",
        "issue": "py-03",
        "source": {"path": "app/web.py", "line": 3, "kind": "http", "lang": "python"},
        "sink": {"path": sink_path, "line": 20, "symbol": "query", "kind": "sql"},
        "steps": [
            {"path": "app/web.py", "line": 3, "role": "source"},
            {"path": sink_path, "line": 20, "role": "sink"},
        ],
    }


class TestSWR006(unittest.TestCase):

    # -- guard structure keeps the three states -----------------------------
    def test_guard_record_three_states_round_trip(self):
        for status in ("observed", "not_found", "unknown"):
            guard = GuardRecord(
                guard_id=f"g-{status}",
                status=status,
                mechanism=f"mechanism for {status}",
                anchors=[{"path": "app/db.py", "line_start": 1, "line_end": 5}],
                applicability="app/db.py",
                exceptions=["app/db.py"] if status == "observed" else [],
            )
            data = guard.to_dict()
            self.assertEqual(data["status"], status)
            revived = GuardRecord.from_dict(data)
            self.assertEqual(revived.status, status)
            self.assertEqual(revived.anchors, guard.anchors)
            self.assertEqual(revived.exceptions, guard.exceptions)

    def test_guard_summary_discloses_unknown_and_exception(self):
        manager = GuardManager()
        manager.add_guard(GuardRecord(
            guard_id="g-waf", status="unknown", mechanism="possible WAF",
            applicability="", exceptions=[],
        ))
        manager.add_guard(GuardRecord(
            guard_id="g-sanitize", status="observed", mechanism="param wrapper",
            anchors=[{"path": "app/db.py", "line_start": 10, "line_end": 12}],
            applicability="app/db.py", exceptions=["app/db.py"],
        ))
        summary = manager.render_prompt_summary()
        self.assertIn("[UNKNOWN] g-waf", summary)
        self.assertIn("[OBSERVED] g-sanitize", summary)
        self.assertIn("(1 anchors)", summary)
        self.assertIn("Exceptions: app/db.py", summary)

    # -- evaluate_guards: three scenarios never become a global effect ------
    def test_conditional_enablement_requires_applicability_coverage(self):
        """An observed guard only applies where its applicability covers."""
        guard = GuardRecord(
            guard_id="g-filter", status="observed", mechanism="input filter",
            anchors=[{"path": "app/db.py", "line_start": 1, "line_end": 3}],
            applicability="app/db.py", exceptions=[],
        )
        inside = evaluate_guards(_candidate("app/db.py"), [guard])
        outside = evaluate_guards(_candidate("other/store.py"), [guard])

        self.assertFalse(inside["exempt"])
        self.assertEqual(inside["status"], "not_exempt")
        self.assertTrue(
            any("applies to 'app/db.py'" in r for r in inside["reasons"]),
            inside["reasons"],
        )
        # Outside the applicability the guard has no effect on the decision
        # and is never promoted to a global exemption.
        self.assertFalse(outside["exempt"])
        self.assertEqual(outside["status"], "not_exempt")
        self.assertTrue(
            any("does not cover" in r for r in outside["reasons"]),
            outside["reasons"],
        )

    def test_registered_anchor_alone_neither_exempts_nor_rejects(self):
        """A registered guard with anchors but no exception keeps the candidate.

        "单靠注册锚点不得驳回候选" — the decision object has no rejection
        outcome: status stays not_exempt, the candidate continues in the flow,
        and the anchor is recorded as insufficient, not as proof.
        """
        guard = GuardRecord(
            guard_id="g-verified-wrapper", status="observed",
            mechanism="parameterized-query wrapper",
            anchors=[{"path": "app/db.py", "line_start": 10, "line_end": 12}],
            applicability="app/db.py",
            exceptions=[],  # no explicit exception for this path
        )
        decision = evaluate_guards(_candidate(), [guard])
        self.assertFalse(decision["exempt"])
        self.assertEqual(decision["status"], "not_exempt")
        self.assertNotIn("reject", " ".join(decision["reasons"]).lower())
        self.assertTrue(
            any("no exemption" in r for r in decision["reasons"]),
            decision["reasons"],
        )
        # Nothing in the decision dismisses the candidate: it may proceed to
        # verification with the guard noted.
        self.assertIn("g-verified-wrapper", decision["evaluated_guards"])

    def test_explicit_exception_grants_exemption_with_evidence(self):
        guard = GuardRecord(
            guard_id="g-sanitizer", status="observed", mechanism="strict encoder",
            anchors=[{"path": "app/db.py", "line_start": 10, "line_end": 12}],
            applicability="app/db.py", exceptions=["app/db.py"],
        )
        decision = evaluate_guards(_candidate(), [guard])
        self.assertTrue(decision["exempt"])
        self.assertEqual(decision["status"], "exempt")
        self.assertEqual(len(decision["evidence"]), 1)
        evidence = decision["evidence"][0]
        self.assertEqual(evidence["type"], "explicit_exception")
        self.assertEqual(evidence["covered_path"], "app/db.py")
        self.assertEqual(evidence["guard_id"], "g-sanitizer")

    def test_unknown_guard_keeps_decision_unknown(self):
        guard = GuardRecord(
            guard_id="g-waf", status="unknown", mechanism="maybe a WAF",
        )
        decision = evaluate_guards(_candidate(), [guard])
        self.assertFalse(decision["exempt"])
        self.assertEqual(decision["status"], "unknown")
        self.assertTrue(any("unknown" in r for r in decision["reasons"]))

    def test_unknown_guard_dominates_over_explicit_exception(self):
        """An unknown guard can never be promoted to a global exemption."""
        exception_guard = GuardRecord(
            guard_id="g-sanitizer", status="observed", mechanism="encoder",
            anchors=[{"path": "app/db.py", "line_start": 1, "line_end": 2}],
            applicability="app/db.py", exceptions=["app/db.py"],
        )
        unknown_guard = GuardRecord(
            guard_id="g-unverified-claims", status="unknown",
            mechanism="worker claims a global sanitizer",
        )
        decision = evaluate_guards(_candidate(), [exception_guard, unknown_guard])
        self.assertFalse(decision["exempt"])
        self.assertEqual(decision["status"], "unknown")

    def test_not_found_guard_has_no_effect_and_invalid_status_rejected(self):
        guard = GuardRecord(
            guard_id="g-absent", status="not_found", mechanism="checked, absent",
        )
        decision = evaluate_guards(_candidate(), [guard])
        self.assertFalse(decision["exempt"])
        self.assertEqual(decision["status"], "not_exempt")
        self.assertTrue(any("not_found" in r for r in decision["reasons"]))

        with self.assertRaises(InvalidInputError):
            evaluate_guards(_candidate(), [GuardRecord("g-bad", "assumed", "m")])
        with self.assertRaises(InvalidInputError):
            evaluate_guards("not-a-candidate", [])

    # -- no fabricated baseline ---------------------------------------------
    def test_missing_recon_baseline_leaves_hunt_packet_without_guards(self):
        """With no recon-established baseline, no guard section is invented.

        "with no recon worker no baseline is fabricated" (service contract):
        the hunt packet built from an empty baseline summary carries no
        Environment Guards section, i.e. the guard state stays unknown.
        """
        unit = {
            "unit_id": "u-hunt",
            "language": "python",
            "ranges": [{"path": "app.py", "line_start": 1, "line_end": 2}],
        }
        contents = {"app.py": "def f():\n    pass\n"}
        packet, digest, overflow = PacketBuilder().build_hunt_packet(
            "snp-x", unit, contents, guard_summary="",
        )
        self.assertNotIn("Environment Guards", packet["prompt_text"])
        self.assertNotIn("Defense Baseline", packet["prompt_text"])

    def test_empty_guard_manager_states_no_baseline_instead_of_inventing(self):
        empty_summary = GuardManager().render_prompt_summary()
        self.assertIn("No environment guards established", empty_summary)
        self.assertNotIn("[OBSERVED]", empty_summary)
        # And with guards, the summary never claims blanket protection.
        manager = GuardManager()
        manager.add_guard(GuardRecord(
            guard_id="g-observed", status="observed", mechanism="filter",
            applicability="app/db.py",
        ))
        summary = manager.render_prompt_summary()
        self.assertNotIn("global", summary.lower())
        self.assertIn("[OBSERVED] g-observed", summary)

    def test_recon_packet_embeds_baseline_and_language_index(self):
        builder = PacketBuilder()
        indexes = {"python": ["py-01: unsafe deserialization"]}
        packet, _, _ = builder.build_recon_packet(
            "snp-r",
            {"unit_id": "u-recon", "language": "python",
             "ranges": [{"path": "a.py", "line_start": 1, "line_end": 1}]},
            {"a.py": "x = 1\n"},
            guard_summary="Environment Defense Baseline:\n- [OBSERVED] g1: filter",
            language_indexes=indexes,
        )
        self.assertEqual(packet["task_kind"], "recon")
        self.assertIn("Environment Guards", packet["prompt_text"])
        self.assertIn("[OBSERVED] g1: filter", packet["prompt_text"])
        self.assertIn("py-01: unsafe deserialization", packet["prompt_text"])


if __name__ == "__main__":
    unittest.main()
