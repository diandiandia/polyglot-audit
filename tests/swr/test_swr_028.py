"""SWR-028 acceptance tests: upgrade admission, independent-run counting,
blocking exceptions, synthetic regressions, and auditable records.

验收原文 (docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2, SWR-028):
    "建立升级准入、独立运行计数、阻断例外、合成回归与审核记录；测试单次非
    阻断性条目不能直接准入。"

细化依据: DSR-045: "两次独立运行或有记录的阻断例外可进入评审而非自动合并。"
DSR-077: "实现语言卡正向准入、公开来源和合成正反例检查；自动检查与逐语言
人工评审分开……不能仅凭 150 数量宣称质量。"

Covered here:
- A single non-blocking entry is never admitted (single run, duplicated run
  id, or empty evidence all fail).
- Two genuinely independent runs admit the entry into review; a recorded
  blocking exception with an explicit rationale admits it too.
- An admission record is reviewable: decision, UTC timestamp, payload digest,
  and the deduplicated run list are all recorded and reproducible.
- A synthetic regression entry (a proposed knowledge-card change backed by a
  single run and no exception) is refused; a card that fails the quality
  gate cannot be admitted either.
"""

import copy
import unittest
from datetime import datetime

from auditkit.knowledge.admission import CardAdmissionChecker

VALID_PAYLOAD = {
    "schema_version": "1.0",
    "generation_id": "gen-abcdef01",
    "run_id": "run-1234abcd",
    "run_summary": {
        "run_state": "complete",
        "total_files_audited": 3,
        "total_lines_audited": 90,
        "total_confirmed_findings": 0,
        "total_needs_validation": 1,
        "total_tasks_executed": 4,
        "retries": 0,
        "language": "en",
    },
    "anomaly_categories": ["verification"],
}


class TestSWR028(unittest.TestCase):

    def setUp(self):
        self.checker = CardAdmissionChecker()

    # -- single non-blocking entries never admit -----------------------------
    def test_single_run_entry_is_not_admitted(self):
        """单次非阻断性条目不能直接准入."""
        admitted, reason = self.checker.check_upgrade_admission(
            "card-update-1", independent_run_ids=["run-1"]
        )
        self.assertFalse(admitted)
        self.assertIn("2 independent runs", reason)
        self.assertIn("found 1", reason)

    def test_duplicated_run_ids_count_once(self):
        admitted, reason = self.checker.check_upgrade_admission(
            "card-update-2", independent_run_ids=["run-1", "run-1", "run-1"]
        )
        self.assertFalse(admitted)
        self.assertIn("found 1", reason)

    def test_empty_evidence_is_not_admitted(self):
        admitted, reason = self.checker.check_upgrade_admission(
            "card-update-3", independent_run_ids=[]
        )
        self.assertFalse(admitted)
        self.assertIn("found 0", reason)

    def test_single_run_portable_review_is_rejected_with_reason(self):
        result = self.checker.admit_portable_review(
            copy.deepcopy(VALID_PAYLOAD), independent_run_ids=["run-only"]
        )
        self.assertFalse(result["admitted"])
        self.assertTrue(
            any("2 independent runs" in r for r in result["reasons"]),
            result["reasons"],
        )
        self.assertEqual(result["admission_record"]["decision"], "rejected")

    # -- two independent runs or a recorded blocking exception ----------------
    def test_two_independent_runs_admit_into_review(self):
        """Two distinct runs admit the entry for review — not an auto-merge."""
        admitted, reason = self.checker.check_upgrade_admission(
            "card-update-4", independent_run_ids=["run-a", "run-b"]
        )
        self.assertTrue(admitted)
        self.assertIn("2 independent run corroborations", reason)

        result = self.checker.admit_portable_review(
            copy.deepcopy(VALID_PAYLOAD), independent_run_ids=["run-a", "run-b"]
        )
        self.assertTrue(result["admitted"])
        self.assertEqual(result["admission_record"]["decision"], "admitted")
        # The outcome is a reviewable admission record — the caller still
        # owns the merge decision; admission itself writes nothing anywhere.
        self.assertIn("payload_digest", result["admission_record"])

    def test_blocking_exception_requires_a_recorded_rationale(self):
        """An unexplained "blocking" claim is not an exception."""
        admitted, reason = self.checker.check_upgrade_admission(
            "card-update-5",
            independent_run_ids=["run-1"],
            is_blocking_exception=True,
            blocking_rationale="",
        )
        self.assertFalse(admitted)
        self.assertIn("explicit rationale", reason)

    def test_recorded_blocking_exception_admits_with_rationale(self):
        admitted, reason = self.checker.check_upgrade_admission(
            "card-update-6",
            independent_run_ids=["run-1"],
            is_blocking_exception=True,
            blocking_rationale="incorrect safe-example ships broken guidance to all users",
        )
        self.assertTrue(admitted)
        self.assertIn("blocking exception", reason)
        self.assertIn("incorrect safe-example", reason)

        result = self.checker.admit_portable_review(
            copy.deepcopy(VALID_PAYLOAD),
            independent_run_ids=["run-1"],
            is_blocking_exception=True,
            blocking_rationale="privacy incident requires immediate review",
        )
        self.assertTrue(result["admitted"])
        self.assertTrue(result["admission_record"]["is_blocking_exception"])

    # -- the admission record is reviewable ------------------------------------
    def test_admission_record_is_reviewable_and_reproducible(self):
        payload = copy.deepcopy(VALID_PAYLOAD)
        first = self.checker.admit_portable_review(payload, ["run-a", "run-b"])
        second = self.checker.admit_portable_review(payload, ["run-a", "run-b"])

        record = first["admission_record"]
        self.assertEqual(record["decision"], "admitted")
        self.assertEqual(
            record["independent_run_ids"], ["run-a", "run-b"],
            "the reviewed run list is recorded, deduplicated and sorted",
        )
        decided_at = datetime.fromisoformat(record["decided_at"])
        self.assertEqual(decided_at.tzinfo is not None, True, "UTC timestamp")
        self.assertEqual(len(record["payload_digest"]), 64)

        # Identical decisions reproduce the same digest; different payloads
        # and different evidence produce different records.
        self.assertEqual(first["payload_digest"], second["payload_digest"])
        other = self.checker.admit_portable_review(
            payload, ["run-a", "run-b", "run-c"]
        )
        self.assertNotEqual(
            first["admission_record"]["independent_run_ids"],
            other["admission_record"]["independent_run_ids"],
        )
        payload_variant = copy.deepcopy(payload)
        payload_variant["run_summary"]["total_tasks_executed"] = 5
        variant = self.checker.admit_portable_review(
            payload_variant, ["run-a", "run-b"]
        )
        self.assertNotEqual(first["payload_digest"], variant["payload_digest"])

    def test_rejected_admission_record_is_reviewable_too(self):
        result = self.checker.admit_portable_review(
            copy.deepcopy(VALID_PAYLOAD), independent_run_ids=[]
        )
        record = result["admission_record"]
        self.assertEqual(record["decision"], "rejected")
        self.assertEqual(record["independent_run_ids"], [])
        self.assertEqual(record["payload_digest"], result["payload_digest"])
        self.assertTrue(result["reasons"])

    # -- synthetic regression entries -------------------------------------------
    def test_synthetic_regression_with_single_run_cannot_enter(self):
        """A one-run synthetic regression is refused like any other change."""
        regression_payload = copy.deepcopy(VALID_PAYLOAD)
        regression_payload["anomaly_categories"] = ["knowledge"]
        result = self.checker.admit_portable_review(
            regression_payload, independent_run_ids=["run-reg-1"]
        )
        self.assertFalse(result["admitted"])

    def test_card_failing_quality_gate_cannot_be_admitted(self):
        """The positive admission gate rejects a card without counterexamples."""
        weak_card = {
            "id": "xx-01",
            "title": "Some issue",
            "language": "x",
            "platform_conditions": "any",
            "security_mechanism": "mechanism",
            "source_sink_clues": {"source": "s", "sink": "k"},
            "tracking_guards": "guards",
            "not_candidate_when": "",  # missing false-positive conditions
            "synthetic_vulnerable_example": "eval(user_input_template) + padding!!",
            "synthetic_safe_example": "render(template_literal, user_data) + pad!",
            "public_references": ["CWE-95: https://cwe.mitre.org/data/definitions/95.html"],
            "signals": [{"pattern_id": "s", "pattern": "eval\\(", "kind": "sink", "strength": 3}],
            "review_record": {
                "status": "reviewed",
                "reviewer": "expert-1",
                "reviewed_at": "2026-11-16T00:00:00Z",
            },
        }
        ok, errors = self.checker.validate_card(weak_card)
        self.assertFalse(ok)
        self.assertTrue(any("not_candidate_when" in e for e in errors), errors)


if __name__ == "__main__":
    unittest.main()
