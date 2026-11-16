"""Controlled import tests for portable skill-review data (DSR-071 / SWR-016 / SR-028).

The import gate is default-deny: a portable payload enters skill knowledge
only with (a) exact export-whitelist structure, (b) no free text / paths /
target identifiers, and (c) upgrade evidence (two independent runs or a
recorded blocking exception).
"""

# 需求追踪 (Requirement Traceability)
# ---------------------------------------------------------------------------
# 上层需求: docs/design/DETAILED_DEVELOPMENT_REQUIREMENTS.md DSR-071
# 设计依据: docs/design/SOFTWARE_DESIGN.md §8 (SD-11), SYSTEM_REQUIREMENTS.md SR-016/SR-028
# SWR-016  导出只允许有限的无自由文本字段，经审核后才可用于升级；失败关闭
# SWR-028  同类问题来自至少两次独立运行或属于阻断性缺陷，例外须记录
# ==============================================================================

from __future__ import annotations

import unittest

from auditkit.contracts.errors import InvalidInputError
from auditkit.knowledge.admission import CardAdmissionChecker


def _valid_payload() -> dict:
    return {
        "schema_version": "1.0",
        "generation_id": "gen-00000001",
        "run_id": "run-00000001",
        "run_summary": {
            "run_state": "complete",
            "total_files_audited": 12,
            "total_lines_audited": 400,
            "total_confirmed_findings": 1,
            "total_needs_validation": 0,
            "total_tasks_executed": 5,
            "retries": 0,
            "language": "zh",
        },
        "anomaly_categories": ["coverage", "cost"],
    }


class TestControlledImport(unittest.TestCase):

    def setUp(self):
        self.checker = CardAdmissionChecker()

    # --- happy path -------------------------------------------------------
    def test_valid_payload_with_two_independent_runs_is_admitted(self):
        result = self.checker.admit_portable_review(
            _valid_payload(), independent_run_ids=["run-a", "run-b"]
        )
        self.assertTrue(result["admitted"])
        self.assertEqual(result["reasons"], [])
        self.assertEqual(result["admission_record"]["decision"], "admitted")

    def test_blocking_exception_with_rationale_is_admitted(self):
        result = self.checker.admit_portable_review(
            _valid_payload(),
            independent_run_ids=["run-a"],
            is_blocking_exception=True,
            blocking_rationale="privacy incident requires immediate review",
        )
        self.assertTrue(result["admitted"])
        self.assertTrue(result["admission_record"]["is_blocking_exception"])

    # --- evidence gate (default deny) -------------------------------------
    def test_single_run_without_exception_is_rejected(self):
        result = self.checker.admit_portable_review(
            _valid_payload(), independent_run_ids=["run-a"]
        )
        self.assertFalse(result["admitted"])
        self.assertTrue(any("2 independent runs" in r for r in result["reasons"]))

    def test_blocking_exception_without_rationale_is_rejected(self):
        result = self.checker.admit_portable_review(
            _valid_payload(),
            independent_run_ids=["run-a"],
            is_blocking_exception=True,
            blocking_rationale="",
        )
        self.assertFalse(result["admitted"])

    def test_no_evidence_at_all_is_rejected(self):
        result = self.checker.admit_portable_review(
            _valid_payload(), independent_run_ids=[]
        )
        self.assertFalse(result["admitted"])

    # --- structural whitelist (raises, mirroring export side) --------------
    def test_non_whitelisted_root_key_raises(self):
        payload = _valid_payload()
        payload["project_name"] = "acme-portal"
        with self.assertRaises(InvalidInputError):
            self.checker.admit_portable_review(payload, ["run-a", "run-b"])

    def test_non_whitelisted_run_summary_key_raises(self):
        payload = _valid_payload()
        payload["run_summary"]["repo_url"] = "https://example.invalid/acme"
        with self.assertRaises(InvalidInputError):
            self.checker.admit_portable_review(payload, ["run-a", "run-b"])

    def test_non_scalar_run_summary_value_raises(self):
        payload = _valid_payload()
        payload["run_summary"]["total_files_audited"] = {"nested": 1}
        with self.assertRaises(InvalidInputError):
            self.checker.admit_portable_review(payload, ["run-a", "run-b"])

    def test_anomaly_category_outside_fixed_enum_raises(self):
        payload = _valid_payload()
        payload["anomaly_categories"] = ["the upload handler in app/handlers leaks"]
        with self.assertRaises(InvalidInputError):
            self.checker.admit_portable_review(payload, ["run-a", "run-b"])

    # --- free-text / path / identifier guard -------------------------------
    def test_long_free_text_in_scalar_is_policy_rejected(self):
        payload = _valid_payload()
        payload["run_summary"]["language"] = (
            "this language note is far too long and carries free text descriptions"
        )
        result = self.checker.admit_portable_review(payload, ["run-a", "run-b"])
        self.assertFalse(result["admitted"])
        self.assertTrue(any("exceeds 64 chars" in r for r in result["reasons"]))

    def test_path_like_string_is_policy_rejected(self):
        payload = _valid_payload()
        payload["run_summary"]["run_state"] = "complete"
        payload["generation_id"] = "../targets/acme/report"
        result = self.checker.admit_portable_review(payload, ["run-a", "run-b"])
        self.assertFalse(result["admitted"])
        self.assertTrue(any("path-like" in r for r in result["reasons"]))

    # --- record integrity --------------------------------------------------
    def test_admission_record_is_stable_and_digest_bound(self):
        payload = _valid_payload()
        r1 = self.checker.admit_portable_review(payload, ["run-a", "run-b"])
        r2 = self.checker.admit_portable_review(payload, ["run-a", "run-b"])
        self.assertEqual(r1["payload_digest"], r2["payload_digest"])
        self.assertEqual(r1["admission_record"]["payload_digest"], r1["payload_digest"])
        self.assertEqual(r1["admission_record"]["independent_run_ids"], ["run-a", "run-b"])


if __name__ == "__main__":
    unittest.main()

    def test_digest_is_key_order_independent(self):
        """SWR-016/028: semantically identical payloads produce identical
        admission records regardless of key insertion order (canonical JSON)."""
        p1 = _valid_payload()
        p2 = {
            "anomaly_categories": ["coverage", "cost"],
            "run_summary": {
                "language": "zh",
                "retries": 0,
                "total_tasks_executed": 5,
                "total_needs_validation": 0,
                "total_confirmed_findings": 1,
                "total_lines_audited": 400,
                "total_files_audited": 12,
                "run_state": "complete",
            },
            "run_id": "run-00000001",
            "generation_id": "gen-00000001",
            "schema_version": "1.0",
        }
        r1 = self.checker.admit_portable_review(p1, ["run-a", "run-b"])
        r2 = self.checker.admit_portable_review(p2, ["run-a", "run-b"])
        self.assertTrue(r1["admitted"])
        self.assertTrue(r2["admitted"])
        self.assertEqual(r1["payload_digest"], r2["payload_digest"])
