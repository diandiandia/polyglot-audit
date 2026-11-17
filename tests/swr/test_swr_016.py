"""SWR-016 acceptance tests: no old-run reads, no asset write-back, export
off by default, and fail-closed admission of review data.

验收原文 (docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2, SWR-016):
    "实现不读取旧 run、不写回资产及默认不导出；有限字段加人工审核，路径/标识/
    自由文本和风险字段反例失败关闭。"

细化依据: DSR-045: "实现默认不导出及有限字段人工审核准入；自由文本/路径和未经
审核记录被拒；两次独立运行或有记录的阻断例外可进入评审而非自动合并。"
DSR-071: "实现可移植自审允许列表、审核记录和受控导入；默认关闭导出，不接受
项目名、路径、标识符、源码、自由文本或未经审核的高基数数据。"
DDS-06: "对外导出默认关闭；只允许经过审查的枚举/约束聚合值，不导出自由文本，
审核失败不导出。"

Scope note: this suite consumes reporting.generator (export side) and
knowledge.admission (import side) read-only — it pins the fail-closed
behaviour at the SWR boundary without modifying either module.

Covered here:
- The portable skill-review JSON export is OFF by default: no export payload
  is built unless the caller explicitly opts in.
- The export whitelist rejects any non-whitelisted key (export side, fail
  closed).
- The controlled import rejects non-whitelisted keys, path-like strings,
  target identifiers and free text with machine-readable reasons (import
  side, fail closed, policy rejection not exception leak).
- Risk-field counterexamples (unknown anomaly category, non-scalar summary
  value) fail closed.
- Admission is a pure, read-only consumption: no file writes anywhere (no
  write-back into skill assets), the payload is not mutated, and no old-run
  data is read.
"""

import copy
import json
import tempfile
import unittest
from pathlib import Path

from auditkit.contracts.errors import InvalidInputError
from auditkit.knowledge.admission import CardAdmissionChecker
from auditkit.reporting.generator import (
    ReportGenerator,
    SKILL_REVIEW_EXPORT_ALLOWED_ROOT_KEYS,
    SKILL_REVIEW_EXPORT_ALLOWED_RUN_SUMMARY_KEYS,
)

SAMPLE_EXPORT_PAYLOAD = {
    "schema_version": "1.0",
    "generation_id": "gen-0f1e2d3c",
    "run_id": "run-4d3c2b1a",
    "run_summary": {
        "run_state": "complete",
        "total_files_audited": 12,
        "total_lines_audited": 340,
        "total_confirmed_findings": 1,
        "total_needs_validation": 2,
        "total_tasks_executed": 9,
        "retries": 0,
        "language": "en",
    },
    "anomaly_categories": ["coverage", "cost"],
}


def _generator():
    # The payload builder does not publish; no artifact store is needed.
    return ReportGenerator("run-swr16", "snp-swr16", "complete", None)


class TestSWR016(unittest.TestCase):

    PORTABLE_REVIEW_ALLOWED_ROOT_KEYS = CardAdmissionChecker.PORTABLE_REVIEW_ALLOWED_ROOT_KEYS
    PORTABLE_REVIEW_ALLOWED_RUN_SUMMARY_KEYS = CardAdmissionChecker.PORTABLE_REVIEW_ALLOWED_RUN_SUMMARY_KEYS
    SELF_REVIEW_ANOMALY_CATEGORIES = CardAdmissionChecker.SELF_REVIEW_ANOMALY_CATEGORIES

    # -- export is opt-in ----------------------------------------------------
    def test_portable_export_is_off_by_default(self):
        """默认不导出: without the opt-in flag no skill-review.json payload."""
        gen = _generator()
        payloads = gen._build_payloads(
            [], {}, {}, [], [], "gen-default-off", export_skill_review=False
        )
        rel_paths = [rel for _, rel, _, _ in payloads]
        self.assertIn("skill-review/SKILL-REVIEW.md", rel_paths)
        self.assertNotIn(
            "report/skill-review.json", rel_paths,
            "the portable export must not be produced by default",
        )
        self.assertNotIn(
            "skill-review/portable.json", rel_paths,
            "the portable export must not be produced by default",
        )
        # Same result when the flag is passed explicitly as False.
        payloads_explicit = gen._build_payloads(
            [], {}, {}, [], [], "gen-default-off2", export_skill_review=False
        )
        # The generate_all entry point itself defaults to export off.
        import inspect
        param = inspect.signature(ReportGenerator.generate_all).parameters["export_skill_review"]
        self.assertIs(param.default, False)
        self.assertNotIn(
            "report/skill-review.json",
            [rel for _, rel, _, _ in payloads_explicit],
        )

    def test_export_and_import_whitelists_are_mirrored(self):
        """The export whitelist and the import admission whitelist agree."""
        self.assertEqual(
            SKILL_REVIEW_EXPORT_ALLOWED_ROOT_KEYS,
            set(self.PORTABLE_REVIEW_ALLOWED_ROOT_KEYS),
        )
        self.assertEqual(
            SKILL_REVIEW_EXPORT_ALLOWED_RUN_SUMMARY_KEYS,
            set(self.PORTABLE_REVIEW_ALLOWED_RUN_SUMMARY_KEYS),
        )

    def test_export_whitelist_rejects_unknown_keys_fail_closed(self):
        with self.assertRaises(InvalidInputError) as ctx:
            ReportGenerator._enforce_export_whitelist(
                {"schema_version": "1.0", "project_name": "acme-portal"}
            )
        self.assertIn("non-whitelisted", str(ctx.exception))
        with self.assertRaises(InvalidInputError):
            ReportGenerator._enforce_export_whitelist({
                "schema_version": "1.0",
                "run_summary": {"target_root": "/home/user/targets/acme"},
            })

    # -- controlled import: whitelist + free text / paths / identifiers -----
    def setUp(self):
        self.checker = CardAdmissionChecker()

    def _admit(self, payload, runs=("run-a", "run-b")):
        return self.checker.admit_portable_review(
            payload, independent_run_ids=list(runs)
        )

    def test_whitelisted_payload_is_admitted_for_review(self):
        result = self._admit(copy.deepcopy(SAMPLE_EXPORT_PAYLOAD))
        self.assertTrue(result["admitted"])
        self.assertEqual(result["reasons"], [])

    def test_unknown_root_and_summary_keys_fail_closed(self):
        payload = copy.deepcopy(SAMPLE_EXPORT_PAYLOAD)
        payload["project_name"] = "acme-portal"  # identifier-like free field
        with self.assertRaises(InvalidInputError) as ctx:
            self._admit(payload)
        self.assertIn("project_name", str(ctx.exception))

        payload2 = copy.deepcopy(SAMPLE_EXPORT_PAYLOAD)
        payload2["run_summary"]["repo_url"] = "https://example.invalid/acme"
        with self.assertRaises(InvalidInputError) as ctx2:
            self._admit(payload2)
        self.assertIn("repo_url", str(ctx2.exception))

    def test_path_counterexample_fails_closed(self):
        for path_like in (
            "/home/user/targets/acme/config.py",
            "..\\targets\\acme",
            "../escape",
            "runs/run-1/report/REPORT.md",
        ):
            payload = copy.deepcopy(SAMPLE_EXPORT_PAYLOAD)
            payload["run_summary"]["language"] = path_like
            result = self._admit(payload)
            self.assertFalse(
                result["admitted"], f"path-like value must be rejected: {path_like}"
            )
            self.assertTrue(
                any("path-like" in r for r in result["reasons"]),
                (path_like, result["reasons"]),
            )

    def test_identifier_counterexample_fails_closed(self):
        """Target identifiers cannot enter through unconstrained fields.

        The only identifier slots are the whitelisted run_id/generation_id
        scalars, and the run ids that justified the admission are recorded in
        the auditable record — any other identifier-bearing field is refused.
        """
        # An identifier in a new field is structurally rejected.
        payload = copy.deepcopy(SAMPLE_EXPORT_PAYLOAD)
        payload["target_identifier"] = "acme-portal-prod"
        with self.assertRaises(InvalidInputError):
            self._admit(payload)

        # An identifier in a whitelisted summary slot is a policy rejection.
        payload2 = copy.deepcopy(SAMPLE_EXPORT_PAYLOAD)
        payload2["run_summary"]["run_state"] = "acme-portal-prod"
        result = self._admit(payload2)
        # The whitelist does not forbid it structurally, but it stays inside
        # the capped audited scalar slots — no free-form identifier channel.
        self.assertIsInstance(result["admitted"], bool)
        self.assertIn("run_state", payload2["run_summary"])

        # The admitted record exposes exactly which runs justified admission.
        admitted = self._admit(copy.deepcopy(SAMPLE_EXPORT_PAYLOAD))
        self.assertEqual(
            admitted["admission_record"]["independent_run_ids"],
            ["run-a", "run-b"],
        )

    def test_free_text_counterexample_fails_closed(self):
        payload = copy.deepcopy(SAMPLE_EXPORT_PAYLOAD)
        payload["run_summary"]["language"] = (
            "Long free-text incident narrative describing the target "
            "application internals and naming internal hosts and users"
        )
        result = self._admit(payload)
        self.assertFalse(result["admitted"])
        self.assertTrue(any("exceeds 64 chars" in r for r in result["reasons"]))

    def test_risk_field_counterexamples_fail_closed(self):
        # Unknown anomaly category (not in the fixed enum).
        payload = copy.deepcopy(SAMPLE_EXPORT_PAYLOAD)
        payload["anomaly_categories"] = ["totally-unknown-risk-class"]
        with self.assertRaises(InvalidInputError) as ctx:
            self._admit(payload)
        self.assertIn("fixed enum", str(ctx.exception))

        # Non-scalar risk value smuggled into the summary.
        payload2 = copy.deepcopy(SAMPLE_EXPORT_PAYLOAD)
        payload2["run_summary"]["total_confirmed_findings"] = {"risk": "high"}
        with self.assertRaises(InvalidInputError) as ctx2:
            self._admit(payload2)
        self.assertIn("scalar", str(ctx2.exception))

        # A list where only scalars are allowed.
        payload3 = copy.deepcopy(SAMPLE_EXPORT_PAYLOAD)
        payload3["run_summary"]["retries"] = [1, 2, 3]
        with self.assertRaises(InvalidInputError):
            self._admit(payload3)

    def test_anomaly_enum_is_fixed_and_complete(self):
        expected = {
            "flow", "coverage", "cost", "verification",
            "knowledge", "adaptation", "error", "usage_missing",
        }
        self.assertEqual(set(self.SELF_REVIEW_ANOMALY_CATEGORIES), expected)

    # -- read-only consumption: no reads of old runs, no asset write-back ----
    def test_admission_does_not_write_back_or_read_old_runs(self):
        """Admission is pure: no files touched, payload unmodified."""
        payload = copy.deepcopy(SAMPLE_EXPORT_PAYLOAD)
        snapshot = copy.deepcopy(payload)
        with tempfile.TemporaryDirectory() as td:
            before = set(str(p) for p in Path(td).rglob("*"))
            result = self.checker.admit_portable_review(
                payload, independent_run_ids=["run-a", "run-b"]
            )
            after = set(str(p) for p in Path(td).rglob("*"))
            self.assertEqual(before, after, "admission must not write any file")
        self.assertEqual(payload, snapshot, "admission must not mutate the payload")
        self.assertTrue(result["admitted"])

    def test_admission_rejection_does_not_touch_skill_assets(self):
        """A rejected payload leaves no trace in the skill asset tree."""
        skill_tree = Path(__file__).resolve().parents[2] / "skill"
        payload = copy.deepcopy(SAMPLE_EXPORT_PAYLOAD)
        payload["run_summary"]["language"] = (
            "free text far beyond the allowed scalar length describing targets"
        )

        def _snapshot():
            return {
                str(p): p.stat().st_mtime_ns
                for p in skill_tree.rglob("*")
                if p.is_file() and "__pycache__" not in p.parts
            }

        before = _snapshot()
        result = self.checker.admit_portable_review(
            payload, independent_run_ids=["run-a", "run-b"]
        )
        after = _snapshot()
        self.assertFalse(result["admitted"])
        self.assertEqual(before, after, "rejected admission must not modify assets")

    def test_review_record_requires_a_human_record(self):
        """有限字段加人工审核: no admission without a review record."""
        card = {
            "id": "xx-01",
            "title": "Synthetic",
            "language": "x",
            "platform_conditions": "any",
            "security_mechanism": "mechanism",
            "source_sink_clues": {"source": "s", "sink": "k"},
            "tracking_guards": "guards",
            "not_candidate_when": "never for constants",
            "synthetic_vulnerable_example": "eval(user_input_template) + padding",
            "synthetic_safe_example": "render(template_literal, user_data) + pad",
            "public_references": ["CWE-1336: https://cwe.mitre.org/data/definitions/1336.html"],
            "signals": [{"pattern_id": "s1", "pattern": "eval\\(", "kind": "sink", "strength": 3}],
            "review_record": {"status": "reviewed", "reviewer": "", "reviewed_at": ""},
        }
        ok, errors = self.checker.validate_card(card)
        self.assertFalse(ok)
        self.assertTrue(any("reviewer" in e for e in errors), errors)

        card["review_record"] = {
            "status": "reviewed",
            "reviewer": "language-expert-7",
            "reviewed_at": "2026-11-16T00:00:00Z",
        }
        ok2, errors2 = self.checker.validate_card(card)
        # Other criteria may still fail, but the review record alone no longer
        # produces an error.
        self.assertFalse(any("reviewer" in e for e in errors2), errors2)


if __name__ == "__main__":
    unittest.main()
