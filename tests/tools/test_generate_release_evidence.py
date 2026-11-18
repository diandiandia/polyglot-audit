"""Release evidence generator unit tests (DSR-051 / SR-029).

Lightweight tests for tools/generate_release_evidence.py: the normalization
functions are exercised against SAMPLE subprocess outputs (orchestrator
summary table, holdout report, isolation report, doctor envelope, unittest
verbose run, coordinator usage evidence) — the full unified suite is never
re-run here. Structure assertions cover:

- run_all_tests summary-table parsing (categories, counts, totals, skip list).
- Honest per-category verdicts (fail / pass / unknown; skips never become a
  pass).
- gateNN-summary.json bodies carry counts / duration / skip list / timestamp /
  environment+hardware.
- doctor envelope -> capability_matrix normalization consumed by
  ReleaseGateEvaluator.check_gate_01 (states kept verbatim, unknown blocks).
- holdout evidence keeps llm_results unknown (no fabricated online eval).
- P2.1a: the coordinator GATE-03 usage evidence is consumed verbatim
  (downgrade_documented / release_note_required pass through; missing
  file/fields stay unknown), the usage-telemetry sub-item leaves
  manual_pending, and check_gate_03 emits fail + release-note reason for a
  documented downgrade (SD §5.2 honest-degradation branch — never a pass).
- P2.1b: unittest -v export-boundary output parses into per-test outcomes;
  gate06-export-boundary.json carries counts / key assertions / manual_review
  pending; the GATE-06 evidence entry is wired into the evaluator.
- collect_evidence with a MOCK subprocess runner writes every evidence file
  and yields release_blocked; a failing step degrades its own gate to
  error+unknown without blocking the other steps.
"""

from __future__ import annotations
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent.parent
TOOLS_DIR = ROOT / "tools"
SKILL_SCRIPTS = ROOT / "skill" / "scripts"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))
if str(SKILL_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SKILL_SCRIPTS))

import generate_release_evidence as gre  # noqa: E402
from auditkit.app.release import ReleaseGateEvaluator  # noqa: E402

ENV = {"python_version": "3.11.0", "platform": "test-platform", "cpu_count": 4}


def _row(category: str, label: str, n: int, f: int, e: int, s: int,
         t: float, st: str) -> str:
    """Render a summary row EXACTLY in the orchestrator's documented layout."""
    return (
        f"{category:<16} {label:<34} {n:>5} {f:>5} {e:>5} {s:>5} {t:>6.1f}s  {st}"
    )


SAMPLE_RUN_ALL = "\n".join([
    "=" * 92,
    "polyglot-audit: Unified Verification Suite (five-category orchestration, DSR-078)",
    "=" * 92,
    "",
    "### CATEGORY: deterministic",
    "  [RUNNING] Contracts & Schemas (tests/contracts)...",
    _row("deterministic", "Contracts & Schemas", 120, 0, 0, 2, 10.5, "PASS"),
    _row("deterministic", "Analysis, Verifier, & Rating", 72, 0, 0, 0, 3.2, "PASS"),
    _row("deterministic", "-- subtotal --", 700, 0, 0, 4, 60.0, "missing=0"),
    "",
    "### CATEGORY: real_cli",
    _row("real_cli", "Real Host CLI", 4, 0, 0, 0, 95.0, "PASS"),
    _row("real_cli", "-- subtotal --", 4, 0, 0, 0, 95.0, "missing=0"),
    "",
    "### CATEGORY: fault_injection",
    _row("fault_injection", "Fault Injection", 30, 0, 0, 1, 12.0, "PASS"),
    _row("fault_injection", "-- subtotal --", 30, 0, 0, 1, 12.0, "missing=0"),
    "",
    "### CATEGORY: scale",
    _row("scale", "Performance & Scale", 25, 1, 0, 0, 80.0, "FAIL"),
    _row("scale", "-- subtotal --", 25, 1, 0, 0, 80.0, "missing=0"),
    "=" * 92,
    "Total: tests=759 fail=1 err=0 skipped=5 missing=0 time=247.0s",
    "RESULT: FAILURES/ERRORS PRESENT",
])

SAMPLE_HOLDOUT = {
    "schema_version": "1.0",
    "generated_at": "2026-11-16T00:00:00Z",
    "corpus_status": "present",
    "totals": {
        "denominator": 300, "true_positive": 150, "false_negative": 0,
        "true_negative": 150, "false_positive": 0, "pending": 0,
        "unknown_categories": 0, "cards_total": 150,
    },
    "llm_worker": {
        "status": "host_available_dry_run_only",
        "host_clis": {"claude": True, "codex": True},
        "llm_results": "unknown",
        "note": "host CLI detected but no model call is executed by this tool",
    },
    "disclaimer": "synthetic development-time corpus",
}

SAMPLE_ISOLATION = {
    "schema_version": "1.0",
    "generated_at": "2026-11-16T00:00:00Z",
    "scope": "development-time demo fixtures (tempdir)",
    "probes": [
        {"probe": "symlink_escape", "status": "detected", "observed": True},
        {"probe": "race_write", "status": "detected", "observed": True},
    ],
    "real_target_results": "unknown",
    "limitations": ["probe result applies to the development-time demo fixture only"],
}

SAMPLE_CAPABILITIES = [
    {
        "schema_version": "1.0",
        "adapter": "python_core",
        "adapter_version": "3.11.0",
        "features": {
            "sqlite_wal": {"state": "ENFORCED", "method": "introspection"},
            "stdlib_offline": {"state": "ENFORCED", "method": "import probe"},
        },
    },
    {
        "schema_version": "1.0",
        "adapter": "claude_cli",
        "adapter_version": "2.1.319",
        "features": {
            "installed": {"state": "ENFORCED", "method": "shutil.which"},
            "headless_cli": {"state": "ENFORCED", "method": "claude --print"},
            "filesystem_isolation": {"state": "UNKNOWN", "method": "counterexample"},
        },
    },
    {
        "schema_version": "1.0",
        "adapter": "codex_cli",
        "adapter_version": "unknown",
        "features": {
            "installed": {"state": "ENFORCED", "method": "shutil.which"},
            "headless_cli": {"state": "UNKNOWN", "reason": "headless probe timed out after 90s"},
        },
    },
]

# P2.1a: coordinator-produced GATE-03 usage evidence (mirrors the shape of
# docs/evidence/gate03-usage-unavailable.json; run ids are run-XXX form only).
SAMPLE_GATE03_USAGE = {
    "schema_version": "1.0",
    "generated_at": "2026-11-18T13:12:26Z",
    "evidence_type": "GATE-03 real-run usage telemetry (SR-020/DSR-033)",
    "status": "downgrade_documented",
    "release_note_required": True,
    "attempts_total": 26,
    "availability_distribution": {"unavailable": 26},
    "conclusion": (
        "real host CLI (this version) does not report per-call token usage in "
        "headless mode; hard token budget claims remain unsupported"
    ),
    "per_run": [
        {"run_id": "run-7e0205c7", "attempts": 6,
         "availability_distribution": {"unavailable": 6}},
        {"run_id": "run-ecbd39fc", "attempts": 10,
         "availability_distribution": {"unavailable": 10}},
        {"run_id": "run-263f518b", "attempts": 10,
         "availability_distribution": {"unavailable": 10}},
    ],
}

# P2.1b: unittest -v output of the targeted export-boundary run (verbatim
# renderer layout, including the two-line docstring form).
SAMPLE_UNITTEST_VERBOSE = "\n".join([
    "test_export_injected_foreign_run_stats_fail_closed "
    "(tests.security.test_skill_isolation.TestExportFailureClosed."
    "test_export_injected_foreign_run_stats_fail_closed)",
    "run_stats carrying a non-whitelisted key must abort before staging. ... ok",
    "test_export_whitelist_rejects_foreign_stats_and_writes_nothing "
    "(tests.security.test_skill_isolation.TestExportFailureClosed."
    "test_export_whitelist_rejects_foreign_stats_and_writes_nothing) ... ok",
    "test_export_write_failure_raises_and_leaves_no_half_files "
    "(tests.security.test_skill_isolation.TestExportFailureClosed."
    "test_export_write_failure_raises_and_leaves_no_half_files) ... ok",
    "test_all_media_mask_secrets (tests.reporting.test_reporting.TestReporting."
    "test_all_media_mask_secrets) ... ok",
    "test_mask_csv_masks_cells (tests.reporting.test_reporting.TestReporting."
    "test_mask_csv_masks_cells) ... ok",
    "test_mask_tree_masks_nested_json_values (tests.reporting.test_reporting."
    "TestReporting.test_mask_tree_masks_nested_json_values) ... ok",
    "test_report_contains_unrecognized_secret_risk_clause "
    "(tests.reporting.test_reporting.TestReporting."
    "test_report_contains_unrecognized_secret_risk_clause) ... ok",
    "test_secret_masker (tests.reporting.test_reporting.TestReporting."
    "test_secret_masker) ... ok",
    "test_skill_review_export_rejects_non_whitelisted_keys "
    "(tests.reporting.test_reporting.TestReporting."
    "test_skill_review_export_rejects_non_whitelisted_keys) ... ok",
    "test_skill_review_json_exported_when_explicitly_enabled "
    "(tests.reporting.test_reporting.TestReporting."
    "test_skill_review_json_exported_when_explicitly_enabled) ... ok",
    "test_skill_review_json_not_exported_by_default "
    "(tests.reporting.test_reporting.TestReporting."
    "test_skill_review_json_not_exported_by_default) ... ok",
    "test_complete_run_archives_lessons_md_per_template "
    "(tests.swr.test_swr_031.TestSWR031LessonsArchive."
    "test_complete_run_archives_lessons_md_per_template) ... ok",
    "-" * 70,
    "Ran 12 tests in 0.256s",
    "",
    "OK",
])

SAMPLE_UNITTEST_FAIL_VERBOSE = "\n".join([
    "test_export_whitelist_rejects_foreign_stats_and_writes_nothing "
    "(tests.security.test_skill_isolation.TestExportFailureClosed."
    "test_export_whitelist_rejects_foreign_stats_and_writes_nothing) ... FAIL",
    "test_secret_masker (tests.reporting.test_reporting.TestReporting."
    "test_secret_masker) ... ok",
    "=" * 70,
    "FAIL: test_export_whitelist_rejects_foreign_stats_and_writes_nothing "
    "(tests.security.test_skill_isolation.TestExportFailureClosed."
    "test_export_whitelist_rejects_foreign_stats_and_writes_nothing)",
    "-" * 70,
    'Traceback (most recent call last):',
    '  File "tests/security/test_skill_isolation.py", line 362, in '
    'test_export_whitelist_rejects_foreign_stats_and_writes_nothing',
    "AssertionError: InvalidInputError not raised",
    "-" * 70,
    "Ran 2 tests in 0.100s",
    "",
    "FAILED (failures=1)",
])


class TestParseRunAllOutput(unittest.TestCase):

    def test_categories_counts_and_total_are_extracted(self):
        parsed = gre.parse_run_all_output(SAMPLE_RUN_ALL)
        self.assertEqual(parsed["result_line"], "FAILURES/ERRORS PRESENT")
        self.assertEqual(parsed["total"]["tests"], 759)
        self.assertEqual(parsed["total"]["fail"], 1)
        self.assertEqual(parsed["total"]["skipped"], 5)
        categories = parsed["categories"]
        for expected in ("deterministic", "real_cli", "fault_injection", "scale"):
            self.assertIn(expected, categories)
        self.assertEqual(categories["real_cli"]["tests"], 4)
        self.assertEqual(categories["real_cli"]["fail"], 0)
        self.assertEqual(categories["scale"]["fail"], 1)
        self.assertEqual(categories["deterministic"]["skipped"], 4)
        # Suite rows keep their names for the skip list.
        real_cli_suites = categories["real_cli"]["suites"]
        self.assertEqual([s["suite"] for s in real_cli_suites], ["Real Host CLI"])

    def test_garbage_output_yields_empty_parse_not_invented_counts(self):
        parsed = gre.parse_run_all_output("boom\nnot a table\n")
        self.assertEqual(parsed["suites"], [])
        self.assertEqual(parsed["categories"], {})
        self.assertEqual(parsed["total"], {})


class TestCategoryVerdict(unittest.TestCase):

    def test_fail_on_any_failure_or_error(self):
        status, summary = gre.category_verdict(
            {"tests": 25, "fail": 1, "error": 0, "skipped": 0,
             "missing_suites": 0, "duration_seconds": 1.0}, "scale"
        )
        self.assertEqual(status, "fail")
        self.assertIn("fail=1", summary)

    def test_all_skipped_is_unknown_never_pass(self):
        status, _ = gre.category_verdict(
            {"tests": 0, "fail": 0, "error": 0, "skipped": 4,
             "missing_suites": 0, "duration_seconds": 0.0}, "real_cli"
        )
        self.assertEqual(status, "unknown")

    def test_missing_suites_only_is_unknown(self):
        status, _ = gre.category_verdict(
            {"tests": 0, "fail": 0, "error": 0, "skipped": 0,
             "missing_suites": 2, "duration_seconds": 0.0}, "fault_injection"
        )
        self.assertEqual(status, "unknown")

    def test_absent_category_is_unknown(self):
        status, _ = gre.category_verdict(None, "model_eval")
        self.assertEqual(status, "unknown")

    def test_clean_category_passes_with_skips_disclosed(self):
        status, summary = gre.category_verdict(
            {"tests": 700, "fail": 0, "error": 0, "skipped": 4,
             "missing_suites": 0, "duration_seconds": 60.0}, "deterministic"
        )
        self.assertEqual(status, "pass")
        self.assertIn("skipped=4", summary)


class TestGateEvidenceBodies(unittest.TestCase):

    def test_gate_summary_carries_counts_duration_skips_timestamp_env(self):
        parsed = gre.parse_run_all_output(SAMPLE_RUN_ALL)
        body = gre.build_gate_test_summary(
            "GATE-02", "并发/崩溃/迟到提交/快照竞态夹具", "fault_injection", parsed, ENV
        )
        self.assertEqual(body["gate"], "GATE-02")
        self.assertEqual(body["status"], "pass")
        for key in ("generated_at", "environment", "counts", "duration_seconds",
                    "skipped_or_missing_suites", "suites", "summary", "notes"):
            self.assertIn(key, body)
        self.assertEqual(body["counts"]["tests"], 30)
        self.assertEqual(body["counts"]["skipped"], 1)
        self.assertEqual(body["environment"], ENV)
        skipped = body["skipped_or_missing_suites"]
        self.assertTrue(skipped and skipped[0]["skipped"] == 1)

    def test_failing_category_marks_gate_fail(self):
        parsed = gre.parse_run_all_output(SAMPLE_RUN_ALL)
        body = gre.build_gate_test_summary(
            "GATE-05", "性能与规模", "scale", parsed, ENV
        )
        self.assertEqual(body["status"], "fail")
        self.assertEqual(body["counts"]["fail"], 1)

    def test_absent_category_marks_gate_unknown(self):
        body = gre.build_gate_test_summary(
            "GATE-02", "故障注入", "fault_injection",
            {"suites": [], "categories": {}, "total": {}, "result_line": ""}, ENV,
            extra_notes=["统一测试编排器结果: skipped；本门禁证据保持 unknown。"],
        )
        self.assertEqual(body["status"], "unknown")
        self.assertIn("unknown", body["summary"])


class TestCapabilityMatrixEvidence(unittest.TestCase):

    def test_matrix_normalizes_and_blocks_on_unknown(self):
        real_cli_gate = {"status": "unknown", "summary": "skipped"}
        body = gre.build_capability_matrix_evidence(SAMPLE_CAPABILITIES, ENV, real_cli_gate)
        matrix = body["capability_matrix"]
        self.assertEqual(matrix["python_core"]["sqlite_wal"], "enforced")
        self.assertEqual(matrix["claude_cli"]["filesystem_isolation"], "unknown")
        self.assertEqual(matrix["codex_cli"]["headless_cli"], "unknown")
        # unknown capabilities are never promoted: the evidence status fails
        # and the blocking detail names the exact host.capability pairs.
        self.assertEqual(body["status"], "fail")
        self.assertIn("codex_cli.headless_cli=unknown", body["summary"])
        self.assertIn("claude_cli.filesystem_isolation=unknown", body["summary"])
        # Original probe records are preserved verbatim for auditability.
        self.assertEqual(body["adapters"], SAMPLE_CAPABILITIES)

    def test_envelope_extraction_is_defensive(self):
        envelope = json.dumps({"schema_version": "1.0", "ok": True,
                               "value": {"capabilities": SAMPLE_CAPABILITIES}})
        self.assertEqual(
            gre.extract_doctor_capabilities(envelope), SAMPLE_CAPABILITIES
        )
        # Alternate envelope shape (capabilities at top level) still found.
        self.assertEqual(
            gre.extract_doctor_capabilities(json.dumps({"capabilities": SAMPLE_CAPABILITIES})),
            SAMPLE_CAPABILITIES,
        )
        self.assertIsNone(gre.extract_doctor_capabilities("not json"))
        self.assertIsNone(gre.extract_doctor_capabilities(
            json.dumps({"ok": False, "error": {"code": "X", "message": "boom"}})
        ))


class TestHoldoutAndIsolationEvidence(unittest.TestCase):

    def test_holdout_evidence_keeps_llm_results_unknown(self):
        body = gre.build_holdout_evidence(SAMPLE_HOLDOUT, ENV)
        self.assertEqual(body["gate"], "GATE-04")
        self.assertEqual(body["status"], "unknown")
        self.assertEqual(body["llm_results"], "unknown")
        self.assertEqual(body["totals"]["denominator"], 300)
        self.assertIn("unknown", body["summary"])
        self.assertIn("LLM 在线评测", " ".join(body["not_automated"]))
        self.assertEqual(body["report"], SAMPLE_HOLDOUT)

    def test_isolation_evidence_stays_unknown_for_real_targets(self):
        body = gre.build_isolation_evidence(SAMPLE_ISOLATION, ENV)
        self.assertEqual(body["status"], "unknown")
        self.assertEqual(body["real_target_results"], "unknown")
        self.assertIn("symlink_escape=detected", body["summary"])


class TestParseUnittestVerbose(unittest.TestCase):
    """P2.1b: the unittest -v renderer is parsed into per-test outcomes."""

    def test_both_renderer_forms_and_counts_are_extracted(self):
        parsed = gre.parse_unittest_verbose(SAMPLE_UNITTEST_VERBOSE)
        self.assertEqual(parsed["counts"]["total"], 12)
        self.assertEqual(parsed["counts"]["passed"], 12)
        self.assertEqual(parsed["counts"]["failed"], 0)
        self.assertEqual(parsed["result_line"], "OK")
        self.assertIn("Ran 12 tests", parsed["summary_line"])
        ids = [t["test_id"] for t in parsed["tests"]]
        # Two-line docstring form is attributed to the preceding id line.
        self.assertIn(
            "tests.security.test_skill_isolation.TestExportFailureClosed."
            "test_export_injected_foreign_run_stats_fail_closed",
            ids,
        )
        # Single-line form and the lessons assertion are both captured.
        self.assertIn(
            "tests.reporting.test_reporting.TestReporting.test_secret_masker", ids
        )
        self.assertIn(
            "tests.swr.test_swr_031.TestSWR031LessonsArchive."
            "test_complete_run_archives_lessons_md_per_template",
            ids,
        )
        self.assertTrue(all(t["outcome"] == "ok" for t in parsed["tests"]))

    def test_failures_and_summary_lines_are_counted(self):
        parsed = gre.parse_unittest_verbose(SAMPLE_UNITTEST_FAIL_VERBOSE)
        self.assertEqual(parsed["counts"]["total"], 2)
        self.assertEqual(parsed["counts"]["failed"], 1)
        self.assertEqual(parsed["counts"]["passed"], 1)
        self.assertEqual(parsed["result_line"], "FAILED (failures=1)")
        # The stale pending id from the failure header must not swallow the
        # "Ran 2 tests" summary line, nor duplicate the failed test entry.
        self.assertEqual(
            len([t for t in parsed["tests"] if "whitelist" in t["test_id"]]), 1
        )
        self.assertIn("Ran 2 tests", parsed["summary_line"])

    def test_garbage_output_yields_empty_parse(self):
        parsed = gre.parse_unittest_verbose("boom\nnot unittest output\n")
        self.assertEqual(parsed["tests"], [])
        self.assertEqual(parsed["counts"]["total"], 0)
        self.assertEqual(parsed["result_line"], "")


class TestGate06ExportBoundaryEvidence(unittest.TestCase):

    def test_pass_body_carries_counts_assertions_and_manual_review(self):
        parsed = gre.parse_unittest_verbose(SAMPLE_UNITTEST_VERBOSE)
        body = gre.build_gate06_export_boundary_evidence(
            parsed, ENV, gre.GATE06_EXPORT_TEST_MODULES,
            gre.GATE06_EXPORT_TEST_PATTERNS, 0,
        )
        self.assertEqual(body["gate"], "GATE-06")
        self.assertEqual(body["evidence_kind"], "export_boundary_unittest")
        self.assertEqual(body["status"], "pass")
        self.assertEqual(body["counts"]["total"], 12)
        # Key assertion list is the verbatim per-test outcome list.
        self.assertEqual(len(body["key_assertions"]), 12)
        self.assertEqual(body["key_assertions"][0]["outcome"], "ok")
        for key in ("generated_at", "environment", "source", "summary", "notes"):
            self.assertIn(key, body)
        self.assertEqual(body["source"]["patterns"],
                         list(gre.GATE06_EXPORT_TEST_PATTERNS))
        self.assertEqual(body["source"]["exit_code"], 0)
        # The expert-review part of GATE-06 stays explicitly pending — the
        # automated run never closes it.
        self.assertEqual(body["manual_review"]["status"], "pending")
        self.assertTrue(body["manual_review"]["items"])

    def test_failures_mark_evidence_fail(self):
        parsed = gre.parse_unittest_verbose(SAMPLE_UNITTEST_FAIL_VERBOSE)
        body = gre.build_gate06_export_boundary_evidence(
            parsed, ENV, gre.GATE06_EXPORT_TEST_MODULES,
            gre.GATE06_EXPORT_TEST_PATTERNS, 1,
        )
        self.assertEqual(body["status"], "fail")
        self.assertEqual(body["counts"]["failed"], 1)
        self.assertEqual(body["source"]["exit_code"], 1)

    def test_no_matched_tests_stays_unknown_never_pass(self):
        parsed = gre.parse_unittest_verbose("no tests matched\n")
        body = gre.build_gate06_export_boundary_evidence(
            parsed, ENV, gre.GATE06_EXPORT_TEST_MODULES,
            gre.GATE06_EXPORT_TEST_PATTERNS, 5,
        )
        self.assertEqual(body["status"], "unknown")
        self.assertIn("unknown", body["summary"])


class TestGate03UsageEvidence(unittest.TestCase):

    def _write_usage_file(self, payload: dict, dir_path: Path) -> Path:
        path = dir_path / "gate03-usage-unavailable.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_downgrade_markers_pass_through_verbatim(self):
        with tempfile.TemporaryDirectory(prefix="g03-usage-") as tmp:
            path = self._write_usage_file(SAMPLE_GATE03_USAGE, Path(tmp))
            body = gre.load_gate03_usage_evidence(path, ENV)
            self.assertEqual(body["gate"], "GATE-03")
            self.assertEqual(body["status"], "downgrade_documented")
            self.assertIs(body["release_note_required"], True)
            self.assertEqual(body["attempts_total"], 26)
            self.assertEqual(
                body["availability_distribution"], {"unavailable": 26}
            )
            self.assertEqual(body["conclusion"], SAMPLE_GATE03_USAGE["conclusion"])
            # The tool records the honest-degradation reading without
            # upgrading it into a pass.
            self.assertIn("不给 pass", body["summary"])
            for key in ("generated_at", "environment", "source"):
                self.assertIn(key, body)

    def test_missing_file_stays_unknown(self):
        body = gre.load_gate03_usage_evidence(
            Path("/nonexistent/gate03-usage-unavailable.json"), ENV
        )
        self.assertEqual(body["status"], "unknown")
        self.assertEqual(body["release_note_required"], "unknown")
        self.assertIn("error", body)

    def test_missing_fields_are_recorded_as_unknown(self):
        with tempfile.TemporaryDirectory(prefix="g03-usage-") as tmp:
            path = self._write_usage_file({"attempts_total": 26}, Path(tmp))
            body = gre.load_gate03_usage_evidence(path, ENV)
            self.assertEqual(body["status"], "unknown")
            self.assertEqual(body["release_note_required"], "unknown")
            self.assertEqual(body["attempts_total"], 26)

    def test_non_boolean_release_note_required_is_unknown(self):
        with tempfile.TemporaryDirectory(prefix="g03-usage-") as tmp:
            path = self._write_usage_file(
                {"status": "downgrade_documented", "release_note_required": "yes"},
                Path(tmp),
            )
            body = gre.load_gate03_usage_evidence(path, ENV)
            self.assertEqual(body["status"], "downgrade_documented")
            self.assertEqual(body["release_note_required"], "unknown")


class TestGate03Gate06EvaluatorSemantics(unittest.TestCase):
    """P2.1a/2.1b evaluator wiring: the documented GATE-03 downgrade is never
    a pass; the GATE-06 evidence entry is consumed with the existing generic
    (fail-closed) contract."""

    def test_documented_downgrade_is_fail_with_release_note_reason(self):
        evaluator = ReleaseGateEvaluator({
            "GATE-03": {
                "status": "downgrade_documented",
                "release_note_required": True,
                "attempts_total": 26,
                "availability_distribution": {"unavailable": 26},
            },
        })
        result = evaluator.evaluate_gate("GATE-03")
        self.assertEqual(result.status, "fail")
        self.assertIn("发布说明", result.reason)
        self.assertIn("release_note_required=True", result.reason)
        self.assertIn("硬预算", result.reason)
        self.assertEqual(result.checks[0].status, "fail")
        aggregate = evaluator.evaluate_all({
            "GATE-03": {
                "status": "downgrade_documented",
                "release_note_required": True,
            },
        })
        self.assertFalse(aggregate["release_allowed"])
        self.assertTrue(
            any("GATE-03" in b and "发布说明" in b for b in aggregate["blocking"])
        )

    def test_gate03_generic_statuses_keep_existing_semantics(self):
        passing = ReleaseGateEvaluator(
            {"GATE-03": {"status": "pass", "summary": "仅发布软预算/任务预算模式"}}
        ).evaluate_gate("GATE-03")
        self.assertEqual(passing.status, "pass")

        unknown = ReleaseGateEvaluator().evaluate_gate("GATE-03")
        self.assertEqual(unknown.status, "fail")
        self.assertIn("未提供证据", unknown.reason)

    def test_gate06_pass_evidence_is_consumed_generic_fail_closed(self):
        passing = ReleaseGateEvaluator(
            {"GATE-06": {"status": "pass", "summary": "导出边界合成反例通过"}}
        ).evaluate_gate("GATE-06")
        self.assertEqual(passing.status, "pass")

        blocked = ReleaseGateEvaluator(
            {"GATE-06": {"status": "unknown", "summary": "未匹配到测试"}}
        ).evaluate_gate("GATE-06")
        self.assertEqual(blocked.status, "fail")


class TestCollectEvidenceWithMockRunner(unittest.TestCase):
    """Mock-subprocess end-to-end: every evidence file gets written from
    sample outputs and the release conclusion is honestly blocked."""

    def _fake_runner(self, run_all_stdout=SAMPLE_RUN_ALL, run_all_rc=0,
                     doctor_caps=SAMPLE_CAPABILITIES, doctor_ok=True,
                     holdout=SAMPLE_HOLDOUT, isolation=SAMPLE_ISOLATION,
                     unittest_output=SAMPLE_UNITTEST_VERBOSE, unittest_rc=0):
        calls = []

        def runner(cmd, capture_output, text, timeout, cwd):
            calls.append(" ".join(cmd[:3]))
            completed = SimpleNamespace(returncode=0, stdout="", stderr="")
            joined = " ".join(cmd)
            if "run_all_tests.py" in joined:
                completed.returncode = run_all_rc
                completed.stdout = run_all_stdout
            elif "evaluate_holdout.py" in joined:
                out = Path(cmd[cmd.index("--out") + 1])
                out.mkdir(parents=True, exist_ok=True)
                (out / "holdout_report.json").write_text(
                    json.dumps(holdout), encoding="utf-8"
                )
            elif "probe_isolation.py" in joined:
                out = Path(cmd[cmd.index("--out") + 1])
                out.mkdir(parents=True, exist_ok=True)
                (out / "isolation_probe_report.json").write_text(
                    json.dumps(isolation), encoding="utf-8"
                )
            elif "audit.py" in joined:
                if doctor_ok:
                    completed.stdout = json.dumps(
                        {"schema_version": "1.0", "ok": True,
                         "value": {"capabilities": doctor_caps}}
                    )
                else:
                    completed.returncode = 1
                    completed.stderr = "doctor exploded"
            elif "-m unittest" in joined:
                completed.returncode = unittest_rc
                completed.stdout = unittest_output
            else:
                completed.returncode = 1
            return completed

        runner.calls = calls
        return runner

    def test_all_steps_produce_evidence_and_blocked_release(self):
        with tempfile.TemporaryDirectory(prefix="evidence-test-") as tmp:
            out_dir = Path(tmp)
            usage_path = out_dir / "gate03-usage-unavailable.json"
            usage_path.write_text(json.dumps(SAMPLE_GATE03_USAGE), encoding="utf-8")
            result = gre.collect_evidence(
                out_dir, run_tests=True, runner=self._fake_runner(),
                usage_unavailable_path=usage_path,
            )
            payload = result["payload"]
            # Every mandated artifact exists with the mandated name.
            expected = {
                "gate01-summary.json", "gate02-summary.json", "gate05-summary.json",
                "gate07-summary.json", "gate01-isolation.json",
                "gate01-capability-matrix.json", "gate04-holdout.json",
                "gate06-export-boundary.json", "release_gate_summary.json",
            }
            for name in expected:
                self.assertTrue((out_dir / name).exists(), f"missing {name}")
                with open(out_dir / name, "r", encoding="utf-8") as f:
                    doc = json.load(f)
                self.assertIn("generated_at", doc)
                self.assertIn("environment", doc)
            # GATE-01 evidence carries the matrix the evaluator reads.
            with open(out_dir / "gate01-capability-matrix.json", encoding="utf-8") as f:
                matrix_doc = json.load(f)
            self.assertIn("capability_matrix", matrix_doc)
            self.assertEqual(
                matrix_doc["capability_matrix"]["claude_cli"]["installed"], "enforced"
            )
            # P2.1b: the export-boundary evidence file carries the measured
            # per-test outcomes plus the pending expert-review block.
            with open(out_dir / "gate06-export-boundary.json", encoding="utf-8") as f:
                gate06_doc = json.load(f)
            self.assertEqual(gate06_doc["status"], "pass")
            self.assertEqual(gate06_doc["counts"]["total"], 12)
            self.assertEqual(len(gate06_doc["key_assertions"]), 12)
            self.assertEqual(gate06_doc["manual_review"]["status"], "pending")
            # P2.1a: the coordinator usage evidence is inlined verbatim.
            inline = payload["evidence_inline"]["gate03_usage"]
            self.assertEqual(inline["status"], "downgrade_documented")
            self.assertIs(inline["release_note_required"], True)
            self.assertEqual(inline["attempts_total"], 26)
            self.assertEqual(payload["evidence_files"]["GATE-03-usage"],
                             str(usage_path))
            self.assertEqual(payload["evidence_files"]["GATE-06"],
                             str(out_dir / "gate06-export-boundary.json"))
            # Release conclusion: unknown capability -> blocked, honestly.
            self.assertEqual(payload["verdict"], "release_blocked")
            self.assertFalse(payload["release_allowed"])
            gate_statuses = {
                g["gate_id"]: g["status"] for g in payload["release_gate"]["gates"]
            }
            self.assertEqual(
                gate_statuses,
                {"GATE-01": "fail", "GATE-02": "pass", "GATE-03": "fail",
                 "GATE-04": "fail", "GATE-05": "fail", "GATE-06": "pass",
                 "GATE-07": "pass"},
                "GATE-05 must fail from the sample scale failure; GATE-03 "
                "takes the SD §5.2 documented-downgrade branch (fail + "
                "release-note reason, never a pass); GATE-06 consumes the "
                "automated export-boundary evidence under the existing "
                "generic contract; the deterministic sample passes GATE-07",
            )
            self.assertTrue(
                any("GATE-01" in b for b in payload["release_gate"]["blocking"])
            )
            # The GATE-03 blocking reason names the release-note requirement.
            g03_block = [b for b in payload["release_gate"]["blocking"]
                         if b.startswith("GATE-03")]
            self.assertTrue(g03_block and "发布说明" in g03_block[0])
            # GATE-06 consumed the automated evidence: it no longer blocks.
            self.assertTrue(
                all(not b.startswith("GATE-06")
                    for b in payload["release_gate"]["blocking"])
            )
            manual_gates = {m["gate"] for m in payload["manual_pending"]}
            self.assertIn("GATE-03", manual_gates)
            self.assertIn("GATE-04", manual_gates)
            self.assertIn("GATE-06", manual_gates)
            # The usage-telemetry sub-item left manual_pending: the GATE-03
            # item is now about the token/cost hard caps only.
            g03_manual = [m for m in payload["manual_pending"]
                          if m["gate"] == "GATE-03"]
            self.assertEqual(len(g03_manual), 1)
            self.assertNotIn("用量完整性", g03_manual[0]["item"])
            self.assertIn("token", g03_manual[0]["item"])
            # The six collection steps were recorded.
            self.assertEqual(len(payload["steps"]), 6)
            by_step = {s["step"]: s for s in payload["steps"]}
            self.assertTrue(by_step["gate03_usage_evidence"]["ok"])
            self.assertTrue(by_step["gate06_export_tests"]["ok"])

    def test_nonzero_orchestrator_exit_still_parses_category_failures(self):
        """exit != 0 means some category FAILED — the summary table must then
        drive per-gate fail verdicts, not degrade everything to unknown."""
        with tempfile.TemporaryDirectory(prefix="evidence-test-") as tmp:
            out_dir = Path(tmp)
            runner = self._fake_runner(run_all_rc=1, run_all_stdout=SAMPLE_RUN_ALL)
            result = gre.collect_evidence(
                out_dir, run_tests=True, runner=runner,
                usage_unavailable_path=out_dir / "absent-usage.json",
            )
            payload = result["payload"]
            by_step = {s["step"]: s for s in payload["steps"]}
            self.assertEqual(by_step["run_all_tests"].get("exit_code"), 1)
            # The failing scale category is reported as a gate fail...
            with open(out_dir / "gate05-summary.json", encoding="utf-8") as f:
                gate05 = json.load(f)
            self.assertEqual(gate05["status"], "fail")
            self.assertEqual(gate05["source"]["orchestrator_exit_code"], 1)
            # ...while the clean categories keep their measured evidence.
            with open(out_dir / "gate02-summary.json", encoding="utf-8") as f:
                gate02 = json.load(f)
            self.assertEqual(gate02["status"], "pass")
            # And the release summary preserves the orchestrator provenance.
            self.assertEqual(payload["orchestrator"]["exit_code"], 1)
            self.assertEqual(payload["orchestrator"]["total"]["tests"], 759)

    def test_single_step_failure_degrades_only_its_own_gate(self):
        with tempfile.TemporaryDirectory(prefix="evidence-test-") as tmp:
            out_dir = Path(tmp)
            runner = self._fake_runner(run_all_rc=1, run_all_stdout="boom",
                                       doctor_ok=False)
            usage_path = out_dir / "absent-usage.json"
            result = gre.collect_evidence(
                out_dir, run_tests=True, runner=runner,
                usage_unavailable_path=usage_path,
            )
            payload = result["payload"]
            # The failing steps are recorded with their error, honestly.
            by_step = {s["step"]: s for s in payload["steps"]}
            self.assertFalse(by_step["run_all_tests"]["ok"])
            self.assertFalse(by_step["doctor_probe"]["ok"])
            # The coordinator usage artifact is absent: the read step records
            # unknown (no invented evidence) and GATE-03 stays fail-closed.
            self.assertFalse(by_step["gate03_usage_evidence"]["ok"])
            self.assertEqual(by_step["gate03_usage_evidence"]["status"], "unknown")
            g03_block = [b for b in payload["release_gate"]["blocking"]
                         if b.startswith("GATE-03")]
            self.assertTrue(g03_block and "未提供证据" in g03_block[0])
            self.assertNotIn("GATE-03-usage", payload["evidence_files"])
            # ...while the independent holdout/isolation steps still collected.
            self.assertTrue(by_step["evaluate_holdout"]["ok"])
            self.assertTrue(by_step["probe_isolation"]["ok"])
            self.assertTrue(by_step["gate06_export_tests"]["ok"])
            # The gate files all exist; the affected ones stay unknown.
            for name in ("gate01-summary.json", "gate01-capability-matrix.json",
                         "gate04-holdout.json", "gate01-isolation.json",
                         "gate06-export-boundary.json",
                         "release_gate_summary.json"):
                self.assertTrue((out_dir / name).exists())
            with open(out_dir / "gate01-summary.json", encoding="utf-8") as f:
                gate01 = json.load(f)
            self.assertEqual(gate01["status"], "unknown")
            with open(out_dir / "gate01-capability-matrix.json", encoding="utf-8") as f:
                matrix = json.load(f)
            self.assertEqual(matrix["status"], "unknown")
            self.assertEqual(matrix["capability_matrix"], {})
            # Without the usage evidence the usage-telemetry sub-item stays
            # in manual_pending (both aspects listed).
            g03_manual = [m for m in payload["manual_pending"]
                          if m["gate"] == "GATE-03"]
            self.assertEqual(len(g03_manual), 1)
            self.assertIn("用量完整性", g03_manual[0]["item"])
            # Release stays fail-closed blocked.
            self.assertEqual(payload["verdict"], "release_blocked")


class TestGateMapping(unittest.TestCase):

    def test_mandated_gates_are_mapped_to_orchestrator_categories(self):
        self.assertEqual(gre.GATE_CATEGORIES["GATE-01"]["category"], "real_cli")
        self.assertEqual(gre.GATE_CATEGORIES["GATE-02"]["category"], "fault_injection")
        self.assertEqual(gre.GATE_CATEGORIES["GATE-05"]["category"], "scale")
        self.assertEqual(gre.GATE_CATEGORIES["GATE-07"]["category"], "deterministic")


if __name__ == "__main__":
    unittest.main()
