"""Tests for coverage calculation, secret masking, cost metrics, and report generation."""

import json
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from auditkit.contracts.errors import InvalidInputError, StorageError
from auditkit.ledger.artifacts import ArtifactManager
from auditkit.ledger.db import get_db_connection, init_database
from auditkit.reporting.cost import CostTracker
from auditkit.reporting.coverage import CoverageCalculator, compute_interval_union, count_covered_lines
from auditkit.reporting.generator import (
    ReportGenerator,
    SKILL_REVIEW_EXPORT_ALLOWED_ROOT_KEYS,
    SKILL_REVIEW_EXPORT_ALLOWED_RUN_SUMMARY_KEYS,
)
from auditkit.reporting.secret_masker import mask_csv_text, mask_json_text, mask_secrets

SECRET_VALUE = "supersecretpassword99"
SECRET_SNIPPET = f"password = '{SECRET_VALUE}'"
REDACT_MARKER = "[REDACTED_PASSWORD]"

REPORT_MEDIA = [
    "REPORT.md",
    "findings.json",
    "NEEDS-VALIDATION.md",
    "COVERAGE.md",
    "coverage.csv",
    "AUDIT-TRAIL.md",
    "COST.md",
    "SKILL-REVIEW.md",
]


def sample_findings():
    return [{
        "schema_version": "1.0",
        "finding_id": "F-001",
        "candidate_refs": ["c1"],
        "verdict": "confirmed",
        "evidence_level": "E2",
        "title": "Unsafe Deserialization",
        "issue": "py-01",
        "languages": ["python"],
        "source": {"path": "upload.py", "line": 10, "kind": "http"},
        "sink": {"path": "state.py", "line": 50, "kind": "pickle"},
        "steps": [
            {"path": "upload.py", "line": 10, "role": "source", "note": "read request body"},
            {"path": "state.py", "line": 50, "role": "sink", "note": f"unpickle; {SECRET_SNIPPET}"},
        ],
        "rating": {
            "impact": 4, "exploitability": 4,
            "calculated_severity": "Critical", "calculated_urgency": "P0",
            "final_severity": "Critical", "final_urgency": "P0",
            "factor_reasons": {"impact_why": "RCE", "exploitability_why": "Remote"},
        },
        "remediation": {"where": "state.py:50", "change": "Use JSON", "regression_test": "Reject pickle"},
        "provenance": {
            "hunt_tasks": ["HT-1"],
            "verify_tasks": ["VT-2"],
            "candidate_refs": ["C-9"],
            "attempt_ids": ["att-77"],
        },
    }]


def sample_coverage_summary():
    return {
        "total_files": 2,
        "total_inventoried_lines": 100,
        "dimension_covered_lines": {"inventoried": 100, "observed_read": 80},
        "dimension_percentages": {"inventoried": 100.0, "observed_read": 80.0},
        "file_breakdown": [
            {"path": "state.py", "language": "python", "total_lines": 100, "coverage_lines": {"inventoried": 100}}
        ],
    }


def sample_cost_metrics():
    return {
        "stage_tasks": {"hunt": 2, "verify": 1, "report": 1},
        "total_tasks": 4,
        "total_enqueued": 4,
        "total_executed": 3,
        "rates_denominator": "executed",
        "retries": 0,
        "tasks_per_kloc": 40.0,
        "tasks_per_finding": 4.0,
        "token_availability": "unavailable",
        "unavailable_reason": f"CLI does not supply token metrics; {SECRET_SNIPPET}",
    }


class ReportingTestBase(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "events.db"
        init_database(self.db_path)
        self.conn = get_db_connection(self.db_path)

        self.run_id = "run-rep-test"
        self.conn.execute(
            """
            INSERT INTO runs (run_id, snapshot_id, state, schema_version, skill_version, knowledge_version, config_ref, revision, created_at, updated_at)
            VALUES (?, 'snp-01', 'finalizing', '1.0', '0.1.0', '1.0', 'cfg', 1, '2026-11-14T00:00:00Z', '2026-11-14T00:00:00Z')
            """,
            (self.run_id,),
        )
        self.art_mgr = ArtifactManager(self.temp_dir, self.conn)
        self.rep_dir = Path(self.temp_dir) / "report"

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.temp_dir)

    def make_generator(self, language="en", state="complete"):
        return ReportGenerator(self.run_id, "snp-01", state, self.art_mgr, report_language=language)

    def generate(self, generator=None, findings=None, coverage=None, cost=None, events=None, **kwargs):
        generator = generator or self.make_generator()
        return generator.generate_all(
            findings if findings is not None else sample_findings(),
            coverage if coverage is not None else sample_coverage_summary(),
            cost if cost is not None else sample_cost_metrics(),
            events if events is not None else [],
            **kwargs,
        )

    def read(self, fname):
        return (self.rep_dir / fname).read_text(encoding="utf-8")


class TestReporting(ReportingTestBase):

    def test_interval_union_algorithm(self):
        # Disjoint
        self.assertEqual(compute_interval_union([(1, 10), (20, 30)]), [(1, 10), (20, 30)])
        # Overlapping
        self.assertEqual(compute_interval_union([(1, 10), (5, 15)]), [(1, 15)])
        # Adjacent
        self.assertEqual(compute_interval_union([(1, 10), (11, 20)]), [(1, 20)])
        # Contained
        self.assertEqual(compute_interval_union([(1, 20), (5, 10)]), [(1, 20)])

        self.assertEqual(count_covered_lines([(1, 10), (5, 15)]), 15)

    def test_secret_masker(self):
        raw_text = 'Bearer my_secret_token_1234567890\napi_key = "abc1234567890123"\npassword: "supersecretpass"'
        masked = mask_secrets(raw_text)

        self.assertNotIn("my_secret_token_1234567890", masked)
        self.assertNotIn("abc1234567890123", masked)
        self.assertIn("[REDACTED_BEARER_TOKEN]", masked)
        self.assertIn("[REDACTED_API_KEY]", masked)

    def test_mask_tree_masks_nested_json_values(self):
        # DSR-069: JSON media must be masked recursively by value.
        obj = {
            "note": SECRET_SNIPPET,
            "nested": {"deep": [{"bearer": f"Bearer {SECRET_VALUE}abc123"}]},
            "count": 3,
        }
        masked = mask_json_text(json.dumps(obj))
        self.assertNotIn(SECRET_VALUE, masked)
        self.assertIn(REDACT_MARKER, masked)
        self.assertIn('"count": 3', masked)

    def test_mask_csv_masks_cells(self):
        # DSR-069: CSV media must be masked per cell.
        csv_text = f"path,line,note\na.py,1,{SECRET_SNIPPET}\n"
        masked = mask_csv_text(csv_text)
        self.assertNotIn(SECRET_VALUE, masked)
        self.assertIn(REDACT_MARKER, masked)
        self.assertIn("a.py", masked)

    # --------------------------------------------------------------- DSR-045
    def test_skill_review_json_not_exported_by_default(self):
        # DSR-045 / SWR-016: portable export is opt-in.
        gen_id = self.generate()
        self.assertTrue(gen_id.startswith("gen-"))

        expected_files = REPORT_MEDIA
        for fname in expected_files:
            self.assertTrue((self.rep_dir / fname).exists(), f"Missing expected report file: {fname}")
        self.assertFalse((self.rep_dir / "skill-review.json").exists())

    def test_skill_review_json_exported_when_explicitly_enabled(self):
        self.generate(export_skill_review=True)
        self.assertTrue((self.rep_dir / "skill-review.json").exists())
        exported = json.loads(self.read("skill-review.json"))

        self.assertEqual(set(exported.keys()), set(SKILL_REVIEW_EXPORT_ALLOWED_ROOT_KEYS))
        self.assertTrue(set(exported["run_summary"].keys()).issubset(SKILL_REVIEW_EXPORT_ALLOWED_RUN_SUMMARY_KEYS))
        review_md = self.read("SKILL-REVIEW.md")
        gen_in_md = review_md.split("`gen-")[1][:8]
        self.assertEqual(exported["generation_id"], f"gen-{gen_in_md}")
        self.assertEqual(exported["schema_version"], "1.0")
        # Whitelisted statistics only; no findings detail leaked.
        dumped = json.dumps(exported)
        self.assertNotIn("Unsafe Deserialization", dumped)
        self.assertNotIn("upload.py", dumped)

    def test_skill_review_export_rejects_non_whitelisted_keys(self):
        from auditkit.reporting.generator import ReportGenerator as _RG

        with self.assertRaises(InvalidInputError) as ctx:
            _RG._enforce_export_whitelist({"schema_version": "1.0", "findings": [{"a": 1}]})
        self.assertIn("findings", str(ctx.exception))

        with self.assertRaises(InvalidInputError):
            _RG._enforce_export_whitelist({
                "schema_version": "1.0",
                "run_summary": {"run_state": "complete", "leaked_key": "x"},
            })

        with self.assertRaises(InvalidInputError):
            _RG._enforce_export_whitelist({
                "schema_version": "1.0",
                "run_summary": {"run_state": {"nested": "object"}},
            })

    # ------------------------------------------------------- DSR-069 / SWR-010
    def test_all_media_mask_secrets(self):
        self.generate(export_skill_review=True)
        media = REPORT_MEDIA + ["skill-review.json"]
        for fname in media:
            content = self.read(fname)
            self.assertNotIn(SECRET_VALUE, content, f"raw secret leaked in {fname}")
        # Redaction markers appear in every medium that carried the secret:
        # the step note reaches REPORT.md and findings.json, the cost
        # unavailable-reason reaches COST.md.
        for fname in ("REPORT.md", "findings.json", "COST.md"):
            self.assertIn(REDACT_MARKER, self.read(fname), f"expected redaction marker in {fname}")

    def test_report_contains_unrecognized_secret_risk_clause(self):
        self.generate()
        report = self.read("REPORT.md")
        self.assertIn("unrecognized", report.lower())
        self.assertIn("manually review", report.lower())

    # ---------------------------------------------------------------- DSR-035
    def test_finding_provenance_traceable(self):
        # DSR-035 / SWR-013: findings.json provenance must round-trip and the
        # AUDIT-TRAIL must expose hunt/verify tasks and candidate/attempt anchors.
        findings = sample_findings()
        self.generate(findings=findings)

        on_disk = json.loads(self.read("findings.json"))
        self.assertEqual(on_disk[0]["provenance"], findings[0]["provenance"])

        trail = self.read("AUDIT-TRAIL.md")
        prov = findings[0]["provenance"]
        for anchor in (
            prov["hunt_tasks"][0], prov["verify_tasks"][0],
            prov["candidate_refs"][0], prov["attempt_ids"][0],
        ):
            self.assertIn(anchor, trail, f"provenance anchor {anchor} missing from AUDIT-TRAIL")
        self.assertIn("F-001", trail)

    # ------------------------------------------------ O-03 cost denominators
    def test_cost_md_reports_enqueued_and_executed_as_two_lines(self):
        """O-03 (run lessons): COST.md labels the enqueued plan scope and the
        actually-executed count on two separate lines — a run that planned
        4464 units but processed 7 can never dress the plan up as executed
        work, and each number stays independently recomputable."""
        cost = dict(sample_cost_metrics())
        cost["total_enqueued"] = 12
        cost["total_tasks"] = 12
        cost["total_executed"] = 4
        self.generate(cost=cost)
        cost_md = self.read("COST.md")
        self.assertIn("**Total Enqueued Tasks**: 12", cost_md)
        self.assertIn("**Total Executed Tasks**: 4", cost_md)
        self.assertNotIn("**Total Executed Tasks**: 12", cost_md)
        self.assertNotIn("**Total Enqueued Tasks**: 4", cost_md)

    def test_cost_md_notes_unrecorded_executed_count(self):
        """A cost dict without executed counts renders the enqueued total on
        the executed line WITH the explicit not-recorded note — never as a
        silently promoted plan number."""
        cost = dict(sample_cost_metrics())
        cost.pop("total_executed")
        cost.pop("total_enqueued")
        self.generate(cost=cost)
        cost_md = self.read("COST.md")
        self.assertIn("**Total Executed Tasks**: 4 (executed count not recorded", cost_md)
        self.assertIn("**Total Enqueued Tasks**: 4", cost_md)

    # ------------------------------------------------- DSR-068 / SWR-012 i18n
    def test_language_en_default_headings(self):
        self.generate()  # default language is en
        report = self.read("REPORT.md")
        self.assertIn("Findings Summary", report)
        self.assertNotIn("发现总表", report)

    def test_language_zh_headings(self):
        self.generate(generator=self.make_generator(language="zh"))
        self.assertIn("发现总表", self.read("REPORT.md"))

    def test_unknown_language_falls_back_to_zh_and_is_recorded(self):
        self.generate(generator=self.make_generator(language="klingon"))
        report = self.read("REPORT.md")
        self.assertIn("发现总表", report)
        self.assertIn("klingon", report)  # fallback recorded in the report header
        self.assertIn("zh", report)

    def test_generation_id_in_all_attached_reports(self):
        gen_id = self.generate()
        for fname in ("REPORT.md", "NEEDS-VALIDATION.md", "COVERAGE.md", "AUDIT-TRAIL.md", "COST.md", "SKILL-REVIEW.md"):
            self.assertIn(gen_id, self.read(fname), f"generation id missing from {fname}")
        csv_content = self.read("coverage.csv")
        self.assertTrue(csv_content.startswith(f"# generation_id: {gen_id}"))

    # ------------------------------------------------ DSR-036 / SWR-012 atomic
    def test_write_failure_at_nth_file_leaves_no_mixed_generation(self):
        gen_a = self.generate()
        before_files = sorted(p.name for p in self.rep_dir.iterdir())
        before_report = self.read("REPORT.md")
        self.assertIn(gen_a, before_report)

        # Fail the tmp write of the Nth staged file (fsync raises on 4th call).
        real_fsync = __import__("os").fsync
        calls = {"n": 0}

        def flaky_fsync(fd):
            calls["n"] += 1
            if calls["n"] == 4:
                raise OSError("simulated disk failure")
            return real_fsync(fd)

        with mock.patch("auditkit.reporting.generator.os.fsync", side_effect=flaky_fsync):
            with self.assertRaises(StorageError):
                self.generate()

        # Old generation fully intact: same file set, same generation id.
        after_files = sorted(p.name for p in self.rep_dir.iterdir())
        self.assertEqual(before_files, after_files)
        self.assertEqual(self.read("REPORT.md"), before_report)
        for fname in REPORT_MEDIA:
            if fname == "findings.json":
                continue  # findings.json is a plain list; no generation marker by design
            self.assertIn(gen_a, self.read(fname), f"{fname} lost its generation after failed publish")
        # No staged temp leftovers.
        self.assertFalse([p.name for p in self.rep_dir.iterdir() if p.name.startswith(".tmp-stage-")])

    def test_staged_files_carry_generation_id_before_publish(self):
        # DSR-036: the pre-publish verification gate (marker check) aborts the
        # publish when a staged file lacks the generation marker.
        generator = self.make_generator()
        payloads = generator._build_payloads(
            sample_findings(), sample_coverage_summary(), sample_cost_metrics(), [],
            [], "gen-deadbeef", False,
        )
        # Every markdown medium and the CSV must carry the marker.
        for kind, rel_path, has_marker, content in payloads:
            if rel_path.endswith(".md") or rel_path.endswith(".csv"):
                self.assertTrue(has_marker, rel_path)
                self.assertIn(b"gen-deadbeef", content, rel_path)
            if rel_path == "report/findings.json":
                self.assertFalse(has_marker)

    # ---------------------------------------------------------------- DSR-044
    def test_skill_review_complete_scenario(self):
        stats = {
            "total_tasks": 12,
            "stage_tasks": {"recon": 2, "hunt": 6, "verify": 3, "report": 1},
            "coverage_summary": {"coverage_gaps": []},
            "cost_metrics": {"token_availability": "exact", "tasks_per_kloc": 4.5},
            "verdict_distribution": {"confirmed": 9, "needs_validation": 1, "unverified": 0},
            "knowledge_gaps": [],
            "knowledge_version": "1.0",
            "detected_languages": ["python", "go"],
            "uncovered_languages": [],
            "error_events": 0,
            "usage_missing_count": 0,
        }
        gen_id = self.generate(
            generator=self.make_generator(state="complete"),
            self_review_inputs=stats,
        )
        review = self.read("SKILL-REVIEW.md")
        self.assertIn(gen_id, review)
        self.assertIn("No significant process or contract anomalies detected.", review)

    def test_skill_review_incomplete_scenario(self):
        stats = {
            "total_tasks": 5,
            "stage_tasks": {"recon": 1, "hunt": 4, "verify": 0, "report": 0},
            "coverage_summary": {"coverage_gaps": [{"path": "x.py"}]},
            "cost_metrics": {"token_availability": "unavailable", "unavailable_reason": "no host telemetry", "tasks_per_kloc": None},
            "verdict_distribution": {"confirmed": 1, "needs_validation": 4, "unverified": 2},
            "knowledge_gaps": ["ts-js-sinks"],
            "knowledge_version": "1.0",
            "detected_languages": ["typescript"],
            "uncovered_languages": ["ruby"],
            "error_events": 2,
            "usage_missing_count": 3,
        }
        self.generate(
            generator=self.make_generator(state="incomplete"),
            self_review_inputs=stats,
        )
        review = self.read("SKILL-REVIEW.md")
        self.assertIn("incomplete", review)
        for category in ("flow", "coverage", "cost", "verification", "knowledge", "adaptation", "error", "usage_missing"):
            self.assertIn(category, review)

    def test_skill_review_write_failure_raises_storage_error_and_preserves_state(self):
        self.generate()  # establish a good generation first
        before = self.read("SKILL-REVIEW.md")

        real_fsync = __import__("os").fsync

        def failing_fsync(fd):
            raise OSError("simulated artifacts write failure")

        with mock.patch("auditkit.reporting.generator.os.fsync", side_effect=failing_fsync):
            with self.assertRaises(StorageError):
                self.generate()

        self.assertEqual(self.read("SKILL-REVIEW.md"), before)

    def test_skill_review_registered_in_artifacts_table(self):
        gen_id = self.generate()
        rows = self.conn.execute(
            "SELECT kind, relative_path, generation FROM artifacts WHERE run_id = ?", (self.run_id,)
        ).fetchall()
        rel_paths = {r["relative_path"] for r in rows}
        for fname in REPORT_MEDIA:
            self.assertIn(f"report/{fname}", rel_paths)
        self.assertTrue(all(r["generation"] == gen_id for r in rows))


class TestCostMetrics(unittest.TestCase):
    """DSR-067 / SWR-020 / O-03 (enqueued vs executed denominators)."""

    def test_zero_kloc_denominator_is_non_computable(self):
        tracker = CostTracker()
        tracker.record_task("hunt")
        metrics = tracker.compute_metrics(0, 0)
        self.assertIsNone(metrics["tasks_per_kloc"])
        self.assertEqual(metrics["tasks_per_kloc_status"], "non-computable")
        self.assertIn("total_lines", metrics["tasks_per_kloc_reason"])
        self.assertIsNone(metrics["tasks_per_finding"])
        self.assertEqual(metrics["tasks_per_finding_status"], "non-computable")

    def test_computable_rates(self):
        tracker = CostTracker()
        tracker.record_task("hunt")
        tracker.record_task("hunt")
        tracker.record_task("verify")
        metrics = tracker.compute_metrics(2000, 1)
        self.assertEqual(metrics["tasks_per_kloc"], 1.5)
        self.assertEqual(metrics["tasks_per_kloc_status"], "computed")
        self.assertEqual(metrics["tasks_per_finding"], 3.0)
        # O-03: this legacy tracker never recorded executed counts, so the
        # rates fall back to the enqueued total and SAY SO instead of
        # presenting the plan scope as executed work.
        self.assertEqual(metrics["rates_denominator"], "enqueued_fallback")
        self.assertIn("enqueued", metrics["tasks_per_kloc_reason"])
        self.assertIn("executed counts were not recorded", metrics["tasks_per_finding_reason"])

    def test_enqueued_and_executed_totals_are_reported_separately(self):
        """O-03 (run lessons): a run that enqueued far more work than it
        processed must report BOTH totals, and the normalized rates divide
        by the EXECUTED count with the denominator stated in the reason."""
        tracker = CostTracker()
        for _ in range(10):
            tracker.record_task("hunt")   # enqueued plan scope
        tracker.record_task("recon")
        for _ in range(3):
            tracker.record_executed_task("hunt")  # work actually processed
        tracker.record_executed_task("recon")
        metrics = tracker.compute_metrics(2000, 1)

        self.assertEqual(metrics["total_enqueued"], 11)
        self.assertEqual(metrics["total_executed"], 4)
        self.assertNotEqual(metrics["total_enqueued"], metrics["total_executed"])
        self.assertEqual(metrics["rates_denominator"], "executed")
        # 4 executed tasks over 2 kLOC; the enqueued 11 must NOT leak into
        # the rate denominator.
        self.assertEqual(metrics["tasks_per_kloc"], 2.0)
        self.assertEqual(metrics["tasks_per_finding"], 4.0)
        self.assertIn("executed tasks", metrics["tasks_per_kloc_reason"])
        self.assertIn("executed tasks", metrics["tasks_per_finding_reason"])
        self.assertEqual(metrics["stage_tasks_executed"], {"hunt": 3, "recon": 1})

    def test_recorded_zero_executed_uses_a_real_zero_denominator(self):
        """A caller that tracked executions and observed ZERO of them gets a
        computed rate over a real executed denominator of 0 — not the
        enqueued fallback, and not a fabricated positive number."""
        tracker = CostTracker()
        tracker.record_task("hunt")
        tracker.record_task("hunt")
        tracker.set_executed_tasks({})
        metrics = tracker.compute_metrics(1000, 1)
        self.assertEqual(metrics["total_enqueued"], 2)
        self.assertEqual(metrics["total_executed"], 0)
        self.assertEqual(metrics["rates_denominator"], "executed")
        self.assertEqual(metrics["tasks_per_kloc"], 0.0)
        self.assertIn("executed tasks", metrics["tasks_per_kloc_reason"])

    def test_set_executed_tasks_accepts_ledger_counts(self):
        """The LED wiring point records executed counts per stage directly."""
        tracker = CostTracker()
        tracker.record_task("hunt")
        tracker.record_task("verify")
        tracker.record_task("report")
        tracker.set_executed_tasks({"hunt": 1, "verify": 1, "report": 1})
        metrics = tracker.compute_metrics(1000, 1)
        self.assertEqual(metrics["total_executed"], 3)
        self.assertEqual(metrics["rates_denominator"], "executed")
        self.assertEqual(metrics["tasks_per_kloc"], 3.0)

    def test_cache_and_protocol_overhead_unavailable_by_default(self):
        metrics = CostTracker().compute_metrics(1000, 1)
        self.assertEqual(metrics["cache_hits"]["availability"], "unavailable")
        self.assertIsNone(metrics["cache_hits"]["value"])
        self.assertTrue(metrics["cache_hits"]["reason"])
        self.assertEqual(metrics["protocol_overhead"]["availability"], "unavailable")
        self.assertIsNone(metrics["protocol_overhead"]["value"])

    def test_cache_and_protocol_overhead_when_supplied(self):
        tracker = CostTracker()
        tracker.set_cache_hits(12)
        tracker.set_protocol_overhead(4)
        metrics = tracker.compute_metrics(1000, 1)
        self.assertEqual(metrics["cache_hits"]["value"], 12)
        self.assertIsNone(metrics["cache_hits"]["reason"])
        self.assertEqual(metrics["protocol_overhead"]["value"], 4)

    def test_retries_from_caller_override_observed(self):
        tracker = CostTracker()
        tracker.record_task("hunt", is_retry=True)  # observed retry = 1
        tracker.set_retries(7, source="host")
        metrics = tracker.compute_metrics(1000, 1)
        self.assertEqual(metrics["retries"], 7)
        self.assertEqual(metrics["retries_source"], "host")

    def test_retries_observed_when_no_caller_override(self):
        tracker = CostTracker()
        tracker.record_task("hunt", is_retry=True)
        metrics = tracker.compute_metrics(1000, 1)
        self.assertEqual(metrics["retries"], 1)
        self.assertEqual(metrics["retries_source"], "observed")


class TestCoverageUnknown(unittest.TestCase):
    """DSR-034: no intervals -> explicit unknown flag, not silent zeros."""

    def test_empty_manifest_flags_unknown(self):
        summary = CoverageCalculator([]).get_summary()
        self.assertTrue(summary["unknown"])
        self.assertTrue(summary["unknown_reason"])
        # Backward-compatible keys still present.
        self.assertIn("total_files", summary)
        self.assertIn("dimension_percentages", summary)
        self.assertIn("file_breakdown", summary)

    def test_zero_line_manifest_flags_unknown(self):
        summary = CoverageCalculator([{"path": "empty.py", "language": "python", "line_count": 0}]).get_summary()
        self.assertTrue(summary["unknown"])
        self.assertIn("zero", summary["unknown_reason"])

    def test_manifest_with_lines_is_known(self):
        summary = CoverageCalculator([{"path": "a.py", "language": "python", "line_count": 10}]).get_summary()
        self.assertFalse(summary["unknown"])
        self.assertNotIn("unknown_reason", summary)
        self.assertEqual(summary["dimension_covered_lines"]["inventoried"], 10)


if __name__ == "__main__":
    unittest.main()
