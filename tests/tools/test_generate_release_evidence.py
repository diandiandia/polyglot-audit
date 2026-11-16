"""Release evidence generator unit tests (DSR-051 / SR-029).

Lightweight tests for tools/generate_release_evidence.py: the normalization
functions are exercised against SAMPLE subprocess outputs (orchestrator
summary table, holdout report, isolation report, doctor envelope) — the full
unified suite is never re-run here. Structure assertions cover:

- run_all_tests summary-table parsing (categories, counts, totals, skip list).
- Honest per-category verdicts (fail / pass / unknown; skips never become a
  pass).
- gateNN-summary.json bodies carry counts / duration / skip list / timestamp /
  environment+hardware.
- doctor envelope -> capability_matrix normalization consumed by
  ReleaseGateEvaluator.check_gate_01 (states kept verbatim, unknown blocks).
- holdout evidence keeps llm_results unknown (no fabricated online eval).
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
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import generate_release_evidence as gre  # noqa: E402

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


class TestCollectEvidenceWithMockRunner(unittest.TestCase):
    """Mock-subprocess end-to-end: every evidence file gets written from
    sample outputs and the release conclusion is honestly blocked."""

    def _fake_runner(self, run_all_stdout=SAMPLE_RUN_ALL, run_all_rc=0,
                     doctor_caps=SAMPLE_CAPABILITIES, doctor_ok=True,
                     holdout=SAMPLE_HOLDOUT, isolation=SAMPLE_ISOLATION):
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
            else:
                completed.returncode = 1
            return completed

        runner.calls = calls
        return runner

    def test_all_steps_produce_evidence_and_blocked_release(self):
        with tempfile.TemporaryDirectory(prefix="evidence-test-") as tmp:
            out_dir = Path(tmp)
            result = gre.collect_evidence(
                out_dir, run_tests=True, runner=self._fake_runner()
            )
            payload = result["payload"]
            # Every mandated artifact exists with the mandated name.
            expected = {
                "gate01-summary.json", "gate02-summary.json", "gate05-summary.json",
                "gate07-summary.json", "gate01-isolation.json",
                "gate01-capability-matrix.json", "gate04-holdout.json",
                "release_gate_summary.json",
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
            # Release conclusion: unknown capability -> blocked, honestly.
            self.assertEqual(payload["verdict"], "release_blocked")
            self.assertFalse(payload["release_allowed"])
            gate_statuses = {
                g["gate_id"]: g["status"] for g in payload["release_gate"]["gates"]
            }
            self.assertEqual(
                gate_statuses,
                {"GATE-01": "fail", "GATE-02": "pass", "GATE-03": "fail",
                 "GATE-04": "fail", "GATE-05": "fail", "GATE-06": "fail",
                 "GATE-07": "pass"},
                "GATE-05 must fail from the sample scale failure; GATE-03/06 "
                "have no automated evidence and must fail closed; the sample "
                "deterministic category passes the GATE-07 compat proxy",
            )
            self.assertTrue(
                any("GATE-01" in b for b in payload["release_gate"]["blocking"])
            )
            manual_gates = {m["gate"] for m in payload["manual_pending"]}
            self.assertIn("GATE-03", manual_gates)
            self.assertIn("GATE-04", manual_gates)
            self.assertIn("GATE-06", manual_gates)
            # The four collector steps were recorded.
            self.assertEqual(len(payload["steps"]), 4)

    def test_nonzero_orchestrator_exit_still_parses_category_failures(self):
        """exit != 0 means some category FAILED — the summary table must then
        drive per-gate fail verdicts, not degrade everything to unknown."""
        with tempfile.TemporaryDirectory(prefix="evidence-test-") as tmp:
            out_dir = Path(tmp)
            runner = self._fake_runner(run_all_rc=1, run_all_stdout=SAMPLE_RUN_ALL)
            result = gre.collect_evidence(out_dir, run_tests=True, runner=runner)
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
            result = gre.collect_evidence(out_dir, run_tests=True, runner=runner)
            payload = result["payload"]
            # The failing steps are recorded with their error, honestly.
            by_step = {s["step"]: s for s in payload["steps"]}
            self.assertFalse(by_step["run_all_tests"]["ok"])
            self.assertFalse(by_step["doctor_probe"]["ok"])
            # ...while the independent holdout/isolation steps still collected.
            self.assertTrue(by_step["evaluate_holdout"]["ok"])
            self.assertTrue(by_step["probe_isolation"]["ok"])
            # The gate files all exist; the affected ones stay unknown.
            for name in ("gate01-summary.json", "gate01-capability-matrix.json",
                         "gate04-holdout.json", "gate01-isolation.json",
                         "release_gate_summary.json"):
                self.assertTrue((out_dir / name).exists())
            with open(out_dir / "gate01-summary.json", encoding="utf-8") as f:
                gate01 = json.load(f)
            self.assertEqual(gate01["status"], "unknown")
            with open(out_dir / "gate01-capability-matrix.json", encoding="utf-8") as f:
                matrix = json.load(f)
            self.assertEqual(matrix["status"], "unknown")
            self.assertEqual(matrix["capability_matrix"], {})
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
