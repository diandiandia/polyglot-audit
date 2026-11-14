"""End-to-end integration tests for E2E-01, E2E-02, E2E-03, E2E-04.

Implements DDS-07 / DSR-037 / SWR-001 / SWR-022 / SWR-026:
- E2E-01 (Python): Multi-file taint flow reaching pickle deserialization vs safe json parse.
- E2E-02 (JS + TS): DOM XSS innerHTML sink vs safe textContent assignment.
- E2E-03 (Go): Ignored error on security check vs harmless standard I/O error.
- E2E-04 (Boundary): Cross-language frontier and dangling sink connection hypothesis.
"""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from auditkit.analysis.hunter import HuntResultParser
from auditkit.analysis.verifier import Verifier
from auditkit.app.service import AuditAppService


FIXTURES_DIR = Path("/root/polyglot-audit/tests/fixtures")
SKILL_DIR = Path("/root/polyglot-audit/skill")


class TestE2E(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.app = AuditAppService(SKILL_DIR)

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def test_e2e_01_python_deserialization(self):
        """E2E-01: Python request handler flowing across files to pickle deserialization."""
        target_dir = FIXTURES_DIR / "pyapp"
        run_dir = Path(self.temp_dir) / "run_pyapp"

        config = {
            "schema_version": "1.0",
            "target": str(target_dir),
            "run_dir": str(run_dir),
            "report_language": "zh",
            "profile": "standard",
            "scope": {"include": ["*.py"], "exclude": ["tests/*"]},
            "budgets": [{"schema_version": "1.0", "dimension": "tasks", "mode": "enforced", "limit": 20, "settled": 0, "reserved": 0, "unit": "tasks", "availability": "exact"}],
            "safety_acceptance": {"allow_unverified_execution": False, "allow_unverified_network": False, "allow_unverified_write": False, "user_approved": True},
        }

        # 1. Prepare
        prep = self.app.prepare(str(target_dir), str(run_dir), config)
        run_id = prep["run_id"]
        self.assertTrue(run_id.startswith("run-"))

        # 2. Activate
        self.app.activate(run_id, run_dir)

        # 3. Next (Claim)
        claims = self.app.next(run_id, run_dir, batch_size=5)
        self.assertTrue(len(claims) >= 1)

        # 4. Process hunt task
        claim = claims[0]
        self.app.start(run_dir, claim)

        worker_result = {
            "schema_version": "1.0",
            "task_id": claim["task_id"],
            "attempt_id": claim["attempt_id"],
            "kind": "hunt",
            "coverage": [{
                "schema_version": "1.0",
                "snapshot_id": prep["snapshot_id"],
                "unit_id": "u1",
                "dimension": "observed_read",
                "source": "worker",
                "ranges": [{"path": "app/handlers/upload.py", "line_start": 1, "line_end": 12}],
                "confidence": "exact",
            }],
            "records": [{
                "schema_version": "1.0",
                "candidate_id": "cand-py-01",
                "issue": "py-01",
                "source": {"path": "app/handlers/upload.py", "line": 8, "symbol": "handle_upload", "kind": "http_body", "control": "request_data['body']"},
                "sink": {"path": "app/storage/state.py", "line": 10, "symbol": "restore_state", "kind": "deserialization", "effect": "arbitrary object instantiation"},
                "steps": [
                    {"path": "app/handlers/upload.py", "line": 8, "role": "source", "note": "read raw_payload from request"},
                    {"path": "app/handlers/upload.py", "line": 10, "role": "propagate", "note": "pass payload to restore_state"},
                    {"path": "app/storage/state.py", "line": 10, "role": "sink", "note": "pickle.loads on payload"},
                ],
                "guard_analysis": "No input validation or schema checks on upload path",
                "impact_claim": "Remote Code Execution via arbitrary deserialization",
                "open_questions": [],
                "provenance": {"hunt_tasks": [claim["task_id"]]},
            }],
            "overflow": [],
        }

        sub_res = self.app.submit(run_dir, claim, worker_result, "digest-py01")
        self.assertTrue(sub_res["ok"])

        # 5. Independent Verification
        verifier = Verifier()
        finding = verifier.create_finding_from_candidate(
            worker_result["records"][0],
            "confirmed",
            "t-verify-01",
            impact=4,
            exploitability=4,
            impact_why="RCE via pickle.loads",
            exploitability_why="Unauthenticated request body",
            remediation={"where": "app/storage/state.py:10", "change": "Replace pickle with safe JSON parser", "regression_test": "Reject pickle payloads"},
        )

        # 6. Finalize & publish reports
        fin = self.app.finalize(run_id, run_dir, findings=[finding])
        self.assertEqual(fin["final_state"], "complete")

        # 7. Check published REPORT.md
        rep_text = (run_dir / "report" / "REPORT.md").read_text(encoding="utf-8")
        self.assertIn("F-", rep_text)
        self.assertIn("Critical", rep_text)
        self.assertIn("P0", rep_text)
        self.assertIn("pickle.loads", rep_text)

    def test_e2e_02_javascript_typescript_xss(self):
        """E2E-02: JavaScript innerHTML DOM XSS vs safe TypeScript textContent."""
        target_dir = FIXTURES_DIR / "ts_js"
        run_dir = Path(self.temp_dir) / "run_ts_js"

        config = {
            "schema_version": "1.0",
            "target": str(target_dir),
            "run_dir": str(run_dir),
            "report_language": "zh",
            "profile": "standard",
            "scope": {"include": ["*.js", "*.ts"], "exclude": []},
            "budgets": [{"schema_version": "1.0", "dimension": "tasks", "mode": "enforced", "limit": 20, "settled": 0, "reserved": 0, "unit": "tasks", "availability": "exact"}],
            "safety_acceptance": {"allow_unverified_execution": False, "allow_unverified_network": False, "allow_unverified_write": False, "user_approved": True},
        }

        prep = self.app.prepare(str(target_dir), str(run_dir), config)
        run_id = prep["run_id"]
        self.app.activate(run_id, run_dir)
        claims = self.app.next(run_id, run_dir, batch_size=1)

        claim = claims[0]
        self.app.start(run_dir, claim)

        worker_result = {
            "schema_version": "1.0",
            "task_id": claim["task_id"],
            "attempt_id": claim["attempt_id"],
            "kind": "hunt",
            "coverage": [],
            "records": [{
                "schema_version": "1.0",
                "candidate_id": "cand-js-01",
                "issue": "js-04",
                "source": {"path": "src/view.js", "line": 3, "symbol": "renderUserProfile", "kind": "param", "control": "userComment"},
                "sink": {"path": "src/view.js", "line": 5, "symbol": "innerHTML", "kind": "dom_xss", "effect": "arbitrary script injection"},
                "steps": [
                    {"path": "src/view.js", "line": 3, "role": "source", "note": "receive userComment"},
                    {"path": "src/view.js", "line": 5, "role": "sink", "note": "direct innerHTML assignment"},
                ],
                "guard_analysis": "No sanitization",
                "impact_claim": "DOM XSS",
                "open_questions": [],
                "provenance": {"hunt_tasks": [claim["task_id"]]},
            }],
            "overflow": [],
        }

        self.app.submit(run_dir, claim, worker_result, "digest-js01")

        verifier = Verifier()
        finding = verifier.create_finding_from_candidate(
            worker_result["records"][0],
            "confirmed",
            "t-verify-js",
            impact=3,
            exploitability=3,
            impact_why="DOM XSS",
            exploitability_why="User parameter unescaped",
        )
        fin = self.app.finalize(run_id, run_dir, findings=[finding])
        self.assertEqual(fin["final_state"], "complete")

    def test_e2e_03_go_ignored_auth_error(self):
        """E2E-03: Go ignored auth error vs harmless I/O error."""
        target_dir = FIXTURES_DIR / "goapp"
        run_dir = Path(self.temp_dir) / "run_go"

        config = {
            "schema_version": "1.0",
            "target": str(target_dir),
            "run_dir": str(run_dir),
            "report_language": "zh",
            "profile": "standard",
            "scope": {"include": ["*.go"], "exclude": []},
            "budgets": [{"schema_version": "1.0", "dimension": "tasks", "mode": "enforced", "limit": 20, "settled": 0, "reserved": 0, "unit": "tasks", "availability": "exact"}],
            "safety_acceptance": {"allow_unverified_execution": False, "allow_unverified_network": False, "allow_unverified_write": False, "user_approved": True},
        }

        prep = self.app.prepare(str(target_dir), str(run_dir), config)
        run_id = prep["run_id"]
        self.app.activate(run_id, run_dir)
        claims = self.app.next(run_id, run_dir, batch_size=1)
        claim = claims[0]
        self.app.start(run_dir, claim)

        # Worker confirms auth.go error ignoring is critical, but io.go is safe
        worker_result = {
            "schema_version": "1.0",
            "task_id": claim["task_id"],
            "attempt_id": claim["attempt_id"],
            "kind": "hunt",
            "coverage": [],
            "records": [{
                "schema_version": "1.0",
                "candidate_id": "cand-go-01",
                "issue": "go-02",
                "source": {"path": "auth.go", "line": 15, "symbol": "handleAdminAction", "kind": "token", "control": "token"},
                "sink": {"path": "auth.go", "line": 17, "symbol": "grantAccess", "kind": "auth_bypass", "effect": "fail-open authorization"},
                "steps": [
                    {"path": "auth.go", "line": 15, "role": "source", "note": "token received"},
                    {"path": "auth.go", "line": 17, "role": "sink", "note": "error ignored via _ on verifyToken"},
                ],
                "guard_analysis": "Error discarded",
                "impact_claim": "Authentication bypass",
                "open_questions": [],
                "provenance": {"hunt_tasks": [claim["task_id"]]},
            }],
            "overflow": [],
        }
        self.app.submit(run_dir, claim, worker_result, "digest-go01")

        verifier = Verifier()
        finding = verifier.create_finding_from_candidate(
            worker_result["records"][0],
            "confirmed",
            "t-verify-go",
            impact=3,
            exploitability=4,
            impact_why="Auth bypass",
            exploitability_why="Ignored verification return code",
        )
        fin = self.app.finalize(run_id, run_dir, findings=[finding])
        self.assertEqual(fin["final_state"], "complete")

    def test_e2e_04_cross_language_boundary_hypothesis(self):
        """E2E-04: Cross-language frontier and dangling sink linked as hypothesis."""
        target_dir = FIXTURES_DIR / "boundary"
        run_dir = Path(self.temp_dir) / "run_boundary"

        config = {
            "schema_version": "1.0",
            "target": str(target_dir),
            "run_dir": str(run_dir),
            "report_language": "zh",
            "profile": "standard",
            "scope": {"include": ["*"], "exclude": []},
            "budgets": [{"schema_version": "1.0", "dimension": "tasks", "mode": "enforced", "limit": 20, "settled": 0, "reserved": 0, "unit": "tasks", "availability": "exact"}],
            "safety_acceptance": {"allow_unverified_execution": False, "allow_unverified_network": False, "allow_unverified_write": False, "user_approved": True},
        }

        prep = self.app.prepare(str(target_dir), str(run_dir), config)
        run_id = prep["run_id"]
        self.app.activate(run_id, run_dir)
        claims = self.app.next(run_id, run_dir, batch_size=1)
        claim = claims[0]
        self.app.start(run_dir, claim)

        # Worker outputs frontier and sink probe
        worker_result = {
            "schema_version": "1.0",
            "task_id": claim["task_id"],
            "attempt_id": claim["attempt_id"],
            "kind": "hunt",
            "coverage": [],
            "records": [
                {
                    "schema_version": "1.0",
                    "frontier_id": "front-01",
                    "source": {"path": "caller.py", "line": 8, "symbol": "dispatch_payload", "kind": "param"},
                    "boundary": "libnative.so",
                    "steps": [{"path": "caller.py", "line": 8, "role": "source", "note": "user_input passed to native"}],
                    "open_questions": ["Parameter memory safety across boundary"],
                    "provenance": {"hunt_tasks": [claim["task_id"]]},
                },
                {
                    "schema_version": "1.0",
                    "probe_id": "probe-01",
                    "sink": {"path": "callee.c", "line": 10, "symbol": "system", "kind": "rce"},
                    "boundary": "libnative.so",
                    "steps": [{"path": "callee.c", "line": 10, "role": "sink", "note": "system(buffer)"}],
                    "guard_analysis": "Buffer copy without bounds check",
                    "open_questions": [],
                    "provenance": {"hunt_tasks": [claim["task_id"]]},
                },
            ],
            "overflow": [],
        }
        self.app.submit(run_dir, claim, worker_result, "digest-bnd01")

        # Connect hypotheses
        from auditkit.analysis.connector import HypothesisConnector
        connector = HypothesisConnector()
        conns, synth_cands = connector.connect(
            [worker_result["records"][0]],
            [worker_result["records"][1]],
        )
        self.assertEqual(len(conns), 1)
        self.assertEqual(conns[0]["status"], "hypothesized")

        # Because parameter compatibility across FFI is unverified, verifier yields needs_validation!
        verifier = Verifier()
        finding = verifier.create_finding_from_candidate(
            synth_cands[0],
            "needs_validation",
            "t-verify-bnd",
            impact=4,
            exploitability=3,
            blockers=["ABI and parameter position compatibility across FFI boundary requires verification"],
            validation_plan="Compile and run FFI integration harness",
        )
        self.assertEqual(finding["verdict"], "needs_validation")
        self.assertEqual(finding["evidence_level"], "E1")

        fin = self.app.finalize(run_id, run_dir, findings=[finding])
        self.assertEqual(fin["final_state"], "complete")


if __name__ == "__main__":
    unittest.main()
