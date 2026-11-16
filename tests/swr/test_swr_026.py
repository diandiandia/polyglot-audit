"""SWR-026 acceptance tests (逐编号验收).

验收原文 (docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2):
    SWR-026 | SR-026 → SD-08、SD-10 | P1／SWR-018、SWR-025 |
    实现 G0～G4 可程序化检查和 incomplete 分支；
    每个门禁有通过及必失败 fixture，不能把完整性说成安全结论。

上游系统需求 (SYSTEM_REQUIREMENTS.md §2):
    SR-026: 以可程序化检查输出 G0～G4 结果与 incomplete 分支；完整性表示
    流程闭环，不表示安全结论。发布门禁汇总证据，未知能力不标支持。

Acceptance coverage
-------------------
1. G0～G4 每个门禁各有通过 fixture 与必失败 fixture; 失败定位到具体 check
   (check_id + message), 状态词汇仅 pass/fail/not_applicable。
2. not_applicable 必须有理由: GateResult / GateCheck 的 N/A 无理由在构造时
   即拒绝 (InvalidInputError); to_dict 携带理由。
3. 部分运行生成如实标注的报告: 只处理部分计划范围的运行终态 incomplete 且
   REPORT.md 标注 incomplete; 反之 complete 运行的报告必须保留"完整性不等于
   安全结论"的局限声明 (静态分析、环境、脱敏范围三条)。
4. GATE-01～07 发布检查器 (ReleaseGateEvaluator): 每个门禁在证据缺失或
   unknown 时判定 fail (unknown 不标支持); 汇总结论 release_blocked 并逐条
   列出阻塞原因; N/A 带理由且同样计入阻塞 (fail-closed)。
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

SKILL_SCRIPTS = Path(__file__).resolve().parents[2] / "skill" / "scripts"
if str(SKILL_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SKILL_SCRIPTS))

from auditkit.analysis.verifier import Verifier  # noqa: E402
from auditkit.app.release import ReleaseGateEvaluator  # noqa: E402
from auditkit.app.service import AuditAppService  # noqa: E402
from auditkit.contracts.errors import InvalidInputError  # noqa: E402
from auditkit.contracts.gates import GATE_STATUSES, GateCheck, GateEvaluator, GateResult  # noqa: E402
from auditkit.ledger.db import get_db_connection  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
SKILL_DIR = REPO_ROOT / "skill"

DANGER_SOURCE = "import os\n\n\ndef handler(user_input):\n    os.system(user_input)\n"

HASH64 = "a" * 64


def valid_confirmed_finding(finding_id: str = "F-G2-1") -> dict:
    """A semantically valid confirmed finding (passes the G2 validator)."""
    candidate = {
        "schema_version": "1.0",
        "candidate_id": "cand-g2",
        "issue": "py-01",
        "source": {"path": "a.py", "line": 4, "symbol": "h", "kind": "param"},
        "sink": {"path": "b.py", "line": 9, "symbol": "sink", "kind": "sink"},
        "steps": [
            {"path": "a.py", "line": 4, "role": "source", "note": "in"},
            {"path": "b.py", "line": 9, "role": "sink", "note": "out"},
        ],
        "guard_analysis": "none",
        "impact_claim": "high",
        "open_questions": [],
        "provenance": {"hunt_tasks": ["HT-1"]},
    }
    finding = Verifier().create_finding_from_candidate(
        candidate, "confirmed", "VT-1",
        verify_attempt_id="att-v1", hunt_attempt_id="att-h1",
        impact=3, exploitability=2,
        impact_why="issue on studied path",
        exploitability_why="authenticated path",
        remediation={"where": "b.py:9", "change": "safe api", "regression_test": "t"},
    )
    finding["finding_id"] = finding_id
    return finding


class TestSWR026RuntimeGates(unittest.TestCase):
    """G0～G4 每个门禁的通过与必失败 fixture。"""

    def test_g0_snapshot_inventory_plan_pass_and_fail(self):
        manifest = {"root_hash": HASH64, "files": [{"path": "a.py"}, {"path": "b.py"}]}
        plan = {"units": [{"unit_id": "u1"}]}

        ok = GateEvaluator.evaluate_g0(manifest, plan, revision=3)
        self.assertEqual(ok.status, "pass")
        self.assertEqual(ok.gate_id, "G0")

        missing = GateEvaluator.evaluate_g0(None, plan, revision=3)
        self.assertEqual(missing.status, "fail")
        self.assertIn("manifest", missing.checks[0].message.lower())

        bad_hash = GateEvaluator.evaluate_g0({"root_hash": "abc", "files": manifest["files"]}, plan, 3)
        self.assertEqual(bad_hash.status, "fail")
        empty_inventory = GateEvaluator.evaluate_g0({"root_hash": HASH64, "files": []}, plan, 3)
        self.assertEqual(empty_inventory.status, "fail")
        no_plan = GateEvaluator.evaluate_g0(manifest, None, 3)
        self.assertEqual(no_plan.status, "fail")

    def test_g1_unit_dispatch_pass_and_fail(self):
        ok = GateEvaluator.evaluate_g1(3, 3, [], 5)
        self.assertEqual(ok.status, "pass")
        under = GateEvaluator.evaluate_g1(3, 1, [], 5)
        self.assertEqual(under.status, "fail")
        self.assertTrue(any(c.status == "fail" and "1/3" in c.message for c in under.checks))

    def test_g2_dispatch_reconciliation_and_finding_integrity(self):
        finding = valid_confirmed_finding()
        ok = GateEvaluator.evaluate_g2([finding], 7, submitted_tasks=5, dispatched_tasks=5, in_flight_tasks=0)
        self.assertEqual(ok.status, "pass", [c.message for c in ok.checks])

        # Must-fail A: lost results (dispatched without submitted or lease).
        lost = GateEvaluator.evaluate_g2([finding], 7, submitted_tasks=3, dispatched_tasks=5, in_flight_tasks=0)
        self.assertEqual(lost.status, "fail")
        self.assertTrue(any(c.check_id == "G2-0" for c in lost.checks))
        # In-flight lease legitimately covers the gap (not lost).
        leased = GateEvaluator.evaluate_g2([finding], 7, submitted_tasks=3, dispatched_tasks=5, in_flight_tasks=2)
        self.assertNotIn("G2-0", [c.check_id for c in leased.checks if c.status == "fail"])

        # Must-fail B: semantically invalid finding is located.
        broken = dict(finding, evidence_level="E3")
        bad = GateEvaluator.evaluate_g2([broken], 7, submitted_tasks=1, dispatched_tasks=1, in_flight_tasks=0)
        self.assertEqual(bad.status, "fail")
        self.assertTrue(
            any(c.status == "fail" and "E3" in c.message for c in bad.checks),
            f"failing check must locate the invalid finding: {[c.message for c in bad.checks]}",
        )

    def test_g3_reconciliation_and_generation_pass_and_fail(self):
        ok = GateEvaluator.evaluate_g3(4, 4, "gen-1", 2)
        self.assertEqual(ok.status, "pass")
        mismatch = GateEvaluator.evaluate_g3(4, 2, "gen-1", 2)
        self.assertEqual(mismatch.status, "fail")
        no_gen = GateEvaluator.evaluate_g3(4, 4, "", 2)
        self.assertEqual(no_gen.status, "fail")

    def test_g4_revision_and_sanitization_pass_and_fail(self):
        ok = GateEvaluator.evaluate_g4(True, True, 9)
        self.assertEqual(ok.status, "pass")
        unclean = GateEvaluator.evaluate_g4(True, False, 9)
        self.assertEqual(unclean.status, "fail")
        inconsistent = GateEvaluator.evaluate_g4(False, True, 9)
        self.assertEqual(inconsistent.status, "fail")

    def test_gate_result_contract_and_failing_check_location(self):
        """契约: schema_version/gate_id/status/checks/revision; 失败定位。"""
        result = GateEvaluator.evaluate_g1(2, 0, [], 4)
        d = result.to_dict()
        self.assertEqual(d["schema_version"], "1.0")
        self.assertEqual(d["gate_id"], "G1")
        self.assertEqual(d["revision"], 4)
        self.assertIn(d["status"], GATE_STATUSES)
        failing = [c for c in d["checks"] if c["status"] == "fail"]
        self.assertTrue(failing)
        self.assertTrue(all(c["message"] for c in failing), "failures must be located with a message")


class TestSWR026NotApplicable(unittest.TestCase):
    """not_applicable 必须有理由。"""

    def test_gate_result_na_requires_reason(self):
        with self.assertRaises(InvalidInputError):
            GateResult("G0", "not_applicable", [], 1, reason=None)
        with self.assertRaises(InvalidInputError):
            GateResult("G0", "not_applicable", [], 1, reason="   ")
        ok = GateResult("G0", "not_applicable", [], 1, reason="target is a docs-only tree")
        self.assertEqual(ok.to_dict()["reason"], "target is a docs-only tree")

    def test_gate_check_na_requires_message(self):
        with self.assertRaises(InvalidInputError):
            GateCheck("G0-1", "Snapshot Manifest", "not_applicable", "")
        ok = GateCheck("G0-1", "Snapshot Manifest", "not_applicable", "no snapshot for this run kind")
        self.assertEqual(ok.to_dict()["message"], "no snapshot for this run kind")

    def test_invalid_status_rejected(self):
        with self.assertRaises(InvalidInputError):
            GateResult("G0", "unknown", [], 1, reason="x")
        with self.assertRaises(InvalidInputError):
            GateCheck("G0-1", "n", "pass?", "msg")


class TestSWR026HonestPartialReports(unittest.TestCase):
    """部分运行如实标注; complete 报告不得声称安全结论。"""

    def setUp(self) -> None:
        self.temp_dir = Path(tempfile.mkdtemp(prefix="swr026-"))
        self.app = AuditAppService(SKILL_DIR)
        self.run_dir = self.temp_dir / "run"
        self._run_id = None

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def prepare_run(self) -> None:
        target = self.temp_dir / "target"
        target.mkdir(parents=True)
        (target / "danger.py").write_text(DANGER_SOURCE, encoding="utf-8")
        config = {
            "schema_version": "1.0",
            "target": str(target),
            "run_dir": str(self.run_dir),
            "report_language": "en",
            "profile": "quick",
            "scope": {"include": ["*.py"], "exclude": []},
            "budgets": [{
                "schema_version": "1.0", "dimension": "tasks", "mode": "enforced",
                "limit": 20, "settled": 0, "reserved": 0, "unit": "tasks",
                "availability": "exact",
            }],
            "safety_acceptance": {
                "allow_unverified_execution": False,
                "allow_unverified_network": False,
                "allow_unverified_write": False,
                "user_approved": True,
            },
        }
        prep = self.app.prepare(str(target), str(self.run_dir), config)
        self.app.activate(prep["run_id"], self.run_dir)
        self._run_id = prep["run_id"]

    @property
    def run_id(self) -> str:
        if self._run_id is None:
            conn = get_db_connection(self.run_dir / "events.db")
            try:
                self._run_id = conn.execute("SELECT run_id FROM runs LIMIT 1").fetchone()["run_id"]
            finally:
                conn.close()
        return self._run_id

    def submit_claims(self, claims) -> None:
        for claim in claims:
            self.app.start(self.run_dir, claim)
            kind = (claim.get("spec") or {}).get("task_kind") or "hunt"
            result = {
                "schema_version": "1.0",
                "task_id": claim["task_id"],
                "attempt_id": claim["attempt_id"],
                "kind": kind,
                "coverage": [],
                "records": [],
                "overflow": [],
            }
            self.app.submit(self.run_dir, claim, result, f"digest-{claim['attempt_id']}")

    def test_partial_run_report_is_labeled_incomplete(self):
        self.prepare_run()
        # Process only the recon task; planned hunt work stays unprocessed.
        claims = self.app.next(self.run_id, self.run_dir, batch_size=1)
        self.assertEqual(claims[0]["spec"]["task_kind"], "recon")
        self.submit_claims(claims)

        fin = self.app.finalize(self.run_id, self.run_dir, findings=[])
        self.assertEqual(fin["final_state"], "incomplete")
        self.assertIn("unprocessed_units", fin["incomplete_reasons"])

        report = (self.run_dir / "report" / "REPORT.md").read_text(encoding="utf-8")
        self.assertIn("incomplete", report)
        # The incomplete dossier must not claim the complete state anywhere
        # in its status header.
        self.assertNotIn("`complete (`complete`)`", report)
        conn = get_db_connection(self.run_dir / "events.db")
        try:
            state = conn.execute(
                "SELECT state FROM runs WHERE run_id = ?", (self.run_id,)
            ).fetchone()["state"]
        finally:
            conn.close()
        self.assertEqual(state, "incomplete")

    def test_complete_report_keeps_the_not_a_security_conclusion_limits(self):
        """完整性不是安全结论: a fully processed run states 'complete' but its
        report must retain the scope limitations (static analysis, environment,
        redaction coverage)."""
        self.prepare_run()
        while True:
            claims = self.app.next(self.run_id, self.run_dir, batch_size=10)
            if not claims:
                break
            self.submit_claims(claims)
        fin = self.app.finalize(self.run_id, self.run_dir, findings=[])
        self.assertEqual(fin["final_state"], "complete")

        report = (self.run_dir / "report" / "REPORT.md").read_text(encoding="utf-8")
        self.assertIn("Limitations & Scope", report)
        self.assertIn("pure static semantic analysis", report)
        self.assertIn("External environment variables", report)
        self.assertIn("Secrets in unrecognized formats", report)


class TestSWR026ReleaseGates(unittest.TestCase):
    """GATE-01～07 发布检查器: unknown 不标支持, 结论 release_blocked。"""

    FULL_PASS_EVIDENCE = {
        "capability_matrix": {
            "claude": {"structured_output": "verified", "config_load": "verified",
                       "delegation": "verified", "auth": "verified",
                       "readonly": "verified", "execution": "verified",
                       "network": "verified"},
            "codex": {"structured_output": "verified", "auth": "verified"},
        },
        "GATE-02": {"status": "pass", "summary": "concurrency/crash fixtures passed"},
        "GATE-03": {"status": "pass", "summary": "soft budget mode only"},
        "GATE-04": {"status": "pass", "summary": "per-language review measured"},
        "GATE-05": {"status": "pass", "summary": "performance measured on stated hardware"},
        "GATE-06": {"status": "pass", "summary": "export sanitization tested"},
        "GATE-07": {"status": "pass", "summary": "python floor and schema subset fixed"},
        "compatibility_tests": {"status": "pass", "summary": "compatibility passed"},
    }

    def test_every_gate_with_missing_evidence_is_fail_and_release_blocked(self):
        """GATE-01～07 各自: 证据缺失 → fail (unknown 不标支持) → 阻塞发布。"""
        for gate_id in (f"GATE-{i:02d}" for i in range(1, 8)):
            evaluator = ReleaseGateEvaluator({})
            result = evaluator.evaluate_gate(gate_id)
            self.assertEqual(
                result.status, "fail",
                f"{gate_id} with no evidence must be fail, not silently supported",
            )
            self.assertTrue(
                any(c.status == "fail" for c in result.checks),
                f"{gate_id} must locate its failing check",
            )

        blocked = ReleaseGateEvaluator({}).evaluate_all({})
        self.assertEqual(blocked["verdict"], "release_blocked")
        self.assertFalse(blocked["release_allowed"])
        self.assertEqual(len(blocked["blocking"]), 7)

    def test_unknown_capability_is_never_promoted_to_supported(self):
        evidence = dict(self.FULL_PASS_EVIDENCE)
        evidence["capability_matrix"] = {
            "claude": {"structured_output": "verified", "network": "unknown"},
        }
        blocked = ReleaseGateEvaluator(evidence).evaluate_all(evidence)
        self.assertEqual(blocked["verdict"], "release_blocked")
        g1 = blocked["gates"][0]
        self.assertEqual(g1["status"], "fail")
        self.assertTrue(
            any("claude.network" in part for part in blocked["blocking"]),
            f"blocking must name the unknown capability: {blocked['blocking']}",
        )

    def test_unknown_evidence_status_blocks_per_gate(self):
        for gate_id in ("GATE-02", "GATE-04", "GATE-06"):
            evidence = dict(self.FULL_PASS_EVIDENCE)
            evidence[gate_id] = {"status": "unknown", "summary": "not measured"}
            blocked = ReleaseGateEvaluator(evidence).evaluate_all(evidence)
            self.assertEqual(blocked["verdict"], "release_blocked", gate_id)
            gate = next(g for g in blocked["gates"] if g["gate_id"] == gate_id)
            self.assertEqual(gate["status"], "fail", gate_id)

    def test_not_applicable_carries_reason_and_still_blocks_release(self):
        """N/A 有理由且 fail-closed: 未关闭门禁进发布说明, 不允许发布。"""
        evidence = dict(self.FULL_PASS_EVIDENCE)
        evidence["GATE-03"] = {"status": "not_applicable",
                               "summary": "this release makes no hard-budget claim"}
        result = ReleaseGateEvaluator(evidence).evaluate_all(evidence)
        g3 = next(g for g in result["gates"] if g["gate_id"] == "GATE-03")
        self.assertEqual(g3["status"], "not_applicable")
        self.assertTrue((g3.get("reason") or "").strip())
        self.assertEqual(result["verdict"], "release_blocked")
        self.assertTrue(any("GATE-03" in part for part in result["blocking"]))

    def test_missing_compat_evidence_blocks_gate_07(self):
        """GATE-07 的兼容测试证据缺失时, 证据条目通过也不放行。"""
        evidence = dict(self.FULL_PASS_EVIDENCE)
        del evidence["compatibility_tests"]
        blocked = ReleaseGateEvaluator(evidence).evaluate_all(evidence)
        g7 = next(g for g in blocked["gates"] if g["gate_id"] == "GATE-07")
        self.assertEqual(g7["status"], "fail")
        self.assertEqual(blocked["verdict"], "release_blocked")

    def test_all_pass_evidence_allows_release(self):
        allowed = ReleaseGateEvaluator(dict(self.FULL_PASS_EVIDENCE)).evaluate_all(
            dict(self.FULL_PASS_EVIDENCE)
        )
        self.assertEqual(allowed["verdict"], "release_allowed")
        self.assertTrue(allowed["release_allowed"])
        self.assertEqual(allowed["blocking"], [])


if __name__ == "__main__":
    unittest.main()
