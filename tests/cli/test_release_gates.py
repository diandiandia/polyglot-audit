"""Release gate evaluator tests for GATE-01..GATE-07 (DSR-051 / SWR-026).

Implements DSR-051:
- Every gate yields pass / fail / not_applicable + reason (GateResult contract).
- Missing or unknown evidence blocks the release: unknown capability is never
  silently promoted to supported.
- An all-pass evidence set allows the release.
"""

import json
import tempfile
import unittest
from pathlib import Path

import sys as _sys
_sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "skill" / "scripts"))

from auditkit.app.release import ReleaseGateEvaluator
from auditkit.contracts.errors import InvalidInputError
from auditkit.contracts.gates import GATE_STATUSES


FULL_PASS_EVIDENCE = {
    "capability_matrix": {
        "claude": {"structured_output": "verified", "config_load": "verified",
                   "delegation": "verified", "auth": "verified",
                   "readonly": "verified", "execution": "verified", "network": "verified"},
        "codex": {"structured_output": "verified", "auth": "verified"},
    },
    "GATE-02": {"status": "pass", "summary": "并发/崩溃/迟到提交/快照竞态夹具全部通过；文件系统适用范围已记录"},
    "GATE-03": {"status": "pass", "summary": "仅发布软预算/任务预算模式，未声称硬预算"},
    "GATE-04": {"status": "pass", "summary": "150 类逐语言评审完成，留出语料已测量"},
    "GATE-05": {"status": "pass", "summary": "性能/成本/覆盖已在规定机器测量，缺失数据已公布"},
    "GATE-06": {"status": "pass", "summary": "导出字段与失败关闭行为已用合成反例测试"},
    "GATE-07": {"status": "pass", "summary": "Python 下限/Schema 子集/CLI+MCP 接口版本已确定"},
    "compatibility_tests": {"status": "pass", "summary": "兼容测试通过"},
}


class TestReleaseGateEvaluator(unittest.TestCase):

    def test_all_pass_evidence_allows_release(self):
        result = ReleaseGateEvaluator().evaluate_all(dict(FULL_PASS_EVIDENCE))
        self.assertTrue(result["release_allowed"])
        self.assertEqual(result["verdict"], "release_allowed")
        self.assertEqual(result["blocking"], [])
        self.assertEqual(len(result["gates"]), 7)
        for g in result["gates"]:
            self.assertEqual(g["status"], "pass")

    def test_no_evidence_blocks_release(self):
        result = ReleaseGateEvaluator().evaluate_all({})
        self.assertFalse(result["release_allowed"])
        self.assertEqual(result["verdict"], "release_blocked")
        self.assertEqual(len(result["blocking"]), 7)

    def test_unknown_capability_blocks_and_not_supported(self):
        evidence = dict(FULL_PASS_EVIDENCE)
        evidence["capability_matrix"] = {
            "claude": {"structured_output": "verified", "network": "unknown"},
        }
        result = ReleaseGateEvaluator().evaluate_all(evidence)
        self.assertFalse(result["release_allowed"])
        g1 = result["gates"][0]
        self.assertEqual(g1["status"], "fail")
        self.assertIn("unknown", g1["reason"] or "")
        self.assertIn("claude.network", "; ".join(result["blocking"]))

    def test_unknown_evidence_status_blocks(self):
        evidence = dict(FULL_PASS_EVIDENCE)
        evidence["GATE-04"] = {"status": "unknown", "summary": "留出语料未测量"}
        result = ReleaseGateEvaluator().evaluate_all(evidence)
        self.assertFalse(result["release_allowed"])
        g4 = result["gates"][3]
        self.assertEqual(g4["status"], "fail")

    def test_not_applicable_requires_explicit_reason(self):
        evidence = dict(FULL_PASS_EVIDENCE)
        evidence["GATE-03"] = {"status": "not_applicable", "summary": "本次发布不含预算强制声明"}
        result = ReleaseGateEvaluator().evaluate_all(evidence)
        g3 = result["gates"][2]
        self.assertEqual(g3["status"], "not_applicable")
        self.assertTrue((g3.get("reason") or "").strip())

    def test_gate_without_evidence_is_fail_not_na(self):
        # Missing evidence must never silently become not_applicable.
        result = ReleaseGateEvaluator().evaluate_gate("GATE-05")
        self.assertEqual(result.status, "fail")

    def test_na_without_summary_carries_default_reason(self):
        # DSR-022: not_applicable always carries an explicit reason, even when
        # the evidence entry omits a summary (a default reason is substituted).
        evaluator = ReleaseGateEvaluator({"GATE-05": {"status": "not_applicable"}})
        result = evaluator.evaluate_gate("GATE-05")
        self.assertEqual(result.status, "not_applicable")
        self.assertTrue((result.reason or "").strip())

    def test_evidence_file_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "gate06.json"
            path.write_text(json.dumps({"status": "pass", "summary": "file evidence"}), encoding="utf-8")
            evidence = dict(FULL_PASS_EVIDENCE)
            evidence["GATE-06"] = str(path)
            result = ReleaseGateEvaluator().evaluate_all(evidence)
            self.assertTrue(result["release_allowed"])

            missing = Path(tmp) / "missing.json"
            evidence["GATE-06"] = str(missing)
            result = ReleaseGateEvaluator().evaluate_all(evidence)
            self.assertFalse(result["release_allowed"])

    def test_gate_statuses_use_gate_contract_vocabulary(self):
        result = ReleaseGateEvaluator().evaluate_all({})
        for g in result["gates"]:
            self.assertIn(g["status"], GATE_STATUSES)

    def test_unknown_gate_id_rejected(self):
        with self.assertRaises(InvalidInputError):
            ReleaseGateEvaluator().evaluate_gate("GATE-99")


if __name__ == "__main__":
    unittest.main()
