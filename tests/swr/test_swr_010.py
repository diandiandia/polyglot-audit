"""SWR-010 acceptance tests (逐编号验收).

验收原文 (docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2):
    SWR-010 | SR-010 → SD-05、SD-08 | P2／SWR-009、SWR-013 |
    实现确认发现字段和报告呈现；以跨语言 fixture 检验链、修复、等级、
    来源及凭据值不外泄。

上游系统需求 (SYSTEM_REQUIREMENTS.md §2):
    SR-010: 对确认发现报告 source、sink、跨文件/语言有序证据、守卫、攻击前提、
    影响、修复建议和回归建议，分别呈现严重度及修复紧迫度。
    验收：逐字段追溯至记录与证据；密钥值不得出现在报告。

Acceptance coverage
-------------------
1. 逐字段呈现: 确认发现的 source / sink / 有序证据链(steps) / 守卫(guards) /
   攻击前提(attacker + preconditions) / 影响(impact + impact_why) /
   可利用性 / 修复建议(change) / 回归建议(regression_test) 在 REPORT.md 的
   明细节逐字段渲染, 且每个渲染值可逐字追溯至输入 finding 记录。
2. 跨语言 fixture: Python / JavaScript / Go 三条确认发现各自呈现自己的链、
   修复与来源 (跨文件证据有序: 链首步为 source、末步为 sink)。
3. 严重度与修复紧迫度分别呈现: 汇总表同时带 Severity 与 Urgency 两列,
   明细同时渲染 `final_severity` 与 `final_urgency` (P0..P3)。
4. 凭据值不外泄: 不同凭据模式 (password / api_key / bearer token / 私钥 /
   claim_token) 植入 finding 的各字段后, 任何报告介质 (REPORT.md、
   findings.json、NEEDS-VALIDATION.md、COVERAGE.md、coverage.csv、
   AUDIT-TRAIL.md、COST.md、SKILL-REVIEW.md) 中都不得出现原始密钥值,
   且脱敏占位符存在。
"""

from __future__ import annotations

import json
import shutil
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

SKILL_SCRIPTS = Path(__file__).resolve().parents[2] / "skill" / "scripts"
if str(SKILL_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SKILL_SCRIPTS))

from auditkit.analysis.verifier import Verifier  # noqa: E402
from auditkit.ledger.artifacts import ArtifactManager  # noqa: E402
from auditkit.ledger.db import init_database  # noqa: E402
from auditkit.reporting.generator import ReportGenerator  # noqa: E402

# Distinct credential values, one per masking pattern family. Each is planted
# in a different finding field so a per-field leak would be attributable.
SECRET_PASSWORD = "Pr0d-Sup3rSecret-PW-9911"
SECRET_APIKEY = "AKIA-swrfixed-apikeyvalue-4455"
SECRET_BEARER = "Bearer swrbearertokenvalue1234567890abcdef"
SECRET_CLAIM = "swrclaimtokenvalue0123456789abcdef"
SECRET_PEM = (
    "-----BEGIN RSA PRIVATE KEY-----\nswrleakprivatekeymaterial123\n"
    "-----END RSA PRIVATE KEY-----"
)

ALL_SECRETS = (SECRET_PASSWORD, SECRET_APIKEY, SECRET_BEARER, SECRET_CLAIM, SECRET_PEM)

REPORT_MEDIA = [
    "report/REPORT.md",
    "report/findings.json",
    "report/NEEDS-VALIDATION.md",
    "report/COVERAGE.md",
    "report/coverage.csv",
    "report/AUDIT-TRAIL.md",
    "report/COST.md",
    "report/SKILL-REVIEW.md",
]


def make_confirmed_finding(
    finding_id: str,
    issue: str,
    language: str,
    source_path: str,
    sink_path: str,
    *,
    impact: int = 4,
    exploitability: int = 4,
    impact_why: str = "Remote code execution on the host",
    exploitability_why: str = "Unauthenticated request reaches the sink",
    guards=None,
    attacker: str = "remote_unauth",
    preconditions=None,
    remediation_change: str = "Replace the unsafe sink API with its safe counterpart",
    remediation_regression: str = "Feed a malicious payload and assert safe rejection",
    extra_fields=None,
) -> dict:
    """Build a confirmed finding via the real Verifier (SWR-009 output shape)."""
    candidate = {
        "schema_version": "1.0",
        "candidate_id": f"cand-{finding_id.lower()}",
        "issue": issue,
        "source": {"path": source_path, "line": 8, "symbol": "handler", "kind": "param"},
        "sink": {"path": sink_path, "line": 42, "symbol": "sensitive_op", "kind": "sink"},
        "steps": [
            {"path": source_path, "line": 8, "role": "source", "note": "attacker-controlled entry"},
            {"path": source_path, "line": 20, "role": "propagate", "note": "passed unvalidated"},
            {"path": sink_path, "line": 42, "role": "sink", "note": "sensitive operation"},
        ],
        "guard_analysis": "none",
        "impact_claim": "high",
        "open_questions": [],
        "provenance": {"hunt_tasks": ["HT-X"], "hunt_attempt_id": "att-hunt-x"},
    }
    verifier = Verifier()
    finding = verifier.create_finding_from_candidate(
        candidate,
        "confirmed",
        "VT-X",
        verify_attempt_id="att-verify-x",
        impact=impact,
        exploitability=exploitability,
        impact_why=impact_why,
        exploitability_why=exploitability_why,
        remediation={
            "where": f"{sink_path}:42",
            "change": remediation_change,
            "regression_test": remediation_regression,
        },
    )
    finding["finding_id"] = finding_id
    if guards is None:
        guards = [{
            "schema_version": "1.0",
            "guard_id": f"guard-{finding_id.lower()}",
            "status": "observed",
            "mechanism": "Framework middleware validates the request body",
            "anchors": [{"path": source_path, "line": 3}],
            "applicability": f"{Path(source_path).parent}/",
            "exceptions": [],
        }]
    finding["guards"] = guards
    finding["attacker"] = attacker
    finding["preconditions"] = preconditions if preconditions is not None else [
        "Default configuration", "Endpoint reachable without authentication",
    ]
    if extra_fields:
        finding.update(extra_fields)
    return finding


def cross_language_findings() -> list:
    """Three confirmed findings in three languages (跨语言 fixture)."""
    return [
        make_confirmed_finding(
            "F-PY-01", "py-01", "python",
            "app/handlers/upload.py", "app/storage/state.py",
            remediation_change="Use a safe JSON parser instead of pickle.loads",
        ),
        make_confirmed_finding(
            "F-JS-01", "js-01", "javascript",
            "src/routes/profile.ts", "src/render/page.js",
            impact=3, exploitability=3,
            impact_why="Reflected script runs in the victim browser",
            exploitability_why="Attacker-controlled URL fragment reaches innerHTML",
            remediation_change="Escape with a contextual encoder before insertion",
            remediation_regression="Assert <script> payload renders inert",
        ),
        make_confirmed_finding(
            "F-GO-01", "go-01", "go",
            "api/handler.go", "internal/exec/run.go",
            impact=4, exploitability=2,
            impact_why="Command execution on the server host",
            exploitability_why="Input reaches exec only via an admin endpoint",
            remediation_change="Replace exec of raw input with an allow-list dispatcher",
            remediation_regression="Fuzz the dispatcher with shell metacharacters",
        ),
    ]


def coverage_summary() -> dict:
    return {
        "total_files": 3,
        "total_inventoried_lines": 300,
        "dimension_covered_lines": {"inventoried": 300, "observed_read": 240},
        "dimension_percentages": {"inventoried": 100.0, "observed_read": 80.0},
        "file_breakdown": [],
    }


def cost_metrics() -> dict:
    return {
        "stage_tasks": {"hunt": 3, "verify": 3, "report": 1},
        "total_tasks": 7,
        "retries": 0,
        "tasks_per_kloc": 23.3,
        "tasks_per_finding": 2.3,
        "token_availability": "unavailable",
        "unavailable_reason": "host did not report token usage",
    }


class SWR010Base(unittest.TestCase):

    def setUp(self) -> None:
        self.temp_dir = Path(tempfile.mkdtemp(prefix="swr010-"))
        self.run_dir = self.temp_dir / "run"
        self.run_dir.mkdir()
        db_path = self.run_dir / "events.db"
        init_database(db_path)
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        self.artifacts = ArtifactManager(self.run_dir, conn)
        self.generator = ReportGenerator(
            "run-swr010", "snap-swr010", "complete", self.artifacts, report_language="en"
        )

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _generate(self, findings):
        self.generation_id = self.generator.generate_all(
            findings, coverage_summary(), cost_metrics(), events=[],
            anomalies=[],
        )
        self.report_md = (self.run_dir / "report" / "REPORT.md").read_text(encoding="utf-8")
        return self.report_md

    def _finding_section(self, report: str, finding_id: str) -> str:
        """Return the detailed-findings block for one finding."""
        start = report.index(f"### {finding_id} ")
        nxt = report.find("### F-", start + 1)
        return report[start:nxt if nxt != -1 else len(report)]


class TestSWR010(SWR010Base):
    """确认发现字段与报告呈现：链、修复、等级、来源逐字段可追溯。"""

    def test_confirmed_finding_presents_every_required_field(self):
        """SR-010: source、sink、有序证据、守卫、攻击前提、影响、修复建议、
        回归建议逐字段呈现。"""
        self._generate([cross_language_findings()[0]])
        section = self._finding_section(self.report_md, "F-PY-01")

        expectations = {
            "source": ("**Source**:", "app/handlers/upload.py:8"),
            "sink": ("**Sink**:", "app/storage/state.py:42"),
            "ordered evidence chain": ("**Taint Path:**", "app/handlers/upload.py:8"),
            "guards": ("**Guards**:", "guard-f-py-01"),
            "attacker": ("**Attacker**:", "remote_unauth"),
            "attack preconditions": ("**Attack Preconditions**:", "Default configuration"),
            "impact": ("**Impact**:", "Remote code execution on the host"),
            "exploitability": ("**Exploitability**:", "Unauthenticated request reaches the sink"),
            "remediation": ("**Remediation**", "Use a safe JSON parser instead of pickle.loads"),
            "regression": ("**Regression Test**", "Feed a malicious payload and assert safe rejection"),
        }
        for label, (needle_a, needle_b) in expectations.items():
            self.assertIn(needle_a, section, f"missing presentation of {label}")
            self.assertIn(needle_b, section, f"missing record value for {label}")

    def test_evidence_chain_is_ordered_source_first_sink_last(self):
        """The rendered taint path keeps the record order: step 1 is the source,
        the last step is the sink (有序证据/跨文件链)."""
        finding = cross_language_findings()[0]
        self._generate([finding])
        section = self._finding_section(self.report_md, "F-PY-01")
        path_start = section.index("**Taint Path:**")
        path_block = section[path_start:]
        step_lines = [
            line for line in path_block.splitlines()
            if line.strip().startswith(("1.", "2.", "3."))
        ]
        self.assertEqual(len(step_lines), len(finding["steps"]))
        self.assertIn("source", step_lines[0])
        self.assertIn("sink", step_lines[-1])
        # Cross-file: the chain really spans two files.
        self.assertIn("app/handlers/upload.py", step_lines[0])
        self.assertIn("app/storage/state.py", step_lines[-1])

    def test_every_rendered_value_traces_to_the_finding_record(self):
        """逐字段追溯至记录: each rendered detail value occurs verbatim in the
        input finding dict (stringified)."""
        finding = cross_language_findings()[1]
        self._generate([finding])
        section = self._finding_section(self.report_md, "F-JS-01")

        record_values = [
            finding["source"]["path"], str(finding["source"]["line"]),
            finding["sink"]["path"], str(finding["sink"]["line"]),
            finding["attacker"],
            *finding["preconditions"],
            finding["guards"][0]["guard_id"], finding["guards"][0]["mechanism"],
            finding["guards"][0]["status"],
            finding["remediation"]["change"], finding["remediation"]["regression_test"],
            finding["rating"]["factor_reasons"]["impact_why"],
            finding["rating"]["factor_reasons"]["exploitability_why"],
        ]
        missing = [v for v in record_values if v not in section]
        self.assertEqual(
            missing, [],
            f"rendered report lost record values (SR-010 逐字段追溯): {missing}",
        )

    def test_cross_language_findings_each_keep_their_own_chain(self):
        """以跨语言 fixture 检验: three languages in one report, each finding
        presents its own source/sink/chain without cross-contamination."""
        findings = cross_language_findings()
        self._generate(findings)
        for finding in findings:
            section = self._finding_section(self.report_md, finding["finding_id"])
            self.assertIn(finding["source"]["path"], section, finding["finding_id"])
            self.assertIn(finding["sink"]["path"], section, finding["finding_id"])
            self.assertIn(finding["remediation"]["change"], section, finding["finding_id"])
            self.assertIn(finding["issue"], section, finding["finding_id"])
        # The summary table lists all three finding ids.
        for finding in findings:
            self.assertIn(finding["finding_id"], self.report_md)

    def test_severity_and_urgency_presented_separately(self):
        """分别呈现严重度及修复紧迫度: the summary table carries both a
        Severity and an Urgency column, and each detailed finding shows its
        final_severity and final_urgency values independently."""
        findings = [
            make_confirmed_finding(
                "F-SEV-C", "py-01", "python",
                "a/one.py", "a/two.py",
                impact=4, exploitability=4,
            ),  # Critical / P0
            make_confirmed_finding(
                "F-SEV-M", "js-01", "javascript",
                "b/one.ts", "b/two.js",
                impact=2, exploitability=3,
            ),  # Medium / P2 (per rating matrix)
        ]
        self._generate(findings)

        # Both dimensions are columns of the summary table.
        header = next(line for line in self.report_md.splitlines() if line.startswith("| ID |"))
        self.assertIn("Severity", header)
        self.assertIn("Urgency", header)

        crit = self._finding_section(self.report_md, "F-SEV-C")
        med = self._finding_section(self.report_md, "F-SEV-M")
        self.assertIn("[P0]", crit)
        self.assertIn("Critical", crit)
        self.assertIn("[P0]", crit)
        self.assertIn("[P2]", med)
        self.assertIn("Medium", med)
        # The two findings do not collapse into one grade.
        self.assertNotEqual(
            crit[crit.index("[P") + 1:crit.index("[P") + 3],
            med[med.index("[P") + 1:med.index("[P") + 3],
        )

    def test_guard_absence_is_disclosed_not_claimed(self):
        """A finding without recorded guards states that none were recorded;
        it must NOT claim that no guard exists (SD-04: 不强制声称守卫不存在)."""
        finding = cross_language_findings()[0]
        finding["guards"] = []
        self._generate([finding])
        section = self._finding_section(self.report_md, "F-PY-01")
        self.assertIn("**Guards**", section)
        self.assertIn("none recorded", section)
        self.assertNotIn("No guards exist", section)
        self.assertNotIn("no guard present", section)


class TestSWR010SecretNonLeakage(SWR010Base):
    """密钥值不得出现在任何报告介质 (SR-010 验收红线)。"""

    def secret_findings(self) -> list:
        """Plant one credential pattern per finding field."""
        return [make_confirmed_finding(
            "F-SEC-01", "py-01", "python",
            "app/upload.py", "app/state.py",
            remediation_change=f"rotate now, password = '{SECRET_PASSWORD}' in config",
            remediation_regression=f"assert api_key = \"{SECRET_APIKEY}\" is rejected",
            guards=[{
                "schema_version": "1.0", "guard_id": "guard-sec",
                "status": "observed",
                "mechanism": f"middleware sends {SECRET_BEARER} upstream",
                "anchors": [{"path": "app/upload.py", "line": 3}],
                "applicability": "app/",
                "exceptions": [],
            }],
            preconditions=[
                f"attacker holds claim_token: {SECRET_CLAIM}",
                "default deployment",
            ],
            extra_fields={
                "title": f"Leak via {SECRET_PEM}",
                "steps": [
                    {"path": "app/upload.py", "line": 8, "role": "source",
                     "note": f"reads request body with password = '{SECRET_PASSWORD}'"},
                    {"path": "app/state.py", "line": 42, "role": "sink",
                     "note": f"persists api_key = \"{SECRET_APIKEY}\""},
                ],
            },
        )]

    def test_no_secret_value_appears_in_any_report_medium(self):
        """Every raw credential value is absent from every medium; the
        redaction placeholders are present instead."""
        self._generate(self.secret_findings())
        for rel_path in REPORT_MEDIA:
            text = (self.run_dir / rel_path).read_text(encoding="utf-8")
            for secret in ALL_SECRETS:
                self.assertNotIn(
                    secret, text,
                    f"credential value leaked into {rel_path} (SR-010 凭据值不外泄)",
                )
        report = (self.run_dir / "report" / "REPORT.md").read_text(encoding="utf-8")
        self.assertIn("[REDACTED_PASSWORD]", report)
        self.assertIn("[REDACTED_API_KEY]", report)
        self.assertIn("[REDACTED_BEARER_TOKEN]", report)
        self.assertIn("[REDACTED_PRIVATE_KEY]", report)

    def test_machine_readable_findings_json_masks_nested_values(self):
        """findings.json masks string values nested in steps/guards/remediation
        while preserving the record structure (machine-readable result)."""
        self._generate(self.secret_findings())
        payload = json.loads((self.run_dir / "report" / "findings.json").read_text(encoding="utf-8"))
        flattened = json.dumps(payload, ensure_ascii=False)
        for secret in ALL_SECRETS:
            self.assertNotIn(secret, flattened)
        finding = payload[0]
        self.assertIn("[REDACTED_PASSWORD]", finding["remediation"]["change"])
        self.assertIn("[REDACTED_PASSWORD]", finding["steps"][0]["note"])
        self.assertIn("[REDACTED_API_KEY]", finding["steps"][1]["note"])
        self.assertIn("[REDACTED_BEARER_TOKEN]", finding["guards"][0]["mechanism"])
        # Structure (keys, anchors, line numbers) survives masking.
        self.assertEqual(finding["finding_id"], "F-SEC-01")
        self.assertEqual(finding["steps"][0]["line"], 8)
        self.assertEqual(finding["guards"][0]["guard_id"], "guard-sec")

    def test_audit_trail_and_needs_validation_do_not_leak_secrets(self):
        """AUDIT-TRAIL.md renders provenance; NEEDS-VALIDATION.md renders
        pending work — neither may carry raw credential values."""
        findings = self.secret_findings()
        findings.append({
            "schema_version": "1.0",
            "finding_id": "F-SEC-PENDING",
            "candidate_refs": ["cand-sec-pending"],
            "verdict": "needs_validation",
            "evidence_level": "E1",
            "title": f"pending check with password = '{SECRET_PASSWORD}'",
            "blockers": [f"guard status unknown; claim_token: {SECRET_CLAIM} unverified"],
            "validation_plan": "re-run verification with host telemetry",
            "rating": {"validation_priority": "V1"},
            "provenance": {"candidates": ["cand-sec-pending"], "hunt_tasks": ["HT-1"]},
        })
        self._generate(findings)
        for rel_path in ("report/AUDIT-TRAIL.md", "report/NEEDS-VALIDATION.md"):
            text = (self.run_dir / rel_path).read_text(encoding="utf-8")
            for secret in ALL_SECRETS:
                self.assertNotIn(secret, text, f"leak into {rel_path}")

    def test_unrecognized_secret_format_residual_risk_is_disclosed(self):
        """Masking is pattern-scoped: for values in formats outside the
        declared families the report must explicitly disclose the residual
        risk instead of implying completeness (DSR-069 / SR-010)."""
        self._generate(self.secret_findings())
        self.assertIn("Secrets in unrecognized formats", self.report_md)
        self.assertIn("manually review", self.report_md)


if __name__ == "__main__":
    unittest.main()
