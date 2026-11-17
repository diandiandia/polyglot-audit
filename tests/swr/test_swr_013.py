"""SWR-013 acceptance tests (逐编号验收).

验收原文 (docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2):
    SWR-013 | SR-013 → SD-06、SD-08 | P2／SWR-017、SWR-018 |
    持久化提示包、结果、验证、拒绝及快照摘要引用；
    测试从报告双向追踪和丢失文件报错。

上游系统需求 (SYSTEM_REQUIREMENTS.md §2):
    SR-013: 保留审计卷宗及结论到任务、提示、结果、源快照和锚点的追溯关系。
    验收：任一发现可追至快照文件摘要、候选及独立验证；驳回理由、失败与
    未决记录可查询。

Acceptance coverage
-------------------
1. 卷宗持久化: 每个领取的任务都有提示包工件 tasks/{id}/packet.json; 三类任务
   (recon/hunt/verify) 各自发布 tasks/{id}/result.json 且内容与提交一致; recon
   守卫基线汇总在 recon/recon-result.json; 验证结果 findings/verified-<attempt>.json;
   候选保存在 verify 任务 spec 中可查询。
2. 正向追踪 (报告 → 记录): findings.json 中任一 confirmed finding 的
   provenance (candidates / hunt_tasks / verify_tasks / verify_attempt_id)
   与提交时深等值; provenance 引用的任务 id 在任务表中存在; sink/source
   路径可追至快照 manifest 的文件摘要 (path + sha256); AUDIT-TRAIL.md 逐键
   渲染 provenance。
3. 反向追踪 (记录 → 报告): verified_findings_stored 事件指向的工件内的
   finding_id 出现在 findings.json、AUDIT-TRAIL.md 与 REPORT.md; REPORT.md
   的 snapshot_id 与快照 manifest 一致。
4. 驳回理由/未决记录可查询: rejected finding 的 counter_evidence.rationale
   与 needs_validation finding 的 blockers/validation_plan 持久化并可从
   findings.json / NEEDS-VALIDATION.md 查询。
5. 丢失引用工件: finalize 前删除被引用工件 → CorruptRunError、运行转
   corrupt、记录 run_corrupted 事件且不产出报告; 内容被篡改 (哈希不符)
   同样报 corrupt。
"""

from __future__ import annotations

import copy
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
from auditkit.app.service import AuditAppService  # noqa: E402
from auditkit.contracts.errors import CorruptRunError  # noqa: E402
from auditkit.ledger.db import get_db_connection  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
SKILL_DIR = REPO_ROOT / "skill"

DANGER_SOURCE = "import os\n\n\ndef handler(user_input):\n    os.system(user_input)\n"


class SWR013Base(unittest.TestCase):

    def setUp(self) -> None:
        self.temp_dir = Path(tempfile.mkdtemp(prefix="swr013-"))
        self.app = AuditAppService(SKILL_DIR)
        self.run_dir = self.temp_dir / "run"
        self._run_id = None
        self.submitted_results = {}

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # ------------------------------------------------------------ helpers
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

    def candidate_for(self, hunt_task_id: str, hunt_attempt_id: str) -> dict:
        return {
            "schema_version": "1.0",
            "candidate_id": "cand-swr013-01",
            "issue": "py-01",
            "source": {"path": "danger.py", "line": 4, "symbol": "handler",
                       "kind": "param", "control": "user_input"},
            "sink": {"path": "danger.py", "line": 4, "symbol": "os.system",
                     "kind": "rce", "effect": "command execution"},
            "steps": [
                {"path": "danger.py", "line": 4, "role": "source", "note": "request body"},
                {"path": "danger.py", "line": 4, "role": "sink", "note": "os.system call"},
            ],
            "guard_analysis": "none",
            "impact_claim": "RCE",
            "open_questions": [],
            "provenance": {
                "hunt_tasks": [hunt_task_id],
                "hunt_attempt_id": hunt_attempt_id,
            },
        }

    def worker_result(self, claim, records=()):
        kind = (claim.get("spec") or {}).get("task_kind") or "hunt"
        return {
            "schema_version": "1.0",
            "task_id": claim["task_id"],
            "attempt_id": claim["attempt_id"],
            "kind": kind,
            "coverage": [],
            "records": list(records),
            "overflow": [],
        }

    def submit_all(self, claims, records_fn=None, usage_fn=None) -> None:
        """Start and submit every claim; a snapshot of each submitted payload
        is recorded keyed by task id so the dossier artifacts can be asserted
        against the exact worker results that were accepted (the service
        enriches finding records in place during acceptance, so the snapshot
        must be taken before submit)."""
        for claim in claims:
            self.app.start(self.run_dir, claim)
            records = records_fn(claim) if records_fn else []
            result = self.worker_result(claim, records)
            self.submitted_results[claim["task_id"]] = copy.deepcopy(result)
            self.app.submit(
                self.run_dir, claim, result,
                f"digest-{claim['attempt_id']}",
                usage=usage_fn(claim) if usage_fn else None,
            )

    def events(self, event_type: str) -> list:
        conn = get_db_connection(self.run_dir / "events.db")
        try:
            return [
                json.loads(r["payload_json"]) for r in conn.execute(
                    "SELECT payload_json FROM events WHERE run_id = ? AND event_type = ? "
                    "ORDER BY revision",
                    (self.run_id, event_type),
                ).fetchall()
            ]
        finally:
            conn.close()

    def task_rows(self) -> list:
        conn = get_db_connection(self.run_dir / "events.db")
        try:
            return [dict(r) for r in conn.execute(
                "SELECT task_id, kind, state FROM tasks WHERE run_id = ?",
                (self.run_id,),
            ).fetchall()]
        finally:
            conn.close()

    def run_state(self) -> str:
        conn = get_db_connection(self.run_dir / "events.db")
        try:
            return conn.execute(
                "SELECT state FROM runs WHERE run_id = ?", (self.run_id,)
            ).fetchone()["state"]
        finally:
            conn.close()

    @property
    def run_id(self) -> str:
        if self._run_id is None:
            conn = get_db_connection(self.run_dir / "events.db")
            try:
                self._run_id = conn.execute("SELECT run_id FROM runs LIMIT 1").fetchone()["run_id"]
            finally:
                conn.close()
        return self._run_id


class TestSWR013Traceability(SWR013Base):
    """卷宗持久化 + 报告双向追踪（候选、独立验证、快照摘要）。"""

    def _run_to_complete_with_verified_finding(self):
        """Full flow: recon → hunt (candidate) → independent verify (confirmed
        + rejected findings) → finalize. Returns (verify_claim, submitted
        findings, fin)."""
        self.prepare_run()
        claims = self.app.next(self.run_id, self.run_dir, batch_size=10)
        recon = next(c for c in claims if c["spec"]["task_kind"] == "recon")
        hunts = [c for c in claims if c["spec"]["task_kind"] == "hunt"]
        self.submit_all([recon])

        hunt_claim = hunts[0]
        candidate = self.candidate_for(hunt_claim["task_id"], hunt_claim["attempt_id"])
        self.submit_all(hunts, records_fn=lambda c: [candidate])

        # Independent verification: a real verify task claim.
        verify_claims = self.app.next(self.run_id, self.run_dir, batch_size=10)
        verify_claims = [c for c in verify_claims if c["spec"]["task_kind"] == "verify"]
        self.assertTrue(verify_claims, "candidate must enqueue a verify task")
        verify_claim = verify_claims[0]

        verifier = Verifier()
        # Medium severity (impact 3 x exploitability 2): below the High/Critical
        # second-opinion scope, so the verify submission completes without
        # extra fan-out and the run can reach the complete terminal state.
        confirmed = verifier.create_finding_from_candidate(
            candidate, "confirmed", verify_claim["task_id"],
            verify_attempt_id=verify_claim["attempt_id"],
            impact=3, exploitability=2,
            impact_why="Command execution on the studied path",
            exploitability_why="Reachable only from an authenticated session",
            remediation={"where": "danger.py:4", "change": "drop shell exec",
                         "regression_test": "reject metacharacters"},
        )
        rejected_candidate = dict(candidate, candidate_id="cand-swr013-02")
        rejected = verifier.create_finding_from_candidate(
            rejected_candidate, "rejected", verify_claim["task_id"],
            verify_attempt_id=verify_claim["attempt_id"],
            counter_evidence={
                "rationale": "Input is strictly validated by the framework",
                "anchors": [{"path": "danger.py", "line": 3}],
            },
        )
        submitted = [confirmed, rejected]
        self.submit_all([verify_claim], records_fn=lambda c: submitted)

        fin = self.app.finalize(self.run_id, self.run_dir, findings=[])
        self.assertEqual(fin["final_state"], "complete")
        return verify_claim, submitted, fin

    def test_dossier_persists_packets_results_and_verification(self):
        """提示包 / 结果 / 验证工件在卷宗中持久化并可查询。"""
        verify_claim, _, _ = self._run_to_complete_with_verified_finding()

        conn = get_db_connection(self.run_dir / "events.db")
        try:
            task_ids = [r["task_id"] for r in conn.execute(
                "SELECT task_id FROM tasks WHERE run_id = ?", (self.run_id,)
            ).fetchall()]
        finally:
            conn.close()
        # 1. Prompt packets: every dispatched task has its persisted packet.
        for task_id in task_ids:
            packet = self.run_dir / "tasks" / task_id / "packet.json"
            self.assertTrue(packet.exists(), f"missing prompt packet for {task_id}")
            payload = json.loads(packet.read_text(encoding="utf-8"))
            self.assertIn("packet_digest", payload)
        # 2. Per-task result artifacts (§10.1): result.json is published for
        #    EVERY task kind — recon, hunt and verify — and its content is the
        #    exact worker result that was submitted.
        for task_id, submitted in self.submitted_results.items():
            result_path = self.run_dir / "tasks" / task_id / "result.json"
            self.assertTrue(result_path.exists(), f"missing result.json for {task_id}")
            self.assertEqual(
                json.loads(result_path.read_text(encoding="utf-8")),
                submitted,
                f"result.json for {task_id} must equal the submitted worker result",
            )
        # 3. Recon summary artifact: the guard baseline lands in the recon/
        #    directory of the dossier.
        conn = get_db_connection(self.run_dir / "events.db")
        try:
            recon_tasks = [r["task_id"] for r in conn.execute(
                "SELECT task_id FROM tasks WHERE run_id = ? AND kind='recon'",
                (self.run_id,),
            ).fetchall()]
        finally:
            conn.close()
        self.assertTrue(recon_tasks)
        recon_summary = json.loads(
            (self.run_dir / "recon" / "recon-result.json").read_text(encoding="utf-8")
        )
        self.assertIn("guards", recon_summary)
        self.assertEqual(recon_summary["task_id"], recon_tasks[0])
        # 4. Verification artifact: one file per verify attempt.
        verified_files = list(self.run_dir.glob("findings/verified-*.json"))
        self.assertTrue(verified_files)
        self.assertTrue(
            any(v.name.endswith(f"{verify_claim['attempt_id']}.json") for v in verified_files),
            "verify attempt's findings artifact missing",
        )
        # 5. Candidates remain queryable from the verify task spec.
        conn = get_db_connection(self.run_dir / "events.db")
        try:
            spec = json.loads(conn.execute(
                "SELECT spec_json FROM tasks WHERE task_id = ?",
                (verify_claim["task_id"],),
            ).fetchone()["spec_json"])
        finally:
            conn.close()
        self.assertEqual(
            spec["input"]["candidate"]["candidate_id"], "cand-swr013-01",
            "the candidate must stay queryable from the persisted task spec",
        )

    def test_any_finding_traces_to_candidate_independent_verification_and_snapshot(self):
        """任一发现可追至快照文件摘要、候选及独立验证 (provenance 深等值)。"""
        verify_claim, submitted, _ = self._run_to_complete_with_verified_finding()
        confirmed_submitted = submitted[0]

        findings = json.loads(
            (self.run_dir / "report" / "findings.json").read_text(encoding="utf-8")
        )
        by_id = {f["finding_id"]: f for f in findings}
        stored = by_id[confirmed_submitted["finding_id"]]

        # Provenance deep equality: candidate + independent verification
        # anchors survive persistence verbatim (plus the run_id stamp only).
        self.assertEqual(stored["provenance"], confirmed_submitted["provenance"])
        self.assertEqual(stored["candidate_refs"], ["cand-swr013-01"])
        self.assertEqual(stored["run_id"], self.run_id)

        # Every provenance task reference resolves to a real ledger task.
        task_ids = {t["task_id"] for t in self.task_rows()}
        prov = stored["provenance"]
        for ref in prov["hunt_tasks"] + prov["verify_tasks"]:
            self.assertIn(ref, task_ids, f"provenance task {ref} not in ledger")

        # The candidate itself is queryable and carries the same hunt anchor.
        conn = get_db_connection(self.run_dir / "events.db")
        try:
            spec_rows = conn.execute(
                "SELECT spec_json FROM tasks WHERE run_id = ? AND kind='verify'",
                (self.run_id,),
            ).fetchall()
        finally:
            conn.close()
        candidates = [
            json.loads(r["spec_json"])["input"]["candidate"] for r in spec_rows
            if isinstance(json.loads(r["spec_json"]).get("input"), dict)
            and json.loads(r["spec_json"])["input"].get("candidate")
        ]
        self.assertTrue(candidates)
        self.assertIn(
            confirmed_submitted["provenance"]["hunt_tasks"][0],
            candidates[0]["provenance"]["hunt_tasks"],
        )

        # Snapshot file summary: the finding's sink path resolves to a frozen
        # manifest entry with its content digest.
        manifest = json.loads(
            (self.run_dir / "snapshot" / "manifest.json").read_text(encoding="utf-8")
        )
        by_path = {f["path"]: f for f in manifest["files"]}
        sink_path = stored["sink"]["path"]
        self.assertIn(sink_path, by_path, "finding sink not traceable to snapshot summary")
        self.assertRegex(by_path[sink_path]["sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(stored["sink"]["path"], stored["steps"][-1]["path"])

    def test_backward_trace_from_ledger_record_to_published_report(self):
        """反向追踪: ledger 事件 → 持久化工件 → 报告呈现。"""
        _, submitted, _ = self._run_to_complete_with_verified_finding()
        stored_events = self.events("verified_findings_stored")
        self.assertTrue(stored_events, "missing verified_findings_stored event")

        report_md = (self.run_dir / "report" / "REPORT.md").read_text(encoding="utf-8")
        trail_md = (self.run_dir / "report" / "AUDIT-TRAIL.md").read_text(encoding="utf-8")
        findings_json = (self.run_dir / "report" / "findings.json").read_text(encoding="utf-8")

        for ev in stored_events:
            artifact = self.run_dir / ev["artifact"]
            self.assertTrue(artifact.exists(), f"event references missing artifact {ev['artifact']}")
            on_disk = json.loads(artifact.read_text(encoding="utf-8"))
            for f in on_disk:
                # Finding ids recorded in the event match the artifact content.
                self.assertIn(f["finding_id"], ev["finding_ids"])
                # Machine-readable result carries every persisted finding...
                self.assertIn(f["finding_id"], findings_json)
                # ...the audit trail maps every finding's provenance...
                self.assertIn(f"**{f['finding_id']}**", trail_md)
                # ...and confirmed findings are presented in the main report.
                if f["verdict"] == "confirmed":
                    self.assertIn(f["finding_id"], report_md)

        # The snapshot id in the report header equals the frozen manifest's.
        manifest = json.loads(
            (self.run_dir / "snapshot" / "manifest.json").read_text(encoding="utf-8")
        )
        self.assertIn(manifest["snapshot_id"], report_md)

    def test_audit_trail_renders_provenance_keys_of_every_finding(self):
        """AUDIT-TRAIL.md 逐键渲染 provenance（报告 → 任务/候选/尝试锚点）。"""
        _, submitted, _ = self._run_to_complete_with_verified_finding()
        trail_md = (self.run_dir / "report" / "AUDIT-TRAIL.md").read_text(encoding="utf-8")
        prov_section = trail_md.split("Finding Provenance", 1)[1]
        for f in submitted:
            self.assertIn(f"**{f['finding_id']}**", prov_section)
            for key, value in f["provenance"].items():
                self.assertIn(f"{key}:", prov_section, f"provenance key {key} not rendered")
                rendered = json.dumps(value, ensure_ascii=False)
                self.assertIn(rendered.strip('"'), prov_section, f"value of {key} not rendered")


class TestSWR013RejectionAndPending(SWR013Base):
    """驳回理由 / 未决记录可查询。"""

    def test_rejected_rationale_and_pending_blockers_are_queryable(self):
        self.prepare_run()
        claims = self.app.next(self.run_id, self.run_dir, batch_size=10)
        recon = next(c for c in claims if c["spec"]["task_kind"] == "recon")
        hunts = [c for c in claims if c["spec"]["task_kind"] == "hunt"]
        self.submit_all([recon])
        hunt_claim = hunts[0]
        candidate = self.candidate_for(hunt_claim["task_id"], hunt_claim["attempt_id"])
        self.submit_all(hunts, records_fn=lambda c: [candidate])

        verify_claims = [
            c for c in self.app.next(self.run_id, self.run_dir, batch_size=10)
            if c["spec"]["task_kind"] == "verify"
        ]
        verify_claim = verify_claims[0]
        verifier = Verifier()
        rejected = verifier.create_finding_from_candidate(
            candidate, "rejected", verify_claim["task_id"],
            verify_attempt_id=verify_claim["attempt_id"],
            counter_evidence={
                "rationale": "guard framework.py enforces allow-list at entry",
                "anchors": [{"path": "danger.py", "line": 3}],
            },
        )
        pending_candidate = dict(candidate, candidate_id="cand-swr013-pending")
        pending = verifier.create_finding_from_candidate(
            pending_candidate, "needs_validation", verify_claim["task_id"],
            verify_attempt_id=verify_claim["attempt_id"],
            blockers=["requires runtime environment probe"],
            validation_plan="probe the deployment with a canary payload",
        )
        self.submit_all([verify_claim], records_fn=lambda c: [rejected, pending])
        fin = self.app.finalize(self.run_id, self.run_dir, findings=[])
        self.assertEqual(fin["final_state"], "complete")

        # Rejection reason queryable from the machine-readable result.
        findings = json.loads(
            (self.run_dir / "report" / "findings.json").read_text(encoding="utf-8")
        )
        by_id = {f["finding_id"]: f for f in findings}
        self.assertEqual(rejected["finding_id"] in by_id, True)
        self.assertEqual(
            by_id[rejected["finding_id"]]["counter_evidence"]["rationale"],
            "guard framework.py enforces allow-list at entry",
        )
        # Pending record queryable: blockers + validation plan persisted and
        # rendered in NEEDS-VALIDATION.md.
        stored_pending = by_id[pending["finding_id"]]
        self.assertEqual(stored_pending["blockers"], ["requires runtime environment probe"])
        self.assertEqual(stored_pending["validation_plan"], "probe the deployment with a canary payload")
        needs_md = (self.run_dir / "report" / "NEEDS-VALIDATION.md").read_text(encoding="utf-8")
        self.assertIn(pending["finding_id"], needs_md)
        self.assertIn("requires runtime environment probe", needs_md)
        self.assertIn("probe the deployment with a canary payload", needs_md)
        # The finalize unverified list exposes the pending verdict too.
        pending_entry = next(
            u for u in fin["unverified"] if u["finding_id"] == pending["finding_id"]
        )
        self.assertEqual(pending_entry["verdict"], "needs_validation")


class TestSWR013Corruption(SWR013Base):
    """丢失引用工件报 corrupt。"""

    def _prepare_with_artifact(self) -> Path:
        """Prepare + submit ONLY the recon claim so the dossier holds a
        referenced artifact while no attempt lease is left in flight."""
        self.prepare_run()
        claims = self.app.next(self.run_id, self.run_dir, batch_size=1)
        self.assertEqual(claims[0]["spec"]["task_kind"], "recon")
        self.submit_all(claims)
        artifact = self.run_dir / "tasks" / claims[0]["task_id"] / "result.json"
        self.assertTrue(artifact.exists())
        return artifact

    def test_missing_referenced_artifact_reports_corrupt(self):
        artifact = self._prepare_with_artifact()
        artifact.unlink()

        with self.assertRaises(CorruptRunError):
            self.app.finalize(self.run_id, self.run_dir, findings=[])
        # Honest terminal state + explicit event; no report produced.
        self.assertEqual(self.run_state(), "corrupt")
        corrupted = self.events("run_corrupted")
        self.assertEqual(len(corrupted), 1)
        self.assertFalse((self.run_dir / "report" / "REPORT.md").exists())

    def test_tampered_artifact_content_reports_corrupt(self):
        artifact = self._prepare_with_artifact()
        artifact.write_text('{"tampered": true}\n', encoding="utf-8")

        with self.assertRaises(CorruptRunError):
            self.app.finalize(self.run_id, self.run_dir, findings=[])
        self.assertEqual(self.run_state(), "corrupt")
        self.assertFalse((self.run_dir / "report" / "REPORT.md").exists())


if __name__ == "__main__":
    unittest.main()
