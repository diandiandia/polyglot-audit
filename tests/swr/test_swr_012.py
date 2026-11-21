"""SWR-012 acceptance tests (逐编号验收).

验收原文 (docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2):
    SWR-012 | SR-012 → SD-06、SD-08 | P2／SWR-018、SWR-021、SWR-025 |
    实现主报告、结果、未决、覆盖、轨迹、成本和终态渲染；
    正常/预算耗尽/中断对账，不可写显式失败。

上游系统需求 (SYSTEM_REQUIREMENTS.md §2):
    SR-012: 生成面向用户语言的主报告、机器可读结果、未决事项、覆盖、轨迹、
    成本和 Skill 自审；在受控中断、预算耗尽或任务失败时输出不完整报告。
    验收：报告与持久状态对账，说明终态和缺口；存储损坏或不可写时显式报错
    而非伪称已生成。

Acceptance coverage
-------------------
1. 七件套 + SKILL-REVIEW: 正常完成的运行在 report/ 下生成 REPORT.md /
   findings.json / NEEDS-VALIDATION.md / COVERAGE.md / coverage.csv /
   AUDIT-TRAIL.md / COST.md, 并在独立目录 skill-review/ 下生成本地自审
   (SKILL-REVIEW.md, 设计 §10.1), 全部登记在同一 generation 下, 报告与持久
   状态对账 (终态 complete、任务计数、事件数)。
2. 预算耗尽: enforced tasks 预算小于排队任务数时, 真实 claim 路径记
   budget_exhausted 事件; finalize 输出终态 incomplete (含 budget_exhausted
   理由) 且报告如实标注 incomplete, run_finalized 事件与报告一致。
3. 受控中断: 存在未完成 verify 任务时 finalize → incomplete
   (unprocessed_units), 未决候选以 F-UNVERIFIED-* 显式进入 NEEDS-VALIDATION,
   不静默消失; 在途 claim 租约未归还时 finalize 拒绝 (InvalidStateError),
   不产出伪造卷宗。
4. 存储不可写: report 发布路径不可写时显式 StorageError (含失败路径),
   运行不得伪称 complete, 也不得留下半成品报告。

Requirements: SWR-012(七件套+终态对账) / DSR-036(分代发布), DSR-068(语言与拆分), DSR-076(incomplete原因)
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

from auditkit.app.service import AuditAppService  # noqa: E402
from auditkit.contracts.errors import InvalidStateError, StorageError  # noqa: E402
from auditkit.ledger.db import get_db_connection  # noqa: E402

SKILL_DIR = REPO_ROOT = Path(__file__).resolve().parents[2] / "skill"

DANGER_SOURCE = "import os\n\n\ndef handler(user_input):\n    os.system(user_input)\n"

# The seven report deliverables (design §9.3) plus the always-written local
# self-review (design §10.1 keeps the skill self-review in its own
# skill-review/ directory — report/ holds only the report set). The portable
# export stays opt-in and is asserted absent.
SEVEN_DELIVERABLES = (
    "report/REPORT.md",
    "report/findings.json",
    "report/NEEDS-VALIDATION.md",
    "report/COVERAGE.md",
    "report/coverage.csv",
    "report/AUDIT-TRAIL.md",
    "report/COST.md",
)
SELF_REVIEW_DELIVERABLE = "skill-review/SKILL-REVIEW.md"


class SWR012Base(unittest.TestCase):

    def setUp(self) -> None:
        self.temp_dir = Path(tempfile.mkdtemp(prefix="swr012-"))
        self.app = AuditAppService(SKILL_DIR)
        self.run_dir = self.temp_dir / "run"
        self._run_id = None

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # ------------------------------------------------------------ helpers
    def make_target(self) -> Path:
        target = self.temp_dir / "target"
        target.mkdir(parents=True)
        (target / "danger.py").write_text(DANGER_SOURCE, encoding="utf-8")
        return target

    def make_config(self, target: Path, task_budget: int = 10, autosize: bool = True) -> dict:
        return {
            "schema_version": "1.0",
            "target": str(target),
            "run_dir": str(self.run_dir),
            "report_language": "en",
            "profile": "quick",
            "scope": {"include": ["*.py"], "exclude": []},
            "budgets": [{
                "schema_version": "1.0", "dimension": "tasks", "mode": "enforced",
                "limit": task_budget, "settled": 0, "reserved": 0, "unit": "tasks",
                "availability": "exact",
            }],
            "budget_autosize": autosize,
            "safety_acceptance": {
                "allow_unverified_execution": False,
                "allow_unverified_network": False,
                "allow_unverified_write": False,
                "user_approved": True,
            },
        }

    def prepare_run(self, task_budget: int = 10, autosize: bool = True) -> dict:
        target = self.make_target()
        config = self.make_config(target, task_budget=task_budget, autosize=autosize)
        prep = self.app.prepare(str(target), str(self.run_dir), config)
        self.app.activate(prep["run_id"], self.run_dir)
        self._run_id = prep["run_id"]
        return prep

    def candidate_record(self, claim_task_id: str) -> dict:
        return {
            "schema_version": "1.0",
            "candidate_id": "cand-swr012-01",
            "issue": "py-01",
            "source": {"path": "danger.py", "line": 4, "symbol": "handler",
                       "kind": "param", "control": "user_input"},
            "sink": {"path": "danger.py", "line": 4, "symbol": "os.system",
                     "kind": "rce", "effect": "command execution"},
            "steps": [
                {"path": "danger.py", "line": 4, "role": "source", "note": "n1"},
                {"path": "danger.py", "line": 4, "role": "sink", "note": "n2"},
            ],
            "guard_analysis": "none",
            "impact_claim": "RCE",
            "open_questions": [],
            "provenance": {"hunt_tasks": [claim_task_id]},
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

    def drain(self, hunt_records_fn=None):
        """Claim+start+submit every queued task until the queue is drained.

        ``stop_after`` bounds the number of claim rounds; ``None`` drains fully.
        """
        return self.drain_rounds(hunt_records_fn=hunt_records_fn)

    def drain_rounds(self, hunt_records_fn=None, stop_after=None):
        """Run up to ``stop_after`` claim rounds (None = drain the queue)."""
        drained = []
        rounds = 0
        while True:
            if stop_after is not None and rounds >= stop_after:
                break
            claims = self.app.next(self.run_id, self.run_dir, batch_size=10)
            if not claims:
                break
            for claim in claims:
                self.app.start(self.run_dir, claim)
                records = hunt_records_fn(claim) if hunt_records_fn else []
                self.app.submit(
                    self.run_dir, claim,
                    self.worker_result(claim, records),
                    f"digest-{claim['attempt_id']}",
                )
                drained.append(claim)
            rounds += 1
        return drained

    @property
    def run_id(self) -> str:
        if self._run_id is None:
            conn = get_db_connection(self.run_dir / "events.db")
            try:
                self._run_id = conn.execute("SELECT run_id FROM runs LIMIT 1").fetchone()["run_id"]
            finally:
                conn.close()
        return self._run_id

    def run_state(self) -> str:
        conn = get_db_connection(self.run_dir / "events.db")
        try:
            return conn.execute(
                "SELECT state FROM runs WHERE run_id = ?", (self.run_id,)
            ).fetchone()["state"]
        finally:
            conn.close()

    def artifact_generations(self) -> set:
        conn = get_db_connection(self.run_dir / "events.db")
        try:
            return {
                r["generation"] for r in conn.execute(
                    "SELECT DISTINCT generation FROM artifacts "
                    "WHERE run_id = ? AND generation IS NOT NULL",
                    (self.run_id,),
                ).fetchall()
            }
        finally:
            conn.close()

    def last_event_payload(self, event_type: str) -> dict:
        conn = get_db_connection(self.run_dir / "events.db")
        try:
            row = conn.execute(
                "SELECT payload_json FROM events WHERE event_type = ? "
                "ORDER BY revision DESC LIMIT 1",
                (event_type,),
            ).fetchone()
            return json.loads(row["payload_json"]) if row else {}
        finally:
            conn.close()

    def event_types(self) -> set:
        conn = get_db_connection(self.run_dir / "events.db")
        try:
            return {
                r["event_type"] for r in conn.execute(
                    "SELECT DISTINCT event_type FROM events WHERE run_id = ?",
                    (self.run_id,),
                ).fetchall()
            }
        finally:
            conn.close()


class TestSWR012Complete(SWR012Base):
    """正常完成的运行: report/ 七件套 + skill-review/ 本地自审全部生成并与持久状态对账。"""

    def test_complete_run_publishes_seven_deliverables_plus_skill_review(self):
        self.prepare_run()
        self.drain()
        fin = self.app.finalize(self.run_id, self.run_dir, findings=[])

        # Terminal state: fully drained run is complete; completeness is a
        # flow statement (SD-06), never a security conclusion.
        self.assertEqual(fin["final_state"], "complete")
        self.assertEqual(fin["incomplete_reasons"], [])
        self.assertEqual(set(fin["gates"].values()), {"pass"})
        self.assertEqual(self.run_state(), "complete")

        # The seven report deliverables + the local self-review all exist and
        # are non-empty.
        for rel_path in SEVEN_DELIVERABLES + (SELF_REVIEW_DELIVERABLE,):
            p = self.run_dir / rel_path
            self.assertTrue(p.exists(), f"missing deliverable {rel_path}")
            self.assertGreater(p.stat().st_size, 0, f"empty deliverable {rel_path}")
        # Design §10.1: the skill self-review lives in skill-review/; the
        # report/ directory holds only the §9.3 report set.
        self.assertFalse((self.run_dir / "report" / "SKILL-REVIEW.md").exists())
        # The portable export stays opt-in (DSR-045): not written by default.
        self.assertFalse((self.run_dir / "skill-review" / "portable.json").exists())
        # run.json (immutable run metadata) is part of the dossier.
        self.assertTrue((self.run_dir / "run.json").exists())

        # One generation id across the whole dossier; the report header and
        # the finalize result agree (报告与持久状态对账).
        generations = self.artifact_generations()
        self.assertEqual(len(generations), 1)
        self.assertEqual(generations.pop(), fin["generation_id"])
        report = (self.run_dir / "report" / "REPORT.md").read_text(encoding="utf-8")
        self.assertIn(fin["generation_id"], report)
        self.assertIn("complete", report)
        self.assertEqual(self.run_id, fin["run_id"])

    def test_deliverables_reconcile_with_persistent_state(self):
        """COST / COVERAGE / AUDIT-TRAIL / findings.json numbers reconcile with
        the ledger (报告与持久状态对账)."""
        self.prepare_run()
        drained = self.drain()
        fin = self.app.finalize(self.run_id, self.run_dir, findings=[])

        cost_md = (self.run_dir / "report" / "COST.md").read_text(encoding="utf-8")
        # recon + hunt tasks from the ledger, plus the report stage itself.
        n_tasks = len(drained) + 1
        self.assertIn(f"Total Executed Tasks**: {n_tasks}", cost_md)

        coverage_csv = (self.run_dir / "report" / "coverage.csv").read_text(encoding="utf-8")
        self.assertIn("danger.py", coverage_csv)

        trail_md = (self.run_dir / "report" / "AUDIT-TRAIL.md").read_text(encoding="utf-8")
        # Trail reconciliation: the stated event total equals the number of
        # rendered timeline rows, and the rendered timeline is a real in-order
        # prefix of the persisted event ledger. (Finalize's own gate/run_finalized
        # events are appended after publication by the documented G4 ordering,
        # so equality with the FINAL ledger count is not the contract.)
        conn = get_db_connection(self.run_dir / "events.db")
        try:
            ledger_revs = [
                r["revision"] for r in conn.execute(
                    "SELECT revision FROM events WHERE run_id = ? ORDER BY revision",
                    (self.run_id,),
                ).fetchall()
            ]
        finally:
            conn.close()
        stated = int(
            next(line for line in trail_md.splitlines() if "Total events" in line)
            .rsplit(":", 1)[1]
            .replace("**", "")
            .strip()
        )
        row_revs = []
        for line in trail_md.splitlines():
            if line.startswith("| ") and "`" in line and "|" in line:
                parts = [p.strip() for p in line.strip("|").split("|")]
                if parts and parts[0].isdigit():
                    row_revs.append(int(parts[0]))
        self.assertEqual(stated, len(row_revs), "trail total must equal rendered rows")
        self.assertEqual(row_revs, ledger_revs[: len(row_revs)],
                         "trail rows must be the ledger's in-order prefix")
        self.assertGreater(len(row_revs), 0)

        findings_json = json.loads(
            (self.run_dir / "report" / "findings.json").read_text(encoding="utf-8")
        )
        self.assertEqual(findings_json, [], "drained run with no candidates has no findings")


class TestSWR012BudgetExhausted(SWR012Base):
    """预算耗尽: dispatch 停止、事件入账、finalize 如实输出 incomplete。"""

    def test_budget_exhaustion_yields_incomplete_dossier_and_honest_event(self):
        # tasks budget = 1 covers only the recon claim; the hunt claim then
        # exhausts the enforced budget (real ledger path, not a synthetic
        # injected event).
        self.prepare_run(task_budget=1, autosize=False)
        claims = self.app.next(self.run_id, self.run_dir, batch_size=10)
        self.assertEqual(len(claims), 1, "only the recon claim fits the 1-task budget")
        self.assertEqual(claims[0]["spec"]["task_kind"], "recon")
        self.app.start(self.run_dir, claims[0])
        self.app.submit(
            self.run_dir, claims[0], self.worker_result(claims[0]), "digest-recon"
        )

        # The stop sequence recorded the exhaustion with the blocked task.
        payload = self.last_event_payload("budget_exhausted")
        self.assertEqual(payload.get("dimension"), "tasks")
        self.assertTrue(payload.get("blocked_task_id"))
        # Hunt work remains queued.
        conn = get_db_connection(self.run_dir / "events.db")
        try:
            queued = conn.execute(
                "SELECT count(*) AS c FROM tasks WHERE run_id = ? AND state = 'queued'",
                (self.run_id,),
            ).fetchone()["c"]
        finally:
            conn.close()
        self.assertGreaterEqual(queued, 1)

        fin = self.app.finalize(self.run_id, self.run_dir, findings=[])
        self.assertEqual(fin["final_state"], "incomplete")
        self.assertIn("budget_exhausted", fin["incomplete_reasons"])
        self.assertEqual(self.run_state(), "incomplete")
        self.assertEqual(fin["gates"]["G1"], "fail")

        # The published dossier states the true terminal state.
        report = (self.run_dir / "report" / "REPORT.md").read_text(encoding="utf-8")
        self.assertIn("incomplete", report)
        self.assertNotIn("`complete (`complete`)`", report)
        # run_finalized event agrees with the report (对账).
        finalized = self.last_event_payload("run_finalized")
        self.assertEqual(finalized["final_state"], "incomplete")
        self.assertIn("budget_exhausted", finalized["incomplete_reasons"])

    def test_reports_are_still_published_for_budget_exhausted_runs(self):
        """SR-012: a budget-exhausted run still publishes the report set — the
        deliverables exist and carry the incomplete state, instead of producing
        nothing."""
        self.prepare_run(task_budget=1, autosize=False)
        claims = self.app.next(self.run_id, self.run_dir, batch_size=10)
        self.app.start(self.run_dir, claims[0])
        self.app.submit(self.run_dir, claims[0], self.worker_result(claims[0]), "d")
        self.app.finalize(self.run_id, self.run_dir, findings=[])
        for rel_path in SEVEN_DELIVERABLES:
            self.assertTrue(
                (self.run_dir / rel_path).exists(),
                f"budget-exhausted run must still publish {rel_path}",
            )


class TestSWR012Interrupted(SWR012Base):
    """受控中断与在途租约: incomplete 终态、未决候选显式化、finalize 拒绝。"""

    def test_interrupted_run_incomplete_with_unverified_candidate_surfaced(self):
        self.prepare_run()
        # One claim round only: recon + hunts complete, the hunt carries a
        # candidate so a verify task is enqueued and never processed
        # (simulated interruption before the verify fan-out).
        self.drain_rounds(
            hunt_records_fn=lambda c: [self.candidate_record(c["task_id"])],
            stop_after=1,
        )
        conn = get_db_connection(self.run_dir / "events.db")
        try:
            verify_queued = conn.execute(
                "SELECT count(*) AS c FROM tasks WHERE run_id = ? AND kind='verify' AND state='queued'",
                (self.run_id,),
            ).fetchone()["c"]
        finally:
            conn.close()
        self.assertGreaterEqual(verify_queued, 1)

        fin = self.app.finalize(self.run_id, self.run_dir, findings=[])
        self.assertEqual(fin["final_state"], "incomplete")
        self.assertIn("unprocessed_units", fin["incomplete_reasons"])
        self.assertEqual(self.run_state(), "incomplete")

        # DSR-066: the never-verified candidate is surfaced as an explicit
        # unverified finding, not silently dropped.
        unverified_ids = [u["finding_id"] for u in fin["unverified"]]
        self.assertTrue(
            any(i.startswith("F-UNVERIFIED-") for i in unverified_ids),
            f"unverified candidate missing from finalize result: {fin['unverified']}",
        )
        needs_md = (self.run_dir / "report" / "NEEDS-VALIDATION.md").read_text(encoding="utf-8")
        self.assertIn("F-UNVERIFIED-", needs_md)
        self.assertIn("verification_not_completed_before_finalize", needs_md)
        report = (self.run_dir / "report" / "REPORT.md").read_text(encoding="utf-8")
        self.assertIn("incomplete", report)

    def test_finalize_refused_while_claims_are_in_flight(self):
        """SD-06 §5.1: finalize over attempts still held under a valid claim
        lease fails closed (InvalidStateError) and publishes nothing."""
        self.prepare_run()
        claims = self.app.next(self.run_id, self.run_dir, batch_size=10)
        self.assertTrue(claims)
        self.app.start(self.run_dir, claims[0])

        with self.assertRaises(InvalidStateError):
            self.app.finalize(self.run_id, self.run_dir, findings=[])
        # No terminal state was forged and no report was published.
        self.assertEqual(self.run_state(), "active")
        self.assertFalse((self.run_dir / "report" / "REPORT.md").exists())
        self.assertEqual(self.artifact_generations(), set())


class TestSWR012StorageUnwritable(SWR012Base):
    """存储不可写: 显式报错而非伪称已生成。"""

    def test_unwritable_report_destination_fails_explicitly(self):
        self.prepare_run()
        self.drain()
        # Block the publish destination: `report` exists as a FILE, so the
        # staged publication cannot create the report directory.
        (self.run_dir / "report").write_text("not a directory\n", encoding="utf-8")

        with self.assertRaises(StorageError) as ctx:
            self.app.finalize(self.run_id, self.run_dir, findings=[])
        # The explicit error names the failing report path (故障路径可见).
        self.assertIn("report", str(ctx.exception))
        self.assertIn("Failed to stage report artifact", str(ctx.exception))

        # The run never claims a terminal 'complete' state.
        self.assertNotEqual(self.run_state(), "complete")
        # No half-published report artifacts exist.
        self.assertFalse((self.run_dir / "report" / "REPORT.md").exists())
        self.assertFalse((self.run_dir / "report" / "findings.json").exists())


if __name__ == "__main__":
    unittest.main()
