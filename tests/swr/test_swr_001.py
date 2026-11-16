"""SWR-001 acceptance tests (逐编号验收).

验收原文 (docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2):
    SWR-001 | SR-001 → SD-01 | P2／SWR-023 |
    实现 guide/audit 分流、范围/预算采集和模糊请求确认；
    测试 guide 不建卷宗、audit 缺条件不运行。

上游系统需求 (SYSTEM_REQUIREMENTS.md §2):
    SR-001: 提供 guide 问答与 audit 正式审计两种入口；guide 只回答方法论问题，
    不创建运行卷宗；audit 需要显式范围与预算，条件缺失时不运行。

Acceptance coverage
-------------------
1. guide/audit 两种输入分别触发相应行为:
   - guide 请求（方法论提问）走 GuideService, 返回 knowledge-catalog 卡片引导,
     不进入 AuditAppService 的任何状态变更入口（分流正确）。
   - audit 请求走 prepare/activate 流程, 携带显式 scope + budgets + safety
     acceptance（范围/预算采集）。
2. 模糊请求不静默启动完整审计: 空/过短/无请求动词的查询进入显式 ambiguous
   状态并返回澄清问题, 全程不调用 prepare（无静默 full audit）。
3. guide 不产生任何卷宗文件: 问答前后工作目录均无 events.db / snapshot /
   plan.json / report 等卷宗工件。
4. audit 缺条件不运行: 缺 schema 必填字段、安全确认缺失（user_approved 缺失或
   为 False）、run_dir 非空时 prepare 显式失败, 且不产生任何卷宗工件
   （events.db / snapshot / plan.json 均不存在）。
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[2]
SKILL_SCRIPTS = REPO_ROOT / "skill" / "scripts"
if str(SKILL_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SKILL_SCRIPTS))

from auditkit.app.guide import GuideService, MIN_QUERY_LENGTH  # noqa: E402
from auditkit.app.service import AuditAppService  # noqa: E402
from auditkit.contracts.errors import AuditError  # noqa: E402

SKILL_DIR = REPO_ROOT / "skill"
PYAPP_FIXTURE = REPO_ROOT / "tests" / "fixtures" / "pyapp"

# Dossier markers: none of these may exist after a guide interaction, and none
# may exist after a prepare that failed its preconditions.
DOSSIER_MARKERS = ("events.db", "snapshot", "plan.json", "report", "config.json")


class TestSWR001(unittest.TestCase):
    """guide/audit 分流、模糊请求确认、guide 不建卷宗、audit 缺条件不运行。"""

    def setUp(self) -> None:
        self.temp_dir = Path(tempfile.mkdtemp(prefix="swr001-"))
        # The CLI wires GuideService to the knowledge root (audit.py:704).
        self.guide = GuideService(SKILL_DIR / "knowledge")

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # ------------------------------------------------------------ helpers
    def _audit_config(self, target: Path) -> dict:
        """A fully-conditions-satisfied audit config (explicit scope+budgets)."""
        return {
            "schema_version": "1.0",
            "target": str(target),
            "run_dir": str(self.temp_dir / "run"),
            "report_language": "en",
            "profile": "quick",
            "scope": {"include": ["*.py"], "exclude": []},
            "budgets": [{
                "schema_version": "1.0", "dimension": "tasks", "mode": "enforced",
                "limit": 10, "settled": 0, "reserved": 0, "unit": "tasks",
                "availability": "exact",
            }],
            "safety_acceptance": {
                "allow_unverified_execution": False,
                "allow_unverified_network": False,
                "allow_unverified_write": False,
                "user_approved": True,
            },
        }

    def _no_dossier(self, *dirs: Path, msg: str = "") -> None:
        for d in dirs:
            for marker in DOSSIER_MARKERS:
                self.assertFalse(
                    (d / marker).exists(),
                    f"{msg}: guide must not create dossier artifact "
                    f"{d / marker} (SWR-001: guide 不建卷宗)",
                )

    # ------------------------------------------------- 1. guide/audit 分流
    def test_guide_request_answers_from_catalog_and_never_enters_audit_service(self):
        """A concrete methodology question is a guide request: catalog-backed
        answer, and the audit service's state-mutating entry points are never
        touched (分流: guide 输入触发 guide 行为)."""
        target = self.temp_dir / "target"
        target.mkdir()
        (target / "app.py").write_text("print('hi')\n", encoding="utf-8")

        with mock.patch.object(
            AuditAppService, "prepare",
            side_effect=AssertionError("guide request must not launch audit prepare"),
        ), mock.patch.object(
            AuditAppService, "activate",
            side_effect=AssertionError("guide request must not activate a run"),
        ):
            result = self.guide.answer_query("请解释 python 反序列化漏洞的审计方法")

        self.assertEqual(result["mode"], "guide")
        self.assertEqual(result["status"], "ok")
        # Guide answers with knowledge-catalog material, not a run.
        self.assertIsInstance(result["relevant_cards"], list)
        self.assertTrue(result["catalog_index"])
        for key in ("run_id", "run_dir", "snapshot_id"):
            self.assertNotIn(key, result, "guide response must not carry run identity")

    def test_audit_request_runs_prepare_with_explicit_scope_and_budgets(self):
        """An audit request (prepare with explicit scope/budget/safety) starts a
        real run: dossier is created with the supplied scope and budgets
        (分流: audit 输入触发 audit 行为; 范围/预算采集)."""
        target = self.temp_dir / "target2"
        target.mkdir()
        (target / "app.py").write_text("value = 1\n", encoding="utf-8")
        app = AuditAppService(SKILL_DIR)
        config = self._audit_config(target)

        prep = app.prepare(str(target), config["run_dir"], config)
        self.assertTrue(prep["run_id"].startswith("run-"))
        run_dir = Path(config["run_dir"])
        # The audit dossier really exists now (contrast with guide above).
        self.assertTrue((run_dir / "events.db").exists())
        self.assertTrue((run_dir / "snapshot" / "manifest.json").exists())
        saved = json.loads((run_dir / "config.json").read_text(encoding="utf-8"))
        self.assertEqual(saved["scope"], config["scope"])
        self.assertEqual(saved["budgets"], config["budgets"])

    # --------------------------------- 2. 模糊请求不静默启动完整审计
    def test_ambiguous_queries_enter_explicit_ambiguous_state(self):
        """Empty / too-short / no-request-verb queries are classified
        ambiguous with a reason and answered with clarification questions."""
        cases = [
            ("", "empty_query"),
            ("   \t ", "empty_query"),
            ("py" * 2, "query_too_short"),  # 4 chars < MIN_QUERY_LENGTH
            ("蓝鲸企鹅和北极熊的下午茶", "no_request_verb"),
        ]
        for query, expected_reason in cases:
            result = self.guide.answer_query(query)
            self.assertEqual(result["status"], "ambiguous", f"query={query!r}")
            self.assertEqual(result["ambiguity_reason"], expected_reason, f"query={query!r}")
            self.assertTrue(
                result["clarification_questions"],
                f"ambiguous query {query!r} must get clarification questions",
            )
            self.assertEqual(result["relevant_cards"], [])
            self.assertEqual(result["catalog_index"], [])
            # The guidance states explicitly that nothing was executed.
            self.assertTrue(result["guidance"])

    def test_short_query_threshold_matches_declared_minimum(self):
        """MIN_QUERY_LENGTH governs the too-short boundary deterministically."""
        self.assertEqual(MIN_QUERY_LENGTH, 8)
        self.assertEqual(
            self.guide.classify_query("x" * (MIN_QUERY_LENGTH - 1)),
            ("ambiguous", "query_too_short"),
        )

    def test_ambiguous_query_never_silently_launches_full_audit(self):
        """DSR-032: an ambiguous request must not silently start a full audit.
        prepare/activate/next are asserted un-called while several ambiguous
        phrasings are answered."""
        with mock.patch.object(
            AuditAppService, "prepare",
            side_effect=AssertionError("ambiguous request silently launched prepare"),
        ), mock.patch.object(
            AuditAppService, "activate",
            side_effect=AssertionError("ambiguous request silently activated a run"),
        ), mock.patch.object(
            AuditAppService, "next",
            side_effect=AssertionError("ambiguous request silently dispatched tasks"),
        ):
            # "蓝鲸企鹅…" has no whitelisted request verb; "嗯" is too short.
            for query in ("", "嗯", "蓝鲸企鹅和北极熊的下午茶点心"):
                result = self.guide.answer_query(query)
                self.assertEqual(result["status"], "ambiguous")
        # And nothing was created on disk either.
        self._no_dossier(self.temp_dir, msg="ambiguous request")

    # --------------------------------------- 3. guide 不产生任何卷宗文件
    def test_guide_produces_no_dossier_files_for_concrete_queries(self):
        """Even a fully concrete guide query leaves the filesystem without any
        run dossier artifact (guide 不建卷宗)."""
        before = sorted(p.name for p in self.temp_dir.iterdir())
        result = self.guide.answer_query("如何审计 java 反序列化? 帮我列出检查步骤")
        after = sorted(p.name for p in self.temp_dir.iterdir())
        self.assertEqual(result["status"], "ok")
        self.assertEqual(before, after, "guide interaction changed the working directory")
        self._no_dossier(self.temp_dir, msg="concrete guide query")

    def test_guide_service_object_holds_no_run_state(self):
        """GuideService carries no run identity at all: it cannot have created
        a dossier because it does not know one."""
        self.assertFalse(hasattr(self.guide, "run_id"))
        self.assertFalse(hasattr(self.guide, "run_dir"))
        self.assertFalse(hasattr(self.guide, "conn"))

    # --------------------------------------- 4. audit 缺条件不运行
    def test_audit_without_required_config_fields_does_not_run(self):
        """Missing schema-required fields (budgets / safety_acceptance / scope)
        fail prepare explicitly and produce no dossier (缺条件不运行)."""
        target = self.temp_dir / "target3"
        target.mkdir()
        (target / "app.py").write_text("value = 1\n", encoding="utf-8")
        app = AuditAppService(SKILL_DIR)

        for missing in ("budgets", "safety_acceptance", "scope"):
            config = self._audit_config(target)
            config["run_dir"] = str(self.temp_dir / f"run-missing-{missing}")
            del config[missing]
            with self.assertRaises(AuditError, msg=f"missing {missing} must not run"):
                app.prepare(str(target), config["run_dir"], config)
            run_dir = Path(config["run_dir"])
            self._no_dossier(run_dir, msg=f"prepare without {missing}")

    def test_audit_without_user_approval_does_not_run(self):
        """Safety acceptance is a hard precondition: user_approved missing or
        False refuses to run (安全确认缺失不运行)."""
        target = self.temp_dir / "target4"
        target.mkdir()
        (target / "app.py").write_text("value = 1\n", encoding="utf-8")
        app = AuditAppService(SKILL_DIR)

        for label, mutate in (
            ("user_approved_false", lambda c: c["safety_acceptance"].update({"user_approved": False})),
            ("user_approved_absent", lambda c: c["safety_acceptance"].pop("user_approved")),
            ("safety_block_absent", lambda c: c["safety_acceptance"].pop("allow_unverified_execution")),
        ):
            config = self._audit_config(target)
            config["run_dir"] = str(self.temp_dir / f"run-{label}")
            mutate(config)
            with self.assertRaises(AuditError, msg=f"{label} must not run"):
                app.prepare(str(target), config["run_dir"], config)
            self._no_dossier(Path(config["run_dir"]), msg=label)

    def test_audit_with_nonempty_run_dir_does_not_run(self):
        """A non-empty run directory refuses prepare instead of silently
        overwriting an existing dossier (卷宗已存在不重跑)."""
        target = self.temp_dir / "target5"
        target.mkdir()
        (target / "app.py").write_text("value = 1\n", encoding="utf-8")
        app = AuditAppService(SKILL_DIR)
        run_dir = self.temp_dir / "run-existing"
        run_dir.mkdir()
        (run_dir / "user-data.txt").write_text("precious\n", encoding="utf-8")

        with self.assertRaises(AuditError):
            app.prepare(str(target), str(run_dir), self._audit_config(target))
        # The pre-existing file is untouched and no dossier was started.
        self.assertEqual(
            (run_dir / "user-data.txt").read_text(encoding="utf-8"), "precious\n"
        )
        self._no_dossier(run_dir, msg="non-empty run dir")

    def test_audit_with_missing_target_does_not_run(self):
        """A nonexistent target directory is an explicit precondition failure
        (目标不存在不运行)."""
        app = AuditAppService(SKILL_DIR)
        config = self._audit_config(self.temp_dir / "does-not-exist")
        config["run_dir"] = str(self.temp_dir / "run-no-target")
        with self.assertRaises(AuditError):
            app.prepare(config["target"], config["run_dir"], config)
        self._no_dossier(Path(config["run_dir"]), msg="missing target")


if __name__ == "__main__":
    unittest.main()
