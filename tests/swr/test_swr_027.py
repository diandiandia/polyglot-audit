"""SWR-027 acceptance tests: version declaration, read compatibility, no auto-migration.

验收准则原文 (docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2):
| SWR-027 | SR-027 -> SD-06 | P1 / SWR-018、SWR-025 | 实现版本声明、旧格式只读及报告重渲染的受支持范围；
  测试旧样本、未知版本拒绝和不自动迁移活动 run。 |

上游系统需求 (SYSTEM_REQUIREMENTS.md §2):
| SR-027 | 状态、卷宗与知识资产有版本和兼容策略，升级不隐式迁移未完成审计或篡改历史记录。
  验收：受支持旧格式的读取/重渲染有测试，不支持的版本显式拒绝，升级需用户确认。 |

绑定实现: ledger/db.py:check_version_compatibility / SUPPORTED_SCHEMA_VERSIONS /
SUPPORTED_KNOWLEDGE_VERSION_MAJOR (DSR-072), app/service.py:_open_run_db（fail closed）。
"""

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

_SKILL_SCRIPTS = Path(__file__).resolve().parents[2] / "skill" / "scripts"
if str(_SKILL_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SKILL_SCRIPTS))

from auditkit.app.service import AuditAppService  # noqa: E402
from auditkit.contracts.errors import UnsupportedSchemaError  # noqa: E402
from auditkit.ledger.db import (  # noqa: E402
    SUPPORTED_KNOWLEDGE_VERSION_MAJOR,
    SUPPORTED_SCHEMA_VERSIONS,
    SKILL_VERSION,
    check_version_compatibility,
    get_db_connection,
    init_database,
)
from auditkit.ledger.task_queue import TaskQueue  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
SKILL_DIR = REPO_ROOT / "skill"
FIXTURES_APP = REPO_ROOT / "tests" / "fixtures" / "pyapp" / "app"

_RUN_INSERT = """
INSERT INTO runs (run_id, snapshot_id, state, schema_version, skill_version,
                  knowledge_version, config_ref, revision, created_at, updated_at)
VALUES (?, 'snp-027', ?, ?, ?, ?, 'config.json', 0,
        '2026-11-14T00:00:00Z', '2026-11-14T00:00:00Z')
"""


class TestSWR027(unittest.TestCase):
    """版本声明、受支持版本正常读取、旧/未来版本显式拒绝、活动 run 不自动迁移、
    knowledge/skill 版本同口径。"""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="swr-027-"))
        self.app = AuditAppService(SKILL_DIR)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # ------------------------------------------------------------ helpers
    def _seed_run(self, db_path, run_id="run-swr-027", state="active",
                  schema_version="1.0", skill_version="0.1.0", knowledge_version="1.0",
                  with_work=False):
        init_database(db_path)
        conn = get_db_connection(db_path)
        conn.execute(
            _RUN_INSERT,
            (run_id, state, schema_version, skill_version, knowledge_version),
        )
        if with_work:
            # An active run mid-flight: tasks, attempts, budget rows, events.
            conn.execute(
                """
                INSERT INTO tasks (task_id, run_id, task_key, kind, state, priority,
                                   generation, spec_digest, spec_json)
                VALUES ('task-027', ?, 'hunt:u1', 'hunt', 'claimed', 10, 1, 'digest', '{}')
                """,
                (run_id,),
            )
            conn.execute(
                """
                INSERT INTO attempts (attempt_id, task_id, generation, status,
                                      token_digest, expires_at)
                VALUES ('att-027', 'task-027', 1, 'claimed',
                        'aa' * 32, '2099-01-01T00:00:00+00:00')
                """
            )
            conn.execute(
                """
                INSERT INTO budget_dimensions (run_id, dimension, mode, limit_val,
                                               settled, reserved, unit)
                VALUES (?, 'tasks', 'enforced', 5, 1, 1, 'tasks')
                """,
                (run_id,),
            )
            conn.execute(
                """
                INSERT INTO events (event_id, run_id, revision, event_type, occurred_at,
                                    actor, payload_version, payload_json)
                VALUES ('evt-027', ?, 1, 'attempt_claimed', '2026-11-14T00:00:01Z',
                        'worker', '1.0', '{"task_id": "task-027"}')
                """,
                (run_id,),
            )
        conn.commit()
        conn.close()
        return run_id

    def _snapshot_db(self, db_path):
        """Full logical snapshot of every user table (rows) plus the schema."""
        conn = get_db_connection(db_path)
        try:
            tables = [
                r["name"]
                for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table' "
                    "AND name NOT LIKE 'sqlite_%' ORDER BY name"
                ).fetchall()
            ]
            dump = {"tables": tables}
            for t in tables:
                dump[t] = conn.execute(f"SELECT * FROM {t}").fetchall()
            return dump
        finally:
            conn.close()

    # ------------------------------------------------------- 版本声明
    def test_version_declaration_recorded_at_prepare(self):
        """新 run 落库即声明 schema/skill/knowledge 版本（版本声明），三者皆受支持。"""
        target = self.temp_dir / "target"
        run_dir = self.temp_dir / "run"
        shutil.copytree(FIXTURES_APP, target)
        config = {
            "schema_version": "1.0",
            "target": str(target),
            "run_dir": str(run_dir),
            "report_language": "en",
            "profile": "standard",
            "scope": {"include": ["*"], "exclude": []},
            "budgets": [],
            "safety_acceptance": {
                "allow_unverified_execution": False,
                "allow_unverified_network": False,
                "allow_unverified_write": False,
                "user_approved": True,
            },
        }
        prep = self.app.prepare(target, run_dir, config)
        conn = get_db_connection(run_dir / "events.db")
        try:
            row = conn.execute(
                "SELECT schema_version, skill_version, knowledge_version FROM runs "
                "WHERE run_id = ?",
                (prep["run_id"],),
            ).fetchone()
        finally:
            conn.close()
        self.assertIn(row["schema_version"], SUPPORTED_SCHEMA_VERSIONS)
        self.assertEqual(row["schema_version"], "1.0")
        self.assertEqual(row["skill_version"], SKILL_VERSION)
        self.assertEqual(row["knowledge_version"].split(".", 1)[0],
                         SUPPORTED_KNOWLEDGE_VERSION_MAJOR)

    # --------------------------------------- 受支持版本读取正常
    def test_supported_version_reads_normally(self):
        """受支持版本（1.0）：版本检查放行并返回版本信息，服务读路径与派发均正常。"""
        db_path = self.temp_dir / "events.db"
        run_id = self._seed_run(db_path, with_work=True)
        conn = get_db_connection(db_path)
        try:
            info = check_version_compatibility(conn, run_id)
            self.assertEqual(info["run_id"], run_id)
            self.assertEqual(info["schema_version"], "1.0")

            queue = TaskQueue(conn)
            claim = queue.claim(run_id, batch_size=1)
            # The seeded attempt already holds the task; nothing new to claim.
            self.assertEqual(claim, [])
        finally:
            conn.close()

    # ------------------------------------- 未来/旧版本拒绝且记录不动
    def _assert_rejection_leaves_record_untouched(self, schema_version):
        run_dir = self.temp_dir / f"run-{schema_version}"
        run_dir.mkdir()
        db_path = run_dir / "events.db"
        run_id = self._seed_run(db_path, schema_version=schema_version, with_work=True)
        before = self._snapshot_db(db_path)

        # 1. The version check itself fails closed, explicitly.
        conn = get_db_connection(db_path)
        try:
            with self.assertRaises(UnsupportedSchemaError) as ctx:
                check_version_compatibility(conn, run_id)
            self.assertIn(schema_version, str(ctx.exception))
            self.assertIn("prohibited", str(ctx.exception))
        finally:
            conn.close()

        # 2. Every service read/dispatch path fails closed (no degraded read).
        with self.assertRaises(UnsupportedSchemaError):
            self.app.status(run_id, run_dir)
        conn = get_db_connection(db_path)
        try:
            with self.assertRaises(UnsupportedSchemaError):
                TaskQueue(conn).claim(run_id, batch_size=1)
        finally:
            conn.close()

        # 3. The record is byte-for-byte untouched: no migration write path.
        after = self._snapshot_db(db_path)
        self.assertEqual(after["tables"], before["tables"], "no tables may be created/renamed")
        for table in before["tables"]:
            self.assertEqual(
                after[table], before[table],
                f"table {table} was modified during a rejected open (auto-migration?)",
            )

    def test_future_schema_version_rejected_and_record_untouched(self):
        """未来 schema_version（'99.0'）显式拒绝；活动 run 的全部表内容保持原样
        （无迁移写路径）。"""
        self._assert_rejection_leaves_record_untouched("99.0")

    def test_unsupported_old_schema_version_rejected_and_record_untouched(self):
        """旧 schema_version（'0.9'）显式拒绝；记录不被修改（旧格式只读需显式支持）。"""
        self._assert_rejection_leaves_record_untouched("0.9")

    def test_event_payload_version_rejected_on_append_and_replay(self):
        """事件 payload_version 同口径：未知版本在写入与重放两侧都拒绝，
        已落库的未知版本事件使重放失败关闭而不是静默再解释。"""
        from auditkit.ledger.event_store import EventStore

        db_path = self.temp_dir / "events-payload.db"
        run_id = self._seed_run(db_path)
        conn = get_db_connection(db_path)
        try:
            store = EventStore(conn)
            with self.assertRaises(UnsupportedSchemaError):
                store.append_event(run_id, "run_paused", "service", {}, payload_version="2.0")

            # Forge an event with an unsupported payload version directly, then
            # require replay to refuse (no silent reinterpretation).
            conn.execute(
                """
                INSERT INTO events (event_id, run_id, revision, event_type, occurred_at,
                                    actor, payload_version, payload_json)
                VALUES ('evt-future', ?, 1, 'run_paused', '2026-11-14T00:00:02Z',
                        'service', '2.0', '{"reason": "x"}')
                """,
                (run_id,),
            )
            conn.commit()
            with self.assertRaises(UnsupportedSchemaError):
                store.replay_events(run_id)
        finally:
            conn.close()

    # ------------------------------- knowledge / skill 版本同口径
    def test_knowledge_and_skill_versions_follow_the_same_policy(self):
        """knowledge_version 与 skill_version 同口径：主版本不匹配即拒绝（含未来
        主版本），同主版本的旧小版本正常读取；错误信息明确禁止自动迁移。"""
        db_path = self.temp_dir / "events-kv.db"

        # Future knowledge major: rejected.
        run_id = self._seed_run(db_path, knowledge_version="2.0")
        conn = get_db_connection(db_path)
        try:
            with self.assertRaises(UnsupportedSchemaError) as ctx:
                check_version_compatibility(conn, run_id)
            self.assertIn("knowledge_version", str(ctx.exception))
            self.assertIn("prohibited", str(ctx.exception))
        finally:
            conn.close()

        # Same major, older minor: still readable (compatible old format).
        db_path2 = self.temp_dir / "events-kv-ok.db"
        run_id2 = self._seed_run(db_path2, knowledge_version="1.3")
        conn2 = get_db_connection(db_path2)
        try:
            info = check_version_compatibility(conn2, run_id2)
            self.assertEqual(info["knowledge_version"], "1.3")
        finally:
            conn2.close()

        # Skill major mismatch is rejected with the same fail-closed policy.
        db_path3 = self.temp_dir / "events-sv.db"
        run_id3 = self._seed_run(db_path3, skill_version="1.0.0")
        conn3 = get_db_connection(db_path3)
        try:
            with self.assertRaises(UnsupportedSchemaError) as ctx:
                check_version_compatibility(conn3, run_id3)
            self.assertIn("skill_version", str(ctx.exception))
        finally:
            conn3.close()

        # Same skill major, older minor: readable.
        db_path4 = self.temp_dir / "events-sv-ok.db"
        run_id4 = self._seed_run(db_path4, skill_version="0.0.9")
        conn4 = get_db_connection(db_path4)
        try:
            info = check_version_compatibility(conn4, run_id4)
            self.assertEqual(info["skill_version"], "0.0.9")
        finally:
            conn4.close()

    def test_error_identifies_the_offending_run_and_version(self):
        """拒绝错误可定位：指明出问题的 run 与其版本及受支持范围（不可静默修复）。"""
        db_path = self.temp_dir / "events-locate.db"
        bad_run = self._seed_run(db_path, run_id="run-bad", schema_version="2.5")
        good_run = self._seed_run(
            Path(str(db_path) + ".2"), run_id="run-good", schema_version="1.0"
        )
        self.assertEqual(bad_run, "run-bad")
        self.assertEqual(good_run, "run-good")
        conn = get_db_connection(db_path)
        try:
            with self.assertRaises(UnsupportedSchemaError) as ctx:
                check_version_compatibility(conn, bad_run)
        finally:
            conn.close()
        self.assertIn("run-bad", str(ctx.exception))
        self.assertIn("2.5", str(ctx.exception))
        detail = ctx.exception.details or {}
        self.assertEqual(detail.get("run_id"), "run-bad")
        self.assertEqual(detail.get("schema_version"), "2.5")


if __name__ == "__main__":
    unittest.main()
