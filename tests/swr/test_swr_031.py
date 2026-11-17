"""SR-031 / SWR-031 / DSR-081 验收测试：运行教训文档归档。

Requirements: SR-031（每次可结束运行产出运行教训文档；防污染红线）
             SWR-031 / DSR-081（模板资产 docs/LESSONS-TEMPLATE.md；归档于
             <run-dir>/report/lessons.md，允许人工续写）
"""

import hashlib
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "skill" / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from auditkit.app.service import AuditAppService

FIXTURES_APP = Path(__file__).resolve().parents[1] / "fixtures" / "pyapp"
SKILL_DIR = Path(__file__).resolve().parents[2] / "skill"

class TestSWR031LessonsArchive(unittest.TestCase):
    """SR-031 / DSR-081: 每次可结束运行在卷宗内归档 lessons.md（模板驱动，
    自动填充元信息与自审摘要；3-7 节留待人工续写；不进可移植导出）。"""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())
        self.app = AuditAppService(SKILL_DIR)
        self.target = FIXTURES_APP
        self.run_dir = self.temp_dir / "run"
        cfg = {
            "schema_version": "1.0",
            "target": str(self.target),
            "run_dir": str(self.run_dir),
            "report_language": "zh",
            "profile": "standard",
            "scope": {"include": ["*"], "exclude": []},
            "budgets": [{
                "schema_version": "1.0", "dimension": "tasks", "mode": "enforced",
                "limit": 30, "settled": 0, "reserved": 0, "unit": "tasks",
                "availability": "exact",
            }],
            "safety_acceptance": {
                "allow_unverified_execution": False, "allow_unverified_network": False,
                "allow_unverified_write": False, "user_approved": True,
            },
        }
        prep = self.app.prepare(str(self.target), str(self.run_dir), cfg)
        self.run_id = prep["run_id"]
        self.app.activate(self.run_id, self.run_dir)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _drain_and_finalize(self):
        for _ in range(15):
            claims = self.app.next(self.run_id, self.run_dir, batch_size=5)
            if not claims:
                break
            for c in claims:
                self.app.start(self.run_dir, c)
                kind = (c.get("spec") or {}).get("task_kind") or "hunt"
                res = {"schema_version": "1.0", "task_id": c["task_id"],
                       "attempt_id": c["attempt_id"], "kind": kind,
                       "coverage": [], "records": [], "overflow": []}
                digest = hashlib.sha256(
                    json.dumps(res, sort_keys=True, ensure_ascii=False).encode("utf-8")
                ).hexdigest()
                self.app.submit(self.run_dir, c, res, digest)

    def test_complete_run_archives_lessons_md_per_template(self):
        self._drain_and_finalize()
        result = self.app.finalize(self.run_id, self.run_dir)
        lessons_path = self.run_dir / "report" / "lessons.md"
        self.assertTrue(lessons_path.exists(), "SR-031: lessons.md must be archived in the dossier")
        text = lessons_path.read_text(encoding="utf-8")
        # 模板红线与设计目标段必须保留（AI 修复前置上下文）
        self.assertIn("AI 修复前置红线", text)
        self.assertIn("数据单向流动", text)
        # 自动填充段：元信息与自审摘要
        self.assertIn(f"`{self.run_id}`", text)
        self.assertIn("自动自审结论", text)
        # 3-7 节模板占位保留（人工续写区）
        self.assertIn("## 三、已确认缺陷", text)
        # lessons.md 属报告目录产物，不进可移植导出
        self.assertFalse((self.run_dir / "skill-review" / "lessons.md").exists())
        self.assertEqual(result["final_state"], "complete")
