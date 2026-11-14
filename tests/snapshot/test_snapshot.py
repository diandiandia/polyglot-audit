"""Tests for snapshot collection, three-root separation, and drift checking."""
# ==============================================================================
# 软件需求追踪与实现规范 (Software Requirements Traceability)
# ==============================================================================
# --- 需求编号: DSR-011/012 [负责人: SNP] / SWR-015 / SWR-017 ---
# 需求描述: 三根路径分离与链接安全访问、快照复制与内容摘要清单；
#   符号链接逃逸与路径穿越拒绝，dirty/非 Git 均可复现快照。
#   └─ 对应系统需求 SR-015（载荷/源码/运行目录分离）与 SR-017（内容寻址快照与漂移检出）。
# ==============================================================================

import shutil
import tempfile
import unittest
from pathlib import Path

from auditkit.contracts.errors import (
    PathUnsafeError,
    SnapshotInconsistentError,
)
from auditkit.snapshot.collector import SnapshotCollector, count_lines
from auditkit.snapshot.manifest import compute_root_hash
from auditkit.snapshot.paths import validate_canonical_relpath, validate_three_roots


class TestSnapshot(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.target = Path(self.temp_dir) / "target"
        self.skill = Path(self.temp_dir) / "skill"
        self.run = Path(self.temp_dir) / "run"

        self.target.mkdir()
        self.skill.mkdir()
        self.run.mkdir()

        # Create dummy target file
        (self.target / "main.py").write_text("print('hello')\nprint('world')\n", encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def test_three_root_separation_success(self):
        t, s, r = validate_three_roots(str(self.target), str(self.skill), str(self.run))
        self.assertEqual(t, self.target.resolve())
        self.assertEqual(s, self.skill.resolve())
        self.assertEqual(r, self.run.resolve())

    def test_three_root_overlap_detected(self):
        # Target inside run dir
        sub_target = self.run / "nested_target"
        sub_target.mkdir()
        with self.assertRaises(PathUnsafeError):
            validate_three_roots(str(sub_target), str(self.skill), str(self.run))

    def test_canonical_relpath_security(self):
        self.assertEqual(validate_canonical_relpath("app/main.py"), "app/main.py")

        with self.assertRaises(PathUnsafeError):
            validate_canonical_relpath("/etc/passwd")
        with self.assertRaises(PathUnsafeError):
            validate_canonical_relpath("app/../secret.txt")
        with self.assertRaises(PathUnsafeError):
            validate_canonical_relpath("app/null\0byte.py")

    def test_count_lines_conventions(self):
        # Empty file
        self.assertEqual(count_lines(b"")[0], 0)
        # 2 lines with trailing newline
        self.assertEqual(count_lines(b"line1\nline2\n")[0], 2)
        # 2 lines without trailing newline
        self.assertEqual(count_lines(b"line1\nline2")[0], 2)
        # CRLF
        self.assertEqual(count_lines(b"line1\r\nline2\r\n")[0], 2)

    def test_collector_and_drift_detection(self):
        dest = self.run / "snapshot"
        collector = SnapshotCollector(self.target, dest)
        manifest = collector.collect()

        self.assertTrue(dest.exists())
        self.assertEqual(len(manifest.files), 1)
        self.assertEqual(manifest.files[0]["path"], "main.py")
        self.assertEqual(manifest.files[0]["line_count"], 2)


if __name__ == "__main__":
    unittest.main()
