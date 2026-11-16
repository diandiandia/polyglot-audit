"""SWR-017 acceptance tests (逐编号验收测试).

验收原文 (docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2):
    | SWR-017 | SR-017 → SD-03 | P1／— |
    实现内容寻址的只读快照、采集复查、漂移及失败处理；
    覆盖 dirty/非 Git、同 mtime 同大小改写、采集中变化与磁盘不足。

对应 DSR-012/013（docs/design/DETAILED_DEVELOPMENT_REQUIREMENTS.md）:
    | DSR-012 | 实现快照复制、内容摘要和清单；dirty Git、非 Git、同大小同时间
      改写及冻结后源文件变更均可复现快照，禁止仅用 mtime 判断。 |
    | DSR-013 | 实现采集复查、文件类型/解码失败和存储失败处理；注入采集中的
      变更、链接、读失败、磁盘不足，均阻止 ready 或如实记录范围缺口。 |

验收要点（本文件逐条对应）:
- dirty Git：检出并记录 dirty；可配置拒绝（reject_dirty_git）在复制任何
  文件前中止（拒绝继续），快照目标不被创建；
- 非 Git：如实记录 non_git（不猜测、不阻塞）；
- 同大小同 mtime 改写：内容级 SHA-256 复查（authoritative）必检出——
  mtime/大小永不作为稳定性证明；record 模式下冻结副本仍是原内容；
- 采集中变化：新增/删除文件 → SnapshotInconsistentError（不能确保一致时
  拒绝继续，不产出快照）；record 模式如实记 drift gap；
- 磁盘不足：存储写入失败 → 不产出快照目标、不留半成品临时目录；
- 内容寻址：相同内容 → 相同 root_hash/snapshot_id；不同内容 → 不同；
  冻结副本逐文件 SHA-256 与清单一致；采集只读不修改源树。
"""

from __future__ import annotations

import builtins
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SKILL_SCRIPTS = Path(__file__).resolve().parents[2] / "skill" / "scripts"
if str(SKILL_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SKILL_SCRIPTS))

from auditkit.contracts.errors import SnapshotInconsistentError
from auditkit.snapshot.collector import GAP_DRIFT_DETECTED, SnapshotCollector, check_git_status
from auditkit.snapshot.manifest import SnapshotManifest, compute_root_hash

GIT_AVAILABLE = shutil.which("git") is not None


class TestSWR017(unittest.TestCase):
    """SWR-017: 内容寻址只读快照、采集复查、漂移检出与失败处理。"""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="swr017_"))
        self.target = self.temp_dir / "target"
        self.run_dir = self.temp_dir / "run"
        self.target.mkdir()
        self.run_dir.mkdir()
        self.main_file = self.target / "main.py"
        self.main_file.write_bytes(b"print('hello')\nprint('world')\n")
        self.second_file = self.target / "second.py"
        self.second_file.write_bytes(b"value = 2\n")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _git(self, *args):
        subprocess.run(
            ["git", "-C", str(self.target), *args],
            capture_output=True, text=True, timeout=30, check=True,
        )

    def _two_phase_scanner(self, collector, mutate, after_scan=1):
        """Wrap the collector's tree scan so `mutate` runs inside the
        collection window.

        ``after_scan=1``: right after the pre-collection scan, before any
        file is copied (a structural mid-collection change).
        ``after_scan=2``: after the post-collection scan but before the
        content-hash re-verification (a same-size/same-mtime rewrite is only
        observable by the authoritative content re-check at that point).
        """
        orig_scan = collector._scan_source_tree
        calls = {"n": 0}

        def two_phase_scan():
            calls["n"] += 1
            result = orig_scan()
            if calls["n"] == after_scan:
                mutate()
            return result

        collector._scan_source_tree = two_phase_scan

    # -- dirty Git / 非 Git -------------------------------------------------

    @unittest.skipUnless(GIT_AVAILABLE, "git binary not available")
    def test_dirty_git_detected_and_refusal_blocks_snapshot(self):
        """dirty 工作区被检出；reject_dirty_git 在冻结前拒绝，无快照产出。"""
        self._git("init", "-q")
        self._git("config", "user.email", "t@example.com")
        self._git("config", "user.name", "t")
        self._git("add", "main.py")
        self._git("commit", "-q", "-m", "init")
        # Uncommitted change makes the worktree dirty.
        self.main_file.write_bytes(b"print('changed')\n")

        status = check_git_status(self.target)
        self.assertEqual(status["status"], "dirty")
        self.assertIn("details", status)

        refusing = SnapshotCollector(
            self.target, self.run_dir / "snapshot", reject_dirty_git=True
        )
        with self.assertRaises(SnapshotInconsistentError):
            refusing.collect()
        # Refusal happened before freezing anything.
        self.assertFalse((self.run_dir / "snapshot").exists())

        # Default policy records the dirty state honestly instead of guessing.
        recording = SnapshotCollector(self.target, self.run_dir / "snapshot_default")
        manifest = recording.collect()
        self.assertEqual(manifest.source_control["status"], "dirty")

    @unittest.skipUnless(GIT_AVAILABLE, "git binary not available")
    def test_clean_git_detected(self):
        """干净工作区如实记录 clean。"""
        self._git("init", "-q")
        self._git("config", "user.email", "t@example.com")
        self._git("config", "user.name", "t")
        self._git("add", ".")
        self._git("commit", "-q", "-m", "init")
        self.assertEqual(check_git_status(self.target)["status"], "clean")

    def test_non_git_target_recorded_not_guessed(self):
        """非 Git 目录如实记录 non_git；采集照常完成且清单带该元数据。"""
        self.assertEqual(check_git_status(self.target)["status"], "non_git")

        manifest = SnapshotCollector(self.target, self.run_dir / "snapshot").collect()
        self.assertEqual(manifest.source_control["status"], "non_git")
        self.assertTrue(manifest.source_control.get("reason"))

    # -- 同 mtime 同大小改写（内容摘要是权威复查） ---------------------------

    def test_same_size_same_mtime_rewrite_detected_by_content_digest(self):
        """改写后恢复 mtime/大小：元数据复查不报，内容复查必报（禁仅用 mtime）。"""
        collector = SnapshotCollector(self.target, self.run_dir / "snapshot")
        original = self.main_file.read_bytes()
        original_sha = hashlib.sha256(original).hexdigest()
        st = self.main_file.stat()

        pre_scan = collector._scan_source_tree()

        rewritten = b"print('olleh')\nprint('dlrow')\n"
        self.assertEqual(len(rewritten), len(original))
        self.main_file.write_bytes(rewritten)
        os.utime(self.main_file, (st.st_atime, st.st_mtime))

        post_scan = collector._scan_source_tree()

        # mtime/size comparison alone must stay silent (never proof of stability).
        collector._verify_drift(pre_scan, post_scan)  # must not raise
        # Content-level re-check is authoritative and must flag the rewrite.
        drift = collector._verify_content_hashes({"main.py": original_sha})
        self.assertEqual(drift, ["main.py"])

    def test_frozen_copy_keeps_original_bytes_when_drift_recorded(self):
        """record 模式：漂移如实记 gap 并置 drift_detected，冻结副本保持原内容。"""
        collector = SnapshotCollector(
            self.target, self.run_dir / "snapshot", on_drift="record"
        )
        original = self.main_file.read_bytes()
        st = self.main_file.stat()

        def mutate():
            # Same-size, same-mtime rewrite during the collection window.
            self.main_file.write_bytes(b"print('olleh')\nprint('dlrow')\n")
            os.utime(self.main_file, (st.st_atime, st.st_mtime))

        self._two_phase_scanner(collector, mutate, after_scan=2)
        manifest = collector.collect()

        self.assertTrue(manifest.drift_detected)
        drift_gaps = [g for g in manifest.gaps if g["reason"] == GAP_DRIFT_DETECTED]
        self.assertEqual([g["path"] for g in drift_gaps], ["main.py"])

        # The frozen copy holds the ORIGINAL content, not the rewritten one.
        frozen = self.run_dir / "snapshot" / "main.py"
        self.assertEqual(frozen.read_bytes(), original)
        entry = next(f for f in manifest.files if f["path"] == "main.py")
        self.assertEqual(entry["sha256"], hashlib.sha256(original).hexdigest())

    def test_raise_mode_refuses_to_continue_on_drift(self):
        """raise 模式（默认）：不能确保一致时拒绝继续，不产出快照。"""
        collector = SnapshotCollector(self.target, self.run_dir / "snapshot")
        st = self.main_file.stat()

        def mutate():
            self.main_file.write_bytes(b"print('olleh')\nprint('dlrow')\n")
            os.utime(self.main_file, (st.st_atime, st.st_mtime))

        self._two_phase_scanner(collector, mutate, after_scan=2)
        with self.assertRaises(SnapshotInconsistentError):
            collector.collect()
        self.assertFalse((self.run_dir / "snapshot").exists())

    # -- 采集中变化（拒绝继续） ---------------------------------------------

    def test_file_added_mid_collection_refuses(self):
        """新增文件发生在预扫描之后、复制完成之前 → 拒绝继续。"""
        collector = SnapshotCollector(self.target, self.run_dir / "snapshot")
        self._two_phase_scanner(
            collector, lambda: (self.target / "injected.py").write_bytes(b"late = 1\n")
        )
        with self.assertRaises(SnapshotInconsistentError):
            collector.collect()
        self.assertFalse((self.run_dir / "snapshot").exists())

    def test_file_removed_mid_collection_refuses(self):
        """删除文件发生在采集窗口内 → 拒绝继续（不产出半截快照）。"""
        collector = SnapshotCollector(self.target, self.run_dir / "snapshot")
        self._two_phase_scanner(collector, self.second_file.unlink)
        with self.assertRaises(SnapshotInconsistentError):
            collector.collect()
        self.assertFalse((self.run_dir / "snapshot").exists())

    def test_change_after_freeze_does_not_alter_frozen_content(self):
        """冻结之后源文件再变：已冻结快照与清单摘要保持不变（可复现）。"""
        manifest = SnapshotCollector(self.target, self.run_dir / "snapshot").collect()
        original_hashes = {f["path"]: f["sha256"] for f in manifest.files}
        original_root = manifest.root_hash

        # Freeze-then-mutate: the source tree changes afterwards.
        self.main_file.write_bytes(b"changed = True\n")

        frozen_manifest_path = self.run_dir / "snapshot" / "manifest.json"
        frozen = (self.run_dir / "snapshot" / "main.py").read_bytes()
        self.assertEqual(frozen, b"print('hello')\nprint('world')\n")
        self.assertEqual(original_hashes["main.py"], hashlib.sha256(frozen).hexdigest())
        # The persisted manifest is stable and re-loads with the same root.
        reloaded = SnapshotManifest.load_json(str(frozen_manifest_path))
        self.assertEqual(reloaded.root_hash, original_root)

    # -- 磁盘不足（存储失败处理） -------------------------------------------

    def test_disk_full_aborts_without_snapshot_or_temp_litter(self):
        """注入 ENOSPC 写失败：采集失败、无快照目录、无 .tmp 残留。"""
        dest = self.run_dir / "snapshot"
        temp_dest = dest.parent / f"{dest.name}.tmp"
        real_open = builtins.open

        def disk_full_open(path, mode="r", *args, **kwargs):
            path_str = str(path)
            if "w" in mode and path_str.startswith(str(temp_dest)):
                raise OSError(28, "No space left on device")
            return real_open(path, mode, *args, **kwargs)

        collector = SnapshotCollector(self.target, dest)
        with mock.patch("builtins.open", side_effect=disk_full_open):
            with self.assertRaises(OSError) as ctx:
                collector.collect()
        self.assertEqual(ctx.exception.errno, 28)

        # 阻止 ready: no snapshot destination, no half-written temp dir.
        self.assertFalse(dest.exists())
        self.assertFalse(temp_dest.exists())

    # -- 内容寻址与只读采集 --------------------------------------------------

    def test_identical_content_yields_identical_root_hash_and_snapshot_id(self):
        """相同内容 → 相同 root_hash/snapshot_id；不同内容 → 不同（内容寻址）。"""
        manifest_a = SnapshotCollector(self.target, self.run_dir / "snapshot_a").collect()
        manifest_b = SnapshotCollector(self.target, self.run_dir / "snapshot_b").collect()

        self.assertEqual(manifest_a.root_hash, manifest_b.root_hash)
        self.assertEqual(manifest_a.snapshot_id, manifest_b.snapshot_id)
        self.assertTrue(manifest_a.snapshot_id.startswith("snp-"))
        self.assertEqual(manifest_a.snapshot_id, f"snp-{manifest_a.root_hash[:12]}")

        self.second_file.write_bytes(b"value = 3\n")
        manifest_c = SnapshotCollector(self.target, self.run_dir / "snapshot_c").collect()
        self.assertNotEqual(manifest_c.root_hash, manifest_a.root_hash)

    def test_root_hash_ignores_mtime_and_absolute_paths(self):
        """清单摘要不含 mtime/绝对路径：仅内容与相对路径参与摘要。"""
        files = [
            {"path": "a.py", "file_type": "regular", "bytes": 3, "sha256": "a" * 64},
            {"path": "b.py", "file_type": "regular", "bytes": 4, "sha256": "b" * 64},
        ]
        hash_one = compute_root_hash(files)
        files[0]["line_count"] = 99  # non-participating field
        self.assertEqual(compute_root_hash(files), hash_one)
        self.assertEqual(compute_root_hash(list(reversed(files))), hash_one)

    def test_frozen_copies_match_recorded_digests(self):
        """每个冻结副本的 SHA-256 与清单记录一致（可复现快照）。"""
        manifest = SnapshotCollector(self.target, self.run_dir / "snapshot").collect()
        for f in manifest.files:
            frozen = self.run_dir / "snapshot" / f["path"]
            self.assertEqual(
                hashlib.sha256(frozen.read_bytes()).hexdigest(), f["sha256"],
                f"frozen copy digest mismatch for {f['path']}",
            )
            self.assertEqual(frozen.stat().st_size, f["bytes"])

    def test_collection_is_read_only_on_source_tree(self):
        """采集不修改源树：内容与 mtime 保持不变（目标只读）。"""
        before = {}
        for p in sorted(self.target.rglob("*")):
            st = p.stat()
            before[p] = (p.read_bytes(), st.st_mtime_ns, st.st_size)

        SnapshotCollector(self.target, self.run_dir / "snapshot").collect()

        for p, (content, mtime_ns, size) in before.items():
            st = p.stat()
            self.assertEqual(p.read_bytes(), content)
            self.assertEqual(st.st_mtime_ns, mtime_ns, f"mtime changed for {p}")
            self.assertEqual(st.st_size, size)


if __name__ == "__main__":
    unittest.main()
