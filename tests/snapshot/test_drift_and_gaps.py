"""DSR-011 / DSR-012 / DSR-013 regression tests.

Covers:
- DSR-012: content-level drift re-check (same size + same mtime rewrite MUST
  be detected; mtime alone is never trusted) and dirty Git detection.
- DSR-011: symlink safety wiring in the collector (O_NOFOLLOW + realpath
  re-verification; escaping symlinks are excluded and never read).
- DSR-013: coverage-gap records ({path, reason}) for read failures, decode
  failures, symlink exclusions and drift.
"""

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
from auditkit.snapshot.collector import (
    SnapshotCollector,
    check_git_status,
    count_lines,
)
from auditkit.snapshot.manifest import SnapshotManifest

GIT_AVAILABLE = shutil.which("git") is not None
O_NOFOLLOW_SUPPORTED = hasattr(os, "O_NOFOLLOW")


class DriftAndGapTestBase(unittest.TestCase):

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())
        self.target = self.temp_dir / "target"
        self.run_dir = self.temp_dir / "run"
        self.target.mkdir()
        self.run_dir.mkdir()
        self.main_file = self.target / "main.py"
        self.main_file.write_bytes(b"print('hello')\nprint('world')\n")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)


class TestContentLevelDrift(DriftAndGapTestBase):
    """DSR-012: same-size, same-mtime rewrites must be reproducibly detected."""

    def test_same_size_same_mtime_rewrite_detected(self):
        collector = SnapshotCollector(self.target, self.run_dir / "snapshot")

        original = self.main_file.read_bytes()
        old_sha = hashlib.sha256(original).hexdigest()
        st = self.main_file.stat()

        pre_scan = collector._scan_source_tree()

        # Rewrite with identical size and identical timestamps.
        rewritten = b"print('olleh')\nprint('dlrow')\n"
        self.assertEqual(len(rewritten), len(original))
        self.main_file.write_bytes(rewritten)
        os.utime(self.main_file, (st.st_atime, st.st_mtime))

        post_scan = collector._scan_source_tree()

        # Metadata check alone must NOT flag the rewrite (that is the bug).
        collector._verify_drift(pre_scan, post_scan)  # must not raise

        # Content-level re-check MUST flag it.
        drift = collector._verify_content_hashes({"main.py": old_sha})
        self.assertEqual(drift, ["main.py"])

    def test_collect_raises_on_silent_rewrite(self):
        collector = SnapshotCollector(self.target, self.run_dir / "snapshot")
        original = self.main_file.read_bytes()
        st = self.main_file.stat()
        orig_scan = collector._scan_source_tree
        calls = {"n": 0}

        def two_phase_scan():
            calls["n"] += 1
            result = orig_scan()
            if calls["n"] == 2:
                # Simulate a mid-collection rewrite with same size + mtime.
                self.main_file.write_bytes(b"print('olleh')\nprint('dlrow')\n")
                self.assertEqual(len(self.main_file.read_bytes()), len(original))
                os.utime(self.main_file, (st.st_atime, st.st_mtime))
            return result

        collector._scan_source_tree = two_phase_scan
        with self.assertRaises(SnapshotInconsistentError):
            collector.collect()

    def test_collect_record_mode_flags_drift_in_gaps(self):
        collector = SnapshotCollector(
            self.target, self.run_dir / "snapshot", on_drift="record"
        )
        st = self.main_file.stat()
        orig_scan = collector._scan_source_tree
        calls = {"n": 0}

        def two_phase_scan():
            calls["n"] += 1
            result = orig_scan()
            if calls["n"] == 2:
                self.main_file.write_bytes(b"print('olleh')\nprint('dlrow')\n")
                os.utime(self.main_file, (st.st_atime, st.st_mtime))
            return result

        collector._scan_source_tree = two_phase_scan
        manifest = collector.collect()

        self.assertTrue(manifest.drift_detected)
        reasons = {g["reason"] for g in manifest.gaps}
        self.assertIn("drift_detected", reasons)
        drifted = [g["path"] for g in manifest.gaps if g["reason"] == "drift_detected"]
        self.assertEqual(drifted, ["main.py"])

    def test_content_hashes_stable_when_untouched(self):
        collector = SnapshotCollector(self.target, self.run_dir / "snapshot")
        content = self.main_file.read_bytes()
        drift = collector._verify_content_hashes(
            {"main.py": hashlib.sha256(content).hexdigest()}
        )
        self.assertEqual(drift, [])

    def test_count_lines_binary_detection(self):
        # NUL bytes + invalid UTF-8 classify as binary, not latin1 text.
        self.assertEqual(count_lines(b"\x00\xff\xfe\x10binary\x00")[1], "binary")
        # Non-UTF-8 but no NUL bytes stays latin1 text.
        self.assertEqual(count_lines("caf\xe9\n".encode("latin1"))[1], "latin1")
        self.assertEqual(count_lines(b"")[1], "utf-8")


@unittest.skipUnless(GIT_AVAILABLE, "git binary not available")
class TestDirtyGitDetection(DriftAndGapTestBase):
    """DSR-012: dirty Git worktree detection; non-Git never blocks."""

    def _git(self, *args):
        subprocess.run(
            ["git", "-C", str(self.target)] + list(args),
            check=True,
            capture_output=True,
            env={**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull},
        )

    def _init_repo(self):
        self._git("init", "-q")
        self._git("config", "user.email", "audit@example.com")
        self._git("config", "user.name", "Audit Fixture")
        self._git("add", "-A")
        self._git("commit", "-q", "-m", "baseline")

    def test_clean_repo_detected(self):
        self._init_repo()
        status = check_git_status(self.target)
        self.assertEqual(status["status"], "clean")

    def test_dirty_repo_detected(self):
        self._init_repo()
        (self.target / "main.py").write_bytes(b"print('dirty')\n")
        status = check_git_status(self.target)
        self.assertEqual(status["status"], "dirty")
        self.assertIn("main.py", status.get("details", ""))

    def test_non_git_target_reported(self):
        status = check_git_status(self.target)
        self.assertEqual(status["status"], "non_git")

    def test_missing_git_binary_recorded_unknown(self):
        with mock.patch(
            "auditkit.snapshot.collector.subprocess.run",
            side_effect=FileNotFoundError("git not found"),
        ):
            status = check_git_status(self.target)
        self.assertEqual(status["status"], "unknown")

    def test_reject_dirty_git_refuses_snapshot(self):
        self._init_repo()
        (self.target / "main.py").write_bytes(b"print('dirty')\n")
        collector = SnapshotCollector(
            self.target, self.run_dir / "snapshot", reject_dirty_git=True
        )
        with self.assertRaises(SnapshotInconsistentError):
            collector.collect()
        self.assertFalse((self.run_dir / "snapshot").exists())

    def test_dirty_git_recorded_honestly_by_default(self):
        self._init_repo()
        (self.target / "main.py").write_bytes(b"print('dirty')\n")
        collector = SnapshotCollector(self.target, self.run_dir / "snapshot")
        manifest = collector.collect()
        self.assertEqual(manifest.source_control["status"], "dirty")
        persisted = SnapshotManifest.load_json(
            str(self.run_dir / "snapshot" / "manifest.json")
        )
        self.assertEqual(persisted.source_control["status"], "dirty")


class TestSymlinkSafety(DriftAndGapTestBase):
    """DSR-011: symlinks pointing outside the target are excluded, never read."""

    def test_symlink_escape_excluded_and_not_read(self):
        outside = self.temp_dir / "outside"
        outside.mkdir()
        secret = outside / "secret.txt"
        secret.write_bytes(b"TOP SECRET CONTENT\n")

        link = self.target / "link.py"
        os.symlink(str(secret), str(link))

        dest = self.run_dir / "snapshot"
        collector = SnapshotCollector(self.target, dest)
        manifest = collector.collect()

        collected_paths = [f["path"] for f in manifest.files]
        self.assertNotIn("link.py", collected_paths)
        self.assertEqual(collected_paths, ["main.py"])

        excluded = {e["path"]: e["reason"] for e in manifest.excluded}
        self.assertIn("link.py", excluded)
        self.assertIn("symlink_excluded", excluded["link.py"])

        gap_reasons = {g["path"]: g["reason"] for g in manifest.gaps}
        self.assertEqual(gap_reasons.get("link.py"), "symlink_excluded")

        # Snapshot must not contain the link nor the secret content.
        self.assertFalse((dest / "link.py").exists())
        snapshot_blob = (dest / "manifest.json").read_bytes()
        self.assertNotIn(b"TOP SECRET", snapshot_blob)

    def test_open_nofollow_rejects_symlink(self):
        if not O_NOFOLLOW_SUPPORTED:
            self.skipTest("O_NOFOLLOW not supported on this platform")
        inner = self.target / "inner.txt"
        inner.write_bytes(b"inside\n")
        link = self.target / "link.txt"
        os.symlink(str(inner), str(link))

        collector = SnapshotCollector(self.target, self.run_dir / "snapshot")
        with self.assertRaises(OSError):
            collector._read_file_nofollow(link)

    def test_read_real_file_via_nofollow(self):
        collector = SnapshotCollector(self.target, self.run_dir / "snapshot")
        content = collector._read_file_nofollow(self.main_file)
        self.assertEqual(content, b"print('hello')\nprint('world')\n")


class TestCoverageGaps(DriftAndGapTestBase):
    """DSR-013: read/decode failures recorded as explicit gaps, not silent."""

    def test_read_failure_recorded_as_gap(self):
        collector = SnapshotCollector(
            self.target, self.run_dir / "snapshot", on_drift="record"
        )

        # Patch os.open so source reads fail, while snapshot-side plain
        # open() calls (builtin, C level) keep working for the copy step.
        with mock.patch(
            "auditkit.snapshot.collector.os.open",
            side_effect=PermissionError(13, "denied"),
        ):
            manifest = collector.collect()

        self.assertNotIn(
            "main.py", [f["path"] for f in manifest.files],
            "unreadable file must not be inventoried as collected",
        )
        read_gaps = [g for g in manifest.gaps if g["reason"] == "read_failure"]
        self.assertEqual([g["path"] for g in read_gaps], ["main.py"])
        self.assertTrue(read_gaps[0].get("detail"))

    def test_binary_content_classified_with_decode_gap(self):
        blob = self.target / "blob.dat"
        blob.write_bytes(b"\x00\xff\xfe\x10BINARY\x00PAYLOAD\x00")

        dest = self.run_dir / "snapshot"
        collector = SnapshotCollector(self.target, dest)
        manifest = collector.collect()

        entry = next(f for f in manifest.files if f["path"] == "blob.dat")
        self.assertEqual(entry["encoding"], "binary")
        self.assertEqual(entry["line_count"], 0)

        decode_gaps = [g for g in manifest.gaps if g["reason"] == "decode_failure"]
        self.assertEqual([g["path"] for g in decode_gaps], ["blob.dat"])

    def test_gap_records_use_documented_reason_codes(self):
        blob = self.target / "blob.dat"
        blob.write_bytes(b"\x00binary\x00")
        link = self.target / "link.py"
        os.symlink(str(self.main_file), str(link))

        collector = SnapshotCollector(self.target, self.run_dir / "snapshot")
        manifest = collector.collect()

        allowed = {"decode_failure", "read_failure", "symlink_excluded", "drift_detected"}
        for gap in manifest.gaps:
            self.assertIn(gap["reason"], allowed)
            self.assertIn("path", gap)


if __name__ == "__main__":
    unittest.main()
