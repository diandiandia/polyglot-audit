"""100k-file scale test (DSR-049 / SWR-030).

Builds a synthetic 100,000-file tree in a tempdir (layered directories:
200 modules x 10 packages x 50 files), then measures:

- inventory walk time (file counting / listing)
- snapshot manifest construction time (content SHA-256 per file + root hash)
- tracemalloc peak memory across the manifest build

Thresholds are deliberately loose so the test can pass in CI: the whole
measured phase must finish under 120 seconds and peak traced memory must
stay under 1 GB. The measured results (hardware profile, file distribution,
timings, peak memory) are written to a JSON record under
tests/performance/records/scale_100k_last_run.json.

Resource guard: when the environment cannot host the tree (insufficient
free disk, or POLYGLOT_SKIP_SCALE=1) the test is SKIPPED — a skip is never
counted as a pass and scale capability stays `unknown`.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import tempfile
import time
import tracemalloc
import unittest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]

TOTAL_FILES = 100_000
MODULES = 200          # top-level module dirs
PACKAGES = 10          # packages per module
FILES_PER_PACKAGE = TOTAL_FILES // (MODULES * PACKAGES)  # 50

TIME_BUDGET_SECONDS = 120.0
MEMORY_BUDGET_BYTES = 1_000_000_000  # 1 GB traced peak
MIN_FREE_DISK_BYTES = 3_000_000_000  # 3 GB needed to host the tree comfortably

RECORDS_DIR = ROOT_DIR / "tests" / "performance" / "records"
RECORD_PATH = RECORDS_DIR / "scale_100k_last_run.json"


def _environment_supported() -> bool:
    if os.environ.get("POLYGLOT_SKIP_SCALE") == "1":
        return False
    try:
        # Probe free space on the filesystem that will host the tempdir.
        probe_dir = tempfile.mkdtemp(prefix="scale_probe_disk_")
        try:
            usage = shutil.disk_usage(probe_dir)
        finally:
            shutil.rmtree(probe_dir, ignore_errors=True)
        return usage.free >= MIN_FREE_DISK_BYTES
    except OSError:
        return False


_ENV_OK = _environment_supported()


def _build_tree(root: Path) -> None:
    """Create the layered synthetic tree (200 x 10 x 50 = 100,000 files)."""
    line = "value = %d\n"
    for mod in range(MODULES):
        for pkg in range(PACKAGES):
            d = root / f"module_{mod:03d}" / f"pkg_{pkg:02d}"
            d.mkdir(parents=True, exist_ok=True)
            for i in range(FILES_PER_PACKAGE):
                serial = mod * (PACKAGES * FILES_PER_PACKAGE) + pkg * FILES_PER_PACKAGE + i
                (d / f"file_{i:03d}.py").write_text(
                    f"# synthetic module {mod} pkg {pkg} file {i}\n" + line % serial,
                    encoding="utf-8",
                )


def _measure(root: Path) -> dict:
    """Inventory walk + manifest build with timing and traced peak memory."""
    timings = {}

    t0 = time.perf_counter()
    count = 0
    total_bytes = 0
    for dirpath, _dirnames, filenames in os.walk(root):
        for fname in filenames:
            count += 1
            try:
                total_bytes += os.stat(os.path.join(dirpath, fname)).st_size
            except OSError:
                pass
    timings["inventory_walk_seconds"] = round(time.perf_counter() - t0, 3)
    if count != TOTAL_FILES:
        raise AssertionError(f"tree miscount: {count} != {TOTAL_FILES}")

    tracemalloc.start()
    t0 = time.perf_counter()
    entries = []
    for dirpath, _dirnames, filenames in os.walk(root):
        rel_base = os.path.relpath(dirpath, root)
        for fname in filenames:
            full = os.path.join(dirpath, fname)
            with open(full, "rb") as f:
                data = f.read()
            relpath = fname if rel_base == "." else f"{rel_base}{os.sep}{fname}".replace(os.sep, "/")
            entries.append({
                "path": relpath,
                "file_type": "regular",
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            })
    sorted_entries = sorted(entries, key=lambda e: e["path"].encode("utf-8"))
    hasher = hashlib.sha256()
    for e in sorted_entries:
        p, t, b, s = e["path"], e["file_type"], str(e["bytes"]), e["sha256"]
        hasher.update(f"{len(p.encode('utf-8'))}:{p}:{len(t.encode('utf-8'))}:{t}:{b}:{s}\n".encode("utf-8"))
    root_hash = hasher.hexdigest()
    timings["manifest_build_seconds"] = round(time.perf_counter() - t0, 3)

    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    return {
        "timings": timings,
        "file_count": count,
        "total_bytes": total_bytes,
        "peak_traced_bytes": peak,
        "root_hash": root_hash,
    }


@unittest.skipUnless(
    _ENV_OK,
    "environment cannot host the 100k-file tree (insufficient disk or "
    "POLYGLOT_SKIP_SCALE=1); scale capability remains unknown, not failed",
)
class TestScale100k(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.mkdtemp(prefix="scale_100k_")
        cls.root = Path(cls._tmp) / "tree"
        build_start = time.perf_counter()
        _build_tree(cls.root)
        cls.build_seconds = round(time.perf_counter() - build_start, 3)
        cls.results = _measure(cls.root)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls._tmp, ignore_errors=True)

    def _record(self, status: str) -> dict:
        usage = shutil.disk_usage(self._tmp)
        record = {
            "schema_version": "1.0",
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "status": status,
            "hardware": {
                "cpu_count": os.cpu_count(),
                "platform": platform.platform(),
                "python_version": platform.python_version(),
                "tmp_free_bytes": usage.free,
            },
            "file_distribution": {
                "modules": MODULES,
                "packages_per_module": PACKAGES,
                "files_per_package": FILES_PER_PACKAGE,
                "total_files": TOTAL_FILES,
            },
            "tree_build_seconds": self.build_seconds,
            "timings": self.results["timings"],
            "total_measured_seconds": round(
                self.results["timings"]["inventory_walk_seconds"]
                + self.results["timings"]["manifest_build_seconds"], 3),
            "total_bytes": self.results["total_bytes"],
            "peak_traced_bytes": self.results["peak_traced_bytes"],
            "root_hash": self.results["root_hash"],
            "thresholds": {
                "time_budget_seconds": TIME_BUDGET_SECONDS,
                "memory_budget_bytes": MEMORY_BUDGET_BYTES,
            },
        }
        if status == "unknown":
            record["note"] = (
                "skipped run; scale capability unknown — thresholds are "
                "unverified in this environment"
            )
        try:
            RECORDS_DIR.mkdir(parents=True, exist_ok=True)
            RECORD_PATH.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        except OSError:
            pass  # record writing is best-effort; never masks test outcome
        return record

    def test_inventory_and_manifest_within_budgets(self):
        total = (self.results["timings"]["inventory_walk_seconds"]
                 + self.results["timings"]["manifest_build_seconds"])
        record = self._record("measured")

        self.assertEqual(record["file_distribution"]["total_files"], TOTAL_FILES)
        self.assertLess(
            total, TIME_BUDGET_SECONDS,
            f"scale phase took {total:.1f}s (budget {TIME_BUDGET_SECONDS}s)",
        )
        self.assertLess(
            record["peak_traced_bytes"], MEMORY_BUDGET_BYTES,
            f"peak traced memory {record['peak_traced_bytes']} exceeds budget",
        )
        self.assertEqual(len(record["root_hash"]), 64)

    def test_record_written(self):
        self._record("measured")
        self.assertTrue(RECORD_PATH.is_file(), f"missing measurement record: {RECORD_PATH}")
        data = json.loads(RECORD_PATH.read_text(encoding="utf-8"))
        for key in ("hardware", "file_distribution", "timings", "peak_traced_bytes", "thresholds"):
            self.assertIn(key, data)


class TestScale100kUnknownMarking(unittest.TestCase):
    """When the scale run cannot execute, the outcome must be marked unknown."""

    def test_unsupported_environment_records_unknown(self):
        if _ENV_OK:
            self.skipTest("environment supports the scale run; measured elsewhere")
        RECORDS_DIR.mkdir(parents=True, exist_ok=True)
        RECORD_PATH.write_text(json.dumps({
            "schema_version": "1.0",
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "status": "unknown",
            "reason": "environment cannot host the 100k-file tree; scale capability unverified",
            "hardware": {"cpu_count": os.cpu_count(), "platform": platform.platform()},
        }, indent=2) + "\n", encoding="utf-8")
        data = json.loads(RECORD_PATH.read_text(encoding="utf-8"))
        self.assertEqual(data["status"], "unknown")


if __name__ == "__main__":
    unittest.main()
