"""DSR-015 / DSR-055 / DSR-056 / DSR-057 regression tests.

Covers:
- DSR-015: signal hit ordering (line asc, strength desc); slicer interval
  planning for empty/CRLF/large no-signal files; cross-chunk coverage with
  overlap; merged-interval union counts without double counting.
- DSR-055: tightened boundary matching (exact basename or stem + extension
  family), os.system/popen script-call patterns, unmatched declarations left
  as explicit gaps.
- DSR-056: profile strategies quick/standard/deep with tier + disposition
  fields and deterministic output.
- DSR-057: per-language signals.json loading, hit-cap counting and scan
  error (read failure) counting.
"""

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

SKILL_SCRIPTS = Path(__file__).resolve().parents[2] / "skill" / "scripts"
if str(SKILL_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SKILL_SCRIPTS))

from auditkit.inventory.boundaries import BoundaryScanner
from auditkit.inventory.signals import (
    SignalScanner,
    load_language_signals,
    scan_snapshot_files,
)
from auditkit.inventory.slicer import UnitPlanner, slice_file_ranges

REPO_ROOT = Path(__file__).resolve().parents[2]
SKILL_DIR = REPO_ROOT / "skill"


def merged_interval_size(ranges):
    """Total number of distinct lines covered by a set of 1-based intervals."""
    merged = []
    for start, end in sorted(ranges):
        if merged and start <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return sum(end - start + 1 for start, end in merged)


class TestSignalOrdering(unittest.TestCase):
    """DSR-015: deterministic (line, strength desc) hit ordering."""

    def test_hits_sorted_by_line_then_strength_desc(self):
        scanner = SignalScanner()
        # Line 1: source(3) then source(2); line 2: sink(3); line 3: weak.
        lines = [
            "data = request.form  # os.environ",
            "eval(user_input)",
            "open('f')",
        ]
        hits, overflow = scanner.scan_file("a.py", lines, max_hits=200)

        self.assertIsNone(overflow)
        self.assertEqual([h["line"] for h in hits], sorted(h["line"] for h in hits))
        for i in range(1, len(hits)):
            prev, cur = hits[i - 1], hits[i]
            if prev["line"] == cur["line"]:
                self.assertGreaterEqual(prev["strength"], cur["strength"])
        # Line 1 strongest first
        line1 = [h for h in hits if h["line"] == 1]
        self.assertEqual(line1[0]["signal_id"], "src_http_input")
        self.assertEqual(line1[1]["signal_id"], "src_cli_env")

    def test_hit_cap_overflow_counted(self):
        scanner = SignalScanner()
        lines = ["eval(x)"] * 50
        hits, overflow = scanner.scan_file("a.py", lines, max_hits=5)
        self.assertEqual(len(hits), 5)
        self.assertIsNotNone(overflow)
        self.assertEqual(
            scanner.language_hit_cap_counts.get("unknown"), 1
        )


class TestSlicer(unittest.TestCase):
    """DSR-015: interval planning and union guarantees."""

    def test_empty_file_yields_no_ranges(self):
        self.assertEqual(slice_file_ranges(0), [])
        self.assertEqual(slice_file_ranges(-3), [])

    def test_crlf_and_small_files_single_window(self):
        self.assertEqual(slice_file_ranges(1), [(1, 1)])
        self.assertEqual(slice_file_ranges(400), [(1, 400)])

    def test_large_no_signal_file_still_produces_windows(self):
        ranges = slice_file_ranges(1000, chunk_size=400, overlap=30)
        self.assertTrue(ranges)
        # Ordered ascending, file-order chunks.
        self.assertEqual(
            [r[0] for r in ranges], sorted(r[0] for r in ranges)
        )
        # Union covers 1..1000 exactly (overlap merged away).
        self.assertEqual(merged_interval_size(ranges), 1000)
        self.assertEqual(min(r[0] for r in ranges), 1)
        self.assertEqual(max(r[1] for r in ranges), 1000)
        # Overlap actually exists between consecutive windows.
        for prev, cur in zip(ranges, ranges[1:]):
            self.assertGreater(prev[1], cur[0] - 1)  # prev end >= cur start

    def test_cross_chunk_symbol_covered_by_overlap(self):
        # A "symbol" at line 400/401 boundary must be covered by at least
        # one window fully, and the boundary lines by at least two windows.
        ranges = slice_file_ranges(1000, chunk_size=400, overlap=30)
        for line in (399, 400, 401):
            self.assertTrue(any(s <= line <= e for s, e in ranges), msg=f"line {line} uncovered")

    def test_overlapping_window_union_not_double_counted(self):
        # Two deliberately overlapping groups of windows on the same file.
        group_a = slice_file_ranges(1000, chunk_size=400, overlap=30)
        group_b = slice_file_ranges(1000, chunk_size=500, overlap=50)
        union = group_a + group_b
        self.assertEqual(merged_interval_size(union), 1000)

    def test_planner_deterministic_for_same_inputs(self):
        files = [
            {"path": "b.py", "sha256": "f" * 64, "line_count": 10,
             "language": "python", "component": "app"},
            {"path": "a.py", "sha256": "e" * 64, "line_count": 10,
             "language": "python", "component": "app"},
        ]
        signals = {
            "a.py": [{"kind": "sink", "strength": 3, "line": 1}],
            "b.py": [],
        }
        planner = UnitPlanner("snp-x", profile="deep")
        u1 = planner.create_units(files, signals, [])
        u2 = planner.create_units(list(reversed(files)), signals, [])
        self.assertEqual([u["unit_id"] for u in u1], [u["unit_id"] for u in u2])
        self.assertEqual(u1, u2)


class TestProfiles(unittest.TestCase):
    """DSR-056: quick/standard/deep planning strategies with dispositions."""

    def setUp(self):
        self.files = [
            {"path": "t1.py", "sha256": "1" * 64, "line_count": 5,
             "language": "python", "component": "app"},
            {"path": "t2.py", "sha256": "2" * 64, "line_count": 5,
             "language": "python", "component": "app"},
            {"path": "t3.py", "sha256": "3" * 64, "line_count": 5,
             "language": "python", "component": "app"},
            {"path": "t4.py", "sha256": "4" * 64, "line_count": 5,
             "language": "python", "component": "app"},
        ]
        self.signals = {
            # T1: source + sink
            "t1.py": [
                {"kind": "source", "strength": 3, "line": 1},
                {"kind": "sink", "strength": 3, "line": 2},
            ],
            # T2: sink only
            "t2.py": [{"kind": "sink", "strength": 3, "line": 1}],
            # T3: guard only
            "t3.py": [{"kind": "guard", "strength": 2, "line": 1}],
            # T4: no signals
            "t4.py": [],
        }

    def _paths_by_disposition(self, units):
        out = {}
        for u in units:
            self.assertIn(u["tier"], ("T1", "T2", "T3", "T4"))
            self.assertIn(u["disposition"], ("analyze", "triage_only", "inventory_only"))
            out.setdefault(u["disposition"], set()).add(u["ranges"][0]["path"])
        return out

    def test_quick_profile_covers_t1_and_t2(self):
        units = UnitPlanner("snp-x", profile="quick").create_units(
            self.files, self.signals, []
        )
        buckets = self._paths_by_disposition(units)
        self.assertEqual(buckets.get("analyze"), {"t1.py", "t2.py"})
        self.assertNotIn("triage_only", buckets)
        self.assertNotIn("inventory_only", buckets)

    def test_standard_profile_keeps_t3_triage_only(self):
        units = UnitPlanner("snp-x", profile="standard").create_units(
            self.files, self.signals, []
        )
        buckets = self._paths_by_disposition(units)
        self.assertEqual(buckets.get("analyze"), {"t1.py", "t2.py"})
        self.assertEqual(buckets.get("triage_only"), {"t3.py"})
        self.assertNotIn("inventory_only", buckets)

    def test_deep_profile_includes_t4_inventory_only(self):
        units = UnitPlanner("snp-x", profile="deep").create_units(
            self.files, self.signals, []
        )
        buckets = self._paths_by_disposition(units)
        self.assertEqual(buckets.get("inventory_only"), {"t4.py"})
        self.assertEqual(buckets.get("triage_only"), {"t3.py"})
        self.assertEqual(buckets.get("analyze"), {"t1.py", "t2.py"})

    def test_profile_output_deterministic(self):
        planner = UnitPlanner("snp-x", profile="deep")
        u1 = planner.create_units(self.files, self.signals, [])
        u2 = planner.create_units(self.files, self.signals, [])
        self.assertEqual(u1, u2)

    def test_unknown_profile_rejected(self):
        with self.assertRaises(ValueError):
            UnitPlanner("snp-x", profile="yolo")


class TestBoundaryMatching(unittest.TestCase):
    """DSR-055: strict matching, script calls, unmatched declarations stay gaps."""

    def setUp(self):
        self.scanner = BoundaryScanner()

    def test_ffi_exact_basename_match(self):
        lines = ['lib = ctypes.CDLL("./libnative.so")']
        bounds = self.scanner.scan_file("caller.py", lines, "python")
        self.assertEqual(bounds[0]["boundary_type"], "ctypes_ffi")
        self.assertEqual(bounds[0]["target_ref"], "./libnative.so")

        matched = self.scanner.match_boundaries(
            bounds, ["caller.py", "native/libnative.so"]
        )
        self.assertFalse(matched[0]["is_gap"])
        self.assertEqual(matched[0]["matched_implementation"], "native/libnative.so")

    def test_declaration_matched_via_stem_and_extension_family(self):
        lines = ["#include <util.h>"]
        bounds = self.scanner.scan_file("main.c", lines, "c")
        self.assertEqual(bounds[0]["target_ref"], "util")  # header extension stripped by pattern

        # Only the implementation side exists; stem matches, .c/.h family.
        matched = self.scanner.match_boundaries(bounds, ["src/util.c"])
        self.assertFalse(matched[0]["is_gap"])
        self.assertEqual(matched[0]["matched_implementation"], "src/util.c")

    def test_substring_false_positive_eliminated(self):
        # Old substring logic matched "libnative.so" inside "libnative.so.old";
        # strict matching must leave this an explicit gap.
        lines = ['lib = ctypes.CDLL("./libnative.so")']
        bounds = self.scanner.scan_file("caller.py", lines, "python")
        matched = self.scanner.match_boundaries(bounds, ["libs/libnative.so.old"])
        self.assertTrue(matched[0]["is_gap"])
        self.assertIsNone(matched[0]["matched_implementation"])

    def test_script_call_patterns_os_system_and_popen(self):
        lines = [
            'os.system("shutdown -r now")',
            'popen("netstat -an")',
            'subprocess.run(["ls", "-la"])',
        ]
        bounds = self.scanner.scan_file("ops.py", lines, "python")
        types = {b["boundary_type"] for b in bounds}
        self.assertIn("os_system_call", types)
        self.assertIn("popen_call", types)
        self.assertIn("subprocess_call", types)
        # References extracted from the literal command.
        by_type = {b["boundary_type"]: b for b in bounds}
        self.assertEqual(by_type["os_system_call"]["target_ref"], "shutdown -r now")
        self.assertEqual(by_type["popen_call"]["target_ref"], "netstat -an")

    def test_unmatched_declaration_remains_gap(self):
        lines = ["#include <missing_impl.h>"]
        bounds = self.scanner.scan_file("main.c", lines, "c")
        matched = self.scanner.match_boundaries(bounds, ["main.c", "unrelated.py"])
        self.assertTrue(matched[0]["is_gap"])
        self.assertIsNone(matched[0]["matched_implementation"])


class TestPerLanguageSignals(unittest.TestCase):
    """DSR-057: per-language signals.json loading and honest error counts."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())
        self.knowledge_dir = self.temp_dir / "knowledge"

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _write_lang_signals(self, language, entries):
        lang_dir = self.knowledge_dir / "languages" / language
        lang_dir.mkdir(parents=True, exist_ok=True)
        with open(lang_dir / "signals.json", "w", encoding="utf-8") as f:
            json.dump(entries, f)

    def test_load_language_signals(self):
        self._write_lang_signals("python", [
            {
                "pattern_id": "sig_py_test",
                "pattern": "dangerous_api\\(",
                "kind": "sink",
                "strength": 3,
            }
        ])
        raw = load_language_signals(self.knowledge_dir, "python")
        self.assertEqual(len(raw), 1)
        self.assertEqual(raw[0][0], "sig_py_test")

    def test_per_language_signals_merged_into_scan(self):
        self._write_lang_signals("python", [
            {"pattern_id": "sig_py_test", "pattern": "dangerous_api\\(",
             "kind": "sink", "strength": 3}
        ])
        scanner = SignalScanner(knowledge_dir=self.knowledge_dir)

        py_hits, _ = scanner.scan_file(
            "a.py", ["value = dangerous_api(input)"], language="python"
        )
        self.assertEqual([h["signal_id"] for h in py_hits], ["sig_py_test"])

        # Same line under another language must not use python signals.
        go_hits, _ = scanner.scan_file(
            "a.go", ["value = dangerous_api(input)"], language="go"
        )
        self.assertEqual(go_hits, [])

    def test_real_skill_knowledge_python_signals_loaded(self):
        scanner = SignalScanner(knowledge_dir=SKILL_DIR / "knowledge")
        hits, _ = scanner.scan_file(
            "app.py", ["data = pickle.loads(untrusted_payload)"], language="python"
        )
        self.assertIn("sig_py_01", [h["signal_id"] for h in hits])

    def test_missing_language_signals_is_empty(self):
        self.assertEqual(load_language_signals(self.knowledge_dir, "rust"), [])

    def test_malformed_language_signals_counted_as_load_error(self):
        lang_dir = self.knowledge_dir / "languages" / "go"
        lang_dir.mkdir(parents=True)
        (lang_dir / "signals.json").write_text("{not json", encoding="utf-8")

        scanner = SignalScanner(knowledge_dir=self.knowledge_dir)
        hits, _ = scanner.scan_file("x.go", ["eval(x)"], language="go")
        self.assertIn("go", scanner.language_load_errors)
        # Common rules still applied despite the language load failure.
        self.assertTrue(hits)

    def test_scan_snapshot_files_counts_scan_errors_as_gaps(self):
        real = self.temp_dir / "a.py"
        real.write_text("eval(x)\n", encoding="utf-8")
        files = [
            {"path": "a.py", "language": "python"},
            {"path": "gone.py", "language": "python"},
        ]
        scanner = SignalScanner()
        result = scan_snapshot_files(scanner, files, self.temp_dir)

        self.assertEqual(result["scan_error_count"], 1)
        self.assertEqual(result["gaps"][0]["reason"], "read_failure")
        self.assertEqual(result["gaps"][0]["path"], "gone.py")
        self.assertEqual(result["file_signals"]["gone.py"], [])
        self.assertTrue(result["file_signals"]["a.py"])

    def test_scan_snapshot_files_counts_overflow(self):
        big = self.temp_dir / "big.py"
        big.write_text("eval(x)\n" * 50, encoding="utf-8")
        files = [{"path": "big.py", "language": "python"}]
        result = scan_snapshot_files(
            SignalScanner(), files, self.temp_dir, max_hits=10
        )
        self.assertEqual(result["overflow_count"], 1)
        self.assertEqual(len(result["file_signals"]["big.py"]), 10)


if __name__ == "__main__":
    unittest.main()
