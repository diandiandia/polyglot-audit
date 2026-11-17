"""DSR-014 / DSR-054 regression tests.

Covers:
- DSR-014: inventory reconciliation counts (included / excluded /
  unknown_language / by_language / by_component) over a mixed fixture, with
  the three-way sum invariant known + excluded + unknown == total.
- DSR-054: inclusion summary bucketed into included / unknown_extension
  (inventoried but unknown language) plus exclusion categories
  (directory_rule / generated / test / binary / archive / user_rule /
  symlink / other).
"""

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

SKILL_SCRIPTS = Path(__file__).resolve().parents[2] / "skill" / "scripts"
if str(SKILL_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SKILL_SCRIPTS))

from auditkit.contracts.errors import InvalidInputError
from auditkit.inventory.languages import detect_language
from auditkit.inventory.reconcile import reconcile
from auditkit.inventory.rules import ExclusionRules, inclusion_summary
from auditkit.snapshot.collector import SnapshotCollector

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures"
MIXED_LANG_DIR = FIXTURES_DIR / "mixed_lang"



def _purge_fixture_pycache():
    """Remove bytecode caches under the fixture source before scanning.

    Test collectors (pytest / IDEs) may compile ``tests/fixtures/**`` in
    place; the resulting ``__pycache__`` files would otherwise shift the
    inventory denominators (DSR-014/054) depending on collection order.
    """
    for cache_dir in MIXED_LANG_DIR.rglob("__pycache__"):
        shutil.rmtree(cache_dir, ignore_errors=True)


class TestInventoryReconcile(unittest.TestCase):
    """DSR-014: mixed included/excluded/unknown-language reconciliation."""

    @classmethod
    def setUpClass(cls):
        _purge_fixture_pycache()
        cls.temp_dir = Path(tempfile.mkdtemp())
        cls.dest = cls.temp_dir / "snapshot"
        rules = ExclusionRules()
        collector = SnapshotCollector(
            MIXED_LANG_DIR,
            cls.dest,
            is_excluded_fn=rules.evaluate,
            language_detector_fn=lambda p, b: (detect_language(p, b), "default"),
        )
        cls.manifest = collector.collect()
        cls.discovered_total = sum(
            1 for p in MIXED_LANG_DIR.rglob("*") if p.is_file()
        )

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def test_three_way_reconciliation_balances(self):
        summary = reconcile(self.manifest, discovered_total=self.discovered_total)

        self.assertTrue(summary["reconciled"])
        self.assertEqual(summary["total_files"], self.discovered_total)
        self.assertEqual(summary["included"] + summary["excluded"], self.discovered_total)
        self.assertEqual(
            summary["known_language"] + summary["excluded"] + summary["unknown_language"],
            summary["total_files"],
        )
        self.assertEqual(summary["included_plus_excluded_plus_unknown"], self.discovered_total)

    def test_unknown_language_counted_separately(self):
        summary = reconcile(self.manifest, discovered_total=self.discovered_total)
        # config.xyz and readme.rst are inventoried with unknown language.
        self.assertEqual(summary["unknown_language"], 2)
        self.assertIn("unknown", summary["by_language"])
        self.assertEqual(summary["by_language"]["unknown"], 2)
        self.assertEqual(summary["known_language"], summary["included"] - 2)

    def test_by_language_and_component_aggregates(self):
        summary = reconcile(self.manifest, discovered_total=self.discovered_total)
        self.assertEqual(summary["by_language"]["python"], 1)
        self.assertEqual(summary["by_language"]["go"], 1)
        self.assertEqual(
            summary["by_language"], dict(sorted(summary["by_language"].items()))
        )
        self.assertEqual(
            sum(summary["by_component"].values()), summary["included"]
        )

    def test_strict_reconcile_raises_on_impossible_total(self):
        with self.assertRaises(InvalidInputError):
            reconcile(self.manifest, discovered_total=self.discovered_total + 5, strict=True)

    def test_reconcile_reports_gap_when_files_escape_counts(self):
        # A file that is neither included nor excluded (e.g. read failure)
        # makes the discovered total unreconcilable — surfaced, not hidden.
        summary = reconcile(self.manifest, discovered_total=self.discovered_total + 1)
        self.assertFalse(summary["reconciled"])

    def test_derived_total_when_discovered_total_omitted(self):
        summary = reconcile(self.manifest)
        self.assertTrue(summary["reconciled"])
        self.assertEqual(summary["total_files"], summary["included"] + summary["excluded"])


class TestInclusionSummary(unittest.TestCase):
    """DSR-054: exclusion categories counted, excluded never counted as coverage."""

    @classmethod
    def setUpClass(cls):
        _purge_fixture_pycache()
        cls.temp_dir = Path(tempfile.mkdtemp())
        cls.dest = cls.temp_dir / "snapshot"
        rules = ExclusionRules()
        collector = SnapshotCollector(
            MIXED_LANG_DIR,
            cls.dest,
            is_excluded_fn=rules.evaluate,
            language_detector_fn=lambda p, b: (detect_language(p, b), "default"),
        )
        cls.manifest = collector.collect()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def test_categories_are_counted(self):
        summary = inclusion_summary(self.manifest)

        # Included: main.py + util.go with known languages.
        self.assertEqual(summary["included"], 2)
        # Unknown extensions inventoried: config.xyz + readme.rst.
        self.assertEqual(summary["unknown_extension"], 2)
        # Exclusions: vendor (generated), tests (test), logo.png (binary),
        # bundle.zip (archive).
        self.assertEqual(summary["generated"], 1)
        self.assertEqual(summary["test"], 1)
        self.assertEqual(summary["binary"], 1)
        self.assertEqual(summary["archive"], 1)
        self.assertEqual(summary["excluded_total"], 4)

    def test_excluded_never_counted_as_included(self):
        summary = inclusion_summary(self.manifest)
        self.assertNotIn("dep.js", [f["path"] for f in self.manifest.files])
        self.assertNotIn("test_main.py", [f["path"] for f in self.manifest.files])
        self.assertEqual(
            summary["included"] + summary["unknown_extension"] + summary["excluded_total"],
            self.discovered_count(),
        )

    def discovered_count(self):
        return sum(1 for p in MIXED_LANG_DIR.rglob("*") if p.is_file())

    def test_directory_rule_vs_generated_split(self):
        summary = inclusion_summary(self.manifest)
        # vendor is a generated-output dir; .git/.idea style dirs would be
        # directory_rule. In this fixture only generated appears.
        self.assertGreaterEqual(summary["generated"], 1)
        # Every excluded file lands in exactly one category.
        categorized = (
            summary["directory_rule"]
            + summary["generated"]
            + summary["test"]
            + summary["binary"]
            + summary["archive"]
            + summary["user_rule"]
            + summary["symlink"]
            + summary["other"]
        )
        self.assertEqual(categorized, summary["excluded_total"])


if __name__ == "__main__":
    unittest.main()
