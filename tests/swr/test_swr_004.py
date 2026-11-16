"""SWR-004 acceptance tests (逐编号验收测试).

验收原文 (docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2):
    | SWR-004 | SR-004 → SD-03 | P1／SWR-017 |
    实现流式清点、纳入/排除、语言/组件和信号排序；
    以固定快照测试分母对账、未知语言和无命中路径。

验收要点（本文件逐条对应）:
- 同一固定快照上：纳入 / 排除 / 未知语言三路对账，分母精确重建；
- 未知语言单列计数（by_language["unknown"]），仍计入纳入分母并可采用
  通用（common）信号方法扫描；
- 无信号不等于安全：无命中文件保持审读资格（保持清点、保留计划单元、
  风险措辞不出现"安全"结论），信号按（行升序、强度降序）排序；
- 语言/组件聚合反映真实构建组件（web/ 由 package.json 标记，顶层为
  default），排除条目带原因并可归类。
"""

from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

SKILL_SCRIPTS = Path(__file__).resolve().parents[2] / "skill" / "scripts"
if str(SKILL_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SKILL_SCRIPTS))

from auditkit.inventory.components import detect_components
from auditkit.inventory.languages import detect_language
from auditkit.inventory.reconcile import reconcile
from auditkit.inventory.rules import ExclusionRules, classify_exclusion_reason, inclusion_summary
from auditkit.inventory.signals import SignalScanner
from auditkit.inventory.slicer import UnitPlanner, calculate_risk_tier
from auditkit.snapshot.collector import SnapshotCollector

# Expected counts for the deterministic fixture below (kept in one place so
# the reconciliation assertions read against an independently derived total).
EXPECTED_DISCOVERED_TOTAL = 10   # every regular file in the fixed target tree
EXPECTED_INCLUDED = 6            # inventoried: 3 known-language + 3 unknown
EXPECTED_KNOWN = 3               # app.py, web/main.py (python), web/helper.go (go)
EXPECTED_UNKNOWN = 3             # web/config.xyz, notes.rst, web/package.json
EXPECTED_EXCLUDED = 4            # vendor/dep.js, tests/test_app.py, logo.png, bundle.zip


def _build_fixed_target(root: Path) -> None:
    """Deterministic fixed snapshot source: known + excluded + unknown mix."""
    (root / "app.py").write_text(
        "import os\n"
        "os.system(os.environ.get('CMD'))\n",
        encoding="utf-8",
    )
    # web/ is a build component marked by package.json.
    (root / "web").mkdir(parents=True)
    (root / "web" / "package.json").write_text('{"name": "web"}\n', encoding="utf-8")
    (root / "web" / "main.py").write_text(
        "import os\n"
        "cmd = os.environ.get('CMD')\n"
        "os.system(cmd)\n",
        encoding="utf-8",
    )
    (root / "web" / "helper.go").write_text(
        "package web\n"
        "func helper() string { return \"ok\" }\n",
        encoding="utf-8",
    )
    # Unknown-language file inside the component: inventoried, listed
    # separately, and deliberately carrying a generic (language-independent)
    # source signal so common-rule scanning is observable.
    (root / "web" / "config.xyz").write_text(
        "value = os.environ.get('X')\n",
        encoding="utf-8",
    )
    (root / "notes.rst").write_text("title\n=====\n", encoding="utf-8")
    # Excluded: vendor dependency (generated), tests dir, binary, archive.
    (root / "vendor").mkdir()
    (root / "vendor" / "dep.js").write_text("module.exports = 1;\n", encoding="utf-8")
    (root / "tests").mkdir()
    (root / "tests" / "test_app.py").write_text(
        "def test_x():\n    assert True\n", encoding="utf-8"
    )
    (root / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\nnot-really")
    (root / "bundle.zip").write_bytes(b"PK\x03\x04placeholder")


class TestSWR004(unittest.TestCase):
    """SWR-004: 固定快照上的分母对账、未知语言单列、无命中路径与信号排序。"""

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = Path(tempfile.mkdtemp(prefix="swr004_"))
        cls.target = cls.temp_dir / "target"
        cls.target.mkdir(parents=True)
        _build_fixed_target(cls.target)
        rules = ExclusionRules()
        collector = SnapshotCollector(
            cls.target,
            cls.temp_dir / "snapshot",
            is_excluded_fn=rules.evaluate,
            language_detector_fn=lambda p, b: (detect_language(p, b), "default"),
        )
        cls.manifest = collector.collect()
        # Discovered total is computed independently of auditkit, from the
        # fixed source tree itself (this is the denominator to reconcile).
        cls.discovered_total = sum(1 for p in cls.target.rglob("*") if p.is_file())
        cls.snapshot_root = cls.temp_dir / "snapshot"
        cls.scanner = SignalScanner()
        cls.file_signals = {}
        for f in cls.manifest.files:
            src = cls.snapshot_root / f["path"]
            lines = src.read_text(encoding="utf-8", errors="replace").splitlines()
            hits, _overflow = cls.scanner.scan_file(f["path"], lines, language=f.get("language"))
            cls.file_signals[f["path"]] = hits

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.temp_dir, ignore_errors=True)

    # -- 固定快照本身的确定性（对账前提） -----------------------------------

    def test_fixed_snapshot_has_expected_shape(self):
        """The fixed snapshot itself is deterministic: known/unknown/excluded mix."""
        self.assertEqual(self.discovered_total, EXPECTED_DISCOVERED_TOTAL)
        self.assertEqual(len(self.manifest.files), EXPECTED_INCLUDED)
        self.assertEqual(len(self.manifest.excluded), EXPECTED_EXCLUDED)

    # -- 分母对账 -----------------------------------------------------------

    def test_three_way_denominator_reconciles_on_fixed_snapshot(self):
        """纳入 + 排除 + 未知语言三路求和精确重建发现总数（无静默双计）。"""
        summary = reconcile(self.manifest, discovered_total=self.discovered_total)

        self.assertTrue(summary["reconciled"])
        self.assertEqual(summary["total_files"], self.discovered_total)
        self.assertEqual(
            summary["known_language"] + summary["excluded"] + summary["unknown_language"],
            summary["total_files"],
        )
        self.assertEqual(summary["included"], len(self.manifest.files))
        self.assertEqual(summary["excluded"], len(self.manifest.excluded))
        self.assertEqual(summary["known_language"], EXPECTED_KNOWN)
        self.assertEqual(summary["unknown_language"], EXPECTED_UNKNOWN)
        self.assertEqual(
            summary["included_plus_excluded_plus_unknown"], self.discovered_total
        )

    def test_by_language_aggregate_equals_included(self):
        """by_language 分解之和 == 纳入数；无跨桶重复计数。"""
        summary = reconcile(self.manifest)
        self.assertEqual(sum(summary["by_language"].values()), summary["included"])
        self.assertEqual(summary["by_language"].get("python"), 2)
        self.assertEqual(summary["by_language"].get("go"), 1)

    def test_excluded_files_carry_reason_and_leave_review_denominator(self):
        """每个排除条目带原因且归类完整；被排除文件不进入审读分母。"""
        self.assertGreater(len(self.manifest.excluded), 0)
        included_paths = {f["path"] for f in self.manifest.files}
        for entry in self.manifest.excluded:
            self.assertTrue(entry.get("reason"), f"excluded entry without reason: {entry}")
            self.assertNotIn(entry["path"], included_paths)
        summary = inclusion_summary(self.manifest)
        categorized = sum(
            summary[k]
            for k in (
                "directory_rule", "generated", "test", "binary",
                "archive", "user_rule", "symlink", "other",
            )
        )
        self.assertEqual(categorized, summary["excluded_total"])
        # The four deliberately excluded fixture files are all accounted for.
        self.assertEqual(summary["excluded_total"], EXPECTED_EXCLUDED)
        reasons = {e["path"]: e["reason"] for e in self.manifest.excluded}
        self.assertEqual(classify_exclusion_reason(reasons["vendor/dep.js"]), "generated")
        self.assertEqual(classify_exclusion_reason(reasons["tests/test_app.py"]), "test")
        self.assertEqual(classify_exclusion_reason(reasons["logo.png"]), "binary")
        self.assertEqual(classify_exclusion_reason(reasons["bundle.zip"]), "archive")

    # -- 未知语言单列且可采用通用方法 ---------------------------------------

    def test_unknown_language_listed_separately_and_still_inventoried(self):
        """未知语言单列（by_language["unknown"]），仍计入纳入分母。"""
        summary = reconcile(self.manifest, discovered_total=self.discovered_total)

        self.assertEqual(summary["unknown_language"], EXPECTED_UNKNOWN)
        self.assertEqual(summary["by_language"].get("unknown"), EXPECTED_UNKNOWN)
        self.assertEqual(summary["known_language"], summary["included"] - EXPECTED_UNKNOWN)
        included_paths = {f["path"] for f in self.manifest.files}
        self.assertIn("web/config.xyz", included_paths)
        self.assertIn("notes.rst", included_paths)
        # Unknown-language files are NOT counted as excluded.
        excluded_paths = {e["path"] for e in self.manifest.excluded}
        self.assertNotIn("web/config.xyz", excluded_paths)
        self.assertNotIn("notes.rst", excluded_paths)

    def test_unknown_language_scannable_with_generic_common_rules(self):
        """未知语言文件可采用通用（common）信号方法扫描，不因语言缺失被丢弃。"""
        hits = self.file_signals["web/config.xyz"]
        self.assertEqual(
            self.scanner.language_load_errors, {},
            "unknown language must fall back to common rules, not record a load error",
        )
        # Generic method applies: an env-var source signal is found by the
        # COMMON_SIGNALS set even though the extension is unknown.
        self.assertIn("src_cli_env", {h["signal_id"] for h in hits})
        self.assertEqual(hits[0]["line"], 1, "hits carry 1-based line anchors")
        self.assertEqual(hits[0]["kind"], "source")

    # -- 无信号不等于安全（无命中路径） -------------------------------------

    def test_no_signal_file_keeps_inventory_and_review_eligibility(self):
        """无命中文件：tier T4、保留在清单内、deep 计划仍生成单元（审读资格保留）。"""
        # web/helper.go has no security signals in the fixed snapshot.
        hits = self.file_signals["web/helper.go"]
        self.assertEqual(hits, [])
        tier, factors = calculate_risk_tier(hits, has_boundary=False)
        self.assertEqual(tier, "T4")
        self.assertTrue(any("No security signals" in f for f in factors))
        # "No signal" must never be worded as a safety conclusion.
        for f in factors:
            self.assertNotIn("safe", f.lower())

        planner = UnitPlanner("snp-swr004", profile="deep")
        units = planner.create_units(self.manifest.files, self.file_signals, boundaries=[])
        t4_units = [u for u in units if u["tier"] == "T4"]
        self.assertGreaterEqual(len(t4_units), 1)
        self.assertTrue(all(u["disposition"] == "inventory_only" for u in t4_units))
        # The no-signal file is still planned (kept in the denominator).
        self.assertIn(
            "web/helper.go", {a["path"] for u in units for a in u["ranges"]}
        )

        # Lower profiles do not plan it, but the inventory still counts it.
        quick = UnitPlanner("snp-swr004", profile="quick").create_units(
            self.manifest.files, self.file_signals, boundaries=[]
        )
        self.assertNotIn("web/helper.go", {a["path"] for u in quick for a in u["ranges"]})
        summary = reconcile(self.manifest, discovered_total=self.discovered_total)
        self.assertEqual(summary["included"], EXPECTED_INCLUDED)  # includes helper.go

    def test_no_signal_files_are_still_included_in_denominator(self):
        """无信号文件计入纳入分母（不因无命中被排除出清点）。"""
        summary = reconcile(self.manifest, discovered_total=self.discovered_total)
        self.assertEqual(summary["by_language"].get("go"), 1)

    # -- 信号排序 / 语言·组件聚合 -------------------------------------------

    def test_signal_ordering_line_asc_strength_desc(self):
        """信号按（行升序、强度降序）排序（DSR-015）。"""
        single_dir = self.temp_dir / "single_target"
        single_dir.mkdir()
        (single_dir / "multi.py").write_text(
            "value = int('1')\n"            # line 1: guard (strength 2)
            "os.system(request.args)\n"     # line 2: sink(3) + source(3)
            "open('x')\n",                  # line 3: source (strength 1)
            encoding="utf-8",
        )
        rules = ExclusionRules()
        collector = SnapshotCollector(
            single_dir,
            self.temp_dir / "single_snapshot",
            is_excluded_fn=rules.evaluate,
            language_detector_fn=lambda p, b: (detect_language(p, b), "default"),
        )
        manifest = collector.collect()
        lines = (self.temp_dir / "single_snapshot" / "multi.py").read_text(
            encoding="utf-8"
        ).splitlines()
        scanner = SignalScanner()
        hits, _ = scanner.scan_file("multi.py", lines, language="python")

        self.assertTrue(hits)
        keys = [(h["line"], -h["strength"]) for h in hits]
        self.assertEqual(keys, sorted(keys), f"hits not (line asc, strength desc): {keys}")
        # Line 1 (guard) precedes the two strength-3 hits on line 2, which in
        # turn precede the strength-1 source on line 3.
        self.assertEqual(hits[0]["line"], 1)
        line2 = [h for h in hits if h["line"] == 2]
        self.assertGreaterEqual(len(line2), 2)
        self.assertTrue(all(h["strength"] == 3 for h in line2))
        self.assertEqual(max(h["line"] for h in hits), 3)

    def test_component_aggregation_reflects_build_manifest(self):
        """组件聚合来自真实构建清单（web/ 由 package.json 标记），非恒 default。"""
        assignment = detect_components(self.manifest.files, self.snapshot_root)
        self.assertEqual(len(assignment), len(self.manifest.files))
        self.assertEqual(assignment["web/main.py"], "web")
        self.assertEqual(assignment["web/helper.go"], "web")
        self.assertEqual(assignment["app.py"], "default")
        self.assertEqual(assignment["notes.rst"], "default")

        files = [dict(f, component=assignment[f["path"]]) for f in self.manifest.files]
        manifest_like = type("M", (), {"files": files, "excluded": self.manifest.excluded})()
        summary = reconcile(manifest_like, discovered_total=self.discovered_total)
        self.assertEqual(summary["by_component"], {"default": 2, "web": 4})
        self.assertEqual(sum(summary["by_component"].values()), summary["included"])


if __name__ == "__main__":
    unittest.main()
