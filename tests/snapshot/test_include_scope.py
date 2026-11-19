"""Positive include-scope semantics (SR-004 / SD-03 narrowing, L-13 / O-10).

Covers:
- A non-empty ``scope.include`` other than ``["*"]`` is a POSITIVE filter:
  a regular file matching none of the include patterns is excluded with the
  explicit reason "Outside user include scope" — it never reaches the
  directory / binary / test rules (after an explicit narrowing, the rest of
  the tree is irrelevant to those rules).
- A file matched by an include still walks the exclusion chain: an include
  never exempts a file from explicit user excludes or default rules.
- ``["*"]`` keeps the historical universal semantics (everything short-
  circuits to included ahead of all other rules).
- An empty include list keeps the historical default behavior (everything
  walks the default exclusion chain).
- The scope reason classifies as the ``user_rule`` bucket (DSR-054).
- End to end: a precise include list yields a snapshot whose manifest holds
  ONLY the included files; every other discovered file is excluded with the
  scope reason (regression for the "precise path include still snapshotted
  thousands of files" finding).

All fixtures are synthetic trees built in temporary directories.
"""

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

SKILL_SCRIPTS = Path(__file__).resolve().parents[2] / "skill" / "scripts"
if str(SKILL_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SKILL_SCRIPTS))

from auditkit.inventory.languages import detect_language
from auditkit.inventory.rules import ExclusionRules, classify_exclusion_reason, inclusion_summary
from auditkit.snapshot.collector import SnapshotCollector

SCOPE_REASON = "Outside user include scope"


def _write(root: Path, rel: str, content: str = "x = 1\n") -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def _reasons(rules: ExclusionRules, relpaths) -> dict:
    return {rel: rules.evaluate(rel) for rel in relpaths}


class TestIncludeScopeRules(unittest.TestCase):
    """Unit semantics of ExclusionRules.evaluate under an include list."""

    def test_exact_path_include_narrows_everything_else(self):
        rules = ExclusionRules(user_includes=["src/main.py", "README.md"])

        decision = rules.evaluate("src/main.py")
        self.assertEqual(decision, (False, ""))

        decision = rules.evaluate("README.md")
        self.assertEqual(decision, (False, ""))

        # Every other file is excluded with the scope reason — regardless of
        # where it lives (inside default-excluded dirs, test dirs, binaries):
        # once the user narrows the scope those rules are irrelevant.
        others = [
            "app/util.py",
            "lib/other.py",
            "tests/test_app.py",
            "node_modules/dep/index.js",
            "vendor/lib.so",
            "logo.png",
            "docs/design.md",
            "main.py",
            "src/main.py.bak",
        ]
        for rel, (excluded, reason) in _reasons(rules, others).items():
            self.assertTrue(excluded, f"{rel} must be excluded outside include scope")
            self.assertEqual(reason, SCOPE_REASON, f"{rel} must carry the scope reason")

    def test_wildcard_pattern_include_narrows_outside_matches(self):
        rules = ExclusionRules(user_includes=["src/**", "docs/*.md"])

        self.assertEqual(rules.evaluate("src/core/engine.py"), (False, ""))
        self.assertEqual(rules.evaluate("docs/design.md"), (False, ""))
        # fnmatch (unlike glob) lets "*" cross directory separators, so both
        # patterns match at any depth — the pre-existing matching behavior,
        # unchanged. What the positive filter adds: everything outside the
        # matched subtrees is excluded with the scope reason.
        self.assertEqual(rules.evaluate("docs/deep/nested.md"), (False, ""))
        excluded, reason = rules.evaluate("app/util.py")
        self.assertTrue(excluded)
        self.assertEqual(reason, SCOPE_REASON)
        excluded, reason = rules.evaluate("scripts/build.md")
        self.assertTrue(excluded)
        self.assertEqual(reason, SCOPE_REASON)

    def test_basename_include_still_matches(self):
        # A bare basename pattern matches by full path or basename, as before.
        rules = ExclusionRules(user_includes=["Makefile"])

        self.assertEqual(rules.evaluate("Makefile"), (False, ""))
        self.assertEqual(rules.evaluate("sub/Makefile"), (False, ""))
        excluded, reason = rules.evaluate("sub/other.mk")
        self.assertTrue(excluded)
        self.assertEqual(reason, SCOPE_REASON)

    def test_include_does_not_exempt_from_user_exclude(self):
        # A precise user exclude wins over a matching include.
        rules = ExclusionRules(
            user_includes=["src/**"],
            user_excludes=["src/secret.py"],
        )

        self.assertEqual(rules.evaluate("src/main.py"), (False, ""))
        excluded, reason = rules.evaluate("src/secret.py")
        self.assertTrue(excluded)
        self.assertEqual(reason, "Matched user exclude pattern: src/secret.py")

    def test_include_does_not_exempt_from_default_rules(self):
        # Matching an include still walks the default chain: test files,
        # binaries and default-excluded directories are excluded as usual.
        rules = ExclusionRules(user_includes=["src/**"], include_tests=False)

        excluded, reason = rules.evaluate("src/test_main.py")
        self.assertTrue(excluded)
        self.assertEqual(reason, "Default excluded test file: test_main.py")

        excluded, reason = rules.evaluate("src/logo.png")
        self.assertTrue(excluded)
        self.assertEqual(reason, "Excluded binary/media extension: .png")

        excluded, reason = rules.evaluate("src/vendor/dep.js")
        self.assertTrue(excluded)
        self.assertEqual(reason, "Inside excluded directory: vendor")

    def test_include_with_tests_enabled_keeps_test_files_in_scope(self):
        rules = ExclusionRules(user_includes=["src/**"], include_tests=True)

        self.assertEqual(rules.evaluate("src/test_main.py"), (False, ""))

    def test_star_include_semantics_unchanged(self):
        # ["*"] is the universal include: it narrows nothing -- regular source
        # still walks the default exclusion chain and stays included.
        # (RUN-LESSONS revision: the old short-circuit past the chain shipped
        # VCS internals and compiled binaries into the inventory across two
        # real-target run series; hygiene exclusions are not content
        # preferences, so include scope never overrides them.)
        rules = ExclusionRules(
            user_includes=["*"],
            user_excludes=["node_modules/**"],
            include_tests=False,
        )

        self.assertEqual(rules.evaluate("app/main.py"), (False, ""))
        self.assertEqual(
            rules.evaluate("node_modules/dep/index.js"),
            (True, "Matched user exclude pattern: node_modules/**"),
        )
        self.assertEqual(
            rules.evaluate("tests/test_app.py"),
            (True, "Default excluded test directory: tests"),
        )
        self.assertEqual(
            rules.evaluate("logo.png"),
            (True, "Excluded binary/media extension: .png"),
        )

        # VCS internals never pass, regardless of include scope.
        self.assertEqual(
            rules.evaluate(".git/objects/ab/cdef"),
            (True, "Inside excluded directory: .git"),
        )

    def test_empty_include_semantics_unchanged(self):
        # No include list: everything walks the default exclusion chain.
        for includes in ([], None):
            rules = ExclusionRules(user_includes=includes)

            self.assertEqual(rules.evaluate("app/main.py"), (False, ""))
            self.assertEqual(
                rules.evaluate("node_modules/dep/index.js"),
                (True, "Inside excluded directory: node_modules"),
            )
            self.assertEqual(
                rules.evaluate("tests/test_app.py"),
                (True, "Default excluded test directory: tests"),
            )
            self.assertEqual(
                rules.evaluate("logo.png"),
                (True, "Excluded binary/media extension: .png"),
            )

    def test_scope_reason_classifies_as_user_rule(self):
        self.assertEqual(classify_exclusion_reason(SCOPE_REASON), "user_rule")


class TestIncludeScopeSnapshot(unittest.TestCase):
    """End to end: a precise include list yields a narrowed snapshot manifest."""

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = Path(tempfile.mkdtemp())
        cls.target = cls.temp_dir / "target"
        # Synthetic "large" tree: only src/main.py is in the user's scope.
        for rel in [
            "src/main.py",
            "src/helper.py",
            "app/util.py",
            "lib/thing.py",
            "docs/readme.md",
            "tests/test_app.py",
            "node_modules/dep/index.js",
            "logo.png",
        ]:
            _write(cls.target, rel)
        cls.dest = cls.temp_dir / "snapshot"

        rules = ExclusionRules(user_includes=["src/main.py"])
        collector = SnapshotCollector(
            cls.target,
            cls.dest,
            is_excluded_fn=rules.evaluate,
            language_detector_fn=lambda p, b: (detect_language(p, b), "default"),
        )
        cls.manifest = collector.collect()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def test_manifest_contains_only_included_files(self):
        included = sorted(f["path"] for f in self.manifest.files)
        self.assertEqual(included, ["src/main.py"])

    def test_all_other_files_excluded_with_scope_reason(self):
        excluded = {e["path"]: e["reason"] for e in self.manifest.excluded}
        expected_others = [
            "src/helper.py",
            "app/util.py",
            "lib/thing.py",
            "docs/readme.md",
            "tests/test_app.py",
            "node_modules/dep/index.js",
            "logo.png",
        ]
        for rel in expected_others:
            self.assertIn(rel, excluded, f"{rel} must be recorded as excluded")
            self.assertEqual(excluded[rel], SCOPE_REASON, f"{rel} must carry the scope reason")

    def test_scope_exclusions_are_never_counted_as_coverage(self):
        summary = inclusion_summary(self.manifest)

        self.assertEqual(summary["included"], 1)
        self.assertEqual(summary["excluded_total"], 7)
        self.assertEqual(summary["user_rule"], 7)
        self.assertEqual(
            summary["included"] + summary["excluded_total"],
            len(self.manifest.files) + len(self.manifest.excluded),
        )


if __name__ == "__main__":
    unittest.main()
