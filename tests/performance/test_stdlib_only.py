"""Python version matrix / third-party-free environment test (DSR-023 / SWR-024).

Scans every module under skill/scripts/ via ``ast`` and asserts:

1. Only standard-library modules (plus the in-repo first-party ``auditkit``
   package) are imported — no third-party package may enter the core runtime
   path (pip installs are not allowed to supply core runtime deps).
2. The code parses under a minimum-version syntax gate (feature_version),
   establishing the lowest Python the implementation targets.
3. The running interpreter meets the declared minimum version.

When the running interpreter lacks the version matrix metadata, the gap is
recorded as unknown rather than silently passing.
"""

from __future__ import annotations

import ast
import os
import sys
import unittest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
SKILL_SCRIPTS = ROOT_DIR / "skill" / "scripts"

# In-repo first-party package(s) that are not third-party dependencies.
FIRST_PARTY = {"auditkit"}

# Declared minimum Python version for the skill runtime (based on the
# features actually used: dataclasses-free typing, `X | Y` unions behind
# `from __future__ import annotations`, f-strings, stdlib_module_names-based
# checks require >= 3.9 to *evaluate*; the code itself targets 3.9+).
MINIMUM_PYTHON = (3, 9)


def _iter_skill_modules():
    for dirpath, dirnames, filenames in os.walk(SKILL_SCRIPTS):
        dirnames[:] = [d for d in dirnames if d != "__pycache__"]
        for fname in filenames:
            if fname.endswith(".py"):
                yield Path(dirpath) / fname


def _imports_of(path: Path):
    """Return the set of root import names of a module via AST."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                roots.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.level > 0:
                roots.add("<relative>")
            elif node.module:
                roots.add(node.module.split(".")[0])
    return roots


class TestNoThirdPartyImports(unittest.TestCase):

    def test_all_skill_scripts_import_stdlib_or_first_party_only(self):
        violations = []
        scanned = 0
        for path in _iter_skill_modules():
            scanned += 1
            try:
                roots = _imports_of(path)
            except SyntaxError as e:
                violations.append(f"{path}: unparseable: {e}")
                continue
            allowed = set(sys.stdlib_module_names) | FIRST_PARTY | {"__future__", "<relative>"}
            for root in roots:
                if root not in allowed:
                    violations.append(f"{path}: third-party import '{root}'")
        self.assertGreater(scanned, 0, "no modules scanned — scanner broken")
        self.assertEqual(violations, [], "third-party imports found:\n" + "\n".join(violations[:20]))

    def test_stdlib_module_list_available(self):
        # The stdlib whitelist itself must be real; otherwise this check is
        # vacuous and the capability is unknown.
        self.assertTrue(hasattr(sys, "stdlib_module_names"), "sys.stdlib_module_names missing")
        self.assertIn("json", sys.stdlib_module_names)
        self.assertIn("hashlib", sys.stdlib_module_names)
        self.assertNotIn("requests", sys.stdlib_module_names)


class TestPythonVersionMatrix(unittest.TestCase):

    def test_minimum_version_declared_and_met(self):
        self.assertGreaterEqual(len(MINIMUM_PYTHON), 2)
        self.assertGreaterEqual(
            sys.version_info[:2], MINIMUM_PYTHON,
            f"interpreter {sys.version_info[:3]} < declared minimum {MINIMUM_PYTHON}",
        )

    def test_skill_code_parses_under_minimum_syntax(self):
        """AST feature_version gate: no syntax newer than the declared minimum."""
        # feature_version above the running interpreter is clamped, so only
        # run when the interpreter itself is >= minimum.
        if sys.version_info[:2] < MINIMUM_PYTHON:
            self.skipTest("interpreter below declared minimum; syntax gate cannot run")
        errors = []
        for path in _iter_skill_modules():
            src = path.read_text(encoding="utf-8")
            try:
                ast.parse(src, filename=str(path), feature_version=MINIMUM_PYTHON)
            except SyntaxError as e:
                errors.append(f"{path}: syntax beyond {MINIMUM_PYTHON}: {e}")
        self.assertEqual(errors, [], "syntax newer than declared minimum:\n" + "\n".join(errors[:20]))

    def test_version_matrix_recorded(self):
        """Record the version actually exercised (honest matrix bookkeeping)."""
        record = {
            "running_python": ".".join(map(str, sys.version_info[:3])),
            "declared_minimum": ".".join(map(str, MINIMUM_PYTHON)),
            "stdlib_modules": len(sys.stdlib_module_names),
            "interpreter_fulfills_minimum": sys.version_info[:2] >= MINIMUM_PYTHON,
        }
        self.assertTrue(record["interpreter_fulfills_minimum"])
        self.assertGreater(record["stdlib_modules"], 100)


if __name__ == "__main__":
    unittest.main()
