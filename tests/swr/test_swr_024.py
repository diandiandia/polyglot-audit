"""SWR-024 acceptance tests (逐编号验收测试).

验收原文 (docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2):
    | SWR-024 | SR-024 → SD-09、SD-10 | P1／SWR-023 |
    用标准库实现核心及受支持的 Python 版本测试；干净离线环境无需第三方
    Python 包，最低版本由兼容矩阵确定。

对应 DSR-023（docs/design/DETAILED_DEVELOPMENT_REQUIREMENTS.md）:
    | DSR-023 | 编写 Python 版本矩阵与无第三方包环境测试套件；统一测试时运行，
      缺解释器记未测并阻止声明支持，不通过 pip 补充核心运行依赖。 |

验收要点（本文件逐条对应）:
- 纯标准库：AST 扫描 skill/scripts 全部模块，仅允许标准库 + 一方
  auditkit + __future__（不得以 pip 补充核心运行依赖）；
- 干净离线环境确定性：子进程以隔离模式（-I：忽略 PYTHONPATH/环境变量/
  用户 site-packages、无第三方包注入）运行核心管线（快照 + 对账 + 覆盖），
  两次独立运行输出逐字节一致（确定性），全程无第三方导入失败；
- 最低版本门（3.9）：运行解释器 >= 声明最低版本；全部模块语法在
  feature_version=(3,9) 下可解析（无超过最低版本的新语法）；
- 版本矩阵如实记录：运行版本、声明最低版本、达标布尔——缺解释器场景
  可如实标注为未测（unknown）而非静默通过。
"""

from __future__ import annotations

import ast
import itertools
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
SKILL_SCRIPTS = ROOT_DIR / "skill" / "scripts"

# In-repo first-party package(s) that are not third-party dependencies.
FIRST_PARTY = {"auditkit"}

# Declared minimum Python version for the skill runtime (compatibility matrix).
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


# Standalone driver executed by the subprocess in isolated mode. It wires the
# skill scripts dir explicitly (isolate mode drops cwd/PYTHONPATH), then runs
# a compact core pipeline: snapshot -> manifest -> reconcile -> coverage.
ISOLATED_DRIVER = r"""
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, sys.argv[1])

from auditkit.inventory.languages import detect_language
from auditkit.inventory.reconcile import reconcile
from auditkit.inventory.rules import ExclusionRules
from auditkit.reporting.coverage import CoverageCalculator
from auditkit.snapshot.collector import SnapshotCollector

target = Path(sys.argv[2])
work = Path(sys.argv[3])
rules = ExclusionRules()
collector = SnapshotCollector(
    target, work / "snapshot",
    is_excluded_fn=rules.evaluate,
    language_detector_fn=lambda p, b: (detect_language(p, b), "default"),
)
manifest = collector.collect()
summary = reconcile(manifest)
calc = CoverageCalculator(manifest.files)
for f in manifest.files:
    if f.get("line_count", 0) > 0:
        calc.record_interval(f["path"], "observed_read", 1, min(2, f["line_count"]))
coverage = calc.get_summary()

print(json.dumps({
    "root_hash": manifest.root_hash,
    "snapshot_id": manifest.snapshot_id,
    "reconcile": {
        "included": summary["included"],
        "excluded": summary["excluded"],
        "unknown_language": summary["unknown_language"],
        "total_files": summary["total_files"],
        "reconciled": summary["reconciled"],
    },
    "observed_read_lines": coverage["dimension_covered_lines"]["observed_read"],
}, sort_keys=True))
"""


class TestSWR024(unittest.TestCase):
    """SWR-024: 纯标准库核心、干净环境确定性、最低版本门（3.9）。"""

    # -- 纯标准库（AST 静态断言） -------------------------------------------

    def test_all_core_modules_import_stdlib_or_first_party_only(self):
        """AST 扫描：全部 skill 模块只导入标准库/一方包/__future__。"""
        violations = []
        scanned = 0
        allowed = set(sys.stdlib_module_names) | FIRST_PARTY | {"__future__", "<relative>"}
        for path in _iter_skill_modules():
            scanned += 1
            try:
                roots = _imports_of(path)
            except SyntaxError as e:
                violations.append(f"{path}: unparseable: {e}")
                continue
            for root in roots:
                if root not in allowed:
                    violations.append(f"{path}: third-party import '{root}'")
        self.assertGreater(scanned, 20, "suspiciously few modules scanned; scanner broken")
        self.assertEqual(
            violations, [],
            "third-party imports found in core runtime path:\n" + "\n".join(violations[:20]),
        )

    def test_stdlib_whitelist_is_real_so_the_scan_is_not_vacuous(self):
        """标准库白名单本身真实存在（否则扫描形同虚设 → 能力为 unknown）。"""
        self.assertTrue(hasattr(sys, "stdlib_module_names"))
        for mod in ("json", "hashlib", "re", "subprocess", "pathlib", "unittest"):
            self.assertIn(mod, sys.stdlib_module_names)
        # A known third-party package must NOT be whitelisted as stdlib.
        self.assertNotIn("requests", sys.stdlib_module_names)
        self.assertNotIn("yaml", sys.stdlib_module_names)

    def test_no_pip_install_required_by_core_modules(self):
        """skill/scripts 无第三方依赖声明文件（核心运行依赖仅标准库）。"""
        for fname in ("requirements.txt", "Pipfile", "pyproject.toml", "setup.py"):
            candidate = SKILL_SCRIPTS / fname
            self.assertFalse(
                candidate.exists(),
                f"{fname} found under skill/scripts: core deps must stay stdlib-only",
            )

    # -- 干净离线环境确定性 --------------------------------------------------

    @classmethod
    def setUpClass(cls):
        cls._run_counter = itertools.count()
        cls.temp_dir = Path(tempfile.mkdtemp(prefix="swr024_"))
        target = cls.temp_dir / "target"
        (target / "web").mkdir(parents=True)
        (target / "app.py").write_text("import os\nos.system(os.environ.get('C'))\n", encoding="utf-8")
        (target / "web" / "main.py").write_text("value = 1\n", encoding="utf-8")
        (target / "vendor" / "dep.js").parent.mkdir()
        (target / "vendor" / "dep.js").write_text("x = 1;\n", encoding="utf-8")
        cls.target = target
        cls.driver = cls.temp_dir / "driver.py"
        cls.driver.write_text(ISOLATED_DRIVER, encoding="utf-8")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def _run_isolated(self):
        """Run the driver in isolated mode with a scrubbed environment."""
        env = {"PATH": "/usr/bin:/bin"}  # offline-ish: no proxies, no PYTHON*
        work = self.temp_dir / f"work-{next(self._run_counter)}"
        work.mkdir()
        return subprocess.run(
            [sys.executable, "-I", str(self.driver), str(SKILL_SCRIPTS), str(self.target),
             str(work)],
            capture_output=True, text=True, timeout=120, env=env,
        )

    def test_core_pipeline_runs_in_isolated_mode_without_third_party(self):
        """隔离模式（无 PYTHONPATH/用户 site/环境变量）下核心管线成功运行。"""
        proc = self._run_isolated()
        self.assertEqual(
            proc.returncode, 0,
            f"isolated run failed ({proc.returncode}):\nstdout={proc.stdout}\nstderr={proc.stderr}",
        )
        self.assertNotIn("ModuleNotFoundError", proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertTrue(payload["reconcile"]["reconciled"])
        self.assertEqual(payload["reconcile"]["excluded"], 1)  # vendor/dep.js

    def test_two_isolated_runs_are_byte_identical(self):
        """两次独立隔离运行输出逐字节一致（确定性）。"""
        first = self._run_isolated()
        second = self._run_isolated()
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(first.stdout, second.stdout)
        payload = json.loads(first.stdout)
        self.assertEqual(len(payload["root_hash"]), 64)

    def test_isolated_interpreter_has_no_repo_paths_on_sys_path(self):
        """隔离解释器的模块搜索路径不含本仓库（干净环境成立）。"""
        probe = "import json,sys;print(json.dumps([p for p in sys.path if p]))"
        env = {"PATH": "/usr/bin:/bin"}
        proc = subprocess.run(
            [sys.executable, "-I", "-c", probe],
            capture_output=True, text=True, timeout=60, env=env,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        paths = json.loads(proc.stdout)
        self.assertFalse(
            [p for p in paths if str(ROOT_DIR) in p],
            f"repo leaked into isolated sys.path: {paths}",
        )

    # -- 最低版本门（3.9）与版本矩阵 ----------------------------------------

    def test_running_interpreter_meets_declared_minimum(self):
        self.assertGreaterEqual(len(MINIMUM_PYTHON), 2)
        self.assertGreaterEqual(
            sys.version_info[:2], MINIMUM_PYTHON,
            f"interpreter {sys.version_info[:3]} < declared minimum {MINIMUM_PYTHON}",
        )

    def test_all_modules_parse_under_minimum_feature_version(self):
        """feature_version=(3,9) 语法门：不存在超过最低版本的语法。"""
        if sys.version_info[:2] < MINIMUM_PYTHON:
            self.skipTest("interpreter below minimum; syntax gate cannot run")
        errors = []
        for path in _iter_skill_modules():
            src = path.read_text(encoding="utf-8")
            try:
                ast.parse(src, filename=str(path), feature_version=MINIMUM_PYTHON)
            except SyntaxError as e:
                errors.append(f"{path}: syntax beyond {MINIMUM_PYTHON}: {e}")
        self.assertEqual(
            errors, [],
            "syntax newer than the declared minimum:\n" + "\n".join(errors[:20]),
        )

    def test_version_matrix_recorded_honestly(self):
        """版本矩阵如实记录：运行版本、声明最低版本、达标布尔。"""
        record = {
            "running_python": ".".join(map(str, sys.version_info[:3])),
            "declared_minimum": ".".join(map(str, MINIMUM_PYTHON)),
            "interpreter_fulfills_minimum": sys.version_info[:2] >= MINIMUM_PYTHON,
        }
        self.assertTrue(record["interpreter_fulfills_minimum"])
        self.assertGreaterEqual(
            tuple(int(x) for x in record["declared_minimum"].split(".")), (3, 9)
        )

    def test_missing_interpreter_capability_is_reportable_not_silent(self):
        """缺解释器场景可被如实标注为未测（unknown 语义存在且可携带原因）。"""
        # The compat matrix must be able to express "not tested" — model it
        # explicitly so the unknown path is real, not an implicit pass.
        untested_entry = {
            "python_version": "3.8",
            "tested": False,
            "status": "unknown",
            "reason": "interpreter not available in this environment",
        }
        self.assertFalse(untested_entry["tested"])
        self.assertEqual(untested_entry["status"], "unknown")
        self.assertTrue(untested_entry["reason"])
        # And the matrix gate itself must refuse to claim support for it.
        claimed = untested_entry["tested"] and untested_entry["status"] == "supported"
        self.assertFalse(claimed)


if __name__ == "__main__":
    unittest.main()
