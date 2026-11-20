#!/usr/bin/env python3
"""Unified Test Suite Orchestrator — five-category execution (DSR-078 / SWR-029).

Suites are grouped into exactly five categories:

1. deterministic     — schema/contract, snapshot, ledger, analysis, knowledge,
                       reporting, security/adversarial, holdout wiring, E2E
                       synthetics, CLI determinism, and mock-based host tests.
2. real_cli          — tests/hosts/test_real_hosts.py ONLY. These run against
                       real `claude` / `codex` CLIs. When no CLI is present the
                       tests are SKIPPED and the category is reported as
                       SKIPPED-NOT-PASSED; mock results are never counted as
                       real-host passes.
3. model_eval        — LLM/model-in-the-loop evaluation suites (expected at
                       tests/model_eval). Missing directories are reported as
                       missing, never silently dropped.
4. fault_injection   — fault/chaos suites (expected at tests/fault_injection).
5. scale             — performance/scale suites (tests/performance), including
                       the 100k-file run, cost accounting, and stdlib-only
                       environment checks.

The summary table is grouped by category with pass / fail / error / skipped /
missing columns. `skipped` is taken from unittest's result.skipped and is
single-counted — a skip is never reported as a pass.

Exit code: 0 when no failures/errors occurred in any category. Missing
optional suites (tests/cli, tests/model_eval, tests/fault_injection) lower the
denominator honestly — they are listed as MISSING and keep their capability
`unknown`; use --strict to turn missing into a non-zero exit.
"""

# 需求追踪 (Requirement Traceability)
# ---------------------------------------------------------------------------
# 上层需求: docs/design/DETAILED_DEVELOPMENT_REQUIREMENTS.md (DSR-078)
# 设计依据: docs/design/SOFTWARE_DESIGN.md
# SWR-029  统一测试编排：五类套件分组汇总；缺失/跳过单列；禁止把 mock 计为
#          真实宿主通过。
#   绑定实现: DSR-078
# 状态以统一测试结论为准；未实测能力保持 unknown（设计原则 8：能观测的不靠声明）。
#

from __future__ import annotations

import argparse
import sys
import time
import unittest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
SKILL_SCRIPTS = ROOT_DIR / "skill" / "scripts"
TESTS_DIR = ROOT_DIR / "tests"

if str(SKILL_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SKILL_SCRIPTS))
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# (label, relative test dir, pattern, exclude_substring, optional)
# optional=True suites are reported MISSING (not FAIL) when the dir is absent.
CATEGORY_SUITES = {
    "deterministic": [
        ("Contracts & Schemas", "tests/contracts", "test_*.py", None, False),
        ("Snapshot & Paths", "tests/snapshot", "test_*.py", None, False),
        ("Ledger, Tasks, & Budget", "tests/ledger", "test_*.py", None, False),
        ("Analysis, Verifier, & Rating", "tests/analysis", "test_*.py", None, False),
        ("Knowledge Catalog & 150 Cards", "tests/knowledge", "test_*.py", None, False),
        ("Reporting & Coverage", "tests/reporting", "test_*.py", None, False),
        ("Security & Adversarial", "tests/security", "test_*.py", None, False),
        ("Holdout Wiring (synthetic corpus)", "tests/holdout", "test_*.py", None, False),
        ("End-to-End Synthetics", "tests/e2e", "test_*.py", None, False),
        ("SWR Acceptance (per-SWR tests/swr)", "tests/swr", "test_*.py", None, False),
        ("CLI Determinism", "tests/cli", "test_*.py", None, True),  # built by another workstream
        ("Host Adapters (mock)", "tests/hosts", "test_*.py", "test_real_hosts", False),
    ],
    "real_cli": [
        ("Real Host CLI", "tests/hosts", "test_real_hosts.py", None, False),
    ],
    "model_eval": [
        ("Model-in-the-loop Evaluation", "tests/model_eval", "test_*.py", None, True),
    ],
    "fault_injection": [
        ("Fault Injection", "tests/fault_injection", "test_*.py", None, True),
    ],
    "scale": [
        ("Performance & Scale", "tests/performance", "test_*.py", None, False),
    ],
}


def _filter_out(suite: unittest.TestSuite, exclude: str) -> unittest.TestSuite:
    """Drop tests whose id contains `exclude` (used to split real-CLI tests
    out of the mock-based host suite)."""
    kept = []
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            kept.append(_filter_out(item, exclude))
        elif isinstance(item, unittest.TestCase):
            if exclude not in item.id():
                kept.append(item)
        else:
            kept.append(item)
    return unittest.TestSuite(kept)


def _discover(rel_dir: str, pattern: str, exclude: str | None) -> unittest.TestSuite:
    loader = unittest.TestLoader()
    suite = loader.discover(str(ROOT_DIR / rel_dir), pattern=pattern)
    if exclude:
        suite = _filter_out(suite, exclude)
    return suite


def run_all(strict: bool = False, only_categories: frozenset[str] | None = None) -> int:
    print("=" * 92)
    if only_categories is not None:
        print(
            "polyglot-audit: Unified Verification Suite (subset: "
            + ", ".join(sorted(only_categories))
            + "; release evidence still requires the FULL run, DSR-078)"
        )
    else:
        print("polyglot-audit: Unified Verification Suite (five-category orchestration, DSR-078)")
    print("=" * 92)

    t_all = time.time()
    # category -> dict of counters
    category_totals = {cat: {"tests": 0, "fail": 0, "err": 0, "skip": 0, "missing": 0, "time": 0.0}
                       for cat in CATEGORY_SUITES}
    rows: list[tuple[str, str, int, int, int, int, float, str]] = []

    for category, suites in CATEGORY_SUITES.items():
        if only_categories is not None and category not in only_categories:
            # Subset run (--fast / --categories): skipped categories are NOT
            # reported as skipped-passes -- they are simply not claimed, and
            # the header states that release evidence needs the full run
            # (DSR-078: skipped 单列不进分母, missing remains unclaimed).
            continue
        print(f"\n### CATEGORY: {category}")
        for label, rel_dir, pattern, exclude, optional in suites:
            suite_path = ROOT_DIR / rel_dir
            if not suite_path.is_dir():
                category_totals[category]["missing"] += 1
                rows.append((category, label, 0, 0, 0, 0, 0.0, "MISSING (dir absent)"))
                print(f"  [MISSING] {label} — {rel_dir} does not exist; capability stays unknown")
                continue

            print(f"  [RUNNING] {label} ({rel_dir})...")
            suite = _discover(rel_dir, pattern, exclude)
            runner = unittest.TextTestRunner(verbosity=1, stream=sys.stderr)
            t0 = time.time()
            res = runner.run(suite)
            elapsed = time.time() - t0

            n_tests = res.testsRun
            n_fail = len(res.failures)
            n_err = len(res.errors)
            n_skip = len(res.skipped)

            category_totals[category]["tests"] += n_tests
            category_totals[category]["fail"] += n_fail
            category_totals[category]["err"] += n_err
            category_totals[category]["skip"] += n_skip
            category_totals[category]["time"] += elapsed

            if n_fail or n_err:
                status = "FAIL"
            elif n_tests == 0 and n_skip == 0:
                status = "MISSING (no tests discovered)"
                category_totals[category]["missing"] += 1
            elif n_tests == 0 and n_skip > 0:
                # SKIPPED-NOT-PASSED: nothing ran, nothing is claimed.
                status = "SKIPPED-NOT-PASSED"
            elif n_skip == n_tests and category == "real_cli":
                status = "SKIPPED-NOT-PASSED (no real CLI on PATH)"
            else:
                status = "PASS"
            rows.append((category, label, n_tests, n_fail, n_err, n_skip, elapsed, status))

    elapsed_all = time.time() - t_all

    print("\n" + "=" * 92)
    print("UNIFIED TEST SUMMARY — grouped by category")
    print("=" * 92)
    header = f"{'Category':<16} {'Suite':<34} {'Tests':>5} {'Fail':>5} {'Err':>5} {'Skip':>5} {'Time':>7}  Status"
    print(header)
    print("-" * 92)
    for category, suites in CATEGORY_SUITES.items():
        for row in rows:
            if row[0] == category:
                _, label, n, f, e, s, t, st = row
                print(f"{category:<16} {label:<34} {n:>5} {f:>5} {e:>5} {s:>5} {t:>6.1f}s  {st}")
        ct = category_totals[category]
        print(f"{category:<16} {'-- subtotal --':<34} {ct['tests']:>5} {ct['fail']:>5} "
              f"{ct['err']:>5} {ct['skip']:>5} {ct['time']:>6.1f}s  "
              f"missing={ct['missing']}")
        print("-" * 92)

    total_tests = sum(c["tests"] for c in category_totals.values())
    total_fail = sum(c["fail"] for c in category_totals.values())
    total_err = sum(c["err"] for c in category_totals.values())
    total_skip = sum(c["skip"] for c in category_totals.values())
    total_missing = sum(c["missing"] for c in category_totals.values())

    print(f"Total: tests={total_tests} fail={total_fail} err={total_err} "
          f"skipped={total_skip} missing={total_missing} time={elapsed_all:.1f}s")
    print()
    print("Notes:")
    print("- real_cli counts ONLY tests/hosts/test_real_hosts.py against real CLIs;")
    print("  mock-based host results live under deterministic and are never counted as real passes.")
    print("- skipped is single-counted from unittest result.skipped; a skip is never a pass.")
    print("- missing suites keep their capability unknown; they do not raise the pass denominator.")
    print("=" * 92)

    if total_fail or total_err:
        print("RESULT: FAILURES/ERRORS PRESENT")
        return 1
    if strict and total_missing:
        print("RESULT: STRICT MODE — missing suites are fatal")
        return 2
    print("RESULT: NO FAILURES OR ERRORS (missing/skipped categories remain honestly unclaimed)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="DSR-078 five-category test orchestrator")
    parser.add_argument("--strict", action="store_true",
                        help="treat missing optional suites as a non-zero exit")
    parser.add_argument(
        "--fast", action="store_true",
        help="daily mode: skip the network/credential-bound categories "
             "(real_cli, model_eval) whose probes wait on external hosts; "
             "release evidence still requires the FULL run",
    )
    parser.add_argument(
        "--categories", default="",
        help="comma-separated subset of categories to run (e.g. "
             "deterministic,fault_injection,scale); empty = all five",
    )
    args = parser.parse_args(argv)

    only_categories: frozenset[str] | None = None
    if args.categories:
        requested = {c.strip() for c in args.categories.split(",") if c.strip()}
        unknown = requested - set(CATEGORY_SUITES)
        if unknown:
            parser.error(
                "unknown categories: " + ", ".join(sorted(unknown))
                + " (valid: " + ", ".join(sorted(CATEGORY_SUITES)) + ")"
            )
        only_categories = frozenset(requested)
    elif args.fast:
        only_categories = frozenset(set(CATEGORY_SUITES) - {"real_cli", "model_eval"})

    return run_all(strict=args.strict, only_categories=only_categories)


if __name__ == "__main__":
    sys.exit(main())
