# tests/holdout — Holdout Evaluation Domain (DSR-047 / SWR-029)

This domain hosts the holdout evaluation harness for the QAV area.

## What lives here

- `test_holdout_eval.py` — deterministic tests that the synthetic corpus is
  complete (one vulnerable + one safe file per knowledge card) and that
  `tools/evaluate_holdout.py` runs end-to-end and produces honest JSON +
  Markdown reports.
- `reports/` — runtime output of the evaluator (`holdout_report.json`,
  `holdout_report.md`). Regenerated on every run; never a release artifact.

## Holdout isolation warning (READ BEFORE TUNING)

The corpus under `tests/fixtures/holdout/` is **development-time synthetic
data derived programmatically** from `skill/knowledge/languages/` — the same
`synthetic_vulnerable_example` / `synthetic_safe_example` snippets the
per-language detection signals were authored against. Consequences:

1. It measures **pipeline wiring and regression only**. A 150/150 detection
   rate here proves the scanner finds what the signals were written to find.
   It is NOT evidence of generalization.
2. It MUST NOT be used for tuning: adjusting signals or cards against this
   corpus is fitting on the test set.
3. A **real holdout set must be written independently by the maintainers**,
   ideally against code that none of the signal authors have seen, kept out
   of all tuning loops, and evaluated at most once per release. Until such a
   set exists, every holdout-derived claim stays **unknown**, and the
   evaluator marks it as such (`llm_results: unknown`,
   `claims.independent_holdout: false`).

The evaluator (`tools/evaluate_holdout.py`) reports true positives, false
positives, pending (unscannable) files, and the denominator per
language x card. Categories with missing corpus files or that were not run
are reported as `unknown`, never silently dropped, and the tool never claims
an objective ranking or full coverage.
