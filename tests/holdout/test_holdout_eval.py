"""Deterministic tests for the holdout evaluation domain (DSR-047 / SWR-029).

These tests verify:
1. The synthetic corpus under tests/fixtures/holdout/ covers every knowledge
   card with exactly one vulnerable and one safe file.
2. tools/evaluate_holdout.py runs end-to-end, writes JSON + Markdown reports,
   and reports denominators honestly (unknown categories stay unknown).

The corpus itself is development-time synthetic data (see tests/holdout/
README.md); nothing here asserts model quality or ranking.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
SKILL_SCRIPTS = ROOT_DIR / "skill" / "scripts"
if str(SKILL_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SKILL_SCRIPTS))
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from tools.evaluate_holdout import (  # noqa: E402
    CORPUS_DIR,
    KNOWLEDGE_DIR,
    discover_corpus,
    evaluate,
    load_cards,
)

# Import the module by file path so the tool works both as a script and here.
import importlib.util  # noqa: E402

_TOOL_PATH = ROOT_DIR / "tools" / "evaluate_holdout.py"
_spec = importlib.util.spec_from_file_location("evaluate_holdout_main", _TOOL_PATH)
_tool_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_tool_mod)


class TestCorpusCompleteness(unittest.TestCase):
    """The synthetic corpus must cover all 150 cards, 2 files each."""

    def test_corpus_present(self):
        self.assertTrue(CORPUS_DIR.is_dir(), f"missing corpus dir: {CORPUS_DIR}")

    def test_all_cards_have_vuln_and_safe_files(self):
        cards = load_cards(KNOWLEDGE_DIR)
        self.assertGreaterEqual(len(cards), 150, "knowledge card registry shrank below 150")
        corpus = discover_corpus(CORPUS_DIR)
        missing = []
        for card in cards:
            lang, cid = card["corpus_language"], card["id"]
            entry = corpus.get(lang, {}).get(cid, {})
            for role in ("vuln", "safe"):
                if role not in entry or not entry[role].is_file():
                    missing.append(f"{lang}/{cid}_{role}")
        self.assertEqual(missing, [], f"corpus entries missing: {missing[:10]}")

    def test_vulnerable_files_differ_from_safe_files(self):
        corpus = discover_corpus(CORPUS_DIR)
        for lang, cards_map in corpus.items():
            for cid, entry in cards_map.items():
                if "vuln" in entry and "safe" in entry:
                    self.assertNotEqual(
                        entry["vuln"].read_text(encoding="utf-8"),
                        entry["safe"].read_text(encoding="utf-8"),
                        f"{lang}/{cid}: vuln and safe corpus files are identical",
                    )


class TestEvaluateTool(unittest.TestCase):
    """The evaluator must run and report denominators honestly."""

    @classmethod
    def setUpClass(cls):
        cls.report = evaluate(CORPUS_DIR, KNOWLEDGE_DIR, llm_dry_run=True)

    def test_report_structure(self):
        for key in ("totals", "languages", "unknown_categories", "llm_worker",
                    "disclaimer", "claims"):
            self.assertIn(key, self.report)

    def test_denominator_counts_every_corpus_file(self):
        corpus = discover_corpus(CORPUS_DIR)
        expected = sum(len(entries) for lang in corpus.values() for entries in lang.values())
        self.assertEqual(self.report["totals"]["denominator"], expected)
        # Every card category is accounted for:
        # tp + fn + tn + fp + pending == files evaluated == denominator
        # (unknown/missing-corpus cards reserve 2 slots and evaluate nothing).
        for lang, lstat in self.report["languages"].items():
            evaluated = 0
            reserved = 0
            for c in lstat["cards"].values():
                per_card = (
                    c["true_positive"] + c.get("false_negative", 0)
                    + c.get("true_negative", 0) + c["false_positive"]
                    + c["pending"]
                )
                if c["status"] == "evaluated":
                    self.assertEqual(per_card, c["denominator"], f"{lang}: card not fully accounted")
                    evaluated += per_card
                else:
                    self.assertEqual(per_card, 0, f"{lang}: unknown card produced results")
                    reserved += c["denominator"]
            self.assertEqual(evaluated + reserved, lstat["denominator"], f"{lang}: denominator mismatch")

    def test_no_unknown_categories_when_corpus_complete(self):
        # With a complete generated corpus there must be no unknown slots left.
        self.assertEqual(self.report["unknown_categories"], [])
        self.assertEqual(self.report["totals"]["unknown_categories"], 0)

    def test_scanner_actually_runs(self):
        # Structural floor only: the signal pipeline must have produced at
        # least one true positive somewhere; no specific score is asserted.
        self.assertGreaterEqual(self.report["totals"]["true_positive"], 1)
        self.assertGreaterEqual(self.report["totals"]["denominator"], 300)

    def test_no_ranking_or_coverage_claims(self):
        claims = self.report["claims"]
        self.assertFalse(claims["objective_ranking"])
        self.assertFalse(claims["full_coverage"])
        self.assertFalse(claims["independent_holdout"])
        self.assertTrue(self.report["disclaimer"])

    def test_llm_worker_marked_unknown(self):
        llm = self.report["llm_worker"]
        self.assertEqual(llm["llm_results"], "unknown")
        self.assertIn(llm["status"], ("skipped_no_host", "host_available_dry_run_only"))

    def test_reports_written_and_parseable(self):
        with tempfile.TemporaryDirectory() as td:
            json_path, md_path = _tool_mod.write_reports(self.report, Path(td))
            data = json.loads(Path(json_path).read_text(encoding="utf-8"))
            self.assertIn("totals", data)
            md = Path(md_path).read_text(encoding="utf-8")
            self.assertIn("Holdout Evaluation Report", md)
            self.assertIn("unknown", md)


class TestUnknownHandling(unittest.TestCase):
    """Missing corpus entries must surface as unknown, never as silence."""

    def test_missing_language_reported_unknown(self):
        with tempfile.TemporaryDirectory() as td:
            empty = Path(td) / "corpus"
            empty.mkdir()
            report = evaluate(empty, KNOWLEDGE_DIR, llm_dry_run=False)
            self.assertEqual(report["corpus_status"], "missing")
            self.assertEqual(report["totals"]["denominator"],
                             2 * len(load_cards(KNOWLEDGE_DIR)))
            self.assertGreater(report["totals"]["unknown_categories"], 0)
            self.assertEqual(report["totals"]["true_positive"], 0)
            self.assertEqual(report["totals"]["false_positive"], 0)
            self.assertEqual(report["totals"]["pending"], 0)

    def test_partially_missing_card_is_unknown(self):
        cards = load_cards(KNOWLEDGE_DIR)
        target = cards[0]
        with tempfile.TemporaryDirectory() as td:
            partial = Path(td) / "corpus" / target["corpus_language"]
            partial.mkdir(parents=True)
            src = CORPUS_DIR / target["corpus_language"]
            # Copy only the safe half for the first card.
            for f in src.glob(f"{target['id']}_safe.*"):
                (partial / f.name).write_text(f.read_text(encoding="utf-8"), encoding="utf-8")
            report = evaluate(Path(td) / "corpus", KNOWLEDGE_DIR, llm_dry_run=False)
            cat = report["languages"][target["corpus_language"]]["cards"][target["id"]]
            self.assertEqual(cat["status"], "unknown_missing_corpus")
            self.assertIn(f"{target['corpus_language']}/{target['id']}",
                          report["unknown_categories"])


if __name__ == "__main__":
    unittest.main()
