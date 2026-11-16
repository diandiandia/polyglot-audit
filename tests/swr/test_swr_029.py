"""SWR-029 acceptance tests (逐编号验收).

验收原文 (docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2):
    SWR-029 | SR-029 → SD-10 | P4／SWR-002、SWR-010、SWR-022、SWR-026 |
    建立合成和隔离留出评测及双宿主运行记录；发布各语言、跨单元的分母、
    检出、误报、未决与成本，不伪造缺失结果。

上游系统需求 (SYSTEM_REQUIREMENTS.md §2):
    SR-029: 留出评测按语言×卡片发布分母、TP/FN/TN/FP、未决与成本；
    缺失语料或未运行的类别如实标 unknown，不伪造结果、不宣称客观排名。

Acceptance coverage
-------------------
1. 分类口径: TP(有命中的漏洞样本) / FN(无命中的漏洞样本) / TN(无命中的
   安全样本) / FP(有命中的安全样本) / pending(读取或扫描失败) 逐格判定,
   且分母闭合: 每卡片 tp+fn+tn+fp+pending == 卡片分母; 语言汇总 == 卡片
   求和; 总分母 == 已评测 + 缺语料保留位 (每卡 2)。
2. 缺语料 / 未运行标 unknown: 空语料 → corpus_status missing, 全部卡片
   unknown_missing_corpus 且分母保留 2/卡, 分类计数保持零 (不伪造);
   半缺 (只有 vuln 无 safe) 的卡片同样 unknown。
3. claims 块断言: objective_ranking / full_coverage / independent_holdout
   全为 False; 免责声明进入 JSON 报告与 Markdown 渲染, 且 Markdown 明文
   禁止引用为排名/能力/全覆盖证据。
4. 双宿主记录单列: probe_llm_worker 在有/无宿主 CLI 两种情况下都单列
   host_clis 记录 (claude/codex) 且 llm_results == "unknown"; 关闭 dry-run
   时 LLM 侧保持未运行语义, 不得宣称模型侧结果。
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SKILL_SCRIPTS = REPO_ROOT / "skill" / "scripts"
for p in (SKILL_SCRIPTS, REPO_ROOT):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from tools.evaluate_holdout import (  # noqa: E402
    CORPUS_DIR,
    KNOWLEDGE_DIR,
    discover_corpus,
    evaluate,
    load_cards,
    probe_llm_worker,
    render_markdown,
)

# Import the module by file path (same technique as tests/holdout) so script
# entry points like write_reports stay usable here.
_TOOL_PATH = REPO_ROOT / "tools" / "evaluate_holdout.py"
_spec = importlib.util.spec_from_file_location("evaluate_holdout_swr029", _TOOL_PATH)
_tool_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_tool_mod)


def one_card():
    cards = load_cards(KNOWLEDGE_DIR)
    return cards[0]


def corpus_entry(card, role):
    entry = discover_corpus(CORPUS_DIR).get(card["corpus_language"], {}).get(card["id"], {})
    return entry.get(role)


class TestSWR029ClassificationAndClosure(unittest.TestCase):
    """TP/FN/TN/FP/pending 判定与分母闭合。"""

    @classmethod
    def setUpClass(cls):
        # Deterministic fixture card: the first card whose real vulnerable
        # example produces >=1 signal hit AND whose real safe example produces
        # none (TP/TN ground truth for the classification wiring).
        cards = load_cards(KNOWLEDGE_DIR)
        corpus = discover_corpus(CORPUS_DIR)
        cls.card = None
        for card in cards:
            entry = corpus.get(card["corpus_language"], {}).get(card["id"], {})
            if "vuln" not in entry or "safe" not in entry:
                continue
            vuln_hits = cls._hit_count(entry["vuln"], card["corpus_language"])
            safe_hits = cls._hit_count(entry["safe"], card["corpus_language"])
            if vuln_hits > 0 and safe_hits == 0:
                cls.card = card
                cls.vuln_path, cls.safe_path = entry["vuln"], entry["safe"]
                break
        cls.assertIsNotNone(
            cls.card, "no card with a hitting vuln example and a clean safe example"
        )

    @staticmethod
    def _hit_count(path: Path, language: str) -> int:
        from auditkit.inventory.signals import SignalScanner
        scanner = SignalScanner(knowledge_dir=KNOWLEDGE_DIR)
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        hits, _overflow = scanner.scan_file(path.name, lines, language=language)
        return len(hits)

    def _lang_dir(self, tmp: Path) -> Path:
        lang_dir = tmp / "corpus" / self.card["corpus_language"]
        lang_dir.mkdir(parents=True)
        return lang_dir

    def _ext(self) -> str:
        return self.vuln_path.suffix.lstrip(".")

    def _copy(self, src: Path, lang_dir: Path, card_id: str, role: str) -> None:
        shutil.copy(src, lang_dir / f"{card_id}_{role}.{self._ext()}")

    def test_tp_and_tn_classified_by_role(self):
        """TP = 有命中的漏洞样本; TN = 无命中的安全样本。"""
        with tempfile.TemporaryDirectory() as td:
            lang_dir = self._lang_dir(Path(td))
            self._copy(self.vuln_path, lang_dir, self.card["id"], "vuln")
            self._copy(self.safe_path, lang_dir, self.card["id"], "safe")
            report = evaluate(Path(td) / "corpus", KNOWLEDGE_DIR, llm_dry_run=False)
            card = report["languages"][self.card["corpus_language"]]["cards"][self.card["id"]]
            self.assertEqual(card["status"], "evaluated")
            self.assertEqual(card["true_positive"], 1, "vuln sample with hits is TP")
            self.assertEqual(card["true_negative"], 1, "safe sample without hits is TN")
            self.assertEqual(card["false_negative"], 0)
            self.assertEqual(card["false_positive"], 0)
            # Detection is attributable to the card's own signal.
            self.assertGreaterEqual(card["detected_by_card_signal"], 1)

    def test_fn_is_vuln_named_file_without_hits(self):
        """FN = 无命中的漏洞样本 (漏洞命名文件带无命中内容)。"""
        with tempfile.TemporaryDirectory() as td:
            lang_dir = self._lang_dir(Path(td))
            # vuln-named file carrying the (verified clean) safe snippet.
            shutil.copy(self.safe_path, lang_dir / f"{self.card['id']}_vuln.{self._ext()}")
            self._copy(self.safe_path, lang_dir, self.card["id"], "safe")
            report = evaluate(Path(td) / "corpus", KNOWLEDGE_DIR, llm_dry_run=False)
            card = report["languages"][self.card["corpus_language"]]["cards"][self.card["id"]]
            self.assertEqual(card["false_negative"], 1)
            self.assertEqual(card["true_positive"], 0)
            # The FN records why (queryable evidence), never a silent drop.
            self.assertTrue(any(d.get("role") == "vuln" for d in card["detail"]))

    def test_fp_is_safe_named_file_with_hits(self):
        """FP = 有命中的安全样本 (安全命名文件携带命中内容)。"""
        with tempfile.TemporaryDirectory() as td:
            lang_dir = self._lang_dir(Path(td))
            self._copy(self.vuln_path, lang_dir, self.card["id"], "vuln")
            # safe-named file carrying the (known-hitting) vuln snippet.
            shutil.copy(self.vuln_path, lang_dir / f"{self.card['id']}_safe.{self._ext()}")
            report = evaluate(Path(td) / "corpus", KNOWLEDGE_DIR, llm_dry_run=False)
            card = report["languages"][self.card["corpus_language"]]["cards"][self.card["id"]]
            self.assertEqual(card["false_positive"], 1)
            self.assertEqual(card["true_positive"], 1)
            self.assertTrue(
                any(d.get("role") == "safe" and d.get("signal_ids") for d in card["detail"]),
                "the FP must record which signals fired",
            )

    def test_pending_counts_unclassifiable_files(self):
        with tempfile.TemporaryDirectory() as td:
            lang_dir = self._lang_dir(Path(td))
            self._copy(self.vuln_path, lang_dir, self.card["id"], "vuln")
            # An unreadable corpus entry (directory) → pending, never a
            # fabricated classification.
            (lang_dir / f"{self.card['id']}_safe.{self._ext()}").mkdir()
            report = evaluate(Path(td) / "corpus", KNOWLEDGE_DIR, llm_dry_run=False)
            card = report["languages"][self.card["corpus_language"]]["cards"][self.card["id"]]
            self.assertEqual(card["pending"], 1)
            self.assertEqual(card["true_positive"] + card["false_negative"]
                             + card["true_negative"] + card["false_positive"], 1)
            self.assertTrue(card["detail"])
            self.assertIn(card["detail"][0]["status"], ("read_error", "scan_error"))

    def test_denominator_closes_at_card_language_and_total(self):
        with tempfile.TemporaryDirectory() as td:
            lang_dir = self._lang_dir(Path(td))
            self._copy(self.vuln_path, lang_dir, self.card["id"], "vuln")
            (lang_dir / f"{self.card['id']}_safe.{self._ext()}").mkdir()  # pending

            report = evaluate(Path(td) / "corpus", KNOWLEDGE_DIR, llm_dry_run=False)
            # Card level.
            for lang_stat in report["languages"].values():
                evaluated = reserved = 0
                for c in lang_stat["cards"].values():
                    accounted = (c["true_positive"] + c.get("false_negative", 0)
                                 + c.get("true_negative", 0) + c["false_positive"]
                                 + c["pending"])
                    if c["status"] == "evaluated":
                        self.assertEqual(
                            accounted, c["denominator"],
                            "card classification must cover its whole denominator",
                        )
                        evaluated += accounted
                    else:
                        self.assertEqual(accounted, 0, "unknown cards fabricate results")
                        reserved += c["denominator"]
                # Language level.
                self.assertEqual(evaluated + reserved, lang_stat["denominator"])
                summed = (lang_stat["true_positive"] + lang_stat.get("false_negative", 0)
                          + lang_stat.get("true_negative", 0) + lang_stat["false_positive"]
                          + lang_stat["pending"])
                self.assertEqual(summed, evaluated, "language totals must equal card sums")
            # Global level: evaluated files + 2 slots per unknown card.
            t = report["totals"]
            self.assertEqual(
                t["true_positive"] + t["false_negative"] + t["true_negative"]
                + t["false_positive"] + t["pending"],
                t["denominator"] - 2 * t["unknown_categories"],
            )

    def test_per_language_rows_are_published(self):
        """SR-029: per-language denominators/detection/FP/pending are published
        in the rendered report, not just buried in JSON."""
        with tempfile.TemporaryDirectory() as td:
            lang_dir = self._lang_dir(Path(td))
            self._copy(self.vuln_path, lang_dir, self.card["id"], "vuln")
            self._copy(self.safe_path, lang_dir, self.card["id"], "safe")
            report = evaluate(Path(td) / "corpus", KNOWLEDGE_DIR, llm_dry_run=False)
            md = render_markdown(report)
            lang = self.card["corpus_language"]
            self.assertRegex(md, rf"\|\s*{lang}\s*\|")
            for column in ("denominator", "TP", "FN", "TN", "FP", "pending"):
                self.assertIn(column, md)


class TestSWR029UnknownSemantics(unittest.TestCase):
    """缺语料 / 未运行标 unknown, 不伪造缺失结果。"""

    @classmethod
    def setUpClass(cls):
        cls.card = one_card()

    def test_empty_corpus_is_missing_and_all_categories_unknown(self):
        with tempfile.TemporaryDirectory() as td:
            corpus = Path(td) / "corpus"
            corpus.mkdir()
            report = evaluate(corpus, KNOWLEDGE_DIR, llm_dry_run=False)
            self.assertEqual(report["corpus_status"], "missing")
            n_cards = len(load_cards(KNOWLEDGE_DIR))
            self.assertEqual(report["totals"]["unknown_categories"], n_cards)
            self.assertEqual(report["totals"]["denominator"], 2 * n_cards)
            # No fabricated results for the missing corpus:
            self.assertEqual(report["totals"]["true_positive"], 0)
            self.assertEqual(report["totals"]["false_positive"], 0)
            self.assertEqual(report["totals"]["pending"], 0)
            # The unknown categories are listed and excluded from pass claims.
            self.assertIn(f"{self.card['corpus_language']}/{self.card['id']}",
                          report["unknown_categories"])
            md = render_markdown(report)
            self.assertIn("Unknown categories", md)
            self.assertIn("excluded from all pass claims", md)

    def test_card_missing_one_role_is_unknown_not_partially_scored(self):
        with tempfile.TemporaryDirectory() as td:
            corpus = Path(td) / "corpus" / self.card["corpus_language"]
            corpus.mkdir(parents=True)
            src = corpus_entry(self.card, "vuln")
            shutil.copy(src, corpus / src.name)  # vuln only; safe missing
            report = evaluate(Path(td) / "corpus", KNOWLEDGE_DIR, llm_dry_run=False)
            card = report["languages"][self.card["corpus_language"]]["cards"][self.card["id"]]
            self.assertEqual(card["status"], "unknown_missing_corpus")
            self.assertEqual(card["denominator"], 2)
            self.assertEqual(card["true_positive"] + card["false_positive"]
                             + card["pending"], 0)
            self.assertIn(f"{self.card['corpus_language']}/{self.card['id']}",
                          report["unknown_categories"])

    def test_language_signal_load_error_is_recorded(self):
        """A language whose signal definitions fail to load stays recorded as
        an honest coverage gap instead of silently scoring zero."""
        with tempfile.TemporaryDirectory() as td:
            knowledge = Path(td) / "knowledge"
            shutil.copytree(KNOWLEDGE_DIR, knowledge)
            signals = knowledge / "languages" / self.card["corpus_language"] / "signals.json"
            signals.write_text("{ not valid json", encoding="utf-8")
            corpus = Path(td) / "corpus"
            # Copy this card's corpus entry so the scan is attempted at all.
            lang_dir = corpus / self.card["corpus_language"]
            lang_dir.mkdir(parents=True)
            for role in ("vuln", "safe"):
                shutil.copy(corpus_entry(self.card, role), lang_dir / Path(corpus_entry(self.card, role)).name)
            report = evaluate(corpus, knowledge, llm_dry_run=False)
            self.assertIn(
                self.card["corpus_language"],
                report["language_signal_load_errors"],
                "signal load failure must be disclosed per language",
            )


class TestSWR029Claims(unittest.TestCase):
    """不宣称客观排名 / 全覆盖 / 独立留出。"""

    def test_claims_block_asserts_no_ranking_no_coverage_no_independence(self):
        report = evaluate(CORPUS_DIR, KNOWLEDGE_DIR, llm_dry_run=False)
        claims = report["claims"]
        self.assertFalse(claims["objective_ranking"])
        self.assertFalse(claims["full_coverage"])
        self.assertFalse(claims["independent_holdout"])
        self.assertTrue(report["disclaimer"].strip())

    def test_disclaimer_is_carried_into_both_media(self):
        report = evaluate(CORPUS_DIR, KNOWLEDGE_DIR, llm_dry_run=False)
        md = render_markdown(report)
        self.assertIn(report["disclaimer"], md)
        self.assertIn("MUST NOT be cited", md)
        self.assertIn("objective ranking", md)
        # The isolation warning is present in the corpus itself and the tool
        # is explicit that this is development-time synthetic data.
        self.assertIn("synthetic", md)


class TestSWR029DualHostRecord(unittest.TestCase):
    """双宿主运行记录单列, LLM 侧结果保持 unknown。"""

    def test_probe_single_lists_both_host_clis_and_unknown_results(self):
        probe = probe_llm_worker()
        self.assertIn(probe["status"], ("skipped_no_host", "host_available_dry_run_only"))
        # Dual-host record: a single entry listing each known host CLI.
        self.assertEqual(sorted(probe["host_clis"]), ["claude", "codex"])
        self.assertTrue(all(isinstance(v, bool) for v in probe["host_clis"].values()))
        # Whether or not a CLI is present, NO model results are claimed here.
        self.assertEqual(probe["llm_results"], "unknown")

    def test_dry_run_disabled_states_not_run_honestly(self):
        report = evaluate(CORPUS_DIR, KNOWLEDGE_DIR, llm_dry_run=False)
        llm = report["llm_worker"]
        self.assertEqual(llm["status"], "not_run")
        self.assertIn("unknown", llm["note"])
        self.assertFalse(llm.get("host_clis"), "no host results may be claimed when not run")

    def test_not_run_mode_carries_llm_results_unknown_marker(self):
        """PROD-BUG fixed (200e533 后续合流): the not_run branch now carries
        llm_results="unknown" like the two dry-run branches."""
        report = evaluate(CORPUS_DIR, KNOWLEDGE_DIR, llm_dry_run=False)
        self.assertEqual(report["llm_worker"].get("llm_results"), "unknown")


if __name__ == "__main__":
    unittest.main()
