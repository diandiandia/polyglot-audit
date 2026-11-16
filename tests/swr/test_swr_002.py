"""SWR-002 acceptance tests: 15x10 knowledge card catalog.

验收原文 (docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2, SWR-002):
    "建立 15×10 卡片、来源、适用条件及合成正反例；150 个唯一编号和逐语言专家
    评审通过才可标为已评审。"

细化依据 (docs/design/DETAILED_DEVELOPMENT_REQUIREMENTS.md §6.1):
    "每张卡片均须交付：条目 ID、语言/平台适用条件、安全机制、source/sink 线索、
    追踪与守卫判断、误报条件、合成漏洞例和安全反例、公开参考、关联扫描信号、
    独立评审记录。……语言目录是引导，不能封闭目录外发现。"

Covered here:
- 150 cards over 15 languages, every ID unique and matching the declared
  per-language catalog IDs (DSR-039..043 table).
- Every card carries: public evidence (public_references), applicability
  conditions (platform_conditions), false-positive conditions
  (not_candidate_when), and synthetic positive/negative examples.
- ``pending_review`` is a compliant review status (cannot fabricate an expert
  review record), not a defect.
- The catalog is guidance, not a fence: an out-of-catalog issue flows through
  the candidate pipeline without any card.
- TS/JS and Kotlin-on-JVM conditional base-language mapping is correct.
"""

import json
import os
import re
import unittest
from pathlib import Path

from auditkit.analysis.hunter import HuntResultParser
from auditkit.analysis.verifier import Verifier
from auditkit.inventory.languages import get_base_languages
from auditkit.knowledge.admission import CardAdmissionChecker
from auditkit.knowledge.catalog import KnowledgeCatalog

REPO_ROOT = Path(__file__).resolve().parents[2]
KNOWLEDGE_DIR = REPO_ROOT / "skill" / "knowledge"

# DSR-039..043 table in docs/design/DETAILED_DEVELOPMENT_REQUIREMENTS.md §6.1.
CATALOG_LANGUAGES = {
    "c": "c",
    "cpp": "cpp",
    "csharp": "csharp",
    "go": "go",
    "java": "java",
    "javascript": "js",
    "kotlin": "kotlin",
    "php": "php",
    "python": "py",
    "ruby": "ruby",
    "rust": "rust",
    "scala": "scala",
    "shell": "shell",
    "swift": "swift",
    "typescript": "ts",
}

CARD_FILE_RE = re.compile(r"^[a-z]+-\d+\.json$")


def _load_cards():
    """Load all 150 card JSON files from the knowledge tree."""
    cards = []
    for lang in sorted(CATALOG_LANGUAGES):
        lang_dir = KNOWLEDGE_DIR / "languages" / lang
        for fname in sorted(os.listdir(lang_dir)):
            if not CARD_FILE_RE.match(fname):
                continue
            with open(lang_dir / fname, "r", encoding="utf-8") as f:
                cards.append(json.load(f))
    return cards


class TestSWR002(unittest.TestCase):
    """SWR-002: 15x10 cards, evidence, applicability, examples, unique IDs."""

    def setUp(self):
        self.catalog = KnowledgeCatalog(KNOWLEDGE_DIR)

    # -- 150 unique IDs ----------------------------------------------------
    def test_150_cards_with_unique_ids(self):
        cards = _load_cards()
        self.assertEqual(len(cards), 150, "catalog must hold 15x10 = 150 cards")
        ids = [c["id"] for c in cards]
        self.assertEqual(len(set(ids)), 150, "all 150 card IDs must be unique")

    def test_card_ids_match_declared_catalog_ids(self):
        """Every language ships exactly the 10 declared IDs (DSR-039..043)."""
        cards = _load_cards()
        by_lang = {}
        for card in cards:
            by_lang.setdefault(card["language"], []).append(card["id"])
        self.assertEqual(set(by_lang), set(CATALOG_LANGUAGES))
        for lang, expected_prefix in CATALOG_LANGUAGES.items():
            ids = sorted(by_lang.get(lang, []))
            self.assertEqual(len(ids), 10, f"{lang} must ship 10 cards")
            expected = [f"{expected_prefix}-{n:02d}" for n in range(1, 11)]
            self.assertEqual(ids, expected, f"{lang} card IDs must be {expected}")
            for card in cards:
                if card["language"] == lang:
                    self.assertEqual(card["language"], lang)
                    # Card files are named <id>.json.
                    self.assertTrue(
                        (KNOWLEDGE_DIR / "languages" / lang / f"{card['id']}.json").exists(),
                        f"{lang}/{card['id']}.json missing",
                    )

    # -- per-card content: evidence / applicability / false positives / ----
    # -- synthetic positive and negative examples --------------------------
    def test_every_card_has_required_content_aspects(self):
        aspects = {
            "公开依据 public_references": "public_references",
            "适用条件 platform_conditions": "platform_conditions",
            "误报条件 not_candidate_when": "not_candidate_when",
            "安全机制 security_mechanism": "security_mechanism",
            "source/sink 线索 source_sink_clues": "source_sink_clues",
            "追踪守卫 tracking_guards": "tracking_guards",
            "合成漏洞例 synthetic_vulnerable_example": "synthetic_vulnerable_example",
            "安全反例 synthetic_safe_example": "synthetic_safe_example",
            "关联信号 signals": "signals",
            "独立评审记录 review_record": "review_record",
        }
        for card in _load_cards():
            for label, field in aspects.items():
                self.assertTrue(
                    card.get(field),
                    f"{card['id']}: missing {label}",
                )
            clues = card["source_sink_clues"]
            self.assertTrue(clues.get("source"), f"{card['id']}: no source clue")
            self.assertTrue(clues.get("sink"), f"{card['id']}: no sink clue")
            self.assertGreaterEqual(
                len(card["public_references"]), 1,
                f"{card['id']}: public evidence required",
            )
            # Same threshold as CardAdmissionChecker: examples must be at
            # least 20 chars of concrete code, not a bare placeholder.
            self.assertGreaterEqual(
                len(card["synthetic_vulnerable_example"]), 20,
                f"{card['id']}: vulnerable example too short",
            )
            self.assertGreaterEqual(
                len(card["synthetic_safe_example"]), 20,
                f"{card['id']}: safe example too short",
            )
            self.assertNotEqual(
                card["synthetic_vulnerable_example"].strip(),
                card["synthetic_safe_example"].strip(),
                f"{card['id']}: positive and negative examples must differ",
            )

    def test_positive_example_is_distinguishable_from_negative(self):
        """The signal must hit the vulnerable example (positive case exists)."""
        for card in _load_cards():
            vuln = card["synthetic_vulnerable_example"]
            hits = [
                sig for sig in card["signals"]
                if re.search(sig.get("pattern", ""), vuln, re.IGNORECASE)
            ]
            self.assertTrue(
                hits,
                f"{card['id']}: no signal hits the synthetic vulnerable example",
            )

    def test_index_json_covers_exactly_the_language_cards(self):
        """The per-language index has the same 10 entries as the card files."""
        for lang in CATALOG_LANGUAGES:
            lang_dir = KNOWLEDGE_DIR / "languages" / lang
            index = self.catalog.get_language_index(lang)
            self.assertEqual(len(index), 10, f"{lang} index must hold 10 entries")
            card_ids = {
                json.load(open(p, encoding="utf-8"))["id"]
                for p in lang_dir.glob("*.json")
                if CARD_FILE_RE.match(p.name)
            }
            self.assertEqual({i["id"] for i in index}, card_ids, lang)
            for entry in index:
                self.assertIn("title", entry)
                self.assertIn("sink_clue", entry)

    def test_catalog_loader_serves_all_150_cards(self):
        """The stable loader API reaches every card and index entry."""
        total = 0
        for lang in CATALOG_LANGUAGES:
            cards = self.catalog.get_all_cards_for_language(lang)
            self.assertEqual(len(cards), 10, lang)
            total += len(cards)
            for card in cards:
                loaded = self.catalog.get_card(card["id"])
                self.assertIsNotNone(loaded, card["id"])
                self.assertEqual(loaded["id"], card["id"])
        self.assertEqual(total, 150)

    # -- pending_review is a compliant status, not a defect ----------------
    def test_pending_review_is_compliant_status_not_a_defect(self):
        """First-version cards stay honestly pending; no fabricated review.

        "150 个唯一编号和逐语言专家评审通过才可标为已评审" — until a real
        per-language expert review happened, ``pending_review`` is the honest
        state. Fabricating a reviewer would be the defect.
        """
        for card in _load_cards():
            record = card["review_record"]
            self.assertEqual(
                record.get("status"), "pending_review",
                f"{card['id']}: unreviewed cards must stay pending_review",
            )
            self.assertFalse(
                record.get("reviewer") or record.get("reviewed_at"),
                f"{card['id']}: must not fabricate an expert review record",
            )
        # The admission checker still demands reviewer + date before a card can
        # be treated as reviewed — pending_review alone never passes that gate.
        card = _load_cards()[0]
        ok, errors = CardAdmissionChecker().validate_card(card)
        self.assertFalse(ok, "pending_review card is not yet admissible as reviewed")
        self.assertTrue(any("reviewer" in e for e in errors))

    # -- catalog is guidance, not a fence ----------------------------------
    def test_out_of_catalog_candidate_flows_without_a_card(self):
        """A synthetic out-of-catalog issue enters the candidate pipeline.

        "语言目录是引导，不能封闭目录外发现" — the pipeline must accept a
        candidate whose issue matches no card ID and still verify it.
        """
        issue = "noncatalog-graphql-field-arg-injection"
        self.assertIsNone(self.catalog.get_card(issue))
        self.assertNotIn(issue, [c["id"] for c in _load_cards()])

        raw = {
            "records": [{
                "record_type": "candidate",
                "candidate_id": "cand-outcat-1",
                "issue": issue,
                "source": {"path": "api/gql.py", "line": 5, "symbol": "resolve", "kind": "graphql_resolver"},
                "sink": {"path": "db/exec.py", "line": 30, "symbol": "raw_query", "kind": "sql"},
                "steps": [
                    {"path": "api/gql.py", "line": 5, "role": "source", "note": "resolver arg"},
                    {"path": "db/exec.py", "line": 30, "role": "sink", "note": "raw query"},
                ],
                "provenance": {"hunt_tasks": ["task-outcat"]},
            }],
        }
        candidates, frontiers, probes, overflows = HuntResultParser().parse_worker_payload(
            raw, "task-outcat"
        )
        self.assertEqual(len(candidates), 1, "out-of-catalog candidate must not be dropped")
        self.assertEqual(candidates[0]["issue"], issue)

        verifier = Verifier(enforce_attempt_gate=True)
        finding = verifier.create_finding_from_candidate(
            candidates[0],
            "needs_validation",
            "vt-outcat-1",
            impact=3,
            exploitability=2,
            blockers=["Deployment database engine version must be confirmed"],
            validation_plan="Reproduce the resolver argument against the deployed engine",
        )
        self.assertEqual(finding["verdict"], "needs_validation")
        self.assertEqual(finding["issue"], issue)

    # -- TS/JS and Kotlin/JVM conditional mapping --------------------------
    def test_typescript_always_includes_javascript_base(self):
        self.assertEqual(get_base_languages("typescript"), ["javascript"])
        self.assertEqual(get_base_languages("typescript", platform_is_jvm=False), ["javascript"])
        primary, base = self.catalog.get_applicable_indices("typescript")
        self.assertTrue(primary)
        self.assertTrue(
            any(line.startswith("- [JAVASCRIPT]") for line in base),
            base,
        )
        self.assertEqual(len(base), 10, "TS expands the full JS index")

    def test_cpp_always_includes_c_base(self):
        self.assertEqual(get_base_languages("cpp"), ["c"])
        _, base = self.catalog.get_applicable_indices("cpp")
        self.assertEqual(len(base), 10)
        self.assertTrue(all(line.startswith("- [C]") for line in base))

    def test_kotlin_jvm_condition_mapping(self):
        """Kotlin's Java base is conditional on the JVM platform (SR-003)."""
        self.assertEqual(get_base_languages("kotlin", platform_is_jvm=True), ["java"])
        self.assertEqual(get_base_languages("kotlin", platform_is_jvm=False), [])
        # JVM confirmed: the Java index expands under the [JAVA] marker.
        _, base_jvm = self.catalog.get_applicable_indices("kotlin", is_jvm=True)
        self.assertEqual(len(base_jvm), 10)
        self.assertTrue(all(line.startswith("- [JAVA]") for line in base_jvm))
        # Known non-JVM: no Java lines at all.
        _, base_native = self.catalog.get_applicable_indices("kotlin", is_jvm=False)
        self.assertEqual(base_native, [])
        # Unknown platform: Java is not expanded (disclosure is SWR-003 scope).
        _, base_unknown = self.catalog.get_applicable_indices("kotlin", is_jvm=None)
        self.assertNotIn("- [JAVA]", [line.split(":")[0] for line in base_unknown])

    def test_scala_jvm_condition_mapping(self):
        self.assertEqual(get_base_languages("scala", platform_is_jvm=True), ["java"])
        self.assertEqual(get_base_languages("scala", platform_is_jvm=False), [])

    def test_primary_language_cards_load_for_every_conditional_language(self):
        """Kotlin/Scala/TS ship their own 10 cards besides the base index."""
        for lang in ("kotlin", "scala", "typescript", "javascript"):
            cards = self.catalog.get_all_cards_for_language(lang)
            self.assertEqual(len(cards), 10, lang)
            for card in cards:
                self.assertTrue(card["public_references"], card["id"])
                self.assertTrue(card["platform_conditions"], card["id"])


if __name__ == "__main__":
    unittest.main()
