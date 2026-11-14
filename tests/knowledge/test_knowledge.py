"""Tests for knowledge catalog, 150 language cards, and admission rules.

SR-002 / DSR-039..043 checks:
- 150 cards exist with all schema fields present.
- Every card is pending per-language expert review (no fabricated
  "Security-Review-Board" reviewer records).
- Card content is substantive and per-card specific (no template sentences).
- Platform conditions are honest: Android-specific Kotlin cards name Android.
- No fabricated internal URLs (security.internal) anywhere in the catalog.
- Signals still hit their card's synthetic vulnerable example.
"""

import json
import re
import unittest
from pathlib import Path

from auditkit.knowledge.admission import CardAdmissionChecker
from auditkit.knowledge.catalog import KnowledgeCatalog


SKILL_DIR = Path("/root/polyglot-audit/skill")
KNOWLEDGE_DIR = SKILL_DIR / "knowledge"

LANGUAGES = [
    "c", "cpp", "csharp", "go", "java", "rust", "python",
    "javascript", "typescript", "kotlin", "scala", "php", "ruby", "swift", "shell"
]

REQUIRED_CARD_FIELDS = [
    "id",
    "title",
    "language",
    "platform_conditions",
    "security_mechanism",
    "source_sink_clues",
    "tracking_guards",
    "not_candidate_when",
    "synthetic_vulnerable_example",
    "synthetic_safe_example",
    "public_references",
    "signals",
    "review_record",
]

# Template sentences from the old single-template generator. None of these
# generic strings may remain in the regenerated cards.
FORBIDDEN_SNIPPETS = [
    "Root cause lies in language semantics",
    "Not a candidate when input is a hardcoded constant",
    "External input from HTTP, CLI, file, or environment",
    "Verify whether bounds, type checks, or sanitizers are applied prior to",
    "Standard Kotlin platform runtime",
    "Security-Review-Board",
]

# Cards for Android-specific APIs must name Android explicitly. These
# card IDs use Android-only platform APIs per LANGUAGE_CATALOG_DRAFT.md.
KOTLIN_ANDROID_CARDS = {
    "kotlin-02",  # exported components / Intent handling
    "kotlin-03",  # getSerializableExtra / getParcelableExtra
    "kotlin-04",  # WebView
    "kotlin-06",  # rawQuery / ContentProvider openFile
    "kotlin-08",  # SharedPreferences / Keystore storage
}


def iter_all_cards():
    for lang in LANGUAGES:
        for path in sorted((KNOWLEDGE_DIR / "languages" / lang).glob("[a-z]*-??.json")):
            with open(path, "r", encoding="utf-8") as f:
                yield lang, json.load(f)


class TestKnowledge(unittest.TestCase):

    def setUp(self):
        self.catalog = KnowledgeCatalog(KNOWLEDGE_DIR)
        self.checker = CardAdmissionChecker()
        self.all_cards = [(lang, card) for lang, card in iter_all_cards()]
        self.cards_by_id = {card["id"]: (lang, card) for lang, card in self.all_cards}

    def test_all_15_languages_have_10_cards(self):
        self.assertEqual(len(LANGUAGES), 15)

        total_cards = 0
        for lang in LANGUAGES:
            idx = self.catalog.get_language_index(lang)
            self.assertEqual(len(idx), 10, f"Language {lang} must have 10 index items, got {len(idx)}")
            cards = self.catalog.get_all_cards_for_language(lang)
            self.assertEqual(len(cards), 10, f"Language {lang} must have 10 card files, got {len(cards)}")
            total_cards += len(cards)

            # Validate each card
            for card in cards:
                ok, errs = self.checker.validate_card(card)
                # SR-002: cards ship as pending_review without a fabricated
                # reviewer. The admission checker still requires a reviewer,
                # so that one expected error is filtered here; every other
                # admission defect must be absent.
                substantive_errors = [e for e in errs if not e.startswith("review_record")]
                self.assertEqual(
                    substantive_errors, [],
                    f"Card {card.get('id')} failed substantive admission checks: {substantive_errors}",
                )
                # The expected pending-review error must actually be the
                # reviewer requirement, not something else about review_record.
                self.assertTrue(
                    all("reviewer and reviewed_at" in e for e in errs if e.startswith("review_record")),
                    f"Card {card.get('id')} has unexpected review_record errors: {errs}",
                )

        self.assertEqual(total_cards, 150)
        self.assertEqual(len(self.cards_by_id), 150, "card IDs must be unique across the catalog")

    def test_cards_have_complete_schema_fields(self):
        for lang, card in self.all_cards:
            for field in REQUIRED_CARD_FIELDS:
                self.assertIn(field, card, f"Card {card['id']} missing field {field}")
                self.assertTrue(card[field], f"Card {card['id']} field {field} is empty")

    def test_cards_are_pending_review_without_fabricated_reviewer(self):
        for lang, card in self.all_cards:
            rev = card["review_record"]
            self.assertEqual(rev.get("status"), "pending_review", f"Card {card['id']}")
            self.assertEqual(
                rev.get("note"), "awaiting per-language expert review", f"Card {card['id']}"
            )
            self.assertNotIn("reviewer", rev, f"Card {card['id']} must not fabricate a reviewer")
            self.assertNotIn("reviewed_at", rev, f"Card {card['id']} must not fabricate a review date")

    def test_no_template_content_or_fabricated_entities_remain(self):
        corpus = json.dumps([card for _, card in self.all_cards], ensure_ascii=False)
        for snippet in FORBIDDEN_SNIPPETS:
            self.assertNotIn(snippet, corpus, f"Template/fabricated string remains: {snippet}")

        # Every card must carry distinct substantive content.
        mechanisms = [card["security_mechanism"] for _, card in self.all_cards]
        self.assertEqual(len(set(mechanisms)), 150, "security_mechanism values must be per-card")
        not_candidates = [card["not_candidate_when"] for _, card in self.all_cards]
        self.assertEqual(len(set(not_candidates)), 150, "not_candidate_when values must be per-card")

        # Per-card substantive length floors (template output was ~1 sentence).
        for _, card in self.all_cards:
            self.assertGreater(len(card["security_mechanism"]), 120, card["id"])
            self.assertGreater(len(card["tracking_guards"]), 40, card["id"])
            self.assertGreater(len(card["not_candidate_when"]), 60, card["id"])

    def test_public_references_cite_real_public_sources(self):
        url_re = re.compile(r"https?://[^\s\]\)\"]+")
        allowed_domains = (
            "cwe.mitre.org", "docs.python.org", "peps.python.org",
            "cheatsheetseries.owasp.org", "nodejs.org", "developer.mozilla.org",
            "docs.oracle.com", "learn.microsoft.com", "pkg.go.dev", "go.dev",
            "php.net", "www.php.net", "docs.ruby-lang.org", "www.ruby-lang.org",
            "developer.android.com", "developer.apple.com", "kotlinlang.org",
            "doc.rust-lang.org", "www.rust-lang.org", "man7.org",
            "en.cppreference.com", "isocpp.github.io", "www.gnu.org",
            "pubs.opengroup.org", "www.typescriptlang.org", "www.scala-lang.org",
            "www.securecoding.cert.org", "owasp.org", "www.oracle.com",
            "serde.rs", "docs.rs", "docs.swift.org", "www.swift.org",
        )
        for lang, card in self.all_cards:
            refs = card["public_references"]
            self.assertTrue(refs, f"Card {card['id']} must cite at least one reference")
            has_cwe = any("CWE-" in r for r in refs)
            self.assertTrue(has_cwe, f"Card {card['id']} must cite a CWE")
            for r in refs:
                for url in url_re.findall(r):
                    self.assertTrue(url.startswith("https://"),
                                    f"Card {card['id']}: non-https URL {url}")
                    domain = url.split("://", 1)[1].split("/", 1)[0]
                    self.assertTrue(
                        any(domain == d or domain.endswith("." + d) for d in allowed_domains),
                        f"Card {card['id']}: URL on non-vetted domain {url}",
                    )

    def test_registry_apis_has_no_internal_urls(self):
        with open(KNOWLEDGE_DIR / "registry" / "apis.json", "r", encoding="utf-8") as f:
            apis = json.load(f)
        self.assertEqual(len(apis), 150)
        corpus = json.dumps(apis)
        self.assertNotIn("security.internal", corpus)
        self.assertNotIn(".internal", corpus)
        for entry in apis:
            if "doc_url" in entry:
                self.assertTrue(entry["doc_url"].startswith("https://"),
                                f"{entry['card_id']}: doc_url must be a public https URL")

    def test_kotlin_android_cards_name_android_platform(self):
        for card_id in KOTLIN_ANDROID_CARDS:
            _, card = self.cards_by_id[card_id]
            self.assertIn("Android", card["platform_conditions"],
                          f"{card_id} platform_conditions must name Android: {card['platform_conditions']}")

    def test_base_language_resolution(self):
        # TypeScript includes JavaScript
        ts_primary, ts_base = self.catalog.get_applicable_indices("typescript")
        self.assertEqual(len(ts_primary), 10)
        self.assertTrue(any("[JAVASCRIPT]" in b for b in ts_base))

        # C++ includes C
        cpp_primary, cpp_base = self.catalog.get_applicable_indices("cpp")
        self.assertEqual(len(cpp_primary), 10)
        self.assertTrue(any("[C]" in b for b in cpp_base))

        # Kotlin on JVM includes Java
        kt_primary, kt_base = self.catalog.get_applicable_indices("kotlin", is_jvm=True)
        self.assertEqual(len(kt_primary), 10)
        self.assertTrue(any("[JAVA]" in b for b in kt_base))

        # Kotlin non-JVM does NOT include Java
        _, kt_non_jvm_base = self.catalog.get_applicable_indices("kotlin", is_jvm=False)
        self.assertEqual(len(kt_non_jvm_base), 0)

    def test_upgrade_admission_rules(self):
        # 2 independent runs succeeds
        ok, reason = self.checker.check_upgrade_admission("py-11", ["run-001", "run-002"])
        self.assertTrue(ok)

        # 1 run fails
        ok, reason = self.checker.check_upgrade_admission("py-11", ["run-001"])
        self.assertFalse(ok)

        # Blocking exception succeeds with rationale
        ok, reason = self.checker.check_upgrade_admission("py-11", ["run-001"], is_blocking_exception=True, blocking_rationale="Crashes parser")
        self.assertTrue(ok)


if __name__ == "__main__":
    unittest.main()
