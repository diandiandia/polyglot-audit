#!/usr/bin/env python3
"""Holdout evaluation tool (DSR-047 / SWR-029).

Runs signal scanning plus an optional LLM-worker dry run over the synthetic
holdout corpus under ``tests/fixtures/holdout/`` and reports, per
language x card:

- true positives   (vulnerable example files that produced >=1 signal hit)
- false negatives  (vulnerable example files with 0 hits)
- true negatives   (safe example files with 0 hits)
- false positives  (safe example files that produced >=1 signal hit)
- pending          (files that could not be classified: read/scan failures,
                    language-signal load errors)
- denominator      (all corpus files that the category SHOULD have)

Categories with missing corpus files or that were not run are reported as
``unknown``. This tool NEVER claims an objective ranking and NEVER claims
full coverage; see the disclaimers embedded in the emitted report.

IMPORTANT holdout-isolation note: the corpus under ``tests/fixtures/holdout/``
is development-time synthetic data DERIVED from ``skill/knowledge/languages/``
(the same snippets that the signals were written against). It therefore
measures wiring and regression, NOT independent generalization. A real
holdout set must be written independently by the maintainers and must not be
used for tuning. See ``tests/holdout/README.md``.

Usage:
    python3 tools/evaluate_holdout.py                 # run evaluation
    python3 tools/evaluate_holdout.py --generate      # (re)build the corpus
    python3 tools/evaluate_holdout.py --out DIR       # report output dir
"""

# 需求追踪 (Requirement Traceability)
# ---------------------------------------------------------------------------
# 上层需求: docs/design/DETAILED_DEVELOPMENT_REQUIREMENTS.md (DSR-047)
# 设计依据: docs/design/SOFTWARE_DESIGN.md
# SWR-029  留出集评测：检出/误报/未决/分母如实统计；缺语料或未运行标 unknown；
#          禁止宣称客观排名或全覆盖。
#   绑定实现: DSR-047
# 状态以统一测试结论为准；未实测能力保持 unknown（设计原则 8：能观测的不靠声明）。
#

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT_DIR = Path(__file__).resolve().parent.parent
SKILL_SCRIPTS = ROOT_DIR / "skill" / "scripts"
KNOWLEDGE_DIR = ROOT_DIR / "skill" / "knowledge"
CORPUS_DIR = ROOT_DIR / "tests" / "fixtures" / "holdout"
DEFAULT_OUT_DIR = ROOT_DIR / "tests" / "holdout" / "reports"

if str(SKILL_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SKILL_SCRIPTS))

from auditkit.inventory.signals import SignalScanner  # noqa: E402

DISCLAIMER = (
    "本报告为开发期合成语料的接线/回归评测，不构成独立留出集结论；"
    "不得据此宣称客观排名、模型能力或全覆盖。正式留出集必须由维护者"
    "独立编写，且在评测前不得参与任何调参。"
)

CARD_FILE_RE = re.compile(r"^[a-z]+-\d+\.json$")
CORPUS_FILE_RE = re.compile(r"^(?P<card>[a-z]+-\d+)_(?P<role>vuln|safe)\.(?P<ext>[^.]+)$")

# Canonical corpus extension per language directory name.
LANGUAGE_EXTENSIONS = {
    "c": "c",
    "cpp": "cpp",
    "csharp": "cs",
    "go": "go",
    "java": "java",
    "javascript": "js",
    "kotlin": "kt",
    "php": "php",
    "python": "py",
    "ruby": "rb",
    "rust": "rs",
    "scala": "scala",
    "shell": "sh",
    "swift": "swift",
    "typescript": "ts",
}

# Line-comment prefix per language (used only for corpus wrapping).
HASH_COMMENT_LANGS = {"python", "shell", "ruby"}
SLASH_COMMENT_LANGS = {
    "c", "cpp", "csharp", "go", "java", "javascript", "typescript",
    "kotlin", "scala", "rust", "swift", "php",
}


# ---------------------------------------------------------------------------
# Corpus generation
# ---------------------------------------------------------------------------

def _comment_prefix(language: str) -> Optional[str]:
    if language in HASH_COMMENT_LANGS:
        return "#"
    if language in SLASH_COMMENT_LANGS:
        return "//"
    return None


def load_cards(knowledge_dir: Path = KNOWLEDGE_DIR) -> List[Dict[str, Any]]:
    """Load all knowledge cards (id, language, snippets, signal ids)."""
    cards: List[Dict[str, Any]] = []
    languages_root = knowledge_dir / "languages"
    if not languages_root.is_dir():
        return cards
    for language in sorted(os.listdir(languages_root)):
        lang_dir = languages_root / language
        if not lang_dir.is_dir():
            continue
        for fname in sorted(os.listdir(lang_dir)):
            if not CARD_FILE_RE.match(fname):
                continue
            try:
                with open(lang_dir / fname, "r", encoding="utf-8") as f:
                    raw = json.load(f)
            except (OSError, ValueError):
                continue
            if not isinstance(raw, dict) or not raw.get("id"):
                continue
            signal_ids = [
                s.get("pattern_id")
                for s in raw.get("signals", [])
                if isinstance(s, dict) and s.get("pattern_id")
            ]
            cards.append({
                "id": raw["id"],
                "language": raw.get("language") or language,
                "corpus_language": language,
                "vuln": raw.get("synthetic_vulnerable_example") or "",
                "safe": raw.get("synthetic_safe_example") or "",
                "signal_ids": signal_ids,
            })
    return cards


def _wrap(card: Dict[str, Any], role: str, snippet: str) -> str:
    language = card["corpus_language"]
    prefix = _comment_prefix(language)
    header = (
        f"holdout corpus entry {card['id']} role={role} "
        "(development-time synthetic; derived from knowledge card)"
    )
    warning = (
        "NOT an independent holdout item; real holdout must be "
        "maintainer-authored. See tests/holdout/README.md"
    )
    lines = []
    for text in (header, warning):
        if prefix:
            lines.append(f"{prefix} {text}")
        else:
            # Unknown comment syntax: fall back to a bare snippet (rare).
            pass
    lines.append(snippet.rstrip("\n"))
    return "\n".join(lines) + "\n"


def generate_corpus(corpus_dir: Path = CORPUS_DIR, knowledge_dir: Path = KNOWLEDGE_DIR) -> Dict[str, Any]:
    """Derive one positive + one negative file per knowledge card."""
    cards = load_cards(knowledge_dir)
    written = 0
    languages_written: Dict[str, int] = {}
    for card in cards:
        language = card["corpus_language"]
        ext = LANGUAGE_EXTENSIONS.get(language)
        if ext is None:
            continue
        out_dir = corpus_dir / language
        out_dir.mkdir(parents=True, exist_ok=True)
        for role, key in (("vuln", "vuln"), ("safe", "safe")):
            snippet = card[key]
            if not str(snippet).strip():
                continue
            path = out_dir / f"{card['id']}_{role}.{ext}"
            path.write_text(_wrap(card, role, str(snippet)), encoding="utf-8")
            written += 1
            languages_written[language] = languages_written.get(language, 0) + 1
    readme = corpus_dir / "README.md"
    readme.write_text(
        "# Holdout fixture corpus (SYNTHETIC, development-time)\n\n"
        "Generated by `tools/evaluate_holdout.py --generate` from "
        "`skill/knowledge/languages/` (one vulnerable + one safe file per "
        "card). Layout: `<language>/<card-id>_{vuln,safe}.<ext>`.\n\n"
        "**Isolation warning:** these files are derived from the same "
        "synthetic snippets the detection signals were authored against, so "
        "they measure pipeline wiring and regression only. They are NOT an "
        "independent holdout set and must never be cited as generalization "
        "evidence. A true holdout corpus must be written independently by "
        "maintainers, kept out of all tuning loops, and versioned separately.\n",
        encoding="utf-8",
    )
    return {"cards": len(cards), "files": written, "languages": languages_written}


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------

def discover_corpus(corpus_dir: Path = CORPUS_DIR) -> Dict[str, Dict[str, Dict[str, Path]]]:
    """Return {language: {card_id: {role: path}}} for corpus files."""
    index: Dict[str, Dict[str, Dict[str, Path]]] = {}
    if not corpus_dir.is_dir():
        return index
    for language in sorted(os.listdir(corpus_dir)):
        lang_dir = corpus_dir / language
        if not lang_dir.is_dir():
            continue
        for fname in sorted(os.listdir(lang_dir)):
            m = CORPUS_FILE_RE.match(fname)
            if not m:
                continue
            entry = index.setdefault(language, {}).setdefault(m.group("card"), {})
            entry[m.group("role")] = lang_dir / fname
    return index


def _scan_one(scanner: SignalScanner, path: Path, language: str) -> Tuple[str, List[Dict[str, Any]], Optional[str]]:
    """Scan a single corpus file. Returns (status, hits, error_detail)."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    except OSError as e:
        return "read_error", [], str(e)
    try:
        hits, _overflow = scanner.scan_file(path.name, lines, language=language)
    except Exception as e:  # defensive: never fabricate results on scanner bugs
        return "scan_error", [], str(e)
    return "ok", hits, None


def evaluate(
    corpus_dir: Path = CORPUS_DIR,
    knowledge_dir: Path = KNOWLEDGE_DIR,
    llm_dry_run: bool = True,
) -> Dict[str, Any]:
    """Run holdout evaluation and return the report dict."""
    cards = load_cards(knowledge_dir)
    corpus = discover_corpus(corpus_dir)
    scanner = SignalScanner(knowledge_dir=knowledge_dir)

    languages: Dict[str, Dict[str, Any]] = {}
    unknown_categories: List[str] = []

    def blank_lang() -> Dict[str, Any]:
        return {
            "cards": {},
            "denominator": 0,
            "true_positive": 0,
            "false_negative": 0,
            "true_negative": 0,
            "false_positive": 0,
            "pending": 0,
            "unknown_cards": 0,
        }

    for card in cards:
        lang = card["corpus_language"]
        card_id = card["id"]
        lang_stat = languages.setdefault(lang, blank_lang())
        category = {
            "denominator": 0,
            "true_positive": 0,
            "false_negative": 0,
            "true_negative": 0,
            "false_positive": 0,
            "pending": 0,
            "detected_by_card_signal": 0,
            "status": "evaluated",
            "detail": [],
        }

        files = corpus.get(lang, {}).get(card_id)
        if not files or "vuln" not in files or "safe" not in files:
            category["status"] = "unknown_missing_corpus"
            category["denominator"] = 2
            unknown_categories.append(f"{lang}/{card_id}")
            lang_stat["unknown_cards"] += 1
            lang_stat["denominator"] += 2
            lang_stat["cards"][card_id] = category
            continue

        for role in ("vuln", "safe"):
            path = files[role]
            category["denominator"] += 1
            status, hits, err = _scan_one(scanner, path, lang)
            if status != "ok":
                category["pending"] += 1
                category["detail"].append({"role": role, "status": status, "error": err})
                continue
            hit_ids = sorted({h["signal_id"] for h in hits})
            if role == "vuln":
                if hits:
                    category["true_positive"] += 1
                    if any(h["signal_id"] in card["signal_ids"] for h in hits):
                        category["detected_by_card_signal"] += 1
                    else:
                        category["detail"].append({
                            "role": role,
                            "note": "detected only by common signals, not by the card's own signal",
                            "signal_ids": hit_ids,
                        })
                else:
                    category["false_negative"] += 1
                    category["detail"].append({"role": role, "note": "no signal hit on vulnerable example"})
            else:  # safe
                if hits:
                    category["false_positive"] += 1
                    category["detail"].append({"role": role, "signal_ids": hit_ids})
                else:
                    category["true_negative"] += 1

        lang_stat["denominator"] += category["denominator"]
        lang_stat["true_positive"] += category["true_positive"]
        lang_stat["false_negative"] += category["false_negative"]
        lang_stat["true_negative"] += category["true_negative"]
        lang_stat["false_positive"] += category["false_positive"]
        lang_stat["pending"] += category["pending"]
        lang_stat["cards"][card_id] = category

    # Language signal-definition load errors are honest coverage gaps.
    signal_load_errors = dict(scanner.language_load_errors)
    for lang, err in signal_load_errors.items():
        if lang in languages:
            languages[lang]["signal_load_error"] = err

    # Cards whose language is absent from the corpus entirely.
    covered_langs = set(languages.keys())
    for card in cards:
        lang = card["corpus_language"]
        if card["id"] not in languages.get(lang, {}).get("cards", {}):
            stat = languages.setdefault(lang, blank_lang())
            stat["unknown_cards"] += 1
            stat["denominator"] += 2
            stat["cards"][card["id"]] = {
                "denominator": 2,
                "true_positive": 0,
                "false_negative": 0,
                "false_positive": 0,
                "pending": 0,
                "detected_by_card_signal": 0,
                "status": "unknown_missing_corpus",
                "detail": [],
            }
            unknown_categories.append(f"{lang}/{card['id']}")

    totals = {
        "denominator": sum(l["denominator"] for l in languages.values()),
        "true_positive": sum(l["true_positive"] for l in languages.values()),
        "false_negative": sum(l["false_negative"] for l in languages.values()),
        "true_negative": sum(l["true_negative"] for l in languages.values()),
        "false_positive": sum(l["false_positive"] for l in languages.values()),
        "pending": sum(l["pending"] for l in languages.values()),
        "unknown_categories": len(unknown_categories),
        "cards_total": len(cards),
    }

    llm = probe_llm_worker() if llm_dry_run else {
        "status": "not_run",
        "llm_results": "unknown",
        "host_clis": {},
        "note": "LLM worker dry run disabled by flag; LLM-side results are unknown",
    }

    return {
        "schema_version": "1.0",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "corpus_dir": str(corpus_dir),
        "knowledge_dir": str(knowledge_dir),
        "corpus_status": "present" if corpus else "missing",
        "totals": totals,
        "languages": languages,
        "unknown_categories": unknown_categories,
        "language_signal_load_errors": signal_load_errors,
        "llm_worker": llm,
        "disclaimer": DISCLAIMER,
        "claims": {
            "objective_ranking": False,
            "full_coverage": False,
            "independent_holdout": False,
            "note": "synthetic development-time corpus; no ranking or coverage claim is made",
        },
    }


def probe_llm_worker() -> Dict[str, Any]:
    """Dry-run the LLM worker path WITHOUT calling any host.

    Detection is limited to PATH lookup for known host CLIs. When no host CLI
    is available the LLM-side evaluation category is explicitly skipped; when
    a CLI is present we still do NOT execute model calls here, so LLM-side
    results remain unknown either way.
    """
    host_clis = {name: bool(shutil.which(name)) for name in ("claude", "codex")}
    available = any(host_clis.values())
    if not available:
        return {
            "status": "skipped_no_host",
            "host_clis": host_clis,
            "note": "no host CLI on PATH; LLM-worker evaluation skipped (unknown, not passed)",
            "llm_results": "unknown",
        }
    return {
        "status": "host_available_dry_run_only",
        "host_clis": host_clis,
        "note": (
            "host CLI detected but no model call is executed by this tool; "
            "LLM-side holdout results remain unknown until a real evaluation run"
        ),
        "llm_results": "unknown",
    }


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def render_markdown(report: Dict[str, Any]) -> str:
    lines: List[str] = []
    lines.append("# Holdout Evaluation Report (synthetic development-time corpus)")
    lines.append("")
    lines.append(f"- Generated: `{report['generated_at']}`")
    lines.append(f"- Corpus: `{report['corpus_dir']}` ({report['corpus_status']})")
    lines.append(f"- Knowledge: `{report['knowledge_dir']}`")
    lines.append(f"- LLM worker: **{report['llm_worker']['status']}** — {report['llm_worker']['note']}")
    lines.append("")
    t = report["totals"]
    lines.append("## Totals")
    lines.append("")
    lines.append("| metric | value |")
    lines.append("|---|---|")
    lines.append(f"| denominator (corpus files) | {t['denominator']} |")
    lines.append(f"| true positive (vuln files with >=1 hit) | {t['true_positive']} |")
    lines.append(f"| false negative (vuln files with 0 hits) | {t['false_negative']} |")
    lines.append(f"| true negative (safe files with 0 hits) | {t['true_negative']} |")
    lines.append(f"| false positive (safe files with >=1 hit) | {t['false_positive']} |")
    lines.append(f"| pending (scan/read errors) | {t['pending']} |")
    lines.append(f"| unknown categories | {t['unknown_categories']} / {t['cards_total']} cards |")
    lines.append("")
    lines.append("## Per language")
    lines.append("")
    lines.append("| language | denominator | TP | FN | TN | FP | pending | unknown cards |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for lang in sorted(report["languages"]):
        l = report["languages"][lang]
        lines.append(
            f"| {lang} | {l['denominator']} | {l['true_positive']} | "
            f"{l.get('false_negative', 0)} | {l.get('true_negative', 0)} | "
            f"{l['false_positive']} | {l['pending']} | {l['unknown_cards']} |"
        )
    lines.append("")
    if report["unknown_categories"]:
        lines.append("## Unknown categories (missing corpus or not run)")
        lines.append("")
        for c in report["unknown_categories"]:
            lines.append(f"- {c} — **unknown**, excluded from all pass claims")
        lines.append("")
    for lang, err in report.get("language_signal_load_errors", {}).items():
        lines.append(f"- language `{lang}` signal load error (category treated as pending/unknown): {err}")
    lines.append("")
    lines.append("## Disclaimers")
    lines.append("")
    lines.append(report["disclaimer"])
    lines.append("")
    lines.append(
        "This report MUST NOT be cited as evidence of objective ranking, "
        "model capability, or full coverage. The corpus is synthetic and "
        "derived from the knowledge cards themselves; the real holdout set "
        "is maintainer-authored and evaluated separately."
    )
    lines.append("")
    return "\n".join(lines)


def write_reports(report: Dict[str, Any], out_dir: Path) -> Tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "holdout_report.json"
    md_path = out_dir / "holdout_report.md"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(report), encoding="utf-8")
    return json_path, md_path


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="DSR-047 holdout evaluation tool")
    parser.add_argument("--generate", action="store_true", help="(re)generate the synthetic corpus and exit")
    parser.add_argument("--corpus", default=str(CORPUS_DIR), help="corpus directory")
    parser.add_argument("--knowledge", default=str(KNOWLEDGE_DIR), help="knowledge directory")
    parser.add_argument("--out", default=str(DEFAULT_OUT_DIR), help="report output directory")
    parser.add_argument("--no-llm-dry-run", action="store_true", help="skip LLM worker dry-run probe")
    args = parser.parse_args(argv)

    if args.generate:
        stats = generate_corpus(Path(args.corpus), Path(args.knowledge))
        print(f"Corpus generated: {stats['cards']} cards, {stats['files']} files")
        for lang, n in sorted(stats["languages"].items()):
            print(f"  {lang}: {n} files")
        return 0

    report = evaluate(Path(args.corpus), Path(args.knowledge), llm_dry_run=not args.no_llm_dry_run)
    json_path, md_path = write_reports(report, Path(args.out))
    t = report["totals"]
    print(f"Holdout evaluation complete: denominator={t['denominator']} "
          f"tp={t['true_positive']} fn={t['false_negative']} tn={t['true_negative']} fp={t['false_positive']} "
          f"pending={t['pending']} unknown={t['unknown_categories']}/{t['cards_total']} cards")
    print(f"Reports: {json_path}")
    print(f"         {md_path}")
    print("NOTE: synthetic development-time corpus; no ranking or coverage claim.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
