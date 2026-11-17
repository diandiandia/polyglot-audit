"""Knowledge catalog loader, card indexing, and base language resolution.

Implements DSR-038 / DSR-041 / DSR-042 / SD-02 / DR-014:
- Loads language cards, signals, and indices from skill/knowledge/languages/<lang>/.
- Resolves composite base language indices:
  - TypeScript includes JavaScript index.
  - C++ includes C index.
  - Kotlin/Scala include the Java index ONLY for JVM platforms; with unknown
    platform evidence (is_jvm=None) the Java index is not expanded and the
    packet carries an explicit "platform unknown" note (SR-003 / SD-02).
"""

# 需求追踪 (Requirement Traceability)
# ---------------------------------------------------------------------------
# 上层需求: docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2
# 设计依据: docs/design/SOFTWARE_DESIGN.md
# SWR-002  15×10 语言卡片目录：来源、适用条件、合成正反例；目录是引导不是围栏
#   绑定实现: DSR-038, DSR-077
# SWR-003  平台条件化基座语言：TypeScript 加载 JavaScript；Kotlin/Scala 的 Java 索引仅对 JVM 目标适用
#   绑定实现: DSR-038, DSR-041, DSR-042
# 状态以统一测试结论为准；未实测能力保持 unknown（设计原则 8：能观测的不靠声明）。
#

from __future__ import annotations
import glob
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from auditkit.inventory.languages import get_base_languages


class KnowledgeCatalog:
    """Loads and serves language vulnerability cards and indices.

    Requirements: SWR-002(卡片目录), SWR-003(平台条件) / DSR-038(索引与模板)
    """

    def __init__(self, knowledge_root: str | Path) -> None:
        """Resolve the knowledge root; reads skill assets only, no run state.

        Requirements: SWR-002(support) / DSR-038(support)
        """
        self.knowledge_root = Path(os.path.realpath(os.path.abspath(knowledge_root)))
        self.languages_dir = self.knowledge_root / "languages"
        self._cards_cache: Dict[str, Dict[str, Any]] = {}
        self._indices_cache: Dict[str, List[Dict[str, Any]]] = {}
        self._signals_cache: Dict[str, List[Dict[str, Any]]] = {}

    def get_language_index(self, lang: str) -> List[Dict[str, Any]]:
        """Return 10-item index for a language.

        Requirements: SWR-002(每语言10条目索引) / DSR-038(support)
        """
        if lang in self._indices_cache:
            return self._indices_cache[lang]

        index_file = self.languages_dir / lang / "index.json"
        if not index_file.exists():
            return []

        with open(index_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            self._indices_cache[lang] = data
            return data

    def get_applicable_indices(
        self, lang: str, is_jvm: Optional[bool] = None
    ) -> Tuple[List[str], List[str]]:
        """Return primary language lines and base language lines for prompt packet.

        ``is_jvm`` is three-state (SR-003 / SD-02: state uncertainty when platform
        unknown):
        - True: JVM platform confirmed — Kotlin/Scala expand the Java base index.
        - False: known non-JVM — Kotlin/Scala do NOT expand the Java base index.
        - None (default, unknown): the Java base index is NOT expanded and the
          returned packet lines carry an explicit "platform unknown" note, so
          the omission is disclosed instead of silently assumed.
        For languages without a platform-conditional base (TypeScript, C++, ...)
        the flag has no effect.

        Requirements: SWR-003(平台未知不假设,披露缺口) / DSR-038(TS加JS,Kotlin/Scala条件)
        """
        primary_items = self.get_language_index(lang)
        primary_lines = [
            f"- {item['id']}: {item['title']} (Sink: {item.get('sink_clue', 'N/A')})"
            for item in primary_items
        ]

        base_lines: List[str] = []
        if lang in ("kotlin", "scala") and is_jvm is None:
            base_lines.append(
                "- [PLATFORM UNKNOWN] No JVM build evidence (pom.xml / build.gradle / "
                ".sbt / .mvn) was found in the snapshot; whether this Kotlin/Scala "
                "target runs on a JVM is unknown, so the Java base-language index is "
                "NOT loaded. Java-runtime risks may therefore be missed for this "
                "target and are explicitly not claimed (SR-003 / SD-02)."
            )
        else:
            base_langs = get_base_languages(lang, platform_is_jvm=bool(is_jvm))
            for base in base_langs:
                base_items = self.get_language_index(base)
                for item in base_items:
                    base_lines.append(f"- [{base.upper()}] {item['id']}: {item['title']}")

        return primary_lines, base_lines

    def get_card(self, card_id: str) -> Optional[Dict[str, Any]]:
        """Load card by ID (e.g. py-01, c-03).

        Requirements: SWR-002(按ID取卡,support) / DSR-038(support)
        """
        if card_id in self._cards_cache:
            return self._cards_cache[card_id]

        # Scan card files
        for card_path in glob.glob(str(self.languages_dir / "*" / f"{card_id}.json")):
            with open(card_path, "r", encoding="utf-8") as f:
                card = json.load(f)
                self._cards_cache[card_id] = card
                return card

        return None

    def get_all_cards_for_language(self, lang: str) -> List[Dict[str, Any]]:
        """Load all 10 cards for a language.

        Requirements: SWR-002(每语言10卡) / DSR-038(support)
        """
        cards = []
        lang_dir = self.languages_dir / lang
        if not lang_dir.exists():
            return []

        for card_path in sorted(glob.glob(str(lang_dir / "*.json"))):
            fname = os.path.basename(card_path)
            if fname in ("index.json", "signals.json"):
                continue
            with open(card_path, "r", encoding="utf-8") as f:
                cards.append(json.load(f))
        return cards

    def get_signals_for_language(self, lang: str) -> List[Dict[str, Any]]:
        """Return regex signal rules defined for language.

        Requirements: SWR-002(关联扫描信号) / DSR-038(support)
        """
        if lang in self._signals_cache:
            return self._signals_cache[lang]

        sig_file = self.languages_dir / lang / "signals.json"
        if not sig_file.exists():
            return []

        with open(sig_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            self._signals_cache[lang] = data
            return data
