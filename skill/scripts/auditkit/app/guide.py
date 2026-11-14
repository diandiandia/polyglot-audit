"""Lightweight guide mode for interactive Q&A.

Implements SR-001 / SWR-001 / DSR-032 / DSR-052 / SD-01:
- Answers security inquiries using core methodology and catalog knowledge.
- Strictly does NOT create a run directory, events database, or audit artifacts.
- Prohibits implicit full audit execution on ambiguous queries: a query that is
  empty, too short, or carries no recognizable request verb enters an explicit
  ambiguous state and the guide answers with clarification questions instead of
  executing anything (DSR-032).
"""

# 需求追踪 (Requirement Traceability)
# ---------------------------------------------------------------------------
# 上层需求: docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2
# 设计依据: docs/design/SOFTWARE_DESIGN.md
# SWR-001  guide 模式：不创建正式运行卷宗，模糊请求不静默启动完整审计
#   绑定实现: DSR-032, DSR-052
# 状态以统一测试结论为准；未实测能力保持 unknown（设计原则 8：能观测的不靠声明）。
#

from __future__ import annotations
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from auditkit.knowledge.catalog import KnowledgeCatalog


# Default verb keyword whitelist (DSR-032). Configurable via GuideService
# constructor so hosts can localize or extend it without code changes.
# A query must contain at least one of these keywords to be considered a
# concrete, actionable request.
DEFAULT_VERB_WHITELIST: Tuple[str, ...] = (
    # Chinese request verbs / interrogatives
    "问", "查", "审", "审计", "分析", "看", "讲", "解释", "说明", "评估",
    "检查", "排查", "怎么", "如何", "为什么", "什么", "哪些", "是否", "列出",
    # English request verbs / interrogatives
    "audit", "review", "check", "explain", "analyze", "assess", "inspect",
    "describe", "list", "show", "find", "detect", "fix", "mitigate", "prevent",
    "how", "what", "why", "when", "which", "does", "is", "are", "should",
    "can", "help",
)

# Queries shorter than this (in characters) are treated as too vague to act on.
MIN_QUERY_LENGTH = 8

DEFAULT_CLARIFICATION_QUESTIONS: Tuple[str, ...] = (
    "你想了解哪一种语言或框架（如 Python / Java / Go）？",
    "你想解决什么安全问题（如注入、反序列化、路径逃逸），还是想对某个目录做正式审计？",
    "如果需要正式审计，请提供 --target / --run-dir / --config 并使用 prepare/run 流程。",
)


class GuideService:
    """Answers code security questions without creating runs or touching disks."""

    def __init__(
        self,
        knowledge_root: str | Path,
        verb_whitelist: Optional[Sequence[str]] = None,
        min_query_length: int = MIN_QUERY_LENGTH,
    ) -> None:
        self.catalog = KnowledgeCatalog(knowledge_root)
        self.verb_whitelist = tuple(
            verb.lower() for verb in (verb_whitelist if verb_whitelist is not None else DEFAULT_VERB_WHITELIST)
        )
        self.min_query_length = min_query_length

    # -- DSR-032: ambiguous-request detection --------------------------------

    def classify_query(self, query: str) -> Tuple[str, str]:
        """Classify a query as "ok" or "ambiguous" (with a reason).

        Ambiguous means: empty / whitespace, shorter than min_query_length, or
        containing none of the configured verb keywords. Ambiguous queries are
        never executed; the guide responds with clarification questions.
        """
        q = (query or "").strip()
        if not q:
            return "ambiguous", "empty_query"
        if len(q) < self.min_query_length:
            return "ambiguous", "query_too_short"
        lowered = q.lower()
        if not any(verb in lowered for verb in self.verb_whitelist):
            return "ambiguous", "no_request_verb"
        return "ok", ""

    def clarification_response(self, query: str, reason: str, language: Optional[str] = None) -> Dict[str, Any]:
        """Build the explicit ambiguous-state response (no execution, no cards)."""
        return {
            "mode": "guide",
            "status": "ambiguous",
            "query": query,
            "language": language or "python",
            "ambiguity_reason": reason,
            "guidance": "请求不明确：未执行任何审计动作。请补充说明后再试。",
            "clarification_questions": list(DEFAULT_CLARIFICATION_QUESTIONS),
            "relevant_cards": [],
            "catalog_index": [],
        }

    def answer_query(self, query: str, language: Optional[str] = None) -> Dict[str, Any]:
        """Provide lightweight guidance.

        Ambiguous queries (empty / too short / no verb keyword) return an
        explicit ambiguous state with clarification questions instead of
        executing or silently launching a full audit (DSR-032).
        """
        status, reason = self.classify_query(query)
        if status == "ambiguous":
            return self.clarification_response(query, reason, language=language)

        lang = language or "python"
        index_items = self.catalog.get_language_index(lang)

        # Look for matching cards
        matched_cards = []
        for item in index_items:
            cid = item["id"]
            if cid in query.lower() or item["title"].lower() in query.lower():
                card = self.catalog.get_card(cid)
                if card:
                    matched_cards.append(card)

        return {
            "mode": "guide",
            "status": "ok",
            "query": query,
            "language": lang,
            "guidance": "Guide mode active: no run directory or formal dossier created.",
            "relevant_cards": matched_cards,
            "catalog_index": index_items[:5],
        }
