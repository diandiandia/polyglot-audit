"""Candidate fingerprinting and reversible deduplication suggestions.

Implements DSR-063 / SD-04 / REV-06:
- Computes stable fingerprints based on (issue, sink_path, sink_symbol, source_kind).
- Explicitly prevents irreversible merging of candidates with distinct sources into the same sink.
- Retains original candidate records and provenance links.
- Merging is gated: propose_deduplication() only suggests; confirm_merge()
  executes and records who confirmed it, keeping the original candidate
  record for traceability.
"""

# 需求追踪 (Requirement Traceability)
# ---------------------------------------------------------------------------
# 上层需求: docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2
# 设计依据: docs/design/SOFTWARE_DESIGN.md
# SWR-007  指纹只生成去重建议；保留原始记录与 source 区别，合并需确认且可回溯
#   绑定实现: DSR-063
# 状态以统一测试结论为准；未实测能力保持 unknown（设计原则 8：能观测的不靠声明）。
#

from __future__ import annotations
import hashlib
from typing import Any, Dict, List, Set, Tuple

from auditkit.contracts.errors import InvalidInputError, InvalidStateError


def compute_fingerprint(candidate: Dict[str, Any]) -> str:
    """Compute stable fingerprint for candidate.

    Excludes line numbers so minor formatting changes don't fracture identity.
    Includes source kind, sink path, sink symbol, issue.
    """
    issue = candidate.get("issue", "")
    source = candidate.get("source", {})
    sink = candidate.get("sink", {})

    s_kind = source.get("kind", "")
    s_path = source.get("path", "")
    sink_path = sink.get("path", "")
    sink_sym = sink.get("symbol", "")

    raw = f"{issue}:{source.get('control', '')}:{s_kind}:{sink_path}:{sink_sym}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


class CandidateDeduplicator:
    """Clusters and provides reversible deduplication suggestions."""

    def propose_deduplication(
        self,
        candidates: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Propose merges between duplicate candidates without executing them (DSR-063).

        No candidate is mutated and no merge is performed: the callers list is
        left untouched. Candidates with distinct source paths (same sink) are
        never proposed for merging. Each suggestion embeds a snapshot of the
        original duplicate candidate so a mistaken merge stays reversible.

        Returns: list of suggestions with status "proposed"
        """
        seen_keys: Dict[str, Dict[str, Any]] = {}
        suggestions: List[Dict[str, Any]] = []

        for cand in candidates:
            fp = compute_fingerprint(cand)
            source_path = cand.get("source", {}).get("path", "")
            # Distinct sources for the same sink are never merged
            composite_key = f"{fp}:{source_path}"

            if composite_key in seen_keys:
                rep = seen_keys[composite_key]
                suggestions.append({
                    "schema_version": "1.0",
                    "suggestion_id": f"dedup-{len(suggestions) + 1:04d}",
                    "fingerprint": fp,
                    "merged_candidate_id": cand.get("candidate_id", ""),
                    "representative_id": rep.get("candidate_id", ""),
                    "reason": "Identical fingerprint and source origin",
                    "status": "proposed",
                    # Snapshot of the original candidate record so a mistaken
                    # merge can be traced back / rolled back.
                    "merged_candidate_snapshot": dict(cand),
                })
            else:
                seen_keys[composite_key] = cand

        return suggestions

    def confirm_merge(
        self,
        suggestion: Dict[str, Any],
        confirmed_by: str = "",
    ) -> Dict[str, Any]:
        """Execute a proposed merge after explicit confirmation (DSR-063).

        Records merged_candidate_id -> representative_id plus reason and
        confirmed_by, and retains the original candidate record (snapshot)
        inside the merge record so a mistaken merge is traceable and
        reversible. Only suggestions still in status "proposed" can be
        confirmed.

        Returns: merge record with status "confirmed"
        """
        if not isinstance(suggestion, dict):
            raise InvalidInputError("suggestion must be a dict")
        if not confirmed_by or not str(confirmed_by).strip():
            raise InvalidInputError("confirm_merge requires a non-empty confirmed_by")
        status = suggestion.get("status")
        if status == "confirmed":
            raise InvalidStateError(
                f"Suggestion '{suggestion.get('suggestion_id', '')}' was already confirmed"
            )
        if status != "proposed":
            raise InvalidInputError(
                f"Only proposed suggestions can be confirmed, got status '{status}'"
            )

        suggestion["status"] = "confirmed"
        suggestion["confirmed_by"] = confirmed_by

        return {
            "schema_version": "1.0",
            "suggestion_id": suggestion.get("suggestion_id", ""),
            "merged_candidate_id": suggestion.get("merged_candidate_id", ""),
            "representative_id": suggestion.get("representative_id", ""),
            "reason": suggestion.get("reason", ""),
            "confirmed_by": confirmed_by,
            "status": "confirmed",
            # Original candidate record retained for traceability/rollback
            "original_candidate": suggestion.get("merged_candidate_snapshot", {}),
        }

    def deduplicate(
        self,
        candidates: List[Dict[str, Any]],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Group candidates by fingerprint while keeping distinct sources unmerged.

        Returns: (deduplicated_representatives, merge_history)
        """
        seen_keys: Dict[str, Dict[str, Any]] = {}
        duplicates: List[Dict[str, Any]] = []

        for cand in candidates:
            fp = compute_fingerprint(cand)
            source_path = cand.get("source", {}).get("path", "")
            # Distinct sources for same sink are preserved separately
            composite_key = f"{fp}:{source_path}"

            if composite_key in seen_keys:
                rep = seen_keys[composite_key]
                # Reversibly append to provenance
                rep.setdefault("provenance", {}).setdefault("candidates", []).append(
                    cand.get("candidate_id", "")
                )
                duplicates.append({
                    "merged_candidate_id": cand.get("candidate_id"),
                    "representative_id": rep.get("candidate_id"),
                    "reason": "Identical fingerprint and source origin",
                })
            else:
                seen_keys[composite_key] = cand

        return list(seen_keys.values()), duplicates
