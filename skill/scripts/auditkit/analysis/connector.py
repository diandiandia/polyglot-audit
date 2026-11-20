"""Hypothesis connector for linking Frontiers and Dangling Sinks.

Implements DSR-026 / DSR-058 / DR-013 / SD-04 / SR-005:
- Synthesizes connection hypotheses between outgoing frontiers and incoming sink probes.
- Matches based on symbol name, parameter signature, and boundary types.
- Never falsely promotes ambiguous or parameter-incompatible matches to verified.
- Emits Connection records with status: hypothesized, verified, rejected, unresolved.
- Unmatched frontiers/probes produce explicit ``unresolved`` records (DSR-058);
  they are never silently dropped.
- Depth, connection-count, and budget caps are enforced with explicit gap
  records (dimension + estimated_count + reason) instead of silent breaks.
- Same-name parameter-signature incompatibility prevents pairing and is
  recorded as an ``incompatible`` record.
"""

# 需求追踪 (Requirement Traceability)
# ---------------------------------------------------------------------------
# 上层需求: docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2
# 设计依据: docs/design/SOFTWARE_DESIGN.md
# SWR-003  混合语言边界进入同一候选与验证流程
#   绑定实现: DSR-026, DSR-055
# SWR-005  跨单元/跨语言半链关联：未连接或超额条目有明确状态，不静默丢弃
#   绑定实现: DSR-026, DSR-058
# 状态以统一测试结论为准；未实测能力保持 unknown（设计原则 8：能观测的不靠声明）。
#

from __future__ import annotations
import re
import uuid
from typing import Any, Dict, List, Optional, Tuple

from auditkit.contracts.errors import InvalidInputError


def _param_arity(participant: Dict[str, Any]) -> Optional[int]:
    """Extract parameter arity from ``params`` list or ``signature`` string.

    Returns None when no signature information is declared.

    Requirements: SWR-005(参数签名,support) / DSR-026(support)
    """
    params = participant.get("params")
    if isinstance(params, list):
        return len(params)
    signature = participant.get("signature")
    if isinstance(signature, str) and signature.strip():
        inner = signature.strip()
        if inner.startswith("(") and inner.endswith(")"):
            inner = inner[1:-1].strip()
        if not inner:
            return 0
        return len(inner.split(","))
    return None


_TOKEN_SPLIT = re.compile(r"[^a-z0-9_]+")


def _name_affinity(left: str, right: str) -> Optional[str]:
    """Component-aware name affinity for hypothesis joins (RUN-LESSONS O-06).

    Returns ``"exact"`` (full equality), ``"component"`` (at least one
    complete separator-delimited token shared by both names), or ``None``.
    Raw bidirectional substring containment no longer pairs anything: names
    that merely share a loose token ("util.encode" vs "encode", "encode"
    inside "encode_state") formed false hypothesis edges and spent
    independent verification budget on them. An edge now needs ONE exact
    factor (boundary or symbol) or TWO independent component factors
    (boundary AND symbol) -- a single loose component match pairs nothing.
    """
    if not left or not right:
        return None
    left_l, right_l = left.lower(), right.lower()
    if left_l == right_l:
        return "exact"
    left_tokens = {t for t in _TOKEN_SPLIT.split(left_l) if t}
    right_tokens = {t for t in _TOKEN_SPLIT.split(right_l) if t}
    if left_tokens & right_tokens:
        return "component"
    return None


class HypothesisConnector:
    """Connects Frontiers and SinkProbes into candidate paths.

    Requirements: SWR-003(跨语言边界), SWR-005(半链关联) / DSR-026(不伪verified)
    """

    def connect(
        self,
        frontiers: List[Dict[str, Any]],
        probes: List[Dict[str, Any]],
        max_connections: int = 50,
        max_depth: int = 1,
        budget: Optional[int] = None,
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Attempt to join frontiers and probes (backward-compatible form).

        Returns: (connections, synthesized_candidates)

        Requirements: SWR-005(连接假设,support) / DSR-026(support)
        """
        result = self.connect_ex(
            frontiers,
            probes,
            max_connections=max_connections,
            max_depth=max_depth,
            budget=budget,
        )
        return result["connections"], result["candidates"]

    def connect_ex(
        self,
        frontiers: List[Dict[str, Any]],
        probes: List[Dict[str, Any]],
        max_connections: int = 50,
        max_depth: int = 1,
        budget: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Attempt to join frontiers and probes with explicit dispositions.

        - ``max_depth`` caps the hypothesis chain depth. This connector only
          performs direct (depth-1) joins; deeper multi-hop chains are not
          attempted and the involved records stay in ``unresolved`` with a
          reason.
        - ``budget`` optionally caps the number of pairing evaluations (work
          units). Actual charge accounting stays in the LED domain; this only
          respects the allowance it is given.
        - When ``max_connections`` or ``budget`` is exhausted, remaining
          unscheduled items produce a gap record
          (dimension + estimated_count + reason), mirroring hunter overflow.

        Returns a dict with keys: connections, candidates, unresolved,
        incompatible, gaps, stats.

        Requirements: SWR-003(跨语言保留未决), SWR-005(未连接显式状态) / DSR-026(不兼容不成verified), DSR-058(无匹配与超额留缺口)
        """
        if max_connections < 1:
            raise InvalidInputError(f"max_connections must be >= 1, got {max_connections}")
        if max_depth < 1:
            raise InvalidInputError(f"max_depth must be >= 1, got {max_depth}")
        if budget is not None and budget < 0:
            raise InvalidInputError(f"budget must be >= 0 or None, got {budget}")

        connections: List[Dict[str, Any]] = []
        candidates: List[Dict[str, Any]] = []
        unresolved: List[Dict[str, Any]] = []
        incompatible: List[Dict[str, Any]] = []
        gaps: List[Dict[str, Any]] = []

        matched_frontier_ids: set = set()
        matched_probe_ids: set = set()
        evaluations = 0
        stopped_by_cap: Optional[str] = None
        unscheduled_frontiers: List[Dict[str, Any]] = []

        if max_depth > 1:
            gaps.append({
                "dimension": "connection_depth",
                "estimated_count": max(len(frontiers), len(probes)),
                "reason": (
                    f"Direct depth-1 joins only; deeper hypothesis chains beyond "
                    f"max_depth={max_depth} were not attempted."
                ),
            })

        for f_index, f in enumerate(frontiers):
            if len(connections) >= max_connections:
                stopped_by_cap = "connections"
                unscheduled_frontiers = frontiers[f_index:]
                break
            if budget is not None and evaluations >= budget:
                stopped_by_cap = "budget"
                unscheduled_frontiers = frontiers[f_index:]
                break

            f_boundary = f.get("boundary", "").lower()
            f_source = f.get("source", {})
            f_id = f.get("frontier_id", "")
            frontier_matched = False

            for p in probes:
                if len(connections) >= max_connections:
                    stopped_by_cap = "connections"
                    unscheduled_frontiers = frontiers[f_index:]
                    break
                if budget is not None and evaluations >= budget:
                    stopped_by_cap = "budget"
                    unscheduled_frontiers = frontiers[f_index:]
                    break

                evaluations += 1
                p_boundary = p.get("boundary", "").lower()
                p_sink = p.get("sink", {})
                p_id = p.get("probe_id", "")

                # Same-name parameter-signature compatibility: a declared
                # arity mismatch prevents pairing entirely (DSR-026).
                f_arity = _param_arity(f_source)
                p_arity = _param_arity(p_sink)
                if f_arity is not None and p_arity is not None and f_arity != p_arity:
                    incompatible.append({
                        "schema_version": "1.0",
                        "frontier_id": f_id,
                        "probe_id": p_id,
                        "frontier_symbol": f_source.get("symbol", ""),
                        "probe_symbol": p_sink.get("symbol", ""),
                        "frontier_arity": f_arity,
                        "probe_arity": p_arity,
                        "reason": (
                            f"Parameter signature mismatch: frontier arity {f_arity} "
                            f"vs probe arity {p_arity}; pair not formed"
                        ),
                    })
                    continue

                # Name affinity (RUN-LESSONS O-06): component-aware, not raw
                # substring. One exact factor or two independent component
                # factors warrant a hypothesis edge; a single loose component
                # match pairs nothing (it stays in unresolved with a reason).
                f_sym = f_source.get("symbol", "").lower()
                p_sym = p_sink.get("symbol", "").lower()
                b_affinity = _name_affinity(f_boundary, p_boundary)
                s_affinity = _name_affinity(f_sym, p_sym)
                edge_warranted = (
                    b_affinity == "exact"
                    or s_affinity == "exact"
                    or (b_affinity == "component" and s_affinity == "component")
                )

                matching_factors: List[str] = []
                if edge_warranted:
                    if b_affinity:
                        label = "Boundary match" if b_affinity == "exact" else "Boundary component match"
                        matching_factors.append(f"{label}: '{f_boundary}' ~ '{p_boundary}'")
                    if s_affinity:
                        label = "Symbol affinity" if s_affinity == "exact" else "Symbol component affinity"
                        matching_factors.append(f"{label}: '{f_sym}' ~ '{p_sym}'")

                if matching_factors:
                    frontier_matched = True
                    matched_probe_ids.add(p_id)
                    conn_id = f"conn-{uuid.uuid4().hex[:8]}"
                    # Connections default to hypothesized; heuristic joins are
                    # never promoted to verified (DSR-058).
                    status = "hypothesized"

                    conn = {
                        "schema_version": "1.0",
                        "connection_id": conn_id,
                        "frontier_id": f_id,
                        "probe_id": p_id,
                        "matching_factors": matching_factors,
                        "status": status,
                    }
                    connections.append(conn)

                    # Synthesize linked candidate for independent verification
                    cand_id = f"cand-linked-{uuid.uuid4().hex[:8]}"
                    combined_steps = list(f.get("steps", [])) + list(p.get("steps", []))

                    synth_candidate = {
                        "schema_version": "1.0",
                        "candidate_id": cand_id,
                        "issue": f"cross_boundary:{f_boundary}",
                        "source": f_source,
                        "sink": p_sink,
                        "steps": combined_steps,
                        "guard_analysis": p.get("guard_analysis", "Cross-boundary guard unverified"),
                        "impact_claim": "Hypothesized cross-module/cross-language taint flow",
                        "open_questions": [
                            f"Verify actual parameter compatibility across {f_boundary}",
                            f"Confirm {f_id} routes to {p_id}",
                        ],
                        "provenance": {
                            "candidates": [f_id, p_id],
                            "hunt_tasks": list(set(
                                f.get("provenance", {}).get("hunt_tasks", [])
                                + p.get("provenance", {}).get("hunt_tasks", [])
                            )),
                        },
                    }
                    candidates.append(synth_candidate)

            if frontier_matched:
                matched_frontier_ids.add(f_id)
            elif stopped_by_cap is None:
                unresolved.append({
                    "schema_version": "1.0",
                    "kind": "frontier",
                    "frontier_id": f_id,
                    "record": f,
                    "reason": "No compatible sink probe matched this frontier.",
                })

        # Probes that were evaluated but never matched become unresolved; they
        # are never silently dropped (DSR-058). Probes skipped because a cap
        # hit first are accounted in the gap record below instead.
        evaluated_probe_ids = set()
        if stopped_by_cap is None:
            for p in probes:
                p_id = p.get("probe_id", "")
                evaluated_probe_ids.add(p_id)
                if p_id not in matched_probe_ids:
                    unresolved.append({
                        "schema_version": "1.0",
                        "kind": "probe",
                        "probe_id": p_id,
                        "record": p,
                        "reason": "No compatible frontier matched this sink probe.",
                    })

        if stopped_by_cap == "connections":
            gaps.append({
                "dimension": "connections",
                "estimated_count": len(unscheduled_frontiers),
                "reason": (
                    f"Connection cap {max_connections} reached; remaining frontiers "
                    f"(and their probes) were not scheduled."
                ),
            })
        elif stopped_by_cap == "budget":
            gaps.append({
                "dimension": "connection_budget",
                "estimated_count": len(unscheduled_frontiers),
                "reason": (
                    f"Pairing budget {budget} exhausted; remaining frontiers "
                    f"(and their probes) were not scheduled. Budget charge "
                    f"accounting remains in the LED domain."
                ),
            })

        stats = {
            "frontiers": len(frontiers),
            "probes": len(probes),
            "connections": len(connections),
            "candidates": len(candidates),
            "unresolved": len(unresolved),
            "incompatible": len(incompatible),
            "gaps": len(gaps),
            "evaluations": evaluations,
            "budget": budget,
        }

        return {
            "schema_version": "1.0",
            "connections": connections,
            "candidates": candidates,
            "unresolved": unresolved,
            "incompatible": incompatible,
            "gaps": gaps,
            "stats": stats,
        }
