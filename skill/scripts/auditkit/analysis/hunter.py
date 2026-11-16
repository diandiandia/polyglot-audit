"""Hunter parser for Candidate, Frontier, SinkProbe, and overflow records.

Implements DSR-025 / DSR-060 / SD-04 / SR-007:
- Separates findings into Candidates, Frontiers (half-chains), and SinkProbes (dangling sinks).
- Enforces array capacity limits; records explicit overflow instead of silent truncations.
- Normalizes worker output to strict schema objects.
"""

# 需求追踪 (Requirement Traceability)
# ---------------------------------------------------------------------------
# 上层需求: docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2
# 设计依据: docs/design/SOFTWARE_DESIGN.md
# SWR-007  候选、悬空 sink、frontier 独立记录；无 source 半链不伪装成完整发现，溢出可追踪
#   绑定实现: DSR-025
# 状态以统一测试结论为准；未实测能力保持 unknown（设计原则 8：能观测的不靠声明）。
#

from __future__ import annotations
import uuid
from typing import Any, Dict, List, Optional, Tuple


class HuntResultParser:
    """Parses raw worker responses into structured hunt records."""

    def __init__(self, max_records_per_kind: int = 50) -> None:
        self.max_records = max_records_per_kind

    def parse_worker_payload(
        self,
        raw_result: Dict[str, Any],
        task_id: str,
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Parse raw JSON into candidates, frontiers, sink_probes, and overflows.

        Returns: (candidates, frontiers, sink_probes, overflows)
        """
        candidates: List[Dict[str, Any]] = []
        frontiers: List[Dict[str, Any]] = []
        sink_probes: List[Dict[str, Any]] = []
        overflows: List[Dict[str, Any]] = list(raw_result.get("overflow", []))

        records = raw_result.get("records", [])

        for rec in records:
            kind = rec.get("record_type") or rec.get("kind")
            if not kind:
                # Infer from keys. A record carrying only one endpoint of the
                # chain is a half-chain: sink-without-source is a dangling
                # sink (sink_probe), source-without-sink is a frontier. Only a
                # record with both endpoints parses as a candidate — inferring
                # "candidate" for a one-sided record would fabricate a
                # complete source->sink finding from a half-chain (SR-007).
                has_source = "source" in rec
                has_sink = "sink" in rec
                if has_source and has_sink:
                    kind = "candidate"
                elif has_sink:
                    kind = "sink_probe"
                elif has_source:
                    kind = "frontier"
                else:
                    # Shapeless record: keep it visible as a candidate so the
                    # candidate contract validation rejects it with an
                    # explicit error instead of dropping it silently.
                    kind = "candidate"

            if kind == "candidate":
                if len(candidates) >= self.max_records:
                    overflows.append({
                        "dimension": "candidate",
                        "estimated_count": len(records) - len(candidates),
                        "reason": f"Candidate cap {self.max_records} reached for task {task_id}",
                    })
                    continue
                c_id = rec.get("candidate_id") or f"cand-{uuid.uuid4().hex[:8]}"
                rec["schema_version"] = "1.0"
                rec["candidate_id"] = c_id
                rec.setdefault("provenance", {"hunt_tasks": [task_id]})
                candidates.append(rec)

            elif kind == "frontier":
                if len(frontiers) >= self.max_records:
                    overflows.append({
                        "dimension": "frontier",
                        "estimated_count": len(records) - len(frontiers),
                        "reason": f"Frontier cap {self.max_records} reached for task {task_id}",
                    })
                    continue
                f_id = rec.get("frontier_id") or f"front-{uuid.uuid4().hex[:8]}"
                rec["schema_version"] = "1.0"
                rec["frontier_id"] = f_id
                rec.setdefault("provenance", {"hunt_tasks": [task_id]})
                frontiers.append(rec)

            elif kind == "sink_probe":
                if len(sink_probes) >= self.max_records:
                    overflows.append({
                        "dimension": "sink_probe",
                        "estimated_count": len(records) - len(sink_probes),
                        "reason": f"SinkProbe cap {self.max_records} reached for task {task_id}",
                    })
                    continue
                p_id = rec.get("probe_id") or f"probe-{uuid.uuid4().hex[:8]}"
                rec["schema_version"] = "1.0"
                rec["probe_id"] = p_id
                rec.setdefault("provenance", {"hunt_tasks": [task_id]})
                sink_probes.append(rec)

        return candidates, frontiers, sink_probes, overflows
