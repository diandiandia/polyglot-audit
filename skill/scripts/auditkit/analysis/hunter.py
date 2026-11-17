"""Hunter parser for Candidate, Frontier, SinkProbe, and overflow records.

Implements DSR-025 / DSR-060 / SD-04 / SR-007:
- Separates findings into Candidates, Frontiers (half-chains), and SinkProbes (dangling sinks).
- Enforces array capacity limits; records explicit overflow instead of silent truncations.
- Normalizes worker output to strict schema objects.

Real-run shape defense (RUN-LESSONS.md L-07 / O-01): real models emit
records as bare prose strings, scalars, non-list ``records``/``overflow``
fields, and endpoints as plain strings instead of {path, line, ...} maps.
The parser keeps every such value visible verbatim and routes it to the
existing contract/dedup rejection path (located analysis_gap) instead of
crashing on ``.get`` or dropping the record silently (DSR-059).
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
from typing import Any, Dict, List, Tuple


# Record kinds the hunt contract defines (DSR-025).
_KNOWN_KINDS = ("candidate", "frontier", "sink_probe")


def _as_entry_list(value: Any) -> List[Any]:
    """Normalize a worker list field (records/overflow) into entries.

    A bare string used to be exploded per character by ``list(<str>)`` —
    silent corruption of the records/overflow channel; a mapping used to
    contribute only its keys. Scalars and mappings are kept as verbatim
    entries so the downstream contract guards can reject them explicitly.

    Defense provenance: RUN-LESSONS.md L-07 / O-01 (real model output shapes).
    """
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, dict):
        return list(value.values())
    return [value]


def _as_overflow_record(entry: Any, task_id: str) -> Dict[str, Any]:
    """Coerce an overflow entry into the dict shape downstream events read.

    Consumers (service event fan-out) read ``dimension``/``estimated_count``/
    ``reason`` keys; a non-dict entry used to crash that fan-out. The raw
    value is preserved verbatim under ``overflow_raw`` so nothing is lost or
    fabricated.

    Defense provenance: RUN-LESSONS.md O-01 (family of L-07).
    """
    if isinstance(entry, dict):
        return entry
    return {
        "dimension": "unparsed_overflow",
        "estimated_count": 1,
        "reason": (
            f"overflow entry was {type(entry).__name__}, expected an object; "
            f"kept verbatim (task {task_id})"
        ),
        "overflow_raw": entry,
    }


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

        # RUN-LESSONS L-07 / O-01: list fields may arrive as scalars or
        # mappings from real models; entries are kept verbatim (see
        # _as_entry_list) instead of crashing here or being silently
        # reshaped. Overflow entries are coerced to the dict shape the
        # downstream event fan-out reads.
        overflow_entries: List[Any]
        records: List[Any]
        if not isinstance(raw_result, dict):
            # A non-object payload (bare list, prose string) is kept visible
            # as one unparseable candidate record; the candidate contract
            # rejects it explicitly downstream instead of this parser
            # crashing on .get (DSR-059: located, never silent).
            records = [raw_result]
            overflow_entries = []
        else:
            records = _as_entry_list(raw_result.get("records"))
            overflow_entries = _as_entry_list(raw_result.get("overflow"))

        overflows: List[Dict[str, Any]] = [
            _as_overflow_record(entry, task_id) for entry in overflow_entries
        ]

        for rec in records:
            if not isinstance(rec, dict):
                # RUN-LESSONS L-07 / O-01: real models emit records as bare
                # prose strings or scalars. Wrap the value verbatim and route
                # it to the candidate contract so the existing guards reject
                # it with a located error instead of this parser crashing on
                # rec.get(...) or dropping the record silently (DSR-059).
                rec = {
                    "record_type": "candidate",
                    "record_raw": rec,
                    "record_raw_type": type(rec).__name__,
                }
                kind = "candidate"
            else:
                kind = rec.get("record_type") or rec.get("kind")
                if not isinstance(kind, str) or kind not in _KNOWN_KINDS:
                    # Infer from keys. A record carrying only one endpoint of
                    # the chain is a half-chain: sink-without-source is a
                    # dangling sink (sink_probe), source-without-sink is a
                    # frontier. Only a record with both endpoints parses as a
                    # candidate — inferring "candidate" for a one-sided record
                    # would fabricate a complete source->sink finding from a
                    # half-chain (SR-007).
                    source = rec.get("source")
                    sink = rec.get("sink")
                    has_source = isinstance(source, dict)
                    has_sink = isinstance(sink, dict)
                    if has_source and has_sink:
                        kind = "candidate"
                    elif has_source and sink is None:
                        kind = "frontier"
                    elif has_sink and source is None:
                        kind = "sink_probe"
                    else:
                        # RUN-LESSONS L-07: real models emit endpoints as bare
                        # strings ("source": "path/to/x.py") or omit them. A
                        # present but non-dict endpoint must stay visible as a
                        # candidate so the candidate contract validation
                        # rejects it with an explicit error; routing it to a
                        # half-chain kind would fabricate "no source known"
                        # from a record that does carry one (SR-007). An
                        # unknown kind label from the model falls through to
                        # the same path instead of being silently dropped
                        # (DSR-059).
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
