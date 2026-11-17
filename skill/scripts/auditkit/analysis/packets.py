"""Prompt packet builder and token budget enforcement.

Implements DSR-024 / DSR-059 / SD-04 / DR-016 / DDS-05:
- Encapsulates untrusted target source in <untrusted_code> tags.
- Binds snapshot ID, unit ID, language index, and guard summary.
- Declares an explicit task role (hunt / verify / triage) with a per-role
  output contract in the packet header (DSR-059).
- Builds dedicated recon packets with the language index selected from the
  unit language and a guard baseline summary (DSR-024).
- Enforces ~4000 token limit (~16,000 chars) with overflow gap reporting.
- Deterministic packet hashing.

Real-run shape defense (RUN-LESSONS.md O-01, family of L-06 / L-07):
real LLM planners and real units carry shapes the synthetic fixtures never
produced (bare-string range anchors, string-valued indexes, guard summaries
that are mappings, units with no ranges at all). Every section of the packet
defends its inputs by type:

- str          -> embedded verbatim (escaped nowhere, it is program-owned data)
- dict         -> rendered as key/value lines (keys and values kept visible)
- list/tuple   -> iterated entry by entry
- other/None   -> honest degradation: the section is marked ``[degraded]``
                 with the reason and the supplied value kept visible verbatim.

Nothing is fabricated, nothing is silently truncated or dropped (DSR-059).
Capacity overflow keeps the existing "record a gap" semantics; pagination /
splitting remains a documented follow-up (RUN-LESSONS O-05), not silently
absorbed here.
"""

# 需求追踪 (Requirement Traceability)
# ---------------------------------------------------------------------------
# 上层需求: docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2
# 设计依据: docs/design/SOFTWARE_DESIGN.md
# SWR-006  Recon 与守卫结构和提示包；条件启用、例外和未知，单靠注册锚点不得驳回候选
#   绑定实现: DSR-024, DSR-059
# SWR-007  Hunt 提示包：候选、悬空 sink、frontier 独立记录；容量溢出记录数量下界
#   绑定实现: DSR-025, DSR-059, DSR-060
# 状态以统一测试结论为准；未实测能力保持 unknown（设计原则 8：能观测的不靠声明）。
#

from __future__ import annotations
import hashlib
import json
from typing import Any, Dict, List, Optional, Tuple

from auditkit.contracts.errors import InvalidInputError


# Per-role output contracts declared in the packet header (DSR-059).
_WORKER_ENVELOPE_CONTRACT = (
    "Emit one JSON object: {schema_version: \"1.0\", task_id, attempt_id, kind, "
    "coverage: [{snapshot_id, unit_id, dimension (observed_read|signal_scanned|"
    "context_supplied), ranges: [{path, line_start, line_end}]}], records: [...], "
    "overflow: [...]}. coverage entries MUST carry snapshot_id, unit_id, "
    "dimension and ranges with path/line_start/line_end."
)

ROLE_OUTPUT_CONTRACTS: Dict[str, str] = {
    "hunt": (
        "Emit Candidate / Frontier / SinkProbe records plus an overflow array; "
        "never truncate silently; every record carries anchors and provenance. "
        + _WORKER_ENVELOPE_CONTRACT
    ),
    "verify": (
        "Emit a verdict object (confirmed | needs_validation | rejected | unverified) "
        "with evidence anchors and provenance; E2 requires a verification attempt id "
        "distinct from the hunt attempt. "
        + _WORKER_ENVELOPE_CONTRACT
    ),
    "triage": (
        "Emit sparse triage dispositions (candidate_created | dismissed | pending) "
        "plus an overflow array; strong signals left pending must never be counted "
        "as reviewed. "
        + _WORKER_ENVELOPE_CONTRACT
    ),
}


def _as_text(value: Any) -> str:
    """Faithful text rendering of a packet field value.

    Never invents content: strings pass through unchanged, bytes are decoded
    with errors replaced, mappings/sequences are rendered as compact JSON,
    and other scalars via str(). Used so a non-string value stays visible
    verbatim instead of crashing the renderer.

    Defense provenance: RUN-LESSONS.md O-01 (real-run packet render crashes,
    ``AttributeError: 'str' object has no attribute 'get'``, family of L-07).
    """
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    if value is None:
        return ""
    return str(value)


def _render_index_lines(value: Any) -> Tuple[List[str], List[str]]:
    """Render an index/guard-style packet field into text lines.

    Returns ``(lines, degradation_notes)``. The contract shape is a list of
    strings (or a plain string for guard summaries); any other shape is
    rendered faithfully and flagged with a degradation note instead of
    crashing or disappearing.

    Defense provenance: RUN-LESSONS.md O-01 / L-07 — ``"\\n".join(<str>)``
    used to explode a string-valued index into one character per line, and a
    dict-valued index used to join its keys only, silently dropping values.
    """
    if value is None:
        return [], []
    if isinstance(value, str):
        if not value.strip():
            # Empty guard summary / index: honest "not established", the
            # section is omitted exactly as before (DDS-05 honest unknown).
            return [], []
        return [value], []
    if isinstance(value, (list, tuple)):
        return [_as_text(item) for item in value], []
    note = (
        f"expected a list of strings, got {type(value).__name__}; "
        "the supplied value is rendered verbatim below"
    )
    if isinstance(value, dict):
        return [f"{_as_text(k)}: {_as_text(v)}" for k, v in value.items()], [note]
    return [_as_text(value)], [note]


def _normalize_range_entries(ranges: Any) -> Tuple[List[Any], List[str]]:
    """Normalize a unit's ``ranges`` into iterable entries plus notes.

    Defense provenance: RUN-LESSONS.md O-01 / L-06 — real units have been
    observed with ``ranges`` missing, as a bare string, or as a mapping.
    """
    if ranges is None:
        return [], ["unit carries no ranges; no target code could be supplied"]
    if isinstance(ranges, (list, tuple)):
        return list(ranges), []
    if isinstance(ranges, dict):
        return list(ranges.values()), [
            f"ranges was a mapping with {len(ranges)} entries, not a list; "
            "its values are rendered as range entries"
        ]
    return [ranges], [
        f"ranges was {type(ranges).__name__}, not a list; "
        "the value is rendered verbatim below"
    ]


def _render_range_entry(
    entry: Any, contents: Dict[Any, Any], position: int
) -> Tuple[Optional[str], Optional[str]]:
    """Render one unit range entry as a code block or a degradation note.

    Returns ``(block_or_None, note_or_None)``. A block participates in the
    packet capacity budget exactly as before (DSR-059); a note keeps the
    un-renderable entry visible verbatim instead of dropping it silently
    (DSR-059: record gaps, never fabricate bounds).
    """
    if not isinstance(entry, dict):
        # RUN-LESSONS O-01 / L-07 family: real models emit range entries as
        # bare strings ("src/file.ts:10-20") or other scalars; subscript
        # access used to raise here. Render the value verbatim.
        return None, (
            f"range entry #{position} is {type(entry).__name__}, not an anchor "
            f"object; rendered verbatim: {_as_text(entry)}"
        )

    path = entry.get("path")
    start = entry.get("line_start")
    end = entry.get("line_end")

    if path is None or (isinstance(path, str) and not path.strip()):
        return None, (
            f"range entry #{position} carries no usable 'path'; "
            f"rendered verbatim: {_as_text(entry)}"
        )
    if start is None or end is None:
        # RUN-LESSONS L-06: real models omit range bounds. The worker_result
        # schema rejects such coverage entries, so a packet unit doing the
        # same is degraded with the raw entry kept visible — line bounds are
        # never guessed, because guessed bounds would fabricate evidence.
        return None, (
            f"range entry #{position} for path '{_as_text(path)}' is missing "
            f"line_start/line_end; rendered verbatim: {_as_text(entry)}"
        )
    try:
        start_i = max(1, int(start))
        end_i = int(end)
    except (TypeError, ValueError):
        return None, (
            f"range entry #{position} for path '{_as_text(path)}' has non-integer "
            f"line bounds (line_start={_as_text(start)}, line_end={_as_text(end)}); "
            f"rendered verbatim: {_as_text(entry)}"
        )

    path_text = _as_text(path)
    header = f'<untrusted_code path="{path_text}" lines="{start_i}-{end_i}">'
    if path_text not in contents:
        # RUN-LESSONS O-01: a range whose file content is absent used to
        # render as a silently empty code block; the gap is marked instead.
        return (
            f"{header}\n"
            f"[unavailable] no file content was supplied for this path\n"
            f"</untrusted_code>"
        ), None

    content = _as_text(contents[path_text])
    lines = content.splitlines()
    # Slice lines 1-based closed interval
    selected_lines = lines[start_i - 1 : end_i]
    numbered_code = "\n".join(
        f"{line_num:4d} | {line}"
        for line_num, line in enumerate(selected_lines, start=start_i)
    )
    return f"{header}\n{numbered_code}\n</untrusted_code>", None


class PacketBuilder:
    """Builds bounded prompt packets for worker execution."""

    def __init__(self, max_chars: int = 16000) -> None:
        self.max_chars = max_chars

    def build_packet(
        self,
        role: str,
        snapshot_id: str,
        unit: Dict[str, Any],
        file_contents: Dict[str, str],
        guard_summary: str = "",
        language_index: Optional[List[str]] = None,
        base_language_index: Optional[List[str]] = None,
        task_kind: Optional[str] = None,
        degrade_notes: Optional[List[str]] = None,
    ) -> Tuple[Dict[str, Any], str, Optional[Dict[str, Any]]]:
        """Build a bounded prompt packet for an explicit task role.

        role must be one of hunt / verify / triage (DSR-059); the packet header
        declares the role and its output contract.

        degrade_notes carries program-owned degradation records (e.g. from
        recon index selection) that are surfaced in the packet header.

        Returns: (packet_dict, packet_digest, overflow_record_if_any)
        """
        if role not in ROLE_OUTPUT_CONTRACTS:
            raise InvalidInputError(
                f"Unknown packet role '{role}'; expected one of {sorted(ROLE_OUTPUT_CONTRACTS)}"
            )

        # -- unit-level defense (RUN-LESSONS O-01, family of L-07) ----------
        # The packet must bind to a unit identity. When the unit itself is not
        # the contract mapping (real planners have been observed emitting a
        # bare path string or null), the packet cannot be bound: reject it
        # explicitly with the offending type instead of crashing on subscript
        # access or fabricating a placeholder identity.
        if not isinstance(unit, dict):
            raise InvalidInputError(
                f"unit must be a mapping carrying unit_id/ranges, got "
                f"{type(unit).__name__}; packet cannot be bound (RUN-LESSONS O-01)"
            )
        raw_unit_id = unit.get("unit_id")
        if raw_unit_id is None or (
            isinstance(raw_unit_id, str) and not raw_unit_id.strip()
        ):
            raise InvalidInputError(
                "unit carries no usable 'unit_id'; packet cannot be bound "
                "(RUN-LESSONS O-01)"
            )
        unit_id = _as_text(raw_unit_id)
        lang = _as_text(unit.get("language")).strip() or "unknown"

        notes: List[str] = list(degrade_notes or [])

        # -- file-contents defense (RUN-LESSONS O-01) ------------------------
        contents: Dict[Any, Any]
        if file_contents is None:
            contents = {}
            notes.append(
                "file contents were None, expected a mapping keyed by path; "
                "affected ranges are marked unavailable below"
            )
        elif isinstance(file_contents, dict):
            contents = file_contents
        else:
            contents = {}
            notes.append(
                f"file contents were {type(file_contents).__name__}, expected a "
                "mapping keyed by path; affected ranges are marked unavailable below"
            )

        kind = task_kind or role
        overflow = None

        sections: List[str] = [
            f"# {kind.capitalize()} Task: {unit_id}",
            f"Snapshot: {snapshot_id} | Language: {lang}",
            f"Role: {role}",
            f"Output Contract: {ROLE_OUTPUT_CONTRACTS[role]}",
        ]

        for note in notes:
            sections.append(f"[degraded] {note}")

        # -- guard summary defense (RUN-LESSONS O-01) ------------------------
        # Real guard payloads have been observed as mappings/None instead of
        # the summary string; render faithfully and flag, never crash.
        guard_lines, guard_notes = _render_index_lines(guard_summary)
        for note in guard_notes:
            sections.append(f"[degraded] guard_summary: {note}")
        if guard_lines:
            sections.append("## Environment Guards\n" + "\n".join(guard_lines))

        # -- language index defense (RUN-LESSONS O-01 / L-07) ----------------
        if language_index:
            index_lines, index_notes = _render_index_lines(language_index)
            for note in index_notes:
                sections.append(f"[degraded] language_index: {note}")
            if index_lines:
                sections.append(
                    "## Primary Language Index (Top 10)\n" + "\n".join(index_lines)
                )

        if base_language_index:
            base_lines, base_notes = _render_index_lines(base_language_index)
            for note in base_notes:
                sections.append(f"[degraded] base_language_index: {note}")
            if base_lines:
                sections.append(
                    "## Applicable Base Language Index\n" + "\n".join(base_lines)
                )

        sections.append("## Target Code under Review")

        # -- range defense (RUN-LESSONS O-01 / L-06) -------------------------
        range_entries, range_notes = _normalize_range_entries(unit.get("ranges"))
        for note in range_notes:
            sections.append(f"[degraded] ranges: {note}")

        # Add target code
        code_blocks: List[str] = []
        noted_entries = 0
        total_entries = len(range_entries)
        current_len = sum(len(s) for s in sections)

        for position, entry in enumerate(range_entries, start=1):
            block, note = _render_range_entry(entry, contents, position)
            if note is not None:
                # The entry cannot become a code block but stays visible in
                # the packet (DSR-059: no silent drop).
                sections.append(f"[degraded] {note}")
                current_len += len(sections[-1])
                noted_entries += 1
                continue
            assert block is not None

            if current_len + len(block) > self.max_chars:
                overflow = {
                    "dimension": "packet_capacity",
                    "estimated_count": total_entries
                    - len(code_blocks)
                    - noted_entries,
                    "reason": f"Unit ranges exceeded maximum packet character budget of {self.max_chars}",
                }
                break

            code_blocks.append(block)
            current_len += len(block)

        sections.extend(code_blocks)
        full_text = "\n\n".join(sections)
        packet_digest = hashlib.sha256(full_text.encode("utf-8")).hexdigest()

        packet_dict = {
            "schema_version": "1.0",
            "snapshot_id": snapshot_id,
            "unit_id": unit_id,
            "role": role,
            "task_kind": kind,
            "output_contract": ROLE_OUTPUT_CONTRACTS[role],
            "prompt_text": full_text,
            "packet_digest": packet_digest,
        }

        return packet_dict, packet_digest, overflow

    def build_hunt_packet(
        self,
        snapshot_id: str,
        unit: Dict[str, Any],
        file_contents: Dict[str, str],
        guard_summary: str = "",
        language_index: Optional[List[str]] = None,
        base_language_index: Optional[List[str]] = None,
    ) -> Tuple[Dict[str, Any], str, Optional[Dict[str, Any]]]:
        """Build hunt prompt packet (role: hunt).

        Returns: (packet_dict, packet_digest, overflow_record_if_any)
        """
        return self.build_packet(
            "hunt",
            snapshot_id,
            unit,
            file_contents,
            guard_summary=guard_summary,
            language_index=language_index,
            base_language_index=base_language_index,
            task_kind="hunt",
        )

    def build_recon_packet(
        self,
        snapshot_id: str,
        unit: Dict[str, Any],
        file_contents: Dict[str, str],
        guard_summary: str = "",
        language_indexes: Optional[Dict[str, List[str]]] = None,
        language_index: Optional[List[str]] = None,
        base_language_index: Optional[List[str]] = None,
    ) -> Tuple[Dict[str, Any], str, Optional[Dict[str, Any]]]:
        """Build recon prompt packet (DSR-024).

        The primary language index is selected from ``language_indexes`` by the
        unit language when ``language_index`` is not supplied explicitly. The
        guard baseline summary is embedded in the header. Capacity overflow
        follows the same pattern as the hunt packet.

        Returns: (packet_dict, packet_digest, overflow_record_if_any)
        """
        recon_notes: List[str] = []
        if language_index is None and language_indexes is not None:
            if isinstance(language_indexes, dict):
                # RUN-LESSONS O-01: the unit language keys this map; a
                # non-string (or unhashable) language used to raise here.
                if isinstance(unit, dict):
                    language_index = language_indexes.get(
                        _as_text(unit.get("language")) or "unknown"
                    )
            elif isinstance(language_indexes, (list, tuple)):
                # A list already has index shape; use it faithfully instead of
                # crashing on ``.get`` (RUN-LESSONS O-01 / L-07 family).
                language_index = list(language_indexes)
            else:
                recon_notes.append(
                    f"language_indexes was {type(language_indexes).__name__}, "
                    "expected a mapping keyed by language; no primary language "
                    "index could be selected"
                )

        return self.build_packet(
            "hunt",
            snapshot_id,
            unit,
            file_contents,
            guard_summary=guard_summary,
            language_index=language_index,
            base_language_index=base_language_index,
            task_kind="recon",
            degrade_notes=recon_notes,
        )
