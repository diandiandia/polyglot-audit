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
    ) -> Tuple[Dict[str, Any], str, Optional[Dict[str, Any]]]:
        """Build a bounded prompt packet for an explicit task role.

        role must be one of hunt / verify / triage (DSR-059); the packet header
        declares the role and its output contract.

        Returns: (packet_dict, packet_digest, overflow_record_if_any)
        """
        if role not in ROLE_OUTPUT_CONTRACTS:
            raise InvalidInputError(
                f"Unknown packet role '{role}'; expected one of {sorted(ROLE_OUTPUT_CONTRACTS)}"
            )

        kind = task_kind or role
        unit_id = unit["unit_id"]
        lang = unit.get("language", "unknown")
        overflow = None

        sections: List[str] = [
            f"# {kind.capitalize()} Task: {unit_id}",
            f"Snapshot: {snapshot_id} | Language: {lang}",
            f"Role: {role}",
            f"Output Contract: {ROLE_OUTPUT_CONTRACTS[role]}",
        ]

        if guard_summary:
            sections.append(f"## Environment Guards\n{guard_summary}")

        if language_index:
            sections.append("## Primary Language Index (Top 10)\n" + "\n".join(language_index))

        if base_language_index:
            sections.append("## Applicable Base Language Index\n" + "\n".join(base_language_index))

        sections.append("## Target Code under Review")

        # Add target code
        code_blocks = []
        current_len = sum(len(s) for s in sections)

        for anchor in unit.get("ranges", []):
            path = anchor["path"]
            start = anchor["line_start"]
            end = anchor["line_end"]
            content = file_contents.get(path, "")
            lines = content.splitlines()

            # Slice lines 1-based closed interval
            selected_lines = lines[start - 1 : end]
            numbered_code = "\n".join(
                f"{line_num:4d} | {line}"
                for line_num, line in enumerate(selected_lines, start=start)
            )

            block = (
                f'<untrusted_code path="{path}" lines="{start}-{end}">\n'
                f"{numbered_code}\n"
                f"</untrusted_code>"
            )

            if current_len + len(block) > self.max_chars:
                overflow = {
                    "dimension": "packet_capacity",
                    "estimated_count": len(unit.get("ranges", [])) - len(code_blocks),
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
        if language_index is None and language_indexes:
            language_index = language_indexes.get(unit.get("language", "unknown"))

        return self.build_packet(
            "hunt",
            snapshot_id,
            unit,
            file_contents,
            guard_summary=guard_summary,
            language_index=language_index,
            base_language_index=base_language_index,
            task_kind="recon",
        )
