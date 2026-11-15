"""Typed interface definitions for core polyglot-audit exchange objects.

Implements DSR-073 / IFC-02:
- TypedDict definitions for every IFC-02 exchange object so the gate, usage,
  queue and pipeline chains (and external consumers) share a single typed
  source of truth with the JSON schemas in skill/schemas/.
- ``TaskSpec`` is the union of the three schema branches (HuntTaskSpec /
  ReconTaskSpec / VerifyTaskSpec), mirroring task_spec.schema.json's oneOf.
- Every TypedDict is ``total=False`` (schema properties are optional unless
  the schema marks them required; requiredness is enforced by the schemas and
  the runtime validators, not by the typing layer).
- These are typing-only views over plain dicts; no runtime coercion is
  performed. Key sets are kept aligned with the schema properties by the
  table-driven tests in tests/contracts/test_typed_contracts.py.

Runtime surfaces may carry MORE fields than the schema surface (documented on
the affected classes, e.g. SnapshotManifest's honest gap accounting); the
typed contracts mirror the schema surface, which is the interchange contract.
"""

# 需求追踪 (Requirement Traceability)
# ---------------------------------------------------------------------------
# 上层需求: docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2
# 设计依据: docs/design/SOFTWARE_DESIGN.md
# SWR-025  结构化契约的类型化接口（TypedDict/dataclass）
#   绑定实现: DSR-073
# 状态以统一测试结论为准；未实测能力保持 unknown（设计原则 8：能观测的不靠声明）。
#

from __future__ import annotations
from typing import Any, Dict, List, TypedDict, Union


# ---------------------------------------------------------------------------
# Shared / nested shapes
# ---------------------------------------------------------------------------
class Anchor(TypedDict, total=False):
    """Source location anchor (anchor.schema.json)."""

    schema_version: str
    snapshot_id: str
    path: str
    line_start: int
    line_end: int
    file_sha256: str
    symbol: str


class Step(TypedDict, total=False):
    """Single trace step from source to sink (candidate/frontier/sink_probe
    steps items; candidate.schema.json)."""

    path: str
    line: int
    role: str
    note: str
    lang: str


class CoverageRange(TypedDict, total=False):
    """Observed-read line range (coverage_observation.schema.json ranges items)."""

    path: str
    line_start: int
    line_end: int


# ---------------------------------------------------------------------------
# Task specification branches (task_spec.schema.json oneOf, DSR-073)
# ---------------------------------------------------------------------------
class PacketUnit(TypedDict, total=False):
    """Prompt-packet unit handed to a worker (task_spec $defs/packet_unit)."""

    unit_id: str
    ranges: List[Dict[str, Any]]


class KnowledgeHints(TypedDict, total=False):
    """Knowledge-catalog clues carried by the recon spec
    (task_spec $defs/recon_spec properties/knowledge_hints)."""

    primary_language: str
    languages_in_scope: List[str]
    catalog_languages: List[str]


class HuntTaskSpec(TypedDict, total=False):
    """hunt 任务规格：prepare 为每个 analyze 单元入队（DSR-056）。"""

    schema_version: str
    task_kind: str
    snapshot_id: str
    unit: PacketUnit


class ReconTaskSpec(TypedDict, total=False):
    """recon 任务规格：每 run 恰一个，建立 guard 基线（DDS-05 S1 / DSR-024）。"""

    schema_version: str
    task_kind: str
    role: str
    snapshot_id: str
    unit: PacketUnit
    language_index: List[str]
    base_language_index: List[str]
    knowledge_hints: KnowledgeHints


class VerifyTaskSpec(TypedDict, total=False):
    """verify 任务规格：常规验证或 High/Critical 第二意见（DSR-061，E2 新 attempt）。"""

    schema_version: str
    task_kind: str
    role: str
    verify_task_id: str
    candidate_id: str
    output_contract: str
    requires_new_attempt: bool
    input: Dict[str, Any]
    second_opinion: bool
    target_finding_id: str
    target_severity: str


# Union alias matching task_spec.schema.json's oneOf: a TaskSpec is exactly
# one of the three branch shapes.
TaskSpec = Union[HuntTaskSpec, ReconTaskSpec, VerifyTaskSpec]


# ---------------------------------------------------------------------------
# IFC-02 exchange objects
# ---------------------------------------------------------------------------
class Budget(TypedDict, total=False):
    """Budget dimension state (budget.schema.json)."""

    schema_version: str
    dimension: str
    mode: str
    limit: int
    settled: int
    reserved: int
    unit: str
    availability: str


class CapabilityFeature(TypedDict, total=False):
    """Single host capability feature probe result (capability.schema.json)."""

    state: str
    evidence: str
    reason: str


class Capability(TypedDict, total=False):
    """Host adapter capability probe (capability.schema.json)."""

    schema_version: str
    adapter: str
    adapter_version: str
    checked_at: str
    features: Dict[str, CapabilityFeature]


class Claim(TypedDict, total=False):
    """Lease-bound task claim handed to a worker (claim.schema.json)."""

    schema_version: str
    run_id: str
    task_id: str
    attempt_id: str
    generation: int
    claim_token: str
    expires_at: str
    packet_ref: str
    spec: Dict[str, Any]


class Connection(TypedDict, total=False):
    """Heuristic frontier <-> sink-probe connection (connection.schema.json)."""

    schema_version: str
    connection_id: str
    frontier_id: str
    probe_id: str
    matching_factors: List[str]
    status: str


class CoverageObservation(TypedDict, total=False):
    """Worker-reported observed-read coverage (coverage_observation.schema.json)."""

    schema_version: str
    snapshot_id: str
    unit_id: str
    dimension: str
    source: str
    ranges: List[CoverageRange]
    confidence: str


class ErrorEnvelope(TypedDict, total=False):
    """Structured error envelope (error.schema.json)."""

    schema_version: str
    code: str
    message: str
    retryable: bool
    details: Dict[str, Any]


class Frontier(TypedDict, total=False):
    """Half-chain frontier record (frontier.schema.json, DSR-026/058)."""

    schema_version: str
    frontier_id: str
    source: Dict[str, Any]
    boundary: str
    steps: List[Step]
    open_questions: List[str]
    provenance: Dict[str, Any]


class SinkProbe(TypedDict, total=False):
    """Half-chain sink probe record (sink_probe.schema.json, DSR-026/058)."""

    schema_version: str
    probe_id: str
    sink: Dict[str, Any]
    boundary: str
    steps: List[Step]
    guard_analysis: str
    open_questions: List[str]
    provenance: Dict[str, Any]


class GateCheckData(TypedDict, total=False):
    """Single check within a gate result (gate_result.schema.json checks items)."""

    check_id: str
    name: str
    status: str
    message: str
    evidence_ref: str


class GateResultData(TypedDict, total=False):
    """Serialized gate result (gate_result.schema.json)."""

    schema_version: str
    gate_id: str
    status: str
    checks: List[GateCheckData]
    revision: int
    reason: str


class Guard(TypedDict, total=False):
    """Guard mechanism record (guard.schema.json, DSR-024)."""

    schema_version: str
    guard_id: str
    status: str
    mechanism: str
    anchors: List[Dict[str, Any]]
    applicability: str
    exceptions: List[str]


class RunScope(TypedDict, total=False):
    """Audit scope selection (run_config.schema.json properties/scope)."""

    include: List[str]
    exclude: List[str]
    languages: List[str]


class SafetyAcceptance(TypedDict, total=False):
    """User safety acceptance flags (run_config.schema.json)."""

    allow_unverified_execution: bool
    allow_unverified_network: bool
    allow_unverified_write: bool
    user_approved: bool


class RunConfig(TypedDict, total=False):
    """Audit run configuration (run_config.schema.json)."""

    schema_version: str
    target: str
    run_dir: str
    report_language: str
    profile: str
    scope: RunScope
    budgets: List[Dict[str, Any]]
    safety_acceptance: SafetyAcceptance


class SnapshotFileEntry(TypedDict, total=False):
    """Frozen snapshot file record (snapshot_manifest.schema.json files items)."""

    path: str
    sha256: str
    bytes: int
    line_count: int
    encoding: str
    component: str
    language: str


class SnapshotManifest(TypedDict, total=False):
    """Frozen snapshot manifest (snapshot_manifest.schema.json).

    Note: the runtime SnapshotManifest.to_dict() surface additionally carries
    honest accounting fields (gaps / source_control / drift_detected) that the
    schema surface does not declare; this typed contract mirrors the schema.
    """

    schema_version: str
    snapshot_id: str
    hash_algorithm: str
    root_hash: str
    files: List[SnapshotFileEntry]
    excluded: List[Dict[str, Any]]
    collection_assumptions: List[str]


class Unit(TypedDict, total=False):
    """Planned analysis unit (unit.schema.json).

    Note: runtime slicing additionally stamps tier/disposition (DSR-056) which
    the schema surface does not declare; this typed contract mirrors the
    schema.
    """

    schema_version: str
    unit_id: str
    snapshot_id: str
    component: str
    language: str
    ranges: List[Dict[str, Any]]
    risk_factors: List[str]


class Candidate(TypedDict, total=False):
    """Hunt-stage candidate (candidate.schema.json)."""

    schema_version: str
    candidate_id: str
    issue: str
    source: Dict[str, Any]
    sink: Dict[str, Any]
    steps: List[Step]
    guard_analysis: str
    impact_claim: str
    open_questions: List[str]
    provenance: Dict[str, Any]


class Usage(TypedDict, total=False):
    """Trusted host usage record (usage.schema.json / DSR-033)."""

    schema_version: str
    attempt_id: str
    dimension: str
    availability: str  # "exact" | "estimated" | "unavailable"
    value: int
    unit: str
    source: str
    reason: str


class Finding(TypedDict, total=False):
    """Audit finding (finding.schema.json)."""

    schema_version: str
    finding_id: str
    run_id: str
    candidate_refs: List[str]
    verdict: str
    evidence_level: str
    provenance: Dict[str, Any]
    title: str
    issue: str
    languages: List[str]
    source: Dict[str, Any]
    sink: Dict[str, Any]
    steps: List[Step]
    guards: List[Dict[str, Any]]
    attacker: str
    preconditions: List[str]
    rating: Dict[str, Any]
    remediation: Dict[str, Any]
    variants: List[str]
    blockers: List[str]
    validation_plan: str
    counter_evidence: Dict[str, Any]
    unverified_reason: str
    variant_search: Dict[str, Any]
    second_opinion: Dict[str, Any]
