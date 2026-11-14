"""Typed interface definitions for core polyglot-audit exchange objects.

Implements DSR-073:
- Provides TypedDict definitions for Finding, Candidate, TaskSpec, Usage, and
  GateResult so that the gate and usage chains (and external consumers) share a
  single typed source of truth with the JSON schemas in skill/schemas/.
- These are typing-only views over plain dicts; no runtime coercion is performed.
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
from typing import Any, Dict, List, TypedDict


class Anchor(TypedDict, total=False):
    """Source location anchor used in traces and findings."""

    path: str
    line_start: int
    line_end: int
    file_sha256: str


class TaskSpec(TypedDict, total=False):
    """Task specification packet handed to a worker (task_spec.schema.json)."""

    schema_version: str
    task_id: str
    kind: str
    unit_ids: List[str]
    packet_digest: str
    priority: int
    limits: Dict[str, Any]


class Step(TypedDict, total=False):
    """Single trace step from source to sink."""

    path: str
    line: int
    role: str
    note: str
    lang: str


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


class GateCheckData(TypedDict, total=False):
    """Single check within a gate result (gate_result.schema.json)."""

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
