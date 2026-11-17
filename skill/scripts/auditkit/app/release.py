"""Release gate evaluator for GATE-01..GATE-07 (DSR-051 / SWR-026).

Aggregates evidence produced by unified testing (capability matrix, test
results, evidence files) into per-gate GateResult verdicts, using the same
GateResult contract as the runtime G0..G4 gates (contracts.gates, read-only
import).

Design source: docs/design/SOFTWARE_DESIGN_REVIEW.md §3 "尚未关闭的验证门禁".
Behavioral rules (DSR-051):
- Every GATE-01..07 yields pass / fail / not_applicable + reason
  (not_applicable always carries an explicit reason, DSR-022).
- Any required capability whose state is "unknown" is treated as NOT supported:
  the gate fails and the release conclusion is blocked. Unverified capabilities
  are never silently promoted to supported (design principle 8).
- The aggregate verdict ("release_allowed") is False whenever any gate is not
  pass (fail, unknown-evidence fail, or not_applicable); the blocking reasons
  are reported explicitly. Fail-closed: an unverified or explicitly deferred
  gate never lets a release through.
"""

# 需求追踪 (Requirement Traceability)
# ---------------------------------------------------------------------------
# 上层需求: docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2
# 设计依据: docs/design/SOFTWARE_DESIGN_REVIEW.md §3, docs/design/SOFTWARE_DESIGN.md §8
# SWR-026  G0~G4 与 GATE-01~07 证据汇总与发布检查；未知能力不标支持
#   绑定实现: DSR-051
# 状态以统一测试结论为准；未实测能力保持 unknown（设计原则 8：能观测的不靠声明）。
#

from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from auditkit.contracts.errors import InvalidInputError
from auditkit.contracts.gates import GateCheck, GateResult

# Evidence entry: either an inline dict or a path to a JSON evidence file.
EvidenceEntry = Union[Dict[str, Any], str, Path, None]

VALID_ENTRY_STATUSES = ("pass", "fail", "unknown", "not_applicable")

GATE_IDS = ("GATE-01", "GATE-02", "GATE-03", "GATE-04", "GATE-05", "GATE-06", "GATE-07")

GATE_DESCRIPTIONS: Dict[str, str] = {
    "GATE-01": "明确受支持的 Claude/Codex 版本，并在真实宿主验证结构化结果、配置加载、委派、只读/执行/网络和认证。",
    "GATE-02": "用并发/崩溃/迟到提交及快照竞态夹具验证一致性，给出文件系统适用范围。",
    "GATE-03": "以宿主证据证明 token/费用最坏上限和用量完整性，或只发布明确的软预算/任务预算模式。",
    "GATE-04": "逐语言评审 150 类的公开依据、适用性和正反例，实际测量跨单元与留出语料。",
    "GATE-05": "在规定机器、文件分布、预算及统计口径下测量性能、成本与覆盖；公布缺失数据。",
    "GATE-06": "明确导出字段、敏感性、人工审核责任和失败关闭行为；以合成反例测试。",
    "GATE-07": "选定受支持 Python 下限、JSON Schema 子集与 CLI/MCP 接口版本并通过兼容测试。",
}


def _load_entry(entry: EvidenceEntry, gate_id: str) -> Dict[str, Any]:
    """Normalize an evidence entry (inline dict or JSON file path) to a dict.

    Requirements: SWR-026(证据缺失unknown) / DSR-051(缺证据不标支持)
    """
    if entry is None:
        return {"status": "unknown", "summary": f"{gate_id}: 未提供证据"}
    if isinstance(entry, (str, Path)):
        p = Path(entry)
        if not p.exists():
            return {"status": "unknown", "summary": f"{gate_id}: 证据文件不存在: {p}"}
        try:
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError) as ex:
            return {"status": "unknown", "summary": f"{gate_id}: 证据文件不可解析: {ex}"}
        if not isinstance(data, dict):
            return {"status": "unknown", "summary": f"{gate_id}: 证据文件顶层必须是 JSON 对象"}
        return data
    if isinstance(entry, dict):
        return dict(entry)
    raise InvalidInputError(f"{gate_id}: 不支持的证据类型 {type(entry).__name__}")


class ReleaseGateEvaluator:
    """Evaluates release gates GATE-01..GATE-07 against unified-test evidence."""

    def __init__(self, evidence: Optional[Dict[str, Any]] = None) -> None:
        """Hold the unified-test evidence bundle for GATE-01..07 evaluation.

        Requirements: SWR-026(发布门禁) / DSR-051(证据汇总)
        """
        self.evidence: Dict[str, Any] = dict(evidence or {})

    # -- evidence accessors ---------------------------------------------------

    def _gate_evidence(self, gate_id: str) -> Dict[str, Any]:
        """Load one gate's evidence entry (missing becomes unknown).

        Requirements: SWR-026(门禁证据) / DSR-051(support)
        """
        return _load_entry(self.evidence.get(gate_id), gate_id)

    def _requirement_evidence(self, key: str) -> Dict[str, Any]:
        """Load a named supporting-evidence entry (compatibility tests, ...).

        Requirements: SWR-026(佐证证据) / DSR-051(support)
        """
        return _load_entry(self.evidence.get(key), key)

    @staticmethod
    def _entry_status(data: Dict[str, Any]) -> str:
        """Normalize an entry status; unrecognized values fall to unknown.

        Requirements: SWR-026(未知不标支持) / DSR-051(状态收敛)
        """
        status = str(data.get("status", "unknown")).lower()
        return status if status in VALID_ENTRY_STATUSES else "unknown"

    # -- per-gate checks ------------------------------------------------------

    def check_gate_01(self) -> GateResult:
        """Host support matrix: real-host verified versions + capabilities.

        Any required capability that is unknown/unverified means the host
        combination is NOT supported (blocking, per the design review).

        Requirements: SWR-026(发布门禁), SWR-023(宿主实测) / DSR-051(unknown不标支持)
        """
        gate_id = "GATE-01"
        data = self._gate_evidence(gate_id)
        matrix = data.get("capability_matrix") or self.evidence.get("capability_matrix") or {}
        checks: List[GateCheck] = []
        if not matrix:
            checks.append(GateCheck(
                "GATE-01-a", "Capability matrix present", "fail",
                "未提供宿主能力矩阵（capability_matrix）；未验证的组合不标受支持",
            ))
            return GateResult(gate_id, "fail", checks, 0, "无能力矩阵证据")

        blocking: List[str] = []
        for host, caps in sorted(matrix.items()):
            if not isinstance(caps, dict):
                blocking.append(f"{host}: 能力矩阵条目格式无效")
                continue
            for cap, state in sorted(caps.items()):
                state_s = str(state).lower()
                if state_s in ("unknown", "unverified", "not_verified"):
                    blocking.append(f"{host}.{cap}=unknown")
                elif state_s not in ("verified", "pass", "enforced", "supported"):
                    blocking.append(f"{host}.{cap}={state_s}")
        if blocking:
            checks.append(GateCheck(
                "GATE-01-b", "Real-host capability verification", "fail",
                "必需能力未在真实宿主验证（unknown 不标支持）: " + ", ".join(blocking),
            ))
            return GateResult(gate_id, "fail", checks, 0, "存在 unknown/unverified 必需能力")

        checks.append(GateCheck(
            "GATE-01-b", "Real-host capability verification", "pass",
            "全部必需能力在真实宿主验证通过",
        ))
        return GateResult(gate_id, "pass", checks, 0, data.get("summary"))

    def check_generic(self, gate_id: str, check_name: str) -> GateResult:
        """Generic single-evidence gate: status comes from the gate's evidence entry.

        Requirements: SWR-026(门禁三态) / DSR-051(NA必有理由), DSR-022(契约一致)
        """
        data = self._gate_evidence(gate_id)
        status = self._entry_status(data)
        summary = str(data.get("summary") or "")
        checks: List[GateCheck] = []
        if status == "pass":
            checks.append(GateCheck(f"{gate_id}-a", check_name, "pass", summary or "证据通过"))
            return GateResult(gate_id, "pass", checks, 0, data.get("summary"))
        if status == "not_applicable":
            reason = summary or f"{gate_id} 标记为 not_applicable"
            checks.append(GateCheck(f"{gate_id}-a", check_name, "not_applicable", reason))
            return GateResult(gate_id, "not_applicable", checks, 0, reason)
        if status == "fail":
            reason = summary or f"{gate_id} 证据为 fail"
            checks.append(GateCheck(f"{gate_id}-a", check_name, "fail", reason))
            return GateResult(gate_id, "fail", checks, 0, reason)
        # unknown / missing evidence: never silently supported
        reason = summary or f"{gate_id} 证据缺失或状态 unknown；不支持/阻止发布"
        checks.append(GateCheck(f"{gate_id}-a", check_name, "fail", reason))
        return GateResult(gate_id, "fail", checks, 0, reason)

    def check_gate_07(self) -> GateResult:
        """Supported Python floor, JSON Schema subset, CLI/MCP interface versions.

        Additionally cross-checks test_results["compatibility"] when provided:
        an explicit fail there overrides an otherwise passing evidence entry.

        Requirements: SWR-026(发布门禁), SWR-024(版本下限) / DSR-051(兼容必过)
        """
        gate_id = "GATE-07"
        result = self.check_generic(gate_id, "Python 下限 / Schema 子集 / CLI+MCP 接口版本")
        compat = self._requirement_evidence("compatibility_tests")
        compat_status = self._entry_status(compat)
        if compat_status == "fail":
            reason = str(compat.get("summary") or "兼容测试失败")
            result.checks.append(GateCheck("GATE-07-b", "Compatibility test suite", "fail", reason))
            return GateResult(gate_id, "fail", result.checks, 0, reason)
        if compat_status == "unknown":
            result.checks.append(GateCheck(
                "GATE-07-b", "Compatibility test suite", "fail",
                "兼容测试证据缺失或 unknown；未测版本不公布为支持",
            ))
            return GateResult(gate_id, "fail", result.checks, 0, "兼容测试证据缺失")
        result.checks.append(GateCheck("GATE-07-b", "Compatibility test suite", "pass",
                                      str(compat.get("summary") or "兼容测试通过")))
        return result

    # -- aggregate ------------------------------------------------------------

    def evaluate_gate(self, gate_id: str) -> GateResult:
        """Evaluate a single release gate by id.

        Requirements: SWR-026(按门禁评估) / DSR-051(未知门禁拒绝)
        """
        if gate_id not in GATE_IDS:
            raise InvalidInputError(f"Unknown release gate id '{gate_id}'")
        if gate_id == "GATE-01":
            return self.check_gate_01()
        if gate_id == "GATE-07":
            return self.check_gate_07()
        return self.check_generic(gate_id, GATE_DESCRIPTIONS[gate_id])

    def evaluate_all(self, evidence: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Evaluate all release gates and produce the release conclusion.

        Returns a dict with per-gate GateResult dicts, the overall verdict and
        blocking reasons. Any gate that is not pass blocks the release —
        including not_applicable, which requires (and always has) an explicit
        reason (DSR-022) and is listed as blocking so deferred gates can never
        be silently promoted into an allowed release.

        Requirements: SWR-026(发布结论) / DSR-051(阻塞明示), DSR-022(NA理由)
        """
        if evidence is not None:
            self.evidence = dict(evidence)

        gate_results: List[GateResult] = [self.evaluate_gate(g) for g in GATE_IDS]
        blocking: List[str] = []
        for res in gate_results:
            if res.status == "pass":
                continue
            reason = res.reason or ""
            detail = "; ".join(c.message for c in res.checks if c.status != "pass")
            combined = " — ".join(part for part in (reason, detail) if part) or res.status
            blocking.append(f"{res.gate_id}: {res.status} — {combined}")

        release_allowed = not blocking
        verdict = (
            "release_allowed"
            if release_allowed
            else "release_blocked"
        )
        return {
            "schema_version": "1.0",
            "verdict": verdict,
            "release_allowed": release_allowed,
            "gates": [res.to_dict() for res in gate_results],
            "blocking": blocking,
            "conclusion": (
                "全部发布门禁通过，允许发布。"
                if release_allowed
                else "发布被阻止：存在 fail/unknown 门禁或未验证（unknown）必需能力；相应组合不标受支持。"
            ),
        }
