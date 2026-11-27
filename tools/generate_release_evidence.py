#!/usr/bin/env python3
"""Release evidence generator — one command, unified-test evidence into docs/evidence/
(DSR-051 / SR-029).

Runs the automated evidence collectors as independent subprocess steps and
normalizes their outputs into per-gate JSON evidence files, then drives
``auditkit.app.release.ReleaseGateEvaluator`` over them to produce the release
conclusion:

1. ``python3 tools/run_all_tests.py``            -> parsed per-category results
   written as gateNN-summary.json (gate01 real_cli, gate02 fault_injection,
   gate05 scale/performance, gate07 stdlib/CLI-compat proxy categories) with
   counts / duration / skip list / timestamp / environment+hardware.
2. ``python3 tools/evaluate_holdout.py <corpus> <knowledge>`` -> gate04-holdout.json
   (denominator / detections / false positives / unknown categories; the
   LLM-side results stay whatever the tool honestly reported — "unknown":
   no online model evaluation is fabricated here).
3. ``python3 tools/probe_isolation.py``          -> gate01-isolation.json.
4. ``python3 skill/scripts/audit.py doctor --probe`` -> gate01-capability-matrix.json
   (normalized capability_matrix consumed by the GATE-01 check).
5. targeted export-boundary unittest run (tests/security + tests/reporting +
   tests/swr lessons, filtered to export/whitelist/lessons/secret/mask with
   ``-k``) -> gate06-export-boundary.json (per-test outcomes / counts /
   timestamp / environment; the expert-review part of GATE-06 stays manual).
6. GATE-03 usage evidence read: docs/evidence/gate03-usage-unavailable.json
   (coordinator-produced real-run measurement) is consumed verbatim into the
   release summary; missing file/fields stay ``unknown`` — nothing invented.
7. ``ReleaseGateEvaluator.evaluate_all(evidence)`` -> release_gate_summary.json
   (per-GATE pass/fail/unknown + release_allowed conclusion).

Design constraints (DSR-051 / SR-029 / design principle 8):
- Every step runs in its own try: a failing step never blocks the remaining
  evidence collection; the failed step records ``error`` + ``status: unknown``
  instead of invented data.
- Every emitted JSON carries ``generated_at`` and the environment/hardware
  block.
- Nothing is fabricated: items that cannot be automated (LLM online
  evaluation, expert review of the 150 knowledge cards, provider-side token
  cost bounds, aggressive-level isolation counterexamples, expert review of
  export-field sensitivity) stay unknown and are listed under
  ``manual_pending`` in the release summary. A blocked release is the
  expected honest outcome until those human steps are done.

Usage:
    python3 tools/generate_release_evidence.py                 # full collection
    python3 tools/generate_release_evidence.py --out DIR       # custom evidence dir
    python3 tools/generate_release_evidence.py --skip-tests    # reuse, no full test run
"""

# 需求追踪 (Requirement Traceability)
# ---------------------------------------------------------------------------
# 上层需求: docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2 (SR-029)
# 设计依据: docs/design/SOFTWARE_DESIGN.md §8, docs/design/SOFTWARE_DESIGN_REVIEW.md §3
# SWR-026  G0~G4 与 GATE-01~07 证据汇总与发布检查；未知能力不标支持
# SWR-029  统一测试编排：五类套件分组汇总；缺失/跳过单列；禁止把 mock 计为真实宿主通过
#   绑定实现: DSR-051 (ReleaseGateEvaluator), 本工具做证据自动收集与规约
# SR-020/DSR-033  GATE-03 用量遥测实测证据只读接入（P2.1a，协调方产物；
#   downgrade_documented 走 SD §5.2 明确降级分支，不给 pass）
# SR-016/SWR-016  GATE-06 导出边界定向测试自动化规约（P2.1b，
#   gate06-export-boundary.json；专家评审保持 manual）
# 状态以统一测试结论为准；未实测能力保持 unknown（设计原则 8：能观测的不靠声明）。
# ---------------------------------------------------------------------------

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

ROOT_DIR = Path(__file__).resolve().parent.parent
SKILL_SCRIPTS = ROOT_DIR / "skill" / "scripts"
DEFAULT_OUT_DIR = ROOT_DIR / "docs" / "evidence"
HOLDOUT_CORPUS_DIR = ROOT_DIR / "tests" / "fixtures" / "holdout"
KNOWLEDGE_DIR = ROOT_DIR / "skill" / "knowledge"

if str(SKILL_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SKILL_SCRIPTS))

from auditkit.app.release import ReleaseGateEvaluator  # noqa: E402

EVIDENCE_SCHEMA_VERSION = "1.0"

# Subprocess budgets. run_all_tests runs the whole unified suite (observed
# ~1-2 min); the collectors are single-purpose tools.
STEP_TIMEOUTS_SECONDS = {
    "run_all_tests": 3600,
    "evaluate_holdout": 600,
    "probe_isolation": 600,
    "doctor_probe": 600,
    "gate06_export_tests": 600,
}

# GATE-03 usage evidence (P2.1a): coordinator-produced real-run artifact. The
# generator CONSUMES it (never rewrites it): its ``status`` /
# ``release_note_required`` fields are passed through verbatim; a missing file
# or missing fields stay ``unknown`` in the summary (nothing invented).
GATE03_USAGE_EVIDENCE_NAME = "gate03-usage-unavailable.json"
GATE03_DOWNGRADE_STATUS = "downgrade_documented"

# GATE-06 export-boundary tests (P2.1b): a targeted unittest run filtered to
# the export-boundary assertions (whitelist fail-closed, export default-off,
# secret masking, lessons.md never exported). Modules are named explicitly —
# package-name loading finds nothing under tests.reporting without a
# load_tests hook. The patterns are OR-combined substring filters (case
# insensitive) applied by unittest -k.
GATE06_EXPORT_TEST_MODULES = (
    "tests.security.test_skill_isolation",
    "tests.reporting.test_reporting",
    "tests.swr.test_swr_031",
)
GATE06_EXPORT_TEST_PATTERNS = ("export", "whitelist", "lessons", "secret", "mask")

# GATE-NN <- run_all_tests category mapping (DSR-078 five-category split).
# gate07 additionally cites the stdlib-only checks that run in the scale
# category; the mapping keeps one primary category per gate file.
GATE_CATEGORIES: Dict[str, Dict[str, str]] = {
    "GATE-01": {
        "category": "real_cli",
        "title": "真实宿主 CLI 测试（tests/hosts/test_real_hosts.py ONLY）",
    },
    "GATE-02": {
        "category": "fault_injection",
        "title": "并发/崩溃/迟到提交/快照竞态夹具",
    },
    "GATE-05": {
        "category": "scale",
        "title": "规定口径下的性能、成本与覆盖（含 stdlib-only 环境检查）",
    },
    "GATE-07": {
        "category": "deterministic",
        "title": "Python 下限 / Schema 子集 / CLI+MCP 接口兼容（确定性套件代理口径）",
    },
}

RUN_ALL_TOTAL_RE = re.compile(
    r"^Total: tests=(?P<tests>\d+) fail=(?P<fail>\d+) err=(?P<err>\d+) "
    r"skipped=(?P<skip>\d+) missing=(?P<missing>\d+) time=(?P<time>\d+(?:\.\d+)?)s"
)
RUN_ALL_RESULT_RE = re.compile(r"^RESULT: (?P<result>.+)$")


# ---------------------------------------------------------------------------
# Environment / hardware disclosure (every emitted file carries it)
# ---------------------------------------------------------------------------

def environment_info() -> Dict[str, Any]:
    """Observable environment + hardware facts (stdlib only, no fabrication)."""
    info: Dict[str, Any] = {
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "machine": platform.machine() or "unknown",
        "processor": platform.processor() or "unknown",
        "cpu_count": os.cpu_count() or "unknown",
        "hostname": "unknown",
    }
    try:
        info["hostname"] = platform.node() or "unknown"
    except Exception:  # noqa: BLE001 - disclosure must never crash collection
        pass
    mem_bytes = "unknown"
    try:
        if sys.platform == "linux" and os.path.exists("/proc/meminfo"):
            with open("/proc/meminfo", "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        mem_bytes = int(line.split()[1]) * 1024
                        break
    except (OSError, ValueError, IndexError):
        mem_bytes = "unknown"
    info["memory_total_bytes"] = mem_bytes
    return info


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# ---------------------------------------------------------------------------
# run_all_tests.py output parsing (text summary table -> structured counts)
# ---------------------------------------------------------------------------

def _parse_summary_row(line: str) -> Optional[Dict[str, Any]]:
    """Parse one summary-table row using the orchestrator's fixed layout.

    run_all_tests.py renders rows as
    ``f"{category:<16} {label:<34} {n:>5} {f:>5} {e:>5} {s:>5} {t:>6.1f}s  {st}"``
    so the column positions are fixed; fixed slicing is immune to large
    counts that would defeat whitespace-splitting heuristics. Returns None
    for anything that does not match the layout.
    """
    if len(line) < 85:
        return None
    category = line[0:16].strip()
    if category not in ("deterministic", "real_cli", "model_eval",
                        "fault_injection", "scale"):
        return None
    try:
        tests = int(line[52:57])
        fail = int(line[58:63])
        err = int(line[64:69])
        skip = int(line[70:75])
        duration = float(line[76:82])
    except ValueError:
        return None
    return {
        "category": category,
        "suite": line[17:51].strip(),
        "tests": tests,
        "fail": fail,
        "error": err,
        "skipped": skip,
        "duration_seconds": duration,
        "status": line[85:].strip(),
    }


def parse_run_all_output(stdout: str) -> Dict[str, Any]:
    """Parse the DSR-078 orchestrator summary table.

    Returns {"suites": [row dicts], "categories": {name: aggregate},
    "total": {...}, "result_line": str}. Suite-level ``skipped`` counts and
    SKIPPED-NOT-PASSED statuses are the honest skip list; the orchestrator
    does not emit per-test skip ids, and this parser does not invent them.
    """
    suites: List[Dict[str, Any]] = []
    subtotals: Dict[str, Dict[str, Any]] = {}
    total: Dict[str, Any] = {}
    result_line = ""

    for raw in stdout.splitlines():
        line = raw.strip()
        row = _parse_summary_row(line)
        if row is not None:
            if row["suite"] == "-- subtotal --":
                subtotals[row["category"]] = row
            else:
                suites.append(row)
            continue
        total_match = RUN_ALL_TOTAL_RE.match(line)
        if total_match:
            total = {
                "tests": int(total_match.group("tests")),
                "fail": int(total_match.group("fail")),
                "error": int(total_match.group("err")),
                "skipped": int(total_match.group("skip")),
                "missing_suites": int(total_match.group("missing")),
                "duration_seconds": float(total_match.group("time")),
            }
            continue
        result_match = RUN_ALL_RESULT_RE.match(line)
        if result_match:
            result_line = result_match.group("result").strip()

    categories: Dict[str, Dict[str, Any]] = {}
    for category in {s["category"] for s in suites} | set(subtotals):
        cat_suites = [s for s in suites if s["category"] == category]
        subtotal = subtotals.get(category)
        if subtotal:
            agg = {
                "tests": subtotal["tests"],
                "fail": subtotal["fail"],
                "error": subtotal["error"],
                "skipped": subtotal["skipped"],
                "duration_seconds": subtotal["duration_seconds"],
            }
        else:
            agg = {
                "tests": sum(s["tests"] for s in cat_suites),
                "fail": sum(s["fail"] for s in cat_suites),
                "error": sum(s["error"] for s in cat_suites),
                "skipped": sum(s["skipped"] for s in cat_suites),
                "duration_seconds": round(
                    sum(s["duration_seconds"] for s in cat_suites), 1
                ),
            }
        agg["missing_suites"] = sum(
            1 for s in cat_suites if s["status"].startswith("MISSING")
        )
        agg["suites"] = cat_suites
        categories[category] = agg

    return {
        "suites": suites,
        "categories": categories,
        "total": total,
        "result_line": result_line,
    }


def category_verdict(cat: Optional[Dict[str, Any]], category: str) -> Tuple[str, str]:
    """Honest per-category verdict: fail / pass / unknown (never invented).

    - failures or errors -> fail
    - nothing ran (all skipped / all suites missing) -> unknown
      (SKIPPED-NOT-PASSED is never a pass)
    - at least one test ran with no failure -> pass (skips stay listed)
    """
    if not cat:
        return (
            "unknown",
            f"类别 {category} 未出现在编排器输出中；证据保持 unknown（未运行，不 claim）",
        )
    missing = cat.get("missing_suites", 0)
    if cat["fail"] or cat["error"]:
        return (
            "fail",
            f"类别 {category} 存在 fail={cat['fail']} error={cat['error']}",
        )
    if missing and cat["tests"] == 0:
        return "unknown", f"类别 {category} 的套件缺失/未发现（能力保持 unknown）"
    if cat["tests"] == 0 and cat["skipped"] > 0:
        return (
            "unknown",
            f"类别 {category} 全部跳过（SKIPPED-NOT-PASSED；跳过永远不计为通过）",
        )
    if cat["tests"] == 0:
        return "unknown", f"类别 {category} 无可运行测试（保持 unknown）"
    summary = (
        f"类别 {category}: tests={cat['tests']} fail=0 error=0 "
        f"skipped={cat['skipped']} 耗时 {cat['duration_seconds']}s"
    )
    if cat["skipped"]:
        summary += f"（{cat['skipped']} 项跳过，单列不计入通过分母）"
    if missing:
        summary += f"（{missing} 个套件缺失，保持 unknown）"
    return "pass", summary


def build_gate_test_summary(
    gate_id: str,
    title: str,
    category: str,
    parsed: Dict[str, Any],
    env: Dict[str, Any],
    extra_notes: Optional[List[str]] = None,
    orchestrator_exit_code: Optional[int] = None,
) -> Dict[str, Any]:
    """Normalize one run_all_tests category into a GATE evidence file body.

    ``orchestrator_exit_code`` is recorded verbatim: a non-zero exit means
    some category failed (the per-category verdict carries which), never
    that the whole output is unusable.
    """
    cat = parsed["categories"].get(category)
    status, summary = category_verdict(cat, category)
    notes = list(extra_notes or [])
    if orchestrator_exit_code not in (None, 0):
        notes.append(
            f"编排器退出码为 {orchestrator_exit_code}（存在失败类别）；"
            "各门禁按其类别实测结论分别标注，不影响已通过类别的证据。"
        )
    skipped_suites = [
        {"suite": s["suite"], "skipped": s["skipped"], "status": s["status"]}
        for s in (cat or {}).get("suites", [])
        if s["skipped"] or s["status"].startswith(("SKIPPED", "MISSING"))
    ]
    if not cat:
        notes.append("编排器输出中无该类别；本文件只记录 unknown，不宣称通过。")
    notes.append(
        "skip 清单为套件粒度（编排器只输出套件级 skipped 计数；不伪造逐测试 skip id）。"
    )
    return {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "gate": gate_id,
        "evidence_kind": "unified_test_category",
        "title": title,
        "source": {
            "tool": "tools/run_all_tests.py",
            "category": category,
            "orchestrator_exit_code": orchestrator_exit_code,
            "orchestrator_result": parsed.get("result_line", ""),
        },
        "generated_at": utc_now(),
        "environment": env,
        "status": status,
        "summary": summary,
        "counts": {
            "tests": (cat or {}).get("tests", 0),
            "fail": (cat or {}).get("fail", 0),
            "error": (cat or {}).get("error", 0),
            "skipped": (cat or {}).get("skipped", 0),
            "missing_suites": (cat or {}).get("missing_suites", 0),
        },
        "duration_seconds": (cat or {}).get("duration_seconds", 0.0),
        "skipped_or_missing_suites": skipped_suites,
        "suites": (cat or {}).get("suites", []),
        "notes": notes,
    }


# ---------------------------------------------------------------------------
# doctor --probe envelope -> capability matrix evidence (GATE-01)
# ---------------------------------------------------------------------------

def extract_doctor_capabilities(stdout: str) -> Optional[List[Dict[str, Any]]]:
    """Extract the capability list from the audit.py doctor JSON envelope.

    Defensive by design: the envelope shape is `{"ok": true, "value": {...}}`;
    if a parallel workstream reshapes the envelope, the capabilities list is
    still located by key rather than by exact path. Returns None when the
    output cannot be parsed honestly.
    """
    for line in reversed(stdout.splitlines()):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            envelope = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(envelope, dict):
            continue
        if envelope.get("ok") is False:
            return None
        value = envelope.get("value", envelope)
        if isinstance(value, dict):
            caps = value.get("capabilities")
            if isinstance(caps, list):
                return caps
    return None


def build_capability_matrix_evidence(
    capabilities: List[Dict[str, Any]],
    env: Dict[str, Any],
    real_cli_gate: Dict[str, Any],
) -> Dict[str, Any]:
    """Normalize doctor capabilities into the matrix the GATE-01 check reads.

    ``capability_matrix`` maps adapter -> feature -> state (lower-case), the
    exact shape ReleaseGateEvaluator.check_gate_01 consumes. States stay as
    probed: unknown / not_enforced are preserved verbatim so the gate fails
    closed on unverified capabilities (design principle 8).
    """
    matrix: Dict[str, Dict[str, str]] = {}
    for cap in capabilities:
        adapter = str(cap.get("adapter") or "unknown_adapter")
        features = cap.get("features") or {}
        per_host: Dict[str, str] = {}
        for name, feat in features.items():
            state = feat.get("state", "unknown") if isinstance(feat, dict) else str(feat)
            per_host[name] = str(state).lower()
        matrix[adapter] = per_host
    blocking = [
        f"{host}.{feat}={state}"
        for host, feats in sorted(matrix.items())
        for feat, state in sorted(feats.items())
        if state not in ("verified", "pass", "enforced", "supported")
    ]
    status = "fail" if blocking else "pass"
    summary = (
        "全部必需能力在真实宿主验证通过"
        if status == "pass"
        else "存在未验证（unknown/not_enforced）能力；相应组合不标受支持: " + ", ".join(blocking[:12])
        + (f" 等 {len(blocking)} 项" if len(blocking) > 12 else "")
    )
    return {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "gate": "GATE-01",
        "evidence_kind": "host_capability_matrix",
        "generated_at": utc_now(),
        "environment": env,
        "status": status,
        "summary": summary,
        "capability_matrix": matrix,
        "real_cli_gate": {
            "status": real_cli_gate.get("status"),
            "summary": real_cli_gate.get("summary"),
        },
        "adapters": capabilities,
        "notes": [
            "矩阵由 `audit.py doctor --probe`（headless 级）归一化；状态为探测原值，未提升。",
            "aggressive 级反例（执行/网络隔离）未由本工具执行；对应能力保持探测原状态。",
        ],
    }


# ---------------------------------------------------------------------------
# holdout / isolation evidence (GATE-04, GATE-01 isolation)
# ---------------------------------------------------------------------------

def build_holdout_evidence(report: Dict[str, Any], env: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize the holdout tool report into GATE-04 evidence.

    The gate04 requirement includes per-language expert review of the 150
    cards, an independent (maintainer-authored) holdout corpus, and real
    LLM-side measurement. Only the signal-level wiring measurement is
    automated, so the gate evidence stays ``unknown`` overall — the measured
    numbers are recorded verbatim, never promoted into a pass.
    """
    llm = report.get("llm_worker") or {}
    totals = report.get("totals") or {}
    return {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "gate": "GATE-04",
        "evidence_kind": "holdout_evaluation",
        "generated_at": utc_now(),
        "environment": env,
        "status": "unknown",
        "summary": (
            "已自动化：信号级留出语料接线评测（分母={denominator}, 检出 tp={tp}, "
            "漏报 fn={fn}, 误报 fp={fp}, 未决 pending={pending}, unknown 类别={unknown}/{cards}）。"
            "未自动化（保持 unknown）：LLM 在线评测（llm_results={llm}）、独立留出集、"
            "150 类逐语言专家评审。".format(
                denominator=totals.get("denominator", "unknown"),
                tp=totals.get("true_positive", "unknown"),
                fn=totals.get("false_negative", "unknown"),
                fp=totals.get("false_positive", "unknown"),
                pending=totals.get("pending", "unknown"),
                unknown=totals.get("unknown_categories", "unknown"),
                cards=totals.get("cards_total", "unknown"),
                llm=llm.get("llm_results", "unknown"),
            )
        ),
        "totals": totals,
        "llm_results": llm.get("llm_results", "unknown"),
        "llm_worker": llm,
        "corpus_status": report.get("corpus_status", "unknown"),
        "disclaimer": report.get("disclaimer", ""),
        "report": report,
        "not_automated": [
            "LLM 在线评测（不伪造在线模型结论；llm_results 保持 unknown）",
            "独立维护者编写的留出集（当前语料为开发期合成数据）",
            "150 类知识卡逐语言公开依据/适用性/正反例专家评审",
        ],
    }


def build_isolation_evidence(report: Dict[str, Any], env: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize the isolation probe report into GATE-01 supporting evidence."""
    probes_list = report.get("probes") or []
    statuses = ", ".join(
        f"{p.get('probe')}={p.get('status')}" for p in probes_list
    ) or "no probes returned"
    return {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "gate": "GATE-01",
        "evidence_kind": "isolation_probe",
        "generated_at": utc_now(),
        "environment": env,
        # The tool itself scopes its result to demo fixtures and reports
        # real_target_results as unknown — that honesty carries over here.
        "status": "unknown",
        "summary": (
            f"开发期 demo 夹具探测: {statuses}; 真实目标隔离结果 "
            f"real_target_results={report.get('real_target_results', 'unknown')}（保持 unknown）"
        ),
        "probes": probes_list,
        "real_target_results": report.get("real_target_results", "unknown"),
        "limitations": report.get("limitations", []),
        "report": report,
    }


# ---------------------------------------------------------------------------
# GATE-03 usage evidence (coordinator artifact, consumed read-only)
# ---------------------------------------------------------------------------

def load_gate03_usage_evidence(path: Path, env: Dict[str, Any]) -> Dict[str, Any]:
    """Consume the coordinator-produced GATE-03 usage evidence verbatim.

    The file records the MEASURED real-run unavailability (26/26 attempts
    returned no usage block, SR-020/DSR-033) plus the honest-degradation
    markers (``status: "downgrade_documented"`` / ``release_note_required``).
    Requirements: SR-020 / DSR-033 / SD §5.2 (明确降级分支), P2.1a.

    Semantics (fail-closed by construction):
    - The markers are passed through AS-IS. A documented downgrade is never
      upgraded into a pass here: whether the gate can close (via the required
      release note) is a design-review decision, not a tool verdict.
    - A missing file, unreadable JSON, or missing ``status`` /
      ``release_note_required`` fields are recorded as ``unknown`` — the
      unknown capability is not invented away (design principle 8).
    """
    body: Dict[str, Any] = {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "gate": "GATE-03",
        "evidence_kind": "usage_telemetry_unavailable_measurement",
        "generated_at": utc_now(),
        "environment": env,
        "source": {"file": str(path)},
        "status": "unknown",
        "release_note_required": "unknown",
        "attempts_total": "unknown",
        "availability_distribution": {},
        "conclusion": "",
        "summary": "GATE-03 用量遥测证据缺失或不可解析；usage 完整性保持 unknown，不伪造。",
        "notes": [
            "本条目只归档协调方实测证据的规约视图（不重写原始文件）；"
            "门禁结论由 ReleaseGateEvaluator 按 SD §5.2 明确降级分支输出。",
        ],
    }
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except (OSError, ValueError) as exc:
        body["error"] = f"usage evidence unreadable: {exc}"
        return body
    if not isinstance(raw, dict):
        body["error"] = "usage evidence top level must be a JSON object"
        return body
    raw_status = raw.get("status")
    body["status"] = str(raw_status).strip().lower() if raw_status else "unknown"
    note_required = raw.get("release_note_required")
    body["release_note_required"] = (
        note_required if isinstance(note_required, bool) else "unknown"
    )
    body["attempts_total"] = raw.get("attempts_total", "unknown")
    dist = raw.get("availability_distribution")
    body["availability_distribution"] = dist if isinstance(dist, dict) else {}
    body["conclusion"] = str(raw.get("conclusion", ""))
    body["per_run_count"] = len(raw.get("per_run") or [])
    if body["status"] == GATE03_DOWNGRADE_STATUS:
        body["summary"] = (
            f"诚实降级已实测归档：attempts_total={body['attempts_total']}, "
            f"availability={body['availability_distribution']}；"
            f"release_note_required={body['release_note_required']}"
            "——工具只如实规约，不给 pass；门禁关闭与否由设计审查决定。"
        )
    elif body["status"] == "unknown":
        body["error"] = (
            "usage evidence lacks a recognized status field; recorded as unknown"
        )
    return body


# ---------------------------------------------------------------------------
# GATE-06 export-boundary unittest run (targeted -k filter)
# ---------------------------------------------------------------------------

_UNITTEST_ID_RE = re.compile(
    r"^(?P<name>\S+) \((?P<test_id>[^)]+)\)(?: \.\.\. (?P<inline>.+))?$"
)
_UNITTEST_OUTCOME_RE = re.compile(
    r"\.\.\. (?P<outcome>ok|FAIL|ERROR|skipped|expected failure|unexpected success)"
    r"(?: '(?P<reason>[^']*)')?\s*$"
)
# Single-line renderer form: the outcome follows the "... " separator, so the
# captured inline group is exactly the outcome token (no separator left).
_UNITTEST_INLINE_OUTCOME_RE = re.compile(
    r"^(?P<outcome>ok|FAIL|ERROR|skipped|expected failure|unexpected success)"
    r"(?: '(?P<reason>[^']*)')?\s*$"
)
_UNITTEST_RAN_RE = re.compile(r"^Ran (?P<total>\d+) tests? in (?P<seconds>\d+(?:\.\d+)?)s$")
_UNITTEST_RESULT_LINE_RE = re.compile(r"^(?P<result>(OK|FAILED).*)$")


def parse_unittest_verbose(stdout: str) -> Dict[str, Any]:
    """Parse ``python3 -m unittest -v`` output into per-test outcomes.

    Both renderer layouts are handled: the single-line form
    ``test_x (module.Class.test_x) ... ok`` and the two-line form where the
    test docstring is printed before the outcome line. Only tests with an
    observed outcome are listed — nothing is inferred for tests whose output
    was cut off (those lower the denominator honestly instead of passing).
    """
    tests: List[Dict[str, Any]] = []
    pending: Optional[str] = None
    ran_line = ""
    result_line = ""
    for raw_line in stdout.splitlines():
        line = raw_line.rstrip()
        # Summary/result lines are checked FIRST: "FAILED (failures=1)" has
        # the same parenthesized shape as a test id line and would otherwise
        # be swallowed as a stale pending id.
        stripped = line.strip()
        ran_match = _UNITTEST_RAN_RE.match(stripped)
        if ran_match:
            ran_line = stripped
            pending = None
            continue
        result_match = _UNITTEST_RESULT_LINE_RE.match(stripped)
        if result_match:
            result_line = result_match.group("result").strip()
            continue
        id_match = _UNITTEST_ID_RE.match(line)
        if id_match:
            inline = id_match.group("inline")
            if inline is None:
                pending = id_match.group("test_id")
                continue
            outcome_match = _UNITTEST_INLINE_OUTCOME_RE.match(inline)
            if outcome_match:
                tests.append({
                    "test_id": id_match.group("test_id"),
                    "outcome": outcome_match.group("outcome"),
                    "detail": outcome_match.group("reason"),
                })
                pending = None
            continue
        if pending:
            outcome_match = _UNITTEST_OUTCOME_RE.search(line)
            if outcome_match:
                tests.append({
                    "test_id": pending,
                    "outcome": outcome_match.group("outcome"),
                    "detail": outcome_match.group("reason"),
                })
                pending = None

    counts: Dict[str, Any] = {
        "passed": 0, "failed": 0, "errors": 0, "skipped": 0,
        "expected_failures": 0, "unexpected_successes": 0, "total": len(tests),
    }
    for t in tests:
        outcome = t["outcome"]
        if outcome == "ok":
            counts["passed"] += 1
        elif outcome == "FAIL":
            counts["failed"] += 1
        elif outcome == "ERROR":
            counts["errors"] += 1
        elif outcome == "skipped":
            counts["skipped"] += 1
        elif outcome == "expected failure":
            counts["expected_failures"] += 1
        elif outcome == "unexpected success":
            counts["unexpected_successes"] += 1
    return {
        "tests": tests,
        "counts": counts,
        "summary_line": ran_line,
        "result_line": result_line,
    }


def build_gate06_export_boundary_evidence(
    parsed: Dict[str, Any],
    env: Dict[str, Any],
    modules: Tuple[str, ...],
    patterns: Tuple[str, ...],
    exit_code: Optional[int],
) -> Dict[str, Any]:
    """Normalize the targeted export-boundary unittest run into GATE-06 evidence.

    The file documents the AUTOMATED portion of GATE-06 only (synthetic
    counterexamples, whitelist fail-closed, export default-off, secret
    masking, lessons never exported). The expert-review obligations
    (export-field sensitivity, human-review responsibility) stay explicitly
    pending in ``manual_review`` — the tool neither closes them nor hides
    them (design principle 8 / SR-016).
    """
    counts = dict(parsed["counts"])
    blocking = counts["failed"] + counts["errors"] + counts["unexpected_successes"]
    if counts["total"] == 0:
        status = "unknown"
        summary = (
            "导出边界过滤器未匹配到任何测试（或输出不可解析）；"
            "GATE-06 自动化部分保持 unknown，不宣称通过。"
        )
    elif blocking:
        status = "fail"
        summary = (
            f"导出边界定向测试存在失败: fail={counts['failed']} "
            f"error={counts['errors']} unexpected_success={counts['unexpected_successes']}；"
            "失败关闭语义被破坏的测试不得计入通过。"
        )
    else:
        status = "pass"
        summary = (
            f"导出边界定向测试通过: passed={counts['passed']}, "
            f"skipped={counts['skipped']}（跳过单列不计入通过分母）；"
            f"覆盖白名单失败关闭/默认不导出/秘密脱敏/lessons 不导出共 "
            f"{counts['total']} 项断言。"
        )
    return {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "gate": "GATE-06",
        "evidence_kind": "export_boundary_unittest",
        "title": "导出边界定向测试（合成反例/白名单失败关闭/默认不导出/秘密脱敏）",
        "source": {
            "tool": "python3 -m unittest (targeted -k filter)",
            "modules": list(modules),
            "patterns": list(patterns),
            "exit_code": exit_code,
            "unittest_summary": parsed.get("summary_line", ""),
            "unittest_result": parsed.get("result_line", ""),
        },
        "generated_at": utc_now(),
        "environment": env,
        "status": status,
        "summary": summary,
        "counts": counts,
        "key_assertions": parsed["tests"],
        "manual_review": {
            "status": "pending",
            "items": [
                "导出字段敏感性专家评审（REV-10：白名单不证明匿名）",
                "人工审核责任（维护者）确认",
                "合成反例与白名单字段的专家评审",
            ],
        },
        "not_automated": [
            "导出字段敏感性与人工审核责任的专家评审（保持 manual_pending，"
            "不由本工具裁决为通过）",
        ],
        "notes": [
            "本文件只记录自动化导出边界测试的实测结果；关键断言清单来自 "
            "unittest -v 逐测试输出（test_id + outcome；unittest 将进度流写入 "
            "stderr，本工具合并 stdout/stderr 解析），无伪造条目。",
            "GATE-06 关闭与否由评估器按证据与设计审查裁决；本文件的 "
            "manual_review 块如实保留待审项。",
        ],
    }


# ---------------------------------------------------------------------------
# Step runners (each step independent; failure recorded as error + unknown)
# ---------------------------------------------------------------------------

def _write_json(path: Path, payload: Dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return path


def _run_step(
    name: str,
    cmd: List[str],
    timeout: int,
    runner: Callable[..., subprocess.CompletedProcess],
) -> Dict[str, Any]:
    """Run one collector subprocess; never raise — record honestly instead."""
    started = time.time()
    try:
        proc = runner(
            cmd, capture_output=True, text=True, timeout=timeout, cwd=str(ROOT_DIR)
        )
    except subprocess.TimeoutExpired:
        return {
            "step": name,
            "command": cmd,
            "ok": False,
            "error": f"step timed out after {timeout}s",
            "status": "unknown",
            "duration_seconds": round(time.time() - started, 1),
        }
    except OSError as exc:
        return {
            "step": name,
            "command": cmd,
            "ok": False,
            "error": f"failed to execute: {exc}",
            "status": "unknown",
            "duration_seconds": round(time.time() - started, 1),
        }
    return {
        "step": name,
        "command": cmd,
        "ok": proc.returncode == 0,
        "exit_code": proc.returncode,
        "stdout": proc.stdout or "",
        "stderr": (proc.stderr or "")[-4000:],
        "status": "ok" if proc.returncode == 0 else "error",
        "duration_seconds": round(time.time() - started, 1),
    }


def collect_evidence(
    out_dir: Path,
    *,
    run_tests: bool = True,
    runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
    corpus_dir: Path = HOLDOUT_CORPUS_DIR,
    knowledge_dir: Path = KNOWLEDGE_DIR,
    usage_unavailable_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Collect all automated evidence and return the release summary payload.

    Every step is independently guarded: a failing step writes its error into
    the affected evidence file (status unknown) and never blocks the others.

    ``usage_unavailable_path`` points at the coordinator-produced GATE-03
    usage evidence (P2.1a); it defaults to the repo docs/evidence artifact.
    """
    env = environment_info()
    out_dir.mkdir(parents=True, exist_ok=True)
    steps: List[Dict[str, Any]] = []

    # -- step 1: unified test orchestrator -> gateNN-summary.json -----------
    parsed: Dict[str, Any] = {"suites": [], "categories": {}, "total": {}, "result_line": ""}
    run_all_error: Optional[str] = None
    run_all_exit: Optional[int] = None
    if run_tests:
        res = _run_step(
            "run_all_tests",
            [sys.executable, str(ROOT_DIR / "tools" / "run_all_tests.py")],
            STEP_TIMEOUTS_SECONDS["run_all_tests"],
            runner,
        )
        steps.append({k: v for k, v in res.items() if k not in ("stdout", "stderr")})
        run_all_exit = res.get("exit_code")
        # The summary table is parsed INDEPENDENTLY of the exit code: a
        # non-zero exit means some category failed — exactly what the
        # per-category verdicts must report — not that the output is
        # unusable. Only an unparseable/absent table degrades to unknown.
        parsed = parse_run_all_output(res.get("stdout") or "")
        if not parsed["suites"] and not parsed["total"]:
            run_all_error = (
                f"编排器无可用汇总表 (exit={res.get('exit_code')}, "
                f"error={res.get('error') or res.get('status')})"
            )
    else:
        steps.append({"step": "run_all_tests", "ok": False, "skipped": True,
                      "status": "unknown", "error": "skipped by --skip-tests"})
        run_all_error = "skipped by --skip-tests"

    gate_paths: Dict[str, str] = {}
    gate_summaries: Dict[str, Dict[str, Any]] = {}
    for gate_id, spec in GATE_CATEGORIES.items():
        body = build_gate_test_summary(
            gate_id, spec["title"], spec["category"], parsed, env,
            extra_notes=(
                [f"统一测试编排器结果: {run_all_error}；本门禁证据保持 unknown。"]
                if run_all_error else None
            ),
            orchestrator_exit_code=run_all_exit,
        )
        path = _write_json(out_dir / f"{gate_id.lower().replace('-', '')}-summary.json", body)
        gate_paths[gate_id] = str(path)
        gate_summaries[gate_id] = body

    # -- step 2: holdout evaluation -> gate04-holdout.json ------------------
    with tempfile.TemporaryDirectory(prefix="evidence-holdout-") as tmp:
        res = _run_step(
            "evaluate_holdout",
            [
                sys.executable, str(ROOT_DIR / "tools" / "evaluate_holdout.py"),
                "--corpus", str(corpus_dir),
                "--knowledge", str(knowledge_dir),
                "--out", tmp,
            ],
            STEP_TIMEOUTS_SECONDS["evaluate_holdout"],
            runner,
        )
        steps.append({k: v for k, v in res.items() if k not in ("stdout", "stderr")})
        holdout_path = Path(tmp) / "holdout_report.json"
        report: Optional[Dict[str, Any]] = None
        if holdout_path.exists():
            try:
                with open(holdout_path, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                report = loaded if isinstance(loaded, dict) else None
            except (OSError, ValueError) as exc:
                res.setdefault("error", f"holdout report unreadable: {exc}")
        if report is None:
            res["ok"] = False
            res["status"] = "error"
            res.setdefault("error", "holdout_report.json was not produced")
            body = {
                "schema_version": EVIDENCE_SCHEMA_VERSION,
                "gate": "GATE-04",
                "evidence_kind": "holdout_evaluation",
                "generated_at": utc_now(),
                "environment": env,
                "status": "unknown",
                "error": res.get("error"),
                "summary": "留出集评测步骤失败；证据保持 unknown，不伪造。",
                "llm_results": "unknown",
            }
        else:
            body = build_holdout_evidence(report, env)
        path = _write_json(out_dir / "gate04-holdout.json", body)
        gate_paths["GATE-04"] = str(path)
        gate_summaries["GATE-04"] = body

    # -- step 3: isolation probes -> gate01-isolation.json ------------------
    with tempfile.TemporaryDirectory(prefix="evidence-isolation-") as tmp:
        res = _run_step(
            "probe_isolation",
            [
                sys.executable, str(ROOT_DIR / "tools" / "probe_isolation.py"),
                "--out", tmp,
            ],
            STEP_TIMEOUTS_SECONDS["probe_isolation"],
            runner,
        )
        steps.append({k: v for k, v in res.items() if k not in ("stdout", "stderr")})
        iso_path = Path(tmp) / "isolation_probe_report.json"
        report = None
        if iso_path.exists():
            try:
                with open(iso_path, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                report = loaded if isinstance(loaded, dict) else None
            except (OSError, ValueError) as exc:
                res.setdefault("error", f"isolation report unreadable: {exc}")
        if report is None:
            res["ok"] = False
            res["status"] = "error"
            res.setdefault("error", "isolation_probe_report.json was not produced")
            body = {
                "schema_version": EVIDENCE_SCHEMA_VERSION,
                "gate": "GATE-01",
                "evidence_kind": "isolation_probe",
                "generated_at": utc_now(),
                "environment": env,
                "status": "unknown",
                "error": res.get("error"),
                "summary": "隔离探测步骤失败；证据保持 unknown，不伪造。",
            }
        else:
            body = build_isolation_evidence(report, env)
        path = _write_json(out_dir / "gate01-isolation.json", body)
        gate_paths["GATE-01-isolation"] = str(path)
        gate_summaries["GATE-01-isolation"] = body

    # -- step 4: doctor --probe -> gate01-capability-matrix.json ------------
    res = _run_step(
        "doctor_probe",
        [
            sys.executable, str(SKILL_SCRIPTS / "audit.py"),
            "doctor", "--probe", "--format", "json",
        ],
        STEP_TIMEOUTS_SECONDS["doctor_probe"],
        runner,
    )
    steps.append({k: v for k, v in res.items() if k not in ("stdout", "stderr")})
    capabilities = extract_doctor_capabilities(res.get("stdout", "")) if res["ok"] else None
    if capabilities is None:
        res.setdefault("error", res.get("error") or "doctor envelope 中未找到 capabilities")
        res["status"] = "error"
        matrix_body = {
            "schema_version": EVIDENCE_SCHEMA_VERSION,
            "gate": "GATE-01",
            "evidence_kind": "host_capability_matrix",
            "generated_at": utc_now(),
            "environment": env,
            "status": "unknown",
            "error": res.get("error"),
            "summary": "doctor --probe 步骤失败；能力矩阵保持 unknown，不标注支持。",
            "capability_matrix": {},
        }
    else:
        matrix_body = build_capability_matrix_evidence(
            capabilities, env, gate_summaries.get("GATE-01", {})
        )
    path = _write_json(out_dir / "gate01-capability-matrix.json", matrix_body)
    gate_paths["GATE-01-matrix"] = str(path)
    gate_summaries["GATE-01-matrix"] = matrix_body

    # -- step 5: GATE-03 usage evidence (coordinator artifact, read-only) ---
    # Consumed verbatim (P2.1a); never rewritten by this tool. A missing file
    # or missing downgrade markers stays unknown and keeps the GATE-03 usage
    # telemetry item in manual_pending.
    if usage_unavailable_path is None:
        usage_unavailable_path = DEFAULT_OUT_DIR / GATE03_USAGE_EVIDENCE_NAME
    usage_body = load_gate03_usage_evidence(usage_unavailable_path, env)
    usage_documented = usage_body["status"] == GATE03_DOWNGRADE_STATUS
    steps.append({
        "step": "gate03_usage_evidence",
        "ok": usage_documented,
        "status": usage_body["status"],
        "source": str(usage_unavailable_path),
        "error": None if usage_documented else (
            usage_body.get("error")
            or "usage evidence missing or downgrade markers absent; "
               "GATE-03 usage telemetry stays unknown"
        ),
        "duration_seconds": 0.0,
    })

    # -- step 6: targeted export-boundary tests -> gate06-export-boundary ---
    gate06_cmd = [sys.executable, "-m", "unittest", "-v"]
    for module in GATE06_EXPORT_TEST_MODULES:
        gate06_cmd.append(module)
    for pattern in GATE06_EXPORT_TEST_PATTERNS:
        gate06_cmd.extend(["-k", pattern])
    res = _run_step(
        "gate06_export_tests",
        gate06_cmd,
        STEP_TIMEOUTS_SECONDS["gate06_export_tests"],
        runner,
    )
    steps.append({k: v for k, v in res.items() if k not in ("stdout", "stderr")})
    # unittest writes its progress stream (including -v output) to STDERR;
    # both captured streams are parsed, so the evidence never depends on
    # which stream the interpreter chose.
    gate06_output = (res.get("stdout") or "") + "\n" + (res.get("stderr") or "")
    gate06_parsed = parse_unittest_verbose(gate06_output)
    gate06_body = build_gate06_export_boundary_evidence(
        gate06_parsed, env,
        GATE06_EXPORT_TEST_MODULES, GATE06_EXPORT_TEST_PATTERNS,
        res.get("exit_code"),
    )
    path = _write_json(out_dir / "gate06-export-boundary.json", gate06_body)
    gate_paths["GATE-06"] = str(path)
    gate_summaries["GATE-06"] = gate06_body

    # -- step 7: ReleaseGateEvaluator over the collected evidence -----------
    det_body = gate_summaries.get("GATE-07", {})
    compatibility_tests = {
        "status": det_body.get("status", "unknown"),
        "summary": (
            "确定性套件代理口径（contracts/snapshot/ledger/analysis/knowledge/"
            "reporting/security/holdout-wiring/e2e/swr/CLI 确定性/宿主 mock）: "
            + str(det_body.get("summary", ""))
            + "；stdlib-only 环境检查随 GATE-05 类别运行。"
        ),
    }
    evidence = {
        "GATE-01": gate_paths.get("GATE-01-matrix", ""),
        "GATE-02": gate_paths.get("GATE-02", ""),
        "GATE-04": gate_paths.get("GATE-04", ""),
        "GATE-05": gate_paths.get("GATE-05", ""),
        "GATE-07": gate_paths.get("GATE-07", ""),
        "compatibility_tests": compatibility_tests,
    }
    if usage_unavailable_path.exists():
        # P2.1a: the evaluator consumes the coordinator artifact directly;
        # check_gate_03 applies the SD §5.2 honest-degradation branch.
        evidence["GATE-03"] = str(usage_unavailable_path)
        gate_paths["GATE-03-usage"] = str(usage_unavailable_path)
    evidence["GATE-06"] = gate_paths.get("GATE-06", "")
    try:
        gate_result = ReleaseGateEvaluator().evaluate_all(dict(evidence))
    except Exception as exc:  # noqa: BLE001 - evaluator failure must not crash the tool
        gate_result = {
            "schema_version": "1.0",
            "verdict": "release_blocked",
            "release_allowed": False,
            "gates": [],
            "blocking": [f"GATE evaluator failure: {exc.__class__.__name__}: {exc}"],
            "conclusion": "门禁评估器异常；发布结论按失败关闭（blocked）处理。",
        }

    # GATE-03 manual split (P2.1a): the usage-telemetry sub-item leaves
    # manual_pending once the coordinator evidence documents the honest
    # downgrade; the token/cost hard-cap sub-item stays manual — the host
    # provides no verifiable hard caps.
    if usage_documented:
        gate03_manual = {
            "gate": "GATE-03",
            "item": "token/费用最坏上限证据（宿主未提供可验证的单次调用硬限额与可靠上游计量）"
                    "无法离线自动化；用量遥测不可用已实测归档（gate03-usage-unavailable.json），"
                    "按 SD §5.2 只能以明确的软预算/任务预算模式发布",
            "status": "unknown",
        }
    else:
        gate03_manual = {
            "gate": "GATE-03",
            "item": "token/费用最坏上限证据（上游用量完整性）无法离线自动化；"
                    "或显式发布软预算/任务预算模式",
            "status": "unknown",
        }
    manual_pending = [
        {
            "gate": "GATE-01",
            "item": "aggressive 级隔离反例（执行/网络隔离）与结构化输出/用量证明未由 doctor --probe 执行",
            "status": "unknown",
        },
        gate03_manual,
        {
            "gate": "GATE-04",
            "item": "LLM 在线评测、独立维护者留出集、150 类逐语言专家评审",
            "status": "unknown",
        },
        {
            "gate": "GATE-06",
            "item": "导出字段敏感性与人工审核责任的专家评审及合成反例评审"
                    "（合成反例边界测试已自动化归档于 gate06-export-boundary.json）",
            "status": "unknown",
        },
    ]

    summary_payload = {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "tool": "tools/generate_release_evidence.py",
        "requirement": "DSR-051 / SR-029 / SWR-026",
        "run_id": f"ev-{uuid.uuid4().hex[:8]}",
        "generated_at": utc_now(),
        "environment": env,
        "verdict": gate_result.get("verdict"),
        "release_allowed": gate_result.get("release_allowed"),
        "release_gate": gate_result,
        "orchestrator": {
            "exit_code": run_all_exit,
            "total": parsed.get("total", {}),
            "result_line": parsed.get("result_line", ""),
            "suites": parsed.get("suites", []),
        },
        "evidence_files": gate_paths,
        "evidence_inline": {
            "compatibility_tests": compatibility_tests,
            "gate03_usage": {
                "source_file": str(usage_unavailable_path),
                "status": usage_body["status"],
                "release_note_required": usage_body["release_note_required"],
                "attempts_total": usage_body["attempts_total"],
                "availability_distribution": usage_body["availability_distribution"],
                "conclusion": usage_body["conclusion"],
                "evaluator_semantics": (
                    "downgrade_documented 走 SD §5.2 明确降级分支：评估输出 fail + "
                    "发布说明前置 reason，不给 pass；门禁关闭由设计审查决定。"
                ),
            },
            "gate06_export_boundary": {
                "status": gate06_body["status"],
                "counts": gate06_body["counts"],
                "manual_review": gate06_body["manual_review"],
            },
        },
        "steps": steps,
        "manual_pending": manual_pending,
        "automation_notes": [
            "每步独立采集：单步失败仅将对应门禁证据记为 error+unknown，不影响其余步骤。",
            "所有无法自动化的项保持 unknown 并列入 manual_pending；本工具不伪造在线评测或专家评审。",
            "GATE-03 用量遥测不可用已实测归档（协调方证据只读接入）；按 SD §5.2 走明确降级分支，"
            "评估结论如实输出 fail + 发布说明前置，不放行为 pass。",
            "GATE-06 导出边界合成反例测试已自动化归档；导出字段敏感性/人工审核责任的专家评审仍为 manual。",
            "release_blocked 是未完成人工项时的如实结论，不是工具失败。",
        ],
    }
    summary_path = _write_json(out_dir / "release_gate_summary.json", summary_payload)
    return {"summary_path": summary_path, "payload": summary_payload}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="DSR-051/SR-029 release evidence generator (docs/evidence/)"
    )
    parser.add_argument("--out", default=str(DEFAULT_OUT_DIR), help="evidence output directory")
    parser.add_argument(
        "--skip-tests", action="store_true",
        help="skip the full unified test run (gateNN summaries become unknown)",
    )
    parser.add_argument("--corpus", default=str(HOLDOUT_CORPUS_DIR), help="holdout corpus dir")
    parser.add_argument("--knowledge", default=str(KNOWLEDGE_DIR), help="knowledge dir")
    args = parser.parse_args(argv)

    # Evidence-regression guard (RUN-LESSONS 2026-11-19 incident, recurred
    # via --fast test runs on 2026-11-26): regenerating evidence WITHOUT a
    # real orchestrator run degrades the committed summaries to unknown --
    # a quality regression that must never silently overwrite the
    # authoritative evidence directory. Skip mode must target a scratch
    # directory explicitly; the default evidence dir refuses it.
    if args.skip_tests and str(Path(args.out).resolve()) == str(Path(DEFAULT_OUT_DIR).resolve()):
        import sys as _sys
        _sys.stderr.write(
            "[evidence-guard] refusing --skip-tests against the default "
            "evidence directory: skipped runs degrade gateNN summaries to "
            "unknown (quality regression). Use --out <scratch-dir> for "
            "format experiments, or run the full suite without --skip-tests."
            "\n"
        )
        return 2

    result = collect_evidence(
        Path(args.out),
        run_tests=not args.skip_tests,
        corpus_dir=Path(args.corpus),
        knowledge_dir=Path(args.knowledge),
    )
    payload = result["payload"]
    gate = payload["release_gate"]
    print(f"Evidence directory: {result['summary_path'].parent}")
    for step in payload["steps"]:
        state = "ok" if step.get("ok") else ("skipped" if step.get("skipped") else "ERROR")
        print(f"  step {step.get('step')}: {state} ({step.get('duration_seconds', '?')}s)")
    for g in gate.get("gates", []):
        print(f"  {g.get('gate_id')}: {g.get('status')}")
    print(f"VERDICT: {payload['verdict']} (release_allowed={payload['release_allowed']})")
    manual = ", ".join(sorted({m['gate'] for m in payload['manual_pending']}))
    print(f"Manual pending (kept unknown, not fabricated): {manual}")
    failed = [s for s in payload["steps"] if not s.get("ok") and not s.get("skipped")]
    return 1 if len(failed) == len(payload["steps"]) else 0


if __name__ == "__main__":
    sys.exit(main())
