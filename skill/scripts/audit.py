#!/usr/bin/env python3
"""polyglot-audit CLI - Command-Line Interface for Source Code Security Audit.

Implements IFC-04 / IFC-06 / DSR-074:
- Unified CLI interface supporting:
  doctor, prepare, run, next, start, submit, status, pause, resume, finalize, report, mcp, host-fail, guide.
- `run` mounts the driver loop (IFC-06): --host claude/codex drives
  run_dispatch_loop with the matching DriverAdapter + AIMD ConcurrencyController;
  --host session (default) only activates the run and prints the in-session
  next/start/submit guidance (no idle spin, no fake execution). A missing host
  CLI exits non-zero (HOST_FAILURE) instead of idling.
- `pause` surfaces the service pause result: revision, in_flight_tasks and
  in_flight_attempt_ids; --reason beyond 256 characters exits non-zero (2).
- `report` returns {"generation_id", "report_md"}; generation_id comes from the
  artifacts ledger (latest REPORT record) with the REPORT.md header Generation
  line as fallback.
- Every ledger-bound subcommand (run/next/start/submit/status/pause/resume/
  finalize/mcp/host-fail) prechecks the run directory for events.db BEFORE any
  sqlite3.connect call (connect would silently create an empty database file):
  a run directory without a valid dossier fails with the standard
  INVALID_INPUT envelope (exit 2) and the run directory is left untouched —
  never a non-standard INTERNAL_ERROR ("no such table: runs").
- Dual output format (DSR-074): every subcommand accepts --format {json,human}
  with json as the default, so the frozen JSON envelope contract for automation
  consumers is untouched. --format human renders compact human-readable text:
  custom renderers for status/finalize/report/pause/run, a generic fallback
  (top-level scalars as `key: value`, nested dict/list as indented JSON) for
  the rest, and errors as `ERROR <code>: <message>` with indented details.
  Exit codes are format-independent. The legacy --json switch is kept (it is
  the historical default); an explicit --format takes precedence.
- JSON envelope on stdout (default, --format json):
  {"schema_version": "1.0", "ok": true, "value": {...}}
  {"schema_version": "1.0", "ok": false, "error": {"code": "...", "message": "...", "retryable": false, "details": {}}}
- `mcp` runs a standard MCP JSON-RPC 2.0 stdio server (initialize /
  notifications/initialized / tools/list / tools/call over the four tools
  next/submit/status/read_artifact; unknown methods -> -32601). The legacy
  custom transport (JSON-RPC method IS the tool name) stays compatible.
  Its wire format is fixed by JSON-RPC 2.0, so --format only accepts json.
- Exit codes: 0 (success), 2 (input/schema), 3 (state/concurrency), 4 (budget/capability),
              5 (host failure), 6 (storage/corrupt), 7 (gate failed), 130 (cancel).
- Diagnostics strictly to stderr.
"""

# 需求追踪 (Requirement Traceability)
# ---------------------------------------------------------------------------
# 上层需求: docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2
# 设计依据: docs/design/SOFTWARE_DESIGN.md
# SWR-001  guide/audit 分流、范围/预算采集和模糊请求确认；guide 不建卷宗、audit 缺条件不运行
#   绑定实现: DSR-032, DSR-052, DSR-053, DSR-074
# SWR-022  driver 与 in-session 共用调度、领取、提交及暂停切换；同一合成案例状态/报告等价
#   绑定实现: DSR-032, DSR-065, DSR-064
# IFC-06   audit run 挂载驱动循环：--host claude/codex 经 DriverAdapter +
#          ConcurrencyController 驱动 run_dispatch_loop；--host session 只激活并
#          打印会话内执行指引（不空转、不伪装执行）；宿主 CLI 缺失时非零退出。
#   绑定实现: audit run / pause / report 子命令（本文件）
# SWR-023  适配 Claude Code CLI / Codex CLI 已验收版本：认证、结构化输出、能力矩阵；未知不得静默降级
#   绑定实现: DSR-074, DSR-075
# 状态以统一测试结论为准；未实测能力保持 unknown（设计原则 8：能观测的不靠声明）。
#

from __future__ import annotations
import argparse
import json
import os
import re
import shutil
import sys
from pathlib import Path

# Add scripts directory to sys.path so auditkit is importable
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from auditkit.app.guide import GuideService
from auditkit.app.service import AuditAppService
from auditkit.contracts.errors import (
    AuditError,
    ERROR_CODE_TO_EXIT_CODE,
    HostFailureError,
    InvalidInputError,
    InvalidStateError,
)
from auditkit.hosts.claude_adapter import ClaudeDriverAdapter
from auditkit.hosts.codex_adapter import CodexDriverAdapter
from auditkit.hosts.concurrency import ConcurrencyController
from auditkit.hosts.mcp_adapter import MCPServer, MCPMethodNotFoundError
from auditkit.ledger.db import get_db_connection
from auditkit.ledger.event_store import utc_now_iso


SKILL_DIR = SCRIPT_DIR.parent

# --host claude/codex -> host CLI binary looked up on PATH (IFC-06 / DSR-074).
HOST_BINARIES = {"claude": "claude", "codex": "codex"}

# REPORT.md header line (en + zh i18n variants) used as the generation-id
# fallback source when the artifacts ledger has no REPORT record.
_GENERATION_HEADER_RE = re.compile(r"Generation\)?\*\*: `([^`]+)`")

# pause --reason upper bound (chars); service raises InvalidInputError past it.
PAUSE_REASON_MAX_CHARS = 256

# DSR-074 dual output format. json is the default on every subcommand (frozen
# envelope contract); human renders compact human-readable text. The mcp
# subcommand's wire format is fixed by JSON-RPC 2.0, so it accepts json only.
_FORMAT_HELP = (
    "Output format: 'json' envelope (default, automation contract) or "
    "'human' compact human-readable text (DSR-074)"
)


def _add_format_argument(parser, choices=("json", "human")) -> None:
    if list(choices) == ["json"]:
        help_text = "Output format; the MCP stdio wire protocol is fixed JSON-RPC 2.0"
    else:
        help_text = _FORMAT_HELP
    parser.add_argument("--format", choices=list(choices), default="json", help=help_text)


def emit_json_success(value: dict) -> None:
    envelope = {
        "schema_version": "1.0",
        "ok": True,
        "value": value,
    }
    sys.stdout.write(json.dumps(envelope, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def emit_json_error(code: str, message: str, retryable: bool = False, details: dict = None) -> None:
    envelope = {
        "schema_version": "1.0",
        "ok": False,
        "error": {
            "code": code,
            "message": message,
            "retryable": retryable,
            "details": details or {},
        },
    }
    sys.stdout.write(json.dumps(envelope, ensure_ascii=False) + "\n")
    sys.stdout.flush()


# ---------------------------------------------------------------------------
# DSR-074 human output format (--format human). json stays the default so the
# frozen envelope contract and every automation consumer are untouched. Human
# rendering is a compact diagnostics view: per-command renderers for the four
# high-frequency commands plus run, and a generic fallback (top-level scalars
# as aligned `key: value`, dict/list values as indented JSON). Errors render
# as `ERROR <code>: <message>` with indented details. Rendering is defensive
# (missing keys / shape drift degrade to the generic view, never crash).
# ---------------------------------------------------------------------------

_KV_WIDTH = 24


def _human_scalar(value) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _human_kv(key: str, value) -> str:
    label = f"{key}:"
    return f"{label:<{_KV_WIDTH}}{_human_scalar(value)}"


def _human_nested(obj, indent: str = "  ") -> str:
    body = json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True)
    return "\n".join(indent + line for line in body.splitlines())


def _render_remaining(lines: list, value: dict, consumed: set) -> list:
    """Append generic rendering of keys not handled by a custom renderer."""
    for key, val in value.items():
        if key in consumed:
            continue
        if isinstance(val, (dict, list)):
            if not val:
                lines.append(_human_kv(key, "[]" if isinstance(val, list) else "{}"))
            else:
                lines.append(f"{key}:")
                lines.append(_human_nested(val, "  "))
        else:
            lines.append(_human_kv(key, val))
    return lines


def render_human_generic(value: dict) -> str:
    lines = []
    for key, val in value.items():
        if isinstance(val, (dict, list)):
            if not val:
                lines.append(_human_kv(key, "[]" if isinstance(val, list) else "{}"))
            else:
                lines.append(f"{key}:")
                lines.append(_human_nested(val, "  "))
        else:
            lines.append(_human_kv(key, val))
    return "\n".join(lines)


def render_human_status(value: dict) -> str:
    lines = [
        _human_kv("run_id", value.get("run_id")),
        _human_kv("snapshot_id", value.get("snapshot_id")),
        _human_kv("state", value.get("state")),
        _human_kv("revision", value.get("revision")),
    ]
    tasks = value.get("tasks") or {}
    lines.append("tasks:")
    if tasks:
        lines.extend(f"  {state}: {count}" for state, count in sorted(tasks.items()))
    else:
        lines.append("  (none)")
    budgets = value.get("budgets") or []
    lines.append("budgets:")
    if budgets:
        for budget in budgets:
            label = budget.get("dimension") or "?"
            lines.append(
                f"  {label}: limit={_human_scalar(budget.get('limit'))} "
                f"settled={_human_scalar(budget.get('settled'))} "
                f"reserved={_human_scalar(budget.get('reserved'))} "
                f"mode={_human_scalar(budget.get('mode'))} "
                f"availability={_human_scalar(budget.get('availability'))}"
            )
    else:
        lines.append("  (none)")
    return "\n".join(
        _render_remaining(lines, value, {"run_id", "snapshot_id", "state", "revision", "tasks", "budgets"})
    )


def render_human_finalize(value: dict) -> str:
    lines = [
        _human_kv("run_id", value.get("run_id")),
        _human_kv("final_state", value.get("final_state")),
        _human_kv("generation_id", value.get("generation_id")),
        "gates:",
    ]
    gates = value.get("gates") or {}
    if gates:
        lines.extend(f"  {name}: {_human_scalar(gates[name])}" for name in sorted(gates))
    else:
        lines.append("  (none)")
    reasons = value.get("incomplete_reasons") or []
    lines.append("incomplete_reasons:")
    if reasons:
        lines.extend(f"  - {reason}" for reason in reasons)
    else:
        lines.append("  (none)")
    unverified = value.get("unverified") or []
    lines.append(f"unverified_findings: {len(unverified)}")
    gaps = value.get("coverage_gaps") or []
    lines.append(f"coverage_gaps: {len(gaps)}")
    if gaps:
        lines.append(_human_nested(gaps, "  "))
    return "\n".join(
        _render_remaining(
            lines,
            value,
            {"run_id", "final_state", "generation_id", "gates", "incomplete_reasons", "unverified", "coverage_gaps"},
        )
    )


def render_human_report(value: dict) -> str:
    body = value.get("report_md") or ""
    lines = [
        _human_kv("generation_id", value.get("generation_id")),
        _human_kv("report_md_chars", len(body)),
        _human_kv("report_md_lines", len(body.splitlines())),
        "",
        "---",
        body.rstrip("\n"),
        "---",
    ]
    return "\n".join(_render_remaining(lines, value, {"generation_id", "report_md"}))


def render_human_pause(value: dict) -> str:
    attempts = value.get("in_flight_attempt_ids") or []
    lines = [
        (
            f"paused {_human_scalar(value.get('run_id'))} at revision "
            f"{_human_scalar(value.get('revision'))} (in_flight: "
            f"{_human_scalar(value.get('in_flight_tasks'))} task(s); attempt_ids: "
            f"{', '.join(attempts) if attempts else 'none'})"
        ),
        _human_kv("run_id", value.get("run_id")),
        _human_kv("state", value.get("state")),
        _human_kv("revision", value.get("revision")),
        _human_kv("in_flight_tasks", value.get("in_flight_tasks")),
        _human_kv("in_flight_attempt_ids", json.dumps(attempts, ensure_ascii=False)),
    ]
    return "\n".join(
        _render_remaining(
            lines,
            value,
            {"run_id", "state", "revision", "in_flight_tasks", "in_flight_attempt_ids"},
        )
    )


def render_human_run(value: dict) -> str:
    lines = [
        (
            f"run {_human_scalar(value.get('run_id'))} -> "
            f"state={_human_scalar(value.get('state'))} mode={_human_scalar(value.get('mode'))}"
        ),
    ]
    if value.get("message"):
        lines.append(str(value["message"]))
    for key in ("concurrency", "queued_tasks"):
        if key in value:
            lines.append(_human_kv(key, value[key]))
    steps = value.get("next_steps") or []
    if steps:
        lines.append("next_steps:")
        lines.extend(f"  - {step}" for step in steps)
    if "dispatch" in value:
        lines.append("dispatch:")
        lines.append(_human_nested(value["dispatch"], "  "))
    return "\n".join(
        _render_remaining(lines, value, {"run_id", "state", "mode", "message", "next_steps", "concurrency", "queued_tasks", "dispatch"})
    )


_HUMAN_RENDERERS = {
    "status": render_human_status,
    "finalize": render_human_finalize,
    "report": render_human_report,
    "pause": render_human_pause,
    "run": render_human_run,
}


def render_human_error(code: str, message: str, retryable: bool = False, details: dict = None) -> str:
    lines = [
        f"ERROR {code}: {message}",
        f"  retryable: {'true' if retryable else 'false'}",
    ]
    if details:
        lines.append("  details:")
        lines.append(_human_nested(details, "    "))
    return "\n".join(lines)


def emit_result(value: dict, fmt: str, command: str) -> None:
    """Emit a successful command result: JSON envelope (default) or the
    DSR-074 human rendering for --format human."""
    if fmt == "human":
        renderer = _HUMAN_RENDERERS.get(command, render_human_generic)
        sys.stdout.write(renderer(value) + "\n")
        sys.stdout.flush()
    else:
        emit_json_success(value)


def emit_failure(code: str, message: str, retryable: bool = False, details: dict = None, fmt: str = "json") -> None:
    """Emit a command failure in the requested format (DSR-074)."""
    if fmt == "human":
        sys.stdout.write(render_human_error(code, message, retryable, details) + "\n")
        sys.stdout.flush()
    else:
        emit_json_error(code, message, retryable, details)


# ---------------------------------------------------------------------------
# IFC-06 driver-loop helpers (audit run --host claude|codex)
# The CLI consumes only existing service/host-layer interfaces:
# run_dispatch_loop, ClaudeDriverAdapter/CodexDriverAdapter.execute_worker,
# ConcurrencyController. No auditkit module is modified here.
# ---------------------------------------------------------------------------


def _resolve_host_binary(host: str) -> str:
    """Locate the host CLI on PATH or fail loudly (never a silent no-op)."""
    binary = HOST_BINARIES[host]
    resolved = shutil.which(binary)
    if not resolved:
        raise HostFailureError(
            f"Host CLI '{binary}' (--host {host}) was not found on PATH; "
            "the driver loop cannot execute workers, so 'run' refuses to "
            "start instead of idling",
            retryable=False,
            details={"host": host, "binary": binary},
        )
    return resolved


def _require_events_db(run_dir) -> None:
    """Fail closed when the run directory carries no valid dossier ledger.

    sqlite3.connect silently creates an empty events.db when the file is
    missing, which both pollutes the filesystem and only surfaces later as a
    non-standard INTERNAL_ERROR ("no such table: runs"). This precheck must
    run before ANY connect call so a missing dossier yields the standard
    INVALID_INPUT envelope (exit 2, ERROR_CODE_TO_EXIT_CODE mapping) and the
    run directory is left untouched.
    """
    db_path = Path(run_dir) / "events.db"
    if not db_path.exists():
        raise InvalidInputError(
            f"Run directory '{run_dir}' does not contain a valid audit dossier "
            f"(no events.db ledger); run 'audit prepare' first",
            details={"run_dir": str(run_dir), "events_db": str(db_path)},
        )


def _load_run_row(conn, run_dir: str):
    """Return the single run row of the dossier, or raise InvalidInputError."""
    run_row = conn.execute("SELECT run_id, state FROM runs LIMIT 1").fetchone()
    if not run_row:
        raise InvalidInputError(f"No run found in database at {run_dir}")
    return run_row


def _task_kind(conn, claim: dict) -> str:
    """Read the authoritative task kind for a claim from the ledger."""
    row = conn.execute(
        "SELECT kind FROM tasks WHERE task_id = ?", (claim["task_id"],)
    ).fetchone()
    return row["kind"] if row else "hunt"


def _build_worker_prompt(claim: dict, run_dir: str) -> str:
    """Compose the headless worker prompt for one claim.

    Carries only task metadata and the claim spec (unit ranges, output
    contract). The claim token / lease credentials are deliberately excluded:
    the prompt is passed as an argv argument to the host CLI and argv is not a
    credential channel (DSR-074).
    """
    spec = claim.get("spec") if isinstance(claim.get("spec"), dict) else {}
    snapshot_id = spec.get("snapshot_id", "unknown")
    lines = [
        "You are executing one polyglot-audit task as an external worker.",
        f"task_id: {claim['task_id']}",
        f"attempt_id: {claim['attempt_id']}",
        f"snapshot_id: {snapshot_id}",
        "",
        "Output contract: reply with exactly ONE JSON object and no other prose:",
        '{"schema_version": "1.0", "task_id": "...", "attempt_id": "...", '
        '"kind": "hunt|verify", "coverage": [], "records": [], "overflow": []}',
        "- records: candidate/finding candidate objects with source/sink/steps provenance.",
        "- overflow: [{\"dimension\": ..., \"estimated_count\": N, \"reason\": ...}] when work was cut off.",
        "- coverage: observed-read ranges you actually reviewed.",
        "",
        "The frozen snapshot copy of the target lives under "
        f"{Path(run_dir).resolve() / 'snapshot'}; read files there, never from the live tree.",
        "",
        "Task spec:",
        json.dumps(spec, ensure_ascii=False, sort_keys=True),
    ]
    return "\n".join(lines)



def _derive_packet_coverage(run_dir: str, claim: dict) -> list:
    """Deterministically derive ``context_supplied`` coverage from the packet.

    Design principle 1 (记账交给程序) / SR-021: the packet is published by the
    toolkit itself, so the paths and line ranges it supplied to the worker are
    observed facts owned by the program -- never a model self-report. The
    published packet is parsed for its ``<untrusted_code path=... lines=...>``
    markers and each marker becomes one coverage range. Worker-claimed
    coverage is not trusted for the denominator (SR-021: 自述不能替代观测).
    """
    import re as _re
    packet_path = Path(run_dir) / "tasks" / claim["task_id"] / "packet.json"
    ranges = []
    try:
        packet = json.loads(packet_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return ranges
    text = json.dumps(packet, ensure_ascii=False)
    for m in _re.finditer(
        r'<untrusted_code path="([^"]+)" lines="(\d+)-(\d+)"', text
    ):
        path, start, end = m.group(1), int(m.group(2)), int(m.group(3))
        if ranges and ranges[-1]["path"] == path:
            prev = ranges[-1]
            if start <= prev["line_end"] + 1:
                prev["line_end"] = max(prev["line_end"], end)
                continue
        ranges.append({
            "path": path,
            "line_start": start,
            "line_end": end,
        })
    return ranges


def _normalize_worker_result(raw: object, claim: dict, kind: str, run_dir: str) -> dict:
    """Bind a raw worker payload to the claim identity and worker_result schema.

    The claim is the authoritative identity: task_id/attempt_id/kind are
    stamped from it. Lists (coverage/records/overflow) pass through when the
    worker provided them; a present-but-malformed list is a worker format
    failure (HostFailureError), never silently coerced into an empty one.
    """
    if not isinstance(raw, dict):
        raise HostFailureError(
            f"Worker for task {claim['task_id']} returned "
            f"{type(raw).__name__} instead of a JSON object",
            retryable=False,
            details={"task_id": claim["task_id"]},
        )
    result: dict = {
        "schema_version": "1.0",
        "task_id": claim["task_id"],
        "attempt_id": claim["attempt_id"],
        "kind": kind,
    }
    for field in ("records", "overflow"):
        value = raw.get(field)
        if value is None:
            result[field] = []
        elif isinstance(value, list):
            result[field] = value
        else:
            raise HostFailureError(
                f"Worker output field '{field}' for task {claim['task_id']} is "
                f"{type(value).__name__}, expected a list",
                retryable=True,
                details={"task_id": claim["task_id"], "field": field},
            )
    # Coverage is program-owned accounting (design principle 1 / SR-021):
    # derived deterministically from what the toolkit actually supplied in
    # the packet. Model-claimed coverage entries are dropped honestly with
    # a count on stderr -- never normalized into observed facts, and never
    # a reason to burn a bounded retry on contract-shape non-compliance.
    dropped = len(raw.get("coverage") or []) if isinstance(raw.get("coverage"), list) else 0
    result["coverage"] = _derive_packet_coverage(run_dir, claim)
    if dropped:
        print(
            f"[coverage] dropped {dropped} worker-claimed coverage entr"
            "ies (untrusted self-report); context_supplied coverage "
            "derived from the published packet instead",
            file=sys.stderr,
        )
    return result


def _make_execute_fn(app: AuditAppService, conn, run_dir: str, adapter) -> object:
    """Build the execute_fn consumed by run_dispatch_loop.

    Calls the adapter's worker execution entry point (execute_worker), which
    returns ``(worker_result, usage_dict_or_None)``: the usage dict is
    captured by the SAME invocation that produced the result, so concurrent
    workers can never cross-attribute per-attempt usage through a shared
    adapter slot (P0 usage envelope contract). run_dispatch_loop converts the
    returned usage via app.build_usage into the trusted usage object submitted
    per attempt; the claim's attempt_id is passed through so the usage dict is
    stamped with the attempt this call executes.

    Adapters built on the pre-envelope contract (bare worker_result return)
    still work: execute_fn then yields a ``None`` usage and run_dispatch_loop
    falls back to the legacy build_usage path.
    """
    def execute_fn(claim: dict) -> object:
        prompt = _build_worker_prompt(claim, run_dir)
        outcome = adapter.execute_worker(
            prompt,
            task_id=claim["task_id"],
            attempt_id=claim["attempt_id"],
        )
        if isinstance(outcome, tuple) and len(outcome) == 2:
            raw, usage = outcome
        else:
            # Pre-envelope adapter: no per-task usage channel.
            raw, usage = outcome, None
        return _normalize_worker_result(raw, claim, _task_kind(conn, claim), run_dir), usage
    return execute_fn


def _stop_reason_for_drain(conn, run_id: str, summary: dict) -> str:
    """Disambiguate an empty-claim stop: drained vs budget exhausted.

    The service loop reports stop_reason 'queue_drained' for any empty claim
    batch; when queued tasks remain the real cause is the stop sequence, so
    the CLI names it honestly from the ledger instead of mislabeling it.
    """
    if summary.get("stop_reason") != "queue_drained":
        return summary.get("stop_reason")
    queued = conn.execute(
        "SELECT count(*) AS cnt FROM tasks WHERE run_id = ? AND state = 'queued'",
        (run_id,),
    ).fetchone()["cnt"]
    if queued == 0:
        return "queue_drained"
    budget_events = conn.execute(
        "SELECT count(*) AS cnt FROM events WHERE run_id = ? AND event_type = 'budget_exhausted'",
        (run_id,),
    ).fetchone()["cnt"]
    return "budget_exhausted" if budget_events else "paused_or_blocked"


def _in_flight_stats(conn, run_id: str):
    """Count in-flight work: claimed/running attempts under a valid lease.

    Mirrors the ledger's own in-flight definition used by finalize gate G2
    (status claimed/running and the attempt lease not yet expired).
    """
    rows = conn.execute(
        """
        SELECT a.attempt_id AS attempt_id, a.task_id AS task_id
        FROM attempts a
        JOIN tasks t ON a.task_id = t.task_id
        WHERE t.run_id = ? AND a.status IN ('claimed', 'running') AND a.expires_at >= ?
        """,
        (run_id, utc_now_iso()),
    ).fetchall()
    task_ids = {r["task_id"] for r in rows}
    return len(task_ids), [r["attempt_id"] for r in rows]


def _resolve_generation_id(run_dir: str, report_md: str):
    """Resolve the report generation id (artifacts ledger first, header fallback)."""
    db_path = Path(run_dir) / "events.db"
    if db_path.exists():
        conn = get_db_connection(db_path)
        try:
            row = conn.execute(
                """
                SELECT generation FROM artifacts
                WHERE relative_path = 'report/REPORT.md' AND generation IS NOT NULL
                ORDER BY rowid DESC LIMIT 1
                """
            ).fetchone()
            if row and row["generation"]:
                return row["generation"]
        finally:
            conn.close()
    # Fallback: the published generation marker in the REPORT.md header
    # (DSR-036 verified every staged report carries it).
    for line in report_md.splitlines()[:30]:
        m = _GENERATION_HEADER_RE.search(line)
        if m:
            return m.group(1)
    return None


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="audit",
        description="polyglot-audit: Universal source code security audit skill",
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Sub-commands")

    # doctor
    p_doc = subparsers.add_parser("doctor", help="Probe host capabilities and installed CLIs")
    p_doc.add_argument("--host", choices=["claude", "codex", "session"], default="session")
    p_doc.add_argument("--probe", action="store_true", help="Perform active CLI version check")
    p_doc.add_argument("--json", action="store_true", default=True)
    _add_format_argument(p_doc)

    # prepare
    p_prep = subparsers.add_parser("prepare", help="Create new run, freeze snapshot, and generate plan")
    p_prep.add_argument("--target", required=True, help="Target repository directory")
    p_prep.add_argument("--run-dir", required=True, help="Output run directory")
    p_prep.add_argument("--config", required=True, help="Path to RunConfig JSON")
    p_prep.add_argument("--json", action="store_true", default=True)
    _add_format_argument(p_prep)

    # run
    p_run = subparsers.add_parser("run", help="Activate run and execute driver loop")
    p_run.add_argument("--run-dir", required=True, help="Run directory")
    p_run.add_argument("--host", choices=["claude", "codex", "session"], default="session")
    p_run.add_argument("--concurrency", type=int, default=1)
    p_run.add_argument(
        "--lease-seconds", type=int, default=300,
        help="claim lease duration per task; real LLM workers often need "
             "more than the 300s default (e.g. --lease-seconds 1800)",
    )
    p_run.add_argument(
        "--task-timeout", type=int, default=None,
        help="per-task worker timeout in seconds; real audit tasks routinely "
             "exceed the 120s adapter default (e.g. --task-timeout 1200)",
    )
    p_run.add_argument(
        "--max-tasks", type=int, default=None,
        help="cap the number of tasks dispatched this session; remaining "
             "queued units stay honest incomplete coverage (SR-019/DSR-066)",
    )
    p_run.add_argument("--json", action="store_true", default=True)
    _add_format_argument(p_run)

    # next
    p_next = subparsers.add_parser("next", help="Claim next batch of tasks")
    p_next.add_argument("--run-dir", required=True, help="Run directory")
    p_next.add_argument("--batch", type=int, default=1, help="Batch size")
    p_next.add_argument("--json", action="store_true", default=True)
    _add_format_argument(p_next)

    # start
    p_start = subparsers.add_parser("start", help="Mark task attempt as started (stdin for claim)")
    p_start.add_argument("--run-dir", required=True, help="Run directory")
    p_start.add_argument("--json", action="store_true", default=True)
    _add_format_argument(p_start)

    # submit
    p_sub = subparsers.add_parser("submit", help="Submit task result (stdin for claim + result)")
    p_sub.add_argument("--run-dir", required=True, help="Run directory")
    p_sub.add_argument("--json", action="store_true", default=True)
    _add_format_argument(p_sub)

    # status
    p_stat = subparsers.add_parser("status", help="Get run status and budget metrics")
    p_stat.add_argument("--run-dir", required=True, help="Run directory")
    p_stat.add_argument("--json", action="store_true", default=True)
    _add_format_argument(p_stat)

    # pause
    p_pause = subparsers.add_parser("pause", help="Pause run dispatch")
    p_pause.add_argument("--run-dir", required=True, help="Run directory")
    p_pause.add_argument("--reason", default="user_requested")
    p_pause.add_argument("--json", action="store_true", default=True)
    _add_format_argument(p_pause)

    # resume
    p_res = subparsers.add_parser("resume", help="Verify integrity and resume paused run")
    p_res.add_argument("--run-dir", required=True, help="Run directory")
    p_res.add_argument("--json", action="store_true", default=True)
    _add_format_argument(p_res)

    # finalize
    p_fin = subparsers.add_parser("finalize", help="Evaluate gates and publish reports")
    p_fin.add_argument("--run-dir", required=True, help="Run directory")
    p_fin.add_argument("--json", action="store_true", default=True)
    _add_format_argument(p_fin)

    # report
    p_rep = subparsers.add_parser("report", help="Read latest published report")
    p_rep.add_argument("--run-dir", required=True, help="Run directory")
    p_rep.add_argument("--json", action="store_true", default=True)
    _add_format_argument(p_rep)

    # mcp
    # The MCP wire protocol is fixed JSON-RPC 2.0 (standard MCP methods plus
    # legacy direct tool names), so --format only accepts json here.
    p_mcp = subparsers.add_parser("mcp", help="Run MCP stdio server (standard MCP protocol + legacy direct tools)")
    p_mcp.add_argument("--run-dir", required=True, help="Run directory")
    _add_format_argument(p_mcp, choices=("json",))

    # host-fail (DSR-065 / SWR-022): report a host/worker failure for a claim.
    # Credentials/claim payloads are read from stdin, never from argv (DSR-074).
    p_hfail = subparsers.add_parser(
        "host-fail",
        help="Report host/worker failure for a claimed attempt (stdin for claim + details)",
    )
    p_hfail.add_argument("--run-dir", required=True, help="Run directory")
    p_hfail.add_argument("--task", default=None, help="Optional task_id cross-check against the claim")
    p_hfail.add_argument("--retryable", action="store_true", help="Mark the failure retryable")
    p_hfail.add_argument("--max-retries", type=int, default=2, help="Maximum retry attempts")
    p_hfail.add_argument("--json", action="store_true", default=True)
    _add_format_argument(p_hfail)

    # guide
    p_guide = subparsers.add_parser("guide", help="Interactive lightweight security guidance")
    p_guide.add_argument("--query", required=True, help="Security question or code topic")
    p_guide.add_argument("--language", default="python", help="Target language")
    p_guide.add_argument("--json", action="store_true", default=True)
    _add_format_argument(p_guide)

    args = parser.parse_args()
    if not args.subcommand:
        parser.print_help(sys.stderr)
        return 2

    app = AuditAppService(SKILL_DIR)

    try:
        if args.subcommand == "doctor":
            res = app.doctor(probe_cli=args.probe)
            emit_result({"capabilities": res}, args.format, args.subcommand)
            return 0

        elif args.subcommand == "guide":
            guide_svc = GuideService(SKILL_DIR / "knowledge")
            res = guide_svc.answer_query(args.query, language=args.language)
            emit_result(res, args.format, args.subcommand)
            return 0

        elif args.subcommand == "prepare":
            with open(args.config, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            res = app.prepare(args.target, args.run_dir, cfg)
            emit_result(res, args.format, args.subcommand)
            return 0

        elif args.subcommand == "run":
            # IFC-06: run mounts the dispatch loop. --host session (default)
            # only activates the run and prints the in-session to-do guidance
            # (the host session itself drives next/start/submit — the CLI
            # neither idles nor pretends to execute). --host claude/codex
            # drives app.run_dispatch_loop to completion with the matching
            # DriverAdapter and an AIMD ConcurrencyController.
            run_path = Path(args.run_dir)
            _require_events_db(run_path)
            conn = get_db_connection(run_path / "events.db")
            run_row = _load_run_row(conn, args.run_dir)
            run_id = run_row["run_id"]

            if args.host == "session":
                if run_row["state"] in ("ready", "paused"):
                    app.activate(run_id, args.run_dir)
                elif run_row["state"] != "active":
                    raise InvalidStateError(
                        f"Cannot drive run '{run_id}' in state '{run_row['state']}'"
                    )
                emit_result({
                    "run_id": run_id,
                    "state": "active",
                    "mode": "session",
                    "message": (
                        "Run activated. The dispatch loop is driven by this host "
                        "session; the CLI does not idle and does not fake execution."
                    ),
                    "next_steps": [
                        f"audit next --run-dir {args.run_dir} --batch N   # claim tasks",
                        f"audit start --run-dir {args.run_dir} < claim.json",
                        f"audit submit --run-dir {args.run_dir} < payload.json",
                        (
                            "repeat next/start/submit until next returns no claims, "
                            f"then audit finalize --run-dir {args.run_dir}"
                        ),
                    ],
                }, args.format, args.subcommand)
                return 0

            binary = _resolve_host_binary(args.host)
            if args.concurrency < 1:
                raise InvalidInputError(
                    f"--concurrency must be >= 1 (got {args.concurrency})",
                    details={"concurrency": args.concurrency},
                )
            if run_row["state"] in ("ready", "paused"):
                app.activate(run_id, args.run_dir)

            if args.host == "claude":
                adapter = ClaudeDriverAdapter(claude_binary=binary)
            else:
                adapter = CodexDriverAdapter(codex_binary=binary)
            if args.task_timeout:
                # Real audit tasks routinely exceed the 120s adapter default;
                # without this the breaker trips and mass-quarantines tasks.
                adapter.timeout_seconds = int(args.task_timeout)
            controller = ConcurrencyController(initial=args.concurrency)
            execute_fn = _make_execute_fn(app, conn, args.run_dir, adapter)
            summary = app.run_dispatch_loop(
                run_id,
                args.run_dir,
                execute_fn,
                adapter=adapter,
                controller=controller,
                lease_seconds=max(1, args.lease_seconds),
                max_batches=args.max_tasks,
            )
            summary["stop_reason"] = _stop_reason_for_drain(conn, run_id, summary)
            queued = conn.execute(
                "SELECT count(*) AS cnt FROM tasks WHERE run_id = ? AND state = 'queued'",
                (run_id,),
            ).fetchone()["cnt"]
            final_state = conn.execute(
                "SELECT state FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone()["state"]
            emit_result({
                "run_id": run_id,
                "state": final_state,
                "mode": args.host,
                "concurrency": controller.current,
                "queued_tasks": queued,
                "dispatch": summary,
            }, args.format, args.subcommand)
            return 0

        elif args.subcommand == "next":
            _require_events_db(args.run_dir)
            conn = get_db_connection(Path(args.run_dir) / "events.db")
            run_row = conn.execute("SELECT run_id FROM runs LIMIT 1").fetchone()
            if not run_row:
                raise InvalidInputError("No run found in database")
            claims = app.next(run_row["run_id"], args.run_dir, batch_size=args.batch)
            emit_result({"claims": claims}, args.format, args.subcommand)
            return 0

        elif args.subcommand == "start":
            _require_events_db(args.run_dir)
            # Read claim authentication payload from stdin
            input_text = sys.stdin.read().strip()
            if not input_text:
                raise InvalidInputError("stdin required for start credentials")
            claim_data = json.loads(input_text)
            res = app.start(args.run_dir, claim_data)
            emit_result(res, args.format, args.subcommand)
            return 0

        elif args.subcommand == "submit":
            _require_events_db(args.run_dir)
            # Read submit payload from stdin
            input_text = sys.stdin.read().strip()
            if not input_text:
                raise InvalidInputError("stdin required for submit payload")
            payload = json.loads(input_text)
            claim = payload["claim"]
            worker_result = payload["result"]
            digest = payload.get("result_digest") or payload.get("digest")
            if not digest:
                digest = payload.get("claim", {}).get("result_digest") or "digest-omitted"
            res = app.submit(args.run_dir, claim, worker_result, digest, usage=payload.get("usage"))
            emit_result(res, args.format, args.subcommand)
            return 0

        elif args.subcommand == "status":
            _require_events_db(args.run_dir)
            conn = get_db_connection(Path(args.run_dir) / "events.db")
            run_row = conn.execute("SELECT run_id FROM runs LIMIT 1").fetchone()
            if not run_row:
                raise InvalidInputError("No run found in database")
            res = app.status(run_row["run_id"], args.run_dir)
            emit_result(res, args.format, args.subcommand)
            return 0

        elif args.subcommand == "pause":
            # IFC-06: the pause envelope surfaces the service pause result with
            # in-flight accounting (revision, in_flight_tasks,
            # in_flight_attempt_ids). Over-long reasons fail loudly (exit 2),
            # never silently truncated.
            if len(args.reason) > PAUSE_REASON_MAX_CHARS:
                raise InvalidInputError(
                    f"pause --reason exceeds {PAUSE_REASON_MAX_CHARS} characters "
                    f"(got {len(args.reason)})",
                    details={"limit": PAUSE_REASON_MAX_CHARS, "length": len(args.reason)},
                )
            _require_events_db(args.run_dir)
            conn = get_db_connection(Path(args.run_dir) / "events.db")
            run_row = _load_run_row(conn, args.run_dir)
            res = app.pause(run_row["run_id"], args.run_dir, reason=args.reason)
            if isinstance(res, dict):
                # New service shape: {revision, in_flight_tasks, in_flight_attempt_ids}
                value = {
                    "run_id": run_row["run_id"],
                    "state": "paused",
                    "revision": res.get("revision"),
                    "in_flight_tasks": res.get("in_flight_tasks"),
                    "in_flight_attempt_ids": res.get("in_flight_attempt_ids"),
                }
            else:
                # Service still returns the bare revision int: compute the
                # in-flight stats read-only so the contract holds either way.
                n_tasks, attempt_ids = _in_flight_stats(conn, run_row["run_id"])
                value = {
                    "run_id": run_row["run_id"],
                    "state": "paused",
                    "revision": res,
                    "in_flight_tasks": n_tasks,
                    "in_flight_attempt_ids": attempt_ids,
                }
            emit_result(value, args.format, args.subcommand)
            return 0

        elif args.subcommand == "resume":
            _require_events_db(args.run_dir)
            conn = get_db_connection(Path(args.run_dir) / "events.db")
            run_row = conn.execute("SELECT run_id FROM runs LIMIT 1").fetchone()
            if not run_row:
                raise InvalidInputError("No run found in database")
            res = app.resume(run_row["run_id"], args.run_dir)
            emit_result(res, args.format, args.subcommand)
            return 0

        elif args.subcommand == "finalize":
            _require_events_db(args.run_dir)
            conn = get_db_connection(Path(args.run_dir) / "events.db")
            run_row = conn.execute("SELECT run_id FROM runs LIMIT 1").fetchone()
            if not run_row:
                raise InvalidInputError("No run found in database")
            # res transparently carries incomplete_reasons and coverage_gaps
            # (SWR-012: incomplete runs must state why, never fake complete).
            res = app.finalize(run_row["run_id"], args.run_dir)
            emit_result(res, args.format, args.subcommand)
            return 0

        elif args.subcommand == "host-fail":
            # DSR-065 / SWR-022: consume service.report_host_failure.
            # The claim and failure details come from stdin, never argv (DSR-074).
            _require_events_db(args.run_dir)
            input_text = sys.stdin.read().strip()
            if not input_text:
                raise InvalidInputError("stdin required for host-fail claim and details")
            payload = json.loads(input_text)
            claim = payload.get("claim") if isinstance(payload.get("claim"), dict) else payload
            for required_field in ("run_id", "task_id", "attempt_id", "generation", "claim_token"):
                if required_field not in claim:
                    raise InvalidInputError(
                        f"host-fail claim missing required field '{required_field}'",
                        details={"missing": required_field},
                    )
            if args.task and claim.get("task_id") != args.task:
                raise InvalidInputError(
                    f"--task '{args.task}' does not match claim task_id '{claim.get('task_id')}'"
                )
            reason = payload.get("reason") or claim.get("reason") or "unspecified host failure"
            retryable = bool(args.retryable or payload.get("retryable", False))
            failure = HostFailureError(reason, retryable=retryable)
            res = app.report_host_failure(
                args.run_dir,
                claim,
                failure,
                max_retries=args.max_retries,
            )
            emit_result(res, args.format, args.subcommand)
            return 0

        elif args.subcommand == "report":
            report_path = Path(args.run_dir) / "report" / "REPORT.md"
            if not report_path.exists():
                raise InvalidInputError(f"Report not found at {report_path}")
            with open(report_path, "r", encoding="utf-8") as f:
                content = f.read()
            # IFC-06: the envelope carries the report generation id. The
            # artifacts ledger (latest REPORT record) is authoritative; the
            # REPORT.md header Generation line is the fallback source.
            generation_id = _resolve_generation_id(args.run_dir, content)
            emit_result({"generation_id": generation_id, "report_md": content}, args.format, args.subcommand)
            return 0

        elif args.subcommand == "mcp":
            # DDS-01: MCP transport must route through AuditAppService (the
            # single state-transition entry point), never a bare TaskQueue.
            # A run directory without a valid dossier ledger refuses to start
            # the stdio server (standard INVALID_INPUT envelope, exit 2) rather
            # than answering every request with a non-standard JSON-RPC error.
            _require_events_db(args.run_dir)
            app = AuditAppService(SKILL_DIR)
            server = MCPServer(args.run_dir, app)
            # Standard JSON-RPC 2.0 stdio loop (DSR-031 / SR-022 / SR-023):
            # initialize -> notifications/initialized -> tools/list ->
            # tools/call. The legacy custom transport (method IS the tool
            # name) stays compatible via handle_protocol. Requests without an
            # "id" are JSON-RPC notifications and never get a response, which
            # is what keeps standard clients from desyncing on the stream.
            for line in sys.stdin:
                line = line.strip()
                if not line:
                    continue
                try:
                    req = json.loads(line)
                except ValueError:
                    resp = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}
                    sys.stdout.write(json.dumps(resp) + "\n")
                    sys.stdout.flush()
                    continue
                if not isinstance(req, dict):
                    resp = {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid Request"}}
                    sys.stdout.write(json.dumps(resp) + "\n")
                    sys.stdout.flush()
                    continue
                req_id = req.get("id")
                method = req.get("method")
                params = req.get("params")
                if not isinstance(params, dict):
                    params = {}
                try:
                    result = server.handle_protocol(method, params)
                    resp = {"jsonrpc": "2.0", "id": req_id, "result": result}
                except MCPMethodNotFoundError as mnf:
                    resp = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {
                            "code": -32601,
                            "message": "Method not found",
                            "data": {"method": str(mnf.method)},
                        },
                    }
                except AuditError as ae:
                    resp = {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32000, "message": ae.message, "data": ae.to_dict()}}
                except Exception as ex:
                    resp = {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32603, "message": str(ex)}}
                if "id" in req:
                    # JSON-RPC notifications (no id) never receive a response.
                    sys.stdout.write(json.dumps(resp) + "\n")
                    sys.stdout.flush()
            return 0

    except AuditError as ae:
        emit_failure(ae.code, ae.message, ae.retryable, ae.details, fmt=args.format)
        return ae.exit_code
    except Exception as ex:
        import traceback
        traceback.print_exc(file=sys.stderr)
        emit_failure("INTERNAL_ERROR", str(ex), retryable=False, fmt=args.format)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
