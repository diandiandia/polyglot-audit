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
- Standard JSON envelope on stdout:
  {"schema_version": "1.0", "ok": true, "value": {...}}
  {"schema_version": "1.0", "ok": false, "error": {"code": "...", "message": "...", "retryable": false, "details": {}}}
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
from auditkit.hosts.mcp_adapter import MCPServer
from auditkit.ledger.db import get_db_connection
from auditkit.ledger.event_store import utc_now_iso
from auditkit.ledger.task_queue import TaskQueue


SKILL_DIR = SCRIPT_DIR.parent

# --host claude/codex -> host CLI binary looked up on PATH (IFC-06 / DSR-074).
HOST_BINARIES = {"claude": "claude", "codex": "codex"}

# REPORT.md header line (en + zh i18n variants) used as the generation-id
# fallback source when the artifacts ledger has no REPORT record.
_GENERATION_HEADER_RE = re.compile(r"Generation\)?\*\*: `([^`]+)`")

# pause --reason upper bound (chars); service raises InvalidInputError past it.
PAUSE_REASON_MAX_CHARS = 256


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


def _normalize_worker_result(raw: object, claim: dict, kind: str) -> dict:
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
    for field in ("coverage", "records", "overflow"):
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
    return result


def _make_execute_fn(app: AuditAppService, conn, run_dir: str, adapter) -> object:
    """Build the execute_fn consumed by run_dispatch_loop.

    Calls the adapter's worker execution entry point (execute_worker), then
    normalizes the payload into a schema-valid worker_result bound to the
    claim. Adapter.last_usage is converted by run_dispatch_loop itself via
    app.build_usage into the trusted usage object submitted per attempt.
    """
    def execute_fn(claim: dict) -> dict:
        prompt = _build_worker_prompt(claim, run_dir)
        raw = adapter.execute_worker(prompt, task_id=claim["task_id"])
        return _normalize_worker_result(raw, claim, _task_kind(conn, claim))
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

    # prepare
    p_prep = subparsers.add_parser("prepare", help="Create new run, freeze snapshot, and generate plan")
    p_prep.add_argument("--target", required=True, help="Target repository directory")
    p_prep.add_argument("--run-dir", required=True, help="Output run directory")
    p_prep.add_argument("--config", required=True, help="Path to RunConfig JSON")
    p_prep.add_argument("--json", action="store_true", default=True)

    # run
    p_run = subparsers.add_parser("run", help="Activate run and execute driver loop")
    p_run.add_argument("--run-dir", required=True, help="Run directory")
    p_run.add_argument("--host", choices=["claude", "codex", "session"], default="session")
    p_run.add_argument("--concurrency", type=int, default=1)
    p_run.add_argument("--json", action="store_true", default=True)

    # next
    p_next = subparsers.add_parser("next", help="Claim next batch of tasks")
    p_next.add_argument("--run-dir", required=True, help="Run directory")
    p_next.add_argument("--batch", type=int, default=1, help="Batch size")
    p_next.add_argument("--json", action="store_true", default=True)

    # start
    p_start = subparsers.add_parser("start", help="Mark task attempt as started (stdin for claim)")
    p_start.add_argument("--run-dir", required=True, help="Run directory")
    p_start.add_argument("--json", action="store_true", default=True)

    # submit
    p_sub = subparsers.add_parser("submit", help="Submit task result (stdin for claim + result)")
    p_sub.add_argument("--run-dir", required=True, help="Run directory")
    p_sub.add_argument("--json", action="store_true", default=True)

    # status
    p_stat = subparsers.add_parser("status", help="Get run status and budget metrics")
    p_stat.add_argument("--run-dir", required=True, help="Run directory")
    p_stat.add_argument("--json", action="store_true", default=True)

    # pause
    p_pause = subparsers.add_parser("pause", help="Pause run dispatch")
    p_pause.add_argument("--run-dir", required=True, help="Run directory")
    p_pause.add_argument("--reason", default="user_requested")
    p_pause.add_argument("--json", action="store_true", default=True)

    # resume
    p_res = subparsers.add_parser("resume", help="Verify integrity and resume paused run")
    p_res.add_argument("--run-dir", required=True, help="Run directory")
    p_res.add_argument("--json", action="store_true", default=True)

    # finalize
    p_fin = subparsers.add_parser("finalize", help="Evaluate gates and publish reports")
    p_fin.add_argument("--run-dir", required=True, help="Run directory")
    p_fin.add_argument("--json", action="store_true", default=True)

    # report
    p_rep = subparsers.add_parser("report", help="Read latest published report")
    p_rep.add_argument("--run-dir", required=True, help="Run directory")
    p_rep.add_argument("--json", action="store_true", default=True)

    # mcp
    p_mcp = subparsers.add_parser("mcp", help="Run MCP stdio 4-tool server")
    p_mcp.add_argument("--run-dir", required=True, help="Run directory")

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

    # guide
    p_guide = subparsers.add_parser("guide", help="Interactive lightweight security guidance")
    p_guide.add_argument("--query", required=True, help="Security question or code topic")
    p_guide.add_argument("--language", default="python", help="Target language")
    p_guide.add_argument("--json", action="store_true", default=True)

    args = parser.parse_args()
    if not args.subcommand:
        parser.print_help(sys.stderr)
        return 2

    app = AuditAppService(SKILL_DIR)

    try:
        if args.subcommand == "doctor":
            res = app.doctor(probe_cli=args.probe)
            emit_json_success({"capabilities": res})
            return 0

        elif args.subcommand == "guide":
            guide_svc = GuideService(SKILL_DIR / "knowledge")
            res = guide_svc.answer_query(args.query, language=args.language)
            emit_json_success(res)
            return 0

        elif args.subcommand == "prepare":
            with open(args.config, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            res = app.prepare(args.target, args.run_dir, cfg)
            emit_json_success(res)
            return 0

        elif args.subcommand == "run":
            # IFC-06: run mounts the dispatch loop. --host session (default)
            # only activates the run and prints the in-session to-do guidance
            # (the host session itself drives next/start/submit — the CLI
            # neither idles nor pretends to execute). --host claude/codex
            # drives app.run_dispatch_loop to completion with the matching
            # DriverAdapter and an AIMD ConcurrencyController.
            run_path = Path(args.run_dir)
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
                emit_json_success({
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
                })
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
            controller = ConcurrencyController(initial=args.concurrency)
            execute_fn = _make_execute_fn(app, conn, args.run_dir, adapter)
            summary = app.run_dispatch_loop(
                run_id,
                args.run_dir,
                execute_fn,
                adapter=adapter,
                controller=controller,
            )
            summary["stop_reason"] = _stop_reason_for_drain(conn, run_id, summary)
            queued = conn.execute(
                "SELECT count(*) AS cnt FROM tasks WHERE run_id = ? AND state = 'queued'",
                (run_id,),
            ).fetchone()["cnt"]
            final_state = conn.execute(
                "SELECT state FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone()["state"]
            emit_json_success({
                "run_id": run_id,
                "state": final_state,
                "mode": args.host,
                "concurrency": controller.current,
                "queued_tasks": queued,
                "dispatch": summary,
            })
            return 0

        elif args.subcommand == "next":
            conn = get_db_connection(Path(args.run_dir) / "events.db")
            run_row = conn.execute("SELECT run_id FROM runs LIMIT 1").fetchone()
            if not run_row:
                raise InvalidInputError("No run found in database")
            claims = app.next(run_row["run_id"], args.run_dir, batch_size=args.batch)
            emit_json_success({"claims": claims})
            return 0

        elif args.subcommand == "start":
            # Read claim authentication payload from stdin
            input_text = sys.stdin.read().strip()
            if not input_text:
                raise InvalidInputError("stdin required for start credentials")
            claim_data = json.loads(input_text)
            res = app.start(args.run_dir, claim_data)
            emit_json_success(res)
            return 0

        elif args.subcommand == "submit":
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
            emit_json_success(res)
            return 0

        elif args.subcommand == "status":
            conn = get_db_connection(Path(args.run_dir) / "events.db")
            run_row = conn.execute("SELECT run_id FROM runs LIMIT 1").fetchone()
            if not run_row:
                raise InvalidInputError("No run found in database")
            res = app.status(run_row["run_id"], args.run_dir)
            emit_json_success(res)
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
            emit_json_success(value)
            return 0

        elif args.subcommand == "resume":
            conn = get_db_connection(Path(args.run_dir) / "events.db")
            run_row = conn.execute("SELECT run_id FROM runs LIMIT 1").fetchone()
            if not run_row:
                raise InvalidInputError("No run found in database")
            res = app.resume(run_row["run_id"], args.run_dir)
            emit_json_success(res)
            return 0

        elif args.subcommand == "finalize":
            conn = get_db_connection(Path(args.run_dir) / "events.db")
            run_row = conn.execute("SELECT run_id FROM runs LIMIT 1").fetchone()
            if not run_row:
                raise InvalidInputError("No run found in database")
            # res transparently carries incomplete_reasons and coverage_gaps
            # (SWR-012: incomplete runs must state why, never fake complete).
            res = app.finalize(run_row["run_id"], args.run_dir)
            emit_json_success(res)
            return 0

        elif args.subcommand == "host-fail":
            # DSR-065 / SWR-022: consume service.report_host_failure.
            # The claim and failure details come from stdin, never argv (DSR-074).
            if not (Path(args.run_dir) / "events.db").exists():
                raise InvalidInputError(f"No events.db found in run directory {args.run_dir}")
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
            emit_json_success(res)
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
            emit_json_success({"generation_id": generation_id, "report_md": content})
            return 0

        elif args.subcommand == "mcp":
            conn = get_db_connection(Path(args.run_dir) / "events.db")
            queue = TaskQueue(conn)
            server = MCPServer(args.run_dir, queue)
            # Run simple stdio loop
            for line in sys.stdin:
                line = line.strip()
                if not line:
                    continue
                req = json.loads(line)
                method = req.get("method")
                params = req.get("params", {})
                req_id = req.get("id")
                try:
                    result = server.handle_call(method, params)
                    resp = {"jsonrpc": "2.0", "id": req_id, "result": result}
                except AuditError as ae:
                    resp = {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32000, "message": ae.message, "data": ae.to_dict()}}
                except Exception as ex:
                    resp = {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32603, "message": str(ex)}}
                sys.stdout.write(json.dumps(resp) + "\n")
                sys.stdout.flush()
            return 0

    except AuditError as ae:
        emit_json_error(ae.code, ae.message, ae.retryable, ae.details)
        return ae.exit_code
    except Exception as ex:
        emit_json_error("INTERNAL_ERROR", str(ex), retryable=False)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
