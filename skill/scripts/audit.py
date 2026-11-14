#!/usr/bin/env python3
"""polyglot-audit CLI - Command-Line Interface for Source Code Security Audit.

Implements IFC-04 / IFC-06 / DSR-074:
- Unified CLI interface supporting:
  doctor, prepare, run, next, start, submit, status, pause, resume, finalize, report, mcp, host-fail, guide.
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
#   绑定实现: DSR-032, DSR-065
# SWR-023  适配 Claude Code CLI / Codex CLI 已验收版本：认证、结构化输出、能力矩阵；未知不得静默降级
#   绑定实现: DSR-074, DSR-075
# 状态以统一测试结论为准；未实测能力保持 unknown（设计原则 8：能观测的不靠声明）。
#

from __future__ import annotations
import argparse
import json
import os
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
)
from auditkit.hosts.mcp_adapter import MCPServer
from auditkit.ledger.db import get_db_connection
from auditkit.ledger.task_queue import TaskQueue


SKILL_DIR = SCRIPT_DIR.parent


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
            # Activate and process tasks in-session
            run_path = Path(args.run_dir)
            conn = get_db_connection(run_path / "events.db")
            run_row = conn.execute("SELECT run_id, state FROM runs LIMIT 1").fetchone()
            if not run_row:
                raise InvalidInputError("No active run found in database")
            run_id = run_row["run_id"]
            if run_row["state"] in ("ready", "paused"):
                app.activate(run_id, args.run_dir)

            emit_json_success({"run_id": run_id, "state": "active", "message": "Run activated"})
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
            conn = get_db_connection(Path(args.run_dir) / "events.db")
            run_row = conn.execute("SELECT run_id FROM runs LIMIT 1").fetchone()
            if not run_row:
                raise InvalidInputError("No run found in database")
            rev = app.pause(run_row["run_id"], args.run_dir, reason=args.reason)
            emit_json_success({"run_id": run_row["run_id"], "state": "paused", "revision": rev})
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
            emit_json_success({"report_md": content})
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
