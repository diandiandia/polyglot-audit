"""Fake host CLI fixtures for the hosts test suite (DSR-002/003/029/048).

Builds executable shell scripts that impersonate the `claude` / `codex` CLIs
with fixed, test-controlled behaviour (version output, exit codes, stderr
patterns, headless output, delays, attempt counters). Tests inject the
directory via PATH or pass the script path directly as the adapter binary.

The fake `codex` models the REAL CLI grammar: `codex exec` takes the prompt
either as a positional argument or (when no positional prompt is given) from
stdin; any occurrence of `--prompt` in argv is rejected with the clap error
and exit code 2 (P0-1), and the real `--skip-git-repo-check` option is
accepted. It records the last invocation's arguments into `<name>.argv.log`
and the consumed stdin into `<name>.stdin.log`, so tests can assert exactly
HOW the prompt was transmitted (argv vs stdin) and that argv stays within
OS arg-length limits for large payloads. This keeps the fake from masking an
adapter that passes `--prompt` — the defect class that once hid behind
permissive fakes.

Standard library only; no test framework dependency (usable from unittest).
"""

from __future__ import annotations
import os
import stat
import sys
import tempfile

_SCRIPT_TEMPLATE = """#!/bin/sh
# Auto-generated fake host CLI (tests/hosts/fake_hosts.py). Do not edit.
if [ "$1" = "--version" ]; then
  echo '@@VERSION_OUTPUT@@'
  exit @@VERSION_EXIT@@
fi
@@CODEX_ARG_GUARD@@
# Record the arguments of the current (headless) invocation; overwritten each
# call so readers always observe the LAST invocation only.
printf '%s\\n' "$@" > '@@ARGV_LOG_PATH@@'
@@STDIN_CAPTURE@@
@@PRE_HEADLESS@@
if [ "@@SLEEP_SECONDS@@" -gt 0 ] 2>/dev/null; then
  sleep @@SLEEP_SECONDS@@
fi
@@COUNTER_BLOCK@@
# Quote-safe emission (case, not [ -n "..." ]): payloads carry JSON with
# double quotes, which broke the old `[ -n "@@..." ]` guard and silently
# swallowed stdout for some payload shapes.
case '@@HEADLESS_STDERR@@' in
  '') ;;
  *) printf '%s\n' '@@HEADLESS_STDERR@@' >&2 ;;
esac
case '@@HEADLESS_STDOUT@@' in
  '') ;;
  *) printf '%s\n' '@@HEADLESS_STDOUT@@' ;;
esac
exit @@HEADLESS_EXIT@@
"""

# Real clap rejection emitted by codex-cli 0.167.0 for `codex exec --prompt X`
# (P0-1): the prompt is a positional argument of `codex exec [OPTIONS] [PROMPT]`.
# `--skip-git-repo-check` is a real option of `codex exec` and is accepted (it
# disables codex's own git trust gate); the guard below intentionally does NOT
# reject it, so an adapter/probe that passes it is modelled faithfully.
_CODEX_ARG_GUARD = """# Real-codex argument grammar (P0-1, verified against codex-cli 0.167.0):
# 1. `--prompt` is NOT a valid option of `codex exec`; the clap parser rejects
#    it with exit code 2 before any execution.
# 2. The git trust gate refuses a headless exec without --skip-git-repo-check
#    ("Not inside a trusted directory ..."), exit code 1. The fake models the
#    conservative non-Git cwd, so the option is REQUIRED for the headless path.
for arg in "$@"; do
  if [ "$arg" = "--prompt" ]; then
    echo "error: unexpected argument '--prompt' found" >&2
    echo "" >&2
    echo "  tip: to pass '--prompt' as a value, use '-- --prompt'" >&2
    echo "" >&2
    echo "Usage: codex exec [OPTIONS] [PROMPT]" >&2
    echo "       codex exec [OPTIONS] <COMMAND> [ARGS]" >&2
    echo "" >&2
    echo "For more information, try '--help'." >&2
    exit 2
  fi
done
SKIP_GIT_CHECK=false
for arg in "$@"; do
  if [ "$arg" = "--skip-git-repo-check" ]; then
    SKIP_GIT_CHECK=true
  fi
done
if [ "$SKIP_GIT_CHECK" != "true" ]; then
  echo "Not inside a trusted directory and --skip-git-repo-check was not specified." >&2
  exit 1
fi"""


def _write_executable(path: str, content: str) -> str:
    """Write content to path and mark it executable."""
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    mode = os.stat(path).st_mode
    os.chmod(path, mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


def _render(
    version_output: str,
    version_exit: int,
    headless_stdout: str,
    headless_stderr: str,
    headless_exit: int,
    sleep_seconds: int = 0,
    counter_block: str = "",
    codex_arg_guard: str = "",
    argv_log_path: str = "/dev/null",
    stdin_log_path: str = "/dev/null",
) -> str:
    if stdin_log_path != "/dev/null":
        # Capture the consumed stdin so tests can assert prompt delivery.
        # Guarded on stdin not being a TTY: the adapter always supplies a
        # pipe (prompt written then closed); an interactive caller is left
        # alone instead of blocking on `cat`.
        stdin_capture = (
            "if [ ! -t 0 ]; then\n"
            f"  cat > '{stdin_log_path}'\n"
            "fi\n"
        )
    else:
        stdin_capture = ""
    script = _SCRIPT_TEMPLATE
    replacements = {
        "@@VERSION_OUTPUT@@": version_output,
        "@@VERSION_EXIT@@": str(version_exit),
        "@@HEADLESS_STDOUT@@": headless_stdout,
        "@@HEADLESS_STDERR@@": headless_stderr,
        "@@HEADLESS_EXIT@@": str(headless_exit),
        "@@SLEEP_SECONDS@@": str(sleep_seconds),
        "@@COUNTER_BLOCK@@": counter_block,
        "@@PRE_HEADLESS@@": "",
        "@@CODEX_ARG_GUARD@@": codex_arg_guard,
        "@@ARGV_LOG_PATH@@": argv_log_path,
        "@@STDIN_CAPTURE@@": stdin_capture,
    }
    for token, value in replacements.items():
        script = script.replace(token, value)
    return script


def _models_real_codex(name: str) -> bool:
    """True when the fake impersonates the real codex CLI argument grammar."""
    return name == "codex" or name.startswith("codex")


def create_fake_host(
    directory: str,
    name: str,
    version_output: str = "fake-host version 9.9.9",
    version_exit: int = 0,
    headless_stdout: str = '{"ok": true}',
    headless_stderr: str = "",
    headless_exit: int = 0,
    sleep_seconds: int = 0,
) -> str:
    """Create a fake host CLI script and return its path.

    `--version` prints version_output and exits version_exit. Any other
    invocation (headless path) sleeps sleep_seconds, then prints
    headless_stderr to stderr and headless_stdout to stdout before exiting
    headless_exit.

    A fake named `codex` (or `codex*`) additionally models the real CLI's
    argument grammar: the prompt is accepted only as a positional argument,
    `--prompt` anywhere in argv is rejected with the clap error and exit 2,
    and `--skip-git-repo-check` is accepted as the real option is.
    The last invocation's arguments are recorded in `<name>.argv.log`.
    """
    codex_guard = _CODEX_ARG_GUARD if _models_real_codex(name) else ""
    argv_log = os.path.join(directory, f"{name}.argv.log") if codex_guard else "/dev/null"
    stdin_log = os.path.join(directory, f"{name}.stdin.log") if codex_guard else "/dev/null"
    script = _render(
        version_output,
        version_exit,
        headless_stdout,
        headless_stderr,
        headless_exit,
        sleep_seconds,
        codex_arg_guard=codex_guard,
        argv_log_path=argv_log,
        stdin_log_path=stdin_log,
    )
    return _write_executable(os.path.join(directory, name), script)


def last_invoked_args(directory: str, name: str) -> list:
    """Return the arguments of the fake host's last (headless) invocation.

    Only meaningful for fakes built with the real-codex argument grammar
    (`<name>.argv.log`); other fakes log to /dev/null and return [].
    """
    log = os.path.join(directory, f"{name}.argv.log")
    if not os.path.exists(log):
        return []
    with open(log, encoding="utf-8") as f:
        return [line for line in f.read().split("\n") if line != ""]


def last_stdin(directory: str, name: str) -> str:
    """Return the stdin the fake host's last (headless) invocation consumed.

    Only meaningful for fakes that capture stdin (`<name>.stdin.log`); other
    fakes leave the capture disabled and return "".
    """
    log = os.path.join(directory, f"{name}.stdin.log")
    if not os.path.exists(log):
        return ""
    with open(log, encoding="utf-8") as f:
        return f.read()


def create_rate_limited_fake_host(
    directory: str,
    name: str,
    fail_first: int = 2,
    rate_limit_stderr: str = "rate limit exceeded, retry later",
    success_stdout: str = '{"ok": true, "usage": {"input_tokens": 10, "output_tokens": 5}}',
    version_output: str = "fake-host version 9.9.9",
) -> str:
    """Fake host that fails the first `fail_first` headless calls with a
    rate-limit stderr, then succeeds. Each attempt is appended to a counter
    file so tests can assert how many invocations occurred."""
    counter_file = os.path.join(directory, f"{name}.attempt_counter")
    counter_block = (
        f"echo attempt >> '{counter_file}'\n"
        f"if [ \"$(wc -l < '{counter_file}')\" -le {fail_first} ]; then\n"
        f"  echo '{rate_limit_stderr}' >&2\n"
        f"  exit 1\n"
        f"fi"
    )
    codex_guard = _CODEX_ARG_GUARD if _models_real_codex(name) else ""
    argv_log = os.path.join(directory, f"{name}.argv.log") if codex_guard else "/dev/null"
    stdin_log = os.path.join(directory, f"{name}.stdin.log") if codex_guard else "/dev/null"
    script = _render(
        version_output,
        0,
        success_stdout,
        "",
        0,
        counter_block=counter_block,
        codex_arg_guard=codex_guard,
        argv_log_path=argv_log,
        stdin_log_path=stdin_log,
    )
    return _write_executable(os.path.join(directory, name), script)


def create_mcp_stdio_fake_server(directory: str, name: str = "fake_mcp_server.py") -> str:
    """Create a fake stdio MCP server that completes a JSON-RPC initialize
    handshake: it echoes any request back with the same id."""
    path = os.path.join(directory, name)
    script = (
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        "for line in sys.stdin:\n"
        "    line = line.strip()\n"
        "    if not line:\n"
        "        continue\n"
        "    try:\n"
        "        req = json.loads(line)\n"
        "    except json.JSONDecodeError:\n"
        "        continue\n"
        "    resp = {\"jsonrpc\": \"2.0\", \"id\": req.get(\"id\"), \"result\": {\"serverInfo\": {\"name\": \"fake-mcp\"}}}\n"
        "    sys.stdout.write(json.dumps(resp) + \"\\n\")\n"
        "    sys.stdout.flush()\n"
    )
    return _write_executable(path, script)


def make_path_dir() -> str:
    """Create an empty directory usable as a PATH entry (missing-CLI scenario)."""
    return tempfile.mkdtemp(prefix="fakepath-")


# Synthetic host whose headless call HONOURS the network counterexample
# prompt: it parses the loopback address/port out of the prompt text and
# connects as the host CLI process would. Three synthesised behaviours cover
# the probe's verdict space (connect = host used the network, refuse =
# sandboxed host that fails its headless call, hang = host slower than the
# probe window). The shebang pins the interpreter absolutely so the fake
# keeps working under tests that replace PATH with a bare directory.
_NETWORK_FAKE_TEMPLATE = """#!@@INTERPRETER@@
# Auto-generated fake host CLI with network behaviour (tests/hosts/fake_hosts.py). Do not edit.
import re
import socket
import sys
import time

BEHAVIOUR = '@@NET_BEHAVIOUR@@'
CONNECT_DELAY = @@CONNECT_DELAY@@
HANG_SECONDS = @@HANG_SECONDS@@

args = sys.argv[1:]
if args and args[0] == "--version":
    print('fake-host version 9.9.9')
    sys.exit(0)

# The headless prompt is the trailing positional argument for both supported
# shapes (claude --print PROMPT / codex exec --skip-git-repo-check PROMPT).
prompt = args[-1] if args else ''
match = re.search(r"127\\.0\\.0\\.1 port (\\d+)", prompt)
if BEHAVIOUR == 'connect':
    if match:
        if CONNECT_DELAY:
            time.sleep(CONNECT_DELAY)
        sock = socket.create_connection(('127.0.0.1', int(match.group(1))), timeout=5)
        sock.close()
        print('connected to listener')
    else:
        print('OK')
    sys.exit(0)
if BEHAVIOUR == 'refuse':
    sys.stderr.write('connection refused by sandbox policy')
    sys.exit(7)
if BEHAVIOUR == 'hang':
    time.sleep(HANG_SECONDS)
    print('OK')
    sys.exit(0)
sys.exit(0)
"""


def create_network_fake_host(
    directory: str,
    name: str,
    behaviour: str,
    connect_delay: int = 0,
    hang_seconds: int = 0,
) -> str:
    """Create a fake host CLI with synthesised network behaviour.

    behaviour="connect": the headless call reads the loopback port out of the
    prompt and opens a TCP connection to it (after an optional delay).
    behaviour="refuse": the headless call fails with exit 7 and a sandbox
    refusal on stderr - the fake of a host whose process cannot use sockets.
    behaviour="hang": the headless call sleeps hang_seconds (longer than the
    probe window) - the fake of a host slower than its probe timeout.

    Standard library only; usable from unittest like the other fakes.
    """
    if behaviour not in ("connect", "refuse", "hang"):
        raise ValueError(f"invalid behaviour: {behaviour!r}")
    script = (
        _NETWORK_FAKE_TEMPLATE
        .replace("@@INTERPRETER@@", sys.executable)
        .replace("@@NET_BEHAVIOUR@@", behaviour)
        .replace("@@CONNECT_DELAY@@", str(connect_delay))
        .replace("@@HANG_SECONDS@@", str(hang_seconds))
    )
    return _write_executable(os.path.join(directory, name), script)
