"""Fake host CLI fixtures for the hosts test suite (DSR-002/003/029/048).

Builds executable shell scripts that impersonate the `claude` / `codex` CLIs
with fixed, test-controlled behaviour (version output, exit codes, stderr
patterns, headless output, delays, attempt counters). Tests inject the
directory via PATH or pass the script path directly as the adapter binary.

Standard library only; no test framework dependency (usable from unittest).
"""

from __future__ import annotations
import os
import stat
import tempfile

_SCRIPT_TEMPLATE = """#!/bin/sh
# Auto-generated fake host CLI (tests/hosts/fake_hosts.py). Do not edit.
if [ "$1" = "--version" ]; then
  echo '@@VERSION_OUTPUT@@'
  exit @@VERSION_EXIT@@
fi
@@PRE_HEADLESS@@
if [ "@@SLEEP_SECONDS@@" -gt 0 ] 2>/dev/null; then
  sleep @@SLEEP_SECONDS@@
fi
@@COUNTER_BLOCK@@
if [ -n "@@HEADLESS_STDERR@@" ]; then
  echo '@@HEADLESS_STDERR@@' >&2
fi
if [ -n "@@HEADLESS_STDOUT@@" ]; then
  echo '@@HEADLESS_STDOUT@@'
fi
exit @@HEADLESS_EXIT@@
"""


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
) -> str:
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
    }
    for token, value in replacements.items():
        script = script.replace(token, value)
    return script


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
    """
    script = _render(
        version_output, version_exit, headless_stdout, headless_stderr, headless_exit, sleep_seconds
    )
    return _write_executable(os.path.join(directory, name), script)


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
    script = _render(
        version_output,
        0,
        success_stdout,
        "",
        0,
        counter_block=counter_block,
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
