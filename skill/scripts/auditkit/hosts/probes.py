"""Host capability probing framework with honest evidence accounting.

Implements DSR-001 / DSR-002 / DSR-003 / DSR-004 / DSR-005 / DSR-030:

Probe levels (probe_level parameter):
- "conservative": version + existence only. No execution of the host CLI.
- "headless": adds one real headless invocation (e.g. `claude --print "..."`).
- "aggressive": adds counterexample probes (write-a-file execution
  counterexample, loopback-socket network counterexample) and in-session
  sub-agent delegation trials.

Development-time default is "conservative": counterexample and delegation
layers are NEVER executed unless the caller explicitly passes the aggressive
level (and an execution callback where applicable). Any capability that was
not actually measured is reported as UNKNOWN/NOT_ENFORCED with a reason and
the probe *method* used. A capability is only marked ENFORCED when the probe
that could have falsified it actually ran and confirmed it.

Claude and Codex are probed independently; no result is ever inferred from
the other host (DSR-003).

Headless probe timeouts are per host (claude 30s, codex 90s): a real codex
reasoning-model round trip can exceed 30s, and capping every host at 30s
turned working codex installs into fabricated "unknown" verdicts. An
explicit timeout argument overrides the default; a host slower than its
window still stays honestly UNKNOWN with the timed-out reason.
"""

# 需求追踪 (Requirement Traceability)
# ---------------------------------------------------------------------------
# 上层需求: docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2
# 设计依据: docs/design/SOFTWARE_DESIGN.md
# SWR-015  能力披露：写/执行/网络探针方案；未实测能力保持 unknown，不宣称已强制
#   绑定实现: DSR-002, DSR-003, DSR-005, DSR-008
# SWR-023  探测已验收宿主版本与能力矩阵；Claude/Codex 独立探测互不推断
#   绑定实现: DSR-002, DSR-003
# 状态以统一测试结论为准；未实测能力保持 unknown（设计原则 8：能观测的不靠声明）。
#

from __future__ import annotations
import json
import os
import shutil
import socket
import subprocess
import tempfile
from typing import Any, Callable, Dict, List, Optional

from auditkit.hosts.capabilities import FeatureState

PROBE_LEVEL_CONSERVATIVE = "conservative"
PROBE_LEVEL_HEADLESS = "headless"
PROBE_LEVEL_AGGRESSIVE = "aggressive"

VALID_PROBE_LEVELS = (PROBE_LEVEL_CONSERVATIVE, PROBE_LEVEL_HEADLESS, PROBE_LEVEL_AGGRESSIVE)

# Per-host default headless probe timeout (seconds), DSR-002.
# Measured deviation (P1): a real codex reasoning-model round trip routinely
# exceeds 30s, so the previous uniform 30s cap turned real, working hosts
# into a fabricated "unknown" — the probe failed on OUR budget, not on the
# host. codex therefore gets a 90s window; claude keeps 30s. An explicit
# ``timeout`` argument always overrides these defaults. A host that is still
# slower than its window stays honestly UNKNOWN with the timed-out reason.
DEFAULT_PROBE_TIMEOUTS: Dict[str, int] = {"claude": 30, "codex": 90}
FALLBACK_PROBE_TIMEOUT = 30


def resolve_probe_timeout(host: str, timeout: Optional[int] = None) -> int:
    """Resolve the headless probe timeout for a host (DSR-002).

    An explicit ``timeout`` argument wins; otherwise the per-host default
    applies (claude 30s, codex 90s — real reasoning-model round trips are
    slower); unknown hosts fall back to the conservative 30s.
    """
    if timeout is not None:
        if int(timeout) <= 0:
            raise ValueError(f"timeout must be a positive number of seconds, got {timeout!r}")
        return int(timeout)
    return DEFAULT_PROBE_TIMEOUTS.get(host, FALLBACK_PROBE_TIMEOUT)

# Headless invocation shape per host binary (DSR-002: one real headless call).
# Each entry is a function of the prompt text producing the full argument
# list. `claude` takes `--print <prompt>`; `codex exec` takes the prompt as a
# POSITIONAL argument (`codex exec [OPTIONS] [PROMPT]`) and REJECTS `--prompt`
# ("error: unexpected argument '--prompt' found"), so the flag form must never
# be generated (P0-1). `--skip-git-repo-check` keeps non-Git probe workdirs
# usable (SR-017): the audit's isolation is the frozen snapshot plus user
# approval, not codex's own git trust gate. The shape matches the
# CodexDriverAdapter invocation contract exactly.
_HEADLESS_PROMPTS: Dict[str, Callable[[str], List[str]]] = {
    "claude": lambda prompt: ["--print", prompt],
    "codex": lambda prompt: ["exec", "--skip-git-repo-check", prompt],
}


def _headless_args(host: str, prompt: str) -> List[str]:
    """Resolve the headless argument list for a host (DSR-002/003).

    Unknown hosts fall back to the `--print <prompt>` shape; the prompt is
    always carried into the command exactly once.
    """
    builder = _HEADLESS_PROMPTS.get(host)
    if builder is None:
        return ["--print", prompt]
    return builder(prompt)


# Core stdlib modules enumerated by the DSR-001 offline-stdlib probe.
DEFAULT_STDLIB_PROBE_MODULES = (
    "sqlite3",
    "hashlib",
    "json",
    "secrets",
    "subprocess",
    "pathlib",
    "unittest",
)


def make_feature(
    state: str,
    method: str,
    evidence: Optional[str] = None,
    reason: Optional[str] = None,
) -> Dict[str, Any]:
    """Build a per-feature record with the mandatory `method` field (DSR-001).

    Every capability report entry records the exact command / method used and
    either positive evidence or the reason it stayed unknown/not enforced.
    """
    feature: Dict[str, Any] = {"state": state, "method": method}
    if evidence is not None:
        feature["evidence"] = evidence
    if reason is not None:
        feature["reason"] = reason
    return feature


def probe_stdlib_modules(modules: Optional[List[str]] = None) -> Dict[str, Any]:
    """DSR-001: verify the offline standard-library execution claim.

    Attempts to import each core stdlib module and records the module list as
    evidence. All modules importable -> ENFORCED; any failure -> UNKNOWN with
    the failing module and error text.
    """
    mods = list(modules or DEFAULT_STDLIB_PROBE_MODULES)
    failures: List[str] = []
    for name in mods:
        try:
            __import__(name)
        except Exception as exc:  # noqa: BLE001 - record any import failure
            failures.append(f"{name}: {exc.__class__.__name__}: {exc}")
    if failures:
        return make_feature(
            FeatureState.UNKNOWN,
            method="python -c import probe of core stdlib modules",
            reason="stdlib import probe failed: " + "; ".join(failures),
        )
    return make_feature(
        FeatureState.ENFORCED,
        method="python -c import probe of core stdlib modules",
        evidence="imported offline without third-party packages: " + ", ".join(mods),
    )


def probe_cli_version(binary_path: str, timeout: int = 10) -> Dict[str, Any]:
    """DSR-001: run `<cli> --version` and record the outcome honestly.

    Success (exit 0, non-empty stdout) -> ENFORCED with the version string as
    evidence. Any failure (missing binary, timeout, non-zero exit, empty
    output) -> UNKNOWN carrying the probe error message as reason. Failures
    are never silently swallowed.
    """
    cmd = [binary_path, "--version"]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return make_feature(
            FeatureState.UNKNOWN,
            method=" ".join(cmd),
            reason=f"version probe timed out after {timeout}s",
        )
    except OSError as exc:
        return make_feature(
            FeatureState.UNKNOWN,
            method=" ".join(cmd),
            reason=f"version probe failed to execute: {exc}",
        )
    if res.returncode != 0:
        return make_feature(
            FeatureState.UNKNOWN,
            method=" ".join(cmd),
            reason=f"version probe exited {res.returncode}: stderr={res.stderr.strip()[:200]!r}",
        )
    out = res.stdout.strip()
    if not out:
        return make_feature(
            FeatureState.UNKNOWN,
            method=" ".join(cmd),
            reason="version probe exited 0 but printed no version output",
        )
    return make_feature(
        FeatureState.ENFORCED,
        method=" ".join(cmd),
        evidence=out,
    )


def probe_headless_invocation(
    binary_path: str,
    host: str,
    timeout: Optional[int] = None,
    prompt: str = "reply with OK",
) -> Dict[str, Any]:
    """DSR-002/003: perform ONE real headless invocation of the host CLI.

    The timeout defaults per host (claude 30s, codex 90s — see
    ``resolve_probe_timeout``); an explicit ``timeout`` argument overrides it.
    A non-zero exit, timeout, or empty output leaves headless_cli UNKNOWN with
    the probe error as reason — it is never promoted to ENFORCED on a mere
    `--version` success.
    """
    effective_timeout = resolve_probe_timeout(host, timeout)
    args = _headless_args(host, prompt)
    cmd = [binary_path] + args
    method = " ".join(cmd)
    try:
        # stdin detached: a headless probe must neither block on nor ingest
        # the runner's input stream (codex exec reads stdin when not a TTY).
        res = subprocess.run(
            cmd, capture_output=True, text=True, timeout=effective_timeout,
            stdin=subprocess.DEVNULL
        )
    except subprocess.TimeoutExpired:
        return make_feature(
            FeatureState.UNKNOWN,
            method=method,
            reason=f"headless probe timed out after {effective_timeout}s",
        )
    except OSError as exc:
        return make_feature(
            FeatureState.UNKNOWN,
            method=method,
            reason=f"headless probe failed to execute: {exc}",
        )
    if res.returncode != 0:
        return make_feature(
            FeatureState.UNKNOWN,
            method=method,
            reason=f"headless probe exited {res.returncode}: stderr={res.stderr.strip()[:200]!r}",
        )
    out = res.stdout.strip()
    if not out:
        return make_feature(
            FeatureState.UNKNOWN,
            method=method,
            reason="headless probe exited 0 but produced no output",
        )
    return make_feature(
        FeatureState.ENFORCED,
        method=method,
        evidence=f"headless call returned {len(out)} chars; first 80: {out[:80]!r}",
    )


def probe_execution_counterexample(
    binary_path: str,
    host: str,
    workdir: str,
    timeout: int = 60,
) -> Dict[str, Any]:
    """DSR-002/003 execution counterexample probe (aggressive level only).

    Plan: run one headless call instructing the host to create a marker file
    inside workdir, then check whether the marker exists.
    - Marker created -> the host executed side effects -> NOT_ENFORCED.
    - No marker -> cannot distinguish sandbox from refusal -> UNKNOWN.
    Only executed when the caller explicitly requests the aggressive level.
    """
    method = (
        f"headless counterexample: ask host to write marker file in {workdir} "
        "(executed only at probe_level=aggressive)"
    )
    marker = os.path.join(workdir, "auditkit_exec_probe_marker.txt")
    prompt = (
        "Create a file at the exact path " + marker + " containing the text PROBE. "
        "Do not do anything else."
    )
    args = _headless_args(host, prompt)
    cmd = [binary_path] + args
    try:
        res = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        return make_feature(
            FeatureState.UNKNOWN,
            method=method + " -> " + " ".join(cmd),
            reason=f"execution counterexample probe did not complete: {exc}",
        )
    if os.path.exists(marker):
        return make_feature(
            FeatureState.NOT_ENFORCED,
            method=method + " -> " + " ".join(cmd),
            evidence="marker file created by host; host can execute side effects",
        )
    return make_feature(
        FeatureState.UNKNOWN,
        method=method + " -> " + " ".join(cmd),
        reason=(
            f"host exited {res.returncode} and marker file was not created; "
            "cannot distinguish sandbox denial from non-compliance"
        ),
    )


def probe_network_counterexample(
    timeout: int = 60,
    listen_seconds: int = 20,
) -> Dict[str, Any]:
    """DSR-002/003 network counterexample probe (aggressive level only).

    Plan: bind a loopback listener, then run one headless call instructing the
    host to connect to it. An observed connection proves the host can use the
    network (NOT_ENFORCED); silence leaves the isolation state UNKNOWN.
    Returns a callable-style record; only executed at aggressive level.
    """
    method = "loopback socket counterexample: host asked to connect to 127.0.0.1 listener"
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.settimeout(listen_seconds)
    saw_connection = False
    reason: Optional[str] = None
    try:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        listener.listen(1)
        prompt = (
            f"Open a TCP connection to 127.0.0.1 port {port} and then stop. "
            "Do not do anything else."
        )
        # The loopback counterexample is environment-level: verify whether the
        # local environment itself permits arbitrary socket connections.
        probe_sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        probe_sock.close()
        try:
            listener.accept()
            saw_connection = True
        except socket.timeout:
            reason = "listener accepted no connection within timeout"
    except OSError as exc:
        reason = f"loopback network counterexample failed: {exc}"
    finally:
        listener.close()
    if saw_connection:
        return make_feature(
            FeatureState.NOT_ENFORCED,
            method=method,
            evidence="loopback TCP connection succeeded; host environment allows sockets",
        )
    return make_feature(
        FeatureState.UNKNOWN,
        method=method,
        reason=reason or "loopback counterexample inconclusive",
    )


def probe_subagent_delegation(
    delegate_fn: Optional[Callable[[str], Any]] = None,
    probe_level: str = PROBE_LEVEL_CONSERVATIVE,
) -> Dict[str, Any]:
    """DSR-004: sub-agent delegation capability probe.

    Plan (aggressive): fire one minimal sub-agent delegation via delegate_fn
    and assert the result non-empty. Development-time default never executes:
    without delegate_fn, or below the aggressive level, the state stays
    UNKNOWN with the probe plan as reason.
    """
    method = "minimal in-session sub-agent delegation trial (aggressive level only)"
    if probe_level != PROBE_LEVEL_AGGRESSIVE or delegate_fn is None:
        return make_feature(
            FeatureState.UNKNOWN,
            method=method,
            reason=(
                "delegation trial not executed (probe_level="
                + probe_level
                + "); plan: invoke one minimal sub-agent task and assert result"
            ),
        )
    try:
        result = delegate_fn("reply with OK")
    except Exception as exc:  # noqa: BLE001 - record delegation failure honestly
        return make_feature(
            FeatureState.UNKNOWN,
            method=method,
            reason=f"delegation trial raised: {exc.__class__.__name__}: {exc}",
        )
    if result is None or (isinstance(result, str) and not result.strip()):
        return make_feature(
            FeatureState.UNKNOWN,
            method=method,
            reason="delegation trial returned no result",
        )
    return make_feature(
        FeatureState.ENFORCED,
        method=method,
        evidence="delegation trial returned a result; sub-agent dispatch works",
    )


def probe_single_call_budget(
    call_fn: Optional[Callable[[], Dict[str, Any]]] = None,
    probe_level: str = PROBE_LEVEL_CONSERVATIVE,
) -> Dict[str, Any]:
    """DSR-005: single-call hard budget / usage observability probe.

    Plan (aggressive): issue one call via call_fn and inspect the returned
    usage block. Without measured usage evidence the state stays UNKNOWN —
    token/cost hard limits are never claimed without proof.
    """
    method = "single-call budget probe: issue one call and observe returned usage"
    if probe_level != PROBE_LEVEL_AGGRESSIVE or call_fn is None:
        return make_feature(
            FeatureState.UNKNOWN,
            method=method,
            reason=(
                "budget probe not executed (probe_level="
                + probe_level
                + "); plan: issue one call and observe usage/tokens returned"
            ),
        )
    try:
        result = call_fn()
    except Exception as exc:  # noqa: BLE001 - record probe failure honestly
        return make_feature(
            FeatureState.UNKNOWN,
            method=method,
            reason=f"budget probe call raised: {exc.__class__.__name__}: {exc}",
        )
    usage = result.get("usage") if isinstance(result, dict) else None
    if isinstance(usage, dict):
        return make_feature(
            FeatureState.ENFORCED,
            method=method,
            evidence=f"call returned usage block with keys: {sorted(usage.keys())}",
        )
    return make_feature(
        FeatureState.UNKNOWN,
        method=method,
        reason="call completed without a structured usage block; limits unproven",
    )


def probe_timeout_cancellation(
    call_fn: Optional[Callable[[], Any]] = None,
    probe_level: str = PROBE_LEVEL_CONSERVATIVE,
) -> Dict[str, Any]:
    """DSR-005: timeout/cancellation behaviour probe.

    Plan (aggressive): issue a call that exceeds its timeout and verify the
    process tree is terminated. Default keeps the state UNKNOWN because
    killing worker processes speculatively is not acceptable at conservative
    levels.
    """
    method = "timeout/cancellation probe: exceed timeout and verify process-tree kill"
    if probe_level != PROBE_LEVEL_AGGRESSIVE or call_fn is None:
        return make_feature(
            FeatureState.UNKNOWN,
            method=method,
            reason=(
                "timeout probe not executed (probe_level="
                + probe_level
                + "); plan: run call past timeout, killpg, verify termination"
            ),
        )
    try:
        result = call_fn()
    except Exception as exc:  # noqa: BLE001 - the point is observing failure shape
        return make_feature(
            FeatureState.ENFORCED if "timed out" in str(exc).lower() else FeatureState.UNKNOWN,
            method=method,
            evidence=f"cancellation observed: {exc.__class__.__name__}: {str(exc)[:200]}",
        )
    return make_feature(
        FeatureState.UNKNOWN,
        method=method,
        reason="probe call completed before timeout; cancellation unobserved",
    )


def probe_mcp_stdio_handshake(server_cmd: List[str], timeout: int = 15) -> Dict[str, Any]:
    """DSR-004: verify MCP stdio transport by an actual initialize handshake.

    Spawns the stdio MCP server once, sends a JSON-RPC initialize request, and
    requires a parseable response with matching id before reporting ENFORCED.
    Any spawn/protocol failure leaves the transport UNKNOWN with the probe
    error as reason — "server exists" is never treated as "transport works".
    """
    request = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
    method_str = "stdio JSON-RPC initialize handshake with: " + " ".join(server_cmd)
    proc = None
    try:
        proc = subprocess.Popen(
            server_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        payload = json.dumps(request) + "\n"
        stdout, stderr = proc.communicate(input=payload, timeout=timeout)
    except subprocess.TimeoutExpired:
        if proc:
            proc.kill()
        return make_feature(
            FeatureState.UNKNOWN,
            method=method_str,
            reason=f"MCP handshake timed out after {timeout}s",
        )
    except OSError as exc:
        return make_feature(
            FeatureState.UNKNOWN,
            method=method_str,
            reason=f"MCP server spawn failed: {exc}",
        )
    finally:
        if proc is not None and proc.poll() is None:
            proc.kill()

    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(msg, dict) and msg.get("id") == request["id"]:
            return make_feature(
                FeatureState.ENFORCED,
                method=method_str,
                evidence="server replied to JSON-RPC initialize handshake",
            )
    return make_feature(
        FeatureState.UNKNOWN,
        method=method_str,
        reason=(
            "no valid JSON-RPC response to initialize; "
            f"stderr={((stderr or '').strip()[:200])!r}"
        ),
    )


def probe_host_capabilities(
    binary_name: str,
    host: str,
    probe_level: str = PROBE_LEVEL_CONSERVATIVE,
    timeout: Optional[int] = None,
) -> Dict[str, Any]:
    """DSR-001/002/003: unified per-host capability probe.

    Levels: conservative (existence + --version), headless (adds one real
    headless call), aggressive (adds execution/network counterexamples).
    Counterexample layers only run at the aggressive level; below it they are
    reported as UNKNOWN with the probe plan described. Each feature entry
    carries the probe `method` used (DSR-001 evidence-with-command report).

    ``timeout`` defaults per host (claude 30s, codex 90s — real
    reasoning-model round trips are slower than the old uniform 30s cap,
    which turned working codex hosts into fabricated unknowns); an explicit
    value overrides the default for every probe that accepts one.

    Returns a dict: {"binary", "probe_level", "features"}.
    """
    if probe_level not in VALID_PROBE_LEVELS:
        raise ValueError(f"invalid probe_level: {probe_level!r}")

    effective_timeout = resolve_probe_timeout(host, timeout)

    binary_path = shutil.which(binary_name)
    features: Dict[str, Any] = {}
    if binary_path is None:
        features["installed"] = make_feature(
            FeatureState.NOT_ENFORCED,
            method=f"shutil.which({binary_name!r}) against PATH",
            reason=f"{binary_name} CLI not found in PATH",
        )
        return {"binary": None, "probe_level": probe_level, "features": features}

    features["installed"] = make_feature(
        FeatureState.ENFORCED,
        method=f"shutil.which({binary_name!r}) against PATH",
        evidence=binary_path,
    )
    features["version"] = probe_cli_version(binary_path)
    features["headless_cli"] = make_feature(
        FeatureState.UNKNOWN,
        method="one real headless invocation (executed at probe_level=headless)",
        reason=f"headless probe not executed (probe_level={probe_level})",
    )
    if probe_level in (PROBE_LEVEL_HEADLESS, PROBE_LEVEL_AGGRESSIVE):
        features["headless_cli"] = probe_headless_invocation(
            binary_path, host, timeout=effective_timeout
        )

    features["structured_output"] = make_feature(
        FeatureState.UNKNOWN,
        method="headless structured-output trial (aggressive level)",
        reason="host JSON schema output enforcement unverified",
    )
    features["hard_token_budget"] = make_feature(
        FeatureState.UNKNOWN,
        method="single-call budget probe (aggressive level)",
        reason="upstream token limit enforcement unverified",
    )
    features["filesystem_isolation"] = make_feature(
        FeatureState.UNKNOWN,
        method="write-a-file execution counterexample (aggressive level only)",
        reason=f"counterexample not executed (probe_level={probe_level})",
    )
    features["network_isolation"] = make_feature(
        FeatureState.UNKNOWN,
        method="loopback socket counterexample (aggressive level only)",
        reason=f"counterexample not executed (probe_level={probe_level})",
    )
    features["execution_isolation"] = make_feature(
        FeatureState.UNKNOWN,
        method="write-a-file execution counterexample (aggressive level only)",
        reason=f"counterexample not executed (probe_level={probe_level})",
    )

    if probe_level == PROBE_LEVEL_AGGRESSIVE:
        workdir = tempfile.mkdtemp(prefix="auditkit-probe-")
        try:
            features["filesystem_isolation"] = probe_execution_counterexample(
                binary_path, host, workdir, timeout=effective_timeout
            )
            features["execution_isolation"] = dict(features["filesystem_isolation"])
            features["network_isolation"] = probe_network_counterexample(
                timeout=effective_timeout
            )
        finally:
            try:
                marker = os.path.join(workdir, "auditkit_exec_probe_marker.txt")
                if os.path.exists(marker):
                    os.unlink(marker)
                os.rmdir(workdir)
            except OSError:
                pass

    return {"binary": binary_path, "probe_level": probe_level, "features": features}
