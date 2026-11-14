---
name: polyglot-audit
description: Universal source code security audit skill for multi-language repositories. Supports static taint-reachability analysis across 15 core languages without dynamic execution of untrusted target code.
---

# polyglot-audit: Universal Source Code Security Audit Skill

## 1. Overview & Modes

`polyglot-audit` is a static, evidence-oriented source code security audit engine designed for multi-language repositories. It operates in two strictly separated modes:

1. **`guide` Mode (Default / Interactive Q&A)**:
   - For ad-hoc security questions or analyzing small code snippets.
   - Strictly does **NOT** create a run directory, events database, or audit dossier.
   - Responds using core methodology and catalog knowledge directly.
   - Ambiguous requests (empty / very short / no request verb) are never executed: guide returns an explicit ambiguous state with clarification questions instead of silently launching an audit (DSR-032).
   - Command: `python3 skill/scripts/audit.py guide --query "<question>" --language <lang>`

2. **`audit` Mode (Formal Audit Workflow)**:
   - For formal, evidence-backed audits on repositories.
   - Requires explicit three-root separation: target directory, skill payload, and output run directory.
   - Requires explicit RunConfig with budget limits and user safety acceptance.
   - Freezes content-addressed read-only snapshot, builds SQLite event ledger, performs Recon, Hunt, Verify, and produces a complete audit dossier with G0..G4 gates.

## 2. Safety & Sandboxing Boundaries

- **Target Code is Untrusted**: Target code is never executed. Prompt packets encapsulate target snippets inside `<untrusted_code>` boundaries to resist prompt injection.
- **Three-Root Path Isolation**: The target repository, skill payload, and run output directory must be distinct and non-overlapping. Traversal (`..`, symlink escapes) is strictly blocked.
- **No Inherent OS Sandbox**: Prompts and MCP tools provide transport isolation, not operating system sandboxes. If OS-level execution/network isolation is unverified, `safety_acceptance.user_approved: true` is strictly required before starting.

## 3. Workflow Progression & Commands

The audit CLI (`skill/scripts/audit.py`) provides full lifecycle commands:

| Command | Usage | Description |
|---|---|---|
| `doctor` | `audit doctor [--probe] [--json]` | Probes host environment, Python runtime, and CLI availability non-destructively. |
| `prepare` | `audit prepare --target <DIR> --run-dir <DIR> --config <JSON>` | Validates roots and config, freezes snapshot, plans units, and evaluates G0. |
| `run` | `audit run --run-dir <DIR> [--host claude\|codex\|session]` | Activates run and dispatches tasks. |
| `next` | `audit next --run-dir <DIR> [--batch N]` | Claims next batch of tasks with secure random token. |
| `start` | `audit start --run-dir <DIR>` (stdin credentials) | Marks claimed attempt as running. |
| `submit` | `audit submit --run-dir <DIR>` (stdin result) | Idempotently submits verified worker result. |
| `status` | `audit status --run-dir <DIR>` | Reports run state, revision, task counts, and budget status. |
| `pause` | `audit pause --run-dir <DIR> [--reason TEXT]` | Pauses dispatch safely. |
| `resume` | `audit resume --run-dir <DIR>` | Verifies snapshot and artifact integrity and restores paused run. |
| `finalize` | `audit finalize --run-dir <DIR>` | Evaluates G1..G4 gates, reconciles ledger, and publishes all reports. |
| `report` | `audit report --run-dir <DIR>` | Reads published `REPORT.md`. |
| `mcp` | `audit mcp --run-dir <DIR>` | Launches stdio MCP candidate server with 4 tools: `next`, `submit`, `status`, `read_artifact`. |
| `host-fail` | `audit host-fail --run-dir <DIR> [--task <ID>] [--retryable]` (stdin: claim + failure details) | Reports a host/worker failure for a claim: retryable failures requeue the task (generation+1); beyond the retry limit the task is quarantined with a coverage gap. |

## 4. Deliverables in Run Directory

Each formal audit run produces an isolated dossier under `<run-dir>/`:
- `config.json`: Run configuration.
- `events.db`: Append-only SQLite event ledger and task attempts.
- `snapshot/manifest.json`: Content-addressed frozen snapshot manifest.
- `report/REPORT.md`: Findings-first primary Markdown report.
- `report/findings.json`: Structured machine-readable findings.
- `report/NEEDS-VALIDATION.md`: Blockers and validation plans sorted by priority.
- `report/COVERAGE.md` & `report/coverage.csv`: Multi-dimensional line coverage.
- `report/AUDIT-TRAIL.md`: Event timeline and provenance graph.
- `report/COST.md`: Resource consumption, tasks/kLOC, and token metrics.
- `report/SKILL-REVIEW.md` & `report/skill-review.json`: Local review and sanitized export.

## 5. Troubleshooting & Diagnostics

- **`PATH_UNSAFE`**: Ensure target, skill, and run directories do not overlap and do not contain symlinks escaping the root.
- **`SNAPSHOT_INCONSISTENT`**: The target repository was modified while the snapshot was being collected. Ensure files are static and retry.
- **`BUDGET_EXHAUSTED`**: The configured budget (tasks or time) has been reached. Review partial findings in `report/NEEDS-VALIDATION.md` or increase budget.
- **`CORRUPT_RUN`**: An artifact referenced in the SQLite database was moved or modified. Run `audit resume` to inspect integrity.

## 6. Installation & Uninstallation

> **候选（CANDIDATE）— 实际支持由统一测试决定**: The host installation paths and configuration below are candidates. Which Claude Code / Codex CLI versions and combinations are actually supported is decided by unified testing (GATE-01) and recorded in `docs/RELEASE-CHECKLIST.md`. Unverified capabilities stay `unknown` and are never presented as supported.

### 6.1 Prerequisites (both hosts)

- Python >= 3.8 (candidate floor, confirmed by GATE-07 compatibility tests). Standard library only — zero third-party packages.
- Place the repository anywhere; the skill payload root is `skill/`, the CLI entry point is `skill/scripts/audit.py`.
- Three-root separation must hold: target repository, skill payload (`skill/`), and run output directory are mutually non-overlapping.
- Verify with `python3 -I skill/scripts/audit.py doctor [--probe]` (read-only, creates nothing).

### 6.2 Claude Code (candidate)

- Install: copy/link this repository into the Claude Code skills path — user-level `~/.claude/skills/polyglot-audit` or project-level `.claude/skills/polyglot-audit`; entry point `skill/SKILL.md`.
- Configuration: the host must allow spawning `python3` (for `skill/scripts/audit.py`). Claims and results are exchanged over stdin only; credentials never travel through argv.
- Probe: `python3 -I skill/scripts/audit.py doctor --host claude --probe`.

### 6.3 Codex CLI (candidate)

- Install: drive the same CLI entry point as a subprocess (`--host codex`); optionally register the MCP candidate server `audit.py mcp --run-dir <DIR>` in the Codex CLI configuration.
- Configuration: structured output, delegation, and read-only/execution/network capabilities must be probed with `doctor --probe` before use; unverified items remain `unknown` with no silent downgrade.
- Probe: `python3 -I skill/scripts/audit.py doctor --host codex --probe`.

### 6.4 Uninstall (both hosts)

1. Stop running processes (`run` driver loop, `mcp` server); interruption exits with code 130.
2. Optionally delete published run dossiers (each `<run-dir>/` contains `events.db`, `snapshot/`, `report/`).
3. Remove the skill directory from the host skills path (Claude: delete `~/.claude/skills/polyglot-audit` or the project-level copy; Codex: remove the driver/MCP entries from the CLI configuration).
4. Delete the repository. There are no global packages, caches, or registry entries to clean up.

Full step-by-step operations, diagnostics/recovery, exit-code semantics, supported-version status, known limitations, and troubleshooting: see **docs/OPERATIONS.md**.
