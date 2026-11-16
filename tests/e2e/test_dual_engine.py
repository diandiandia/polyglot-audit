"""Dual-engine fixed-response normalization equivalence (DSR-037 / SWR-022).

Acceptance design: the same synthetic case is executed by BOTH driver engines
(Claude Code CLI and Codex CLI) and their normalized results must be
equivalent. Each host is impersonated by a fixed-output fake CLI
(tests/hosts/fake_hosts.py pattern, standard library only):

- Claude walks the ``--print`` stdout JSON-extraction path: the fixed output is
  wrapped in a markdown ```` ```json ```` fence plus prose, and carries
  host-specific metadata (usage / session_id / model).
- Codex walks the ``exec`` plain-JSON path with an equivalent payload whose
  shell differences are confined to host metadata (a telemetry block).

Both payloads describe the SAME hunt task (same candidate) and the SAME verify
task (same finding). Host-only metadata is explicitly ignored during
comparison; the remaining normalized candidate/record fields must be equal.

Each engine then runs the full service lifecycle (prepare -> activate ->
next -> start -> adapter execution -> submit -> verify -> finalize); both runs
must reach the ``complete`` terminal state with structurally equivalent final
findings and identical gate outcomes.
"""

import json
import os
import re
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SKILL_SCRIPTS = REPO_ROOT / "skill" / "scripts"
HOSTS_TEST_DIR = REPO_ROOT / "tests" / "hosts"
for p in (str(SKILL_SCRIPTS), str(HOSTS_TEST_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

from auditkit.app.service import AuditAppService  # noqa: E402
from auditkit.hosts.claude_adapter import ClaudeDriverAdapter  # noqa: E402
from auditkit.hosts.codex_adapter import CodexDriverAdapter  # noqa: E402
from auditkit.ledger.task_queue import sha256_text  # noqa: E402

REPO_SKILL_DIR = REPO_ROOT / "skill"

# Host-specific metadata: engine shells may differ here WITHOUT breaking
# equivalence. This is the explicit ignore list (DSR-037).
IGNORED_HOST_METADATA_KEYS = {
    "usage",       # host telemetry shape differs per CLI
    "session_id",
    "model",
    "cost",
    "meta",        # Codex exec shell nests telemetry here
    "telemetry",
    "engine",
    "host",
    "raw_output",
}

# Volatile identity values: regenerated per run, never part of equivalence.
_VOLATILE_VALUE_RE = re.compile(r"^(task|att|run|vt|snp)-[0-9a-f]")


def normalize(obj):
    """Project a payload onto the engine-independent contract.

    Drops host-only metadata keys and canonicalizes volatile per-run identity
    values so two runs of different engines are comparable.
    """
    if isinstance(obj, dict):
        return {
            k: normalize(v)
            for k, v in sorted(obj.items())
            if k not in IGNORED_HOST_METADATA_KEYS
        }
    if isinstance(obj, list):
        return [normalize(v) for v in obj]
    if isinstance(obj, str) and _VOLATILE_VALUE_RE.match(obj):
        return "<volatile-id>"
    return obj


def write_fixed_output_cli(path: Path, stdout_text: str) -> str:
    """Create a fixed-output fake host CLI (fake_hosts.py pattern).

    A quoted heredoc keeps arbitrary JSON on stdout byte-exact, unlike shell
    echo quoting, which is fragile for double-quoted payload content.
    """
    script = (
        "#!/bin/sh\n"
        "# Auto-generated fixed-output fake host CLI (test_dual_engine.py).\n"
        "cat <<'PYAUDIT_FIXED_OUTPUT'\n"
        + stdout_text
        + "\nPYAUDIT_FIXED_OUTPUT\n"
        "exit 0\n"
    )
    path.write_text(script, encoding="utf-8")
    os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return str(path)


def assemble_worker_result(parsed, claim):
    """Wire an adapter's parsed output into a schema-valid worker_result.

    Host-only metadata keys never cross the contract boundary; the claim
    supplies the task/attempt identity.
    """
    return {
        "schema_version": parsed["schema_version"],
        "task_id": claim["task_id"],
        "attempt_id": claim["attempt_id"],
        "kind": parsed["kind"],
        "coverage": parsed.get("coverage", []),
        "records": parsed.get("records", []),
        "overflow": parsed.get("overflow", []),
    }


# --------------------------------------------------------------------- payloads
# One synthetic case: python request body reaching an unvalidated persist sink.
HUNT_RECORD = {
    "schema_version": "1.0",
    "candidate_id": "cand-dual-01",
    "issue": "py-01",
    "source": {"path": "app/handlers/upload.py", "line": 4, "symbol": "handle_upload", "kind": "http_body", "control": "request_data body field", "lang": "python"},
    "sink": {"path": "app/storage/state.py", "line": 4, "symbol": "restore_state", "kind": "deserialization", "effect": "unvalidated payload restored"},
    "steps": [
        {"path": "app/handlers/upload.py", "line": 4, "role": "source", "note": "raw request body read"},
        {"path": "app/storage/state.py", "line": 4, "role": "sink", "note": "restore_state without validation"},
    ],
    "guard_analysis": "No input validation on the upload path",
    "impact_claim": "Unvalidated payload persistence",
    "open_questions": [],
    "provenance": {"hunt_tasks": ["__CLAIM_TASK__"]},
}

VERIFY_RECORD = {
    "schema_version": "1.0",
    "finding_id": "F-DUAL-001",
    "candidate_refs": ["cand-dual-01"],
    "verdict": "confirmed",
    "evidence_level": "E2",
    "provenance": {
        "hunt_tasks": ["__HUNT_TASK__"],
        "verify_tasks": ["__VERIFY_TASK__"],
        "verify_attempt_id": "__VERIFY_ATTEMPT__",
    },
    "title": "Unvalidated request body persisted",
    "issue": "py-01",
    "languages": ["python"],
    "source": HUNT_RECORD["source"],
    "sink": HUNT_RECORD["sink"],
    "steps": HUNT_RECORD["steps"],
    "guards": [],
    "attacker": "remote_unauth",
    "preconditions": ["Default configuration"],
    "rating": {
        "schema_version": "1.0",
        "impact": 3,
        "exploitability": 3,
        "factor_reasons": {"impact_why": "Sensitive payload persisted", "exploitability_why": "Remote unauthenticated input"},
        "calculated_severity": "High",
        "calculated_urgency": "P1",
        "final_severity": "High",
        "final_urgency": "P1",
    },
    "remediation": {
        "where": "app/storage/state.py:4",
        "change": "Validate payload shape before persisting",
        "regression_test": "Reject malformed payloads",
    },
}


def hunt_payload(kind_shell):
    """Fixed hunt output; `kind_shell` carries only host-shell differences."""
    payload = {
        "schema_version": "1.0",
        "kind": "hunt",
        "coverage": [{
            "schema_version": "1.0",
            "snapshot_id": "__SNAPSHOT__",
            "unit_id": "__UNIT__",
            "dimension": "observed_read",
            "source": "worker",
            "ranges": [{"path": "app/handlers/upload.py", "line_start": 1, "line_end": 7}],
            "confidence": "exact",
        }],
        "records": [dict(HUNT_RECORD)],
        "overflow": [],
    }
    payload.update(kind_shell)
    return payload


VERIFY_PAYLOAD = {
    "schema_version": "1.0",
    "kind": "verify",
    "coverage": [],
    "records": [dict(VERIFY_RECORD)],
    "overflow": [],
}


class TestDualEngineEquivalence(unittest.TestCase):
    """DSR-037 / SWR-022: both driver engines produce equivalent results."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="dual-engine-"))
        self.bin_dir = self.temp_dir / "bin"
        self.bin_dir.mkdir()

        # Claude: --print JSON extraction path (markdown fence + prose shell).
        claude_hunt_shell = {
            "usage": {"input_tokens": 120, "output_tokens": 40},
            "session_id": "sess-claude-fixed",
            "model": "claude-fixed",
        }
        claude_verify_shell = {"usage": {"input_tokens": 90, "output_tokens": 30}}
        claude_hunt_line = (
            "audit result: ```json"
            + json.dumps(hunt_payload(claude_hunt_shell), ensure_ascii=False)
            + "``` end of result"
        )
        claude_verify_line = (
            "audit result: ```json"
            + json.dumps(VERIFY_PAYLOAD, ensure_ascii=False)
            + "``` end of result"
        )
        self.claude_hunt_bin = write_fixed_output_cli(
            self.bin_dir / "claude-hunt", claude_hunt_line
        )
        self.claude_verify_bin = write_fixed_output_cli(
            self.bin_dir / "claude-verify", claude_verify_line
        )

        # Codex: exec plain-JSON path; telemetry nested under meta.
        codex_hunt_shell = {"meta": {"telemetry": {"engine": "codex-fixed"}}}
        codex_hunt_line = json.dumps(hunt_payload(codex_hunt_shell), ensure_ascii=False)
        codex_verify_line = json.dumps(VERIFY_PAYLOAD, ensure_ascii=False)
        self.codex_hunt_bin = write_fixed_output_cli(
            self.bin_dir / "codex-hunt", codex_hunt_line
        )
        self.codex_verify_bin = write_fixed_output_cli(
            self.bin_dir / "codex-verify", codex_verify_line
        )

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # ------------------------------------------------------------- engine run
    def _make_config(self, target_dir: Path, run_dir: Path) -> dict:
        return {
            "schema_version": "1.0",
            "target": str(target_dir),
            "run_dir": str(run_dir),
            "report_language": "en",
            "profile": "standard",
            "scope": {"include": ["*.py"], "exclude": []},
            "budgets": [{
                "schema_version": "1.0",
                "dimension": "tasks",
                "mode": "enforced",
                "limit": 20,
                "settled": 0,
                "reserved": 0,
                "unit": "tasks",
                "availability": "exact",
            }],
            "safety_acceptance": {
                "allow_unverified_execution": False,
                "allow_unverified_network": False,
                "allow_unverified_write": False,
                "user_approved": True,
            },
        }

    def _run_engine(self, engine: str, index: int) -> dict:
        """Full lifecycle for one engine; returns run facts and normalized artifacts."""
        target_dir = self.temp_dir / f"target-{engine}"
        fixture_app = REPO_ROOT / "tests" / "fixtures" / "pyapp" / "app"
        shutil.copytree(fixture_app, target_dir / "app")

        if engine == "claude":
            adapter = ClaudeDriverAdapter(claude_binary=str(self.claude_hunt_bin), timeout_seconds=30)
            verify_adapter = ClaudeDriverAdapter(claude_binary=str(self.claude_verify_bin), timeout_seconds=30)
        else:
            adapter = CodexDriverAdapter(codex_binary=str(self.codex_hunt_bin), timeout_seconds=30)
            verify_adapter = CodexDriverAdapter(codex_binary=str(self.codex_verify_bin), timeout_seconds=30)

        app = AuditAppService(REPO_SKILL_DIR)
        run_dir = self.temp_dir / f"run-{engine}"
        prep = app.prepare(str(target_dir), str(run_dir), self._make_config(target_dir, run_dir))
        run_id = prep["run_id"]
        app.activate(run_id, run_dir)

        normalized_hunt_results = []
        # --- hunt pass through the engine adapter -------------------------
        hunt_task_ids = []
        claims = app.next(run_id, run_dir, batch_size=50)
        self.assertTrue(claims, f"{engine}: no hunt tasks dispatched")
        for claim in claims:
            app.start(run_dir, claim)
            parsed, hunt_usage = adapter.execute_worker(
                prompt=f"hunt {claim['task_id']}",
                task_id=claim["task_id"],
                attempt_id=claim["attempt_id"],
            )
            # The adapter output may carry host metadata; it must not enter
            # the contract boundary.
            worker_result = assemble_worker_result(parsed, claim)
            worker_result["coverage"][0]["snapshot_id"] = prep["snapshot_id"]
            worker_result["coverage"][0]["unit_id"] = claim["spec"]["unit"]["unit_id"]
            worker_result["records"][0]["provenance"]["hunt_tasks"] = [claim["task_id"]]
            digest = sha256_text(json.dumps(worker_result, sort_keys=True, ensure_ascii=False))
            app.submit(run_dir, claim, worker_result, digest)
            hunt_task_ids.append(claim["task_id"])
            normalized_hunt_results.append(normalize(worker_result))

        # --- verify pass through the same engine --------------------------
        normalized_verify_results = []
        while True:
            claims = app.next(run_id, run_dir, batch_size=50)
            if not claims:
                break
            for claim in claims:
                app.start(run_dir, claim)
                parsed, _verify_usage = verify_adapter.execute_worker(
                    prompt=f"verify {claim['task_id']}",
                    task_id=claim["task_id"],
                    attempt_id=claim["attempt_id"],
                )
                worker_result = assemble_worker_result(parsed, claim)
                rec = worker_result["records"][0]
                rec["provenance"]["hunt_tasks"] = list(hunt_task_ids)
                rec["provenance"]["verify_tasks"] = [claim["task_id"]]
                rec["provenance"]["verify_attempt_id"] = claim["attempt_id"]
                digest = sha256_text(json.dumps(worker_result, sort_keys=True, ensure_ascii=False))
                app.submit(run_dir, claim, worker_result, digest)
                normalized_verify_results.append(normalize(worker_result))

        fin = app.finalize(run_id, run_dir)
        status = app.status(run_id, run_dir)

        findings = []
        for vf_path in sorted(run_dir.glob("findings/verified-*.json")):
            findings.extend(json.loads(vf_path.read_text(encoding="utf-8")))

        return {
            "engine": engine,
            "run_id": run_id,
            "snapshot_id": prep["snapshot_id"],
            "finalize": fin,
            "status": status,
            "hunt_usage": hunt_usage,
            "normalized_hunt": normalized_hunt_results,
            "normalized_verify": normalized_verify_results,
            "findings": [normalize(f) for f in findings],
        }

    # ---------------------------------------------------------------- tests
    def test_dual_engine_normalized_equivalence(self):
        facts = {e: self._run_engine(e, i) for i, e in enumerate(("claude", "codex"))}
        claude, codex = facts["claude"], facts["codex"]

        # 1. Normalized hunt results are equivalent: candidate fields equal
        #    after ignoring host-specific metadata (explicit ignore list).
        self.assertEqual(claude["normalized_hunt"], codex["normalized_hunt"])
        self.assertEqual(claude["normalized_verify"], codex["normalized_verify"])

        # Sanity: the host shells genuinely differ (Claude reports usage from
        # its --print JSON, the Codex shell carries none), so the equality
        # assertions above are meaningful.
        self.assertIsNotNone(claude["hunt_usage"])
        self.assertIsNone(codex["hunt_usage"])

        # 2. Both runs reach the same terminal contract: complete.
        self.assertEqual(claude["finalize"]["final_state"], "complete")
        self.assertEqual(codex["finalize"]["final_state"], "complete")
        self.assertEqual(claude["status"]["state"], "complete")
        self.assertEqual(codex["status"]["state"], "complete")

        # 3. Gate outcomes identical across engines.
        self.assertEqual(claude["finalize"]["gates"], codex["finalize"]["gates"])
        self.assertEqual(claude["finalize"]["gates"], {
            "G1": "pass", "G2": "pass", "G3": "pass", "G4": "pass",
        })

        # 4. Final findings structures are equivalent (modulo volatile ids and
        #    the per-run run_id stamp).
        self.assertEqual(len(claude["findings"]), 1)
        self.assertEqual(claude["findings"], codex["findings"])
        finding = claude["findings"][0]
        self.assertEqual(finding["verdict"], "confirmed")
        self.assertEqual(finding["evidence_level"], "E2")
        self.assertEqual(finding["candidate_refs"], ["cand-dual-01"])
        self.assertEqual(finding["rating"]["final_severity"], "High")
        self.assertEqual(finding["run_id"], "<volatile-id>")

        # 5. Same synthetic target: content-addressed snapshot identity is
        #    equal, yet each run generated its own dossier independently.
        self.assertEqual(claude["snapshot_id"], codex["snapshot_id"])
        self.assertNotEqual(claude["run_id"], codex["run_id"])


if __name__ == "__main__":
    unittest.main()
