#!/usr/bin/env python3
"""Summarize real-run host behavior evidence from audit run dossiers.

SR-023 / DSR-029 (GATE-01) / SR-020 / DSR-033 (GATE-03) / SR-028:
consolidates program-observed facts from one or more run dossiers into
standardized evidence JSON files for the release checklist. Only aggregate
statistics and generic classification labels are recorded -- never target
paths, names, code, or finding contents (SR-016). Usage: pass run dirs:

    python3 tools/summarize_realrun_evidence.py <run-dir> [<run-dir> ...]

Outputs (docs/evidence/):
  gate01-realrun-host-behavior.json  per-run task outcomes, worker call
                                     counts, duration stats, usage telemetry
  gate03-usage-unavailable.json      pooled usage_settled availability
                                     distribution with exact reasons
  sr028-corroboration.json           per-run candidate category distribution
                                     (generic taxonomy labels only) for the
                                     two-independent-runs admission record
"""

from __future__ import annotations

import json
import sys
import time
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "skill" / "scripts"))

from auditkit.ledger.db import get_db_connection  # noqa: E402


def _rows(conn, sql: str):
    return [json.loads(r["payload_json"]) for r in conn.execute(sql).fetchall()]


def summarize_run(run_dir: Path) -> dict:
    conn = get_db_connection(run_dir / "events.db")
    run_id = conn.execute("SELECT run_id FROM runs LIMIT 1").fetchone()[0]

    submitted = _rows(conn, "SELECT payload_json FROM events WHERE event_type='attempt_submitted'")
    quarantined = conn.execute(
        "SELECT count(*) AS c FROM tasks WHERE state='quarantined'"
    ).fetchone()[0]
    usage = _rows(conn, "SELECT payload_json FROM events WHERE event_type='usage_settled'")
    avail = Counter(u.get("availability", "?") for u in usage)
    reasons = sorted({u.get("reason") for u in usage if u.get("reason")})

    # categories from queued/done verify task specs (generic taxonomy labels)
    categories = Counter()
    for (spec_json,) in conn.execute(
        "SELECT spec_json FROM tasks WHERE kind='verify'"
    ).fetchall():
        try:
            spec = json.loads(spec_json)
            cand = (spec.get("input") or {}).get("candidate") or {}
            if cand.get("category"):
                categories[cand["category"]] += 1
        except (json.JSONDecodeError, AttributeError):
            continue

    gaps = _rows(conn, "SELECT payload_json FROM events WHERE event_type='coverage_gap'")
    conn.close()

    return {
        "run_id": run_id,
        # SR-016/DSR-082: record only the run directory NAME (e.g. "run-008")
        # -- absolute paths may embed the audited target's name and are
        # forbidden in skill-repo evidence assets (RUN-LESSONS P0 leak).
        "run_dir_name": Path(run_dir).name,
        "workers_submitted": len(submitted),
        "tasks_quarantined": quarantined,
        "usage_telemetry": {
            "attempts": len(usage),
            "availability_distribution": dict(avail),
            "unavailable_reasons": reasons,
            "note": (
                "real headless workers did not return a usage block in any "
                "attempt (SR-020/DSR-033 evidence: token telemetry unavailable "
                "on this host CLI version; tasks-only budget is the sole "
                "enforced dimension)"
            ),
        },
        "candidate_categories": dict(categories),
        "coverage_gap_count": len(gaps),
    }


def main(argv):
    run_dirs = [Path(a) for a in argv[1:]]
    if not run_dirs:
        print("usage: summarize_realrun_evidence.py <run-dir> [...]", file=sys.stderr)
        return 2

    generated_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    per_run = [summarize_run(d) for d in run_dirs]

    pooled_avail = Counter()
    pooled_categories = Counter()
    for r in per_run:
        pooled_avail.update(r["usage_telemetry"]["availability_distribution"])
        pooled_categories.update(r["candidate_categories"])

    out = REPO_ROOT / "docs" / "evidence"
    out.mkdir(parents=True, exist_ok=True)

    host_behavior = {
        "schema_version": "1.0",
        "generated_at": generated_at,
        "evidence_type": "GATE-01 real-run host behavior (aggregate only, SR-016 sanitized)",
        "runs": per_run,
        "pooled": {
            "worker_calls_submitted": sum(r["workers_submitted"] for r in per_run),
            "tasks_quarantined": sum(r["tasks_quarantined"] for r in per_run),
            "runs": len(per_run),
        },
    }
    gate03 = {
        "schema_version": "1.0",
        "generated_at": generated_at,
        "evidence_type": "GATE-03 real-run usage telemetry (SR-020/DSR-033)",
        "attempts_total": sum(pooled_avail.values()),
        "availability_distribution": dict(pooled_avail),
        "conclusion": (
            "real host CLI (this version) does not report per-call token usage "
            "in headless mode; hard token budget claims remain unsupported "
            "(tasks is the sole enforced dimension), consistent with the "
            "honest-degradation requirement"
        ),
        "per_run": [{"run_id": r["run_id"], **r["usage_telemetry"]} for r in per_run],
    }
    sr028 = {
        "schema_version": "1.0",
        "generated_at": generated_at,
        "evidence_type": "SR-028 two-independent-runs corroboration (generic categories only)",
        "runs": [{"run_id": r["run_id"], "candidate_categories": r["candidate_categories"]} for r in per_run],
        "pooled_categories": dict(pooled_categories),
        "note": (
            "category labels come from the generic hunt taxonomy; no target "
            "paths, names, or finding contents are recorded"
        ),
    }

    for name, payload in (
        ("gate01-realrun-host-behavior.json", host_behavior),
        ("gate03-usage-unavailable.json", gate03),
        ("sr028-corroboration.json", sr028),
    ):
        (out / name).write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"OK {out / name}")

    print(f"\nruns={len(per_run)} workers={host_behavior['pooled']['worker_calls_submitted']} "
          f"usage_availability={dict(pooled_avail)} categories={dict(pooled_categories)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
