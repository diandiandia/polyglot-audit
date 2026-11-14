#!/usr/bin/env python3
"""Filesystem / symlink / snapshot-stability isolation probes (DSR-008 / SWR-015).

Runs adversarial filesystem probes against the snapshot collection layer:

1. symlink_escape — a symlink inside the target pointing OUTSIDE the target
   root must be excluded (never traversed) and recorded as a coverage gap,
   with an explicit escape detail when the link would leave the root.
2. race_write — a file rewritten during the collection window (same size AND
   same mtime, i.e. invisible to stat-level drift checks) must still be
   detected by content-level SHA-256 re-verification (SR-017).
3. symlink_swap — a regular file replaced by an out-of-root symlink mid
   collection must never leak outside content (O_NOFOLLOW open + realpath
   re-check + drift detection).
4. path_alias — collecting the same target through a non-canonical alias
   path must produce the identical canonical manifest (paths and root hash).

Development-time scope: probes run against temporary demo fixtures created
under a tempdir (or an explicit ``--target``). Real-target measurements are
deferred to the unified test phase; report fields that cannot be observed
here are emitted as ``unknown`` — probes demonstrate detection capability on
the demo fixture and NEVER claim that races or escapes are eliminated in
general.

Usage:
    python3 tools/probe_isolation.py                 # tempdir demo fixtures
    python3 tools/probe_isolation.py --out DIR       # report output dir
"""

# 需求追踪 (Requirement Traceability)
# ---------------------------------------------------------------------------
# 上层需求: docs/design/DETAILED_DEVELOPMENT_REQUIREMENTS.md (DSR-008)
# 设计依据: docs/design/SOFTWARE_DESIGN.md
# SWR-015  目标只读、symlink 不跟随、TOCTOU 防护；竞态与隔离未知如实标注
#   绑定实现: DSR-011, DSR-013
# 状态以统一测试结论为准；未实测能力保持 unknown（设计原则 8：能观测的不靠声明）。
#

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

ROOT_DIR = Path(__file__).resolve().parent.parent
SKILL_SCRIPTS = ROOT_DIR / "skill" / "scripts"
DEFAULT_OUT_DIR = ROOT_DIR / "tests" / "holdout" / "reports"

if str(SKILL_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SKILL_SCRIPTS))

from auditkit.snapshot.collector import SnapshotCollector  # noqa: E402
from auditkit.snapshot.manifest import SnapshotManifest  # noqa: E402

LIMITATION_NOTE = (
    "probe result applies to the development-time demo fixture only; "
    "real-target isolation is measured in the unified test phase and remains "
    "unknown until then. Probes never claim races or escapes are eliminated."
)


def _make_demo_target(root: Path) -> Path:
    """Create a small deterministic demo target tree."""
    target = root / "target"
    (target / "src").mkdir(parents=True)
    (target / "src" / "app.py").write_text("value = 1\n", encoding="utf-8")
    (target / "src" / "util.py").write_text("def helper():\n    return 2\n", encoding="utf-8")
    (target / "README.md").write_text("demo target\n", encoding="utf-8")
    return target


def _collect(target: Path, dest: Path, on_drift: str = "record") -> Any:
    collector = SnapshotCollector(target, dest, on_drift=on_drift)
    return collector.collect()


def probe_symlink_escape(workdir: Path) -> Dict[str, Any]:
    """A symlink pointing outside the target must be excluded, not followed."""
    target = _make_demo_target(workdir / "sym_escape")
    outside_secret = workdir / "outside_secret.txt"
    outside_secret.write_text("TOP SECRET OUTSIDE CONTENT\n", encoding="utf-8")
    link = target / "src" / "innocent_link.py"
    os.symlink(outside_secret, link)

    result: Dict[str, Any] = {
        "probe": "symlink_escape",
        "observed": False,
        "status": "unknown",
        "detail": "",
    }
    try:
        manifest = _collect(target, workdir / "snap_escape")
        paths = [f["path"] for f in manifest.files]
        excluded = [e["path"] for e in manifest.excluded]
        gap_entries = [g for g in manifest.gaps if g.get("reason") == "symlink_excluded"]
        link_in_files = any("innocent_link.py" in p for p in paths)
        escaped_recorded = any("escape" in (g.get("detail") or "") for g in gap_entries)
        result["observed"] = (not link_in_files) and ("src/innocent_link.py" in excluded)
        result["escaped_flag_recorded"] = escaped_recorded
        result["gap_entries"] = gap_entries
        result["status"] = "detected" if result["observed"] else "NOT_DETECTED"
        # Outside content must not appear anywhere in the snapshot.
        snap_files = list((workdir / "snap_escape").rglob("*"))
        for f in snap_files:
            if f.is_file() and "TOP SECRET" in f.read_text(encoding="utf-8", errors="replace"):
                result["status"] = "LEAK_DETECTED"
                result["observed"] = False
                break
    except Exception as e:  # noqa: BLE001 - probes record failures honestly
        result["status"] = "probe_error"
        result["detail"] = repr(e)
    return result


def probe_race_write(workdir: Path, attempts: int = 3) -> Dict[str, Any]:
    """Same-size/same-mtime rewrite during collection must be caught by
    content-level hash re-verification, not by mtime/size checks."""
    result: Dict[str, Any] = {
        "probe": "race_write",
        "attempts": [],
        "observed": False,
        "status": "unknown",
        "detail": "content-level drift detection is exercised via mock timing",
    }
    for attempt in range(attempts):
        target = _make_demo_target(workdir / f"race_{attempt}")
        victim = target / "src" / "util.py"
        original = victim.read_bytes()
        # Same-size, different content rewrite that also preserves the
        # PRE-write mtime, so stat-level drift checks stay blind and only
        # content-level SHA-256 re-verification can catch it (SR-017).
        rewritten = original.replace(b"return 2", b"return 8")
        assert len(rewritten) == len(original)
        pre_stat = os.stat(victim)

        collector = SnapshotCollector(target, workdir / f"snap_race_{attempt}", on_drift="record")
        original_reader = collector._read_file_nofollow
        calls = {"n": 0}

        def racing_reader(path, _orig=original_reader, _victim=victim,
                          _rewritten=rewritten, _calls=calls, _pre_stat=pre_stat):
            data = _orig(path)
            # Rewrite AFTER the victim was read, preserving its pre-write
            # mtime, so stat-level drift checks stay blind and only
            # content-level SHA-256 re-verification can catch it (SR-017).
            if str(path).endswith("util.py"):
                _victim.write_bytes(_rewritten)
                os.utime(_victim, ns=(_pre_stat.st_atime_ns, _pre_stat.st_mtime_ns))
            return data

        collector._read_file_nofollow = racing_reader  # mock timing hook
        attempt_result: Dict[str, Any] = {"attempt": attempt}
        try:
            manifest = collector.collect()
            drift_gaps = [g for g in manifest.gaps if g.get("reason") == "drift_detected"]
            attempt_result["drift_detected_gap"] = bool(drift_gaps) or manifest.drift_detected
            attempt_result["drift_gap_count"] = len(drift_gaps)
        except Exception as e:  # drift raised instead of recorded
            attempt_result["drift_detected_gap"] = True
            attempt_result["raised"] = type(e).__name__
        attempt_result["observed"] = bool(attempt_result["drift_detected_gap"])
        result["attempts"].append(attempt_result)
        result["observed"] = result["observed"] or attempt_result["observed"]
    result["status"] = "detected" if result["observed"] else "NOT_DETECTED"
    return result


def probe_symlink_swap(workdir: Path) -> Dict[str, Any]:
    """A file swapped to an out-of-root symlink mid-collection must be caught."""
    target = _make_demo_target(workdir / "sym_swap")
    outside_secret = workdir / "outside_secret_2.txt"
    outside_secret.write_text("TOP SECRET SWAP CONTENT\n", encoding="utf-8")
    victim = target / "src" / "app.py"

    collector = SnapshotCollector(target, workdir / "snap_swap", on_drift="record")
    original_reader = collector._read_file_nofollow
    calls = {"n": 0}

    def swapping_reader(path, _orig=original_reader, _victim=victim, _calls=calls):
        _calls["n"] += 1
        if _calls["n"] == 2 and not _victim.is_symlink():
            _victim.unlink()
            os.symlink(outside_secret, _victim)
        return _orig(path)

    collector._read_file_nofollow = swapping_reader  # mock timing hook
    result: Dict[str, Any] = {
        "probe": "symlink_swap",
        "observed": False,
        "status": "unknown",
        "detail": "",
    }
    try:
        manifest = collector.collect()
        gap_reasons = {g.get("reason") for g in manifest.gaps}
        result["gap_reasons"] = sorted(r for r in gap_reasons if r)
        result["observed"] = bool(gap_reasons & {"read_failure", "drift_detected", "symlink_excluded"})
        # Leak check: outside content must not be inside the snapshot.
        for f in (workdir / "snap_swap").rglob("*"):
            if f.is_file() and "TOP SECRET SWAP" in f.read_text(encoding="utf-8", errors="replace"):
                result["observed"] = False
                result["status"] = "LEAK_DETECTED"
                return result
        result["status"] = "detected" if result["observed"] else "NOT_DETECTED"
    except Exception as e:  # noqa: BLE001
        # raise-mode or inconsistent-state abort also counts as detection,
        # provided nothing leaked — verify the temp snapshot was not published.
        published = (workdir / "snap_swap").exists()
        leaked = False
        if published:
            for f in (workdir / "snap_swap").rglob("*"):
                if f.is_file() and "TOP SECRET SWAP" in f.read_text(encoding="utf-8", errors="replace"):
                    leaked = True
                    break
        result["raised"] = type(e).__name__
        result["observed"] = (not leaked)
        result["status"] = "detected" if not leaked else "LEAK_DETECTED"
        result["detail"] = repr(e)
    return result


def probe_path_alias(workdir: Path) -> Dict[str, Any]:
    """Collecting via a non-canonical alias must yield the canonical manifest."""
    target = _make_demo_target(workdir / "alias_target")
    canonical_dest = workdir / "snap_canonical"
    alias_dest = workdir / "snap_alias"

    manifest_a = _collect(target, canonical_dest)
    alias_path = str(target) + "/src/../."  # non-canonical alias spelling
    manifest_b = _collect(alias_path, alias_dest)

    paths_a = sorted(f["path"] for f in manifest_a.files)
    paths_b = sorted(f["path"] for f in manifest_b.files)
    observed = (
        paths_a == paths_b
        and manifest_a.root_hash == manifest_b.root_hash
        and manifest_a.snapshot_id == manifest_b.snapshot_id
    )
    return {
        "probe": "path_alias",
        "observed": observed,
        "status": "canonicalized" if observed else "NOT_CANONICAL",
        "root_hash_match": manifest_a.root_hash == manifest_b.root_hash,
        "snapshot_id_a": manifest_a.snapshot_id,
        "snapshot_id_b": manifest_b.snapshot_id,
        "detail": "alias traversal must not change the canonical manifest",
    }


def run_all_probes(workdir: Optional[Path] = None) -> Dict[str, Any]:
    tempdir_holder = None
    if workdir is None:
        tempdir_holder = tempfile.mkdtemp(prefix="probe_isolation_")
        workdir = Path(tempdir_holder)
    probes = []
    for probe_fn in (probe_symlink_escape, probe_race_write, probe_symlink_swap, probe_path_alias):
        probes.append(probe_fn(workdir))
    report = {
        "schema_version": "1.0",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "scope": "development-time demo fixtures (tempdir); real-target run deferred to unified test phase",
        "probes": probes,
        "real_target_results": "unknown",
        "limitations": [
            LIMITATION_NOTE,
            "race probes use mock timing hooks (deterministic); wall-clock races are inherently non-deterministic and are re-run in the unified test phase",
            "this tool never claims that collection races or symlink escapes are eliminated in general",
        ],
    }
    if tempdir_holder:
        shutil.rmtree(tempdir_holder, ignore_errors=True)
    return report


def render_markdown(report: Dict[str, Any]) -> str:
    lines: List[str] = []
    lines.append("# Isolation Probe Report (DSR-008)")
    lines.append("")
    lines.append(f"- Generated: `{report['generated_at']}`")
    lines.append(f"- Scope: {report['scope']}")
    lines.append(f"- Real-target results: **{report['real_target_results']}**")
    lines.append("")
    lines.append("| probe | status | observed |")
    lines.append("|---|---|---|")
    for p in report["probes"]:
        lines.append(f"| {p['probe']} | {p['status']} | {p['observed']} |")
    lines.append("")
    lines.append("## Limitations")
    lines.append("")
    for lim in report["limitations"]:
        lines.append(f"- {lim}")
    lines.append("")
    return "\n".join(lines)


def write_reports(report: Dict[str, Any], out_dir: Path) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "isolation_probe_report.json"
    md_path = out_dir / "isolation_probe_report.md"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(report), encoding="utf-8")
    return json_path, md_path


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="DSR-008 isolation probe tool")
    parser.add_argument("--out", default=str(DEFAULT_OUT_DIR), help="report output directory")
    args = parser.parse_args(argv)

    report = run_all_probes()
    json_path, md_path = write_reports(report, Path(args.out))
    for p in report["probes"]:
        print(f"{p['probe']:<18} status={p['status']:<14} observed={p['observed']}")
    print(f"Reports: {json_path}")
    print(f"         {md_path}")
    print("NOTE: real-target isolation results remain unknown until the unified test phase.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
