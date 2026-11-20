"""Irreversibly pseudonymize run identifiers in evidence JSON (delivery prep).

Evidence files (docs/evidence/*.json) carry real run identifiers -- e.g.
``"run-7e0205c7"``-style run ids, ``"run-008"``-style run directory names and
``"ev-..."`` evidence generation ids. They contain no target source code, but
before open-sourcing the repository or handing a dossier to a third party the
identifiers are replaced with salted hashes:

- **Irreversible**: the hash is keyed with a per-invocation random salt and NO
  mapping is written anywhere -- the original ids cannot be recovered from the
  output.
- **Stable within one export**: the same identifier always maps to the same
  pseudonym across all files of one invocation, so cross-file references
  (per-run evidence rows, corroboration records) stay consistent.
- **Scoped**: only ``run-*`` / ``ev-*`` tokens inside string values are
  rewritten; field names, numbers and prose that contains no identifier pass
  through verbatim.

Usage:
    python3 tools/anonymize_evidence.py --src docs/evidence --dst dist/evidence-portable

Standard library only. Requirements: SR-031(运行侧数据单向流动,支持) / DSR-082(泄漏检查,支持)。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

_RUN_ID_RE = re.compile(r"\b(run|ev)-([0-9a-zA-Z]{3,})\b")
_PSEUDONYM_LEN = 12


def _pseudonymize_string(value: str, salt: str) -> tuple[str, int]:
    """Rewrite every run/ev identifier in the string; return (new, count)."""
    count = 0

    def _sub(match: re.Match[str]) -> str:
        nonlocal count
        count += 1
        digest = hashlib.sha256(f"{salt}:{match.group(0)}".encode("utf-8")).hexdigest()
        return f"{match.group(1)}-{digest[:_PSEUDONYM_LEN]}"

    return _RUN_ID_RE.sub(_sub, value), count


def _pseudonymize_node(node: Any, salt: str) -> tuple[Any, int]:
    """Walk a JSON structure; every string value gets identifier rewriting."""
    if isinstance(node, str):
        return _pseudonymize_string(node, salt)
    if isinstance(node, dict):
        replaced = 0
        out: dict = {}
        for key, value in node.items():
            new_value, n = _pseudonymize_node(value, salt)
            out[key] = new_value
            replaced += n
        return out, replaced
    if isinstance(node, list):
        out_list: list = []
        replaced = 0
        for item in node:
            new_item, n = _pseudonymize_node(item, salt)
            out_list.append(new_item)
            replaced += n
        return out_list, replaced
    return node, 0


def anonymize_evidence_dir(src: Path, dst: Path, salt: str) -> list[dict]:
    """Pseudonymize every ``*.json`` under ``src`` into ``dst``.

    Non-JSON files are copied verbatim. The mapping is never written:
    each pseudonym is ``sha256(salt + ":" + original)[:12]`` keyed by a
    caller-supplied random salt, so the output is irreversible by
    construction.
    """
    dst.mkdir(parents=True, exist_ok=True)
    report: list[dict] = []
    for path in sorted(src.rglob("*")):
        if path.is_dir():
            continue
        rel = path.relative_to(src)
        target = dst / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        if path.suffix != ".json":
            target.write_bytes(path.read_bytes())
            report.append({"file": str(rel), "replacements": 0, "copied_verbatim": True})
            continue
        payload = json.loads(path.read_text(encoding="utf-8"))
        new_payload, replaced = _pseudonymize_node(payload, salt)
        target.write_text(
            json.dumps(new_payload, indent=2, ensure_ascii=False, sort_keys=False) + "\n",
            encoding="utf-8",
        )
        report.append({"file": str(rel), "replacements": replaced})
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Irreversibly pseudonymize run identifiers in evidence JSON (delivery prep)"
    )
    parser.add_argument("--src", default="docs/evidence", help="evidence source directory")
    parser.add_argument("--dst", required=True, help="portable output directory (new)")
    args = parser.parse_args(argv)

    src = Path(args.src)
    if not src.is_dir():
        parser.error(f"source directory not found: {src}")
    if Path(args.dst).resolve() == src.resolve():
        parser.error("--dst must differ from --src (in-place anonymization is not supported)")

    # Per-invocation random salt: two exports of the same evidence produce
    # different pseudonyms by design -- the output must not be correlatable
    # across deliveries either.
    salt = os.urandom(16).hex()
    report = anonymize_evidence_dir(src, Path(args.dst), salt)
    total = sum(r["replacements"] for r in report)
    print(f"Anonymized evidence: {args.src} -> {args.dst}")
    for row in report:
        state = "verbatim" if row.get("copied_verbatim") else f"{row['replacements']} identifier(s)"
        print(f"  {row['file']}: {state}")
    print(f"Total identifiers pseudonymized: {total} (no mapping written; irreversible)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
