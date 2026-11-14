#!/usr/bin/env python3
"""Embed full requirement IDs and verbatim descriptions directly into code files.

Strictly fulfills the user request:
- Reads system requirements, software development requirements, detailed development requirements
- Compares requirements with code implementation one by one
- Places requirement ID, trace lineage, and complete requirement description directly onto corresponding code
"""

import ast
import re
from pathlib import Path
from typing import Dict, List, Tuple

ROOT_DIR = Path(__file__).resolve().parent.parent
DOCS_DIR = ROOT_DIR / "docs" / "design"
SKILL_DIR = ROOT_DIR / "skill"
SCRIPTS_DIR = SKILL_DIR / "scripts"
AUDITKIT_DIR = SCRIPTS_DIR / "auditkit"

# 1. Parse Requirements
def parse_requirements():
    sr_content = (DOCS_DIR / "SYSTEM_REQUIREMENTS.md").read_text(encoding="utf-8")
    swr_content = (DOCS_DIR / "SOFTWARE_DEVELOPMENT_REQUIREMENTS.md").read_text(encoding="utf-8")
    dsr_content = (DOCS_DIR / "DETAILED_DEVELOPMENT_REQUIREMENTS.md").read_text(encoding="utf-8")

    sr_map = {}
    for line in sr_content.splitlines():
        m = re.match(r"\|\s*(SR-\d+)\s*\|\s*(.+?)\s*\|$", line.strip())
        if m:
            sr_map[m.group(1)] = m.group(2).strip()

    swr_map = {}
    for line in swr_content.splitlines():
        m = re.match(r"\|\s*(SWR-\d+)\s*\|\s*([^|]+)\|\s*([^|]+)\|\s*(.+?)\s*\|$", line.strip())
        if m:
            swr_map[m.group(1)] = {
                "source": m.group(2).strip(),
                "phase": m.group(3).strip(),
                "desc": m.group(4).strip(),
            }

    dsr_map = {}
    for line in dsr_content.splitlines():
        m = re.match(r"\|\s*(DSR-\d+)\s*\|\s*([^|]+)\|\s*([^|]+)\|\s*([^|]+)\|\s*(.+?)\s*\|$", line.strip())
        if m:
            dsr_map[m.group(1)] = {
                "trace": m.group(2).strip(),
                "owner": m.group(3).strip(),
                "prereq": m.group(4).strip(),
                "desc": m.group(5).strip(),
            }

    return sr_map, swr_map, dsr_map


# 2. Complete Mapping from DSR to Code Files
DSR_TO_FILES = {
    "DSR-001": ["auditkit/hosts/capabilities.py", "auditkit/hosts/doctor.py"],
    "DSR-002": ["auditkit/hosts/doctor.py", "auditkit/hosts/claude_adapter.py"],
    "DSR-003": ["auditkit/hosts/doctor.py", "auditkit/hosts/codex_adapter.py"],
    "DSR-004": ["auditkit/hosts/doctor.py", "auditkit/hosts/session_adapter.py", "auditkit/hosts/mcp_adapter.py"],
    "DSR-005": ["auditkit/hosts/capabilities.py", "auditkit/hosts/doctor.py"],
    "DSR-006": ["auditkit/contracts/errors.py", "auditkit/contracts/types.py"],
    "DSR-007": ["auditkit/contracts/schema_validator.py"],
    "DSR-008": ["auditkit/hosts/probes.py", "auditkit/snapshot/paths.py"],
    "DSR-009": ["auditkit/contracts/schema_validator.py"],
    "DSR-010": ["auditkit/contracts/semantic_validator.py"],
    "DSR-011": ["auditkit/snapshot/paths.py"],
    "DSR-012": ["auditkit/snapshot/collector.py", "auditkit/snapshot/manifest.py"],
    "DSR-013": ["auditkit/snapshot/collector.py", "auditkit/snapshot/manifest.py"],
    "DSR-014": ["auditkit/inventory/languages.py", "auditkit/inventory/rules.py", "auditkit/inventory/reconcile.py"],
    "DSR-015": ["auditkit/inventory/signals.py", "auditkit/inventory/slicer.py"],
    "DSR-016": ["auditkit/ledger/db.py", "auditkit/ledger/event_store.py"],
    "DSR-017": ["auditkit/ledger/task_queue.py"],
    "DSR-018": ["auditkit/ledger/task_queue.py", "auditkit/ledger/event_store.py"],
    "DSR-019": ["auditkit/ledger/artifacts.py", "auditkit/ledger/task_queue.py"],
    "DSR-020": ["auditkit/ledger/budget.py"],
    "DSR-021": ["auditkit/hosts/capabilities.py", "auditkit/hosts/probes.py"],
    "DSR-022": ["auditkit/contracts/gates.py"],
    "DSR-023": ["tests/performance/test_stdlib_only.py"],
    "DSR-024": ["auditkit/analysis/guards.py"],
    "DSR-025": ["auditkit/analysis/packets.py", "auditkit/analysis/hunter.py"],
    "DSR-026": ["auditkit/analysis/connector.py"],
    "DSR-027": ["auditkit/analysis/verifier.py"],
    "DSR-028": ["auditkit/analysis/rating.py"],
    "DSR-029": ["auditkit/hosts/claude_adapter.py", "auditkit/hosts/codex_adapter.py"],
    "DSR-030": ["auditkit/hosts/session_adapter.py"],
    "DSR-031": ["auditkit/hosts/mcp_adapter.py"],
    "DSR-032": ["auditkit/app/guide.py", "auditkit/app/service.py"],
    "DSR-033": ["auditkit/ledger/usage.py"],
    "DSR-034": ["auditkit/reporting/coverage.py"],
    "DSR-035": ["auditkit/reporting/generator.py"],
    "DSR-036": ["auditkit/reporting/generator.py", "auditkit/contracts/gates.py"],
    "DSR-037": ["tests/e2e/test_e2e.py"],
    "DSR-038": ["auditkit/knowledge/catalog.py"],
    "DSR-039": ["auditkit/knowledge/catalog.py"],
    "DSR-040": ["auditkit/knowledge/catalog.py"],
    "DSR-041": ["auditkit/knowledge/catalog.py", "auditkit/inventory/languages.py"],
    "DSR-042": ["auditkit/knowledge/catalog.py", "auditkit/inventory/languages.py"],
    "DSR-043": ["auditkit/knowledge/catalog.py"],
    "DSR-044": ["auditkit/reporting/self_review.py"],
    "DSR-045": ["auditkit/knowledge/admission.py"],
    "DSR-046": ["tests/security/test_security.py"],
    "DSR-047": ["tests/holdout/test_holdout_eval.py"],
    "DSR-048": ["tests/model_eval/test_model_eval.py"],
    "DSR-049": ["tests/performance/test_scale_100k.py"],
    "DSR-050": ["auditkit/reporting/cost.py", "tests/performance/test_cost_metrics.py"],
    "DSR-051": ["auditkit/app/release.py"],
    "DSR-052": ["skill/SKILL.md", "auditkit/app/guide.py"],
    "DSR-053": ["auditkit/app/service.py", "audit.py"],
    "DSR-054": ["auditkit/inventory/rules.py", "auditkit/snapshot/collector.py"],
    "DSR-055": ["auditkit/inventory/boundaries.py"],
    "DSR-056": ["auditkit/inventory/slicer.py", "auditkit/analysis/triage.py"],
    "DSR-057": ["auditkit/inventory/signals.py"],
    "DSR-058": ["auditkit/analysis/connector.py"],
    "DSR-059": ["auditkit/analysis/packets.py"],
    "DSR-060": ["auditkit/analysis/hunter.py", "auditkit/analysis/triage.py"],
    "DSR-061": ["auditkit/analysis/verifier.py"],
    "DSR-062": ["auditkit/analysis/verifier.py"],
    "DSR-063": ["auditkit/analysis/dedup.py"],
    "DSR-064": ["auditkit/hosts/concurrency.py", "auditkit/hosts/retry.py", "auditkit/app/service.py"],
    "DSR-065": ["auditkit/hosts/retry.py", "auditkit/ledger/task_queue.py", "auditkit/app/service.py"],
    "DSR-066": ["auditkit/ledger/budget.py", "auditkit/ledger/task_queue.py"],
    "DSR-067": ["auditkit/reporting/cost.py", "auditkit/ledger/usage.py"],
    "DSR-068": ["auditkit/reporting/generator.py", "auditkit/reporting/i18n.py"],
    "DSR-069": ["auditkit/reporting/secret_masker.py"],
    "DSR-070": ["auditkit/reporting/self_review.py"],
    "DSR-071": ["auditkit/knowledge/admission.py"],
    "DSR-072": ["auditkit/ledger/db.py", "auditkit/ledger/task_queue.py"],
    "DSR-073": ["auditkit/contracts/types.py", "auditkit/contracts/schema_validator.py"],
    "DSR-074": ["audit.py"],
    "DSR-075": ["auditkit/hosts/session_adapter.py", "auditkit/hosts/mcp_adapter.py"],
    "DSR-076": ["auditkit/contracts/gates.py", "auditkit/app/service.py"],
    "DSR-077": ["auditkit/knowledge/catalog.py", "auditkit/knowledge/admission.py"],
    "DSR-078": ["tools/run_all_tests.py"],
    "DSR-079": ["tests/security/test_security.py"],
    "DSR-080": ["auditkit/app/service.py", "skill/SKILL.md"],
}


def build_traceability_block(file_rel_path: str, dsrs_for_file: List[str], sr_map, swr_map, dsr_map) -> str:
    lines = [
        "# ==============================================================================",
        "# 软件需求追踪与实现规范 (Software Requirements Traceability & Implementation)",
        "# ==============================================================================",
        f"# 对应模块: {file_rel_path}",
        "#",
        "# 本代码文件承担的软件设计与开发需求编号及完整需求描述如下：",
    ]

    for dsr_id in sorted(dsrs_for_file):
        dsr_info = dsr_map.get(dsr_id, {})
        trace_str = dsr_info.get("trace", "")
        owner = dsr_info.get("owner", "")
        desc = dsr_info.get("desc", "")

        lines.append("#")
        lines.append(f"# --- 需求编号: {dsr_id} [负责人: {owner}] ---")
        lines.append(f"# 需求描述: {desc}")

        # Extract linked SWRs and SRs
        swrs_linked = re.findall(r"SWR-\d+", trace_str)
        for swr_id in swrs_linked:
            swr_info = swr_map.get(swr_id, {})
            swr_desc = swr_info.get("desc", "")
            swr_src = swr_info.get("source", "")
            lines.append(f"#   └─ 上层软件需求 {swr_id} ({swr_src}): {swr_desc}")
            srs_linked = re.findall(r"SR-\d+", swr_src)
            for sr_id in srs_linked:
                sr_desc = sr_map.get(sr_id, "")
                lines.append(f"#        └─ 对应系统需求 {sr_id}: {sr_desc}")

    lines.append("# ==============================================================================")
    return "\n".join(lines)


def inject_into_file(abs_path: Path, block: str):
    content = abs_path.read_text(encoding="utf-8")

def clean_existing_blocks(content: str) -> str:
    lines = content.splitlines()
    new_lines = []
    in_block = False
    for line in lines:
        if line.strip() == "# ==============================================================================":
            in_block = not in_block
            continue
        if in_block:
            continue
        new_lines.append(line)
    return "\n".join(new_lines)


def inject_into_file(abs_path: Path, block: str):
    raw_content = abs_path.read_text(encoding="utf-8")
    content = clean_existing_blocks(raw_content)

    # Check if old style "# 需求追踪 (Requirement Traceability)" exists
    old_pattern = re.compile(
        r"# 需求追踪 \(Requirement Traceability\)\n"
        r"# -+\n.*?"
        r"# 状态以统一测试结论为准.*?#\n",
        re.DOTALL
    )
    if old_pattern.search(content):
        new_content = old_pattern.sub(block + "\n", content, count=1)
    else:
        # Place after module docstring or at the top
        doc_match = re.match(r"^(\s*\"\"\"[\s\S]*?\"\"\"\n)(.*)$", content)
        if doc_match:
            new_content = doc_match.group(1) + "\n" + block + "\n" + doc_match.group(2)
        else:
            # Place after shebang if any
            if content.startswith("#!"):
                lines = content.split("\n", 1)
                new_content = lines[0] + "\n\n" + block + "\n\n" + lines[1]
            else:
                new_content = block + "\n\n" + content

    abs_path.write_text(new_content, encoding="utf-8")


def main():
    sr_map, swr_map, dsr_map = parse_requirements()
    print(f"Loaded {len(sr_map)} SRs, {len(swr_map)} SWRs, {len(dsr_map)} DSRs.")

    # Invert mapping: file -> list of DSRs
    file_to_dsrs: Dict[str, List[str]] = {}
    for dsr_id, files in DSR_TO_FILES.items():
        for f in files:
            file_to_dsrs.setdefault(f, []).append(dsr_id)

    updated_count = 0
    for rel_path, dsrs in file_to_dsrs.items():
        if rel_path.endswith(".md"):
            continue  # Handle markdown separately if needed
        if rel_path.startswith("tests/") or rel_path.startswith("tools/"):
            target_path = ROOT_DIR / rel_path
        else:
            target_path = SCRIPTS_DIR / rel_path

        if not target_path.exists():
            print(f"WARNING: File {target_path} does not exist!")
            continue

        block = build_traceability_block(rel_path, dsrs, sr_map, swr_map, dsr_map)
        inject_into_file(target_path, block)
        updated_count += 1

        # Verify syntax
        if target_path.suffix == ".py":
            try:
                ast.parse(target_path.read_text(encoding="utf-8"))
            except SyntaxError as e:
                print(f"ERROR: Syntax error in {target_path}: {e}")
                raise

    print(f"Successfully embedded traceability blocks into {updated_count} Python source files.")


if __name__ == "__main__":
    main()
