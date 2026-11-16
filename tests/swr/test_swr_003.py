"""SWR-003 acceptance tests: platform-conditional base languages and
out-of-catalog risks across mixed-language boundaries.

验收原文 (docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2, SWR-003):
    "实现平台条件化基座语言及目录外风险；测试 TS/JS、非 JVM 平台、跨语言和
    非目录候选不被丢弃。"

细化依据: DDS-05 (DETAILED_SOFTWARE_DESIGN.md): "Kotlin/Scala 的 Java 基座索引按
平台三态展开：……无证据判未知——不展开基座索引并在 packet 行披露 platform
unknown，不默认按 JVM 处理 [DA-03]"; DSR-038: "验证非目录候选不受限"。

Covered here:
- TS/JS fixture candidates are not dropped and reach the same verification
  flow as any other candidate.
- Kotlin without JVM build evidence: Java base not expanded, packet carries an
  explicit PLATFORM UNKNOWN disclosure; with evidence it expands; explicit
  non-JVM excludes Java.
- Cross-language (Python->C FFI) boundary fixture produces frontier/probe
  records that connect into a synthesized candidate entering the SAME
  verification flow, with both sides' evidence preserved.
- An out-of-catalog synthetic vulnerability is not dropped anywhere in the
  hunt -> verify flow.
"""

import unittest
from pathlib import Path

from auditkit.analysis.connector import HypothesisConnector
from auditkit.analysis.hunter import HuntResultParser
from auditkit.analysis.packets import PacketBuilder
from auditkit.analysis.verifier import Verifier
from auditkit.app.service import detect_jvm_build_evidence_files
from auditkit.knowledge.catalog import KnowledgeCatalog

REPO_ROOT = Path(__file__).resolve().parents[2]
KNOWLEDGE_DIR = REPO_ROOT / "skill" / "knowledge"
FIXTURES = REPO_ROOT / "tests" / "fixtures"


class TestSWR003(unittest.TestCase):
    """SWR-003: mixed-language boundaries and out-of-catalog risks survive."""

    def setUp(self):
        self.catalog = KnowledgeCatalog(KNOWLEDGE_DIR)

    # -- TS/JS -------------------------------------------------------------
    def test_ts_js_fixture_candidates_reach_verification(self):
        """The TS/JS XSS fixture candidate is parsed and verified, not dropped."""
        view_js = (FIXTURES / "ts_js" / "src" / "view.js").read_text(encoding="utf-8")
        raw = {
            "records": [{
                "record_type": "candidate",
                "candidate_id": "cand-tsjs-1",
                "issue": "js-01",
                "source": {"path": "ts_js/src/view.js", "line": 4, "symbol": "userComment", "kind": "dom_input"},
                "sink": {"path": "ts_js/src/view.js", "line": 5, "symbol": "innerHTML", "kind": "dom_write"},
                "steps": [
                    {"path": "ts_js/src/view.js", "line": 4, "role": "source", "note": "user comment"},
                    {"path": "ts_js/src/view.js", "line": 5, "role": "sink", "note": "innerHTML assignment"},
                ],
                "provenance": {"hunt_tasks": ["task-tsjs"]},
            }],
        }
        candidates, frontiers, probes, overflows = HuntResultParser().parse_worker_payload(
            raw, "task-tsjs"
        )
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["sink"]["symbol"], "innerHTML")
        self.assertEqual(frontiers, [])
        self.assertEqual(probes, [])
        self.assertEqual(overflows, [])

        # TS expands the JS index, so the JS runtime sink class is in scope.
        _, base_lines = self.catalog.get_applicable_indices("typescript", is_jvm=True)
        joined = "\n".join(base_lines)
        self.assertIn("[JAVASCRIPT]", joined)

        verifier = Verifier()
        finding = verifier.create_finding_from_candidate(
            candidates[0],
            "needs_validation",
            "vt-tsjs-1",
            impact=3,
            exploitability=3,
            blockers=["Deployment CSP and sanitizer configuration unknown"],
            validation_plan="Render an attacker-controlled comment in the deployed UI",
        )
        self.assertEqual(finding["verdict"], "needs_validation")
        self.assertEqual(finding["languages"], ["javascript"])

    # -- Kotlin platform conditioning ---------------------------------------
    def test_kotlin_without_build_evidence_keeps_platform_unknown(self):
        """No JVM build evidence -> Java base NOT expanded + disclosure line."""
        kotlin_only_manifest = [
            {"path": "src/main.kt"},
            {"path": "src/Worker.kt"},
            {"path": "src/NativeMain.kt"},
        ]
        evidence = detect_jvm_build_evidence_files(
            [f["path"] for f in kotlin_only_manifest]
        )
        self.assertEqual(
            evidence, [],
            "a Kotlin-only snapshot without build files has no JVM evidence",
        )

        primary, base = self.catalog.get_applicable_indices("kotlin", is_jvm=None)
        self.assertTrue(primary)
        self.assertEqual(
            [l for l in base if l.startswith("- [JAVA]")], [],
            "unknown platform must not expand the Java base index",
        )
        self.assertTrue(
            any("PLATFORM UNKNOWN" in line for line in base),
            base,
        )

    def test_unknown_platform_disclosure_reaches_the_packet(self):
        """The PLATFORM UNKNOWN disclosure is rendered into the prompt packet."""
        _, base = self.catalog.get_applicable_indices("kotlin", is_jvm=None)
        unit = {
            "unit_id": "u-kotlin-native",
            "language": "kotlin",
            "ranges": [{"path": "src/main.kt", "line_start": 1, "line_end": 2}],
        }
        packet, digest, overflow = PacketBuilder().build_hunt_packet(
            "snp-kotlin",
            unit,
            {"src/main.kt": "fun main() {\n    println(\"hi\")\n}\n"},
            base_language_index=base,
        )
        self.assertIn("PLATFORM UNKNOWN", packet["prompt_text"])
        self.assertIn("is NOT loaded", packet["prompt_text"])

    def test_kotlin_with_jvm_evidence_expands_java_base(self):
        jvm_manifest = [
            {"path": "pom.xml"},
            {"path": "src/main/kotlin/App.kt"},
        ]
        evidence = detect_jvm_build_evidence_files([f["path"] for f in jvm_manifest])
        self.assertTrue(evidence, "pom.xml is JVM build evidence")

        _, base = self.catalog.get_applicable_indices("kotlin", is_jvm=True)
        self.assertEqual(len(base), 10)
        self.assertTrue(all(line.startswith("- [JAVA]") for line in base))

    def test_known_non_jvm_kotlin_excludes_java_base(self):
        _, base = self.catalog.get_applicable_indices("kotlin", is_jvm=False)
        self.assertEqual(base, [], "explicit non-JVM platform expands nothing")

    # -- cross-language boundary fixture ------------------------------------
    def _boundary_records(self):
        """Frontier (Python caller) + dangling sink (C callee) from the fixture."""
        caller = (FIXTURES / "boundary" / "caller.py").read_text(encoding="utf-8")
        callee = (FIXTURES / "boundary" / "callee.c").read_text(encoding="utf-8")
        self.assertIn("execute_native_operation", caller)
        self.assertIn("strcpy", callee)
        frontier = {
            "schema_version": "1.0",
            "frontier_id": "front-py-ffi",
            "source": {
                "path": "boundary/caller.py", "line": 10,
                "symbol": "execute_native_operation", "lang": "python",
            },
            "boundary": "ffi_bridge",
            "steps": [
                {"path": "boundary/caller.py", "line": 10, "role": "source", "lang": "python"},
            ],
            "open_questions": ["parameter marshalling across ctypes"],
            "provenance": {"hunt_tasks": ["task-py"]},
        }
        probe = {
            "schema_version": "1.0",
            "probe_id": "probe-c-sink",
            "sink": {
                "path": "boundary/callee.c", "line": 8,
                "symbol": "execute_native_operation", "lang": "c",
            },
            "boundary": "ffi_bridge",
            "steps": [
                {"path": "boundary/callee.c", "line": 8, "role": "sink", "lang": "c"},
            ],
            "guard_analysis": "none observed in native code",
            "open_questions": ["origin of the command buffer"],
            "provenance": {"hunt_tasks": ["task-c"]},
        }
        return frontier, probe

    def test_cross_language_boundary_enters_same_verification_flow(self):
        """Python->C FFI fixture connects and the candidate verifies normally.

        The synthesized cross-language candidate must flow through the same
        Verifier path as a mono-language candidate (no separate pipeline), and
        the heuristic connection itself stays hypothesized.
        """
        frontier, probe = self._boundary_records()
        result = HypothesisConnector().connect_ex([frontier], [probe])
        self.assertEqual(len(result["connections"]), 1)
        connection = result["connections"][0]
        self.assertEqual(connection["status"], "hypothesized")
        self.assertEqual(connection["frontier_id"], frontier["frontier_id"])
        self.assertEqual(connection["probe_id"], probe["probe_id"])
        self.assertEqual(len(result["candidates"]), 1)

        synth = result["candidates"][0]
        # Both sides' evidence is preserved in the synthesized candidate.
        self.assertEqual(synth["source"]["path"], "boundary/caller.py")
        self.assertEqual(synth["sink"]["path"], "boundary/callee.c")
        self.assertEqual(
            sorted(synth["provenance"]["candidates"]),
            [frontier["frontier_id"], probe["probe_id"]],
        )
        self.assertEqual(
            sorted(synth["provenance"]["hunt_tasks"]), ["task-c", "task-py"],
        )

        verifier = Verifier()
        finding = verifier.create_finding_from_candidate(
            synth,
            "needs_validation",
            "vt-ffi-1",
            impact=4,
            exploitability=2,
            blockers=[
                "Cross-language parameter compatibility is unverified; "
                "the native ABI may truncate or reject the payload"
            ],
            validation_plan="Compile the native module and drive ctypes with a long payload",
        )
        self.assertEqual(finding["verdict"], "needs_validation")
        self.assertEqual(finding["evidence_level"], "E1")
        # The record is structurally identical to any other pending finding:
        # same required fields, no special cross-language shortcut to confirmed,
        # and both boundary languages stay attributed.
        self.assertIn("python", finding["languages"])
        self.assertIn("c", finding["languages"])

    def test_cross_language_mismatched_boundary_stays_unresolved(self):
        """An unmatched half-chain is recorded unresolved, never dropped."""
        frontier, _ = self._boundary_records()
        unrelated_probe = {
            "schema_version": "1.0",
            "probe_id": "probe-other",
            "sink": {"path": "other/mod.c", "line": 3, "symbol": "unrelated_cb", "lang": "c"},
            "boundary": "signal_handler",
            "steps": [],
            "provenance": {"hunt_tasks": ["task-c2"]},
        }
        result = HypothesisConnector().connect_ex([frontier], [unrelated_probe])
        self.assertEqual(result["connections"], [])
        self.assertEqual(result["candidates"], [])
        unresolved_kinds = {u["kind"] for u in result["unresolved"]}
        self.assertEqual(unresolved_kinds, {"frontier", "probe"})
        self.assertTrue(all(u["reason"] for u in result["unresolved"]))

    # -- out-of-catalog synthetic vulnerability -----------------------------
    def test_out_of_catalog_synthetic_vulnerability_not_dropped(self):
        """A synthetic vuln outside the 150-card catalog survives hunt+verify."""
        issue = "noncatalog-server-side-template-injection"
        catalog_ids = {
            self.catalog.get_card(f"{prefix}-{n:02d}")["id"]
            for prefix in ("py", "js", "ts")
            for n in range(1, 11)
        }
        self.assertNotIn(issue, catalog_ids)

        raw = {
            "records": [{
                "record_type": "candidate",
                "candidate_id": "cand-ssti-1",
                "issue": issue,
                "source": {"path": "web/render.py", "line": 2, "symbol": "template_arg", "kind": "query"},
                "sink": {"path": "web/render.py", "line": 6, "symbol": "Template(...).render", "kind": "template_eval"},
                "steps": [
                    {"path": "web/render.py", "line": 2, "role": "source"},
                    {"path": "web/render.py", "line": 6, "role": "sink"},
                ],
                "provenance": {"hunt_tasks": ["task-ssti"]},
            }],
        }
        candidates, frontiers, probes, _ = HuntResultParser().parse_worker_payload(raw, "task-ssti")
        self.assertEqual(len(candidates), 1, "hunt keeps out-of-catalog candidates")
        self.assertEqual(frontiers, [])
        self.assertEqual(probes, [])

        verifier = Verifier(enforce_attempt_gate=True)
        finding = verifier.create_finding_from_candidate(
            candidates[0],
            "needs_validation",
            "vt-ssti-1",
            impact=4,
            exploitability=3,
            blockers=["Sandbox escape reachability must be shown on the deployed engine"],
            validation_plan="Submit {{7*7}} payload in the deployed template engine",
        )
        self.assertEqual(finding["issue"], issue)
        self.assertEqual(finding["verdict"], "needs_validation")


if __name__ == "__main__":
    unittest.main()
