"""Platform conditioning tests: Kotlin/Scala only inherit the Java base index
when JVM build evidence exists (SR-003 / SD-02 / DR-014).

Cross-layer assertions:
- KnowledgeCatalog three-state ``is_jvm`` (True / False / None=unknown):
  unknown expands NO Java base index and emits an explicit "platform unknown"
  disclosure line instead of a silent assumption.
- prepare detects JVM build markers in the snapshot manifest (pom.xml,
  build.gradle, .sbt, .mvn/) and records the evidence in plan/plan.json.
- The hunt packet for a Kotlin unit carries the Java base index only when the
  target has JVM build evidence; without evidence the packet says the platform
  is unknown and omits the Java base lines.
"""

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SKILL_SCRIPTS = REPO_ROOT / "skill" / "scripts"
if str(SKILL_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SKILL_SCRIPTS))

from auditkit.app.service import AuditAppService, detect_jvm_build_evidence_files  # noqa: E402
from auditkit.knowledge.catalog import KnowledgeCatalog  # noqa: E402
from auditkit.ledger.db import get_db_connection  # noqa: E402

SKILL_DIR = REPO_ROOT / "skill"

KOTLIN_SOURCE = (
    "fun run(cmd: String) {\n"
    "    Runtime.getRuntime().exec(\"sh -c $cmd\")\n"
    "}\n"
)


class TestPlatformConditioning(unittest.TestCase):

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="platform-cond-"))
        self.app = AuditAppService(SKILL_DIR)
        self.run_dir = self.temp_dir / "run"
        self._run_id = None

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # ------------------------------------------------------------- helpers
    def make_config(self, target):
        return {
            "schema_version": "1.0",
            "target": str(target),
            "run_dir": str(self.run_dir),
            "report_language": "en",
            "profile": "standard",
            "scope": {"include": ["*"], "exclude": []},
            "budgets": [{
                "schema_version": "1.0", "dimension": "tasks", "mode": "enforced",
                "limit": 12, "settled": 0, "reserved": 0, "unit": "tasks",
                "availability": "exact",
            }],
            "safety_acceptance": {
                "allow_unverified_execution": False,
                "allow_unverified_network": False,
                "allow_unverified_write": False,
                "user_approved": True,
            },
        }

    def write_kotlin_target(self, build_marker=None):
        target = self.temp_dir / "kt-target"
        (target / "src").mkdir(parents=True)
        (target / "src" / "Main.kt").write_text(KOTLIN_SOURCE, encoding="utf-8")
        if build_marker:
            (target / build_marker).write_text("// build marker fixture\n", encoding="utf-8")
        return target

    def prepare(self, target):
        prep = self.app.prepare(target, self.run_dir, self.make_config(target))
        self.app.activate(self.run_id, self.run_dir)
        return prep

    def hunt_packet_text(self):
        claims = self.app.next(self.run_id, self.run_dir, batch_size=10)
        hunt_claims = [c for c in claims if c["spec"].get("task_kind") == "hunt"]
        self.assertTrue(hunt_claims, "expected at least one hunt claim")
        packet = json.loads(
            (self.run_dir / hunt_claims[0]["packet_ref"]).read_text(encoding="utf-8")
        )
        return packet["prompt_text"]

    @property
    def run_id(self):
        if self._run_id is None:
            conn = get_db_connection(self.run_dir / "events.db")
            try:
                self._run_id = conn.execute("SELECT run_id FROM runs LIMIT 1").fetchone()["run_id"]
            finally:
                conn.close()
        return self._run_id

    # ------------------------------------------------------------- catalog
    def test_catalog_three_state_is_jvm(self):
        catalog = KnowledgeCatalog(SKILL_DIR / "knowledge")

        _, jvm_base = catalog.get_applicable_indices("kotlin", is_jvm=True)
        self.assertTrue(any("[JAVA]" in b for b in jvm_base))

        _, non_jvm_base = catalog.get_applicable_indices("kotlin", is_jvm=False)
        self.assertEqual(non_jvm_base, [])

        # Unknown platform: no Java base expansion, explicit disclosure line.
        _, unknown_base = catalog.get_applicable_indices("kotlin", is_jvm=None)
        self.assertEqual(len(unknown_base), 1)
        self.assertIn("PLATFORM UNKNOWN", unknown_base[0])
        self.assertNotIn("[JAVA]", unknown_base[0])

        # Platform conditioning never affects TS->JS and C++->C.
        _, ts_base = catalog.get_applicable_indices("typescript", is_jvm=None)
        self.assertTrue(any("[JAVASCRIPT]" in b for b in ts_base))
        _, cpp_base = catalog.get_applicable_indices("cpp", is_jvm=None)
        self.assertTrue(any("[C]" in b for b in cpp_base))

        # Default is the honest unknown (SR-003: never assume JVM).
        _, kotlin_default = catalog.get_applicable_indices("kotlin")
        self.assertIn("PLATFORM UNKNOWN", kotlin_default[0])

    # ------------------------------------------------------ build evidence
    def test_detect_jvm_build_evidence_files(self):
        evidence = detect_jvm_build_evidence_files([
            "src/Main.kt",
            "pom.xml",
            "build.gradle.kts",
            "settings.gradle",
            "build.sbt",
            ".mvn/wrapper/maven-wrapper.properties",
            "docs/readme.md",
        ])
        self.assertEqual(evidence, [
            ".mvn/wrapper/maven-wrapper.properties",
            "build.gradle.kts",
            "build.sbt",
            "pom.xml",
            "settings.gradle",
        ])
        self.assertEqual(detect_jvm_build_evidence_files(["src/Main.kt", "app.py"]), [])

    # ---------------------------------------------------------- end to end
    def test_kotlin_without_build_markers_does_not_inherit_java_base(self):
        target = self.write_kotlin_target()
        prep = self.prepare(target)

        # The plan records the honest unknown platform evidence.
        plan = json.loads((self.run_dir / "plan" / "plan.json").read_text(encoding="utf-8"))
        self.assertIsNone(plan["platform_evidence"]["is_jvm"])
        self.assertEqual(plan["platform_evidence"]["build_marker_files"], [])

        packet_text = self.hunt_packet_text()
        self.assertIn("Primary Language Index", packet_text)
        self.assertIn("kotlin-01", packet_text)
        # No Java base inheritance without evidence; the packet says why.
        self.assertNotIn("[JAVA]", packet_text)
        self.assertIn("PLATFORM UNKNOWN", packet_text)
        self.assertIn("No JVM build evidence", packet_text)

    def test_kotlin_with_gradle_marker_inherits_java_base(self):
        target = self.write_kotlin_target(build_marker="build.gradle")
        self.prepare(target)

        plan = json.loads((self.run_dir / "plan" / "plan.json").read_text(encoding="utf-8"))
        self.assertTrue(plan["platform_evidence"]["is_jvm"])
        self.assertEqual(plan["platform_evidence"]["build_marker_files"], ["build.gradle"])

        packet_text = self.hunt_packet_text()
        self.assertIn("[JAVA]", packet_text)
        self.assertIn("Applicable Base Language Index", packet_text)
        self.assertNotIn("PLATFORM UNKNOWN", packet_text)


if __name__ == "__main__":
    unittest.main()
