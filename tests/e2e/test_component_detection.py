"""E2E tests for DSR-055 build-manifest component identification in prepare.

Drives a real prepare() over a polyglot monorepo fixture
(tests/fixtures/components_mono: svc-a/pom.xml, web/package.json, plus a
top-level script outside any component root) and asserts:

- inventory reconciliation by_component reports the two real build components
  plus "default" for files outside every component root;
- the frozen snapshot manifest.json carries the detected component per file
  (injected before freeze consumption, root hash unaffected);
- every planned unit's component field comes from the nearest enclosing root;
- plan_summary records the detected component roots (DSR-055 accounting);
- targets WITHOUT any build manifest keep the all-default behavior (existing
  contract unchanged).
"""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from auditkit.app.service import AuditAppService

FIXTURES_DIR = Path("/root/polyglot-audit/tests/fixtures")
SKILL_DIR = Path("/root/polyglot-audit/skill")


class TestPrepareComponentDetection(unittest.TestCase):
    """prepare() writes real build components into manifest, plan and units."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())
        self.app = AuditAppService(SKILL_DIR)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _config(self, target):
        return {
            "schema_version": "1.0",
            "target": str(target),
            "run_dir": str(self.temp_dir / "run"),
            "report_language": "en",
            "profile": "standard",
            "scope": {"include": ["*"], "exclude": []},
            "budgets": [
                {
                    "schema_version": "1.0",
                    "dimension": "tasks",
                    "mode": "enforced",
                    "limit": 30,
                    "settled": 0,
                    "reserved": 0,
                    "unit": "tasks",
                    "availability": "exact",
                }
            ],
            "safety_acceptance": {
                "allow_unverified_execution": False,
                "allow_unverified_network": False,
                "allow_unverified_write": False,
                "user_approved": True,
            },
        }

    def test_prepare_assigns_real_components_and_default(self):
        config = self._config(FIXTURES_DIR / "components_mono")
        prep = self.app.prepare(config["target"], config["run_dir"], config)
        run_dir = Path(config["run_dir"])

        # Inventory reconciliation aggregates real components + default.
        by_component = prep["inventory_reconciliation"]["by_component"]
        self.assertEqual(
            by_component.get("svc-a", 0) + by_component.get("web", 0), 7,
            f"expected the two build components to cover 7 files: {by_component}",
        )
        self.assertEqual(
            by_component.get("svc-a"), 4,
            "pom.xml + Repo.kt + Helper.java + Detector.py",
        )
        self.assertEqual(by_component.get("web"), 3)  # package.json + api.ts + Home.vue
        self.assertEqual(by_component.get("default"), 1)  # loose.py

        # plan_summary records the detected component roots (DSR-055).
        detection = json.loads((run_dir / "plan" / "plan.json").read_text(encoding="utf-8"))
        roots = {
            (r["root"], r["label"], r["manifest"])
            for r in detection["component_detection"]["roots"]
        }
        self.assertIn(("svc-a", "svc-a", "svc-a/pom.xml"), roots)
        self.assertIn(("web", "web", "web/package.json"), roots)
        self.assertEqual(detection["component_detection"]["default_component_files"], 1)

        # The frozen snapshot manifest itself carries the components.
        manifest = json.loads(
            (run_dir / "snapshot" / "manifest.json").read_text(encoding="utf-8")
        )
        components = {f["path"]: f["component"] for f in manifest["files"]}
        self.assertEqual(components["svc-a/pom.xml"], "svc-a")
        self.assertEqual(components["svc-a/src/Repo.kt"], "svc-a")
        self.assertEqual(components["svc-a/lib/Helper.java"], "svc-a")
        self.assertEqual(components["svc-a/src/Detector.py"], "svc-a")
        self.assertEqual(components["web/package.json"], "web")
        self.assertEqual(components["web/src/api.ts"], "web")
        self.assertEqual(components["web/pages/Home.vue"], "web")
        self.assertEqual(components["loose.py"], "default")
        # Snapshot identity is unaffected by the component injection: the
        # recorded snapshot_id still matches the manifest's root hash prefix.
        self.assertEqual(manifest["snapshot_id"], prep["snapshot_id"])

        # Every planned unit inherits its file's component. DA-10 full
        # coverage: ALL files are planned (not only the signal-bearing
        # module), so the component set spans the whole inventory.
        unit_components = {u["component"] for u in detection["units"]}
        self.assertEqual(unit_components, {"svc-a", "web", "default"})
        for unit in detection["units"]:
            self.assertIn(unit["component"], {"svc-a", "web", "default"})
            self.assertEqual(
                unit["component"], components[unit["ranges"][0]["path"]]
            )

    def test_target_without_build_manifests_stays_all_default(self):
        config = self._config(FIXTURES_DIR / "pyapp")
        prep = self.app.prepare(config["target"], config["run_dir"], config)

        by_component = prep["inventory_reconciliation"]["by_component"]
        self.assertEqual(set(by_component.keys()), {"default"})
        detection = json.loads(
            (Path(config["run_dir"]) / "plan" / "plan.json").read_text(encoding="utf-8")
        )
        self.assertEqual(detection["component_detection"]["roots"], [])
        self.assertEqual(
            detection["component_detection"]["default_component_files"],
            detection["total_files"],
        )

    def test_manifest_integrity_survives_component_injection(self):
        """resume/finalize integrity recomputes the root hash from contents.

        The component injection rewrites manifest.json; snapshot verification
        must still pass because the root hash never covered the component
        field.
        """
        config = self._config(FIXTURES_DIR / "components_mono")
        prep = self.app.prepare(config["target"], config["run_dir"], config)
        self.app.activate(prep["run_id"], config["run_dir"])

        # Drive the queue manually and finalize: integrity checks run at
        # finalize (artifact + snapshot verification).
        run_id, run_dir = prep["run_id"], Path(config["run_dir"])
        while True:
            claims = self.app.next(run_id, run_dir, batch_size=5)
            if not claims:
                break
            for claim in claims:
                self.app.start(run_dir, claim)
                kind = (claim.get("spec") or {}).get("task_kind") or "hunt"
                self.app.submit(
                    run_dir, claim,
                    {
                        "schema_version": "1.0",
                        "task_id": claim["task_id"],
                        "attempt_id": claim["attempt_id"],
                        "kind": kind,
                        "coverage": [],
                        "records": [],
                        "overflow": [],
                    },
                    f"digest-{claim['attempt_id']}",
                )
        fin = self.app.finalize(run_id, run_dir, findings=[])
        self.assertEqual(fin["final_state"], "complete")


if __name__ == "__main__":
    unittest.main()
