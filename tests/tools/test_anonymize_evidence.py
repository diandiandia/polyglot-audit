"""Delivery-prep pseudonymization (tools/anonymize_evidence.py).

Pins the input-shape -> expected-behavior contract with synthetic fixtures:
run/ev identifiers are irreversibly replaced, prose without identifiers and
non-JSON files pass through, the mapping is never written, and pseudonyms are
stable within one export but differ across exports (different salts).
"""

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS_DIR = Path("/root/polyglot-audit/tools")
sys.path.insert(0, str(TOOLS_DIR))

import anonymize_evidence  # noqa: E402


class TestAnonymizeEvidence(unittest.TestCase):
    def setUp(self):
        self.temp = Path(tempfile.mkdtemp(prefix="anon-ev-"))
        self.src = self.temp / "src"
        self.dst = self.temp / "dst"
        self.src.mkdir(parents=True)

    def tearDown(self):
        shutil.rmtree(self.temp, ignore_errors=True)

    def _write(self, name, payload):
        (self.src / name).write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
        )

    def test_run_ids_replaced_irreversibly_and_consistently(self):
        self._write("gate.json", {
            "run_id": "run-1a2b3c4d",
            "generation": "ev-9f8e7d6c",
            "per_run": [
                {"run_id": "run-1a2b3c4d", "attempts": 6},
                {"run_id": "run-042", "attempts": 2},
            ],
            "note": "26/26 usage records were unavailable; no ids mentioned here",
        })
        report = anonymize_evidence.anonymize_evidence_dir(
            self.src, self.dst, salt="salt-one"
        )
        self.assertEqual(report[0]["replacements"], 4)

        out = json.loads((self.dst / "gate.json").read_text(encoding="utf-8"))
        # Every identifier became an irreversible pseudonym with its prefix kept.
        self.assertNotIn("run-1a2b3c4d", json.dumps(out))
        self.assertNotIn("ev-9f8e7d6c", json.dumps(out))
        self.assertNotIn("run-042", json.dumps(out))
        self.assertTrue(out["run_id"].startswith("run-"))
        self.assertEqual(len(out["run_id"]), 4 + 12)
        # Same identifier -> same pseudonym across the whole file.
        self.assertEqual(out["run_id"], out["per_run"][0]["run_id"])
        # Different identifiers -> different pseudonyms.
        self.assertNotEqual(out["run_id"], out["per_run"][1]["run_id"])
        # Prose without identifiers passes through verbatim.
        self.assertIn("26/26 usage records were unavailable", out["note"])

    def test_pseudonyms_differ_across_exports_and_mapping_is_never_written(self):
        self._write("corroboration.json", {"runs": [{"run_id": "run-5e6f7a8b"}]})
        anonymize_evidence.anonymize_evidence_dir(self.src, self.dst, salt="salt-one")
        second = self.temp / "dst2"
        anonymize_evidence.anonymize_evidence_dir(self.src, second, salt="salt-two")

        first = json.loads((self.dst / "corroboration.json").read_text(encoding="utf-8"))
        other = json.loads((second / "corroboration.json").read_text(encoding="utf-8"))
        self.assertNotEqual(first["runs"][0]["run_id"], other["runs"][0]["run_id"])
        # No mapping artifact anywhere in the output trees.
        self.assertEqual(sorted(p.name for p in self.dst.rglob("*")), ["corroboration.json"])
        self.assertEqual(sorted(p.name for p in second.rglob("*")), ["corroboration.json"])

    def test_non_json_files_are_copied_verbatim(self):
        (self.src / "README.txt").write_text(
            "evidence bundle for run-1a2b3c4d (text file, verbatim copy)",
            encoding="utf-8",
        )
        report = anonymize_evidence.anonymize_evidence_dir(
            self.src, self.dst, salt="salt-one"
        )
        self.assertTrue(report[0].get("copied_verbatim"))
        copied = (self.dst / "README.txt").read_text(encoding="utf-8")
        self.assertIn("run-1a2b3c4d", copied)

    def test_in_place_anonymization_is_rejected(self):
        with self.assertRaises(SystemExit):
            anonymize_evidence.main(["--src", str(self.src), "--dst", str(self.src)])


if __name__ == "__main__":
    unittest.main()
