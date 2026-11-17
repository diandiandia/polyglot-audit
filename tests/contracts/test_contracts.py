"""Tests for JSON schema validator, semantic validator, and gate evaluator."""

import unittest
from auditkit.contracts.errors import (
    AuditError,
    InvalidInputError,
    UnsupportedSchemaError,
)
from auditkit.contracts.gates import GateCheck, GateEvaluator, GateResult
from auditkit.contracts.schema_validator import SchemaValidator
from auditkit.contracts.semantic_validator import (
    SemanticValidator,
    calculate_severity,
    calculate_urgency,
    calculate_validation_priority,
)
from auditkit.contracts.types import (
    Candidate,
    Finding,
    GateResultData,
    TaskSpec,
    Usage,
)


class TestContracts(unittest.TestCase):

    def test_schema_validator_supported_keywords(self):
        schema = {
            "type": "object",
            "required": ["id", "count"],
            "additionalProperties": False,
            "properties": {
                "id": {"type": "string", "minLength": 2},
                "count": {"type": "integer", "minimum": 0},
            },
        }
        v = SchemaValidator(schema)
        # Valid instance
        self.assertEqual(len(v.validate({"id": "item1", "count": 5})), 0)

        # Invalid type (boolean instead of integer)
        errs = v.validate({"id": "item1", "count": True})
        self.assertTrue(len(errs) > 0)
        self.assertIn("integer", errs[0].message)

        # Missing required
        errs = v.validate({"id": "item1"})
        self.assertTrue(any("count" in e.message for e in errs))

        # Additional property disallowed
        errs = v.validate({"id": "item1", "count": 5, "extra": "forbidden"})
        self.assertTrue(any("extra" in e.message for e in errs))

    def test_schema_validator_rejects_unsupported_keyword(self):
        schema = {
            "type": "string",
            "unsupportedKeywordXYZ": True,
        }
        with self.assertRaises(UnsupportedSchemaError):
            SchemaValidator(schema)

    def test_schema_validator_rejects_unsupported_keyword_in_additionalProperties(self):
        """DSR-007 fail-closed: a dict-form additionalProperties is a schema
        of its own — an unknown keyword inside it must be rejected at
        construction time. The earlier revision recursed only into
        properties/items/oneOf/$defs, so the keyword was neither effective
        nor reported (a silent hole in the subset boundary)."""
        schema = {
            "type": "object",
            "properties": {
                "meta": {
                    "type": "object",
                    "additionalProperties": {"type": "string", "frobnicateXYZ": 1},
                },
            },
        }
        with self.assertRaises(UnsupportedSchemaError) as ctx:
            SchemaValidator(schema)
        self.assertIn("frobnicateXYZ", str(ctx.exception))
        self.assertEqual(
            ctx.exception.details["path"], "#/properties/meta/additionalProperties"
        )

    def test_schema_validator_rejects_unsupported_keyword_at_top_additionalProperties(self):
        schema = {
            "type": "object",
            "additionalProperties": {"type": "string", "frobnicateXYZ": 1},
        }
        with self.assertRaises(UnsupportedSchemaError):
            SchemaValidator(schema)

    def test_schema_validator_still_applies_dict_additionalProperties_schema(self):
        """The boolean form is not a schema and the dict form remains a live
        constraint at validation time — recursion at construction must not
        break runtime application of the subschema."""
        schema = {
            "type": "object",
            "additionalProperties": {"type": "string"},
        }
        v = SchemaValidator(schema)
        self.assertEqual(v.validate({"anything": "ok"}), [])
        errs = v.validate({"anything": 5})
        self.assertTrue(any(e.keyword == "type" for e in errs))

    def test_semantic_validator_rating_matrix(self):
        # 4x4 matrix exhaustive verification
        matrix_expectations = {
            (4, 4): ("Critical", "P0"),
            (4, 3): ("High", "P1"),
            (4, 2): ("High", "P1"),
            (4, 1): ("Medium", "P2"),
            (3, 4): ("High", "P0"),
            (3, 3): ("High", "P1"),
            (3, 2): ("Medium", "P2"),
            (3, 1): ("Low", "P3"),
            (2, 4): ("Medium", "P1"),
            (2, 3): ("Medium", "P2"),
            (2, 2): ("Low", "P3"),
            (2, 1): ("Low", "P3"),
            (1, 4): ("Low", "P2"),
            (1, 3): ("Low", "P2"),
            (1, 2): ("Low", "P3"),
            (1, 1): ("Info", "P3"),
        }

        for (impact, exploitability), (expected_sev, expected_urg) in matrix_expectations.items():
            calc_sev = calculate_severity(impact, exploitability)
            calc_urg = calculate_urgency(calc_sev, exploitability)
            self.assertEqual(calc_sev, expected_sev, f"Failed at ({impact}, {exploitability})")
            self.assertEqual(calc_urg, expected_urg, f"Failed at ({impact}, {exploitability})")

    def test_semantic_validator_finding_e3_rejected(self):
        val = SemanticValidator()
        finding = {
            "schema_version": "1.0",
            "finding_id": "F-001",
            "candidate_refs": ["c1"],
            "verdict": "confirmed",
            "evidence_level": "E3",  # Prohibited
            "provenance": {"hunt_tasks": ["t1"], "verify_tasks": ["v1"]},
        }
        with self.assertRaises(InvalidInputError) as ctx:
            val.validate_finding(finding)
        self.assertIn("E3", str(ctx.exception))

    def test_gate_evaluator_g0(self):
        # G0 pass
        manifest = {
            "root_hash": "a" * 64,
            "files": [{"path": "main.py"}],
        }
        plan = {"units": [{"unit_id": "u1"}]}
        res = GateEvaluator.evaluate_g0(manifest, plan, 1)
        self.assertEqual(res.status, "pass")

        # G0 fail on invalid root hash
        bad_manifest = {"root_hash": "short", "files": []}
        res_bad = GateEvaluator.evaluate_g0(bad_manifest, plan, 1)
        self.assertEqual(res_bad.status, "fail")


    # ------------------------------------------------------------------
    # DSR-010: cross-run reference validation
    # ------------------------------------------------------------------
    def test_semantic_validator_cross_run_reference(self):
        val = SemanticValidator(current_run_id="run-a")
        finding = {
            "schema_version": "1.0",
            "finding_id": "F-100",
            "candidate_refs": ["c1"],
            "verdict": "unverified",
            "evidence_level": "E1",
            "unverified_reason": "missing deployment facts",
            "run_id": "run-a",
            "provenance": {"hunt_tasks": ["t1"], "verify_tasks": [], "run_id": "run-a"},
        }
        # Same-run references are accepted
        val.validate_finding(finding)

        # A reference to another run (nested) is rejected with the field path
        finding_bad = dict(finding)
        finding_bad["provenance"] = {"hunt_tasks": ["t1"], "verify_tasks": [], "run_id": "run-b"}
        with self.assertRaises(InvalidInputError) as ctx:
            val.validate_finding(finding_bad)
        self.assertIn("run-b", str(ctx.exception))
        self.assertIn("provenance", str(ctx.exception))

        # Top-level mismatch rejected too
        finding_top = dict(finding)
        finding_top["run_id"] = "run-c"
        with self.assertRaises(InvalidInputError):
            val.validate_finding(finding_top)

        # Without a current run id the check is not applied
        val_no_run = SemanticValidator()
        val_no_run.validate_finding(finding_top)

    def test_validate_run_references_direct(self):
        val = SemanticValidator()
        obj = {"candidate": {"run_id": "run-1"}, "items": [{"run_id": "run-2"}]}
        with self.assertRaises(InvalidInputError) as ctx:
            val.validate_run_references(obj, current_run_id="run-1")
        self.assertIn("items/0", str(ctx.exception))

    # ------------------------------------------------------------------
    # DSR-022: not_applicable requires an explicit reason
    # ------------------------------------------------------------------
    def test_gate_not_applicable_requires_reason(self):
        with self.assertRaises(InvalidInputError):
            GateResult("G3", "not_applicable", [], 1, reason=None)
        res = GateResult("G3", "not_applicable", [], 1, reason="no findings produced in this run")
        self.assertEqual(res.status, "not_applicable")

        with self.assertRaises(InvalidInputError):
            GateCheck("G1-9", "Overflow", "not_applicable", "   ")

        # Invalid statuses are rejected outright
        with self.assertRaises(InvalidInputError):
            GateResult("G1", "skipped", [], 1)

    # ------------------------------------------------------------------
    # DSR-073: typed interface definitions
    # ------------------------------------------------------------------
    def test_typed_interface_definitions(self):
        finding: Finding = {
            "schema_version": "1.0",
            "finding_id": "F-1",
            "verdict": "unverified",
            "evidence_level": "E1",
            "provenance": {"hunt_tasks": [], "verify_tasks": []},
        }
        self.assertEqual(finding["verdict"], "unverified")

        usage: Usage = {
            "schema_version": "1.0",
            "attempt_id": "att-1",
            "dimension": "tasks",
            "availability": "exact",
            "value": 1,
            "unit": "tasks",
            "source": "host_cli_report",
        }
        self.assertEqual(usage["availability"], "exact")

        candidate: Candidate = {"schema_version": "1.0", "candidate_id": "c-1"}
        # TaskSpec is the union of the three task_spec.schema.json branches;
        # this example uses the hunt branch actually produced by prepare().
        task_spec: TaskSpec = {
            "schema_version": "1.0",
            "task_kind": "hunt",
            "snapshot_id": "snp-1",
            "unit": {
                "unit_id": "unit-1",
                "ranges": [{"path": "app/handlers/upload.py", "line_start": 1, "line_end": 10}],
            },
        }
        gate_data: GateResultData = {"schema_version": "1.0", "gate_id": "G4", "status": "pass"}
        self.assertEqual(
            (candidate["candidate_id"], task_spec["task_kind"], gate_data["gate_id"]),
            ("c-1", "hunt", "G4"),
        )


if __name__ == "__main__":
    unittest.main()
