"""Tests for schema positive/negative fixtures and the meta schema (DSR-006 / DSR-007).

- Every core production schema is loaded from skill/schemas/ and validated
  against valid and invalid sample fixtures (invalid samples cover missing
  required fields, unknown fields, and enum/bounds violations).
- The meta schema describing the supported keyword subset is used to validate
  all 20 production schemas; schemas using unsupported keywords are rejected.
"""

import json
import unittest
from pathlib import Path

from auditkit.contracts.errors import UnsupportedSchemaError
from auditkit.contracts.schema_validator import SchemaValidator
from auditkit.ledger.usage import parse_usage

REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMAS_DIR = REPO_ROOT / "skill" / "schemas"
FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def load_schema(name: str) -> dict:
    with open(SCHEMAS_DIR / f"{name}.schema.json", "r", encoding="utf-8") as f:
        return json.load(f)


class TestSchemaFixtures(unittest.TestCase):
    """Positive/negative samples validated against the production schemas."""

    # schema name -> fixture directory; entries mapping a fixture stem to
    # schema-level validity. Files not listed as schema-valid are asserted
    # invalid at the schema level.
    CORE_SCHEMAS = {
        "task_spec": "task_spec",
        "finding": "finding",
        "worker_result": "worker_result",
        "candidate": "candidate",
        "usage": "usage",
    }

    # Fixtures that are schema-valid but semantically invalid (validated via
    # the runtime usage parser instead of the declarative schema).
    SEMANTIC_ONLY_INVALID = {"invalid_unavailable_with_value"}

    def _fixture_dir(self, name: str) -> Path:
        return FIXTURES_DIR / self.CORE_SCHEMAS[name]

    def test_core_schema_valid_and_invalid_fixtures(self):
        for schema_name in self.CORE_SCHEMAS:
            schema = load_schema(schema_name)
            validator = SchemaValidator(schema)
            fixture_dir = self._fixture_dir(schema_name)

            samples = sorted(fixture_dir.glob("*.json"))
            self.assertGreaterEqual(len(samples), 4, f"{schema_name}: expected >= 4 fixtures")

            for sample in samples:
                with open(sample, "r", encoding="utf-8") as f:
                    instance = json.load(f)

                if sample.stem == "valid" or sample.stem.startswith("valid"):
                    errors = validator.validate(instance)
                    self.assertEqual(
                        errors, [], f"{sample.name} should be valid: {[str(e) for e in errors]}"
                    )
                elif sample.stem in self.SEMANTIC_ONLY_INVALID:
                    # Schema-valid but rejected by the semantic usage rules
                    errors = validator.validate(instance)
                    self.assertEqual(errors, [], f"{sample.name} should be schema-valid")
                    if schema_name == "usage":
                        with self.assertRaises(Exception):
                            parse_usage(instance)
                else:
                    errors = validator.validate(instance)
                    self.assertTrue(
                        len(errors) > 0, f"{sample.name} should be invalid but passed schema validation"
                    )

    def test_invalid_fixtures_cover_missing_and_unknown_fields(self):
        for schema_name in self.CORE_SCHEMAS:
            fixture_dir = self._fixture_dir(schema_name)
            self.assertTrue(
                (fixture_dir / "invalid_missing_field.json").exists(),
                f"{schema_name}: missing-field fixture required",
            )
            self.assertTrue(
                (fixture_dir / "invalid_unknown_field.json").exists(),
                f"{schema_name}: unknown-field fixture required",
            )

    def test_boolean_not_accepted_as_integer(self):
        """DSR-006: booleans are never valid integers."""
        schema = load_schema("task_spec")
        validator = SchemaValidator(schema)
        with open(self._fixture_dir("task_spec") / "valid_verify_spec.json", "r", encoding="utf-8") as f:
            instance = json.load(f)
        instance["requires_new_attempt"] = 1
        errors = validator.validate(instance)
        self.assertTrue(errors)
        # oneOf reports the branch mismatch; drill into the verify branch for
        # the precise boolean/integer type error (DSR-006).
        branch_validator = SchemaValidator(schema["$defs"]["verify_spec"], root_schema=schema)
        branch_errors = branch_validator.validate(instance)
        self.assertTrue(any("integer" in e.message for e in branch_errors))

    def test_task_spec_matches_real_enqueue_shapes(self):
        """DSR-073: the schema is the single source of the REAL contract.

        The three branch shapes must accept exactly the specs the service
        enqueue points construct (hunt / recon / verify incl. second opinion)
        and reject the pre-DSR-073 speculative shape (kind/unit_ids/packet_
        digest/limits) that was never validated.
        """
        schema = load_schema("task_spec")
        validator = SchemaValidator(schema)

        hunt_spec = {
            "schema_version": "1.0", "task_kind": "hunt", "snapshot_id": "snp-1",
            "unit": {"unit_id": "unit-1", "ranges": []},
        }
        recon_spec = {
            "schema_version": "1.0", "task_kind": "recon", "role": "hunt",
            "snapshot_id": "snp-1", "unit": {"unit_id": "recon-1", "ranges": []},
            "language_index": ["- py-01: x"], "base_language_index": [],
            "knowledge_hints": {
                "primary_language": "python",
                "languages_in_scope": ["python"],
                "catalog_languages": ["python"],
            },
        }
        verify_spec = {
            "schema_version": "1.0", "task_kind": "verify", "role": "verify",
            "verify_task_id": "vt-1", "candidate_id": "cand-1",
            "output_contract": "verdict", "requires_new_attempt": True,
            "input": {"candidate": {"candidate_id": "cand-1"}},
            "second_opinion": True, "target_finding_id": "F-1",
            "target_severity": "High",
        }
        for spec in (hunt_spec, recon_spec, verify_spec):
            self.assertEqual(validator.validate(spec), [], str(spec))

        # The retired speculative shape (never produced by any enqueue point)
        # must be rejected by every branch.
        legacy = {
            "schema_version": "1.0", "kind": "hunt", "unit_ids": ["u-1"],
            "packet_digest": "a" * 64, "priority": 10,
            "limits": {"max_candidates": 5, "timeout_seconds": 120},
        }
        errors = validator.validate(legacy)
        self.assertTrue(any(e.keyword == "oneOf" for e in errors))

        # A hunt spec cannot masquerade as recon/verify: exactly one branch.
        cross = dict(recon_spec, task_kind="hunt")
        self.assertTrue(validator.validate(cross))


class TestMetaSchema(unittest.TestCase):
    """The meta schema captures the supported keyword subset (DSR-007)."""

    def setUp(self):
        with open(SCHEMAS_DIR / "meta.schema.json", "r", encoding="utf-8") as f:
            self.meta_schema = json.load(f)
        # The meta schema itself must use only supported keywords
        SchemaValidator(self.meta_schema)
        self.meta_validator = SchemaValidator(self.meta_schema)

    def test_all_production_schemas_conform_to_meta_schema(self):
        schema_files = sorted(SCHEMAS_DIR.glob("*.schema.json"))
        self.assertGreaterEqual(len(schema_files), 20, "expected all 20 production schemas")

        for path in schema_files:
            with open(path, "r", encoding="utf-8") as f:
                schema = json.load(f)
            errors = self.meta_validator.validate(schema)
            self.assertEqual(
                errors, [], f"{path.name} does not conform to the meta schema: {[str(e) for e in errors]}"
            )

    def test_meta_schema_rejects_unsupported_keyword(self):
        bad_schema = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {
                "when": {"type": "string", "format": "date-time"},
            },
        }
        errors = self.meta_validator.validate(bad_schema)
        self.assertTrue(
            any(e.keyword == "additionalProperties" and "format" in e.path for e in errors),
            f"expected 'format' to be rejected, got {[str(e) for e in errors]}",
        )

    def test_validator_rejects_unsupported_keyword_at_construction(self):
        """Fail-closed double check: the validator itself refuses unknown keywords."""
        with self.assertRaises(UnsupportedSchemaError):
            SchemaValidator({"type": "object", "dependencies": {"a": ["b"]}})

    def test_meta_schema_self_conformance(self):
        """The meta schema validates against itself."""
        errors = self.meta_validator.validate(self.meta_schema)
        self.assertEqual(errors, [], f"meta schema not self-conformant: {[str(e) for e in errors]}")


if __name__ == "__main__":
    unittest.main()
