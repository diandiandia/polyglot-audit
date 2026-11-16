"""SWR-025 acceptance tests: versioned schemas, the standard-library schema
subset validator, and semantic rules.

验收原文 (docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2, SWR-025):
    "定义版本化 schema 及标准库子集校验器、语义规则；类型、条件字段、额外
    属性、超限、锚点和未知关键字反例失败。"

细化依据: DSR-009: "嵌套 required、额外属性、类型、enum、数组/字符串界限和
条件字段正反例通过，未知关键字报错。" DSR-010: "实现语义校验：anchor 范围/
摘要、跨 run 引用和条件 verdict；行超界、缺反证或伪 E3 均拒绝并返回字段
位置。" IFC-01: "不通过静态结构校验时不得产生成功结论。"

Covered here:
- Every production schema is versioned ($schema + $id, schema_version pinned
  to "1.0" by the contract) and uses only supported keywords.
- Type counterexamples fail with a locatable field path (nested included).
- Required/conditional-field counterexamples fail.
- additionalProperties counterexamples fail at the offending key path.
- Limit counterexamples (min/max, string length, item counts) fail with the
  keyword and path; booleans are not integers; NaN/Infinity rejected.
- Unknown schema keywords fail closed at construction time.
- Validation never silently repairs an invalid instance: the instance and
  the schema are left unmutated, and validate_or_raise refuses success.
- Anchor counterexamples (bounds, manifest existence, digest, line count)
  fail with the field position.
"""

import copy
import json
import unittest
from pathlib import Path

from auditkit.contracts.errors import InvalidInputError, UnsupportedSchemaError
from auditkit.contracts.schema_validator import SchemaValidator
from auditkit.contracts.semantic_validator import SemanticValidator

REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMAS_DIR = REPO_ROOT / "skill" / "schemas"


def _candidate_document():
    return {
        "schema_version": "1.0",
        "candidate_id": "cand-1",
        "issue": "py-01",
        "source": {
            "path": "app/handlers/upload.py", "line": 8,
            "symbol": "handle_upload", "kind": "http_body", "control": "body",
        },
        "sink": {
            "path": "app/storage/state.py", "line": 10,
            "symbol": "restore_state", "kind": "deserialization",
        },
        "steps": [
            {"path": "app/handlers/upload.py", "line": 8, "role": "source"},
            {"path": "app/storage/state.py", "line": 10, "role": "sink"},
        ],
        "guard_analysis": "no validation",
        "impact_claim": "rce",
        "open_questions": [],
        "provenance": {"hunt_tasks": ["task-1"]},
    }


class TestSWR025(unittest.TestCase):

    # -- versioned schemas ----------------------------------------------------
    def test_every_production_schema_is_versioned_and_declared(self):
        schema_files = sorted(SCHEMAS_DIR.glob("*.schema.json"))
        self.assertGreaterEqual(len(schema_files), 20)
        for path in schema_files:
            schema = json.loads(path.read_text(encoding="utf-8"))
            self.assertIn("$schema", schema, path.name)
            self.assertIn("$id", schema, path.name)
            self.assertTrue(schema["$id"].endswith(path.name), path.name)

    def test_data_contracts_pin_schema_version_const(self):
        """The contract version is pinned, not just declared."""
        for name in ("candidate", "finding", "rating", "anchor", "connection"):
            schema = json.loads((SCHEMAS_DIR / f"{name}.schema.json").read_text(encoding="utf-8"))
            version_schema = schema.get("properties", {}).get("schema_version", {})
            self.assertEqual(
                version_schema.get("const"), "1.0",
                f"{name}.schema.json must pin schema_version to 1.0",
            )

    def _candidate_validator(self):
        return SchemaValidator(
            json.loads((SCHEMAS_DIR / "candidate.schema.json").read_text(encoding="utf-8"))
        )

    # -- type counterexamples with field paths --------------------------------
    def test_type_counterexamples_fail_with_field_path(self):
        validator = self._candidate_validator()

        base = _candidate_document()
        base["source"]["line"] = "eight"  # string where integer required
        errors = validator.validate(base)
        self.assertTrue(errors)
        self.assertIn("#/source/line", [e.path for e in errors])
        self.assertIn("type", [e.keyword for e in errors])

        nested_list = _candidate_document()
        nested_list["provenance"] = {"hunt_tasks": "task-1"}  # not an array
        errors2 = validator.validate(nested_list)
        self.assertTrue(errors2)
        self.assertIn("#/provenance/hunt_tasks", [e.path for e in errors2])

        wrong_top = _candidate_document()
        wrong_top["steps"] = {"0": "step"}  # object where array required
        errors3 = validator.validate(wrong_top)
        self.assertTrue(errors3)
        self.assertIn("#/steps", [e.path for e in errors3])

    def test_boolean_is_not_an_integer(self):
        validator = self._candidate_validator()
        doc = _candidate_document()
        doc["source"]["line"] = True  # bool is an int subclass in Python
        errors = validator.validate(doc)
        self.assertTrue(
            any(e.path == "#/source/line" and e.keyword == "type" for e in errors),
            [(e.path, e.keyword) for e in errors],
        )

    def test_nan_and_infinity_are_rejected(self):
        schema = {
            "type": "object",
            "properties": {"score": {"type": "number"}},
            "additionalProperties": False,
        }
        validator = SchemaValidator(schema)
        for bad in (float("nan"), float("inf"), -float("inf")):
            errors = validator.validate({"score": bad})
            self.assertTrue(
                any("NaN" in e.message or "Infinity" in e.message for e in errors),
                bad,
            )

    # -- required / conditional field counterexamples --------------------------
    def test_required_field_counterexamples_fail_with_path(self):
        validator = self._candidate_validator()
        doc = _candidate_document()
        del doc["impact_claim"]
        errors = validator.validate(doc)
        self.assertTrue(errors)
        missing = [e for e in errors if e.keyword == "required"]
        self.assertTrue(missing)
        self.assertIn("impact_claim", missing[0].message)

        nested = _candidate_document()
        del nested["source"]["control"]
        errors2 = validator.validate(nested)
        self.assertTrue(
            any("control" in e.message and e.keyword == "required" for e in errors2),
            [(e.path, e.message) for e in errors2],
        )

    def test_conditional_verdict_fields_fail_on_semantic_side(self):
        """Conditional requirements (verdict -> fields) are enforced."""
        validator = SemanticValidator()
        with self.assertRaises(InvalidInputError) as ctx:
            validator.validate_finding({
                "schema_version": "1.0",
                "finding_id": "F-1",
                "verdict": "needs_validation",
                "evidence_level": "E1",
                # missing blockers + validation_plan
            })
        self.assertIn("blockers", str(ctx.exception))
        with self.assertRaises(InvalidInputError) as ctx2:
            validator.validate_finding({
                "schema_version": "1.0",
                "finding_id": "F-2",
                "verdict": "rejected",
                "evidence_level": "E1",
            })
        self.assertIn("counter_evidence", str(ctx2.exception))

    # -- additionalProperties counterexamples ----------------------------------
    def test_additional_property_counterexamples_fail_at_key_path(self):
        validator = self._candidate_validator()
        doc = _candidate_document()
        doc["remediation_hint"] = "trust me, it is fine"  # not in the contract
        errors = validator.validate(doc)
        self.assertTrue(errors)
        self.assertIn("#/remediation_hint", [e.path for e in errors])
        self.assertIn("additionalProperties", [e.keyword for e in errors])

        nested_extra = _candidate_document()
        nested_extra["source"]["bypass"] = True
        errors2 = validator.validate(nested_extra)
        self.assertIn("#/source/bypass", [e.path for e in errors2])

    # -- limit counterexamples --------------------------------------------------
    def test_limit_counterexamples_fail_with_keyword_and_path(self):
        schema = {
            "type": "object",
            "required": ["id", "tags", "score", "name"],
            "additionalProperties": False,
            "properties": {
                "id": {"type": "string", "minLength": 3, "maxLength": 8},
                "tags": {"type": "array", "minItems": 1, "maxItems": 2,
                         "items": {"type": "string"}},
                "score": {"type": "integer", "minimum": 1, "maximum": 4},
                "name": {"type": "string", "pattern": "^[a-z]+$"},
            },
        }
        validator = SchemaValidator(schema)

        doc = {"id": "toolongidentifier", "tags": [], "score": 1, "name": "abc"}
        errors = validator.validate(doc)
        self.assertIn("maxLength", [e.keyword for e in errors])
        self.assertIn("#/id", [e.path for e in errors])
        self.assertIn("minItems", [e.keyword for e in errors])
        self.assertIn("#/tags", [e.path for e in errors])

        doc2 = {"id": "ok", "tags": ["a", "b", "c"], "score": 5, "name": "abc"}
        errors2 = validator.validate(doc2)
        self.assertIn("maxItems", [e.keyword for e in errors2])
        self.assertIn("maximum", [e.keyword for e in errors2])
        self.assertIn("#/score", [e.path for e in errors2])

        doc3 = {"id": "ok", "tags": ["a"], "score": 0, "name": "UPPER"}
        errors3 = validator.validate(doc3)
        self.assertIn("minimum", [e.keyword for e in errors3])
        self.assertIn("pattern", [e.keyword for e in errors3])

        # uniqueItems counterexample.
        schema_u = {
            "type": "object",
            "properties": {"items": {"type": "array", "uniqueItems": True}},
        }
        errors4 = SchemaValidator(schema_u).validate({"items": [{"a": 1}, {"a": 1}]})
        self.assertIn("uniqueItems", [e.keyword for e in errors4])

    def test_semantic_factor_bounds_are_enforced_with_position(self):
        validator = SemanticValidator()
        for bad in (0, 5):
            rating = {
                "impact": bad, "exploitability": 3,
                "factor_reasons": {"impact_why": "i", "exploitability_why": "e"},
                "calculated_severity": "High", "calculated_urgency": "P1",
                "final_severity": "High", "final_urgency": "P1",
            }
            with self.assertRaises(InvalidInputError) as ctx:
                validator.validate_rating(rating, is_confirmed=True)
            self.assertIn("rating.impact", str(ctx.exception))

    # -- unknown keywords fail closed -------------------------------------------
    def test_unknown_schema_keyword_fails_at_construction(self):
        for keyword in ("if", "then", "dependencies", "not", "contains"):
            schema = {
                "type": "object",
                "properties": {"a": {"type": "string", keyword: True}},
            }
            with self.assertRaises(UnsupportedSchemaError) as ctx:
                SchemaValidator(schema)
            self.assertIn(keyword, str(ctx.exception))

    def test_unknown_keyword_error_locates_the_schema_path(self):
        schema = {
            "type": "object",
            "properties": {
                "child": {"type": "object", "unevaluatedProperties": False},
            },
        }
        with self.assertRaises(UnsupportedSchemaError) as ctx:
            SchemaValidator(schema)
        details = getattr(ctx.exception, "details", None) or {}
        self.assertIn("unevaluatedProperties", str(details) + str(ctx.exception))
        self.assertIn("child", str(details) + str(ctx.exception))

    def test_only_local_refs_are_supported(self):
        """Non-local $ref fails closed (resolution happens at validate time)."""
        validator = SchemaValidator({"$ref": "https://elsewhere.invalid/schema.json"})
        with self.assertRaises(UnsupportedSchemaError) as ctx:
            validator.validate({"a": 1})
        self.assertIn("Only local references", str(ctx.exception))
        dangling = SchemaValidator({"$ref": "#/does/not/exist"})
        with self.assertRaises(UnsupportedSchemaError):
            dangling.validate({"a": 1})

    # -- no silent repair --------------------------------------------------------
    def test_invalid_instance_is_not_silently_repaired(self):
        """校验失败不得静默修复: validation never mutates instance or schema."""
        validator = self._candidate_validator()
        doc = _candidate_document()
        doc["source"]["line"] = "eight"
        schema_snapshot = copy.deepcopy(validator.schema)
        doc_snapshot = copy.deepcopy(doc)
        errors = validator.validate(doc)
        self.assertTrue(errors)
        self.assertEqual(doc, doc_snapshot, "instance must not be mutated")
        self.assertEqual(validator.schema, schema_snapshot, "schema must not be mutated")
        self.assertEqual(doc["source"]["line"], "eight")

        with self.assertRaises(InvalidInputError):
            validator.validate_or_raise(doc)

        # A verdict that cannot be interpreted is refused, not coerced.
        with self.assertRaises(InvalidInputError):
            SemanticValidator().validate_finding({
                "schema_version": "1.0",
                "finding_id": "F-9",
                "verdict": "probably",
                "evidence_level": "E2",
            })

    # -- anchor counterexamples ---------------------------------------------------
    MANIFEST = {
        "files": [
            {"path": "app/main.py", "sha256": "a" * 64, "line_count": 40},
            {"path": "lib/util.py", "sha256": "b" * 64, "line_count": 5},
        ]
    }

    def _anchor(self, **overrides):
        anchor = {
            "path": "app/main.py",
            "line_start": 10,
            "line_end": 20,
            "file_sha256": "a" * 64,
        }
        anchor.update(overrides)
        return anchor

    def test_anchor_counterexamples_fail_with_field_position(self):
        validator = SemanticValidator(manifest=self.MANIFEST)

        with self.assertRaises(InvalidInputError) as ctx:
            validator.validate_anchor(self._anchor(line_start=0))
        self.assertIn("line_start", str(ctx.exception))

        with self.assertRaises(InvalidInputError) as ctx2:
            validator.validate_anchor(self._anchor(line_start=20, line_end=10))
        self.assertIn("line_end", str(ctx2.exception))

        with self.assertRaises(InvalidInputError) as ctx3:
            validator.validate_anchor(self._anchor(path="absent/file.py"))
        self.assertIn("does not exist in snapshot manifest", str(ctx3.exception))
        self.assertIn("absent/file.py", str(ctx3.exception))

        with self.assertRaises(InvalidInputError) as ctx4:
            validator.validate_anchor(self._anchor(file_sha256="c" * 64))
        self.assertIn("mismatch", str(ctx4.exception))

        with self.assertRaises(InvalidInputError) as ctx5:
            validator.validate_anchor(self._anchor(line_end=41))
        self.assertIn("exceeds file line count", str(ctx5.exception))

    def test_valid_anchor_passes_and_cross_run_refs_fail_located(self):
        validator = SemanticValidator(
            manifest=self.MANIFEST, current_run_id="run-current"
        )
        validator.validate_anchor(self._anchor())  # must not raise

        with self.assertRaises(InvalidInputError) as ctx:
            validator.validate_run_references(
                {"finding_id": "F-1", "run_id": "run-old"}, path="finding"
            )
        self.assertIn("run-old", str(ctx.exception))
        self.assertIn("finding.run_id", str(ctx.exception))
        details = getattr(ctx.exception, "details", None) or {}
        self.assertEqual(details.get("path"), "finding.run_id")

    def test_semantic_validator_without_manifest_checks_bounds_only(self):
        validator = SemanticValidator()
        validator.validate_anchor(self._anchor(line_end=10 ** 6))  # bounds only


if __name__ == "__main__":
    unittest.main()
