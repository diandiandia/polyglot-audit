"""Typed-contract alignment tests (DSR-073 / IFC-02).

Every TypedDict in auditkit.contracts.types is bound to its JSON schema via an
explicit mapping table and mechanically checked to stay aligned:

- every TypedDict key is declared by the bound schema's properties (no typed
  field exists that the interchange contract does not define);
- every schema-required field exists in the TypedDict (no required contract
  field is missing from the typing layer);
- every TypedDict stays total=False (typing-only optionality; requiredness
  belongs to the schemas and runtime validators);
- the TaskSpec union alias covers exactly the three task_spec.schema.json
  oneOf branches.

This prevents the typed layer from drifting away from the schemas again: a
schema field rename or a new required field fails these tests until the
TypedDict is updated (and vice versa).
"""

import json
import unittest
from pathlib import Path
from typing import get_args

from auditkit.contracts import types

REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMAS_DIR = REPO_ROOT / "skill" / "schemas"

# Mapping table: (TypedDict name, schema file, pointer path into the schema
# JSON identifying the bound subschema). A pointer of [] binds the schema's
# top-level object; nested pointers bind $defs branches or property/item
# subschemas.
TYPED_CONTRACT_MAP = [
    # Shared / nested shapes
    ("Anchor", "anchor.schema.json", []),
    ("Step", "candidate.schema.json", ["properties", "steps", "items"]),
    ("CoverageRange", "coverage_observation.schema.json", ["properties", "ranges", "items"]),
    # Task specification branches (task_spec oneOf)
    ("HuntTaskSpec", "task_spec.schema.json", ["$defs", "hunt_spec"]),
    ("ReconTaskSpec", "task_spec.schema.json", ["$defs", "recon_spec"]),
    ("VerifyTaskSpec", "task_spec.schema.json", ["$defs", "verify_spec"]),
    ("PacketUnit", "task_spec.schema.json", ["$defs", "packet_unit"]),
    (
        "KnowledgeHints",
        "task_spec.schema.json",
        ["$defs", "recon_spec", "properties", "knowledge_hints"],
    ),
    # IFC-02 exchange objects
    ("Budget", "budget.schema.json", []),
    ("Capability", "capability.schema.json", []),
    (
        "CapabilityFeature",
        "capability.schema.json",
        ["properties", "features", "additionalProperties"],
    ),
    ("Claim", "claim.schema.json", []),
    ("Connection", "connection.schema.json", []),
    ("CoverageObservation", "coverage_observation.schema.json", []),
    ("ErrorEnvelope", "error.schema.json", []),
    ("Frontier", "frontier.schema.json", []),
    ("SinkProbe", "sink_probe.schema.json", []),
    ("GateCheckData", "gate_result.schema.json", ["properties", "checks", "items"]),
    ("GateResultData", "gate_result.schema.json", []),
    ("Guard", "guard.schema.json", []),
    ("RunScope", "run_config.schema.json", ["properties", "scope"]),
    ("SafetyAcceptance", "run_config.schema.json", ["properties", "safety_acceptance"]),
    ("RunConfig", "run_config.schema.json", []),
    ("SnapshotFileEntry", "snapshot_manifest.schema.json", ["properties", "files", "items"]),
    ("SnapshotManifest", "snapshot_manifest.schema.json", []),
    ("Unit", "unit.schema.json", []),
    # Pipeline objects
    ("Candidate", "candidate.schema.json", []),
    ("Usage", "usage.schema.json", []),
    ("Finding", "finding.schema.json", []),
]


def _load_schema(name: str) -> dict:
    with open(SCHEMAS_DIR / name, "r", encoding="utf-8") as f:
        return json.load(f)


def _resolve_pointer(schema: dict, pointer: list) -> dict:
    node = schema
    for key in pointer:
        node = node[key]
    return node


class TestTypedContractAlignment(unittest.TestCase):
    """Every TypedDict stays key-aligned with its JSON schema (DSR-073)."""

    def test_mapping_table_covers_the_whole_typed_module(self):
        # The table is the single alignment source of truth: every TypedDict
        # exported by the module must be bound to a schema through it.
        mapped = {name for name, _schema, _pointer in TYPED_CONTRACT_MAP}
        exported = {
            name
            for name in vars(types)
            if isinstance(getattr(types, name), type)
            and issubclass(getattr(types, name), dict)
            and hasattr(getattr(types, name), "__annotations__")
        }
        self.assertEqual(
            exported - mapped,
            set(),
            f"TypedDicts missing from the alignment table: {sorted(exported - mapped)}",
        )
        # ...and every mapped name really exists on the module.
        self.assertEqual(mapped - exported, set())

    def test_every_typed_dict_is_total_false(self):
        for name, _schema, _pointer in TYPED_CONTRACT_MAP:
            with self.subTest(typeddict=name):
                cls = getattr(types, name)
                self.assertFalse(cls.__total__, f"{name} must stay total=False")

    def test_keys_align_with_schema_properties_and_required(self):
        for name, schema_name, pointer in TYPED_CONTRACT_MAP:
            with self.subTest(typeddict=name, schema=schema_name):
                cls = getattr(types, name)
                subschema = _resolve_pointer(_load_schema(schema_name), pointer)
                typed_keys = set(cls.__annotations__.keys())
                schema_props = set(subschema.get("properties", {}).keys())
                schema_required = set(subschema.get("required", []))

                undeclared = typed_keys - schema_props
                self.assertEqual(
                    undeclared,
                    set(),
                    f"{name} declares keys the schema does not: {sorted(undeclared)}",
                )
                missing = schema_required - typed_keys
                self.assertEqual(
                    missing,
                    set(),
                    f"{name} is missing schema-required keys: {sorted(missing)}",
                )

    def test_task_spec_union_covers_exactly_the_schema_branches(self):
        # TaskSpec is a Union alias (not a TypedDict class) and its args are
        # exactly the three task_spec.schema.json oneOf branches.
        self.assertNotIsInstance(types.TaskSpec, type)
        self.assertEqual(
            set(get_args(types.TaskSpec)),
            {types.HuntTaskSpec, types.ReconTaskSpec, types.VerifyTaskSpec},
        )

    def test_task_spec_branches_match_schema_discriminators(self):
        # The branch discriminators (const fields in the schema) are typed.
        self.assertIn("task_kind", types.HuntTaskSpec.__annotations__)
        self.assertIn("task_kind", types.ReconTaskSpec.__annotations__)
        self.assertIn("task_kind", types.VerifyTaskSpec.__annotations__)
        # The retired speculative TaskSpec shape must not reappear.
        retired = {"kind", "unit_ids", "packet_digest", "priority", "limits"}
        for branch in (types.HuntTaskSpec, types.ReconTaskSpec, types.VerifyTaskSpec):
            self.assertEqual(retired & set(branch.__annotations__.keys()), set())


class TestTypedContractsStayUsable(unittest.TestCase):
    """The typed layer must not break existing runtime consumers."""

    def test_usage_annotation_round_trip(self):
        # ledger.usage.to_dict() is annotated -> Usage; the keys it emits must
        # stay within the typed contract.
        usage: types.Usage = {
            "schema_version": "1.0",
            "attempt_id": "att-1",
            "dimension": "tokens",
            "availability": "unavailable",
            "unit": "tokens",
            "source": "service",
            "reason": "no host usage block",
        }
        self.assertEqual(set(usage.keys()) - set(types.Usage.__annotations__.keys()), set())

    def test_claim_annotation_round_trip(self):
        claim: types.Claim = {
            "schema_version": "1.0",
            "run_id": "run-1",
            "task_id": "task-1",
            "attempt_id": "att-1",
            "generation": 1,
            "claim_token": "tok",
            "expires_at": "2026-01-01T00:00:00+00:00",
            "packet_ref": "tasks/task-1/packet.json",
            "spec": {"schema_version": "1.0", "task_kind": "hunt"},
        }
        self.assertEqual(set(claim.keys()) - set(types.Claim.__annotations__.keys()), set())

    def test_gate_result_annotation_round_trip(self):
        gate: types.GateResultData = {
            "schema_version": "1.0",
            "gate_id": "G4",
            "status": "pass",
            "checks": [
                {
                    "check_id": "G4-1",
                    "name": "Report Gate",
                    "status": "pass",
                    "message": "ok",
                }
            ],
            "revision": 3,
        }
        self.assertEqual(
            set(gate.keys()) - set(types.GateResultData.__annotations__.keys()), set()
        )
        for check in gate["checks"]:
            self.assertEqual(
                set(check.keys()) - set(types.GateCheckData.__annotations__.keys()), set()
            )


if __name__ == "__main__":
    unittest.main()
