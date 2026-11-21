"""Real-run output shape regressions, abstracted from RUN-LESSONS L-04/L-06/L-07/O-01.

Six real-run defect rounds all came from shapes the synthetic fixtures never
produced (RUN-LESSONS.md §4.1). This suite pins the *output shapes* of real
models against the hunter parser and the packet builder, using only fictional
paths (example-service/sample-web/...) and synthetic prose. No real project
content is reproduced here.

Covered lessons:
- L-04  prose-wrapped / non-list worker payload fields (hunter layer only;
        the fenced-vs-prose JSON extractor itself lives in the host adapter
        and is owned elsewhere).
- L-06  coverage entries / ranges missing required fields: the worker_result
        schema must reject them with an exact field path.
- L-07  endpoints (candidate.source / sink) as bare strings: classified into
        the candidate contract so existing guards reject them explicitly,
        never a crash.
- O-01  packet rendering of real units: string range anchors, oversized
        content, string/None guard summaries and indexes must render, degrade
        honestly, or record an overflow gap -- never raise AttributeError.
"""

import json
import unittest
from pathlib import Path

from auditkit.analysis.hunter import HuntResultParser
from auditkit.analysis.packets import PacketBuilder
from auditkit.contracts.errors import InvalidInputError
from auditkit.contracts.schema_validator import SchemaValidator

_REPO_ROOT = Path(__file__).resolve().parents[2]
_WORKER_RESULT_SCHEMA = _REPO_ROOT / "skill" / "schemas" / "worker_result.schema.json"

# Synthetic, fictional packet unit and contents (no real project material).
UNIT = {
    "schema_version": "1.0",
    "unit_id": "unit-example-0001",
    "snapshot_id": "snp-example",
    "component": "sample-web",
    "language": "typescript",
    "ranges": [
        {
            "path": "example-service/sample-web/handler.ts",
            "line_start": 1,
            "line_end": 3,
        }
    ],
    "tier": "T1",
    "disposition": "analyze",
}
CONTENTS = {
    "example-service/sample-web/handler.ts": (
        "import { loadSession } from './session';\n"
        "export function handle(req) { return loadSession(req.query.token); }\n"
    )
}


def _envelope(coverage, schema_version="1.0", kind="hunt"):
    """Build a minimal worker_result envelope for schema validation."""
    envelope = {
        "task_id": "task-example-0001",
        "attempt_id": "att-example-0001",
        "kind": kind,
        "records": [],
        "overflow": [],
        "coverage": coverage,
    }
    if schema_version is not None:
        envelope["schema_version"] = schema_version
    return envelope


class TestProsePayloadShapesHunterLayer(unittest.TestCase):
    """L-04 shape family at the hunter layer (extraction itself is adapter-owned).

    RUN-LESSONS L-04: the real model wrapped its JSON in prose ("All checks
    done.\n\n{...}") and the extractor only accepted fenced blocks. The
    adapter-side extraction is out of this suite's ownership; what must hold
    HERE is that whichever payload shape survives extraction reaches the
    hunter without crashing and stays visible.
    """

    def test_records_field_as_prose_string_is_kept_visible(self):
        """L-04: ``records`` arriving as one prose string, not a list."""
        parser = HuntResultParser()
        raw = {
            "records": "All checks done. No reachable sinks in example-service.",
        }
        candidates, frontiers, probes, overflows = parser.parse_worker_payload(raw, "task-p1")
        self.assertEqual(frontiers, [])
        self.assertEqual(probes, [])
        self.assertEqual(len(candidates), 1, "prose payload must not vanish silently")
        self.assertEqual(
            candidates[0]["record_raw"],
            "All checks done. No reachable sinks in example-service.",
        )
        self.assertEqual(candidates[0]["record_raw_type"], "str")
        # Downstream dict-based guards stay crash-free: records stay dicts.
        self.assertIsInstance(candidates[0], dict)

    def test_records_field_as_mapping_yields_values(self):
        """L-04 family: ``records`` as an id->record mapping."""
        parser = HuntResultParser()
        raw = {
            "records": {
                "r1": {
                    "record_type": "candidate",
                    "source": {"path": "example-service/lib/db.ts", "line": 4},
                    "sink": {"path": "example-service/lib/exec.ts", "line": 9},
                }
            }
        }
        candidates, _, _, _ = parser.parse_worker_payload(raw, "task-p2")
        self.assertEqual(len(candidates), 1)
        self.assertEqual(
            candidates[0]["source"], {"path": "example-service/lib/db.ts", "line": 4}
        )
        self.assertTrue(candidates[0]["candidate_id"])

    def test_non_object_payload_is_kept_visible_not_fatal(self):
        """L-04 family: extraction handed through a bare non-object payload."""
        parser = HuntResultParser()
        candidates, frontiers, probes, overflows = parser.parse_worker_payload(
            "audit finished, nothing found", "task-p3"
        )
        self.assertEqual(frontiers, [])
        self.assertEqual(probes, [])
        self.assertEqual(overflows, [])
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["record_raw"], "audit finished, nothing found")

    def test_overflow_entries_as_strings_stay_dict_shaped(self):
        """L-04/O-01: string overflow entries must stay consumable downstream.

        The service fan-out reads dimension/estimated_count/reason off every
        overflow entry; a verbatim string would crash that fan-out, so the
        parser wraps it while preserving the raw value.
        """
        parser = HuntResultParser()
        raw = {
            "records": [],
            "overflow": "unit exceeded the 16000 character packet budget",
        }
        _, _, _, overflows = parser.parse_worker_payload(raw, "task-p4")
        self.assertEqual(len(overflows), 1)
        self.assertIsInstance(overflows[0], dict)
        self.assertEqual(overflows[0]["overflow_raw"], "unit exceeded the 16000 character packet budget")
        self.assertTrue(overflows[0]["reason"])
        # The exact keys the downstream event fan-out reads.
        for key in ("dimension", "estimated_count", "reason"):
            self.assertIn(key, overflows[0])


class TestStringEndpointCandidates(unittest.TestCase):
    """L-07: candidate.source as a bare string -> candidate, never a crash.

    RUN-LESSONS L-07: the real model emitted ``"source": "path/to/x.py"`` and
    the classifier crashed on dict-only access. String endpoints must land in
    the candidate bucket so the existing contract / dedup guards reject them
    with a located error (existing rejection semantics preserved).
    """

    def test_source_as_bare_string_is_classified_candidate(self):
        parser = HuntResultParser()
        raw = {
            "records": [
                {
                    "source": "example-service/sample-web/handler.ts",
                    "sink": {"path": "example-service/lib/exec.ts", "line": 9},
                }
            ]
        }
        candidates, frontiers, probes, _ = parser.parse_worker_payload(raw, "task-s1")
        self.assertEqual(len(candidates), 1, "string source must become a candidate")
        self.assertEqual(frontiers, [])
        self.assertEqual(probes, [], "a record carrying a source is no dangling sink")
        self.assertEqual(candidates[0]["source"], "example-service/sample-web/handler.ts")

    def test_both_endpoints_as_strings_is_classified_candidate(self):
        parser = HuntResultParser()
        raw = {
            "records": [
                {
                    "source": "sample-web/utils/session.ts",
                    "sink": "sample-web/utils/exec.ts",
                }
            ]
        }
        candidates, frontiers, probes, _ = parser.parse_worker_payload(raw, "task-s2")
        self.assertEqual(len(candidates), 1)
        self.assertEqual(frontiers, [])
        self.assertEqual(probes, [])

    def test_sink_as_bare_string_without_source_is_candidate(self):
        parser = HuntResultParser()
        raw = {"records": [{"sink": "example-service/lib/exec.ts"}]}
        candidates, frontiers, probes, _ = parser.parse_worker_payload(raw, "task-s3")
        self.assertEqual(len(candidates), 1, "non-contract sink shape must be rejected via candidate contract")
        self.assertEqual(probes, [], "a string sink is not a usable dangling-sink probe")

    def test_explicit_unknown_record_kind_is_not_silently_dropped(self):
        """DSR-059: an unknown kind label must stay visible, never vanish."""
        parser = HuntResultParser()
        raw = {
            "records": [
                {
                    "record_type": "finding",
                    "issue": "synthetic: prototype member used as map key",
                    "source": {"path": "sample-web/utils/session.ts", "line": 2},
                    "sink": {"path": "sample-web/utils/exec.ts", "line": 5},
                }
            ]
        }
        candidates, frontiers, probes, _ = parser.parse_worker_payload(raw, "task-s4")
        self.assertEqual(len(candidates), 1, "unknown kind must not be dropped silently")
        self.assertEqual(frontiers, [])
        self.assertEqual(probes, [])

    def test_prose_string_record_is_wrapped_and_located(self):
        """L-07/O-01 family: a bare prose record must not crash rec.get()."""
        parser = HuntResultParser()
        raw = {
            "records": [
                "step 1: session token read in sample-web/utils/session.ts",
                {"record_type": "frontier", "source": {"path": "a.ts", "line": 1}},
            ]
        }
        candidates, frontiers, probes, _ = parser.parse_worker_payload(raw, "task-s5")
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["record_raw"], "step 1: session token read in sample-web/utils/session.ts")
        self.assertEqual(len(frontiers), 1, "well-formed sibling records still parse")

    def test_every_emitted_record_is_a_dict(self):
        """Contract shape guarantee: downstream dict guards can inspect safely."""
        parser = HuntResultParser()
        raw = {
            "records": [
                "prose",
                42,
                {"source": {"path": "a.ts"}, "sink": {"path": "b.ts"}},
            ],
            "overflow": [None, "cap text"],
        }
        candidates, frontiers, probes, overflows = parser.parse_worker_payload(raw, "task-s6")
        for record in candidates + frontiers + probes + overflows:
            self.assertIsInstance(record, dict)


class TestCoverageSchemaRejections(unittest.TestCase):
    """L-06: coverage/ranges missing fields are rejected with exact paths.

    RUN-LESSONS L-06: a real coverage range without path/line fields crashed
    the accounting loop, and worker_result.schema imposed no constraints on
    coverage/ranges. The schema now rejects them and the error must carry the
    field path (located rejection, SR-025).
    """

    @classmethod
    def setUpClass(cls):
        cls.validator = SchemaValidator(json.loads(_WORKER_RESULT_SCHEMA.read_text(encoding="utf-8")))

    def _coverage(self, ranges, **overrides):
        entry = {
            "snapshot_id": "snp-example",
            "unit_id": "unit-example-0001",
            "dimension": "observed_read",
            "ranges": ranges,
        }
        entry.update(overrides)
        return [entry]

    def test_valid_envelope_passes(self):
        errors = self.validator.validate(
            _envelope(
                self._coverage(
                    [{"path": "example-service/sample-web/handler.ts", "line_start": 1, "line_end": 3}]
                )
            )
        )
        self.assertEqual(errors, [])

    def test_range_missing_path_rejected_with_field_path(self):
        errors = self.validator.validate(_envelope(self._coverage([{"line_start": 1, "line_end": 3}])))
        self.assertTrue(errors, "range without path must be rejected (L-06)")
        joined = " | ".join(f"{e.path}: {e.message}" for e in errors)
        self.assertIn("coverage", joined)
        self.assertIn("ranges", joined)
        self.assertIn("path", joined)
        self.assertIn("#/coverage/0", joined)

    def test_envelope_missing_schema_version_rejected_with_field_path(self):
        errors = self.validator.validate(_envelope(self._coverage([]), schema_version=None))
        self.assertTrue(errors, "missing envelope schema_version must be rejected")
        joined = " | ".join(f"{e.path}: {e.message}" for e in errors)
        self.assertIn("schema_version", joined)

    def test_coverage_entry_missing_unit_id_rejected_with_field_path(self):
        errors = self.validator.validate(
            _envelope(self._coverage([], unit_id=None))
        )
        self.assertTrue(errors, "coverage entry without unit_id must be rejected (L-06)")
        joined = " | ".join(f"{e.path}: {e.message}" for e in errors)
        self.assertIn("#/coverage/0", joined)
        self.assertIn("unit_id", joined)

    def test_range_with_non_integer_line_bounds_rejected_with_field_path(self):
        errors = self.validator.validate(
            _envelope(
                self._coverage(
                    [{"path": "example-service/sample-web/handler.ts", "line_start": "one", "line_end": 3}]
                )
            )
        )
        self.assertTrue(errors, "string line bounds must be rejected (SR-025)")
        joined = " | ".join(f"{e.path}: {e.message}" for e in errors)
        self.assertIn("line_start", joined)


class TestOversizedAndOddUnitPackets(unittest.TestCase):
    """O-01: packet rendering of real-run unit shapes never raises.

    RUN-LESSONS O-01: fifteen packet_render_failed events, root cause
    ``AttributeError: 'str' object has no attribute 'get'`` — one real T1 unit
    burned all three attempts. Ranges/guards/indexes with string or None
    elements and oversized content must render, degrade with a located note,
    or record an overflow gap (DSR-059) — pagination/splitting remains the
    documented follow-up (RUN-LESSONS O-05).
    """

    def test_string_and_scalar_range_entries_render_without_attributeerror(self):
        builder = PacketBuilder()
        unit = dict(UNIT)
        unit["ranges"] = [
            "example-service/sample-web/handler.ts:1-40",  # bare string anchor
            {"path": "example-service/sample-web/handler.ts", "line_start": 1, "line_end": 3},
            None,  # null entry
            {"line_start": 1, "line_end": 2},  # missing path
            {"path": "sample-web/utils/session.ts", "line_start": "two", "line_end": 5},  # bad bounds
        ]
        packet, digest, overflow = builder.build_packet("hunt", "snp-example", unit, CONTENTS)
        self.assertIsNone(overflow)
        self.assertEqual(packet["role"], "hunt")
        self.assertTrue(digest)
        prompt = packet["prompt_text"]
        self.assertEqual(prompt.count("[degraded] range entry #"), 4)
        # The verbatim string anchor stays visible (no silent drop).
        self.assertIn("example-service/sample-web/handler.ts:1-40", prompt)
        self.assertIn("</untrusted_code>", prompt)

    def test_huge_unit_overflows_with_gap_record_not_crash(self):
        builder = PacketBuilder()
        huge = "const padding = 'x'; // synthetic filler line\n" * 3000
        unit = dict(UNIT)
        unit["ranges"] = [
            {"path": "example-service/sample-web/handler.ts", "line_start": 1, "line_end": 3000}
        ]
        contents = {"example-service/sample-web/handler.ts": huge}
        packet, digest, overflow = builder.build_hunt_packet("snp-example", unit, contents)
        self.assertIsNotNone(overflow, "capacity breach must record a gap (DSR-059)")
        self.assertEqual(overflow["dimension"], "packet_capacity")
        self.assertGreaterEqual(overflow["estimated_count"], 1)
        self.assertTrue(overflow["reason"])
        # Existing gap semantics: the oversized block is excluded and the gap
        # is explicit — the packet is still published (no silent truncation,
        # no fabricated partial block). Pagination is RUN-LESSONS O-05.
        self.assertNotIn("<untrusted_code", packet["prompt_text"])
        self.assertIsInstance(packet["packet_digest"], str)

    def test_ranges_as_bare_string_is_rendered_verbatim(self):
        builder = PacketBuilder()
        unit = dict(UNIT)
        unit["ranges"] = "example-service/sample-web/handler.ts whole file"
        packet, _, overflow = builder.build_packet("hunt", "snp-example", unit, CONTENTS)
        self.assertIsNone(overflow)
        self.assertIn("[degraded] ranges: ranges was str, not a list", packet["prompt_text"])
        self.assertIn("example-service/sample-web/handler.ts whole file", packet["prompt_text"])

    def test_ranges_as_mapping_renders_values(self):
        builder = PacketBuilder()
        unit = dict(UNIT)
        unit["ranges"] = {
            "anchor-1": {"path": "example-service/sample-web/handler.ts", "line_start": 1, "line_end": 3}
        }
        packet, _, _ = builder.build_packet("hunt", "snp-example", unit, CONTENTS)
        self.assertIn("[degraded] ranges: ranges was a mapping with 1 entries", packet["prompt_text"])
        self.assertIn('<untrusted_code path="example-service/sample-web/handler.ts"', packet["prompt_text"])

    def test_missing_file_content_marks_gap_instead_of_empty_block(self):
        builder = PacketBuilder()
        unit = dict(UNIT)
        unit["ranges"] = [
            {"path": "sample-web/utils/absent.ts", "line_start": 1, "line_end": 5}
        ]
        packet, _, _ = builder.build_packet("hunt", "snp-example", unit, CONTENTS)
        self.assertIn("[unavailable] no file content was supplied for this path", packet["prompt_text"])

    def test_file_contents_none_degrades_without_crash(self):
        builder = PacketBuilder()
        packet, _, _ = builder.build_packet("hunt", "snp-example", UNIT, None)
        self.assertIn("[degraded] file contents were None", packet["prompt_text"])
        self.assertIn("[unavailable] no file content", packet["prompt_text"])

    def test_unit_with_mixed_risk_factor_shapes_is_harmless(self):
        """O-01: real units carry risk_factors with mixed element shapes."""
        builder = PacketBuilder()
        unit = dict(UNIT)
        unit["risk_factors"] = ["tier-t1", "entrypoint", 42, None, {"signal": "auth"}]
        packet, _, _ = builder.build_packet("hunt", "snp-example", unit, CONTENTS)
        self.assertTrue(packet["prompt_text"])
        self.assertNotIn("Traceback", packet["prompt_text"])

    def test_unit_without_ranges_notes_the_gap(self):
        builder = PacketBuilder()
        unit = {k: v for k, v in UNIT.items() if k != "ranges"}
        packet, _, overflow = builder.build_packet("verify", "snp-example", unit, CONTENTS)
        self.assertIsNone(overflow)
        self.assertIn("[degraded] ranges: unit carries no ranges", packet["prompt_text"])

    def test_non_mapping_unit_is_rejected_explicitly(self):
        """O-01/L-07: a string unit must raise a located contract error, not
        AttributeError/TypeError from subscript access."""
        builder = PacketBuilder()
        with self.assertRaises(InvalidInputError) as ctx:
            builder.build_packet("hunt", "snp-example", "example-service/sample-web/handler.ts", CONTENTS)
        self.assertIn("unit", str(ctx.exception))

    def test_unit_without_unit_id_is_rejected_explicitly(self):
        builder = PacketBuilder()
        unit = {k: v for k, v in UNIT.items() if k != "unit_id"}
        with self.assertRaises(InvalidInputError):
            builder.build_packet("hunt", "snp-example", unit, CONTENTS)

    def test_well_formed_unit_produces_no_degradations(self):
        """Control: the hardened builder keeps well-formed packets clean."""
        builder = PacketBuilder()
        packet, digest, overflow = builder.build_hunt_packet("snp-example", UNIT, CONTENTS)
        self.assertIsNone(overflow)
        self.assertNotIn("[degraded]", packet["prompt_text"])
        self.assertIn("## Target Code under Review", packet["prompt_text"])

    def test_odd_units_render_deterministically(self):
        """Same odd input -> same digest (packet hashing stays deterministic)."""
        builder = PacketBuilder()
        unit = dict(UNIT)
        unit["ranges"] = ["example-service/sample-web/handler.ts:1-40", None]
        _, d1, _ = builder.build_packet("hunt", "snp-example", unit, CONTENTS)
        _, d2, _ = builder.build_packet("hunt", "snp-example", unit, CONTENTS)
        self.assertEqual(d1, d2)


class TestIndexAndReconShapes(unittest.TestCase):
    """O-01: language index shapes from real specs (L-07 family)."""

    def test_string_language_index_renders_one_line_not_per_character(self):
        """L-07 family: "\\n".join(<str>) used to explode into characters."""
        builder = PacketBuilder()
        packet, _, _ = builder.build_packet(
            "hunt", "snp-example", UNIT, CONTENTS, language_index="sink-hints: exec, eval"
        )
        prompt = packet["prompt_text"]
        self.assertIn("sink-hints: exec, eval", prompt)
        self.assertNotIn("s\ni\nn\nk", prompt, "string index must not explode per character")

    def test_dict_language_index_renders_pairs_with_degraded_note(self):
        builder = PacketBuilder()
        packet, _, _ = builder.build_packet(
            "hunt",
            "snp-example",
            UNIT,
            CONTENTS,
            language_index={"sample-web": ["hint-1", "hint-2"]},
        )
        prompt = packet["prompt_text"]
        self.assertIn("[degraded] language_index: expected a list of strings, got dict", prompt)
        self.assertIn("sample-web: [\"hint-1\", \"hint-2\"]", prompt)

    def test_scalar_language_index_degrades(self):
        builder = PacketBuilder()
        packet, _, _ = builder.build_packet("hunt", "snp-example", UNIT, CONTENTS, language_index=7)
        self.assertIn("[degraded] language_index", packet["prompt_text"])
        self.assertIn("7", packet["prompt_text"])

    def test_recon_language_indexes_as_list_is_used_as_index(self):
        builder = PacketBuilder()
        packet, _, _ = builder.build_recon_packet(
            "snp-example", UNIT, CONTENTS, language_indexes=["recon-hint-1", "recon-hint-2"]
        )
        self.assertIn("recon-hint-1", packet["prompt_text"])

    def test_recon_language_indexes_as_string_degrades_without_crash(self):
        builder = PacketBuilder()
        packet, _, _ = builder.build_recon_packet(
            "snp-example", UNIT, CONTENTS, language_indexes="recon-hints-as-prose"
        )
        self.assertIn("[degraded] language_indexes was str", packet["prompt_text"])
        self.assertNotIn("r\ne\nc\no\nn", packet["prompt_text"])

    def test_recon_selection_with_non_string_unit_language_does_not_crash(self):
        """O-01: a non-string (unhashable) unit language must not raise on the
        index-map lookup; the selection simply cannot succeed and the packet
        renders with the language value visible verbatim."""
        builder = PacketBuilder()
        unit = dict(UNIT)
        unit["language"] = {"name": "typescript", "tier": "T1"}
        packet, _, _ = builder.build_recon_packet(
            "snp-example",
            unit,
            CONTENTS,
            language_indexes={"typescript": ["ts-hint-1"]},
        )
        self.assertIn('"name": "typescript"', packet["prompt_text"])
        self.assertNotIn("ts-hint-1", packet["prompt_text"])
        self.assertTrue(packet["packet_digest"])

    def test_recon_selection_miss_keeps_packet_valid(self):
        builder = PacketBuilder()
        packet, _, _ = builder.build_recon_packet(
            "snp-example", UNIT, CONTENTS, language_indexes={"go": ["go-hint-1"]}
        )
        self.assertNotIn("go-hint-1", packet["prompt_text"])
        self.assertNotIn("[degraded]", packet["prompt_text"])


class TestGuardSummaryShapes(unittest.TestCase):
    """O-01: guard_summary None/string/mixed shapes degrade instead of crashing."""

    def test_none_guard_summary_omits_section(self):
        packet, _, _ = PacketBuilder().build_packet(
            "hunt", "snp-example", UNIT, CONTENTS, guard_summary=None
        )
        self.assertNotIn("Environment Guards", packet["prompt_text"])

    def test_empty_guard_summary_omits_section(self):
        packet, _, _ = PacketBuilder().build_packet(
            "hunt", "snp-example", UNIT, CONTENTS, guard_summary=""
        )
        self.assertNotIn("Environment Guards", packet["prompt_text"])

    def test_string_guard_summary_embedded(self):
        packet, _, _ = PacketBuilder().build_packet(
            "hunt",
            "snp-example",
            UNIT,
            CONTENTS,
            guard_summary="Environment Defense Baseline:\n- [OBSERVED] guard-example: input filter",
        )
        self.assertIn("Environment Guards", packet["prompt_text"])
        self.assertIn("guard-example: input filter", packet["prompt_text"])

    def test_dict_guard_summary_renders_verbatim_with_degraded_note(self):
        packet, _, _ = PacketBuilder().build_packet(
            "hunt",
            "snp-example",
            UNIT,
            CONTENTS,
            guard_summary={"guards": [{"guard_id": "guard-example", "status": "OBSERVED"}]},
        )
        prompt = packet["prompt_text"]
        self.assertIn("[degraded] guard_summary: expected a list of strings, got dict", prompt)
        self.assertIn("guard-example", prompt, "guard content stays visible verbatim")

    def test_list_guard_summary_renders_items(self):
        packet, _, _ = PacketBuilder().build_packet(
            "hunt",
            "snp-example",
            UNIT,
            CONTENTS,
            guard_summary=["[OBSERVED] guard-example: input filter", "[MISSING] guard-output-encode"],
        )
        prompt = packet["prompt_text"]
        self.assertIn("Environment Guards", prompt)
        self.assertIn("[OBSERVED] guard-example: input filter", prompt)
        self.assertIn("[MISSING] guard-output-encode", prompt)

    def test_scalar_guard_summary_degrades(self):
        packet, _, _ = PacketBuilder().build_packet(
            "hunt", "snp-example", UNIT, CONTENTS, guard_summary=3
        )
        self.assertIn("[degraded] guard_summary", packet["prompt_text"])

    def test_mixed_guard_shapes_across_calls_never_crash(self):
        """O-01: the exact real-run failure mode — a batch of renders where a
        single odd guard shape used to abort the whole batch."""
        builder = PacketBuilder()
        shapes = [None, "", "plain summary", {"a": 1}, ["x", "y"], 5, {"nested": {"b": 2}}]
        for shape in shapes:
            packet, digest, _ = builder.build_packet(
                "hunt", "snp-example", UNIT, CONTENTS, guard_summary=shape
            )
            self.assertTrue(packet["prompt_text"])
            self.assertTrue(len(digest) == 64)


class TestCandidateProvenanceShapes(unittest.TestCase):
    """Verify-spec construction against real-model candidate shapes.

    A real worker emitted candidate.provenance as a bare string; the
    unguarded ``candidate.get("provenance", {}).get(...)`` chain raised
    AttributeError through the submit path and killed the dispatch loop.
    The contract rejection must be an InvalidInputError (DSR-018 bounded
    retry family), never an AttributeError."""

    def _candidate(self, provenance):
        return {
            "candidate_id": "cand-1",
            "source": {"path": "sample-web/src/main.py", "line": 3},
            "sink": {"path": "sample-web/src/main.py", "line": 7},
            "provenance": provenance,
        }

    def test_provenance_as_bare_string_is_contract_rejected(self):
        from auditkit.analysis.verifier import Verifier

        with self.assertRaises(InvalidInputError) as ctx:
            Verifier().build_verify_task(self._candidate("hunt att-1 via task-2"))
        self.assertIn("provenance", str(ctx.exception))

    def test_provenance_missing_is_contract_rejected(self):
        from auditkit.analysis.verifier import Verifier

        cand = self._candidate({"hunt_tasks": ["task-1"]})
        del cand["provenance"]
        with self.assertRaises(InvalidInputError):
            Verifier().build_verify_task(cand)

    def test_provenance_as_contract_dict_is_accepted(self):
        from auditkit.analysis.verifier import Verifier

        spec = Verifier().build_verify_task(
            self._candidate({"hunt_tasks": ["task-1"], "snapshot_id": "snp-1"})
        )
        self.assertEqual(spec["role"], "verify")


if __name__ == "__main__":
    unittest.main()
