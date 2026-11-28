"""DSR-024 recon packets and DSR-059 task roles in prompt packets."""

import unittest

from auditkit.analysis.packets import PacketBuilder
from auditkit.contracts.errors import InvalidInputError


UNIT = {
    "unit_id": "u-recon",
    "language": "python",
    "ranges": [{"path": "app.py", "line_start": 1, "line_end": 3}],
}
CONTENTS = {"app.py": "import os\nos.system(cmd)\n"}


class TestPacketRoles(unittest.TestCase):

    def test_hunt_role_declared_in_header(self):
        packet, digest, overflow = PacketBuilder().build_hunt_packet("snp-1", UNIT, CONTENTS)
        self.assertEqual(packet["role"], "hunt")
        self.assertEqual(packet["task_kind"], "hunt")
        self.assertIn("Role: hunt", packet["prompt_text"])
        self.assertIn("Output Contract:", packet["prompt_text"])
        # Hunt-distinct contract: the three hunt record types plus the
        # structured source/sink mandate (never plain strings).
        self.assertIn("candidate|frontier|sink_probe", packet["output_contract"])
        self.assertIn("source and sink MUST be objects", packet["output_contract"])

    def test_verify_role_declared_in_header(self):
        packet, _, _ = PacketBuilder().build_packet("verify", "snp-1", UNIT, CONTENTS)
        self.assertEqual(packet["role"], "verify")
        self.assertEqual(packet["task_kind"], "verify")
        self.assertIn("Role: verify", packet["prompt_text"])
        self.assertIn("confirmed", packet["output_contract"])

    def test_triage_role_declared_in_header(self):
        packet, _, _ = PacketBuilder().build_packet("triage", "snp-1", UNIT, CONTENTS)
        self.assertEqual(packet["role"], "triage")
        self.assertIn("candidate_created", packet["output_contract"])
        self.assertIn("pending", packet["prompt_text"])

    def test_invalid_role_rejected(self):
        with self.assertRaises(InvalidInputError):
            PacketBuilder().build_packet("recon_extra", "snp-1", UNIT, CONTENTS)

    def test_roles_produce_distinct_contracts(self):
        builder = PacketBuilder()
        hunt, _, _ = builder.build_packet("hunt", "snp-1", UNIT, CONTENTS)
        triage, _, _ = builder.build_packet("triage", "snp-1", UNIT, CONTENTS)
        self.assertNotEqual(hunt["output_contract"], triage["output_contract"])
        self.assertNotEqual(hunt["packet_digest"], triage["packet_digest"])


class TestReconPacket(unittest.TestCase):

    def test_recon_packet_selects_language_index_by_unit_language(self):
        builder = PacketBuilder()
        indexes = {
            "python": ["py-sink-1", "py-src-2"],
            "go": ["go-sink-1"],
        }
        packet, digest, overflow = builder.build_recon_packet(
            "snp-1", UNIT, CONTENTS, language_indexes=indexes
        )
        self.assertEqual(packet["task_kind"], "recon")
        self.assertIn("py-sink-1", packet["prompt_text"])
        self.assertNotIn("go-sink-1", packet["prompt_text"])

    def test_recon_packet_includes_guard_baseline_summary(self):
        packet, _, _ = PacketBuilder().build_recon_packet(
            "snp-1",
            UNIT,
            CONTENTS,
            guard_summary="Environment Defense Baseline:\n- [OBSERVED] g1: filter",
        )
        self.assertIn("Environment Guards", packet["prompt_text"])
        self.assertIn("g1: filter", packet["prompt_text"])

    def test_recon_packet_explicit_index_overrides_map(self):
        packet, _, _ = PacketBuilder().build_recon_packet(
            "snp-1",
            UNIT,
            CONTENTS,
            language_indexes={"python": ["auto-selected"]},
            language_index=["explicit-index"],
        )
        self.assertIn("explicit-index", packet["prompt_text"])
        self.assertNotIn("auto-selected", packet["prompt_text"])

    def test_recon_packet_overflow_same_pattern_as_hunt(self):
        builder = PacketBuilder(max_chars=200)
        unit = {
            "unit_id": "u-recon-big",
            "language": "python",
            "ranges": [{"path": "long.py", "line_start": 1, "line_end": 50}],
        }
        contents = {"long.py": "a = 1\n" * 100}
        packet, digest, overflow = builder.build_recon_packet("snp-1", unit, contents)
        self.assertIsNotNone(overflow)
        self.assertEqual(overflow["dimension"], "packet_capacity")
        self.assertGreaterEqual(overflow["estimated_count"], 1)
        self.assertTrue(overflow["reason"])

    def test_recon_packet_digest_deterministic(self):
        builder = PacketBuilder()
        p1, d1, _ = builder.build_recon_packet("snp-1", UNIT, CONTENTS)
        p2, d2, _ = builder.build_recon_packet("snp-1", UNIT, CONTENTS)
        self.assertEqual(d1, d2)
        self.assertEqual(p1["packet_digest"], d2)


if __name__ == "__main__":
    unittest.main()

    def test_unknown_language_packet_carries_generic_asset_guidance(self):
        """O-07: a unit whose language is outside the catalog gets a generic
        non-code asset guidance section (language-agnostic review strategy),
        while catalog-covered units do not."""
        from auditkit.analysis.packets import PacketBuilder
        unit_unknown = {
            "unit_id": "unit-example-u",
            "language": "unknown",
            "ranges": [{"path": "example-conf/app.conf", "line_start": 1, "line_end": 3}],
        }
        unit_known = dict(unit_unknown, language="python", unit_id="unit-example-k")
        contents = {"example-conf/app.conf": "key=value\nother=1\n", "app.py": "x = 1\n"}
        pkt_u, _, _ = PacketBuilder().build_packet(
            "hunt", "snp-example", unit_unknown, contents
        )
        pkt_k, _, _ = PacketBuilder().build_packet(
            "hunt", "snp-example", unit_known, contents
        )
        self.assertIn("Asset Note", pkt_u["prompt_text"])
        self.assertIn("embedded credentials", pkt_u["prompt_text"])
        self.assertNotIn("Asset Note", pkt_k["prompt_text"])
