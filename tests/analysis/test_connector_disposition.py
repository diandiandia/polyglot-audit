"""DSR-026/058: connector no-match disposition, caps, and signature compat."""

import unittest

from auditkit.analysis.connector import HypothesisConnector
from auditkit.contracts.errors import InvalidInputError


def _matching_pair(idx: int = 0) -> tuple:
    frontier = {
        "frontier_id": f"front-{idx}",
        "source": {"path": "main.go", "symbol": "Process"},
        "boundary": "ffi_bridge",
        "steps": [],
        "provenance": {"hunt_tasks": ["t1"]},
    }
    probe = {
        "probe_id": f"probe-{idx}",
        "sink": {"path": f"native{idx}.c", "symbol": "process_internal"},
        "boundary": "ffi_bridge",
        "steps": [],
        "provenance": {"hunt_tasks": ["t2"]},
    }
    return frontier, probe


class TestConnectorDisposition(unittest.TestCase):

    def test_no_match_produces_unresolved_records_not_silence(self):
        connector = HypothesisConnector()
        frontier = {
            "frontier_id": "front-net",
            "source": {"path": "a.go", "symbol": "Dial"},
            "boundary": "net_io",
            "steps": [],
        }
        probe = {
            "probe_id": "probe-file",
            "sink": {"path": "b.c", "symbol": "fopen"},
            "boundary": "file_io",
            "steps": [],
        }
        result = connector.connect_ex([frontier], [probe])
        self.assertEqual(len(result["connections"]), 0)
        self.assertEqual(len(result["candidates"]), 0)

        kinds = {u["kind"] for u in result["unresolved"]}
        self.assertEqual(kinds, {"frontier", "probe"})
        for u in result["unresolved"]:
            # Original record preserved verbatim + a reason
            self.assertIn("reason", u)
            self.assertTrue(u["reason"])
            self.assertIn("record", u)
            self.assertIsNotNone(u["record"])
        by_kind = {u["kind"]: u for u in result["unresolved"]}
        self.assertEqual(by_kind["frontier"]["record"], frontier)
        self.assertEqual(by_kind["probe"]["record"], probe)

    def test_connection_cap_produces_gap_record(self):
        connector = HypothesisConnector()
        frontiers, probes = zip(*(_matching_pair(i) for i in range(5)))
        result = connector.connect_ex(
            list(frontiers), list(probes), max_connections=2
        )
        self.assertEqual(len(result["connections"]), 2)
        self.assertEqual(len(result["gaps"]), 1)
        gap = result["gaps"][0]
        self.assertEqual(gap["dimension"], "connections")
        self.assertGreaterEqual(gap["estimated_count"], 1)
        self.assertIn("cap", gap["reason"].lower())
        # Unscheduled items are accounted in the gap, not silently dropped
        unresolved_ids = {u.get("frontier_id") for u in result["unresolved"] if u["kind"] == "frontier"}
        self.assertNotIn("front-4", unresolved_ids)

    def test_budget_cap_respected_with_gap_record(self):
        connector = HypothesisConnector()
        frontiers, probes = zip(*(_matching_pair(i) for i in range(5)))
        result = connector.connect_ex(list(frontiers), list(probes), budget=3)
        self.assertLessEqual(len(result["connections"]), 3)
        self.assertEqual(result["stats"]["evaluations"], 3)
        self.assertEqual(len(result["gaps"]), 1)
        gap = result["gaps"][0]
        self.assertEqual(gap["dimension"], "connection_budget")
        self.assertGreaterEqual(gap["estimated_count"], 1)
        self.assertIn("budget", gap["reason"].lower())

    def test_parameter_arity_mismatch_prevents_pairing_and_records_incompatible(self):
        connector = HypothesisConnector()
        frontier = {
            "frontier_id": "front-sig",
            "source": {"path": "a.go", "symbol": "Process", "params": ["buf", "len"]},
            "boundary": "ffi_bridge",
            "steps": [],
        }
        probe = {
            "probe_id": "probe-sig",
            "sink": {"path": "b.c", "symbol": "process_internal", "params": ["buf"]},
            "boundary": "ffi_bridge",
            "steps": [],
        }
        result = connector.connect_ex([frontier], [probe])
        self.assertEqual(len(result["connections"]), 0)
        self.assertEqual(len(result["candidates"]), 0)
        self.assertEqual(len(result["incompatible"]), 1)
        inc = result["incompatible"][0]
        self.assertEqual(inc["frontier_id"], "front-sig")
        self.assertEqual(inc["probe_id"], "probe-sig")
        self.assertIn("mismatch", inc["reason"].lower())

    def test_signature_string_arity_mismatch_prevents_pairing(self):
        connector = HypothesisConnector()
        frontier = {
            "frontier_id": "front-sig2",
            "source": {"path": "a.go", "symbol": "Run", "signature": "(int, char *)"},
            "boundary": "ffi_bridge",
        }
        probe = {
            "probe_id": "probe-sig2",
            "sink": {"path": "b.c", "symbol": "run_internal", "signature": "(int)"},
            "boundary": "ffi_bridge",
        }
        result = connector.connect_ex([frontier], [probe])
        self.assertEqual(len(result["connections"]), 0)
        self.assertEqual(len(result["incompatible"]), 1)

    def test_compatible_signatures_still_pair(self):
        connector = HypothesisConnector()
        frontier = {
            "frontier_id": "front-ok",
            "source": {"path": "a.go", "symbol": "Run", "params": ["buf", "len"]},
            "boundary": "ffi_bridge",
            "steps": [],
        }
        probe = {
            "probe_id": "probe-ok",
            "sink": {"path": "b.c", "symbol": "run_internal", "params": ["x", "y"]},
            "boundary": "ffi_bridge",
            "steps": [],
        }
        result = connector.connect_ex([frontier], [probe])
        self.assertEqual(len(result["connections"]), 1)
        self.assertEqual(result["connections"][0]["status"], "hypothesized")
        self.assertEqual(len(result["incompatible"]), 0)

    def test_depth_cap_validation_and_gap(self):
        connector = HypothesisConnector()
        with self.assertRaises(InvalidInputError):
            connector.connect_ex([], [], max_depth=0)
        with self.assertRaises(InvalidInputError):
            connector.connect_ex([], [], max_connections=0)

        frontier, probe = _matching_pair(0)
        result = connector.connect_ex([frontier], [probe], max_depth=2)
        # Deep chains are not attempted by the depth-1 connector; recorded.
        self.assertTrue(
            any(g["dimension"] == "connection_depth" for g in result["gaps"]),
            result["gaps"],
        )

    def test_connect_backward_compat_two_tuple(self):
        connector = HypothesisConnector()
        frontier, probe = _matching_pair(0)
        conns, cands = connector.connect([frontier], [probe])
        self.assertEqual(len(conns), 1)
        self.assertEqual(len(cands), 1)


if __name__ == "__main__":
    unittest.main()
