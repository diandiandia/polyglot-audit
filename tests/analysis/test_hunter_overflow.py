"""DSR-025: hunter overflow records for each record kind exceeding capacity."""

import unittest

from auditkit.analysis.hunter import HuntResultParser


class TestHunterOverflow(unittest.TestCase):

    def test_candidate_overflow(self):
        parser = HuntResultParser(max_records_per_kind=5)
        records = [
            {"record_type": "candidate", "source": {"path": "a.py"}, "sink": {"path": "b.py"}},
            {"record_type": "candidate", "source": {"path": "c.py"}, "sink": {"path": "d.py"}},
            {"record_type": "candidate", "source": {"path": "e.py"}, "sink": {"path": "f.py"}},
            {"record_type": "candidate", "source": {"path": "g.py"}, "sink": {"path": "h.py"}},
            {"record_type": "candidate", "source": {"path": "i.py"}, "sink": {"path": "j.py"}},
            {"record_type": "candidate", "source": {"path": "k.py"}, "sink": {"path": "l.py"}},
            {"record_type": "candidate", "source": {"path": "m.py"}, "sink": {"path": "n.py"}},
            {"record_type": "candidate", "source": {"path": "o.py"}, "sink": {"path": "p.py"}},
        ]
        cands, fronts, probes, overflows = parser.parse_worker_payload(
            {"records": records}, "task-cand"
        )
        self.assertEqual(len(cands), 5)
        cand_overflows = [o for o in overflows if o["dimension"] == "candidate"]
        self.assertTrue(cand_overflows)
        for o in cand_overflows:
            self.assertGreaterEqual(o["estimated_count"], 1)
            self.assertIn("cap 5", o["reason"])
        # Lower bound: 8 candidate records against a cap of 5 means >= 3 dropped
        self.assertGreaterEqual(max(o["estimated_count"] for o in cand_overflows), 3)

    def test_frontier_overflow(self):
        parser = HuntResultParser(max_records_per_kind=5)
        records = [
            {"record_type": "frontier", "source": {"path": f"s{i}.py"}, "boundary": "ffi"}
            for i in range(7)
        ]
        cands, fronts, probes, overflows = parser.parse_worker_payload(
            {"records": records}, "task-front"
        )
        self.assertEqual(len(fronts), 5)
        front_overflows = [o for o in overflows if o["dimension"] == "frontier"]
        self.assertTrue(front_overflows)
        self.assertGreaterEqual(
            max(o["estimated_count"] for o in front_overflows), 2
        )
        self.assertTrue(all("cap 5" in o["reason"] for o in front_overflows))

    def test_sink_probe_overflow(self):
        parser = HuntResultParser(max_records_per_kind=5)
        records = [
            {"record_type": "sink_probe", "sink": {"path": f"t{i}.py"}, "boundary": "ffi"}
            for i in range(6)
        ]
        cands, fronts, probes, overflows = parser.parse_worker_payload(
            {"records": records}, "task-probe"
        )
        self.assertEqual(len(probes), 5)
        probe_overflows = [o for o in overflows if o["dimension"] == "sink_probe"]
        self.assertTrue(probe_overflows)
        self.assertGreaterEqual(
            max(o["estimated_count"] for o in probe_overflows), 1
        )
        self.assertTrue(all("cap 5" in o["reason"] for o in probe_overflows))

    def test_mixed_kinds_overflow_independently(self):
        parser = HuntResultParser(max_records_per_kind=2)
        records = [
            {"record_type": "candidate", "source": {"path": "a.py"}, "sink": {"path": "b.py"}},
            {"record_type": "candidate", "source": {"path": "c.py"}, "sink": {"path": "d.py"}},
            {"record_type": "candidate", "source": {"path": "e.py"}, "sink": {"path": "f.py"}},
            {"record_type": "frontier", "source": {"path": "g.py"}, "boundary": "ffi"},
            {"record_type": "frontier", "source": {"path": "h.py"}, "boundary": "ffi"},
            {"record_type": "frontier", "source": {"path": "i.py"}, "boundary": "ffi"},
            {"record_type": "sink_probe", "sink": {"path": "j.py"}, "boundary": "ffi"},
            {"record_type": "sink_probe", "sink": {"path": "k.py"}, "boundary": "ffi"},
            {"record_type": "sink_probe", "sink": {"path": "l.py"}, "boundary": "ffi"},
            {"record_type": "sink_probe", "sink": {"path": "m.py"}, "boundary": "ffi"},
        ]
        cands, fronts, probes, overflows = parser.parse_worker_payload({"records": records}, "task-mix")
        self.assertEqual(len(cands), 2)
        self.assertEqual(len(fronts), 2)
        self.assertEqual(len(probes), 2)
        dimensions = {o["dimension"] for o in overflows}
        self.assertEqual(dimensions, {"candidate", "frontier", "sink_probe"})
        # All three kinds overflowed: explicit records, never silent truncation
        for dim in ("candidate", "frontier", "sink_probe"):
            entries = [o for o in overflows if o["dimension"] == dim]
            self.assertTrue(all(o["estimated_count"] >= 1 for o in entries), dim)
            self.assertTrue(all(o["reason"] for o in entries), dim)


if __name__ == "__main__":
    unittest.main()
