"""DSR-060: strong-signal triage records, overflow, and review state machine."""

import unittest

from auditkit.analysis.triage import StrongSignalTriage, triage_strong_signals
from auditkit.contracts.errors import InvalidInputError


def _hits(n: int) -> list:
    return [
        {
            "signal_id": f"sig-{i}",
            "kind": "sink",
            "strength": 3,
            "path": f"app/mod{i}.py",
            "line": i + 1,
        }
        for i in range(n)
    ]


class TestStrongSignalTriage(unittest.TestCase):

    def test_sparse_records_with_explicit_dispositions(self):
        triage = StrongSignalTriage(max_records=10)
        result = triage.triage_signals(
            _hits(3),
            dispositions={"sig-0": "candidate_created", "sig-1": "dismissed"},
        )
        records = result["records"]
        self.assertEqual(len(records), 3)
        self.assertEqual(records[0]["disposition"], "candidate_created")
        self.assertEqual(records[1]["disposition"], "dismissed")
        # Undispositioned strong signals stay pending, never silently dismissed
        self.assertEqual(records[2]["disposition"], "pending")
        self.assertFalse(records[2]["reviewed"])
        self.assertEqual(result["overflow"], [])
        self.assertEqual(result["stats"]["candidate_created"], 1)
        self.assertEqual(result["stats"]["dismissed"], 1)
        self.assertEqual(result["stats"]["pending"], 1)
        self.assertEqual(result["stats"]["reviewed"], 0)

    def test_capacity_overflow_record_mirrors_hunter_pattern(self):
        triage = StrongSignalTriage(max_records=2)
        result = triage.triage_signals(_hits(5))
        self.assertEqual(len(result["records"]), 2)
        self.assertEqual(len(result["overflow"]), 1)
        overflow = result["overflow"][0]
        self.assertEqual(overflow["dimension"], "triage")
        self.assertEqual(overflow["estimated_count"], 3)
        self.assertIn("cap 2", overflow["reason"])
        self.assertEqual(result["stats"]["overflowed"], 3)

    def test_pending_signal_cannot_be_marked_reviewed(self):
        triage = StrongSignalTriage()
        result = triage.triage_signals(_hits(1))
        record = result["records"][0]
        with self.assertRaises(InvalidInputError):
            triage.mark_reviewed(record)
        self.assertFalse(record["reviewed"])
        self.assertEqual(triage.compute_stats([record])["reviewed"], 0)

    def test_decided_signal_can_be_marked_reviewed(self):
        triage = StrongSignalTriage()
        result = triage.triage_signals(
            _hits(2),
            dispositions={"sig-0": "candidate_created", "sig-1": "dismissed"},
        )
        for rec in result["records"]:
            triage.mark_reviewed(rec, reviewed_by="SecurityLead")
        stats = triage.compute_stats(result["records"])
        self.assertEqual(stats["reviewed"], 2)

    def test_pending_record_manually_flagged_reviewed_is_not_counted(self):
        """State machine invariant: pending must never count as reviewed."""
        triage = StrongSignalTriage()
        record = triage.triage_signals(_hits(1))["records"][0]
        record["reviewed"] = True  # force the flag; disposition still pending
        stats = triage.compute_stats([record])
        self.assertEqual(stats["reviewed"], 0)

    def test_set_disposition_and_invalid_values(self):
        triage = StrongSignalTriage()
        record = triage.triage_signals(_hits(1))["records"][0]
        triage.set_disposition(record, "dismissed")
        self.assertEqual(record["disposition"], "dismissed")
        self.assertFalse(record["reviewed"])
        with self.assertRaises(InvalidInputError):
            triage.set_disposition(record, "auto_confirmed")
        with self.assertRaises(InvalidInputError):
            triage.triage_signals(_hits(1), dispositions={"sig-0": "maybe"})

    def test_module_level_wrapper(self):
        result = triage_strong_signals(_hits(4), max_records=3)
        self.assertEqual(len(result["records"]), 3)
        self.assertEqual(result["overflow"][0]["estimated_count"], 1)


if __name__ == "__main__":
    unittest.main()
