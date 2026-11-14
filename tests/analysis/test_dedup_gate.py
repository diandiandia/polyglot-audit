"""DSR-063: dedup proposal/confirmation gate with traceable, reversible merges."""

import unittest

from auditkit.analysis.dedup import CandidateDeduplicator
from auditkit.contracts.errors import InvalidInputError, InvalidStateError


def _cand(cid: str, src_path: str, src_kind: str = "http") -> dict:
    return {
        "candidate_id": cid,
        "issue": "sqli",
        "source": {"path": src_path, "kind": src_kind},
        "sink": {"path": "db.py", "symbol": "query"},
    }


class TestDedupGate(unittest.TestCase):

    def test_propose_does_not_mutate_or_merge(self):
        dedup = CandidateDeduplicator()
        cands = [
            _cand("c1", "a.py"),
            _cand("c2", "a.py"),
            _cand("c3", "b.py"),
        ]
        import copy
        before = copy.deepcopy(cands)
        suggestions = dedup.propose_deduplication(cands)

        # Exactly one merge proposed (c2 -> c1); c3 distinct source never merged
        self.assertEqual(len(suggestions), 1)
        s = suggestions[0]
        self.assertEqual(s["merged_candidate_id"], "c2")
        self.assertEqual(s["representative_id"], "c1")
        self.assertEqual(s["status"], "proposed")

        # No state change: candidates untouched, no merge executed
        self.assertEqual(cands, before)
        self.assertNotIn("provenance", cands[1])

    def test_confirm_merge_executes_and_records_trace(self):
        dedup = CandidateDeduplicator()
        cands = [_cand("c1", "a.py"), _cand("c2", "a.py")]
        suggestion = dedup.propose_deduplication(cands)[0]

        merge = dedup.confirm_merge(suggestion, confirmed_by="SecurityLead")
        self.assertEqual(merge["status"], "confirmed")
        self.assertEqual(merge["merged_candidate_id"], "c2")
        self.assertEqual(merge["representative_id"], "c1")
        self.assertEqual(merge["confirmed_by"], "SecurityLead")
        self.assertTrue(merge["reason"])
        # Original candidate retained: mistaken merge is traceable/reversible
        self.assertEqual(merge["original_candidate"]["candidate_id"], "c2")
        self.assertEqual(merge["original_candidate"]["source"]["path"], "a.py")

    def test_double_confirm_rejected(self):
        dedup = CandidateDeduplicator()
        suggestion = dedup.propose_deduplication([_cand("c1", "a.py"), _cand("c2", "a.py")])[0]
        dedup.confirm_merge(suggestion, confirmed_by="Lead")
        with self.assertRaises(InvalidStateError):
            dedup.confirm_merge(suggestion, confirmed_by="Lead")

    def test_confirm_requires_confirmed_by(self):
        dedup = CandidateDeduplicator()
        suggestion = dedup.propose_deduplication([_cand("c1", "a.py"), _cand("c2", "a.py")])[0]
        with self.assertRaises(InvalidInputError):
            dedup.confirm_merge(suggestion)

    def test_confirm_rejects_non_proposed_suggestion(self):
        dedup = CandidateDeduplicator()
        with self.assertRaises(InvalidInputError):
            dedup.confirm_merge({"status": "executed", "merged_candidate_id": "x"})

    def test_distinct_sources_same_sink_never_merged(self):
        dedup = CandidateDeduplicator()
        cands = [_cand("c1", "a.py", "http"), _cand("c2", "b.py", "cli")]
        self.assertEqual(len(dedup.propose_deduplication(cands)), 0)
        reps, merges = dedup.deduplicate(cands)
        self.assertEqual(len(reps), 2)
        self.assertEqual(len(merges), 0)

    def test_deduplicate_backward_compat_still_executes(self):
        dedup = CandidateDeduplicator()
        cands = [_cand("c1", "a.py"), _cand("c2", "a.py")]
        reps, merges = dedup.deduplicate(cands)
        self.assertEqual(len(reps), 1)
        self.assertEqual(len(merges), 1)
        self.assertEqual(merges[0]["merged_candidate_id"], "c2")


if __name__ == "__main__":
    unittest.main()
