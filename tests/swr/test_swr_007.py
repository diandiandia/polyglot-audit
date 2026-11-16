"""SWR-007 acceptance tests: candidates, dangling sinks, frontier records,
connection hypotheses, triage and dedup.

验收原文 (docs/design/SOFTWARE_DEVELOPMENT_REQUIREMENTS.md §2, SWR-007):
    "实现候选、悬空 sink、frontier 独立记录和连接假设；测试无 source、歧义
    连接、分页及溢出时不伪造成功。"

细化依据: DSR-025 "超出容量必须分页或返回溢出区域及数量下界，不能报告 full";
DSR-026 "连接 frontier/sink 假设，保留歧义及无匹配；同名参数不兼容不得形成
verified"; DSR-060 "强信号未处置不能计为已审查"; DSR-063 "source 不同的同
sink 候选不能被不可逆合并，误合并可追溯且不丢原记录"; IFC-02 SinkProbe:
"不要求 source 或局部无守卫的断言；缺失不应伪造"。

Covered here:
- Candidates / frontiers / sink probes land in three independent record
  lists with their own identifiers and provenance.
- A half-chain without a source (or without a sink) is never parsed into the
  complete-finding record type — half-chains stay half-chains.
- Ambiguous connections stay hypothesized (never verified).
- No-match, connection caps and per-kind overflow produce explicit statuses
  with a count lower bound instead of fabricated success.
- Dedup suggestions preserve source distinction and keep the original record
  on confirmed merges.
"""

import unittest

from auditkit.analysis.connector import HypothesisConnector
from auditkit.analysis.dedup import CandidateDeduplicator, compute_fingerprint
from auditkit.analysis.hunter import HuntResultParser
from auditkit.analysis.triage import StrongSignalTriage
from auditkit.contracts.errors import InvalidInputError, InvalidStateError


def _candidate_record(cid: str, source_path: str, sink_path: str):
    return {
        "record_type": "candidate",
        "candidate_id": cid,
        "issue": "py-01",
        "source": {"path": source_path, "line": 4, "symbol": "handle", "kind": "http_body"},
        "sink": {"path": sink_path, "line": 9, "symbol": "restore_state", "kind": "deserialization"},
        "steps": [
            {"path": source_path, "line": 4, "role": "source"},
            {"path": sink_path, "line": 9, "role": "sink"},
        ],
        "provenance": {"hunt_tasks": ["task-h1"]},
    }


class TestSWR007(unittest.TestCase):

    # -- independent record kinds -------------------------------------------
    def test_three_record_kinds_stay_in_separate_lists(self):
        raw = {
            "records": [
                _candidate_record("cand-1", "a.py", "b.py"),
                {"record_type": "frontier", "frontier_id": "front-1",
                 "source": {"path": "c.py", "line": 1}, "boundary": "ffi",
                 "steps": [], "provenance": {"hunt_tasks": ["task-h1"]}},
                {"record_type": "sink_probe", "probe_id": "probe-1",
                 "sink": {"path": "d.py", "line": 2}, "boundary": "ffi",
                 "steps": [], "provenance": {"hunt_tasks": ["task-h1"]}},
            ],
        }
        candidates, frontiers, probes, overflows = HuntResultParser().parse_worker_payload(
            raw, "task-h1"
        )
        self.assertEqual([c["candidate_id"] for c in candidates], ["cand-1"])
        self.assertEqual([f["frontier_id"] for f in frontiers], ["front-1"])
        self.assertEqual([p["probe_id"] for p in probes], ["probe-1"])
        self.assertEqual(overflows, [])
        # Records never leak across kinds.
        self.assertNotIn("boundary", candidates[0])
        self.assertNotIn("sink", frontiers[0])
        self.assertNotIn("source", probes[0])

    def test_half_chain_without_source_is_not_disguised_as_candidate(self):
        """A dangling sink without a source stays a sink_probe (half-chain).

        "无 source……不伪装成功" — the parser must not turn a sink-only record
        into the complete-finding record type (candidate), which would
        fabricate a source->sink finding from a half-chain. This must hold
        even when the worker omitted the boundary tag: the presence of a sink
        without any source is what makes it a half-chain.
        """
        raw = {
            "records": [
                {"sink": {"path": "native.c", "line": 8, "symbol": "execute"}, "boundary": "ffi"},
                # Same record but the worker forgot the boundary tag.
                {"sink": {"path": "native2.c", "line": 9, "symbol": "execute"}},
                {"record_type": "sink_probe", "probe_id": "probe-explicit",
                 "sink": {"path": "x.py", "line": 1}, "boundary": "ffi"},
            ],
        }
        candidates, frontiers, probes, _ = HuntResultParser().parse_worker_payload(raw, "t")
        self.assertEqual(candidates, [], "sink-only record must not become a candidate")
        self.assertEqual(frontiers, [])
        self.assertEqual(len(probes), 3)
        self.assertEqual(
            {p["probe_id"] for p in probes},
            {"probe-explicit", probes[0]["probe_id"], probes[1]["probe_id"]},
        )

    def test_source_without_sink_is_frontier_not_candidate(self):
        raw = {
            "records": [
                {"source": {"path": "caller.py", "line": 10, "symbol": "dispatch"}, "boundary": "ffi"},
                # Same record but the worker forgot the boundary tag.
                {"source": {"path": "caller2.py", "line": 11, "symbol": "dispatch2"}},
            ],
        }
        candidates, frontiers, probes, _ = HuntResultParser().parse_worker_payload(raw, "t")
        self.assertEqual(candidates, [], "source-only record must not become a candidate")
        self.assertEqual(len(frontiers), 2)
        self.assertEqual(probes, [])

    def test_complete_candidate_still_parsed_with_implicit_kind(self):
        raw = {"records": [{"source": {"path": "a.py"}, "sink": {"path": "b.py"}}]}
        candidates, frontiers, probes, _ = HuntResultParser().parse_worker_payload(raw, "t")
        self.assertEqual(len(candidates), 1)
        self.assertEqual(frontiers, [])
        self.assertEqual(probes, [])

    # -- ambiguous connections ----------------------------------------------
    def test_ambiguous_connections_stay_hypothesized(self):
        """One frontier matching two probes yields hypotheses, never facts."""
        frontier = {
            "frontier_id": "front-amb",
            "source": {"path": "caller.py", "symbol": "dispatch_op"},
            "boundary": "ffi_bridge",
            "steps": [],
            "provenance": {"hunt_tasks": ["t1"]},
        }
        probes = [
            {"probe_id": f"probe-{i}",
             "sink": {"path": f"native{i}.c", "symbol": "dispatch_op_impl"},
             "boundary": "ffi_bridge", "steps": [], "provenance": {"hunt_tasks": ["t2"]}}
            for i in range(2)
        ]
        result = HypothesisConnector().connect_ex([frontier], probes)
        self.assertEqual(len(result["connections"]), 2)
        for conn in result["connections"]:
            self.assertEqual(conn["status"], "hypothesized")
            self.assertNotEqual(conn["status"], "verified")
            self.assertTrue(conn["matching_factors"])
        # Each ambiguous pairing synthesizes its own to-verify candidate.
        self.assertEqual(len(result["candidates"]), 2)
        self.assertNotEqual(
            result["candidates"][0]["candidate_id"],
            result["candidates"][1]["candidate_id"],
        )

    def test_incompatible_arity_never_becomes_verified_connection(self):
        frontier = {
            "frontier_id": "front-arity",
            "source": {"path": "caller.py", "symbol": "op", "params": ["a", "b"]},
            "boundary": "ffi", "steps": [], "provenance": {"hunt_tasks": ["t1"]},
        }
        probe = {
            "probe_id": "probe-arity",
            "sink": {"path": "n.c", "symbol": "op", "params": ["a"]},
            "boundary": "ffi", "steps": [], "provenance": {"hunt_tasks": ["t2"]},
        }
        result = HypothesisConnector().connect_ex([frontier], [probe])
        self.assertEqual(result["connections"], [])
        self.assertEqual(result["candidates"], [])
        self.assertEqual(len(result["incompatible"]), 1)
        self.assertIn("mismatch", result["incompatible"][0]["reason"])

    # -- no match / caps / overflow carry status and a lower bound -----------
    def test_no_match_produces_explicit_unresolved_records(self):
        frontier = {
            "frontier_id": "front-lone",
            "source": {"path": "a.py", "symbol": "f"},
            "boundary": "b1", "steps": [], "provenance": {"hunt_tasks": ["t1"]},
        }
        result = HypothesisConnector().connect_ex([frontier], [])
        self.assertEqual(result["connections"], [])
        self.assertEqual(len(result["unresolved"]), 1)
        unresolved = result["unresolved"][0]
        self.assertEqual(unresolved["kind"], "frontier")
        self.assertEqual(unresolved["frontier_id"], "front-lone")
        self.assertTrue(unresolved["reason"])

    def test_connection_cap_produces_gap_with_count_lower_bound(self):
        frontiers = [
            {"frontier_id": f"f{i}", "source": {"path": f"a{i}.py", "symbol": f"sym{i}"},
             "boundary": "bd", "steps": [], "provenance": {"hunt_tasks": ["t1"]}}
            for i in range(4)
        ]
        probes = [
            {"probe_id": f"p{i}", "sink": {"path": f"b{i}.py", "symbol": f"sym{i}"},
             "boundary": "bd", "steps": [], "provenance": {"hunt_tasks": ["t2"]}}
            for i in range(4)
        ]
        result = HypothesisConnector().connect_ex(
            frontiers, probes, max_connections=2
        )
        self.assertEqual(len(result["connections"]), 2)
        cap_gaps = [g for g in result["gaps"] if g["dimension"] == "connections"]
        self.assertTrue(cap_gaps, "cap must be recorded as a gap")
        gap = cap_gaps[0]
        self.assertGreaterEqual(gap["estimated_count"], 1)
        self.assertTrue(gap["reason"])

    def test_budget_cap_produces_gap_and_leaves_records_unscheduled(self):
        frontiers = [
            {"frontier_id": f"f{i}", "source": {"path": f"a{i}.py", "symbol": f"s{i}"},
             "boundary": "bd", "steps": [], "provenance": {"hunt_tasks": ["t1"]}}
            for i in range(3)
        ]
        probes = [
            {"probe_id": f"p{i}", "sink": {"path": f"b{i}.py", "symbol": f"s{i}"},
             "boundary": "bd", "steps": [], "provenance": {"hunt_tasks": ["t2"]}}
            for i in range(3)
        ]
        result = HypothesisConnector().connect_ex(frontiers, probes, budget=1)
        budget_gaps = [g for g in result["gaps"] if g["dimension"] == "connection_budget"]
        self.assertTrue(budget_gaps)
        self.assertGreaterEqual(budget_gaps[0]["estimated_count"], 1)
        self.assertIn("budget", budget_gaps[0]["reason"])

    def test_overflow_per_kind_records_lower_bound(self):
        parser = HuntResultParser(max_records_per_kind=2)
        records = [
            _candidate_record(f"cand-{i}", f"s{i}.py", f"k{i}.py") for i in range(4)
        ]
        records.append({
            "record_type": "frontier", "frontier_id": "front-ov",
            "source": {"path": "z.py", "line": 1}, "boundary": "ffi",
            "steps": [], "provenance": {"hunt_tasks": ["t"]},
        })
        candidates, frontiers, probes, overflows = HuntResultParser(
            max_records_per_kind=2
        ).parse_worker_payload({"records": records}, "task-ov")
        candidates, frontiers, probes, overflows = (
            candidates, frontiers, probes, overflows
        )
        self.assertEqual(len(candidates), 2)
        self.assertEqual(len(frontiers), 1)
        cand_overflow = [o for o in overflows if o["dimension"] == "candidate"]
        self.assertTrue(cand_overflow)
        # Lower bound: 4 candidate records against cap 2 means >= 2 dropped.
        self.assertGreaterEqual(
            max(o["estimated_count"] for o in cand_overflow), 2
        )
        for o in overflows:
            self.assertTrue(o["reason"], "overflow records must carry a reason")

    def test_triage_overflow_and_pending_not_counted_reviewed(self):
        hits = [
            {"path": f"f{i}.py", "line": i + 1, "kind": "sink", "strength": 3,
             "signal_id": f"sig-{i}"}
            for i in range(5)
        ]
        triage = StrongSignalTriage(max_records=2)
        result = triage.triage_signals(
            hits, dispositions={"sig-0": "candidate_created", "sig-1": "dismissed"}
        )
        self.assertEqual(len(result["records"]), 2)
        self.assertTrue(result["overflow"])
        self.assertGreaterEqual(result["overflow"][0]["estimated_count"], 3)
        self.assertGreaterEqual(result["stats"]["total_hits"], 5)
        self.assertEqual(result["stats"]["candidate_created"], 1)
        self.assertEqual(result["stats"]["dismissed"], 1)
        # Only decided + reviewed records count as reviewed.
        self.assertEqual(result["stats"]["reviewed"], 0)
        pending_record = triage.set_disposition(result["records"][0], "pending")
        with self.assertRaises(InvalidInputError):
            triage.mark_reviewed(pending_record)
        decided = next(
            r for r in result["records"] if r["disposition"] == "dismissed"
        )
        triage.mark_reviewed(decided, reviewed_by="operator-1")
        self.assertEqual(triage.compute_stats(result["records"])["reviewed"], 1)

    # -- dedup suggestions preserve source distinction -----------------------
    def test_dedup_suggestion_preserves_distinct_sources(self):
        dup1 = _candidate_record("cand-a", "src.py", "sink.py")
        dup2 = dict(_candidate_record("cand-b", "src.py", "sink.py"))
        # Different source kind changes the fingerprint (spec: issue + sink
        # file/symbol + source KIND, no line numbers and no source path).
        other_kind = _candidate_record("cand-c", "src.py", "sink.py")
        other_kind["source"]["kind"] = "query_param"
        # Different source path (same kind) keeps the same fingerprint but is
        # protected from merging by the composite key.
        other_path = _candidate_record("cand-d", "other.py", "sink.py")
        self.assertEqual(compute_fingerprint(dup1), compute_fingerprint(dup2))
        self.assertEqual(compute_fingerprint(dup1), compute_fingerprint(other_path))
        self.assertNotEqual(compute_fingerprint(dup1), compute_fingerprint(other_kind))

        dedup = CandidateDeduplicator()
        suggestions = dedup.propose_deduplication(
            [dup1, dup2, other_kind, other_path]
        )
        self.assertEqual(len(suggestions), 1, "only identical fingerprint+source proposes merge")
        suggestion = suggestions[0]
        self.assertEqual(suggestion["status"], "proposed")
        self.assertEqual(suggestion["merged_candidate_id"], "cand-b")
        self.assertEqual(suggestion["representative_id"], "cand-a")
        # Original record retained for traceability/rollback.
        self.assertEqual(suggestion["merged_candidate_snapshot"]["candidate_id"], "cand-b")

        # Distinct sources for the same sink are never proposed for merging.
        self.assertEqual(
            [s for s in suggestions if s["merged_candidate_id"] == "cand-d"],
            [],
        )

        merge = dedup.confirm_merge(suggestion, confirmed_by="operator-1")
        self.assertEqual(merge["status"], "confirmed")
        self.assertEqual(merge["confirmed_by"], "operator-1")
        self.assertEqual(merge["original_candidate"]["candidate_id"], "cand-b")
        self.assertEqual(merge["merged_candidate_id"], "cand-b")
        self.assertEqual(merge["representative_id"], "cand-a")

        # Input candidates are never mutated by proposing.
        self.assertEqual(dup1["candidate_id"], "cand-a")
        self.assertEqual(dup2["candidate_id"], "cand-b")

        with self.assertRaises(InvalidStateError):
            dedup.confirm_merge(suggestion, confirmed_by="operator-2")


if __name__ == "__main__":
    unittest.main()
