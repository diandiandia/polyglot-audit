"""Tests for analysis, hunter parsing, connector, verifier, and rating engine."""
# ==============================================================================
# 软件需求追踪与实现规范 (Software Requirements Traceability)
# ==============================================================================
# --- 需求编号: DSR-025/026/028/061/063 [负责人: ANA] / SWR-005~009 / SWR-011 ---
# 需求描述: hunt packet 溢出、frontier/sink 连接假设、影响×可利用性矩阵、第二意见、
#   去重合并闸门的单元测试；半链不伪装成完整发现，调整边界拒绝。
#   └─ 对应系统需求 SR-005~009（分析/验证/裁决）与 SR-011（定级矩阵可复现）。
# ==============================================================================

import unittest
from auditkit.analysis.connector import HypothesisConnector
from auditkit.analysis.dedup import CandidateDeduplicator
from auditkit.analysis.guards import GuardManager, GuardRecord
from auditkit.analysis.hunter import HuntResultParser
from auditkit.analysis.packets import PacketBuilder
from auditkit.analysis.rating import RatingEngine
from auditkit.analysis.verifier import Verifier
from auditkit.contracts.errors import InvalidInputError


class TestAnalysis(unittest.TestCase):

    def test_packet_builder_overflow(self):
        builder = PacketBuilder(max_chars=200)
        unit = {
            "unit_id": "u1",
            "ranges": [
                {"path": "long.py", "line_start": 1, "line_end": 50},
            ],
        }
        contents = {"long.py": "a = 1\n" * 100}
        packet, digest, overflow = builder.build_hunt_packet("snp-1", unit, contents)

        self.assertIsNotNone(overflow)
        self.assertEqual(overflow["dimension"], "packet_capacity")

    def test_hunter_parser_separation(self):
        parser = HuntResultParser(max_records_per_kind=5)
        raw = {
            "records": [
                {"source": {"path": "a.py"}, "sink": {"path": "b.py"}},
                {"source": {"path": "c.py"}, "boundary": "cgo"},
                {"sink": {"path": "d.py"}, "boundary": "cgo"},
            ]
        }
        cands, fronts, probes, overflows = parser.parse_worker_payload(raw, "task-1")
        self.assertEqual(len(cands), 1)
        self.assertEqual(len(fronts), 1)
        self.assertEqual(len(probes), 1)

    def test_connector_hypothesis_generation(self):
        connector = HypothesisConnector()
        frontiers = [{
            "frontier_id": "front-1",
            "source": {"path": "main.go", "symbol": "Process"},
            "boundary": "ffi_bridge",
            "steps": [],
        }]
        probes = [{
            "probe_id": "probe-1",
            "sink": {"path": "native.c", "symbol": "process_internal"},
            "boundary": "ffi_bridge",
            "steps": [],
        }]
        conns, synth_cands = connector.connect(frontiers, probes)
        self.assertEqual(len(conns), 1)
        self.assertEqual(conns[0]["status"], "hypothesized")
        self.assertEqual(len(synth_cands), 1)

    def test_verifier_verdicts(self):
        verifier = Verifier()
        cand = {
            "candidate_id": "cand-1",
            "source": {"path": "app.py", "line": 10, "symbol": "get_input", "kind": "http"},
            "sink": {"path": "db.py", "line": 40, "symbol": "query", "kind": "sqli"},
            "steps": [
                {"path": "app.py", "line": 10, "role": "source", "note": "read"},
                {"path": "db.py", "line": 40, "role": "sink", "note": "exec"},
            ],
            "provenance": {"hunt_tasks": ["t1"]},
        }

        # Confirmed -> E2
        f_conf = verifier.create_finding_from_candidate(cand, "confirmed", "t-v1", impact=4, exploitability=4)
        self.assertEqual(f_conf["verdict"], "confirmed")
        self.assertEqual(f_conf["evidence_level"], "E2")
        self.assertEqual(f_conf["rating"]["final_severity"], "Critical")
        self.assertEqual(f_conf["rating"]["final_urgency"], "P0")

        # Needs Validation -> E1
        f_val = verifier.create_finding_from_candidate(
            cand, "needs_validation", "t-v2", blockers=["Missing config"], validation_plan="Run integration"
        )
        self.assertEqual(f_val["verdict"], "needs_validation")
        self.assertEqual(f_val["evidence_level"], "E1")

    def test_second_opinion_adjudication_conflict(self):
        verifier = Verifier()
        cand = {
            "candidate_id": "cand-1",
            "source": {"path": "app.py", "line": 10},
            "sink": {"path": "db.py", "line": 40},
            "steps": [
                {"path": "app.py", "line": 10, "role": "source", "note": "read"},
                {"path": "db.py", "line": 40, "role": "sink", "note": "exec"},
            ],
            "provenance": {"hunt_tasks": ["t1"]},
        }
        finding = verifier.create_finding_from_candidate(cand, "confirmed", "t-v1", impact=4, exploitability=4)

        # Second opinion disagrees!
        adj = verifier.adjudicate_second_opinion(finding, "rejected", "Sanitizer observed on line 25")
        self.assertEqual(adj["verdict"], "needs_validation")
        self.assertEqual(adj["evidence_level"], "E1")

    def test_rating_manual_adjustment(self):
        # Base: Impact 3, Exploitability 3 -> High, P1
        # Adjust 1 grade down -> Medium, P2
        rating = RatingEngine.compute_rating(
            impact=3,
            exploitability=3,
            impact_why="Impact",
            exploitability_why="Exploit",
            adjustment={"operator": "SecurityLead", "reason": "Compensating firewall in place", "direction": "down"},
        )
        self.assertEqual(rating["calculated_severity"], "High")
        self.assertEqual(rating["final_severity"], "Medium")
        self.assertEqual(rating["final_urgency"], "P2")

        # More than 1 grade adjustment is blocked by direction logic
        with self.assertRaises(InvalidInputError):
            RatingEngine.compute_rating(
                impact=4,
                exploitability=4,
                impact_why="Impact",
                exploitability_why="Exploit",
                adjustment={"operator": "Lead", "reason": "Reason", "direction": "up"},  # Can't go above Critical
            )

    def test_deduplicator_keeps_distinct_sources(self):
        dedup = CandidateDeduplicator()
        cands = [
            # Same sink, different source
            {"candidate_id": "c1", "issue": "sqli", "source": {"path": "a.py", "kind": "http"}, "sink": {"path": "db.py", "symbol": "q"}},
            {"candidate_id": "c2", "issue": "sqli", "source": {"path": "b.py", "kind": "cli"}, "sink": {"path": "db.py", "symbol": "q"}},
        ]
        reps, merges = dedup.deduplicate(cands)
        # Both must be preserved!
        self.assertEqual(len(reps), 2)
        self.assertEqual(len(merges), 0)


if __name__ == "__main__":
    unittest.main()
