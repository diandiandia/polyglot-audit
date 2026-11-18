"""Verdict shape conformance samples (SR-029): 抽象自真实运行的输出形态，
全部合成虚构。断言样本满足验证记录契约：verdict 合法、rejected 必带反证、
confirmed 不虚构未观测字段。"""

import json
import unittest
from pathlib import Path

SAMPLES = Path(__file__).resolve().parent / "samples" / "verdict-shapes"
LEGAL = {"confirmed", "needs_validation", "rejected", "unverified"}


class TestVerdictShapeSamples(unittest.TestCase):

    def test_samples_exist_and_parse(self):
        files = sorted(SAMPLES.glob("*.json"))
        self.assertGreaterEqual(len(files), 4)

    def test_every_sample_has_legal_verdict_and_identity(self):
        for f in sorted(SAMPLES.glob("*.json")):
            d = json.loads(f.read_text(encoding="utf-8"))
            self.assertIn(d["verdict"], LEGAL, f"{f.name}")
            self.assertTrue(d.get("finding_id"), f"{f.name}")

    def test_rejected_carries_counter_evidence(self):
        for f in sorted(SAMPLES.glob("*.json")):
            d = json.loads(f.read_text(encoding="utf-8"))
            if d["verdict"] == "rejected":
                self.assertTrue(d.get("counter_evidence"), "rejected 需反证")

    def test_confirmed_does_not_fabricate_unobserved_fields(self):
        for f in sorted(SAMPLES.glob("*.json")):
            d = json.loads(f.read_text(encoding="utf-8"))
            if d["verdict"] == "confirmed":
                rating = d.get("rating") or {}
                reasons = (rating.get("factor_reasons") or {})
                self.assertTrue(str(reasons.get("impact_why") or "").strip(),
                                f"{f.name}: confirmed 需 impact_why")

    def test_no_target_identifiers_in_samples(self):
        banned = ("zcode", "zcode-protocol", "file-config.adapter", "marketplace")
        for f in sorted(SAMPLES.glob("*.json")):
            text = f.read_text(encoding="utf-8").lower()
            for b in banned:
                self.assertNotIn(b, text, f"{f.name}: 目标标识泄漏")
