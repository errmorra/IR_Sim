"""Session, save/resume and report tests. Imports app.py (needs the tkinter module
installed, but no display)."""
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import app  # noqa: E402


def load_scenarios():
    with open(ROOT / "scenarios.json", encoding="utf-8") as f:
        return json.load(f)["scenarios"]


def play(session, scenario, quality, quiz=True):
    for inj in scenario["injects"]:
        choice = next(c for c in inj["choices"] if c["quality"] == quality)
        session.apply_decision(inj, choice)
        if quiz and app.is_attack_id(inj["mitre"]["technique_id"]):
            session.record_identification(inj, inj["mitre"]["technique_id"])


class SessionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scenarios = load_scenarios()

    def test_scores_none_before_first_decision(self):
        s = app.SimulationSession(self.scenarios[0])
        self.assertIsNone(s.scores())
        self.assertEqual(s.grade()[0], "—")

    def test_optimal_run_scores_100(self):
        scenario = self.scenarios[0]
        s = app.SimulationSession(scenario)
        play(s, scenario, "optimal")
        self.assertEqual(s.scores(), {"nist": 100, "compliance": 100, "legal": 100})
        self.assertEqual(s.grade()[0], "A")
        self.assertTrue(s.complete)
        self.assertEqual(s.techniques_identified, s.techniques_quizzed)
        self.assertGreater(s.techniques_quizzed, 0)

    def test_identification_is_independent_of_choice(self):
        scenario = self.scenarios[0]
        s = app.SimulationSession(scenario)
        inj = scenario["injects"][1]
        choice = next(c for c in inj["choices"] if c["quality"] == "optimal")
        s.apply_decision(inj, choice)
        self.assertFalse(s.record_identification(inj, "T9999"))
        self.assertEqual(s.techniques_identified, 0)
        self.assertEqual(s.techniques_quizzed, 1)

    def test_framework_refs_are_not_techniques(self):
        scenario = self.scenarios[0]
        s = app.SimulationSession(scenario)
        play(s, scenario, "neutral")
        ids = {t["technique_id"] for t in s.mitre_techniques}
        self.assertTrue(all(app.is_attack_id(t) for t in ids))
        self.assertTrue(any(not app.is_attack_id(r["technique_id"]) for r in s.framework_refs))

    def test_story_variants(self):
        inj = self.scenarios[0]["injects"][1]
        self.assertEqual(app.ScenarioManager.story_for(inj, None), inj["story"])
        self.assertNotEqual(app.ScenarioManager.story_for(inj, "detrimental"), inj["story"])
        plain = self.scenarios[1]["injects"][1]
        self.assertEqual(app.ScenarioManager.story_for(plain, "detrimental"), plain["story"])

    def test_save_resume_roundtrip(self):
        scenario = self.scenarios[2]
        s = app.SimulationSession(scenario)
        s.facilitated = True
        for inj in scenario["injects"][:3]:
            choice = next(c for c in inj["choices"] if c["quality"] == "neutral")
            s.apply_decision(inj, choice)
            if app.is_attack_id(inj["mitre"]["technique_id"]):
                s.record_identification(inj, "T0000")
        s.current_inject_index = 3
        data = json.loads(json.dumps(s.to_dict()))
        restored = app.SimulationSession.from_dict(scenario, data)
        self.assertEqual(restored.current_inject_index, 3)
        self.assertEqual(restored.scores(), s.scores())
        self.assertEqual(len(restored.identifications), len(s.identifications))
        self.assertTrue(restored.facilitated)
        with self.assertRaises(ValueError):
            app.SimulationSession.from_dict(self.scenarios[3], data)


class ReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scenarios = load_scenarios()

    def _report(self, index, quality):
        scenario = self.scenarios[index]
        s = app.SimulationSession(scenario)
        play(s, scenario, quality)
        return s, app.ReportGenerator(s).generate()

    def test_report_sections_present(self):
        _, md = self._report(0, "optimal")
        for heading in ("# Post-Incident & GRC Compliance Review Report", "## Executive Summary",
                        "## GRC Performance Metrics", "## Incident Response Decision Timeline",
                        "## MITRE ATT&CK Techniques Encountered", "## Executive Recommendations",
                        "## Regulatory & Legal Obligations Checklist", "## Report Certification"):
            self.assertIn(heading, md)
        self.assertNotIn("if applicable", md)
        self.assertIn("Alternatives Not Taken", md)

    def test_recommendations_track_techniques_and_weak_decisions(self):
        _, md_opt = self._report(0, "optimal")
        _, md_det = self._report(0, "detrimental")
        self.assertIn("Immutable, Tested Offline Backup", md_opt)      # T1486 present in ransomware scenario
        self.assertNotIn("Revisit", md_opt)                              # no weak decisions
        self.assertIn("Revisit Preparation Playbook", md_det)
        self.assertIn("**Priority:** CRITICAL", md_det)

    def test_recommendations_differ_by_scenario(self):
        _, ransomware = self._report(0, "optimal")
        _, ddos = self._report(4, "optimal")
        self.assertIn("DDoS Mitigation Capacity", ddos)
        self.assertNotIn("DDoS Mitigation Capacity", ransomware)

    def test_obligations_scoped_to_industry(self):
        _, healthcare = self._report(0, "optimal")
        _, defi = self._report(19, "optimal")
        self.assertIn("HIPAA §164.408", healthcare)
        self.assertNotIn("HIPAA §164.408", defi)
        self.assertNotIn("PCI DSS", healthcare)
        self.assertIn("Exercise Indication", defi)

    def test_industry_tokens(self):
        self.assertEqual(app.industry_tokens("Defense / Technology"), {"defense", "technology"})
        self.assertIn("commerce", app.industry_tokens("E-Commerce"))
        self.assertEqual(app.industry_segments("Retail / E-Commerce"), ["Retail", "E-Commerce"])

    def test_ransom_payment_flags_ofac_risk(self):
        s, md = self._report(0, "detrimental")
        self.assertIn("At risk (payment chosen)", md)


if __name__ == "__main__":
    unittest.main()
