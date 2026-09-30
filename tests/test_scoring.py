import json
import random
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import scoring  # noqa: E402


def load_scenarios():
    with open(ROOT / "scenarios.json", encoding="utf-8") as f:
        raw = json.load(f)
    return raw["scenarios"] if "scenarios" in raw else [raw]


class GradeBandTests(unittest.TestCase):
    def test_bands(self):
        self.assertEqual(scoring.grade_for(100), "A")
        self.assertEqual(scoring.grade_for(85), "A")
        self.assertEqual(scoring.grade_for(84.9), "B")
        self.assertEqual(scoring.grade_for(70), "B")
        self.assertEqual(scoring.grade_for(55), "C")
        self.assertEqual(scoring.grade_for(30), "D")
        self.assertEqual(scoring.grade_for(29.9), "F")
        self.assertEqual(scoring.grade_for(0), "F")


class NormalisationTests(unittest.TestCase):
    def test_bounds_and_normalise(self):
        injects = [{"choices": [
            {"nist_score_delta": 20, "compliance_score_delta": 10, "legal_score_delta": 5},
            {"nist_score_delta": 5, "compliance_score_delta": 0, "legal_score_delta": -5},
            {"nist_score_delta": -10, "compliance_score_delta": -20, "legal_score_delta": -15},
        ]}]
        bounds = scoring.axis_bounds(injects)
        self.assertEqual(bounds["nist"], (-10, 20))
        self.assertEqual(bounds["compliance"], (-20, 10))
        self.assertEqual(bounds["legal"], (-15, 5))
        self.assertEqual(scoring.normalise(20, -10, 20), 100)
        self.assertEqual(scoring.normalise(-10, -10, 20), 0)
        self.assertEqual(scoring.normalise(5, -10, 20), 50)
        self.assertEqual(scoring.normalise(3, 3, 3), 100)


class ScenarioPathTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scenarios = load_scenarios()

    def test_every_scenario_has_meaningful_extremes(self):
        for s in self.scenarios:
            sid = s["scenario_meta"]["id"]
            opt = scoring.score_path(s, "optimal")
            neu = scoring.score_path(s, "neutral")
            det = scoring.score_path(s, "detrimental")
            self.assertEqual(opt["grade"], "A", sid)
            self.assertIn(neu["grade"], ("C", "D"), sid)
            self.assertEqual(det["grade"], "F", sid)
            self.assertGreater(opt["overall"], neu["overall"], sid)
            self.assertGreater(neu["overall"], det["overall"], sid)

    def test_every_inject_moves_the_score(self):
        """The final inject must still be able to change the grade (no saturation)."""
        for s in self.scenarios:
            sid = s["scenario_meta"]["id"]
            injects = s["injects"]
            optimal_path = [next(c for c in inj["choices"] if c["quality"] == "optimal") for inj in injects]
            spoiled = optimal_path[:-1] + [next(c for c in injects[-1]["choices"] if c["quality"] == "detrimental")]
            full = scoring.score_choices(s, optimal_path)
            worse = scoring.score_choices(s, spoiled)
            self.assertLess(worse["overall"], full["overall"], sid)

    def test_shuffle_stability(self):
        random.seed(1234)
        for s in self.scenarios:
            baseline = scoring.score_path(s, "optimal")
            picked = []
            for inj in s["injects"]:
                shuffled = list(inj["choices"])
                random.shuffle(shuffled)
                picked.append(next(c for c in shuffled if c["quality"] == "optimal"))
            result = scoring.score_choices(s, picked)
            for axis in scoring.AXES:
                self.assertEqual(result[axis], baseline[axis], s["scenario_meta"]["id"])

    def test_phase_efficiency(self):
        s = self.scenarios[0]
        decisions = []
        for inj in s["injects"]:
            c = next(x for x in inj["choices"] if x["quality"] == "optimal")
            decisions.append({"inject_id": inj["id"], "nist_delta": c["nist_score_delta"]})
        rows = scoring.phase_efficiency(s["injects"], decisions, s["nist_phases"])
        self.assertEqual(len(rows), 5)
        self.assertTrue(all(r["efficiency"] == 100 for r in rows))
        partial = scoring.phase_efficiency(s["injects"], decisions[:1], s["nist_phases"])
        self.assertEqual(partial[0]["efficiency"], 100)
        self.assertIsNone(partial[1]["efficiency"])


if __name__ == "__main__":
    unittest.main()
