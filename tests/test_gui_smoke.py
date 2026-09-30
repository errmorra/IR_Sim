"""GUI smoke test. Skipped unless a display is available (CI runs it under xvfb-run)."""
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import app  # noqa: E402

HAS_DISPLAY = bool(os.environ.get("DISPLAY")) or sys.platform in ("win32", "darwin")


@unittest.skipUnless(HAS_DISPLAY, "no display available")
class GuiSmokeTests(unittest.TestCase):
    def setUp(self):
        try:
            self.app = app.IncidentSimulatorApp()
        except app.tk.TclError as exc:  # pragma: no cover - environment dependent
            self.skipTest(f"Tk could not open a display: {exc}")
        self.app.update()

    def tearDown(self):
        self.app.destroy()

    def _pick(self, quality):
        token = next(t for t, c in self.app._choice_token_map.items() if c["quality"] == quality)
        self.app._select_token(token)

    def test_full_walkthrough(self):
        a = self.app
        a.scenario_mgr.select(0)
        a._restart_simulation()
        self.assertEqual(a._view, "briefing")
        a._begin_exercise()
        a.update()
        self.assertEqual(a._view, "inject")
        self.assertEqual(str(a._action_primary["state"]), "disabled")

        n = a.scenario_mgr.total_injects
        for i in range(n):
            self._pick("optimal" if i % 2 == 0 else "neutral")
            self.assertEqual(str(a._action_primary["state"]), "normal")
            a._on_submit()
            a.update()
            self.assertEqual(len(a.session.decision_log), i + 1)
            if a._quiz_pending:
                # Next must be blocked until the technique is identified
                self.assertEqual(str(a._action_primary["state"]), "disabled")
                correct = a.scenario_mgr.get_inject(i)["mitre"]["technique_id"]
                token = next(t for t, o in a._quiz_options.items() if o["technique_id"] == correct)
                a._answer_quiz(token)
                a.update()
            self.assertEqual(str(a._action_primary["state"]), "normal")
            if i < n - 1:
                a._on_next()
                a.update()
        a._on_finish()
        a.update()
        self.assertEqual(a._view, "debrief")
        self.assertEqual(str(a._report_btn["state"]), "normal")
        md = app.ReportGenerator(a.session).generate()
        self.assertIn("Decision Timeline", md)

    def test_branching_story_is_shown(self):
        a = self.app
        a.scenario_mgr.select(0)
        a._restart_simulation()
        a._begin_exercise()
        self._pick("detrimental")
        a._on_submit()
        if a._quiz_pending:
            a._answer_quiz(a._quiz_tokens[0])
        a._on_next()
        a.update()
        inj = a.scenario_mgr.get_inject(1)
        self.assertEqual(app.ScenarioManager.story_for(inj, "detrimental"), inj["story_variants"]["detrimental"])

    def test_facilitator_mode_hides_scores(self):
        a = self.app
        a._facilitated.set(True)
        a._on_toggle_facilitator()
        a._begin_exercise()
        self._pick("optimal")
        a._on_submit()
        a.update()
        self.assertTrue(a.session.facilitated)
        self.assertEqual(a._grade_label["text"], "GRADE: —")

    def test_restart_keeps_geometry(self):
        a = self.app
        a.geometry("1100x700+10+10")
        a.update()
        before = a.geometry()
        a._on_new_scenario()
        a.update()
        self.assertEqual(a.geometry(), before)


if __name__ == "__main__":
    unittest.main()
