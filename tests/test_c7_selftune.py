"""Atomic tests for C7 SELFTUNE (operator roadmap item C7).

Laws under test:
- budgets scale ONLY from real run evidence (budget-exhaustion markers)
- growth is bounded (x selftune_multiplier_max), decay stops at 1.0 --
  the loop never shrinks the committed base below the operator's value
- every change is disclosed in the ledger (capped, newest kept)
- toggle off disables read AND write; corrupt state is ignored, disclosed
- never-fail: garbage partials / corrupt files never raise
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

from pipeline.params import Params  # noqa: E402
from pipeline.selftune import applied_budgets, update_tuning  # noqa: E402


def _isolated_root() -> Path:
    tmp = Path(tempfile.mkdtemp())
    for rel in ("tools.yaml", "wordlists.yaml", "scope.yaml"):
        src = _ROOT / rel
        if src.is_file():
            (tmp / rel).write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    return tmp


class TestSelftuneBase(unittest.TestCase):
    def setUp(self) -> None:
        self.params = Params(_isolated_root())
        self.target_dir = self.params.root / "targets" / "example.com"
        self.target_dir.mkdir(parents=True, exist_ok=True)

    def _state(self) -> dict:
        path = (
            self.target_dir / str(self.params.require("selftune_dirname"))
            / str(self.params.require("selftune_state_filename"))
        )
        return json.loads(path.read_text(encoding="utf-8"))


class TestAppliedBudgets(TestSelftuneBase):
    def test_no_state_returns_base_budgets_silent(self):
        p, a, note = applied_budgets(self.params, self.target_dir, 1200.0, 7200.0)
        self.assertEqual((p, a), (1200.0, 7200.0))
        self.assertEqual(note, "")

    def test_state_multipliers_scale_budgets(self):
        update_tuning(self.params, self.target_dir, "example.com", ["passive_budget"], "r1")
        p, a, note = applied_budgets(self.params, self.target_dir, 1200.0, 7200.0)
        self.assertEqual(p, 1200.0 * 1.25)
        self.assertEqual(a, 7200.0)
        self.assertIn("passive x1.25", note)

    def test_disabled_toggle_returns_base_even_with_state(self):
        self.params.settings["selftune_enabled"] = False
        update_tuning(self.params, self.target_dir, "example.com", ["passive_budget"], "r1")
        p, a, note = applied_budgets(self.params, self.target_dir, 1200.0, 7200.0)
        self.assertEqual((p, a, note), (1200.0, 7200.0, ""))

    def test_corrupt_state_treated_as_absent(self):
        path = (
            self.target_dir / str(self.params.require("selftune_dirname"))
            / str(self.params.require("selftune_state_filename"))
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{{{not-json", encoding="utf-8")
        p, a, _ = applied_budgets(self.params, self.target_dir, 1200.0, 7200.0)
        self.assertEqual((p, a), (1200.0, 7200.0))


class TestUpdateLaws(TestSelftuneBase):
    def test_budget_marker_grows_only_that_branch(self):
        update_tuning(self.params, self.target_dir, "example.com", ["passive_budget"], "r1")
        state = self._state()
        self.assertEqual(state["multipliers"]["passive"], 1.25)
        self.assertEqual(state["multipliers"]["active"], 1.0)
        self.assertTrue(state["ledger"][-1]["changed"])
        self.assertIn("passive", state["ledger"][-1]["observation"])

    def test_growth_is_bounded_by_max(self):
        for i in range(10):
            update_tuning(self.params, self.target_dir, "example.com", ["active_budget"], f"r{i}")
        state = self._state()
        self.assertLessEqual(state["multipliers"]["active"], 2.0)
        self.assertEqual(state["multipliers"]["active"], 2.0)

    def test_clean_runs_decay_back_to_one_never_below(self):
        update_tuning(self.params, self.target_dir, "example.com", ["passive_budget"], "r1")
        self.assertEqual(self._state()["multipliers"]["passive"], 1.25)
        # clean run 1: streak builds, no decay yet
        update_tuning(self.params, self.target_dir, "example.com", [], "r2")
        self.assertEqual(self._state()["multipliers"]["passive"], 1.25)
        # clean run 2: decay fires (0.9 step), stays above 1.0
        update_tuning(self.params, self.target_dir, "example.com", [], "r3")
        self.assertEqual(self._state()["multipliers"]["passive"], 1.125)
        # more clean runs: decay clamps at exactly 1.0, never below
        for i in range(10):
            update_tuning(self.params, self.target_dir, "example.com", [], f"r{i + 4}")
        self.assertEqual(self._state()["multipliers"]["passive"], 1.0)

    def test_marker_resets_clean_streak(self):
        update_tuning(self.params, self.target_dir, "example.com", [], "r1")
        self.assertEqual(self._state()["clean_streak"], 1)
        update_tuning(self.params, self.target_dir, "example.com", ["active_budget"], "r2")
        self.assertEqual(self._state()["clean_streak"], 0)

    def test_module_failures_never_move_budgets(self):
        update_tuning(
            self.params, self.target_dir, "example.com",
            ["passive:ffuf:boom", "active:port-check:boom", "owasp:boom", "portsweep:boom"], "r1",
        )
        state = self._state()
        self.assertEqual(state["multipliers"], {"passive": 1.0, "active": 1.0})
        self.assertIn("circuit breaker", state["ledger"][-1]["observation"])

    def test_ledger_is_capped_newest_kept(self):
        cap = int(self.params.require("selftune_ledger_max"))
        for i in range(cap + 7):
            update_tuning(self.params, self.target_dir, "example.com", ["passive_budget"], f"r{i}")
        state = self._state()
        self.assertEqual(len(state["ledger"]), cap)
        self.assertEqual(state["ledger"][-1]["run"], f"r{cap + 6}")

    def test_garbage_partial_entries_never_raise(self):
        summary = update_tuning(self.params, self.target_dir, "example.com", [1, None, object()], "r1")
        self.assertEqual(summary["passive"], 1.0)

    def test_update_summary_shape(self):
        summary = update_tuning(self.params, self.target_dir, "example.com", ["active_budget"], "r1")
        self.assertTrue(summary["updated"])
        self.assertEqual(summary["passive"], 1.0)
        self.assertEqual(summary["active"], 1.25)
        self.assertTrue(summary["reason"])


if __name__ == "__main__":
    unittest.main()
