"""Limiter pauses must clear themselves — the operator never clicks RESET LIMITER."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from pipeline.breaker import CircuitBreaker, FakeClock
from pipeline.engine import _filter_paused, _release_breaker
from pipeline.params import Params
from pipeline import state as state_engine

_ROOT = Path(__file__).resolve().parents[1]


class TestBreakerAutoReset(unittest.TestCase):
    def test_reset_paused_clears_persisted_pause(self):
        params = Params(_ROOT)
        target_dir = Path(tempfile.mkdtemp()) / "example.com"
        target_dir.mkdir()
        state_engine.init_state(params, target_dir, "example.com")
        clock = FakeClock()
        breaker = CircuitBreaker(params, clock=clock, notify=lambda *_: None, target_dir=target_dir, target="example.com")
        breaker.force_pause("dns-resolve", "canary")
        self.assertFalse(breaker.allow("dns-resolve"))
        self.assertIn("dns-resolve", state_engine.paused_modules(params, target_dir, "example.com"))

        cleared = breaker.reset_paused("dns-resolve", reason="continue run")
        self.assertEqual(cleared, ["dns-resolve"])
        self.assertTrue(breaker.allow("dns-resolve"))
        self.assertEqual(state_engine.paused_modules(params, target_dir, "example.com"), {})

    def test_module_boundary_releases_pause_so_ladder_continues(self):
        params = Params(_ROOT)
        target_dir = Path(tempfile.mkdtemp()) / "example.com"
        target_dir.mkdir()
        state_engine.init_state(params, target_dir, "example.com")
        breaker = CircuitBreaker(params, notify=lambda *_: None, target_dir=target_dir, target="example.com")
        breaker.force_pause("port-sweep", "error ratio")
        _release_breaker(breaker, "port-sweep")
        self.assertTrue(breaker.allow("port-sweep"))
        kept = _filter_paused(params, target_dir, breaker, ["dns-resolve", "port-sweep"])
        self.assertEqual(kept, ["dns-resolve", "port-sweep"])


if __name__ == "__main__":
    unittest.main()
