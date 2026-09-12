"""Long tool jobs must not poison circuit-breaker latency / QPS."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from pipeline.breaker import CircuitBreaker, FakeClock
from pipeline.params import Params

_ROOT = Path(__file__).resolve().parents[1]


class TestBreakerLatencyProbes(unittest.TestCase):
    def test_multi_minute_job_does_not_throttle(self):
        tmp = Path(tempfile.mkdtemp())
        (tmp / "tools.yaml").write_text((_ROOT / "tools.yaml").read_text(encoding="utf-8"), encoding="utf-8")
        params = Params(tmp)
        clock = FakeClock()
        breaker = CircuitBreaker(params, clock=clock, target_dir=tmp, target="example.com")
        breaker.record("dns-resolve", success=True, latency_sec=1.0)
        clock.advance(1)
        breaker.record("dns-resolve", success=True, latency_sec=1.3)
        before = breaker.throttle_factor("dns-resolve")
        breaker.record("dns-resolve", success=True, latency_sec=1532.0)
        self.assertEqual(breaker.throttle_factor("dns-resolve"), before)
