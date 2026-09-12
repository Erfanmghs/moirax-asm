"""Pace + native DNS + resolver cache + host-fit ceiling."""

from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pipeline.ceiling import ResourceCeiling
from pipeline.fast_dns import build_query, canary_ok, encode_qname, response_has_a
from pipeline.params import Params
from pipeline.resolver_forge import _SESSION, forge_resolvers
from pipeline.textio import read_line_window

_ROOT = Path(__file__).resolve().parents[1]


def _params() -> Params:
    tmp = Path(tempfile.mkdtemp())
    (tmp / "tools.yaml").write_text((_ROOT / "tools.yaml").read_text(encoding="utf-8"), encoding="utf-8")
    return Params(tmp)


def _a_response(name: str) -> bytes:
    qname = encode_qname(name)
    header = struct.pack("!HHHHHH", 1, 0x8180, 1, 1, 0, 0)
    question = qname + struct.pack("!HH", 1, 1)
    # pointer to offset 12 (the question name)
    answer = struct.pack("!HHHIH", 0xC00C, 1, 1, 60, 4) + bytes([93, 184, 216, 34])
    return header + question + answer


class TestFastDns(unittest.TestCase):
    def test_response_has_a(self):
        self.assertTrue(response_has_a(_a_response("example.com")))
        self.assertFalse(response_has_a(b"short"))
        self.assertFalse(response_has_a(struct.pack("!HHHHHH", 1, 0x8182, 0, 0, 0, 0)))

    def test_build_query_roundtrip_qname(self):
        q = build_query("Example.COM")
        self.assertIn(encode_qname("example.com"), q)

    def test_canary_uses_first_hit(self):
        with patch("pipeline.fast_dns.query_a", side_effect=[False, True]):
            self.assertTrue(canary_ok(["example.com"], ["1.1.1.1", "8.8.8.8"]))
        with patch("pipeline.fast_dns.query_a", return_value=False):
            self.assertFalse(canary_ok(["example.com"], ["1.1.1.1"]))


class TestResolverCache(unittest.TestCase):
    def setUp(self):
        _SESSION.clear()
        self.params = _params()
        self.target_dir = self.params.root / "recon" / "example.com"
        self.target_dir.mkdir(parents=True)
        (self.params.root / "resolvers.yaml").write_text(
            "schema_version: 1\nsources: []\nmanual_add:\n  - 1.1.1.1\nmanual_remove: []\n",
            encoding="utf-8",
        )
        (self.params.root / "resolvers").mkdir()
        (self.params.root / "resolvers" / "seed.txt").write_text("1.1.1.1\n", encoding="utf-8")

    def test_native_probe_then_session_reuse(self):
        calls = {"n": 0}

        def fake_probe(resolvers, domains, timeout_sec=1.5, workers=32):
            calls["n"] += 1
            return {ip: 1.0 for ip in resolvers}

        with patch("pipeline.fast_dns.probe_resolvers", side_effect=fake_probe):
            first = forge_resolvers(self.params, None, self.target_dir, "example.com")
            second = forge_resolvers(self.params, None, self.target_dir, "example.com")
        self.assertEqual(calls["n"], 1)
        self.assertEqual(first, second)
        text = first.read_text(encoding="utf-8")
        self.assertIn("1.1.1.1", text)
        log = (self.target_dir / "logs" / "run.log").read_text(encoding="utf-8")
        self.assertIn("native UDP", log)
        self.assertIn("session reuse", log)

    def test_disk_cache_skips_probe(self):
        cache = self.params.root / str(self.params.require("resolver_health_cache"))
        cache.parent.mkdir(parents=True, exist_ok=True)
        domains = [str(x) for x in self.params.require("resolver_validate_domains")]
        from pipeline.resolver_forge import _gather_hash, _save_cache

        _save_cache(self.params, _gather_hash(["1.1.1.1"], domains), ["1.1.1.1"])
        with patch("pipeline.fast_dns.probe_resolvers", side_effect=AssertionError("must not probe")):
            dest = forge_resolvers(self.params, None, self.target_dir, "example.com")
        self.assertIn("1.1.1.1", dest.read_text(encoding="utf-8"))


class TestCeilingHostFit(unittest.TestCase):
    def test_auto_off_keeps_committed_budget(self):
        params = _params()
        params.settings["resource_budget_auto"] = False
        params.settings["resource_budget_ram_mb"] = 2048
        params.settings["resource_budget_cpu_cores"] = 2
        params.settings["meminfo_path"] = "/no/such/meminfo"
        ceiling = ResourceCeiling(params)
        self.assertEqual(ceiling.budget_ram_mb, 2048)
        self.assertEqual(ceiling.budget_cpu, 2.0)
        four = ceiling.plan(4)
        self.assertLessEqual(four.concurrency, 4)
        self.assertLessEqual(four.memory_mb * four.concurrency, ceiling.budget_ram_mb)
        self.assertLessEqual(four.cpus * four.concurrency, ceiling.budget_cpu + 1e-9)

    def test_cpu_floor_reduces_concurrency(self):
        params = _params()
        params.settings["resource_budget_auto"] = False
        params.settings["resource_budget_cpu_cores"] = 1
        params.settings["container_cpu_floor"] = 0.5
        params.settings["container_ram_floor_mb"] = 1
        params.settings["meminfo_path"] = "/no/such/meminfo"
        ceiling = ResourceCeiling(params)
        planned = ceiling.plan(8)
        self.assertLessEqual(planned.concurrency, 2)


class TestLineWindow(unittest.TestCase):
    def test_offset_and_nonempty(self):
        path = Path(tempfile.mkdtemp()) / "run.log"
        path.write_text("a\n\nb\nc\n", encoding="utf-8")
        chunk, total = read_line_window(path, 1, 2, nonempty=False)
        self.assertEqual(chunk, ["", "b"])
        self.assertEqual(total, 4)
        chunk2, total2 = read_line_window(path, 0, 10, nonempty=True)
        self.assertEqual(chunk2, ["a", "b", "c"])
        self.assertEqual(total2, 3)


if __name__ == "__main__":
    unittest.main()
