"""DNSR-2 refinement (spec v1.9, approved Option-1 item 3) unit proof.

AGGREGATE CAP + SUSPECT-NAME EXCLUSION:
  - per-host cap first, then the aggregate cap bounds the TOTAL perm
    candidate set per target per run (B2 evidence: 51,872 perms from 199
    vhost-feedback FQDNs — per-host cap alone leaves the aggregate
    unbounded);
  - wildcard-suspect and misconfig_suspect-flagged names are EXCLUDED from
    the alterx seed input.

No docker, no network — pure function test.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from pipeline.modules.dns_resolve import (
    _cap_perms,
    _filter_seeds,
    _misconfig_flagged,
    _wildcard_ip_members,
)


class _Gate:
    def enforce(self, target_dir: Path, host: str) -> bool:
        return True


class _Params:
    def __init__(self, root: Path, settings: dict) -> None:
        self.root = root
        self.settings = settings

    def require(self, key: str):
        if key in self.settings:
            return self.settings[key]
        raise KeyError(f"unnamed parameter {key!r}")


class TestAggregateCap(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_aggregate_binds_after_per_host_caps(self):
        path = self.root / "alterx-out.txt"
        parents = ["a.test", "b.test", "c.test"]
        # 2 per host after per-host cap 2 => 6 total
        lines = [f"{i}.{p}" for p in parents for i in (1, 2, 3)]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        perms, dropped = _cap_perms(path, parents, cap=2, gate=_Gate(), target_dir=self.root, aggregate=4)
        self.assertEqual(len(perms), 4)
        self.assertEqual(dropped, 2)
        self.assertEqual(len(path.read_text(encoding="utf-8").splitlines()), 4)
        # per-host discipline preserved inside the aggregate window (first 2 of each host, in order)
        self.assertEqual(perms, ["1.a.test", "2.a.test", "1.b.test", "2.b.test"])

    def test_aggregate_zero_disables(self):
        path = self.root / "alterx-out.txt"
        parents = ["a.test"]
        lines = [f"{i}.a.test" for i in range(10)]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        perms, dropped = _cap_perms(path, parents, cap=100, gate=_Gate(), target_dir=self.root, aggregate=0)
        self.assertEqual(len(perms), 10)
        self.assertEqual(dropped, 0)


class TestSeedExclusion(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_filter_seeds_excludes_flagged_and_wildcard(self):
        known = ["app.test", "mail.test", "dev.app.test", "ok.test"]
        flagged = {"dev.app.test"}
        wildcard = ["mail.test"]
        seeds, counts = _filter_seeds(known, flagged, wildcard)
        self.assertEqual(seeds, ["app.test", "ok.test"])
        self.assertEqual(
            counts,
            {
                "seeds_before": 4,
                "seeds_after": 2,
                "excluded_misconfig_flagged": 1,
                "excluded_wildcard_suspect": 1,
            },
        )

    def test_wildcard_ip_members(self):
        resolved = {
            "x.test": {"ips": ["6.6.6.6"]},
            "y.test": {"ips": ["7.7.7.7"]},
        }
        self.assertEqual(
            _wildcard_ip_members(["x.test", "y.test"], resolved, "6.6.6.6"),
            ["x.test"],
        )
        self.assertEqual(_wildcard_ip_members(["x.test"], resolved, None), [])

    def test_misconfig_flagged_reads_ffuf_doc(self):
        root = self.root
        p = root / "10_subdomains/ffuf/data.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(
            json.dumps(
                {
                    "module": "ffuf",
                    "vhosts": [
                        {"vhost": "Dev.App.Test", "misconfig_suspect": True},
                        {"vhost": "www.test", "misconfig_suspect": False},
                        {"vhost": "plain.test"},
                        "not-a-dict",
                    ],
                }
            ),
            encoding="utf-8",
        )
        params = _Params(root, {"ffuf_data_json": "10_subdomains/ffuf/data.json"})
        self.assertEqual(_misconfig_flagged(params, root), {"dev.app.test"})

    def test_misconfig_flagged_absent_doc(self):
        with tempfile.TemporaryDirectory() as td:
            params = _Params(Path(td), {"ffuf_data_json": "missing/data.json"})
            self.assertEqual(_misconfig_flagged(params, Path(td)), set())


if __name__ == "__main__":
    unittest.main()
