"""DNS-first vhost seeding: ffuf does not HTTP-brute when the flag is off."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from pipeline.modules.ffuf import _hosts_from_dnsr


class _Params:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.settings = {"dnsr_data_json": "20_dns/dnsx/data.json"}

    def require(self, key: str):
        return self.settings[key]


class TestFfufDnsSeed(unittest.TestCase):
    def test_seeds_vhost_bases_from_dnsx_resolved(self):
        tmp = Path(tempfile.mkdtemp())
        path = tmp / "20_dns/dnsx/data.json"
        path.parent.mkdir(parents=True)
        path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "module": "dns-resolve",
                    "resolved": [
                        {
                            "host": "api.example.com",
                            "ips": ["1.2.3.4"],
                            "resolution_status": "resolved",
                            "alive": True,
                            "http_status": 200,
                            "length": 512,
                            "tech": ["nginx"],
                        },
                        {
                            "host": "gone.example.com",
                            "ips": [],
                            "resolution_status": "unresolved",
                        },
                    ],
                    "candidates": {"brute": 1, "perms": 0, "valid": 1},
                    "wildcard_suspects": [],
                }
            ),
            encoding="utf-8",
        )
        hosts = _hosts_from_dnsr(_Params(tmp), tmp, ["example.com"])
        self.assertIn("api.example.com", hosts)
        self.assertNotIn("gone.example.com", hosts)
        self.assertEqual(hosts["api.example.com"]["length"], 512)
        self.assertEqual(hosts["api.example.com"]["tech"], ["nginx"])

    def test_falls_back_to_apex_when_dnsr_missing(self):
        tmp = Path(tempfile.mkdtemp())
        hosts = _hosts_from_dnsr(_Params(tmp), tmp, ["example.com"])
        self.assertEqual(list(hosts), ["example.com"])


if __name__ == "__main__":
    unittest.main()
