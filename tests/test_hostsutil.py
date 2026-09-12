"""Target-scoped wildcard seeds -- a run for host A must not fuzz host B."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from pipeline.hostsutil import keep_resolved_host, wildcard_seeds
from pipeline.params import Params
from pipeline.scope import ScopeGate


class WildcardSeedsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.params = Params(ROOT)
        self.gate = ScopeGate(
            self.params,
            {
                "includes": [
                    "example.com",
                    "*.example.com",
                    "other.net",
                    "*.other.net",
                    "192.0.2.0/24",
                ],
                "excludes": [],
            },
        )

    def test_unrelated_includes_are_not_seeded_for_the_typed_target(self) -> None:
        seeds = wildcard_seeds(self.gate, "other.net")
        self.assertEqual(seeds, ["other.net"])
        self.assertNotIn("example.com", seeds)

    def test_without_target_keeps_every_domain_include(self) -> None:
        seeds = wildcard_seeds(self.gate, None)
        self.assertIn("example.com", seeds)
        self.assertIn("other.net", seeds)

    def test_unknown_target_outside_scope_yields_no_seeds(self) -> None:
        self.assertEqual(wildcard_seeds(self.gate, "not-in-scope.test"), [])


class KeepResolvedHostTests(unittest.TestCase):
    def test_drops_brute_names_that_only_share_the_catchall_ip(self) -> None:
        wild = {"9.9.9.9"}
        self.assertTrue(keep_resolved_host("app.com", ["9.9.9.9"], wild, "app.com", source="brute"))
        self.assertFalse(keep_resolved_host("app2.app.com", ["9.9.9.9"], wild, "app.com", source="brute"))
        self.assertTrue(keep_resolved_host("api.app.com", ["1.2.3.4"], wild, "app.com", source="brute"))
        self.assertTrue(
            keep_resolved_host("www.app.com", ["9.9.9.9"], wild, "app.com", source="known")
        )


class KeepAssetRowTests(unittest.TestCase):
    def test_results_drop_dns_catchall_but_keep_osint(self) -> None:
        from pipeline.hostsutil import keep_asset_row

        wild = {"9.9.9.9"}
        self.assertFalse(keep_asset_row(
            {"host": "app2.app.com", "ips": ["9.9.9.9"], "sources": ["dnsx"]},
            wild,
            "app.com",
        ))
        self.assertTrue(keep_asset_row(
            {"host": "mail.app.com", "ips": ["9.9.9.9"], "sources": ["crtsh"]},
            wild,
            "app.com",
        ))


if __name__ == "__main__":
    unittest.main()
