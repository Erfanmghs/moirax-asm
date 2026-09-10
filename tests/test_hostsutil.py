"""Target-scoped wildcard seeds -- a run for host A must not fuzz host B."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from pipeline.hostsutil import wildcard_seeds
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


if __name__ == "__main__":
    unittest.main()
