"""Atomic tests for C4 fleet (release directive): multi-target concurrency
with automatic request/resource management and per-target settings.

Laws under test (no docker, no network — pure orchestration):
  - member list resolution ('all' from the C3 registry, explicit list,
    dedup, sanitization)
  - concurrency clamp to the committed fleet_max_concurrency
  - member preparation: isolated root carries ALL control files, an empty
    recon tree, and the C3 profile BAKED in (loader-parseable, correct
    values) — including BLOCK-list keys (modules) and wordlist selections
  - global slot lockfile counting (acquire/release/exhaust)
  - failure isolation semantics in the ledger
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from pipeline.fleet import (  # noqa: E402
    FleetError,
    GlobalSlots,
    _bake_profile,
    fleet_targets,
    max_concurrency,
    prepare_member,
    run_fleet,
)
from pipeline.params import Params  # noqa: E402
from pipeline.target_profiles import set_profile  # noqa: E402
from pipeline.yaml_util import load_yaml_file  # noqa: E402


def make_root(tmp: Path) -> Path:
    for name in ("tools.yaml", "wordlists.yaml", "scope.yaml", "search_engines.yaml",
                 "dorks.yaml", "resolvers.yaml", "tools.lock", "views.yaml", "remediation.yaml"):
        src = ROOT / name
        if src.is_file():
            (tmp / name).write_bytes(src.read_bytes())
    for d in ("pipeline", "resolvers", "dorks", "schemas", "wordlists/local", "wordlists/custom"):
        src = ROOT / d
        if src.is_dir():
            (tmp / d).mkdir(parents=True, exist_ok=True)
            for f in src.rglob("*"):
                if f.is_file():
                    rel = f.relative_to(src)
                    dst = tmp / d / rel
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    dst.write_bytes(f.read_bytes())
    (tmp / "wordlists" / "custom" / "index.yaml").write_text(
        "schema_version: 1\nroot: wordlists/custom\nlists:\n", encoding="utf-8")
    return tmp


class MemberList(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.params = Params(make_root(Path(self._tmp.name)))

    def tearDown(self):
        self._tmp.cleanup()

    def test_explicit_list_dedup_sanitized(self):
        self.assertEqual(fleet_targets(self.params, "a.test, b.test ,a.test"), ["a.test", "b.test"])
        self.assertEqual(fleet_targets(self.params, "good.test,../evil,Bad"), ["good.test"])

    def test_all_pulls_registry(self):
        set_profile(self.params, "zulu.test", {"budgets": {"passive_recursion_depth": 1}})
        set_profile(self.params, "alpha.test", {"budgets": {"passive_recursion_depth": 1}})
        self.assertEqual(fleet_targets(self.params, "all"), ["alpha.test", "zulu.test"])

    def test_empty_refused(self):
        with self.assertRaises(FleetError):
            fleet_targets(self.params, "")
        with self.assertRaises(FleetError):
            fleet_targets(self.params, " , ,")


class ConcurrencyClamp(unittest.TestCase):
    def test_committed_value_and_bounds(self):
        self.assertEqual(max_concurrency(Params(ROOT)), 3)
        with tempfile.TemporaryDirectory() as td:
            root = make_root(Path(td))
            p = root / "tools.yaml"
            p.write_text(p.read_text(encoding="utf-8").replace(
                "  fleet_max_concurrency: 3", "  fleet_max_concurrency: 99"), encoding="utf-8")
            self.assertEqual(max_concurrency(Params(root)), 8)  # hard ceiling


class MemberPreparation(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.params = Params(make_root(Path(self._tmp.name)))
        set_profile(self.params, "example.com", {
            "budgets": {"passive_branch_budget_sec": 3000, "passive_recursion_depth": 1},
            "modules": {"active_branch_modules": ["ffuf", "dns-resolve"]},
            "wordlist_selection": {"FFUF-0": ["test_smoke_200"]},
        })

    def tearDown(self):
        self._tmp.cleanup()

    def test_member_root_isolated_and_baked(self):
        fleet_root = Path(self._tmp.name) / "history" / "fleet" / "x"
        ledger = prepare_member(self.params, "example.com", fleet_root)
        member = Path(ledger["root"])
        # isolation: control files present, recon tree empty, member ledger written
        self.assertTrue((member / "tools.yaml").is_file())
        self.assertTrue((member / "scope.yaml").is_file())
        self.assertTrue((member / "recon").is_dir())
        self.assertTrue((member / "fleet-member.json").is_file())
        # baked budget + scalar override visible through the FROZEN loader
        doc = load_yaml_file(str(member / "tools.yaml"))
        self.assertEqual(int(doc["settings"]["passive_branch_budget_sec"]), 3000)
        self.assertEqual(int(doc["settings"]["passive_recursion_depth"]), 1)
        # BLOCK-list key replaced atomically (no stale duplicates)
        self.assertEqual(doc["settings"]["active_branch_modules"], ["ffuf", "dns-resolve"])
        self.assertEqual(str(doc["settings"]["active_branch_modules"]).count("port-check"), 0)
        # wordlist selection baked and parseable
        wl = load_yaml_file(str(member / "wordlists.yaml"))
        self.assertEqual(wl["tasks"]["FFUF-0"]["selection"], ["test_smoke_200"])
        self.assertIn("tools.yaml:passive_branch_budget_sec", ledger["baked"])
        self.assertIn("wordlists.yaml:FFUF-0", ledger["baked"])

    def test_bake_does_not_leak_into_source_root(self):
        fleet_root = Path(self._tmp.name) / "history" / "fleet" / "y"
        prepare_member(self.params, "example.com", fleet_root)
        src = load_yaml_file(str(self.params.root / "tools.yaml"))
        self.assertEqual(int(src["settings"]["passive_branch_budget_sec"]), 1200)


class GlobalSlotsLaw(unittest.TestCase):
    def test_acquire_release_and_exhaust(self):
        with tempfile.TemporaryDirectory() as td:
            params = Params(make_root(Path(td)))
            slots = GlobalSlots(params, 2)
            self.assertTrue(slots.acquire())
            self.assertTrue(slots.acquire())
            other = GlobalSlots(params, 2)
            self.assertFalse(other.acquire())  # exhausted at limit 2
            slots.release()
            self.assertTrue(other.acquire())
            other.release()


class FailureIsolation(unittest.TestCase):
    def test_run_fleet_ledger_shape_with_a_dead_member(self):
        with tempfile.TemporaryDirectory() as td:
            params = Params(make_root(Path(td)))
            # a target that cannot exist as a runnable member: pipeline copy
            # exists, but recon.sh is absent in the member root -> subprocess
            # fails fast; the OTHER member still records its own result.
            ledger = run_fleet(params, "one.test,two.test", concurrency=2, member_timeout_sec=60)
            self.assertEqual(sorted(r["target"] for r in ledger["results"]), ["one.test", "two.test"])
            self.assertFalse(ledger["clean"])  # members fail without recon.sh -> isolated, recorded
            self.assertTrue((Path(params.root) / "history" / "fleet").is_dir())


if __name__ == "__main__":
    unittest.main()
