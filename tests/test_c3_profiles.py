"""Atomic tests for C3 per-target settings profiles (release directive).

Laws under test:
  - closed override allow-list (unknown sections / budget / notification
    keys REJECTED)
  - registry upsert in frozen-loader dialect (set -> get round-trip)
  - transient apply: working-copy edits match the plan, frozen loader still
    parses both files, restore returns the tree byte-identically
  - wordlist_selection key law against the LIVE registry (unregistered keys
    refused)
"""

from __future__ import annotations

import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from pipeline.params import Params  # noqa: E402
from pipeline.target_profiles import (  # noqa: E402
    ProfileError,
    apply_transient,
    build_edit_plan,
    get_profile,
    load_registry,
    restore_transient,
    set_profile,
    validate_profile,
)
from pipeline.yaml_util import load_yaml_file  # noqa: E402


def make_root(tmp: Path) -> Path:
    src = ROOT
    for name in ("tools.yaml", "wordlists.yaml", "wordlists"):
        s = src / name
        d = tmp / name
        if s.is_file():
            shutil.copy2(s, d)
        else:
            shutil.copytree(s, d, dirs_exist_ok=True)
    (tmp / "wordlists" / "custom").mkdir(parents=True, exist_ok=True)
    (tmp / "wordlists" / "custom" / "index.yaml").write_text(
        "schema_version: 1\n"
        "root: wordlists/custom\n"
        "lists:\n"
        "  platform_learned:\n"
        "    path: wordlists/custom/platform-learned.txt\n"
        "    entries: 0\n"
        "    shape: hostname\n"
        "    origin: platform\n",
        encoding="utf-8",
    )
    return tmp


class ValidationLaw(unittest.TestCase):
    def test_closed_allowlist_rejects_unknown_section(self):
        with self.assertRaises(ProfileError):
            validate_profile("example.com", {"scope_includes": ["evil.com"]})

    def test_budget_allowlist(self):
        ok = validate_profile("example.com", {"budgets": {"passive_branch_budget_sec": 3000}})
        self.assertEqual(ok["budgets"]["passive_branch_budget_sec"], 3000)
        ok2 = validate_profile("example.com", {"budgets": {"recon_depth": 2}})
        self.assertEqual(ok2["budgets"]["recon_depth"], 2)
        with self.assertRaises(ProfileError):
            validate_profile("example.com", {"budgets": {"resolver_min_healthy_count": 1}})

    def test_notification_allowlist(self):
        ok = validate_profile("example.com", {"notifications": {"telegram_chat": "12345"}})
        self.assertEqual(ok["notifications"]["telegram_chat"], "12345")
        with self.assertRaises(ProfileError):
            validate_profile("example.com", {"notifications": {"api_key": "x"}})

    def test_scheduler_allowlist(self):
        ok = validate_profile("example.com", {"scheduler": {"enabled": True, "interval_minutes": 60}})
        self.assertEqual(ok["scheduler"]["interval_minutes"], 60)
        with self.assertRaises(ProfileError):
            validate_profile("example.com", {"scheduler": {"last_run": "now"}})
        with self.assertRaises(ProfileError):
            validate_profile("example.com", {"scheduler": {"interval_minutes": 5}})

    def test_target_name_law(self):
        with self.assertRaises(ProfileError):
            validate_profile("../evil", {"budgets": {}})


class RegistryRoundTrip(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = make_root(Path(self._tmp.name))
        self.params = Params(self.root)

    def tearDown(self):
        self._tmp.cleanup()

    def test_set_get_roundtrip(self):
        set_profile(self.params, "example.com", {
            "description": "unit fixture",
            "budgets": {"passive_branch_budget_sec": 3000},
            "wordlist_selection": {"FFUF-0": ["test_smoke_200"]},
        })
        self.assertEqual(get_profile(self.params, "example.com")["description"], "unit fixture")
        doc = load_yaml_file(str(self.root / "targets.yaml"))
        prof = doc["targets"]["example.com"]["settings"]
        self.assertEqual(int(prof["budgets"]["passive_branch_budget_sec"]), 3000)
        self.assertEqual(prof["wordlist_selection"]["FFUF-0"], ["test_smoke_200"])
        # a second target coexists
        set_profile(self.params, "second.test", {"budgets": {"passive_recursion_depth": 1}})
        self.assertEqual(len(load_registry(self.params)), 2)

    def test_empty_profile_removes_entry(self):
        set_profile(self.params, "example.com", {"budgets": {"passive_recursion_depth": 1}})
        set_profile(self.params, "example.com", {})
        self.assertEqual(get_profile(self.params, "example.com"), {})

    def test_description_only_apply_leaves_globals_untouched(self):
        from pipeline.target_profiles import profile_has_overrides

        set_profile(self.params, "example.com", {"description": "added from SCAN"})
        self.assertFalse(profile_has_overrides(get_profile(self.params, "example.com")))
        tools_before = (self.root / "tools.yaml").read_bytes()
        wl_before = (self.root / "wordlists.yaml").read_bytes()
        applied = apply_transient(self.params, "example.com", self.root)
        self.assertEqual((self.root / "tools.yaml").read_bytes(), tools_before)
        self.assertEqual((self.root / "wordlists.yaml").read_bytes(), wl_before)
        restore_transient(applied)

    def test_unregistered_wordlist_key_refused_at_apply(self):
        set_profile(self.params, "example.com", {"wordlist_selection": {"FFUF-0": ["not_a_real_key"]}})
        with self.assertRaises(ProfileError):
            apply_transient(self.params, "example.com", self.root)


class TransientApplyRestore(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = make_root(Path(self._tmp.name))
        self.params = Params(self.root)
        set_profile(self.params, "example.com", {
            "budgets": {"passive_branch_budget_sec": 3000},
            "wordlist_selection": {"DNSR-1": ["test_smoke_200"]},
        })
        self.tools_before = (self.root / "tools.yaml").read_bytes()
        self.wl_before = (self.root / "wordlists.yaml").read_bytes()

    def tearDown(self):
        self._tmp.cleanup()

    def test_apply_edits_match_plan_and_loader_parses(self):
        plan = build_edit_plan(self.params, "example.com")
        self.assertEqual(plan["tools_edits"], [{"key": "passive_branch_budget_sec", "value": 3000}])
        applied = apply_transient(self.params, "example.com", self.root)
        tools_doc = load_yaml_file(str(self.root / "tools.yaml"))
        # the budget edit landed (frozen loader reads it)
        self.assertEqual(int(tools_doc["settings"]["passive_branch_budget_sec"]), 3000)
        wl_doc = load_yaml_file(str(self.root / "wordlists.yaml"))
        self.assertEqual(wl_doc["tasks"]["DNSR-1"]["selection"], ["test_smoke_200"])
        # restore returns byte-identical working copies
        restore_transient(applied)
        self.assertEqual((self.root / "tools.yaml").read_bytes(), self.tools_before)
        self.assertEqual((self.root / "wordlists.yaml").read_bytes(), self.wl_before)

    def test_no_selection_stacking(self):
        first = apply_transient(self.params, "example.com", self.root)
        restore_transient(first)
        second = apply_transient(self.params, "example.com", self.root)
        restore_transient(second)
        # crash-recovery law: applying again WITHOUT restoring REPLACES the
        # leftover selection in place -- two selections can never stack.
        # (per-token before-dirs mirror the vehicle contract: one dir per
        # restore token, so snapshots never clobber each other)
        snap_a = self.root / "snap-a"
        snap_a.mkdir()
        applied = apply_transient(self.params, "example.com", snap_a)
        snap_b = self.root / "snap-b"
        snap_b.mkdir()
        again = apply_transient(self.params, "example.com", snap_b)
        text = (self.root / "wordlists.yaml").read_text(encoding="utf-8")
        # Per-task law: DNSR-1 keeps exactly one selection block after re-apply.
        m = re.search(r"^  DNSR-1:\s*(?:#.*)?$", text, re.M)
        self.assertIsNotNone(m)
        rest = text[m.end():]
        nxt = re.search(r"^  [A-Za-z0-9_-]+:", rest, re.M)
        block = rest[: nxt.start()] if nxt else rest
        self.assertEqual(len(re.findall(r"^ {4}selection:", block, re.M)), 1)
        wl_live = load_yaml_file(str(self.root / "wordlists.yaml"))
        self.assertEqual(wl_live["tasks"]["DNSR-1"]["selection"], ["test_smoke_200"])
        # nested restores unwind byte-identically to the clean template
        restore_transient(again)
        restore_transient(applied)
        self.assertEqual((self.root / "wordlists.yaml").read_bytes(), self.wl_before)


if __name__ == "__main__":
    unittest.main()
