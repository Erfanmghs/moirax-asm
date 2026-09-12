"""Nested recon depth: DNS parents, clamp, independent DNS vs vhost knobs."""

from __future__ import annotations

import re
import tempfile
import unittest
from pathlib import Path

from dashboard.service import load_settings, save_settings, validate_settings
from pipeline.params import Params
from pipeline.recon_depth import (
    child_depth,
    clamp_ffuf_depth,
    clamp_recon_depth,
    recursion_parents,
    vhost_bases,
    vhost_driven_parents,
)
from pipeline.target_profiles import apply_transient, restore_transient, set_profile, validate_profile

_ROOT = Path(__file__).resolve().parents[1]


class TestChildDepth(unittest.TestCase):
    def test_levels(self):
        self.assertEqual(child_depth("example.com", "example.com"), 0)
        self.assertEqual(child_depth("api.example.com", "example.com"), 1)
        self.assertEqual(child_depth("dev.api.example.com", "example.com"), 2)
        self.assertEqual(child_depth("other.net", "example.com"), -1)

    def test_recursion_parents_level2(self):
        resolved = {
            "api.example.com": {"ips": ["1.2.3.4"]},
            "wild.example.com": {"ips": ["9.9.9.9"]},
            "gone.example.com": {"ips": []},
            "dev.api.example.com": {"ips": ["1.2.3.5"]},
        }
        parents = recursion_parents(resolved, "example.com", 2, wildcard_ip="9.9.9.9", cap=100)
        self.assertEqual(parents, ["api.example.com"])
        self.assertEqual(recursion_parents(resolved, "example.com", 1, None, 100), ["example.com"])


class TestVhostBases(unittest.TestCase):
    def test_depth_one_is_apex_only(self):
        self.assertEqual(
            vhost_bases("example.com", ["api.example.com", "www.example.com"], 1),
            ["example.com"],
        )

    def test_depth_two_includes_one_label(self):
        bases = vhost_bases("example.com", ["api.example.com", "dev.api.example.com"], 2)
        self.assertEqual(bases, ["example.com", "api.example.com"])

    def test_vhost_driven_parents_skip_too_deep(self):
        resolved = {"api.example.com": {"ips": ["1.1.1.1"]}}
        extra = ["staging.api.example.com", "api.example.com"]
        parents = vhost_driven_parents(
            "example.com", 2, resolved, extra, already={"example.com"}, wildcard_names=set(), cap=100
        )
        self.assertEqual(parents, ["api.example.com"])
        self.assertNotIn("staging.api.example.com", parents)


class TestClamp(unittest.TestCase):
    def test_prefers_recon_depth(self):
        params = Params(_ROOT)
        params.settings["recon_depth"] = 3
        params.settings["ffuf_depth"] = 1
        self.assertEqual(clamp_recon_depth(params), 3)
        self.assertEqual(clamp_ffuf_depth(params), 1)

    def test_falls_back_to_ffuf_depth(self):
        params = Params(_ROOT)
        params.settings.pop("recon_depth", None)
        params.settings["ffuf_depth"] = 2
        self.assertEqual(clamp_recon_depth(params), 2)

    def test_ffuf_depth_independent(self):
        params = Params(_ROOT)
        params.settings["recon_depth"] = 4
        params.settings["ffuf_depth"] = 2
        self.assertEqual(clamp_recon_depth(params), 4)
        self.assertEqual(clamp_ffuf_depth(params), 2)


class TestProfileAndSettings(unittest.TestCase):
    def test_recon_depth_is_overridable(self):
        ok = validate_profile("example.com", {"budgets": {"recon_depth": 2, "ffuf_depth": 3}})
        self.assertEqual(ok["budgets"]["recon_depth"], 2)
        self.assertEqual(ok["budgets"]["ffuf_depth"], 3)

    def test_global_save_writes_depths_independently(self):
        tmp = Path(tempfile.mkdtemp())
        (tmp / "tools.yaml").write_text((_ROOT / "tools.yaml").read_text(encoding="utf-8"), encoding="utf-8")
        (tmp / "dashboard").mkdir()
        params = Params(tmp)
        self.assertEqual(validate_settings({"recon_depth": 2, "ffuf_depth": 4}), [])
        self.assertTrue(validate_settings({"recon_depth": 9}))
        saved = save_settings(params, {"recon_depth": 2, "ffuf_depth": 4, "passive_recursion_depth": 1})
        self.assertEqual(saved["recon_depth"], 2)
        self.assertEqual(saved["ffuf_depth"], 4)
        text = (tmp / "tools.yaml").read_text(encoding="utf-8")
        self.assertIn("  recon_depth: 2", text)
        self.assertIn("  ffuf_depth: 4", text)
        self.assertIn("  passive_recursion_depth: 1", text)
        loaded = load_settings(Params(tmp))
        self.assertEqual(loaded["recon_depth"], 2)
        self.assertEqual(loaded["ffuf_depth"], 4)

    def test_transient_plan_does_not_sync_ffuf_from_recon(self):
        tmp = Path(tempfile.mkdtemp())
        tools_src = (_ROOT / "tools.yaml").read_text(encoding="utf-8")
        # Robust to the committed default (may be tuned for speed): force a
        # distinct high base so we can prove ffuf_depth is NOT synced from recon.
        tools_src = re.sub(r"^  ffuf_depth: \d+", "  ffuf_depth: 5", tools_src, flags=re.M)
        tools_src = re.sub(r"^  recon_depth: \d+", "  recon_depth: 5", tools_src, flags=re.M)
        (tmp / "tools.yaml").write_text(tools_src, encoding="utf-8")
        (tmp / "wordlists.yaml").write_text((_ROOT / "wordlists.yaml").read_text(encoding="utf-8"), encoding="utf-8")
        params = Params(tmp)
        set_profile(params, "site.test", {"budgets": {"recon_depth": 2}})
        before = tmp / "before"
        before.mkdir()
        token = apply_transient(params, "site.test", before)
        text = (tmp / "tools.yaml").read_text(encoding="utf-8")
        self.assertIn("  recon_depth: 2", text)
        self.assertIn("  ffuf_depth: 5", text)
        params.reload()
        self.assertEqual(clamp_recon_depth(params), 2)
        self.assertEqual(clamp_ffuf_depth(params), 5)
        restore_transient(token)

    def test_module_list_override_and_reload(self):
        tmp = Path(tempfile.mkdtemp())
        (tmp / "tools.yaml").write_text((_ROOT / "tools.yaml").read_text(encoding="utf-8"), encoding="utf-8")
        (tmp / "wordlists.yaml").write_text((_ROOT / "wordlists.yaml").read_text(encoding="utf-8"), encoding="utf-8")
        params = Params(tmp)
        set_profile(
            params,
            "site.test",
            {
                "budgets": {"recon_depth": 2},
                "modules": {"active_branch_modules": ["dns-resolve", "ffuf", "port-check"]},
            },
        )
        before = tmp / "before"
        before.mkdir()
        token = apply_transient(params, "site.test", before)
        params.reload()
        self.assertEqual(params.require("active_branch_modules"), ["dns-resolve", "ffuf", "port-check"])
        self.assertEqual(clamp_recon_depth(params), 2)
        restore_transient(token)


if __name__ == "__main__":
    unittest.main()
