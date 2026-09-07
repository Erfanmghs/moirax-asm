"""Atomic tests for C5 IP ROTATION / PROXY POOL (operator directive).

Laws under test:
- pool parse/dedupe/scheme law; credentials never echoed (masking)
- fail-fast gate names the unreachable entry, masked
- round-robin assignment per module + honest DIRECT rows for hook-less tools
- resolution chain: transient profile/tools.yaml pool > dashboard config pool
- per-target profile: closed key allow-list + scheme law + edit-plan emission
- dashboard settings: proxy_pool accepted (valid) / refused (bad scheme)
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dashboard.service import validate_settings  # noqa: E402
from pipeline.ip_rotation import (  # noqa: E402
    ProxyAssigner,
    ProxyPool,
    gate_pool_or_legacy,
    mask_proxy,
    parse_pool,
    spec_has_proxy_hook,
    validate_pool_value,
)
from pipeline.params import Params  # noqa: E402
from pipeline.target_profiles import (  # noqa: E402
    ProfileError,
    build_edit_plan,
    set_profile,
    validate_profile,
)

_ROOT = Path(__file__).resolve().parents[1]


def _isolated_root() -> Path:
    tmp = Path(tempfile.mkdtemp())
    for rel in ("tools.yaml", "wordlists.yaml", "scope.yaml"):
        src = _ROOT / rel
        if src.is_file():
            (tmp / rel).write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    (tmp / "dashboard").mkdir(exist_ok=True)
    (tmp / "wordlists" / "local").mkdir(parents=True, exist_ok=True)
    return tmp


def _params(root: Path | None = None) -> Params:
    return Params(root or _isolated_root())


def _write_config(params: Params, doc: dict) -> None:
    path = params.root / str(params.require("dashboard_config_relpath"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")


class TestPoolLaws(unittest.TestCase):
    def test_parse_pool_splits_dedupes_preserving_order(self):
        pool = parse_pool("http://a:1, socks5://b:2 ,http://a:1,https://c:3")
        self.assertEqual(pool, ["http://a:1", "socks5://b:2", "https://c:3"])

    def test_parse_pool_refuses_bad_scheme_by_name(self):
        with self.assertRaises(ValueError) as ctx:
            parse_pool("http://a:1,ftp://evil:21")
        self.assertIn("ftp", str(ctx.exception))
        with self.assertRaises(ValueError):
            parse_pool("not-a-url")

    def test_parse_pool_accepts_list_form(self):
        self.assertEqual(parse_pool(["socks5://a:1", "socks5://a:1"]), ["socks5://a:1"])

    def test_validate_pool_value_type_law(self):
        with self.assertRaises(ValueError):
            validate_pool_value({"proxy": "http://a:1"})
        with self.assertRaises(ValueError):
            validate_pool_value([42])
        self.assertEqual(validate_pool_value(None), [])
        self.assertEqual(validate_pool_value(""), [])

    def test_mask_proxy_never_echoes_credentials(self):
        masked = mask_proxy("http://alice:s3cret-pw@proxy.example.com:8080")
        self.assertNotIn("s3cret-pw", masked)
        self.assertEqual(masked, "http://alice:***@proxy.example.com:8080")
        self.assertEqual(mask_proxy("socks5://10.0.0.9:1080"), "socks5://10.0.0.9:1080")
        self.assertEqual(mask_proxy("garbage"), "***")


class TestRotation(unittest.TestCase):
    def test_round_robin_order_and_ledger_masking(self):
        pool = ProxyPool(["http://u:secret@a:1", "socks5://b:2"])
        first = pool.assign("ffuf", "ffuf", proxied=True)
        second = pool.assign("httpx", "httpx-alive", proxied=True)
        third = pool.assign("ffuf", "ffuf-2", proxied=True)
        self.assertEqual((first[0], second[0], third[0]),
                         ("http://u:secret@a:1", "socks5://b:2", "http://u:secret@a:1"))
        self.assertEqual(first[1], 0)
        self.assertEqual(second[1], 1)
        self.assertEqual(third[1], 0)
        for row in pool.rows:
            self.assertNotIn("secret", row["proxy"])

    def test_hookless_tools_get_honest_direct_rows(self):
        pool = ProxyPool(["http://a:1"])
        url, idx = pool.assign("naabu", "port-sweep", proxied=False)
        self.assertEqual((url, idx), ("", -1))
        self.assertEqual(pool.rows[0]["proxy"], "direct (tool has no proxy hook)")

    def test_spec_hook_detection_uses_real_registry(self):
        params = _params()
        self.assertTrue(spec_has_proxy_hook(params.tools["ffuf"]))
        self.assertTrue(spec_has_proxy_hook(params.tools["httpx"]))
        self.assertFalse(spec_has_proxy_hook(params.tools["naabu"]))


class TestGateAndResolutionChain(unittest.TestCase):
    def _checker(self, reachable: set[str]):
        def check(url: str):
            if url in reachable:
                return True, "ok"
            return False, f"proxy unreachable at {url}"

        return check

    def test_gate_passes_when_all_reachable(self):
        params = _params()
        _write_config(params, {"proxy_pool": "http://u:pw@a:1,socks5://b:2"})
        assigner = ProxyAssigner.from_params(
            params, checker=self._checker({"http://u:pw@a:1", "socks5://b:2"})
        )
        self.assertIsNotNone(assigner)
        ok, reason = assigner.gate()
        self.assertTrue(ok, reason)
        self.assertIn("2 entries", reason)
        self.assertIn("http://u:***@a:1", reason)   # masked rendering
        self.assertNotIn("pw", reason)              # credentials never echoed

    def test_gate_fails_fast_naming_bad_entry_masked(self):
        pool = ProxyPool(["http://good:1", "http://u:pw@bad:2"])
        assigner = ProxyAssigner(pool, checker=self._checker({"http://good:1"}))
        ok, reason = assigner.gate()
        self.assertFalse(ok)
        self.assertIn("#2", reason)
        self.assertIn("http://u:***@bad:2", reason)
        self.assertNotIn("pw", reason)

    def test_resolution_chain_tools_yaml_beats_config(self):
        params = _params()
        params.settings["proxy_pool"] = "http://from-tools:1"
        _write_config(params, {"proxy_pool": "http://from-config:1"})
        assigner = ProxyAssigner.from_params(params)
        self.assertEqual(assigner.pool.entries, ["http://from-tools:1"])

    def test_resolution_chain_config_fallback(self):
        params = _params()
        _write_config(params, {"proxy_pool": "http://from-config:1"})
        assigner = ProxyAssigner.from_params(params)
        self.assertEqual(assigner.pool.entries, ["http://from-config:1"])

    def test_no_pool_anywhere_returns_none(self):
        self.assertIsNone(ProxyAssigner.from_params(_params()))

    def test_gate_facade_falls_back_to_legacy_single_proxy(self):
        params = _params()
        params.settings["proxy_url"] = "http://single:9"
        legacy = mock.MagicMock(return_value=(False, "single unreachable"))
        ok, reason, assigner = gate_pool_or_legacy(params, legacy_gate=legacy)
        self.assertFalse(ok)
        self.assertEqual(reason, "single unreachable")
        self.assertIsNone(assigner)
        legacy.assert_called_once_with(params)

    def test_gate_facade_uses_pool_when_configured(self):
        params = _params()
        params.settings["proxy_pool"] = "http://a:1"
        ok, reason, assigner = gate_pool_or_legacy(
            params, checker=self._checker({"http://a:1"})
        )
        self.assertTrue(ok)
        self.assertIsNotNone(assigner)


class TestHookValues(unittest.TestCase):
    def test_hook_values_injects_proxy_url_for_hooked_tool(self):
        params = _params()
        assigner = ProxyAssigner(ProxyPool(["http://a:1", "socks5://b:2"]))
        values = assigner.hook_values("ffuf", "ffuf", params.tools["ffuf"])
        self.assertEqual(values, {"proxy_url": "http://a:1"})
        values2 = assigner.hook_values("httpx", "httpx-alive", params.tools["httpx"])
        self.assertEqual(values2, {"proxy_url": "socks5://b:2"})

    def test_hook_values_empty_for_hookless_tool(self):
        params = _params()
        assigner = ProxyAssigner(ProxyPool(["http://a:1"]))
        values = assigner.hook_values("naabu", "port-sweep", params.tools["naabu"])
        self.assertEqual(values, {})
        self.assertEqual(assigner.pool.rows[0]["proxy_index"], -1)

    def test_ledger_write_is_masked_and_never_fails(self):
        params = _params()
        target_dir = params.root / "targets" / "example.com"
        assigner = ProxyAssigner(ProxyPool(["http://u:topsecret@a:1"]))
        assigner.hook_values("ffuf", "ffuf", params.tools["ffuf"])
        assigner.write_ledger(target_dir)
        doc = json.loads((target_dir / "logs" / "proxy-rotation.json").read_text(encoding="utf-8"))
        self.assertEqual(doc["pool"], ["http://u:***@a:1"])
        self.assertNotIn("topsecret", json.dumps(doc))
        # a second write into a nonexistent tree must not raise either
        assigner.write_ledger(params.root / "does" / "not" / "exist" / "deep")


class TestProfileProxyLaws(unittest.TestCase):
    def test_valid_per_target_pool_accepted(self):
        clean = validate_profile("bugdasht.ir", {
            "proxy": {"proxy_pool": "http://a:1, socks5://b:2"},
        })
        self.assertEqual(clean["proxy"]["proxy_pool"], "http://a:1, socks5://b:2")

    def test_unknown_proxy_key_refused(self):
        with self.assertRaises(ProfileError):
            validate_profile("bugdasht.ir", {"proxy": {"proxy_enabled": True}})

    def test_bad_scheme_refused_before_registry(self):
        with self.assertRaises(ProfileError) as ctx:
            validate_profile("bugdasht.ir", {"proxy": {"proxy_pool": "ftp://evil:21"}})
        self.assertIn("ftp", str(ctx.exception))

    def test_edit_plan_emits_quoted_tools_edit(self):
        params = _params()
        set_profile(params, "bugdasht.ir", {
            "proxy": {"proxy_pool": "http://u:p@a:1,socks5://b:2"},
        })
        plan = build_edit_plan(params, "bugdasht.ir")
        proxy_edits = [e for e in plan["tools_edits"] if e["key"] == "proxy_pool"]
        self.assertEqual(len(proxy_edits), 1)
        self.assertEqual(proxy_edits[0]["value"], '"http://u:p@a:1,socks5://b:2"')


class TestSettingsProxyPool(unittest.TestCase):
    def test_valid_pool_accepted(self):
        errors = validate_settings({"proxy_pool": "http://a:1,socks5://b:2"})
        self.assertEqual(errors, [])

    def test_empty_pool_cleared(self):
        errors = validate_settings({"proxy_pool": ""})
        self.assertEqual(errors, [])

    def test_bad_scheme_refused(self):
        errors = validate_settings({"proxy_pool": "http://a:1,ftp://evil:21"})
        self.assertEqual(len(errors), 1)
        self.assertIn("proxy_pool invalid", errors[0])

    def test_non_string_refused(self):
        errors = validate_settings({"proxy_pool": ["http://a:1"]})
        self.assertEqual(len(errors), 1)
        self.assertIn("comma-separated", errors[0])


if __name__ == "__main__":
    unittest.main()
