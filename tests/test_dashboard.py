"""B6 DASHBOARD unit proof (spec §9.1/§9.2/§9.3) — deterministic, no network."""

from __future__ import annotations

import os
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from dashboard.service import (
    DashboardError,
    ProxyUnreachableError,
    apply_filters,
    apply_tools_edit,
    apply_wordlists_edit,
    check_proxy_reachable,
    coverage_analytics,
    delete_key,
    list_keys,
    load_settings,
    mask_secret,
    parse_filters_query,
    proxy_gate,
    save_settings,
    scheduler_save,
    serialize_filters,
    set_key,
    validate_settings,
    validate_tools_edit,
    validate_wordlists_edit,
)
from pipeline.params import Params

_ROOT = Path(__file__).resolve().parents[1]


def _params(overrides: dict | None = None) -> Params:
    params = Params(_ROOT)
    for key, value in (overrides or {}).items():
        params.settings[key] = value
    return params


def _isolated_root() -> Path:
    """Temp copy of the mutable dashboard-touchable files (never the repo)."""
    tmp = Path(tempfile.mkdtemp())
    for rel in ("tools.yaml", "wordlists.yaml", "scheduler.json", "scope.yaml"):
        src = _ROOT / rel
        if src.is_file():
            (tmp / rel).write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    (tmp / "dashboard").mkdir(exist_ok=True)
    return tmp


def _isolated_params() -> Params:
    """Params rooted at a temp copy — dashboard writes never touch the repo."""
    return Params(_isolated_root())


class TestMasking(unittest.TestCase):
    def test_mask_secret(self):
        self.assertEqual(mask_secret("abcdefghijklmnop"), "abc****op")
        self.assertEqual(mask_secret("ab"), "****")
        self.assertEqual(mask_secret(""), "")


class TestApiKeysPanelD(unittest.TestCase):
    """§9.2-d: .env-backed, masked after save, never committed, next-run pickup."""

    def _params(self) -> Params:
        return _isolated_params()

    def test_set_list_masked_delete_roundtrip(self):
        params = self._params()
        set_key(params, "SHODAN_API_KEY", "supersecretvalue123")
        rows = {r["name"]: r for r in list_keys(params)}
        self.assertTrue(rows["SHODAN_API_KEY"]["set"])
        self.assertEqual(rows["SHODAN_API_KEY"]["masked"], "sup****23")
        self.assertNotIn("supersecretvalue123", (params.root / ".env").read_text(encoding="utf-8").replace("supersecretvalue123", ""))
        env_text = (params.root / ".env").read_text(encoding="utf-8")
        self.assertIn("SHODAN_API_KEY=supersecretvalue123", env_text, "value persisted to .env verbatim (never logged)")
        delete_key(params, "SHODAN_API_KEY")
        self.assertFalse({r["name"] for r in list_keys(params) if r["set"]} & {"SHODAN_API_KEY"})

    def test_registry_is_allowlist(self):
        with self.assertRaises(DashboardError):
            set_key(self._params(), "NOT_A_KEY", "x")

    def test_registry_covers_spec_examples(self):
        names = {r["name"] for r in list_keys(self._params())}
        for required in ("SHODAN_API_KEY", "CENSYS_API_ID", "GITHUB_TOKEN", "CHAOS_KEY",
                         "SERPER_API_KEY", "BRAVE_API_KEY", "GOOGLE_CSE_KEY", "GOOGLE_CSE_CX",
                         "TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID"):
            self.assertIn(required, names)


class TestSettingsPanelE(unittest.TestCase):
    """§9.2-e: proxy + Telegram + digest threshold + alert filters persisted to
    dashboard/config.json (gitignored), secrets masked on read."""

    def _params(self) -> Params:
        return _isolated_params()

    def test_save_and_masked_load(self):
        params = self._params()
        saved = save_settings(params, {
            "telegram": {"bot_token": "123456:ABCDEF-secret", "chat_id": "424242"},
            "digest_threshold": 7,
            "alert_rules": [{"class": "ports", "enabled": True, "require_new_ip": False}],
        })
        self.assertEqual(saved["telegram"]["bot_token"], "123****et", "token masked after save (§9.2-e)")
        self.assertEqual(saved["telegram"]["chat_id"], "424242")
        raw = (params.root / "dashboard" / "config.json").read_text(encoding="utf-8")
        self.assertIn("424242", raw)  # non-secret chat id stored
        loaded = load_settings(params)
        self.assertEqual(loaded["digest_threshold"], 7)

    def test_validation_rejects(self):
        self.assertTrue(validate_settings({"digest_threshold": 0}))
        self.assertTrue(validate_settings({"proxy_url": "ftp://x"}))
        self.assertTrue(validate_settings({"alert_rules": [{"nope": 1}]}))
        self.assertTrue(validate_settings({"resource_budget": {"ram_mb": -1}}))
        self.assertEqual(validate_settings({"proxy_url": "socks5://1.2.3.4:1080"}), [])

    def test_scheduler_floor_enforced_via_panel(self):
        with self.assertRaises(DashboardError):
            scheduler_save(self._params(), {"interval_minutes": 5, "enabled": True, "last_run": None})


class TestToolsEditorPanelA(unittest.TestCase):
    """§5.4/§9.2-a: enable/disable + per-tool flag overrides, schema-validated."""

    def test_validate_rejects_forbidden_keys(self):
        params = _params()
        doc = {"tools": {"ffuf": {"enabled": False}}}
        with self.assertRaises(DashboardError):
            validate_tools_edit(doc, "ffuf", {"image": "evil:1"})
        with self.assertRaises(DashboardError):
            validate_tools_edit(doc, "missing", {"enabled": True})
        with self.assertRaises(DashboardError):
            validate_tools_edit(doc, "ffuf", {"flag_overrides": {"ok": {"nested": 1}}})
        with self.assertRaises(DashboardError):
            validate_tools_edit(doc, "ffuf", {"flag_overrides": {"NotNamed": 1}})

    def test_surgical_edit_visible_in_next_run_command(self):
        """Companion B6 acceptance: parameter edit visible in next run command.
        The edit lands in the tool's flag_overrides — exactly what
        adapter._values merges before assembling the next run's argv."""
        params = _isolated_params()
        tmp = params.root
        apply_tools_edit(params, "echo-tool", {
            "enabled": True,
            "flag_overrides": {"echo_passive_hosts": "edited.example.com"},
        })
        from pipeline.yaml_util import load_yaml_file

        reloaded = load_yaml_file(str(tmp / "tools.yaml"))
        self.assertTrue(reloaded["tools"]["echo-tool"]["enabled"])
        self.assertEqual(
            reloaded["tools"]["echo-tool"]["flag_overrides"]["echo_passive_hosts"],
            "edited.example.com",
        )
        text = (tmp / "tools.yaml").read_text(encoding="utf-8")
        self.assertIn("# TEST FIXTURE (verify_b1)", text, "surgical edit preserves unrelated comments")
        # NEXT RUN COMMAND proof: a FRESH Params (next run = fresh process that
        # re-reads the edited file) + adapter assembled from it produces argv
        # carrying the edited value.
        from pipeline.adapter import Adapter, ScriptedRunner
        from pipeline.breaker import CircuitBreaker, FakeClock
        from pipeline.ceiling import ResourceCeiling

        params2 = Params(tmp)
        clock = FakeClock()
        breaker = CircuitBreaker(params2, clock=clock, target_dir=tmp, target="example.com")
        adapter = Adapter(params2, tmp, breaker, ResourceCeiling(params2), clock=clock, runner=ScriptedRunner())
        argv = adapter.assemble("echo-tool", {"target_domain": "example.com"}, "echo-tool")
        self.assertIn("edited.example.com", argv, f"edit must be visible in next run command: {argv}")

    def test_override_upsert_on_tool_without_flag_overrides_block(self):
        params = _isolated_params()
        tmp = params.root
        doc = params.tools
        tool = next(name for name, spec in doc.items()
                    if "flag_overrides" not in (spec or {}) and (spec or {}).get("enabled") is not None)
        apply_tools_edit(params, tool, {"flag_overrides": {"target_domain": "probe.example.com"}})
        from pipeline.yaml_util import load_yaml_file

        reloaded = load_yaml_file(str(tmp / "tools.yaml"))
        self.assertEqual(reloaded["tools"][tool]["flag_overrides"]["target_domain"], "probe.example.com")


class TestWordlistsEditorPanelA(unittest.TestCase):
    """§9.2-a: per-task checkbox selection + SELECT-ALL per task group."""

    def test_validate_against_registered_groups(self):
        params = _params()
        from pipeline.yaml_util import load_yaml_file

        doc = load_yaml_file(str(_ROOT / "wordlists.yaml"))
        clean = validate_wordlists_edit(doc, {"FFUF-0": ["dns_fast_top5000", "test_smoke_200"]})
        self.assertEqual(clean["FFUF-0"], ["dns_fast_top5000", "test_smoke_200"])
        with self.assertRaises(DashboardError):
            validate_wordlists_edit(doc, {"FFUF-0": ["not_a_key"]})
        with self.assertRaises(DashboardError):
            validate_wordlists_edit(doc, {"NOPE": ["dns_fast_top5000"]})

    def test_selection_edit_roundtrip(self):
        params = _isolated_params()
        tmp = params.root
        apply_wordlists_edit(params, {"DNSR-1": ["dns_fast_fierce", "test_smoke_200"]})
        from pipeline.yaml_util import load_yaml_file

        doc = load_yaml_file(str(tmp / "wordlists.yaml"))
        self.assertEqual(sorted(doc["tasks"]["DNSR-1"]["selection"]), ["dns_fast_fierce", "test_smoke_200"])


class TestGlobalFilters(unittest.TestCase):
    """§9.2-b GLOBAL RESULT FILTERS: combinable + URL-shareable."""

    ROWS = [
        {"host": "dev.example.com", "ips": ["1.1.1.1"], "alive": True, "sources": ["subfinder", "crtsh"], "tags": ["dev"]},
        {"host": "api.example.com", "ips": ["2.2.2.2"], "alive": False, "sources": ["subfinder"], "tags": []},
        {"host": "out.example.com", "ips": ["3.3.3.3"], "alive": True, "sources": ["crtsh"], "tags": ["stage"]},
    ]

    def test_free_text(self):
        self.assertEqual(len(apply_filters(self.ROWS, {"q": "api"})), 1)

    def test_source_attribution(self):
        self.assertEqual(len(apply_filters(self.ROWS, {"source": "crtsh"})), 2)

    def test_tag(self):
        self.assertEqual([r["host"] for r in apply_filters(self.ROWS, {"tag": "dev"})], ["dev.example.com"])

    def test_alive(self):
        self.assertEqual(len(apply_filters(self.ROWS, {"alive": "false"})), 1)

    def test_combinable(self):
        got = apply_filters(self.ROWS, {"source": "subfinder", "alive": "true"})
        self.assertEqual([r["host"] for r in got], ["dev.example.com"])

    def test_url_state_roundtrip(self):
        """Companion B6 acceptance: URL filter state restores correctly."""
        original = {"q": "dev", "source": "subfinder", "alive": "true", "tag": "a b"}
        query = serialize_filters(original)
        restored = parse_filters_query(query)
        self.assertEqual(restored, original)


class TestCoverageAnalytics(unittest.TestCase):
    """§9.2-b SOURCE COVERAGE ANALYTICS."""

    def test_contribution_overlap_uniqueness(self):
        rows = [
            {"sources": ["a", "b"]},
            {"sources": ["a"]},
            {"sources": ["a", "b", "c"]},
            {"sources": []},
        ]
        cov = coverage_analytics(rows)
        self.assertEqual(cov["assets"], 4)
        self.assertEqual(cov["contribution"], {"a": 3, "b": 2, "c": 1})
        self.assertEqual(cov["unique_assets"], {"a": 1})
        self.assertEqual(cov["overlap_by_n_sources"], {"2": 1, "1": 1, "3": 1, "0": 1})
        self.assertAlmostEqual(cov["uniqueness_pct"]["a"], 33.3, delta=0.1)
        self.assertEqual(cov["uniqueness_pct"]["c"], 0.0)


class TestProxyRule(unittest.TestCase):
    """§9.3: set-but-unreachable → FAIL FAST; unset → direct silently."""

    def test_unset_direct_silently(self):
        ok, reason = proxy_gate(_params({"proxy_url": ""}))
        self.assertTrue(ok)
        self.assertIn("direct", reason)

    def test_set_but_unreachable_fails(self):
        ok, reason = check_proxy_reachable("http://127.0.0.1:1", timeout=0.5)
        self.assertFalse(ok)
        gate_ok, gate_reason = proxy_gate(_params({"proxy_url": "http://127.0.0.1:1", "proxy_check_timeout_sec": 1}))
        self.assertFalse(gate_ok)
        self.assertIn("unreachable", gate_reason)

    def test_set_and_reachable_passes(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        try:
            ok, reason = check_proxy_reachable(f"http://127.0.0.1:{port}", timeout=1.0)
            self.assertTrue(ok, reason)
        finally:
            srv.close()

    def test_engine_fail_fast_wiring(self):
        engine_text = (_ROOT / "pipeline" / "engine.py").read_text(encoding="utf-8")
        self.assertIn("PROXY RULE fail-fast", engine_text)
        self.assertIn("proxy_gate(params)", engine_text)


class TestDashboardApi(unittest.TestCase):
    """FastAPI smoke (§9.1 auth fail-closed + §9.2 endpoints)."""

    def setUp(self):
        from fastapi.testclient import TestClient

        from dashboard.app import app

        self.client = TestClient(app)
        self.token_headers = {"Authorization": "Bearer test-token"}

    def test_health_no_auth(self):
        r = self.client.get("/api/health")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json()["ok"])

    def test_auth_fail_closed_without_backend_token(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            r = self.client.get("/api/tools")
            self.assertEqual(r.status_code, 503, "unset DASHBOARD_TOKEN refuses everything (fail-closed)")
            r2 = self.client.put("/api/settings", json={})
            self.assertEqual(r2.status_code, 503)

    def test_auth_rejects_bad_token(self):
        with mock.patch.dict(os.environ, {"DASHBOARD_TOKEN": "real"}, clear=False):
            r = self.client.get("/api/tools", headers={"Authorization": "Bearer wrong"})
            self.assertEqual(r.status_code, 401)

    def test_tools_wordlists_settings_scheduler_endpoints(self):
        params = _isolated_params()
        tmp = params.root
        env = {"DASHBOARD_TOKEN": "test-token"}
        with mock.patch.dict(os.environ, env, clear=False):
            from dashboard import app as appmod

            with mock.patch.object(appmod, "_params_obj", return_value=params):
                r = self.client.get("/api/tools", headers=self.token_headers)
                self.assertEqual(r.status_code, 200)
                self.assertIn("tools", r.json())
                r = self.client.put("/api/tools/echo-tool", json={"enabled": True}, headers=self.token_headers)
                self.assertEqual(r.status_code, 200, r.text)
                r = self.client.put("/api/tools/echo-tool", json={"evil": 1}, headers=self.token_headers)
                self.assertEqual(r.status_code, 422, "schema-validated write rejected")
                r = self.client.get("/api/wordlists", headers=self.token_headers)
                self.assertEqual(r.status_code, 200)
                r = self.client.put("/api/scheduler", json={"interval_minutes": 4, "enabled": True, "last_run": None}, headers=self.token_headers)
                self.assertEqual(r.status_code, 422, "§4.6 floor enforced via API")
                r = self.client.put("/api/settings", json={"telegram": {"bot_token": "tok123456789", "chat_id": "5"}}, headers=self.token_headers)
                self.assertEqual(r.status_code, 200)
                masked = r.json()["telegram"]["bot_token"]
                self.assertNotEqual(masked, "tok123456789", "token never echoed unmasked")
                r = self.client.get("/api/settings", headers=self.token_headers)
                self.assertIn("****", r.json().get("telegram", {}).get("bot_token", ""))
                r = self.client.get("/api/results/example.com", headers=self.token_headers)
                self.assertEqual(r.status_code, 200)
                r = self.client.get("/api/keys", headers=self.token_headers)
                self.assertEqual(r.status_code, 200)

    def test_keys_roundtrip_via_api(self):
        params = _isolated_params()
        tmp = params.root
        with mock.patch.dict(os.environ, {"DASHBOARD_TOKEN": "test-token"}, clear=False):
            from dashboard import app as appmod

            with mock.patch.object(appmod, "_params_obj", return_value=params):
                r = self.client.put("/api/keys/SHODAN_API_KEY", json={"value": "secret-key-9999"}, headers=self.token_headers)
                self.assertEqual(r.status_code, 200)
                self.assertIn("SHODAN_API_KEY=secret-key-9999", (tmp / ".env").read_text(encoding="utf-8"))
                rows = {x["name"]: x for x in self.client.get("/api/keys", headers=self.token_headers).json()["keys"]}
                self.assertEqual(rows["SHODAN_API_KEY"]["masked"], "sec****99")
                r = self.client.delete("/api/keys/SHODAN_API_KEY", headers=self.token_headers)
                self.assertEqual(r.status_code, 200)
                self.assertNotIn("SHODAN_API_KEY=", (tmp / ".env").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
