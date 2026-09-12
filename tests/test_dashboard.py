"""B6 DASHBOARD unit proof (spec section 9.1/section 9.2/section 9.3) -- deterministic, no network."""

from __future__ import annotations

import json
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
    attach_open_ports,
    apply_tools_edit,
    apply_wordlists_edit,
    check_proxy_reachable,
    coverage_analytics,
    delete_key,
    list_keys,
    load_settings,
    mask_secret,
    results_rows_for,
    parse_filters_query,
    ports_for_host,
    proxy_gate,
    save_settings,
    scheduler_save,
    serialize_filters,
    set_key,
    unique_wordlist_keys_by_path,
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
    """Params rooted at a temp copy -- dashboard writes never touch the repo."""
    return Params(_isolated_root())


class TestMasking(unittest.TestCase):
    def test_mask_secret(self):
        self.assertEqual(mask_secret("abcdefghijklmnop"), "abc****op")
        self.assertEqual(mask_secret("ab"), "****")
        self.assertEqual(mask_secret(""), "")


class TestApiKeysPanelD(unittest.TestCase):
    """section 9.2-d: .env-backed, masked after save, never committed, next-run pickup."""

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

    def test_env_write_preserves_comments_and_unrelated_keys(self):
        params = self._params()
        env_path = params.root / ".env"
        env_path.write_text("# keep me\nUNRELATED=stay\nSHODAN_API_KEY=old\n", encoding="utf-8")
        set_key(params, "BRAVE_API_KEY", "newbravevalue")
        text = env_path.read_text(encoding="utf-8")
        self.assertIn("# keep me", text)
        self.assertIn("UNRELATED=stay", text)
        self.assertIn("BRAVE_API_KEY=newbravevalue", text)
        self.assertIn("SHODAN_API_KEY=old", text)

    def test_registry_is_allowlist(self):
        with self.assertRaises(DashboardError):
            set_key(self._params(), "NOT_A_KEY", "x")

    def test_registry_covers_spec_examples(self):
        names = {r["name"] for r in list_keys(self._params())}
        for required in ("SHODAN_API_KEY", "CENSYS_API_ID", "GITHUB_TOKEN", "CHAOS_KEY",
                         "SERPER_API_KEY", "BRAVE_API_KEY", "GOOGLE_CSE_KEY", "GOOGLE_CSE_CX",
                         "TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID",
                         "SECURITYTRAILS_API_KEY", "VIRUSTOTAL_API_KEY"):
            self.assertIn(required, names)


class TestSettingsPanelE(unittest.TestCase):
    """section 9.2-e: proxy + Telegram + digest threshold + alert filters persisted to
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
        self.assertEqual(saved["telegram"]["bot_token"], "123****et", "token masked after save (section 9.2-e)")
        self.assertEqual(saved["telegram"]["chat_id"], "424242")
        raw = (params.root / "dashboard" / "config.json").read_text(encoding="utf-8")
        self.assertIn("424242", raw)  # non-secret chat id stored
        loaded = load_settings(params)
        self.assertEqual(loaded["digest_threshold"], 7)

    def test_partial_save_does_not_clobber_bot_token(self):
        params = self._params()
        save_settings(params, {
            "telegram": {"bot_token": "123456:ABCDEF-secret", "chat_id": "424242"},
            "digest_threshold": 7,
        })
        saved = save_settings(params, {
            "digest_threshold": 11,
            "telegram": {"chat_id": "999"},
        })
        self.assertEqual(saved["digest_threshold"], 11)
        self.assertEqual(saved["telegram"]["chat_id"], "999")
        self.assertEqual(saved["telegram"]["bot_token"], "123****et")
        raw = (params.root / "dashboard" / "config.json").read_text(encoding="utf-8")
        self.assertIn("123456:ABCDEF-secret", raw)
        self.assertNotIn("123****et", raw)
        save_settings(params, {"telegram": {"bot_token": "123****et", "chat_id": "999"}})
        raw2 = (params.root / "dashboard" / "config.json").read_text(encoding="utf-8")
        self.assertIn("123456:ABCDEF-secret", raw2)

    def test_nested_settings_closed_allow_list(self):
        self.assertTrue(validate_settings({"telegram": {"receiver_map": {"x": "1"}}}))
        self.assertTrue(validate_settings({"agent": {"shell": "id"}}))

    def test_validation_rejects(self):
        self.assertTrue(validate_settings({"digest_threshold": 0}))
        self.assertTrue(validate_settings({"proxy_url": "ftp://x"}))
        self.assertTrue(validate_settings({"alert_rules": [{"nope": 1}]}))
        self.assertTrue(validate_settings({"resource_budget": {"ram_mb": -1}}))
        self.assertEqual(validate_settings({"proxy_url": "socks5://1.2.3.4:1080"}), [])

    def test_retention_validation(self):
        self.assertTrue(validate_settings({"retention": "nope"}))
        self.assertTrue(validate_settings({"retention": {"keep_runs": 0}}))
        self.assertTrue(validate_settings({"retention": {"log_max_mb": True}}))
        self.assertTrue(validate_settings({"retention": {"max_total_mb": -5}}))
        self.assertEqual(validate_settings({"retention": {"keep_runs": 5, "log_max_mb": 10, "journal_max_mb": 5, "log_keep_gz": 3, "max_total_mb": 1024}}), [])
        self.assertEqual(validate_settings({"recon_depth": 2}), [])
        self.assertTrue(validate_settings({"recon_depth": 0}))

    def test_scheduler_floor_enforced_via_panel(self):
        with self.assertRaises(DashboardError):
            scheduler_save(self._params(), {"interval_minutes": 5, "enabled": True, "last_run": None})


class TestToolsEditorPanelA(unittest.TestCase):
    """section 5.4/section 9.2-a: enable/disable + per-tool flag overrides, schema-validated."""

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
        The edit lands in the tool's flag_overrides -- exactly what
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

    def test_full_port_sweep_cannot_be_disabled(self):
        params = _isolated_params()
        from pipeline.yaml_util import load_yaml_file

        doc = load_yaml_file(str(params.root / "tools.yaml"))
        with self.assertRaises(DashboardError):
            validate_tools_edit(doc, "naabu-full", {"enabled": False})
        apply_tools_edit(params, "naabu", {"enabled": True})
        reloaded = load_yaml_file(str(params.root / "tools.yaml"))
        self.assertTrue(reloaded["tools"]["naabu"]["enabled"])


class TestWordlistsEditorPanelA(unittest.TestCase):
    """section 9.2-a: per-task checkbox selection + SELECT-ALL per task group."""

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

    def test_duplicate_paths_collapse_on_save(self):
        params = _params()
        from pipeline.yaml_util import load_yaml_file

        doc = load_yaml_file(str(_ROOT / "wordlists.yaml"))
        clean = validate_wordlists_edit(doc, {"FFUF-0": ["dns_fast_top5000", "vhost_top5000", "dns_fast_top5000"]})
        self.assertEqual(clean["FFUF-0"], ["dns_fast_top5000"])

    def test_unique_wordlist_keys_by_path_prefers_task_family(self):
        lists = {
            "dns_fast_top5000": {"path": "Discovery/DNS/subdomains-top1million-5000.txt"},
            "vhost_top5000": {"path": "Discovery/DNS/subdomains-top1million-5000.txt"},
            "sl_discovery__dns__subdomains_top1million_5000": {"path": "Discovery/DNS/subdomains-top1million-5000.txt"},
            "dns_fast_fierce": {"path": "Discovery/DNS/fierce-hostlist.txt"},
            "vhost_fierce": {"path": "Discovery/DNS/fierce-hostlist.txt"},
        }
        keys = list(lists)
        self.assertEqual(
            unique_wordlist_keys_by_path(lists, keys, task="DNSR-1"),
            ["dns_fast_fierce", "dns_fast_top5000"],
        )
        self.assertEqual(
            unique_wordlist_keys_by_path(lists, keys, task="FFUF-2"),
            ["vhost_fierce", "vhost_top5000"],
        )

    def test_selection_edit_roundtrip(self):
        params = _isolated_params()
        tmp = params.root
        apply_wordlists_edit(params, {"DNSR-1": ["dns_fast_fierce", "test_smoke_200"]})
        from pipeline.yaml_util import load_yaml_file

        doc = load_yaml_file(str(tmp / "wordlists.yaml"))
        self.assertEqual(sorted(doc["tasks"]["DNSR-1"]["selection"]), ["dns_fast_fierce", "test_smoke_200"])


class TestGlobalFilters(unittest.TestCase):
    """section 9.2-b GLOBAL RESULT FILTERS: combinable + URL-shareable."""

    ROWS = [
        {"host": "dev.example.com", "ips": ["1.1.1.1"], "alive": True, "sources": ["subfinder", "crtsh"], "tags": ["dev"], "open_ports_total": 2, "tech": ["nginx"], "length": 1234, "first_seen": "20260101T000000Z"},
        # genuinely dead: never resolved (no IP). An IP-bearing host is a live
        # asset regardless of its stored alive flag, so a dead row must have no IP.
        {"host": "api.example.com", "ips": [], "alive": False, "sources": ["subfinder"], "tags": []},
        {"host": "out.example.com", "ips": ["3.3.3.3"], "alive": True, "sources": ["crtsh"], "tags": ["stage"], "open_ports_total": 0},
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
        original = {"q": "dev", "source": "subfinder", "alive": "true", "tag": "a b", "ports": "open", "host": "dev"}
        query = serialize_filters(original)
        restored = parse_filters_query(query)
        self.assertEqual(restored, original)

    def test_open_ports_column(self):
        self.assertEqual([r["host"] for r in apply_filters(self.ROWS, {"ports": "open"})], ["dev.example.com"])
        none = {r["host"] for r in apply_filters(self.ROWS, {"ports": "none"})}
        self.assertIn("api.example.com", none)
        self.assertIn("out.example.com", none)
        self.assertNotIn("dev.example.com", none)

    def test_host_ip_tech_length_columns(self):
        self.assertEqual([r["host"] for r in apply_filters(self.ROWS, {"host": "dev"})], ["dev.example.com"])
        self.assertEqual([r["host"] for r in apply_filters(self.ROWS, {"ip": "1.1.1.1"})], ["dev.example.com"])
        self.assertEqual([r["host"] for r in apply_filters(self.ROWS, {"tech": "nginx"})], ["dev.example.com"])
        self.assertEqual([r["host"] for r in apply_filters(self.ROWS, {"length": "1234"})], ["dev.example.com"])
        self.assertEqual([r["host"] for r in apply_filters(self.ROWS, {"first_seen": "20260101"})], ["dev.example.com"])


class TestCoverageAnalytics(unittest.TestCase):
    """section 9.2-b SOURCE COVERAGE ANALYTICS."""

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
    """section 9.3: set-but-unreachable -> FAIL FAST; unset -> direct silently."""

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
        # C5: the engine gates through the pool-aware facade; the legacy
        # single-proxy law stays reachable behind it (gate_pool_or_legacy).
        self.assertIn("gate_pool_or_legacy(params)", engine_text)


class TestDashboardApi(unittest.TestCase):
    """FastAPI smoke (section 9.1 auth fail-closed + section 9.2 endpoints)."""

    def setUp(self):
        from fastapi.testclient import TestClient

        from dashboard import authstore
        from dashboard.app import app

        self._auth_tmp = tempfile.TemporaryDirectory()
        self._auth_db = str(Path(self._auth_tmp.name) / "operator.sqlite")
        self._auth_env = mock.patch.dict(os.environ, {"RECON_AUTH_DB": self._auth_db}, clear=False)
        self._auth_env.start()
        authstore.reset()
        self.client = TestClient(app)
        self.token_headers = {"Authorization": "Bearer test-token"}

    def tearDown(self):
        from dashboard import authstore

        authstore.reset()
        self._auth_env.stop()
        self._auth_tmp.cleanup()

    def test_health_no_auth(self):
        r = self.client.get("/api/health")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json()["ok"])

    def test_auth_fail_closed_without_backend_token(self):
        from dashboard import authstore

        with mock.patch.dict(os.environ, {"RECON_AUTH_DB": self._auth_db}, clear=True):
            authstore.reset()
            r = self.client.get("/api/tools")
            self.assertEqual(r.status_code, 503, "unset DASHBOARD_TOKEN refuses everything (fail-closed)")
            r2 = self.client.put("/api/settings", json={})
            self.assertEqual(r2.status_code, 503)

    def test_auth_rejects_bad_token(self):
        with mock.patch.dict(os.environ, {"DASHBOARD_TOKEN": "real-token"}, clear=False):
            r = self.client.get("/api/tools", headers={"Authorization": "Bearer wrong"})
            self.assertEqual(r.status_code, 401)
        with mock.patch.dict(os.environ, {"DASHBOARD_TOKEN": "short"}, clear=False):
            r3 = self.client.get("/api/tools", headers={"Authorization": "Bearer short"})
            self.assertEqual(r3.status_code, 503, "token shorter than 8 chars is fail-closed")

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
                names = [t.get("name") for t in r.json()["tools"]]
                self.assertIn("ffuf", names)
                self.assertNotIn("echo-tool", names)
                dnsx = next(t for t in r.json()["tools"] if t.get("id") == "dnsx")
                self.assertIn("subdomain", (dnsx.get("technique") or "").lower())
                httpx = next(t for t in r.json()["tools"] if t.get("id") == "httpx")
                self.assertIn("length", httpx.get("technique") or "")
                r = self.client.put("/api/tools/echo-tool", json={"enabled": True}, headers=self.token_headers)
                self.assertEqual(r.status_code, 200, r.text)
                r = self.client.put("/api/tools/echo-tool", json={"evil": 1}, headers=self.token_headers)
                self.assertEqual(r.status_code, 422, "schema-validated write rejected")
                r = self.client.get("/api/wordlists", headers=self.token_headers)
                self.assertEqual(r.status_code, 200)
                r = self.client.put("/api/scheduler", json={"interval_minutes": 4, "enabled": True, "last_run": None}, headers=self.token_headers)
                self.assertEqual(r.status_code, 422, "section 4.6 floor enforced via API")
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

    def test_log_and_journal_export_endpoints(self):
        params = _isolated_params()
        target = "example.com"
        logs = params.root / "recon" / target / "logs"
        logs.mkdir(parents=True)
        (logs / "run.log").write_text("line-one\nline-two\n", encoding="utf-8")
        (logs / "agent-journal.jsonl").write_text(
            '{"ts":"2026-01-01T00:00:00Z","event":"engage"}\n',
            encoding="utf-8",
        )
        params.settings["agent_journal_relpath"] = "logs/agent-journal.jsonl"
        with mock.patch.dict(os.environ, {"DASHBOARD_TOKEN": "test-token"}, clear=False):
            from dashboard import app as appmod

            with mock.patch.object(appmod, "ROOT", params.root), mock.patch.object(
                appmod, "_params_obj", return_value=params
            ):
                missing = self.client.get(
                    "/api/run/log/missing.example/export",
                    headers=self.token_headers,
                )
                self.assertEqual(missing.status_code, 404)
                log_r = self.client.get(
                    f"/api/run/log/{target}/export",
                    headers=self.token_headers,
                )
                self.assertEqual(log_r.status_code, 200, log_r.text)
                self.assertIn("attachment", log_r.headers.get("content-disposition", "").lower())
                self.assertEqual(log_r.text, "line-one\nline-two\n")
                page = self.client.get(
                    f"/api/run/log/{target}?offset=0",
                    headers=self.token_headers,
                )
                self.assertEqual(page.status_code, 200)
                self.assertEqual(page.json()["lines"], ["line-one", "line-two"])
                journal_r = self.client.get(
                    f"/api/run/agent-journal/{target}/export",
                    headers=self.token_headers,
                )
                self.assertEqual(journal_r.status_code, 200, journal_r.text)
                self.assertIn("attachment", journal_r.headers.get("content-disposition", "").lower())
                self.assertIn("engage", journal_r.text)
                jpage = self.client.get(
                    f"/api/run/agent-journal/{target}?offset=0",
                    headers=self.token_headers,
                )
                self.assertEqual(jpage.status_code, 200)
                self.assertTrue(jpage.json()["exists"])
                self.assertEqual(len(jpage.json()["rows"]), 1)

    def test_log_journal_export_requires_auth_no_bac(self):
        """Anonymous / wrong-token clients must never receive log or journal bytes."""
        params = _isolated_params()
        target = "example.com"
        logs = params.root / "recon" / target / "logs"
        logs.mkdir(parents=True)
        secret = "SECRET-LOG-LINE-SHOULD-NOT-LEAK\n"
        (logs / "run.log").write_text(secret, encoding="utf-8")
        (logs / "agent-journal.jsonl").write_text(
            '{"ts":"2026-01-01T00:00:00Z","event":"secret-engage"}\n',
            encoding="utf-8",
        )
        params.settings["agent_journal_relpath"] = "logs/agent-journal.jsonl"
        export_paths = (
            f"/api/run/log/{target}/export",
            f"/api/run/agent-journal/{target}/export",
            f"/api/run/log/{target}",
            f"/api/run/agent-journal/{target}",
            f"/static-file/{target}/logs/run.log",
            f"/static-file/{target}/logs/agent-journal.jsonl",
        )
        with mock.patch.dict(os.environ, {"DASHBOARD_TOKEN": "test-token"}, clear=False):
            from dashboard import app as appmod

            with mock.patch.object(appmod, "ROOT", params.root), mock.patch.object(
                appmod, "_params_obj", return_value=params
            ):
                for path in export_paths:
                    anon = self.client.get(path)
                    self.assertIn(anon.status_code, (401, 503), path)
                    self.assertNotIn(b"SECRET-LOG", anon.content)
                    self.assertNotIn(b"secret-engage", anon.content)
                    bad = self.client.get(path, headers={"Authorization": "Bearer wrong-token"})
                    self.assertEqual(bad.status_code, 401, path)
                    self.assertNotIn(b"SECRET-LOG", bad.content)
                # Even with a valid session token, /static-file must not serve logs.
                blocked = self.client.get(
                    f"/static-file/{target}/logs/run.log",
                    headers=self.token_headers,
                )
                self.assertEqual(blocked.status_code, 403)
                self.assertNotIn(b"SECRET-LOG", blocked.content)
                blocked_j = self.client.get(
                    f"/static-file/{target}/logs/agent-journal.jsonl",
                    headers=self.token_headers,
                )
                self.assertEqual(blocked_j.status_code, 403)
                for bad_target in ("../etc", "a/b.com", "--flag", ""):
                    r = self.client.get(
                        f"/api/run/log/{bad_target}/export",
                        headers=self.token_headers,
                    )
                    self.assertIn(r.status_code, (404, 422), bad_target)

    def test_wordlists_expose_original_filenames(self):
        with mock.patch.dict(os.environ, {"DASHBOARD_TOKEN": "test-token"}, clear=False):
            r = self.client.get("/api/wordlists", headers=self.token_headers)
            self.assertEqual(r.status_code, 200)
            lists = r.json().get("lists") or {}
            smoke = lists.get("test_smoke_200") or {}
            self.assertEqual(smoke.get("name"), "test-smoke-200.txt")
            top = lists.get("dns_fast_top5000") or {}
            self.assertEqual(top.get("name"), "subdomains-top1million-5000.txt")
            tasks = r.json().get("tasks") or {}
            self.assertIn("DNSR-1", tasks)
            self.assertIn("FFUF-0", tasks)
            self.assertIn("FFUF-2", tasks)
            self.assertEqual(tasks.get("DNSR-1", {}).get("default_key"), "dns_fast_top5000")
            self.assertEqual(tasks.get("FFUF-2", {}).get("default_key"), "vhost_top5000")

    def test_wordlist_preview_returns_up_to_twenty_random_lines(self):
        from dashboard.service import wordlist_preview

        params = _isolated_params()
        dest = params.root / "wordlists" / "local"
        dest.mkdir(parents=True, exist_ok=True)
        src = _ROOT / "wordlists" / "local" / "test-smoke-200.txt"
        if src.is_file():
            (dest / "test-smoke-200.txt").write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
        else:
            (dest / "test-smoke-200.txt").write_text("\n".join(f"h{i}.example" for i in range(40)) + "\n", encoding="utf-8")
        a = wordlist_preview(params, "test_smoke_200", 20)
        self.assertEqual(a["key"], "test_smoke_200")
        self.assertLessEqual(len(a["samples"]), 20)
        self.assertGreaterEqual(len(a["samples"]), 1)
        self.assertTrue(all(isinstance(s, str) and s.isascii() for s in a["samples"]))
        with self.assertRaises(DashboardError):
            wordlist_preview(params, "../etc/passwd", 20)

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

    def test_warehouse_api_auth_isolation_and_results_enrichment(self):
        from pipeline.factory import ensure_layout
        from pipeline.history import empty_maps
        from pipeline.warehouse import ingest_maps

        params = _isolated_params()
        a = ensure_layout(params, "alpha.example")
        b = ensure_layout(params, "beta.example")

        def maps(hosts):
            out = empty_maps()
            for row in hosts:
                out["hosts"][str(row["host"])] = row
            return out

        ingest_maps(params, a, "alpha.example", "20260101T000000Z", "completed", {},
                    maps([{"host": "only-alpha.example", "alive": True}]))
        ingest_maps(params, a, "alpha.example", "20260102T000000Z", "completed", {},
                    maps([{"host": "only-alpha.example", "alive": True}, {"host": "new-alpha.example", "alive": True}]))
        ingest_maps(params, b, "beta.example", "20260101T000000Z", "completed", {},
                    maps([{"host": "only-beta.example", "alive": True}]))
        with mock.patch.dict(os.environ, {"DASHBOARD_TOKEN": "test-token"}, clear=False):
            from dashboard import app as appmod

            with mock.patch.object(appmod, "_params_obj", return_value=params):
                denied = self.client.get("/api/warehouse/alpha.example")
                self.assertEqual(denied.status_code, 401)
                st_a = self.client.get("/api/warehouse/alpha.example", headers=self.token_headers)
                st_b = self.client.get("/api/warehouse/beta.example", headers=self.token_headers)
                self.assertEqual(st_a.status_code, 200, st_a.text)
                self.assertEqual(st_a.json()["bound_target"], "alpha.example")
                self.assertEqual(st_b.json()["bound_target"], "beta.example")
                self.assertEqual(st_a.json()["facts"]["hosts"], 2)
                self.assertEqual(st_b.json()["facts"]["hosts"], 1)
                self.assertEqual(st_a.json()["path"], "warehouse.sqlite")
                self.assertTrue(st_a.json()["sealed"])
                self.assertTrue(st_b.json()["sealed"])
                illegal = self.client.get("/api/warehouse/-x", headers=self.token_headers)
                self.assertEqual(illegal.status_code, 422)
                diff = self.client.get(
                    "/api/results/alpha.example/diff?from_run=20260101T000000Z&to_run=20260102T000000Z",
                    headers=self.token_headers,
                )
                self.assertEqual(diff.status_code, 200, diff.text)
                added = {row["host"] for row in (diff.json().get("added") or {}).get("hosts") or []}
                self.assertEqual(added, {"new-alpha.example"})
                self.assertNotIn("only-beta.example", added)
                snap = self.client.get(
                    "/api/results/alpha.example?run=20260102T000000Z",
                    headers=self.token_headers,
                )
                self.assertEqual(snap.status_code, 200)
                names = {row["host"] for row in snap.json().get("assets") or []}
                self.assertEqual(names, {"only-alpha.example", "new-alpha.example"})
                self.assertTrue(all(row.get("first_seen") for row in snap.json()["assets"]))
                rebuilt = self.client.post("/api/warehouse/alpha.example/rebuild", headers=self.token_headers)
                self.assertEqual(rebuilt.status_code, 200)
                self.assertTrue(rebuilt.json().get("ok"))


class TestOpenPortsJoin(unittest.TestCase):
    """RESULTS rows show which ports are open on which host, from port JSON (no warehouse schema)."""

    def test_join_sweep_ports_to_subdomain(self):
        params = _isolated_params()
        target = "example.com"
        td = params.root / "recon" / target
        (td / "30_ports" / "naabu-full").mkdir(parents=True)
        (td / "30_ports" / "naabu-full" / "data.json").write_text(
            json.dumps({
                "scans": [
                    {
                        "ip": "1.2.3.4",
                        "hosts": ["api.example.com", "www.example.com"],
                        "ports": [
                            {"port": 443, "proto": "tcp", "state": "open"},
                            {"port": 80, "proto": "tcp"},
                        ],
                    },
                    {
                        "ip": "9.9.9.9",
                        "hosts": ["dev.example.com"],
                        "ports": [{"port": 22, "proto": "tcp"}],
                    },
                ],
                "services": [
                    {"ip": "1.2.3.4", "port": 443, "proto": "tcp", "name": "https", "product": "nginx", "version": "1.25"},
                ],
            })
            + "\n",
            encoding="utf-8",
        )
        out = attach_open_ports(params, target, [
            {"host": "www.example.com", "ip": "1.2.3.4", "alive": True},
            {"host": "api.example.com", "ips": ["1.2.3.4"], "alive": True},
            {"host": "dev.example.com", "ip": "9.9.9.9", "alive": True},
            {"host": "lonely.example.com", "ip": "8.8.8.8", "alive": False},
        ], include_ports=True)
        by = {r["host"]: r for r in out}
        self.assertEqual(by["www.example.com"]["open_ports_text"], "2")
        self.assertEqual(by["api.example.com"]["open_ports_text"], "2")
        self.assertEqual(by["dev.example.com"]["open_ports_text"], "1")
        self.assertEqual(by["lonely.example.com"]["open_ports_text"], "")
        self.assertEqual(by["www.example.com"]["open_ports_by_ip"], [{"ip": "1.2.3.4", "count": 2}])
        self.assertEqual(by["lonely.example.com"]["open_ports_by_ip"], [{"ip": "8.8.8.8", "count": 0}])
        self.assertEqual([p["port"] for p in by["www.example.com"]["open_ports"]], [80, 443])
        https = next(p for p in by["www.example.com"]["open_ports"] if p["port"] == 443)
        self.assertEqual(https["product"], "nginx")
        self.assertEqual(https["version"], "1.25")
        self.assertEqual(https["name"], "https")
        self.assertEqual(by["www.example.com"]["open_ports_total"], 2)
        detail = ports_for_host(params, target, "www.example.com", "1.2.3.4")
        self.assertEqual(detail["count"], 2)
        self.assertEqual([p["port"] for p in detail["ports"]], [80, 443])
        https = next(p for p in detail["ports"] if p["port"] == 443)
        self.assertEqual(https["product"], "nginx")
        self.assertEqual(https["version"], "1.25")
        http = next(p for p in detail["ports"] if p["port"] == 80)
        self.assertEqual(http["product"], "")
        self.assertEqual(http["version"], "")

    def test_all_valid_ports_are_kept(self):
        params = _isolated_params()
        target = "example.com"
        td = params.root / "recon" / target
        (td / "30_ports" / "naabu-full").mkdir(parents=True)
        ports = [{"port": n, "proto": "tcp"} for n in range(1, 201)]
        ports.append({"port": 0, "proto": "tcp"})
        ports.append({"port": 70000, "proto": "tcp"})
        (td / "30_ports" / "naabu-full" / "data.json").write_text(
            json.dumps({
                "scans": [{
                    "ip": "13.0.0.1",
                    "hosts": ["cdn.example.com"],
                    "ports": ports,
                }],
                "services": [],
            })
            + "\n",
            encoding="utf-8",
        )
        out = attach_open_ports(
            params, target, [{"host": "cdn.example.com", "ips": ["13.0.0.1"]}],
            include_ports=True,
        )
        row = out[0]
        self.assertEqual(row["open_ports_total"], 200)
        self.assertEqual(len(row["open_ports"]), 200)
        self.assertEqual(row["open_ports_by_ip"], [{"ip": "13.0.0.1", "count": 200}])
        nums = {p["port"] for p in row["open_ports"]}
        self.assertNotIn(0, nums)
        self.assertNotIn(70000, nums)
        detail = ports_for_host(params, target, "cdn.example.com", "13.0.0.1")
        self.assertEqual(detail["count"], 200)


class TestResultsHotPath(unittest.TestCase):
    def test_latest_results_read_assets_json_not_warehouse(self):
        params = _isolated_params()
        target = "example.com"
        target_dir = params.root / "recon" / target
        assets = target_dir / "00_assets"
        assets.mkdir(parents=True)
        (assets / "assets.json").write_text(
            json.dumps({"schema_version": 1, "assets": [{"host": "www.example.com", "alive": True}]})
            + "\n",
            encoding="utf-8",
        )
        with mock.patch("pipeline.warehouse.ingest_live", side_effect=AssertionError("poll must not ingest")):
            rows = results_rows_for(params, target, "")
        self.assertEqual(rows[0]["host"], "www.example.com")


class TestResultsDropCatchall(unittest.TestCase):
    def test_wildcard_only_host_is_omitted_from_results(self):
        params = _isolated_params()
        target = "example.com"
        target_dir = params.root / "recon" / target
        assets = target_dir / "00_assets"
        assets.mkdir(parents=True)
        (assets / "assets.json").write_text(
            json.dumps({
                "schema_version": 1,
                "assets": [
                    {"host": "example.com", "ips": ["9.9.9.9"], "alive": True, "sources": ["dnsx"]},
                    {"host": "app2.example.com", "ips": ["9.9.9.9"], "alive": True, "sources": ["dnsx"]},
                    {"host": "api.example.com", "ips": ["1.2.3.4"], "alive": True, "sources": ["dnsx"]},
                ],
            })
            + "\n",
            encoding="utf-8",
        )
        dnsx = target_dir / "20_dns" / "dnsx"
        dnsx.mkdir(parents=True)
        (dnsx / "data.json").write_text(
            json.dumps({"wildcard_ips": ["9.9.9.9"], "resolved": []}) + "\n",
            encoding="utf-8",
        )
        rows = results_rows_for(params, target, "")
        hosts = {r["host"] for r in rows}
        self.assertIn("example.com", hosts)
        self.assertIn("api.example.com", hosts)
        self.assertNotIn("app2.example.com", hosts)


if __name__ == "__main__":
    unittest.main()
