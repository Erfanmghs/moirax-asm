"""Atomic tests for the D-protocol batch (operator directives):

  D1 Telegram per-target redesign:
    - user sets ONLY their Telegram user id; bot token is platform provisioning
    - chat-id resolution precedence: target profile > dashboard config > .env
    - per-system opt-out (telegram_enabled=false) mutes a target outright
    - per-target digest threshold / watchtower toggle win over global config
    - SEND TEST ledger explains every skip reason (never silent)
    - profile value laws: injection-safe telegram_chat, positive threshold,
      boolean toggles
  D2 attacker-proofing + new API surface:
    - fleet member roots carry targets.yaml (per-target notify inside fleet)
    - latest_fleet_ledger / fleet_members_view contracts
    - FastAPI: hardening headers, openapi/docs disabled, target-name gate on
      run endpoints (flag/traversal/metachar injection refused pre-spawn),
      /api/notify/test, auth fail-closed on new routes
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dashboard.service import fleet_members_view, latest_fleet_ledger  # noqa: E402
from pipeline.fleet import CONTROL_FILES, prepare_member  # noqa: E402
from pipeline.notify import (  # noqa: E402
    DISABLED_BY_PROFILE,
    TELEGRAM_CHAT_RE,
    resolve_bot_token,
    resolve_chat_id,
    send_test_notification,
)
from pipeline.params import Params  # noqa: E402
from pipeline.target_profiles import (  # noqa: E402
    ProfileError,
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


def _write_env(params: Params, pairs: dict[str, str]) -> None:
    path = params.root / str(params.require("env_filename"))
    path.write_text("\n".join(f"{k}={v}" for k, v in pairs.items()) + "\n", encoding="utf-8")


def _scrub_telegram_env() -> None:
    """load_dotenv caches into os.environ (process-global). Every test class
    that resolves credentials starts from a scrubbed slate so the resolution
    chain under test is exactly the one on disk."""
    for key in [k for k in os.environ if k.startswith("TELEGRAM_")]:
        del os.environ[key]


class TestChatIdLaw(unittest.TestCase):
    def test_chat_id_regex_accepts_user_ids_and_channels(self):
        for ok in ("123456789", "-100200300", "9876543210", "@channel_name", "@abcd"):
            self.assertTrue(TELEGRAM_CHAT_RE.match(ok), ok)
        for bad in ("", "ab", "12 34", "id; rm -rf /", "5\n6", "${jndi:ldap://x}", "abc def"):
            self.assertFalse(TELEGRAM_CHAT_RE.match(bad), bad)


class TestProfileNotificationLaws(unittest.TestCase):
    def test_valid_notifications_accepted(self):
        clean = validate_profile("bugdasht.ir", {
            "notifications": {
                "telegram_chat": "123456789",
                "digest_threshold": 5,
                "telegram_enabled": True,
                "watchtower_enabled": False,
            },
        })
        self.assertEqual(clean["notifications"]["telegram_chat"], "123456789")

    def test_injection_chat_refused(self):
        for bad in ("123; rm -rf /", "abc def", "5\n6", "x' or '1'='1"):
            with self.assertRaises(ProfileError, msg=bad):
                validate_profile("bugdasht.ir", {"notifications": {"telegram_chat": bad}})

    def test_bad_threshold_and_toggles_refused(self):
        with self.assertRaises(ProfileError):
            validate_profile("bugdasht.ir", {"notifications": {"digest_threshold": "10"}})
        with self.assertRaises(ProfileError):
            validate_profile("bugdasht.ir", {"notifications": {"telegram_enabled": "true"}})
        with self.assertRaises(ProfileError):
            validate_profile("bugdasht.ir", {"notifications": {"watchtower_enabled": 1}})


class TestChatResolutionChain(unittest.TestCase):
    def setUp(self):
        _scrub_telegram_env()

    def test_target_profile_beats_everything(self):
        params = _params()
        set_profile(params, "bugdasht.ir", {"notifications": {"telegram_chat": "111000111"}})
        _write_config(params, {"telegram": {"chat_id": "222222222"}})
        _write_env(params, {"TELEGRAM_CHAT_ID": "333333333"})
        chat, source = resolve_chat_id(params, "bugdasht.ir")
        self.assertEqual((chat, source), ("111000111", "target_profile"))

    def test_global_config_beats_env(self):
        params = _params()
        _write_config(params, {"telegram": {"chat_id": "222222222"}})
        _write_env(params, {"TELEGRAM_CHAT_ID": "333333333"})
        chat, source = resolve_chat_id(params, "bugdasht.ir")
        self.assertEqual((chat, source), ("222222222", "dashboard_config"))

    def test_env_is_final_fallback(self):
        params = _params()
        _write_env(params, {"TELEGRAM_CHAT_ID": "333333333"})
        chat, source = resolve_chat_id(params)
        self.assertEqual((chat, source), ("333333333", "env"))

    def test_profile_optout_mutes_target_even_with_globals(self):
        params = _params()
        set_profile(params, "muted.example", {"notifications": {"telegram_enabled": False}})
        _write_config(params, {"telegram": {"chat_id": "222222222"}})
        _write_env(params, {"TELEGRAM_CHAT_ID": "333333333"})
        chat, source = resolve_chat_id(params, "muted.example")
        self.assertEqual((chat, source), ("", DISABLED_BY_PROFILE))

    def test_other_targets_unaffected_by_one_profile(self):
        params = _params()
        set_profile(params, "muted.example", {"notifications": {"telegram_enabled": False}})
        _write_env(params, {"TELEGRAM_CHAT_ID": "333333333"})
        chat, source = resolve_chat_id(params, "other.example")
        self.assertEqual((chat, source), ("333333333", "env"))


class TestBotTokenAndSendTest(unittest.TestCase):
    def setUp(self):
        _scrub_telegram_env()

    def test_bot_token_platform_provisioning_chain(self):
        params = _params()
        _write_config(params, {"telegram": {"bot_token": "cfg-token-123456"}})
        token, source = resolve_bot_token(params)
        self.assertEqual((token, source), ("cfg-token-123456", "dashboard_config"))
        params2 = _params()
        _write_env(params2, {"TELEGRAM_BOT_TOKEN": "env-token-654321"})
        token2, source2 = resolve_bot_token(params2)
        self.assertEqual((token2, source2), ("env-token-654321", "env"))

    def test_send_test_delivers_via_injected_sender(self):
        params = _params()
        set_profile(params, "bugdasht.ir", {"notifications": {"telegram_chat": "111000111"}})
        _write_env(params, {"TELEGRAM_BOT_TOKEN": "test-token-000"})
        seen: list[str] = []
        ledger = send_test_notification(params, "bugdasht.ir", sender=seen.append)
        self.assertTrue(ledger["sent"])
        self.assertEqual(ledger["source"], "target_profile")
        self.assertEqual(len(seen), 1)
        self.assertIn("target=bugdasht.ir", seen[0])
        self.assertNotIn("111000111", seen[0], "chat id never echoed into messages")
        self.assertNotIn("test-token-000", seen[0], "bot token never echoed into messages")

    def test_send_test_skip_reasons_are_never_silent(self):
        params = _params()
        ledger = send_test_notification(params, "nothing.example", sender=lambda _t: None)
        self.assertFalse(ledger["sent"])
        self.assertIn("username or id", ledger["reason"])
        self.assertIn("hint", ledger, "user-friendly next step always present")
        params2 = _params()
        set_profile(params2, "muted.example", {"notifications": {"telegram_enabled": False}})
        ledger2 = send_test_notification(params2, "muted.example", sender=lambda _t: None)
        self.assertFalse(ledger2["sent"])
        self.assertIn("disabled", ledger2["reason"])
        params3 = _params()
        _write_config(params3, {"telegram": {"chat_id": "222222222"}})
        ledger3 = send_test_notification(params3, None, sender=lambda _t: None)
        self.assertFalse(ledger3["sent"])
        self.assertIn("bot token", ledger3["reason"])


class TestPerTargetRunEndFanout(unittest.TestCase):
    def setUp(self):
        _scrub_telegram_env()

    def test_run_end_delivers_to_target_receiver_and_mutes_optout(self):
        from pipeline.notify import run_end_notifications

        params = _params()
        set_profile(params, "a.example", {"notifications": {"telegram_chat": "111000111"}})
        set_profile(params, "b.example", {"notifications": {"telegram_enabled": False}})
        seen: dict[str, list[str]] = {}

        def sender(text: str) -> None:
            seen.setdefault("all", []).append(text)

        for target in ("a.example", "b.example"):
            run_end_notifications(
                params,
                params.root / "recon" / target,
                target,
                str(params.require("run_status_completed")),
                None,
                None,
                {"dns-resolve": 5},
                61.0,
                sender=sender,
            )
        joined = "\n".join(seen.get("all", []))
        self.assertIn("target: a.example", joined)
        self.assertNotIn("target: b.example", joined, "muted target delivers nothing")


class TestFleetCarriesTargetsRegistry(unittest.TestCase):
    def test_member_root_has_targets_yaml(self):
        params = _params()
        set_profile(params, "bugdasht.ir", {"notifications": {"telegram_chat": "111000111"}})
        fleet_root = params.root / "history" / "fleet" / "t0"
        ledger = prepare_member(params, "bugdasht.ir", fleet_root)
        member_targets = Path(ledger["root"]) / "targets.yaml"
        self.assertTrue(member_targets.is_file(), "D-protocol: member root carries the registry")
        self.assertIn("bugdasht.ir", member_targets.read_text(encoding="utf-8"))
        self.assertIn("targets.yaml", CONTROL_FILES)


class TestFleetServiceSurface(unittest.TestCase):
    def test_latest_ledger_contract(self):
        params = _params()
        self.assertFalse(latest_fleet_ledger(params)["exists"])
        base = params.root / "history" / "fleet"
        for ts, clean in (("20260101T000000Z", True), ("20260102T000000Z", False)):
            d = base / ts
            d.mkdir(parents=True)
            (d / "fleet-ledger.json").write_text(json.dumps({"clean": clean, "ts": ts}) + "\n", encoding="utf-8")
        doc = latest_fleet_ledger(params)
        self.assertTrue(doc["exists"])
        self.assertEqual(doc["ts"], "20260102T000000Z", "lexicographic ts = latest")

    def test_members_view(self):
        params = _params()
        set_profile(params, "bugdasht.ir", {"notifications": {"telegram_chat": "123456789"}})
        view = fleet_members_view(params)
        self.assertIn("bugdasht.ir", view["members"])
        self.assertGreaterEqual(view["max_concurrency"], 1)


class TestDashboardApiHardening(unittest.TestCase):
    def setUp(self):
        _scrub_telegram_env()

    def setUp(self):
        from fastapi.testclient import TestClient

        from dashboard.app import app

        self.client = TestClient(app)
        self.headers = {"Authorization": "Bearer dproto-token"}

    def _patched(self):
        params = _params()
        env = {"DASHBOARD_TOKEN": "dproto-token"}
        from dashboard import app as appmod

        return mock.patch.object(appmod, "_params_obj", return_value=params), \
            mock.patch.dict(os.environ, env, clear=False)

    def test_hardening_headers_on_every_response(self):
        for path in ("/", "/api/health", "/static/theme.css"):
            r = self.client.get(path)
            self.assertEqual(r.headers.get("X-Content-Type-Options"), "nosniff", path)
            self.assertEqual(r.headers.get("X-Frame-Options"), "DENY", path)
            self.assertEqual(r.headers.get("Referrer-Policy"), "no-referrer", path)
            self.assertEqual(r.headers.get("Cache-Control"), "no-store", path)
        r = self.client.get("/")
        csp = r.headers.get("Content-Security-Policy", "")
        self.assertIn("script-src 'self'", csp)
        self.assertIn("frame-ancestors 'none'", csp)

    def test_openapi_and_docs_disabled(self):
        for path in ("/openapi.json", "/docs", "/redoc"):
            self.assertEqual(self.client.get(path).status_code, 404, path)

    def test_run_start_target_name_gate(self):
        patch, envpatch = self._patched()
        with patch, envpatch:
            for bad in ("--aggressive", "../etc/passwd", "a;id", "a$(id)", "-x", "UPPER.COM", "", "a b.com"):
                r = self.client.post("/api/run/start", json={"target": bad}, headers=self.headers)
                self.assertEqual(r.status_code, 422, f"{bad!r} must be refused pre-spawn")
            r = self.client.post("/api/run/stop", json={"target": "../../x"}, headers=self.headers)
            self.assertEqual(r.status_code, 422)
            r = self.client.post("/api/run/restart", json={"target": "../../x"}, headers=self.headers)
            self.assertEqual(r.status_code, 422)

    def test_run_start_refuses_when_nested_docker_is_dead(self):
        patch, envpatch = self._patched()
        with patch, envpatch, \
             mock.patch("dashboard.app.scan_require_registered", return_value="example.com"), \
             mock.patch("pipeline.dockerbin.docker_available", return_value=False):
            r = self.client.post(
                "/api/run/start", json={"target": "example.com"}, headers=self.headers,
            )
            self.assertEqual(r.status_code, 503, r.text)
            self.assertIn("docker.sock", r.json().get("detail", ""))

    def test_fleet_run_member_token_gate(self):
        patch, envpatch = self._patched()
        with patch, envpatch:
            r = self.client.post("/api/fleet/run", json={"members": "ok.example,../evil"}, headers=self.headers)
            self.assertEqual(r.status_code, 422)
            r = self.client.post("/api/fleet/run", json={"members": "ok.example", "concurrency": "x"}, headers=self.headers)
            self.assertEqual(r.status_code, 422)

    def test_notify_test_endpoint_auth_and_ledger(self):
        r = self.client.post("/api/notify/test", json={})
        self.assertIn(r.status_code, (401, 503), "new routes honor the fail-closed auth law")
        patch, envpatch = self._patched()
        with patch, envpatch:
            r = self.client.post("/api/notify/test", json={"target": "bugdasht.ir"}, headers=self.headers)
            self.assertEqual(r.status_code, 200, r.text)
            doc = r.json()
            self.assertFalse(doc["sent"])
            self.assertTrue(doc["reason"], "never silent: the skip reason is always explained")
            r2 = self.client.post("/api/notify/test", json={"target": "../evil"}, headers=self.headers)
            self.assertEqual(r2.status_code, 422)

    def test_settings_closed_allow_list(self):
        patch, envpatch = self._patched()
        with patch, envpatch:
            r = self.client.put("/api/settings", json={"evil_key": {"x": 1}}, headers=self.headers)
            self.assertEqual(r.status_code, 422, "unknown settings keys are refused, never merged")
            r2 = self.client.put("/api/settings", json={"digest_threshold": 7}, headers=self.headers)
            self.assertEqual(r2.status_code, 200)
            self.assertNotIn("evil_key", r2.json())

    def test_fleet_get_surface(self):
        patch, envpatch = self._patched()
        with patch, envpatch:
            r = self.client.get("/api/fleet", headers=self.headers)
            self.assertEqual(r.status_code, 200)
            self.assertIn("max_concurrency", r.json())
            r = self.client.get("/api/fleet/ledger", headers=self.headers)
            self.assertEqual(r.status_code, 200)
            self.assertFalse(r.json()["exists"])


class TestUsernameReceivers(unittest.TestCase):
    """Operator directive v2: a Telegram HANDLE (jackjohns / @jackjohns) is a
    first-class receiver next to numeric ids; bare handles normalize to @form;
    a learned username -> numeric id map resolves personal accounts."""

    def setUp(self):
        _scrub_telegram_env()
        from pipeline import notify
        notify._REJECTED_TOKENS.clear()

    def test_normalize_receiver(self):
        from pipeline.notify import normalize_receiver
        self.assertEqual(normalize_receiver("jackjohns"), "@jackjohns")
        self.assertEqual(normalize_receiver("@jackjohns"), "@jackjohns")
        self.assertEqual(normalize_receiver("  @JackJohns  "), "@JackJohns")
        self.assertEqual(normalize_receiver("123456789"), "123456789")
        self.assertEqual(normalize_receiver("-100200300"), "-100200300")
        for bad in ("", "ab", "bad name", "5\n6", "id; rm -rf /"):
            self.assertEqual(normalize_receiver(bad), "", bad)

    def test_receiver_regex_accepts_bare_handles(self):
        for ok in ("jackjohns", "@jackjohns", "123456789", "@channel_name"):
            self.assertTrue(TELEGRAM_CHAT_RE.match(ok), ok)
        for bad in ("jack johns", "ab", "${jndi:ldap://x}"):
            self.assertFalse(TELEGRAM_CHAT_RE.match(bad), bad)

    def test_profile_accepts_bare_username(self):
        clean = validate_profile("bugdasht.ir", {"notifications": {"telegram_chat": "jackjohns"}})
        self.assertEqual(clean["notifications"]["telegram_chat"], "jackjohns")

    def test_username_resolved_through_learned_map(self):
        params = _params()
        _write_config(params, {"telegram": {"chat_id": "JackJohns",
                                            "receiver_map": {"jackjohns": "424242"}}})
        chat, source = resolve_chat_id(params)
        self.assertEqual(chat, "424242")
        self.assertEqual(source, "dashboard_config")

    def test_unmapped_username_stays_at_form(self):
        params = _params()
        _write_config(params, {"telegram": {"chat_id": "@newuser"}})
        chat, source = resolve_chat_id(params)
        self.assertEqual((chat, source), ("@newuser", "dashboard_config"))

    def test_bare_env_username_normalized(self):
        params = _params()
        _write_env(params, {"TELEGRAM_CHAT_ID": "jackjohns"})
        chat, source = resolve_chat_id(params)
        self.assertEqual((chat, source), ("@jackjohns", "env"))


class TestBotTokenPoolAndRotation(unittest.TestCase):
    """Operator directive v2: comma-separated TELEGRAM_BOT_TOKEN pool; a token
    rejected by Telegram (401) is replaced AUTOMATICALLY by the next pool
    entry inside the same send; token values are never echoed anywhere."""

    def setUp(self):
        _scrub_telegram_env()
        from pipeline import notify
        notify._REJECTED_TOKENS.clear()

    def test_pool_parsed_from_comma_separated_env(self):
        from pipeline.notify import resolve_bot_token_pool
        params = _params()
        _write_env(params, {"TELEGRAM_BOT_TOKEN": "tokA, tokB ,tokA,tokC"})
        self.assertEqual(resolve_bot_token_pool(params), ["tokA", "tokB", "tokC"])

    def test_dashboard_token_leads_then_env_backups(self):
        from pipeline.notify import resolve_bot_token_pool
        params = _params()
        _write_config(params, {"telegram": {"bot_token": "tok-dash"}})
        _write_env(params, {"TELEGRAM_BOT_TOKEN": "tok-env1,tok-env2"})
        self.assertEqual(resolve_bot_token_pool(params), ["tok-dash", "tok-env1", "tok-env2"])

    def test_invalid_token_rotates_to_replacement_mid_send(self):
        from pipeline import notify
        params = _params()
        _write_env(params, {"TELEGRAM_BOT_TOKEN": "tok-dead,tok-live"})
        calls: list[str] = []

        def fake_post(_params, token, method, payload):
            calls.append((method, payload["chat_id"]))
            return (401, "Unauthorized") if token == "tok-dead" else (200, "ok")

        with mock.patch("pipeline.notify._telegram_post", side_effect=fake_post):
            ok, detail = notify._send_with_pool(params, "4242", "hello")
        self.assertTrue(ok)
        self.assertIn("rotated", detail)
        self.assertEqual(calls, [("sendMessage", "4242"), ("sendMessage", "4242")])

    def test_rejected_token_skipped_on_next_send(self):
        from pipeline import notify
        params = _params()
        _write_env(params, {"TELEGRAM_BOT_TOKEN": "tok-dead,tok-live"})
        calls: list[str] = []

        def fake_post(_params, token, method, payload):
            calls.append(token)
            return (401, "Unauthorized") if token == "tok-dead" else (200, "ok")

        with mock.patch("pipeline.notify._telegram_post", side_effect=fake_post):
            notify._send_with_pool(params, "4242", "one")
        calls.clear()
        with mock.patch("pipeline.notify._telegram_post", side_effect=fake_post):
            ok, _detail = notify._send_with_pool(params, "4242", "two")
        self.assertTrue(ok)
        self.assertNotIn("tok-dead", calls, "known-invalid token must be skipped")
        self.assertEqual(calls, ["tok-live"])

    def test_all_tokens_invalid_is_honest_and_never_echoes(self):
        from pipeline import notify
        params = _params()
        _write_env(params, {"TELEGRAM_BOT_TOKEN": "tok-dead-one,tok-dead-two"})

        def fake_post(_params, token, method, payload):
            return (401, "Unauthorized")

        with mock.patch("pipeline.notify._telegram_post", side_effect=fake_post):
            ok, detail = notify._send_with_pool(params, "4242", "hello")
        self.assertFalse(ok)
        self.assertTrue(detail)
        self.assertNotIn("tok-dead-one", detail)
        self.assertNotIn("tok-dead-two", detail)

    def test_send_test_hint_on_chat_not_found(self):
        from pipeline import notify
        params = _params()
        _write_config(params, {"telegram": {"chat_id": "@newuser"}})
        _write_env(params, {"TELEGRAM_BOT_TOKEN": "tok-live"})

        def fake_post(_params, token, method, payload):
            return (400, "chat not found")

        with mock.patch("pipeline.notify._telegram_post", side_effect=fake_post), \
             mock.patch("pipeline.notify.learn_receiver_map", return_value={}):
            ledger = send_test_notification(params, None)
        self.assertFalse(ledger["sent"])
        self.assertIn("START", ledger["hint"])
        self.assertNotIn("tok-live", json.dumps(ledger))

    def test_send_test_hint_on_token_pool_exhausted(self):
        from pipeline import notify
        params = _params()
        _write_config(params, {"telegram": {"chat_id": "4242"}})
        _write_env(params, {"TELEGRAM_BOT_TOKEN": "tok-dead"})

        def fake_post(_params, token, method, payload):
            return (401, "Unauthorized")

        with mock.patch("pipeline.notify._telegram_post", side_effect=fake_post):
            ledger = send_test_notification(params, None)
        self.assertFalse(ledger["sent"])
        self.assertIn("BotFather", ledger["hint"])
        self.assertNotIn("tok-dead", json.dumps(ledger))

    def test_learn_receiver_map_persists_getupdates_pair(self):
        from pipeline import notify
        params = _params()
        _write_env(params, {"TELEGRAM_BOT_TOKEN": "tok-live"})

        class FakeResp:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self):
                return json.dumps({"ok": True, "result": [
                    {"update_id": 7, "message": {"chat": {"id": 424242,
                                                          "username": "JackJohns"}}},
                    {"update_id": 8, "message": {"chat": {"id": 555555}}},
                ]}).encode()

        def fake_urlopen(req, timeout=0):
            return FakeResp()

        with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
            merged = notify.learn_receiver_map(params)
        self.assertEqual(merged.get("jackjohns"), "424242")
        self.assertNotIn("555555", merged.values(),
                         "chat without a username must not map by id")
        stored = json.loads((params.root / str(params.require("dashboard_config_relpath")))
                            .read_text(encoding="utf-8"))
        self.assertEqual(stored["telegram"]["receiver_map"]["jackjohns"], "424242")


if __name__ == "__main__":
    unittest.main()
