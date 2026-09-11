"""Operator password store + session idle timeout (isolated from recon/)."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient


class TestOperatorAuth(unittest.TestCase):
    def setUp(self):
        from dashboard import authstore
        from dashboard.app import app

        self._tmp = tempfile.TemporaryDirectory()
        self._db = str(Path(self._tmp.name) / "operator.sqlite")
        self._env = mock.patch.dict(os.environ, {"RECON_AUTH_DB": self._db}, clear=True)
        self._env.start()
        authstore.reset()
        self.client = TestClient(app)

    def tearDown(self):
        from dashboard import authstore

        authstore.reset()
        self._env.stop()
        self._tmp.cleanup()

    def test_setup_required_and_apis_fail_closed(self):
        st = self.client.get("/api/auth/status").json()
        self.assertTrue(st["setup_required"])
        self.assertFalse(st["authenticated"])
        self.assertEqual(self.client.get("/api/tools").status_code, 503)

    def test_setup_hashes_password_and_sets_httponly_cookie(self):
        r = self.client.post("/api/auth/setup", json={"password": "operator-pass-1", "confirm": "operator-pass-1"})
        self.assertEqual(r.status_code, 200, r.text)
        cookie = r.cookies.get("asm_session")
        self.assertTrue(cookie)
        header = r.headers.get("set-cookie", "")
        self.assertIn("HttpOnly", header)
        self.assertIn("samesite=strict", header.lower())
        raw = Path(self._db).read_bytes()
        self.assertNotIn(b"operator-pass-1", raw)
        self.assertEqual(self.client.get("/api/tools").status_code, 200)
        again = self.client.post("/api/auth/setup", json={"password": "operator-pass-2", "confirm": "operator-pass-2"})
        self.assertEqual(again.status_code, 403)

    def test_setup_rejects_short_or_mismatched_password(self):
        r = self.client.post("/api/auth/setup", json={"password": "short", "confirm": "short"})
        self.assertEqual(r.status_code, 422)
        r2 = self.client.post("/api/auth/setup", json={"password": "operator-pass-1", "confirm": "other-password"})
        self.assertEqual(r2.status_code, 422)
        self.assertEqual(self.client.get("/api/tools").status_code, 503)

    def test_login_and_bac_second_setup(self):
        self.client.post("/api/auth/setup", json={"password": "operator-pass-1", "confirm": "operator-pass-1"})
        self.client.post("/api/auth/logout")
        bad = self.client.post("/api/auth/login", json={"password": "nope-nope-nope"})
        self.assertEqual(bad.status_code, 401)
        self.assertEqual(self.client.get("/api/tools").status_code, 401)
        ok = self.client.post("/api/auth/login", json={"password": "operator-pass-1"})
        self.assertEqual(ok.status_code, 200)
        self.assertEqual(self.client.get("/api/tools").status_code, 200)

    def test_idle_timeout_not_extended_by_polling(self):
        from dashboard import authstore

        t0 = 1_700_000_000.0
        with mock.patch.object(authstore.time, "time", return_value=t0):
            self.assertEqual(
                self.client.post("/api/auth/setup", json={"password": "operator-pass-1", "confirm": "operator-pass-1"}).status_code,
                200,
            )
            self.assertEqual(self.client.get("/api/tools").status_code, 200)
        with mock.patch.object(authstore.time, "time", return_value=t0 + 10 * 60):
            self.assertEqual(self.client.get("/api/tools").status_code, 200, "GET polling must not idle-out yet")
        with mock.patch.object(authstore.time, "time", return_value=t0 + 15 * 60 + 1):
            self.assertEqual(self.client.get("/api/tools").status_code, 401)
            self.assertEqual(self.client.post("/api/auth/touch").status_code, 401)

    def test_touch_extends_idle_window(self):
        from dashboard import authstore

        t0 = 1_700_000_000.0
        with mock.patch.object(authstore.time, "time", return_value=t0):
            self.assertEqual(
                self.client.post("/api/auth/setup", json={"password": "operator-pass-1", "confirm": "operator-pass-1"}).status_code,
                200,
            )
        with mock.patch.object(authstore.time, "time", return_value=t0 + 14 * 60):
            self.assertEqual(self.client.post("/api/auth/touch").status_code, 200)
        with mock.patch.object(authstore.time, "time", return_value=t0 + 20 * 60):
            self.assertEqual(self.client.get("/api/tools").status_code, 200)

    def test_env_token_login_when_setup_skipped(self):
        with mock.patch.dict(os.environ, {"RECON_AUTH_DB": self._db, "DASHBOARD_TOKEN": "ci-legacy-token"}, clear=True):
            from dashboard import authstore
            authstore.reset()
            st = self.client.get("/api/auth/status").json()
            self.assertTrue(st["setup_required"])
            login = self.client.post("/api/auth/login", json={"password": "ci-legacy-token"})
            self.assertEqual(login.status_code, 200)
            self.assertEqual(self.client.get("/api/tools").status_code, 200)
            bearer = self.client.get("/api/tools", headers={"Authorization": "Bearer ci-legacy-token"})
            self.assertEqual(bearer.status_code, 200)

    def test_cross_origin_mutating_auth_is_refused(self):
        r = self.client.post(
            "/api/auth/setup",
            json={"password": "operator-pass-1", "confirm": "operator-pass-1"},
            headers={"Origin": "http://evil.example", "Host": "127.0.0.1:8080"},
        )
        self.assertEqual(r.status_code, 403)
        self.assertEqual(self.client.get("/api/tools").status_code, 503)
