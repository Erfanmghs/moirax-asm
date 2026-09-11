"""Server-side error fences: a failed step must not crash the process."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from pipeline.breaker import Clock
from pipeline.engine import (
    _append_log,
    _engage_agent,
    _finalize_crash,
    _run_passive_modules,
    run_pipeline,
)
from pipeline.params import Params
from pipeline.state import load_state, new_run_state, read_run_pid, write_run_pid

_ROOT = Path(__file__).resolve().parents[1]


def _params() -> Params:
    return Params(_ROOT)


class TestEngageAgentNeverCrashesBranch(unittest.TestCase):
    def test_passive_failure_continues_without_nameerror(self):
        params = _params()
        tdir = Path(tempfile.mkdtemp()) / "err.example"
        tdir.mkdir()
        new_run_state(params, tdir, tdir.name)
        calls: list[str] = []

        def _boom(*_a, **_k):
            calls.append("a")
            raise RuntimeError("module exploded")

        def _ok(*_a, **_k):
            calls.append("b")
            return {"schema_version": 1, "module": "passive-recon", "counts": {}}

        adapter = mock.Mock()
        adapter.breaker.allow.return_value = True
        adapter.breaker.pause_reason.return_value = None
        real_require = params.require

        def _require(name: str):
            if name == "passive_branch_modules":
                return ["a", "b"]
            return real_require(name)

        with mock.patch.object(params, "require", side_effect=_require):
            with mock.patch.dict("pipeline.engine.RUNNERS", {"a": _boom, "b": _ok}, clear=False):
                docs = _run_passive_modules(
                    params, None, adapter, tdir, tdir.name, {}, 30.0, Clock(), 1, []
                )
        self.assertEqual(calls, ["a", "b"])
        self.assertTrue(isinstance(docs, list))
        st = load_state(params, tdir, tdir.name)
        self.assertEqual(st["modules"]["a"]["status"], "failed")
        self.assertEqual(st["modules"]["b"]["status"], "done")

    def test_engage_agent_swallows_supervisor_errors(self):
        params = _params()
        tdir = Path(tempfile.mkdtemp()) / "agent.example"
        tdir.mkdir()
        _engage_agent(params, tdir, "ffuf", "active", "boom")


class TestCrashFinalize(unittest.TestCase):
    def test_finalize_crash_clears_pid_and_marks_failed(self):
        params = _params()
        tdir = Path(tempfile.mkdtemp()) / "crash.example"
        tdir.mkdir()
        new_run_state(params, tdir, tdir.name)
        write_run_pid(tdir, 99999)
        code = _finalize_crash(params, tdir, tdir.name, RuntimeError("disk full"))
        self.assertEqual(code, int(params.require("exit_code_failed")))
        st = load_state(params, tdir, tdir.name)
        self.assertEqual(st["run"]["status"], str(params.require("run_status_failed")))
        self.assertIn("engine crash", st["run"].get("reason") or "")
        self.assertIsNone(read_run_pid(tdir))

    def test_run_pipeline_wrapper_finalizes_on_impl_crash(self):
        params = _params()
        tdir = Path(tempfile.mkdtemp()) / "wrap.example"
        tdir.mkdir()
        gate = mock.Mock()
        with mock.patch("pipeline.engine.ensure_layout", return_value=tdir):
            with mock.patch("pipeline.engine._run_pipeline_impl", side_effect=RuntimeError("boom")):
                code = run_pipeline(params, gate, tdir.name)
        self.assertEqual(code, int(params.require("exit_code_failed")))
        st = load_state(params, tdir, tdir.name)
        self.assertEqual(st["run"]["status"], str(params.require("run_status_failed")))

    def test_append_log_does_not_raise(self):
        params = _params()
        tdir = Path(tempfile.mkdtemp()) / "log.example"
        tdir.mkdir()
        new_run_state(params, tdir, tdir.name)
        with mock.patch.object(Path, "open", side_effect=OSError("ro fs")):
            _append_log(params, tdir, "ffuf", "ffuf", 1, "nope")


class TestDashboardNeverCrashesWorker(unittest.TestCase):
    def setUp(self):
        from fastapi.testclient import TestClient

        from dashboard import authstore
        from dashboard.app import app

        self._auth_tmp = tempfile.TemporaryDirectory()
        self._auth_db = str(Path(self._auth_tmp.name) / "operator.sqlite")
        self._auth_env = mock.patch.dict(os.environ, {"RECON_AUTH_DB": self._auth_db, "DASHBOARD_TOKEN": "err-token-ok"}, clear=False)
        self._auth_env.start()
        authstore.reset()
        self.client = TestClient(app, raise_server_exceptions=False)
        self.headers = {"Authorization": "Bearer err-token-ok"}

    def tearDown(self):
        from dashboard import authstore

        authstore.reset()
        self._auth_env.stop()
        self._auth_tmp.cleanup()

    def test_unhandled_route_error_is_json_500(self):
        from dashboard import app as appmod

        with mock.patch.object(appmod, "_params_obj", side_effect=RuntimeError("tools.yaml gone")):
            r = self.client.get("/api/tools", headers=self.headers)
        self.assertEqual(r.status_code, 500)
        self.assertEqual(r.json().get("detail"), "internal error")
        self.assertEqual(self.client.get("/api/health").status_code, 200)

    def test_spawn_oserror_is_503(self):
        from fastapi import HTTPException

        from dashboard import app as appmod

        with mock.patch.object(appmod.subprocess, "Popen", side_effect=OSError("nope")):
            with self.assertRaises(HTTPException) as caught:
                appmod._spawn_detached(["./missing-bin", "run", "example.com"])
        self.assertEqual(caught.exception.status_code, 503)

    def test_auth_status_survives_broken_sqlite(self):
        from dashboard import authstore

        with mock.patch.object(authstore, "_connect", side_effect=OSError("db missing")):
            r = self.client.get("/api/auth/status")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json().get("ok"))
