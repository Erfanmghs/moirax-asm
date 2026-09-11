"""RESTART is stop-then-fresh-run: not START (no overlap) and not RESUME (no skip-done)."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from pipeline.cli import cmd_restart
from pipeline.params import Params
from pipeline.state import run_pid_is_live, write_run_pid

_ROOT = Path(__file__).resolve().parents[1]


class TestRunPidLive(unittest.TestCase):
    def test_live_pid_and_stale_pid(self) -> None:
        tdir = Path(tempfile.mkdtemp()) / "pid-live.example"
        tdir.mkdir()
        self.assertFalse(run_pid_is_live(tdir))
        write_run_pid(tdir, os.getpid())
        self.assertTrue(run_pid_is_live(tdir))
        write_run_pid(tdir, 99999999)
        self.assertFalse(run_pid_is_live(tdir))


class TestCmdRestart(unittest.TestCase):
    def test_stops_then_runs_fresh_not_resume(self) -> None:
        params = Params(_ROOT)
        tdir = Path(tempfile.mkdtemp()) / "restart.example"
        tdir.mkdir()
        gate = mock.Mock()
        gate.validate_candidate.return_value = (True, "")
        with mock.patch("pipeline.cli._load_gate", return_value=gate), \
             mock.patch("pipeline.cli.ensure_layout", return_value=tdir), \
             mock.patch("pipeline.cli._run_with_target_profile", side_effect=lambda p, t, r: r()), \
             mock.patch("pipeline.engine.stop_target", return_value=["cid"]) as stop_fn, \
             mock.patch("pipeline.engine.run_pipeline", return_value=0) as run_fn:
            code = cmd_restart(params, "restart.example")
        self.assertEqual(code, 0)
        stop_fn.assert_called_once()
        self.assertEqual(stop_fn.call_args[0][1], tdir)
        run_fn.assert_called_once()
        self.assertFalse(run_fn.call_args.kwargs.get("resume", False))


class TestDashboardRestart(unittest.TestCase):
    def setUp(self) -> None:
        from fastapi.testclient import TestClient

        from dashboard import app as appmod

        self.appmod = appmod
        self.client = TestClient(appmod.app)
        self.headers = {"Authorization": "Bearer restart-token-ok"}

    def _ctx(self):
        params = Params(_ROOT)
        env = mock.patch.dict(os.environ, {"DASHBOARD_TOKEN": "restart-token-ok"}, clear=False)
        pp = mock.patch.object(self.appmod, "_params_obj", return_value=params)
        return env, pp

    def test_restart_stops_then_spawns_run_not_resume(self) -> None:
        pop = mock.Mock()
        pop.return_value.pid = 4242
        env, pp = self._ctx()
        with env, pp, \
             mock.patch("dashboard.app.scan_require_registered", return_value="example.com"), \
             mock.patch("pipeline.dockerbin.docker_available", return_value=True), \
             mock.patch("pipeline.engine.stop_target", return_value=["cid1"]) as stop_fn, \
             mock.patch("pipeline.factory.ensure_layout", return_value=Path(tempfile.mkdtemp()) / "example.com"), \
             mock.patch("subprocess.Popen", pop), \
             mock.patch("pipeline.state.write_run_pid"):
            r = self.client.post("/api/run/restart", json={"target": "example.com"}, headers=self.headers)
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertTrue(body["restarted"])
        self.assertFalse(body["started"])
        self.assertFalse(body["resumed"])
        self.assertEqual(body["cmd"], ["./recon.sh", "run", "example.com"])
        self.assertNotIn("resume", body["cmd"])
        stop_fn.assert_called_once()
        argv = pop.call_args[0][0]
        self.assertIn("run", argv)
        self.assertNotIn("resume", argv)
        self.assertNotIn("restart", argv)

    def test_start_refuses_live_pid_restart_does_not(self) -> None:
        pop = mock.Mock()
        pop.return_value.pid = 77
        env, pp = self._ctx()
        with env, pp, \
             mock.patch("dashboard.app.scan_require_registered", return_value="example.com"), \
             mock.patch("pipeline.dockerbin.docker_available", return_value=True), \
             mock.patch("pipeline.state.run_pid_is_live", return_value=True), \
             mock.patch("subprocess.Popen", pop):
            r = self.client.post("/api/run/start", json={"target": "example.com"}, headers=self.headers)
        self.assertEqual(r.status_code, 409, r.text)
        self.assertIn("RESTART", r.json().get("detail", ""))
        pop.assert_not_called()

        env, pp = self._ctx()
        with env, pp, \
             mock.patch("dashboard.app.scan_require_registered", return_value="example.com"), \
             mock.patch("pipeline.dockerbin.docker_available", return_value=True), \
             mock.patch("pipeline.state.run_pid_is_live", return_value=True), \
             mock.patch("pipeline.engine.stop_target", return_value=[]), \
             mock.patch("pipeline.factory.ensure_layout", return_value=Path(tempfile.mkdtemp()) / "example.com"), \
             mock.patch("subprocess.Popen", pop), \
             mock.patch("pipeline.state.write_run_pid"):
            r2 = self.client.post("/api/run/restart", json={"target": "example.com"}, headers=self.headers)
        self.assertEqual(r2.status_code, 200, r2.text)
        pop.assert_called()


if __name__ == "__main__":
    unittest.main()
