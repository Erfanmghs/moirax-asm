"""Operator STOP must kill the pipeline process and freeze module rows."""

from __future__ import annotations

import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from pipeline.breaker import Clock
from pipeline.cli import cmd_stop
from pipeline.engine import OperatorStop, _append_log, _run_active_modules, stop_target
from pipeline.params import Params
from pipeline.state import (
    fail_running_modules,
    load_state,
    new_run_state,
    operator_stopped,
    read_run_pid,
    set_run_status,
    set_status,
    write_run_pid,
)

_ROOT = Path(__file__).resolve().parents[1]


class TestOperatorStop(unittest.TestCase):
    def test_pid_roundtrip_and_running_rows_fail(self):
        params = Params(_ROOT)
        tdir = Path(tempfile.mkdtemp()) / "pid-target.test"
        tdir.mkdir()
        new_run_state(params, tdir, tdir.name)
        set_status(params, tdir, "dns-resolve", "running")
        write_run_pid(tdir, 4242)
        self.assertEqual(read_run_pid(tdir), 4242)
        names = fail_running_modules(params, tdir, tdir.name)
        self.assertEqual(names, ["dns-resolve"])
        st = load_state(params, tdir, tdir.name)
        self.assertEqual(st["modules"]["dns-resolve"]["status"], "failed")

    def test_stop_kills_session_and_sets_stopped(self):
        params = Params(_ROOT)
        tdir = Path(tempfile.mkdtemp()) / "kill-target.test"
        tdir.mkdir()
        new_run_state(params, tdir, tdir.name)
        set_status(params, tdir, "dns-resolve", "running")
        child = subprocess.Popen(["sleep", "30"], start_new_session=True)
        write_run_pid(tdir, child.pid)
        with mock.patch("pipeline.dockerbin.docker_prefix", return_value=["true"]):
            ids = stop_target(params, tdir)
        self.assertEqual(ids, [])
        deadline = time.time() + 3
        while child.poll() is None and time.time() < deadline:
            time.sleep(0.05)
        self.assertIsNotNone(child.poll(), "STOP must terminate the recorded run pid")
        st = load_state(params, tdir, tdir.name)
        self.assertEqual(st["run"]["status"], "stopped")
        self.assertEqual(st["run"]["reason"], "operator stop")
        self.assertEqual(st["modules"]["dns-resolve"]["status"], "failed")
        self.assertTrue(operator_stopped(params, tdir, tdir.name))
        self.assertIsNone(read_run_pid(tdir))

    def test_cmd_stop_without_state_json_still_requests_stop(self):
        params = Params(_ROOT)
        tdir = Path(tempfile.mkdtemp()) / "nostate.example"
        with mock.patch("pipeline.cli.target_root", return_value=tdir):
            with mock.patch("pipeline.dockerbin.docker_prefix", return_value=["true"]):
                code = cmd_stop(params, tdir.name)
        self.assertEqual(code, int(params.require("exit_code_stopped")))
        self.assertTrue(operator_stopped(params, tdir, tdir.name))
        st = load_state(params, tdir, tdir.name)
        self.assertEqual(st["run"]["reason"], "operator stop")

    def test_running_status_does_not_clobber_operator_stop(self):
        params = Params(_ROOT)
        tdir = Path(tempfile.mkdtemp()) / "clobber.example"
        tdir.mkdir()
        new_run_state(params, tdir, tdir.name)
        set_run_status(params, tdir, tdir.name, "stopped", reason="operator stop")
        set_run_status(params, tdir, tdir.name, "running")
        self.assertTrue(operator_stopped(params, tdir, tdir.name))
        set_run_status(params, tdir, tdir.name, "running", overwrite_stopped=True)
        self.assertFalse(operator_stopped(params, tdir, tdir.name))
        st = load_state(params, tdir, tdir.name)
        self.assertEqual(st["run"]["status"], "running")

    def test_active_branch_refuses_next_module_after_stop(self):
        params = Params(_ROOT)
        tdir = Path(tempfile.mkdtemp()) / "nextmod.example"
        tdir.mkdir()
        new_run_state(params, tdir, tdir.name)
        calls: list[str] = []

        def _factory(label: str):
            def _run(_params, _gate, _adapter, target_dir, target, *_rest):
                calls.append(label)
                if label == "dns-resolve":
                    set_run_status(_params, target_dir, target, "stopped", reason="operator stop")
                return None

            return _run

        patched = {
            "dns-resolve": _factory("dns-resolve"),
            "ffuf": _factory("ffuf"),
            "ffuf-3": _factory("ffuf-3"),
            "port-check": _factory("port-check"),
        }
        adapter = mock.Mock()
        adapter.breaker.allow.return_value = True
        adapter.breaker.pause_reason.return_value = None
        with mock.patch.dict("pipeline.engine.RUNNERS", patched, clear=False):
            with self.assertRaises(OperatorStop):
                _run_active_modules(
                    params, None, adapter, tdir, tdir.name, {}, 30.0, Clock(), 1, []
                )
        self.assertEqual(calls, ["dns-resolve"])
        self.assertEqual(load_state(params, tdir, tdir.name)["modules"]["dns-resolve"]["status"], "failed")
        self.assertEqual(load_state(params, tdir, tdir.name)["modules"]["ffuf"]["status"], "pending")

    def test_append_log_silent_after_stop(self):
        params = Params(_ROOT)
        tdir = Path(tempfile.mkdtemp()) / "nolog.example"
        tdir.mkdir()
        new_run_state(params, tdir, tdir.name)
        set_run_status(params, tdir, tdir.name, "stopped", reason="operator stop")
        _append_log(params, tdir, "ffuf", "ffuf", 1, "should not appear")
        log_path = tdir / str(params.require("run_log"))
        self.assertFalse(log_path.exists())

    def test_dashboard_stop_calls_stop_target(self):
        from fastapi.testclient import TestClient

        from dashboard import app as appmod

        client = TestClient(appmod.app)
        headers = {"Authorization": "Bearer stop-token-ok"}
        with mock.patch.dict(os.environ, {"DASHBOARD_TOKEN": "stop-token-ok"}, clear=False):
            with mock.patch("pipeline.engine.stop_target", return_value=["cid1"]) as stop_fn:
                with mock.patch("pipeline.factory.ensure_layout", return_value=Path(tempfile.mkdtemp()) / "example.com"):
                    r = client.post("/api/run/stop", json={"target": "example.com"}, headers=headers)
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["exit"], int(Params(_ROOT).require("exit_code_stopped")))
        self.assertEqual(body["containers"], 1)
        self.assertTrue(stop_fn.called)
        self.assertEqual(stop_fn.call_args[0][1].name, "example.com")


if __name__ == "__main__":
    unittest.main()
