"""Tool containers must not deadlock when they write more than a pipe buffer."""

from __future__ import annotations

import time
import unittest
from pathlib import Path

from pipeline.adapter import _DockerRunner, _container_name
from pipeline.params import Params

_ROOT = Path(__file__).resolve().parents[1]


class TestDockerRunnerPipes(unittest.TestCase):
    def test_container_name_from_docker_argv(self):
        self.assertEqual(_container_name(["docker", "run", "--name", "recon-abc", "img"]), "recon-abc")
        self.assertEqual(_container_name(["docker", "run", "img"]), "")

    def test_large_stdout_does_not_deadlock(self):
        runner = _DockerRunner(Params(_ROOT))
        payload = 2_000_000
        cmd = ["python3", "-c", f"print('A'*{payload}, end='')"]
        started = time.time()
        completed = runner.run(cmd, timeout_sec=8)
        self.assertLess(time.time() - started, 6)
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(len(completed.stdout), payload)

    def test_timeout_returns_124(self):
        runner = _DockerRunner(Params(_ROOT))
        completed = runner.run(["python3", "-c", "import time; time.sleep(30)"], timeout_sec=0.4)
        self.assertEqual(completed.returncode, 124)
        self.assertIn("container timeout", completed.stderr)

    def test_dnsx_with_output_file_is_silent(self):
        params = Params(_ROOT)
        argv = (params.tools.get("dnsx") or {}).get("argv_template") or []
        self.assertIn("-silent", argv)
        self.assertIn("-o", argv)
        canary = (params.tools.get("dnsx-canary") or {}).get("argv_template") or []
        self.assertNotIn("-silent", canary)
