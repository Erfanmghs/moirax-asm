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


class TestLocalToolImages(unittest.TestCase):
    def test_missing_local_image_runs_build(self):
        from unittest import mock

        from pipeline.local_images import ensure_local_tool_images

        params = Params(_ROOT)
        notes: list[str] = []
        inspect = mock.Mock(return_value=mock.Mock(returncode=1, stdout="", stderr=""))
        build = mock.Mock(return_value=mock.Mock(returncode=0, stdout="", stderr=""))

        def _run(cmd, **_kwargs):
            if cmd[:3] == ["docker", "image", "inspect"] or (len(cmd) >= 3 and cmd[1] == "image"):
                return inspect()
            return build()

        with mock.patch("pipeline.local_images.docker_available", return_value=True):
            with mock.patch("pipeline.local_images.docker_prefix", return_value=["docker"]):
                with mock.patch("pipeline.local_images.subprocess.run", side_effect=_run):
                    built = ensure_local_tool_images(params, note=notes.append)
        self.assertEqual(built, ["moirax-asm/passive-tools:v1", "moirax-asm/ffuf:v2.1.0"])
        self.assertTrue(any("building missing" in n for n in notes))

    def test_present_local_image_skips_build(self):
        from unittest import mock

        from pipeline.local_images import ensure_local_tool_images

        params = Params(_ROOT)
        notes: list[str] = []
        with mock.patch("pipeline.local_images.docker_available", return_value=True):
            with mock.patch("pipeline.local_images.docker_prefix", return_value=["docker"]):
                with mock.patch(
                    "pipeline.local_images.subprocess.run",
                    return_value=mock.Mock(returncode=0, stdout="", stderr=""),
                ) as run:
                    built = ensure_local_tool_images(params, note=notes.append)
        self.assertEqual(built, [])
        self.assertTrue(all("inspect" in " ".join(c[0][0]) for c in run.call_args_list))
