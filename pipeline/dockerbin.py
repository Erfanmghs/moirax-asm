"""Resolve the docker CLI as a direct Linux-native binary (master §2.7)."""

from __future__ import annotations

import shlex
import shutil
import subprocess

from pathlib import Path

from pipeline.params import Params

_WSL_ONLY = "run inside WSL with Docker Engine installed and on PATH (no Windows docker shim)"


def docker_prefix(params: Params) -> list[str]:
    raw = str(params.require("docker_binary"))
    parts = shlex.split(raw, posix=True)
    if not parts:
        raise RuntimeError(f"docker_binary is empty — {_WSL_ONLY}")
    if shutil.which(parts[0]) is None:
        raise RuntimeError(f"{parts[0]!r} not found on PATH — {_WSL_ONLY}")
    return parts


def docker_available(params: Params) -> bool:
    try:
        prefix = docker_prefix(params)
    except RuntimeError:
        return False
    try:
        proc = subprocess.run(
            [*prefix, "info"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0


def volume_host_path(params: Params, host_path: Path) -> str:
    """Return a Linux host path for docker -v binds (no Windows/UNC translation)."""
    _ = params.require("docker_binary")  # keep §5.6 params wire live
    return str(host_path.resolve())
