"""Build pinned local tool images that are not on Docker Hub.

CI vehicles already `docker build -t moirax-asm/passive-tools:v1` (and ffuf)
before a run. A compose-only dashboard start does not, so the first operator
scan used to 125-fail those tools with `pull access denied`.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from pipeline.dockerbin import docker_available, docker_prefix
from pipeline.params import Params

# Local-only images (empty digest in tools.lock). Hub pull will never succeed.
_RECIPES: tuple[tuple[str, str, str], ...] = (
    ("moirax-asm/passive-tools:v1", "docker/passive-tools/Dockerfile", "docker/passive-tools"),
    ("moirax-asm/ffuf:v2.1.0", "docker/ffuf/Dockerfile", "docker/ffuf"),
)


def ensure_local_tool_images(params: Params, note=print) -> list[str]:
    """Inspect and, if missing, build local moirax-asm tool images.

    Disclosed and never-silent. Does not abort the run: Hub images still work
    if a local build fails. Returns the refs that were built this call.
    """
    built: list[str] = []
    if not docker_available(params):
        note("local-images: docker unavailable -- skipped, never silent")
        return built
    prefix = docker_prefix(params)
    root = params.root
    for ref, dockerfile, context in _RECIPES:
        if _image_present(prefix, ref):
            continue
        df = root / dockerfile
        ctx = root / context
        if not df.is_file() or not ctx.is_dir():
            note(f"local-images: missing recipe for {ref} ({dockerfile}) -- skipped, never silent")
            continue
        note(f"local-images: building missing {ref}")
        proc = subprocess.run(
            [*prefix, "build", "-t", ref, "-f", str(df), str(ctx)],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            err = (proc.stderr or proc.stdout or "").strip().splitlines()
            tail = err[-3:] if err else ["no docker output"]
            note(f"local-images: build failed for {ref} exit={proc.returncode} {' | '.join(tail)}")
            continue
        built.append(ref)
        note(f"local-images: built {ref}")
    return built


def _image_present(prefix: list[str], ref: str) -> bool:
    proc = subprocess.run(
        [*prefix, "image", "inspect", ref],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode == 0
