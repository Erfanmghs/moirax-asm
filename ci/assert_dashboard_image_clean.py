#!/usr/bin/env python3
"""Fail if a dashboard image baked operator estate or secrets.

The published image may contain fixture scope (example.com / e2e zone) and
an empty targets.yaml. Live allow-lists, recon warehouses, dashboard auth,
and .env must stay on the operator host -- never in image layers.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "ci"))

from c1_release_gate import extra_scope_includes, extra_target_names  # noqa: E402
from pipeline.yaml_util import load_yaml  # noqa: E402

FORBIDDEN_PATHS = (
    "/app/.env",
    "/app/compose.env",
    "/app/.dashboard-operator-pass",
    "/app/dashboard/config.json",
    "/app/dashboard/.warehouse-hmac",
    "/app/dashboard/auth/auth.sqlite",
    "/app/wordlists/custom/platform-learned.txt",
)


def _run(image: str, args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "run", "--rm", "--network", "none", "--entrypoint", args[0], image, *args[1:]],
        capture_output=True,
        text=True,
        check=False,
    )


def _cat(image: str, path: str) -> str:
    proc = _run(image, ["cat", path])
    if proc.returncode != 0:
        raise SystemExit(f"FAIL cannot read {path} in {image}: {(proc.stderr or proc.stdout).strip()}")
    return proc.stdout


def _exists(image: str, path: str) -> bool:
    proc = _run(image, ["test", "-e", path])
    return proc.returncode == 0


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: assert_dashboard_image_clean.py IMAGE", file=sys.stderr)
        return 2
    image = sys.argv[1]
    failures: list[str] = []

    for path in FORBIDDEN_PATHS:
        if _exists(image, path):
            failures.append(f"forbidden path present: {path}")

    if _exists(image, "/app/recon"):
        proc = subprocess.run(
            [
                "docker", "run", "--rm", "--network", "none", "--entrypoint", "sh",
                image, "-c", "find /app/recon -mindepth 1 -print 2>/dev/null | head",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        extra = (proc.stdout or "").strip()
        if extra:
            failures.append("recon/ is not empty in the image")

    targets = load_yaml(_cat(image, "/app/targets.yaml")) or {}
    names = list((targets.get("targets") or {}).keys())
    extra_names = extra_target_names(names)
    if extra_names:
        failures.append(f"targets.yaml is not fixture-empty: {extra_names}")

    scope = load_yaml(_cat(image, "/app/scope.yaml")) or {}
    includes = [str(i) for i in (scope.get("includes") or [])]
    extra_inc = extra_scope_includes(includes)
    if extra_inc:
        failures.append(f"scope.yaml includes are not fixture-only: {extra_inc}")

    if failures:
        print("FAIL dashboard image contains operator estate or secrets:")
        for item in failures:
            print(f"  - {item}")
        return 1
    print(f"PASS {image} has fixture scope only, empty targets, no operator files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
