"""recon/<target>/ directory factory (master prompt section 6.1)."""

from __future__ import annotations

import re
from pathlib import Path

from pipeline.params import Params

_SAFE_TARGET = re.compile(r"^[A-Za-z0-9._-]+$")


def sanitize_target(target: str) -> str:
    value = target.strip().lower().rstrip(".")
    if not value or not _SAFE_TARGET.match(value):
        raise ValueError(f"invalid target name: {target!r}")
    return value


def target_root(params: Params, target: str) -> Path:
    recon_root = params.root / str(params.require("recon_root"))
    return recon_root / sanitize_target(target)


def ensure_layout(params: Params, target: str) -> Path:
    root = target_root(params, target)
    for rel in params.require("recon_layout_dirs"):
        (root / str(rel)).mkdir(parents=True, exist_ok=True)
    return root
