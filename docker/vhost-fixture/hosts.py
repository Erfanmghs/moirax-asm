#!/usr/bin/env python3
"""Install/remove /etc/hosts lines for the vhost fixture (host-network ffuf/httpx)."""

from __future__ import annotations

import sys
from pathlib import Path

MARKER = "# recon-pipeline vhost-fixture"
LINE = "172.28.100.10 fixture-target.test app.fixture-target.test www.fixture-target.test " + MARKER
HOSTS = Path("/etc/hosts")


def install() -> None:
    text = HOSTS.read_text(encoding="utf-8")
    if MARKER in text:
        return
    HOSTS.write_text(text.rstrip() + "\n" + LINE + "\n", encoding="utf-8")


def remove() -> None:
    lines = HOSTS.read_text(encoding="utf-8").splitlines(keepends=True)
    HOSTS.write_text("".join(ln for ln in lines if MARKER not in ln), encoding="utf-8")


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in {"install", "remove"}:
        raise SystemExit("usage: hosts.py install|remove")
    (install if sys.argv[1] == "install" else remove)()
