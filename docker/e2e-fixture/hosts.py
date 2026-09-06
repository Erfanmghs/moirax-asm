#!/usr/bin/env python3
"""Install/remove /etc/hosts lines for the E2E fixture (host-network ffuf/httpx).

Maps the FULL E2E zone (apex + flat + nested names) to 127.0.0.1 — the
host-network fixture binds its HTTP listeners on the runner itself. The DNS
answers (for dnsx) point at 172.17.0.1 instead: the docker bridge gateway,
which is the same host. Marker-scoped: never touches other /etc/hosts content.
"""

from __future__ import annotations

import sys
from pathlib import Path

MARKER = "# recon-pipeline e2e-fixture"
HOSTS = Path("/etc/hosts")

FLAT = ("www", "app", "dev", "api", "mail")
NESTED = ("dev.app", "k8s.dev", "api.dev.app", "git.staging.app", "mail.api.dev.app")
NAMES = ("fixture-target.test",) + tuple(f"{n}.fixture-target.test" for n in FLAT + NESTED)

LINE = "127.0.0.1 " + " ".join(NAMES) + " " + MARKER


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
