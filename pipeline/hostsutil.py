"""Hostname normalization and scope seeds."""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from pipeline.scope import ScopeGate

_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_FQDN = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$"
)
_ASN = re.compile(r"^AS\d+$", re.IGNORECASE)


def normalize_label(raw: str) -> str | None:
    token = raw.strip().lower().rstrip(".")
    if token.startswith("#") or not token:
        return None
    if "." in token:
        return None
    if not _LABEL.match(token):
        return None
    return token


def normalize_fqdn(raw: str) -> str | None:
    host = raw.strip().lower().rstrip(".")
    if not host or not _FQDN.match(host):
        return None
    return host


def labels_from_host(host: str, seed: str) -> list[str]:
    host_n = host.strip().lower().rstrip(".")
    seed_n = seed.strip().lower().rstrip(".")
    if host_n == seed_n:
        return []
    if host_n.endswith("." + seed_n):
        relative = host_n[: -(len(seed_n) + 1)]
    else:
        relative = host_n.split(".")[0]
    found: list[str] = []
    seen: set[str] = set()
    for part in relative.split("."):
        label = normalize_label(part)
        if label and label not in seen:
            seen.add(label)
            found.append(label)
    return found


def wildcard_seeds(gate: ScopeGate) -> list[str]:
    seeds: list[str] = []
    seen: set[str] = set()
    for item in gate.includes:
        token = str(item).strip().lower().rstrip(".")
        if not token or _ASN.match(token):
            continue
        try:
            ipaddress.ip_network(token, strict=False)
            continue
        except ValueError:
            pass
        try:
            ipaddress.ip_address(token)
            continue
        except ValueError:
            pass
        if token.startswith("*."):
            base = token[2:]
        else:
            base = token
        if base and base not in seen:
            seen.add(base)
            seeds.append(base)
    return seeds


def container_path(params: Any, target: str, rel: str) -> str:
    mount = str(params.require("recon_container_mount")).rstrip("/")
    rel_n = rel.replace("\\", "/").lstrip("/")
    return f"{mount}/{target}/{rel_n}"
