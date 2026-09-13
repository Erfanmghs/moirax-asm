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


def wildcard_seeds(gate: ScopeGate, target: str | None = None) -> list[str]:
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
    if not target:
        return seeds
    wanted = target.strip().lower().rstrip(".")
    matched = [seed for seed in seeds if seed == wanted or wanted.endswith("." + seed)]
    if matched:
        return matched
    allowed, _ = gate.validate_candidate(wanted)
    if allowed and wanted:
        return [wanted]
    return []


def is_wildcard_only(ips: list[str] | None, wildcard_ips: set[str] | None) -> bool:
    """True when every resolved IP is a catch-all / nonce probe address."""
    wild = {str(ip) for ip in (wildcard_ips or []) if ip}
    have = [str(ip) for ip in (ips or []) if ip]
    if not have or not wild:
        return False
    return all(ip in wild for ip in have)


def keep_resolved_host(
    host: str,
    ips: list[str] | None,
    wildcard_ips: set[str] | None,
    apex: str,
    source: str | None = None,
    independent: set[str] | None = None,
) -> bool:
    """Keep the live apex and independently found names; drop brute catch-all noise."""
    h = (host or "").strip().lower().rstrip(".")
    a = (apex or "").strip().lower().rstrip(".")
    if not h:
        return False
    if a and h == a:
        return True
    if source in ("known", "passive", "ffuf"):
        return True
    if independent and h in independent:
        return True
    have = [str(ip) for ip in (ips or []) if ip]
    if not have:
        return False
    return not is_wildcard_only(ips, wildcard_ips)


_INDEPENDENT_SOURCES = frozenset({
    "crtsh", "subfinder", "amass", "findomain", "assetfinder", "assetfinder-related",
    "passive", "passive-recon", "waybackurls", "gau", "chaos", "ffuf", "httpx", "known",
})


def asset_discovery_source(row: dict[str, Any]) -> str:
    sources = [str(s).strip().lower() for s in (row.get("sources") or []) if s]
    if any(s in _INDEPENDENT_SOURCES or s.startswith("psv") for s in sources):
        return "known"
    return str(row.get("source") or "brute")


def keep_asset_row(row: dict[str, Any], wildcard_ips: set[str] | None, apex: str) -> bool:
    host = str(row.get("host") or "").strip().lower().rstrip(".")
    ips = [str(x) for x in (row.get("ips") or ([row.get("ip")] if row.get("ip") else [])) if x]
    return keep_resolved_host(host, ips, wildcard_ips, apex, source=asset_discovery_source(row))


def container_path(params: Any, target: str, rel: str) -> str:
    mount = str(params.require("recon_container_mount")).rstrip("/")
    rel_n = rel.replace("\\", "/").lstrip("/")
    return f"{mount}/{target}/{rel_n}"
