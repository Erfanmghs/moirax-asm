"""Parse public OSINT API bodies into hostnames (keyless + optional keyed).

These sources run through the existing curl-fetch adapter. No extra operator
signup is required for the keyless endpoints; SecurityTrails and VirusTotal
activate only when their keys are already in .env.
"""

from __future__ import annotations

import json
import re

from pipeline.hostsutil import normalize_fqdn

_HOST_RE = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}", re.I)


def hosts_from_api_body(source: str, body: str, apex: str) -> list[str]:
    """Return unique FQDNs extracted from one API response body."""
    apex_n = (apex or "").strip().lower().rstrip(".")
    raw = _dispatch(source, body or "", apex_n)
    out: list[str] = []
    seen: set[str] = set()
    for item in raw:
        host = normalize_fqdn(str(item).strip().lstrip("*.").lower())
        if not host or host in seen:
            continue
        seen.add(host)
        out.append(host)
    return out


def _dispatch(source: str, body: str, apex: str) -> list[str]:
    if source == "hackertarget":
        return _hackertarget(body)
    if source == "anubis":
        return _json_string_list(body)
    if source == "otx":
        return _otx(body)
    if source == "urlscan":
        return _urlscan(body)
    if source == "securitytrails":
        return _securitytrails(body, apex)
    if source == "virustotal":
        return _virustotal(body, apex)
    return _fallback_hosts(body)


def _hackertarget(body: str) -> list[str]:
    out: list[str] = []
    for line in body.splitlines():
        line = line.strip()
        if not line or line.lower().startswith("error"):
            continue
        host = line.split(",")[0].strip().lower()
        if host:
            out.append(host)
    return out


def _json_string_list(body: str) -> list[str]:
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return _fallback_hosts(body)
    if isinstance(data, list):
        return [str(x) for x in data if isinstance(x, str)]
    return []


def _otx(body: str) -> list[str]:
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return _fallback_hosts(body)
    out: list[str] = []
    rows = data.get("passive_dns") if isinstance(data, dict) else None
    if isinstance(rows, list):
        for row in rows:
            if isinstance(row, dict):
                for key in ("hostname", "hostname_unhashed"):
                    val = row.get(key)
                    if isinstance(val, str) and val.strip():
                        out.append(val)
    return out


def _urlscan(body: str) -> list[str]:
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return _fallback_hosts(body)
    out: list[str] = []
    rows = data.get("results") if isinstance(data, dict) else None
    if isinstance(rows, list):
        for row in rows:
            if not isinstance(row, dict):
                continue
            page = row.get("page") or {}
            if isinstance(page, dict):
                for key in ("domain", "apexDomain"):
                    val = page.get(key)
                    if isinstance(val, str) and val.strip():
                        out.append(val)
            task = row.get("task") or {}
            if isinstance(task, dict) and isinstance(task.get("domain"), str):
                out.append(str(task["domain"]))
    return out


def _securitytrails(body: str, apex: str) -> list[str]:
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return _fallback_hosts(body)
    labels = data.get("subdomains") if isinstance(data, dict) else None
    if not isinstance(labels, list):
        return []
    out: list[str] = []
    for label in labels:
        if not isinstance(label, str) or not label.strip():
            continue
        token = label.strip().lower().rstrip(".")
        if token.endswith("." + apex) or token == apex:
            out.append(token)
        else:
            out.append(f"{token}.{apex}" if apex else token)
    return out


def _virustotal(body: str, apex: str) -> list[str]:
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return _fallback_hosts(body)
    out: list[str] = []
    if isinstance(data, dict):
        for key in ("subdomains", "subdomain"):
            rows = data.get(key)
            if isinstance(rows, list):
                for item in rows:
                    if isinstance(item, str):
                        out.append(item)
        inner = data.get("data")
        if isinstance(inner, list):
            for row in inner:
                if isinstance(row, dict):
                    ident = row.get("id")
                    if isinstance(ident, str):
                        out.append(ident)
    return out


def _fallback_hosts(body: str) -> list[str]:
    return [m.group(0).lower() for m in _HOST_RE.finditer(body or "")]
