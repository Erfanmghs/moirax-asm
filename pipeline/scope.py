"""Authorization gate — master prompt §3. Zero network."""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from pipeline.params import Params
from pipeline.yaml_util import load_yaml_file

SETUP_INSTRUCTIONS = """scope.yaml is missing, empty, or invalid.

Setup:
  1. Copy the example:  cp scope.yaml.example scope.yaml
  2. Set engagement.name and engagement.authorization_date
  3. List authorized includes (apex domains, wildcards like *.example.com, CIDRs, ASNs)
  4. List excludes (hosts/CIDRs that must never be touched)
  5. Confirm written authorization for every include

The pipeline will not run and will not open any network connection until scope.yaml is valid.
"""

_ASN_RE = re.compile(r"^AS\d+$", re.IGNORECASE)
_HOST_RE = re.compile(r"^(?:\*\.)?(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$")


class ScopeError(Exception):
    def __init__(self, message: str, instructions: bool = False) -> None:
        super().__init__(message)
        self.instructions = instructions


class ScopeGate:
    def __init__(self, params: Params, document: dict[str, Any]) -> None:
        self.params = params
        self.document = document
        self.includes = [str(item).strip() for item in document.get("includes") or []]
        self.excludes = [str(item).strip() for item in document.get("excludes") or []]
        self._include_networks = _networks_from(self.includes)
        self._exclude_networks = _networks_from(self.excludes)
        self._rfc1918 = _parse_cidrs(params.require("rfc1918_cidrs"))
        self._loopback = _parse_cidrs(params.require("loopback_cidrs"))
        self._link_local = _parse_cidrs(params.require("link_local_cidrs"))
        self._cloud_suffixes = [s.lower().lstrip(".") for s in params.require("cloud_wildcard_suffixes")]

    @classmethod
    def load(cls, params: Params, scope_path: Path) -> "ScopeGate":
        if not scope_path.exists():
            raise ScopeError("scope.yaml is missing.", instructions=True)
        raw = scope_path.read_text(encoding="utf-8").strip()
        if not raw:
            raise ScopeError("scope.yaml is empty.", instructions=True)
        try:
            document = load_yaml_file(str(scope_path))
        except (OSError, ValueError) as exc:
            raise ScopeError(f"scope.yaml is invalid YAML: {exc}", instructions=True) from exc
        if not isinstance(document, dict):
            raise ScopeError("scope.yaml must be a mapping.", instructions=True)
        _validate_document(document)
        return cls(params, document)

    def validate_candidate(self, candidate: str) -> tuple[bool, str]:
        value = candidate.strip()
        if not value:
            return False, "empty candidate"
        if "://" in value:
            parsed = urlparse(value)
            host = parsed.hostname
            if not host:
                return False, "URL has no host"
            return self.validate_candidate(host)
        ip_obj = _try_ip(value)
        if ip_obj is not None:
            return self._validate_ip(ip_obj)
        host = value.lower().rstrip(".")
        return self._validate_host(host)

    def _validate_ip(self, ip_obj: ipaddress._BaseAddress) -> tuple[bool, str]:
        if _in_any(ip_obj, self._exclude_networks):
            return False, "excluded CIDR/IP"
        private_sets = (
            (self._rfc1918, "RFC1918"),
            (self._loopback, "loopback"),
            (self._link_local, "link-local"),
        )
        for networks, label in private_sets:
            if _in_any(ip_obj, networks) and not _in_any(ip_obj, self._include_networks):
                return False, f"{label} not listed in includes"
        if self._include_networks and _in_any(ip_obj, self._include_networks):
            return True, "in-scope IP"
        if self._include_networks:
            return False, "IP not in included CIDRs"
        return False, "no IP includes"

    def _validate_host(self, host: str) -> tuple[bool, str]:
        if _host_matches_any(host, self.excludes):
            return False, "excluded host"
        cloud_hit = _cloud_suffix(host, self._cloud_suffixes)
        if cloud_hit and not _host_matches_any(host, self.includes):
            return False, f"cloud wildcard {cloud_hit} not explicitly authorized"
        if _host_matches_any(host, self.includes):
            return True, "in-scope host"
        return False, "host not in includes"

    def enforce(self, target_dir: Path, candidate: str) -> bool:
        allowed, reason = self.validate_candidate(candidate)
        if allowed:
            return True
        log_rel = Path(str(self.params.require("out_of_scope_log")))
        self.log_rejection(target_dir / log_rel, candidate, reason)
        return False

    def log_rejection(self, log_path: Path, candidate: str, reason: str) -> None:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(f"{stamp}\trejected\t{candidate}\t{reason}\n")


def _validate_document(document: dict[str, Any]) -> None:
    engagement = document.get("engagement")
    if not isinstance(engagement, dict):
        raise ScopeError("scope.yaml missing engagement mapping.", instructions=True)
    name = engagement.get("name")
    if not isinstance(name, str) or not name.strip():
        raise ScopeError("engagement.name is required.", instructions=True)
    auth = engagement.get("authorization_date")
    if not isinstance(auth, str) or not auth.strip():
        raise ScopeError("engagement.authorization_date is required.", instructions=True)
    includes = document.get("includes")
    if not isinstance(includes, list) or not includes:
        raise ScopeError("includes must be a non-empty list.", instructions=True)
    excludes = document.get("excludes", [])
    if excludes is None:
        excludes = []
    if not isinstance(excludes, list):
        raise ScopeError("excludes must be a list.", instructions=True)
    for item in includes + excludes:
        if not isinstance(item, str) or not str(item).strip():
            raise ScopeError("scope entries must be non-empty strings.", instructions=True)
        if not _looks_like_scope_entry(str(item).strip()):
            raise ScopeError(f"unrecognized scope entry: {item}", instructions=True)


def _looks_like_scope_entry(value: str) -> bool:
    if _ASN_RE.match(value):
        return True
    if _try_ip(value) is not None:
        return True
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        pass
    host = value.lower().rstrip(".")
    if host.startswith("*."):
        return bool(_HOST_RE.match(host[2:]))
    return bool(_HOST_RE.match(host))


def _try_ip(value: str) -> ipaddress._BaseAddress | None:
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _parse_cidrs(values: list[str]) -> list[ipaddress._BaseNetwork]:
    return [ipaddress.ip_network(item, strict=False) for item in values]


def _networks_from(entries: list[str]) -> list[ipaddress._BaseNetwork]:
    networks: list[ipaddress._BaseNetwork] = []
    for item in entries:
        try:
            networks.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            ip_obj = _try_ip(item)
            if ip_obj is not None:
                networks.append(ipaddress.ip_network(ip_obj))
    return networks


def _in_any(ip_obj: ipaddress._BaseAddress, networks: list[ipaddress._BaseNetwork]) -> bool:
    for net in networks:
        if ip_obj.version == net.version and ip_obj in net:
            return True
    return False


def _cloud_suffix(host: str, suffixes: list[str]) -> str | None:
    for suffix in suffixes:
        if host == suffix or host.endswith("." + suffix):
            return suffix
    return None


def _host_matches_any(host: str, entries: list[str]) -> bool:
    host = host.lower().rstrip(".")
    for entry in entries:
        token = entry.strip().lower().rstrip(".")
        if _ASN_RE.match(token):
            continue
        try:
            ipaddress.ip_network(token, strict=False)
            continue
        except ValueError:
            pass
        if _try_ip(token) is not None:
            continue
        if _host_match(host, token):
            return True
    return False


def _host_match(host: str, pattern: str) -> bool:
    if pattern.startswith("*."):
        base = pattern[2:]
        return host == base or host.endswith("." + base)
    return host == pattern
