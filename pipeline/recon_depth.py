"""Operator recon depths: nested DNS and nested vhost are independent knobs."""

from __future__ import annotations

from pipeline.hostsutil import normalize_fqdn
from pipeline.params import Params


def _clamp_depth(params: Params, primary_key: str, fallback_key: str | None = None) -> int:
    lo = int(params.require("ffuf_depth_min"))
    hi = int(params.require("ffuf_depth_max"))
    raw = params.settings.get(primary_key)
    if (raw is None or raw == "") and fallback_key:
        raw = params.settings.get(fallback_key)
        if raw is None or raw == "":
            try:
                raw = params.require(fallback_key)
            except Exception:  # noqa: BLE001 -- missing fallback uses floor
                raw = lo
    elif raw is None or raw == "":
        try:
            raw = params.require(primary_key)
        except Exception:  # noqa: BLE001
            raw = lo
    try:
        depth = int(raw)
    except (TypeError, ValueError):
        depth = lo
    return max(lo, min(depth, hi))


def clamp_recon_depth(params: Params) -> int:
    """Nested DNS / second-pass dnsx depth (recon_depth)."""
    return _clamp_depth(params, "recon_depth", "ffuf_depth")


def clamp_ffuf_depth(params: Params) -> int:
    """Nested Host-header vhost depth (ffuf_depth). Independent of DNS depth."""
    return _clamp_depth(params, "ffuf_depth", None)


def clamp_dnsx_parallel_parents(params: Params) -> int:
    def _int(name: str, default: int) -> int:
        raw = params.settings.get(name, default)
        try:
            return int(raw)
        except (TypeError, ValueError):
            return default

    lo = max(1, _int("dnsx_parallel_parents_min", 1))
    hi = max(lo, _int("dnsx_parallel_parents_max", 8))
    return max(lo, min(hi, _int("dnsx_parallel_parents", lo)))


def dnsx_parent_worker_count(params: Params, parent_count: int, current_qps: int) -> int:
    """Split live QPS across nested dnsx jobs (4×1250 at cap 5000)."""
    n = max(1, int(parent_count))
    want = clamp_dnsx_parallel_parents(params)
    qps = max(1, int(current_qps))
    return max(1, min(want, n, qps))


def dnsx_job_qps(current_qps: int, workers: int) -> int:
    return max(1, int(current_qps) // max(1, int(workers)))


def child_depth(host: str, apex: str) -> int:
    """How many extra labels `host` has under `apex`. Apex itself is 0.

    api.example.com vs example.com -> 1
    dev.api.example.com vs example.com -> 2
    """
    h = (host or "").strip().lower().rstrip(".")
    a = (apex or "").strip().lower().rstrip(".")
    if not h or not a:
        return -1
    if h == a:
        return 0
    if not h.endswith("." + a):
        return -1
    rel = h[: -(len(a) + 1)]
    if not rel or ".." in rel:
        return -1
    return rel.count(".") + 1


def recursion_parents(
    resolved: dict,
    apex: str,
    level: int,
    wildcard_ip: str | set[str] | None,
    cap: int,
) -> list[str]:
    """Hosts to brute as dnsx -d PARENT at this level (level 1 = apex)."""
    if level <= 1:
        return [apex]
    want = level - 1
    if isinstance(wildcard_ip, str):
        wild = {wildcard_ip} if wildcard_ip else set()
    else:
        wild = {str(ip) for ip in (wildcard_ip or []) if ip}
    out: list[str] = []
    for host, row in sorted((resolved or {}).items()):
        if child_depth(str(host), apex) != want:
            continue
        if not isinstance(row, dict):
            continue
        ips = [str(ip) for ip in (row.get("ips") or []) if ip]
        if not ips:
            continue
        if wild and wild.intersection(ips):
            continue
        out.append(str(host))
    if cap and len(out) > cap:
        return out[:cap]
    return out


def vhost_bases(apex: str, names: list[str], depth: int) -> list[str]:
    """Host-header parents allowed at this nested vhost depth (ffuf_depth).

    depth 1 -> only the apex (Host: FUZZ.apex)
    depth 2 -> apex plus one-label names (Host: FUZZ.api.apex)
    """
    apex_n = normalize_fqdn(apex) or (apex or "").strip().lower().rstrip(".")
    if not apex_n or depth < 1:
        return []
    out: list[str] = []
    seen: set[str] = set()

    def _add(host: str) -> None:
        token = normalize_fqdn(host) or (host or "").strip().lower().rstrip(".")
        if token and token not in seen:
            seen.add(token)
            out.append(token)

    _add(apex_n)
    for raw in names:
        token = normalize_fqdn(raw) or (raw or "").strip().lower().rstrip(".")
        extra = child_depth(token, apex_n)
        if extra >= 1 and extra < depth:
            _add(token)
    return out


def vhost_driven_parents(
    apex: str,
    depth: int,
    resolved: dict,
    extra_names: list[str],
    already: set[str],
    wildcard_names: set[str],
    cap: int,
) -> list[str]:
    """Parents for a second-pass dnsx brute after vhost names appear.

    A vhost hit like staging.api.example.com at depth 2 is itself a DNS
    parent: brute FUZZ.staging.api.example.com is depth 3 and is skipped.
    """
    apex_n = normalize_fqdn(apex) or (apex or "").strip().lower().rstrip(".")
    skip = {normalize_fqdn(x) or str(x).strip().lower() for x in already}
    skip.add(apex_n)
    wild = {normalize_fqdn(x) or str(x).strip().lower() for x in wildcard_names}
    names = list(extra_names)
    for host in (resolved or {}):
        names.append(str(host))
    out: list[str] = []
    seen: set[str] = set()
    for raw in names:
        host = normalize_fqdn(raw) or (raw or "").strip().lower().rstrip(".")
        if not host or host in seen or host in skip or host in wild:
            continue
        extra = child_depth(host, apex_n)
        if extra < 1 or extra >= depth:
            continue
        row = (resolved or {}).get(host) or {}
        ips = [str(ip) for ip in (row.get("ips") or []) if ip] if isinstance(row, dict) else []
        # Vhost names may not be in DNS yet; still brute under them.
        if row and isinstance(row, dict) and row.get("resolution_status") == "unresolved" and not ips:
            continue
        seen.add(host)
        out.append(host)
    if cap and len(out) > cap:
        return out[:cap]
    return out
