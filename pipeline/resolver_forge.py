"""RESOLVER FORGE: aggregate, validate, quarantine <80%, >=100 healthy."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from pipeline.adapter import Adapter
from pipeline.hostsutil import container_path
from pipeline.ndjson import parse_json_payload
from pipeline.params import Params
from pipeline.textio import atomic_write_text, read_lines
from pipeline.yaml_util import load_yaml_file

# Same-process reuse so nested DNS after vhost does not re-probe the fleet.
_SESSION: dict[str, tuple[str, list[str]]] = {}


def _opt(params: Params, name: str, default: Any) -> Any:
    if name in params.settings:
        return params.settings[name]
    return default


def _cache_path(params: Params) -> Path:
    return params.root / str(_opt(params, "resolver_health_cache", "resolvers/forge/health-cache.json"))


def _gather_hash(ips: list[str], domains: list[str]) -> str:
    blob = "\n".join(ips) + "|" + "\n".join(domains)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _load_cache(params: Params, digest: str) -> list[str] | None:
    path = _cache_path(params)
    if not path.is_file():
        return None
    try:
        ttl = float(_opt(params, "resolver_cache_ttl_sec", 21600))
        doc = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return None
    if not isinstance(doc, dict) or str(doc.get("digest") or "") != digest:
        return None
    try:
        age = time.time() - float(doc.get("ts") or 0)
    except (TypeError, ValueError):
        return None
    if age < 0 or age > ttl:
        return None
    healthy = [str(x).strip() for x in (doc.get("healthy") or []) if str(x).strip()]
    return healthy if healthy else None


def _save_cache(params: Params, digest: str, healthy: list[str]) -> None:
    path = _cache_path(params)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "digest": digest,
        "ts": time.time(),
        "healthy": healthy,
        "count": len(healthy),
    }
    atomic_write_text(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def _write_fleet(
    params: Params,
    target_dir: Path,
    healthy: list[str],
    quarantined: list[str],
) -> Path:
    forge_rel = str(params.require("resolver_forge_output"))
    forge_path = params.root / forge_rel
    q_path = params.root / str(params.require("resolver_quarantine_output"))
    atomic_write_text(forge_path, "\n".join(healthy) + ("\n" if healthy else ""))
    existing_q = {line.strip() for line in read_lines(q_path) if line.strip()}
    existing_q.update(quarantined)
    atomic_write_text(q_path, "\n".join(sorted(existing_q)) + ("\n" if existing_q else ""))
    dest = target_dir / str(params.require("resolver_target_copy"))
    dest.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(dest, forge_path.read_text(encoding="utf-8") if forge_path.is_file() else "")
    return dest


def forge_resolvers(params: Params, adapter: Adapter, target_dir: Path, target: str) -> Path:
    registry = load_yaml_file(str(params.root / str(params.require("resolvers_registry"))))
    if not isinstance(registry, dict):
        raise ValueError("resolvers.yaml must be a mapping")
    domains = [str(x).strip() for x in params.require("resolver_validate_domains") if str(x).strip()]
    session_key = str(params.root.resolve())
    cached = _SESSION.get(session_key)
    if cached:
        dest = _write_fleet(params, target_dir, cached[1], [])
        _log(
            params,
            target_dir,
            f"resolver-forge session reuse healthy={len(cached[1])} (skip re-validate)",
        )
        return dest
    gathered = _collect(params, registry)
    digest = _gather_hash(gathered, domains)

    cached_healthy = _load_cache(params, digest)
    if cached_healthy:
        dest = _write_fleet(params, target_dir, cached_healthy, [])
        _SESSION[session_key] = (digest, cached_healthy)
        _log(
            params,
            target_dir,
            f"resolver-forge cache hit healthy={len(cached_healthy)} ttl={params.require('resolver_cache_ttl_sec')}s",
        )
        return dest

    health = _validate(params, adapter, target_dir, target, gathered)
    min_ratio = float(params.require("resolver_min_success_ratio"))
    healthy: list[str] = []
    quarantined: list[str] = []
    for ip, ratio in health.items():
        if ratio < min_ratio:
            quarantined.append(ip)
        else:
            healthy.append(ip)
    min_healthy = int(params.require("resolver_min_healthy_count"))
    if len(healthy) < min_healthy:
        _log(
            params,
            target_dir,
            f"healthy_resolvers={len(healthy)} below resolver_min_healthy_count={min_healthy}",
        )
    dest = _write_fleet(params, target_dir, healthy, quarantined)
    _SESSION[session_key] = (digest, healthy)
    try:
        _save_cache(params, digest, healthy)
    except OSError as exc:
        _log(params, target_dir, f"resolver-forge cache write failed (disclosed): {exc}")
    _log(
        params,
        target_dir,
        f"resolver-forge healthy={len(healthy)} quarantined={len(quarantined)} "
        f"forged={params.require('resolver_forge_output')}",
    )
    if quarantined:
        _log(params, target_dir, "quarantined: " + ",".join(quarantined[:20]))
    return dest


def _collect(params: Params, registry: dict[str, Any]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    seed = params.root / str(params.require("resolver_seed_file"))
    for ip in _ips_from_lines(read_lines(seed)):
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    timeout = int(params.require("resolver_source_timeout_sec"))
    cap = int(params.require("resolver_source_cap"))
    urls = []
    for src in registry.get("sources") or []:
        if not isinstance(src, dict):
            continue
        url = str(src.get("url") or "").strip()
        if url:
            urls.append(url)

    def fetch(url: str) -> list[str]:
        try:
            req = urllib.request.Request(url, method="GET", headers={"User-Agent": "moirax-ASM"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode("utf-8", errors="replace")
        except (urllib.error.URLError, TimeoutError, OSError):
            return []
        found: list[str] = []
        for ip in _ips_from_lines(body.splitlines()):
            found.append(ip)
            if len(found) >= cap:
                break
        return found

    if urls:
        workers = max(1, min(8, len(urls)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for extra in pool.map(fetch, urls):
                for ip in extra:
                    if ip not in seen:
                        seen.add(ip)
                        out.append(ip)
    for ip in _ips_from_lines([str(x) for x in (registry.get("manual_add") or [])]):
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    removed = set(_ips_from_lines([str(x) for x in (registry.get("manual_remove") or [])]))
    q_path = params.root / str(params.require("resolver_quarantine_output"))
    removed.update(x.strip() for x in read_lines(q_path) if x.strip())
    return [ip for ip in out if ip not in removed]


def _validate(
    params: Params,
    adapter: Adapter,
    target_dir: Path,
    target: str,
    resolvers: list[str],
) -> dict[str, float]:
    domains = [str(x).strip() for x in params.require("resolver_validate_domains")]
    domains = [d for d in domains if d]
    if not domains:
        raise ValueError("resolver_validate_domains is empty")
    health: dict[str, float] = {}
    if not resolvers:
        return health
    workers = max(1, min(int(params.require("resolver_validate_concurrency")), len(resolvers)))

    hosts_rel = str(params.require("resolver_probe_hosts_rel"))
    hosts_path = target_dir / hosts_rel
    atomic_write_text(hosts_path, "\n".join(domains) + "\n")
    hosts_c = container_path(params, target, hosts_rel)

    native_on = bool(_opt(params, "fast_dns_enabled", True))
    if native_on:
        from pipeline.fast_dns import probe_resolvers

        udp_timeout = float(_opt(params, "resolver_probe_udp_timeout_sec", 1.5))
        native_workers = max(workers, int(_opt(params, "resolver_native_concurrency", 64)))
        health = probe_resolvers(
            resolvers,
            domains,
            timeout_sec=udp_timeout,
            workers=native_workers,
        )
        _log(
            params,
            target_dir,
            f"resolver-forge native UDP probes={len(resolvers)} workers={native_workers} "
            "(docker dnsx-probe skipped)",
        )
        min_ratio = float(params.require("resolver_min_success_ratio"))
        native_healthy = sum(1 for ratio in health.values() if ratio >= min_ratio)
        if native_healthy > 0 or not bool(_opt(params, "fast_dns_fallback_docker", True)):
            return health
        _log(
            params,
            target_dir,
            "resolver-forge native UDP returned zero healthy -- falling back to docker dnsx-probe",
        )

    def probe(ip: str) -> tuple[str, float]:
        extra = {
            "dnsx_hosts": hosts_c,
            "probe_resolver": ip,
            "skip_parse": True,
            "output_raw_dir": f"logs/raw/resolver-probe/{ip.replace(':', '_')}",
            "breaker_probe": True,
        }
        result = adapter.invoke(
            "dnsx-probe",
            module="resolver-forge",
            extra=extra,
            planned_concurrency=workers,
            timeout_sec=float(params.require("resolver_probe_timeout_sec")),
            allow_fallback=False,
        )
        answered = _answered_hosts(result.stdout)
        ratio = len(answered) / len(domains) if domains else 0.0
        return ip, ratio

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = [pool.submit(probe, ip) for ip in resolvers]
        for fut in as_completed(futs):
            ip, ratio = fut.result()
            health[ip] = ratio
    return health


def _answered_hosts(stdout: str) -> set[str]:
    payload = parse_json_payload(stdout)
    rows: list[Any]
    if isinstance(payload, list):
        rows = payload
    elif isinstance(payload, dict):
        rows = [payload]
    else:
        rows = []
    found: set[str] = set()
    for row in rows:
        if not isinstance(row, dict) or not _row_has_a(row):
            continue
        host = str(row.get("host") or row.get("input") or "").strip().lower().rstrip(".")
        if host:
            found.add(host)
    return found


def _row_has_a(row: dict[str, Any]) -> bool:
    if row.get("a"):
        return True
    status = str(row.get("status_code") or row.get("status") or "").upper()
    return status in {"NOERROR", "NOERR"} and bool(row.get("host"))


def _ips_from_lines(lines: list[str]) -> list[str]:
    found: list[str] = []
    for raw in lines:
        token = raw.strip().split("#", 1)[0].strip()
        if not token:
            continue
        token = token.split()[0]
        try:
            obj = ipaddress.ip_address(token)
        except ValueError:
            continue
        if obj.is_loopback or obj.is_unspecified or obj.is_multicast or obj.is_link_local or obj.is_private:
            continue
        found.append(str(obj))
    return found


def _log(params: Params, target_dir: Path, detail: str) -> None:
    from datetime import datetime, timezone

    path = target_dir / str(params.require("run_log"))
    path.parent.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with path.open("a", encoding="utf-8") as handle:
        handle.write(f"{stamp}\tresolver-forge\tresolvers\t0\tok\t{detail}\n")
