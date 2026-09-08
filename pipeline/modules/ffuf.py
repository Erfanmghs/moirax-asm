"""FFUF-0 forge + optional HTTP label brute + FFUF-2 vhost (after DNS-RESOLVE)."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from pipeline.adapter import Adapter, InvokeResult
from pipeline.hostsutil import container_path, normalize_fqdn, normalize_label, wildcard_seeds
from pipeline.jsonio import write_json
from pipeline.ndjson import load_json_file, parse_json_payload
from pipeline.params import Params
from pipeline.scope import ScopeGate
from pipeline.wordlist_forge import (
    copy_into_target,
    forge_custom_subdomains,
    materialize_effective,
)
from pipeline import httpx_probe


def run_ffuf(
    params: Params,
    gate: ScopeGate,
    adapter: Adapter,
    target_dir: Path,
    target: str,
    extra: dict[str, Any],
    planned: int,
    timeout_sec: float | None,
    partial: list[str],
) -> dict[str, Any]:
    seeds = wildcard_seeds(gate, target)
    custom = forge_custom_subdomains(params)
    wl_rel = str(params.require("ffuf_target_wordlist_rel"))
    copy_into_target(params, target_dir, custom, wl_rel)
    wl_c = container_path(params, target, wl_rel)
    allowed_ffuf = _labels_in(custom)
    wordlist_n = len(allowed_ffuf)
    hosts: dict[str, dict[str, Any]] = {}
    vhosts: list[dict[str, Any]] = []
    request_count = 0
    max_req = int(params.require("max_total_requests"))
    max_level = int(params.require("max_hosts_per_level"))
    depth = int(params.require("ffuf_depth"))
    depth = max(int(params.require("ffuf_depth_min")), min(depth, int(params.require("ffuf_depth_max"))))

    if bool(params.require("ffuf_http_subdomain_brute")):
        parents_by_level: dict[int, list[str]] = {1: list(seeds)}
        for level in range(1, depth + 1):
            parents = parents_by_level.get(level) or []
            next_parents: list[str] = []
            for parent in parents:
                if request_count + wordlist_n > max_req:
                    partial.append("max_total_requests")
                    break
                url = f"http://FUZZ.{parent}"
                out_rel = f"10_subdomains/ffuf/level{level}_{_safe(parent)}.json"
                result = _ffuf_job(
                    adapter,
                    extra,
                    planned,
                    timeout_sec,
                    {
                        "ffuf_url": url,
                        "ffuf_wordlist": wl_c,
                        "ffuf_output": container_path(params, target, out_rel),
                        "output_raw_dir": f"logs/raw/ffuf/level{level}_{_safe(parent)}",
                        "skip_parse": True,
                    },
                )
                request_count += wordlist_n
                hits = _ffuf_hits(target_dir / out_rel, result)
                for hit in hits:
                    label = _wordlist_fuzz_label(hit, parent, allowed_ffuf)
                    if not label:
                        continue
                    fqdn = normalize_fqdn(f"{label}.{parent}")
                    if not fqdn:
                        continue
                    if not gate.enforce(target_dir, fqdn):
                        continue
                    row = {
                        "fqdn": fqdn,
                        "level": level,
                        "parent": parent,
                        "alive": None,
                        "http_status": hit.get("status"),
                        "length": hit.get("length"),
                    }
                    hosts[fqdn] = row
                    next_parents.append(fqdn)
            if len(next_parents) > max_level:
                partial.append("max_hosts_per_level")
                next_parents = sorted(set(next_parents))[:max_level]
            else:
                next_parents = sorted(set(next_parents))
            parents_by_level[level + 1] = next_parents
            if "max_total_requests" in partial:
                break
    else:
        hosts.update(_hosts_from_dnsr(params, target_dir, seeds))

    host_list = sorted(hosts.values(), key=lambda r: r["fqdn"])
    _probe_alive(params, adapter, target_dir, target, extra, planned, timeout_sec, host_list)

    vhost_src = materialize_effective(params, "FFUF-2")
    v_rel = str(params.require("ffuf_vhost_wordlist_rel"))
    copy_into_target(params, target_dir, vhost_src, v_rel)
    v_c = container_path(params, target, v_rel)
    allowed_vhost = _labels_in(vhost_src)
    v_n = len(allowed_vhost)

    queue = [row["fqdn"] for row in host_list]
    seen_vbase = set(queue)
    if adapter.enabled("ffuf-vhost"):
        for vpass in range(1, depth + 1):
            if not queue:
                break
            round_hosts = list(queue)
            queue = []
            for base in round_hosts:
                if request_count + v_n > max_req:
                    partial.append("max_total_requests")
                    break
                meta = hosts.get(base) or {"alive": None}
                dead = meta.get("alive") is False
                out_rel = f"15_vhosts/ffuf/vhost_{_safe(base)}_p{vpass}.json"
                header = f"Host: FUZZ.{base}"
                result = _ffuf_job(
                    adapter,
                    extra,
                    planned,
                    timeout_sec,
                    {
                        "ffuf_url": f"http://{base}",
                        "ffuf_wordlist": v_c,
                        "ffuf_output": container_path(params, target, out_rel),
                        "ffuf_host_header": header,
                        "output_raw_dir": f"logs/raw/ffuf/vhost_{_safe(base)}_p{vpass}",
                        "skip_parse": True,
                        "ffuf_mode": "vhost",
                    },
                    tool="ffuf-vhost",
                )
                request_count += v_n
                for hit in _ffuf_hits(target_dir / out_rel, result):
                    label = _wordlist_fuzz_label(hit, base, allowed_vhost)
                    if not label:
                        continue
                    vhost = normalize_fqdn(f"{label}.{base}")
                    if not vhost:
                        continue
                    if not gate.enforce(target_dir, vhost):
                        continue
                    status = hit.get("status")
                    length = hit.get("length")
                    alive_hit = status is not None
                    rec = {
                        "base_host": base,
                        "vhost": vhost,
                        "alive": alive_hit,
                        "http_status": status,
                        "length": length,
                        "misconfig_suspect": bool(dead and alive_hit),
                    }
                    vhosts.append(rec)
                    if vhost not in hosts:
                        hosts[vhost] = {
                            "fqdn": vhost,
                            "level": int(meta.get("level") or 1) + 1,
                            "parent": base,
                            "alive": alive_hit,
                            "http_status": status,
                            "length": length,
                        }
                    if vhost not in seen_vbase and vpass < depth:
                        seen_vbase.add(vhost)
                        queue.append(vhost)
            if "max_total_requests" in partial:
                break

    payload = {
        "schema_version": int(params.require("schema_version")),
        "module": "ffuf",
        "hosts": sorted(hosts.values(), key=lambda r: r["fqdn"]),
        "vhosts": vhosts,
    }
    data_path = target_dir / str(params.require("ffuf_data_json"))
    write_json(data_path, payload)
    summary = target_dir / str(params.require("ffuf_summary"))
    summary.parent.mkdir(parents=True, exist_ok=True)
    summary.write_text(
        "\n".join(
            [
                "# ffuf",
                "",
                f"wordlist_entries: {wordlist_n}",
                f"hosts: {len(payload['hosts'])}",
                f"vhosts: {len(vhosts)}",
                f"requests: {request_count}",
                f"partial: {', '.join(partial) if partial else 'none'}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return payload


def _ffuf_job(
    adapter: Adapter,
    extra: dict[str, Any],
    planned: int,
    timeout_sec: float | None,
    local: dict[str, Any],
    tool: str = "ffuf",
) -> InvokeResult:
    merged = dict(extra)
    merged.update(local)
    return adapter.invoke(tool, module="ffuf", extra=merged, planned_concurrency=planned, timeout_sec=timeout_sec)


def _ffuf_hits(out_path: Path, result: InvokeResult) -> list[dict[str, Any]]:
    payload = load_json_file(out_path)
    if payload is None:
        payload = parse_json_payload(result.stdout)
    rows = []
    if isinstance(payload, dict):
        rows = payload.get("results") or []
    elif isinstance(payload, list):
        rows = payload
    hits: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        inp = row.get("input") or {}
        fuzz = ""
        if isinstance(inp, dict):
            fuzz = str(inp.get("FUZZ") or inp.get("fuzz") or next(iter(inp.values()), "") or "")
        status = row.get("status") or row.get("status_code")
        length = row.get("length")
        hits.append(
            {
                "fuzz": fuzz,
                "host": str(row.get("host") or ""),
                "url": str(row.get("url") or ""),
                "status": int(status) if status is not None else None,
                "length": int(length) if length is not None else None,
            }
        )
    return hits


def _hostname_from_hit(hit: dict[str, Any]) -> str:
    host = str(hit.get("host") or "").strip().lower().split(":")[0].rstrip(".")
    if host:
        return host
    url = str(hit.get("url") or "").strip()
    if not url:
        return ""
    parsed = urlparse(url if "://" in url else f"http://{url}")
    return (parsed.hostname or "").lower().rstrip(".")


def _wordlist_fuzz_label(hit: dict[str, Any], parent: str, allowed: set[str]) -> str | None:
    """Accept a hit iff a recovered label is in the job wordlist.

    Autocalib can desync input.FUZZ from the Host/URL that actually answered.
    Recover the relative label from host/url first; still drop values that are
    not in the wordlist (xnrbibej-class / FUZZ tokens invented by -ac).
    """
    candidates: list[str] = []
    parent_n = parent.strip().lower().rstrip(".")
    host = _hostname_from_hit(hit)
    if host and parent_n:
        if host.endswith("." + parent_n):
            rel = host[: -(len(parent_n) + 1)]
            first = rel.split(".")[0] if rel else ""
            if first:
                candidates.append(first)
        elif host != parent_n:
            first = host.split(".")[0]
            if first:
                candidates.append(first)
    fuzz = str(hit.get("fuzz") or "")
    if fuzz:
        candidates.append(fuzz)
    seen: set[str] = set()
    for raw in candidates:
        lab = normalize_label(raw)
        if not lab or lab in seen:
            continue
        seen.add(lab)
        if lab in allowed:
            return lab
    return None


def _hosts_from_dnsr(params: Params, target_dir: Path, seeds: list[str]) -> dict[str, dict[str, Any]]:
    """Vhost bases come from dnsx-resolved names (and apex seeds as fallback)."""
    from pipeline.jsonio import read_json

    out: dict[str, dict[str, Any]] = {}
    path = target_dir / str(params.require("dnsr_data_json"))
    if path.is_file():
        try:
            doc = read_json(path)
        except Exception:
            doc = {}
        for row in (doc or {}).get("resolved") or []:
            if not isinstance(row, dict):
                continue
            fqdn = normalize_fqdn(str(row.get("host") or ""))
            if not fqdn:
                continue
            if row.get("resolution_status") != "resolved" and not row.get("ips"):
                continue
            parent = None
            for seed in seeds:
                if fqdn.endswith("." + seed):
                    parent = seed
                    break
            rec = {
                "fqdn": fqdn,
                "level": 1,
                "parent": parent,
                "alive": row.get("alive"),
                "http_status": row.get("http_status"),
                "length": row.get("length"),
            }
            if row.get("tech"):
                rec["tech"] = row.get("tech")
            if row.get("title"):
                rec["title"] = row.get("title")
            out[fqdn] = rec
    if not out:
        for seed in seeds:
            fqdn = normalize_fqdn(seed) or seed
            out[fqdn] = {
                "fqdn": fqdn,
                "level": 1,
                "parent": None,
                "alive": None,
                "http_status": None,
                "length": None,
            }
    return out


def _probe_alive(
    params: Params,
    adapter: Adapter,
    target_dir: Path,
    target: str,
    extra: dict[str, Any],
    planned: int,
    timeout_sec: float | None,
    hosts: list[dict[str, Any]],
) -> None:
    if not hosts:
        return
    pending = [row for row in hosts if row.get("alive") is None]
    if not pending:
        return
    by_host = httpx_probe.probe_hosts(
        params,
        adapter,
        target_dir,
        target,
        extra,
        planned,
        timeout_sec,
        [row["fqdn"] for row in pending],
        str(params.require("ffuf_httpx_list_rel")),
        str(params.require("ffuf_httpx_out_rel")),
        "ffuf",
        "logs/raw/httpx-ffuf",
    )
    if not by_host and not adapter.enabled("httpx"):
        return
    for row in pending:
        httpx_probe.apply_enrich(row, by_host.get(row["fqdn"]), miss_alive=True)


def _labels_in(path: Path) -> set[str]:
    out: set[str] = set()
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        label = normalize_label(raw)
        if label:
            out.add(label)
    return out


def _safe(name: str) -> str:
    return name.replace(":", "_").replace("/", "_").replace("*", "star")
