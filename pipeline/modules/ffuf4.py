"""FFUF-4 -- vhost enum on HTTP-like ports found by PORT-SWEEP.

Early FFUF-2 only hits default HTTP on the hostname. After the full port
sweep, extra listeners (8080, 8443, 3000, ...) often serve different Host
headers. This pass binds ffuf to ip:port (the real socket). Host headers follow
ffuf_depth: depth 1 is Host: FUZZ.<apex>; depth 2 also uses each
one-label name attributed to that IP (Host: FUZZ.api.apex).

Runs post-MERGE, after PORT-SWEEP, before OWASP-PASSIVE. Not a branch member.
Host-header parents follow ffuf_depth (independent of nested DNS recon_depth).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pipeline.adapter import Adapter
from pipeline.hostsutil import container_path, normalize_fqdn, wildcard_seeds
from pipeline.jsonio import read_json, write_json
from pipeline.merge import append_active_doc
from pipeline.modules.ffuf import _ffuf_hits, _safe, _wordlist_fuzz_label
from pipeline.params import Params
from pipeline.scope import ScopeGate
from pipeline.recon_depth import clamp_ffuf_depth, vhost_bases
from pipeline.wordlist_forge import copy_into_target, materialize_effective

_HTTP_HINTS = ("http", "https", "ssl/http", "http-proxy", "http-alt")


def run_ffuf4(
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
    skipped: str | None = None
    if not adapter.enabled("ffuf-vhost"):
        skipped = "ffuf-vhost disabled"
        _note(params, target_dir, "ffuf-4 skipped: ffuf-vhost switch is OFF")
        return _write(params, target_dir, [], [], 0, skipped, partial)

    jobs = http_vhost_jobs(params, target_dir, target)
    try:
        cap = int(params.require("ffuf4_max_jobs"))
    except (TypeError, ValueError):
        cap = 0
    if cap < 0:
        cap = 0
    if not jobs:
        skipped = "no_http_ports"
        _note(params, target_dir, "ffuf-4 skipped: no HTTP-like open ports after PORT-SWEEP")
        return _write(params, target_dir, [], [], 0, skipped, partial)

    vhost_src = materialize_effective(params, "FFUF-2")
    v_rel = str(params.require("ffuf_vhost_wordlist_rel"))
    copy_into_target(params, target_dir, vhost_src, v_rel)
    v_c = container_path(params, target, v_rel)
    allowed = _labels_in(vhost_src)
    v_n = len(allowed)
    max_req = int(params.require("max_total_requests"))
    request_count = 0
    vhosts: list[dict[str, Any]] = []
    suppressed = 0
    apex = target
    try:
        apex = (wildcard_seeds(gate, target) or [target])[0]
    except Exception:  # noqa: BLE001 -- tests and odd gates still probe the run target
        apex = target
    apex = normalize_fqdn(apex) or target

    _note(params, target_dir, f"ffuf-4 listeners={len(jobs)} apex={apex} wordlist={v_n}")

    depth = clamp_ffuf_depth(params)
    expanded: list[dict[str, Any]] = []
    for job in jobs:
        for base in vhost_bases(apex, job.get("hosts") or [], depth):
            expanded.append({**job, "base": base})
    if cap and len(expanded) > cap:
        partial.append("ffuf4_job_cap")
        _note(params, target_dir, f"ffuf-4 job cap: {len(expanded)} > ffuf4_max_jobs={cap}; probing first {cap}")
        expanded = expanded[:cap]

    for job in expanded:
        if request_count + v_n > max_req:
            partial.append("max_total_requests")
            _note(params, target_dir, "ffuf-4 stopped: max_total_requests")
            break
        ip = job["ip"]
        port = int(job["port"])
        scheme = job["scheme"]
        base = str(job.get("base") or apex)
        url = f"{scheme}://{_hostport(ip, port)}"
        out_rel = f"15_vhosts/ffuf-4/{scheme}_{_safe(ip)}_{port}_{_safe(base)}.json"
        result = adapter.invoke(
            "ffuf-vhost",
            module="ffuf-4",
            extra={
                **extra,
                "ffuf_url": url,
                "ffuf_wordlist": v_c,
                "ffuf_output": container_path(params, target, out_rel),
                "ffuf_host_header": f"Host: FUZZ.{base}",
                "output_raw_dir": f"logs/raw/ffuf-4/{scheme}_{_safe(ip)}_{port}_{_safe(base)}",
                "skip_parse": True,
                "ffuf_mode": "vhost",
            },
            planned_concurrency=planned,
            timeout_sec=timeout_sec,
            allow_fallback=False,
        )
        request_count += v_n
        attributed = {normalize_fqdn(h) or h for h in (job.get("hosts") or [])}
        for hit in _ffuf_hits(target_dir / out_rel, result):
            label = _wordlist_fuzz_label(hit, base, allowed)
            if not label:
                suppressed += 1
                continue
            vhost = normalize_fqdn(f"{label}.{base}")
            if not vhost:
                continue
            if not gate.enforce(target_dir, vhost):
                continue
            status = hit.get("status")
            length = hit.get("length")
            rec = {
                "base_host": base,
                "vhost": vhost,
                "ip": ip,
                "port": port,
                "scheme": scheme,
                "alive": status is not None,
                "http_status": status,
                "length": length,
                "misconfig_suspect": vhost not in attributed,
                "ips": [ip],
            }
            vhosts.append(rec)

    payload = _write(params, target_dir, vhosts, jobs, suppressed, None, partial)
    try:
        append_active_doc(params, gate, target_dir, target, payload)
    except Exception as exc:  # noqa: BLE001 -- promotion never fails the pass
        _note(params, target_dir, f"ffuf-4 asset promote failed (disclosed): {exc}")
    return payload


def http_vhost_jobs(params: Params, target_dir: Path, target: str) -> list[dict[str, Any]]:
    """Unique ip+port+scheme jobs from PORT-SWEEP (and optional PORT-CHECK)."""
    del target  # reserved: per-apex job filters if a future pass needs them
    http_ports = _port_set(params, "vhost_http_ports")
    https_ports = _port_set(params, "vhost_https_ports")
    jobs: list[dict[str, Any]] = []
    seen: set[tuple[str, int, str]] = set()

    def _add(ip: str, port: int, scheme: str, hosts: list[str]) -> None:
        key = (ip, port, scheme)
        if key in seen:
            return
        seen.add(key)
        jobs.append({"ip": ip, "port": port, "scheme": scheme, "hosts": list(hosts)})

    for ip, hosts, ports, services in _scan_rows(params, target_dir):
        open_ports = {int(p["port"]) for p in ports if isinstance(p, dict) and p.get("port") is not None}
        hinted = _service_http_ports(services, ip)
        for port in sorted(open_ports):
            if port in https_ports or port in hinted.get("https", set()):
                _add(ip, port, "https", hosts)
            elif port in http_ports or port in hinted.get("http", set()):
                _add(ip, port, "http", hosts)
    jobs.sort(key=lambda j: (j["ip"], j["port"], j["scheme"]))
    return jobs


def _scan_rows(
    params: Params, target_dir: Path
) -> list[tuple[str, list[str], list[dict[str, Any]], list[dict[str, Any]]]]:
    out: list[tuple[str, list[str], list[dict[str, Any]], list[dict[str, Any]]]] = []
    sweep = _load(target_dir / str(params.require("portsweep_data_json")))
    services = (sweep or {}).get("services") or []
    by_ip_svc: dict[str, list[dict[str, Any]]] = {}
    for row in services:
        if isinstance(row, dict) and row.get("ip"):
            by_ip_svc.setdefault(str(row["ip"]), []).append(row)
    for row in (sweep or {}).get("scans") or []:
        if not isinstance(row, dict) or not row.get("ip"):
            continue
        ip = str(row["ip"])
        hosts = [str(h) for h in (row.get("hosts") or []) if h]
        ports = [p for p in (row.get("ports") or []) if isinstance(p, dict)]
        out.append((ip, hosts, ports, by_ip_svc.get(ip) or []))
    if out:
        return out
    check = _load(target_dir / str(params.require("portcheck_data_json")))
    for row in (check or {}).get("results") or []:
        if not isinstance(row, dict) or not row.get("ip"):
            continue
        ip = str(row["ip"])
        hosts = [str(h) for h in (row.get("hosts") or []) if h]
        ports = [p for p in (row.get("ports") or []) if isinstance(p, dict)]
        out.append((ip, hosts, ports, []))
    return out


def _service_http_ports(services: list[dict[str, Any]], ip: str) -> dict[str, set[int]]:
    hinted = {"http": set(), "https": set()}
    for row in services:
        if not isinstance(row, dict):
            continue
        if str(row.get("ip") or "") != ip:
            continue
        port = row.get("port")
        if port is None:
            continue
        blob = " ".join(
            str(row.get(k) or "") for k in ("service", "product", "name", "tunnel", "proto")
        ).lower()
        if not any(h in blob for h in _HTTP_HINTS):
            continue
        if "https" in blob or "ssl" in blob or "tls" in blob:
            hinted["https"].add(int(port))
        else:
            hinted["http"].add(int(port))
    return hinted


def _hostport(ip: str, port: int) -> str:
    if ":" in ip and not ip.startswith("["):
        return f"[{ip}]:{port}"
    return f"{ip}:{port}"


def _port_set(params: Params, key: str) -> set[int]:
    raw = str(params.require(key) or "")
    out: set[int] = set()
    for part in raw.split(","):
        part = part.strip()
        if part.isdigit():
            out.add(int(part))
    return out


def _write(
    params: Params,
    target_dir: Path,
    vhosts: list[dict[str, Any]],
    jobs: list[dict[str, Any]],
    suppressed: int,
    skipped: str | None,
    partial: list[str],
) -> dict[str, Any]:
    payload = {
        "schema_version": int(params.require("schema_version")),
        "module": "ffuf-4",
        "vhosts": vhosts,
        "targets": [
            {"ip": j["ip"], "port": j["port"], "scheme": j["scheme"], "hosts": j.get("hosts") or []}
            for j in jobs
        ],
        "suppressed": suppressed,
        "skipped": skipped,
    }
    path = target_dir / str(params.require("ffuf4_data_json"))
    path.parent.mkdir(parents=True, exist_ok=True)
    write_json(path, payload)
    summary = target_dir / str(params.require("ffuf4_summary"))
    summary.parent.mkdir(parents=True, exist_ok=True)
    summary.write_text(
        "\n".join(
            [
                "# ffuf-4 (vhost on discovered HTTP ports)",
                "",
                f"jobs: {len(jobs)}",
                f"vhosts: {len(vhosts)}",
                f"suppressed: {suppressed}",
                f"skipped: {skipped or 'none'}",
                f"partial: {', '.join(partial) if partial else 'none'}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return payload


def _load(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        data = read_json(path)
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def _labels_in(path: Path) -> set[str]:
    from pipeline.hostsutil import normalize_label

    out: set[str] = set()
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        label = normalize_label(raw)
        if label:
            out.add(label)
    return out


def _note(params: Params, target_dir: Path, detail: str) -> None:
    from datetime import datetime, timezone

    path = target_dir / str(params.require("run_log"))
    path.parent.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with path.open("a", encoding="utf-8") as handle:
        handle.write(f"{stamp}\tffuf-4\t-\t0\tok\t{detail}\n")
