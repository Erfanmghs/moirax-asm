"""DNS-RESOLVE: DNSR-1 brute, DNSR-2 alterx, DNSR-3 resolve-all + LOAD BALANCE."""

from __future__ import annotations

import secrets
from pathlib import Path
from typing import Any

from pipeline.adapter import Adapter
from pipeline.hostsutil import container_path, normalize_fqdn, wildcard_seeds
from pipeline.jsonio import read_json, write_json
from pipeline.load_balance import LoadBalancer, write_sentinel_file
from pipeline.ndjson import load_json_file, parse_json_payload
from pipeline.params import Params
from pipeline.resolver_forge import forge_resolvers
from pipeline.scope import ScopeGate
from pipeline.textio import atomic_write_text, read_lines
from pipeline.wordlist_forge import copy_into_target, materialize_effective
from pipeline import httpx_probe


def _unlink_stale(path: Path) -> None:
    """TEST 3 (T3-1, authorized live-tree freshness fix; disclosed in PHASE-REPORT).

    dnsx/alterx `-o` APPEND to an existing output file, so an output left in the
    live tree by a previous run era (e.g. brute_chunk_0.json carrying 4860
    unique hosts from the dns_fast_top5000 era while the current selection
    yields 200 candidates) would be re-read by _rows_from() and pollute this
    run's resolved map with stale-era rows. Remove the file before the tool
    writes, so every output contains ONLY this run's rows.
    """
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    except IsADirectoryError:
        pass


def run_dns_resolve(
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
    resolvers_host = forge_resolvers(params, adapter, target_dir, target)
    healthy_n = sum(1 for line in read_lines(resolvers_host) if line.strip())
    min_healthy = int(params.require("resolver_min_healthy_count"))
    if healthy_n < min_healthy:
        partial.append(f"resolver_min_healthy_count:{healthy_n}")
    resolvers_c = container_path(params, target, str(params.require("resolver_target_copy")))

    sentinels = [str(x).strip() for x in params.require("canary_sentinel_hosts")]
    sent_rel = str(params.require("dnsx_canary_list_rel"))
    write_sentinel_file(target_dir / sent_rel, sentinels)
    extra_lb = dict(extra)
    extra_lb["dnsx_canary_hosts"] = container_path(params, target, sent_rel)
    extra_lb["dnsx_resolvers"] = resolvers_c
    balancer = LoadBalancer(params, adapter, target_dir, target, clock=adapter.clock, module="dns-resolve")
    if not balancer.tick(resolvers_c, "logs/raw/dnsx-canary", extra_lb):
        partial.append("load_balance_canary_pause")

    brute_src = materialize_effective(params, "DNSR-1")
    brute_rel = str(params.require("dnsr_brute_wordlist_rel"))
    copy_into_target(params, target_dir, brute_src, brute_rel)
    brute_lines = [line.strip() for line in read_lines(target_dir / brute_rel) if line.strip()]

    known = _ffuf_hosts(params, target_dir) + _passive_hosts(params, target_dir) + _prior_asset_hosts(params, target_dir)
    seeds = wildcard_seeds(gate, target)
    apex = seeds[0] if seeds else target

    resolved: dict[str, dict[str, Any]] = {}
    brute_valid = 0
    perm_candidates = 0

    chunk = int(params.require("dnsx_chunk_size"))
    for i in range(0, len(brute_lines), chunk):
        if not balancer.tick(resolvers_c, "logs/raw/dnsx-canary", extra_lb):
            partial.append("load_balance_canary_pause")
            break
        part = brute_lines[i : i + chunk]
        rel = f"20_dns/dnsx/brute_chunk_{i}.txt"
        atomic_write_text(target_dir / rel, "\n".join(part) + "\n")
        out_rel = f"20_dns/dnsx/brute_chunk_{i}.json"
        rows = _dnsx_run(
            params,
            adapter,
            target_dir,
            target,
            extra,
            planned,
            timeout_sec,
            balancer,
            {
                "target_domain": apex,
                "dnsx_wordlist": container_path(params, target, rel),
                "dnsx_resolvers": resolvers_c,
                "dnsx_max_qps": balancer.current_qps(),
                "dnsx_output": container_path(params, target, out_rel),
                "output_raw_dir": f"logs/raw/dnsx/brute_{i}",
                "skip_parse": True,
            },
            tool="dnsx",
            out_path=target_dir / out_rel,
            brute_rel=rel,
            apex=apex,
        )
        for rec in rows:
            host = normalize_fqdn(str(rec.get("host") or ""))
            if not host or not gate.enforce(target_dir, host):
                continue
            brute_valid += 1
            _merge_resolved(resolved, rec, host, "brute")

    # DNSR-2 AGGREGATE CAP + SUSPECT-NAME EXCLUSION (spec v1.9, approved
    # Option-1 item 3): the wildcard probe is hoisted BEFORE the perm pass so
    # wildcard-suspect and misconfig_suspect-flagged names can be EXCLUDED
    # from the alterx seed input -- suspect-name mutations must never amplify
    # a wildcard/misconfig artifact. The same wildcard_ip classifies the
    # DNSR-3 phase below (one probe per run, as before).
    wildcard_ip = None
    if balancer.tick(resolvers_c, "logs/raw/dnsx-canary", extra_lb):
        wildcard_ip = _wildcard_ip(
            params, adapter, target_dir, target, extra, planned, timeout_sec, balancer, resolvers_c, apex
        )
    else:
        partial.append("load_balance_canary_pause")
    flagged = _misconfig_flagged(params, target_dir)
    # Permute DNS-validated names (brute hits + any earlier ffuf/passive
    # artifacts), not HTTP-fuzz noise. Empty ffuf is expected when dnsx runs first.
    perm_seed = sorted(set(known) | set(resolved.keys()) | set(seeds))
    wildcard_seed_suspects = _wildcard_ip_members(perm_seed, resolved, wildcard_ip)
    perm_hosts, seed_counts = _filter_seeds(perm_seed, flagged, wildcard_seed_suspects)
    dropped_aggregate = 0
    if perm_hosts:
        if not balancer.tick(resolvers_c, "logs/raw/dnsx-canary", extra_lb):
            partial.append("load_balance_canary_pause")
        else:
            in_rel = str(params.require("alterx_input_rel"))
            out_rel = str(params.require("alterx_output_rel"))
            atomic_write_text(target_dir / in_rel, "\n".join(perm_hosts) + "\n")
            _unlink_stale(target_dir / out_rel)  # TEST 3 T3-1: alterx -o appends
            adapter.invoke(
                "alterx",
                module="dns-resolve",
                extra={
                    **extra,
                    "alterx_input": container_path(params, target, in_rel),
                    "alterx_output": container_path(params, target, out_rel),
                    "output_raw_dir": "logs/raw/alterx",
                    "skip_parse": True,
                },
                planned_concurrency=planned,
                timeout_sec=timeout_sec,
                allow_fallback=False,
            )
            cap = int(params.require("max_permutations_per_host"))
            aggregate = int(params.require("max_permutations_aggregate"))
            perms, dropped_aggregate = _cap_perms(
                target_dir / out_rel, perm_hosts, cap, gate, target_dir, aggregate
            )
            perm_candidates = len(perms)
            for i in range(0, len(perms), chunk):
                if not balancer.tick(resolvers_c, "logs/raw/dnsx-canary", extra_lb):
                    partial.append("load_balance_canary_pause")
                    break
                part = perms[i : i + chunk]
                rel = f"20_dns/dnsx/perm_chunk_{i}.txt"
                atomic_write_text(target_dir / rel, "\n".join(part) + "\n")
                outp = f"20_dns/dnsx/perm_chunk_{i}.json"
                rows = _dnsx_list(
                    params,
                    adapter,
                    target_dir,
                    target,
                    extra,
                    planned,
                    timeout_sec,
                    balancer,
                    rel,
                    outp,
                    resolvers_c,
                    "perm",
                )
                for rec in rows:
                    host = normalize_fqdn(str(rec.get("host") or rec.get("input") or ""))
                    if not host or not gate.enforce(target_dir, host):
                        continue
                    _merge_resolved(resolved, rec, host, "perm")

    all_hosts = sorted(set(known) | set(resolved.keys()) | {apex})
    list_rel = str(params.require("dnsr_all_hosts_rel"))
    atomic_write_text(target_dir / list_rel, "\n".join(all_hosts) + "\n")
    wildcard_suspects: list[str] = []
    if not balancer.tick(resolvers_c, "logs/raw/dnsx-canary", extra_lb):
        partial.append("load_balance_canary_pause")
        for host in all_hosts:
            row = resolved.setdefault(host, _empty_resolved(host, "known"))
            if not row["ips"]:
                row["resolution_status"] = "unresolved"
                row["resolution_reason"] = "no A/AAAA"
            else:
                row["resolution_status"] = "resolved"
                row["resolution_reason"] = None
    else:
        outp = str(params.require("dnsr_resolve_out_rel"))
        rows = _dnsx_list(
            params,
            adapter,
            target_dir,
            target,
            extra,
            planned,
            timeout_sec,
            balancer,
            list_rel,
            outp,
            resolvers_c,
            "known",
            full_records=True,
        )
        by_host: dict[str, dict[str, Any]] = {}
        for rec in rows:
            host = normalize_fqdn(str(rec.get("host") or rec.get("input") or ""))
            if host:
                by_host[host] = rec
        suspects: list[str] = []
        for host in all_hosts:
            rec = by_host.get(host)
            source = (resolved.get(host) or {}).get("source") or "known"
            if rec:
                _merge_resolved(resolved, rec, host, source)
            row = resolved.setdefault(host, _empty_resolved(host, source))
            if not row["ips"]:
                row["resolution_status"] = "unresolved"
                row["resolution_reason"] = "no A/AAAA"
            else:
                row["resolution_status"] = "resolved"
                row["resolution_reason"] = None
            if wildcard_ip and wildcard_ip in row["ips"]:
                suspects.append(host)
        wildcard_suspects = sorted(set(suspects))

    _httpx_enrich_resolved(
        params, adapter, target_dir, target, extra, planned, timeout_sec, resolved
    )
    valid = sum(1 for row in resolved.values() if row.get("resolution_status") == "resolved")
    payload = {
        "schema_version": int(params.require("schema_version")),
        "module": "dns-resolve",
        "resolved": sorted(resolved.values(), key=lambda r: r["host"]),
        "candidates": {"brute": len(brute_lines), "perms": perm_candidates, "valid": valid},
        "wildcard_suspects": wildcard_suspects,
    }
    write_json(target_dir / str(params.require("dnsr_data_json")), payload)
    summary = target_dir / str(params.require("dnsr_summary"))
    summary.parent.mkdir(parents=True, exist_ok=True)
    summary.write_text(
        "\n".join(
            [
                "# dns-resolve",
                "",
                f"healthy_resolvers: {healthy_n}",
                f"candidates: {payload['candidates']}",
                f"resolved_rows: {len(payload['resolved'])}",
                f"wildcard_suspects: {len(wildcard_suspects)}",
                f"alterx_seeds: {seed_counts}",
                f"aggregate_cap_dropped: {dropped_aggregate}",
                f"load_balance_qps: {balancer.current_qps()}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return payload


def _dnsx_run(
    params: Params,
    adapter: Adapter,
    target_dir: Path,
    target: str,
    extra: dict[str, Any],
    planned: int,
    timeout_sec: float | None,
    balancer: LoadBalancer,
    local: dict[str, Any],
    tool: str,
    out_path: Path,
    brute_rel: str,
    apex: str,
) -> list[dict[str, Any]]:
    merged = dict(extra)
    merged.update(local)
    _unlink_stale(out_path)  # TEST 3 T3-1: dnsx -o appends
    result = adapter.invoke(
        tool,
        module="dns-resolve",
        extra=merged,
        planned_concurrency=planned,
        timeout_sec=timeout_sec,
        allow_fallback=False,
    )
    rows = _rows_from(out_path, result.stdout)
    if result.exit_code != 0 and not rows:
        rows = _massdns_brute(params, adapter, target_dir, target, extra, planned, timeout_sec, brute_rel, apex, local)
    return rows


def _dnsx_list(
    params: Params,
    adapter: Adapter,
    target_dir: Path,
    target: str,
    extra: dict[str, Any],
    planned: int,
    timeout_sec: float | None,
    balancer: LoadBalancer,
    hosts_rel: str,
    out_rel: str,
    resolvers_c: str,
    source: str,
    full_records: bool = False,
) -> list[dict[str, Any]]:
    tool = "dnsx-resolve" if full_records else "dnsx-list"
    extra_l = {
        **extra,
        "dnsx_hosts": container_path(params, target, hosts_rel),
        "dnsx_resolvers": resolvers_c,
        "dnsx_max_qps": balancer.current_qps(),
        "dnsx_output": container_path(params, target, out_rel),
        "output_raw_dir": f"logs/raw/{tool}/{source}",
        "skip_parse": True,
    }
    _unlink_stale(target_dir / out_rel)  # TEST 3 T3-1: dnsx -o appends
    result = adapter.invoke(
        tool,
        module="dns-resolve",
        extra=extra_l,
        planned_concurrency=planned,
        timeout_sec=timeout_sec,
        allow_fallback=False,
    )
    rows = _rows_from(target_dir / out_rel, result.stdout)
    if result.exit_code != 0 and not rows:
        rows = _massdns_list(params, adapter, target_dir, target, extra, planned, timeout_sec, hosts_rel, resolvers_c, out_rel)
    return rows


def _massdns_brute(
    params: Params,
    adapter: Adapter,
    target_dir: Path,
    target: str,
    extra: dict[str, Any],
    planned: int,
    timeout_sec: float | None,
    brute_rel: str,
    apex: str,
    local: dict[str, Any],
) -> list[dict[str, Any]]:
    _unlink_stale(target_dir / brute_rel.replace(".txt", ".json"))  # TEST 3 T3-1
    labels = [line.strip() for line in read_lines(target_dir / brute_rel) if line.strip()]
    q_rel = brute_rel + ".massdns"
    atomic_write_text(target_dir / q_rel, "\n".join(f"{lab}.{apex} A" for lab in labels) + "\n")
    extra_m = {
        **extra,
        "dnsx_wordlist": container_path(params, target, q_rel),
        "dnsx_resolvers": local.get("dnsx_resolvers"),
        "dnsx_max_qps": local.get("dnsx_max_qps") or params.require("dnsx_ramp_start_qps"),
        "massdns_output": local.get("dnsx_output"),
        "output_raw_dir": "logs/raw/massdns/brute",
        "skip_parse": True,
    }
    result = adapter.invoke(
        "massdns",
        module="dns-resolve",
        extra=extra_m,
        planned_concurrency=planned,
        timeout_sec=timeout_sec,
        allow_fallback=False,
    )
    host_out = target_dir / brute_rel.replace(".txt", ".json")
    return _massdns_rows(host_out, result.stdout)


def _massdns_list(
    params: Params,
    adapter: Adapter,
    target_dir: Path,
    target: str,
    extra: dict[str, Any],
    planned: int,
    timeout_sec: float | None,
    hosts_rel: str,
    resolvers_c: str,
    out_rel: str,
) -> list[dict[str, Any]]:
    _unlink_stale(target_dir / out_rel)  # TEST 3 T3-1
    hosts = [line.strip() for line in read_lines(target_dir / hosts_rel) if line.strip()]
    q_rel = hosts_rel + ".massdns"
    atomic_write_text(target_dir / q_rel, "\n".join(f"{h} A" for h in hosts) + "\n")
    extra_m = {
        **extra,
        "dnsx_wordlist": container_path(params, target, q_rel),
        "dnsx_resolvers": resolvers_c,
        "dnsx_max_qps": extra.get("dnsx_max_qps") or params.require("dnsx_ramp_start_qps"),
        "massdns_output": container_path(params, target, out_rel),
        "output_raw_dir": "logs/raw/massdns",
        "skip_parse": True,
    }
    result = adapter.invoke(
        "massdns",
        module="dns-resolve",
        extra=extra_m,
        planned_concurrency=planned,
        timeout_sec=timeout_sec,
        allow_fallback=False,
    )
    return _massdns_rows(target_dir / out_rel, result.stdout)


def _wildcard_ip(
    params: Params,
    adapter: Adapter,
    target_dir: Path,
    target: str,
    extra: dict[str, Any],
    planned: int,
    timeout_sec: float | None,
    balancer: LoadBalancer,
    resolvers_c: str,
    apex: str,
) -> str | None:
    nonce = "wl" + secrets.token_hex(8)
    host = f"{nonce}.{apex}"
    rel = str(params.require("dnsr_wildcard_list_rel"))
    atomic_write_text(target_dir / rel, host + "\n")
    rows = _dnsx_list(
        params,
        adapter,
        target_dir,
        target,
        extra,
        planned,
        timeout_sec,
        balancer,
        rel,
        str(params.require("dnsr_wildcard_out_rel")),
        resolvers_c,
        "wildcard",
        full_records=False,
    )
    for rec in rows:
        ips = _ips_from_dnsx(rec)
        if ips:
            return ips[0]
    return None


def _cap_perms(
    path: Path,
    parents: list[str],
    cap: int,
    gate: ScopeGate,
    target_dir: Path,
    aggregate: int = 0,
) -> tuple[list[str], int]:
    """Per-host cap first; then the v1.9 DNSR-2 AGGREGATE cap.

    Returns (capped_lines, dropped_aggregate). The aggregate cap bounds the
    TOTAL perm candidate set per target per run, enforced AFTER the per-host
    caps (spec v1.9, approved Option-1 item 3).
    """
    lines = [normalize_fqdn(x) for x in read_lines(path)]
    lines = [h for h in lines if h]
    per_host: dict[str, int] = {p: 0 for p in parents}
    out: list[str] = []
    seen: set[str] = set()
    for host in lines:
        if host in seen:
            continue
        if not gate.enforce(target_dir, host):
            continue
        parent = next((p for p in parents if host.endswith("." + p) or host == p), None)
        key = parent or "_other"
        per_host.setdefault(key, 0)
        if per_host[key] >= cap:
            continue
        per_host[key] += 1
        seen.add(host)
        out.append(host)
    dropped_aggregate = 0
    if aggregate and len(out) > aggregate:
        dropped_aggregate = len(out) - aggregate
        out = out[:aggregate]
    if path.is_file():
        atomic_write_text(path, "\n".join(out) + "\n")
    return out, dropped_aggregate


def _misconfig_flagged(params: Params, target_dir: Path) -> set[str]:
    """DNSR-2 (v1.9 item 3): misconfig_suspect-flagged names are excluded from
    the alterx seed input -- suspect-name mutations must never amplify a
    wildcard/misconfig artifact."""
    doc = _read_doc(target_dir / str(params.require("ffuf_data_json")))
    if not doc:
        return set()
    out: set[str] = set()
    for row in doc.get("vhosts") or []:
        if not isinstance(row, dict):
            continue
        if row.get("misconfig_suspect") is True and row.get("vhost"):
            out.add(str(row["vhost"]).strip().lower().rstrip("."))
    return out


def _wildcard_ip_members(
    hosts: list[str],
    resolved: dict[str, dict[str, Any]],
    wildcard_ip: str | None,
) -> list[str]:
    """Wildcard-suspect seeds visible at DNSR-2 time: known hosts whose
    resolved-so-far row carries the wildcard IP."""
    if not wildcard_ip:
        return []
    return [
        host
        for host in hosts
        if wildcard_ip in ((resolved.get(host) or {}).get("ips") or [])
    ]


def _filter_seeds(
    known: list[str],
    flagged: set[str],
    wildcard_suspects: list[str],
) -> tuple[list[str], dict[str, int]]:
    seeds = sorted(set(known) - set(flagged) - set(wildcard_suspects))
    counts = {
        "seeds_before": len(known),
        "seeds_after": len(seeds),
        "excluded_misconfig_flagged": len(set(known) & set(flagged)),
        "excluded_wildcard_suspect": len(set(known) & set(wildcard_suspects)),
    }
    return seeds, counts


def _read_doc(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        return read_json(path)
    except Exception:
        return None


def _httpx_enrich_resolved(
    params: Params,
    adapter: Adapter,
    target_dir: Path,
    target: str,
    extra: dict[str, Any],
    planned: int,
    timeout_sec: float | None,
    resolved: dict[str, dict[str, Any]],
) -> None:
    """When httpx is ENABLED, tag resolved names with length + technology."""
    for row in resolved.values():
        row.setdefault("alive", None)
        row.setdefault("http_status", None)
        row.setdefault("length", None)
        row.setdefault("tech", [])
        row.setdefault("title", None)
    if not bool(params.require("dnsr_httpx_probe")):
        return
    if not adapter.enabled("httpx"):
        return
    names = [
        host
        for host, row in resolved.items()
        if row.get("resolution_status") == "resolved" and row.get("ips")
    ]
    if not names:
        return
    by_host = httpx_probe.probe_hosts(
        params,
        adapter,
        target_dir,
        target,
        extra,
        planned,
        timeout_sec,
        names,
        str(params.require("dnsr_httpx_list_rel")),
        str(params.require("dnsr_httpx_out_rel")),
        "dns-resolve",
        "logs/raw/httpx-dnsr",
    )
    for host in names:
        row = resolved.get(host)
        if row is None:
            continue
        httpx_probe.apply_enrich(row, by_host.get(host), miss_alive=True)


def _prior_asset_hosts(params: Params, target_dir: Path) -> list[str]:
    """Always re-check FQDNs already proven on this target (no disable switch)."""
    path = target_dir / str(params.require("assets_relpath"))
    doc = _read_doc(path)
    if not doc:
        return []
    found: list[str] = []
    for row in doc.get("assets") or []:
        if not isinstance(row, dict):
            continue
        host = str(row.get("host") or "").strip().lower()
        if host:
            found.append(host)
    return found


def _passive_hosts(params: Params, target_dir: Path) -> list[str]:
    """Use passive candidates as alterx seeds when that branch already wrote data."""
    path = target_dir / str(params.require("passive_data_json"))
    doc = _read_doc(path)
    if not doc:
        return []
    found: list[str] = []
    for row in doc.get("candidates") or []:
        if isinstance(row, dict) and row.get("host"):
            found.append(str(row["host"]).lower())
    return found


def _ffuf_hosts(params: Params, target_dir: Path) -> list[str]:
    path = target_dir / str(params.require("ffuf_data_json"))
    if not path.is_file():
        return []
    doc = read_json(path)
    found: list[str] = []
    for row in doc.get("hosts") or []:
        if isinstance(row, dict) and row.get("fqdn"):
            found.append(str(row["fqdn"]).lower())
    for row in doc.get("vhosts") or []:
        if isinstance(row, dict) and row.get("vhost"):
            found.append(str(row["vhost"]).lower())
    return found


def _rows_from(path: Path, stdout: str) -> list[dict[str, Any]]:
    payload = load_json_file(path)
    if payload is None:
        payload = parse_json_payload(stdout)
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if isinstance(payload, dict):
        if "host" in payload or "a" in payload:
            return [payload]
        inner = payload.get("results") or payload.get("data")
        if isinstance(inner, list):
            return [row for row in inner if isinstance(row, dict)]
    return []


def _massdns_rows(path: Path, stdout: str) -> list[dict[str, Any]]:
    payload = load_json_file(path)
    if payload is None:
        payload = parse_json_payload(stdout)
    rows = payload if isinstance(payload, list) else ([payload] if isinstance(payload, dict) else [])
    out: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = str(row.get("name") or row.get("host") or "").rstrip(".").lower()
        ips: list[str] = []
        data = row.get("data")
        if isinstance(data, dict):
            answers = data.get("answers") or []
            if isinstance(answers, list):
                for ans in answers:
                    if isinstance(ans, dict) and str(ans.get("type") or "").upper() == "A":
                        val = ans.get("data")
                        if val:
                            ips.append(str(val))
        if name:
            out.append({"host": name, "a": ips})
    return out


def _ips_from_dnsx(rec: dict[str, Any]) -> list[str]:
    ips: list[str] = []
    for key in ("a", "aaaa", "ip", "ips"):
        val = rec.get(key)
        if isinstance(val, list):
            for item in val:
                if isinstance(item, str):
                    ips.append(item)
                elif isinstance(item, dict) and item.get("ip"):
                    ips.append(str(item["ip"]))
        elif isinstance(val, str):
            ips.append(val)
    seen: set[str] = set()
    uniq: list[str] = []
    for ip in ips:
        if ip and ip not in seen:
            seen.add(ip)
            uniq.append(ip)
    return uniq


def _as_list(val: Any) -> list[str]:
    if val is None:
        return []
    if isinstance(val, list):
        out: list[str] = []
        for item in val:
            if isinstance(item, str):
                out.append(item)
            elif isinstance(item, dict):
                for k in ("name", "mx", "ns", "txt", "cname"):
                    if item.get(k):
                        out.append(str(item[k]))
                        break
        return out
    if isinstance(val, str):
        return [val]
    return []


def _asn_of(rec: dict[str, Any]) -> Any:
    val = rec.get("asn")
    if isinstance(val, list) and val:
        first = val[0]
        if isinstance(first, dict):
            return first.get("asn") or first.get("as_number")
        return first
    if isinstance(val, dict):
        return val.get("asn")
    return val


def _empty_resolved(host: str, source: str) -> dict[str, Any]:
    row = {
        "host": host,
        "ips": [],
        "cname": [],
        "mx": [],
        "ns": [],
        "txt": [],
        "asn": None,
        "source": source if source in ("brute", "perm", "known") else "known",
        "resolution_status": "unresolved",
        "resolution_reason": "not queried",
    }
    row.update(httpx_probe.empty_http_fields())
    return row


def _merge_resolved(store: dict[str, dict[str, Any]], rec: dict[str, Any], host: str, source: str) -> None:
    row = store.get(host) or _empty_resolved(host, source)
    if source in ("brute", "perm", "known"):
        if row.get("source") == "known" and source != "known":
            row["source"] = source
        elif row.get("source") not in ("brute", "perm"):
            row["source"] = source
    ips = _ips_from_dnsx(rec)
    for ip in ips:
        if ip not in row["ips"]:
            row["ips"].append(ip)
    for field, key in (("cname", "cname"), ("mx", "mx"), ("ns", "ns"), ("txt", "txt")):
        for item in _as_list(rec.get(key)):
            if item not in row[field]:
                row[field].append(item)
    asn = _asn_of(rec)
    if asn is not None:
        row["asn"] = asn
    if row["ips"]:
        row["resolution_status"] = "resolved"
        row["resolution_reason"] = None
    store[host] = row
