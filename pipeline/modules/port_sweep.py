"""PORT-SWEEP -- post-MERGE full-range scan (ACTIVE order 4, master spec section 8).

Order-4 stage consuming assets.json AFTER MERGE (the light top-N PORT-CHECK
stays as order-3 early signal -- both coexist). Hard guarantees implemented
here, exactly as frozen in the master spec:

- INPUT FILTER: hosts with alive=true (PSV-6 / FFUF-2 probes); when the probe
  toggle is off, portsweep_scope alive_only|all_resolved decides the set.
- RULE 1 -- POST-MERGE RESOLUTION GUARANTEE: hosts lacking a resolved IP are
  batch-resolved in ONE dnsx pass (same forged-resolver registry; breaker +
  ceiling apply) BEFORE the IP map is built; still-unresolvable hosts carry
  explicit resolution_status=unresolved + reason and are EXCLUDED with an
  explicit log line -- an IP is never silently missing.
- RULE 2 -- IP DEDUP: each UNIQUE IP is scanned EXACTLY ONCE per run; results
  are attributed back to EVERY hostname sharing it; duplicates logged+skipped.
- RULE 3 -- EXPLICIT TARGET SET: the exact server list is materialized and
  logged (per unique IP: attributed hostnames + discovery sources) BEFORE any
  scan command -- the target set is never implicit.
- PACING: portsweep_duration_hours (default 24, min 1) budget -> effective
  pps = unique_ips x ports_total / (duration x 3600), capped by the profile
  rate cap. Window breach -> PARTIAL + remaining-IP list, never silent.
  Scheduled runs never overlap: a previous sweep still inside its window ->
  skipped: previous_in_progress (diffs use the last completed sweep).
- PROFILES: light (top-N = PORT-CHECK behavior) | full (all ports, default
  cap 1000 pps) | custom (dashboard port-range + rate) -- a thin config layer
  over the adapter, never a new tool.
- FILTERING INTELLIGENCE: known-ALIVE host with ZERO open ports after a full
  sweep -> filtered_suspect + ONE slower re-probe (rate / divisor); > 1000
  open ports -> anomalous_open_suspect (tarpit/honeypot class, never alert-
  spammed).
- SECOND STAGE: nmap -Pn -sV over PORT-SWEEP's open ports ONLY (toggle
  portsweep_nmap_sv, default ON). -Pn skips ICMP host discovery so
  firewalled IPs are still fingerprinted. Toggle only; the VA module
  itself is on the DO-NOT-BUILD list.

Per-IP atomicity: a crashed IP scan is marked unreachable, never failed, and
never corrupts the other scans (section 4.3).
"""

from __future__ import annotations

import ipaddress
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from pipeline.adapter import Adapter
from pipeline.hostsutil import container_path
from pipeline.jsonio import read_json, write_json
from pipeline.modules.port_check import _ip_scan_verdict
from pipeline.params import Params
from pipeline.port_pace import PortPacer
from pipeline.resolver_forge import forge_resolvers
from pipeline.scope import ScopeGate
from pipeline.textio import atomic_write_text, read_lines

# REM8 alignment (same ruling as port-check/merge): as-frozen IP acceptance
# for exactly these two gate reasons; excluded CIDRs and private ranges stay
# REJECTED -- the safety rails are untouched.
_FULL_RANGE_PORTS = 65535
_MIN_PPS = 1
# Throttle mid-sweep full-JSON flushes; the final write still captures every IP.
_FLUSH_INTERVAL_SEC = 3.0


def run_port_sweep(
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
    profile = str(params.require("portsweep_profile")).strip().lower()
    duration = max(
        float(params.require("portsweep_duration_hours_min")),
        float(params.require("portsweep_duration_hours")),
    )
    budget_sec = duration * 3600.0
    started = adapter.clock.time()
    deadline = started + budget_sec
    oos_rel = str(params.require("out_of_scope_log"))
    skips: list[str] = []

    # ---- no-overlap guard (spec: scheduled sweeps never overlap) -----------
    previous = _latest_previous_sweep(params, target_dir)
    if previous is not None:
        stamp_str, doc = previous
        window_h = float((doc.get("pace") or {}).get("duration_hours") or duration)
        try:
            prev_done = datetime.strptime(stamp_str, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        except ValueError:
            prev_done = None
        if prev_done is not None and (started - prev_done.timestamp()) < window_h * 3600.0:
            skips.append("previous sweep still inside its duration window")
            _log(params, target_dir, f"skipped: previous_in_progress completed_at={stamp_str} window_h={window_h}")
            payload = _payload(
                params,
                scans=[],
                services=[],
                pace={"duration_hours": duration, "effective_pps": 0, "window_breached": False},
                unique_ips_scanned=0,
                duplicates_skipped=0,
                skipped="previous_in_progress",
                completed_at=_stamp_now(),
                remaining_ips=[],
                unreachable=[],
                skipped_no_ip=[],
                guarantee={"hosts": 0, "resolved": 0, "unresolved": []},
                sentinels_used=0,
                skips=skips,
            )
            _write_outputs(params, target_dir, payload, skips)
            return payload
    if previous is not None:
        _log(params, target_dir, f"no-overlap clear: previous sweep {previous[0]} outside its window -- proceeding")

    # ---- input filter -------------------------------------------------------
    assets_path = target_dir / str(params.require("assets_relpath"))
    assets: list[dict[str, Any]] = []
    if assets_path.is_file():
        doc = read_json(assets_path)
        assets = [row for row in (doc.get("assets") or []) if isinstance(row, dict)]
    scope_mode = str(params.require("portsweep_scope")).strip().lower()
    if scope_mode == "alive_only":
        candidates = [a for a in assets if a.get("alive") is True]
    else:
        # all_resolved (default): every merged host -- missing IPs go through
        # the resolution-guarantee pass so coverage is not limited to HTTP-alive.
        candidates = list(assets)
    _log(params, target_dir, f"input assets={len(assets)} scope={scope_mode} candidates={len(candidates)}")

    # ---- IP map (RULE 2) from DNSR-3/PSV-6/PSV-8 attributions --------------
    ip_hosts: dict[str, dict[str, Any]] = {}
    duplicates_skipped = 0
    psv8_ips = _psv8_ips(params, target_dir)
    for asset in candidates:
        host = str(asset.get("host") or "").strip().lower()
        if not host:
            continue
        if not gate.enforce(target_dir, host):
            continue
        sources = ",".join(sorted({str(s) for s in (asset.get("sources") or [])})) or "merge"
        for ip in [str(ip) for ip in (asset.get("ips") or []) if ip]:
            eligible, reject_reason = _ip_scan_verdict(gate, ip)
            if not eligible:
                gate.log_rejection(target_dir / oos_rel, ip, reject_reason or "out of scope")
                continue
            bucket = ip_hosts.setdefault(ip, {"hosts": [], "sources": set()})
            if host in bucket["hosts"]:
                continue
            if bucket["hosts"]:
                duplicates_skipped += 1
            bucket["hosts"].append(host)
            bucket["sources"].update(sources.split(","))
    # PSV-8 passive IPs (stored AS-IS, never hostname-gated): scan-only entries
    for ip in psv8_ips:
        if ip in ip_hosts:
            continue
        eligible, reject_reason = _ip_scan_verdict(gate, ip)
        if not eligible:
            gate.log_rejection(target_dir / oos_rel, ip, reject_reason or "out of scope")
            continue
        ip_hosts[ip] = {"hosts": [], "sources": {"psv8-cidr"}}
        _log(params, target_dir, f"psv8-ip\t{ip} (no hostname attribution -- scan-only entry)")

    # ---- RULE 1: post-MERGE resolution guarantee (ONE batched dnsx pass) ---
    # Three exclusive classes per candidate host:
    #   mapped       -- at least one resolved IP passed the scope gate (scanned)
    #   ip_rejected  -- carries asset IPs but every one was rejected by the gate
    #                  (resolved-but-unscannable; explicit log + ledger entry)
    #   no_ip        -- carries NO ips at all (merge-time unresolved) -> the ONE
    #                  batched dnsx guarantee pass; still-unresolvable hosts get
    #                  explicit resolution_status=unresolved + reason
    mapped_hosts = {h for meta in ip_hosts.values() for h in meta["hosts"]}
    candidate_hosts = sorted(
        {str(a.get("host") or "").strip().lower() for a in candidates} - {""}
    )
    asset_ips = {
        str(a.get("host") or "").strip().lower(): [str(ip) for ip in (a.get("ips") or []) if ip]
        for a in candidates
        if isinstance(a, dict)
    }
    no_ip_hosts = [
        h for h in candidate_hosts if h not in mapped_hosts and not asset_ips.get(h)
    ]
    rejected_ip_hosts = [
        h for h in candidate_hosts if h not in mapped_hosts and asset_ips.get(h)
    ]
    for host in rejected_ip_hosts:
        _log(params, target_dir, f"skip-ip-rejected\t{host}\treason=all resolved IPs rejected by the scope gate (see out_of_scope ledger)")
    unresolved: list[dict[str, Any]] = []
    resolved_now = 0
    if no_ip_hosts:
        resolvers_c, resolver_note = _resolver_fleet(params, adapter, target_dir, target)
        _log(params, target_dir, f"resolution-guarantee fleet={resolver_note}")
        rows = _batch_resolve(params, gate, adapter, target_dir, target, extra, no_ip_hosts, resolvers_c, timeout_sec)
        for host, reason in no_ip_host_reasons(rows, no_ip_hosts):
            unresolved.append({"host": host, "resolution_status": "unresolved", "reason": reason})
            _log(params, target_dir, f"skip-unresolved\t{host}\treason={reason}")
        for host, ips, sources in rows:
            added = False
            for ip in ips:
                eligible, reject_reason = _ip_scan_verdict(gate, ip)
                if not eligible:
                    gate.log_rejection(target_dir / oos_rel, ip, reject_reason or "out of scope")
                    continue
                bucket = ip_hosts.setdefault(ip, {"hosts": [], "sources": set()})
                if host not in bucket["hosts"]:
                    if bucket["hosts"]:
                        duplicates_skipped += 1
                    bucket["hosts"].append(host)
                    bucket["sources"].update(sources)
                    added = True
            if added:
                resolved_now += 1
        _log(params, target_dir, f"resolution-guarantee hosts={len(no_ip_hosts)} resolved={resolved_now} unresolved={len(unresolved)}")
    else:
        _log(params, target_dir, "resolution-guarantee hosts=0 resolved=0 unresolved=0 (every candidate already carries a resolved IP)")

    # ---- RULE 3: explicit target set BEFORE any scan command ---------------
    target_set_rel = str(params.require("portsweep_target_set_rel"))
    lines = [
        f"{ip}\t{','.join(meta['hosts']) if meta['hosts'] else '(no-hostname)'}\t{','.join(sorted(meta['sources']))}"
        for ip, meta in sorted(ip_hosts.items())
    ]
    atomic_write_text(target_dir / target_set_rel, "\n".join(lines) + ("\n" if lines else ""))
    _log(
        params,
        target_dir,
        f"target-set unique_ips={len(ip_hosts)} skipped_no_ip={len(unresolved)} duplicates_skipped={duplicates_skipped} psv8_only={sum(1 for m in ip_hosts.values() if not m['hosts'])}",
    )

    # ---- profile -> ports + cap (thin config layer, never a new tool) ------
    ports_expr, ports_total, cap, tool_name = _profile(params, profile)
    if tool_name is None:
        # never-silent config skip: unknown profile or custom without a range
        skips.append(f"profile={profile} not executable: {ports_expr}")
        partial.append(f"portsweep:profile-unusable:{profile}")
        payload = _payload(
            params,
            scans=[],
            services=[],
            pace={"duration_hours": duration, "effective_pps": 0, "window_breached": False},
            unique_ips_scanned=0,
            duplicates_skipped=duplicates_skipped,
            skipped=f"profile_unusable:{profile}",
            completed_at=_stamp_now(),
            remaining_ips=sorted(ip_hosts),
            unreachable=[],
            skipped_no_ip=[u["host"] for u in unresolved],
            guarantee={"hosts": len(no_ip_hosts), "resolved": resolved_now, "unresolved": unresolved},
            sentinels_used=0,
            skips=skips,
        )
        _write_outputs(params, target_dir, payload, skips)
        return payload

    # ---- pacing (duration-budgeted) ----------------------------------------
    unique_n = len(ip_hosts)
    required_pps = (unique_n * ports_total / budget_sec) if unique_n else 0.0
    effective_pps = max(_MIN_PPS, int(min(required_pps, cap))) if unique_n else 0
    window_breached = bool(unique_n and required_pps > cap)
    pace = {
        "duration_hours": duration,
        "effective_pps": effective_pps,
        "window_breached": window_breached,
        "required_pps": round(required_pps, 4),
        "ports_total": ports_total,
        "profile": profile,
        "rate_cap": cap,
    }
    _log(params, target_dir, f"pace unique_ips={unique_n} ports_total={ports_total} required_pps={required_pps:.4f} effective_pps={effective_pps} cap={cap} window_breached={window_breached}")

    # ---- sentinels + pacer (RAMP + CANARY) ---------------------------------
    sentinels = _mine_sentinels(params, target_dir)
    pacer = PortPacer(params, adapter.breaker, adapter.clock, target_dir, module="port-sweep")

    # ---- scan loop: ONE invocation per unique IP, deadline-aware -----------
    scans: list[dict[str, Any]] = []
    services: list[dict[str, Any]] = []
    unreachable: list[str] = []
    remaining: list[str] = []
    reprobe_divisor = max(1, int(params.require("portsweep_filtered_reprobe_divisor")))
    anomalous_threshold = int(params.require("portsweep_anomalous_open_threshold"))
    paused_by_canary = False
    # Mid-sweep flush is throttled: rewriting the full scan JSON after EVERY IP
    # is O(N^2) bytes on large sweeps and stalls the live dashboard reads. We
    # flush at most once per _FLUSH_INTERVAL_SEC; the authoritative final
    # write_json after the loop still captures every IP (never silent).
    _last_flush = 0.0
    for ip in sorted(ip_hosts):
        if getattr(adapter, "stop_requested", lambda: False)():
            remaining.extend(sorted(set(ip_hosts) - {s["ip"] for s in scans}))
            partial.append("operator_stop")
            _log(params, target_dir, f"operator-stop remaining={len(remaining)}")
            break
        meta = ip_hosts[ip]
        rate = min(pacer.current_pps(cap), effective_pps) if effective_pps else pacer.current_pps(cap)
        est_sec = ports_total / max(1, rate)
        # Deferral only exists when the pace is INFEASIBLE (required > cap):
        # then the sweep runs at cap until the window deadline and the tail is
        # disclosed as the remaining-IP list (PARTIAL, never silent). When the
        # pace is feasible, the formula already fits the whole set inside the
        # window -- deferring there would contradict the pacing contract.
        if window_breached and adapter.clock.time() + est_sec > deadline:
            remaining.append(ip)
            _log(params, target_dir, f"window-defer\t{ip}\test_sec={est_sec:.0f}")
            continue
        if not pacer.tick(sentinels, cap):
            partial.append("portsweep_canary_pause")
            paused_by_canary = True
            remaining.extend(sorted(set(ip_hosts) - {s["ip"] for s in scans} - {ip}))
            _log(params, target_dir, f"canary-paused remaining={len(remaining)}")
            break
        result = _scan_ip(params, adapter, target_dir, target, extra, tool_name, ip, ports_expr, rate, timeout_sec, reprobe=False)
        ports = _parse_naabu(result.stdout, ip)
        if result.exit_code != 0 and not ports:
            unreachable.append(ip)
            _log(params, target_dir, f"unreachable\t{ip}")
            continue
        record: dict[str, Any] = {
            "ip": ip,
            "hosts": list(meta["hosts"]),
            "profile": profile,
            "ports": ports,
            "filtered_suspect": False,
            "anomalous_open_suspect": False,
        }
        alive_hosts = bool(meta["hosts"]) and _any_alive(meta["hosts"], assets)
        if profile == "full" and not ports and alive_hosts:
            # FILTERING INTELLIGENCE: one slower re-probe before accepting zero
            slow_rate = max(_MIN_PPS, rate // reprobe_divisor)
            _log(params, target_dir, f"filtered-reprobe\t{ip}\trate={slow_rate}")
            result2 = _scan_ip(params, adapter, target_dir, target, extra, tool_name, ip, ports_expr, slow_rate, timeout_sec, reprobe=True)
            ports2 = _parse_naabu(result2.stdout, ip)
            if not ports2:
                record["filtered_suspect"] = True
                _log(params, target_dir, f"filtered_suspect\t{ip}\treprobe_empty=true")
            else:
                ports = ports2
                record["ports"] = ports2
        if len(record["ports"]) > anomalous_threshold:
            record["anomalous_open_suspect"] = True
            _log(params, target_dir, f"anomalous_open_suspect\t{ip}\topen={len(record['ports'])} (recorded, never alert-spammed)")
        scans.append(record)
        if bool(params.require("portsweep_nmap_sv")) and record["ports"]:
            services.extend(
                _nmap_services(params, adapter, target_dir, target, extra, ip, record["ports"], timeout_sec)
            )
        # Flush so RESULTS/PORTS update mid-sweep (not only at end), but throttled
        # to avoid O(N^2) full-JSON rewrites on large IP sets.
        now = adapter.clock.time()
        if now - _last_flush >= _FLUSH_INTERVAL_SEC:
            _last_flush = now
            mid = _payload(
                params,
                scans=list(scans),
                services=list(services),
                pace=pace,
                unique_ips_scanned=len(scans),
                duplicates_skipped=duplicates_skipped,
                skipped=None,
                completed_at=_stamp_now(),
                remaining_ips=sorted(set(ip_hosts) - {s["ip"] for s in scans}),
                unreachable=list(unreachable),
                skipped_no_ip=[u["host"] for u in unresolved],
                guarantee={"hosts": len(no_ip_hosts), "resolved": resolved_now, "unresolved": unresolved},
                sentinels_used=len(sentinels),
                skips=list(skips),
            )
            _write_outputs(params, target_dir, mid, skips)
    if remaining:
        # window breach / canary pause: the remaining-IP list is disclosed --
        # the sweep is PARTIAL, never silently abandoned.
        partial.append("portsweep_window_breached" if window_breached else "portsweep_budget_stop")
    if paused_by_canary:
        skips.append("canary paused the sweep (2 consecutive bad windows)")

    payload = _payload(
        params,
        scans=scans,
        services=services,
        pace=pace,
        unique_ips_scanned=len(scans),
        duplicates_skipped=duplicates_skipped,
        skipped=None,
        completed_at=_stamp_now(),
        remaining_ips=remaining,
        unreachable=unreachable,
        skipped_no_ip=[u["host"] for u in unresolved],
        guarantee={"hosts": len(no_ip_hosts), "resolved": resolved_now, "unresolved": unresolved},
        sentinels_used=len(sentinels),
        skips=skips,
    )
    _write_outputs(params, target_dir, payload, skips)
    return payload


# ---------------------------------------------------------------------------


def no_ip_host_reasons(rows: list[tuple[str, list[str], set[str]]], no_ip_hosts: list[str]) -> list[tuple[str, str]]:
    got = {host for host, _ips, _s in rows}
    return [(h, "dnsx no answer") for h in no_ip_hosts if h not in got]


def _psv8_ips(params: Params, target_dir: Path) -> list[str]:
    """PSV-8 stored-AS-IS IP list (sources/cidr-ips.txt from passive-recon)."""
    rel = str(params.require("passive_sources_relpath")) + "/cidr-ips.txt"
    path = target_dir / rel
    if not path.is_file():
        return []
    out: list[str] = []
    for line in read_lines(path):
        token = line.strip()
        if not token:
            continue
        try:
            ipaddress.ip_address(token)
        except ValueError:
            continue
        out.append(token)
    return list(dict.fromkeys(out))


def _resolver_fleet(params: Params, adapter: Adapter, target_dir: Path, target: str) -> tuple[str, str]:
    """Same forged-resolver registry as DNSR (RULE 1): reuse the target copy
    when a previous stage forged it; otherwise forge once (forge_resolvers
    itself copies the healthy fleet into the target dir)."""
    rel = str(params.require("resolver_target_copy"))
    path = target_dir / rel
    if path.is_file() and any(read_lines(path)):
        return container_path(params, target, rel), f"reused {rel}"
    forge_resolvers(params, adapter, target_dir, target)
    healthy = sum(1 for line in read_lines(target_dir / rel) if line.strip())
    return container_path(params, target, rel), f"forged healthy={healthy}"


def _batch_resolve(
    params: Params,
    gate: ScopeGate,
    adapter: Adapter,
    target_dir: Path,
    target: str,
    extra: dict[str, Any],
    hosts: list[str],
    resolvers_c: str,
    timeout_sec: float | None,
) -> list[tuple[str, list[str], set[str]]]:
    """ONE batched dnsx pass over every no-IP host (RULE 1)."""
    hosts_rel = str(params.require("portsweep_guarantee_hosts_rel"))
    atomic_write_text(target_dir / hosts_rel, "\n".join(hosts) + "\n")
    out_rel = str(params.require("portsweep_guarantee_output_rel"))
    out_path = target_dir / out_rel
    if out_path.exists():
        out_path.unlink()
    extra_g = {
        **extra,
        "dnsx_hosts": container_path(params, target, hosts_rel),
        "dnsx_resolvers": resolvers_c,
        "dnsx_max_qps": params.require("dnsx_max_qps"),
        "target_domain": target,
        "output_raw_dir": str(params.require("portsweep_raw_dir")) + "/guarantee",
        "skip_parse": True,
    }
    result = adapter.invoke(
        "dnsx-list",
        module="port-sweep",
        extra=extra_g,
        planned_concurrency=1,
        timeout_sec=timeout_sec,
        allow_fallback=True,
    )
    rows = _rows_from_guarantee(out_path, result)
    if not rows and result.exit_code != 0:
        return []
    return rows


def _rows_from_guarantee(out_path: Path, result: Any) -> list[tuple[str, list[str], set[str]]]:
    """Parse dnsx -json rows ({host, a:[...]} or {name, a:[...]})."""
    text = ""
    if out_path.is_file():
        text = out_path.read_text(encoding="utf-8", errors="replace")
    elif result is not None and getattr(result, "stdout", ""):
        text = result.stdout
    rows: list[tuple[str, list[str], set[str]]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = str(row.get("host") or row.get("name") or "").strip().lower()
        ips = [str(x) for x in (row.get("a") or row.get("a_record") or []) if x]
        if host and ips:
            rows.append((host, ips, {"resolution-guarantee"}))
    return rows


def _profile(params: Params, profile: str) -> tuple[str, int, float, str | None]:
    """Thin config layer over the adapter -- never a new tool.

    Returns (naabu -p expression, ports_total, rate cap, tool spec name);
    a non-executable configuration returns tool_name=None with the reason
    in slot 0 (never silent).
    """
    if profile == "full":
        return "-", _FULL_RANGE_PORTS, float(params.require("portsweep_full_rate_cap")), "naabu-full"
    if profile == "light":
        top = int(params.require("portcheck_top_ports"))
        return f"top-{top}", top, float(params.require("portcheck_rate")), "naabu"
    if profile == "custom":
        raw = str(params.require("portsweep_custom_ports") or "").strip()
        if not raw:
            return "custom profile requires a non-empty portsweep_custom_ports range", 0, 0.0, None
        cap = float(params.require("portsweep_custom_rate_cap"))
        total = _count_ports(raw)
        return raw, total, cap, "naabu-sweep"
    return f"unknown profile '{profile}'", 0, 0.0, None


def _count_ports(expr: str) -> int:
    total = 0
    for part in expr.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                lo, hi = part.split("-", 1)
                total += max(0, int(hi) - int(lo) + 1)
                continue
            except ValueError:
                continue
        if part.isdigit():
            total += 1
    return total


def _scan_ip(
    params: Params,
    adapter: Adapter,
    target_dir: Path,
    target: str,
    extra: dict[str, Any],
    tool_name: str,
    ip: str,
    ports_expr: str,
    rate: int,
    timeout_sec: float | None,
    reprobe: bool,
) -> Any:
    extra_n = {
        **extra,
        "naabu_host": ip,
        "portsweep_ports_arg": ports_expr,
        "portsweep_rate": rate,
        "target_domain": target,
        "output_raw_dir": f"{params.require('portsweep_raw_dir')}/{ip}",
        "skip_parse": True,
    }
    _log(params, target_dir, f"{'re-probe-invoke' if reprobe else 'naabu-invoke'}\tip={ip}\trate={rate}\ttool={tool_name}")
    return adapter.invoke(
        tool_name,
        module="port-sweep",
        extra=extra_n,
        planned_concurrency=1,
        timeout_sec=timeout_sec,
        allow_fallback=False,
    )


def _parse_naabu(stdout: str, ip: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[int] = set()
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, dict) or row.get("port") is None:
            continue
        p = int(row["port"])
        if p in seen:
            continue
        seen.add(p)
        proto = str(row.get("protocol") or row.get("proto") or "tcp")
        rows.append({"port": p, "proto": proto, "state": "open"})
    return rows


def _any_alive(hosts: list[str], assets: list[dict[str, Any]]) -> bool:
    alive = {str(a.get("host") or "").lower(): a for a in assets if isinstance(a, dict)}
    return any((alive.get(h) or {}).get("alive") is True for h in hosts)


def _nmap_services(
    params: Params,
    adapter: Adapter,
    target_dir: Path,
    target: str,
    extra: dict[str, Any],
    ip: str,
    ports: list[dict[str, Any]],
    timeout_sec: float | None,
) -> list[dict[str, Any]]:
    """SECOND STAGE -- designated VA hook: runs ONLY behind portsweep_nmap_sv."""
    ports_arg = ",".join(str(p["port"]) for p in ports)
    extra_m = {
        **extra,
        "naabu_host": ip,
        "nmap_ports_arg": ports_arg,
        "target_domain": target,
        "output_raw_dir": f"logs/raw/nmap-sv/{ip}",
        "skip_parse": True,
    }
    _log(params, target_dir, f"nmap-sv-invoke\tip={ip}\tports={ports_arg}")
    result = adapter.invoke(
        "nmap-sv",
        module="port-sweep",
        extra=extra_m,
        planned_concurrency=1,
        timeout_sec=timeout_sec,
        allow_fallback=False,
    )
    parsed = _parse_nmap_xml(result.stdout or "")
    return [
        {
            "ip": ip,
            "port": p,
            "proto": proto,
            "name": name,
            "product": product,
            "version": version,
            "extrainfo": extrainfo,
        }
        for p, proto, name, product, version, extrainfo in parsed
    ]


def _parse_nmap_xml(text: str) -> list[tuple[int, str, str, str, str, str]]:
    services: list[tuple[int, str, str, str, str, str]] = []
    try:
        root = ElementTree.fromstring(text)
    except ElementTree.ParseError:
        return services
    for port_el in root.iter("port"):
        portid = port_el.get("portid")
        proto = port_el.get("protocol") or "tcp"
        state_el = port_el.find("state")
        if portid is None or state_el is None or state_el.get("state") != "open":
            continue
        service_el = port_el.find("service")
        # nmap -sV service element carries the human-useful identity:
        # name (http/ssh/...), product (nginx/OpenSSH/...), version, extrainfo.
        name = (service_el.get("name") if service_el is not None else "") or ""
        product = (service_el.get("product") if service_el is not None else "") or ""
        version = (service_el.get("version") if service_el is not None else "") or ""
        extrainfo = (service_el.get("extrainfo") if service_el is not None else "") or ""
        services.append((int(portid), proto, name, product, version, extrainfo))
    return services


def _latest_previous_sweep(params: Params, target_dir: Path) -> tuple[str, dict[str, Any]] | None:
    """Newest COMPLETED port-sweep doc from history (no-overlap + diff truth)."""
    hist_root = target_dir / str(params.require("history_dirname"))
    if not hist_root.is_dir():
        return None
    rel = str(params.require("portsweep_data_json"))
    for hist in sorted((d for d in hist_root.iterdir() if d.is_dir()), reverse=True):
        doc_path = hist / rel
        if not doc_path.is_file():
            continue
        try:
            doc = read_json(doc_path)
        except Exception:
            continue
        if isinstance(doc, dict) and doc.get("skipped") is None:
            return hist.name, doc
    return None


def _mine_sentinels(params: Params, target_dir: Path) -> list[tuple[str, int]]:
    """3 known-open sentinel (ip, port) pairs from the previous sweep, falling
    back to PORT-CHECK history (spec: sentinels 'from the previous run')."""
    hist_root = target_dir / str(params.require("history_dirname"))
    limit = max(1, int(params.require("portsweep_sentinel_limit")))
    if hist_root.is_dir():
        sweep_rel = str(params.require("portsweep_data_json"))
        check_rel = str(params.require("portcheck_data_json"))
        for hist in sorted((d for d in hist_root.iterdir() if d.is_dir()), reverse=True):
            for rel in (sweep_rel, check_rel):
                path = hist / rel
                if not path.is_file():
                    continue
                try:
                    doc = read_json(path)
                except Exception:
                    continue
                sentinels: list[tuple[str, int]] = []
                for scan in doc.get("scans") or doc.get("results") or []:
                    ip = str(scan.get("ip") or "")
                    for port in scan.get("ports") or []:
                        try:
                            sentinels.append((ip, int(port.get("port"))))
                        except (TypeError, ValueError):
                            continue
                if sentinels:
                    unique = list(dict.fromkeys(sentinels))
                    return unique[:limit]
    return []


def _payload(
    params: Params,
    scans: list[dict[str, Any]],
    services: list[dict[str, Any]],
    pace: dict[str, Any],
    unique_ips_scanned: int,
    duplicates_skipped: int,
    skipped: str | None,
    completed_at: str,
    remaining_ips: list[str],
    unreachable: list[str],
    skipped_no_ip: list[str],
    guarantee: dict[str, Any],
    sentinels_used: int,
    skips: list[str],
) -> dict[str, Any]:
    # Exact section 8 schema keys first; the remaining keys are the never-silent
    # disclosure surface (B3 precedent: additive disclosure keys).
    return {
        "schema_version": int(params.require("schema_version")),
        "module": "port-sweep",
        "scans": scans,
        "services": services,
        "pace": pace,
        "unique_ips_scanned": unique_ips_scanned,
        "duplicates_skipped": duplicates_skipped,
        "skipped": skipped,
        "completed_at": completed_at,
        "remaining_ips": remaining_ips,
        "unreachable": unreachable,
        "resolution_guarantee": guarantee,
        "skipped_no_ip": skipped_no_ip,
        "sentinels_used": sentinels_used,
        "skips": skips,
    }


def _write_outputs(params: Params, target_dir: Path, payload: dict[str, Any], skips: list[str]) -> None:
    write_json(target_dir / str(params.require("portsweep_data_json")), payload)
    summary_rel = str(params.require("portsweep_summary"))
    pace = payload.get("pace") or {}
    lines = [
        "# port-sweep",
        "",
        f"skipped: {payload.get('skipped')}",
        f"profile: {pace.get('profile')}",
        f"duration_hours: {pace.get('duration_hours')} effective_pps: {pace.get('effective_pps')} window_breached: {pace.get('window_breached')}",
        f"unique_ips_scanned: {payload.get('unique_ips_scanned')} duplicates_skipped: {payload.get('duplicates_skipped')}",
        f"unreachable: {len(payload.get('unreachable') or [])} remaining_ips: {len(payload.get('remaining_ips') or [])}",
        f"resolution_guarantee: hosts={payload['resolution_guarantee']['hosts']} resolved={payload['resolution_guarantee']['resolved']} unresolved={len(payload['resolution_guarantee']['unresolved'])}",
        f"sentinels_used: {payload.get('sentinels_used')}",
        f"target_set: {params.require('portsweep_target_set_rel')}",
        "",
    ]
    for skip in skips:
        lines.append(f"skip: {skip}")
    lines.append("")
    atomic_write_text(target_dir / summary_rel, "\n".join(lines))


def _stamp_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _log(params: Params, target_dir: Path, detail: str) -> None:
    path = target_dir / str(params.require("run_log"))
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(f"{_stamp_now()}\tport-sweep\torchestrator\t0\tok\t{detail}\n")
