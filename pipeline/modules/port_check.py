"""PORT-CHECK -- IP-centric naabu top-50 (ACTIVE order 3)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pipeline.adapter import Adapter
from pipeline.jsonio import read_json, write_json
from pipeline.ndjson import parse_json_payload
from pipeline.params import Params
from pipeline.scope import ScopeGate

# REM8 (TEST 3, disclosed in PHASE-REPORT): merge.py's as-frozen IP ruling
# accepts host-attributed public IPs for exactly these two gate reasons.
# Without the same ruling at port-check, a host-includes-only scope (the
# frozen B2 shape) rejects EVERY IP and the one-naabu-per-IP machinery that
# TEST 3 must prove is unreachable dead code.
_IP_ALLOWED_REASONS = ("no IP includes", "IP not in included CIDRs")


def _ip_scan_verdict(gate: ScopeGate, ip: str) -> tuple[bool, str | None]:
    """REM8 alignment: mirror merge.py's as-frozen IP ruling.

    Returns (scan_eligible, rejection_reason). Excluded CIDRs/IPs and private
    ranges (RFC1918/loopback/link-local not listed in includes) stay REJECTED
    - the safety rails are untouched.
    """
    ok, reason = gate.validate_candidate(ip)
    if ok or reason in _IP_ALLOWED_REASONS:
        return True, None
    return False, reason


def run_port_check(
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
    dns_path = target_dir / str(params.require("dnsr_data_json"))
    resolved_rows: list[dict[str, Any]] = []
    if dns_path.is_file():
        doc = read_json(dns_path)
        resolved_rows = [row for row in (doc.get("resolved") or []) if isinstance(row, dict)]

    ip_hosts: dict[str, list[str]] = {}
    skipped_no_ip: list[str] = []
    duplicates_skipped = 0
    oos_rel = str(params.require("out_of_scope_log"))
    for row in resolved_rows:
        host = str(row.get("host") or "").strip().lower()
        if not host:
            continue
        if not gate.enforce(target_dir, host):
            continue
        ips = [str(ip) for ip in (row.get("ips") or []) if ip]
        if not ips or str(row.get("resolution_status") or "") == "unresolved":
            skipped_no_ip.append(host)
            _log(params, target_dir, f"skip-no-ip\t{host}")
            continue
        for ip in ips:
            eligible, reject_reason = _ip_scan_verdict(gate, ip)
            if not eligible:
                gate.log_rejection(target_dir / oos_rel, ip, reject_reason or "out of scope")  # REM8: same rejection ledger as merge
                continue
            bucket = ip_hosts.setdefault(ip, [])
            if host in bucket:
                continue
            if bucket:
                duplicates_skipped += 1
            bucket.append(host)

    target_set_rel = str(params.require("portcheck_target_set_rel"))
    lines = [f"{ip}\t{','.join(hosts)}" for ip, hosts in sorted(ip_hosts.items())]
    (target_dir / target_set_rel).parent.mkdir(parents=True, exist_ok=True)
    (target_dir / target_set_rel).write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    _log(params, target_dir, f"target-set unique_ips={len(ip_hosts)} skipped_no_ip={len(skipped_no_ip)} duplicates_skipped={duplicates_skipped}")

    results: list[dict[str, Any]] = []
    unreachable: list[str] = []
    for ip, hosts in ip_hosts.items():
        _log(params, target_dir, f"naabu-invoke\tip={ip}\thosts={','.join(hosts)}")
        extra_n = {
            **extra,
            "naabu_host": ip,
            "output_raw_dir": f"logs/raw/naabu-light/{ip}",
            "skip_parse": True,
        }
        result = adapter.invoke(
            "naabu",
            module="port-check",
            extra=extra_n,
            planned_concurrency=planned,
            timeout_sec=timeout_sec,
            allow_fallback=False,
        )
        ports = _parse_naabu(result.stdout, ip)
        if result.exit_code != 0 and not ports:
            unreachable.append(ip)
            _log(params, target_dir, f"unreachable\t{ip}")
            continue
        results.append({"ip": ip, "hosts": hosts, "ports": ports})

    payload = {
        "schema_version": int(params.require("schema_version")),
        "module": "port-check",
        "results": results,
        "unreachable": unreachable,
        "unique_ips_checked": len(ip_hosts),
        "duplicates_skipped": duplicates_skipped,
        "skipped_no_ip": skipped_no_ip,
    }
    write_json(target_dir / str(params.require("portcheck_data_json")), payload)
    summary = target_dir / str(params.require("portcheck_summary"))
    summary.parent.mkdir(parents=True, exist_ok=True)
    summary.write_text(
        "\n".join(
            [
                "# port-check",
                "",
                f"unique_ips_checked: {len(ip_hosts)}",
                f"duplicates_skipped: {duplicates_skipped}",
                f"skipped_no_ip: {len(skipped_no_ip)}",
                f"unreachable: {len(unreachable)}",
                f"target_set: {target_set_rel}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return payload


def _parse_naabu(stdout: str, ip: str) -> list[dict[str, Any]]:
    payload = parse_json_payload(stdout)
    rows = payload if isinstance(payload, list) else ([payload] if isinstance(payload, dict) else [])
    ports: list[dict[str, Any]] = []
    seen: set[int] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        if str(row.get("ip") or ip) not in {ip, str(row.get("ip") or "")} and row.get("ip") and row.get("ip") != ip:
            continue
        port = row.get("port")
        if port is None:
            continue
        p = int(port)
        if p in seen:
            continue
        seen.add(p)
        proto = str(row.get("protocol") or row.get("proto") or "tcp")
        ports.append({"port": p, "proto": proto, "state": "open"})
    return ports


def _log(params: Params, target_dir: Path, detail: str) -> None:
    from datetime import datetime, timezone

    path = target_dir / str(params.require("run_log"))
    path.parent.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with path.open("a", encoding="utf-8") as handle:
        handle.write(f"{stamp}\tport-check\tnaabu\t0\tok\t{detail}\n")
