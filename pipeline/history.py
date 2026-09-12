"""Run history snapshots and diff.json (section 6.6)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pipeline.hostsutil import keep_asset_row, keep_resolved_host
from pipeline.jsonio import read_json, write_json
from pipeline.params import Params

FACT_CLASSES = ("hosts", "vhosts", "ports", "services", "passive_ips")
_CLASSES = FACT_CLASSES


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def append_run(params: Params, target_dir: Path, timestamp: str, status: str, counts: dict[str, int]) -> Path:
    path = target_dir / str(params.require("runs_filename"))
    if path.exists():
        data = read_json(path)
        if not isinstance(data, dict):
            data = {"schema_version": int(params.require("schema_version")), "runs": []}
    else:
        data = {"schema_version": int(params.require("schema_version")), "runs": []}
    runs = data.setdefault("runs", [])
    runs.append({"timestamp": timestamp, "status": status, "counts": counts})
    write_json(path, data)
    return path


def snapshot(params: Params, target_dir: Path, timestamp: str) -> Path:
    hist = target_dir / str(params.require("history_dirname")) / timestamp
    hist.mkdir(parents=True, exist_ok=True)
    for path in target_dir.rglob("data.json"):
        if _under_history(path, target_dir, params):
            continue
        rel = path.relative_to(target_dir)
        dest = hist / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
    assets = target_dir / str(params.require("assets_relpath"))
    if assets.is_file():
        dest = hist / Path(str(params.require("assets_relpath")))
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(assets.read_bytes())
    return hist


def previous_timestamp(params: Params, target_dir: Path, current: str) -> str | None:
    path = target_dir / str(params.require("runs_filename"))
    if not path.is_file():
        return None
    data = read_json(path)
    runs = [row.get("timestamp") for row in (data.get("runs") or []) if isinstance(row, dict)]
    prior = [ts for ts in runs if isinstance(ts, str) and ts != current]
    return prior[-1] if prior else None


def write_diff(params: Params, target_dir: Path, from_ts: str | None, to_ts: str) -> Path:
    hist = target_dir / str(params.require("history_dirname"))
    # First run / empty baseline: compare against empty MAPS (not list buckets).
    older = extract_classes(params, hist / from_ts) if from_ts else empty_maps()
    newer = extract_classes(params, hist / to_ts)
    payload = diff_maps(older, newer, int(params.require("schema_version")), from_ts, to_ts)
    dest = target_dir / str(params.require("diff_filename"))
    write_json(dest, payload)
    if to_ts:
        hist_dest = hist / to_ts / str(params.require("diff_filename"))
        write_json(hist_dest, payload)
    return dest


def diff_maps(
    older: dict[str, dict[str, Any]],
    newer: dict[str, dict[str, Any]],
    schema_version: int,
    from_ts: str | None,
    to_ts: str | None,
) -> dict[str, Any]:
    """Compare two class-maps. Shared by JSON diff.json and the per-target warehouse."""
    payload: dict[str, Any] = {
        "schema_version": schema_version,
        "from_run": from_ts,
        "to_run": to_ts,
        "added": empty_classes(),
        "removed": empty_classes(),
        "changed": empty_classes(),
    }
    if from_ts is None:
        payload["baseline"] = "none"
        payload["run_timestamp"] = to_ts
    for cls in FACT_CLASSES:
        old_map = older.get(cls) or {}
        new_map = newer.get(cls) or {}
        for key, val in new_map.items():
            if key not in old_map:
                payload["added"][cls].append(val)
            elif old_map[key] != val:
                payload["changed"][cls].append({"before": old_map[key], "after": val})
        for key, val in old_map.items():
            if key not in new_map:
                payload["removed"][cls].append(val)
    return payload


def _under_history(path: Path, target_dir: Path, params: Params) -> bool:
    hist = target_dir / str(params.require("history_dirname"))
    try:
        path.relative_to(hist)
        return True
    except ValueError:
        return False


def empty_classes() -> dict[str, list[Any]]:
    return {name: [] for name in FACT_CLASSES}


def empty_maps() -> dict[str, dict[str, Any]]:
    """Empty per-class key->asset maps used as the first-run baseline (section 6.6)."""
    return {name: {} for name in FACT_CLASSES}


_empty_classes = empty_classes
_empty_maps = empty_maps


def extract_classes(params: Params, snap: Path, skip_history: bool = False) -> dict[str, dict[str, Any]]:
    buckets = {name: {} for name in _CLASSES}
    if not snap.is_dir():
        return buckets
    assets = snap / str(params.require("assets_relpath"))
    if assets.is_file():
        doc = read_json(assets)
        for row in doc.get("assets") or []:
            if not isinstance(row, dict) or not row.get("host"):
                continue
            host = str(row["host"])
            buckets["hosts"][host] = row
    for data_path in snap.rglob("data.json"):
        if skip_history and _under_history(data_path, snap, params):
            continue
        try:
            doc = read_json(data_path)
        except (OSError, json.JSONDecodeError, ValueError):
            continue
        if not isinstance(doc, dict):
            continue
        for row in doc.get("vhosts") or []:
            if isinstance(row, dict) and row.get("vhost"):
                key = f"{row.get('base_host','')}|{row['vhost']}|{row.get('ip','')}|{row.get('port','')}|{row.get('scheme','')}"
                buckets["vhosts"][key] = row
        for row in doc.get("results") or []:
            if not isinstance(row, dict):
                continue
            host = str(row.get("host") or "")
            ip = str(row.get("ip") or "")
            for port in row.get("ports") or []:
                if isinstance(port, dict) and port.get("port") is not None:
                    key = f"{host}|{ip}|{port['port']}|{port.get('proto','')}"
                    buckets["ports"][key] = {"host": host, "ip": ip, **port}
        for row in doc.get("scans") or []:
            if not isinstance(row, dict):
                continue
            ip = str(row.get("ip") or "")
            for port in row.get("ports") or []:
                if isinstance(port, dict) and port.get("port") is not None:
                    key = f"{ip}|{port['port']}|{port.get('proto','')}"
                    buckets["ports"][key] = {"ip": ip, **port}
        for row in doc.get("services") or []:
            if isinstance(row, dict) and row.get("ip") is not None and row.get("port") is not None:
                key = f"{row['ip']}|{row['port']}|{row.get('proto','')}"
                buckets["services"][key] = row
        for row in doc.get("passive_ips") or []:
            if isinstance(row, dict) and row.get("ip"):
                buckets["passive_ips"][str(row["ip"])] = row
    return buckets


def extract_live_classes(params: Params, target_dir: Path) -> dict[str, dict[str, Any]]:
    """Index the live workspace so RESULTS can refresh before MERGE writes assets.json."""
    buckets = extract_classes(params, target_dir, skip_history=True)
    apex = target_dir.name.strip().lower().rstrip(".")
    wild = live_wildcard_ips(params, target_dir)
    dnsr = target_dir / str(params.require("dnsr_data_json"))
    if dnsr.is_file():
        try:
            doc = read_json(dnsr)
        except (OSError, json.JSONDecodeError, ValueError):
            doc = {}
        if isinstance(doc, dict):
            for rec in doc.get("resolved") or []:
                if not isinstance(rec, dict):
                    continue
                host = str(rec.get("host") or "").strip().lower()
                status = str(rec.get("resolution_status") or "resolved")
                if not host or status not in ("", "resolved"):
                    continue
                if host in buckets["hosts"]:
                    continue
                ips = rec.get("ips") or rec.get("a") or []
                if not isinstance(ips, list):
                    ips = []
                ip_list = [str(ip) for ip in ips if ip]
                if not keep_resolved_host(host, ip_list, wild, apex, source=str(rec.get("source") or "")):
                    continue
                buckets["hosts"][host] = {
                    "host": host,
                    "ips": ip_list,
                    # resolved with an IP => live asset (HTTP detail is separate)
                    "alive": bool(ip_list) or (rec.get("alive") is True),
                    "attribution": "active",
                    "sources": ["dns-resolve"],
                }
    dnsx_dir = target_dir / "20_dns" / "dnsx"
    if dnsx_dir.is_dir():
        for path in sorted(dnsx_dir.glob("brute_*.json")):
            _hosts_from_dnsx_json(buckets["hosts"], path, wild, apex)
    return buckets


def live_wildcard_ips(params: Params, target_dir: Path) -> set[str]:
    ips: set[str] = set()
    dnsr = target_dir / str(params.require("dnsr_data_json"))
    if dnsr.is_file():
        try:
            doc = read_json(dnsr)
        except (OSError, json.JSONDecodeError, ValueError):
            doc = {}
        if isinstance(doc, dict):
            for item in doc.get("wildcard_ips") or []:
                if item:
                    ips.add(str(item))
    probe_paths = []
    probe = target_dir / str(params.require("dnsr_wildcard_out_rel"))
    probe_paths.append(probe)
    dnsx_dir = target_dir / "20_dns" / "dnsx"
    if dnsx_dir.is_dir():
        probe_paths.extend(sorted(dnsx_dir.glob("wildcard-probe*.json")))
    seen: set[str] = set()
    for probe in probe_paths:
        key = str(probe)
        if key in seen or not probe.is_file():
            continue
        seen.add(key)
        try:
            text = probe.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(rec, dict):
                continue
            for key_name in ("a", "aaaa", "A"):
                val = rec.get(key_name)
                if isinstance(val, list):
                    ips.update(str(x) for x in val if x)
                elif isinstance(val, str) and val:
                    ips.add(val)
    return ips


def drop_wildcard_host_rows(params: Params, target_dir: Path, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    wild = live_wildcard_ips(params, target_dir)
    if not wild:
        return rows
    apex = target_dir.name.strip().lower().rstrip(".")
    return [row for row in rows if isinstance(row, dict) and keep_asset_row(row, wild, apex)]


def _hosts_from_dnsx_json(
    hosts: dict[str, Any],
    path: Path,
    wildcard_ips: set[str] | None = None,
    apex: str = "",
) -> None:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(rec, dict):
            continue
        host = str(rec.get("host") or rec.get("input") or "").strip().lower().rstrip(".")
        if not host:
            continue
        ips = rec.get("a") or rec.get("aaaa") or rec.get("A") or []
        if isinstance(ips, str):
            ips = [ips]
        ips = [str(ip) for ip in ips if ip]
        if not keep_resolved_host(host, ips, wildcard_ips, apex, source="brute"):
            continue
        row = hosts.get(host) or {"host": host, "ips": [], "sources": ["dnsx"], "alive": bool(ips)}
        merged = list(row.get("ips") or [])
        for ip in ips:
            if ip not in merged:
                merged.append(ip)
        row["ips"] = merged
        sources = list(row.get("sources") or [])
        if "dnsx" not in sources:
            sources.append("dnsx")
        row["sources"] = sources
        row["alive"] = bool(merged) or bool(row.get("alive"))
        hosts[host] = row


_extract_classes = extract_classes
