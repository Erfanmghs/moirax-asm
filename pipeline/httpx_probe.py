"""Shared httpx enrich: HTTP status, response length, and technology tags.

The probe is opt-in: the operator ENABLED switch on the `httpx` tool in the
dashboard is the gate. When the tool is disabled, callers leave fields null
and never launch a container.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pipeline.adapter import Adapter
from pipeline.hostsutil import container_path, normalize_fqdn
from pipeline.ndjson import load_json_file, parse_json_payload
from pipeline.params import Params
from pipeline.textio import atomic_write_text


def probe_hosts(
    params: Params,
    adapter: Adapter,
    target_dir: Path,
    target: str,
    extra: dict[str, Any],
    planned: int,
    timeout_sec: float | None,
    hosts: list[str],
    list_rel: str,
    out_rel: str,
    module: str,
    raw_dir: str,
    tool: str = "httpx",
) -> dict[str, dict[str, Any]]:
    """Return host -> {alive, http_status, length, tech, title}. Empty if skipped."""
    if not hosts:
        return {}
    if not adapter.enabled(tool):
        return {}
    uniq: list[str] = []
    seen: set[str] = set()
    for raw in hosts:
        host = normalize_fqdn(str(raw or ""))
        if not host or host in seen:
            continue
        seen.add(host)
        uniq.append(host)
    if not uniq:
        return {}
    atomic_write_text(target_dir / list_rel, "\n".join(uniq) + "\n")
    merged = dict(extra)
    merged.update(
        {
            "httpx_list": container_path(params, target, list_rel),
            "httpx_output": container_path(params, target, out_rel),
            "output_raw_dir": raw_dir,
            "skip_parse": True,
        }
    )
    result = adapter.invoke(
        tool,
        module=module,
        extra=merged,
        planned_concurrency=planned,
        timeout_sec=timeout_sec,
        allow_fallback=False,
    )
    payload = load_json_file(target_dir / out_rel)
    if payload is None:
        payload = parse_json_payload(result.stdout)
    return index_httpx_payload(payload)


def index_httpx_payload(payload: Any) -> dict[str, dict[str, Any]]:
    """Parse httpx JSON/JSONL into a per-host enrich map."""
    rows = payload if isinstance(payload, list) else ([payload] if isinstance(payload, dict) else [])
    by_host: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        host = _host_of(row)
        if not host:
            continue
        by_host[host] = enrich_from_row(row)
    return by_host


def enrich_from_row(row: dict[str, Any]) -> dict[str, Any]:
    failed = row.get("failed") is True
    status = row.get("status_code") if row.get("status_code") is not None else row.get("status")
    length = row.get("content_length")
    if length is None:
        length = row.get("length")
    tech = _tech_of(row)
    title = row.get("title")
    alive = (not failed) and status is not None
    return {
        "alive": alive,
        "http_status": int(status) if status is not None else None,
        "length": int(length) if length is not None else None,
        "tech": tech,
        "title": str(title) if title else None,
    }


def apply_enrich(row: dict[str, Any], enrich: dict[str, Any] | None, *, miss_alive: bool = True) -> None:
    """Write enrich fields onto a host/resolved row. Missing probe => alive false."""
    if enrich is None:
        if miss_alive:
            row["alive"] = False
        return
    row["alive"] = enrich.get("alive")
    if enrich.get("http_status") is not None:
        row["http_status"] = enrich["http_status"]
    if enrich.get("length") is not None:
        row["length"] = enrich["length"]
    tech = enrich.get("tech") or []
    if tech:
        row["tech"] = list(tech)
    if enrich.get("title"):
        row["title"] = enrich["title"]


def empty_http_fields() -> dict[str, Any]:
    return {
        "alive": None,
        "http_status": None,
        "length": None,
        "tech": [],
        "title": None,
    }


def _host_of(row: dict[str, Any]) -> str:
    raw = str(row.get("input") or row.get("host") or "").strip().lower()
    raw = raw.split("://")[-1].split("/")[0].split(":")[0].rstrip(".")
    return normalize_fqdn(raw) or raw


def _tech_of(row: dict[str, Any]) -> list[str]:
    val = row.get("tech") if row.get("tech") is not None else row.get("technologies")
    if val is None:
        return []
    if isinstance(val, str):
        item = val.strip()
        return [item] if item else []
    if isinstance(val, list):
        out: list[str] = []
        for item in val:
            if isinstance(item, str) and item.strip():
                out.append(item.strip())
            elif isinstance(item, dict):
                name = item.get("name") or item.get("tech")
                ver = item.get("version")
                if name and ver:
                    out.append(f"{name}:{ver}")
                elif name:
                    out.append(str(name))
        return out
    return []
