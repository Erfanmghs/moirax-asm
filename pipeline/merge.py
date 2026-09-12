"""MERGE: union, exact dedupe, attribution, scope re-validation, wildcard quarantine (section 7.3)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pipeline.jsonio import read_json, write_json
from pipeline.params import Params
from pipeline.scope import ScopeGate

_ATTR_PASSIVE = "passive"
_ATTR_ACTIVE = "active"
_ATTR_BOTH = "both"


def merge_branches(
    params: Params,
    gate: ScopeGate,
    target_dir: Path,
    target: str,
    passive_docs: list[dict[str, Any]],
    active_docs: list[dict[str, Any]],
) -> Path:
    wildcard_ips = _wildcard_ips(passive_docs + active_docs)
    buckets: dict[str, dict[str, Any]] = {}

    for doc in passive_docs:
        _ingest(buckets, doc, _ATTR_PASSIVE)
    for doc in active_docs:
        _ingest(buckets, doc, _ATTR_ACTIVE)

    return _flush_merged(params, gate, target_dir, target, buckets, wildcard_ips)


def append_active_doc(
    params: Params,
    gate: ScopeGate,
    target_dir: Path,
    target: str,
    doc: dict[str, Any],
) -> Path:
    """Re-merge one extra ACTIVE doc into the existing assets.json (post-MERGE finds)."""
    assets_path = target_dir / str(params.require("assets_relpath"))
    existing = load_tool_doc(assets_path)
    buckets: dict[str, dict[str, Any]] = {}
    if existing:
        _seed_from_assets(buckets, existing)
        wildcard_ips = _wildcard_ips([existing, doc])
    else:
        wildcard_ips = _wildcard_ips([doc])
    _ingest(buckets, doc, _ATTR_ACTIVE)
    return _flush_merged(params, gate, target_dir, target, buckets, wildcard_ips)


def _seed_from_assets(buckets: dict[str, dict[str, Any]], existing: dict[str, Any]) -> None:
    for asset in existing.get("assets") or []:
        if not isinstance(asset, dict):
            continue
        host = _norm_host(asset.get("host"))
        if not host:
            continue
        buckets[host] = {
            "attribution": str(asset.get("attribution") or _ATTR_ACTIVE),
            "sources": set(str(s) for s in (asset.get("sources") or [])),
            "ips": [str(ip) for ip in (asset.get("ips") or []) if ip],
            "alive": asset.get("alive"),
            "tags": set(str(t) for t in (asset.get("tags") or [])),
            "misconfig_suspect": bool(asset.get("misconfig_suspect")),
            "http_status": asset.get("http_status"),
            "length": asset.get("length"),
            "tech": [str(t) for t in (asset.get("tech") or []) if t],
            "title": asset.get("title"),
        }


def _flush_merged(
    params: Params,
    gate: ScopeGate,
    target_dir: Path,
    target: str,
    buckets: dict[str, dict[str, Any]],
    wildcard_ips: set[str],
) -> Path:
    assets: list[dict[str, Any]] = []
    quarantine: list[dict[str, Any]] = []
    log_rel = Path(str(params.require("out_of_scope_log")))
    wildcard_reason = str(params.require("merge_wildcard_reason"))
    catchall_reason = str(params.require("merge_catchall_reason"))

    ip_hosts: dict[str, list[str]] = {}
    for host, row in buckets.items():
        for ip in row["ips"]:
            ip_hosts.setdefault(ip, []).append(host)

    for host, row in sorted(buckets.items()):
        allowed, reason = gate.validate_candidate(host)
        if not allowed:
            gate.log_rejection(target_dir / log_rel, host, reason)
            continue
        q_reason = _quarantine_reason(row["ips"], wildcard_ips, ip_hosts, wildcard_reason, catchall_reason)
        if q_reason:
            quarantine.append({"host": host, "ips": list(row["ips"]), "reason": q_reason})
            continue
        in_scope_ips: list[str] = []
        for ip in row["ips"]:
            ip_ok, ip_reason = gate.validate_candidate(ip)
            if ip_ok:
                in_scope_ips.append(ip)
            elif ip_reason in ("no IP includes", "IP not in included CIDRs"):
                in_scope_ips.append(ip)
            else:
                gate.log_rejection(target_dir / log_rel, ip, ip_reason)
        row["ips"] = in_scope_ips
        asset = {
            "host": host,
            "ips": in_scope_ips,
            # A host that resolves to an in-scope IP is a live asset. HTTP
            # reachability (http_status/tech) is separate; never mark an
            # IP-bearing, in-scope host dead in the canonical output.
            "alive": True if in_scope_ips else row["alive"],
            "attribution": row["attribution"],
            "sources": sorted(row["sources"]),
        }
        if row["tags"]:
            asset["tags"] = sorted(row["tags"])
        if row.get("misconfig_suspect"):
            asset["misconfig_suspect"] = True
        if row.get("http_status") is not None:
            asset["http_status"] = row["http_status"]
        if row.get("length") is not None:
            asset["length"] = row["length"]
        if row.get("tech"):
            asset["tech"] = list(row["tech"])
        if row.get("title"):
            asset["title"] = row["title"]
        assets.append(asset)

    payload = {
        "schema_version": int(params.require("schema_version")),
        "target": target,
        "assets": assets,
        "quarantine": quarantine,
    }
    assets_path = target_dir / str(params.require("assets_relpath"))
    assets_path.parent.mkdir(parents=True, exist_ok=True)
    write_json(assets_path, payload)
    # TEST 3 (T3-1, disclosed): composition disclosure line -- attribution split
    # and host->IP map shape of the merged tree, so the acceptance report can
    # show exactly what this run's MERGE composed from THIS run's inputs.
    _attr_counts: dict[str, int] = {}
    for asset in assets:
        _attr_counts[asset["attribution"]] = _attr_counts.get(asset["attribution"], 0) + 1
    distinct_ips = len({ip for asset in assets for ip in asset["ips"]})
    host_ip_pairs = sum(len(asset["ips"]) for asset in assets)
    composition_line = (
        f"composition: passive={_attr_counts.get(_ATTR_PASSIVE, 0)}"
        f" active={_attr_counts.get(_ATTR_ACTIVE, 0)}"
        f" both={_attr_counts.get(_ATTR_BOTH, 0)}"
        f" distinct_ips={distinct_ips} host_ip_pairs={host_ip_pairs}"
    )
    summary = target_dir / str(params.require("assets_summary_relpath"))
    summary.parent.mkdir(parents=True, exist_ok=True)
    summary.write_text(
        "\n".join(
            [
                "# MERGE",
                "",
                f"assets: {len(assets)}",
                f"quarantine: {len(quarantine)}",
                composition_line,
                "",
            ]
        ),
        encoding="utf-8",
    )
    return assets_path


def load_tool_doc(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    data = read_json(path)
    return data if isinstance(data, dict) else None


def _ingest(buckets: dict[str, dict[str, Any]], doc: dict[str, Any], branch: str) -> None:
    tool = str(doc.get("module") or branch)
    for host, meta in _iter_assets(doc):
        row = buckets.get(host)
        if row is None:
            row = {
                "attribution": branch,
                "sources": set(),
                "ips": [],
                "alive": None,
                "tags": set(),
                "misconfig_suspect": False,
                "http_status": None,
                "length": None,
                "tech": [],
                "title": None,
            }
            buckets[host] = row
        else:
            if row["attribution"] != branch:
                row["attribution"] = _ATTR_BOTH
        row["sources"].add(tool)
        for src in meta.get("sources") or []:
            row["sources"].add(str(src))
        for ip in meta.get("ips") or []:
            ip_s = str(ip)
            if ip_s and ip_s not in row["ips"]:
                row["ips"].append(ip_s)
        alive = meta.get("alive")
        if alive is True:
            row["alive"] = True
        elif alive is False and row["alive"] is None:
            row["alive"] = False
        for tag in meta.get("tags") or []:
            row["tags"].add(str(tag))
        if meta.get("misconfig_suspect") is True:
            row["misconfig_suspect"] = True
        if meta.get("http_status") is not None:
            row["http_status"] = meta.get("http_status")
        if meta.get("length") is not None:
            row["length"] = meta.get("length")
        for item in meta.get("tech") or []:
            text = str(item).strip()
            if text and text not in row["tech"]:
                row["tech"].append(text)
        if meta.get("title") and not row.get("title"):
            row["title"] = str(meta.get("title"))


def _iter_assets(doc: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    found: list[tuple[str, dict[str, Any]]] = []
    candidates = doc.get("candidates")
    if isinstance(candidates, list):
        for row in candidates:
            if not isinstance(row, dict):
                continue
            host = _norm_host(row.get("host") or row.get("fqdn"))
            if host:
                found.append((host, row))
    hosts = doc.get("hosts")
    if isinstance(hosts, list):
        for row in hosts:
            if not isinstance(row, dict):
                continue
            host = _norm_host(row.get("fqdn") or row.get("host"))
            if host:
                found.append((host, row))
    resolved = doc.get("resolved")
    if isinstance(resolved, list):
        for row in resolved:
            if not isinstance(row, dict):
                continue
            host = _norm_host(row.get("host"))
            if host:
                found.append((host, row))
    vhosts = doc.get("vhosts")
    if isinstance(vhosts, list):
        for row in vhosts:
            if not isinstance(row, dict):
                continue
            host = _norm_host(row.get("vhost"))
            if host:
                found.append((host, row))
    return found


def _wildcard_ips(docs: list[dict[str, Any]]) -> set[str]:
    ips: set[str] = set()
    for doc in docs:
        # Primary source: dns-resolve emits the catch-all IPs explicitly.
        for item in doc.get("wildcard_ips") or []:
            if isinstance(item, str) and _looks_ip(item):
                ips.add(item)
        # Backward-compat: some docs may still carry IPs (or ip-dicts) here.
        suspects = doc.get("wildcard_suspects") or []
        if isinstance(suspects, list):
            for item in suspects:
                if isinstance(item, str) and _looks_ip(item):
                    ips.add(item)
                elif isinstance(item, dict):
                    for key in ("ip", "wildcard_ip"):
                        val = item.get(key)
                        if isinstance(val, str) and _looks_ip(val):
                            ips.add(val)
        # Any resolved row explicitly tagged as the wildcard probe contributes
        # its IPs to the catch-all set.
        resolved = doc.get("resolved") or []
        if isinstance(resolved, list):
            for row in resolved:
                if isinstance(row, dict) and row.get("source") == "wildcard":
                    for ip in row.get("ips") or []:
                        if isinstance(ip, str) and _looks_ip(ip):
                            ips.add(ip)
    return ips


def _quarantine_reason(
    ips: list[str],
    wildcard_ips: set[str],
    ip_hosts: dict[str, list[str]],
    wildcard_reason: str,
    catchall_reason: str,
) -> str | None:
    # CONSERVATIVE: quarantine only names that resolve EXCLUSIVELY to catch-all
    # IPs. A host that also has any genuine (non-wildcard) IP is a real asset and
    # is kept -- we never hide an IP-bearing host just because it shares one
    # catch-all address (this is the inverse of the "wrongly-dead" bug).
    if not ips or not wildcard_ips:
        return None
    if not all(ip in wildcard_ips for ip in ips):
        return None
    if any(len(ip_hosts.get(ip) or []) > 1 for ip in ips):
        return catchall_reason
    return wildcard_reason


def _norm_host(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    host = value.strip().lower().rstrip(".")
    return host or None


def _looks_ip(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return ":" in value
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
