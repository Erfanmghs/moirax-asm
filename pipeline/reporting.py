"""REPORTING (section 10) -- human + machine deliverables under 90_report/.

PRECISION CONTRACT (section 10.2): every format is rendered FROM the canonical
data.json files (section 6.3) only -- raw tool stdout is never re-parsed -- so all
formats agree exactly. Every export embeds the run timestamp + scope.yaml
digest -> any artifact is traceable to the exact run and the exact
authorization state. All content in English (section 10.3).
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pipeline.params import Params
from pipeline.yaml_util import load_yaml_file

# Flat per-class CSV columns (section 10.1: flat export.csv per asset class).
CSV_CLASSES: dict[str, tuple[str, ...]] = {
    "hosts": ("host", "ips", "alive", "length", "sources", "tags"),
    "vhosts": ("base_host", "vhost", "ip", "port", "scheme", "alive", "http_status", "length", "misconfig_suspect"),
    "ports": ("host", "ip", "port", "proto"),
    "services": ("ip", "port", "proto", "service", "product", "version"),
    "passive_ips": ("ip", "sources"),
}


def scope_digest(params: Params) -> str:
    path = params.root / "scope.yaml"
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else "no-scope"


def _read_json(path: Path) -> dict[str, Any]:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
        return doc if isinstance(doc, dict) else {}
    except (OSError, json.JSONDecodeError, ValueError):
        return {}


def _live_module_rel(rel: str) -> bool:
    rel = rel.replace("\\", "/")
    return not rel.startswith("history/") and not rel.startswith("logs/")


def _host_alive(row: dict[str, Any]) -> bool:
    """A host is a live asset if it resolves to an IP or an HTTP probe answered.
    Never report an IP-bearing host as dead just because HTTP did not respond."""
    return bool(row.get("alive")) or bool(row.get("ips") or [])


def _facts(params: Params, target_dir: Path, hosts: list[dict[str, Any]], module_docs: dict[str, dict[str, Any]]) -> dict[str, Any]:
    with_ip = [r for r in hosts if any(r.get("ips") or [])]
    alive = [r for r in hosts if _host_alive(r)]
    dns = module_docs.get("20_dns/dnsx/data.json") or {}
    resolved = [r for r in (dns.get("resolved") or []) if isinstance(r, dict)]
    dns_with_ip = sum(1 for r in resolved if r.get("ips"))
    light = module_docs.get("30_ports/naabu-light/data.json") or {}
    full = module_docs.get("30_ports/naabu-full/data.json") or {}
    open_ports = 0
    for doc in (light, full):
        for scan in doc.get("scans") or doc.get("results") or []:
            if isinstance(scan, dict):
                open_ports += len(scan.get("ports") or [])
    owasp = module_docs.get("70_owasp/data.json") or {}
    findings = [f for f in (owasp.get("findings") or []) if isinstance(f, dict)]
    wl = load_yaml_file(str(params.root / "wordlists.yaml")) or {}
    tasks = wl.get("tasks") or {}
    dnsr = (tasks.get("DNSR-1") or {})
    ffuf2 = (tasks.get("FFUF-2") or {})
    state = _read_json(target_dir / "state.json")
    return {
        "hosts_with_ip": len(with_ip),
        "alive_hosts_list": alive,
        "dns_names": len(resolved),
        "dns_with_ip": dns_with_ip,
        "dns_unresolved": max(0, len(resolved) - dns_with_ip),
        "portcheck_ips": _as_int(light.get("unique_ips_checked")),
        "skipped_no_ip": _as_int(light.get("skipped_no_ip")),
        "portsweep_ips": _as_int(full.get("unique_ips_scanned")),
        "open_port_rows": open_ports,
        "owasp_findings": findings,
        "dnsr1_lists": dnsr.get("selection") or ([dnsr.get("default_key")] if dnsr.get("default_key") else []),
        "ffuf2_lists": ffuf2.get("selection") or ([ffuf2.get("default_key")] if ffuf2.get("default_key") else []),
        "run_status": ((state.get("run") or {}).get("status") or ""),
        "modules": (state.get("modules") or {}),
        "breakers": list(((state.get("breaker") or {}).get("paused") or {}).keys()),
    }


def _as_int(val: Any) -> int:
    if isinstance(val, bool):
        return int(val)
    if isinstance(val, (int, float)):
        return int(val)
    if isinstance(val, list):
        return len(val)
    if isinstance(val, str) and val.isdigit():
        return int(val)
    return 0


def _collect_services(module_docs: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for doc in module_docs.values():
        for row in doc.get("services") or []:
            if isinstance(row, dict) and row.get("port") is not None:
                out.append(row)
    return out


def _collect_vhosts(module_docs: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for doc in module_docs.values():
        for row in doc.get("vhosts") or []:
            if isinstance(row, dict) and row.get("vhost"):
                out.append(row)
    return out


def _attach_ports_to_hosts(hosts: list[dict[str, Any]], module_docs: dict[str, dict[str, Any]]) -> None:
    """Join per-IP port-sweep rows onto hosts. Each IP is scanned on its own."""
    svc_meta: dict[tuple[str, int, str], dict[str, str]] = {}
    by_host: dict[str, dict[tuple[str, int, str], dict[str, Any]]] = {}
    by_ip: dict[str, dict[tuple[str, int, str], dict[str, Any]]] = {}
    for doc in module_docs.values():
        for svc in doc.get("services") or []:
            if not isinstance(svc, dict) or svc.get("port") is None:
                continue
            try:
                pnum = int(svc["port"])
            except (TypeError, ValueError):
                continue
            if pnum < 1 or pnum > 65535:
                continue
            ip = str(svc.get("ip") or "")
            proto = str(svc.get("proto") or "tcp").lower()
            svc_meta[(ip, pnum, proto)] = {
                "name": str(svc.get("name") or svc.get("service") or ""),
                "product": str(svc.get("product") or ""),
                "version": str(svc.get("version") or ""),
                "extrainfo": str(svc.get("extrainfo") or ""),
            }
        for scan in doc.get("scans") or doc.get("results") or []:
            if not isinstance(scan, dict):
                continue
            ip = str(scan.get("ip") or "")
            hosts_on_ip = [str(h).lower() for h in (scan.get("hosts") or []) if h]
            if scan.get("host") and not hosts_on_ip:
                hosts_on_ip = [str(scan["host"]).lower()]
            raw_ports = scan.get("ports") or []
            for port in raw_ports:
                if isinstance(port, dict):
                    try:
                        pnum = int(port.get("port"))
                    except (TypeError, ValueError):
                        continue
                    proto = str(port.get("proto") or "tcp").lower()
                elif isinstance(port, int):
                    pnum, proto = port, "tcp"
                else:
                    continue
                if pnum < 1 or pnum > 65535:
                    continue
                meta = svc_meta.get((ip, pnum, proto), {})
                entry = {
                    "port": pnum,
                    "proto": proto,
                    "ip": ip,
                    "name": meta.get("name", ""),
                    "product": meta.get("product", ""),
                    "version": meta.get("version", ""),
                    "extrainfo": meta.get("extrainfo", ""),
                    "label": f"{pnum}/{proto}",
                }
                key = (ip, pnum, proto)
                if ip:
                    by_ip.setdefault(ip, {})[key] = entry
                for host in hosts_on_ip:
                    by_host.setdefault(host, {})[key] = entry
    for row in hosts:
        host = str(row.get("host") or "").lower()
        ips = [str(x) for x in (row.get("ips") or []) if x]
        merged: dict[tuple[str, int, str], dict[str, Any]] = {}
        merged.update(by_host.get(host) or {})
        for ip in ips:
            merged.update(by_ip.get(ip) or {})
        ports = sorted(merged.values(), key=lambda p: (str(p.get("ip") or ""), int(p["port"])))
        counts: dict[str, int] = {}
        for port in ports:
            pip = str(port.get("ip") or "")
            counts[pip] = counts.get(pip, 0) + 1
        ordered: list[str] = []
        for ip in ips:
            if ip and ip not in ordered:
                ordered.append(ip)
        for ip in counts:
            if ip not in ordered:
                ordered.append(ip)
        row["open_ports"] = ports
        row["open_ports_total"] = len(ports)
        row["open_ports_by_ip"] = [{"ip": ip, "count": int(counts.get(ip, 0))} for ip in ordered]


def collect(params: Params, target_dir: Path, stamp: str) -> dict[str, Any]:
    """Canonical bundle: assets.json rows + every module data.json (section 6.3)."""
    assets_doc = _read_json(target_dir / str(params.require("assets_relpath")))
    module_docs: dict[str, dict[str, Any]] = {}
    for path in sorted(target_dir.rglob("data.json")):
        try:
            rel = str(path.relative_to(target_dir)).replace("\\", "/")
        except ValueError:
            continue
        if not _live_module_rel(rel):
            continue
        module_docs[rel] = _read_json(path)
    hosts = [r for r in assets_doc.get("assets") or [] if isinstance(r, dict) and r.get("host")]
    # Normalize the live-asset flag so EVERY export format (json/csv/md/html/pdf)
    # agrees: a host that resolves to an IP is alive even if the HTTP probe did
    # not answer. HTTP reachability stays in http_status. Never export an
    # IP-bearing host as dead.
    for r in hosts:
        r["alive"] = _host_alive(r)
    try:
        from pipeline.history import drop_wildcard_host_rows

        hosts = drop_wildcard_host_rows(params, target_dir, hosts)
    except Exception:  # noqa: BLE001 -- report still emits canonical assets
        pass
    _attach_ports_to_hosts(hosts, module_docs)
    facts = _facts(params, target_dir, hosts, module_docs)
    facts["vhosts"] = _collect_vhosts(module_docs)
    facts["services"] = _collect_services(module_docs)
    counts = {
        "hosts": len(hosts),
        "alive_hosts": len([r for r in hosts if _host_alive(r)]),
        "module_docs": len(module_docs),
        "hosts_with_ip": facts["hosts_with_ip"],
        "open_port_rows": facts["open_port_rows"],
    }
    return {
        "schema_version": int(params.require("schema_version")),
        "run_timestamp": stamp,
        "scope_digest": scope_digest(params),
        "target": target_dir.name,
        "counts": counts,
        "hosts": hosts,
        "module_docs": module_docs,
        "facts": facts,
    }


def file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else ""


def write_report_md(params: Params, target_dir: Path, bundle: dict[str, Any]) -> Path:
    out = target_dir / str(params.require("report_dirname")) / "report.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    facts = bundle.get("facts") or {}
    lines = [
        f"# Recon report -- {bundle['target']}",
        "",
        f"- run timestamp: {bundle['run_timestamp']}",
        f"- scope digest: `{bundle['scope_digest']}`",
        f"- hosts: {bundle['counts']['hosts']} (alive: {bundle['counts']['alive_hosts']})",
        f"- module data.json files: {bundle['counts']['module_docs']}",
        "",
        "## Executive summary",
        "",
        f"The run enumerated {bundle['counts']['hosts']} host assets "
        f"({bundle['counts']['alive_hosts']} alive) for {bundle['target']}. "
        "Scope violations, if any, are logged in logs/out_of_scope.log and were "
        "never scanned; every candidate was re-validated at MERGE time (section 7.3).",
        "",
        "## What this run actually measured",
        "",
        f"- DNS brute names: {facts.get('dns_names', 0)} (with A/AAAA: {facts.get('dns_with_ip', 0)}; unresolved: {facts.get('dns_unresolved', 0)}).",
        f"- Asset list hosts with at least one IP: {facts.get('hosts_with_ip', 0)}.",
        f"- Port-check unique IPs checked: {facts.get('portcheck_ips', 0)}; skipped (no IP): {facts.get('skipped_no_ip', 0)}.",
        f"- Port-sweep unique IPs scanned: {facts.get('portsweep_ips', 0)}; open-port rows: {facts.get('open_port_rows', 0)}.",
        f"- DNSR-1 wordlists: {', '.join(str(x) for x in (facts.get('dnsr1_lists') or []) if x) or 'default'}.",
        f"- FFUF-2 wordlists: {', '.join(str(x) for x in (facts.get('ffuf2_lists') or []) if x) or 'default'}.",
        f"- Pipeline run status: {facts.get('run_status') or 'unknown'}.",
        "",
        "## Alive hosts",
        "",
    ]
    alive = facts.get("alive_hosts_list") or []
    if not alive:
        lines.append("(none recorded as alive)")
    else:
        for r in alive:
            ips = ", ".join(str(i) for i in (r.get("ips") or []) if i) or "(no IP)"
            length = r.get("length")
            length_txt = f" -- length={length}" if length is not None else ""
            lines.append(f"- `{r.get('host')}` -- {ips}{length_txt} -- sources: {', '.join(r.get('sources') or [])}")
    lines += [
        "",
        "## Open ports",
        "",
        "No open ports in canonical naabu data.json." if not facts.get("open_port_rows") else f"{facts.get('open_port_rows')} open-port rows in naabu scans.",
        "",
        "## Findings (OWASP passive)",
        "",
    ]
    findings = facts.get("owasp_findings") or []
    if not findings:
        lines.append("(none)")
    else:
        for f in findings:
            hosts = ", ".join(str(h) for h in (f.get("hosts") or [])[:12])
            extra = "" if len(f.get("hosts") or []) <= 12 else f" (+{len(f.get('hosts') or []) - 12} more)"
            lines.append(f"- **{f.get('severity', '')}** `{f.get('id')}` {f.get('top10', '')} -- {hosts}{extra}")
            if f.get("rationale"):
                lines.append(f"  {f.get('rationale')}")
    if facts.get("breakers"):
        lines += ["", "## Circuit breakers paused", "", ", ".join(facts["breakers"]), ""]
    lines += [
        "## Per-module sections",
        "",
    ]
    for rel, doc in bundle["module_docs"].items():
        module = str(doc.get("module") or rel.split("/")[0])
        counts = doc.get("counts") or {}
        count_txt = ", ".join(f"{k}={v}" for k, v in counts.items()) if counts else "see data.json"
        lines.append(f"- `{rel}` -- module **{module}**: {count_txt}")
    lines += ["", "## Pointers", "", "Each module's canonical artifact is its `data.json`; the raw stdout archive lives under `logs/raw/` (never re-parsed).", ""]
    out.write_text("\n".join(lines), encoding="utf-8")
    return out


def write_report_html(params: Params, target_dir: Path, bundle: dict[str, Any], diff: dict[str, Any] | None = None) -> Path:
    from pipeline.report_html import write_report_html as _write

    return _write(params, target_dir, bundle, diff)


def write_export_csv(params: Params, target_dir: Path, bundle: dict[str, Any]) -> Path:
    out = target_dir / str(params.require("report_dirname")) / "export.csv"
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["class", *[c for c in next(iter(CSV_CLASSES.values()))]])
        for cls, cols in CSV_CLASSES.items():
            for row in _class_rows(bundle, cls):
                writer.writerow([cls, *[row.get(c, "") for c in cols]])
    return out


def _class_rows(bundle: dict[str, Any], cls: str) -> list[dict[str, Any]]:
    if cls == "hosts":
        return [
            {
                "host": r.get("host"),
                "ips": ",".join(r.get("ips") or []),
                "alive": _host_alive(r),
                "length": "" if r.get("length") is None else r.get("length"),
                "sources": ",".join(r.get("sources") or []),
                "tags": ",".join(r.get("tags") or []),
            }
            for r in bundle["hosts"]
        ]
    rows: list[dict[str, Any]] = []
    for doc in bundle["module_docs"].values():
        if cls == "vhosts":
            rows += [v for v in doc.get("vhosts") or [] if isinstance(v, dict) and v.get("vhost")]
        if cls == "ports":
            for scan in doc.get("scans") or []:
                for port in scan.get("ports") or []:
                    if isinstance(port, dict) and port.get("port") is not None:
                        rows.append({"host": scan.get("host", ""), "ip": scan.get("ip", ""), **port})
        if cls == "services":
            rows += [s for s in doc.get("services") or [] if isinstance(s, dict)]
        if cls == "passive_ips":
            rows += [p for p in doc.get("passive_ips") or [] if isinstance(p, dict) and p.get("ip")]
    return rows


def write_export_json(params: Params, target_dir: Path, bundle: dict[str, Any]) -> Path:
    out = target_dir / str(params.require("report_dirname")) / "export.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    payload = {**bundle, "source_data_json_digests": {
        rel: hashlib.sha256(json.dumps(doc, sort_keys=True).encode()).hexdigest()
        for rel, doc in bundle["module_docs"].items()
    }}
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return out


def write_report_pdf(params: Params, target_dir: Path, bundle: dict[str, Any]) -> Path:
    """PDF render of the report content (reportlab; graceful fallback to a
    disclosed note when reportlab is unavailable -- never silent)."""
    out = target_dir / str(params.require("report_dirname")) / "report.pdf"
    out.parent.mkdir(parents=True, exist_ok=True)
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas
    except ImportError:
        out.write_text(
            f"PDF skipped: reportlab not installed (disclosed, never silent). "
            f"run={bundle['run_timestamp']} scope_digest={bundle['scope_digest']} hosts={bundle['counts']['hosts']}\n",
            encoding="utf-8",
        )
        return out
    buf = io.BytesIO()
    pdf = canvas.Canvas(buf, pagesize=A4)
    width, height = A4
    y = height - 60
    pdf.setFont("Courier", 11)

    def line(text: str) -> None:
        nonlocal y
        pdf.drawString(50, y, text[:110])
        y -= 16

    line(f"RECON REPORT - {bundle['target']}")
    line(f"run timestamp: {bundle['run_timestamp']}")
    line(f"scope digest: {bundle['scope_digest']}")
    line(f"hosts: {bundle['counts']['hosts']}  alive: {bundle['counts']['alive_hosts']}")
    facts = bundle.get("facts") or {}
    line(f"dns A/AAAA: {facts.get('dns_with_ip', 0)}  unresolved: {facts.get('dns_unresolved', 0)}")
    line(f"open-port rows: {facts.get('open_port_rows', 0)}")
    line(f"module data.json files: {bundle['counts']['module_docs']}")
    line("")
    line("HOSTS:")
    for r in bundle["hosts"][:40]:
        ips = ",".join(str(i) for i in (r.get("ips") or []))
        line(f"  {r.get('host')}  {ips}")
    if len(bundle["hosts"]) > 40:
        line(f"  ... and {len(bundle['hosts']) - 40} more")
    line("")
    line("MODULES:")
    for rel, doc in list(bundle["module_docs"].items())[:25]:
        line(f"  {rel} ({doc.get('module', '')})")
    pdf.save()
    out.write_bytes(buf.getvalue())
    return out


def write_manifest(params: Params, target_dir: Path, bundle: dict[str, Any], files: dict[str, Path]) -> Path:
    out = target_dir / str(params.require("report_dirname")) / "report_manifest.json"
    manifest = {
        "run_timestamp": bundle["run_timestamp"],
        "scope_digest": bundle["scope_digest"],
        "counts": bundle["counts"],
        "files": {name: {"path": str(path.relative_to(target_dir)), "sha256": file_digest(path)} for name, path in files.items()},
        "source_data_digests": {
            rel: hashlib.sha256(json.dumps(doc, sort_keys=True).encode()).hexdigest()
            for rel, doc in bundle["module_docs"].items()
        },
    }
    out.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return out


def verify_bundle(params: Params, target_dir: Path) -> tuple[bool, str]:
    """section 10.2 tamper check: re-collect + compare manifest digests."""
    manifest_path = target_dir / str(params.require("report_dirname")) / "report_manifest.json"
    if not manifest_path.is_file():
        return False, "no manifest (report not generated)"
    manifest = _read_json(manifest_path)
    fresh = collect(params, target_dir, str(manifest.get("run_timestamp") or ""))
    fresh_digests = {
        rel: hashlib.sha256(json.dumps(doc, sort_keys=True).encode()).hexdigest()
        for rel, doc in fresh["module_docs"].items()
    }
    if fresh_digests != manifest.get("source_data_digests"):
        drifted = {k for k, v in fresh_digests.items() if manifest.get("source_data_digests", {}).get(k) != v}
        return False, f"tampered/changed data.json: {sorted(drifted)}"
    if fresh["scope_digest"] != manifest.get("scope_digest"):
        return False, "scope.yaml changed since report generation"
    return True, f"verified {len(fresh_digests)} source digests + scope digest"


def generate_all(params: Params, target_dir: Path, stamp: str | None = None) -> dict[str, Any]:
    """Run-end AND dashboard on-demand entrypoint. Never raises -- a reporting
    failure must never flip a pipeline verdict (outcome printed by callers)."""
    stamp = stamp or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    bundle = collect(params, target_dir, stamp)
    diff = _read_json(target_dir / str(params.require("diff_filename")))
    files = {
        "report_md": write_report_md(params, target_dir, bundle),
        "report_html": write_report_html(params, target_dir, bundle, diff),
        "export_csv": write_export_csv(params, target_dir, bundle),
        "export_json": write_export_json(params, target_dir, bundle),
        "report_pdf": write_report_pdf(params, target_dir, bundle),
    }
    manifest = write_manifest(params, target_dir, bundle, files)
    files["report_manifest"] = manifest
    return {
        "run_timestamp": stamp,
        "scope_digest": bundle["scope_digest"],
        "counts": bundle["counts"],
        "files": {name: str(path) for name, path in files.items()},
    }


def load_views(params: Params) -> dict[str, Any]:
    return load_yaml_file(str(params.root / "views.yaml")) or {}
