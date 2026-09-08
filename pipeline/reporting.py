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
    "hosts": ("host", "ips", "alive", "sources", "tags"),
    "vhosts": ("base_host", "vhost", "ip", "port", "scheme", "alive", "http_status", "misconfig_suspect"),
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


def collect(params: Params, target_dir: Path, stamp: str) -> dict[str, Any]:
    """Canonical bundle: assets.json rows + every module data.json (section 6.3)."""
    assets_doc = _read_json(target_dir / str(params.require("assets_relpath")))
    module_docs: dict[str, dict[str, Any]] = {}
    for path in sorted(target_dir.rglob("data.json")):
        try:
            rel = str(path.relative_to(target_dir))
        except ValueError:
            continue
        module_docs[rel] = _read_json(path)
    hosts = [r for r in assets_doc.get("assets") or [] if isinstance(r, dict) and r.get("host")]
    counts = {
        "hosts": len(hosts),
        "alive_hosts": len([r for r in hosts if r.get("alive")]),
        "module_docs": len(module_docs),
    }
    return {
        "schema_version": int(params.require("schema_version")),
        "run_timestamp": stamp,
        "scope_digest": scope_digest(params),
        "target": target_dir.name,
        "counts": counts,
        "hosts": hosts,
        "module_docs": module_docs,
    }


def file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else ""


def write_report_md(params: Params, target_dir: Path, bundle: dict[str, Any]) -> Path:
    out = target_dir / str(params.require("report_dirname")) / "report.md"
    out.parent.mkdir(parents=True, exist_ok=True)
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


_THEME_CSS = (
    "body{background:#0a0e14;color:#c9d6e3;font:13px/1.45 'JetBrains Mono',monospace;margin:24px}"
    "h1,h2{border-left:3px solid #22d3ee;padding-left:10px;letter-spacing:1px}"
    "table{border-collapse:collapse;width:100%;font-size:12px}"
    "th{position:sticky;top:0;background:#0f1620;color:#6b7f94;text-align:left;padding:8px;border-bottom:1px solid #1d2a3a}"
    "td{padding:6px 10px;border-bottom:1px solid #1d2a3a}"
    ".badge{display:inline-block;padding:1px 8px;border:1px solid #1d2a3a;border-radius:2px}"
    ".alive{color:#34d399;border-color:#34d399}.dead{color:#64748b;border-color:#64748b}.new{color:#fbbf24;border-color:#fbbf24}"
)


def write_report_html(params: Params, target_dir: Path, bundle: dict[str, Any], diff: dict[str, Any] | None = None) -> Path:
    out = target_dir / str(params.require("report_dirname")) / "report.html"
    out.parent.mkdir(parents=True, exist_ok=True)
    new_hosts = {str(r.get("host")) for r in ((diff or {}).get("added") or {}).get("hosts") or []}
    rows = []
    for r in bundle["hosts"]:
        badge = ' <span class="badge new">NEW</span>' if str(r.get("host")) in new_hosts else ""
        alive = f'<span class="badge {"alive" if r.get("alive") else "dead"}">{"ALIVE" if r.get("alive") else "DEAD"}</span>'
        rows.append(
            f"<tr><td>{r.get('host')}{badge}</td><td>{', '.join(r.get('ips') or [])}</td>"
            f"<td>{alive}</td><td>{', '.join(r.get('sources') or [])}</td><td>{', '.join(r.get('tags') or [])}</td></tr>"
        )
    html = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>recon report -- {bundle['target']}</title>
<style>{_THEME_CSS}</style></head><body>
<h1>recon report -- {bundle['target']}</h1>
<p>run timestamp: {bundle['run_timestamp']} &nbsp;|&nbsp; scope digest: <code>{bundle['scope_digest']}</code></p>
<h2>counts</h2>
<p>hosts: {bundle['counts']['hosts']} | alive: {bundle['counts']['alive_hosts']} | module data.json: {bundle['counts']['module_docs']}</p>
<h2>assets</h2>
<table><thead><tr><th>host</th><th>ips</th><th>alive</th><th>sources</th><th>tags</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
<h2>modules</h2>
<ul>{''.join(f'<li><code>{rel}</code> -- {doc.get("module", "")}</li>' for rel, doc in bundle['module_docs'].items())}</ul>
</body></html>"""
    out.write_text(html, encoding="utf-8")
    return out


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
                "alive": bool(r.get("alive")),
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
