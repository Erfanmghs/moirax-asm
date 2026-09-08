"""OWASP-PASSIVE -- post-MERGE passive risk analyzer (C6, operator roadmap).

Roadmap item C6 (docs/HANDOVER.md section 13): OWASP Top 10 (2021) + OWASP
API Top 10 (2023) passive check modules. This module is that deliverable for
BOTH lists in ONE artifact-driven analyzer.

ZERO-PACKET LAW: the module performs file analysis ONLY. It never issues a
tool call, never touches the adapter, never sends anything to the target.
Every finding is derived from artifacts already collected by earlier stages
(httpx probe raw rows, assets.json, port data). A MagicMock adapter passed
in must observe ZERO method calls -- that is a tested contract, not prose.

HONESTY LAWS:
- Passive evidence can surface risk, never prove exploitability. Severity is
  CAPPED at medium; every finding carries review_required=true and cites the
  exact evidence file. No finding may claim "vulnerable" -- the wording is
  "passive evidence suggests review".
- Coverage is disclosed both ways: OWASP items with passive evidence are
  listed under coverage.assessed; items that CANNOT be assessed from passive
  artifacts alone (injection classes, rate limiting, auth flows, ...) are
  listed under coverage.not_passively_assessable with a plain-language
  reason. Silence is forbidden.

EVIDENCE SOURCES (all optional, all disclosed when missing):
- assets.json            -- merged assets: alive flags, OSINT keyword tags,
                            misconfig_suspect (wildcard/catch-all suspects)
- 10_subdomains/passive/sources/httpx.json -- raw JSONL probe rows:
                            host, scheme, port, status_code, title, tech,
                            webserver, content_type (data already fetched by
                            PSV-6; storing it costs ZERO extra packets)
- 30_ports/.../data.json -- open ports per IP with attributed hosts
                            (PORT-CHECK light + PORT-SWEEP full)

FINDING CLASSES (evidence -> OWASP mapping):
1. server banner disclosure          -> A05:2021 (also API8:2023)   low
2. misconfig_suspect assets          -> A05:2021                   low
3. management/admin ports open       -> A05:2021 (also API8:2023)  medium
4. cleartext http exposure           -> A02:2021                   low
5. versioned technology strings      -> A06:2021                   info
6. api-named surface                 -> API3:2023 (also API1:2023) info
7. admin/dev-named surface           -> A01:2021 (also API6:2023)  info

Output: 70_owasp/data.json + 70_owasp/summary.md (summary is operator-
readable; report/dashboard integration reads data.json like every module).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pipeline.jsonio import read_json, write_json
from pipeline.textio import atomic_write_text

# Fixed severity ceiling for passive-only evidence (honesty law above).
_MAX_SEVERITY = "medium"
_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2}

_TOP10_2021 = {
    "A01": "A01:2021 Broken Access Control",
    "A02": "A02:2021 Cryptographic Failures",
    "A05": "A05:2021 Security Misconfiguration",
    "A06": "A06:2021 Vulnerable and Outdated Components",
    "A08": "A08:2021 Software and Data Integrity Failures",
    "A09": "A09:2021 Security Logging and Monitoring Failures",
    "A10": "A10:2021 Server-Side Request Forgery",
    "A03": "A03:2021 Injection",
    "A04": "A04:2021 Insecure Design",
    "A07": "A07:2021 Identification and Authentication Failures",
}
_API_TOP10_2023 = {
    "API1": "API1:2023 Broken Object Level Authorization",
    "API2": "API2:2023 Broken Authentication",
    "API3": "API3:2023 Broken Object Property Level Authorization",
    "API4": "API4:2023 Unrestricted Resource Consumption",
    "API5": "API5:2023 Broken Function Level Authorization",
    "API6": "API6:2023 Unlimited Access to Sensitive Business Flows",
    "API7": "API7:2023 Server Side Security Misconfiguration",
    "API8": "API8:2023 Security Misconfiguration",
    "API9": "API9:2023 Improper Inventory Management",
    "API10": "API10:2023 Unsafe Consumption of APIs",
}

# OWASP items that CANNOT produce findings from passive artifacts alone.
_NOT_PASSIVELY_ASSESSABLE = [
    ("A03:2021 Injection", "proves only with active payloads; passive artifacts carry no injection probes"),
    ("A04:2021 Insecure Design", "requires business-flow review, not artifact observation"),
    ("A07:2021 Identification and Authentication Failures", "requires active auth-flow interaction"),
    ("A08:2021 Software and Data Integrity Failures", "requires supply-chain metadata not collected passively"),
    ("A09:2021 Security Logging and Monitoring Failures", "requires log-response testing; invisible from outside"),
    ("A10:2021 Server-Side Request Forgery", "proves only with active SSRF probes"),
    ("API2:2023 Broken Authentication", "requires active token/credential probing"),
    ("API4:2023 Unrestricted Resource Consumption", "requires measured rate/response behavior over time"),
    ("API5:2023 Broken Function Level Authorization", "requires privileged-vs-unprivileged active comparison"),
    ("API6:2023 Unlimited Access to Sensitive Business Flows", "requires flow automation testing; admin-named hosts are surfaced as a review surface instead"),
    ("API7:2023 Server Side Security Misconfiguration", "passive banner/tech evidence is collected under A05/A06 of the 2021 list"),
    ("API9:2023 Improper Inventory Management", "partially served by the api/admin surface inventories; full version inventory needs active route probing"),
    ("API10:2023 Unsafe Consumption of APIs", "requires third-party API interaction analysis"),
]


def run_owasp_passive(
    params: Any,
    gate: Any,
    adapter: Any,
    target_dir: Path,
    target: str,
    extra: dict[str, Any],
    planned: int,
    timeout_sec: float | None,
    partial: list[str],
) -> dict[str, Any]:
    """Analyze stored artifacts and emit 70_owasp/data.json + summary.md.

    Same runner signature as every RUNNERS entry. Returns the module document
    (the post-merge hook ignores the return value; tests use it directly).
    """
    del extra, planned, timeout_sec  # passive-only: no tool budget is ever spent

    assets = _load_assets(params, target_dir)
    probe_rows = _load_probe_rows(params, target_dir)
    port_rows = _load_port_rows(params, target_dir)

    findings: list[dict[str, Any]] = []
    evidence: dict[str, str] = {}

    assets_rel = str(params.require("assets_relpath"))
    probe_rel = str(params.require("passive_sources_relpath")) + "/httpx.json"
    port_rel = str(params.require("portcheck_data_json"))
    sweep_rel = str(params.require("portsweep_data_json"))

    # 1) server banner disclosure -> A05:2021
    banner_hosts = sorted({row["host"] for row in probe_rows if row["webserver"]})
    if banner_hosts:
        evidence[probe_rel] = probe_rel
        findings.append(_finding(
            "A05", ("API8",), "low", banner_hosts,
            "HTTP server software is disclosed by probe responses (webserver field). "
            "Attackers use banners to target known flaws; consider suppressing or "
            "normalizing server headers.",
            [probe_rel],
        ))

    # 2) platform-flagged misconfig suspects -> A05:2021
    suspect_hosts = sorted({a["host"] for a in assets if a.get("misconfig_suspect")})
    if suspect_hosts:
        evidence[assets_rel] = assets_rel
        findings.append(_finding(
            "A05", (), "low", suspect_hosts,
            "MERGE flagged these hosts as wildcard/catch-all suspects "
            "(misconfig_suspect). DNS misconfiguration is a classic takeover and "
            "misroute primitive; review the wildcard/catch-all ruling.",
            [assets_rel],
        ))

    # 3) management/admin service ports -> A05:2021 (API8 lens included)
    risk_ports = _parse_ports(str(params.require("owasp_risk_ports")))
    mgmt_hosts = _hosts_with_ports(port_rows, risk_ports)
    if mgmt_hosts:
        evidence[port_rel] = port_rel
        evidence[sweep_rel] = sweep_rel
        findings.append(_finding(
            "A05", ("API8",), "medium", mgmt_hosts,
            "Management/datastore service ports are reachable from scan evidence "
            "(databases, caches, orchestration, admin consoles). If these are "
            "internet-reachable unintentionally, restrict with firewall rules.",
            [port_rel, sweep_rel],
        ))

    # 4) cleartext http exposure -> A02:2021
    cleartext_hosts = sorted({row["host"] for row in probe_rows if row["scheme"] == "http"})
    if cleartext_hosts:
        evidence[probe_rel] = probe_rel
        findings.append(_finding(
            "A02", (), "low", cleartext_hosts,
            "Probe evidence shows cleartext http:// exposure. Transport encryption "
            "failures expose sessions and payloads; review TLS termination and "
            "http->https redirection.",
            [probe_rel],
        ))

    # 5) versioned technology strings -> A06:2021
    versioned = sorted({row["host"] for row in probe_rows if row["tech_versions"]})
    if versioned:
        evidence[probe_rel] = probe_rel
        findings.append(_finding(
            "A06", (), "info", versioned,
            "Probe evidence carries versioned technology identifiers. Versioned "
            "components let attackers match public CVEs; verify patch levels and "
            "hide versions where possible.",
            [probe_rel],
        ))

    # 6) api-named surface -> API3:2023 (API1 review lens)
    api_words = _parse_words(str(params.require("owasp_api_words")))
    api_hosts = sorted(set(_hosts_by_word(assets, probe_rows, api_words)))
    if api_hosts:
        evidence[assets_rel] = assets_rel
        evidence[probe_rel] = probe_rel
        findings.append(_finding(
            "API3", ("API1",), "info", api_hosts,
            "Host/title/tag evidence suggests an API surface (api/rest/graphql/"
            "swagger naming). Inventory it and verify object-level authorization "
            "before exposure grows.",
            [assets_rel, probe_rel],
        ))

    # 7) admin/dev-named surface -> A01:2021 (API6 review lens)
    admin_words = _parse_words(str(params.require("owasp_admin_words")))
    admin_hosts = sorted(set(_hosts_by_word(assets, probe_rows, admin_words)) - set(api_hosts))
    if admin_hosts:
        evidence[assets_rel] = assets_rel
        findings.append(_finding(
            "A01", ("API6",), "info", admin_hosts,
            "OSINT tags or host naming suggest admin/dev/staging surfaces "
            "(discovered from public sources; never probed). Such hosts often "
            "lack hardening; verify access control and business-flow exposure.",
            [assets_rel],
        ))

    doc = {
        "schema_version": int(params.require("schema_version")),
        "module": "owasp-passive",
        "target": target,
        "passive_only": True,
        "severity_ceiling": _MAX_SEVERITY,
        "findings": findings,
        "coverage": {
            "assessed": sorted({f["top10"] for f in findings}
                               | {t for f in findings for t in f["also_maps"]}),
            "not_passively_assessable": [
                {"item": item, "reason": reason} for item, reason in _NOT_PASSIVELY_ASSESSABLE
            ],
        },
        "evidence_files": sorted(evidence),
        "sources_scanned": {
            "assets_hosts": len(assets),
            "probe_rows": len(probe_rows),
            "port_results": len(port_rows),
        },
        "counts": _counts(findings),
    }
    out_path = target_dir / str(params.require("owasp_data_json"))
    out_path.parent.mkdir(parents=True, exist_ok=True)
    write_json(out_path, doc)
    summary_path = target_dir / str(params.require("owasp_summary"))
    atomic_write_text(summary_path, _summary_md(doc, _TOP10_2021, _API_TOP10_2023))
    print(
        f"owasp-passive: findings={len(findings)} "
        f"hosts={len({h for f in findings for h in f['hosts']})} "
        f"evidence={len(evidence)} (passive-only, zero packets)"
    )
    return doc


def _finding(top10_id: str, also: tuple[str, ...], severity: str, hosts: list[str],
             rationale: str, evidence_files: list[str]) -> dict[str, Any]:
    if _SEVERITY_ORDER[severity] > _SEVERITY_ORDER[_MAX_SEVERITY]:
        raise ValueError("passive-only severity ceiling violated")
    return {
        "id": f"OWASP-{top10_id}-{abs(hash((top10_id, tuple(hosts)))) % 100000:05d}",
        "top10": _TOP10_2021.get(top10_id, _API_TOP10_2023.get(top10_id, top10_id)),
        "also_maps": [_API_TOP10_2023[a] for a in also if a in _API_TOP10_2023],
        "severity": severity,
        "hosts": hosts,
        "evidence": evidence_files,
        "rationale": rationale,
        "review_required": True,
        "passive_only": True,
    }


def _counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {level: 0 for level in ("high", "medium", "low", "info")}
    counts["high"] = 0  # honesty law: passive evidence never claims high
    for f in findings:
        counts[f["severity"]] += 1
    counts["findings"] = len(findings)
    counts["hosts"] = len({h for f in findings for h in f["hosts"]})
    return counts


def _load_assets(params: Any, target_dir: Path) -> list[dict[str, Any]]:
    path = target_dir / str(params.require("assets_relpath"))
    if not path.is_file():
        return []
    try:
        doc = read_json(path)
    except (ValueError, OSError):
        return []
    return [a for a in (doc.get("assets") or []) if isinstance(a, dict) and a.get("host")]


def _load_probe_rows(params: Any, target_dir: Path) -> list[dict[str, Any]]:
    rel = str(params.require("passive_sources_relpath")) + "/httpx.json"
    path = target_dir / rel
    if not path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if not isinstance(row, dict):
            continue
        host = str(row.get("host") or row.get("input") or "").strip().lower().rstrip(".")
        if not host:
            continue
        tech = row.get("tech") or []
        if isinstance(tech, str):
            tech = [tech]
        tech = [str(t) for t in tech if str(t).strip()]
        rows.append({
            "host": host,
            "scheme": str(row.get("scheme") or "").strip().lower(),
            "webserver": str(row.get("webserver") or "").strip(),
            "title": str(row.get("title") or "").strip().lower(),
            "tech": tech,
            "tech_versions": [t for t in tech if _has_version(t)],
        })
    return rows


def _load_port_rows(params: Any, target_dir: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for key in ("portcheck_data_json", "portsweep_data_json"):
        path = target_dir / str(params.require(key))
        if not path.is_file():
            continue
        try:
            doc = read_json(path)
        except (ValueError, OSError):
            continue
        for res in doc.get("results") or []:
            if not isinstance(res, dict):
                continue
            open_ports: list[int] = []
            for p in res.get("ports") or []:
                if isinstance(p, dict) and p.get("state") == "open" and p.get("port"):
                    try:
                        open_ports.append(int(p["port"]))
                    except (TypeError, ValueError):
                        continue
            if open_ports:
                rows.append({"hosts": [str(h).lower() for h in res.get("hosts") or []],
                             "ports": open_ports})
    return rows


def _hosts_with_ports(port_rows: list[dict[str, Any]], risk_ports: set[int]) -> list[str]:
    hosts: set[str] = set()
    for row in port_rows:
        hit = risk_ports.intersection(row["ports"])
        if hit:
            hosts.update(row["hosts"])
    return sorted(hosts)


def _hosts_by_word(assets: list[dict[str, Any]], probe_rows: list[dict[str, Any]],
                   words: set[str]) -> list[str]:
    hosts: set[str] = set()
    for a in assets:
        blob = " ".join([str(a.get("host") or "")] + [str(t) for t in a.get("tags") or []]).lower()
        if any(w in blob for w in words):
            hosts.add(str(a.get("host")).lower())
    for row in probe_rows:
        blob = " ".join([row["host"], row["title"], " ".join(row["tech"])]).lower()
        if any(w in blob for w in words):
            hosts.add(row["host"])
    return sorted(hosts)


def _has_version(text: str) -> bool:
    digits = "".join(ch for ch in text if ch.isdigit())
    return len(digits) >= 2 and any(ch.isdigit() for ch in text)


def _parse_ports(raw: str) -> set[int]:
    ports: set[int] = set()
    for chunk in raw.replace(" ", "").split(","):
        if not chunk:
            continue
        try:
            ports.add(int(chunk))
        except ValueError:
            continue
    return ports


def _parse_words(raw: str) -> set[str]:
    return {w.strip().lower() for w in raw.split(",") if w.strip()}


def _summary_md(doc: dict[str, Any], top10: dict[str, str], api_top10: dict[str, str]) -> str:
    lines: list[str] = []
    lines.append("# OWASP passive analysis (C6)")
    lines.append("")
    lines.append(
        f"Target `{doc['target']}` -- PASSIVE-ONLY analysis of stored artifacts. "
        "Zero packets were sent to the target. Every finding needs human review; "
        "severity is capped at medium by law."
    )
    lines.append("")
    lines.append(f"Findings: {doc['counts']['findings']} | hosts with findings: {doc['counts']['hosts']}")
    lines.append("")
    if doc["findings"]:
        lines.append("| Finding | Severity | Hosts | Review |")
        lines.append("|---------|----------|-------|--------|")
        for f in doc["findings"]:
            mapped = f["top10"] + (f" (+{', '.join(f['also_maps'])})" if f["also_maps"] else "")
            lines.append(
                f"| {mapped} | {f['severity']} | {', '.join(f['hosts'][:8])}"
                f"{' ...' if len(f['hosts']) > 8 else ''} | {', '.join(f['evidence'])} |"
            )
    else:
        lines.append("No passive-evidence findings from the artifacts of this run.")
    lines.append("")
    lines.append("## Coverage disclosure")
    lines.append("")
    lines.append("Assessed from passive evidence: " + (", ".join(doc["coverage"]["assessed"]) or "none"))
    lines.append("")
    lines.append("Not passively assessable (needs active/flow testing, never silently skipped):")
    lines.append("")
    for item in doc["coverage"]["not_passively_assessable"]:
        lines.append(f"- {item['item']}: {item['reason']}")
    lines.append("")
    lines.append("Reference lists: OWASP Top 10 (2021), OWASP API Top 10 (2023).")
    return "\n".join(lines) + "\n"
