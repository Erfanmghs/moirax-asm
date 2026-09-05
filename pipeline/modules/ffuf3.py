"""FFUF-3 — POST-DNSR VHOST PASS (spec v1.9 §8 FFUF-3, approved Option-1 item 1).

Production path for the vhost-misconfiguration class on DNS-DEAD names.
The frozen FFUF-2 flag-time DNS cross-check is impossible by the APPEND-ONLY
order law (FFUF order 1 finishes before DNS-RESOLVE order 2) — B2 proved the
machinery via the vhost fixture (TEST 2); this module is the production
implementation, implemented at B3 start (§8.2 next-phase rule).

Semantics (exactly as specified, v1.9):
- BASE-HOST SET (exact): FFUF-1 completed enum records UNION DNSR-3 hosts
  with resolution_status "unresolved". Both inputs are logged with counts
  before any probe.
- PROBE BINDING: -u is bound to an ALIVE in-scope base (a host with a
  resolved IP that answers HTTP — e.g. apex/www from the same target) with
  "Host: FUZZ.<dead-name>"; the dead name is never resolved directly. If no
  alive base exists for the target, the pass is SKIPPED with an explicit log
  line (never silent).
- FLAG RULE: misconfig_suspect true IFF DNS-dead(name) AND a NON-FILTERED
  answer — i.e. the response survives the REM4-R1 calibration-drop
  discipline (_wordlist_fuzz_label: the recovered label must be in the job
  wordlist). Filtered answers are logged as suppressed, never flagged.
  dns_status "dead" is inherited from the base-host-set entry's DNSR-3
  record (the probed name is never DNS-queried).
- ASSET-PROMOTION RULING (v1.9 item 2): misconfig_suspect is an ORTHOGONAL
  FLAG, never an alive signal — rows carry alive: null and are never
  promoted; MERGE passthrough carries the flag verbatim (acceptance-tested).
- Output schema (data.json): {"schema_version":1,"module":"ffuf-3",
  "vhosts":[{"base_host","vhost","alive":null,"http_status","length",
  "misconfig_suspect":true,"dns_status":"dead"}],
  "bases":[{"host","ip","alive"}],"suppressed":0}
- Output path: recon/<target>/15_vhosts/ffuf-3/ (never collides with FFUF-2).
- Caps: load flags mirror the FFUF-2 baseline; circuit breaker (§11.4) +
  resource ceiling (§11.5) apply via the shared adapter.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pipeline.adapter import Adapter
from pipeline.hostsutil import container_path, normalize_fqdn
from pipeline.jsonio import read_json, write_json
from pipeline.modules.ffuf import _ffuf_hits, _safe, _wordlist_fuzz_label
from pipeline.params import Params
from pipeline.scope import ScopeGate
from pipeline.textio import atomic_write_text
from pipeline.wordlist_forge import copy_into_target, materialize_effective


def run_ffuf3(
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
    ffuf_doc = _load_doc(target_dir / str(params.require("ffuf_data_json")))
    dnsr_doc = _load_doc(target_dir / str(params.require("dnsr_data_json")))

    ffuf1_records = _ffuf1_records(ffuf_doc)
    dnsr_status = _dnsr_status(dnsr_doc)
    unresolved = _dnsr_unresolved(dnsr_doc, gate, target_dir)

    base_set = sorted(set(ffuf1_records) | set(unresolved))
    dead_names = [name for name in base_set if dnsr_status.get(name) == "unresolved"]
    counts = {
        "ffuf1_records": len(ffuf1_records),
        "dnsr_unresolved": len(unresolved),
        "union": len(base_set),
        "dead_probed": len(dead_names),
    }

    bases = _alive_bases(ffuf_doc, dnsr_doc, gate, target_dir, target)
    _note(params, target_dir, f"ffuf-3 inputs: {counts} bases={[(b['host'], b['ip']) for b in bases]}")

    vhosts: list[dict[str, Any]] = []
    suppressed = 0
    request_count = 0
    max_req = int(params.require("max_total_requests"))
    skipped_reason: str | None = None

    if not bases:
        skipped_reason = "no_alive_base"
        _note(params, target_dir, "ffuf-3 skipped: no alive in-scope base with a resolved IP — pass SKIPPED, never silent")
    elif not dead_names:
        skipped_reason = "no_dns_dead_names"
        _note(params, target_dir, "ffuf-3 skipped: no DNS-dead names in the base-host set — nothing to probe")

    if skipped_reason is None:
        binding = bases[0]
        vhost_src = materialize_effective(params, "FFUF-2")
        v_rel = str(params.require("ffuf_vhost_wordlist_rel"))
        copy_into_target(params, target_dir, vhost_src, v_rel)
        v_c = container_path(params, target, v_rel)
        allowed_vhost = _labels_in(vhost_src)
        v_n = len(allowed_vhost)
        base_url = f"http://{binding['host']}"
        for dead in dead_names:
            if request_count + v_n > max_req:
                partial.append("max_total_requests")
                break
            out_rel = f"15_vhosts/ffuf-3/raw_{_safe(dead)}.json"
            result = adapter.invoke(
                "ffuf-vhost",
                module="ffuf-3",
                extra={
                    **extra,
                    "ffuf_url": base_url,
                    "ffuf_wordlist": v_c,
                    "ffuf_host_header": f"Host: FUZZ.{dead}",
                    "ffuf_output": container_path(params, target, out_rel),
                    "output_raw_dir": f"logs/raw/ffuf-3/{_safe(dead)}",
                    "skip_parse": True,
                    "ffuf_mode": "vhost",
                },
                planned_concurrency=planned,
                timeout_sec=timeout_sec,
            )
            request_count += v_n
            for hit in _ffuf_hits(target_dir / out_rel, result):
                # REM4-R1 calibration-drop discipline: a filtered/wildcard/
                # autocalib artifact never recovers a wordlist label -> it is
                # counted as suppressed and NEVER flagged.
                label = _wordlist_fuzz_label(hit, dead, allowed_vhost)
                if not label:
                    suppressed += 1
                    continue
                vhost = normalize_fqdn(f"{label}.{dead}")
                if not vhost:
                    suppressed += 1
                    continue
                if not gate.enforce(target_dir, vhost):
                    suppressed += 1
                    continue
                vhosts.append(
                    {
                        "base_host": dead,
                        "vhost": vhost,
                        "alive": None,
                        "http_status": hit.get("status"),
                        "length": hit.get("length"),
                        "misconfig_suspect": True,
                        "dns_status": "dead",
                    }
                )

    payload = {
        "schema_version": int(params.require("schema_version")),
        "module": "ffuf-3",
        "vhosts": vhosts,
        "bases": bases,
        "suppressed": suppressed,
    }
    data_path = target_dir / str(params.require("ffuf3_data_json"))
    write_json(data_path, payload)
    summary = target_dir / str(params.require("ffuf3_summary"))
    summary.parent.mkdir(parents=True, exist_ok=True)
    counts_line = " ".join(f"{k}={v}" for k, v in counts.items())
    summary.write_text(
        "\n".join(
            [
                "# ffuf-3 (post-DNSR vhost pass)",
                "",
                f"inputs: {counts_line}",
                f"bases: {len(bases)}",
                f"vhosts_flagged: {len(vhosts)}",
                f"suppressed: {suppressed}",
                f"requests: {request_count}",
                f"skipped: {skipped_reason or 'none'}",
                f"partial: {', '.join(partial) if partial else 'none'}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return payload


def _ffuf1_records(doc: dict[str, Any] | None) -> list[str]:
    """FFUF-1 completed enum records: every fqdn row of the ffuf module doc."""
    if not doc:
        return []
    found: list[str] = []
    for row in doc.get("hosts") or []:
        if isinstance(row, dict) and row.get("fqdn"):
            found.append(str(row["fqdn"]).lower())
    return found


def _dnsr_status(doc: dict[str, Any] | None) -> dict[str, str]:
    if not doc:
        return {}
    out: dict[str, str] = {}
    for row in doc.get("resolved") or []:
        if isinstance(row, dict) and row.get("host"):
            out[str(row["host"]).lower()] = str(row.get("resolution_status") or "")
    return out


def _dnsr_unresolved(doc: dict[str, Any] | None, gate: ScopeGate, target_dir: Path) -> list[str]:
    if not doc:
        return []
    found: list[str] = []
    for row in doc.get("resolved") or []:
        if not isinstance(row, dict):
            continue
        if row.get("resolution_status") != "unresolved":
            continue
        host = normalize_fqdn(str(row.get("host") or ""))
        if not host or not gate.enforce(target_dir, host):
            continue
        found.append(host)
    return sorted(set(found))


def _alive_bases(
    ffuf_doc: dict[str, Any] | None,
    dnsr_doc: dict[str, Any] | None,
    gate: ScopeGate,
    target_dir: Path,
    target: str,
) -> list[dict[str, Any]]:
    """ALIVE in-scope bases: FFUF-1 httpx alive=true AND DNSR-3 resolved IP.

    Deterministic order: the target apex first (when it qualifies), then the
    remaining candidates alphabetically. bases[0] is the binding base.
    """
    alive_ffuf: set[str] = set()
    if ffuf_doc:
        for row in ffuf_doc.get("hosts") or []:
            if isinstance(row, dict) and row.get("alive") is True and row.get("fqdn"):
                alive_ffuf.add(str(row["fqdn"]).lower())
    bases: list[dict[str, Any]] = []
    if not dnsr_doc:
        return bases
    for row in dnsr_doc.get("resolved") or []:
        if not isinstance(row, dict):
            continue
        host = normalize_fqdn(str(row.get("host") or ""))
        if not host or host not in alive_ffuf:
            continue
        if not gate.enforce(target_dir, host):
            continue
        ips = row.get("ips") or []
        if not ips:
            continue
        bases.append({"host": host, "ip": str(ips[0]), "alive": True})
    bases.sort(key=lambda b: b["host"])
    apex = normalize_fqdn(target) or target.lower()
    apex_first = [b for b in bases if b["host"] == apex]
    rest = [b for b in bases if b["host"] != apex]
    return apex_first + rest


def _load_doc(path: Path) -> dict[str, Any] | None:
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
        handle.write(f"{stamp}\tffuf-3\t-\t0\tok\t{detail}\n")
