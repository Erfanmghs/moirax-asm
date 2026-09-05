"""TEST 3 (REAL-TARGET, T3) post-run acceptance table.

Reads the live tree under recon/example.com/ after `recon.sh run example.com`
and emits the assertion table + final verdict line. Exit 0 iff every
MANDATORY assertion holds; DISCLOSURE rows never fail the run.

Table (ID / kind / expectation):
  B1 MANDATORY  run completes: runs.json last entry status == completed
  B2 MANDATORY  live-tree freshness (T3-1 fix proof): brute chunk outputs are
                fresh (mtime + every row timestamp >= dns-resolve started_at)
                AND brute-chunk host set is a subset of the smoke candidate
                set (the 4860-host dns_fast_top5000-era residual is GONE);
                secondary dnsx outputs fresh by timestamp
  B3 MANDATORY  host->IP map: target-set.txt lines are ip<TAB>host[,host...],
                unique-ip count matches, and every (ip, host) pair is
                consistent with dnsr data.json resolved rows
  B4 MANDATORY  one-naabu-per-IP: run.log naabu-invoke ip= lines ==
                unique_ips_checked, invoked IP set == target-set IP set,
                zero duplicate per-IP invocations
  B5 MANDATORY  dedup evidence: duplicates_skipped >= 1 and >=1 target-set
                IP line carries >= 2 hosts (apex + www share IPs)
  B6 MANDATORY  output schema: portcheck data.json results[] rows conform to
                {ip, hosts[], ports[]}, ports rows {port, proto, state=open}
  B7 MANDATORY  forge POST sha == anchor AND verify_b1 clean (GROWTH-0 belt)
  B8 MANDATORY  MERGE composition disclosure line present in 00_assets/summary.md
                (T3-1 disclosure shipped into the run)
  B9 DISCLOSURE T3-0 pre-run residual dissection evidence (ci/test3_dissection.json)
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

TARGET_DIR = ROOT / "recon" / "example.com"
DNS_DIR = TARGET_DIR / "20_dns" / "dnsx"
PORT_DIR = TARGET_DIR / "30_ports" / "naabu-light"
ANCHOR = "7ee5fd817b2f2581df41397d0d0a7ce9e8545b5cb3a91d1171e9b7af15979d3d"

failures: list[str] = []
rows: list[tuple[str, str, str, str]] = []


def row(aid: str, kind: str, ok: bool, detail: str) -> None:
    verdict = "PASS" if ok else ("FAIL" if kind == "MANDATORY" else "DISCLOSED")
    rows.append((aid, kind, verdict, detail))
    print(f"{verdict}\t{aid}\t{detail}")
    if not ok and kind == "MANDATORY":
        failures.append(aid)


def load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def load_ndjson(path: Path) -> list[dict]:
    """dnsx tool outputs (chunk files, resolve-all, wildcard-probe) are NDJSON:
    one JSON object per line. json.loads on the whole file fails -> always
    parse line-by-line."""
    rows: list[dict] = []
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(rec, dict):
                rows.append(rec)
    except OSError:
        return []
    return rows


_TOLERANCE = timedelta(seconds=5)


def _parse_ts(val) -> datetime | None:
    try:
        return datetime.fromisoformat(str(val).replace("Z", "+00:00")).astimezone(timezone.utc)
    except Exception:
        return None


def _smoke_candidates() -> set[str]:
    path = ROOT / "wordlists" / "local" / "test-smoke-200.txt"
    out: set[str] = set()
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                out.add(f"{line.lower()}.example.com")
    return out


def main() -> int:
    state = load_json(TARGET_DIR / "state.json") or {}
    modules = state.get("modules") or {}
    dns_row = modules.get("dns-resolve") or {}
    started = _parse_ts(dns_row.get("started_at"))

    # B1 run completion
    runs = load_json(TARGET_DIR / "runs.json") or {}
    entries = runs.get("runs") or []
    last = entries[-1] if entries else {}
    row("B1", "MANDATORY", last.get("status") == "completed",
        f"runs.json[{len(entries) - 1}].status={last.get('status')} ts={last.get('timestamp')}")

    # B2 live-tree freshness (T3-1 proof)
    smoke = _smoke_candidates()
    brute_files = sorted(DNS_DIR.glob("brute_chunk_*.json"))
    secondary = sorted(DNS_DIR.glob("perm_chunk_*.json")) + [
        DNS_DIR / "resolve-all.json", DNS_DIR / "wildcard-probe.json"]
    secondary = [p for p in secondary if p.is_file()]
    details: list[str] = []
    b2_ok = bool(brute_files) and started is not None
    if not brute_files:
        details.append("no brute chunk outputs")
    if started is None:
        b2_ok = False
        details.append("dns-resolve started_at missing -> evidence STALE")
    residual_hosts: set[str] = set()
    for path in brute_files:
        if started is not None:
            mtime = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
            if mtime < started - _TOLERANCE:
                b2_ok = False
                details.append(f"{path.name}: STALE mtime={mtime.isoformat(timespec='seconds')}")
        for r in load_ndjson(path):
            ts = _parse_ts(r.get("timestamp"))
            if started is not None and ts is not None and ts < started - _TOLERANCE:
                b2_ok = False
                details.append(f"{path.name}: stale row ts={r.get('timestamp')}")
            host = str(r.get("host") or r.get("input") or "").strip().lower().rstrip(".")
            if host and host not in smoke:
                residual_hosts.add(host)
    if residual_hosts:
        b2_ok = False
        details.append(f"non-smoke residual hosts={sorted(residual_hosts)[:5]} (n={len(residual_hosts)})")
    sec_fresh = True
    for path in secondary:
        if started is None:
            sec_fresh = False
            break
        mtime = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
        if mtime < started - _TOLERANCE:
            sec_fresh = False
            details.append(f"{path.name}: STALE mtime={mtime.isoformat(timespec='seconds')}")
        for r in load_ndjson(path):
            ts = _parse_ts(r.get("timestamp"))
            if ts is not None and ts < started - _TOLERANCE:
                sec_fresh = False
                details.append(f"{path.name}: stale row ts={r.get('timestamp')}")
    row("B2", "MANDATORY", b2_ok and sec_fresh,
        f"brute_chunks={len(brute_files)} smoke_subset={'no-residual' if not residual_hosts else 'RESIDUAL'} "
        f"secondary_fresh={sec_fresh} started={started.isoformat(timespec='seconds') if started else None} "
        + ("; ".join(details) if details else "all outputs fresh"))

    # B3 host->IP map
    dnsr = load_json(DNS_DIR / "data.json") or {}
    resolved = {str(r.get("host") or "").lower(): (r.get("ips") or [])
                for r in dnsr.get("resolved") or [] if isinstance(r, dict)}
    ts_path = PORT_DIR / "target-set.txt"
    pairs: list[tuple[str, str]] = []
    map_ok = ts_path.is_file()
    map_detail = "target-set missing"
    if map_ok:
        lines = [ln for ln in ts_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        fmt_bad = [ln for ln in lines if not re.match(r"^\d+(\.\d+){3}\t[\w.\-]+(,[\w.\-]+)*$", ln)]
        for ln in lines:
            ip, _, hosts_s = ln.partition("\t")
            for h in hosts_s.split(","):
                pairs.append((ip, h))
        inconsistent = [(ip, h) for (ip, h) in pairs
                        if h not in resolved or ip not in [str(x) for x in (resolved.get(h) or [])]]
        map_ok = len(lines) >= 1 and not fmt_bad and not inconsistent
        map_detail = (f"lines={len(lines)} pairs={len(pairs)} fmt_bad={len(fmt_bad)} "
                      f"inconsistent={len(inconsistent)}")
    row("B3", "MANDATORY", map_ok, map_detail)

    # B4 one-naabu-per-IP
    log_path = TARGET_DIR / "logs" / "run.log"
    invoked: list[str] = []
    if log_path.is_file():
        for ln in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
            m = re.search(r"\tnaabu-invoke\tip=(\d+(\.\d+){3})\t", ln)
            if m:
                invoked.append(m.group(1))
    invoked_set, target_set = set(invoked), {ip for ip, _ in pairs}
    dupes = len(invoked) - len(invoked_set)
    port_summary = PORT_DIR / "summary.md"
    unique_ips = None
    duplicates_skipped = None
    if port_summary.is_file():
        for ln in port_summary.read_text(encoding="utf-8").splitlines():
            if ln.startswith("unique_ips_checked:"):
                unique_ips = ln.split(":", 1)[1].strip()
            elif ln.startswith("duplicates_skipped:"):
                duplicates_skipped = ln.split(":", 1)[1].strip()
    b4_ok = (unique_ips is not None and len(invoked) == int(unique_ips or -1)
             and dupes == 0 and invoked_set == target_set)
    row("B4", "MANDATORY", b4_ok,
        f"naabu_invocations={len(invoked)} unique_ips={unique_ips} dup_invokes={dupes} "
        f"ip_sets_match={invoked_set == target_set}")

    # B5 dedup evidence
    multi_host = [ip for ip, h in _iter_ip_hosts(pairs).items() if len(h) >= 2]
    b5_ok = (duplicates_skipped is not None and int(duplicates_skipped or 0) >= 1
             and len(multi_host) >= 1)
    sample = {ip: _iter_ip_hosts(pairs)[ip] for ip in multi_host[:2]}
    row("B5", "MANDATORY", b5_ok,
        f"duplicates_skipped={duplicates_skipped} ips_with_multi_hosts={len(multi_host)} "
        f"sample={json.dumps(sample) if sample else '{}'}")

    # B6 output schema
    pc = load_json(PORT_DIR / "data.json") or {}
    results = pc.get("results") or []
    schema_bad = []
    for r in results:
        if not isinstance(r, dict) or not isinstance(r.get("ip"), str) \
                or not isinstance(r.get("hosts"), list) or not r.get("hosts") \
                or not isinstance(r.get("ports"), list):
            schema_bad.append("row-shape")
            continue
        for p in r["ports"]:
            if not isinstance(p, dict) or not isinstance(p.get("port"), int) \
                    or str(p.get("state") or "") != "open":
                schema_bad.append("port-shape")
                break
    b6_ok = pc.get("module") == "port-check" and len(results) >= 1 and not schema_bad \
        and str(pc.get("unique_ips_checked")) == str(unique_ips) \
        and len(results) + len(pc.get("unreachable") or []) <= int(unique_ips or 0)
    row("B6", "MANDATORY", b6_ok,
        f"results={len(results)} schema_bad={len(schema_bad)} unique_ips={unique_ips} "
        f"unreachable={len(pc.get('unreachable') or [])}")

    # B3 row already emitted in table order above

    # B7 forge anchor + verify_b1 clean
    forge = ROOT / "wordlists" / "forge" / "custom-subdomains.txt"
    sha = hashlib.sha256(forge.read_bytes()).hexdigest() if forge.is_file() else "MISSING"
    diff = subprocess.run(
        ["git", "diff", "HEAD", "--stat", "--", "pipeline/verify_b1.py"],
        cwd=ROOT, capture_output=True, text=True,
    )
    row("B7", "MANDATORY", sha == ANCHOR and diff.stdout.strip() == "",
        f"post_sha={sha[:16]}... verify_b1_diff_empty={diff.stdout.strip() == ''}")

    # B8 MERGE composition disclosure line (T3-1 disclosure shipped)
    assets_summary = TARGET_DIR / "00_assets" / "summary.md"
    comp_line = None
    if assets_summary.is_file():
        for ln in assets_summary.read_text(encoding="utf-8").splitlines():
            if ln.startswith("composition:"):
                comp_line = ln.strip()
    assets = load_json(TARGET_DIR / "00_assets" / "assets.json") or []
    n_assets = len((assets.get("assets") or []) if isinstance(assets, dict) else assets)
    row("B8", "MANDATORY", comp_line is not None,
        f"composition_line={'present' if comp_line else 'MISSING'} [{comp_line}] assets={n_assets}")

    # B9 T3-0 dissection disclosure
    dissection = load_json(ROOT / "ci" / "test3_dissection.json") or {}
    ex = ((dissection.get("targets") or {}).get("example.com") or {}).get("20_dns/dnsx/brute_chunk_0.json") or {}
    proof = dissection.get("defect_proof") or {}
    row("B9", "DISCLOSURE", True,
        f"pre_run_rows={ex.get('rows')} pre_run_uniq={ex.get('unique_hosts')} "
        f"candidates_brute={proof.get('candidates_brute')} defect_confirmed={proof.get('defect_confirmed')} "
        f"conclusion={str(dissection.get('conclusion'))[:80]}")

    verdict = "PASS" if not failures else "FAIL"
    print(f"VERDICT\tTEST 3 (REAL-TARGET, T3): {verdict} ({len(failures)} mandatory failures)")
    (ROOT / "ci" / "test3_verdict.txt").write_text(
        "\n".join(f"{a}\t{k}\t{v}\t{d}" for a, k, v, d in rows)
        + f"\nVERDICT\tTEST 3 (REAL-TARGET, T3): {verdict}\n",
        encoding="utf-8",
    )
    return 0 if not failures else 1


def _iter_ip_hosts(pairs: list[tuple[str, str]]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for ip, host in pairs:
        out.setdefault(ip, [])
        if host not in out[ip]:
            out[ip].append(host)
    return out


if __name__ == "__main__":
    raise SystemExit(main())
