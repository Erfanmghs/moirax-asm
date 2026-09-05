"""B3 first sub-step post-run assertions (acceptance table D1..D9).

Reads the live tree under recon/fixture-target.test/ after `recon.sh run` and
emits the assertion table + a final verdict line. Exit 0 iff every MANDATORY
assertion holds; DISCLOSURE rows never fail the run.

Vehicle: fixture-target.test with a TRANSIENT selection override
[test_smoke_200] (wordlists.yaml tasks.*.selection, working-copy edit never
committed) + transient REM5 resolver fleet pin. The run therefore exercises
the PRODUCTION FFUF-3 + DNSR-2 code paths on a deterministic fixture.

Table (ID / kind / expectation):
  D1 MANDATORY  run completes: exit 0 AND runs.json last entry status == completed
  D2 MANDATORY  ordering: dns-resolve finished_at <= ffuf-3 started_at <= merge
                started_at (FFUF-3 runs after DNS-RESOLVE, BEFORE MERGE) and
                ffuf-3 module status == done
  D3 MANDATORY  ffuf-3 data.json: module=="ffuf-3", exact spec root keys,
                bases[] non-empty with host/ip/alive=true
  D4 MANDATORY  flag discipline: every vhosts row has misconfig_suspect=true,
                dns_status="dead", alive=null, and base_host is DNS-unresolved
                in this run's dnsr data (dead never promoted)
  D5 MANDATORY  MERGE passthrough: every ffuf-3 vhost name present in
                assets.json carries misconfig_suspect=true; assets
                misconfig count >= ffuf-3 row count
  D6 MANDATORY  DNSR-2: candidates.perms <= max_permutations_aggregate;
                summary alterx_seeds seeds_after <= seeds_before;
                aggregate_cap_dropped disclosed
  D7 MANDATORY  input-count logging: run.log "ffuf-3 inputs:" line exists and
                predates the first ffuf-3 probe line
  D8 MANDATORY  forge POST sha == anchor (GROWTH-0 anchor discipline)
  D9 MANDATORY  verify_b1.py still clean in working tree
  E1 DISCLOSURE ffuf-3 counts: union/dead_probed/suppressed/vhosts rows
  E2 DISCLOSURE dnsr summary alterx_seeds dict disclosed
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

TARGET_DIR = ROOT / "recon" / "fixture-target.test"
ANCHOR = "7ee5fd817b2f2581df41397d0d0a7ce9e8545b5cb3a91d1171e9b7af15979d3d"

failures: list[str] = []
rows: list[tuple[str, str, str, str]] = []


def row(aid: str, kind: str, ok: bool, detail: str) -> None:
    verdict = "PASS" if ok else ("FAIL" if kind == "MANDATORY" else "DISCLOSED")
    rows.append((aid, kind, verdict, detail))
    print(f"{verdict}\t{aid}\t{detail}")
    if not ok and kind == "MANDATORY":
        failures.append(aid)


def parse_ts(stamp: str | None) -> datetime | None:
    if not stamp:
        return None
    try:
        return datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return None


def read_json(path: Path):
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def main() -> int:
    exit_txt = (ROOT / "ci" / "b3_run_exit.txt").read_text(encoding="utf-8")
    run_exit = int(re.search(r"exit=(-?\d+)", exit_txt).group(1)) if re.search(r"exit=(-?\d+)", exit_txt) else -1

    runs = (read_json(TARGET_DIR / "runs.json") or {}).get("runs") or []
    last = runs[-1] if runs else {}
    row("D1", "MANDATORY", run_exit == 0 and last.get("status") == "completed",
        f"run exit={run_exit} runs.json[{len(runs)-1}].status={last.get('status')} ts={last.get('timestamp')}")

    state = read_json(TARGET_DIR / "state.json") or {}
    modules = state.get("modules") or {}
    ffuf3_m = modules.get("ffuf-3") or {}
    dnsr_m = modules.get("dns-resolve") or {}
    merge_m = modules.get("merge") or {}
    order_ok = (
        ffuf3_m.get("status") == "done"
        and (parse_ts(dnsr_m.get("finished_at")) or datetime.min)
        <= (parse_ts(ffuf3_m.get("started_at")) or datetime.max)
        and (parse_ts(ffuf3_m.get("finished_at")) or datetime.min)
        <= (parse_ts(merge_m.get("started_at")) or datetime.max)
    )
    row("D2", "MANDATORY", order_ok,
        f"dns-resolve finished={dnsr_m.get('finished_at')} ffuf-3 [{ffuf3_m.get('status')}] "
        f"started={ffuf3_m.get('started_at')} finished={ffuf3_m.get('finished_at')} merge started={merge_m.get('started_at')}")

    f3 = read_json(TARGET_DIR / "15_vhosts/ffuf-3/data.json") or {}
    root_keys = set(f3.keys())
    bases = f3.get("bases") or []
    vhosts = f3.get("vhosts") or []
    keys_ok = root_keys == {"schema_version", "module", "vhosts", "bases", "suppressed"} and f3.get("module") == "ffuf-3"
    bases_ok = bool(bases) and all(
        isinstance(b, dict) and b.get("host") and b.get("ip") and b.get("alive") is True for b in bases
    )
    row("D3", "MANDATORY", keys_ok and bases_ok,
        f"root_keys={sorted(root_keys)} module={f3.get('module')} bases={[(b.get('host'), b.get('ip')) for b in bases]}")

    dnsr = read_json(TARGET_DIR / "20_dns/dnsx/data.json") or {}
    status_map = {
        str(r.get("host") or "").lower(): str(r.get("resolution_status") or "")
        for r in (dnsr.get("resolved") or [])
        if isinstance(r, dict)
    }
    flag_ok = bool(vhosts) and all(
        isinstance(v, dict)
        and v.get("misconfig_suspect") is True
        and v.get("dns_status") == "dead"
        and v.get("alive") is None
        and status_map.get(str(v.get("base_host") or "").lower()) == "unresolved"
        and str(v.get("vhost") or "").endswith("." + str(v.get("base_host") or ""))
        for v in vhosts
    )
    row("D4", "MANDATORY", flag_ok,
        f"rows={len(vhosts)} all(flag+dead+alive-null+base-unresolved)={flag_ok} "
        f"bases_dns_status={sorted({status_map.get(str(v.get('base_host') or '').lower(), '?') for v in vhosts})}")

    assets = (read_json(TARGET_DIR / "00_assets/assets.json") or {}).get("assets") or []
    flagged_assets = {
        str(a.get("host") or "").lower(): True
        for a in assets
        if isinstance(a, dict) and a.get("misconfig_suspect") is True
    }
    ffuf3_names = [str(v.get("vhost") or "").lower() for v in vhosts]
    passthrough_ok = all(name in flagged_assets for name in ffuf3_names) and len(flagged_assets) >= len(ffuf3_names)
    row("D5", "MANDATORY", passthrough_ok,
        f"ffuf3_rows={len(ffuf3_names)} assets_with_flag={len(flagged_assets)} "
        f"ffuf3_flagged_in_assets={sum(1 for n in ffuf3_names if n in flagged_assets)}/{len(ffuf3_names)}")

    from pipeline.params import Params

    params = Params(ROOT)
    agg = int(params.require("max_permutations_aggregate"))
    perms = ((dnsr.get("candidates") or {}).get("perms"))
    summary_txt = (TARGET_DIR / "20_dns/dnsx/summary.md").read_text(encoding="utf-8") if (TARGET_DIR / "20_dns/dnsx/summary.md").is_file() else ""
    seeds_match = re.search(r"alterx_seeds: (\{.*\})", summary_txt)
    seeds = ast.literal_eval(seeds_match.group(1)) if seeds_match else {}
    agg_dropped_match = re.search(r"aggregate_cap_dropped: (\d+)", summary_txt)
    agg_dropped = int(agg_dropped_match.group(1)) if agg_dropped_match else -1
    dnsr2_ok = (
        isinstance(perms, int) and perms <= agg
        and seeds.get("seeds_after", 10**9) <= seeds.get("seeds_before", 0)
        and agg_dropped >= 0
    )
    row("D6", "MANDATORY", dnsr2_ok,
        f"perms={perms} <= aggregate={agg} seeds={seeds} aggregate_cap_dropped={agg_dropped}")

    run_log = (TARGET_DIR / "logs/run.log").read_text(encoding="utf-8", errors="replace") if (TARGET_DIR / "logs/run.log").is_file() else ""
    m_inputs = re.search(r"^([0-9T:\-Z]+)\tffuf-3\t-\t0\tok\tffuf-3 inputs:", run_log, re.M)
    m_first_probe = re.search(r"^([0-9T:\-Z]+)\tffuf-3\tffuf-vhost\t", run_log, re.M)
    logged_ok = bool(m_inputs) and (
        not m_first_probe or datetime.strptime(m_inputs.group(1), "%Y-%m-%dT%H:%M:%SZ")
        <= datetime.strptime(m_first_probe.group(1), "%Y-%m-%dT%H:%M:%SZ")
    )
    row("D7", "MANDATORY", logged_ok,
        f"inputs_line={'yes' if m_inputs else 'NO'} at={m_inputs.group(1) if m_inputs else None} "
        f"first_probe_at={m_first_probe.group(1) if m_first_probe else 'none (skip path)'}")

    from pipeline.wordlist_forge import forge_custom_subdomains

    forge = forge_custom_subdomains(params)
    post_sha = hashlib.sha256(forge.read_bytes()).hexdigest()
    row("D8", "MANDATORY", post_sha == ANCHOR, f"post_sha={post_sha[:16]}... anchor-discipline={'ok' if post_sha == ANCHOR else 'VIOLATED'}")

    diff = subprocess.run(
        ["git", "diff", "HEAD", "--stat", "--", "pipeline/verify_b1.py"],
        cwd=ROOT, capture_output=True, text=True,
    )
    row("D9", "MANDATORY", diff.stdout.strip() == "", "verify_b1 working-tree diff empty")

    f3_summary_path = TARGET_DIR / "15_vhosts/ffuf-3/summary.md"
    f3_summary = f3_summary_path.read_text(encoding="utf-8").splitlines()[2] if f3_summary_path.is_file() else "missing"
    row("E1", "DISCLOSURE", True,
        f"vhosts={len(vhosts)} suppressed={f3.get('suppressed')} bases={len(bases)} summary={f3_summary}")
    row("E2", "DISCLOSURE", True, f"dnsr alterx_seeds={seeds} aggregate_cap_dropped={agg_dropped}")

    verdict = "PASS" if not failures else "FAIL"
    print(f"VERDICT\tTEST B3-1 (FFUF-3 + DNSR-2, FIXTURE): {verdict} ({len(failures)} mandatory failures)")
    (ROOT / "ci" / "b3_verdict.txt").write_text(
        "\n".join(f"{aid}\t{kind}\t{vd}\t{detail}" for aid, kind, vd, detail in rows)
        + f"\nVERDICT\tTEST B3-1 (FFUF-3 + DNSR-2, FIXTURE): {verdict}\n",
        encoding="utf-8",
    )
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
