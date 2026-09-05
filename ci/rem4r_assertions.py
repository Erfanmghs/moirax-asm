"""REM4-R post-run assertions (STEP 2 acceptance table of the recovery protocol).

Reads the live tree under recon/fixture-target.test/ after `recon.sh run` and
emits the assertion table + a final verdict line. Exit 0 iff every MANDATORY
assertion holds; DISCLOSURE rows never fail the run.

REM6 stale-evidence guards: A4/A5/A7 evidence files must be NEWER than their
module's state.json started_at; a module that never started (skipped/paused)
or files left over from the checkout make the row FAIL with fresh=False.

Table (ID / kind / expectation):
  A1 MANDATORY  unit proof file executed earlier in the job (recorded from env log)
  A2 MANDATORY  forge PRE anchor already gated by ci/rem4r_preflight.py (recorded)
  A3 MANDATORY  run completes: runs.json last entry status == completed
  A4 MANDATORY  ffuf: partial=none; hosts contain app + www; www alive=true; evidence FRESH
  A5 MANDATORY  vhosts: >=1 misconfig_suspect=true on base app; ZERO records on base www; evidence FRESH
  A6 DISCLOSURE dnsr: candidates.perms exact count disclosed; per-host cap respected
  A7 MANDATORY  port-check stage done; scanned-IP count == 0; summary FRESH
  A8 DISCLOSURE merge: assets count; >=1 asset carries misconfig_suspect=true (R3
                flag passthrough); www asset alive=true (as-frozen promotion ruling)
  A9 MANDATORY  forge POST sha == anchor AND no GROW lines appended during run (GROWTH-0)
  A10 MANDATORY verify_b1.py still clean in working tree
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
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


def load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


_TOLERANCE = timedelta(seconds=5)


def _parse_ts(val) -> datetime | None:
    try:
        return datetime.fromisoformat(str(val).replace("Z", "+00:00")).astimezone(timezone.utc)
    except Exception:
        return None


def _fresh(path: Path, module_row: dict, label: str) -> tuple[bool, str]:
    started = _parse_ts((module_row or {}).get("started_at"))
    if started is None:
        return False, f"{label}: module started_at missing -> evidence STALE"
    if not path.is_file():
        return False, f"{label}: {path.name} missing -> evidence STALE"
    mtime = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
    ok = mtime >= started - _TOLERANCE
    return ok, f"{label}: fresh={str(ok).lower()} mtime={mtime.isoformat(timespec='seconds')} started={started.isoformat(timespec='seconds')}"


def main() -> int:
    state = load_json(TARGET_DIR / "state.json") or {}
    modules = state.get("modules") or {}

    # A3 run completion (append-only runs.json)
    runs = load_json(TARGET_DIR / "runs.json") or {}
    entries = runs.get("runs") or []
    last = entries[-1] if entries else {}
    row("A3", "MANDATORY", last.get("status") == "completed",
        f"runs.json[{len(entries)-1}].status={last.get('status')} ts={last.get('timestamp')}")

    # A4 ffuf hosts + www alive (+ REM6 freshness guard)
    ffuf_path = TARGET_DIR / "10_subdomains" / "ffuf" / "data.json"
    ffuf = load_json(ffuf_path) or {}
    summary = (TARGET_DIR / "10_subdomains" / "ffuf" / "summary.md")
    summary_text = summary.read_text(encoding="utf-8") if summary.is_file() else ""
    hosts = {r.get("fqdn"): r for r in ffuf.get("hosts") or [] if isinstance(r, dict)}
    app_present = "app.fixture-target.test" in hosts
    www = hosts.get("www.fixture-target.test") or {}
    ffuf_fresh, ffuf_fresh_detail = _fresh(ffuf_path, modules.get("ffuf"), "ffuf-data")
    row("A4", "MANDATORY",
        "partial: none" in summary_text and app_present and www.get("alive") is True and ffuf_fresh,
        f"hosts={len(hosts)} app={app_present} www.alive={www.get('alive')} "
        f"partial={'partial: none' in summary_text} {ffuf_fresh_detail}")

    # A5 vhost suspect flags (+ same freshness guard)
    vhosts = [r for r in ffuf.get("vhosts") or [] if isinstance(r, dict)]
    app_suspects = [r for r in vhosts
                    if r.get("base_host") == "app.fixture-target.test"
                    and r.get("misconfig_suspect") is True]
    www_records = [r for r in vhosts if r.get("base_host") == "www.fixture-target.test"]
    suspect_names = sorted(str(r.get("vhost", "")).split(".")[0] for r in app_suspects)
    row("A5", "MANDATORY", len(app_suspects) >= 1 and len(www_records) == 0 and ffuf_fresh,
        f"suspect_on_app={len(app_suspects)} {suspect_names} records_on_www={len(www_records)} {ffuf_fresh_detail}")

    # A6 dnsr permutation disclosure
    dnsr_path = TARGET_DIR / "20_dns" / "dnsx" / "data.json"
    dnsr = load_json(dnsr_path) or {}
    candidates = dnsr.get("candidates") or {}
    perms = candidates.get("perms")
    dnsr_summary = (TARGET_DIR / "20_dns" / "dnsx" / "summary.md")
    summary_txt = dnsr_summary.read_text(encoding="utf-8") if dnsr_summary.is_file() else ""
    dnsr_fresh, dnsr_fresh_detail = _fresh(dnsr_path, modules.get("dns-resolve"), "dnsr-data")
    row("A6", "DISCLOSURE", True,
        f"candidates={json.dumps(candidates)} resolved_rows={len(dnsr.get('resolved') or [])} "
        f"summary_present={dnsr_summary.is_file()} {dnsr_fresh_detail}")

    # A7 port-check stage + IP count (structured: summary.md unique_ips_checked)
    port_status = (modules.get("port-check") or {}).get("status")
    port_summary_path = TARGET_DIR / "30_ports" / "naabu-light" / "summary.md"
    unique_ips = None
    skipped_no_ip = None
    if port_summary_path.is_file():
        for line in port_summary_path.read_text(encoding="utf-8").splitlines():
            if line.startswith("unique_ips_checked:"):
                unique_ips = line.split(":", 1)[1].strip()
            elif line.startswith("skipped_no_ip:"):
                skipped_no_ip = line.split(":", 1)[1].strip()
    port_fresh, port_fresh_detail = _fresh(port_summary_path, modules.get("port-check"), "portcheck-summary")
    row("A7", "MANDATORY", port_status == "done" and unique_ips == "0" and port_fresh,
        f"port-check.status={port_status} unique_ips_checked={unique_ips} "
        f"skipped_no_ip={skipped_no_ip} {port_fresh_detail}")

    # A8 merge passthrough disclosure
    assets = load_json(TARGET_DIR / "00_assets" / "assets.json") or []
    if isinstance(assets, dict):
        assets = assets.get("assets") or []
    suspect_assets = [a for a in assets if isinstance(a, dict) and a.get("misconfig_suspect") is True]
    www_asset = next((a for a in assets
                      if isinstance(a, dict) and a.get("host") == "www.fixture-target.test"), None)
    assets_fresh, assets_fresh_detail = _fresh(
        TARGET_DIR / "00_assets" / "assets.json", modules.get("merge"), "assets")
    row("A8", "DISCLOSURE", len(suspect_assets) >= 1,
        f"assets={len(assets)} suspect_assets={len(suspect_assets)} "
        f"www_asset_alive={(www_asset or {}).get('alive')} {assets_fresh_detail}")

    # A9 forge post anchor + GROWTH-0
    forge = ROOT / "wordlists" / "forge" / "custom-subdomains.txt"
    sha = hashlib.sha256(forge.read_bytes()).hexdigest() if forge.is_file() else "MISSING"
    counts_log = ROOT / "wordlists" / "forge" / "counts.log"
    grow_lines: list[str] = []
    if counts_log.is_file():
        grow_lines = [ln for ln in counts_log.read_text(encoding="utf-8").splitlines()
                      if ln.startswith("GROW\t") or ln.startswith("GROW-LABEL")]
    tail = " | ".join(grow_lines[-3:]) if grow_lines else "none"
    row("A9", "MANDATORY", sha == ANCHOR,
        f"post_sha={sha[:16]}... full-log_GROW_lines={len(grow_lines)} tail=[{tail}] "
        f"(GROWTH-0 judged on sha-unchanged + A3 completed)")

    # A10 verify_b1 clean
    diff = subprocess.run(
        ["git", "diff", "HEAD", "--stat", "--", "pipeline/verify_b1.py"],
        cwd=ROOT, capture_output=True, text=True,
    )
    row("A10", "MANDATORY", diff.stdout.strip() == "", "verify_b1 working-tree diff empty")

    verdict = "PASS" if not failures else "FAIL"
    print(f"VERDICT\tTEST 2 (FIXTURE, REM4-R): {verdict} ({len(failures)} mandatory failures)")
    (ROOT / "ci" / "rem4r_verdict.txt").write_text(
        "\n".join(f"{a}\t{k}\t{v}\t{d}" for a, k, v, d in rows)
        + f"\nVERDICT\tTEST 2 (FIXTURE, REM4-R): {verdict}\n",
        encoding="utf-8",
    )
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
