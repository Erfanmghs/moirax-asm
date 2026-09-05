"""TEST 3 (T3-0) — offline residual dissection of committed stale dnsx outputs.

Runs in the b2-test3 workflow BEFORE `recon.sh run`, against the checkout
tree (pre-run state). The committed live trees carry dnsx chunk outputs from
the pre-smoke era. dnsx `-o` APPENDS to an existing file, so a run-era output
file accumulates rows from every prior run era; `_rows_from()` re-reads the
whole file, so stale-era rows leak into the resolved map and MERGE.

DEFECT PROOF LINE (example.com): current working-tree selection is the B2
test mode [test_smoke_200] -> candidates.brute == 200, yet the committed
20_dns/dnsx/brute_chunk_0.json carries 4860 unique hosts — the dns_fast_top5000
era effective wordlist was 4860 entries (PHASE-REPORT §wordlists). Rows from a
defunct wordlist era therefore survived in the live tree across runs.

Writes ci/test3_dissection.json (evidence for assertion B9) and prints the
dissection table. Exit 0 always — this is evidence collection, not a gate.
"""

from __future__ import annotations

import hashlib
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "ci" / "test3_dissection.json"
SMOKE = ROOT / "wordlists" / "local" / "test-smoke-200.txt"
TARGETS = ("example.com", "fixture-target.test")
CHUNK_RELS = (
    "20_dns/dnsx/brute_chunk_0.json",
    "20_dns/dnsx/perm_chunk_0.json",
    "20_dns/dnsx/resolve-all.json",
    "20_dns/dnsx/wildcard-probe.json",
)


def _ndjson(path: Path) -> list[dict]:
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


def main() -> int:
    labels: list[str] = []
    if SMOKE.is_file():
        for line in SMOKE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                labels.append(line.lower())
    smoke_hosts = {f"{lab}.example.com" for lab in labels}
    smoke_sha = hashlib.sha256(SMOKE.read_bytes()).hexdigest() if SMOKE.is_file() else None

    report: dict = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "purpose": "T3-0 residual dissection of committed stale dnsx outputs (pre-run checkout state)",
        "wordlist": {
            "key": "test_smoke_200",
            "labels": len(labels),
            "sha256": smoke_sha,
            "note": "working-tree B2 test-mode selection; candidates.brute == 200",
        },
        "targets": {},
        "conclusion": None,
    }

    for target in TARGETS:
        per_target: dict = {}
        candidates = ROOT / "recon" / target / "20_dns" / "dnsx" / "data.json"
        brute_candidates = None
        if candidates.is_file():
            try:
                doc = json.loads(candidates.read_text(encoding="utf-8"))
                brute_candidates = ((doc.get("candidates") or {}).get("brute"))
            except Exception:
                brute_candidates = None
        for rel in CHUNK_RELS:
            path = ROOT / "recon" / target / rel
            if not path.is_file():
                continue
            rows = _ndjson(path)
            if not rows:
                per_target[rel] = {"rows": 0, "note": "empty or unparseable"}
                continue
            hosts = [str(r.get("host") or r.get("input") or "").strip().lower().rstrip(".") for r in rows]
            hosts = [h for h in hosts if h]
            uniq = set(hosts)
            ts = sorted(str(r.get("timestamp")) for r in rows if r.get("timestamp"))
            hours = Counter(t[:13] for t in ts)
            if target == "example.com":
                member_rows = sum(1 for h in hosts if h in smoke_hosts)
                residual_rows = len(hosts) - member_rows
                residual_uniq = len(uniq - smoke_hosts)
            else:
                # fixture tree: smoke labels apply to a different apex; classify by
                # brute-era composition instead (no smoke membership cross-check)
                member_rows = None
                residual_rows = None
                residual_uniq = None
            per_target[rel] = {
                "rows": len(rows),
                "unique_hosts": len(uniq),
                "ts_min": ts[0] if ts else None,
                "ts_max": ts[-1] if ts else None,
                "era_hour_histogram": dict(sorted(hours.items())),
                "smoke_member_rows": member_rows,
                "residual_rows": residual_rows,
                "residual_unique_hosts": residual_uniq,
                "candidates_brute_current": brute_candidates,
            }
        report["targets"][target] = per_target

    # defect proof line on the primary dissection target
    ex = (report["targets"].get("example.com") or {}).get("20_dns/dnsx/brute_chunk_0.json") or {}
    uniq_hosts = ex.get("unique_hosts") or 0
    brute = ex.get("candidates_brute_current")
    defect = bool(brute is not None and uniq_hosts > brute)
    report["conclusion"] = (
        f"STALE-RESIDUAL-CONFIRMED: committed brute_chunk_0.json unique_hosts={uniq_hosts} "
        f"> current candidates.brute={brute} (dns_fast_top5000 era, 4860 entries); "
        "dnsx -o appends -> stale-era rows survive across runs. T3-1 fix removes "
        "stale outputs before invoke."
    ) if defect else "NO-RESIDUAL-DETECTED (pre-run tree clean)"
    report["defect_proof"] = {
        "unique_hosts": uniq_hosts,
        "candidates_brute": brute,
        "defect_confirmed": defect,
    }

    OUT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("# T3-0 residual dissection (pre-run checkout state)")
    for target, files in report["targets"].items():
        for rel, d in files.items():
            if d.get("rows") is None:
                continue
            print(
                f"{target}\t{rel}\trows={d.get('rows')}\tuniq={d.get('unique_hosts')}"
                f"\ttc_min={d.get('ts_min')}\ttc_max={d.get('ts_max')}"
                f"\tsmoke_rows={d.get('smoke_member_rows')}\tresidual={d.get('residual_rows')}"
            )
    print(f"# {report['conclusion']}")
    print(f"# evidence -> {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
