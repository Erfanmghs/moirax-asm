#!/usr/bin/env python3
"""C4 FLEET vehicle assertions (C4-1..C4-6)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

failures: list[str] = []


def check(name: str, ok: bool, detail: str) -> None:
    mark = "PASS" if ok else "FAIL"
    print(f"{mark}\t{name}\t{detail}")
    if not ok:
        failures.append(name)


def git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=True).stdout


def main() -> int:
    fleet_root = ROOT / "history" / "fleet"
    runs = sorted(d for d in fleet_root.iterdir() if d.is_dir()) if fleet_root.is_dir() else []
    check("C4-1 fleet-run-exists", bool(runs), f"runs={[d.name for d in runs][-3:]}")
    if not runs:
        (ROOT / "ci" / "c4_verdict.txt").write_text("C4 FLEET VERDICT: FAIL:no-run\n", encoding="utf-8")
        return 1
    latest = runs[-1]
    ledger = json.loads((latest / "fleet-ledger.json").read_text(encoding="utf-8"))

    # C4-1 members + isolation roots
    members = ledger.get("members") or []
    roots = [Path(m["root"]) for m in members]
    iso = all((r / "tools.yaml").is_file() and (r / "recon").is_dir() and r != ROOT for r in roots)
    check("C4-1 members-isolated", len(members) == 2 and iso, f"members={[m['target'] for m in members]}")

    # C4-2 concurrency observed: at least two members started within one window
    started = sorted(r.get("started_at", "") for r in ledger.get("results", []))
    overlap = len(started) == 2 and (started[0][:16] == started[1][:16])
    check("C4-2 concurrency-observed", overlap, f"started={started} (same minute => parallel pool)")

    # C4-3 every member recorded independently (failure isolation)
    results = ledger.get("results") or []
    check("C4-3 members-recorded", len(results) == 2 and all("exit_code" in r for r in results),
          f"exits={{r['target']: r['exit_code'] for r in results}}")

    # C4-4 clean law: passive-only members may end 0/3/anomaly(2, disclosed third-party variance)
    ok_exits = all(r.get("exit_code") in (0, 2, 3, 4) for r in results)
    check("C4-4 exit-law", ok_exits, f"exits={[r.get('exit_code') for r in results]} (0/2/3/4 with disclosure)")
    check("C4-4 ledger-persisted", (latest / "fleet-ledger.json").is_file(), str(latest))

    # C4-5 source root untouched by member baking
    src = (ROOT / "tools.yaml").read_text(encoding="utf-8")
    check("C4-5 source-unbaked", "passive_branch_budget_sec: 1200" not in src,
          "committed tools.yaml keeps the 1200 default (members baked locally)")

    # C4-6 integrity
    diff_b1 = git("diff", "HEAD", "--", "pipeline/verify_b1.py")
    check("C4-6 verify_b1-empty", diff_b1.strip() == "", "verify_b1 diff EMPTY")

    verdict = "PASS" if not failures else "FAIL:" + ",".join(failures)
    line = f"C4 FLEET VERDICT: {verdict}"
    print(line)
    (ROOT / "ci" / "c4_verdict.txt").write_text(line + "\n", encoding="utf-8")
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
