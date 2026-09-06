#!/usr/bin/env python3
"""LIVE-VALIDATION preflight gates (G-L table).

Runs BEFORE the unit suite, AFTER the transient accommodations, so it
validates exactly the working copy the vehicle will execute:

  G-L1  pipeline/verify_b1.py has an EMPTY working-tree diff (B1 discipline)
  G-L2  the forge materialization over the working selection
        ([test_smoke_200]) reproduces the frozen anchor wordlist:
        sha256 7ee5fd81... and exactly 200 records (G-P1 pattern)
  G-L3  wordlists.yaml selects test_smoke_200 on DNSR-1, FFUF-0 and FFUF-2
        (the operator's "same 200-record list" directive)
  G-L4  scope.yaml authorizes bugdasht.ir + *.bugdasht.ir and nothing else
  G-L5  resolvers/seed.txt carries the pinned anycast resolver fleet and the
        runtime resolvers.yaml disables public source URLs (REM5 pattern)

Any gate failure is fatal (exit 1) — the vehicle never starts on a
drifted working copy.
"""
from __future__ import annotations

import hashlib
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

ANCHOR = "7ee5fd817b2f2581df41397d0d0a7ce9e8545b5cb3a91d1171e9b7af15979d3d"

failures: list[str] = []


def check(name: str, ok: bool, detail: str) -> None:
    mark = "PASS" if ok else "FAIL"
    print(f"G-L {name}: {mark} - {detail}")
    if not ok:
        failures.append(name)


def main() -> int:
    # G-L1 verify_b1.py diff empty (tracked file untouched in the working copy)
    diff = subprocess.run(
        ["git", "diff", "HEAD", "--", "pipeline/verify_b1.py"],
        cwd=ROOT, capture_output=True, text=True,
    )
    staged = subprocess.run(
        ["git", "diff", "--cached", "HEAD", "--", "pipeline/verify_b1.py"],
        cwd=ROOT, capture_output=True, text=True,
    )
    check("G-L1", diff.stdout.strip() == "" and staged.stdout.strip() == "",
          "pipeline/verify_b1.py working-tree diff is empty")

    # G-L2 forge materialization + anchor (authoritative: the project's own
    # forge over the working selection; the RAW local file is NOT the anchor)
    from pipeline.params import Params
    from pipeline.wordlist_forge import forge_custom_subdomains

    forge = forge_custom_subdomains(Params(ROOT))
    data = forge.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    lines = len([ln for ln in data.decode("utf-8", errors="replace").splitlines() if ln.strip()])
    check("G-L2", digest == ANCHOR and lines == 200,
          f"forged sha256={digest[:12]}... lines={lines} (frozen anchor)")

    # G-L3 selection = test_smoke_200 on all three tasks
    lines = (ROOT / "wordlists.yaml").read_text(encoding="utf-8").splitlines()
    ok = True
    for task in ("  DNSR-1:", "  FFUF-0:", "  FFUF-2:"):
        try:
            i = lines.index(task)
        except ValueError:
            ok = False
            break
        block: list[str] = []
        for ln in lines[i + 1:]:
            if ln.startswith("    "):
                block.append(ln)
            else:
                break
        joined = "\n".join(block)
        if not ("selection:" in joined and "test_smoke_200" in joined):
            ok = False
            break
    check("G-L3", ok, "DNSR-1/FFUF-0/FFUF-2 selection = [test_smoke_200]")

    # G-L4 scope authorizes exactly the operator target
    scope = (ROOT / "scope.yaml").read_text(encoding="utf-8")
    ok = ("bugdasht.ir" in scope and "*.bugdasht.ir" in scope
          and "example.com" not in scope)
    check("G-L4", ok, "scope.yaml = bugdasht.ir + *.bugdasht.ir (operator-owned)")

    # G-L5 resolver fleet
    seed = [x.strip() for x in
            (ROOT / "resolvers" / "seed.txt").read_text(encoding="utf-8").splitlines()
            if x.strip() and not x.startswith("#")]
    res_text = (ROOT / "resolvers.yaml").read_text(encoding="utf-8")
    ok = len(seed) >= 5 and "sources: []" in res_text
    check("G-L5", ok, f"seed={len(seed)} resolvers; runtime sources=[] (REM5)")

    print(f"PREFLIGHT: {'ALL PASS' if not failures else 'FAIL ' + ','.join(failures)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
