"""REM4-R preflight gates (STEP 0/2 of the recovery protocol).

Runs on the executor host BEFORE `recon.sh run`:
  G-P1  deterministic forge materialization from working selection
        -> sha256 must equal the integrity anchor 7ee5fd81...9d3d, 200 lines
  G-P2  working selection for FFUF-0/DNSR-1/FFUF-2 is [test_smoke_200]
        and committed default_selection remains the three real keys
  G-P3  scope is fixture-only (example.com absent from includes)
  G-P4  verify_b1.py has no working-tree diff

Exit code 0 = all gates hold. Any failure prints GATE-FAIL lines and exits 1.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from pipeline.params import Params  # noqa: E402
from pipeline.wordlist_forge import forge_custom_subdomains  # noqa: E402

ANCHOR = "7ee5fd817b2f2581df41397d0d0a7ce9e8545b5cb3a91d1171e9b7af15979d3d"
EXPECTED_LINES = 200
SMOKE_KEY = "test_smoke_200"

failures: list[str] = []


def check(name: str, ok: bool, detail: str) -> None:
    mark = "PASS" if ok else "GATE-FAIL"
    print(f"{mark}\t{name}\t{detail}")
    if not ok:
        failures.append(name)


def main() -> int:
    params = Params(ROOT)

    # G-P1 forge materialization + anchor
    forge = forge_custom_subdomains(params)
    data = forge.read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    lines = len([ln for ln in data.decode("utf-8", errors="replace").splitlines() if ln.strip()])
    check("G-P1 forge-anchor", sha == ANCHOR and lines == EXPECTED_LINES, f"sha={sha} lines={lines}")

    # G-P2 selections
    from pipeline.yaml_util import load_yaml_file

    wl = load_yaml_file(str(ROOT / "wordlists.yaml"))
    tasks = wl.get("tasks") or {}
    for task in ("FFUF-0", "DNSR-1", "FFUF-2"):
        sel = (tasks.get(task) or {}).get("selection")
        ok = isinstance(sel, list) and sel == [SMOKE_KEY]
        check("G-P2 selection-" + task, ok, f"selection={sel}")
    default_sel = ((tasks.get("FFUF-0") or {}).get("default_selection"))
    expected_default = ["dns_fast_top5000", "dns_exp_combined", "vhost_top5000"]
    check(
        "G-P2 default-selection-untouched",
        default_sel == expected_default,
        f"tasks.FFUF-0.default_selection={default_sel}",
    )

    # G-P3 scope fixture-only
    scope_text = (ROOT / "scope.yaml").read_text(encoding="utf-8")
    includes_ok = "fixture-target.test" in scope_text
    example_leak = "- example.com" in scope_text.replace("out.example.com", "")
    check("G-P3 scope-fixture-only", includes_ok and not example_leak, "includes fixture, no example.com seed")

    # G-P4 verify_b1 untouched (working tree)
    import subprocess

    diff = subprocess.run(
        ["git", "diff", "HEAD", "--stat", "--", "pipeline/verify_b1.py"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    check("G-P4 verify_b1-clean", diff.stdout.strip() == "", "no working-tree diff")

    print(f"PREFLIGHT {'PASS' if not failures else 'FAIL'} ({len(failures)} failing)")
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
