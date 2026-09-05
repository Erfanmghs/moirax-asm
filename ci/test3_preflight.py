"""TEST 3 (REAL-TARGET, T3) preflight gates — run BEFORE `recon.sh run example.com`.

  G-T1  deterministic forge materialization from working selection
        -> sha256 must equal the integrity anchor 7ee5fd81...9d3d, 200 lines
  G-T2  working selection for FFUF-0/DNSR-1/FFUF-2 is [test_smoke_200]
        and committed default_selection remains the three real keys
        (bounded real-target run; TEST 4 restores defaults)
  G-T3  scope restored for the real-target vehicle: example.com + wildcard
        include present, fixture entries RETAINED, out.example.com excluded
  G-T4  verify_b1.py has no working-tree diff
  G-T5  T3-1 authorized freshness fix is present in the dispatch commit:
        _unlink_stale defined + applied at dnsx/massdns/alterx sites;
        MERGE composition disclosure present in merge.py
  G-T6  runner egress sanity: example.com resolves via runner DNS
  G-T7  no dangling run: recon/example.com/runs.json last entry is completed

Exit 0 = all gates hold; any GATE-FAIL exits 1.
"""

from __future__ import annotations

import hashlib
import re
import socket
import subprocess
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

    forge = forge_custom_subdomains(params)
    data = forge.read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    lines = len([ln for ln in data.decode("utf-8", errors="replace").splitlines() if ln.strip()])
    check("G-T1 forge-anchor", sha == ANCHOR and lines == EXPECTED_LINES, f"sha={sha} lines={lines}")

    from pipeline.yaml_util import load_yaml_file

    wl = load_yaml_file(str(ROOT / "wordlists.yaml"))
    tasks = wl.get("tasks") or {}
    for task in ("FFUF-0", "DNSR-1", "FFUF-2"):
        sel = (tasks.get(task) or {}).get("selection")
        ok = isinstance(sel, list) and sel == [SMOKE_KEY]
        check("G-T2 selection-" + task, ok, f"selection={sel}")
    default_sel = ((tasks.get("FFUF-0") or {}).get("default_selection"))
    expected_default = ["dns_fast_top5000", "dns_exp_combined", "vhost_top5000"]
    check(
        "G-T2 default-selection-untouched",
        default_sel == expected_default,
        f"tasks.FFUF-0.default_selection={default_sel}",
    )

    scope_text = (ROOT / "scope.yaml").read_text(encoding="utf-8")
    has_apex = bool(re.search(r"^\s*-\s+example\.com\s*$", scope_text, re.M))
    has_wild = bool(re.search(r"^\s*-\s+[\"']?\*\.example\.com", scope_text, re.M))
    fixture_kept = "fixture-target.test" in scope_text
    excl_kept = "out.example.com" in scope_text
    check("G-T3 scope-real-target-restored", has_apex and has_wild and fixture_kept and excl_kept,
          f"example.com={has_apex} *.example.com={has_wild} fixture_kept={fixture_kept} exclude_kept={excl_kept}")

    diff = subprocess.run(
        ["git", "diff", "HEAD", "--stat", "--", "pipeline/verify_b1.py"],
        cwd=ROOT, capture_output=True, text=True,
    )
    check("G-T4 verify_b1-clean", diff.stdout.strip() == "", "no working-tree diff")

    dns_mod = (ROOT / "pipeline" / "modules" / "dns_resolve.py").read_text(encoding="utf-8")
    n_def = len(re.findall(r"^def _unlink_stale\(", dns_mod, re.M))
    n_calls = len(re.findall(r"_unlink_stale\(", dns_mod)) - n_def
    merge_txt = (ROOT / "pipeline" / "merge.py").read_text(encoding="utf-8")
    comp_ok = "composition:" in merge_txt
    check("G-T5 t31-fix-present", n_def == 1 and n_calls >= 5 and comp_ok,
          f"_unlink_stale def={n_def} call_sites={n_calls} merge_composition={comp_ok}")

    try:
        ip = socket.gethostbyname("example.com")
        ok = bool(re.match(r"^\d+\.\d+\.\d+\.\d+$", ip))
    except OSError as exc:
        ip, ok = f"resolve-error:{exc}", False
    check("G-T6 runner-egress-dns", ok, f"example.com -> {ip}")

    import json

    runs_path = ROOT / "recon" / "example.com" / "runs.json"
    ok = False
    detail = "runs.json missing"
    if runs_path.is_file():
        try:
            entries = (json.loads(runs_path.read_text(encoding="utf-8")) or {}).get("runs") or []
            last = entries[-1] if entries else {}
            ok = last.get("status") == "completed"
            detail = f"runs.json[{len(entries) - 1}].status={last.get('status')}"
        except Exception as exc:
            detail = f"parse-error:{exc}"
    check("G-T7 no-dangling-run", ok, detail)

    print(f"PREFLIGHT {'PASS' if not failures else 'FAIL'} ({len(failures)} failing)")
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
