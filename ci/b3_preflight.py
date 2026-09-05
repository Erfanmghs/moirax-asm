"""B3 first sub-step preflight gates — run BEFORE `recon.sh run fixture-target.test`.

  G-B1  production DNSR-1 materialization from the COMMITTED config
        reproduces the TEST-1-proven anchor byte-exact (4860 lines,
        sha256 a94ea1d5...1695) — post-T4 restore discipline
  G-B2  FFUF-3 wiring (spec v1.9 §8): RUNNERS registry + active_branch_modules
        order [ffuf, dns-resolve, ffuf-3, port-check] + params + layout dir
  G-B3  DNSR-2 refinement (v1.9 item 3): max_permutations_aggregate param
        present; _cap_perms aggregate enforcement; seed-exclusion helpers
  G-B4  verify_b1.py has no working-tree diff
  G-B5  vehicle scope: fixture-target.test committed; example.com retained
  G-B6  committed selection defaults intact: wordlists.yaml carries NO
        tasks.<task>.selection override (the vehicle override is transient)
  G-B7  no dangling run: recon/fixture-target.test/runs.json last entry completed
  G-B8  pinned resolver seed present (>= 10 anycast entries)

Exit 0 = all gates hold; any GATE-FAIL exits 1.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from pipeline.params import Params  # noqa: E402
from pipeline.wordlist_forge import materialize_effective  # noqa: E402

TEST1_DNSR1_ANCHOR = "a94ea1d5d791b6c105bbca2ec064d1a1396e8271d1c8ce6c857f39cef3c71695"
TEST1_DNSR1_LINES = 4860

failures: list[str] = []


def check(name: str, ok: bool, detail: str) -> None:
    mark = "PASS" if ok else "GATE-FAIL"
    print(f"{mark}\t{name}\t{detail}")
    if not ok:
        failures.append(name)


def main() -> int:
    params = Params(ROOT)

    eff = materialize_effective(params, "DNSR-1")
    data = eff.read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    lines = len([ln for ln in data.decode("utf-8", errors="replace").splitlines() if ln.strip()])
    check(
        "G-B1 dnsr1-production-anchor",
        sha == TEST1_DNSR1_ANCHOR and lines == TEST1_DNSR1_LINES,
        f"effective-DNSR-1 lines={lines} sha={sha[:16]}... (TEST-1 anchor {TEST1_DNSR1_LINES} / {TEST1_DNSR1_ANCHOR[:12]}...)",
    )

    modules_pkg = (ROOT / "pipeline" / "modules" / "__init__.py").read_text(encoding="utf-8")
    registry_ok = '"ffuf-3": run_ffuf3' in modules_pkg
    tools_txt = (ROOT / "tools.yaml").read_text(encoding="utf-8")
    order_ok = bool(
        re.search(r"active_branch_modules:\s*\n\s*- ffuf\s*\n\s*- dns-resolve\s*\n(?:\s*#[^\n]*\n)*\s*- ffuf-3\s*\n\s*- port-check", tools_txt, re.M)
    )
    params_ok = (
        "ffuf3_data_json: 15_vhosts/ffuf-3/data.json" in tools_txt
        and "ffuf3_summary: 15_vhosts/ffuf-3/summary.md" in tools_txt
        and "15_vhosts/ffuf-3" in tools_txt
        and re.search(r"^    - ffuf-3$", tools_txt, re.M) is not None
    )
    ffuf3_mod = (ROOT / "pipeline" / "modules" / "ffuf3.py").read_text(encoding="utf-8")
    spec_ok = (
        "Host: FUZZ.{dead}" in ffuf3_module_source(ffuf3_mod)
        and 'misconfig_suspect": True' in ffuf3_mod.replace("'", '"')
        and '"dns_status": "dead"' in ffuf3_mod.replace("'", '"')
    )
    check(
        "G-B2 ffuf-3-wiring",
        registry_ok and order_ok and params_ok and spec_ok,
        f"registry={registry_ok} module_order={order_ok} params={params_ok} spec_strings={spec_ok}",
    )

    agg_param = params.require("max_permutations_aggregate")
    dns_mod = (ROOT / "pipeline" / "modules" / "dns_resolve.py").read_text(encoding="utf-8")
    agg_ok = (
        isinstance(agg_param, int)
        and agg_param > 0
        and "dropped_aggregate" in dns_mod
        and "def _misconfig_flagged(" in dns_mod
        and "def _wildcard_ip_members(" in dns_mod
        and "def _filter_seeds(" in dns_mod
        and "_cap_perms(" in dns_mod
    )
    per_host = int(params.require("max_permutations_per_host"))
    check(
        "G-B3 dnsr2-refinement",
        agg_ok and agg_param <= per_host * 10,
        f"max_permutations_aggregate={agg_param} per_host={per_host} helpers-present={agg_ok}",
    )

    diff = subprocess.run(
        ["git", "diff", "HEAD", "--stat", "--", "pipeline/verify_b1.py"],
        cwd=ROOT, capture_output=True, text=True,
    )
    check("G-B4 verify_b1-clean", diff.stdout.strip() == "", "no working-tree diff")

    scope_text = (ROOT / "scope.yaml").read_text(encoding="utf-8")
    fixture_kept = "fixture-target.test" in scope_text
    real_kept = "example.com" in scope_text
    check("G-B5 vehicle-scope", fixture_kept and real_kept, f"fixture={fixture_kept} example.com={real_kept}")

    from pipeline.yaml_util import load_yaml_file

    wl = load_yaml_file(str(ROOT / "wordlists.yaml"))
    tasks = wl.get("tasks") or {}
    committed_overrides = {t: (tasks.get(t) or {}).get("selection") for t in ("FFUF-0", "DNSR-1", "FFUF-2")}
    no_overrides = all(not sel for sel in committed_overrides.values())
    default_key = (tasks.get("DNSR-1") or {}).get("default_key")
    check(
        "G-B6 committed-defaults-intact",
        no_overrides and default_key == "dns_fast_top5000",
        f"committed selection={committed_overrides} dnsr_default={default_key}",
    )

    runs_path = ROOT / "recon" / "fixture-target.test" / "runs.json"
    ok = False
    detail = "runs.json missing"
    if runs_path.is_file():
        try:
            entries = (json.loads(runs_path.read_text(encoding="utf-8")) or {}).get("runs") or []
            last = entries[-1] if entries else {}
            ok = last.get("status") in ("completed", "partial")
            detail = f"runs.json[{len(entries) - 1}].status={last.get('status')}"
        except Exception as exc:
            detail = f"parse-error:{exc}"
    check("G-B7 no-dangling-run", ok, detail)

    seed = (ROOT / "resolvers" / "seed.txt").read_text(encoding="utf-8")
    seed_n = len([ln for ln in seed.splitlines() if ln.strip() and not ln.strip().startswith("#")])
    check("G-B8 resolver-seed-pinned", seed_n >= 10, f"seed entries={seed_n}")

    print(f"PREFLIGHT {'PASS' if not failures else 'FAIL'} ({len(failures)} failing)")
    return 0 if not failures else 1


def ffuf3_module_source(src: str) -> str:
    return src.replace("'", '"')


if __name__ == "__main__":
    raise SystemExit(main())
