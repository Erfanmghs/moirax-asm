"""B3 PASSIVE-CHAIN preflight gates — run BEFORE `recon.sh run example.com`.

  G-S1  registries parse with the FROZEN loader: search_engines.yaml (>=1
        keyless enabled engine; every keyed engine names its env) + dorks.yaml
        (4 builtin host dorks, 4 github dorks)
  G-S2  PSV wiring: RUNNERS has passive-recon; engine has _run_passive_modules;
        passive_branch_modules == [passive-recon]; pipeline_modules pre-declares
        passive-recon (it already did); recon layout dirs unchanged
  G-S3  passive tool specs registered + adapter-assemblable for every PSV agent
  G-S4  tools.lock pins an image for every passive image_ref
  G-S5  committed passive defaults intact (recursion 2, seeds 100, amass 20min,
        dork 60s, crtsh 120s/x3, httpx threads 200, probe on, github 30 rpm,
        ct_fallback_tool=certspotter) and ACTIVE branch order untouched
        (append-only law: [ffuf, dns-resolve, ffuf-3, port-check])
  G-S6  verify_b1.py has no working-tree diff (frozen since handoff)
  G-S7  vehicle scope: example.com retained (passive acceptance target)
  G-S8  unit suite covers the chain: tests/test_passive.py present with
        SearchForge/candidates/PSV-8/orchestrator classes

Exit 0 = all gates hold; any GATE-FAIL exits 1.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from pipeline.adapter import Adapter, ScriptedRunner  # noqa: E402
from pipeline.breaker import CircuitBreaker, FakeClock  # noqa: E402
from pipeline.ceiling import ResourceCeiling  # noqa: E402
from pipeline.modules import RUNNERS  # noqa: E402
from pipeline.params import Params  # noqa: E402
from pipeline.search_forge import load_dorks_registry, load_registry  # noqa: E402
from pipeline.yaml_util import load_yaml_file  # noqa: E402

failures: list[str] = []


def check(name: str, ok: bool, detail: str) -> None:
    mark = "PASS" if ok else "GATE-FAIL"
    print(f"{mark}\t{name}\t{detail}")
    if not ok:
        failures.append(name)


def main() -> int:
    params = Params(ROOT)

    # ---- G-S1 registries (frozen-loader dialect) --------------------------
    registry = load_registry(params)
    engines = registry.get("engines") or {}
    keyless = [n for n, c in engines.items() if isinstance(c, dict) and c.get("keyless")]
    keyed = [n for n, c in engines.items() if isinstance(c, dict) and not c.get("keyless")]
    keyed_ok = all(
        isinstance(c, dict) and c.get("key_env") for n, c in engines.items() if n in keyed
    )
    check(
        "G-S1 registries",
        bool(keyless) and bool(keyed) and keyed_ok,
        f"engines={len(engines)} keyless={keyless} keyed_with_env={keyed_ok}",
    )
    dorks_reg = load_dorks_registry(params)
    host_dorks = dorks_reg.get("builtin_host_dorks") or []
    github_dorks = dorks_reg.get("github_dorks") or []
    check(
        "G-S1 dorks-corpus",
        len(host_dorks) >= 4 and len(github_dorks) >= 4,
        f"builtin_host_dorks={len(host_dorks)} github_dorks={len(github_dorks)}",
    )

    # ---- G-S2 PSV wiring ---------------------------------------------------
    import inspect

    import pipeline.engine as engine_mod

    wired = "passive-recon" in RUNNERS
    has_runner_fn = hasattr(engine_mod, "_run_passive_modules")
    modules = params.require("passive_branch_modules")
    pipeline_modules = params.require("pipeline_modules")
    layout = params.require("recon_layout_dirs")
    check(
        "G-S2 psv-wiring",
        wired
        and has_runner_fn
        and modules == ["passive-recon"]
        and "passive-recon" in pipeline_modules
        and "10_subdomains/passive/sources" in layout,
        f"RUNNERS={wired} engine_runner={has_runner_fn} passive_branch_modules={modules}",
    )

    # ---- G-S3 tool specs assemble ------------------------------------------
    clock = FakeClock()
    breaker = CircuitBreaker(params, clock=clock, target_dir=ROOT, target="example.com")
    ceiling = ResourceCeiling(params)
    adapter = Adapter(params, ROOT, breaker, ceiling, clock=clock, runner=ScriptedRunner())
    assemble_map = {
        "curl-fetch": {"fetch_cmd": "curl -sS http://x"},
        "crtsh": {"crtsh_url": "https://crt.sh/?q=%.example.com&output=json", "fetch_max_time": "120"},
        "certspotter": {"fetch_max_time": "120"},
        "cdx-fallback": {"fetch_max_time": "60"},
        "subfinder": {},
        "amass": {},
        "assetfinder": {},
        "assetfinder-related": {},
        "assetfinder-resolved": {"puredns_input": "/recon/i", "puredns_resolvers": "/recon/r"},
        "puredns-fallback-dnsx": {"dnsx_hosts": "/recon/i", "dnsx_resolvers": "/recon/r", "dnsx_max_qps": 1000},
        "chaos": {},
        "findomain": {},
        "waybackurls": {},
        "gau": {},
        "httpx-passive": {"httpx_list": "/recon/l", "httpx_output": "/recon/o"},
    }
    missing = []
    for tool, extra in assemble_map.items():
        try:
            values = dict(params.settings)
            values.update({"target_domain": "example.com", **extra})
            argv = adapter.assemble(tool, values, tool)
            if not argv:
                missing.append(tool)
        except Exception:  # noqa: BLE001
            missing.append(tool)
    check("G-S3 passive-specs", not missing, f"assemblable={len(assemble_map) - len(missing)}/{len(assemble_map)} missing={missing}")

    # ---- G-S4 tools.lock pins ----------------------------------------------
    lock_images = params.lock.get("images") or {}
    unpinned = []
    for tool, extra in assemble_map.items():
        ref = str((params.tools.get(tool) or {}).get("image_ref") or "")
        row = lock_images.get(ref) or {}
        if not row.get("image"):
            unpinned.append(f"{tool}:{ref}")
    check("G-S4 tools.lock-pins", not unpinned, f"unpinned={unpinned}")

    # ---- G-S5 committed defaults + append-only order ------------------------
    defaults = {
        "passive_recursion_depth": 2,
        "max_seeds_per_iteration": 100,
        "amass_timeout_min": 20,
        "dork_timeout_sec": 60,
        "crtsh_max_time_sec": 120,
        "crtsh_retries": 3,
        "httpx_threads": 200,
        "github_search_req_per_min": 30,
        "ct_fallback_tool": "certspotter",
    }
    bad = {k: params.require(k) for k, v in defaults.items() if params.require(k) != v}
    probe_on = bool(params.require("passive_httpx_probe"))
    active_order = params.require("active_branch_modules")
    order_ok = active_order == ["ffuf", "dns-resolve", "ffuf-3", "port-check"]
    check(
        "G-S5 committed-defaults",
        not bad and probe_on and order_ok,
        f"violations={bad} probe_on={probe_on} active_order_ok={order_ok}",
    )

    # ---- G-S6 verify_b1 clean ----------------------------------------------
    diff = subprocess.run(
        ["git", "diff", "HEAD", "--stat", "--", "pipeline/verify_b1.py"],
        cwd=ROOT, capture_output=True, text=True, check=False,
    )
    check("G-S6 verify_b1-clean", diff.stdout.strip() == "", "no working-tree diff")

    # ---- G-S7 vehicle scope --------------------------------------------------
    scope = load_yaml_file(str(ROOT / "scope.yaml"))
    includes = [str(i) for i in (scope.get("includes") or [])]
    check(
        "G-S7 vehicle-scope",
        "example.com" in includes and "*.example.com" in includes,
        f"includes={includes}",
    )

    # ---- G-S8 unit suite coverage -------------------------------------------
    test_text = (ROOT / "tests" / "test_passive.py").read_text(encoding="utf-8")
    markers = ("SearchForgeTest", "CandidatesTest", "SubStepsTest", "OrchestratorTest")
    covered = all(m in test_text for m in markers)
    check("G-S8 unit-coverage", covered, f"classes={markers}")

    print(f"PREFLIGHT {'PASS' if not failures else 'FAIL'} ({len(failures)} failing)")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
