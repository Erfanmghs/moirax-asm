"""B4 PORT-SWEEP preflight gates -- run BEFORE the vehicle `recon.sh run`.

  G-W1  committed portsweep defaults (scope all_resolved, duration
        24h min 1h, profile full, full cap 1000 pps, ramp 100/100/30s, retries
        2, timeout 1000ms, reprobe divisor 4, anomalous threshold 1000, nmap
        toggle OFF with max-rate 300, custom ports "" + cap 1000, concurrency
        50, template rate 100, canary connect 3s, sentinel limit 3)
  G-W2  wiring: RUNNERS has port-sweep; engine carries the post-MERGE hook;
        port-sweep NOT in active_branch_modules (it must never run inside the
        branch); pipeline_modules + append-only ACTIVE order intact
  G-W3  tool specs registered + adapter-assemblable: naabu / naabu-full /
        naabu-sweep / nmap-sv / dnsx-list (guarantee pass)
  G-W4  tools.lock pins an image for every new image_ref (naabu, nmap, dnsx)
  G-W5  spec constants: full range = 65,535 ports (module constant)
  G-W6  verify_b1.py has no working-tree diff (frozen since handoff)
  G-W7  vehicle scope: example.com retained
  G-W8  unit suite covers the stage: tests/test_portsweep.py markers

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
from pipeline.modules.port_sweep import _FULL_RANGE_PORTS  # noqa: E402
from pipeline.params import Params  # noqa: E402
from pipeline.yaml_util import load_yaml_file  # noqa: E402

failures: list[str] = []


def check(name: str, ok: bool, detail: str) -> None:
    mark = "PASS" if ok else "GATE-FAIL"
    print(f"{mark}\t{name}\t{detail}")
    if not ok:
        failures.append(name)


def main() -> int:
    params = Params(ROOT)

    # ---- G-W1 committed defaults -------------------------------------------
    defaults = {
        "portsweep_scope": "all_resolved",
        "portsweep_duration_hours": 24,
        "portsweep_duration_hours_min": 1,
        "portsweep_profile": "full",
        "portsweep_full_rate_cap": 1000,
        "portsweep_ramp_start_pps": 100,
        "portsweep_ramp_step_pps": 100,
        "portsweep_ramp_interval_sec": 30,
        "portsweep_retries": 2,
        "portsweep_timeout_ms": 1000,
        "portsweep_filtered_reprobe_divisor": 4,
        "portsweep_anomalous_open_threshold": 1000,
        "portsweep_nmap_sv": False,
        "portsweep_nmap_max_rate": 300,
        "portsweep_module": "port-sweep",
        "portsweep_custom_ports": "",
        "portsweep_custom_rate_cap": 1000,
        "portsweep_concurrency": 50,
        "portsweep_rate": 100,
        "portsweep_canary_connect_timeout_sec": 3,
        "portsweep_sentinel_limit": 3,
        "portsweep_data_json": "30_ports/naabu-full/data.json",
        "portsweep_summary": "30_ports/naabu-full/summary.md",
    }
    bad = {k: params.require(k) for k, v in defaults.items() if params.require(k) != v}
    check("G-W1 committed-defaults", not bad, f"violations={bad}")

    # ---- G-W2 wiring ---------------------------------------------------------
    engine_text = (ROOT / "pipeline" / "engine.py").read_text(encoding="utf-8")
    hook_present = (
        "portsweep_module" in engine_text
        and "post-MERGE" in engine_text
        and "ffuf4_module" in engine_text
    )
    runners_ok = "port-sweep" in RUNNERS and "ffuf-4" in RUNNERS
    active_order = params.require("active_branch_modules")
    not_in_branch = "port-sweep" not in active_order and "ffuf-4" not in active_order
    pipeline_modules = params.require("pipeline_modules")
    declared = "port-sweep" in pipeline_modules and "ffuf-4" in pipeline_modules
    order_ok = active_order == ["dns-resolve", "ffuf", "ffuf-3", "port-check"]
    check(
        "G-W2 wiring",
        hook_present and runners_ok and not_in_branch and declared and order_ok,
        f"hook={hook_present} runner={runners_ok} not_in_branch={not_in_branch} declared={declared} order_ok={order_ok}",
    )

    # ---- G-W3 tool specs assemble -------------------------------------------
    clock = FakeClock()
    breaker = CircuitBreaker(params, clock=clock, target_dir=ROOT, target="example.com")
    ceiling = ResourceCeiling(params)
    adapter = Adapter(params, ROOT, breaker, ceiling, clock=clock, runner=ScriptedRunner())
    assemble_map = {
        "naabu": {},
        "naabu-full": {},
        "naabu-sweep": {"portsweep_ports_arg": "80,443"},
        "nmap-sv": {"nmap_ports_arg": "80,443"},
        "dnsx-list": {"dnsx_hosts": "/recon/h", "dnsx_resolvers": "/recon/r", "dnsx_max_qps": 1000},
    }
    missing = []
    for tool, extra in assemble_map.items():
        try:
            values = dict(params.settings)
            values.update({"target_domain": "example.com", "naabu_host": "93.184.215.14", **extra})
            argv = adapter.assemble(tool, values, tool)
            if not argv:
                missing.append(tool)
        except Exception:  # noqa: BLE001
            missing.append(tool)
    check("G-W3 sweep-specs", not missing, f"assemblable={len(assemble_map) - len(missing)}/{len(assemble_map)} missing={missing}")

    # ---- G-W4 tools.lock pins ------------------------------------------------
    lock_images = params.lock.get("images") or {}
    unpinned = []
    for tool, extra in assemble_map.items():
        ref = str((params.tools.get(tool) or {}).get("image_ref") or "")
        row = lock_images.get(ref) or {}
        if not row.get("image"):
            unpinned.append(f"{tool}:{ref}")
    check("G-W4 tools.lock-pins", not unpinned, f"unpinned={unpinned}")

    # ---- G-W5 spec constants --------------------------------------------------
    check("G-W5 full-range", _FULL_RANGE_PORTS == 65535, f"_FULL_RANGE_PORTS={_FULL_RANGE_PORTS}")

    # ---- G-W6 verify_b1 clean -------------------------------------------------
    diff = subprocess.run(
        ["git", "diff", "HEAD", "--stat", "--", "pipeline/verify_b1.py"],
        cwd=ROOT, capture_output=True, text=True, check=False,
    )
    check("G-W6 verify_b1-clean", diff.stdout.strip() == "", "no working-tree diff")

    # ---- G-W7 vehicle scope ---------------------------------------------------
    scope = load_yaml_file(str(ROOT / "scope.yaml"))
    includes = [str(i) for i in (scope.get("includes") or [])]
    check(
        "G-W7 vehicle-scope",
        "example.com" in includes and "*.example.com" in includes,
        f"includes={includes}",
    )

    # ---- G-W8 unit coverage ----------------------------------------------------
    test_text = (ROOT / "tests" / "test_portsweep.py").read_text(encoding="utf-8")
    markers = (
        "test_ip_dedup_one_invocation_two_hosts",
        "test_resolution_guarantee_resolves_and_excludes",
        "test_pacing_formula_full_profile",
        "test_window_breach_partials_with_remaining_list",
        "test_no_overlap_previous_in_progress",
        "test_filtered_suspect_after_reprobe",
        "test_nmap_toggle_off_zero_containers",
        "test_target_set_materialized_before_scan",
    )
    covered = all(m in test_text for m in markers)
    check("G-W8 unit-coverage", covered, f"markers={len(markers)}")

    print(f"PREFLIGHT {'PASS' if not failures else 'FAIL'} ({len(failures)} failing)")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
