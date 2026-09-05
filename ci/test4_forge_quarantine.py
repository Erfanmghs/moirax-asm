"""TEST 4 (T4-A) — resolver quarantine machinery proof (deterministic injection).

The forge contract (pipeline/resolver_forge.py docstring): aggregate, validate,
quarantine <80% answer ratio, >= min_healthy gate. Never deterministically
proven on the runner era (the fixture runs validated only the 15-anycast seed).

Harness (transient working-copy edits only, NEVER committed; before-copy kept
as evidence like REM5):
  1. resolvers.yaml: sources disabled (determinism + speed) and three
     public, deliberately non-DNS IPs injected via manual_add:
       93.184.216.34   (classic example.com web IP - HTTP, no DNS service)
       151.101.1.140   (Fastly web IP - no DNS service)
       45.33.32.156    (Linode scanme - HTTP, no DNS service)
  2. forge_resolvers() runs for real: dnsx-probe validates every candidate
     against resolver_validate_domains at resolver_validate_concurrency=4.
  3. Assertions:
       injected dead IPs are ALL quarantined (quarantine.txt) and absent
       from the healthy fleet (custom-resolvers.txt);
       healthy fleet is a subset of the 15-anycast seed with >= 14 healthy
       (run #7 measured 14/15 anycast healthy);
       run.log carries the "quarantined:" disclosure line.

Writes ci/test4_forge_result.json as evidence for assertion C4.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from pipeline.adapter import Adapter  # noqa: E402
from pipeline.breaker import CircuitBreaker, Clock  # noqa: E402
from pipeline.ceiling import ResourceCeiling  # noqa: E402
from pipeline.params import Params  # noqa: E402
from pipeline.resolver_forge import forge_resolvers  # noqa: E402
from pipeline.textio import read_lines  # noqa: E402

DEAD = ["93.184.216.34", "151.101.1.140", "45.33.32.156"]
SCRATCH_TARGET = "test4-scratch.test"
OUT = ROOT / "ci" / "test4_forge_result.json"

failures: list[str] = []
results: dict = {}


def check(name: str, ok: bool, detail: str) -> None:
    mark = "PASS" if ok else "GATE-FAIL"
    print(f"{mark}\t{name}\t{detail}")
    results[name] = {"ok": ok, "detail": detail}
    if not ok:
        failures.append(name)


def main() -> int:
    params = Params(ROOT)
    before = ROOT / "ci" / "test4_resolvers_before.yaml"
    reg_path = ROOT / "resolvers.yaml"
    before.write_text(reg_path.read_text(encoding="utf-8"), encoding="utf-8")

    # Transient registry, written in the project's own minimal-YAML style
    # (pipeline/yaml_util.load_yaml parses ONLY indented block lists; a
    # pyyaml safe_dump of a non-empty list emits 0-indent items that the
    # frozen loader rejects: "list item where mapping expected").
    reg_text = "\n".join(
        ["schema_version: 1", "sources: []", "manual_add:"]
        + [f"  - {ip}" for ip in DEAD]
        + ["manual_remove: []", ""]
    )
    reg_path.write_text(reg_text, encoding="utf-8")
    print(f"T4-A transient edit: sources disabled; injected {DEAD} via manual_add (project-style YAML). Never committed.")

    seed = {ln.strip() for ln in read_lines(ROOT / "resolvers" / "seed.txt") if ln.strip()}
    target_dir = ROOT / "recon" / SCRATCH_TARGET
    target_dir.mkdir(parents=True, exist_ok=True)
    clock = Clock()
    breaker = CircuitBreaker(params, clock=clock, target_dir=target_dir, target=SCRATCH_TARGET)
    ceiling = ResourceCeiling(params)
    adapter = Adapter(params, target_dir, breaker, ceiling, clock=clock)

    dest = forge_resolvers(params, adapter, target_dir, SCRATCH_TARGET)
    healthy = [ln.strip() for ln in read_lines(dest) if ln.strip()]
    q_path = ROOT / str(params.require("resolver_quarantine_output"))
    quarantined = [ln.strip() for ln in read_lines(q_path) if ln.strip()]

    results["healthy"] = healthy
    results["quarantined_file"] = quarantined
    results["injected"] = DEAD
    results["seed_size"] = len(seed)

    dead_set = set(DEAD)
    check("C4a injected-all-quarantined", dead_set.issubset(set(quarantined)),
          f"quarantine.txt={quarantined} injected={DEAD}")
    check("C4b injected-not-healthy", dead_set.isdisjoint(set(healthy)),
          f"healthy={len(healthy)} entries; overlap_with_injected={sorted(dead_set & set(healthy))}")
    check("C4c healthy-subset-of-seed", set(healthy).issubset(seed),
          f"healthy={len(healthy)} seed={len(seed)} non_seed_in_healthy={sorted(set(healthy) - seed)}")
    check("C4d healthy-count-plausible", len(healthy) >= 14,
          f"healthy={len(healthy)} (run #7 measured 14/15 anycast healthy; >=14 expected)")
    run_log = target_dir / str(params.require("run_log"))
    log_txt = run_log.read_text(encoding="utf-8", errors="replace") if run_log.is_file() else ""
    check("C4e quarantined-log-line", "quarantined:" in log_txt,
          f"run.log quarantined-line={'present' if 'quarantined:' in log_txt else 'MISSING'}")

    OUT.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    print(f"FORGE-QUARANTINE {'PASS' if not failures else 'FAIL'} ({len(failures)} failing)")
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
