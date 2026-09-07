"""TEST 4 (T4-B) -- restore verification (offline gates, run on the runner).

Verifies that the committed config is back at the production/real-run state:
  C1  selection defaults active: NO test-mode `selection:` overrides in
      wordlists.yaml; tools.yaml config-defaults are the three real keys
      (dnsr_1_wordlist_key=dns_fast_top5000,
       ffuf_0_selection_keys=[dns_fast_top5000, dns_exp_combined, vhost_top5000],
       ffuf_2_wordlist_key=vhost_top5000)
  C2  DNSR-1 materialization from the restored config reproduces the
      TEST-1-proven effective wordlist: 4860 lines, sha256 a94ea1d5...1695
  C3  REM7 fixture-era pin RESTORED: resolver_min_healthy_count == 100
  C5  REM9 correction STANDS (documented permanent fix, not restored):
      portcheck_top_ports == 100 (naabu v2.3.5 accepts only 100|1000|full;
      the as-frozen 50 was never executable)
  C6  verify_b1.py working-tree diff empty

Writes ci/test4_restore_result.json as evidence for the C-table assertions.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from pipeline.params import Params  # noqa: E402
from pipeline.wordlist_forge import materialize_effective  # noqa: E402
from pipeline.yaml_util import load_yaml_file  # noqa: E402

TEST1_DNSR1_ANCHOR = "a94ea1d5d791b6c105bbca2ec064d1a1396e8271d1c8ce6c857f39cef3c71695"
TEST1_DNSR1_LINES = 4860
OUT = ROOT / "ci" / "test4_restore_result.json"

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

    # C1 selection defaults
    wl = load_yaml_file(str(ROOT / "wordlists.yaml"))
    tasks = wl.get("tasks") or {}
    overrides = {t: (tasks.get(t) or {}).get("selection") for t in ("DNSR-1", "FFUF-0", "FFUF-2")}
    no_overrides = all(v is None for v in overrides.values())
    d1 = str(params.require("dnsr_1_wordlist_key"))
    f0 = [str(x) for x in params.require("ffuf_0_selection_keys")]
    f2 = str(params.require("ffuf_2_wordlist_key"))
    defaults_ok = (
        d1 == "dns_fast_top5000"
        and f0 == ["dns_fast_top5000", "dns_exp_combined", "vhost_top5000"]
        and f2 == "vhost_top5000"
    )
    check("C1 selection-defaults-active", no_overrides and defaults_ok,
          f"wordlists.selection_overrides={overrides} tools defaults: dnsr_1={d1} ffuf_0={f0} ffuf_2={f2}")

    # C2 DNSR-1 materialization == TEST-1-proven wordlist
    try:
        eff = materialize_effective(params, "DNSR-1")
        data = eff.read_bytes()
        sha = hashlib.sha256(data).hexdigest()
        lines = len([ln for ln in data.decode("utf-8", errors="replace").splitlines() if ln.strip()])
        check("C2 dnsr1-restored-materialization", lines == TEST1_DNSR1_LINES and sha == TEST1_DNSR1_ANCHOR,
              f"effective-DNSR-1 lines={lines} sha={sha} (TEST-1 anchor {TEST1_DNSR1_LINES} / {TEST1_DNSR1_ANCHOR[:12]}...)")
    except Exception as exc:
        check("C2 dnsr1-restored-materialization", False, f"materialization error: {exc}")

    # C3 REM7 restored
    v = int(params.require("resolver_min_healthy_count"))
    check("C3 rem7-threshold-restored", v == 100, f"resolver_min_healthy_count={v} (production value 100)")

    # C5 REM9 stands
    tp = str(params.require("portcheck_top_ports"))
    check("C5 rem9-correction-stands", tp == "100", f"portcheck_top_ports={tp} (naabu-valid; 50 was unexecutable)")

    # C6 verify_b1 clean
    diff = subprocess.run(
        ["git", "diff", "HEAD", "--stat", "--", "pipeline/verify_b1.py"],
        cwd=ROOT, capture_output=True, text=True,
    )
    check("C6 verify_b1-clean", diff.stdout.strip() == "", "no working-tree diff")

    OUT.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    print(f"RESTORE-VERIFY {'PASS' if not failures else 'FAIL'} ({len(failures)} failing)")
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
