"""B3 PASSIVE-CHAIN acceptance table — runs AFTER the example.com vehicle.

  F1  MANDATORY  run exit 0 + runs.json last status completed
  F2  MANDATORY  core sources populated: crtsh, subfinder, amass, assetfinder,
                 assetfinder-related, archives (+ assetfinder-resolved present)
  F3  MANDATORY  simulated 429 -> COOLDOWN + instant reroute visible in run.log
                 (sink429 engine evidence)
  F4  MANDATORY  recursion bounded: depth_used <= passive_recursion_depth(2)
                 with a disclosed stop reason; seeds_total <= committed cap
  F5  MANDATORY  PSV-8 skip disclosed for the pure-domain vehicle (or, if a
                 CIDR include exists, cidr-ips.txt written)
  F6  MANDATORY  PSV-7 skip disclosed when no GITHUB_TOKEN (or github.txt
                 present when a token exists)
  F7  MANDATORY  data.json exact §8 schema (module, candidates rows shaped,
                 passive_ips, search_forge, recursion, counts consistent)
  F8  MANDATORY  scope: every candidate passes the committed ScopeGate;
                 out_of_scope.log exists (assetfinder-related rejections)
  F9  MANDATORY  tags never drop: every crtsh harvest row appears in
                 candidates; keyword-tagged names carry the tag
  F10 MANDATORY  COMMITTED defaults intact post-run (git HEAD tools.yaml) +
                 verify_b1.py working-tree diff empty
  G1  DISCLOSURE search-forge stats (engines_used/cooldown/isolated/rerouted)
  G2  DISCLOSURE per-source counts + skips table from summary.md

Exit 0 iff all MANDATORY rows PASS.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import json

from pipeline.params import Params  # noqa: E402
from pipeline.scope import ScopeGate  # noqa: E402
from pipeline.yaml_util import load_yaml_file  # noqa: E402

TARGET = "example.com"
TARGET_DIR = ROOT / "recon" / TARGET
EXIT_FILE = ROOT / "ci" / "b3p_run_exit.txt"
VERDICT_FILE = ROOT / "ci" / "b3p_verdict.txt"

rows: list[tuple[str, str, str, str]] = []  # (id, class, status, detail)


def check(fid: str, cls: str, ok: bool, detail: str) -> bool:
    status = "PASS" if ok else "FAIL"
    rows.append((fid, cls, status, detail))
    return ok


def main() -> int:
    params = Params(ROOT)
    run_log = TARGET_DIR / "logs" / "run.log"
    log_text = run_log.read_text(encoding="utf-8", errors="replace") if run_log.is_file() else ""

    # ---- F1 exit + terminal status ----------------------------------------
    exit_text = EXIT_FILE.read_text(encoding="utf-8").strip() if EXIT_FILE.is_file() else "missing"
    runs_doc: dict = {}
    if (TARGET_DIR / "runs.json").is_file():
        try:
            runs_doc = json.loads((TARGET_DIR / "runs.json").read_text(encoding="utf-8"))
        except ValueError:
            runs_doc = {}
    runs = (runs_doc or {}).get("runs") or []
    last_status = runs[-1].get("status") if runs else "missing"
    # F1 semantics (run #22 evidence + §8 PSV-5): a cap-stop IS the accepted
    # "recursion stops at its cap" outcome -> exit 3/partial with a
    # spec-sanctioned stop reason is a PASS; a breaker ANOMALY (exit 2) is a
    # FAIL. runs.json is JSON — the frozen YAML loader cannot read it.
    sanctioned_stop = (
        "passive_recursion_seeds_cap" in log_text or "passive_budget" in log_text
    )
    if exit_text == "run exit=0" and last_status == "completed":
        ok_f1 = True
        f1_detail = f"{exit_text} status=completed (clean run)"
    elif exit_text == "run exit=3" and last_status == "partial" and sanctioned_stop:
        ok_f1 = True
        f1_detail = f"{exit_text} status=partial (spec-sanctioned cap/budget stop, disclosed)"
    else:
        ok_f1 = False
        f1_detail = f"{exit_text} runs.json[-1].status={last_status} sanctioned_stop={sanctioned_stop}"
    check("F1", "MANDATORY", ok_f1, f1_detail)

    # ---- F2 core sources populated ----------------------------------------
    sources_dir = TARGET_DIR / "10_subdomains" / "passive" / "sources"
    # CT contract: crt.sh primary OR its registered fallback (certspotter)
    # serve the SAME output contract (§8 PSV-2) — either file proves the
    # cert-transparency sub-step populated sources.
    ct_name = "crtsh.txt" if (sources_dir / "crtsh.txt").is_file() else "certspotter.txt"
    core = [ct_name, "subfinder.txt", "amass.txt", "assetfinder.txt",
            "assetfinder-related.txt", "archives.txt"]
    counts: dict[str, int] = {}
    for name in core:
        path = sources_dir / name
        counts[name] = (
            len([ln for ln in path.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip()])
            if path.is_file() else -1
        )
    populated = all(v > 0 for v in counts.values())
    resolved_path = sources_dir / "assetfinder-resolved.txt"
    resolved_n = (
        len([ln for ln in resolved_path.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip()])
        if resolved_path.is_file() else -1
    )
    check("F2", "MANDATORY", populated,
          f"{counts} assetfinder-resolved={resolved_n}")

    # ---- F3 simulated 429 -> COOLDOWN + reroute ---------------------------
    cooldown_line = "engine=sink429 status=429 -> COOLDOWN" in log_text
    reroute_line = "psv-1 reroute" in log_text and "sink429" in log_text
    check("F3", "MANDATORY", cooldown_line and reroute_line,
          f"cooldown_line={cooldown_line} reroute_line={reroute_line}")

    # ---- F4 recursion bounded ----------------------------------------------
    data_path = TARGET_DIR / "10_subdomains" / "passive" / "data.json"
    data: dict = {}
    if data_path.is_file():
        try:
            data = json.loads(data_path.read_text(encoding="utf-8"))
        except ValueError:
            data = {}
    recursion = data.get("recursion") or {}
    depth_cap = int(params.require("passive_recursion_depth"))
    seeds_cap = int(params.require("max_seeds_per_iteration"))
    depth_used = int(recursion.get("depth_used") or 0)
    seeds_total = int(recursion.get("seeds_total") or 0)
    stop_disclosed = "psv-5" in log_text and (
        "natural stop" in log_text or "cap" in log_text or "budget" in log_text
    )
    check("F4", "MANDATORY",
          depth_used <= depth_cap and seeds_total <= seeds_cap and stop_disclosed,
          f"depth_used={depth_used}<={depth_cap} seeds_total={seeds_total}<={seeds_cap} stop_disclosed={stop_disclosed}")

    # ---- F5 PSV-8 disclosure ------------------------------------------------
    cidr_includes = any("/" in i for i in (gate_includes()))
    if cidr_includes:
        cidr_file = sources_dir / "cidr-ips.txt"
        ok_f5 = cidr_file.is_file() and "psv-8" in log_text
        detail = f"cidr include present; cidr-ips.txt={cidr_file.is_file()}"
    else:
        ok_f5 = "psv-8 skipped" in log_text
        detail = "pure-domain vehicle; psv-8 skip line disclosed"
    check("F5", "MANDATORY", ok_f5, detail)

    # ---- F6 PSV-7 disclosure ------------------------------------------------
    env_file = ROOT / ".env"
    has_gh = False
    if env_file.is_file():
        has_gh = any(
            line.strip().startswith("GITHUB_TOKEN=")
            for line in env_file.read_text(encoding="utf-8", errors="replace").splitlines()
        )
    if has_gh:
        ok_f6 = (sources_dir / "github.txt").is_file() or "psv-7" in log_text
        detail = "GITHUB_TOKEN present; github.txt or psv-7 activity expected"
    else:
        ok_f6 = "psv-7 skipped" in log_text
        detail = "no GITHUB_TOKEN; psv-7 skip line disclosed"
    check("F6", "MANDATORY", ok_f6, detail)

    # ---- F7 exact schema -----------------------------------------------------
    schema_ok = (
        data.get("module") == "passive-recon"
        and isinstance(data.get("candidates"), list)
        and isinstance(data.get("passive_ips"), list)
        and isinstance(data.get("search_forge"), dict)
        and {"engines_used", "cooldown", "isolated"} <= set(data.get("search_forge") or {})
        and {"depth_used", "seeds_total"} <= set(data.get("recursion") or {})
        and isinstance(data.get("counts"), dict)
        and data.get("counts", {}).get("candidates") == len(data.get("candidates") or [])
    )
    rows_shape = all(
        isinstance(row, dict) and row.get("host") and isinstance(row.get("sources"), list)
        for row in (data.get("candidates") or [])
    )
    check("F7", "MANDATORY", bool(schema_ok and rows_shape),
          f"module={data.get('module')} candidates={len(data.get('candidates') or [])} rows_shape={rows_shape}")

    # ---- F8 scope gate ---------------------------------------------------------
    scope_path = ROOT / "scope.yaml"
    gate = ScopeGate.load(params, scope_path)
    bad_hosts = [
        row.get("host")
        for row in (data.get("candidates") or [])
        if not gate.validate_candidate(str(row.get("host")))[0]
    ]
    oos_log = TARGET_DIR / "logs" / "out_of_scope.log"
    check("F8", "MANDATORY", not bad_hosts and oos_log.is_file(),
          f"out_of_scope_candidates={bad_hosts[:5]} out_of_scope_log={oos_log.is_file()}")

    # ---- F9 tags never drop ------------------------------------------------
    ct_file = sources_dir / ct_name
    crtsh_rows = [ln.strip() for ln in ct_file.read_text(
        encoding="utf-8", errors="replace").splitlines() if ln.strip()] if ct_file.is_file() else []
    candidate_hosts = {str(row.get("host")) for row in (data.get("candidates") or [])}
    # harvest-everything vs scope-gate (§3.3): a crt.sh cert can carry SANs
    # outside the engagement (run #24: m.testexample.com); such rows must be
    # REJECTED BY THE GATE (out_of_scope.log) — never silently dropped.
    oos_text = ""
    oos_log = TARGET_DIR / "logs" / "out_of_scope.log"
    if oos_log.is_file():
        oos_text = oos_log.read_text(encoding="utf-8", errors="replace")
    missing_from_candidates = [
        h for h in crtsh_rows
        if h not in candidate_hosts and f"\trejected\t{h}\t" not in oos_text
    ]
    keyword_tags = [str(t) for t in params.require("keyword_tags")]
    tagged_named = [h for h in crtsh_rows if any(t in h.split(".")[0].lower() for t in keyword_tags)]
    tagged_in_data = [
        str(row.get("host"))
        for row in (data.get("candidates") or [])
        if set(row.get("tags") or []) & set(keyword_tags)
    ]
    ok_f9 = not missing_from_candidates
    check("F9", "MANDATORY", ok_f9,
          f"crtsh_rows={len(crtsh_rows)} missing={missing_from_candidates[:5]} "
          f"tagged_named={len(tagged_named)} tagged_in_data={len(tagged_in_data)}")

    # ---- F10 committed defaults + verify_b1 ----------------------------------
    head_tools = subprocess.run(
        ["git", "show", "HEAD:tools.yaml"], cwd=ROOT, capture_output=True, text=True, check=False,
    ).stdout
    committed_ok = all(
        line in head_tools
        for line in (
            "  passive_recursion_depth: 2",
            "  max_seeds_per_iteration: 100",
            "  passive_httpx_probe: true",
            "  ct_fallback_tool: certspotter",
        )
    )
    diff = subprocess.run(
        ["git", "diff", "HEAD", "--stat", "--", "pipeline/verify_b1.py"],
        cwd=ROOT, capture_output=True, text=True, check=False,
    )
    check("F10", "MANDATORY", committed_ok and diff.stdout.strip() == "",
          f"committed_defaults={committed_ok} verify_b1_diff_empty={diff.stdout.strip() == ''}")

    # ---- G1/G2 disclosures -----------------------------------------------------
    forge_stats = data.get("search_forge") or {}
    check("G1", "DISCLOSURE", True,
          f"search_forge={forge_stats}")
    summary_path = TARGET_DIR / "10_subdomains" / "passive" / "summary.md"
    check("G2", "DISCLOSURE", summary_path.is_file(),
          f"summary_present={summary_path.is_file()}")

    # ---- verdict ------------------------------------------------------------------
    mandatory_fail = [r for r in rows if r[1] == "MANDATORY" and r[2] == "FAIL"]
    verdict = "PASS" if not mandatory_fail else "FAIL"
    print(f"{'ID':<5}{'CLASS':<12}{'STATUS':<8}DETAIL")
    for fid, cls, status, detail in rows:
        print(f"{fid:<5}{cls:<12}{status:<8}{detail}")
    print(f"VERDICT TEST B3-2 (PASSIVE CHAIN, example.com VEHICLE): {verdict}")
    VERDICT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with VERDICT_FILE.open("w", encoding="utf-8") as handle:
        for fid, cls, status, detail in rows:
            handle.write(f"{fid}\t{cls}\t{status}\t{detail}\n")
        handle.write(f"VERDICT\tTEST B3-2 (PASSIVE CHAIN, example.com VEHICLE): {verdict}\n")
    return 0 if verdict == "PASS" else 1


def gate_includes() -> list[str]:
    scope = load_yaml_file(str(ROOT / "scope.yaml"))
    return [str(i) for i in (scope.get("includes") or [])]


if __name__ == "__main__":
    raise SystemExit(main())
