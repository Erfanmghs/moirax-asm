"""TEST 4 (T4) acceptance table — resolver quarantine + selection restore + cleanup.

Reads the committed config, the restore-verification evidence
(ci/test4_restore_result.json) and the forge-quarantine evidence
(ci/test4_forge_result.json), then emits the C-table + final verdict line.
Exit 0 iff every MANDATORY assertion holds.

  C1 MANDATORY  selection defaults active (no test-mode overrides; tools.yaml
                config-defaults are the three real keys)
  C2 MANDATORY  DNSR-1 materialization reproduces the TEST-1-proven wordlist
                (4860 lines, sha a94ea1d5...)
  C3 MANDATORY  REM7 pin restored: resolver_min_healthy_count == 100
  C4 MANDATORY  quarantine machinery: injected non-DNS IPs all quarantined,
                healthy fleet preserved (subset of seed, >= 14 healthy)
  C5 MANDATORY  REM9 correction stands: portcheck_top_ports == 100
                (documented permanent correction; 50 was never executable)
  C6 MANDATORY  verify_b1.py diff empty
  C7 DISCLOSURE fleet protocol: committed seed = 15-anycast pin (REM5),
                public sources intact in the committed registry; the run-time
                source-disable remains a transient, never-committed edit
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

failures: list[str] = []
rows: list[tuple[str, str, str, str]] = []


def row(cid: str, kind: str, ok: bool, detail: str) -> None:
    verdict = "PASS" if ok else ("FAIL" if kind == "MANDATORY" else "DISCLOSED")
    rows.append((cid, kind, verdict, detail))
    print(f"{verdict}\t{cid}\t{detail}")
    if not ok and kind == "MANDATORY":
        failures.append(cid)


def load_result(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}


def main() -> int:
    restore = load_result(ROOT / "ci" / "test4_restore_result.json")
    forge = load_result(ROOT / "ci" / "test4_forge_result.json")

    for cid in ("C1", "C2", "C3"):
        entry = restore.get(cid) or {}
        row(cid, "MANDATORY", bool(entry.get("ok")), str(entry.get("detail") or "restore-verify evidence MISSING"))

    c4_entries = {k: v for k, v in forge.items() if isinstance(v, dict) and "ok" in v}
    c4_ok = bool(c4_entries) and all(v.get("ok") for v in c4_entries.values())
    row("C4", "MANDATORY", c4_ok,
        f"quarantine checks={ {k: v.get('ok') for k, v in c4_entries.items()} } "
        f"healthy={len(forge.get('healthy') or [])} quarantined_file={forge.get('quarantined_file')} "
        f"or forge evidence MISSING")

    entry = restore.get("C5") or {}
    row("C5", "MANDATORY", bool(entry.get("ok")), str(entry.get("detail") or "restore-verify evidence MISSING"))
    entry = restore.get("C6") or {}
    row("C6", "MANDATORY", bool(entry.get("ok")), str(entry.get("detail") or "restore-verify evidence MISSING"))

    seed_path = ROOT / "resolvers" / "seed.txt"
    seed_n = len([ln for ln in seed_path.read_text(encoding="utf-8").splitlines()
                  if ln.strip() and not ln.strip().startswith("#")])
    reg = ROOT / "resolvers.yaml"
    reg_txt = reg.read_text(encoding="utf-8") if reg.is_file() else ""
    sources_intact = "trickest" in reg_txt and "proabiral" in reg_txt
    row("C7", "DISCLOSURE", True,
        f"committed seed={seed_n} anycast (REM5); committed public sources intact={sources_intact}; "
        f"run-time source-disable is a transient working-copy edit (never committed)")

    verdict = "PASS" if not failures else "FAIL"
    print(f"VERDICT\tTEST 4 (QUARANTINE+RESTORE, T4): {verdict} ({len(failures)} mandatory failures)")
    (ROOT / "ci" / "test4_verdict.txt").write_text(
        "\n".join(f"{c}\t{k}\t{v}\t{d}" for c, k, v, d in rows)
        + f"\nVERDICT\tTEST 4 (QUARANTINE+RESTORE, T4): {verdict}\n",
        encoding="utf-8",
    )
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
