#!/usr/bin/env python3
"""C2 WORDLIST UNIVERSE vehicle assertions (C2-1..C2-8).

Mandate (release phase): ALL SecLists available and selectable, operator
custom lists addable, passive finds feeding a selectable platform-learned
list -- proven in-CI against the REAL SecLists clone.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

failures: list[str] = []


def check(name: str, ok: bool, detail: str) -> None:
    mark = "PASS" if ok else "FAIL"
    print(f"{mark}\t{name}\t{detail}")
    if not ok:
        failures.append(name)


def git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=True).stdout


def main() -> int:
    from pipeline.custom_lists import list_custom_lists
    from pipeline.params import Params
    from pipeline.wordlist_forge import materialize_effective, selected_keys
    from pipeline.wordlists import WordlistRegistry
    from pipeline.yaml_util import load_yaml_file

    params = Params(ROOT)

    # C2-1 generated index exists, parses, covers the real SecLists tree
    idx_rel = str(params.require("wordlists_generated_index"))
    idx_path = ROOT / idx_rel
    ok = idx_path.is_file()
    doc = load_yaml_file(str(idx_path)) if ok else None
    n_lists = len((doc or {}).get("lists") or {})
    check("C2-1 seclists-index", ok and n_lists >= 500, f"lists={n_lists} file={idx_rel}")

    # C2-2 registry merge: generated + custom visible; curated wins collisions
    reg = WordlistRegistry(params)
    check("C2-2 registry-merge", len(reg.generated_index) >= 500 and len(reg.custom_index) >= 1,
          f"generated={len(reg.generated_index)} custom={len(reg.custom_index)}")

    # C2-3 registry-wide law on exactly the three fuzzing tasks
    tasks_doc = load_yaml_file(str(ROOT / "wordlists.yaml")).get("tasks") or {}
    flagged = sorted(t for t, s in tasks_doc.items() if isinstance(s, dict) and s.get("allow_registry_wide"))
    check("C2-3 registry-wide-flag", flagged == ["DNSR-1", "FFUF-0", "FFUF-2"], f"flagged={flagged}")
    sample_key = sorted(reg.generated_index)[0] if reg.generated_index else ""
    all_ok = bool(sample_key) and all(sample_key in reg.allowed_keys(t) for t in ("DNSR-1", "FFUF-0", "FFUF-2"))
    check("C2-3 registry-wide-selectable", all_ok, f"sample={sample_key}")

    # C2-4 custom list registered by the vehicle
    custom = list_custom_lists(params)
    check("C2-4 custom-add", "release-fixtures" in custom, f"custom keys={sorted(custom)}")

    # C2-5 materialization honors a generated-key selection
    eff = ROOT / "wordlists" / "forge" / "effective-FFUF-0.txt"
    sel = selected_keys(params, "FFUF-0")
    check("C2-5 selection-honored", bool(sel), f"selection={sel[:3]}")
    check("C2-5 materialized", eff.is_file() and eff.stat().st_size > 0,
          f"effective-FFUF-0 bytes={eff.stat().st_size if eff.is_file() else 0}")

    # C2-6 platform learning fed by the synthetic run tree
    learned = ROOT / "wordlists" / "custom" / "platform-learned.txt"
    labels = [ln.strip() for ln in learned.read_text(encoding="utf-8").splitlines() if ln.strip()] if learned.is_file() else []
    check("C2-6 platform-learned", len(labels) >= 1, f"labels={labels[:8]}")
    idx_custom = load_yaml_file(str(ROOT / str(params.require("wordlists_custom_index"))))
    check("C2-6 learned-entries-accurate",
          int((idx_custom["lists"].get("platform_learned") or {}).get("entries") or 0) == len(labels),
          f"index={idx_custom['lists'].get('platform_learned')} file_lines={len(labels)}")

    # C2-7 CLI surface exists (wordlist-sync/add/rm wired)
    usage = (ROOT / "pipeline" / "cli.py").read_text(encoding="utf-8")
    check("C2-7 cli-surface", all(c in usage for c in ("wordlist-sync", "wordlist-add", "wordlist-rm")),
          "cli commands wired")

    # C2-8 integrity: pipeline frozen at HEAD tree + verify_b1 untouched
    diff_b1 = git("diff", "HEAD", "--", "pipeline/verify_b1.py")
    check("C2-8 verify_b1-empty", diff_b1.strip() == "", "verify_b1 diff EMPTY")
    ALLOW = (".github/", "wordlists/", "wordlists.yaml", "recon/", "ci/")
    dirty = [ln for ln in git("status", "--porcelain").splitlines() if ln.strip()]
    bad = [ln[3:].strip().strip('"') for ln in dirty if not ln[3:].strip().strip('"').startswith(ALLOW)]
    check("C2-8 dirty-allowlist", not bad, f"unexpected={bad[:6]} dirty={len(dirty)}")

    verdict = "PASS" if not failures else "FAIL:" + ",".join(failures)
    line = f"C2 WORDLIST UNIVERSE VERDICT: {verdict}"
    print(line)
    (ROOT / "ci" / "c2_verdict.txt").write_text(line + "\n", encoding="utf-8")
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
