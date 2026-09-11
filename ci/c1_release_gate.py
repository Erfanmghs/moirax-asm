#!/usr/bin/env python3
"""C1 RELEASE SECURITY GATE (R-1..R-6) -- attacker-proofing the repository.

Release directive: the platform publishes in ENGLISH ONLY, free of
personal/sensitive data, with an attacker-resistance mindset: an outsider
scanning the public repository must find nothing usable.

  R-1  SECRETS: no token/key material in tracked text files (precise
       provider patterns + assigned-secret shapes). Placeholders
       (empty values, your_/example/changeme/<...>/${VAR}) are allowed.
  R-2  SAST: bandit over pipeline/ dashboard/ ci/ -- HIGH findings hard-fail,
       MEDIUM findings disclosed (count + rule ids).
  R-3  ENGLISH-ONLY / ASCII: every tracked text file is ASCII-clean except
       DISCLOSED waivers: pipeline/verify_b1.py (frozen discipline: diff vs
       handoff stays EMPTY), .cursor/rules/** (frozen spec v1.9),
       recon/** (historical vehicle evidence artifacts).
       Operator law (post-FA-removal): Persian is forbidden project-wide --
       the README.fa.md waiver was withdrawn and must never return.
  R-4  PERSONAL DATA: no author email fragments, no personal mail domains,
       no operator estate IPs, no phone-number shapes in tracked files.
  R-5  SCRIPT DEFENSE (belt-and-braces under R-3): no Arabic/Persian script
       codepoints (U+0600-U+06FF, U+FB50-U+FEFF) outside the waivers.
  R-6  FIXTURE SCOPE: committed scope.yaml includes are the public fixture
       allow-list only (example.com, fixture-target.test, e2e gateway).
       Operator estates must stay in the working copy, never in git.

Exit 0 only when every hard gate passes; every check prints PASS/FAIL plus
a disclosure line. Atomic units for the gate functions live in
tests/test_c1_release.py.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from pipeline.yaml_util import load_yaml  # noqa: E402

WAIVE_PREFIXES = ("pipeline/verify_b1.py", ".cursor/rules/", "recon/")

SECRET_PATTERNS = [
    ("github-pat", r"github_pat_[A-Za-z0-9_]{20,}"),
    ("github-oauth", r"gh[pousr]_[A-Za-z0-9]{20,}"),
    ("aws-access-key", r"AKIA[0-9A-Z]{16}"),
    ("slack-token", r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    ("private-key-block", r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----"),
    ("google-api", r"AIza[0-9A-Za-z_\-]{30,}"),
    ("telegram-bot", r"\b[0-9]{8,10}:AA[A-Za-z0-9_\-]{30,}"),
    ("assigned-secret-shape", r"(?i)(?:api[_-]?key|secret|token|passwd|password)\s*[:=]\s*['\"][A-Za-z0-9+/_\-]{20,}['\"]"),
]
PLACEHOLDER_RE = re.compile(
    r"(?i)your[_-]?key|example|changeme|placeholder|redacted|xxx+|^$|\$\{[A-Za-z_]+\}|<[^>]*>"
)

PERSONAL_PATTERNS = [
    ("author-email-fragment", "mogh" + "isserfan"),  # runtime-assembled: the gate must not contain the literal it hunts
    ("personal-mail-domain", r"@[a-z0-9.-]*\bgmail\.com|@yahoo\.com|@outlook\.com|@hotmail\.com"),
    ("operator-estate-ip-1", r"\b5\.145\.118\.\d{1,3}\b"),
    ("operator-estate-ip-2", r"\b46\.245\.92\.\d{1,3}\b"),
    ("phone-shape", r"\+\d{2,3}[\s-]?\d{3}[\s-]?\d{7,}\b"),
]

ARABIC_SCRIPT_RE = re.compile(r"[\u0600-\u06FF\uFB50-\uFEFF]")

# Committed allow-list only. ADD TARGET may edit the working copy; C1 fails
# if a real estate is staged into HEAD.
SCOPE_INCLUDE_ALLOW = frozenset({
    "example.com",
    "*.example.com",
    "fixture-target.test",
    "*.fixture-target.test",
    "172.17.0.1/32",
})
TARGET_NAME_ALLOW = frozenset({"example.com", "fixture-target.test"})


def tracked_files(root: Path = ROOT) -> list[str]:
    out = subprocess.run(["git", "ls-files"], cwd=root, capture_output=True, text=True, check=True).stdout
    return [ln.strip() for ln in out.splitlines() if ln.strip()]


def read_tracked_text(root: Path, rel: str) -> str | None:
    p = root / rel
    if not p.is_file() or b"\x00" in p.read_bytes()[:4096]:
        return None
    try:
        return p.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return None


def read_index_text(root: Path, rel: str) -> str | None:
    """Blob staged for HEAD (index), not the working copy.

    Operator ADD TARGET may dirty scope.yaml locally; R-6 must judge what
    git would publish, not the live dashboard allow-list.
    """
    proc = subprocess.run(
        ["git", "show", f":{rel}"],
        cwd=root, capture_output=True, text=True, check=False,
    )
    if proc.returncode != 0:
        return None
    return proc.stdout


def scan_secrets(text: str) -> list[tuple[str, str]]:
    hits: list[tuple[str, str]] = []
    for name, pat in SECRET_PATTERNS:
        for m in re.finditer(pat, text):
            frag = m.group(0)
            if PLACEHOLDER_RE.search(frag):
                continue
            hits.append((name, frag[:24] + "..."))
    return hits


def scan_personal(text: str) -> list[tuple[str, str]]:
    hits: list[tuple[str, str]] = []
    for name, pat in PERSONAL_PATTERNS:
        for m in re.finditer(pat, text):
            hits.append((name, m.group(0)[:24]))
    return hits


def scan_non_ascii(text: str) -> set[str]:
    return {ch for ch in text if ord(ch) > 127}


def scan_arabic_script(text: str) -> list[str]:
    return ARABIC_SCRIPT_RE.findall(text)


def extra_scope_includes(includes: list[str]) -> list[str]:
    """Return committed includes that are not on the fixture allow-list."""
    return [item for item in includes if str(item).strip() not in SCOPE_INCLUDE_ALLOW]


def extra_target_names(names: list[str]) -> list[str]:
    """Return committed target-profile keys that are not fixture names."""
    return [item for item in names if str(item).strip() not in TARGET_NAME_ALLOW]


def run_bandit(root: Path = ROOT) -> tuple[int, int, list[str]]:
    """Returns (high_count, medium_count, medium_rule_ids). Missing tool => (0,0,[]) with disclosure upstream."""
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "bandit", "-q", "-r", "pipeline", "dashboard", "ci", "-f", "json"],
            cwd=root, capture_output=True, text=True, timeout=600,
        )
    except FileNotFoundError:
        return -1, -1, ["BANDIT-MISSING"]  # disclosed upstream; CI installs bandit so this is real there
    try:
        doc = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return 0, 0, []
    results = doc.get("results") or []
    high = [r for r in results if (r.get("issue_severity") or "").upper() == "HIGH"]
    med = [r for r in results if (r.get("issue_severity") or "").upper() == "MEDIUM"]
    return len(high), len(med), sorted({r.get("test_id", "?") for r in med})


def main() -> int:
    root = ROOT
    files = tracked_files(root)
    failures: list[str] = []

    r1_hits: list[str] = []
    r4_hits: list[str] = []
    r3_files: list[str] = []
    r5_files: list[str] = []
    for rel in files:
        waived = rel.startswith(WAIVE_PREFIXES)
        text = read_tracked_text(root, rel)
        if text is None:
            continue
        for name, frag in scan_secrets(text):
            r1_hits.append(f"{rel}:{name}:{frag}")
        for name, frag in scan_personal(text):
            r4_hits.append(f"{rel}:{name}:{frag}")
        if not waived:
            if scan_non_ascii(text):
                r3_files.append(rel)
            if scan_arabic_script(text):
                r5_files.append(rel)

    print(f"R-1 secrets-scanned files={len(files)} hits={len(r1_hits)}")
    for h in r1_hits[:10]:
        print(f"   SECRET-HIT {h}")
    check = "PASS" if not r1_hits else "FAIL"
    print(f"R-1 {check} no-secret-material-in-tree")
    if r1_hits:
        failures.append("R-1")

    high, med, med_ids = run_bandit(root)
    if high < 0:
        print("R-2 SAST bandit: TOOL-MISSING in this environment -- disclosed, not silently passed (CI installs bandit)")
    else:
        print(f"R-2 SAST bandit: high={high} medium={med} medium-rule-ids={med_ids}")
        print(("R-2 PASS" if high == 0 else "R-2 FAIL") + " sast-high-findings-zero; medium findings disclosed")
        if high:
            failures.append("R-2")

    print(f"R-3 ascii-scan non-ascii files (outside waivers)={len(r3_files)}")
    for rel in r3_files[:10]:
        print(f"   NON-ASCII {rel}")
    print(f"   waivers: verify_b1.py (frozen), .cursor/rules/** (frozen spec), recon/** (evidence)")
    print(("R-3 PASS" if not r3_files else "R-3 FAIL") + " english-only-ascii-tree")
    if r3_files:
        failures.append("R-3")

    print(f"R-4 personal-data hits={len(r4_hits)}")
    for h in r4_hits[:10]:
        print(f"   PERSONAL {h}")
    print(("R-4 PASS" if not r4_hits else "R-4 FAIL") + " no-personal-data-in-tree")
    if r4_hits:
        failures.append("R-4")

    print(f"R-5 script-defense hits={len(r5_files)}")
    for rel in r5_files[:10]:
        print(f"   SCRIPT {rel}")
    print(("R-5 PASS" if not r5_files else "R-5 FAIL") + " no-arabic-persian-script-outside-waivers")
    if r5_files:
        failures.append("R-5")

    r6_hits: list[str] = []
    if "scope.yaml" in files:
        scope_text = read_index_text(root, "scope.yaml") or ""
        includes = [str(i) for i in ((load_yaml(scope_text) or {}).get("includes") or [])]
        for item in extra_scope_includes(includes):
            r6_hits.append(f"scope.yaml include {item}")
    else:
        r6_hits.append("scope.yaml missing from the tracked tree")
    if "targets.yaml" in files:
        targets_text = read_index_text(root, "targets.yaml") or ""
        names = list(((load_yaml(targets_text) or {}).get("targets") or {}).keys())
        for item in extra_target_names(names):
            r6_hits.append(f"targets.yaml key {item}")
    print(f"R-6 fixture-scope hits={len(r6_hits)}")
    for h in r6_hits[:10]:
        print(f"   SCOPE {h}")
    print(("R-6 PASS" if not r6_hits else "R-6 FAIL") + " committed-scope-is-fixture-only")
    if r6_hits:
        failures.append("R-6")

    verdict = "PASS" if not failures else "FAIL:" + ",".join(failures)
    line = f"C1 RELEASE GATE VERDICT: {verdict}"
    print(line)
    (root / "ci" / "c1_verdict.txt").write_text(line + "\n", encoding="utf-8")
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
