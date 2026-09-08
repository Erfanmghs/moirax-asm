#!/usr/bin/env bash
# ============================================================================
# LOCAL ACCEPTANCE FLEET -- the whole verification matrix on THIS machine,
# no GitHub Actions needed. Every stage calls the SAME verdict scripts the
# CI vehicles use, so a green run here equals a green fleet run there.
#
# Usage:
#   ./verify_all.sh                # default: stages 0-9 (no docker/sudo needed)
#   ./verify_all.sh --with-docker  # add stage 10 (real container run; needs
#                                  # docker + sudo for the fixture /etc/hosts)
#   ./verify_all.sh --stage N      # run one stage only
#
# Verdict: verify/fleet-verdict.txt (PASS only if every stage passed or is
# explicitly disclosed as skipped with its reason).
# ============================================================================
set -uo pipefail
cd "$(dirname "$0")"

VERDICT_DIR="verify"; mkdir -p "$VERDICT_DIR"
VERDICT="$VERDICT_DIR/fleet-verdict.txt"
: > "$VERDICT"
RESULT=0
ONLY=""; STAGE_ALL=1; WITH_DOCKER=0
while [ $# -gt 0 ]; do
  case "$1" in
    --stage) ONLY="$2"; STAGE_ALL=0; shift 2;;
    --with-docker) WITH_DOCKER=1; shift;;
    *) echo "unknown arg $1"; exit 2;;
  esac
done

run_stage() { # id title command...
  local id="$1" title="$2"; shift 2
  if [ "$STAGE_ALL" = 0 ] && [ "$id" != "$ONLY" ]; then return 0; fi
  echo "=== S$id $title ==="
  if "$@"; then
    echo "S$id PASS $title" >> "$VERDICT"
  else
    local rc=$?
    echo "S$id FAIL $title (exit $rc)" >> "$VERDICT"; RESULT=1
  fi
}

disclose() { # id title reason
  if [ "$STAGE_ALL" = 0 ] && [ "$1" != "$ONLY" ]; then return 0; fi
  echo "S$1 DISCLOSED-SKIP $2 -- $3" >> "$VERDICT"
}

s0_env() {
  # HARD requirements: python3 + git only. Suite deps are S1's job -- failing
  # S0 for them would fail the whole fleet on a virgin machine BEFORE S1 can
  # install them (first-run trap). Advisory here, proven by S4+ anyway.
  command -v python3 >/dev/null || { echo "python3 missing"; return 1; }
  command -v git >/dev/null || { echo "git missing"; return 1; }
  if python3 -c "import fastapi, uvicorn, httpx" 2>/dev/null; then
    echo "python3 + git + suite deps present"
  else
    echo "python3 + git present; suite deps missing (S1 installs them now)"
  fi
}

s1_deps() {
  # PEP 668 (Ubuntu 23+/Debian 12) refuses plain system pip installs -- fall
  # back honestly: system -> --user -> --break-system-packages (this is the
  # operator's own machine; 4 pinned pure-python packages + bandit).
  local pkgs=("fastapi==0.115.6" "uvicorn==0.34.0" "httpx==0.28.1" "reportlab==4.2.5" bandit)
  if python3 -m pip install --quiet "${pkgs[@]}" 2>/dev/null; then
    echo "suite deps installed (system pip)"; return 0
  fi
  if python3 -m pip install --quiet --user "${pkgs[@]}" 2>/dev/null; then
    echo "suite deps installed (--user)"; return 0
  fi
  echo "system pip refused (PEP 668) -- retrying with --break-system-packages"
  python3 -m pip install --quiet --break-system-packages "${pkgs[@]}"
}

s2_seclists() {
  if [ -d "$HOME/seclists" ]; then
    echo "seclists present ($(find "$HOME/seclists" -name '*.txt' | wc -l) files)"; return 0
  fi
  git clone --depth 1 https://github.com/danielmiessler/SecLists "$HOME/seclists" || return 1
  find "$HOME/seclists" -name '*.txt' | wc -l
}

s3_gate() { PYTHONPATH=. python3 ci/c1_release_gate.py; }

s4_units() { PYTHONPATH=. python3 -m unittest discover -s tests -t .; }

s5_dast() { python3 ci/pentest_dast.py; }

s6_ui() { PYTHONPATH=. python3 ci/ui_e2e_journey.py; }

s7_dashboard_preflight() { PYTHONPATH=. python3 ci/b6_preflight.py; }

# operator-law transient selection accommodation (recorded, never committed)
accommodate() {
  mkdir -p wordlists/forge
  rm -f wordlists/forge/custom-subdomains.txt wordlists/forge/effective-*.txt
  rm -rf wordlists/forge/cache
  # snapshot ONLY the pristine original (nested accommodates never clobber it)
  [ -f ci/wordlists_runtime_before.yaml ] || cp wordlists.yaml ci/wordlists_runtime_before.yaml
  python3 - <<'PY'
import pathlib
text = pathlib.Path("wordlists.yaml").read_text(encoding="utf-8")
for task in ("FFUF-0", "DNSR-1", "FFUF-2"):
    marker = f"  {task}:"
    i = text.index(marker) + len(marker)
    text = text[:i] + "\n    selection:\n      - test_smoke_200" + text[i:]
pathlib.Path("wordlists.yaml").write_text(text, encoding="utf-8")
print("SELECTION ACCOMMODATION applied (transient)")
PY
}

restore() {
  if [ -f ci/wordlists_runtime_before.yaml ]; then
    cp ci/wordlists_runtime_before.yaml wordlists.yaml
    rm -f ci/wordlists_runtime_before.yaml
    echo "accommodation restored"
  fi
}
trap restore EXIT

s8_rem4r_preflight() { accommodate; PYTHONPATH=. python3 ci/rem4r_preflight.py; }
s9_test3_preflight() { accommodate; PYTHONPATH=. python3 ci/test3_preflight.py; }

s10_container_fleet() {
  command -v docker >/dev/null || { echo "docker not on PATH"; return 1; }
  sudo -n python3 docker/vhost-fixture/hosts.py add 2>/dev/null || sudo python3 docker/vhost-fixture/hosts.py add || return 1
  docker compose -f docker-compose.yml -f docker-compose.vhost-fixture.yml --profile vhost-fixture up -d --build || return 1
  accommodate || return 1
  PYTHONPATH=. python3 ci/rem4r_preflight.py || return 1
  PYTHONPATH=. python3 -m unittest discover -s tests -t . || return 1
  ./recon.sh run fixture-target.test || return 1
  PYTHONPATH=. python3 ci/rem4r_assertions.py
  local rc=$?
  sudo -n python3 docker/vhost-fixture/hosts.py remove 2>/dev/null || sudo python3 docker/vhost-fixture/hosts.py remove || true
  docker compose -f docker-compose.yml -f docker-compose.vhost-fixture.yml --profile vhost-fixture down -v || true
  return "$rc"
}

run_stage 0 "environment" s0_env
run_stage 1 "install suite deps" s1_deps
run_stage 2 "seclists root" s2_seclists
run_stage 3 "c1 release gate" s3_gate
run_stage 4 "unit suite" s4_units
run_stage 5 "dast pentest" s5_dast
if python3 -c "import playwright" 2>/dev/null; then
  run_stage 6 "ui journey" s6_ui
else
  # DISCLOSED-SKIP law (never silent): the UI journey needs a real browser;
  # a machine without playwright can still pass the fleet honestly, with the
  # one-time fix printed and re-runnable via --stage 6.
  echo "=== S6 ui journey ==="
  echo "playwright not installed -- one-time setup, then re-run stage 6:"
  echo "  python3 -m pip install playwright && python3 -m playwright install chromium"
  echo "  (add --break-system-packages if your Ubuntu refuses the pip call)"
  echo "  then: ./verify_all.sh --stage 6"
  disclose 6 "ui journey" "playwright absent -- one-time install above, then re-run with --stage 6"
fi
run_stage 7 "b6 dashboard preflight" s7_dashboard_preflight
run_stage 8 "rem4r preflight" s8_rem4r_preflight
run_stage 9 "test3 preflight" s9_test3_preflight

if [ "$WITH_DOCKER" = 1 ]; then
  run_stage 10 "container fleet (rem4r end-to-end)" s10_container_fleet
else
  disclose 10 "container fleet" "opt-in via --with-docker (needs docker + sudo)"
fi

{
  echo "======================================================"
  if [ "$RESULT" = 0 ]; then echo "FLEET VERDICT: PASS"; else echo "FLEET VERDICT: FAIL"; fi
} >> "$VERDICT"
cat "$VERDICT"
restore
exit "$RESULT"
