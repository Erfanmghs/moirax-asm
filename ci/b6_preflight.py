"""B6 DASHBOARD preflight gates -- run BEFORE the vehicle `recon.sh run`.

  G-Z1  committed B6 defaults (bind host/port, dashboard config relpath,
        proxy unset default + check timeout, digest/scheduler defaults intact)
  G-Z2  backend surface: dashboard/app.py exposes the section 9.2 API routes and the
        section 9.1 DASHBOARD_TOKEN fail-closed auth
  G-Z3  SPA present + section 9.4 theme markers (dark palette, monospace technical
        values, sticky headers, badges, JSON inspector) + panels a-e
  G-Z4  views.yaml frozen-loader contract: every module fields is a LIST
        (REM20 -- committed file was mangled at B0 and unparseable as lists)
  G-Z5  section 9.3 proxy rule: engine fail-fast wiring (pool-or-legacy) + impls
  G-Z6  verify_b1.py has no working-tree diff (frozen since handoff)
  G-Z7  vehicle scope: example.com retained
  G-Z8  unit coverage markers in tests/test_dashboard.py
  G-Z9  compose dashboard service is REAL (build path, token env, bind, sock)

Exit 0 = all gates hold; any GATE-FAIL exits 1.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

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

    # ---- G-Z1 committed defaults -------------------------------------------
    defaults = {
        "dashboard_bind_host": "127.0.0.1",
        "dashboard_bind_port": 8080,
        "dashboard_config_relpath": "dashboard/config.json",
        "proxy_url": "",
        "proxy_check_timeout_sec": 3,
        "digest_threshold": 10,
        "scheduler_min_interval_min": 10,
    }
    bad = {k: params.require(k) for k, v in defaults.items() if params.require(k) != v}
    check("G-Z1 committed-defaults", not bad, f"violations={bad}")

    # ---- G-Z2 backend surface ------------------------------------------------
    app_text = (ROOT / "dashboard" / "app.py").read_text(encoding="utf-8")
    routes = (
        "/api/health", "/api/tools", "/api/wordlists", "/api/results/{target}",
        "/api/results/{target}/diff", "/api/results/{target}/coverage",
        "/api/run/status/{target}", "/api/run/log/{target}", "/api/run/start",
        "/api/run/stop", "/api/run/resume", "/api/scheduler", "/api/keys",
        "/api/settings", "/api/proxy/check",
    )
    missing = [r for r in routes if f'"{r}"' not in app_text]
    auth_ok = "DASHBOARD_TOKEN" in app_text and "503" in app_text and "401" in app_text
    check("G-Z2 backend-surface", not missing and auth_ok, f"missing={missing} auth_fail_closed={auth_ok}")

    # ---- G-Z3 SPA + theme ------------------------------------------------------
    spa = ROOT / "dashboard" / "static"
    files_ok = all((spa / f).is_file() for f in ("index.html", "app.js", "theme.css"))
    html = (spa / "index.html").read_text(encoding="utf-8") if files_ok else ""
    css = (spa / "theme.css").read_text(encoding="utf-8") if files_ok else ""
    js = (spa / "app.js").read_text(encoding="utf-8") if files_ok else ""
    panels = all(f'panel-{p}' in html for p in ("tools", "results", "run", "keys", "settings"))
    theme_markers = all(
        m in css + js
        for m in ("--bg", "var(--mono)", "position: sticky", "badge", "json-inspector")
    )
    url_state = "pushState" in js and "URLSearchParams" in js
    check("G-Z3 spa-theme", files_ok and panels and theme_markers and url_state,
          f"files={files_ok} panels={panels} theme={theme_markers} url_state={url_state}")

    # ---- G-Z4 views.yaml frozen-loader contract (REM20) ------------------------
    views = load_yaml_file(str(ROOT / "views.yaml")) or {}
    modules = views.get("modules") or {}
    non_list = {m: type((s or {}).get("fields")).__name__ for m, s in modules.items()
                if not isinstance((s or {}).get("fields"), list)}
    check("G-Z4 views-contract", bool(modules) and not non_list,
          f"modules={sorted(modules)} non_list={non_list}")

    # ---- G-Z5 proxy rule (pool-or-legacy law, E1 wiring) -------------------------
    engine_text = (ROOT / "pipeline" / "engine.py").read_text(encoding="utf-8")
    service_text = (ROOT / "dashboard" / "service.py").read_text(encoding="utf-8")
    rotation_text = (ROOT / "pipeline" / "ip_rotation.py").read_text(encoding="utf-8")
    gate_wired = (
        "gate_pool_or_legacy(params)" in engine_text
        and "PROXY RULE fail-fast" in engine_text
    )
    impl = (
        "def check_proxy_reachable(" in service_text
        and "def proxy_gate(" in service_text
        and "def gate_pool_or_legacy(" in rotation_text
        and "def gate(" in rotation_text
    )
    check("G-Z5 proxy-rule", gate_wired and impl, f"engine_wired={gate_wired} impl={impl}")

    # ---- G-Z6 verify_b1 clean ------------------------------------------------------
    diff = subprocess.run(
        ["git", "diff", "HEAD", "--stat", "--", "pipeline/verify_b1.py"],
        cwd=ROOT, capture_output=True, text=True, check=False,
    )
    check("G-Z6 verify_b1-clean", diff.stdout.strip() == "", "no working-tree diff")

    # ---- G-Z7 vehicle scope ---------------------------------------------------------
    scope = load_yaml_file(str(ROOT / "scope.yaml"))
    includes = [str(i) for i in (scope.get("includes") or [])]
    check(
        "G-Z7 vehicle-scope",
        "example.com" in includes and "*.example.com" in includes,
        f"includes={includes}",
    )

    # ---- G-Z8 unit coverage ----------------------------------------------------------
    test_text = (ROOT / "tests" / "test_dashboard.py").read_text(encoding="utf-8")
    markers = (
        "test_set_list_masked_delete_roundtrip",
        "test_save_and_masked_load",
        "test_surgical_edit_visible_in_next_run_command",
        "test_selection_edit_roundtrip",
        "test_url_state_roundtrip",
        "test_contribution_overlap_uniqueness",
        "test_set_but_unreachable_fails",
        "test_keys_roundtrip_via_api",
        "test_auth_fail_closed_without_backend_token",
    )
    covered = all(m in test_text for m in markers)
    check("G-Z8 unit-coverage", covered, f"markers={len(markers)}")

    # ---- G-Z9 compose dashboard service ------------------------------------------------
    import yaml  # compose is CI-side validation only; pipeline uses the frozen loader

    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    svc = (compose.get("services") or {}).get("dashboard") or {}
    build_ok = (svc.get("build") or {}).get("dockerfile") == "docker/dashboard/Dockerfile"
    env_ok = "DASHBOARD_TOKEN" in str(svc.get("environment") or {})
    ports_ok = "8080" in str(svc.get("ports") or [])
    sock_ok = any("docker.sock" in v for v in (svc.get("volumes") or []))
    check("G-Z9 compose-service", build_ok and env_ok and ports_ok and sock_ok,
          f"build={build_ok} token_env={env_ok} bind={ports_ok} docker_sock={sock_ok}")

    print(f"PREFLIGHT {'PASS' if not failures else 'FAIL'} ({len(failures)} failing)")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
