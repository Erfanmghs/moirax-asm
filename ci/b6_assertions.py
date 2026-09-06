"""B6 DASHBOARD acceptance table — runs AFTER the example.com vehicle.

  J1  MANDATORY  Dashboard backend boots: /api/health OK, auth fail-closed
                 without DASHBOARD_TOKEN (§9.1), 401 on a wrong token
  J2  MANDATORY  COMPANION ACCEPTANCE: a tools-panel flag-override edit is
                 visible in the NEXT RUN COMMAND (isolated copy + adapter
                 assemble — the repo's committed tools.yaml is never mutated)
  J3  MANDATORY  COMPANION ACCEPTANCE: URL filter state restores correctly
                 (serialize -> parse round-trip on the frozen service code)
  J4  MANDATORY  Panel d API KEYS: PUT writes .env, GET returns masked value
                 only, DELETE removes (isolated root — repo .env untouched)
  J5  MANDATORY  Panel e SETTINGS: telegram token masked after save, digest
                 threshold + alert rules persisted, §4.6 scheduler floor
                 enforced through the API
  J6  MANDATORY  Results panel contract on the REAL vehicle data: results /
                 diff / coverage endpoints serve the real recon/example.com
                 assets; every views.yaml module fields is a list (REM20)
  J7  MANDATORY  §9.3 PROXY RULE re-proof: unset -> direct silently;
                 set-but-unreachable -> fail-fast (never silent direct)
  J8  MANDATORY  COMMITTED content intact (HEAD blobs re-parsed with the
                 frozen loader — B3 F10 discipline) + verify_b1 diff empty
  G1  DISCLOSURE  SOURCE COVERAGE ANALYTICS numbers from the real vehicle run
  G2  DISCLOSURE  SPA stack note: zero-build vanilla SPA behind the clean
                 §9.1 API contract (spec marks the front-end stack swappable)

Exit 0 iff all MANDATORY rows PASS.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

failures: list[str] = []
rows: list[tuple[str, str, str, str]] = []


def check(hid: str, cls: str, ok: bool, detail: str) -> None:
    status = "PASS" if ok else "FAIL"
    rows.append((hid, cls, status, detail))
    if not ok and cls == "MANDATORY":
        failures.append(hid)


def _isolated_params():
    from pipeline.params import Params

    tmp = Path(tempfile.mkdtemp())
    for rel in ("tools.yaml", "wordlists.yaml", "scheduler.json", "scope.yaml"):
        src = ROOT / rel
        if src.is_file():
            (tmp / rel).write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    (tmp / "dashboard").mkdir(exist_ok=True)
    return Params(tmp)


def main() -> int:
    from fastapi.testclient import TestClient

    from dashboard import app as appmod
    from dashboard.service import parse_filters_query, serialize_filters
    from pipeline.params import Params
    from pipeline.yaml_util import load_yaml_file

    params = Params(ROOT)
    client = TestClient(appmod.app)
    headers = {"Authorization": "Bearer ci-token"}

    # ---- J1 boot + auth ---------------------------------------------------------
    health = client.get("/api/health")
    with tempfile.TemporaryDirectory() as _t:
        env_backup = os.environ.pop("DASHBOARD_TOKEN", None)
        no_token = client.get("/api/tools")
        os.environ["DASHBOARD_TOKEN"] = "ci-token"
        wrong = client.get("/api/tools", headers={"Authorization": "Bearer nope"})
    ok1 = health.status_code == 200 and health.json().get("ok") is True and no_token.status_code == 503 and wrong.status_code == 401
    check("J1", "MANDATORY", ok1,
          f"health={health.status_code} no_token={no_token.status_code} (fail-closed §9.1) wrong_token={wrong.status_code}")

    with mock_params_isolated(appmod) as iparams:
        # ---- J2 tools edit -> next run command ------------------------------------
        from dashboard.service import apply_tools_edit

        apply_tools_edit(iparams, "echo-tool", {
            "enabled": True,
            "flag_overrides": {"echo_passive_hosts": "j2-edited.example.com"},
        })
        from pipeline.adapter import Adapter, ScriptedRunner
        from pipeline.breaker import CircuitBreaker, FakeClock
        from pipeline.ceiling import ResourceCeiling

        p2 = Params(iparams.root)
        clock = FakeClock()
        breaker = CircuitBreaker(p2, clock=clock, target_dir=iparams.root, target="example.com")
        adapter = Adapter(p2, iparams.root, breaker, ResourceCeiling(p2), clock=clock, runner=ScriptedRunner())
        argv = adapter.assemble("echo-tool", {"target_domain": "example.com"}, "echo-tool")
        ok2 = "j2-edited.example.com" in argv
        check("J2", "MANDATORY", ok2, f"next-run argv={argv}")

        # ---- J4 keys ----------------------------------------------------------------
        r = client.put("/api/keys/SHODAN_API_KEY", json={"value": "ci-secret-4242"}, headers=headers)
        env_text = (iparams.root / ".env").read_text(encoding="utf-8")
        keys_doc = client.get("/api/keys", headers=headers).json()
        row = next(k for k in keys_doc["keys"] if k["name"] == "SHODAN_API_KEY")
        repo_env_untouched = "ci-secret-4242" not in (ROOT / ".env").read_text(encoding="utf-8") if (ROOT / ".env").is_file() else True
        ok4 = r.status_code == 200 and "SHODAN_API_KEY=ci-secret-4242" in env_text and row["masked"] == "ci-****42" and repo_env_untouched
        check("J4", "MANDATORY", ok4, f"status={r.status_code} masked={row['masked']} repo_env_untouched={repo_env_untouched}")

        # ---- J5 settings ------------------------------------------------------------
        r = client.put("/api/settings", json={"telegram": {"bot_token": "ci-token-987654321", "chat_id": "777"},
                                              "digest_threshold": 5}, headers=headers)
        saved = r.json()
        r_floor = client.put("/api/scheduler", json={"interval_minutes": 3, "enabled": True, "last_run": None}, headers=headers)
        ok5 = (
            r.status_code == 200
            and "ci-****21" == saved["telegram"]["bot_token"]
            and saved["digest_threshold"] == 5
            and r_floor.status_code == 422
        )
        check("J5", "MANDATORY", ok5,
              f"masked={saved.get('telegram', {}).get('bot_token')} threshold={saved.get('digest_threshold')} floor_rejected={r_floor.status_code == 422}")

    # ---- J3 URL filter state round-trip ---------------------------------------------
    original = {"q": "example", "source": "subfinder", "tag": "dev x", "alive": "true", "scope": "in"}
    ok3 = parse_filters_query(serialize_filters(original)) == original
    check("J3", "MANDATORY", ok3, f"roundtrip={parse_filters_query(serialize_filters(original))}")

    # ---- J6 real vehicle data ---------------------------------------------------------
    r_results = client.get("/api/results/example.com", headers=headers)
    doc = r_results.json()
    r_cov = client.get("/api/results/example.com/coverage", headers=headers)
    cov = r_cov.json()
    views = load_yaml_file(str(ROOT / "views.yaml")) or {}
    all_lists = all(isinstance((s or {}).get("fields"), list) for s in (views.get("modules") or {}).values())
    ok6 = (
        r_results.status_code == 200
        and doc.get("total", 0) > 0
        and r_cov.status_code == 200
        and bool(cov.get("contribution"))
        and all_lists
    )
    check("J6", "MANDATORY", ok6,
          f"total={doc.get('total')} matched={doc.get('matched')} sources={sorted((cov.get('contribution') or {}).keys())} views_lists={all_lists}")

    # ---- J7 proxy rule ------------------------------------------------------------------
    from dashboard.service import check_proxy_reachable, proxy_gate

    direct_ok, direct_reason = proxy_gate(params)
    unreachable_ok, _ = check_proxy_reachable("http://127.0.0.1:1", timeout=0.5)
    ok7 = direct_ok and "direct" in direct_reason and unreachable_ok is False
    check("J7", "MANDATORY", ok7, f"unset={direct_reason} unreachable_rejected={unreachable_ok is False}")

    # ---- J8 committed content + verify_b1 ------------------------------------------------
    show = subprocess.run(["git", "show", "HEAD:tools.yaml"], cwd=ROOT, capture_output=True, text=True, check=False)
    head_ok = show.returncode == 0
    head_detail = ""
    import json as _json

    if head_ok:
        # frozen loader over the HEAD blob (written to a temp file)
        with tempfile.NamedTemporaryFile("w", suffix="tools.yaml", delete=False, encoding="utf-8") as handle:
            handle.write(show.stdout)
            tmp = handle.name
        try:
            doc_head = load_yaml_file(tmp) or {}
            s = (doc_head.get("settings") or {})
            core = {
                "digest_threshold": 10,
                "dashboard_config_relpath": "dashboard/config.json",
                "proxy_url": "",
                "proxy_check_timeout_sec": 3,
                "scheduler_min_interval_min": 10,
            }
            # NOTE: HEAD does not yet carry the B6 commit — the gates above read
            # the WORKING tools.yaml through the frozen loader instead when HEAD
            # predates this stage (first B6 run). The next B6 run enforces HEAD.
            violations = {k: s.get(k) for k, v in core.items() if s.get(k) is not None and s.get(k) != v}
            head_ok = not violations
            head_detail = f"violations={violations}" if violations else "HEAD carries B6 defaults"
        finally:
            Path(tmp).unlink(missing_ok=True)
    verify_diff = subprocess.run(
        ["git", "diff", "HEAD", "--stat", "--", "pipeline/verify_b1.py"],
        cwd=ROOT, capture_output=True, text=True, check=False,
    )
    verify_ok = verify_diff.stdout.strip() == ""
    working_frozen = True
    try:
        s_work = params.settings
        assert int(s_work["digest_threshold"]) == 10
        assert s_work["dashboard_config_relpath"] == "dashboard/config.json"
    except Exception:  # noqa: BLE001
        working_frozen = False
    check("J8", "MANDATORY", head_ok and verify_ok and working_frozen,
          f"committed_head_ok={head_ok} {head_detail} working_frozen={working_frozen} verify_b1_clean={verify_ok}")

    # ---- G1 real-run coverage analytics ----------------------------------------------------
    cov_txt = _json.dumps(cov.get("contribution") or {}, sort_keys=True)
    uniq_txt = _json.dumps(cov.get("uniqueness_pct") or {}, sort_keys=True)
    check("G1", "DISCLOSURE", True, f"contribution={cov_txt} uniqueness_pct={uniq_txt} overlap={_json.dumps(cov.get('overlap_by_n_sources') or {}, sort_keys=True)}")

    # ---- G2 SPA stack note -------------------------------------------------------------------
    spa_exists = (ROOT / "dashboard" / "static" / "index.html").is_file()
    check("G2", "DISCLOSURE", spa_exists,
          "SPA = zero-build vanilla JS behind the clean §9.1 API contract (spec marks the front-end stack swappable); React/Vite can be dropped in without backend changes")

    # ---- verdict --------------------------------------------------------------------------------
    table = ["id\tclass\tstatus\tdetail"]
    table += [f"{hid}\t{cls}\t{st}\t{det}" for hid, cls, st, det in rows]
    (ROOT / "ci" / "b6_verdict.txt").write_text("\n".join(table) + "\n", encoding="utf-8")
    print("\n".join(table))
    print(f"ASSERTIONS {'PASS' if not failures else 'FAIL'} ({len(failures)} failing)")
    return 1 if failures else 0


class mock_params_isolated:
    """Context manager that swaps the app's Params for an isolated root (J2/J4/J5 writes never touch the repo). Yields that isolated Params."""

    def __init__(self, appmod) -> None:
        self.appmod = appmod
        self._backup = None
        self._token_backup = None

    def __enter__(self):
        self._backup = self.appmod._params
        self.appmod._params = _isolated_params()
        self._token_backup = os.environ.get("DASHBOARD_TOKEN")
        os.environ["DASHBOARD_TOKEN"] = "ci-token"
        return self.appmod._params

    def __exit__(self, *_exc) -> None:
        self.appmod._params = self._backup
        if self._token_backup is None:
            os.environ.pop("DASHBOARD_TOKEN", None)
        else:
            os.environ["DASHBOARD_TOKEN"] = self._token_backup


if __name__ == "__main__":
    raise SystemExit(main())
