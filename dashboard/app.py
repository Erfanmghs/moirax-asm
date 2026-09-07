"""FastAPI dashboard backend (spec section 9.1/section 9.2). The ONLY docker.sock client.

Auth: every /api route (except /api/health) requires `Authorization: Bearer
<DASHBOARD_TOKEN>`; if DASHBOARD_TOKEN is unset the backend refuses every
API call (fail-closed -- section 9.1 auth contract).
Bind: 127.0.0.1:8080 (compose maps the same), SPA served from /static.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse

from dashboard.service import (
    DashboardError,
    apply_tools_edit,
    apply_wordlists_edit,
    coverage_analytics,
    delete_key,
    fleet_members_view,
    latest_fleet_ledger,
    list_keys,
    load_settings,
    parse_filters_query,
    proxy_gate,
    save_settings,
    scheduler_save,
    scheduler_view,
    set_key,
    apply_filters,
    target_profile_upsert,
    target_profile_view,
    targets_view,
)
from pipeline.params import Params
from pipeline.scheduler import load_schedule
from pipeline.target_profiles import TARGET_NAME_RE
from pipeline.yaml_util import load_yaml_file

ROOT = Path(__file__).resolve().parents[1]
STATIC = Path(__file__).resolve().parent / "static"

# Pentest hardening (D-protocol): OpenAPI/docs are disabled -- the API contract
# is internal surface, never an attacker map.
app = FastAPI(title="recon-pipeline dashboard", docs_url=None, redoc_url=None, openapi_url=None)


@app.middleware("http")
async def _hardening_headers(request: Any, call_next: Any) -> Any:
    """Attacker-proofing response headers on EVERY response (D-protocol
    pentest vehicle P-7): no framing, no MIME sniffing, no referrer leak,
    no caching of API data, strict CSP for the SPA (no inline script)."""
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Cache-Control", "no-store")
    if request.url.path.startswith("/static") or request.url.path == "/":
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'",
        )
    return response


def _valid_target(value: str) -> str:
    """Pentest hardening (P-9): target names reach subprocess argv via
    run/start|stop|resume -- enforce the same strict name law the fleet uses
    so flag-injection ('-x'), traversal ('../x') and metacharacters are
    refused BEFORE any process is spawned."""
    target = (value or "").strip()
    if not TARGET_NAME_RE.match(target):
        raise HTTPException(status_code=422, detail="illegal target name")
    return target

_params: Params | None = None


def _params_obj() -> Params:
    global _params
    if _params is None:
        _params = Params(ROOT)
    return _params


def _auth(authorization: str | None) -> None:
    token = str(os.environ.get("DASHBOARD_TOKEN") or "").strip()
    if not token:
        raise HTTPException(status_code=503, detail="DASHBOARD_TOKEN is not configured (fail-closed, section 9.1)")
    if authorization != f"Bearer {token}":
        raise HTTPException(status_code=401, detail="invalid dashboard token")


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {"ok": True, "service": "recon-pipeline-dashboard"}


@app.get("/api/views")
def views(authorization: str | None = Header(default=None)) -> Any:
    _auth(authorization)
    return JSONResponse(load_yaml_file(str(ROOT / "views.yaml")))


# --------------------------------------------------------------- panel a: Tools

@app.get("/api/tools")
def tools_list(authorization: str | None = Header(default=None)) -> Any:
    _auth(authorization)
    doc = load_yaml_file(str(ROOT / "tools.yaml")) or {}
    out = []
    for name, spec in (doc.get("tools") or {}).items():
        out.append({
            "name": name,
            "enabled": bool((spec or {}).get("enabled", False)),
            "branch": (spec or {}).get("branch"),
            "image_ref": (spec or {}).get("image_ref"),
            "params": (spec or {}).get("params") or {},
        })
    return JSONResponse({"tools": out})


@app.put("/api/tools/{name}")
async def tools_edit(name: str, patch: dict[str, Any], authorization: str | None = Header(default=None)) -> Any:
    _auth(authorization)
    try:
        result = apply_tools_edit(_params_obj(), name, patch)
    except DashboardError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return JSONResponse(result)


@app.get("/api/wordlists")
def wordlists_view(authorization: str | None = Header(default=None)) -> Any:
    _auth(authorization)
    return JSONResponse(load_yaml_file(str(ROOT / "wordlists.yaml")))


@app.get("/api/targets")
def targets_view_route(authorization: str | None = Header(default=None)) -> Any:
    _auth(authorization)
    return JSONResponse(targets_view(_params_obj()))


@app.get("/api/targets/{target}")
def target_profile_view_route(target: str, authorization: str | None = Header(default=None)) -> Any:
    _auth(authorization)
    return JSONResponse(target_profile_view(_params_obj(), target))


@app.put("/api/targets/{target}")
async def target_profile_upsert_route(target: str, profile: dict[str, Any], authorization: str | None = Header(default=None)) -> Any:
    _auth(authorization)
    try:
        return JSONResponse(target_profile_upsert(_params_obj(), target, profile))
    except DashboardError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@app.put("/api/wordlists")
async def wordlists_edit(patch: dict[str, Any], authorization: str | None = Header(default=None)) -> Any:
    _auth(authorization)
    try:
        return JSONResponse(apply_wordlists_edit(_params_obj(), patch))
    except DashboardError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


# --------------------------------------------------------------- panel b: Results

def _assets_rows(target: str) -> list[dict[str, Any]]:
    params = _params_obj()
    path = ROOT / "recon" / target / str(params.require("assets_relpath"))
    if not path.is_file():
        return []
    doc = read_json_file(path)
    rows = doc.get("assets") or []
    return [r for r in rows if isinstance(r, dict)]


def read_json_file(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        return {}


@app.get("/api/results/{target}")
def results(
    target: str,
    q: str = Query(default=""),
    source: str = Query(default=""),
    tag: str = Query(default=""),
    alive: str = Query(default=""),
    run: str = Query(default=""),
    scope: str = Query(default=""),
    limit: int = Query(default=500, le=5000),
    authorization: str | None = Header(default=None),
) -> Any:
    _auth(authorization)
    params = _params_obj()
    rows = _assets_rows(target)
    filters = parse_filters_query(f"q={q}&source={source}&tag={tag}&alive={alive}&run={run}&scope={scope}")
    filtered = apply_filters(rows, filters)
    diff = read_json_file(ROOT / "recon" / target / str(params.require("diff_filename")))
    new_hosts = {str(r.get("host")) for r in (diff.get("added") or {}).get("hosts") or []}
    for row in filtered:
        row = row  # keep identity
    enriched = [{**r, "is_new": str(r.get("host")) in new_hosts} for r in filtered]
    return JSONResponse({
        "target": target,
        "total": len(rows),
        "matched": len(enriched),
        "returned": min(len(enriched), limit),
        "filters": filters,
        "assets": enriched[:limit],
    })


@app.get("/api/results/{target}/diff")
def results_diff(target: str, authorization: str | None = Header(default=None)) -> Any:
    _auth(authorization)
    params = _params_obj()
    path = ROOT / "recon" / target / str(params.require("diff_filename"))
    if not path.is_file():
        return JSONResponse({"exists": False})
    return JSONResponse({"exists": True, **read_json_file(path)})


@app.get("/api/results/{target}/coverage")
def results_coverage(target: str, authorization: str | None = Header(default=None)) -> Any:
    _auth(authorization)
    return JSONResponse(coverage_analytics(_assets_rows(target)))


@app.get("/api/runs/{target}")
def runs_history(target: str, authorization: str | None = Header(default=None)) -> Any:
    _auth(authorization)
    params = _params_obj()
    path = ROOT / "recon" / target / str(params.require("runs_filename"))
    return JSONResponse(read_json_file(path) if path.is_file() else {})


# --------------------------------------------------------------- panel c: Run Control

@app.get("/api/run/status/{target}")
def run_status(target: str, authorization: str | None = Header(default=None)) -> Any:
    _auth(authorization)
    path = ROOT / "recon" / target / "state.json"
    return JSONResponse(read_json_file(path) if path.is_file() else {"exists": False})


@app.get("/api/run/log/{target}")
def run_log(target: str, offset: int = Query(default=0, ge=0), authorization: str | None = Header(default=None)) -> Any:
    _auth(authorization)
    params = _params_obj()
    path = ROOT / "recon" / target / "logs" / "run.log"
    if not path.is_file():
        return JSONResponse({"exists": False, "offset": offset, "lines": []})
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    chunk = lines[offset:offset + 400]
    return JSONResponse({"exists": True, "offset": offset, "next_offset": offset + len(chunk),
                         "total": len(lines), "lines": chunk})


@app.get("/api/run/agent-journal/{target}")
def agent_journal(target: str, offset: int = Query(default=0, ge=0), authorization: str | None = Header(default=None)) -> Any:
    """section 12.7: agent journal streamed live in Run Control (append-only source)."""
    _auth(authorization)
    params = _params_obj()
    path = ROOT / "recon" / target / str(params.require("agent_journal_relpath"))
    if not path.is_file():
        return JSONResponse({"exists": False, "offset": offset, "rows": []})
    lines = [l for l in path.read_text(encoding="utf-8", errors="replace").splitlines() if l.strip()]
    chunk = lines[offset:offset + 200]
    return JSONResponse({"exists": True, "offset": offset, "next_offset": offset + len(chunk),
                         "total": len(lines), "rows": chunk})


@app.post("/api/run/start")
async def run_start(body: dict[str, Any], authorization: str | None = Header(default=None)) -> Any:
    _auth(authorization)
    params = _params_obj()
    ok, reason = proxy_gate(params)
    if not ok:
        raise HTTPException(status_code=502, detail=f"PROXY RULE fail-fast (section 9.3): {reason}")
    target = _valid_target(str(body.get("target") or ""))
    aggressive = bool(body.get("aggressive", False))
    cmd = ["./recon.sh", "run", target] + (["--aggressive"] if aggressive else [])
    proc = subprocess.Popen(cmd, cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            start_new_session=True)
    return JSONResponse({"started": True, "pid": proc.pid, "cmd": cmd, "proxy": reason})


@app.post("/api/run/stop")
async def run_stop(body: dict[str, Any], authorization: str | None = Header(default=None)) -> Any:
    _auth(authorization)
    target = _valid_target(str(body.get("target") or ""))
    proc = subprocess.run(["./recon.sh", "stop", target], cwd=ROOT, capture_output=True, text=True)
    return JSONResponse({"exit": proc.returncode, "stdout": proc.stdout[-2000:]})


@app.post("/api/run/resume")
async def run_resume(body: dict[str, Any], authorization: str | None = Header(default=None)) -> Any:
    _auth(authorization)
    params = _params_obj()
    ok, reason = proxy_gate(params)
    if not ok:
        raise HTTPException(status_code=502, detail=f"PROXY RULE fail-fast (section 9.3): {reason}")
    target = _valid_target(str(body.get("target") or ""))
    proc = subprocess.Popen(["./recon.sh", "resume", target], cwd=ROOT,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    return JSONResponse({"resumed": True, "pid": proc.pid, "proxy": reason})


@app.get("/api/scheduler")
def scheduler_get(authorization: str | None = Header(default=None)) -> Any:
    _auth(authorization)
    return JSONResponse(scheduler_view(_params_obj()))


@app.put("/api/scheduler")
async def scheduler_put(doc: dict[str, Any], authorization: str | None = Header(default=None)) -> Any:
    _auth(authorization)
    try:
        return JSONResponse(scheduler_save(_params_obj(), doc))
    except DashboardError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


# --------------------------------------------------------------- panel d: API Keys

@app.get("/api/keys")
def keys_list(authorization: str | None = Header(default=None)) -> Any:
    _auth(authorization)
    return JSONResponse({"keys": list_keys(_params_obj())})


@app.put("/api/keys/{name}")
async def keys_put(name: str, body: dict[str, Any], authorization: str | None = Header(default=None)) -> Any:
    _auth(authorization)
    value = str(body.get("value") or "")
    try:
        set_key(_params_obj(), name, value)
    except DashboardError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return JSONResponse({"saved": name, "masked": True, "note": "picked up on the next run without restart (section 9.2-d)"})


@app.delete("/api/keys/{name}")
def keys_delete(name: str, authorization: str | None = Header(default=None)) -> Any:
    _auth(authorization)
    try:
        delete_key(_params_obj(), name)
    except DashboardError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return JSONResponse({"deleted": name})


# --------------------------------------------------------------- panel e: Settings

@app.get("/api/settings")
def settings_get(authorization: str | None = Header(default=None)) -> Any:
    _auth(authorization)
    return JSONResponse(load_settings(_params_obj()))


@app.put("/api/settings")
async def settings_put(patch: dict[str, Any], authorization: str | None = Header(default=None)) -> Any:
    _auth(authorization)
    try:
        return JSONResponse(save_settings(_params_obj(), patch))
    except DashboardError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@app.get("/api/proxy/check")
def proxy_check(authorization: str | None = Header(default=None)) -> Any:
    _auth(authorization)
    ok, reason = proxy_gate(_params_obj())
    return JSONResponse({"ok": ok, "reason": reason})


# ------------------------------------------------- notifications (D-protocol)

@app.post("/api/notify/test")
async def notify_test(body: dict[str, Any], authorization: str | None = Header(default=None)) -> Any:
    """D-protocol 'SEND TEST' button: one harmless message to the RESOLVED
    receiver (target profile > global default > env). Never raises; the
    ledger explains every skip reason; the chat id is never echoed."""
    _auth(authorization)
    target = body.get("target")
    if target is not None and str(target).strip():
        target = _valid_target(str(target))
    else:
        target = None
    from pipeline.notify import send_test_notification

    return JSONResponse(send_test_notification(_params_obj(), target))


# ------------------------------------------------------ fleet (C4 surface)

@app.get("/api/fleet")
def fleet_view_route(authorization: str | None = Header(default=None)) -> Any:
    """Fleet panel: registered members + concurrency cap + latest ledger."""
    _auth(authorization)
    return JSONResponse(fleet_members_view(_params_obj()))


@app.get("/api/fleet/ledger")
def fleet_ledger_route(authorization: str | None = Header(default=None)) -> Any:
    _auth(authorization)
    return JSONResponse(latest_fleet_ledger(_params_obj()))


@app.post("/api/fleet/run")
async def fleet_run_route(body: dict[str, Any], authorization: str | None = Header(default=None)) -> Any:
    """Start a fleet run as a detached subprocess of ./recon.sh fleet run.
    Members law: 'all' or a comma list of STRICTLY valid target names
    (P-9 hardening: every token is validated before argv)."""
    _auth(authorization)
    members = str(body.get("members") or "all").strip()
    if members.lower() != "all":
        for token_raw in members.split(","):
            _valid_target(token_raw)
    concurrency = body.get("concurrency")
    cmd = ["./recon.sh", "fleet", "run", "--targets", members]
    if concurrency is not None:
        try:
            conc = max(1, min(8, int(concurrency)))
        except (TypeError, ValueError):
            raise HTTPException(status_code=422, detail="concurrency must be an integer")
        cmd += ["--concurrency", str(conc)]
    proc = subprocess.Popen(cmd, cwd=ROOT, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, start_new_session=True)
    return JSONResponse({"started": True, "pid": proc.pid, "members": members})


# --------------------------------------------------------------- reporting (B7)

@app.get("/api/report/{target}")
def report_view(target: str, authorization: str | None = Header(default=None)) -> Any:
    _auth(authorization)
    from pipeline.reporting import _read_json, verify_bundle

    target_dir = ROOT / "recon" / target
    report_dir = target_dir / str(_params_obj().require("report_dirname"))
    manifest_path = report_dir / "report_manifest.json"
    verified, verify_reason = verify_bundle(_params_obj(), target_dir)
    return JSONResponse({
        "exists": manifest_path.is_file(),
        "verified": verified,
        "verify_reason": verify_reason,
        "manifest": _read_json(manifest_path),
    })


@app.post("/api/report/{target}/generate")
def report_generate(target: str, authorization: str | None = Header(default=None)) -> Any:
    _auth(authorization)
    from pipeline.reporting import generate_all

    target_dir = ROOT / "recon" / target
    if not target_dir.is_dir():
        raise HTTPException(status_code=404, detail=f"no recon data for {target}")
    try:
        return JSONResponse(generate_all(_params_obj(), target_dir))
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=str(exc))


_REPORT_VIEWABLE = {".md", ".html", ".csv", ".json", ".pdf", ".txt"}


@app.get("/static-file/{target}/{relpath:path}")
def artifact_view(target: str, relpath: str, authorization: str | None = Header(default=None)) -> Any:
    """Read-only report-artifact viewer (REPORTS panel OPEN links).
    Traversal-safe: confined to recon/<target>/ with a viewable-extension
    allow-list; auth'd like every other API surface."""
    _auth(authorization)
    root = (ROOT / "recon" / target).resolve()
    full = (root / relpath).resolve()
    if not str(full).startswith(str(root)) or not full.is_file():
        raise HTTPException(status_code=404, detail="not found")
    if full.suffix.lower() not in _REPORT_VIEWABLE:
        raise HTTPException(status_code=403, detail="extension not viewable")
    return FileResponse(full)


@app.exception_handler(DashboardError)
def dashboard_error_handler(_request: Any, exc: DashboardError) -> JSONResponse:
    return JSONResponse(status_code=422, content={"detail": str(exc)})


@app.get("/static/{path:path}")
def static_files(path: str) -> Any:
    target = (STATIC / path).resolve()
    if not str(target).startswith(str(STATIC)) or not target.is_file():
        raise HTTPException(status_code=404, detail="not found")
    return FileResponse(target)


@app.get("/")
def index() -> Any:
    index_file = STATIC / "index.html"
    if not index_file.is_file():
        return PlainTextResponse("dashboard SPA missing", status_code=404)
    return FileResponse(index_file)
