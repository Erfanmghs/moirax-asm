"""FastAPI dashboard backend (spec §9.1/§9.2). The ONLY docker.sock client.

Auth: every /api route (except /api/health) requires `Authorization: Bearer
<DASHBOARD_TOKEN>`; if DASHBOARD_TOKEN is unset the backend refuses every
API call (fail-closed — §9.1 auth contract).
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
    list_keys,
    load_settings,
    parse_filters_query,
    proxy_gate,
    save_settings,
    scheduler_save,
    scheduler_view,
    set_key,
    apply_filters,
)
from pipeline.params import Params
from pipeline.scheduler import load_schedule
from pipeline.yaml_util import load_yaml_file

ROOT = Path(__file__).resolve().parents[1]
STATIC = Path(__file__).resolve().parent / "static"

app = FastAPI(title="recon-pipeline dashboard", docs_url=None, redoc_url=None)

_params: Params | None = None


def _params_obj() -> Params:
    global _params
    if _params is None:
        _params = Params(ROOT)
    return _params


def _auth(authorization: str | None) -> None:
    token = str(os.environ.get("DASHBOARD_TOKEN") or "").strip()
    if not token:
        raise HTTPException(status_code=503, detail="DASHBOARD_TOKEN is not configured (fail-closed, §9.1)")
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
    """§12.7: agent journal streamed live in Run Control (append-only source)."""
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
        raise HTTPException(status_code=502, detail=f"PROXY RULE fail-fast (§9.3): {reason}")
    target = str(body.get("target") or "").strip()
    if not target:
        raise HTTPException(status_code=422, detail="target is required")
    aggressive = bool(body.get("aggressive", False))
    cmd = ["./recon.sh", "run", target] + (["--aggressive"] if aggressive else [])
    proc = subprocess.Popen(cmd, cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            start_new_session=True)
    return JSONResponse({"started": True, "pid": proc.pid, "cmd": cmd, "proxy": reason})


@app.post("/api/run/stop")
async def run_stop(body: dict[str, Any], authorization: str | None = Header(default=None)) -> Any:
    _auth(authorization)
    target = str(body.get("target") or "").strip()
    if not target:
        raise HTTPException(status_code=422, detail="target is required")
    proc = subprocess.run(["./recon.sh", "stop", target], cwd=ROOT, capture_output=True, text=True)
    return JSONResponse({"exit": proc.returncode, "stdout": proc.stdout[-2000:]})


@app.post("/api/run/resume")
async def run_resume(body: dict[str, Any], authorization: str | None = Header(default=None)) -> Any:
    _auth(authorization)
    params = _params_obj()
    ok, reason = proxy_gate(params)
    if not ok:
        raise HTTPException(status_code=502, detail=f"PROXY RULE fail-fast (§9.3): {reason}")
    target = str(body.get("target") or "").strip()
    if not target:
        raise HTTPException(status_code=422, detail="target is required")
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
    return JSONResponse({"saved": name, "masked": True, "note": "picked up on the next run without restart (§9.2-d)"})


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
