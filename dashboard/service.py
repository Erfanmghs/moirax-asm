"""Dashboard service logic (spec section 9.2 panels a-e, section 9.3 proxy rule).

Pure, unit-testable functions; the FastAPI layer (dashboard/app.py) stays thin.
Secrets are NEVER logged and NEVER echoed back unmasked (section 9.2-d/e).
"""

from __future__ import annotations

import fnmatch
import json
import re
import socket
import urllib.parse
from pathlib import Path
from typing import Any

from pipeline.params import Params
from pipeline.scheduler import validate as validate_schedule
from pipeline.yaml_util import load_yaml_file

# section 9.2-d provider keys inventory (key -> module -> fallback), mirrors
# docs/api-keys.md. The API-keys panel manages exactly these names.
KEYS_REGISTRY: list[dict[str, str]] = [
    {"name": "SERPER_API_KEY", "module": "PSV-0/PSV-1 search forge", "fallback": "engine ISOLATED, reroute to keyless"},
    {"name": "BRAVE_API_KEY", "module": "PSV-0/PSV-1 search forge", "fallback": "engine ISOLATED, reroute to keyless"},
    {"name": "GOOGLE_CSE_KEY", "module": "PSV-0/PSV-1 search forge", "fallback": "engine ISOLATED, reroute to keyless"},
    {"name": "GOOGLE_CSE_CX", "module": "PSV-0/PSV-1 search forge", "fallback": "required with GOOGLE_CSE_KEY"},
    {"name": "CHAOS_KEY", "module": "PSV-3 CT/subfinder chaos source", "fallback": "source skipped, never silent"},
    {"name": "GITHUB_TOKEN", "module": "PSV-7 GitHub OSINT (pool, comma-separated)", "fallback": "source skipped, never silent"},
    {"name": "CENSYS_API_ID", "module": "PSV-8 IP discovery", "fallback": "CIDR source skipped, never silent"},
    {"name": "CENSYS_API_SECRET", "module": "PSV-8 IP discovery", "fallback": "required with CENSYS_API_ID"},
    {"name": "SHODAN_API_KEY", "module": "PSV-8 IP discovery", "fallback": "CIDR source skipped, never silent"},
    {"name": "TELEGRAM_BOT_TOKEN", "module": "Notifications (platform provisioning)", "fallback": "operator sets ONLY their user id; without the bot token notifications skip honestly"},
    {"name": "TELEGRAM_CHAT_ID", "module": "Notifications (deployment fallback only)", "fallback": "D-protocol: per-user id lives in Settings or the target profile"},
]


class DashboardError(ValueError):
    """Schema-validated write rejected (section 5.4 strict validation)."""


class ProxyUnreachableError(RuntimeError):
    """section 9.3 set-but-unreachable proxy -- FAIL FAST, never silent direct."""


def mask_secret(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 4:
        return "****"
    return f"{value[:3]}****{value[-2:]}"


# ---------------------------------------------------------------- .env keys

def _read_env_map(path: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    if not path.is_file():
        return env
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        env[key.strip()] = value.strip().strip('"').strip("'")
    return env


def _write_env_map(path: Path, env: dict[str, str]) -> None:
    lines = [f"{k}={v}" for k, v in env.items()]
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def list_keys(params: Params) -> list[dict[str, Any]]:
    env = _read_env_map(params.root / str(params.require("env_filename")))
    out: list[dict[str, Any]] = []
    for row in KEYS_REGISTRY:
        name = row["name"]
        value = env.get(name, "")
        out.append({**row, "set": bool(value), "masked": mask_secret(value) if value else None})
    return out


def set_key(params: Params, name: str, value: str) -> None:
    if not any(row["name"] == name for row in KEYS_REGISTRY):
        raise DashboardError(f"unknown key name {name!r} (registry is the allow-list)")
    if not value or not value.strip():
        raise DashboardError("empty key value")
    path = params.root / str(params.require("env_filename"))
    env = _read_env_map(path)
    env[name] = value.strip()
    path.parent.mkdir(parents=True, exist_ok=True)
    _write_env_map(path, env)


def delete_key(params: Params, name: str) -> None:
    if not any(row["name"] == name for row in KEYS_REGISTRY):
        raise DashboardError(f"unknown key name {name!r}")
    path = params.root / str(params.require("env_filename"))
    env = _read_env_map(path)
    if name in env:
        del env[name]
        _write_env_map(path, env)


# ------------------------------------------------------------- settings (e)

_SETTINGS_RULES_KEYS = ("class", "enabled")


def load_settings(params: Params) -> dict[str, Any]:
    path = params.root / str(params.require("dashboard_config_relpath"))
    if not path.is_file():
        return {}
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        return {}
    if not isinstance(doc, dict):
        return {}
    if isinstance(doc.get("telegram"), dict) and doc["telegram"].get("bot_token"):
        doc["telegram"] = {**doc["telegram"], "bot_token": mask_secret(str(doc["telegram"]["bot_token"]))}
    return doc


def validate_settings(patch: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    # D-protocol pentest hardening (P-10): CLOSED allow-list -- unknown
    # top-level settings keys are refused, never merged into
    # dashboard/config.json (no attacker-controlled key smuggling).
    unknown = set(patch) - {
        "proxy_url", "digest_threshold", "alert_rules", "telegram",
        "resource_budget", "agent", "retention",
    }
    if unknown:
        errors.append(f"settings keys not allowed: {sorted(unknown)} (closed allow-list)")
    if "proxy_url" in patch:
        proxy = str(patch.get("proxy_url") or "")
        if proxy:
            scheme = urllib.parse.urlparse(proxy).scheme.lower()
            if scheme not in ("http", "https", "socks5"):
                errors.append("proxy_url scheme must be http/socks5 (section 9.3)")
    if "digest_threshold" in patch:
        th = patch.get("digest_threshold")
        if not isinstance(th, int) or isinstance(th, bool) or th <= 0:
            errors.append("digest_threshold must be a positive integer (section 4.7)")
    if "alert_rules" in patch:
        rules = patch.get("alert_rules")
        if not isinstance(rules, list):
            errors.append("alert_rules must be a list (section 4.7)")
        else:
            for rule in rules:
                if not isinstance(rule, dict) or "class" not in rule or "enabled" not in rule:
                    errors.append("each alert rule needs class + enabled (section 4.7)")
                    break
    if "telegram" in patch:
        tg = patch.get("telegram")
        if not isinstance(tg, dict):
            errors.append("telegram must be an object")
        elif "bot_token" in tg and not isinstance(tg["bot_token"], str):
            errors.append("telegram.bot_token must be a string")
    if "resource_budget" in patch:
        budget = patch.get("resource_budget")
        if not isinstance(budget, dict):
            errors.append("resource_budget must be an object (section 11.5)")
        else:
            for key in ("cpu_cores", "ram_mb"):
                if key in budget and (not isinstance(budget[key], int) or isinstance(budget[key], bool) or budget[key] <= 0):
                    errors.append(f"resource_budget.{key} must be a positive integer (section 11.5)")
    if "agent" in patch:
        agent = patch.get("agent")
        if not isinstance(agent, dict):
            errors.append("agent must be an object (section 12.6)")
        else:
            for key in ("autonomy_passive", "autonomy_active"):
                if key in agent and agent[key] not in ("observe", "suggest", "auto-fix"):
                    errors.append(f"agent.{key} must be observe|suggest|auto-fix (section 12.6)")
            if "max_llm_calls" in agent and (not isinstance(agent["max_llm_calls"], int) or isinstance(agent["max_llm_calls"], bool) or agent["max_llm_calls"] < 0):
                errors.append("agent.max_llm_calls must be a non-negative integer (section 12.4)")
    if "retention" in patch:
        retention = patch.get("retention")
        if not isinstance(retention, dict):
            errors.append("retention must be an object (storage management)")
        else:
            for key in ("keep_runs", "log_max_mb", "journal_max_mb", "log_keep_gz", "max_total_mb"):
                if key in retention and (not isinstance(retention[key], int) or isinstance(retention[key], bool) or retention[key] < 1):
                    errors.append(f"retention.{key} must be a positive integer (storage management)")
    return errors


def save_settings(params: Params, patch: dict[str, Any]) -> dict[str, Any]:
    errors = validate_settings(patch)
    if errors:
        raise DashboardError("; ".join(errors))
    path = params.root / str(params.require("dashboard_config_relpath"))
    current = load_settings(params)
    current = {**current, **patch}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(current, indent=2) + "\n", encoding="utf-8")
    return load_settings(params)


# ---------------------------------------------------------------- tools (a)

_TOOLS_EDIT_KEYS = {"enabled", "flag_overrides"}


def validate_tools_edit(tools_doc: dict[str, Any], tool: str, patch: dict[str, Any]) -> dict[str, Any]:
    """section 5.4/section 9.2-a strict schema: only enable/disable + per-tool FLAG OVERRIDES
    (the adapter-merge lever the next run's command assembly consumes)."""
    if tool not in (tools_doc.get("tools") or {}):
        raise DashboardError(f"unknown tool {tool!r}")
    extra = set(patch) - _TOOLS_EDIT_KEYS
    if extra:
        raise DashboardError(f"forbidden edit keys {sorted(extra)} -- only enabled/flag_overrides (section 5.4)")
    clean: dict[str, Any] = {}
    if "enabled" in patch:
        if not isinstance(patch["enabled"], bool):
            raise DashboardError("enabled must be a boolean")
        clean["enabled"] = patch["enabled"]
    if "flag_overrides" in patch:
        overrides = patch["flag_overrides"]
        if not isinstance(overrides, dict):
            raise DashboardError("flag_overrides must be an object of named-parameter overrides")
        for key, value in overrides.items():
            if not re.fullmatch(r"[a-z][a-z0-9_]*", key):
                raise DashboardError(f"flag_overrides key {key!r} is not a named parameter id (section 5.6)")
            if isinstance(value, (dict, list)):
                raise DashboardError(f"flag_overrides value for {key!r} must be a scalar")
            clean.setdefault("flag_overrides", {})[key] = value
    return clean


def apply_tools_edit(params: Params, tool: str, patch: dict[str, Any]) -> dict[str, Any]:
    from pipeline.textio import atomic_write_text

    path = params.root / "tools.yaml"
    tools_doc = load_yaml_file(str(path))
    clean = validate_tools_edit(tools_doc, tool, patch)
    text = _patch_tools_yaml(path.read_text(encoding="utf-8"), tool, clean)
    atomic_write_text(path, text)
    return {"tool": tool, "applied": clean}


def _patch_tools_yaml(text: str, tool: str, clean: dict[str, Any]) -> str:
    """Surgical line edit of ONE tool block (2-space indent), preserving all
    comments/formatting -- the dashboard never rewrites the whole file."""
    lines = text.splitlines()
    start = _find_block(lines, f"  {tool}:")
    if start is None:
        raise DashboardError(f"tool block {tool!r} not found")
    end = _block_end(lines, start, indent=2)
    block = lines[start:end]
    if "enabled" in clean:
        block = _replace_kv(block, "enabled", str(clean["enabled"]).lower(), 4)
    if "flag_overrides" in clean:
        for key, value in clean["flag_overrides"].items():
            block = _upsert_subkey(block, "flag_overrides:", key, value)
    return "\n".join(lines[:start] + block + lines[end:]) + "\n"


def _find_block(lines: list[str], header: str) -> int | None:
    for i, line in enumerate(lines):
        if line.rstrip() == header:
            return i
    return None


def _block_end(lines: list[str], start: int, indent: int) -> int:
    """Block ends at the next non-comment line with indent <= the block's own."""
    for j in range(start + 1, len(lines)):
        stripped = lines[j].strip()
        if stripped and not stripped.startswith("#"):
            cur = len(lines[j]) - len(lines[j].lstrip())
            if cur <= indent:
                return j
    return len(lines)


def _replace_kv(block: list[str], key: str, value: str, indent: int) -> list[str]:
    pad = " " * indent
    for i, line in enumerate(block):
        if line.startswith(f"{pad}{key}:"):
            block[i] = f"{pad}{key}: {value}"
            return block
    raise DashboardError(f"key {key!r} not found in block")


def _upsert_subkey(block: list[str], header: str, key: str, value: Any) -> list[str]:
    """Upsert `key: value` into the `header` sub-block (6-space indent) of a
    4-space-indented tool block; creates the sub-block when absent."""
    pstart = None
    for i, line in enumerate(block):
        if line.startswith(f"    {header}"):
            pstart = i
            break
    if pstart is None:
        return block + [f"    {header}", f"      {key}: {value}"]
    pend = pstart + 1
    while pend < len(block):
        stripped = block[pend].strip()
        if stripped and not stripped.startswith("#"):
            cur = len(block[pend]) - len(block[pend].lstrip())
            if cur <= 6:
                break
        pend += 1
    for i in range(pstart + 1, pend):
        if block[i].startswith(f"      {key}:"):
            block[i] = f"      {key}: {value}"
            return block
    block[pend:pend] = [f"      {key}: {value}"]
    return block


# --------------------------------------------------------------- targets (C3)

def targets_view(params: Params) -> dict[str, Any]:
    """C3: every per-target profile in the registry."""
    from pipeline.target_profiles import load_registry

    return {"targets": load_registry(params)}


def target_profile_view(params: Params, target: str) -> dict[str, Any]:
    """C3: one target's effective profile (empty = committed defaults)."""
    from pipeline.target_profiles import build_edit_plan, get_profile

    return {"target": target, "profile": get_profile(params, target), "edit_plan": build_edit_plan(params, target)}


def target_profile_upsert(params: Params, target: str, profile: dict[str, Any]) -> dict[str, Any]:
    """C3: validate + upsert via the closed allow-list law."""
    from pipeline.target_profiles import ProfileError, set_profile

    try:
        return set_profile(params, target, profile)
    except ProfileError as exc:
        raise DashboardError(str(exc)) from exc


# ------------------------------------------------------------- wordlists (a)

def validate_wordlists_edit(doc: dict[str, Any], patch: dict[str, Any], params: Params | None = None) -> dict[str, Any]:
    tasks = doc.get("tasks") or {}
    clean: dict[str, Any] = {}
    for task, keys in patch.items():
        if task not in tasks:
            raise DashboardError(f"unknown task {task!r}")
        if not isinstance(keys, list):
            raise DashboardError(f"selection for {task!r} must be a list of wordlist keys")
        registered = _registered_keys(doc, task, params)
        unknown = [k for k in keys if k not in registered]
        if unknown:
            raise DashboardError(f"unregistered wordlist keys for {task!r}: {unknown}")
        clean[task] = sorted(set(keys))
    return clean


def apply_wordlists_edit(params: Params, patch: dict[str, Any]) -> dict[str, Any]:
    from pipeline.textio import atomic_write_text

    path = params.root / "wordlists.yaml"
    doc = load_yaml_file(str(path))
    clean = validate_wordlists_edit(doc, patch)
    text = path.read_text(encoding="utf-8")
    for task, keys in clean.items():
        text = _patch_task_selection(text, task, keys, doc, params)
    atomic_write_text(path, text)
    return {"applied": clean}


def _registered_keys(doc: dict[str, Any], task: str, params: Params | None = None) -> list[str]:
    spec = (doc.get("tasks") or {}).get(task) or {}
    keys: list[str] = []
    for field in ("fast", "expansion", "sources", "default_selection"):
        for k in spec.get(field) or []:
            if k not in keys:
                keys.append(k)
    # C2 (release directive): registry-wide tasks also offer the generated
    # full-SecLists index + custom lists (platform-learned + uploads).
    if spec.get("allow_registry_wide"):
        for index_rel in ("wordlists/seclists-index.yaml", "wordlists/custom/index.yaml"):
            root = params.root if params is not None else Path(__file__).resolve().parents[1]
            p = root / index_rel
            if not p.is_file():
                continue
            try:
                idx = load_yaml_file(str(p))
            except Exception:  # noqa: BLE001 -- an unreadable index never breaks the panel
                continue
            for k in (idx or {}).get("lists") or {}:
                if k not in keys:
                    keys.append(k)
    return keys


def _patch_task_selection(text: str, task: str, keys: list[str], doc: dict[str, Any], params: Params | None = None) -> str:
    registered = _registered_keys(doc, task, params)
    unknown = [k for k in keys if k not in registered]
    if unknown:
        raise DashboardError(f"unregistered wordlist keys for {task!r}: {unknown}")
    lines = text.splitlines()
    start = _find_block(lines, f"  {task}:")
    if start is None:
        raise DashboardError(f"task block {task!r} not found")
    end = _block_end(lines, start, indent=2)
    block = lines[start:end]
    sel_start = None
    for i, line in enumerate(block):
        if line.startswith("    selection:"):
            sel_start = i
            break
    items = [f"      - {k}" for k in keys]
    if sel_start is None:
        insert_at = 1  # right after the task header line
        block[insert_at:insert_at] = ["    selection:"] + items
    else:
        sel_end = sel_start + 1
        while sel_end < len(block):
            raw = block[sel_end]
            stripped = raw.strip()
            if not stripped or stripped.startswith("#"):
                sel_end += 1
                continue
            cur = len(raw) - len(raw.lstrip())
            if cur >= 7 or (cur == 6 and stripped.startswith("- ")):
                sel_end += 1  # a list item of this selection block
                continue
            break
        block[sel_start + 1:sel_end] = items if items else []
    return "\n".join(lines[:start] + block + lines[end:]) + "\n"


# ---------------------------------------------------------------- filters (b)

_FILTER_KEYS = ("q", "source", "tag", "alive", "run", "scope")

def apply_filters(rows: list[dict[str, Any]], filters: dict[str, Any], scope_includes: list[str] | None = None,
                  scope_excludes: list[str] | None = None) -> list[dict[str, Any]]:
    """section 9.2-b GLOBAL RESULT FILTERS -- combinable: free-text, per-source
    attribution, tags, alive/dead, run selection, scope in/excludes."""
    out = rows
    q = str(filters.get("q") or "").strip().lower()
    if q:
        out = [r for r in out if q in json.dumps(r, default=str).lower()]
    source = str(filters.get("source") or "").strip()
    if source:
        out = [r for r in out if source in (r.get("sources") or [])]
    tag = str(filters.get("tag") or "").strip()
    if tag:
        out = [r for r in out if tag in (r.get("tags") or [])]
    alive = str(filters.get("alive") or "").strip().lower()
    if alive in ("true", "false"):
        want = alive == "true"
        out = [r for r in out if bool(r.get("alive")) == want]
    run_sel = str(filters.get("run") or "").strip()
    if run_sel:
        out = [r for r in out if str(r.get("run") or "") == run_sel]
    scope = str(filters.get("scope") or "").strip().lower()
    if scope in ("in", "excluded"):
        host = None
        def _match(patterns: list[str], h: str) -> bool:
            return any(fnmatch.fnmatch(h, p.lstrip("*.") and f"*{p.lstrip('*')}" if p.startswith("*.") else p) for p in patterns)
        kept = []
        for r in out:
            h = str(r.get("host") or "")
            if scope == "in":
                ok = any(fnmatch.fnmatch(h, p) or h == p or h.endswith("." + p.lstrip("*."))
                         for p in (scope_includes or []))
            else:
                ok = any(fnmatch.fnmatch(h, p) or h == p or h.endswith("." + p.lstrip("*."))
                         for p in (scope_excludes or []))
            kept.append(r if ok else None)
        out = [r for r in kept if r is not None]
    return out


def serialize_filters(filters: dict[str, Any]) -> str:
    pairs = [f"{k}={urllib.parse.quote(str(v), safe='')}" for k, v in sorted(filters.items()) if str(v).strip()]
    return "&".join(pairs)


def parse_filters_query(query: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for chunk in (query or "").split("&"):
        if not chunk or "=" not in chunk:
            continue
        key, value = chunk.split("=", 1)
        if key in _FILTER_KEYS:
            out[key] = urllib.parse.unquote(value)
    return out


# --------------------------------------------------------------- coverage (b)

def coverage_analytics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """section 9.2-b SOURCE COVERAGE ANALYTICS: per-source contribution (unique
    assets per tool), overlap histogram (assets found by N sources),
    per-source uniqueness %."""
    contribution: dict[str, int] = {}
    unique: dict[str, int] = {}
    overlap: dict[str, int] = {}
    for row in rows:
        sources = [s for s in (row.get("sources") or []) if s]
        for s in set(sources):
            contribution[s] = contribution.get(s, 0) + 1
        n = len(set(sources))
        overlap[str(n)] = overlap.get(str(n), 0) + 1
        if n == 1 and sources:
            unique[sources[0]] = unique.get(sources[0], 0) + 1
    uniqueness = {
        s: round(unique.get(s, 0) / contribution[s] * 100.0, 1) if contribution.get(s) else 0.0
        for s in contribution
    }
    return {"assets": len(rows), "contribution": contribution, "unique_assets": unique,
            "overlap_by_n_sources": overlap, "uniqueness_pct": uniqueness}


# --------------------------------------------------------------- fleet (C4)

def fleet_members_view(params: Params) -> dict[str, Any]:
    """Fleet panel data: registered per-target profiles (members), the global
    concurrency cap, and the targets registry inline so the panel can drive
    RUN FLEET without a second round-trip."""
    from pipeline.fleet import max_concurrency
    from pipeline.target_profiles import load_registry

    registry = load_registry(params)
    return {
        "members": sorted(registry),
        "profiles": registry,
        "max_concurrency": max_concurrency(params),
    }


def latest_fleet_ledger(params: Params) -> dict[str, Any]:
    """Latest history/fleet/<ts>/fleet-ledger.json (exists=false before the
    first fleet run) -- the FLEET panel's status view."""
    base = params.root / "history" / "fleet"
    if not base.is_dir():
        return {"exists": False}
    best: Path | None = None
    for child in base.iterdir():
        ledger = child / "fleet-ledger.json"
        if ledger.is_file() and (best is None or child.name > best.parent.name):
            best = ledger
    if best is None:
        return {"exists": False}
    try:
        doc = json.loads(best.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        return {"exists": False}
    return {"exists": True, "ledger_path": str(best.relative_to(params.root)), **doc}


# ------------------------------------------------------------------ proxy

def check_proxy_reachable(proxy_url: str, timeout: float = 3.0) -> tuple[bool, str]:
    parsed = urllib.parse.urlparse(proxy_url)
    host = parsed.hostname
    port = parsed.port or (1080 if parsed.scheme.startswith("socks") else 8080)
    if not host:
        return False, f"unparseable proxy URL {proxy_url!r}"
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True, f"tcp connect ok {host}:{port}"
    except OSError as exc:
        return False, f"proxy unreachable at {host}:{port}: {exc}"


def proxy_gate(params: Params) -> tuple[bool, str]:
    """section 9.3: set-but-unreachable -> FAIL FAST; unset -> direct, silently."""
    proxy = str(params.require("proxy_url") or "").strip()
    if not proxy:
        return True, "proxy unset -- direct connection (section 9.3)"
    ok, reason = check_proxy_reachable(proxy, timeout=float(params.require("proxy_check_timeout_sec")))
    return ok, reason


# -------------------------------------------------------------- scheduler (c)

def scheduler_view(params: Params) -> dict[str, Any]:
    from pipeline.scheduler import load_schedule

    return load_schedule(params)


def scheduler_save(params: Params, doc: dict[str, Any]) -> dict[str, Any]:
    from pipeline.scheduler import save_schedule

    errors = validate_schedule(doc, int(params.require("scheduler_min_interval_min")))
    if errors:
        raise DashboardError("; ".join(errors))
    save_schedule(params, doc)
    return doc
