"""Dashboard service logic (spec section 9.2 panels a-e, section 9.3 proxy rule).

Pure, unit-testable functions; the FastAPI layer (dashboard/app.py) stays thin.
Secrets are NEVER logged and NEVER echoed back unmasked (section 9.2-d/e).
"""

from __future__ import annotations

import copy
import fnmatch
import json
import os
import random
import re
import socket
import threading
import time
import urllib.parse
from datetime import datetime, timezone
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
    {"name": "SECURITYTRAILS_API_KEY", "module": "PSV-3b subdomain API", "fallback": "source skipped; keyless APIs still run"},
    {"name": "VIRUSTOTAL_API_KEY", "module": "PSV-3b subdomain API", "fallback": "source skipped; keyless APIs still run"},
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


def append_audit(root: Path, action: str, fields: dict[str, Any] | None = None) -> None:
    """Append-only operator audit. Never stores secrets or token values."""
    row = {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "action": str(action)[:80],
        **{k: v for k, v in (fields or {}).items() if k not in {"token", "value", "authorization", "bot_token"}},
    }
    path = root / "logs" / "dashboard-audit.jsonl"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, default=str) + "\n")
        _chmod_private(path)
    except OSError:
        return


# ---------------------------------------------------------------- .env keys

def _read_env_map(path: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    if not path.is_file():
        return env
    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError:
        return env
    for raw in raw_text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        env[key.strip()] = value.strip().strip('"').strip("'")
    return env


def _chmod_private(path: Path) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _write_env_map(path: Path, env: dict[str, str]) -> None:
    """Rewrite .env without dropping comments or keys outside the current map.

    Keys present in the previous file but absent from `env` are deleted
    (used by delete_key). Comments and blank lines are preserved.
    """
    old_lines = path.read_text(encoding="utf-8").splitlines() if path.is_file() else []
    seen: set[str] = set()
    out: list[str] = []
    for raw in old_lines:
        stripped = raw.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            out.append(raw)
            continue
        key = stripped.split("=", 1)[0].strip()
        if key in env:
            out.append(f"{key}={env[key]}")
            seen.add(key)
    for key, value in env.items():
        if key not in seen:
            out.append(f"{key}={value}")
    path.parent.mkdir(parents=True, exist_ok=True)
    text = "\n".join(out)
    if text:
        text += "\n"
    path.write_text(text, encoding="utf-8")
    _chmod_private(path)


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


def _read_settings_doc(params: Params) -> dict[str, Any]:
    path = params.root / str(params.require("dashboard_config_relpath"))
    if not path.is_file():
        return {}
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        return {}
    return doc if isinstance(doc, dict) else {}


def _mask_settings(doc: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(doc)
    if isinstance(out.get("telegram"), dict) and out["telegram"].get("bot_token"):
        out["telegram"] = {
            **out["telegram"],
            "bot_token": mask_secret(str(out["telegram"]["bot_token"])),
        }
    return out


def load_settings(params: Params) -> dict[str, Any]:
    doc = _mask_settings(_read_settings_doc(params))
    try:
        from pipeline.recon_depth import clamp_ffuf_depth, clamp_recon_depth

        doc["recon_depth"] = clamp_recon_depth(params)
        doc["ffuf_depth"] = clamp_ffuf_depth(params)
    except Exception:
        doc.setdefault("recon_depth", 1)
        doc.setdefault("ffuf_depth", 1)
    try:
        from pipeline.recon_depth import clamp_dnsx_parallel_parents

        doc["dnsx_parallel_parents"] = clamp_dnsx_parallel_parents(params)
    except Exception:
        doc.setdefault("dnsx_parallel_parents", 1)
    try:
        doc["passive_recursion_depth"] = int(params.require("passive_recursion_depth"))
    except Exception:
        doc.setdefault("passive_recursion_depth", 1)
    try:
        profile = str(params.require("portsweep_profile") or "full").strip().lower()
        doc["portsweep_profile"] = profile if profile in ("full", "light", "custom") else "full"
    except Exception:
        doc.setdefault("portsweep_profile", "full")
    try:
        doc["portsweep_custom_ports"] = str(params.require("portsweep_custom_ports") or "")
    except Exception:
        doc.setdefault("portsweep_custom_ports", "")
    try:
        doc["portsweep_nmap_sv"] = bool(params.require("portsweep_nmap_sv"))
    except Exception:
        doc.setdefault("portsweep_nmap_sv", True)
    try:
        doc["ffuf4_max_jobs"] = max(0, int(params.require("ffuf4_max_jobs")))
    except Exception:
        doc.setdefault("ffuf4_max_jobs", 0)
    return doc


_TELEGRAM_WRITE_KEYS = frozenset({"bot_token", "chat_id"})
_RESOURCE_WRITE_KEYS = frozenset({"cpu_cores", "ram_mb"})
_AGENT_WRITE_KEYS = frozenset({"enabled", "autonomy_passive", "autonomy_active", "max_llm_calls"})
_RETENTION_WRITE_KEYS = frozenset(
    ("keep_runs", "log_max_mb", "journal_max_mb", "log_keep_gz", "max_total_mb")
)


def validate_settings(patch: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    # D-protocol pentest hardening (P-10): CLOSED allow-list -- unknown
    # top-level settings keys are refused, never merged into
    # dashboard/config.json (no attacker-controlled key smuggling).
    unknown = set(patch) - {
        "proxy_url", "proxy_pool", "digest_threshold", "alert_rules", "telegram",
        "resource_budget", "agent", "retention", "recon_depth", "ffuf_depth",
        "passive_recursion_depth", "dnsx_parallel_parents",
        "portsweep_profile", "portsweep_custom_ports", "portsweep_nmap_sv",
        "ffuf4_max_jobs",
    }
    if unknown:
        errors.append(f"settings keys not allowed: {sorted(unknown)} (closed allow-list)")
    if "proxy_url" in patch:
        proxy = str(patch.get("proxy_url") or "")
        if proxy:
            scheme = urllib.parse.urlparse(proxy).scheme.lower()
            if scheme not in ("http", "https", "socks5"):
                errors.append("proxy_url scheme must be http/socks5 (section 9.3)")
    if "proxy_pool" in patch:
        # C5 IP rotation: comma-separated pool; same scheme law as proxy_url,
        # every entry validated, deduped, never silently dropped.
        pool_raw = patch.get("proxy_pool")
        if pool_raw is None or pool_raw == "":
            pass
        elif not isinstance(pool_raw, str):
            errors.append("proxy_pool must be a comma-separated string of proxy URLs")
        else:
            from pipeline.ip_rotation import parse_pool
            try:
                parse_pool(pool_raw)
            except ValueError as exc:
                errors.append(f"proxy_pool invalid: {exc}")
    if "digest_threshold" in patch:
        th = patch.get("digest_threshold")
        if not isinstance(th, int) or isinstance(th, bool) or th <= 0:
            errors.append("digest_threshold must be a positive integer (section 4.7)")
    if "alert_rules" in patch:
        rules = patch.get("alert_rules")
        if not isinstance(rules, list):
            errors.append("alert_rules must be a list (section 4.7)")
        else:
            allowed_sides = {"added", "removed", "changed"}
            for rule in rules:
                if not isinstance(rule, dict) or "class" not in rule or "enabled" not in rule:
                    errors.append("each alert rule needs class + enabled (section 4.7)")
                    break
                sides = rule.get("sides")
                if sides is None:
                    continue
                if not isinstance(sides, list) or any(str(s) not in allowed_sides for s in sides):
                    errors.append("alert_rules.sides must be a list of added|removed|changed")
                    break
    if "telegram" in patch:
        tg = patch.get("telegram")
        if not isinstance(tg, dict):
            errors.append("telegram must be an object")
        else:
            extra = set(tg) - _TELEGRAM_WRITE_KEYS
            if extra:
                errors.append(f"telegram keys not allowed: {sorted(extra)} (closed allow-list)")
            elif "bot_token" in tg and not isinstance(tg["bot_token"], str):
                errors.append("telegram.bot_token must be a string")
    if "resource_budget" in patch:
        budget = patch.get("resource_budget")
        if not isinstance(budget, dict):
            errors.append("resource_budget must be an object (section 11.5)")
        else:
            extra = set(budget) - _RESOURCE_WRITE_KEYS
            if extra:
                errors.append(f"resource_budget keys not allowed: {sorted(extra)} (closed allow-list)")
            for key in ("cpu_cores", "ram_mb"):
                if key in budget and (not isinstance(budget[key], int) or isinstance(budget[key], bool) or budget[key] <= 0):
                    errors.append(f"resource_budget.{key} must be a positive integer (section 11.5)")
    if "agent" in patch:
        agent = patch.get("agent")
        if not isinstance(agent, dict):
            errors.append("agent must be an object (section 12.6)")
        else:
            extra = set(agent) - _AGENT_WRITE_KEYS
            if extra:
                errors.append(f"agent keys not allowed: {sorted(extra)} (closed allow-list)")
            if "enabled" in agent and not isinstance(agent["enabled"], bool):
                errors.append("agent.enabled must be a boolean")
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
            extra = set(retention) - _RETENTION_WRITE_KEYS
            if extra:
                errors.append(f"retention keys not allowed: {sorted(extra)} (closed allow-list)")
            for key in ("keep_runs", "log_max_mb", "journal_max_mb", "log_keep_gz", "max_total_mb"):
                if key in retention and (not isinstance(retention[key], int) or isinstance(retention[key], bool) or retention[key] < 1):
                    errors.append(f"retention.{key} must be a positive integer (storage management)")
    if "recon_depth" in patch:
        depth = patch.get("recon_depth")
        if not isinstance(depth, int) or isinstance(depth, bool) or depth < 1 or depth > 5:
            errors.append("recon_depth must be an integer 1-5 (nested DNS)")
    if "ffuf_depth" in patch:
        depth = patch.get("ffuf_depth")
        if not isinstance(depth, int) or isinstance(depth, bool) or depth < 1 or depth > 5:
            errors.append("ffuf_depth must be an integer 1-5 (nested vhost)")
    if "passive_recursion_depth" in patch:
        depth = patch.get("passive_recursion_depth")
        if not isinstance(depth, int) or isinstance(depth, bool) or depth < 0 or depth > 5:
            errors.append("passive_recursion_depth must be an integer 0-5")
    if "dnsx_parallel_parents" in patch:
        n = patch.get("dnsx_parallel_parents")
        if not isinstance(n, int) or isinstance(n, bool) or n < 1 or n > 8:
            errors.append("dnsx_parallel_parents must be an integer 1-8 (nested DNS brute)")
    if "portsweep_profile" in patch:
        profile = str(patch.get("portsweep_profile") or "").strip().lower()
        if profile not in ("full", "light", "custom"):
            errors.append("portsweep_profile must be full, light, or custom")
    if "portsweep_custom_ports" in patch:
        raw = patch.get("portsweep_custom_ports")
        if raw is None:
            raw = ""
        if not isinstance(raw, str):
            errors.append("portsweep_custom_ports must be a string")
        else:
            try:
                from pipeline.target_profiles import normalize_portsweep_ports

                patch["portsweep_custom_ports"] = normalize_portsweep_ports(raw)
            except ValueError as exc:
                errors.append(str(exc))
    if "portsweep_nmap_sv" in patch and not isinstance(patch.get("portsweep_nmap_sv"), bool):
        errors.append("portsweep_nmap_sv must be a boolean")
    if "ffuf4_max_jobs" in patch:
        n = patch.get("ffuf4_max_jobs")
        if not isinstance(n, int) or isinstance(n, bool) or n < 0:
            errors.append("ffuf4_max_jobs must be an integer >= 0 (0 = every HTTP listener)")
    profile = str(patch.get("portsweep_profile") or "").strip().lower()
    if profile == "custom" and not str(patch.get("portsweep_custom_ports") or "").strip():
        errors.append("custom port scan needs a non-empty port list (example: 22,80,443,8000-8080)")
    return errors


def _merge_settings(current: dict[str, Any], patch: dict[str, Any]) -> dict[str, Any]:
    """Deep-merge nested objects so a chat_id-only save cannot wipe bot_token.

    Masked token values (containing ****) are ignored so a GET-then-PUT
    round-trip never persists the masked display string as the secret.
    """
    nested = ("telegram", "resource_budget", "agent", "retention")
    merged = dict(current)
    for key, value in patch.items():
        if key in nested and isinstance(value, dict):
            base = dict(merged[key]) if isinstance(merged.get(key), dict) else {}
            incoming = dict(value)
            if key == "telegram":
                tok = incoming.get("bot_token")
                if isinstance(tok, str) and ("****" in tok or not tok.strip()):
                    incoming.pop("bot_token", None)
            merged[key] = {**base, **incoming}
        else:
            merged[key] = value
    return merged


def save_settings(params: Params, patch: dict[str, Any]) -> dict[str, Any]:
    errors = validate_settings(patch)
    if errors:
        raise DashboardError("; ".join(errors))
    path = params.root / str(params.require("dashboard_config_relpath"))
    current = _read_settings_doc(params)
    merged = _merge_settings(current, patch)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(merged, indent=2) + "\n", encoding="utf-8")
    _chmod_private(path)
    depth_keys = ("recon_depth", "ffuf_depth", "passive_recursion_depth", "dnsx_parallel_parents")
    if any(k in patch for k in depth_keys):
        _sync_depth_tools(params, {k: int(patch[k]) for k in depth_keys if k in patch})
    tool_keys = ("portsweep_profile", "portsweep_custom_ports", "portsweep_nmap_sv", "ffuf4_max_jobs")
    if any(k in patch for k in tool_keys):
        _sync_tools_settings(params, {k: patch[k] for k in tool_keys if k in patch})
    return _mask_settings(merged)


def _sync_depth_tools(params: Params, depths: dict[str, int]) -> None:
    """Global SETTINGS writes live tools.yaml knobs the pipeline reads (independently)."""
    _sync_tools_settings(params, depths)


def _sync_tools_settings(params: Params, updates: dict[str, Any]) -> None:
    """Write SETTINGS knobs into tools.yaml so the next pipeline run sees them."""
    from pipeline.target_profiles import _yaml_scalar
    from pipeline.textio import atomic_write_text

    tools = params.root / "tools.yaml"
    if not tools.is_file():
        return
    text = tools.read_text(encoding="utf-8")
    for key, value in updates.items():
        pattern = re.compile(rf"^  {re.escape(key)}:.*$", re.M)
        if pattern.search(text):
            text = pattern.sub(f"  {key}: {_yaml_scalar(value)}", text, count=1)
    atomic_write_text(tools, text)


# ---------------------------------------------------------------- tools (a)

_TOOLS_EDIT_KEYS = {"enabled", "flag_overrides"}
_COVERAGE_LOCKED_TOOLS = {"naabu-full"}


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
        if tool in _COVERAGE_LOCKED_TOOLS and patch["enabled"] is False:
            raise DashboardError(
                f"{tool} stays enabled so PORT SCAN MODE full can run; "
                "choose top ports or custom in SETTINGS / SCAN SETUP instead of disabling this switch"
            )
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

# switch_id, binary, technique, controls (what ENABLED/DISABLED applies to)
OPERATOR_TOOL_CATALOG: tuple[tuple[str, str, str, str], ...] = (
    ("ffuf", "ffuf", "Optional HTTP label brute", "Enables or disables the optional HTTP FUZZ.domain loop (OFF by default; dnsx is the active subdomain brute)"),
    ("ffuf-vhost", "ffuf", "Virtual-host probe", "Enables or disables virtual-host Host-header probes (FFUF-2 / FFUF-3 / FFUF-4); not the DNS brute row"),
    ("httpx", "httpx", "HTTP length + technology", "Enables HTTP probing of dnsx-resolved names: status, response length, and technology shown on RESULTS"),
    ("dnsx", "dnsx", "DNS subdomain brute + IP resolve", "Enables dnsx wordlist brute (DNSR-1): discovers subdomains and their IPs"),
    ("dnsx-list", "dnsx", "DNS list resolve", "Enables or disables resolving a prepared host list"),
    ("dnsx-resolve", "dnsx", "Bulk DNS resolve", "Enables or disables bulk DNS resolve of collected names"),
    ("massdns", "massdns", "Mass DNS resolve", "Enables or disables high-volume DNS resolve"),
    ("alterx", "alterx", "Name permutation", "Enables or disables generating extra name guesses from known hosts"),
    ("naabu", "naabu", "Optional top-ports preview", "OPTIONAL fast peek while DNS is still running (port-check). Default OFF. Post-MERGE coverage is PORT SCAN MODE in SETTINGS / SETUP (full, top ports, or custom)"),
    ("naabu-full", "naabu", "Port sweep -- full mode", "Runs after MERGE only when PORT SCAN MODE is full (TCP 1-65535, like nmap -p-). Not used for top-ports or custom. Switch stays on so full mode can run; change coverage in SETTINGS / SETUP"),
    ("naabu-sweep", "naabu", "Port sweep -- custom mode", "Runs after MERGE only when PORT SCAN MODE is custom (your nmap -p list). Set the list in SETTINGS / SETUP"),
    ("nmap-sv", "nmap", "Service fingerprint", "Enables or disables nmap -Pn -sV on open ports (skip ping so firewalled hosts still get product/version)"),
    ("subfinder", "subfinder", "Passive subdomain OSINT", "Enables or disables subfinder as a passive name source"),
    ("amass", "amass", "Passive subdomain OSINT", "Enables or disables amass as a passive name source"),
    ("assetfinder", "assetfinder", "Related-name OSINT", "Enables or disables assetfinder related-name lookup"),
    ("findomain", "findomain", "Passive subdomain OSINT", "Enables or disables findomain as a passive name source"),
    ("chaos", "chaos", "ProjectDiscovery Chaos", "Enables or disables the Chaos dataset lookup"),
    ("crtsh", "crt.sh", "Certificate Transparency", "Enables or disables crt.sh certificate-transparency lookup"),
    ("certspotter", "certspotter", "Certificate Transparency", "Enables or disables Cert Spotter CT lookup"),
    ("waybackurls", "waybackurls", "Web archive URLs", "Enables or disables Wayback URL collection"),
    ("gau", "gau", "GetAllURLs archives", "Enables or disables gau archive URL collection"),
    ("httpx-passive", "httpx", "Passive HTTP probe", "Enables or disables HTTP probing inside the passive branch; not the active httpx row"),
)


def list_operator_tools(params: Params) -> list[dict[str, Any]]:
    """Operator-facing tool rows: original binary, unique switch id, and
    what ENABLED/DISABLED controls. Internal echo/fallback tools stay hidden."""
    doc = load_yaml_file(str(params.root / "tools.yaml")) or {}
    tools = doc.get("tools") or {}
    out: list[dict[str, Any]] = []
    for key, title, technique, controls in OPERATOR_TOOL_CATALOG:
        spec = tools.get(key)
        if not isinstance(spec, dict):
            continue
        out.append({
            "id": key,
            "name": title,
            "technique": technique,
            "controls": controls,
            "enabled": bool(spec.get("enabled", False)),
            "locked": key in _COVERAGE_LOCKED_TOOLS,
            "branch": spec.get("branch") or "",
            "binary": spec.get("binary") or title,
            "image_ref": spec.get("image_ref") or "",
        })
    return out


def known_target_names(params: Params, *, include_deleted: bool = False) -> list[str]:
    """Registered profiles plus recon/<name>/ workspaces."""
    from pipeline.deleted import is_tombstoned
    from pipeline.target_profiles import TARGET_NAME_RE, load_registry

    names = set(load_registry(params) or {})
    recon = params.root / "recon"
    if recon.is_dir():
        for child in recon.iterdir():
            if child.is_dir() and TARGET_NAME_RE.match(child.name):
                if include_deleted or not is_tombstoned(child):
                    names.add(child.name)
    if not include_deleted:
        hidden = set()
        for name in list(names):
            child = recon / name if recon.is_dir() else None
            if child is not None and child.is_dir() and is_tombstoned(child):
                hidden.add(name)
        names -= hidden
    return sorted(names)


def targets_view(params: Params) -> dict[str, Any]:
    """C3: every per-target profile in the registry."""
    from pipeline.target_profiles import load_registry

    return {"targets": load_registry(params), "known": known_target_names(params)}


def _read_json_silent(path: Path) -> dict[str, Any]:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        return {}
    return doc if isinstance(doc, dict) else {}


def scan_target_row(params: Params, target: str, registry: dict[str, Any] | None = None) -> dict[str, Any]:
    """One SCAN-board row: status, modules, last run -- THIS target only."""
    from pipeline.factory import target_root
    from pipeline.target_profiles import load_registry, profile_has_overrides

    target_dir = target_root(params, target)
    state = _read_json_silent(target_dir / str(params.require("state_filename")))
    run = state.get("run") if isinstance(state.get("run"), dict) else {}
    runs_doc = _read_json_silent(target_dir / str(params.require("runs_filename")))
    runs = [r for r in (runs_doc.get("runs") or []) if isinstance(r, dict)]
    last = runs[-1] if runs else {}
    logs_dir = target_dir / "logs"
    has_logs = any((logs_dir / name).is_file() for name in ("run.log", "dashboard-spawn.log"))
    if registry is None:
        registry = load_registry(params)
    profile = registry.get(target) or {}
    modules = state.get("modules") if isinstance(state.get("modules"), dict) else {}
    running_n = sum(1 for row in modules.values() if isinstance(row, dict) and row.get("status") == "running")
    try:
        from pipeline.live_status import live_status

        health = live_status(params, target_dir)
    except Exception:  # noqa: BLE001 -- SCAN board must still render
        health = {}
    live = health.get("live") if isinstance(health, dict) else {}
    issues = health.get("issues") if isinstance(health, dict) else []

    return {
        "target": target,
        "registered": bool(profile),
        "description": str(profile.get("description") or ""),
        "profile": profile,
        "inherits_globals": not profile_has_overrides(profile),
        "workspace": target_dir.is_dir(),
        "run_status": run.get("status"),
        "reason": run.get("reason"),
        "failing_module": run.get("failing_module"),
        "modules": modules,
        "modules_running": running_n,
        "updated_at": state.get("updated_at"),
        "last_run": last.get("timestamp"),
        "last_counts": last.get("counts") if isinstance(last.get("counts"), dict) else {},
        "run_count": len(runs),
        "has_logs": has_logs,
        "live": live if isinstance(live, dict) else {},
        "issues": issues if isinstance(issues, list) else [],
    }


_PURGE_AT = 0.0


def scan_board_view(params: Params) -> dict[str, Any]:
    """All known targets for the SCAN accordion -- never mixes per-target rows."""
    from pipeline.deleted import purge_expired_all
    from pipeline.target_profiles import load_registry

    global _PURGE_AT
    now = time.time()
    if now - _PURGE_AT >= 60.0:
        try:
            purge_expired_all(params)
        except Exception:  # noqa: BLE001 -- purge must never blank the SCAN board
            pass
        _PURGE_AT = now
    registry = load_registry(params)
    names = known_target_names(params)
    rows = []
    seen: set[str] = set()
    for name in names:
        if name in seen:
            continue
        seen.add(name)
        rows.append(scan_target_row(params, name, registry=registry))
    return {"targets": rows, "count": len(rows)}


def scan_add_target(params: Params, target: str, description: str = "") -> dict[str, Any]:
    """Register + create the isolated recon/<target>/ workspace from SCAN."""
    from pipeline.deleted import clear_tombstone
    from pipeline.factory import ensure_layout, target_root
    from pipeline.target_profiles import ProfileError, get_profile, set_profile

    try:
        ensure_layout(params, target)
    except ValueError as exc:
        raise DashboardError(str(exc)) from exc
    clear_tombstone(target_root(params, target))
    if not get_profile(params, target):
        note = (description or "added from SCAN").strip()
        if not note.isascii() or len(note) > 200:
            raise DashboardError("description must be short ASCII text")
        try:
            set_profile(params, target, {"description": note})
        except ProfileError as exc:
            raise DashboardError(str(exc)) from exc
    return scan_target_row(params, target)


def parse_scan_target_list(raw: Any) -> tuple[list[str], list[str]]:
    """Split SITE box / list paste into unique hostnames. Invalid tokens are rejected."""
    from pipeline.target_profiles import TARGET_NAME_RE

    chunks: list[str] = []
    if isinstance(raw, list):
        chunks = [str(item) for item in raw]
    elif isinstance(raw, str):
        chunks = re.split(r"[\s,;]+", raw)
    seen: set[str] = set()
    valid: list[str] = []
    rejected: list[str] = []
    for chunk in chunks:
        name = chunk.strip().lower().rstrip(".")
        if not name:
            continue
        if not TARGET_NAME_RE.match(name):
            rejected.append(chunk.strip())
            continue
        if name in seen:
            continue
        seen.add(name)
        valid.append(name)
    return valid, rejected


def scan_add_targets(params: Params, names: list[str], description: str = "") -> dict[str, Any]:
    """Register many sites. One bad name never blocks the rest of the list."""
    added: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    for name in names:
        try:
            added.append(scan_add_target(params, name, description))
        except (DashboardError, ValueError) as exc:
            errors.append({"target": name, "error": str(exc)})
    if not added:
        raise DashboardError("no valid sites in the list -- ADD TARGET first with a domain like example.com")
    return {"count": len(added), "targets": added, "errors": errors}


def scan_require_registered(params: Params, target: str) -> str:
    """START SCAN may only run after ADD TARGET / ADD LIST."""
    from pipeline.factory import sanitize_target

    try:
        name = sanitize_target(target)
    except ValueError as exc:
        raise DashboardError(str(exc)) from exc
    if name not in known_target_names(params):
        raise DashboardError("ADD TARGET first -- this site is not on YOUR SITES")
    return name


def scan_delete_target(params: Params, target: str) -> dict[str, Any]:
    """Hide one site from SCAN immediately. Keep its warehouse for keep_days, then purge."""
    import os

    from pipeline.deleted import keep_days, write_tombstone
    from pipeline.factory import sanitize_target, target_root
    from pipeline.target_profiles import ProfileError, set_profile

    try:
        name = sanitize_target(target)
    except ValueError as exc:
        raise DashboardError(str(exc)) from exc
    recon = (params.root / str(params.require("recon_root"))).resolve()
    target_dir = target_root(params, name).resolve()
    try:
        common = os.path.commonpath([str(recon), str(target_dir)])
    except ValueError as exc:
        raise DashboardError("refusing delete outside recon root") from exc
    if common != str(recon) or target_dir == recon:
        raise DashboardError("refusing delete outside recon root")
    try:
        set_profile(params, name, {})
    except ProfileError as exc:
        raise DashboardError(str(exc)) from exc
    marker = write_tombstone(params, target_dir, name)
    from pipeline.warehouse import warehouse_path

    return {
        "deleted": name,
        "hidden": True,
        "workspace_removed": False,
        "kept_days": keep_days(params),
        "purge_after": marker.get("purge_after"),
        "warehouse_kept": warehouse_path(params, target_dir).is_file(),
    }


def target_profile_view(params: Params, target: str) -> dict[str, Any]:
    """C3: one target's effective profile (empty = committed defaults)."""
    from pipeline.target_profiles import build_edit_plan, get_profile, profile_has_overrides

    profile = get_profile(params, target)
    return {
        "target": target,
        "profile": profile,
        "edit_plan": build_edit_plan(params, target),
        "inherits_globals": not profile_has_overrides(profile),
    }


def target_profile_upsert(params: Params, target: str, profile: dict[str, Any]) -> dict[str, Any]:
    """C3: validate + upsert via the closed allow-list law."""
    from pipeline.target_profiles import ProfileError, set_profile

    try:
        return set_profile(params, target, profile)
    except ProfileError as exc:
        raise DashboardError(str(exc)) from exc


# ------------------------------------------------------------- wordlists (a)

def _wordlist_rel_path(entry: Any, key: str = "") -> str:
    if not isinstance(entry, dict):
        return f"key:{key}"
    rel = str(entry.get("path") or "").replace("\\", "/").lstrip("/").lower()
    return rel or f"key:{key}"


def unique_wordlist_keys_by_path(
    lists: dict[str, Any],
    keys: list[str],
    *,
    task: str = "",
    selected: set[str] | None = None,
) -> list[str]:
    """One key per wordlist file. dns_* wins for DNS brute, vhost_* for FFUF-2."""
    chosen: set[str] = set(selected or [])
    picked: dict[str, str] = {}

    def rank(key: str) -> tuple[int, int, str]:
        name = str(key)
        if task == "FFUF-2":
            family = 0 if name.startswith("vhost_") else 1 if name.startswith("dns_") else 2 if not name.startswith("sl_") else 3
        else:
            family = 0 if name.startswith("dns_") else 1 if name.startswith("vhost_") else 2 if not name.startswith("sl_") else 3
        return (0 if name in chosen else 1, family, name)

    for key in keys:
        name = str(key or "").strip()
        if not name:
            continue
        path = _wordlist_rel_path(lists.get(name), name)
        prev = picked.get(path)
        if prev is None or rank(name) < rank(prev):
            picked[path] = name
    ordered = sorted(picked.values())
    learned = [k for k in ordered if k == "platform_learned"]
    rest = [k for k in ordered if k != "platform_learned"]
    return learned + rest


def validate_wordlists_edit(doc: dict[str, Any], patch: dict[str, Any], params: Params | None = None) -> dict[str, Any]:
    tasks = doc.get("tasks") or {}
    lists: dict[str, Any] = dict(doc.get("lists") or {})
    if params is not None:
        try:
            lists.update((wordlists_catalog(params).get("lists") or {}))
        except Exception:  # noqa: BLE001 -- SAVE still validates against the YAML registry
            pass
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
        clean[task] = unique_wordlist_keys_by_path(lists, [str(k) for k in keys], task=str(task), selected=set(str(k) for k in keys))
    return clean


def apply_wordlists_edit(params: Params, patch: dict[str, Any]) -> dict[str, Any]:
    from pipeline.textio import atomic_write_text

    path = params.root / "wordlists.yaml"
    doc = load_yaml_file(str(path))
    clean = validate_wordlists_edit(doc, patch, params)
    text = path.read_text(encoding="utf-8")
    for task, keys in clean.items():
        text = _patch_task_selection(text, task, keys, doc, params)
    atomic_write_text(path, text)
    return {"applied": clean}


def wordlists_catalog(params: Params) -> dict[str, Any]:
    """Curated registry + custom index + live SecLists filenames (original
    .txt names). Does not line-count multi-million lists on GET."""
    from pipeline.seclists_sync import slug_for
    from pipeline.wordlist_forge import seclists_host_root
    from pipeline.wordlists import WordlistRegistry
    from pipeline.custom_lists import ensure_learned_list

    try:
        ensure_learned_list(params)
    except Exception:  # noqa: BLE001 -- catalog still useful without learned file
        pass

    registry = WordlistRegistry(params)
    lists: dict[str, Any] = {}

    def _row(key: str, entry: dict[str, Any]) -> dict[str, Any]:
        rel = str(entry.get("path") or "").replace("\\", "/")
        return {
            **entry,
            "key": key,
            "name": Path(rel).name or key,
            "path": rel,
        }

    for key, entry in registry.lists.items():
        if isinstance(entry, dict):
            lists[str(key)] = _row(str(key), entry)
    seen_paths = {_wordlist_rel_path(entry, key) for key, entry in lists.items()}
    try:
        root = seclists_host_root(params)
    except Exception:  # noqa: BLE001 -- missing SecLists is a disclosed empty extra
        root = Path("/nonexistent")
    dns = root / "Discovery" / "DNS"
    if dns.is_dir():
        for path in sorted(dns.glob("*.txt")):
            if not path.is_file() or path.name.startswith("."):
                continue
            rel = path.relative_to(root)
            key = slug_for(rel)
            rel_s = str(rel).replace("\\", "/")
            path_id = rel_s.replace("\\", "/").lstrip("/").lower()
            if key in lists:
                lists[key]["name"] = path.name
                lists[key]["path"] = rel_s
                continue
            if path_id in seen_paths:
                continue
            seen_paths.add(path_id)
            lists[key] = {
                "key": key,
                "name": path.name,
                "path": rel_s,
                "shape": "hostname",
                "origin": "seclists",
            }
    doc = load_yaml_file(str(params.root / "wordlists.yaml")) or {}
    return {
        "schema_version": doc.get("schema_version"),
        "lists": lists,
        "tasks": doc.get("tasks") or {},
    }


_WL_KEY_RE = re.compile(r"^[A-Za-z0-9._-]{1,160}$")


def wordlist_preview(params: Params, key: str, n: int = 20) -> dict[str, Any]:
    """Random sample of n lines from a registered list. Seeks large files;
    never line-counts a multi-million list."""
    from pipeline.wordlist_forge import host_list_path
    from pipeline.wordlists import WordlistError, WordlistRegistry

    raw = str(key or "").strip()
    if not _WL_KEY_RE.match(raw):
        raise DashboardError("illegal wordlist key")
    n = 20
    catalog = wordlists_catalog(params).get("lists") or {}
    entry = catalog.get(raw)
    if not isinstance(entry, dict):
        raise DashboardError(f"unknown wordlist key {raw!r}")
    rel = str(entry.get("path") or "").replace("\\", "/").lstrip("/")
    path: Path | None = None
    try:
        registry = WordlistRegistry(params)
        if raw in registry.lists:
            path = host_list_path(params, registry, raw)
    except (WordlistError, KeyError, OSError):
        path = None
    if path is None or not path.is_file():
        from pipeline.wordlist_forge import seclists_host_root

        try:
            seclists = seclists_host_root(params)
        except Exception:  # noqa: BLE001
            seclists = Path("/nonexistent")
        for candidate in (params.root / rel, seclists / rel):
            if candidate.is_file():
                path = candidate
                break
    if path is None or not path.is_file():
        return {
            "key": raw,
            "name": entry.get("name") or raw,
            "path": rel,
            "samples": [],
            "count": 0,
            "reason": "file not on disk",
        }
    samples = _sample_wordlist_lines(path, n)
    return {
        "key": raw,
        "name": entry.get("name") or Path(rel).name or raw,
        "path": rel,
        "samples": samples,
        "count": len(samples),
    }


def _sample_wordlist_lines(path: Path, n: int) -> list[str]:
    try:
        size = path.stat().st_size
    except OSError:
        return []
    if size <= 0:
        return []

    def _clean(line: str) -> str | None:
        text = line.strip()
        if not text or text.startswith("#"):
            return None
        if len(text) > 180:
            text = text[:180]
        if any(ord(ch) > 127 for ch in text):
            return None
        return text

    if size < 400_000:
        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        lines = [c for ln in raw.splitlines() if (c := _clean(ln))]
        if len(lines) <= n:
            return lines
        return random.sample(lines, n)
    out: list[str] = []
    seen: set[str] = set()
    try:
        with path.open("rb") as fh:
            for _ in range(n * 8):
                if len(out) >= n:
                    break
                pos = random.randrange(0, max(size - 1, 1))
                fh.seek(pos)
                fh.readline()
                chunk = fh.readline()
                if not chunk:
                    continue
                line = _clean(chunk.decode("utf-8", "replace"))
                if line is None or line in seen:
                    continue
                seen.add(line)
                out.append(line)
    except OSError:
        return out
    return out


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
        if params is not None:
            try:
                for k in (wordlists_catalog(params).get("lists") or {}):
                    if k not in keys:
                        keys.append(k)
            except Exception:  # noqa: BLE001 -- live SecLists miss never blocks SAVE of curated keys
                pass
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

_FILTER_KEYS = (
    "q", "source", "tag", "alive", "run", "scope",
    "host", "ip", "ports", "length", "tech", "first_seen", "last_seen",
)
FILTER_KEYS = _FILTER_KEYS


def _blob(value: Any) -> str:
    if isinstance(value, list):
        return " ".join(str(x) for x in value if x).lower()
    if value is None:
        return ""
    return str(value).lower()


def _filter_haystack(row: dict[str, Any]) -> str:
    bits = [
        str(row.get("host") or ""),
        " ".join(str(x) for x in (row.get("ips") or ([row.get("ip")] if row.get("ip") else []))),
        " ".join(str(x) for x in (row.get("sources") or [])),
        " ".join(str(x) for x in (row.get("tags") or [])),
        " ".join(str(x) for x in (row.get("tech") or [])),
        str(row.get("module") or ""),
        str(row.get("open_ports_total") or ""),
        str(row.get("length") or ""),
        str(row.get("first_seen") or ""),
        str(row.get("last_seen") or ""),
    ]
    return " ".join(bits).lower()


def _text_match(row: dict[str, Any], needle: str, *keys: str) -> bool:
    blob = " ".join(_blob(row.get(k)) for k in keys)
    return needle in blob


def apply_filters(rows: list[dict[str, Any]], filters: dict[str, Any], scope_includes: list[str] | None = None,
                  scope_excludes: list[str] | None = None) -> list[dict[str, Any]]:
    """section 9.2-b GLOBAL RESULT FILTERS -- combinable per column."""
    out = rows
    q = str(filters.get("q") or "").strip().lower()
    if q:
        out = [r for r in out if q in _filter_haystack(r)]
    host = str(filters.get("host") or "").strip().lower()
    if host:
        out = [r for r in out if host in _blob(r.get("host"))]
    ip = str(filters.get("ip") or "").strip().lower()
    if ip:
        out = [r for r in out if _text_match(r, ip, "ips", "ip")]
    source = str(filters.get("source") or "").strip()
    if source:
        sl = source.lower()
        out = [r for r in out if any(sl in str(s).lower() for s in (r.get("sources") or []))]
    tag = str(filters.get("tag") or "").strip()
    if tag:
        tl = tag.lower()
        out = [r for r in out if any(tl in str(t).lower() for t in (r.get("tags") or []))]
    tech = str(filters.get("tech") or "").strip().lower()
    if tech:
        out = [r for r in out if tech in _blob(r.get("tech"))]
    length = str(filters.get("length") or "").strip().lower()
    if length:
        out = [r for r in out if length in str(r.get("length") if r.get("length") is not None else "").lower()]
    first_seen = str(filters.get("first_seen") or "").strip().lower()
    if first_seen:
        out = [r for r in out if first_seen in str(r.get("first_seen") or "").lower()]
    last_seen = str(filters.get("last_seen") or "").strip().lower()
    if last_seen:
        out = [r for r in out if last_seen in str(r.get("last_seen") or "").lower()]
    ports = str(filters.get("ports") or "").strip().lower()
    if ports in ("open", "yes", "true"):
        out = [r for r in out if int(r.get("open_ports_total") or 0) > 0]
    elif ports in ("none", "no", "false", "0"):
        out = [r for r in out if int(r.get("open_ports_total") or 0) <= 0]
    alive = str(filters.get("alive") or "").strip().lower()
    if alive in ("true", "false"):
        want = alive == "true"
        out = [r for r in out if (bool(r.get("alive")) or bool(r.get("ips") or [])) == want]
    run_sel = str(filters.get("run") or "").strip()
    if run_sel:
        out = [r for r in out if str(r.get("run") or "") == run_sel]
    scope = str(filters.get("scope") or "").strip().lower()
    if scope in ("in", "excluded"):
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
            "overlap_by_n_sources": overlap,             "uniqueness_pct": uniqueness}


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


# ----------------------------------------------------------- warehouse (b)

def _target_dir(params: Params, target: str) -> Path:
    from pipeline.factory import target_root

    return target_root(params, target)


def warehouse_status_view(params: Params, target: str) -> dict[str, Any]:
    from pipeline.warehouse import WarehouseError, ensure_ingested, status

    target_dir = _target_dir(params, target)
    try:
        ensure_ingested(params, target_dir, target)
        return status(params, target_dir, target)
    except WarehouseError as exc:
        raise DashboardError(str(exc)) from exc


def warehouse_runs_view(params: Params, target: str) -> dict[str, Any]:
    from pipeline.warehouse import WarehouseError, ensure_ingested, list_runs

    target_dir = _target_dir(params, target)
    try:
        ensure_ingested(params, target_dir, target)
        runs = list_runs(params, target_dir, target)
    except WarehouseError as exc:
        raise DashboardError(str(exc)) from exc
    return {"target": target, "runs": runs, "count": len(runs)}


def warehouse_diff_view(params: Params, target: str, from_ts: str, to_ts: str) -> dict[str, Any]:
    from pipeline.warehouse import WarehouseError, compare_runs, ensure_ingested, list_runs

    target_dir = _target_dir(params, target)
    try:
        ensure_ingested(params, target_dir, target)
        if not to_ts:
            runs = list_runs(params, target_dir, target)
            if not runs:
                return {"exists": False, "target": target, "reason": "no ingested runs"}
            to_ts = str(runs[-1]["timestamp"])
            from_ts = str(runs[-2]["timestamp"]) if len(runs) > 1 else ""
        return compare_runs(params, target_dir, target, from_ts or None, to_ts)
    except WarehouseError as exc:
        raise DashboardError(str(exc)) from exc


def warehouse_rebuild_view(params: Params, target: str) -> dict[str, Any]:
    from pipeline.warehouse import WarehouseError, rebuild_from_history

    target_dir = _target_dir(params, target)
    if not target_dir.is_dir():
        raise DashboardError(f"no recon data for {target}")
    try:
        return rebuild_from_history(params, target_dir, target)
    except WarehouseError as exc:
        raise DashboardError(str(exc)) from exc


_ASSETS_CACHE: dict[str, tuple[float, int, list[dict[str, Any]]]] = {}
_ASSETS_LOCK = threading.Lock()
_LIVE_ROWS_CACHE: dict[str, tuple[float, int, list[dict[str, Any]]]] = {}
_MERGED_ROWS_CACHE: dict[str, tuple[tuple, list[dict[str, Any]]]] = {}


def _assets_from_json(params: Params, target_dir: Path) -> list[dict[str, Any]]:
    path = target_dir / str(params.require("assets_relpath"))
    if not path.is_file():
        return []
    try:
        st = path.stat()
    except OSError:
        return []
    key = str(path)
    with _ASSETS_LOCK:
        hit = _ASSETS_CACHE.get(key)
        if hit and hit[0] == st.st_mtime and hit[1] == st.st_size:
            return hit[2]
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        return []
    rows = [r for r in (doc.get("assets") or []) if isinstance(r, dict)]
    with _ASSETS_LOCK:
        _ASSETS_CACHE[key] = (st.st_mtime, st.st_size, rows)
    return rows


def _live_fingerprint(target_dir: Path, assets_rel: str) -> tuple[float, int]:
    stamp = 0.0
    size = 0
    paths = [target_dir / assets_rel]
    dnsx = target_dir / "20_dns" / "dnsx"
    if dnsx.is_dir():
        paths.extend(dnsx.glob("brute_*.json"))
        data = dnsx / "data.json"
        if data.is_file():
            paths.append(data)
        paths.extend(dnsx.glob("wildcard-probe*.json"))
    for path in paths:
        try:
            st = path.stat()
        except OSError:
            continue
        stamp = max(stamp, st.st_mtime)
        size += int(st.st_size)
    return stamp, size


def _live_host_rows(params: Params, target_dir: Path) -> list[dict[str, Any]]:
    """RESULTS during a scan: hosts from dnsx NDJSON without writing warehouse.sqlite."""
    from pipeline.history import extract_live_classes

    assets_rel = str(params.require("assets_relpath"))
    stamp, size = _live_fingerprint(target_dir, assets_rel)
    key = str(target_dir)
    with _ASSETS_LOCK:
        hit = _LIVE_ROWS_CACHE.get(key)
        if hit and hit[0] == stamp and hit[1] == size:
            return hit[2]
    maps = extract_live_classes(params, target_dir)
    rows: list[dict[str, Any]] = []
    for host, payload in (maps.get("hosts") or {}).items():
        if not isinstance(payload, dict):
            continue
        row = dict(payload)
        row.setdefault("host", host)
        row.setdefault("ips", [])
        row.setdefault("alive", bool(row.get("ips")))
        row.setdefault("sources", ["dnsx"])
        rows.append(row)
    with _ASSETS_LOCK:
        _LIVE_ROWS_CACHE[key] = (stamp, size, rows)
    return rows


def _merge_result_rows(canonical: list[dict[str, Any]], live: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not live:
        return canonical
    if not canonical:
        return live
    by_host: dict[str, dict[str, Any]] = {}
    for row in live:
        host = str(row.get("host") or "")
        if host:
            by_host[host] = dict(row)
    for row in canonical:
        host = str(row.get("host") or "")
        if not host:
            continue
        if host in by_host:
            by_host[host] = {**by_host[host], **row}
        else:
            by_host[host] = dict(row)
    return list(by_host.values())


def results_rows_for(params: Params, target: str, run_stamp: str = "") -> list[dict[str, Any]]:
    """Latest assets plus in-progress dnsx hosts, or a warehouse snapshot when run= is set."""
    from pipeline.warehouse import facts_as_assets, ensure_ingested

    target_dir = _target_dir(params, target)
    if run_stamp:
        try:
            ensure_ingested(params, target_dir, target)
            rows = facts_as_assets(params, target_dir, target, run_stamp)
            if rows:
                from pipeline.history import drop_wildcard_host_rows

                return drop_wildcard_host_rows(params, target_dir, rows)
        except Exception:  # noqa: BLE001 -- fall back to latest canonical index
            pass
    assets_rel = str(params.require("assets_relpath"))
    try:
        ast = (target_dir / assets_rel).stat()
        afp: tuple[float, int] = (ast.st_mtime, ast.st_size)
    except OSError:
        afp = (0.0, 0)
    fingerprint = (afp, _live_fingerprint(target_dir, assets_rel))
    key = str(target_dir)
    with _ASSETS_LOCK:
        hit = _MERGED_ROWS_CACHE.get(key)
        if hit and hit[0] == fingerprint:
            return hit[1]
    canonical = _assets_from_json(params, target_dir)
    try:
        live = _live_host_rows(params, target_dir)
    except Exception:  # noqa: BLE001 -- RESULTS still shows assets.json
        live = []
    merged = _merge_result_rows(canonical, live)
    try:
        from pipeline.history import drop_wildcard_host_rows

        merged = drop_wildcard_host_rows(params, target_dir, merged)
    except Exception:  # noqa: BLE001 -- RESULTS still shows the merged index
        pass
    with _ASSETS_LOCK:
        _MERGED_ROWS_CACHE[key] = (fingerprint, merged)
    return merged


_MAX_TCP_PORT = 65535


def _port_entry(port: Any, ip: str, service: str = "", svc_meta: dict[str, str] | None = None) -> dict[str, Any] | None:
    if isinstance(port, dict):
        raw = port.get("port")
        proto = str(port.get("proto") or port.get("protocol") or "tcp").lower()
        state = str(port.get("state") or "open")
        svc = str(port.get("service") or port.get("product") or service or "")
    elif isinstance(port, int):
        raw, proto, state, svc = port, "tcp", "open", service
    else:
        return None
    try:
        num = int(raw)
    except (TypeError, ValueError):
        return None
    if num < 1 or num > _MAX_TCP_PORT:
        return None
    label = f"{num}/{proto}"
    if svc:
        label = f"{label} {svc}"
    meta = svc_meta or {}
    name = str(meta.get("name") or "")
    product = str(meta.get("product") or "")
    version = str(meta.get("version") or "")
    extrainfo = str(meta.get("extrainfo") or "")
    if isinstance(port, dict):
        name = name or str(port.get("name") or "")
        product = product or str(port.get("product") or "")
        version = version or str(port.get("version") or "")
        extrainfo = extrainfo or str(port.get("extrainfo") or "")
    if not name and svc and not product:
        name = svc
    # name/product/version kept as distinct fields so the UI can render a clean
    # human-readable detail (from nmap -sV); `service`/`label` stay for compat.
    return {
        "port": num,
        "proto": proto,
        "state": state,
        "service": svc,
        "name": name,
        "product": product,
        "version": version,
        "extrainfo": extrainfo,
        "ip": ip,
        "label": label,
    }


def _read_port_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        return {}
    return doc if isinstance(doc, dict) else {}


_PORTS_CACHE: dict[str, tuple[tuple, Any]] = {}


def _collect_open_ports(params: Params, target: str) -> tuple[dict[str, dict[tuple[str, int, str], dict[str, Any]]], dict[str, dict[tuple[str, int, str], dict[str, Any]]]]:
    """host -> {(port, proto): entry}, ip -> same. Sweep wins over light check.

    Cached by the (mtime,size) of the port JSON files: RESULTS polling re-joins
    ports on every tick, and the naabu-full data.json can be multi-MB.
    """
    by_host: dict[str, dict[tuple[str, int, str], dict[str, Any]]] = {}
    by_ip: dict[str, dict[tuple[str, int, str], dict[str, Any]]] = {}
    target_dir = _target_dir(params, target)
    services: dict[tuple[str, int, str], str] = {}
    svc_meta: dict[tuple[str, int, str], dict[str, str]] = {}

    port_rels: list[str] = []
    for param_key in ("portcheck_data_json", "portsweep_data_json"):
        try:
            port_rels.append(str(params.require(param_key)))
        except (KeyError, ValueError, TypeError):
            continue
    fp = []
    for rel in port_rels:
        try:
            st = (target_dir / rel).stat()
            fp.append((st.st_mtime, st.st_size))
        except OSError:
            fp.append((0.0, 0))
    fingerprint = tuple(fp)
    cache_key = str(target_dir)
    with _ASSETS_LOCK:
        hit = _PORTS_CACHE.get(cache_key)
        if hit and hit[0] == fingerprint:
            return hit[1]

    def _put(bucket: dict[str, dict[tuple[str, int, str], dict[str, Any]]], key: str, entry: dict[str, Any]) -> None:
        if not key:
            return
        slot = bucket.setdefault(key, {})
        # Key includes IP so two addresses on the same name keep distinct port rows
        # (80/tcp on 1.2.3.4 is not 80/tcp on 5.6.7.8).
        slot[(str(entry.get("ip") or ""), int(entry["port"]), str(entry["proto"]))] = entry

    for rel in port_rels:
        doc = _read_port_json(target_dir / rel)
        for svc in doc.get("services") or []:
            if not isinstance(svc, dict) or svc.get("port") is None:
                continue
            try:
                pnum = int(svc["port"])
            except (TypeError, ValueError):
                continue
            ip = str(svc.get("ip") or "")
            proto = str(svc.get("proto") or "tcp").lower()
            product = " ".join(x for x in (str(svc.get("product") or ""), str(svc.get("version") or "")) if x).strip()
            if ip:
                if product:
                    services[(ip, pnum, proto)] = product
                svc_meta[(ip, pnum, proto)] = {
                    "name": str(svc.get("name") or svc.get("service") or ""),
                    "product": str(svc.get("product") or ""),
                    "version": str(svc.get("version") or ""),
                    "extrainfo": str(svc.get("extrainfo") or ""),
                }
        rows = doc.get("scans") or doc.get("results") or []
        for scan in rows:
            if not isinstance(scan, dict):
                continue
            ip = str(scan.get("ip") or "")
            hosts = [str(h) for h in (scan.get("hosts") or []) if h]
            if scan.get("host") and not hosts:
                hosts = [str(scan["host"])]
            raw_ports = scan.get("ports") or []
            for port in raw_ports:
                svc_name = ""
                if isinstance(port, dict):
                    try:
                        pnum = int(port.get("port"))
                    except (TypeError, ValueError):
                        continue
                    proto = str(port.get("proto") or port.get("protocol") or "tcp").lower()
                    svc_name = services.get((ip, pnum, proto), "")
                entry = _port_entry(port, ip, svc_name, svc_meta.get((ip, pnum, proto)))
                if not entry:
                    continue
                _put(by_ip, ip, entry)
                for host in hosts:
                    _put(by_host, host.lower(), entry)
    result = (by_host, by_ip)
    with _ASSETS_LOCK:
        _PORTS_CACHE[cache_key] = (fingerprint, result)
    return result


def _row_ips(row: dict[str, Any]) -> list[str]:
    ips = [str(x) for x in (row.get("ips") or ([row.get("ip")] if row.get("ip") else [])) if x]
    return list(dict.fromkeys(ips))


def _merged_ports_for_host(
    by_host: dict[str, dict[tuple[str, int, str], dict[str, Any]]],
    by_ip: dict[str, dict[tuple[str, int, str], dict[str, Any]]],
    host: str,
    ips: list[str],
) -> list[dict[str, Any]]:
    merged: dict[tuple[str, int, str], dict[str, Any]] = {}
    merged.update(by_host.get(host.lower()) or {})
    for ip in ips:
        merged.update(by_ip.get(ip) or {})
    return sorted(
        merged.values(),
        key=lambda p: (str(p.get("ip") or ""), int(p["port"]), str(p["proto"])),
    )


def _ports_by_ip_counts(ports: list[dict[str, Any]], ips: list[str]) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for port in ports:
        ip = str(port.get("ip") or "")
        counts[ip] = counts.get(ip, 0) + 1
    ordered: list[str] = []
    for ip in ips:
        if ip and ip not in ordered:
            ordered.append(ip)
    for ip in counts:
        if ip not in ordered:
            ordered.append(ip)
    return [{"ip": ip, "count": int(counts.get(ip, 0))} for ip in ordered]


def _slim_port(port: dict[str, Any]) -> dict[str, Any]:
    return {
        "port": int(port["port"]),
        "proto": str(port.get("proto") or "tcp"),
        "ip": str(port.get("ip") or ""),
        "product": str(port.get("product") or ""),
        "version": str(port.get("version") or ""),
    }


def attach_open_ports(
    params: Params,
    target: str,
    rows: list[dict[str, Any]],
    *,
    include_ports: bool = False,
) -> list[dict[str, Any]]:
    """Join open ports onto each RESULTS host. List payload is counts per IP; full
    1–65535 port lists are loaded when the operator clicks an IP."""
    try:
        by_host, by_ip = _collect_open_ports(params, target)
    except Exception:  # noqa: BLE001 -- ports are additive, never fail RESULTS
        return rows
    out: list[dict[str, Any]] = []
    for row in rows:
        host = str(row.get("host") or "").lower()
        ips = _row_ips(row)
        ports = _merged_ports_for_host(by_host, by_ip, host, ips)
        total = len(ports)
        entry = {
            **row,
            "open_ports_total": total,
            "open_ports_by_ip": _ports_by_ip_counts(ports, ips),
            "open_ports_text": str(total) if total else "",
        }
        if include_ports:
            entry["open_ports"] = ports
        out.append(entry)
    return out


def ports_for_host(params: Params, target: str, host: str, ip: str | None = None) -> dict[str, Any]:
    """Full open-port list for one host, optionally one IP. Ports outside 1–65535 are omitted."""
    host_l = str(host or "").strip().lower()
    want_ip = str(ip or "").strip()
    try:
        by_host, by_ip = _collect_open_ports(params, target)
    except Exception:  # noqa: BLE001
        by_host, by_ip = {}, {}
    if want_ip:
        entries: dict[tuple[str, int, str], dict[str, Any]] = dict(by_ip.get(want_ip) or {})
        for key, item in (by_host.get(host_l) or {}).items():
            if str(item.get("ip") or "") == want_ip:
                entries[key] = item
        ports = sorted(entries.values(), key=lambda p: (int(p["port"]), str(p["proto"])))
        slim = [_slim_port(p) for p in ports]
        return {"host": host_l, "ip": want_ip, "count": len(slim), "ports": slim}
    extra_ips = []
    if host_l:
        extra_ips = list(dict.fromkeys(
            str(p.get("ip") or "") for p in (by_host.get(host_l) or {}).values() if p.get("ip")
        ))
    ports = _merged_ports_for_host(by_host, by_ip, host_l, extra_ips)
    return {
        "host": host_l,
        "ip": "",
        "count": len(ports),
        "ips": _ports_by_ip_counts(ports, extra_ips),
        "ports": [],
    }


def enrich_results_rows(params: Params, target: str, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    from pipeline.warehouse import enrich_assets

    target_dir = _target_dir(params, target)
    enriched = rows
    try:
        enriched = enrich_assets(params, target_dir, target, rows)
    except Exception:  # noqa: BLE001 -- timeline is additive, never fail the panel
        enriched = rows
    return attach_open_ports(params, target, enriched, include_ports=False)

