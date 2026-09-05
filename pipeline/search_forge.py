"""SEARCH-FORGE — anti-block search infrastructure (master spec §8 PSV-0).

The pipeline NEVER raw-scrapes Google/Bing HTML from pipeline IPs. All search
traffic flows through the registered ENGINE POOL (`search_engines.yaml`) of
API-routed providers. Keys come from §9.2-d/.env; multiple keys per engine
(comma-separated env value) -> per-request key rotation with per-key quota
tracking.

BLOCK HANDLING (PSV-0):
- HTTP 429/403 or a captcha signal -> engine marked COOLDOWN (exponential
  backoff + jitter), traffic instantly re-routed to the next healthy engine.
- Engine error-rate > isolate_error_ratio over isolate_window_sec -> ISOLATED
  (per-engine mirror of the §11.4 breaker).
- Cooldown engines re-probe after the backoff window expires.
- Per-dork TTL cache -> scheduled re-runs never re-burn quota on unchanged
  dorks.

All HTTP goes through the tools.yaml adapter (curl-fetch spec, containers) —
the forge itself performs zero network I/O in-process.
"""

from __future__ import annotations

import random
import re
import shlex
from typing import Any, Callable
from urllib.parse import quote, unquote, urlparse

from pipeline.params import Params
from pipeline.yaml_util import load_yaml_file

_STATUS_RE = re.compile(r"^HTTP/\S+\s+(\d{3})\b", re.MULTILINE)
_CAPTCHA_MARKERS = ("captcha", "unusual traffic", "are you a robot")
_UDDG_RE = re.compile(r"uddg=([^&\"'\s>]+)")
_URL_RE = re.compile(r"https?://[^\s\"'<>\\)]+", re.IGNORECASE)
_XML_URL_RE = re.compile(r"<url>\s*(?:<!\[CDATA\[)?([^<\]]+)(?:\]\]>)?\s*</url>", re.IGNORECASE)


def load_registry(params: Params) -> dict[str, Any]:
    rel = str(params.require("search_engines_registry"))
    data = load_yaml_file(rel)
    if not isinstance(data, dict):
        raise ValueError(f"{rel} must be a mapping")
    return data


def load_dorks_registry(params: Params) -> dict[str, Any]:
    rel = str(params.require("dorks_registry"))
    data = load_yaml_file(rel)
    if not isinstance(data, dict):
        raise ValueError(f"{rel} must be a mapping")
    return data


def env_keys(params: Params, env_name: str) -> list[str]:
    """Read a provider key from the §9.2-d .env file. Comma-separated values
    are a key POOL (per-request rotation). Values are never logged."""
    import os
    from pathlib import Path

    env_file = params.root / str(params.require("env_filename"))
    if env_file.is_file():
        for raw in env_file.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            if k.strip() == env_name:
                return [part.strip() for part in v.strip().strip('"').split(",") if part.strip()]
    value = os.environ.get(env_name, "").strip()
    if value:
        return [part.strip() for part in value.split(",") if part.strip()]
    return []


class SearchForge:
    """Engine pool state machine: ACTIVE -> COOLDOWN/ISOLATED -> re-probe."""

    def __init__(
        self,
        params: Params,
        registry: dict[str, Any],
        clock: Any,
        note: Callable[[str], None],
    ) -> None:
        self.params = params
        self.clock = clock
        self._note = note
        settings = registry.get("settings") or {}
        self.cooldown_base = float(settings.get("cooldown_backoff_base_sec") or 2)
        self.cooldown_max = float(settings.get("cooldown_backoff_max_sec") or 300)
        self.isolate_window = float(settings.get("isolate_window_sec") or 60)
        self.isolate_ratio = float(settings.get("isolate_error_ratio") or 0.2)
        self.ttl = float(settings.get("dork_cache_ttl_sec") or 3600)
        self.user_agent = str(settings.get("http_user_agent") or "recon-pipeline/1.0")
        self.engines: list[dict[str, Any]] = []
        for name, cfg in (registry.get("engines") or {}).items():
            if not isinstance(cfg, dict) or not cfg.get("enabled", True):
                continue
            keys = [""] if cfg.get("keyless") else env_keys(params, str(cfg.get("key_env") or ""))
            if not cfg.get("keyless") and not keys:
                note(
                    f"search-forge: engine={name} disabled — no key in .env "
                    f"({cfg.get('key_env')}); disclosed, never silent"
                )
                continue
            if cfg.get("user_env") and not env_keys(params, str(cfg["user_env"])):
                note(
                    f"search-forge: engine={name} disabled — no user id in .env "
                    f"({cfg['user_env']}); disclosed, never silent"
                )
                continue
            cx = ""
            if cfg.get("cx_env"):
                cx_values = env_keys(params, str(cfg["cx_env"]))
                cx = cx_values[0] if cx_values else ""
            self.engines.append(
                {
                    "name": str(name),
                    "cfg": cfg,
                    "keys": keys,
                    "cx": cx,
                    "status": "active",
                    "cooldown_until": 0.0,
                    "cooldown_level": 0,
                    "events": [],  # (ts, ok) for the ISOLATED window
                    "last_request": 0.0,
                    "key_idx": 0,
                    "requests": 0,
                }
            )
        self.engines.sort(key=lambda e: (int(e["cfg"].get("priority") or 100), e["name"]))
        self.cache: dict[str, tuple[float, list[str]]] = {}
        self.stats = {"engines_used": 0, "cooldown": 0, "isolated": 0}
        self.rerouted = 0

    # -- pool ------------------------------------------------------------
    def healthy(self) -> list[dict[str, Any]]:
        now = self.clock.time()
        out = []
        for engine in self.engines:
            if engine["status"] == "cooldown" and now >= engine["cooldown_until"]:
                engine["status"] = "active"
                self._note(f"search-forge: engine={engine['name']} cooldown expired — re-probed")
            if engine["status"] == "active":
                out.append(engine)
        return out

    def pick(self) -> dict[str, Any] | None:
        healthy = self.healthy()
        return healthy[0] if healthy else None

    def next_key(self, engine: dict[str, Any]) -> str:
        keys = engine["keys"]
        if not keys:
            return ""
        key = keys[engine["key_idx"] % len(keys)]
        engine["key_idx"] += 1
        return key

    def record(self, engine: dict[str, Any], ok: bool, status_code: int | None) -> None:
        now = self.clock.time()
        engine["requests"] += 1
        if engine["requests"] == 1:
            self.stats["engines_used"] += 1
        engine["events"] = [e for e in engine["events"] if now - e[0] <= self.isolate_window]
        engine["events"].append((now, ok))
        if not ok:
            blocked = status_code in (429, 403)
            if blocked:
                level = int(engine["cooldown_level"]) + 1
                engine["cooldown_level"] = level
                backoff = min(self.cooldown_base * (2 ** (level - 1)), self.cooldown_max)
                backoff *= 1.0 + random.uniform(0, 0.25)  # jitter
                engine["status"] = "cooldown"
                engine["cooldown_until"] = now + backoff
                self.stats["cooldown"] += 1
                self._note(
                    f"search-forge: engine={engine['name']} status={status_code} -> "
                    f"COOLDOWN backoff={backoff:.1f}s (blocked response)"
                )
            window = [e for e in engine["events"]]
            if len(window) >= 2:
                ratio = sum(1 for _, good in window if not good) / len(window)
                if ratio > self.isolate_ratio and engine["status"] != "isolated":
                    engine["status"] = "isolated"
                    self.stats["isolated"] += 1
                    self._note(
                        f"search-forge: engine={engine['name']} error-ratio "
                        f"{ratio:.2f} > {self.isolate_ratio} over {self.isolate_window:.0f}s "
                        f"-> ISOLATED"
                    )

    def pace(self, engine: dict[str, Any]) -> None:
        rate = float(engine["cfg"].get("rate_per_min") or 60)
        min_interval = 60.0 / max(rate, 0.001)
        wait = engine["last_request"] + min_interval - self.clock.time()
        if wait > 0:
            self.clock.sleep(wait)
        engine["last_request"] = self.clock.time()

    # -- cache -----------------------------------------------------------
    def cache_get(self, dork: str) -> list[str] | None:
        hit = self.cache.get(dork)
        if hit is None:
            return None
        expires, hosts = hit
        if self.clock.time() > expires:
            del self.cache[dork]
            return None
        return hosts

    def cache_put(self, dork: str, hosts: list[str]) -> None:
        self.cache[dork] = (self.clock.time() + self.ttl, list(hosts))

    # -- request assembly --------------------------------------------------
    def fetch_cmd(self, engine: dict[str, Any], dork: str) -> tuple[str, str]:
        cfg = engine["cfg"]
        key = self.next_key(engine)
        encoded = quote(dork, safe="")
        json_escaped = dork.replace("\\", "\\\\").replace('"', '\\"')
        values = {"key": key, "cx": engine.get("cx", ""), "user": "", "dork_encoded": encoded, "dork_json": json_escaped}
        if cfg.get("user_env"):
            users = env_keys(self.params, str(cfg["user_env"]))
            values["user"] = users[0] if users else ""
        method = str(cfg.get("method") or "GET").upper()
        args = ["curl", "-sS", "-D", "-", "--max-time", "60", "-A", self.user_agent]
        headers = [str(h).format(**values) for h in (cfg.get("headers") or [])]
        for header in headers:
            args.extend(["-H", header])
        if method == "POST":
            body = str(cfg.get("query_body") or "").format(dork_encoded=encoded, dork_json=json_escaped, target=dork)
            args.extend(["--data", body])
        else:
            query = str(cfg.get("query") or "").format(**values)
            url = str(cfg.get("endpoint") or "")
            url = url + ("&" if "?" in url else "?") + query if query else url
            args.append(url)
        return " ".join(shlex.quote(a) for a in args), key


def extract_http_status(stdout: str) -> int | None:
    match = _STATUS_RE.search(stdout or "")
    return int(match.group(1)) if match else None


def split_headers_body(stdout: str) -> tuple[str, str]:
    for sep in ("\r\n\r\n", "\n\n"):
        idx = stdout.find(sep)
        if idx != -1:
            return stdout[:idx], stdout[idx + len(sep):]
    return stdout, ""


def hosts_from_engine_body(kind: str, body: str) -> list[str]:
    """Engine-kind aware hostname extraction; every parser falls back to URL
    harvesting so candidates are never lost to a format drift."""
    hosts: list[str] = []
    if kind == "html":
        for token in _UDDG_RE.findall(body):
            hosts.extend(_host_of(unquote(token)))
    elif kind == "json":
        hosts.extend(_hosts_from_json(_minimal_json_links(body)))
    elif kind == "xml":
        for url in _XML_URL_RE.findall(body):
            hosts.extend(_host_of(url))
    if not hosts:
        for url in _URL_RE.findall(body):
            hosts.extend(_host_of(url))
        for token in _UDDG_RE.findall(body):
            hosts.extend(_host_of(unquote(token)))
    seen: set[str] = set()
    ordered: list[str] = []
    for host in hosts:
        if host and host not in seen:
            seen.add(host)
            ordered.append(host)
    return ordered


def _hosts_from_json(links: list[str]) -> list[str]:
    out: list[str] = []
    for link in links:
        out.extend(_host_of(link))
    return out


def _minimal_json_links(body: str) -> list[str]:
    """Pull link-ish string values out of a JSON body without engine-specific
    schemas: any "link"/"url" value plus bare https URLs (regex below)."""
    import json

    links: list[str] = []
    try:
        payload = json.loads(body)
    except (ValueError, TypeError):
        return links

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key in ("link", "url", "href") and isinstance(value, str):
                    links.append(value)
                else:
                    walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(payload)
    return links


def _host_of(value: str) -> list[str]:
    if not value or "://" not in value:
        return []
    try:
        host = (urlparse(value).hostname or "").lower().rstrip(".")
    except ValueError:
        return []
    return [host] if host else []
