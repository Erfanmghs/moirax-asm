"""C5 IP ROTATION / PROXY POOL (operator directive: spread outgoing tool
traffic across several addresses so a single scanner IP never becomes the
bottleneck or the ban target).

Laws (never convention):
- POOL RESOLUTION: settings ``proxy_pool`` (comma-separated) wins over the
  legacy single ``proxy_url`` (kept for compatibility). Per-target profiles
  reach the pool through the C3 transient edit of the same settings key, so
  run time has exactly one source of truth.
- SCHEME LAW: every entry must be http://, https:// or socks5:// -- anything
  else is refused, never silently ignored.
- FAIL-FAST GATE (section 9.3 extended to pools): every entry must be
  reachable before the first module starts; the failing entry is named with
  its credentials MASKED.
- ROTATION: round-robin, one pool entry per module invocation inside a run;
  the assignment ledger (logs/proxy-rotation.json) records which entry each
  module used, and whether the tool actually has a proxy hook (tools without
  the ``when: proxy_url`` wiring run DIRECT and the ledger says so -- honesty
  law, no silent pretending).
- SECRETS: proxy credentials are never echoed; masked form is
  ``scheme://user:***@host:port``.
"""

from __future__ import annotations

import json
import re
import urllib.parse
from pathlib import Path
from typing import Any, Callable

from pipeline.params import Params
from pipeline.textio import atomic_write_text

ALLOWED_SCHEMES = ("http", "https", "socks5")

_LEDGER_REL = "logs/proxy-rotation.json"


def mask_proxy(url: str) -> str:
    """Masked rendering of a proxy URL: credentials never echoed."""
    raw = str(url or "").strip()
    try:
        parsed = urllib.parse.urlparse(raw)
    except ValueError:
        return "***"
    if not parsed.scheme or not parsed.netloc:
        return "***"
    netloc = parsed.netloc
    if "@" in netloc:
        userinfo, _, hostport = netloc.rpartition("@")
        user = userinfo.split(":", 1)[0]
        netloc = f"{user}:***@{hostport}"
    return f"{parsed.scheme}://{netloc}"


def parse_pool(raw: str | list[str] | None) -> list[str]:
    """Split a comma-separated pool string (or list), dedupe preserving order,
    enforce the scheme law. Raises ValueError naming the bad entry."""
    if raw is None:
        return []
    parts: list[str] = []
    if isinstance(raw, list):
        parts = [str(item).strip() for item in raw]
    else:
        parts = [part.strip() for part in str(raw).split(",")]
    pool: list[str] = []
    for part in parts:
        if not part:
            continue
        scheme = urllib.parse.urlparse(part).scheme.lower()
        if scheme not in ALLOWED_SCHEMES:
            raise ValueError(
                f"proxy entry {mask_proxy(part)!r} has scheme {scheme or '(none)'!r}; "
                f"allowed: {', '.join(ALLOWED_SCHEMES)}"
            )
        if part not in pool:
            pool.append(part)
    return pool


def validate_pool_value(value: Any) -> list[str]:
    """Dashboard/profile validation: a proxy_pool must be a string (comma
    separated) or a list of strings; returns the parsed pool or raises."""
    if value is None:
        return []
    if isinstance(value, list) and not all(isinstance(item, str) for item in value):
        raise ValueError("proxy_pool must be a string or a list of strings")
    if not isinstance(value, (str, list)):
        raise ValueError("proxy_pool must be a string or a list of strings")
    return parse_pool(value)


def spec_has_proxy_hook(spec_raw: dict[str, Any]) -> bool:
    """True when the tool declares the ``when: proxy_url`` optional-argv hook
    (i.e. the underlying binary actually accepts a proxy flag)."""
    for block in spec_raw.get("optional_argv") or []:
        if isinstance(block, dict) and str(block.get("when") or "") == "proxy_url":
            return True
    return False


class ProxyPool:
    """Round-robin pool with a per-run assignment ledger."""

    def __init__(self, entries: list[str]) -> None:
        if not entries:
            raise ValueError("proxy pool is empty")
        self.entries: list[str] = list(entries)
        self._cursor = 0
        self.rows: list[dict[str, Any]] = []

    def assign(self, tool: str, module: str, proxied: bool) -> tuple[str, int]:
        """Next entry (round-robin); records one ledger row. Returns (url, index).
        index -1 means the module runs DIRECT (tool has no proxy hook)."""
        if not proxied:
            self.rows.append({"tool": tool, "module": module, "proxy_index": -1,
                              "proxy": "direct (tool has no proxy hook)"})
            return "", -1
        idx = self._cursor % len(self.entries)
        self._cursor += 1
        self.rows.append({"tool": tool, "module": module, "proxy_index": idx,
                          "proxy": mask_proxy(self.entries[idx])})
        return self.entries[idx], idx

    def summary_lines(self) -> list[str]:
        out: list[str] = []
        for row in self.rows:
            out.append(f"proxy-rotation: module={row['module']} tool={row['tool']} "
                       f"proxy={row['proxy']}")
        return out


class ProxyAssigner:
    """Engine-facing facade: resolve the pool, gate it, feed the adapter."""

    def __init__(self, pool: ProxyPool, checker: Callable[[str], tuple[bool, str]] | None = None) -> None:
        self.pool = pool
        self._checker = checker

    @classmethod
    def from_params(cls, params: Params,
                    checker: Callable[[str], tuple[bool, str]] | None = None) -> "ProxyAssigner | None":
        """Resolution chain (most specific wins): transient per-target profile
        edit / operator tools.yaml value first, then the dashboard global
        setting. When no pool is configured anywhere, None -> the legacy
        single proxy_url gate path stays exactly as it was."""
        pool_raw = str(params.settings.get("proxy_pool") or "").strip()
        if not pool_raw:
            from pipeline.notify import load_dashboard_config
            cfg = load_dashboard_config(params)
            pool_raw = str(cfg.get("proxy_pool") or "").strip()
        if not pool_raw:
            return None
        entries = parse_pool(pool_raw)
        if not entries:
            return None
        return cls(ProxyPool(entries), checker=checker)

    def gate(self) -> tuple[bool, str]:
        """Section 9.3 law extended to pools: every entry reachable or FAIL FAST.
        The checker's reason is sanitized: the raw entry (with credentials)
        must never surface anywhere, even if the checker echoes it."""
        if self._checker is None:
            from dashboard.service import check_proxy_reachable
            self._checker = check_proxy_reachable
        for idx, entry in enumerate(self.pool.entries, start=1):
            ok, reason = self._checker(entry)
            if not ok:
                safe = reason.replace(entry, mask_proxy(entry))
                try:
                    parsed = urllib.parse.urlparse(entry)
                    if "@" in parsed.netloc:
                        userinfo = parsed.netloc.rpartition("@")[0]
                        safe = safe.replace(userinfo, "***")
                except ValueError:
                    pass
                return False, (f"proxy pool entry #{idx} ({mask_proxy(entry)}) "
                               f"is unreachable: {safe}")
        return True, (f"proxy pool active: {len(self.pool.entries)} entries "
                      f"({', '.join(mask_proxy(e) for e in self.pool.entries)})")

    def hook_values(self, tool: str, module: str, spec_raw: dict[str, Any]) -> dict[str, str]:
        """Values fragment for the adapter: only sets proxy_url when the tool
        has the proxy hook; otherwise the module is ledgered DIRECT."""
        url, _idx = self.pool.assign(tool, module, spec_has_proxy_hook(spec_raw))
        return {"proxy_url": url} if url else {}

    def write_ledger(self, target_dir: Path) -> None:
        """Never-fail ledger write (honesty law: rotation is always visible)."""
        try:
            path = target_dir / _LEDGER_REL
            path.parent.mkdir(parents=True, exist_ok=True)
            doc = {
                "pool": [mask_proxy(entry) for entry in self.pool.entries],
                "assignments": self.pool.rows,
            }
            atomic_write_text(path, json.dumps(doc, indent=2) + "\n")
        except OSError:
            pass


def gate_pool_or_legacy(params: Params,
                        checker: Callable[[str], tuple[bool, str]] | None = None,
                        legacy_gate: Callable[[Params], tuple[bool, str]] | None = None,
                        ) -> tuple[bool, str, "ProxyAssigner | None"]:
    """One gate for engine + dashboard pre-flight: a configured POOL is
    health-checked entry by entry (fail-fast naming the bad one, credentials
    masked) and returned as the assigner; no pool -> the legacy single
    proxy_url law runs untouched (section 9.3, zero regression)."""
    if str(params.settings.get("proxy_pool") or "").strip():
        assigner = ProxyAssigner.from_params(params, checker=checker)
        if assigner is not None:
            ok, reason = assigner.gate()
            return ok, reason, assigner
    if str((params.settings.get("proxy_pool") or "").strip()) == "":
        from pipeline.notify import load_dashboard_config
        cfg = load_dashboard_config(params)
        if str(cfg.get("proxy_pool") or "").strip():
            assigner = ProxyAssigner.from_params(params, checker=checker)
            if assigner is not None:
                ok, reason = assigner.gate()
                return ok, reason, assigner
    legacy = legacy_gate
    if legacy is None:
        from dashboard.service import proxy_gate as legacy
    ok, reason = legacy(params)
    return ok, reason, None
