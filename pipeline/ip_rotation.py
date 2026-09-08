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
- ROTATION (per-request law, C5 v2): round-robin with one pool entry PER
  ATTEMPT (the first try and every retry each take the next entry), not one
  per module invocation; the assignment ledger (logs/proxy-rotation.json)
  records which entry each attempt used, and whether the tool actually has a
  proxy hook (tools without the ``when: proxy_url`` wiring run DIRECT and the
  ledger says so once -- honesty law, no silent pretending).
- IP HEALTH TELEMETRY (C5 v2): every proxied attempt records its outcome
  (exit code) per pool entry; entries with >= ``unhealthy_after`` consecutive
  failures are SKIPPED while at least one healthy entry remains; when ALL
  entries are unhealthy the plain round-robin continues (never stall, never
  raise). Telemetry persists per target at logs/proxy-health.json, keyed by
  MASKED urls only, events capped (500), corrupt state ignored + rewritten
  (never-fail law, same class as selftune); telemetry never flips a verdict.
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
_HEALTH_REL = "logs/proxy-health.json"


def _utc_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat(timespec="seconds")


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
    """Health-aware round-robin pool with a per-run assignment ledger."""

    MAX_EVENTS = 500  # telemetry ring: oldest events dropped, file never grows unbounded

    def __init__(self, entries: list[str], unhealthy_after: int = 3) -> None:
        if not entries:
            raise ValueError("proxy pool is empty")
        self.entries: list[str] = list(entries)
        self._cursor = 0
        self.rows: list[dict[str, Any]] = []
        self.unhealthy_after = max(1, int(unhealthy_after))
        # per-index health stats: ok / fail / consecutive_fail / last_outcome
        self.health: dict[int, dict[str, Any]] = {}
        self.health_events: list[dict[str, Any]] = []
        self._health_dir: Path | None = None  # set by load_health (persistence law)

    def assign(self, tool: str, module: str, proxied: bool,
               attempt: int | None = None) -> tuple[str, int]:
        """Next entry (health-aware round-robin); records one ledger row.
        Returns (url, index). index -1 means the module runs DIRECT (tool has
        no proxy hook). ``attempt`` is ledgered when given (per-request law)."""
        if not proxied:
            row: dict[str, Any] = {"tool": tool, "module": module, "proxy_index": -1,
                                   "proxy": "direct (tool has no proxy hook)"}
            if attempt is not None:
                row["attempt"] = attempt
            self.rows.append(row)
            return "", -1
        idx, skipped, note = self._pick()
        row = {"tool": tool, "module": module, "proxy_index": idx,
               "proxy": mask_proxy(self.entries[idx])}
        if skipped:
            row["health_skipped"] = skipped
        if note:
            row["health_note"] = note
        if attempt is not None:
            row["attempt"] = attempt
        self.rows.append(row)
        return self.entries[idx], idx

    def _pick(self) -> tuple[int, list[int], str]:
        """Health-aware pick: scanning from the cursor, unhealthy entries
        (consecutive_fail >= unhealthy_after) are skipped while a healthy one
        remains; when ALL are unhealthy the plain round-robin continues."""
        total = len(self.entries)

        def _unhealthy(i: int) -> bool:
            return int(self.health.get(i, {}).get("consecutive_fail", 0)) >= self.unhealthy_after

        healthy = [i for i in range(total) if not _unhealthy(i)]
        if len(healthy) == total:
            idx = self._cursor % total
            self._cursor = idx + 1
            return idx, [], ""
        order = [(self._cursor + k) % total for k in range(total)]
        if healthy:
            skipped: list[int] = []
            for i in order:
                if i in healthy:
                    self._cursor = i + 1
                    return i, skipped, ""
                skipped.append(i)
        idx = self._cursor % total
        self._cursor = idx + 1
        return idx, [], "all pool entries unhealthy - round-robin continues (never stall)"

    def record_outcome(self, idx: int, ok: bool, duration_sec: float, tool: str,
                       module: str = "", attempt: int | None = None) -> None:
        """Record one attempt outcome per pool entry (health telemetry).
        idx -1 (DIRECT) is not proxy health -- ignored. Never raises: telemetry
        must never flip a verdict (same law class as the selftune hooks)."""
        if idx is None or idx < 0 or idx >= len(self.entries):
            return
        try:
            stats = self.health.setdefault(idx, {"ok": 0, "fail": 0, "consecutive_fail": 0})
            if ok:
                stats["ok"] = int(stats.get("ok", 0)) + 1
                stats["consecutive_fail"] = 0
            else:
                stats["fail"] = int(stats.get("fail", 0)) + 1
                stats["consecutive_fail"] = int(stats.get("consecutive_fail", 0)) + 1
            stats["last_outcome"] = "ok" if ok else "fail"
            stats["last_tool"] = str(tool)
            stats["updated_at"] = _utc_now()
            self.health_events.append({
                "proxy": mask_proxy(self.entries[idx]), "tool": str(tool),
                "module": str(module), "attempt": attempt, "ok": bool(ok),
                "duration_sec": round(float(duration_sec), 3), "ts": _utc_now(),
            })
            del self.health_events[:-self.MAX_EVENTS]
            self._flush_health()
        except Exception:
            pass

    def _flush_health(self) -> None:
        """Masked, capped persistence (caller guards; never raises here)."""
        if self._health_dir is None:
            return
        path = self._health_dir / _HEALTH_REL
        path.parent.mkdir(parents=True, exist_ok=True)
        doc = {
            "unhealthy_after": self.unhealthy_after,
            "entries": {mask_proxy(self.entries[i]): stats
                        for i, stats in sorted(self.health.items())},
            "events": list(self.health_events),
        }
        atomic_write_text(path, json.dumps(doc, indent=2) + "\n")

    def health_lines(self) -> list[str]:
        out: list[str] = []
        for i, stats in sorted(self.health.items()):
            out.append(
                f"proxy-health: proxy={mask_proxy(self.entries[i])} "
                f"ok={stats.get('ok', 0)} fail={stats.get('fail', 0)} "
                f"consecutive_fail={stats.get('consecutive_fail', 0)} "
                f"last={stats.get('last_outcome', '-')}"
            )
        return out

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
        """Compat facade: the attempt-1 fragment (first assignment)."""
        frag, _idx = self.hook_values_for_attempt(tool, module, spec_raw, attempt=1)
        return frag

    def hook_values_for_attempt(self, tool: str, module: str, spec_raw: dict[str, Any],
                                attempt: int) -> tuple[dict[str, str], int]:
        """PER-REQUEST LAW: one fragment + pool index PER attempt. Only sets
        proxy_url when the tool has the proxy hook; otherwise the module is
        ledgered DIRECT once and the fragment stays empty."""
        proxied = spec_has_proxy_hook(spec_raw)
        url, idx = self.pool.assign(tool, module, proxied, attempt=attempt)
        return ({"proxy_url": url} if url else {}), idx

    def record_outcome(self, idx: int, ok: bool, duration_sec: float, tool: str,
                       module: str = "", attempt: int | None = None) -> None:
        """Adapter-facing telemetry hook (delegates to the pool)."""
        self.pool.record_outcome(idx, ok, duration_sec, tool, module=module, attempt=attempt)

    def load_health(self, target_dir: Path) -> None:
        """Seed per-entry health from THIS target's previous runs (masked keys
        only -- credentials are never persisted). Unknown entries are ignored;
        corrupt/missing state starts fresh (never-fail law)."""
        self.pool._health_dir = Path(target_dir)
        path = Path(target_dir) / _HEALTH_REL
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
            by_mask = {mask_proxy(entry): i for i, entry in enumerate(self.pool.entries)}
            for key, stats in (doc.get("entries") or {}).items():
                idx = by_mask.get(str(key))
                if idx is None or not isinstance(stats, dict):
                    continue
                self.pool.health[idx] = {
                    "ok": int(stats.get("ok", 0)),
                    "fail": int(stats.get("fail", 0)),
                    "consecutive_fail": int(stats.get("consecutive_fail", 0)),
                    "last_outcome": str(stats.get("last_outcome", "-")),
                    "last_tool": str(stats.get("last_tool", "")),
                    "updated_at": str(stats.get("updated_at", "")),
                }
        except (OSError, ValueError, TypeError):
            pass  # corrupt state ignored; rewritten on the next flush

    def write_health(self, target_dir: Path) -> None:
        """Never-fail flush of per-IP outcome telemetry (masked, capped)."""
        try:
            self.pool._health_dir = Path(target_dir)
            self.pool._flush_health()
        except OSError:
            pass

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
