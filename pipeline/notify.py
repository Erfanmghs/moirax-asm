"""Telegram notifications — §4.5 run summary, §4.6 watchtower instant alerts,
§4.7 digest threshold + alert filters + self-monitoring.
Credentials: dashboard/config.json (§9.2-e) first, .env fallback; unset → skip silently.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable

from pipeline.jsonio import read_json
from pipeline.params import Params

SendFn = Callable[[str], None]

# §4.6 instant-alert classes: NEW SUBDOMAIN (hosts) + NEWLY OPENED PORT (ports).
# Every other diff class (services / tech / removed / closed ports) → dashboard
# diff view only, never Telegram (§4.6, §8 PORT-SWEEP watchtower wiring).
ALERT_CLASSES = ("hosts", "ports")

# Default §4.7 alert-filter rules when the dashboard has not configured any:
# both §4.6 classes are alert-worthy, no extra condition.
DEFAULT_ALERT_RULES: list[dict[str, Any]] = [
    {"class": "hosts", "enabled": True, "require_new_ip": False},
    {"class": "ports", "enabled": True, "require_new_ip": False},
]

DIGEST_LIST_CAP = 20


def load_dotenv(root: Path, filename: str) -> None:
    path = root / filename
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def load_dashboard_config(params: Params) -> dict[str, Any]:
    """§9.2-e dashboard Settings persistence (gitignored, never committed)."""
    rel = str(params.require("dashboard_config_relpath"))
    path = params.root / rel
    if not path.is_file():
        return {}
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        return {}
    return doc if isinstance(doc, dict) else {}


def resolve_credentials(params: Params) -> tuple[str, str]:
    """§4.5 credentials configured in the dashboard first, .env fallback."""
    config = load_dashboard_config(params)
    tg = config.get("telegram") or {}
    token = str(tg.get("bot_token") or "").strip()
    chat_id = str(tg.get("chat_id") or "").strip()
    if token and chat_id:
        return token, chat_id
    load_dotenv(params.root, str(params.require("env_filename")))
    token_key = str(params.require("telegram_bot_token_env"))
    chat_key = str(params.require("telegram_chat_id_env"))
    token = os.environ.get(token_key, "").strip()
    chat_id = os.environ.get(chat_key, "").strip()
    return token, chat_id


def _deliver(params: Params, text: str, sender: SendFn | None) -> bool:
    """Send one message; unset credentials → skip silently (§4.5)."""
    if sender is not None:
        sender(text)
        return True
    token, chat_id = resolve_credentials(params)
    if not token or not chat_id:
        return False
    timeout = int(params.require("telegram_timeout_sec"))
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = urllib.parse.urlencode({"chat_id": chat_id, "text": text}).encode("utf-8")
    req = urllib.request.Request(url, data=payload, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp.read()
        return True
    except (urllib.error.URLError, TimeoutError, OSError):
        return False


def send_status(params: Params, status: str, module: str, reason: str, sender: SendFn | None = None) -> bool:
    """§4.7 self-monitoring explicit status alert: status + reason + module."""
    text = f"{status}: module={module} reason={reason}"
    return _deliver(params, text, sender)


def send_run_summary(
    params: Params,
    target: str,
    status: str,
    counts: dict[str, int],
    duration_sec: float,
    report_path: str,
    sender: SendFn | None = None,
) -> bool:
    """§4.5 end-of-run summary: target, final status, per-module asset counts,
    duration, report path. completed|partial|failed."""
    per_module = " ".join(f"{key}={val}" for key, val in counts.items()) or "modules=0"
    minutes = int(duration_sec // 60)
    seconds = int(duration_sec % 60)
    text = (
        f"RUN {status}\n"
        f"target: {target}\n"
        f"assets: {per_module}\n"
        f"duration: {minutes}m{seconds:02d}s\n"
        f"report: {report_path}"
    )
    return _deliver(params, text, sender)


def alert_worthy(
    rules: list[dict[str, Any]],
    cls: str,
    asset: dict[str, Any],
    prev_index: dict[str, set[str]],
) -> bool:
    """§4.7 alert-filter rules — decide whether one new asset is alert-worthy.

    Rule schema (dashboard-editable, §9.2-e):
      {"class": "hosts"|"ports", "enabled": bool, "require_new_ip": bool}
    require_new_ip: host must resolve to an IP never seen in the previous run
    (the "new subdomain resolving to a NEW IP" example in §4.7).
    """
    for rule in rules:
        if not isinstance(rule, dict) or str(rule.get("class")) != cls:
            continue
        if not rule.get("enabled", True):
            return False
        if rule.get("require_new_ip"):
            seen = prev_index.get("ips", set())
            candidates: list[str] = []
            if asset.get("ip"):
                candidates.append(str(asset["ip"]))
            for ip in asset.get("ips") or []:
                candidates.append(str(ip))
            return any(ip in seen for ip in candidates) is False and bool(candidates)
        return True
    return False


def _prev_index_from_diff(diff_doc: dict[str, Any]) -> dict[str, set[str]]:
    """IPs already known to the PREVIOUS run — mined from removed/changed rows
    (added rows are new by definition; their IPs are the NEW ones)."""
    seen: set[str] = set()
    for bucket in ("removed", "changed"):
        for row in (diff_doc.get(bucket) or {}).get("hosts") or []:
            if not isinstance(row, dict):
                continue
            if row.get("ip"):
                seen.add(str(row["ip"]))
            for ip in row.get("ips") or []:
                seen.add(str(ip))
        # changed rows carry {"before","after"} — mine both sides
        if bucket == "changed":
            for row in (diff_doc.get("changed") or {}).get("hosts") or []:
                for side in ("before", "after"):
                    item = row.get(side) if isinstance(row, dict) else None
                    if isinstance(item, dict):
                        if item.get("ip"):
                            seen.add(str(item["ip"]))
                        for ip in item.get("ips") or []:
                            seen.add(str(ip))
    return {"ips": seen}


def evaluate_diff_alerts(
    params: Params,
    diff_doc: dict[str, Any],
    sender: SendFn | None = None,
) -> dict[str, Any]:
    """§4.6 watchtower + §4.7 digest threshold, driven by diff.json (§6.6).

    NEW SUBDOMAIN (added hosts) and NEWLY OPENED PORT (added ports) are the
    instant-alert classes; closed ports / removed hosts are never alerted;
    other classes surface in the dashboard diff view only.
    Digest: instant per asset while alert-worthy count < threshold (default 10,
    dashboard-editable); at/above → ONE grouped digest message.
    """
    config = load_dashboard_config(params)
    rules = config.get("alert_rules") if isinstance(config.get("alert_rules"), list) else DEFAULT_ALERT_RULES
    threshold = config.get("digest_threshold")
    if not isinstance(threshold, int) or threshold <= 0:
        threshold = int(params.require("digest_threshold"))

    prev_index = _prev_index_from_diff(diff_doc)
    alertable: dict[str, list[dict[str, Any]]] = {"hosts": [], "ports": []}
    suppressed = 0
    non_alert_class = 0
    added = diff_doc.get("added") or {}
    for cls in ALERT_CLASSES:
        for asset in added.get(cls) or []:
            if isinstance(asset, dict) and alert_worthy(rules, cls, asset, prev_index):
                alertable[cls].append(asset)
            else:
                suppressed += 1
    for cls, rows in added.items():
        if cls not in ALERT_CLASSES:
            non_alert_class += len([r for r in rows or [] if isinstance(r, dict)])

    total = len(alertable["hosts"]) + len(alertable["ports"])
    ledger: dict[str, Any] = {
        "alertable": total,
        "suppressed_by_rules": suppressed,
        "non_alert_class_assets": non_alert_class,
        "digest_threshold": threshold,
        "digest_sent": False,
        "instant_sent": 0,
        "delivered": False,
    }
    if total == 0:
        ledger["skipped_reason"] = "no_alertable_assets" if added else "no_added_assets"
        return ledger

    run_ts = str(diff_doc.get("to_run") or "unknown")
    if total >= threshold:
        lines = [f"DIGEST: {total} new findings (threshold={threshold}) run={run_ts}"]
        listed = 0
        for cls, label in (("hosts", "NEW SUBDOMAIN"), ("ports", "NEW PORT")):
            for asset in alertable[cls]:
                if listed >= DIGEST_LIST_CAP:
                    lines.append(f"... and {total - listed} more")
                    break
                lines.append(f"{label}: {_asset_label(cls, asset)}")
                listed += 1
        ledger["digest_sent"] = True
        ledger["delivered"] = _deliver(params, "\n".join(lines), sender)
        return ledger

    for cls, label in (("hosts", "NEW SUBDOMAIN"), ("ports", "NEW PORT")):
        for asset in alertable[cls]:
            text = f"{label}: {_asset_label(cls, asset)} (run={run_ts})"
            if _deliver(params, text, sender):
                ledger["instant_sent"] += 1
                ledger["delivered"] = True
    return ledger


def _asset_label(cls: str, asset: dict[str, Any]) -> str:
    if cls == "hosts":
        parts = [str(asset.get("host") or "?")]
        if asset.get("ip"):
            parts.append(f"ip={asset['ip']}")
        elif asset.get("ips"):
            parts.append(f"ip={asset['ips'][0]}")
        return " ".join(parts)
    return f"{asset.get('host') or asset.get('ip') or '?'}:{asset.get('port')}/{asset.get('proto', '')}"


def run_end_notifications(
    params: Params,
    target_dir: Path,
    target: str,
    status: str,
    reason: str | None,
    failing_module: str | None,
    counts: dict[str, int],
    duration_sec: float,
    sender: SendFn | None = None,
) -> dict[str, Any]:
    """§4.5 + §4.7 run-end fan-out. Never raises — notification failure must
    never flip a pipeline verdict; every outcome is printed (never-silent)."""
    ledger: dict[str, Any] = {"summary_sent": False, "status_alert_sent": False, "alerts": None}
    completed = str(params.require("run_status_completed"))
    partial_status = str(params.require("run_status_partial"))
    failed = str(params.require("run_status_failed"))
    anomaly = str(params.require("run_status_anomaly"))
    stopped = str(params.require("run_status_stopped"))

    try:
        if status in (completed, partial_status, failed):
            report_rel = str(params.require("report_dirname"))
            ledger["summary_sent"] = send_run_summary(
                params,
                target,
                status,
                counts,
                duration_sec,
                str(target_dir / report_rel),
                sender,
            )
        if status in (failed, anomaly, stopped):
            ledger["status_alert_sent"] = send_status(
                params, status.upper(), failing_module or "-", reason or "-", sender
            )
        diff_rel = str(params.require("diff_filename"))
        diff_path = target_dir / diff_rel
        if diff_path.is_file():
            ledger["alerts"] = evaluate_diff_alerts(params, read_json(diff_path), sender)
    except Exception as exc:  # noqa: BLE001 — notification must never fail a run
        ledger["error"] = str(exc)
    return ledger
