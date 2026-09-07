"""Telegram notifications -- section 4.5 run summary, section 4.6 watchtower instant alerts,
section 4.7 digest threshold + alert filters + self-monitoring.
Credentials: dashboard/config.json (section 9.2-e) first, .env fallback; unset -> skip silently.

D-protocol (operator directive): the OPERATOR sets ONLY their Telegram user id.
The bot token is platform provisioning (.env TELEGRAM_BOT_TOKEN, set once).
Chat-id resolution precedence (highest wins):
  1. per-target profile notifications.telegram_chat  (C3 registry targets.yaml)
  2. dashboard config telegram.chat_id               (global default)
  3. .env TELEGRAM_CHAT_ID                           (deployment fallback)
A profile with notifications.telegram_enabled=false silences that target
outright (explicit per-system opt-out beats every global default).
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable

from pipeline.jsonio import read_json
from pipeline.params import Params

SendFn = Callable[[str], None]

# Telegram chat/user id law: numeric user/chat ids (optionally negative for
# groups) or @channel names. Injection-safe: no whitespace, no metacharacters.
TELEGRAM_CHAT_RE = re.compile(r"^-?\d{2,20}$|^@[A-Za-z0-9_]{4,64}$")

# Sentinel source returned by resolve_chat_id when the target profile
# explicitly disables notifications for that system.
DISABLED_BY_PROFILE = "disabled_by_profile"


def load_target_notifications(params: Params, target: str | None) -> dict[str, Any]:
    """C3 profile notifications block for one target (empty = inherit globals)."""
    if not target:
        return {}
    try:
        from pipeline.target_profiles import get_profile

        settings = (get_profile(params, target) or {}).get("settings") or {}
        notif = settings.get("notifications") or {}
        return notif if isinstance(notif, dict) else {}
    except Exception:  # noqa: BLE001 -- a broken profile never breaks notifications
        return {}


def resolve_chat_id(params: Params, target: str | None = None) -> tuple[str, str]:
    """Telegram user/chat id resolution with per-target override support.
    Returns (chat_id, source); source in {target_profile, dashboard_config,
    env, disabled_by_profile, ''} -- never echoes the id into logs."""
    notif = load_target_notifications(params, target)
    if notif.get("telegram_enabled") is False:
        return "", DISABLED_BY_PROFILE
    chat = str(notif.get("telegram_chat") or "").strip()
    if chat:
        return chat, "target_profile"
    config = load_dashboard_config(params)
    tg = config.get("telegram") or {}
    chat = str(tg.get("chat_id") or "").strip()
    if chat:
        return chat, "dashboard_config"
    load_dotenv(params.root, str(params.require("env_filename")))
    chat = os.environ.get(str(params.require("telegram_chat_id_env")), "").strip()
    return chat, ("env" if chat else "")


def resolve_bot_token(params: Params) -> tuple[str, str]:
    """Bot token is PLATFORM provisioning, not operator UX: dashboard config
    first (masked on read), .env TELEGRAM_BOT_TOKEN fallback."""
    config = load_dashboard_config(params)
    tg = config.get("telegram") or {}
    token = str(tg.get("bot_token") or "").strip()
    if token:
        return token, "dashboard_config"
    load_dotenv(params.root, str(params.require("env_filename")))
    token = os.environ.get(str(params.require("telegram_bot_token_env")), "").strip()
    return token, ("env" if token else "")


def send_test_notification(params: Params, target: str | None = None,
                           sender: SendFn | None = None) -> dict[str, Any]:
    """Dashboard 'SEND TEST' button (D-protocol): one harmless message proving
    the wiring for the resolved receiver. Never raises; the ledger explains
    every skip reason (never-silent law). The chat id is never echoed back."""
    chat_id, source = resolve_chat_id(params, target)
    if source == DISABLED_BY_PROFILE:
        return {"sent": False, "reason": "notifications disabled for this target profile", "source": source}
    if not chat_id:
        return {"sent": False,
                "reason": "no Telegram user id configured (Settings or the target profile)",
                "source": ""}
    token, _token_source = resolve_bot_token(params)
    if not token:
        return {"sent": False,
                "reason": "bot token not provisioned (TELEGRAM_BOT_TOKEN in .env)",
                "source": source}
    scope = f"target={target}" if target else "global default"
    text = f"TEST: notification channel verified ({scope})"
    ok = _deliver(params, text, sender, chat_id=chat_id)
    return {"sent": ok, "reason": "" if ok else "delivery failed (network/API)", "source": source}

# section 4.6 instant-alert classes: NEW SUBDOMAIN (hosts) + NEWLY OPENED PORT (ports).
# Every other diff class (services / tech / removed / closed ports) -> dashboard
# diff view only, never Telegram (section 4.6, section 8 PORT-SWEEP watchtower wiring).
ALERT_CLASSES = ("hosts", "ports")

# Default section 4.7 alert-filter rules when the dashboard has not configured any:
# both section 4.6 classes are alert-worthy, no extra condition.
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
    """section 9.2-e dashboard Settings persistence (gitignored, never committed)."""
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
    """Legacy global resolution (section 4.5): dashboard config first, .env
    fallback. D-protocol run paths use resolve_chat_id + resolve_bot_token
    so per-target overrides are honored."""
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


def _deliver(params: Params, text: str, sender: SendFn | None,
             chat_id: str | None = None, target: str | None = None) -> bool:
    """Send one message; unset credentials -> skip silently (section 4.5).
    D-protocol: when chat_id is None it resolves through the per-target chain
    (target profile > dashboard config > .env); an explicit target-disabled
    profile mutes delivery entirely."""
    if chat_id is None:
        chat_id, source = resolve_chat_id(params, target)
        if source == DISABLED_BY_PROFILE:
            # D-protocol: per-system opt-out beats EVERY delivery path,
            # including injected senders in tests/fixtures (law, not detail).
            return False
    if sender is not None:
        sender(text)
        return True
    token, _token_source = resolve_bot_token(params)
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


def send_status(params: Params, status: str, module: str, reason: str,
                sender: SendFn | None = None, target: str | None = None) -> bool:
    """section 4.7 self-monitoring explicit status alert: status + reason + module."""
    text = f"{status}: module={module} reason={reason}"
    return _deliver(params, text, sender, target=target)


def send_run_summary(
    params: Params,
    target: str,
    status: str,
    counts: dict[str, int],
    duration_sec: float,
    report_path: str,
    sender: SendFn | None = None,
) -> bool:
    """section 4.5 end-of-run summary: target, final status, per-module asset counts,
    duration, report path. completed|partial|failed. D-protocol: delivered to
    the RECEIVER RESOLVED FOR THIS TARGET (per-target override honored)."""
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
    return _deliver(params, text, sender, target=target)


def alert_worthy(
    rules: list[dict[str, Any]],
    cls: str,
    asset: dict[str, Any],
    prev_index: dict[str, set[str]],
) -> bool:
    """section 4.7 alert-filter rules -- decide whether one new asset is alert-worthy.

    Rule schema (dashboard-editable, section 9.2-e):
      {"class": "hosts"|"ports", "enabled": bool, "require_new_ip": bool}
    require_new_ip: host must resolve to an IP never seen in the previous run
    (the "new subdomain resolving to a NEW IP" example in section 4.7).
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
    """IPs already known to the PREVIOUS run -- mined from removed/changed rows
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
        # changed rows carry {"before","after"} -- mine both sides
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
    target: str | None = None,
) -> dict[str, Any]:
    """section 4.6 watchtower + section 4.7 digest threshold, driven by diff.json (section 6.6).

    NEW SUBDOMAIN (added hosts) and NEWLY OPENED PORT (added ports) are the
    instant-alert classes; closed ports / removed hosts are never alerted;
    other classes surface in the dashboard diff view only.
    Digest: instant per asset while alert-worthy count < threshold (default 10,
    dashboard-editable); at/above -> ONE grouped digest message.
    """
    config = load_dashboard_config(params)
    notif = load_target_notifications(params, target)
    # D-protocol: a per-target digest_threshold / watchtower toggle wins over
    # the global dashboard config (closed allow-list keys, C3).
    rules_cfg = notif.get("watchtower_enabled")
    if rules_cfg is None:
        rules_cfg = config.get("alert_rules")
    rules = rules_cfg if isinstance(rules_cfg, list) else DEFAULT_ALERT_RULES
    if notif.get("watchtower_enabled") is False:
        rules = []
    threshold = notif.get("digest_threshold")
    if not isinstance(threshold, int) or isinstance(threshold, bool) or threshold <= 0:
        threshold = config.get("digest_threshold")
    if not isinstance(threshold, int) or isinstance(threshold, bool) or threshold <= 0:
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
    if not rules:
        ledger["skipped_reason"] = "watchtower disabled (target profile)"
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
        ledger["delivered"] = _deliver(params, "\n".join(lines), sender, target=target)
        return ledger

    for cls, label in (("hosts", "NEW SUBDOMAIN"), ("ports", "NEW PORT")):
        for asset in alertable[cls]:
            text = f"{label}: {_asset_label(cls, asset)} (run={run_ts})"
            if _deliver(params, text, sender, target=target):
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
    """section 4.5 + section 4.7 run-end fan-out. Never raises -- notification failure must
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
                params, status.upper(), failing_module or "-", reason or "-", sender, target=target
            )
        diff_rel = str(params.require("diff_filename"))
        diff_path = target_dir / diff_rel
        if diff_path.is_file():
            ledger["alerts"] = evaluate_diff_alerts(params, read_json(diff_path), sender, target=target)
    except Exception as exc:  # noqa: BLE001 -- notification must never fail a run
        ledger["error"] = str(exc)
    return ledger
