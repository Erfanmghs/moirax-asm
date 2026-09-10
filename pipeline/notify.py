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

from pipeline.history import FACT_CLASSES
from pipeline.jsonio import read_json
from pipeline.params import Params

SendFn = Callable[[str], None]

# Telegram receiver law: numeric user/chat ids (optionally negative for
# groups) OR usernames with or without the leading @ (operator directive:
# "if the user's handle is jackjohns, messages go to jackjohns").
# Injection-safe: no whitespace, no metacharacters.
TELEGRAM_CHAT_RE = re.compile(r"^-?\d{2,20}$|^@?[A-Za-z0-9_]{4,64}$")
_NUMERIC_RECEIVER_RE = re.compile(r"^-?\d+$")

# Sentinel source returned by resolve_chat_id when the target profile
# explicitly disables notifications for that system.
DISABLED_BY_PROFILE = "disabled_by_profile"

# Process-lifetime knowledge of which bot tokens Telegram REJECTED (401).
# A rejected token is skipped on every later attempt; the next pool entry
# (the replacement token) takes over automatically. Never persisted, never
# echoed.
_REJECTED_TOKENS: set[str] = set()


def normalize_receiver(raw: str) -> str:
    """Operator UX law: a bare handle like jackjohns becomes @jackjohns;
    @handle stays @handle; numeric chat ids stay numeric. Returns '' for
    anything the receiver law refuses."""
    s = str(raw or "").strip()
    if not TELEGRAM_CHAT_RE.match(s):
        return ""
    if _NUMERIC_RECEIVER_RE.match(s):
        return s
    return s if s.startswith("@") else "@" + s


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
    """Telegram receiver resolution with per-target override support.
    Accepts a username (jackjohns / @jackjohns) or a numeric chat id at every
    layer. A learned username -> numeric chat id map (telegram.receiver_map in
    dashboard config, filled automatically from getUpdates) is consulted so
    personal-account usernames deliver without any manual id lookup.
    Returns (chat_id, source); source in {target_profile, dashboard_config,
    env, disabled_by_profile, ''} -- never echoes the receiver into logs.
    Network-free by law: learning happens only in the send path."""
    notif = load_target_notifications(params, target)
    if notif.get("telegram_enabled") is False:
        return "", DISABLED_BY_PROFILE
    chat = str(notif.get("telegram_chat") or "").strip()
    source = "target_profile"
    if not chat:
        config = load_dashboard_config(params)
        tg = config.get("telegram") or {}
        chat = str(tg.get("chat_id") or "").strip()
        source = "dashboard_config"
    if not chat:
        load_dotenv(params.root, str(params.require("env_filename")))
        chat = os.environ.get(str(params.require("telegram_chat_id_env")), "").strip()
        source = "env"
    chat = normalize_receiver(chat)
    if not chat:
        return "", ""
    if chat.startswith("@"):
        mapped = current_receiver_map(params).get(chat[1:].lower())
        if mapped:
            return mapped, source
    return chat, source


def resolve_bot_token(params: Params) -> tuple[str, str]:
    """Compat wrapper: first token of the pool. See resolve_bot_token_pool."""
    pool = resolve_bot_token_pool(params)
    if not pool:
        return "", ""
    return pool[0], ("dashboard_config" if load_dashboard_config(params).get("telegram", {}).get("bot_token") else "env")


def resolve_bot_token_pool(params: Params) -> list[str]:
    """Bot token POOL (platform provisioning, not operator UX): dashboard
    config token first, then every comma-separated TELEGRAM_BOT_TOKEN entry
    in .env as automatic backups. When a token goes invalid, the send path
    rotates to the next entry by itself (operator directive: the tool must
    replace a broken token with its replacement without human help)."""
    pool: list[str] = []
    config = load_dashboard_config(params)
    tg = config.get("telegram") or {}
    token = str(tg.get("bot_token") or "").strip()
    if token and not token.startswith("****"):
        pool.append(token)
    load_dotenv(params.root, str(params.require("env_filename")))
    raw = os.environ.get(str(params.require("telegram_bot_token_env")), "")
    for part in raw.split(","):
        part = part.strip()
        if part and part not in pool:
            pool.append(part)
    return pool


# --------------------------------------------------------- username learning

def current_receiver_map(params: Params) -> dict[str, str]:
    """Persisted username -> numeric chat id map (dashboard config
    telegram.receiver_map). Learned automatically from getUpdates."""
    tg = (load_dashboard_config(params).get("telegram") or {})
    raw = tg.get("receiver_map") or {}
    return {str(k).strip().lstrip("@").lower(): str(v).strip()
            for k, v in raw.items() if isinstance(k, str) and isinstance(v, (str, int))}


def _persist_receiver_map(params: Params, merged: dict[str, str]) -> None:
    """Atomic write of the receiver map; best-effort, never raises."""
    path = params.root / str(params.require("dashboard_config_relpath"))
    doc: dict[str, Any] = {}
    if path.is_file():
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, ValueError):
            doc = {}
    if not isinstance(doc, dict):
        doc = {}
    tg = doc.get("telegram") if isinstance(doc.get("telegram"), dict) else {}
    tg = {**tg, "receiver_map": merged}
    doc["telegram"] = tg
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(doc, indent=2), encoding="utf-8")
        tmp.replace(path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    except OSError:
        pass


def learn_receiver_map(params: Params) -> dict[str, str]:
    """One getUpdates round-trip: for every account that has pressed START on
    the bot, learn username -> numeric chat id and persist it. This is how a
    bare handle (jackjohns) delivers to the right person without any manual
    id lookup. Best-effort: on any failure the current persisted map is
    returned unchanged. Tokens are never echoed."""
    learned: dict[str, str] = {}
    last_update = 0
    for token in resolve_bot_token_pool(params):
        if token in _REJECTED_TOKENS:
            continue
        timeout = int(params.require("telegram_timeout_sec"))
        url = f"https://api.telegram.org/bot{token}/getUpdates"
        try:
            with urllib.request.urlopen(urllib.request.Request(url), timeout=timeout) as resp:
                doc = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError, ValueError):
            continue
        for upd in doc.get("result") or []:
            if not isinstance(upd, dict):
                continue
            if isinstance(upd.get("update_id"), int):
                last_update = max(last_update, upd["update_id"])
            msg = upd.get("message") or upd.get("channel_post") or {}
            chat = msg.get("chat") if isinstance(msg, dict) else None
            if not isinstance(chat, dict):
                continue
            uname = str(chat.get("username") or "").strip().lstrip("@").lower()
            cid = str(chat.get("id") or "").strip()
            if uname and cid:
                learned[uname] = cid
        if doc.get("result") is not None:
            break
    if learned:
        merged = {**current_receiver_map(params), **learned}
        _persist_receiver_map(params, merged)
        if last_update:
            # confirm consumption so the pending queue does not grow unbounded
            for token in resolve_bot_token_pool(params):
                if token in _REJECTED_TOKENS:
                    continue
                confirm_url = (f"https://api.telegram.org/bot{token}/getUpdates"
                               f"?offset={last_update + 1}")
                try:
                    with urllib.request.urlopen(urllib.request.Request(confirm_url), timeout=5) as resp:
                        resp.read()
                except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError):
                    pass
                break
    return {**current_receiver_map(params), **learned}


# ------------------------------------------------------------- send machinery

def _telegram_post(params: Params, token: str, method: str,
                   payload: dict[str, str]) -> tuple[int, str]:
    """One Bot API call. Returns (http_code, description); code 0 means a
    network-level failure. The description comes from Telegram itself and
    never contains the token."""
    timeout = int(params.require("telegram_timeout_sec"))
    url = f"https://api.telegram.org/bot{token}/{method}"
    data = urllib.parse.urlencode(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
        try:
            desc = str(json.loads(body).get("description") or "")
        except ValueError:
            desc = ""
        return 200, desc
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read().decode("utf-8", "replace")
            desc = str(json.loads(body).get("description") or "")
        except (ValueError, OSError):
            desc = ""
        return exc.code, desc[:120]
    except (urllib.error.URLError, TimeoutError, OSError):
        return 0, "telegram unreachable (network)"


def _send_with_pool(params: Params, chat_id: str, text: str) -> tuple[bool, str]:
    """Deliver one message through the token pool. Invalid (401-rejected)
    tokens are skipped and the NEXT pool entry -- the replacement token --
    takes over automatically in the same send. Returns (ok, human detail);
    the detail names token indexes, never token values."""
    pool = resolve_bot_token_pool(params)
    if not pool:
        return False, "no bot token configured"
    notes: list[str] = []
    detail = ""
    for idx, token in enumerate(pool, start=1):
        if token in _REJECTED_TOKENS:
            notes.append(f"token #{idx} skipped (known invalid)")
            continue
        code, desc = _telegram_post(params, token, "sendMessage",
                                    {"chat_id": chat_id, "text": text})
        if code == 200:
            if notes:
                notes.append(f"delivered with token #{idx}")
            return True, "; ".join(notes)
        if code == 401:
            _REJECTED_TOKENS.add(token)
            notes.append(f"token #{idx} rejected as invalid -- rotated to the replacement")
            continue
        if code == 0:
            detail = "telegram unreachable (network)"
            break
        detail = f"telegram refused (HTTP {code})" + (f": {desc}" if desc else "")
        break
    if notes or detail:
        return False, "; ".join(notes) + (f" | {detail}" if detail else "")
    return False, "all bot tokens rejected as invalid"


def _deliver_username_aware(params: Params, chat_id: str, text: str) -> tuple[bool, str]:
    """Username-shaped receivers get one learning round-trip before and one
    after a failed direct attempt: personal accounts that pressed START on
    the bot are delivered via their learned numeric id; public channel and
    group handles deliver directly."""
    if chat_id.startswith("@"):
        name = chat_id[1:].lower()
        mapped = current_receiver_map(params).get(name)
        if not mapped:
            mapped = learn_receiver_map(params).get(name)
        if mapped:
            ok, _detail = _send_with_pool(params, mapped, text)
            if ok:
                return True, ""
    return _send_with_pool(params, chat_id, text)


def send_test_notification(params: Params, target: str | None = None,
                           sender: SendFn | None = None) -> dict[str, Any]:
    """Dashboard 'SEND TEST' button: one harmless message proving the wiring
    for the resolved receiver. Never raises; the result explains every skip
    with a human next-step HINT (user-friendly UI law). Receivers and tokens
    are never echoed."""
    chat_id, source = resolve_chat_id(params, target)
    if source == DISABLED_BY_PROFILE:
        return {"sent": False,
                "reason": "notifications are disabled for this target",
                "hint": "Re-enable Telegram notifications for this target on the TARGETS page.",
                "source": source}
    if not chat_id:
        return {"sent": False,
                "reason": "no Telegram username or id configured yet",
                "hint": "Type your Telegram username (e.g. @jackjohns) or your numeric id in Settings -- or per target on the TARGETS page -- and press SEND TEST again.",
                "source": ""}
    scope = f"target={target}" if target else "global default"
    text = f"TEST: notification channel verified ({scope})"
    if not resolve_bot_token_pool(params):
        return {"sent": False,
                "reason": "no bot token is provisioned on the platform",
                "hint": "In Telegram, open @BotFather, send /newbot, and paste the token it gives you into .env as TELEGRAM_BOT_TOKEN. Extra tokens separated by commas act as automatic backups.",
                "source": source}
    if sender is not None:
        sender(text)
        return {"sent": True, "reason": "", "hint": "", "source": source}
    ok, detail = _deliver_username_aware(params, chat_id, text)
    hint = ""
    if not ok:
        low = detail.lower()
        if "401" in low or "invalid" in low:
            hint = ("Every configured bot token was rejected. The platform already "
                    "rotated through all backups -- paste a fresh token from @BotFather "
                    "(replacing the broken one) and press SEND TEST again.")
        elif "chat not found" in low:
            hint = ("Open your bot inside Telegram and press START once; the platform "
                    "learns your chat automatically and the next SEND TEST arrives. "
                    "Public channel or group handles (@teamname) work directly once "
                    "the bot is a member.")
        elif "network" in low:
            hint = ("The platform could not reach Telegram. Check this machine's "
                    "internet connection or proxy settings, then try again.")
        elif "429" in low:
            hint = "Telegram is rate-limiting this bot. Wait a moment and press SEND TEST again."
    return {"sent": ok, "reason": detail, "hint": hint, "source": source}

# Operator law: every diff.json change (added / removed / changed) on every
# fact class is Telegram-visible. Dashboard alert_rules may DISABLE a class;
# a class with no matching rule is still alerted so nothing is silently dropped.
# First-run baseline (no previous snapshot) is not a change -- run summary only.
ALERT_CLASSES = FACT_CLASSES
DIFF_SIDES = ("added", "removed", "changed")

DEFAULT_ALERT_RULES: list[dict[str, Any]] = [
    {
        "class": cls,
        "enabled": True,
        "require_new_ip": False,
        "sides": list(DIFF_SIDES),
    }
    for cls in FACT_CLASSES
]

DIGEST_LIST_CAP = 20
TELEGRAM_TEXT_CAP = 3900

_EVENT_LABELS: dict[tuple[str, str], str] = {
    ("added", "hosts"): "NEW SUBDOMAIN",
    ("removed", "hosts"): "REMOVED SUBDOMAIN",
    ("changed", "hosts"): "CHANGED HOST",
    ("added", "ports"): "NEW PORT",
    ("removed", "ports"): "CLOSED PORT",
    ("changed", "ports"): "CHANGED PORT",
    ("added", "vhosts"): "NEW VHOST",
    ("removed", "vhosts"): "REMOVED VHOST",
    ("changed", "vhosts"): "CHANGED VHOST",
    ("added", "services"): "NEW SERVICE",
    ("removed", "services"): "REMOVED SERVICE",
    ("changed", "services"): "CHANGED SERVICE",
    ("added", "passive_ips"): "NEW PASSIVE IP",
    ("removed", "passive_ips"): "REMOVED PASSIVE IP",
    ("changed", "passive_ips"): "CHANGED PASSIVE IP",
}


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
    if not chat_id or not resolve_bot_token_pool(params):
        return False
    ok, _detail = _deliver_username_aware(params, chat_id, text)
    return ok


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
    side: str = "added",
) -> bool:
    """section 4.7 alert-filter rules -- decide whether one diff row is alert-worthy.

    Rule schema (dashboard-editable, section 9.2-e):
      {"class": <fact class>, "enabled": bool, "require_new_ip": bool,
       "sides": ["added"|"removed"|"changed", ...] optional}
    require_new_ip: added host must resolve to an IP never seen in the previous run.
    sides: when present, only those change kinds alert; omit = all sides.
    A class with no matching rule still alerts (nothing silently dropped).
    """
    body = _row_body(asset, side)
    for rule in rules:
        if not isinstance(rule, dict) or str(rule.get("class")) != cls:
            continue
        if not rule.get("enabled", True):
            return False
        sides = rule.get("sides")
        if isinstance(sides, list):
            if not sides:
                return False
            allowed = {str(s).strip().lower() for s in sides if str(s).strip()}
            if side not in allowed:
                return False
        if rule.get("require_new_ip") and side == "added" and cls == "hosts":
            seen = prev_index.get("ips", set())
            candidates: list[str] = []
            if body.get("ip"):
                candidates.append(str(body["ip"]))
            for ip in body.get("ips") or []:
                candidates.append(str(ip))
            return any(ip in seen for ip in candidates) is False and bool(candidates)
        return True
    return True


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


def _row_body(asset: dict[str, Any], side: str) -> dict[str, Any]:
    if side == "changed":
        after = asset.get("after")
        if isinstance(after, dict):
            return after
    return asset


def _event_label(side: str, cls: str) -> str:
    return _EVENT_LABELS.get((side, cls), f"{side.upper()} {cls.upper()}")


def _iter_diff_rows(diff_doc: dict[str, Any]):
    for side in DIFF_SIDES:
        bucket = diff_doc.get(side) or {}
        if not isinstance(bucket, dict):
            continue
        extra = [c for c in bucket if c not in FACT_CLASSES]
        for cls in list(FACT_CLASSES) + extra:
            for asset in bucket.get(cls) or []:
                if isinstance(asset, dict):
                    yield side, str(cls), asset


def _diff_has_rows(diff_doc: dict[str, Any]) -> bool:
    for _side, _cls, _asset in _iter_diff_rows(diff_doc):
        return True
    return False


def evaluate_diff_alerts(
    params: Params,
    diff_doc: dict[str, Any],
    sender: SendFn | None = None,
    target: str | None = None,
) -> dict[str, Any]:
    """Watchtower over the full diff.json (added / removed / changed, every class).

    Digest: instant per row while alert-worthy count < threshold (default 10);
    at/above -> grouped digest message(s). Every alertable row is listed;
    overflow is split across continuation messages, never dropped.
    First-run baseline is skipped (not a change vs a previous run).
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
    events: list[tuple[str, str, dict[str, Any]]] = []
    suppressed = 0
    for side, cls, asset in _iter_diff_rows(diff_doc):
        if alert_worthy(rules, cls, asset, prev_index, side=side):
            events.append((side, cls, asset))
        else:
            suppressed += 1

    total = len(events)
    ledger: dict[str, Any] = {
        "alertable": total,
        "suppressed_by_rules": suppressed,
        "non_alert_class_assets": 0,
        "digest_threshold": threshold,
        "digest_sent": False,
        "digest_messages": 0,
        "instant_sent": 0,
        "delivered": False,
    }
    if diff_doc.get("baseline") == "none" or diff_doc.get("from_run") in (None, ""):
        ledger["skipped_reason"] = "first_run_baseline"
        ledger["alertable"] = 0
        return ledger
    if total == 0:
        ledger["skipped_reason"] = "no_alertable_assets" if _diff_has_rows(diff_doc) else "no_diff_assets"
        return ledger
    if not rules:
        ledger["skipped_reason"] = "watchtower disabled (target profile)"
        return ledger

    run_ts = str(diff_doc.get("to_run") or "unknown")
    scope = f" target={target}" if target else ""
    lines = [f"{_event_label(side, cls)}: {_asset_label(cls, asset, side)}" for side, cls, asset in events]
    if total >= threshold:
        header = f"DIGEST: {total} findings (threshold={threshold}){scope} run={run_ts}"
        chunks = _chunk_digest(header, lines)
        ledger["digest_sent"] = True
        ledger["digest_messages"] = len(chunks)
        for chunk in chunks:
            if _deliver(params, chunk, sender, target=target):
                ledger["delivered"] = True
        return ledger

    for side, cls, asset in events:
        text = f"{_event_label(side, cls)}: {_asset_label(cls, asset, side)}{scope} (run={run_ts})"
        if _deliver(params, text, sender, target=target):
            ledger["instant_sent"] += 1
            ledger["delivered"] = True
    return ledger


def _chunk_digest(header: str, lines: list[str]) -> list[str]:
    """Split a digest so every finding is listed (Telegram size + line cap)."""
    chunks: list[str] = []
    prefix = header
    current: list[str] = [prefix]
    size = len(prefix)
    listed_in_chunk = 0
    for line in lines:
        extra = 1 + len(line)
        overflow = (
            size + extra > TELEGRAM_TEXT_CAP
            or listed_in_chunk >= DIGEST_LIST_CAP
        )
        if overflow and listed_in_chunk:
            chunks.append("\n".join(current))
            prefix = header + " (cont.)"
            current = [prefix]
            size = len(prefix)
            listed_in_chunk = 0
        current.append(line)
        size += extra
        listed_in_chunk += 1
    if listed_in_chunk:
        chunks.append("\n".join(current))
    return chunks or [header]


def _asset_label(cls: str, asset: dict[str, Any], side: str = "added") -> str:
    if side == "changed":
        before = asset.get("before") if isinstance(asset.get("before"), dict) else {}
        after = asset.get("after") if isinstance(asset.get("after"), dict) else {}
        body = after or before or asset
        hint = _change_hint(before or {}, after or {})
        base = _asset_label(cls, body, side="added")
        return f"{base} ({hint})" if hint else base
    if cls == "hosts":
        parts = [str(asset.get("host") or "?")]
        if asset.get("ip"):
            parts.append(f"ip={asset['ip']}")
        elif asset.get("ips"):
            parts.append(f"ip={asset['ips'][0]}")
        if asset.get("tech"):
            parts.append("tech=" + ",".join(str(t) for t in asset["tech"][:6]))
        return " ".join(parts)
    if cls == "vhosts":
        return f"{asset.get('vhost') or '?'} base={asset.get('base_host') or '-'}"
    if cls == "services":
        svc = asset.get("service") or asset.get("name") or ""
        extra = f" {svc}" if svc else ""
        return f"{asset.get('ip') or '?'}:{asset.get('port')}/{asset.get('proto', '')}{extra}"
    if cls == "passive_ips":
        return str(asset.get("ip") or "?")
    return f"{asset.get('host') or asset.get('ip') or '?'}:{asset.get('port')}/{asset.get('proto', '')}"


def _change_hint(before: dict[str, Any], after: dict[str, Any]) -> str:
    keys = sorted(set(before) | set(after))
    hints: list[str] = []
    for key in keys:
        if before.get(key) == after.get(key):
            continue
        hints.append(f"{key}:{_short(before.get(key))}->{_short(after.get(key))}")
        if len(hints) >= 6:
            break
    return ", ".join(hints)


def _short(val: Any) -> str:
    text = str(val)
    return text if len(text) <= 48 else text[:45] + "..."


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
