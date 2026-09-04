"""Telegram self-monitoring alerts (§4.7). Unset credentials → skip silently."""

from __future__ import annotations

import os
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Callable

from pipeline.params import Params

SendFn = Callable[[str], None]


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


def send_status(params: Params, status: str, module: str, reason: str, sender: SendFn | None = None) -> bool:
    text = f"{status}: module={module} reason={reason}"
    if sender is not None:
        sender(text)
        return True
    load_dotenv(params.root, str(params.require("env_filename")))
    token_key = str(params.require("telegram_bot_token_env"))
    chat_key = str(params.require("telegram_chat_id_env"))
    token = os.environ.get(token_key, "").strip()
    chat_id = os.environ.get(chat_key, "").strip()
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
