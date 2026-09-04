"""Parse JSON object or NDJSON tool stdout."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def parse_json_payload(text: str) -> Any:
    raw = (text or "").strip()
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        rows: list[Any] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return rows


def load_json_file(path: Path) -> Any:
    if not path.is_file():
        return None
    return parse_json_payload(path.read_text(encoding="utf-8", errors="replace"))
