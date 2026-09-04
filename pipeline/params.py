"""Named parameters from tools.yaml and tools.lock (§5.6)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pipeline.yaml_util import load_yaml_file


class Params:
    def __init__(self, root: Path) -> None:
        self.root = root
        data = load_yaml_file(str(root / "tools.yaml"))
        if not isinstance(data, dict) or "settings" not in data:
            raise ValueError("tools.yaml must contain a settings mapping")
        self.settings: dict[str, Any] = data["settings"]
        self.tools: dict[str, Any] = data.get("tools") or {}
        lock_path = root / "tools.lock"
        self.lock: dict[str, Any] = load_yaml_file(str(lock_path)) if lock_path.exists() else {}

    def require(self, name: str) -> Any:
        if name not in self.settings:
            raise KeyError(f"unnamed parameter {name!r} — register it in tools.yaml settings")
        return self.settings[name]

    def dashboard_image(self) -> str:
        images = self.lock.get("images") or {}
        dash = images.get("dashboard") or {}
        image = dash.get("image")
        tag = dash.get("tag")
        if image and tag:
            return f"{image}:{tag}"
        return str(self.require("dashboard_image"))

    def expand_user_path(self, name: str) -> Path:
        raw = str(self.require(name))
        return Path(raw).expanduser()

