"""Wordlist registry: modules resolve keys from wordlists.yaml, never raw paths (§5.6)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pipeline.params import Params
from pipeline.yaml_util import load_yaml_file


class WordlistError(ValueError):
    pass


class WordlistRegistry:
    def __init__(self, params: Params) -> None:
        self.params = params
        registry_name = str(params.require("wordlists_registry"))
        if _looks_like_path(registry_name):
            raise WordlistError("wordlists_registry must be a repo-relative filename, not a tool path")
        path = params.root / registry_name
        data = load_yaml_file(str(path))
        if not isinstance(data, dict) or "lists" not in data or "tasks" not in data:
            raise WordlistError("wordlists.yaml must contain lists and tasks mappings")
        self.lists: dict[str, Any] = data["lists"]
        self.tasks: dict[str, Any] = data["tasks"]
        self.seclists_root = str(params.require("seclists_root"))

    def resolve(self, list_key: str, task: str) -> str:
        if _looks_like_path(list_key):
            raise WordlistError("raw wordlist paths are forbidden; use a wordlists.yaml key")
        allowed = self.allowed_keys(task)
        if list_key not in allowed:
            raise WordlistError(f"key {list_key!r} is not registered for task {task}")
        entry = self.lists.get(list_key)
        if not isinstance(entry, dict) or "path" not in entry:
            raise WordlistError(f"unknown wordlist key {list_key!r}")
        rel = str(entry["path"]).replace("\\", "/").lstrip("/")
        return f"{self.seclists_root.rstrip('/')}/{rel}"

    def allowed_keys(self, task: str) -> set[str]:
        spec = self.tasks.get(task)
        if not isinstance(spec, dict):
            raise WordlistError(f"unknown wordlist task {task}")
        keys: set[str] = set()
        for field in ("fast", "expansion", "sources"):
            rows = spec.get(field) or []
            if isinstance(rows, list):
                keys.update(str(item) for item in rows)
        default = spec.get("default_key")
        if default:
            keys.add(str(default))
        return keys

    def default_key(self, task: str) -> str:
        spec = self.tasks.get(task)
        if not isinstance(spec, dict) or not spec.get("default_key"):
            raise WordlistError(f"no default_key for task {task}")
        return str(spec["default_key"])

    def relative_path(self, list_key: str) -> str:
        if _looks_like_path(list_key):
            raise WordlistError("raw wordlist paths are forbidden; use a wordlists.yaml key")
        entry = self.lists.get(list_key)
        if not isinstance(entry, dict) or "path" not in entry:
            raise WordlistError(f"unknown wordlist key {list_key!r}")
        return str(entry["path"]).replace("\\", "/").lstrip("/")

    def entries(self, list_key: str) -> int:
        entry = self.lists.get(list_key)
        if not isinstance(entry, dict) or "entries" not in entry:
            raise WordlistError(f"unknown wordlist key {list_key!r}")
        return int(entry["entries"])


def _looks_like_path(value: str) -> bool:
    if not value:
        return True
    if value.startswith("/") or value.startswith("."):
        return True
    if "\\" in value or "/" in value:
        return True
    if Path(value).suffix in {".txt", ".lst", ".wordlist"}:
        return True
    return False
