"""Wordlist registry: modules resolve keys from wordlists.yaml, never raw paths (section 5.6)."""

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
        self.generated_index: dict[str, Any] = {}
        self.custom_index: dict[str, Any] = {}
        self._merge_generated_and_custom()

    def _merge_generated_and_custom(self) -> None:
        """C2 (release directive): the selectable universe grows beyond the
        curated registry -- the generated full-SecLists index and the custom
        lists index (platform-learned + operator uploads) merge IN. Curated
        entries always win on key collision; generated entries never clobber
        operator data. Index files are repo-relative, frozen-loader dialect,
        and OPTIONAL (absent index == curated-only registry)."""
        for attr, param_name in (
            ("generated_index", "wordlists_generated_index"),
            ("custom_index", "wordlists_custom_index"),
        ):
            try:
                rel = str(self.params.require(param_name))
            except KeyError:
                continue
            _safe_repo_rel(rel, param_name)
            idx_path = self.params.root / rel
            if not idx_path.is_file():
                continue
            doc = load_yaml_file(str(idx_path))
            if not isinstance(doc, dict) or not isinstance(doc.get("lists"), dict):
                raise WordlistError(f"{rel} must contain a lists mapping")
            merged: dict[str, Any] = {}
            for key, entry in doc["lists"].items():
                if str(key) in self.lists:
                    continue  # curated wins
                merged[str(key)] = entry
            setattr(self, attr, merged)
            self.lists.update(merged)

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
        for field in ("fast", "expansion", "sources", "selection", "default_selection"):
            rows = spec.get(field) or []
            if isinstance(rows, list):
                keys.update(str(item) for item in rows)
        default = spec.get("default_key")
        if default:
            keys.add(str(default))
        if spec.get("allow_registry_wide"):
            # C2 (release directive): ALL registered lists are selectable for
            # this task -- the registry-wide universe includes the generated
            # full-SecLists index and custom lists (platform-learned + uploads).
            keys.update(str(k) for k in self.lists)
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


def _safe_repo_rel(value: str, param_name: str) -> None:
    """C2: index params ARE repo-relative paths (with directories), unlike
    registry KEYS; the law is: relative, no traversal, no escapes."""
    bad = (
        not value
        or value.startswith(("/", ".", "~"))
        or "\\" in value
        or ".." in Path(value).parts
        or value.endswith("/")
    )
    if bad:
        raise WordlistError(f"{param_name} must be a safe repo-relative path, got {value!r}")
