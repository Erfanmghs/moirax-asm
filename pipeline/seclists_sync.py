"""C2 (release directive): full-SecLists registry sync.

The operator mandate: ALL SecLists are available in the platform and
selectable, and new lists can be added. This tool walks the local SecLists
clone (seclists_host_path) and generates a frozen-loader-dialect index at
wordlists/seclists-index.yaml. The WordlistRegistry merges that index IN,
and tasks marked allow_registry_wide (DNSR-1 / FFUF-0 / FFUF-2) accept any
registered key in their selection.

Deterministic: same tree -> byte-identical index (stable sort, stable key
slugs, stable integer entries). Raw paths stay forbidden -- modules keep
resolving KEYS only (section 5.6 discipline).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from pipeline.params import Params
from pipeline.textio import atomic_write_text

MAX_INDEX_BYTES = 256 * 1024 * 1024  # index files up to 256 MiB are listed
_SLUG_RE = re.compile(r"[^A-Za-z0-9]+")


def slug_for(rel: Path) -> str:
    """Stable readable key: sl_ + path segments joined by __, e.g.
    Discovery/DNS/x.txt -> sl__discovery__dns__x (lowercased, ascii)."""
    parts = [_SLUG_RE.sub("_", seg).strip("_").lower() for seg in rel.with_suffix("").parts]
    return "sl_" + "__".join(parts)


def shape_for(rel: Path) -> str:
    return "hostname" if "dns" in str(rel).lower() else "generic"


def iter_list_files(root: Path) -> list[Path]:
    out: list[Path] = []
    for p in root.rglob("*.txt"):
        if p.is_file() and not p.name.startswith("."):
            try:
                size = p.stat().st_size
            except OSError:
                continue
            if 0 < size <= MAX_INDEX_BYTES:
                out.append(p)
    out.sort(key=lambda p: str(p.relative_to(root)).lower())
    return out


def build_index_doc(root: Path) -> dict[str, Any]:
    lists: dict[str, Any] = {}
    for p in iter_list_files(root):
        rel = p.relative_to(root)
        try:
            with p.open("rb") as fh:
                entries = sum(1 for _ in fh)
        except OSError:
            continue
        if entries <= 0:
            continue
        lists[slug_for(rel)] = {
            "path": str(rel),
            "entries": entries,
            "shape": shape_for(rel),
        }
    return {
        "schema_version": 1,
        "root": str(root),
        "lists": lists,
    }


def render_index(doc: dict[str, Any]) -> str:
    """Project minimal-YAML dialect via text assembly (frozen-loader safe;
    pyyaml reformatting is forbidden on registry files -- run #14 lesson).
    Deterministic: no timestamps -- byte-identical trees yield byte-identical
    indexes; the git history carries the sync time."""
    out: list[str] = [
        "schema_version: 1",
        "root: seclists",
        "lists:",
    ]
    for key in sorted(doc["lists"]):
        e = doc["lists"][key]
        out.append(f"  {key}:")
        out.append(f"    path: {e['path']}")
        out.append(f"    entries: {int(e['entries'])}")
        out.append(f"    shape: {e['shape']}")
    return "\n".join(out) + "\n"


def sync_seclists_index(params: Params) -> dict[str, Any]:
    root = params.expand_user_path("seclists_host_path")
    if not root.is_dir():
        raise FileNotFoundError(
            f"SecLists clone not found at {root} -- clone danielmiessler/SecLists there and retry"
        )
    doc = build_index_doc(root)
    rel = str(params.require("wordlists_generated_index"))
    target = params.root / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(target, render_index(doc))
    return {
        "index": target,
        "lists": len(doc["lists"]),
        "total_entries": sum(e["entries"] for e in doc["lists"].values()),
    }
