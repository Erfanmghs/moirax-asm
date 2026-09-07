"""C2 (release directive): operator custom wordlists + the PLATFORM-LEARNED
list fed by the pipeline's own passive/active discoveries.

Capabilities:
  - add/remove/list operator custom lists  ->  wordlists/custom/<name>.txt,
    registered in wordlists/custom/index.yaml (frozen-loader dialect)
  - ingest_learned_labels: after every terminal run the engine feeds the
    in-scope hosts it discovered (passive candidates, resolved DNS names,
    active fuzz records) into wordlists/custom/platform-learned.txt --
    APPEND-ONLY, deduplicated, registered as the selectable key
    `platform_learned` so it competes with every other list in selection.

Safety laws (self-contained, unit-tested):
  - names: ^[a-z0-9][a-z0-9_-]{2,40}$ (no paths, no traversal)
  - content: UTF-8 text, non-empty, <= 50 MiB, one entry per line,
    line charset ^[A-Za-z0-9._-]+$ (hostname/path-safe), <= 200 chars
  - secret scan before persisting (provider token shapes; the same law the
    C1 release gate enforces on the tree)
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from pipeline.params import Params
from pipeline.textio import atomic_write_text

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{2,40}$")
LINE_RE = re.compile(r"^[A-Za-z0-9._-]+$")
MAX_BYTES = 50 * 1024 * 1024
MAX_LINE = 200

LEARNED_KEY = "platform_learned"
LEARNED_NAME = "platform-learned.txt"

SECRET_PATTERNS = [
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----"),
    re.compile(r"AIza[0-9A-Za-z_\-]{30,}"),
    re.compile(r"(?i)(?:api[_-]?key|secret|token|password)\s*[:=]\s*['\"][A-Za-z0-9+/_\-]{20,}['\"]"),
]


class CustomListError(ValueError):
    pass


def _secret_scan(text: str) -> list[str]:
    hits: list[str] = []
    for pat in SECRET_PATTERNS:
        m = pat.search(text)
        if m:
            hits.append(m.group(0)[:16] + "...")
    return hits


def _custom_dir(params: Params) -> Path:
    d = params.root / "wordlists" / "custom"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _index_path(params: Params) -> Path:
    return params.root / str(params.require("wordlists_custom_index"))


def _read_index(params: Params) -> dict[str, dict[str, Any]]:
    p = _index_path(params)
    if not p.is_file():
        return {}
    from pipeline.yaml_util import load_yaml_file

    doc = load_yaml_file(str(p))
    if not isinstance(doc, dict):
        return {}
    out: dict[str, dict[str, Any]] = {}
    for key, entry in (doc.get("lists") or {}).items():
        if isinstance(entry, dict):
            out[str(key)] = entry
    return out


def _render_index(lists: dict[str, dict[str, Any]]) -> str:
    out = ["schema_version: 1", "root: wordlists/custom", "lists:"]
    for key in sorted(lists):
        e = lists[key]
        out.append(f"  {key}:")
        out.append(f"    path: {e['path']}")
        out.append(f"    entries: {int(e.get('entries') or 0)}")
        out.append(f"    shape: {e.get('shape') or 'generic'}")
        out.append(f"    origin: {e.get('origin') or 'operator'}")
    return "\n".join(out) + "\n"


def _write_index(params: Params, lists: dict[str, dict[str, Any]]) -> None:
    atomic_write_text(_index_path(params), _render_index(lists))


def normalize_lines(text: str) -> list[str]:
    seen: list[str] = []
    out: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if len(line) > MAX_LINE or not LINE_RE.match(line):
            raise CustomListError(f"line violates charset/length law: {line[:40]!r}")
        if line not in seen:
            seen.append(line)
            out.append(line)
    return out


def add_custom_list(params: Params, name: str, source: Path, origin: str = "operator") -> dict[str, Any]:
    if not NAME_RE.match(name):
        raise CustomListError(f"illegal list name {name!r} (law: {NAME_RE.pattern})")
    data = Path(source).read_bytes()
    if not data:
        raise CustomListError("refusing to register an EMPTY list")
    if len(data) > MAX_BYTES:
        raise CustomListError(f"list exceeds {MAX_BYTES} bytes")
    text = data.decode("utf-8")
    hits = _secret_scan(text)
    if hits:
        raise CustomListError(f"secret material detected in list content: {hits}")
    lines = normalize_lines(text)
    if not lines:
        raise CustomListError("list normalizes to zero usable entries")
    target = _custom_dir(params) / f"{name}.txt"
    atomic_write_text(target, "\n".join(lines) + "\n")
    lists = _read_index(params)
    lists[name] = {"path": f"wordlists/custom/{name}.txt", "entries": len(lines), "shape": "custom", "origin": origin}
    _write_index(params, lists)
    return {"name": name, "entries": len(lines), "path": str(target)}


def remove_custom_list(params: Params, name: str) -> dict[str, Any]:
    if name == LEARNED_KEY:
        raise CustomListError("the platform-learned list is append-only and cannot be removed")
    if not NAME_RE.match(name):
        raise CustomListError(f"illegal list name {name!r}")
    lists = _read_index(params)
    if name not in lists:
        raise CustomListError(f"unknown custom list {name!r}")
    (_custom_dir(params) / f"{name}.txt").unlink(missing_ok=True)
    del lists[name]
    _write_index(params, lists)
    return {"removed": name}


def list_custom_lists(params: Params) -> dict[str, dict[str, Any]]:
    return _read_index(params)


def ensure_learned_list(params: Params) -> Path:
    """Idempotently register the platform-learned list (selectable even when
    still empty -- materializing an empty-only selection fails honestly)."""
    lists = _read_index(params)
    if LEARNED_KEY in lists:
        return params.root / str(lists[LEARNED_KEY]["path"])
    target = _custom_dir(params) / LEARNED_NAME
    if not target.exists():
        target.write_text("", encoding="utf-8")
    lists[LEARNED_KEY] = {
        "path": f"wordlists/custom/{LEARNED_NAME}",
        "entries": 0,
        "shape": "hostname",
        "origin": "platform",
    }
    _write_index(params, lists)
    return target


def _label_of(host: str, target: str) -> str | None:
    host = host.lower().strip().strip(".")
    if host == target:
        return None
    suffix = "." + target
    if not host.endswith(suffix):
        return None
    prefix = host[: -len(suffix)]
    if not prefix or not LINE_RE.match(prefix):
        return None
    return prefix


def ingest_learned_labels(params: Params, target_dir: Path, target: str, gate=None) -> dict[str, Any]:
    """Run-end feed: in-scope discovered hosts -> platform-learned labels.
    Sources: passive candidates, dns-resolve records, active fuzz records.
    Scope law: every host must equal the target or end with .target; if a
    scope gate is supplied, candidates must additionally pass it."""
    import json

    hosts: list[str] = []

    def _rows(rel: str, container_key: str, host_keys: tuple[str, ...]) -> None:
        p = target_dir / rel
        if not p.is_file():
            return
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001 -- a malformed lane never breaks the ingest
            return
        rows = doc.get(container_key) or []
        for row in rows:
            if isinstance(row, dict):
                for hk in host_keys:
                    val = row.get(hk)
                    if isinstance(val, str) and val.strip():
                        hosts.append(val.strip().lower())
                    elif isinstance(val, dict):
                        inner = val.get("FUZZ") or val.get("name")
                        if isinstance(inner, str) and inner.strip():
                            hosts.append(inner.strip().lower())

    _rows("10_subdomains/passive/data.json", "candidates", ("host",))
    _rows("20_dns/dnsx/data.json", "resolved", ("host",))
    _rows("10_subdomains/ffuf/data.json", "hosts", ("fqdn", "host"))
    _rows("10_subdomains/ffuf/data.json", "vhosts", ("vhost", "host"))

    labels: list[str] = []
    seen: set[str] = set()
    for host in hosts:
        if gate is not None:
            allowed, _reason = gate.validate_candidate(host)
            if not allowed:
                continue
        elif not (host == target or host.endswith("." + target)):
            continue
        label = _label_of(host, target)
        if label and label not in seen:
            seen.add(label)
            labels.append(label)

    learned = ensure_learned_list(params)
    existing: list[str] = []
    if learned.is_file():
        existing = [ln.strip() for ln in learned.read_text(encoding="utf-8").splitlines() if ln.strip()]
    known = set(existing)
    added = [ln for ln in labels if ln not in known]
    if added:
        atomic_write_text(learned, "\n".join(existing + added) + "\n")
    lists = _read_index(params)
    if LEARNED_KEY in lists:
        lists[LEARNED_KEY]["entries"] = len(existing) + len(added)
        _write_index(params, lists)
    return {"target": target, "labels_seen": len(labels), "added": len(added), "total": len(existing) + len(added)}
