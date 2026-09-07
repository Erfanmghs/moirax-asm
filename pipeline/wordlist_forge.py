"""WORDLIST FORGE + CONFIG-DEFAULT selection (FFUF-0 / DNSR-1 / FFUF-2)."""

from __future__ import annotations

import hashlib
from pathlib import Path

from pipeline.hostsutil import labels_from_host, normalize_label
from pipeline.params import Params
from pipeline.textio import atomic_write_text, read_lines
from pipeline.wordlists import WordlistError, WordlistRegistry


class EmptyWordlistError(ValueError):
    pass


def selected_keys(params: Params, task: str) -> list[str]:
    """section 8 selection: wordlists.yaml tasks.<task>.selection (operator ticks). No UI."""
    registry = WordlistRegistry(params)
    spec = registry.tasks.get(task)
    if not isinstance(spec, dict):
        raise WordlistError(f"unknown wordlist task {task}")
    raw = spec.get("selection")
    if isinstance(raw, list) and raw:
        keys = [str(item).strip() for item in raw if str(item).strip()]
        if keys:
            return keys
    if task == "FFUF-0":
        fallback = params.require("ffuf_0_selection_keys")
        if isinstance(fallback, list) and fallback:
            keys = [str(item).strip() for item in fallback if str(item).strip()]
            if keys:
                return keys
        raise EmptyWordlistError("empty wordlist selection for task FFUF-0")
    mapping = {
        "DNSR-1": str(params.require("dnsr_1_wordlist_key")),
        "FFUF-2": str(params.require("ffuf_2_wordlist_key")),
    }
    if task not in mapping:
        raise WordlistError(f"no CONFIG-DEFAULT selection for task {task}")
    key = mapping[task].strip()
    if not key:
        raise EmptyWordlistError(f"empty wordlist selection for task {task}")
    return [key]


def seclists_host_root(params: Params) -> Path:
    return params.expand_user_path("seclists_host_path")


def host_list_path(params: Params, registry: WordlistRegistry, key: str) -> Path:
    rel = registry.relative_path(key)
    if rel.startswith("wordlists/"):
        return params.root / rel
    return seclists_host_root(params) / rel


def materialize_effective(params: Params, task: str) -> Path:
    registry = WordlistRegistry(params)
    keys = selected_keys(params, task)
    if not keys:
        raise EmptyWordlistError(f"empty wordlist selection for task {task}")
    for key in keys:
        if key not in registry.allowed_keys(task):
            raise WordlistError(f"key {key!r} is not registered for task {task}")
    sources = [host_list_path(params, registry, key) for key in keys]
    missing = [str(path) for path in sources if not path.is_file()]
    if missing:
        raise WordlistError(f"wordlist source missing: {missing[0]}")
    digest = _selection_hash(keys, sources)
    cache_dir = params.root / "wordlists" / "forge" / "cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_path = cache_dir / f"{task}-{digest}.txt"
    effective = params.root / "wordlists" / "forge" / f"effective-{task}.txt"
    if cache_path.is_file():
        if not effective.is_file() or effective.read_bytes() != cache_path.read_bytes():
            atomic_write_text(effective, cache_path.read_text(encoding="utf-8", errors="replace"))
        _log_count(params, task, keys, _count_lines(effective), digest, cache="HIT")
        return effective
    merged = _union_normalize(sources)
    if not merged:
        raise EmptyWordlistError(f"empty wordlist after union for task {task}")
    body = "\n".join(merged) + "\n"
    atomic_write_text(cache_path, body)
    atomic_write_text(effective, body)
    _log_count(params, task, keys, len(merged), digest, cache="MISS")
    return effective


def forge_custom_subdomains(params: Params) -> Path:
    """FFUF-0: union of CONFIG-DEFAULT keys -> custom-subdomains.txt."""
    effective = materialize_effective(params, "FFUF-0")
    custom = params.root / str(params.require("wordlist_forge_output"))
    custom.parent.mkdir(parents=True, exist_ok=True)
    existing = {line for line in (_normalize_line(x) for x in read_lines(custom)) if line}
    incoming = [line for line in (_normalize_line(x) for x in read_lines(effective)) if line]
    combined: list[str] = []
    seen: set[str] = set()
    for label in incoming + sorted(existing):
        if label in seen:
            continue
        seen.add(label)
        combined.append(label)
    if not combined:
        raise EmptyWordlistError("empty wordlist selection for task FFUF-0")
    atomic_write_text(custom, "\n".join(combined) + "\n")
    return custom


def ingest_if_completed(params: Params, gate, target_dir: Path, target: str, status: str) -> None:
    """section 8 FFUF-0: append validated labels only after a completed run (engine finalization)."""
    log = params.root / "wordlists" / "forge" / "counts.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    completed = str(params.require("run_status_completed"))
    if status != completed:
        with log.open("a", encoding="utf-8") as handle:
            handle.write(f"GROW-SKIP\tstatus={status}\n")
        return
    from pipeline.hostsutil import wildcard_seeds
    from pipeline.jsonio import read_json

    seeds = wildcard_seeds(gate)
    blocked = _probe_blocklist(params)
    tagged: list[tuple[str, str]] = []
    ffuf_path = target_dir / str(params.require("ffuf_data_json"))
    if ffuf_path.is_file():
        doc = read_json(ffuf_path)
        for row in doc.get("hosts") or []:
            host = str(row.get("fqdn") or "").strip().lower()
            if host:
                tagged.append((host, "FFUF-1"))
        for row in doc.get("vhosts") or []:
            host = str(row.get("vhost") or "").strip().lower()
            if host:
                tagged.append((host, "FFUF-2"))
    dnsr_path = target_dir / str(params.require("dnsr_data_json"))
    if dnsr_path.is_file():
        doc = read_json(dnsr_path)
        for row in doc.get("resolved") or []:
            if str(row.get("resolution_status") or "") != "resolved":
                continue
            host = str(row.get("host") or "").strip().lower()
            if host:
                tagged.append((host, "DNSR"))
    hosts: list[str] = []
    sources: dict[str, str] = {}
    for host, source in tagged:
        if host in blocked:
            continue
        hosts.append(host)
        sources[host] = source
    append_validated_labels(params, hosts, seeds, sources=sources)


def append_validated_labels(
    params: Params,
    hosts: list[str],
    seeds: list[str],
    sources: dict[str, str] | None = None,
) -> Path:
    sources = sources or {}
    custom = params.root / str(params.require("wordlist_forge_output"))
    existing = [line for line in (_normalize_line(x) for x in read_lines(custom)) if line]
    seen = set(existing)
    added = 0
    added_labels: list[str] = []
    blocked_labels = _probe_label_blocklist(params)
    for host in hosts:
        for seed in seeds:
            for label in labels_from_host(host, seed):
                if label in blocked_labels:
                    continue
                if label not in seen:
                    seen.add(label)
                    existing.append(label)
                    added += 1
                    src = sources.get(host) or "unknown"
                    added_labels.append(f"{label}\thost={host}\tsource={src}")
    if added:
        atomic_write_text(custom, "\n".join(existing) + "\n")
        log = params.root / "wordlists" / "forge" / "counts.log"
        with log.open("a", encoding="utf-8") as handle:
            handle.write(f"GROW\tadded={added}\n")
            for row in added_labels:
                handle.write(f"GROW-LABEL\t{row}\n")
    return custom


def _probe_blocklist(params: Params) -> set[str]:
    blocked: set[str] = set()
    for key in ("canary_sentinel_hosts", "resolver_validate_domains"):
        raw = params.require(key)
        if isinstance(raw, list):
            for item in raw:
                host = str(item).strip().lower().rstrip(".")
                if host:
                    blocked.add(host)
    return blocked


def _probe_label_blocklist(params: Params) -> set[str]:
    labels: set[str] = set()
    for host in _probe_blocklist(params):
        token = host.split(".")[0]
        label = normalize_label(token)
        if label:
            labels.add(label)
    return labels


def copy_into_target(params: Params, target_dir: Path, source: Path, rel: str) -> Path:
    dest = target_dir / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(dest, source.read_text(encoding="utf-8", errors="replace"))
    return dest


def _union_normalize(sources: list[Path]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for path in sources:
        for raw in read_lines(path):
            label = _normalize_line(raw)
            if not label or label in seen:
                continue
            seen.add(label)
            out.append(label)
    return out


def _normalize_line(raw: str) -> str | None:
    token = raw.strip()
    if not token or token.startswith("#"):
        return None
    if " " in token or "\t" in token:
        token = token.split()[0]
    return normalize_label(token)


def _selection_hash(keys: list[str], sources: list[Path]) -> str:
    h = hashlib.sha256()
    h.update(",".join(keys).encode("utf-8"))
    for path in sources:
        stat = path.stat()
        h.update(str(path).encode("utf-8"))
        h.update(str(stat.st_mtime_ns).encode("utf-8"))
        h.update(str(stat.st_size).encode("utf-8"))
    return h.hexdigest()[:16]


def _count_lines(path: Path) -> int:
    return sum(1 for line in read_lines(path) if line.strip())


def _log_count(params: Params, task: str, keys: list[str], count: int, digest: str, cache: str) -> None:
    log = params.root / "wordlists" / "forge" / "counts.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("a", encoding="utf-8") as handle:
        handle.write(
            f"{task}\tcache={cache}\thash={digest}\tkeys={','.join(keys)}\tentries={count}\n"
        )
