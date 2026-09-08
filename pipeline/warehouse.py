"""Per-target recon warehouse (physical tenant isolation + run-scoped facts).

Architecture:
- One SQLite file lives INSIDE recon/<target>/warehouse.sqlite. A query
  against target A cannot see target B because they are different files.
- meta.target is bound at create time and re-checked on every open. A DB
  copied into another target's directory is refused.
- JSON artifacts (assets.json, history/<stamp>/, diff.json) stay the
  pipeline source of truth. The warehouse is a durable derived index so
  history retention can prune snapshots without losing first-seen /
  last-seen / arbitrary-pair diffs.
- Facts are identity-stable (class + natural_key). Payloads are SCD-2
  versioned. run_facts records which version was observed on which run.

Never-fail at the engine call-site: ingest_run_end raises to the caller
only when the caller wants it; the engine wraps it like reporting.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from pipeline.history import FACT_CLASSES, diff_maps, empty_maps, extract_classes
from pipeline.jsonio import read_json
from pipeline.params import Params

SCHEMA_VERSION = 1
_STAMP_RE = re.compile(r"^\d{8}T\d{6}Z$")
_WAREHOUSE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_MAX_NATURAL_KEY = 4096
_MAX_PAYLOAD = 262144
_APPLICATION_ID = 0x52504C57  # RPLW
_HMAC_RELPATH = "dashboard/.warehouse-hmac"
_CLASS_SQL = ",".join("'" + cls + "'" for cls in FACT_CLASSES)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS runs (
  run_id INTEGER PRIMARY KEY,
  stamp TEXT NOT NULL UNIQUE CHECK(length(stamp) = 16),
  status TEXT NOT NULL CHECK(length(status) BETWEEN 1 AND 64),
  counts_json TEXT NOT NULL CHECK(length(counts_json) <= 65536),
  ingested_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS facts (
  fact_id INTEGER PRIMARY KEY,
  class TEXT NOT NULL CHECK(class IN (""" + _CLASS_SQL + """)),
  natural_key TEXT NOT NULL CHECK(length(natural_key) BETWEEN 1 AND 4096),
  first_run_id INTEGER NOT NULL REFERENCES runs(run_id),
  last_run_id INTEGER NOT NULL REFERENCES runs(run_id),
  last_hash TEXT NOT NULL CHECK(length(last_hash) = 64),
  UNIQUE(class, natural_key)
);
CREATE TABLE IF NOT EXISTS fact_versions (
  version_id INTEGER PRIMARY KEY,
  fact_id INTEGER NOT NULL REFERENCES facts(fact_id),
  payload_hash TEXT NOT NULL CHECK(length(payload_hash) = 64),
  payload_json TEXT NOT NULL CHECK(length(payload_json) <= 262144),
  valid_from_run INTEGER NOT NULL REFERENCES runs(run_id),
  valid_to_run INTEGER,
  UNIQUE(fact_id, payload_hash, valid_from_run)
);
CREATE TABLE IF NOT EXISTS run_facts (
  run_id INTEGER NOT NULL REFERENCES runs(run_id),
  fact_id INTEGER NOT NULL REFERENCES facts(fact_id),
  version_id INTEGER NOT NULL REFERENCES fact_versions(version_id),
  PRIMARY KEY (run_id, fact_id)
);
CREATE TABLE IF NOT EXISTS diffs (
  diff_id INTEGER PRIMARY KEY,
  from_stamp TEXT,
  to_stamp TEXT NOT NULL,
  payload_json TEXT NOT NULL CHECK(length(payload_json) <= 1048576),
  UNIQUE(from_stamp, to_stamp)
);
CREATE INDEX IF NOT EXISTS idx_facts_class ON facts(class);
CREATE INDEX IF NOT EXISTS idx_run_facts_fact ON run_facts(fact_id);
CREATE INDEX IF NOT EXISTS idx_versions_fact ON fact_versions(fact_id);
"""


class WarehouseError(ValueError):
    """Isolation or schema violation -- never mix tenants."""


def warehouse_filename(params: Params) -> str:
    try:
        name = str(params.require("warehouse_filename"))
    except KeyError:
        name = "warehouse.sqlite"
    if not _WAREHOUSE_NAME_RE.match(name) or "/" in name or "\\" in name or ".." in name:
        raise WarehouseError("illegal warehouse filename (must be a single basename)")
    return name


def warehouse_path(params: Params, target_dir: Path) -> Path:
    return target_dir / warehouse_filename(params)


def _confine_warehouse_file(path: Path, target_dir: Path) -> Path:
    """Warehouse file must live directly inside the target directory."""
    directory = target_dir.resolve()
    resolved = path.resolve()
    try:
        resolved.relative_to(directory)
    except ValueError as exc:
        raise WarehouseError("warehouse path escaped target directory") from exc
    if resolved.parent != directory:
        raise WarehouseError("warehouse must be a file in the target directory, not a nested path")
    return resolved


def _chmod_private(path: Path) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    for extra in (path.with_name(path.name + "-wal"), path.with_name(path.name + "-shm")):
        if extra.is_file():
            try:
                os.chmod(extra, 0o600)
            except OSError:
                pass


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def _hash_payload(obj: Any) -> str:
    return hashlib.sha256(_canonical(obj).encode("utf-8")).hexdigest()


def _hmac_key(params: Params) -> bytes:
    """Install-local seal key; lives outside every tenant sqlite file."""
    path = params.root / _HMAC_RELPATH
    if path.is_file():
        text = path.read_text(encoding="utf-8").strip()
        try:
            raw = bytes.fromhex(text)
        except ValueError:
            raw = text.encode("utf-8")
        if len(raw) >= 32:
            return raw
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = secrets.token_bytes(32)
    path.write_text(raw.hex() + "\n", encoding="utf-8")
    _chmod_private(path)
    return raw


def _seal_mac(params: Params, target: str, created_at: str) -> str:
    msg = f"v1|{target}|{created_at}".encode("utf-8")
    return hmac.new(_hmac_key(params), msg, hashlib.sha256).hexdigest()


def _verify_or_apply_seal(
    conn: sqlite3.Connection, params: Params, target: str, *, write: bool
) -> None:
    created = conn.execute("SELECT value FROM meta WHERE key='created_at'").fetchone()
    created_at = str(created["value"]) if created else ""
    row = conn.execute("SELECT value FROM meta WHERE key='hmac'").fetchone()
    expected = _seal_mac(params, target, created_at)
    if row is None:
        if write:
            conn.execute("INSERT INTO meta(key, value) VALUES ('hmac', ?)", (expected,))
        return
    found = str(row["value"] or "")
    if len(found) != len(expected) or not hmac.compare_digest(found, expected):
        raise WarehouseError("warehouse integrity seal mismatch")


def _harden_connection(conn: sqlite3.Connection, *, write: bool) -> None:
    try:
        conn.enable_load_extension(False)
    except (AttributeError, sqlite3.OperationalError):
        pass
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA trusted_schema=OFF")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA recursive_triggers=OFF")
    conn.execute("PRAGMA cell_size_check=ON")
    conn.execute("PRAGMA mmap_size=0")
    if write:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("PRAGMA secure_delete=ON")
        conn.execute("PRAGMA temp_store=MEMORY")
        conn.execute(f"PRAGMA application_id={_APPLICATION_ID}")
        conn.execute("BEGIN IMMEDIATE")


@contextmanager
def _connect(path: Path, *, write: bool = True) -> Iterator[sqlite3.Connection]:
    if write:
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(path), timeout=8)
    else:
        # URI mode=ro never creates a file and cannot mutate the tenant DB.
        conn = sqlite3.connect(f"file:{path.resolve().as_posix()}?mode=ro", uri=True, timeout=8)
    conn.row_factory = sqlite3.Row
    try:
        _harden_connection(conn, write=write)
        yield conn
        if write:
            conn.commit()
            _chmod_private(path)
    except Exception:
        if write:
            conn.rollback()
        raise
    finally:
        conn.close()


def _verify_bound(conn: sqlite3.Connection, params: Params, target: str, *, write: bool) -> None:
    try:
        row = conn.execute("SELECT value FROM meta WHERE key='target'").fetchone()
        ver = conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
    except sqlite3.OperationalError as exc:
        raise WarehouseError("warehouse schema missing or unreadable") from exc
    if row is None:
        raise WarehouseError("warehouse has no target binding (refuse unbound file)")
    bound = str(row["value"] or "")
    if bound != target:
        raise WarehouseError(
            f"warehouse bound to {bound!r} cannot be opened as {target!r} "
            "(physical isolation: refuse a copied database)"
        )
    if ver is not None:
        try:
            found = int(ver["value"])
        except (TypeError, ValueError) as exc:
            raise WarehouseError("warehouse schema_version is not an integer") from exc
        if found != SCHEMA_VERSION:
            raise WarehouseError(
                f"warehouse schema_version {found} incompatible with {SCHEMA_VERSION}"
            )
    _verify_or_apply_seal(conn, params, target, write=write)


def _ensure_schema(
    conn: sqlite3.Connection, params: Params, target: str, *, allow_create: bool
) -> None:
    try:
        has_meta = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='meta'"
        ).fetchone()
    except sqlite3.OperationalError as exc:
        raise WarehouseError("warehouse sqlite_master unreadable") from exc
    if has_meta is None:
        if not allow_create:
            raise WarehouseError("warehouse not initialized")
        # One statement at a time: Connection.executescript() issues COMMIT
        # and would abort the BEGIN IMMEDIATE that keeps ingest atomic.
        for stmt in _SCHEMA.split(";"):
            sql = stmt.strip()
            if sql:
                conn.execute(sql)
        conn.execute("INSERT INTO meta(key, value) VALUES ('target', ?)", (target,))
        conn.execute(
            "INSERT INTO meta(key, value) VALUES ('schema_version', ?)",
            (str(SCHEMA_VERSION),),
        )
        conn.execute("INSERT INTO meta(key, value) VALUES ('created_at', ?)", (_now(),))
        _verify_or_apply_seal(conn, params, target, write=True)
        return
    _verify_bound(conn, params, target, write=allow_create)


def _reconcile_fact_identity(conn: sqlite3.Connection) -> None:
    """Rebuild first/last-seen after a latest-run retry so SCD-2 identity stays true."""
    conn.execute("DELETE FROM facts WHERE fact_id NOT IN (SELECT fact_id FROM run_facts)")
    conn.execute(
        "DELETE FROM fact_versions WHERE fact_id NOT IN (SELECT fact_id FROM facts)"
    )
    rows = conn.execute("SELECT fact_id FROM facts").fetchall()
    for row in rows:
        fact_id = int(row["fact_id"])
        span = conn.execute(
            "SELECT MIN(run_id) AS first_id, MAX(run_id) AS last_id "
            "FROM run_facts WHERE fact_id=?",
            (fact_id,),
        ).fetchone()
        last_ver = conn.execute(
            "SELECT v.payload_hash FROM run_facts rf "
            "JOIN fact_versions v ON v.version_id = rf.version_id "
            "WHERE rf.fact_id=? ORDER BY rf.run_id DESC LIMIT 1",
            (fact_id,),
        ).fetchone()
        if span is None or span["first_id"] is None or last_ver is None:
            continue
        conn.execute(
            "UPDATE facts SET first_run_id=?, last_run_id=?, last_hash=? WHERE fact_id=?",
            (int(span["first_id"]), int(span["last_id"]), str(last_ver["payload_hash"]), fact_id),
        )


def open_bound(params: Params, target_dir: Path, target: str) -> Path:
    """Create/open the warehouse for THIS target only. Path is always under target_dir."""
    path = _confine_warehouse_file(warehouse_path(params, target_dir), target_dir)
    with _connect(path, write=True) as conn:
        _ensure_schema(conn, params, target, allow_create=True)
    return path


def ingest_run_end(
    params: Params,
    target_dir: Path,
    target: str,
    stamp: str,
    status: str,
    counts: dict[str, int],
) -> dict[str, Any]:
    """Engine hook: index the snapshot that was just written."""
    hist = target_dir / str(params.require("history_dirname")) / stamp
    maps = extract_classes(params, hist) if hist.is_dir() else empty_maps()
    diff_path = target_dir / str(params.require("diff_filename"))
    diff_doc: dict[str, Any] | None = None
    if diff_path.is_file():
        try:
            loaded = read_json(diff_path)
            if isinstance(loaded, dict):
                diff_doc = loaded
        except (OSError, json.JSONDecodeError, ValueError):
            diff_doc = None
    return ingest_maps(params, target_dir, target, stamp, status, counts, maps, diff_doc)


def ingest_maps(
    params: Params,
    target_dir: Path,
    target: str,
    stamp: str,
    status: str,
    counts: dict[str, int],
    maps: dict[str, dict[str, Any]],
    diff_doc: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not _STAMP_RE.match(stamp):
        raise WarehouseError(f"illegal run stamp {stamp!r}")
    status = str(status or "unknown")[:64]
    path = open_bound(params, target_dir, target)
    fact_n = 0
    with _connect(path, write=True) as conn:
        _ensure_schema(conn, params, target, allow_create=True)
        later = conn.execute(
            "SELECT stamp FROM runs WHERE stamp > ? ORDER BY stamp ASC LIMIT 1",
            (stamp,),
        ).fetchone()
        existing = conn.execute("SELECT run_id FROM runs WHERE stamp=?", (stamp,)).fetchone()
        if existing is not None and later is not None:
            raise WarehouseError(
                f"refusing out-of-order ingest of {stamp}; later run "
                f"{later['stamp']} exists (rebuild the warehouse)"
            )
        if existing is not None:
            run_id = int(existing["run_id"])
            conn.execute("DELETE FROM run_facts WHERE run_id=?", (run_id,))
            conn.execute(
                "UPDATE runs SET status=?, counts_json=?, ingested_at=? WHERE run_id=?",
                (status, _canonical(counts), _now(), run_id),
            )
        else:
            cur = conn.execute(
                "INSERT INTO runs(stamp, status, counts_json, ingested_at) VALUES (?,?,?,?)",
                (stamp, status, _canonical(counts), _now()),
            )
            run_id = int(cur.lastrowid)
        for cls in FACT_CLASSES:
            bucket = maps.get(cls) or {}
            for key, payload in bucket.items():
                key = str(key)
                if not key or len(key) > _MAX_NATURAL_KEY:
                    raise WarehouseError("fact natural_key rejected")
                fact_n += 1
                payload_hash = _hash_payload(payload)
                body = _canonical(payload)
                if len(body) > _MAX_PAYLOAD:
                    raise WarehouseError("fact payload exceeds warehouse cap")
                row = conn.execute(
                    "SELECT fact_id, last_hash FROM facts WHERE class=? AND natural_key=?",
                    (cls, key),
                ).fetchone()
                if row is None:
                    cur = conn.execute(
                        "INSERT INTO facts(class, natural_key, first_run_id, last_run_id, last_hash) "
                        "VALUES (?,?,?,?,?)",
                        (cls, key, run_id, run_id, payload_hash),
                    )
                    fact_id = int(cur.lastrowid)
                    ver = conn.execute(
                        "INSERT INTO fact_versions(fact_id, payload_hash, payload_json, valid_from_run, valid_to_run) "
                        "VALUES (?,?,?,?,NULL)",
                        (fact_id, payload_hash, body, run_id),
                    )
                    version_id = int(ver.lastrowid)
                else:
                    fact_id = int(row["fact_id"])
                    conn.execute(
                        "UPDATE facts SET last_run_id=?, last_hash=? WHERE fact_id=?",
                        (run_id, payload_hash, fact_id),
                    )
                    if str(row["last_hash"]) != payload_hash:
                        conn.execute(
                            "UPDATE fact_versions SET valid_to_run=? "
                            "WHERE fact_id=? AND valid_to_run IS NULL",
                            (run_id, fact_id),
                        )
                        ver = conn.execute(
                            "INSERT INTO fact_versions(fact_id, payload_hash, payload_json, valid_from_run, valid_to_run) "
                            "VALUES (?,?,?,?,NULL)",
                            (fact_id, payload_hash, body, run_id),
                        )
                        version_id = int(ver.lastrowid)
                    else:
                        ver = conn.execute(
                            "SELECT version_id FROM fact_versions WHERE fact_id=? AND payload_hash=? "
                            "ORDER BY version_id DESC LIMIT 1",
                            (fact_id, payload_hash),
                        ).fetchone()
                        if ver is None:
                            ver = conn.execute(
                                "INSERT INTO fact_versions(fact_id, payload_hash, payload_json, valid_from_run, valid_to_run) "
                                "VALUES (?,?,?,?,NULL)",
                                (fact_id, payload_hash, body, run_id),
                            )
                            version_id = int(ver.lastrowid)
                        else:
                            version_id = int(ver["version_id"])
                conn.execute(
                    "INSERT OR REPLACE INTO run_facts(run_id, fact_id, version_id) VALUES (?,?,?)",
                    (run_id, fact_id, version_id),
                )
        if diff_doc is not None:
            from_stamp = str(diff_doc.get("from_run") or "")
            to_stamp = str(diff_doc.get("to_run") or stamp)
            conn.execute(
                "INSERT OR REPLACE INTO diffs(from_stamp, to_stamp, payload_json) VALUES (?,?,?)",
                (from_stamp, to_stamp, _canonical(diff_doc)),
            )
        _reconcile_fact_identity(conn)
    return {
        "ok": True,
        "target": target,
        "path": str(path),
        "stamp": stamp,
        "facts": fact_n,
        "isolated": True,
    }


def rebuild_from_history(params: Params, target_dir: Path, target: str) -> dict[str, Any]:
    """Replay every remaining history/<stamp> snapshot into a fresh warehouse."""
    path = warehouse_path(params, target_dir)
    if path.is_file():
        path.unlink()
    for extra in (path.with_name(path.name + "-wal"), path.with_name(path.name + "-shm")):
        if extra.is_file():
            extra.unlink()
    hist_root = target_dir / str(params.require("history_dirname"))
    stamps: list[str] = []
    if hist_root.is_dir():
        stamps = sorted(d.name for d in hist_root.iterdir() if d.is_dir() and _STAMP_RE.match(d.name))
    runs_path = target_dir / str(params.require("runs_filename"))
    run_meta: dict[str, dict[str, Any]] = {}
    if runs_path.is_file():
        doc = read_json(runs_path)
        for row in (doc.get("runs") or []) if isinstance(doc, dict) else []:
            if isinstance(row, dict) and isinstance(row.get("timestamp"), str):
                run_meta[str(row["timestamp"])] = row
                if row["timestamp"] not in stamps and (hist_root / str(row["timestamp"])).is_dir():
                    stamps.append(str(row["timestamp"]))
        stamps = sorted(set(stamps))
    ingested = 0
    last: dict[str, Any] | None = None
    prev: str | None = None
    schema_v = int(params.require("schema_version"))
    for stamp in stamps:
        maps = extract_classes(params, hist_root / stamp)
        status = str((run_meta.get(stamp) or {}).get("status") or "completed")
        counts = (run_meta.get(stamp) or {}).get("counts") or {}
        if not isinstance(counts, dict):
            counts = {}
        older = extract_classes(params, hist_root / prev) if prev else empty_maps()
        diff_doc = diff_maps(older, maps, schema_v, prev, stamp)
        last = ingest_maps(params, target_dir, target, stamp, status, counts, maps, diff_doc)
        ingested += 1
        prev = stamp
    if isinstance(last, dict) and "path" in last:
        last = {**last, "path": warehouse_filename(params)}
    return {"ok": True, "target": target, "ingested_runs": ingested, "last": last, "path": warehouse_filename(params)}


def _run_id(conn: sqlite3.Connection, stamp: str) -> int | None:
    row = conn.execute("SELECT run_id FROM runs WHERE stamp=?", (stamp,)).fetchone()
    return int(row["run_id"]) if row else None


def maps_for_run(params: Params, target_dir: Path, target: str, stamp: str) -> dict[str, dict[str, Any]]:
    path = open_bound(params, target_dir, target)
    with _connect(path, write=False) as conn:
        _ensure_schema(conn, params, target, allow_create=False)
        run_id = _run_id(conn, stamp)
        if run_id is None:
            return empty_maps()
        buckets = empty_maps()
        rows = conn.execute(
            "SELECT f.class, f.natural_key, v.payload_json, v.payload_hash "
            "FROM run_facts rf "
            "JOIN facts f ON f.fact_id = rf.fact_id "
            "JOIN fact_versions v ON v.version_id = rf.version_id "
            "WHERE rf.run_id=?",
            (run_id,),
        ).fetchall()
        for row in rows:
            raw = str(row["payload_json"] or "")
            digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
            if digest != str(row["payload_hash"] or ""):
                continue
            try:
                payload = json.loads(raw)
            except (json.JSONDecodeError, TypeError, ValueError):
                continue
            buckets[str(row["class"])][str(row["natural_key"])] = payload
        return buckets


def compare_runs(
    params: Params,
    target_dir: Path,
    target: str,
    from_ts: str | None,
    to_ts: str,
) -> dict[str, Any]:
    """Diff any two ingested runs for ONE target. Never reads another target."""
    schema_v = int(params.require("schema_version"))
    path = open_bound(params, target_dir, target)
    with _connect(path, write=False) as conn:
        _ensure_schema(conn, params, target, allow_create=False)
        cached = conn.execute(
            "SELECT payload_json FROM diffs WHERE from_stamp=? AND to_stamp=?",
            (from_ts or "", to_ts),
        ).fetchone()
        if cached is not None:
            try:
                doc = json.loads(cached["payload_json"])
                if isinstance(doc, dict):
                    return {"exists": True, "source": "warehouse", "target": target, **doc}
            except (json.JSONDecodeError, TypeError, ValueError):
                pass
    older = empty_maps() if not from_ts else maps_for_run(params, target_dir, target, from_ts)
    newer = maps_for_run(params, target_dir, target, to_ts)
    if from_ts and not any(older[c] for c in FACT_CLASSES):
        hist = target_dir / str(params.require("history_dirname")) / from_ts
        if hist.is_dir():
            older = extract_classes(params, hist)
    if not any(newer[c] for c in FACT_CLASSES):
        hist = target_dir / str(params.require("history_dirname")) / to_ts
        if hist.is_dir():
            newer = extract_classes(params, hist)
    payload = diff_maps(older, newer, schema_v, from_ts, to_ts)
    with _connect(path, write=True) as conn:
        _ensure_schema(conn, params, target, allow_create=True)
        conn.execute(
            "INSERT OR REPLACE INTO diffs(from_stamp, to_stamp, payload_json) VALUES (?,?,?)",
            (from_ts or "", to_ts, _canonical(payload)),
        )
    return {"exists": True, "source": "computed", "target": target, **payload}


def list_runs(params: Params, target_dir: Path, target: str) -> list[dict[str, Any]]:
    path = warehouse_path(params, target_dir)
    if not path.is_file():
        return []
    with _connect(path, write=False) as conn:
        _ensure_schema(conn, params, target, allow_create=False)
        rows = conn.execute(
            "SELECT stamp, status, counts_json, ingested_at FROM runs ORDER BY stamp ASC"
        ).fetchall()
        out: list[dict[str, Any]] = []
        for row in rows:
            try:
                counts = json.loads(row["counts_json"])
            except (json.JSONDecodeError, TypeError, ValueError):
                counts = {}
            out.append({
                "timestamp": row["stamp"],
                "status": row["status"],
                "counts": counts,
                "ingested_at": row["ingested_at"],
            })
        return out


def status(params: Params, target_dir: Path, target: str) -> dict[str, Any]:
    path = warehouse_path(params, target_dir)
    public_path = warehouse_filename(params)
    exists = path.is_file()
    if not exists:
        return {
            "exists": False,
            "target": target,
            "path": public_path,
            "isolated": True,
            "sealed": False,
            "runs": 0,
            "facts": {cls: 0 for cls in FACT_CLASSES},
        }
    with _connect(path, write=False) as conn:
        _ensure_schema(conn, params, target, allow_create=False)
        bound = conn.execute("SELECT value FROM meta WHERE key='target'").fetchone()
        hmac_row = conn.execute("SELECT value FROM meta WHERE key='hmac'").fetchone()
        run_n = conn.execute("SELECT COUNT(*) AS n FROM runs").fetchone()["n"]
        facts: dict[str, int] = {}
        for cls in FACT_CLASSES:
            facts[cls] = int(
                conn.execute("SELECT COUNT(*) AS n FROM facts WHERE class=?", (cls,)).fetchone()["n"]
            )
        return {
            "exists": True,
            "target": target,
            "bound_target": str(bound["value"]) if bound else None,
            "path": public_path,
            "isolated": True,
            "sealed": bool(hmac_row and hmac_row["value"]),
            "schema_version": SCHEMA_VERSION,
            "runs": int(run_n),
            "facts": facts,
        }


def host_timeline(params: Params, target_dir: Path, target: str) -> dict[str, dict[str, str]]:
    """host -> {first_seen, last_seen} from the hosts class (this target only)."""
    path = warehouse_path(params, target_dir)
    if not path.is_file():
        return {}
    with _connect(path, write=False) as conn:
        _ensure_schema(conn, params, target, allow_create=False)
        rows = conn.execute(
            "SELECT f.natural_key, r1.stamp AS first_seen, r2.stamp AS last_seen "
            "FROM facts f "
            "JOIN runs r1 ON r1.run_id = f.first_run_id "
            "JOIN runs r2 ON r2.run_id = f.last_run_id "
            "WHERE f.class='hosts'"
        ).fetchall()
        return {
            str(row["natural_key"]): {"first_seen": row["first_seen"], "last_seen": row["last_seen"]}
            for row in rows
        }


def facts_as_assets(params: Params, target_dir: Path, target: str, stamp: str) -> list[dict[str, Any]]:
    maps = maps_for_run(params, target_dir, target, stamp)
    rows: list[dict[str, Any]] = []
    for key, payload in (maps.get("hosts") or {}).items():
        if isinstance(payload, dict):
            row = dict(payload)
            row.setdefault("host", key)
            row["run"] = stamp
            rows.append(row)
    return rows


def enrich_assets(params: Params, target_dir: Path, target: str, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    timeline = host_timeline(params, target_dir, target)
    if not timeline:
        return rows
    out: list[dict[str, Any]] = []
    for row in rows:
        host = str(row.get("host") or "")
        extra = timeline.get(host) or {}
        if extra:
            out.append({**row, **extra})
        else:
            out.append(row)
    return out


def ensure_ingested(params: Params, target_dir: Path, target: str) -> dict[str, Any]:
    """Dashboard lazy fill: if JSON history exists but the warehouse is empty, rebuild."""
    path = warehouse_path(params, target_dir)
    hist = target_dir / str(params.require("history_dirname"))
    has_snaps = hist.is_dir() and any(d.is_dir() and _STAMP_RE.match(d.name) for d in hist.iterdir())
    if not has_snaps:
        return {"ok": True, "rebuilt": False, "reason": "no history snapshots"}
    if path.is_file():
        with _connect(path, write=False) as conn:
            try:
                _ensure_schema(conn, params, target, allow_create=False)
                n = int(conn.execute("SELECT COUNT(*) AS n FROM runs").fetchone()["n"])
            except WarehouseError:
                raise
            if n > 0:
                return {"ok": True, "rebuilt": False, "runs": n}
    return rebuild_from_history(params, target_dir, target)
