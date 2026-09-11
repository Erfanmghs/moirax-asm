"""Operator credential store -- isolated from recon/ scan artifacts.

Single-operator SQLite database. Password is stored as scrypt (never
plaintext). Session tokens are stored as SHA-256 only. Idle timeout is
enforced server-side from last *touch* (operator click), not from
background API polling -- so log refresh cannot keep a session alive.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import sqlite3
import threading
import time
from pathlib import Path

IDLE_SECONDS = 15 * 60
MIN_PASSWORD_LEN = 12
MAX_PASSWORD_LEN = 256
_COOKIE = "asm_session"
_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 32

_lock = threading.Lock()
_conn: sqlite3.Connection | None = None
_conn_path: str | None = None

ROOT = Path(__file__).resolve().parents[1]


def cookie_name() -> str:
    return _COOKIE


def idle_seconds() -> int:
    return IDLE_SECONDS


def db_path() -> Path:
    override = str(os.environ.get("RECON_AUTH_DB") or "").strip()
    if override:
        return Path(override)
    return ROOT / "dashboard" / "auth" / "operator.sqlite"


def reset() -> None:
    """Close cached connection (tests)."""
    global _conn, _conn_path
    with _lock:
        if _conn is not None:
            try:
                _conn.close()
            except sqlite3.Error:
                pass
        _conn = None
        _conn_path = None


def _connect() -> sqlite3.Connection:
    global _conn, _conn_path
    path = db_path()
    key = str(path)
    if _conn is not None and _conn_path == key:
        return _conn
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    conn = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA secure_delete=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS operator (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            password_hash TEXT NOT NULL,
            created_at REAL NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY,
            created_at REAL NOT NULL,
            last_seen REAL NOT NULL
        )
        """
    )
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    _conn = conn
    _conn_path = key
    return conn


def _token_hash(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _scrypt(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=n,
        r=r,
        p=p,
        dklen=_SCRYPT_DKLEN,
    )


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = _scrypt(password, salt, _SCRYPT_N, _SCRYPT_R, _SCRYPT_P)
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        kind, n_s, r_s, p_s, salt_hex, dk_hex = stored.split("$")
        if kind != "scrypt":
            return False
        n, r, p = int(n_s), int(r_s), int(p_s)
        if n > 2**16 or r > 16 or p > 4:
            return False
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(dk_hex)
        got = _scrypt(password, salt, n, r, p)
        return secrets.compare_digest(got, expected)
    except (ValueError, TypeError, ArithmeticError):
        return False


def validate_new_password(password: str) -> str | None:
    if not isinstance(password, str):
        return "password required"
    if "\x00" in password:
        return "illegal password"
    if len(password) < MIN_PASSWORD_LEN:
        return f"password must be at least {MIN_PASSWORD_LEN} characters"
    if len(password) > MAX_PASSWORD_LEN:
        return "password too long"
    return None


def has_operator() -> bool:
    with _lock:
        row = _connect().execute("SELECT 1 FROM operator WHERE id = 1").fetchone()
    return row is not None


def create_operator(password: str) -> None:
    err = validate_new_password(password)
    if err:
        raise ValueError(err)
    digest = hash_password(password)
    now = time.time()
    with _lock:
        conn = _connect()
        conn.execute("BEGIN IMMEDIATE")
        try:
            exists = conn.execute("SELECT 1 FROM operator WHERE id = 1").fetchone()
            if exists:
                conn.execute("ROLLBACK")
                raise FileExistsError("operator already exists")
            conn.execute(
                "INSERT INTO operator (id, password_hash, created_at) VALUES (1, ?, ?)",
                (digest, now),
            )
            conn.execute("COMMIT")
        except FileExistsError:
            raise
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise


def check_operator_password(password: str) -> bool:
    with _lock:
        row = _connect().execute("SELECT password_hash FROM operator WHERE id = 1").fetchone()
    if not row:
        return False
    return verify_password(password, str(row[0]))


def replace_operator_password(password: str) -> None:
    err = validate_new_password(password)
    if err:
        raise ValueError(err)
    digest = hash_password(password)
    now = time.time()
    with _lock:
        conn = _connect()
        conn.execute(
            """
            INSERT INTO operator (id, password_hash, created_at) VALUES (1, ?, ?)
            ON CONFLICT(id) DO UPDATE SET password_hash = excluded.password_hash
            """,
            (digest, now),
        )


def create_session() -> str:
    raw = secrets.token_urlsafe(32)
    now = time.time()
    with _lock:
        _connect().execute(
            "INSERT INTO sessions (token_hash, created_at, last_seen) VALUES (?, ?, ?)",
            (_token_hash(raw), now, now),
        )
    return raw


def session_ok(raw: str) -> bool:
    if not raw or not isinstance(raw, str) or len(raw) > 128:
        return False
    now = time.time()
    digest = _token_hash(raw)
    with _lock:
        row = _connect().execute(
            "SELECT last_seen FROM sessions WHERE token_hash = ?",
            (digest,),
        ).fetchone()
    if not row:
        return False
    last_seen = float(row[0])
    return (now - last_seen) <= IDLE_SECONDS


def touch_session(raw: str) -> bool:
    if not session_ok(raw):
        return False
    now = time.time()
    with _lock:
        cur = _connect().execute(
            "UPDATE sessions SET last_seen = ? WHERE token_hash = ?",
            (now, _token_hash(raw)),
        )
        return cur.rowcount == 1


def revoke_session(raw: str) -> None:
    if not raw:
        return
    with _lock:
        _connect().execute("DELETE FROM sessions WHERE token_hash = ?", (_token_hash(raw),))


def revoke_all_sessions() -> None:
    with _lock:
        _connect().execute("DELETE FROM sessions")


def purge_expired() -> None:
    cutoff = time.time() - IDLE_SECONDS
    with _lock:
        _connect().execute("DELETE FROM sessions WHERE last_seen < ?", (cutoff,))
