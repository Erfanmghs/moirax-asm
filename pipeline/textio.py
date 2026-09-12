"""Atomic text-file writes (forge outputs)."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path


def atomic_write_text(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o755)
    except OSError:
        pass
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.replace(tmp_name, path)
        # mkstemp creates 0600 files; dashboard docker often runs as root, so
        # the host operator must still be able to read forge outputs (git,
        # tests, the SPA).
        try:
            os.chmod(path, 0o644)
        except OSError:
            pass
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    return path


def read_lines(path: Path) -> list[str]:
    if not path.is_file():
        return []
    return path.read_text(encoding="utf-8", errors="replace").splitlines()


def tail_lines(path: Path, n: int, max_bytes: int = 262144) -> list[str]:
    """Return the last ``n`` lines by reading only the file tail (bounded).

    Avoids loading multi-MB logs into RAM just to slice the last few lines.
    Reads at most ``max_bytes`` from EOF; if the window does not start at byte
    0 the first (possibly partial) line is dropped.
    """
    if n <= 0 or not path.is_file():
        return []
    try:
        size = path.stat().st_size
    except OSError:
        return []
    read_from = max(0, size - max(0, int(max_bytes)))
    try:
        with path.open("rb") as handle:
            if read_from:
                handle.seek(read_from)
            data = handle.read()
    except OSError:
        return []
    lines = data.decode("utf-8", errors="replace").splitlines()
    if read_from and lines:
        lines = lines[1:]
    return lines[-n:]


def read_line_window(path: Path, offset: int, limit: int, nonempty: bool = False) -> tuple[list[str], int]:
    """Stream a line slice without loading the whole file into RAM.

    Returns (chunk, total_so_far). total_so_far is the number of counted
    lines (optionally skipping blanks) after reading to EOF, so callers can
    still report `total` for the SPA offset jump.
    """
    if not path.is_file():
        return [], 0
    start = max(0, int(offset))
    take = max(1, int(limit))
    chunk: list[str] = []
    total = 0
    with path.open(encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            line = raw.rstrip("\n\r")
            if nonempty and not line.strip():
                continue
            if start <= total < start + take:
                chunk.append(line)
            total += 1
    return chunk, total
