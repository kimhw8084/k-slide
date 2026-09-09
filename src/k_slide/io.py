"""Atomic, bounded filesystem helpers."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from .errors import ErrorCode, KSlideError


def atomic_write_bytes(path: Path, data: bytes, *, mode: int | None = None) -> None:
    """Write a file beside its final path and replace it atomically."""

    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if mode is not None:
            os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def atomic_write_text(path: Path, text: str, *, mode: int | None = 0o600) -> None:
    atomic_write_bytes(path, text.encode("utf-8"), mode=mode)


def atomic_write_json(path: Path, value: Any, *, mode: int | None = None) -> None:
    atomic_write_text(path, json.dumps(value, indent=2, ensure_ascii=False) + "\n", mode=mode)


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise KSlideError(
            ErrorCode.STATE_CORRUPT,
            f"Could not read structured state: {path.name}",
            {"path": str(path), "reason": str(exc)},
        ) from exc


def ensure_within(candidate: Path, root: Path) -> Path:
    candidate = candidate.resolve()
    root = root.resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise KSlideError(
            ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT,
            "The requested path is outside the allowed K-Slide root.",
            {"path": str(candidate), "root": str(root)},
        ) from exc
    return candidate
