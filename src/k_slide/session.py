"""Session-to-run binding with safe latest-run fallback."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from .errors import KSlideError
from .io import atomic_write_json, read_json
from .state import RunPhase, load_state
from .storage import StorageArtifact, StorageLayout, ensure_workspace_mutation_allowed


def session_key(session_id: str | None) -> str | None:
    if not session_id:
        return None
    return hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:32]


def bind_session(run_root: Path, session_id: str | None, run_id: str) -> str | None:
    key = session_key(session_id)
    if key is None:
        return None
    ensure_workspace_mutation_allowed(Path(run_root) / run_id)
    layout = StorageLayout.for_workspace_root(run_root.parent)
    session_path = layout.path(StorageArtifact.SESSION_BINDING, f"_sessions/{key}.json", create_parent=True)
    atomic_write_json(session_path, {"session_key": key, "run_id": run_id})
    return key


def _run_dirs(run_root: Path) -> list[Path]:
    if not run_root.is_dir():
        return []
    return sorted(
        [path for path in run_root.iterdir() if path.is_dir() and path.name != "_sessions" and re.match(r"^k-slide-", path.name)],
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )


def incomplete_runs(run_root: Path) -> list[Path]:
    values: list[Path] = []
    for candidate in _run_dirs(run_root):
        try:
            state = load_state(candidate)
        except (KSlideError, KeyError, TypeError, ValueError, OSError):
            continue
        if not state.terminal:
            values.append(candidate)
    return values


def resolve_run(run_root: Path, *, explicit: str | None = None, session_id: str | None = None) -> Path | None:
    """Resolve explicit, current-session, then latest incomplete/latest run."""

    run_root = run_root.resolve()
    if explicit:
        candidate = Path(explicit)
        candidates = [candidate] if candidate.is_absolute() else [run_root.parent / candidate, run_root / candidate]
        for candidate_path in candidates:
            candidate_path = candidate_path.resolve()
            if candidate_path.is_dir() and candidate_path.parent == run_root:
                return candidate_path
        return None

    key = session_key(session_id)
    if key:
        mapping = StorageLayout.for_workspace_root(run_root.parent).path(StorageArtifact.SESSION_BINDING, f"_sessions/{key}.json")
        if mapping.is_file():
            try:
                run_id = str(read_json(mapping)["run_id"])
                candidate = run_root / run_id
                if candidate.is_dir():
                    return candidate
            except (KSlideError, KeyError, TypeError, ValueError, OSError):
                pass

    runs = _run_dirs(run_root)
    incomplete = incomplete_runs(run_root)
    if len(incomplete) == 1:
        return incomplete[0]
    if len(incomplete) > 1:
        return None
    return (runs or [None])[0]
