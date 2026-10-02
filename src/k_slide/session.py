"""Session-to-run binding with safe latest-run fallback."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from .errors import KSlideError
from .io import atomic_write_json, read_json
from .state import RunPhase, load_state
from .storage import StorageArtifact, StorageLayout, workspace_mutation_guard


def session_key(session_id: str | None) -> str | None:
    if not session_id:
        return None
    return hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:32]


def bind_session(run_root: Path, session_id: str | None, run_id: str) -> str | None:
    key = session_key(session_id)
    if key is None:
        return None
    workspace_mutation_guard(Path(run_root) / run_id)
    layout = StorageLayout.for_workspace_root(run_root.parent)
    session_path = layout.path(StorageArtifact.SESSION_BINDING, f"_sessions/{key}.json", create_parent=True)
    atomic_write_json(session_path, {"session_key": key, "run_id": run_id})
    return key


def _run_dirs(run_root: Path) -> list[Path]:
    if run_root.is_symlink() or not run_root.is_dir():
        return []
    return sorted(
        [path for path in run_root.iterdir() if not path.is_symlink() and path.is_dir() and re.fullmatch(r"k-slide-[A-Za-z0-9_.:-]{1,120}", path.name)],
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )


def recent_runs(run_root: Path, *, session_id: str | None = None, limit: int = 20) -> list[dict]:
    """Source-free discovery inside the host's already isolated workspace.

    Hosted sessions only see their current binding. No-session access has the
    same local/operator authority as resolve_run, never company-wide access.
    Artifact opening still rechecks the presentation and completion contract.
    """

    from .queue import WorkUnitStatus, load_queue

    if not 1 <= limit <= 100:
        raise ValueError("Run listing limit must be between 1 and 100.")
    if run_root.is_symlink():
        return []
    if session_id is not None:
        bound = resolve_run(run_root, session_id=session_id)
        candidates = [bound] if bound else []
    else:
        candidates = _run_dirs(run_root)
    values = []
    for candidate in candidates:
        try:
            state = load_state(candidate)
            if state.run_id != candidate.name or state.deletion_fence is not None:
                continue
            try:
                queue = load_queue(candidate)
                queue_valid = queue.run_id == state.run_id
            except (KSlideError, KeyError, TypeError, ValueError, OSError):
                queue = None
                queue_valid = False
            units = queue.work_units if queue is not None and queue_valid else ()
            values.append({
                "run_id": state.run_id,
                "phase": state.phase.value,
                "updated_at": state.updated_at,
                "input_count": max(0, state.input_count),
                "progress_available": queue_valid,
                "total_units": len(units),
                "verified_units": sum(unit.status is WorkUnitStatus.VERIFIED for unit in units),
                "review_units": sum(unit.status is WorkUnitStatus.NEEDS_REVIEW for unit in units),
            })
        except (KSlideError, KeyError, TypeError, ValueError, OSError):
            continue
        if len(values) >= limit:
            break
    return values


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
    """Resolve a run without allowing a hosted session to cross its binding.

    A supplied session ID is a routing identifier, not an authority source.
    Once a binding exists, every explicit run selection must match it. An
    unbound session is intentionally not allowed to fall back to another
    session's latest or incomplete run. The no-session form remains the
    explicit local/operator compatibility path.
    """

    if run_root.is_symlink():
        return None
    run_root = run_root.resolve()
    bound_run: Path | None = None
    has_session_binding = False
    key = session_key(session_id)
    if key:
        mapping = StorageLayout.for_workspace_root(run_root.parent).path(StorageArtifact.SESSION_BINDING, f"_sessions/{key}.json")
        if mapping.is_file():
            has_session_binding = True
            try:
                run_id = read_json(mapping)["run_id"]
                if not isinstance(run_id, str):
                    return None
                candidate = (run_root / run_id).resolve()
                if candidate.is_dir() and candidate.parent == run_root:
                    bound_run = candidate
            except (KSlideError, KeyError, TypeError, ValueError, OSError):
                return None

    if explicit:
        candidate = Path(explicit)
        candidates = [candidate] if candidate.is_absolute() else [run_root.parent / candidate, run_root / candidate]
        for candidate_path in candidates:
            candidate_path = candidate_path.resolve()
            if candidate_path.is_dir() and candidate_path.parent == run_root:
                if session_id is not None and (not has_session_binding or bound_run is None or candidate_path != bound_run):
                    return None
                return candidate_path
        return None

    if key:
        return bound_run

    runs = _run_dirs(run_root)
    incomplete = incomplete_runs(run_root)
    if len(incomplete) == 1:
        return incomplete[0]
    if len(incomplete) > 1:
        return None
    return (runs or [None])[0]
