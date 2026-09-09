"""Admin-only, fail-closed cleanup for K-Slide run artifacts."""

from __future__ import annotations

import json
import os
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .errors import ErrorCode, KSlideError


_TERMINAL_PHASES = {"COMPLETE", "FAILED_INPUT", "FAILED_RUNTIME", "FAILED_NORMALIZATION", "FAILED_EXTRACTION", "FAILED_SCHEMA", "FAILED_INTERNAL"}


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc)


def _assert_safe_tree(path: Path, root: Path) -> None:
    if path.is_symlink():
        raise KSlideError(ErrorCode.RETENTION_REFUSED, "Retention cleanup refuses symbolic-link run paths.", {"path": str(path)})
    try:
        path.resolve(strict=True).relative_to(root.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise KSlideError(ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT, "Retention cleanup path escaped the run root.", {"path": str(path), "root": str(root)}) from exc
    for directory, names, files in os.walk(path, followlinks=False):
        for name in (*names, *files):
            candidate = Path(directory) / name
            if candidate.is_symlink():
                raise KSlideError(ErrorCode.RETENTION_REFUSED, "Retention cleanup refuses symbolic links inside a run.", {"path": str(candidate)})


def cleanup_expired_runs(root: Path, retention_days: int, *, now: datetime | None = None, dry_run: bool = False) -> dict[str, Any]:
    """Delete only old terminal runs below ``root/.k-slide-runs``.

    Active/in-progress runs are always retained.  The function validates every
    candidate before deleting any run, so a symlink attack fails closed rather
    than partially cleaning the directory.
    """

    if isinstance(retention_days, bool) or not isinstance(retention_days, int) or retention_days <= 0:
        raise KSlideError(ErrorCode.RETENTION_INVALID, "retention_days must be a positive integer.", {"retention_days": retention_days})
    root = root.expanduser().resolve()
    run_root = root / ".k-slide-runs"
    if not run_root.exists() and not run_root.is_symlink():
        return {"status": "PASS", "dry_run": dry_run, "retention_days": retention_days, "removed": [], "retained": [], "cutoff": None}
    if run_root.is_symlink() or not run_root.is_dir():
        raise KSlideError(ErrorCode.RETENTION_REFUSED, "The K-Slide run root must be a real directory.", {"path": str(run_root)})
    cutoff = (now or datetime.now(timezone.utc)).astimezone(timezone.utc) - timedelta(days=retention_days)
    candidates: list[tuple[Path, datetime, str]] = []
    retained: list[dict[str, str]] = []
    for run in sorted(run_root.iterdir(), key=lambda item: item.name):
        if run.is_symlink():
            raise KSlideError(ErrorCode.RETENTION_REFUSED, "Retention cleanup refuses symbolic-link run directories.", {"path": str(run)})
        if not run.is_dir():
            retained.append({"run_id": run.name, "reason": "not_a_directory"})
            continue
        _assert_safe_tree(run, run_root)
        state_path = run / "RUN_STATE.json"
        state: dict[str, Any] = {}
        if state_path.is_file():
            try:
                loaded = json.loads(state_path.read_text(encoding="utf-8"))
                state = loaded if isinstance(loaded, dict) else {}
            except (OSError, UnicodeError, json.JSONDecodeError):
                retained.append({"run_id": run.name, "reason": "state_unreadable"})
                continue
        phase = str(state.get("phase", state.get("status", "UNKNOWN")))
        updated = _parse_time(state.get("updated_at")) or datetime.fromtimestamp(run.stat().st_mtime, timezone.utc)
        if phase not in _TERMINAL_PHASES:
            retained.append({"run_id": run.name, "reason": f"active:{phase}"})
        elif updated >= cutoff:
            retained.append({"run_id": run.name, "reason": "within_retention"})
        else:
            candidates.append((run, updated, phase))
    removed: list[dict[str, str]] = []
    for run, updated, phase in candidates:
        record = {"run_id": run.name, "phase": phase, "updated_at": updated.isoformat()}
        if not dry_run:
            shutil.rmtree(run)
        removed.append(record)
    return {"status": "PASS", "dry_run": dry_run, "retention_days": retention_days, "cutoff": cutoff.isoformat(), "removed": removed, "retained": retained}
