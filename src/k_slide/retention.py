"""Admin-only, fail-closed cleanup for K-Slide run artifacts."""

from __future__ import annotations

import json
import os
import hashlib
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .deletion import DeletionOutcome, DeletionReason, _operational_root, cleanup_operational_metadata, delete_workspace_run
from .errors import ErrorCode, KSlideError
from .paas import AuthorizedScopeContext
from .retention_policy import RetentionPolicy
from .storage import StorageArtifact, storage_path


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


def cleanup_expired_runs(
    root: Path,
    retention_policy: RetentionPolicy | Mapping[str, Any],
    *,
    now: datetime | None = None,
    dry_run: bool = False,
    hold_provider: Any | None = None,
    scope_context: AuthorizedScopeContext | None = None,
    operational_root: Path | None = None,
    central_operational_root: Path | None = None,
    audit_root: Path | None = None,
) -> dict[str, Any]:
    """Orchestrate KSA-12 content expiry through the KSA-13 lifecycle.

    The reference hold provider is deterministic qualification control only.
    A managed deployment must supply its authoritative records-control adapter.
    ``operational_metadata_retention_days`` is applied separately, after the
    content pass, and never used as a content-deletion cutoff.
    """

    try:
        policy = retention_policy if isinstance(retention_policy, RetentionPolicy) else RetentionPolicy.from_mapping(retention_policy, require_resolved=True)
        policy.require_resolved()
    except (TypeError, ValueError) as exc:
        raise KSlideError(ErrorCode.RETENTION_INVALID, "Invalid retention policy for content cleanup.", {"reason": type(exc).__name__}) from exc
    if not isinstance(scope_context, AuthorizedScopeContext) or scope_context.scope_ref != "workspace":
        raise KSlideError(ErrorCode.EXECUTION_CONFLICT, "Retention expiry requires an authorized workspace scope context.")
    if hold_provider is None:
        raise KSlideError(ErrorCode.LEGAL_HOLD_UNKNOWN, "Retention expiry requires an authoritative legal-hold provider.")
    roots = [value for value in (operational_root, central_operational_root, audit_root) if value is not None]
    if len({Path(value).expanduser().resolve() for value in roots}) > 1:
        raise KSlideError(ErrorCode.DELETION_INVALID, "Retention operational roots disagree.")
    if not roots:
        raise KSlideError(ErrorCode.DELETION_INVALID, "Retention expiry requires an explicit external operational root.")
    content_retention_days = policy.content_retention_days
    assert isinstance(content_retention_days, int)
    root = root.expanduser().resolve()
    selected_operational_root = _operational_root(roots[0], workspace_namespace=root)
    run_root = root / ".k-slide-runs"
    if run_root.is_symlink() or (run_root.exists() and not run_root.is_dir()):
        raise KSlideError(ErrorCode.RETENTION_REFUSED, "The K-Slide run root must be a real directory.", {"path": str(run_root)})
    cutoff = (now or datetime.now(timezone.utc)).astimezone(timezone.utc) - timedelta(days=content_retention_days)
    candidates: list[tuple[Path, datetime, str]] = []
    retained: list[dict[str, str]] = []
    for run in sorted(run_root.iterdir(), key=lambda item: item.name) if run_root.is_dir() else ():
        if run.name.startswith("_"):
            continue
        if run.is_symlink():
            raise KSlideError(ErrorCode.RETENTION_REFUSED, "Retention cleanup refuses symbolic-link run directories.", {"path": str(run)})
        if not run.is_dir():
            retained.append({"run_id": run.name, "reason": "not_a_directory"})
            continue
        _assert_safe_tree(run, run_root)
        state_path = storage_path(run, StorageArtifact.RUN_STATE, "RUN_STATE.json")
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
    planned: list[dict[str, str]] = []
    deletion_results: list[dict[str, Any]] = []
    for run, updated, phase in candidates:
        record = {"run_id": run.name, "phase": phase, "updated_at": updated.isoformat()}
        deletion_id = f"retention-{hashlib.sha256(f'workspace:{run.name}'.encode('utf-8')).hexdigest()[:32]}"
        result = delete_workspace_run(
            root,
            run_ref=run.name,
            deletion_id=deletion_id,
            scope_context=scope_context,
            reason=DeletionReason.RETENTION_EXPIRY,
            hold_provider=hold_provider,
            dry_run=dry_run,
            operational_root=selected_operational_root,
        )
        deletion_results.append(result.as_dict())
        if result.outcome is DeletionOutcome.COMPLETE:
            removed.append(record)
        elif result.outcome is DeletionOutcome.PLANNED:
            planned.append(record)
        else:
            retained.append({"run_id": run.name, "reason": f"deletion:{result.outcome.value.lower()}"})
    operational = cleanup_operational_metadata(
        root,
        policy,
        scope_context=scope_context,
        hold_provider=hold_provider,
        operational_root=selected_operational_root,
        now=now,
        dry_run=dry_run,
    )
    return {
        "status": "PASS",
        "dry_run": dry_run,
        "retention_policy": policy.as_dict(),
        "content_retention_days": content_retention_days,
        "cutoff": cutoff.isoformat(),
        "removed": removed,
        "planned": planned,
        "retained": retained,
        "deletions": deletion_results,
        "operational_metadata": operational,
    }
