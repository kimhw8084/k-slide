"""Run creation and immutable input snapshots."""

from __future__ import annotations

import json
import shutil
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from . import SCHEMA_VERSION
from .errors import ErrorCode, KSlideError
from .environment import RunEnvironmentIdentity
from .execution import ExecutionProfile, WorkspaceRunStore, new_execution_job, sync_workspace_execution
from .host_adapter import HostInputReference, validate_host_inputs
from .io import atomic_write_json, atomic_write_text
from .queue import create_queue, save_queue
from .policy import COMPLETION_POLICY
from .runtime import discover_runtime
from .redaction import sanitize_operational
from .security import InputArtifact, SUPPORTED_EXTENSIONS, sha256_file, validate_input
from .session import bind_session
from .state import RunPhase, RunState, save_state


def _utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def _run_id() -> str:
    return f"k-slide-{_utc_stamp()}-{uuid.uuid4().hex[:6]}"


def _input_candidates(root: Path, explicit_paths: Iterable[str]) -> list[Path]:
    values = list(explicit_paths)
    if values:
        candidates: list[Path] = []
        for value in values:
            path = Path(value).expanduser()
            if path.is_dir():
                candidates.extend(
                    candidate
                    for candidate in path.rglob("*")
                    if candidate.is_file() and candidate.suffix.lower() in SUPPORTED_EXTENSIONS
                )
            else:
                candidates.append(path)
        return sorted(
            candidates,
            key=lambda path: [int(part) if part.isdigit() else part.lower() for part in path.name.replace("-", " ").split()],
        )
    input_dir = root / ".k-slide-input"
    if not input_dir.is_dir():
        return []
    return sorted(
        [path for path in input_dir.rglob("*") if path.is_file() and path.suffix.lower() in SUPPORTED_EXTENSIONS],
        key=lambda path: [int(part) if part.isdigit() else part.lower() for part in path.name.replace("-", " ").split()],
    )


def _artifact_manifest(artifacts: list[InputArtifact]) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "input_count": len(artifacts),
        "inputs": [{"snapshot_id": f"source-{index:03d}", **artifact.as_dict()} for index, artifact in enumerate(artifacts, start=1)],
        "snapshot_policy": "immutable_copy_hashed_at_prepare",
    }


def _write_recovery(run_dir: Path, run_id: str) -> None:
    atomic_write_text(
        run_dir / "RUN_RECOVERY_GUIDE.md",
        "# K-Slide Recovery Guide\n\n"
        f"Run folder: `.k-slide-runs/{run_id}`\n\n"
        "If the session stops unexpectedly, run:\n\n"
        "```text\n/k-slide-status\n/k-slide-continue\n```\n\n"
        "For explicit debugging, the run ID is available above.\n",
    )


def _write_compatibility_artifacts(run_dir: Path, run_id: str, artifacts: list[InputArtifact], *, host_inputs: bool = False) -> None:
    atomic_write_json(run_dir / "RUN_MANIFEST.json", _artifact_manifest(artifacts), mode=0o600)
    inventory = {
        "schema_version": SCHEMA_VERSION,
        "status": "validated",
        "input_count": len(artifacts),
        "input_files": [artifact.source_name for artifact in artifacts],
        "input_sha256": [artifact.sha256 for artifact in artifacts],
        "supported_extensions": sorted(SUPPORTED_EXTENSIONS),
        "attachments": {"supported": host_inputs, "reason": "validated local host references" if host_inputs else "No host references were supplied; using the local compatibility folder."},
    }
    atomic_write_json(run_dir / "00_input_inventory.json", inventory, mode=0o600)
    lines = ["# K-Slide Run Manifest", "", f"Run ID: {run_id}", f"Input count: {len(artifacts)}", ""]
    lines.extend(f"- {artifact.source_name} ({artifact.kind}, sha256 `{artifact.sha256}`)" for artifact in artifacts)
    atomic_write_text(run_dir / "00_run_manifest.md", "\n".join(lines) + "\n")
    atomic_write_json(
        run_dir / "ARTIFACT_MANIFEST.json",
        {
            "schema_version": SCHEMA_VERSION,
            "required_for_complete": list(COMPLETION_POLICY.required_artifacts),
            "canonical_directories": ["inputs", "normalized", "native", "regions", "evidence", "ir", "verification"],
            "compatibility_artifacts": ["00_run_manifest.md", "00_input_inventory.json", "RUN_STATE.json", "EXECUTION_JOB.json", "RUN_RECOVERY_GUIDE.md"],
        },
        mode=0o600,
    )
    atomic_write_json(run_dir / "metrics.json", {"slides_processed": 0, "tables_processed": 0, "regions_processed": 0, "numbers_verified": 0, "unresolved_count": 0, "repair_count": 0, "phase": "INPUT_VALIDATED"}, mode=0o600)


def _workspace_environment_identity(root: Path) -> RunEnvironmentIdentity:
    """Create a source-free local binding when no deployment supplies one."""

    try:
        revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(root), capture_output=True, text=True, timeout=5, check=True).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        revision = ""
    if revision and len(revision) == 40 and all(char in "0123456789abcdef" for char in revision):
        runtime_ref = f"workspace-source-{revision[:16]}"
    else:
        runtime_ref = "workspace-unpinned"
    return RunEnvironmentIdentity.legacy_reference(
        runtime_ref=runtime_ref,
        model_identity="workspace-model-unresolved",
        ocr_identity="workspace-ocr-unresolved",
        termbase_identity="workspace-termbase-unresolved",
        source_revision=revision or None,
    )


def prepare_run(
    root: Path,
    *,
    mode: str = "standard",
    explicit_paths: Iterable[str] = (),
    session_id: str | None = None,
    perform_processing: bool = False,
    host_input_refs: Iterable[HostInputReference | dict[str, Any]] = (),
    approved_root: Path | None = None,
    environment_identity: RunEnvironmentIdentity | None = None,
) -> Path:
    """Create an immutable run, returning its directory even for failed input.

    ``mode`` is retained only as internal/admin compatibility metadata for
    older run records. The host adapter omits it, uses the standard path, and
    no mode value selects a separate production behavior path.
    """

    root = root.expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    run_root = root / ".k-slide-runs"
    input_dir = root / ".k-slide-input"
    run_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    input_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    run_root.chmod(0o700)
    input_dir.chmod(0o700)
    run_id = _run_id()
    run_dir = run_root / run_id
    run_dir.mkdir(mode=0o700)
    run_dir.chmod(0o700)
    for name in ("inputs", "normalized", "native", "regions", "evidence", "ir", "translations", "verification"):
        directory = run_dir / name
        directory.mkdir(mode=0o700)
        directory.chmod(0o700)

    state = RunState(run_id=run_id, mode=mode, session_key=bind_session(run_root, session_id, run_id), next_action="Validate inputs")
    save_state(run_dir, state)
    WorkspaceRunStore(run_dir).create(
        new_execution_job(
            run_id,
            profile=ExecutionProfile.WORKSPACE_LOCAL,
            scope_ref="workspace",
            store_ref=f"workspace-{run_id}",
            engine_state_revision=state.revision,
            environment_identity=environment_identity or _workspace_environment_identity(root),
        )
    )
    _write_recovery(run_dir, run_id)

    try:
        raw_host_refs = tuple(
            reference if isinstance(reference, HostInputReference) else HostInputReference.from_mapping(reference)
            for reference in host_input_refs
        )
    except KSlideError as exc:
        state.transition(RunPhase.FAILED_INPUT, next_action="Correct the input and retry /k-slide.", error_code=exc.code.value, error_message=exc.message)
        save_state(run_dir, state)
        sync_workspace_execution(run_dir)
        atomic_write_json(run_dir / "00_input_inventory.json", {"schema_version": SCHEMA_VERSION, "status": "failed_input", "error": sanitize_operational(exc.as_dict(), roots=(root,))}, mode=0o600)
        atomic_write_text(run_dir / "RUN_FAILED.md", f"# FAILED\n\n{exc.message}\n\nError code: `{exc.code.value}`\n")
        return run_dir
    candidates = [] if raw_host_refs else _input_candidates(root, explicit_paths)
    host_inputs = bool(raw_host_refs)
    if not raw_host_refs and not candidates:
        state.transition(RunPhase.FAILED_INPUT, next_action="Add a supported file to .k-slide-input/ or pass an explicit path.", error_code=ErrorCode.INPUT_NOT_FOUND.value, error_message="No supported input files were found.")
        save_state(run_dir, state)
        sync_workspace_execution(run_dir)
        atomic_write_json(run_dir / "00_input_inventory.json", {"schema_version": SCHEMA_VERSION, "status": "failed_no_input", "input_count": 0, "supported_extensions": sorted(SUPPORTED_EXTENSIONS)}, mode=0o600)
        atomic_write_text(run_dir / "RUN_FAILED.md", "# FAILED\n\nNo supported input files were found. Add a slide image, PDF, or PPTX and run `/k-slide` again.\n")
        return run_dir

    artifacts: list[InputArtifact] = []
    try:
        if raw_host_refs:
            artifacts = validate_host_inputs(raw_host_refs, approved_root=approved_root or root)
        else:
            for candidate in candidates:
                # Explicit paths may be outside the worktree; they are read once and copied into the run.
                artifacts.append(validate_input(candidate))
    except KSlideError as exc:
        state.transition(RunPhase.FAILED_INPUT, next_action="Correct the input and retry /k-slide.", error_code=exc.code.value, error_message=exc.message)
        save_state(run_dir, state)
        sync_workspace_execution(run_dir)
        atomic_write_json(run_dir / "00_input_inventory.json", {"schema_version": SCHEMA_VERSION, "status": "failed_input", "error": sanitize_operational(exc.as_dict(), roots=(root,))}, mode=0o600)
        atomic_write_text(run_dir / "RUN_FAILED.md", f"# FAILED\n\n{exc.message}\n\nError code: `{exc.code.value}`\n")
        return run_dir

    for index, artifact in enumerate(artifacts, start=1):
        destination = run_dir / "inputs" / f"source-{index:03d}{artifact.extension}"
        shutil.copyfile(artifact.source_path, destination)
        destination.chmod(0o600)
        if sha256_file(destination) != artifact.sha256:
            state.transition(RunPhase.FAILED_RUNTIME, next_action="Retry after checking local storage.", error_code="KSLIDE_SNAPSHOT_HASH_MISMATCH", error_message="Immutable input copy failed hash verification.")
            save_state(run_dir, state)
            sync_workspace_execution(run_dir)
            atomic_write_text(run_dir / "RUN_FAILED.md", "# FAILED\n\nImmutable input snapshot hash verification failed.\n")
            return run_dir

    atomic_write_json(run_dir / "inputs" / "checksums.json", _artifact_manifest(artifacts), mode=0o600)
    _write_compatibility_artifacts(run_dir, run_id, artifacts, host_inputs=host_inputs)
    runtime = discover_runtime()
    atomic_write_json(run_dir / "RUNTIME_METADATA.json", runtime.as_dict(), mode=0o600)
    state.input_count = len(artifacts)
    queue = create_queue(run_id, input_count=len(artifacts), now=state.updated_at)
    save_queue(run_dir, queue)
    state.current_work_unit = None
    state.transition(RunPhase.INPUT_VALIDATED, next_action="Normalize documents and create evidence work units.")
    save_state(run_dir, state)
    bind_session(run_root, session_id, run_id)
    if perform_processing:
        from .extraction import extract_run
        from .normalization import normalize_run

        try:
            normalize_run(run_dir)
            extract_run(run_dir)
        finally:
            sync_workspace_execution(run_dir)
    else:
        sync_workspace_execution(run_dir)
    return run_dir
