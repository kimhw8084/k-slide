"""Run creation and immutable input snapshots."""

from __future__ import annotations

import json
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from . import SCHEMA_VERSION
from .errors import ErrorCode, KSlideError
from .io import atomic_write_json, atomic_write_text
from .queue import create_queue, save_queue
from .policy import COMPLETION_POLICY
from .runtime import discover_runtime
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
        "inputs": [artifact.as_dict() for artifact in artifacts],
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


def _write_compatibility_artifacts(run_dir: Path, run_id: str, artifacts: list[InputArtifact]) -> None:
    atomic_write_json(run_dir / "RUN_MANIFEST.json", _artifact_manifest(artifacts), mode=0o600)
    inventory = {
        "schema_version": SCHEMA_VERSION,
        "status": "validated",
        "input_count": len(artifacts),
        "input_files": [artifact.source_name for artifact in artifacts],
        "input_sha256": [artifact.sha256 for artifact in artifacts],
        "supported_extensions": sorted(SUPPORTED_EXTENSIONS),
        "attachments": {"supported": False, "reason": "OpenCode attachment materialization is not yet exposed by this runtime."},
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
            "compatibility_artifacts": ["00_run_manifest.md", "00_input_inventory.json", "RUN_STATE.json", "RUN_RECOVERY_GUIDE.md"],
        },
        mode=0o600,
    )
    atomic_write_json(run_dir / "metrics.json", {"slides_processed": 0, "tables_processed": 0, "regions_processed": 0, "numbers_verified": 0, "unresolved_count": 0, "repair_count": 0, "phase": "INPUT_VALIDATED"}, mode=0o600)


def prepare_run(root: Path, *, mode: str = "smart", explicit_paths: Iterable[str] = (), session_id: str | None = None, perform_processing: bool = False) -> Path:
    """Create an immutable run, returning its directory even for a failed input run."""

    root = root.expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    run_root = root / ".k-slide-runs"
    input_dir = root / ".k-slide-input"
    run_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    input_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    run_id = _run_id()
    run_dir = run_root / run_id
    run_dir.mkdir(mode=0o700)
    for name in ("inputs", "normalized", "native", "regions", "evidence", "ir", "translations", "verification"):
        (run_dir / name).mkdir(mode=0o700)

    state = RunState(run_id=run_id, mode=mode, session_key=bind_session(run_root, session_id, run_id), next_action="Validate inputs")
    save_state(run_dir, state)
    _write_recovery(run_dir, run_id)

    candidates = _input_candidates(root, explicit_paths)
    if not candidates:
        state.transition(RunPhase.FAILED_INPUT, next_action="Add a supported file to .k-slide-input/ or pass an explicit path.", error_code=ErrorCode.INPUT_NOT_FOUND.value, error_message="No supported input files were found.")
        save_state(run_dir, state)
        atomic_write_json(run_dir / "00_input_inventory.json", {"schema_version": SCHEMA_VERSION, "status": "failed_no_input", "input_count": 0, "supported_extensions": sorted(SUPPORTED_EXTENSIONS)}, mode=0o600)
        atomic_write_text(run_dir / "RUN_FAILED.md", "# FAILED\n\nNo supported input files were found. Add a slide image, PDF, or PPTX and run `/k-slide` again.\n")
        return run_dir

    artifacts: list[InputArtifact] = []
    try:
        for candidate in candidates:
            # Explicit paths may be outside the worktree; they are read once and copied into the run.
            artifacts.append(validate_input(candidate))
    except KSlideError as exc:
        state.transition(RunPhase.FAILED_INPUT, next_action="Correct the input and retry /k-slide.", error_code=exc.code.value, error_message=exc.message)
        save_state(run_dir, state)
        atomic_write_json(run_dir / "00_input_inventory.json", {"schema_version": SCHEMA_VERSION, "status": "failed_input", "error": exc.as_dict()}, mode=0o600)
        atomic_write_text(run_dir / "RUN_FAILED.md", f"# FAILED\n\n{exc.message}\n\nError code: `{exc.code.value}`\n")
        return run_dir

    for index, artifact in enumerate(artifacts, start=1):
        destination = run_dir / "inputs" / f"source-{index:03d}{artifact.extension}"
        shutil.copyfile(artifact.source_path, destination)
        destination.chmod(0o600)
        if sha256_file(destination) != artifact.sha256:
            state.transition(RunPhase.FAILED_RUNTIME, next_action="Retry after checking local storage.", error_code="KSLIDE_SNAPSHOT_HASH_MISMATCH", error_message="Immutable input copy failed hash verification.")
            save_state(run_dir, state)
            atomic_write_text(run_dir / "RUN_FAILED.md", "# FAILED\n\nImmutable input snapshot hash verification failed.\n")
            return run_dir

    atomic_write_json(run_dir / "inputs" / "checksums.json", _artifact_manifest(artifacts), mode=0o600)
    _write_compatibility_artifacts(run_dir, run_id, artifacts)
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

        normalize_run(run_dir)
        extract_run(run_dir)
    return run_dir
