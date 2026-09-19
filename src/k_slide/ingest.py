"""Run creation and immutable input snapshots."""

from __future__ import annotations

import json
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from . import SCHEMA_VERSION
from .classification_policy import (
    ClassificationAdmission,
    DEFAULT_CLASSIFICATION,
    InferenceDataUsePolicy,
    admit_classifications,
    load_inference_data_use_policy,
)
from .errors import ErrorCode, KSlideError
from .environment import RunEnvironmentIdentity, resolve_effective_environment
from .execution import ExecutionProfile, WorkspaceRunStore, new_execution_job, sync_workspace_execution
from .host_adapter import HostInputReference, validate_host_inputs
from .io import atomic_write_json, atomic_write_text
from .queue import create_queue, save_queue
from .policy import COMPLETION_POLICY
from .runtime import discover_runtime
from .redaction import safe_diagnostic_text_or_placeholder, sanitize_operational
from .security import InputArtifact, SUPPORTED_EXTENSIONS, sha256_file, validate_input
from .session import bind_session
from .storage import StorageArtifact, StorageLayout, StoragePlane, storage_path
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


def _artifact_manifest(artifacts: list[InputArtifact], *, classification_admission: ClassificationAdmission | None = None) -> dict[str, Any]:
    value = {
        "schema_version": SCHEMA_VERSION,
        "input_count": len(artifacts),
        "inputs": [{"snapshot_id": f"source-{index:03d}", **artifact.as_dict()} for index, artifact in enumerate(artifacts, start=1)],
        "snapshot_policy": "immutable_copy_hashed_at_prepare",
    }
    if classification_admission is not None:
        value["classification_admission"] = classification_admission.as_dict()
    return value


def _write_recovery(run_dir: Path, run_id: str) -> None:
    atomic_write_text(
        storage_path(run_dir, StorageArtifact.RECOVERY_GUIDE, "RUN_RECOVERY_GUIDE.md", create_parent=True),
        "# K-Slide Recovery Guide\n\n"
        f"Run folder: `.k-slide-runs/{run_id}`\n\n"
        "If the session stops unexpectedly, run:\n\n"
        "```text\n/k-slide-status\n/k-slide-continue\n```\n\n"
        "For explicit debugging, the run ID is available above.\n",
    )


def _write_compatibility_artifacts(
    run_dir: Path,
    run_id: str,
    artifacts: list[InputArtifact],
    *,
    host_inputs: bool = False,
    classification_admission: ClassificationAdmission | None = None,
) -> None:
    atomic_write_json(storage_path(run_dir, StorageArtifact.RUN_MANIFEST, "RUN_MANIFEST.json", create_parent=True), _artifact_manifest(artifacts, classification_admission=classification_admission), mode=0o600)
    inventory = {
        "schema_version": SCHEMA_VERSION,
        "status": "validated",
        "input_count": len(artifacts),
        "input_files": [artifact.source_name for artifact in artifacts],
        "input_sha256": [artifact.sha256 for artifact in artifacts],
        "classifications": [artifact.classification for artifact in artifacts],
        "supported_extensions": sorted(SUPPORTED_EXTENSIONS),
        "attachments": {"supported": host_inputs, "reason": "validated local host references" if host_inputs else "No host references were supplied; using the local compatibility folder."},
    }
    if classification_admission is not None:
        inventory["classification_admission"] = classification_admission.as_dict()
    atomic_write_json(storage_path(run_dir, StorageArtifact.INPUT_INVENTORY, "00_input_inventory.json", create_parent=True), inventory, mode=0o600)
    lines = ["# K-Slide Run Manifest", "", f"Run ID: {run_id}", f"Input count: {len(artifacts)}", ""]
    lines.extend(f"- {artifact.source_name} ({artifact.kind}, sha256 `{artifact.sha256}`)" for artifact in artifacts)
    atomic_write_text(storage_path(run_dir, StorageArtifact.SOURCE_MANIFEST, "00_run_manifest.md", create_parent=True), "\n".join(lines) + "\n")
    atomic_write_json(
        storage_path(run_dir, StorageArtifact.SOURCE_MANIFEST, "ARTIFACT_MANIFEST.json", create_parent=True),
        {
            "schema_version": SCHEMA_VERSION,
            "required_for_complete": list(COMPLETION_POLICY.required_artifacts),
            "canonical_directories": ["inputs", "normalized", "native", "regions", "evidence", "ir", "verification"],
            "compatibility_artifacts": ["00_run_manifest.md", "00_input_inventory.json", "RUN_STATE.json", "EXECUTION_JOB.json", "RUN_RECOVERY_GUIDE.md"],
        },
        mode=0o600,
    )
    atomic_write_json(storage_path(run_dir, StorageArtifact.METRICS, "metrics.json", create_parent=True), {"slides_processed": 0, "tables_processed": 0, "regions_processed": 0, "numbers_verified": 0, "unresolved_count": 0, "repair_count": 0, "phase": "INPUT_VALIDATED"}, mode=0o600)


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
    inference_data_use_policy: InferenceDataUsePolicy | dict[str, Any] | None = None,
    classification_policy: InferenceDataUsePolicy | dict[str, Any] | None = None,
) -> Path:
    """Create an immutable run, returning its directory even for failed input.

    ``mode`` is retained only as internal/admin compatibility metadata for
    older run records. The host adapter omits it, uses the standard path, and
    no mode value selects a separate production behavior path.
    """

    root = root.expanduser().resolve()
    bound_environment = resolve_effective_environment(root, environment_identity=environment_identity)
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
    workspace_storage = StorageLayout.for_workspace(run_dir)
    workspace_storage.ensure_root(StoragePlane.EPHEMERAL_PROCESSING_SCRATCH)
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
            environment_identity=bound_environment,
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
        sync_workspace_execution(run_dir, environment_identity=bound_environment)
        atomic_write_json(storage_path(run_dir, StorageArtifact.INPUT_INVENTORY, "00_input_inventory.json", create_parent=True), {"schema_version": SCHEMA_VERSION, "status": "failed_input", "error": sanitize_operational(exc.as_dict(), roots=(root,))}, mode=0o600)
        atomic_write_text(storage_path(run_dir, StorageArtifact.FAILURE_MARKER, "RUN_FAILED.md", create_parent=True), f"# FAILED\n\n{safe_diagnostic_text_or_placeholder(exc.message)}\n\nError code: `{exc.code.value}`\n")
        return run_dir
    candidates = [] if raw_host_refs else _input_candidates(root, explicit_paths)
    host_inputs = bool(raw_host_refs)
    if not raw_host_refs and not candidates:
        state.transition(RunPhase.FAILED_INPUT, next_action="Add a supported file to .k-slide-input/ or pass an explicit path.", error_code=ErrorCode.INPUT_NOT_FOUND.value, error_message="No supported input files were found.")
        save_state(run_dir, state)
        sync_workspace_execution(run_dir, environment_identity=bound_environment)
        atomic_write_json(storage_path(run_dir, StorageArtifact.INPUT_INVENTORY, "00_input_inventory.json", create_parent=True), {"schema_version": SCHEMA_VERSION, "status": "failed_no_input", "input_count": 0, "supported_extensions": sorted(SUPPORTED_EXTENSIONS)}, mode=0o600)
        atomic_write_text(storage_path(run_dir, StorageArtifact.FAILURE_MARKER, "RUN_FAILED.md", create_parent=True), "# FAILED\n\nNo supported input files were found. Add a slide image, PDF, or PPTX and run `/k-slide` again.\n")
        return run_dir

    # Classification admission is intentionally before source validation and
    # immutable snapshot creation.  The labels are host metadata only; no
    # document bytes, filename-derived values, or model/tool arguments enter
    # this decision.
    raw_policy = inference_data_use_policy if inference_data_use_policy is not None else classification_policy
    classifications = tuple(reference.classification for reference in raw_host_refs) if raw_host_refs else tuple(DEFAULT_CLASSIFICATION for _candidate in candidates)
    try:
        policy = load_inference_data_use_policy(
            root,
            route_identity=bound_environment.inference_route_identity,
            policy=raw_policy,
            allow_reference_adapter=bound_environment.inference_route_identity == "reference",
        )
        if (
            policy.policy_version != bound_environment.inference_data_policy_version
            or policy.policy_hash != bound_environment.inference_data_policy_hash
            or policy.policy_identity != bound_environment.inference_data_policy_identity
        ):
            raise KSlideError(
                ErrorCode.CLASSIFICATION_POLICY_IDENTITY_MISMATCH,
                "Inference data-use policy identity is incompatible with the configured run environment.",
            )
        admission = admit_classifications(classifications, policy)
        state.classification_admission = admission.as_dict()
        save_state(run_dir, state)
        atomic_write_json(
            storage_path(run_dir, StorageArtifact.ADMISSION_RECORD, "admission/CLASSIFICATION_ADMISSION.json", create_parent=True),
            admission.as_dict(),
            mode=0o600,
        )
    except KSlideError as exc:
        state.classification_admission = {
            "schema_version": "1.0",
            "status": "REJECTED",
            "classifications": [label if label is not None else DEFAULT_CLASSIFICATION for label in classifications],
            "inference_route_identity": bound_environment.inference_route_identity,
            "inference_data_policy_version": bound_environment.inference_data_policy_version,
            "inference_data_policy_hash": bound_environment.inference_data_policy_hash,
            "inference_data_policy_identity": bound_environment.inference_data_policy_identity,
            "error_code": exc.code.value,
        }
        state.transition(
            RunPhase.FAILED_INPUT,
            next_action="Provide an approved classification policy and retry /k-slide.",
            error_code=exc.code.value,
            error_message=exc.message,
        )
        save_state(run_dir, state)
        atomic_write_json(
            storage_path(run_dir, StorageArtifact.ADMISSION_RECORD, "admission/CLASSIFICATION_ADMISSION.json", create_parent=True),
            state.classification_admission,
            mode=0o600,
        )
        atomic_write_json(
            storage_path(run_dir, StorageArtifact.INPUT_INVENTORY, "00_input_inventory.json", create_parent=True),
            {
                "schema_version": SCHEMA_VERSION,
                "status": "classification_admission_failed",
                "input_count": len(classifications),
                "classification_admission": state.classification_admission,
            },
            mode=0o600,
        )
        atomic_write_text(
            storage_path(run_dir, StorageArtifact.FAILURE_MARKER, "RUN_FAILED.md", create_parent=True),
            f"# FAILED\n\n{safe_diagnostic_text_or_placeholder(exc.message)}\n\nError code: `{exc.code.value}`\n",
        )
        sync_workspace_execution(run_dir, environment_identity=bound_environment)
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
        sync_workspace_execution(run_dir, environment_identity=bound_environment)
        atomic_write_json(storage_path(run_dir, StorageArtifact.INPUT_INVENTORY, "00_input_inventory.json", create_parent=True), {"schema_version": SCHEMA_VERSION, "status": "failed_input", "error": sanitize_operational(exc.as_dict(), roots=(root,))}, mode=0o600)
        atomic_write_text(storage_path(run_dir, StorageArtifact.FAILURE_MARKER, "RUN_FAILED.md", create_parent=True), f"# FAILED\n\n{safe_diagnostic_text_or_placeholder(exc.message)}\n\nError code: `{exc.code.value}`\n")
        return run_dir

    for index, artifact in enumerate(artifacts, start=1):
        destination = storage_path(run_dir, StorageArtifact.SOURCE_SNAPSHOT, f"inputs/source-{index:03d}{artifact.extension}", create_parent=True)
        shutil.copyfile(artifact.source_path, destination)
        destination.chmod(0o600)
        if sha256_file(destination) != artifact.sha256:
            state.transition(RunPhase.FAILED_RUNTIME, next_action="Retry after checking local storage.", error_code="KSLIDE_SNAPSHOT_HASH_MISMATCH", error_message="Immutable input copy failed hash verification.")
            save_state(run_dir, state)
            sync_workspace_execution(run_dir, environment_identity=bound_environment)
            atomic_write_text(storage_path(run_dir, StorageArtifact.FAILURE_MARKER, "RUN_FAILED.md", create_parent=True), "# FAILED\n\nImmutable input snapshot hash verification failed.\n")
            return run_dir

    atomic_write_json(storage_path(run_dir, StorageArtifact.SOURCE_MANIFEST, "inputs/checksums.json", create_parent=True), _artifact_manifest(artifacts, classification_admission=admission), mode=0o600)
    _write_compatibility_artifacts(run_dir, run_id, artifacts, host_inputs=host_inputs, classification_admission=admission)
    runtime = discover_runtime()
    atomic_write_json(storage_path(run_dir, StorageArtifact.RUNTIME_METADATA, "RUNTIME_METADATA.json", create_parent=True), runtime.as_dict(), mode=0o600)
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
            normalize_run(run_dir, environment_identity=bound_environment)
            extract_run(run_dir, environment_identity=bound_environment)
        finally:
            sync_workspace_execution(run_dir, environment_identity=bound_environment)
    else:
        sync_workspace_execution(run_dir, environment_identity=bound_environment)
    return run_dir
