"""The versioned K-Slide three-plane storage contract.

The reference deployment is deliberately filesystem based.  It is a
qualification adapter for the production-facing resolver boundary, not a
claim about a company storage API.  Plane roots are kept separate even when
the durable adapter preserves the historical K-Slide file layout.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from dataclasses import dataclass
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping, Protocol

from .errors import ErrorCode, KSlideError


STORAGE_PLANE_CONTRACT_VERSION = "1.0"
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


class StoragePlane(str, Enum):
    """The only semantic storage planes exposed by K-Slide."""

    EPHEMERAL_PROCESSING_SCRATCH = "ephemeral_processing_scratch"
    DURABLE_USER_WORKSPACE_RUN_DATA = "durable_user_workspace_run_data"
    CENTRAL_NON_CONTENT_OPERATIONAL_TELEMETRY = "central_non_content_operational_telemetry"


class StorageArtifact(str, Enum):
    """Material classes touched by normal K-Slide execution.

    Every class has exactly one plane in ``STORAGE_POLICY``.  The names are
    semantic on purpose: callers cannot select a plane by guessing a path.
    """

    SOURCE_SNAPSHOT = "source_snapshot"
    SOURCE_MANIFEST = "source_manifest"
    INPUT_INVENTORY = "input_inventory"
    RUN_MANIFEST = "run_manifest"
    RECOVERY_GUIDE = "recovery_guide"
    SESSION_BINDING = "session_binding"
    RUNTIME_METADATA = "runtime_metadata"
    RUN_STATE = "run_state"
    WORK_QUEUE = "work_queue"
    EXECUTION_JOB = "execution_job"
    ADMISSION_RECORD = "admission_record"
    ADMISSION_QUEUE = "admission_queue"
    ADMISSION_CONTROL = "admission_control"
    NORMALIZED_RENDER = "normalized_render"
    NATIVE_EXTRACTION = "native_extraction"
    NORMALIZATION_MANIFEST = "normalization_manifest"
    NORMALIZATION_ERROR = "normalization_error"
    REGION_CROP = "region_crop"
    OCR_METADATA = "ocr_metadata"
    EVIDENCE_IR = "evidence_ir"
    EXTRACTION_ERROR = "extraction_error"
    TRANSLATION_PATCH = "translation_patch"
    CANONICAL_IR = "canonical_ir"
    REPORT = "report"
    VERIFICATION = "verification"
    METRICS = "metrics"
    FAILURE_MARKER = "failure_marker"
    COMPLETION_MARKER = "completion_marker"
    COORDINATION_LOCK = "coordination_lock"
    TELEMETRY_COORDINATION_LOCK = "telemetry_coordination_lock"
    CONVERSION_STAGING = "conversion_staging"
    TELEMETRY_EVENT = "telemetry_event"
    # Deletion audits are source-free operational metadata.  This is
    # intentionally a distinct artifact identity rather than an alias for a
    # durable content-plane class.
    DELETION_AUDIT = "deletion_audit"
    # Controlled support copies remain in the durable run-data plane.  They
    # are never ordinary support metadata or central telemetry.
    SUPPORT_CONTENT = "support_content"
    # Support-access audits are source-free operational records in the
    # central non-content plane.
    SUPPORT_ACCESS_AUDIT = "support_access_audit"


STORAGE_POLICY: Mapping[StorageArtifact, StoragePlane] = {
    StorageArtifact.SOURCE_SNAPSHOT: StoragePlane.DURABLE_USER_WORKSPACE_RUN_DATA,
    StorageArtifact.SOURCE_MANIFEST: StoragePlane.DURABLE_USER_WORKSPACE_RUN_DATA,
    StorageArtifact.INPUT_INVENTORY: StoragePlane.DURABLE_USER_WORKSPACE_RUN_DATA,
    StorageArtifact.RUN_MANIFEST: StoragePlane.DURABLE_USER_WORKSPACE_RUN_DATA,
    StorageArtifact.RECOVERY_GUIDE: StoragePlane.DURABLE_USER_WORKSPACE_RUN_DATA,
    StorageArtifact.SESSION_BINDING: StoragePlane.DURABLE_USER_WORKSPACE_RUN_DATA,
    StorageArtifact.RUNTIME_METADATA: StoragePlane.DURABLE_USER_WORKSPACE_RUN_DATA,
    StorageArtifact.RUN_STATE: StoragePlane.DURABLE_USER_WORKSPACE_RUN_DATA,
    StorageArtifact.WORK_QUEUE: StoragePlane.DURABLE_USER_WORKSPACE_RUN_DATA,
    StorageArtifact.EXECUTION_JOB: StoragePlane.DURABLE_USER_WORKSPACE_RUN_DATA,
    StorageArtifact.ADMISSION_RECORD: StoragePlane.DURABLE_USER_WORKSPACE_RUN_DATA,
    StorageArtifact.ADMISSION_QUEUE: StoragePlane.DURABLE_USER_WORKSPACE_RUN_DATA,
    StorageArtifact.ADMISSION_CONTROL: StoragePlane.DURABLE_USER_WORKSPACE_RUN_DATA,
    StorageArtifact.NORMALIZED_RENDER: StoragePlane.DURABLE_USER_WORKSPACE_RUN_DATA,
    StorageArtifact.NATIVE_EXTRACTION: StoragePlane.DURABLE_USER_WORKSPACE_RUN_DATA,
    StorageArtifact.NORMALIZATION_MANIFEST: StoragePlane.DURABLE_USER_WORKSPACE_RUN_DATA,
    StorageArtifact.NORMALIZATION_ERROR: StoragePlane.DURABLE_USER_WORKSPACE_RUN_DATA,
    StorageArtifact.REGION_CROP: StoragePlane.DURABLE_USER_WORKSPACE_RUN_DATA,
    StorageArtifact.OCR_METADATA: StoragePlane.DURABLE_USER_WORKSPACE_RUN_DATA,
    StorageArtifact.EVIDENCE_IR: StoragePlane.DURABLE_USER_WORKSPACE_RUN_DATA,
    StorageArtifact.EXTRACTION_ERROR: StoragePlane.DURABLE_USER_WORKSPACE_RUN_DATA,
    StorageArtifact.TRANSLATION_PATCH: StoragePlane.DURABLE_USER_WORKSPACE_RUN_DATA,
    StorageArtifact.CANONICAL_IR: StoragePlane.DURABLE_USER_WORKSPACE_RUN_DATA,
    StorageArtifact.REPORT: StoragePlane.DURABLE_USER_WORKSPACE_RUN_DATA,
    StorageArtifact.VERIFICATION: StoragePlane.DURABLE_USER_WORKSPACE_RUN_DATA,
    StorageArtifact.METRICS: StoragePlane.DURABLE_USER_WORKSPACE_RUN_DATA,
    StorageArtifact.FAILURE_MARKER: StoragePlane.DURABLE_USER_WORKSPACE_RUN_DATA,
    StorageArtifact.COMPLETION_MARKER: StoragePlane.DURABLE_USER_WORKSPACE_RUN_DATA,
    StorageArtifact.COORDINATION_LOCK: StoragePlane.EPHEMERAL_PROCESSING_SCRATCH,
    StorageArtifact.TELEMETRY_COORDINATION_LOCK: StoragePlane.CENTRAL_NON_CONTENT_OPERATIONAL_TELEMETRY,
    StorageArtifact.CONVERSION_STAGING: StoragePlane.EPHEMERAL_PROCESSING_SCRATCH,
    StorageArtifact.TELEMETRY_EVENT: StoragePlane.CENTRAL_NON_CONTENT_OPERATIONAL_TELEMETRY,
    StorageArtifact.DELETION_AUDIT: StoragePlane.CENTRAL_NON_CONTENT_OPERATIONAL_TELEMETRY,
    StorageArtifact.SUPPORT_CONTENT: StoragePlane.DURABLE_USER_WORKSPACE_RUN_DATA,
    StorageArtifact.SUPPORT_ACCESS_AUDIT: StoragePlane.CENTRAL_NON_CONTENT_OPERATIONAL_TELEMETRY,
}

_OPERATIONAL_JSON_ARTIFACTS = frozenset(
    {
        StorageArtifact.INPUT_INVENTORY,
        StorageArtifact.RUN_MANIFEST,
        StorageArtifact.RECOVERY_GUIDE,
        StorageArtifact.SESSION_BINDING,
        StorageArtifact.RUNTIME_METADATA,
        StorageArtifact.RUN_STATE,
        StorageArtifact.WORK_QUEUE,
        StorageArtifact.EXECUTION_JOB,
        StorageArtifact.ADMISSION_RECORD,
        StorageArtifact.ADMISSION_QUEUE,
        StorageArtifact.ADMISSION_CONTROL,
        StorageArtifact.NORMALIZATION_MANIFEST,
        StorageArtifact.NORMALIZATION_ERROR,
        StorageArtifact.OCR_METADATA,
        StorageArtifact.EXTRACTION_ERROR,
        StorageArtifact.METRICS,
        StorageArtifact.FAILURE_MARKER,
        StorageArtifact.COMPLETION_MARKER,
        StorageArtifact.DELETION_AUDIT,
    }
)
_OPERATIONAL_TEXT_ARTIFACTS = frozenset({StorageArtifact.RECOVERY_GUIDE, StorageArtifact.FAILURE_MARKER, StorageArtifact.COMPLETION_MARKER})


def _error(message: str, *, code: ErrorCode = ErrorCode.EXECUTION_INVALID) -> KSlideError:
    return KSlideError(code, message)


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise _error(f"Storage {label} is invalid.")
    return value


def _artifact(value: StorageArtifact | str) -> StorageArtifact:
    try:
        return value if isinstance(value, StorageArtifact) else StorageArtifact(str(value))
    except ValueError as exc:
        raise _error("Storage artifact class is unsupported.") from exc


def _plane(value: StoragePlane | str) -> StoragePlane:
    try:
        return value if isinstance(value, StoragePlane) else StoragePlane(str(value))
    except ValueError as exc:
        raise _error("Storage plane is unsupported.") from exc


def _safe_relative_path(value: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        raise _error("Storage relative path is invalid.", code=ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT)
    candidate = PurePosixPath(value)
    if candidate.is_absolute() or any(part in {"", ".", ".."} for part in candidate.parts):
        raise _error("Storage relative path is invalid.", code=ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT)
    return candidate.as_posix()


def _resolved(path: Path) -> Path:
    try:
        return path.resolve(strict=False)
    except OSError as exc:
        raise _error("Storage path could not be resolved safely.", code=ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT) from exc


def _reject_symlink_components(path: Path, root: Path) -> None:
    current = root
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise _error("Storage path is outside its plane root.", code=ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT) from exc
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise _error("Storage path contains a symbolic-link or alias component.", code=ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT)


def _assert_root(root: Path) -> Path:
    root = Path(root).expanduser()
    if root.is_symlink():
        raise _error("Storage plane root may not be a symbolic link.", code=ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT)
    root = _resolved(root)
    if root.exists() and not root.is_dir():
        raise _error("Storage plane root is not a directory.")
    return root


def _is_nested(left: Path, right: Path) -> bool:
    try:
        left.relative_to(right)
        return True
    except ValueError:
        return False


def _external_root(root: Path | None, namespace: Path) -> Path | None:
    """Validate an explicitly configured root outside a workspace namespace."""

    if root is None:
        return None
    resolved = _assert_root(root)
    if resolved == namespace or _is_nested(resolved, namespace) or _is_nested(namespace, resolved):
        raise _error("Central telemetry root must be outside the workspace content namespace.", code=ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT)
    return resolved


def workspace_mutation_guard(run_dir: Path) -> None:
    """Reject product writes after a workspace deletion enters its fence.

    The fence is a small control field in the run state, while the deletion
    audit itself remains in the explicitly configured central operational
    plane.  Keeping the check here makes ``StorageLayout`` and direct atomic
    state/queue/evidence producers share one boundary.
    """

    run_dir = Path(run_dir).expanduser()
    if run_dir.is_symlink():
        raise _error("Workspace run directory may not be a symbolic link.", code=ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT)
    fence_path = run_dir.parent / "_deletion-fences" / f"{run_dir.name}.json"
    if fence_path.exists() or fence_path.is_symlink():
        if fence_path.is_symlink():
            raise _error("Workspace deletion fence may not be a symbolic link.", code=ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT)
        try:
            fence = json.loads(fence_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise _error("Workspace deletion fence could not be read safely.", code=ErrorCode.STATE_CORRUPT) from exc
        if not isinstance(fence, dict) or fence.get("run_ref") != run_dir.name or fence.get("state") not in {"IN_PROGRESS", "PARTIAL"}:
            raise _error("Workspace deletion fence is malformed.", code=ErrorCode.STATE_CORRUPT)
        raise _error("Workspace mutation is fenced by an active deletion lifecycle.", code=ErrorCode.EXECUTION_CONFLICT)
    state_path = run_dir / "RUN_STATE.json"
    if not state_path.exists():
        return
    if state_path.is_symlink():
        raise _error("Workspace run state may not be a symbolic link.", code=ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT)
    try:
        value = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        # The run-state authority will reject malformed state when a product
        # operation actually loads it.  This low-level boundary only treats a
        # valid deletion fence as a write barrier, preserving scratch/plane
        # diagnostics for otherwise uninitialized fixtures.
        return
    if not isinstance(value, dict):
        return
    if value.get("deletion_fence") not in {None, "IN_PROGRESS", "PARTIAL"}:
        return
    if value.get("deletion_fence") in {"IN_PROGRESS", "PARTIAL"}:
        raise _error("Workspace mutation is fenced by an active deletion lifecycle.", code=ErrorCode.EXECUTION_CONFLICT)


@dataclass(frozen=True)
class StorageReference:
    """A typed, plane-bearing opaque reference to one filesystem object."""

    plane: StoragePlane
    artifact: StorageArtifact
    relative_path: str
    scope_ref: str | None = None
    run_ref: str | None = None
    contract_version: str = STORAGE_PLANE_CONTRACT_VERSION

    def __post_init__(self) -> None:
        if self.contract_version != STORAGE_PLANE_CONTRACT_VERSION:
            raise _error("Unsupported storage-plane contract version.", code=ErrorCode.EXECUTION_UNSUPPORTED_VERSION)
        plane = _plane(self.plane)
        artifact = _artifact(self.artifact)
        object.__setattr__(self, "plane", plane)
        object.__setattr__(self, "artifact", artifact)
        if STORAGE_POLICY[artifact] is not plane:
            raise _error("Storage reference artifact class does not belong to its plane.")
        _safe_relative_path(self.relative_path)
        if self.scope_ref is not None:
            _identifier(self.scope_ref, "scope reference")
        if self.run_ref is not None:
            _identifier(self.run_ref, "run reference")
        if plane is StoragePlane.DURABLE_USER_WORKSPACE_RUN_DATA and (self.scope_ref is None or self.run_ref is None):
            raise _error("Durable storage references require scope and run references.")
        if plane is StoragePlane.CENTRAL_NON_CONTENT_OPERATIONAL_TELEMETRY and self.scope_ref is not None:
            raise _error("Central telemetry references may not carry a user/workspace scope.")

    def as_dict(self) -> dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "plane": self.plane.value,
            "artifact": self.artifact.value,
            "relative_path": self.relative_path,
            "scope_ref": self.scope_ref,
            "run_ref": self.run_ref,
        }

    @classmethod
    def from_dict(cls, value: Any) -> "StorageReference":
        if not isinstance(value, dict):
            raise _error("Storage reference must be an object.", code=ErrorCode.STATE_CORRUPT)
        allowed = {"contract_version", "plane", "artifact", "relative_path", "scope_ref", "run_ref"}
        if set(value) != allowed:
            raise _error("Storage reference fields are unsupported or incomplete.", code=ErrorCode.STATE_CORRUPT)
        try:
            return cls(
                plane=StoragePlane(value["plane"]),
                artifact=StorageArtifact(value["artifact"]),
                relative_path=value["relative_path"],
                scope_ref=value["scope_ref"],
                run_ref=value["run_ref"],
                contract_version=value["contract_version"],
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise _error("Storage reference has an invalid shape.", code=ErrorCode.STATE_CORRUPT) from exc


@dataclass(frozen=True)
class StorageLayout:
    """Shared resolver/layout boundary used by local and durable adapters."""

    durable_root: Path
    scratch_root: Path
    telemetry_root: Path | None = None
    scope_ref: str | None = None
    run_ref: str | None = None
    contract_version: str = STORAGE_PLANE_CONTRACT_VERSION
    mutation_guard: Callable[[], None] | None = None

    def __post_init__(self) -> None:
        if self.contract_version != STORAGE_PLANE_CONTRACT_VERSION:
            raise _error("Unsupported storage-plane contract version.", code=ErrorCode.EXECUTION_UNSUPPORTED_VERSION)
        durable = _assert_root(self.durable_root)
        scratch = _assert_root(self.scratch_root)
        telemetry = _assert_root(self.telemetry_root) if self.telemetry_root is not None else None
        roots = tuple(root for root in (durable, scratch, telemetry) if root is not None)
        if any(left == right or _is_nested(left, right) or _is_nested(right, left) for index, left in enumerate(roots) for right in roots[index + 1 :]):
            raise _error("Storage plane roots must be physically and logically non-overlapping.")
        if self.scope_ref is not None:
            _identifier(self.scope_ref, "scope reference")
        if self.run_ref is not None:
            _identifier(self.run_ref, "run reference")
        if self.mutation_guard is not None and not callable(self.mutation_guard):
            raise _error("Storage mutation guard is invalid.")
        object.__setattr__(self, "durable_root", durable)
        object.__setattr__(self, "scratch_root", scratch)
        object.__setattr__(self, "telemetry_root", telemetry)

    @classmethod
    def for_workspace(cls, run_dir: Path, *, central_telemetry_root: Path | None = None) -> "StorageLayout":
        run_dir = Path(run_dir).expanduser()
        if run_dir.is_symlink():
            raise _error("Workspace run directory may not be a symbolic link.", code=ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT)
        run_dir = _resolved(run_dir)
        workspace_root = run_dir.parent.parent if run_dir.parent.name == ".k-slide-runs" else run_dir.parent
        return cls(
            durable_root=run_dir,
            scratch_root=workspace_root / ".k-slide-scratch" / run_dir.name,
            telemetry_root=_external_root(central_telemetry_root, workspace_root),
            scope_ref="workspace",
            run_ref=run_dir.name,
            mutation_guard=lambda: workspace_mutation_guard(run_dir),
        )

    @classmethod
    def for_workspace_root(cls, workspace_root: Path, *, central_telemetry_root: Path | None = None) -> "StorageLayout":
        workspace_root = _assert_root(Path(workspace_root).expanduser())
        return cls(
            durable_root=workspace_root / ".k-slide-runs",
            scratch_root=workspace_root / ".k-slide-scratch" / "_workspace",
            telemetry_root=_external_root(central_telemetry_root, workspace_root),
            scope_ref="workspace",
            run_ref="workspace",
        )

    @classmethod
    def for_scoped_reference(cls, *, service_root: Path, durable_root: Path, scope_ref: str, run_ref: str, mutation_guard: Callable[[], None] | None = None) -> "StorageLayout":
        service_root = _assert_root(service_root)
        return cls(
            durable_root=durable_root,
            scratch_root=service_root / "scratch" / hashlib.sha256(scope_ref.encode("utf-8")).hexdigest()[:40] / run_ref,
            telemetry_root=service_root / "telemetry",
            scope_ref=scope_ref,
            run_ref=run_ref,
            mutation_guard=mutation_guard,
        )

    @classmethod
    def for_service(cls, service_root: Path) -> "StorageLayout":
        """Global reference layout for source-free compatibility control only."""

        service_root = _assert_root(service_root)
        return cls(
            durable_root=service_root / "job-service",
            scratch_root=service_root / "scratch" / "legacy-reference",
            telemetry_root=service_root / "telemetry",
        )

    @property
    def roots(self) -> dict[StoragePlane, Path]:
        roots = {
            StoragePlane.DURABLE_USER_WORKSPACE_RUN_DATA: self.durable_root,
            StoragePlane.EPHEMERAL_PROCESSING_SCRATCH: self.scratch_root,
        }
        if self.telemetry_root is not None:
            roots[StoragePlane.CENTRAL_NON_CONTENT_OPERATIONAL_TELEMETRY] = self.telemetry_root
        return roots

    def root_for(self, plane: StoragePlane | str) -> Path:
        plane = _plane(plane)
        if plane is StoragePlane.CENTRAL_NON_CONTENT_OPERATIONAL_TELEMETRY and self.telemetry_root is None:
            raise _error("Central telemetry is unavailable because no central service root was configured.")
        try:
            return self.roots[plane]
        except KeyError as exc:
            raise _error("Storage plane is unsupported.") from exc

    def ensure_root(self, plane: StoragePlane | str) -> Path:
        if self.mutation_guard is not None:
            self.mutation_guard()
        root = self.root_for(plane)
        if root.is_symlink():
            raise _error("Storage plane root may not be a symbolic link.", code=ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT)
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if root.is_symlink() or not root.is_dir():
            raise _error("Storage plane root is unsafe.", code=ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT)
        return root

    def path(self, artifact: StorageArtifact | str, relative_path: str, *, create_parent: bool = False) -> Path:
        artifact = _artifact(artifact)
        plane = STORAGE_POLICY[artifact]
        if create_parent and self.mutation_guard is not None:
            self.mutation_guard()
        root = self.ensure_root(plane) if create_parent else self.root_for(plane)
        relative_path = _safe_relative_path(relative_path)
        candidate = root / relative_path
        _reject_symlink_components(candidate, root)
        resolved = _resolved(candidate)
        try:
            resolved.relative_to(root)
        except ValueError as exc:
            raise _error("Storage path escaped its plane root.", code=ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT) from exc
        if create_parent:
            parent = candidate.parent
            _reject_symlink_components(parent, root)
            parent.mkdir(parents=True, exist_ok=True)
            _reject_symlink_components(parent, root)
        return candidate

    def ensure_directory(self, artifact: StorageArtifact | str, relative_path: str) -> Path:
        """Materialize a private typed directory without changing file-path semantics."""

        artifact = _artifact(artifact)
        root = self.root_for(STORAGE_POLICY[artifact])
        candidate = self.path(artifact, relative_path, create_parent=True)
        if candidate.exists() and candidate.is_symlink():
            raise _error("Storage directory may not be a symbolic link.", code=ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT)
        try:
            candidate.mkdir(mode=0o700, exist_ok=True)
        except FileExistsError as exc:
            raise _error("Storage directory is not a directory.") from exc
        except OSError as exc:
            raise _error("Storage directory could not be created safely.", code=ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT) from exc
        _reject_symlink_components(candidate, root)
        if candidate.is_symlink() or not candidate.is_dir():
            raise _error("Storage directory is unsafe.", code=ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT)
        resolved = _resolved(candidate)
        try:
            resolved.relative_to(root)
        except ValueError as exc:
            raise _error("Storage directory escaped its plane root.", code=ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT) from exc
        try:
            os.chmod(candidate, 0o700, follow_symlinks=False)
        except OSError as exc:
            raise _error("Storage directory permissions could not be secured.", code=ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT) from exc
        _reject_symlink_components(candidate, root)
        if candidate.is_symlink() or not candidate.is_dir() or _resolved(candidate) != resolved:
            raise _error("Storage directory was replaced unsafely.", code=ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT)
        return candidate

    def reference(self, artifact: StorageArtifact | str, relative_path: str) -> StorageReference:
        artifact = _artifact(artifact)
        plane = STORAGE_POLICY[artifact]
        if plane is StoragePlane.CENTRAL_NON_CONTENT_OPERATIONAL_TELEMETRY:
            self.root_for(plane)
            return StorageReference(plane, artifact, _safe_relative_path(relative_path))
        return StorageReference(plane, artifact, _safe_relative_path(relative_path), self.scope_ref, self.run_ref)

    def write_bytes(self, artifact: StorageArtifact | str, relative_path: str, data: bytes, *, mode: int | None = 0o600) -> Path:
        """Write through the typed artifact boundary."""

        from .io import atomic_write_bytes

        if STORAGE_POLICY[_artifact(artifact)] is StoragePlane.CENTRAL_NON_CONTENT_OPERATIONAL_TELEMETRY:
            raise _error("Central telemetry must be written through TelemetryWriter.")
        path = self.path(artifact, relative_path, create_parent=True)
        atomic_write_bytes(path, data, mode=mode)
        return path

    def write_text(self, artifact: StorageArtifact | str, relative_path: str, text: str, *, mode: int | None = 0o600) -> Path:
        from .io import atomic_write_text

        artifact = _artifact(artifact)
        if STORAGE_POLICY[artifact] is StoragePlane.CENTRAL_NON_CONTENT_OPERATIONAL_TELEMETRY:
            raise _error("Central telemetry must be written through TelemetryWriter.")
        path = self.path(artifact, relative_path, create_parent=True)
        if artifact in _OPERATIONAL_TEXT_ARTIFACTS:
            from .redaction import safe_diagnostic_text_or_placeholder

            text = safe_diagnostic_text_or_placeholder(text, roots=(path.parent,))
        atomic_write_text(path, text, mode=mode)
        return path

    def write_json(self, artifact: StorageArtifact | str, relative_path: str, value: Any, *, mode: int | None = 0o600) -> Path:
        from .io import atomic_write_json, atomic_write_text

        artifact = _artifact(artifact)
        if STORAGE_POLICY[artifact] is StoragePlane.CENTRAL_NON_CONTENT_OPERATIONAL_TELEMETRY:
            raise _error("Central telemetry must be written through TelemetryWriter.")
        path = self.path(artifact, relative_path, create_parent=True)
        if artifact in _OPERATIONAL_JSON_ARTIFACTS:
            from .redaction import safe_operational_json

            atomic_write_text(path, safe_operational_json(value), mode=mode)
        else:
            atomic_write_json(path, value, mode=mode)
        return path

    def resolve(self, reference: StorageReference, *, authorized_scope_ref: str | None = None, expected_plane: StoragePlane | str | None = None) -> Path:
        if not isinstance(reference, StorageReference):
            raise _error("Storage resolver requires a typed storage reference.")
        if expected_plane is not None and reference.plane is not _plane(expected_plane):
            raise _error("Storage reference was resolved through the wrong plane.")
        if reference.plane is not StoragePlane.CENTRAL_NON_CONTENT_OPERATIONAL_TELEMETRY and (reference.scope_ref != self.scope_ref or reference.run_ref != self.run_ref):
            raise _error("Storage reference is outside the authorized storage context.", code=ErrorCode.EXECUTION_CONFLICT)
        if authorized_scope_ref is not None and reference.scope_ref != authorized_scope_ref:
            raise _error("Storage reference is outside the authorized scope.", code=ErrorCode.EXECUTION_CONFLICT)
        return self.path(reference.artifact, reference.relative_path)

    def cleanup_scratch(self, *, allow_deletion: bool = False) -> None:
        """Remove only this run's scratch root; durable and telemetry are untouched."""

        if self.mutation_guard is not None and not allow_deletion:
            self.mutation_guard()
        root = self.scratch_root
        if root.is_symlink():
            raise _error("Scratch root may not be a symbolic link.", code=ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT)
        if not root.exists():
            return
        if _is_nested(root, self.durable_root) or (self.telemetry_root is not None and _is_nested(root, self.telemetry_root)):
            raise _error("Scratch root overlaps an authoritative storage plane.")
        shutil.rmtree(root)

    def inventory(self) -> tuple[dict[str, str], ...]:
        return tuple(
            {
                "contract_version": STORAGE_PLANE_CONTRACT_VERSION,
                "artifact": artifact.value,
                "plane": plane.value,
            }
            for artifact, plane in STORAGE_POLICY.items()
        )


class StorageResolver(Protocol):
    """Production-facing boundary implemented by local/reference adapters."""

    def resolve(self, reference: StorageReference, *, authorized_scope_ref: str | None = None, expected_plane: StoragePlane | str | None = None) -> Path: ...


def storage_path(run_dir: Path, artifact: StorageArtifact | str, relative_path: str, *, create_parent: bool = False) -> Path:
    """Resolve an in-run artifact through the shared durable boundary."""

    return StorageLayout.for_workspace(run_dir).path(artifact, relative_path, create_parent=create_parent)


__all__ = [
    "STORAGE_PLANE_CONTRACT_VERSION",
    "STORAGE_POLICY",
    "StorageArtifact",
    "StorageLayout",
    "StoragePlane",
    "StorageReference",
    "StorageResolver",
    "storage_path",
    "workspace_mutation_guard",
]
