"""Host-neutral KSA-13 deletion, expiry, and legal-hold lifecycle.

The module deliberately keeps the destructive part below the existing storage
and execution boundaries.  A backend supplies an authorized scope, a lock,
the KSA-11 inventory enumeration, and the platform-specific invalidation
operation.  The reference backends are deterministic qualification adapters;
they are not company records-control or storage implementations.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Callable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Iterator, Protocol

from .errors import ErrorCode, KSlideError
from .evidence_ir import stable_revision
from .execution import CancellationState, OperationalLifecycle, WorkspaceRunStore
from .io import atomic_write_json, atomic_write_text, read_json
from .locking import filesystem_lock, run_lock
from .retention_policy import RetentionPolicy
from .state import RunPhase, now_utc
from .storage import StorageArtifact, StorageLayout, StoragePlane, register_workspace_operational_root


DELETION_CONTRACT_VERSION = "1.0"
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}$")
_STRICT_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")
_FORBIDDEN = ("access", "secret", "token", "password", "credential", "source", "content", "prompt", "path", "text", "image", "korean", "business")


def _invalid(message: str, *, code: ErrorCode = ErrorCode.DELETION_INVALID) -> KSlideError:
    return KSlideError(code, message)


def _opaque(value: Any, label: str, *, strict: bool = False) -> str:
    pattern = _STRICT_IDENTIFIER if strict else _IDENTIFIER
    if not isinstance(value, str) or not pattern.fullmatch(value) or any(word in value.lower() for word in _FORBIDDEN):
        raise _invalid(f"Deletion {label} is invalid.")
    return value


def _sha(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _TIMESTAMP.fullmatch(value):
        raise _invalid(f"Deletion {label} timestamp is invalid.", code=ErrorCode.STATE_CORRUPT)
    return value


class DeletionReason(str, Enum):
    EXPLICIT = "EXPLICIT"
    RETENTION_EXPIRY = "RETENTION_EXPIRY"


class DeletionState(str, Enum):
    PLANNED = "PLANNED"
    IN_PROGRESS = "IN_PROGRESS"
    BLOCKED = "BLOCKED"
    PARTIAL = "PARTIAL"
    COMPLETE = "COMPLETE"


class DeletionOutcome(str, Enum):
    PLANNED = "PLANNED"
    IN_PROGRESS = "IN_PROGRESS"
    BLOCKED = "BLOCKED"
    PARTIAL = "PARTIAL"
    COMPLETE = "COMPLETE"


class TargetStatus(str, Enum):
    PLANNED = "PLANNED"
    DELETED = "DELETED"
    ABSENT = "ABSENT"
    FAILED = "FAILED"


class DeletionResultCode(str, Enum):
    NONE = "NONE"
    DELETED = "DELETED"
    ALREADY_ABSENT = "ALREADY_ABSENT"
    TARGET_DELETE_FAILED = "TARGET_DELETE_FAILED"
    TARGET_ADDED = "TARGET_ADDED"
    PATH_UNSAFE = "PATH_UNSAFE"
    HOLD_LOOKUP_UNAVAILABLE = "HOLD_LOOKUP_UNAVAILABLE"
    HOLD_ACTIVE = "HOLD_ACTIVE"
    HOLD_STATE_UNKNOWN = "HOLD_STATE_UNKNOWN"
    CANCELLATION_REQUESTED = "CANCELLATION_REQUESTED"
    ACTIVE_RUN = "ACTIVE_RUN"
    NONTERMINAL_RUN = "NONTERMINAL_RUN"
    TARGET_IDENTITY_MISMATCH = "TARGET_IDENTITY_MISMATCH"


class DeletionArtifactClass(str, Enum):
    """Typed audit classes, including a safe catch-all for new run objects."""

    SOURCE_SNAPSHOT = StorageArtifact.SOURCE_SNAPSHOT.value
    SOURCE_MANIFEST = StorageArtifact.SOURCE_MANIFEST.value
    INPUT_INVENTORY = StorageArtifact.INPUT_INVENTORY.value
    RUN_MANIFEST = StorageArtifact.RUN_MANIFEST.value
    RECOVERY_GUIDE = StorageArtifact.RECOVERY_GUIDE.value
    SESSION_BINDING = StorageArtifact.SESSION_BINDING.value
    RUNTIME_METADATA = StorageArtifact.RUNTIME_METADATA.value
    RUN_STATE = StorageArtifact.RUN_STATE.value
    WORK_QUEUE = StorageArtifact.WORK_QUEUE.value
    EXECUTION_JOB = StorageArtifact.EXECUTION_JOB.value
    ADMISSION_RECORD = StorageArtifact.ADMISSION_RECORD.value
    ADMISSION_QUEUE = StorageArtifact.ADMISSION_QUEUE.value
    ADMISSION_CONTROL = StorageArtifact.ADMISSION_CONTROL.value
    NORMALIZED_RENDER = StorageArtifact.NORMALIZED_RENDER.value
    NATIVE_EXTRACTION = StorageArtifact.NATIVE_EXTRACTION.value
    NORMALIZATION_MANIFEST = StorageArtifact.NORMALIZATION_MANIFEST.value
    NORMALIZATION_ERROR = StorageArtifact.NORMALIZATION_ERROR.value
    REGION_CROP = StorageArtifact.REGION_CROP.value
    OCR_METADATA = StorageArtifact.OCR_METADATA.value
    EVIDENCE_IR = StorageArtifact.EVIDENCE_IR.value
    EXTRACTION_ERROR = StorageArtifact.EXTRACTION_ERROR.value
    TRANSLATION_PATCH = StorageArtifact.TRANSLATION_PATCH.value
    CANONICAL_IR = StorageArtifact.CANONICAL_IR.value
    REPORT = StorageArtifact.REPORT.value
    VERIFICATION = StorageArtifact.VERIFICATION.value
    METRICS = StorageArtifact.METRICS.value
    FAILURE_MARKER = StorageArtifact.FAILURE_MARKER.value
    COMPLETION_MARKER = StorageArtifact.COMPLETION_MARKER.value
    RUN_SCOPED_CONTENT = "run_scoped_content"


class LegalHoldStatus(str, Enum):
    HOLD = "HOLD"
    RELEASE = "RELEASE"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class LegalHoldDecision:
    contract_version: str
    scope_ref: str
    run_ref: str
    status: LegalHoldStatus
    authority_ref: str
    decision_ref: str
    decided_at: str

    def __post_init__(self) -> None:
        if self.contract_version != DELETION_CONTRACT_VERSION:
            raise _invalid("Unsupported legal-hold contract version.", code=ErrorCode.EXECUTION_UNSUPPORTED_VERSION)
        _opaque(self.scope_ref, "hold scope reference", strict=True)
        _opaque(self.run_ref, "hold run reference", strict=True)
        _opaque(self.authority_ref, "hold authority reference", strict=True)
        _opaque(self.decision_ref, "hold decision reference", strict=True)
        try:
            object.__setattr__(self, "status", LegalHoldStatus(self.status))
        except ValueError as exc:
            raise _invalid("Legal-hold decision status is invalid.", code=ErrorCode.STATE_CORRUPT) from exc
        _timestamp(self.decided_at, "hold decision")

    @property
    def decision(self) -> LegalHoldStatus:
        return self.status

    def as_dict(self) -> dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "scope_ref": self.scope_ref,
            "run_ref": self.run_ref,
            "status": self.status.value,
            "authority_ref": self.authority_ref,
            "decision_ref": self.decision_ref,
            "decided_at": self.decided_at,
        }


class LegalHoldProvider(Protocol):
    """Authoritative records-control boundary supplied by a deployment."""

    def lookup(self, *, scope_ref: str, run_ref: str) -> LegalHoldDecision: ...


class ReferenceLegalHoldProvider:
    """Deterministic test/control adapter; it reads no run-local input."""

    def __init__(self, *, default_status: LegalHoldStatus = LegalHoldStatus.UNKNOWN, authority_ref: str = "reference-records-control") -> None:
        self._default_status = LegalHoldStatus(default_status)
        self._authority_ref = _opaque(authority_ref, "hold authority reference", strict=True)
        self._decisions: dict[tuple[str, str], LegalHoldDecision] = {}
        self._revision = 0

    def set_decision(self, *, scope_ref: str, run_ref: str, status: LegalHoldStatus, decision_ref: str | None = None) -> LegalHoldDecision:
        scope_ref = _opaque(scope_ref, "hold scope reference", strict=True)
        run_ref = _opaque(run_ref, "hold run reference", strict=True)
        status = LegalHoldStatus(status)
        if status is LegalHoldStatus.UNKNOWN:
            raise _invalid("The reference legal-hold adapter requires an explicit HOLD or RELEASE decision.")
        self._revision += 1
        decision_ref = decision_ref or f"decision-{self._revision:08d}"
        decision = LegalHoldDecision(DELETION_CONTRACT_VERSION, scope_ref, run_ref, status, self._authority_ref, decision_ref, now_utc())
        self._decisions[(scope_ref, run_ref)] = decision
        return decision

    def set_hold(self, *, scope_ref: str, run_ref: str, decision_ref: str | None = None) -> LegalHoldDecision:
        return self.set_decision(scope_ref=scope_ref, run_ref=run_ref, status=LegalHoldStatus.HOLD, decision_ref=decision_ref)

    def set_release(self, *, scope_ref: str, run_ref: str, decision_ref: str | None = None) -> LegalHoldDecision:
        return self.set_decision(scope_ref=scope_ref, run_ref=run_ref, status=LegalHoldStatus.RELEASE, decision_ref=decision_ref)

    def lookup(self, *, scope_ref: str, run_ref: str) -> LegalHoldDecision:
        scope_ref = _opaque(scope_ref, "hold scope reference", strict=True)
        run_ref = _opaque(run_ref, "hold run reference", strict=True)
        decision = self._decisions.get((scope_ref, run_ref))
        if decision is not None:
            return decision
        return LegalHoldDecision(
            DELETION_CONTRACT_VERSION,
            scope_ref,
            run_ref,
            self._default_status,
            self._authority_ref,
            f"decision-default-{_sha((scope_ref, run_ref, self._default_status.value))[:24]}",
            now_utc(),
        )


StaticLegalHoldProvider = ReferenceLegalHoldProvider


@dataclass(frozen=True)
class DeletionRequest:
    contract_version: str
    deletion_id: str
    scope_ref: str
    run_ref: str
    reason: DeletionReason
    requested_at: str

    def __post_init__(self) -> None:
        if self.contract_version != DELETION_CONTRACT_VERSION:
            raise _invalid("Unsupported deletion request version.", code=ErrorCode.EXECUTION_UNSUPPORTED_VERSION)
        _opaque(self.deletion_id, "deletion identity", strict=True)
        _opaque(self.scope_ref, "scope reference", strict=True)
        _opaque(self.run_ref, "run reference", strict=True)
        try:
            object.__setattr__(self, "reason", DeletionReason(self.reason))
        except ValueError as exc:
            raise _invalid("Deletion reason is invalid.") from exc
        _timestamp(self.requested_at, "request")


@dataclass(frozen=True)
class DeletionTargetRecord:
    target_ref: str
    artifact_class: DeletionArtifactClass
    status: TargetStatus
    result_code: str = "NONE"

    def __post_init__(self) -> None:
        _opaque(self.target_ref, "target reference", strict=True)
        try:
            object.__setattr__(self, "artifact_class", DeletionArtifactClass(self.artifact_class))
            object.__setattr__(self, "status", TargetStatus(self.status))
        except ValueError as exc:
            raise _invalid("Deletion target classification is invalid.", code=ErrorCode.STATE_CORRUPT) from exc
        if not isinstance(self.result_code, str) or self.result_code not in {item.value for item in DeletionResultCode}:
            raise _invalid("Deletion target result code is invalid.", code=ErrorCode.STATE_CORRUPT)

    def as_dict(self) -> dict[str, str]:
        return {"target_ref": self.target_ref, "artifact_class": self.artifact_class.value, "status": self.status.value, "result_code": self.result_code}


@dataclass(frozen=True)
class DeletionAudit:
    contract_version: str
    deletion_id: str
    scope_ref: str
    run_ref: str
    reason: DeletionReason
    target_generation_ref: str
    authority_ref: str
    hold_decision_ref: str
    requested_at: str
    updated_at: str
    retry_count: int
    state: DeletionState
    outcome: DeletionOutcome
    error_code: str
    targets: tuple[DeletionTargetRecord, ...] = ()

    def __post_init__(self) -> None:
        if self.contract_version != DELETION_CONTRACT_VERSION:
            raise _invalid("Unsupported deletion audit version.", code=ErrorCode.EXECUTION_UNSUPPORTED_VERSION)
        _opaque(self.deletion_id, "deletion identity", strict=True)
        _opaque(self.scope_ref, "audit scope reference", strict=True)
        _opaque(self.run_ref, "audit run reference", strict=True)
        if not _SHA256.fullmatch(self.target_generation_ref):
            raise _invalid("Deletion target generation reference is invalid.", code=ErrorCode.STATE_CORRUPT)
        _opaque(self.authority_ref, "audit authority reference", strict=True)
        _opaque(self.hold_decision_ref, "audit hold decision reference", strict=True)
        _timestamp(self.requested_at, "audit request")
        _timestamp(self.updated_at, "audit update")
        if not isinstance(self.retry_count, int) or self.retry_count < 0:
            raise _invalid("Deletion retry count is invalid.", code=ErrorCode.STATE_CORRUPT)
        try:
            object.__setattr__(self, "reason", DeletionReason(self.reason))
            object.__setattr__(self, "state", DeletionState(self.state))
            object.__setattr__(self, "outcome", DeletionOutcome(self.outcome))
        except ValueError as exc:
            raise _invalid("Deletion audit lifecycle value is invalid.", code=ErrorCode.STATE_CORRUPT) from exc
        if not isinstance(self.error_code, str) or self.error_code not in {item.value for item in DeletionResultCode}:
            raise _invalid("Deletion audit error code is invalid.", code=ErrorCode.STATE_CORRUPT)
        if not isinstance(self.targets, tuple) or len(self.targets) > 100_000 or any(not isinstance(item, DeletionTargetRecord) for item in self.targets):
            raise _invalid("Deletion audit target inventory is invalid.", code=ErrorCode.STATE_CORRUPT)
        refs = [item.target_ref for item in self.targets]
        if len(refs) != len(set(refs)):
            raise _invalid("Deletion audit target identities are not unique.", code=ErrorCode.STATE_CORRUPT)

    def as_dict(self) -> dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "deletion_id": self.deletion_id,
            "scope_ref": self.scope_ref,
            "run_ref": self.run_ref,
            "reason": self.reason.value,
            "target_generation_ref": self.target_generation_ref,
            "authority_ref": self.authority_ref,
            "hold_decision_ref": self.hold_decision_ref,
            "requested_at": self.requested_at,
            "updated_at": self.updated_at,
            "retry_count": self.retry_count,
            "state": self.state.value,
            "outcome": self.outcome.value,
            "error_code": self.error_code,
            "targets": [item.as_dict() for item in self.targets],
        }

    @classmethod
    def from_dict(cls, value: Any) -> "DeletionAudit":
        required = {"contract_version", "deletion_id", "scope_ref", "run_ref", "reason", "target_generation_ref", "authority_ref", "hold_decision_ref", "requested_at", "updated_at", "retry_count", "state", "outcome", "error_code", "targets"}
        if not isinstance(value, dict) or set(value) != required or not isinstance(value["targets"], list):
            raise _invalid("Deletion audit record is incomplete.", code=ErrorCode.STATE_CORRUPT)
        try:
            targets = tuple(DeletionTargetRecord(item["target_ref"], item["artifact_class"], item["status"], item["result_code"]) for item in value["targets"])
            return cls(
                contract_version=value["contract_version"], deletion_id=value["deletion_id"], scope_ref=value["scope_ref"], run_ref=value["run_ref"],
                reason=value["reason"], target_generation_ref=value["target_generation_ref"], authority_ref=value["authority_ref"], hold_decision_ref=value["hold_decision_ref"],
                requested_at=value["requested_at"], updated_at=value["updated_at"], retry_count=value["retry_count"], state=value["state"], outcome=value["outcome"], error_code=value["error_code"], targets=targets,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise _invalid("Deletion audit record is invalid.", code=ErrorCode.STATE_CORRUPT) from exc


@dataclass(frozen=True)
class DeletionResult:
    request: DeletionRequest
    state: DeletionState
    outcome: DeletionOutcome
    dry_run: bool
    retry_count: int
    error_code: str
    targets: tuple[DeletionTargetRecord, ...] = ()

    def __post_init__(self) -> None:
        if self.error_code not in {item.value for item in DeletionResultCode}:
            raise _invalid("Deletion result code is invalid.")

    def as_dict(self) -> dict[str, Any]:
        return {
            "contract_version": DELETION_CONTRACT_VERSION,
            "request": {
                "deletion_id": self.request.deletion_id,
                "scope_ref": self.request.scope_ref,
                "run_ref": self.request.run_ref,
                "reason": self.request.reason.value,
                "requested_at": self.request.requested_at,
            },
            "state": self.state.value,
            "outcome": self.outcome.value,
            "dry_run": self.dry_run,
            "retry_count": self.retry_count,
            "error_code": self.error_code,
            "targets": [item.as_dict() for item in self.targets],
        }


@dataclass(frozen=True)
class _Candidate:
    artifact_class: DeletionArtifactClass
    target_ref: str
    path: Path | None = None
    paths: tuple[Path, ...] = ()
    control: bool = False


@dataclass(frozen=True)
class _BackendState:
    generation_ref: str
    active: bool
    terminal: bool
    canceled: bool = False


class _DeletionBackend(Protocol):
    scope_ref: str
    run_ref: str

    @contextmanager
    def lock(self) -> Iterator[None]: ...

    def audit_path(self, deletion_id: str, *, create_parent: bool = False) -> Path: ...

    def load_audit(self, deletion_id: str) -> DeletionAudit | None: ...

    def save_audit(self, audit: DeletionAudit) -> None: ...

    def state(self) -> _BackendState: ...

    def request_cancellation(self) -> None: ...

    def enumerate_targets(self, deletion_id: str) -> tuple[_Candidate, ...]: ...

    def delete_target(self, candidate: _Candidate) -> None: ...

    def cleanup_after_targets(self) -> None: ...


def _target_ref(scope_ref: str, run_ref: str, deletion_id: str, artifact: DeletionArtifactClass) -> str:
    """Return an opaque class-level identity with no path/content preimage."""

    return f"target-{_sha((scope_ref, run_ref, deletion_id, artifact.value))[:40]}"


def _safe_files(root: Path) -> tuple[Path, ...]:
    root = Path(root)
    if root.is_symlink():
        raise KSlideError(ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT, "Deletion target root is a symbolic link.")
    if not root.exists():
        return ()
    if not root.is_dir():
        raise KSlideError(ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT, "Deletion target root is not a directory.")
    resolved_root = root.resolve()
    result: list[Path] = []
    for directory, names, files in os.walk(root, followlinks=False):
        current = Path(directory)
        if current.is_symlink():
            raise KSlideError(ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT, "Deletion refuses a symbolic-link directory.")
        try:
            current.resolve().relative_to(resolved_root)
        except (OSError, ValueError) as exc:
            raise KSlideError(ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT, "Deletion target escaped its authorized namespace.") from exc
        for name in (*names, *files):
            candidate = current / name
            if candidate.is_symlink():
                raise KSlideError(ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT, "Deletion refuses symbolic-link or alias targets.")
            try:
                candidate.resolve().relative_to(resolved_root)
            except (OSError, ValueError) as exc:
                raise KSlideError(ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT, "Deletion target escaped its authorized namespace.") from exc
        result.extend(current / name for name in files)
    return tuple(sorted(result, key=lambda item: item.as_posix()))


def _safe_target(path: Path, root: Path) -> None:
    """Re-check the namespace immediately before an unlink operation."""

    if path.is_symlink() or root.is_symlink():
        raise KSlideError(ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT, "Deletion refuses a symbolic-link target.")
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=False))
    except (OSError, ValueError) as exc:
        raise KSlideError(ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT, "Deletion target escaped its authorized namespace.") from exc
    current = root
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise KSlideError(ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT, "Deletion target escaped its authorized namespace.") from exc
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise KSlideError(ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT, "Deletion refuses a symbolic-link or alias component.")


def _class_for_relative(relative: str) -> DeletionArtifactClass:
    top = relative.split("/", 1)[0]
    name = Path(relative).name
    if name == "EXTRACTION_ERROR.json":
        return DeletionArtifactClass.EXTRACTION_ERROR
    if top == "inputs":
        return DeletionArtifactClass.SOURCE_SNAPSHOT
    if top == "normalized":
        if name == "DOCUMENT_MANIFEST.json":
            return DeletionArtifactClass.NORMALIZATION_MANIFEST
        if name == "NORMALIZATION_ERROR.json":
            return DeletionArtifactClass.NORMALIZATION_ERROR
        return DeletionArtifactClass.NORMALIZED_RENDER
    if top == "native":
        return DeletionArtifactClass.NATIVE_EXTRACTION
    if top == "regions":
        return DeletionArtifactClass.REGION_CROP
    if top == "evidence":
        return DeletionArtifactClass.EVIDENCE_IR
    if top == "ir":
        return DeletionArtifactClass.CANONICAL_IR
    if top == "translations":
        return DeletionArtifactClass.TRANSLATION_PATCH
    if top == "verification" or name.startswith("06_"):
        return DeletionArtifactClass.VERIFICATION
    if name in {"00_run_manifest.md", "ARTIFACT_MANIFEST.json"}:
        return DeletionArtifactClass.SOURCE_MANIFEST
    if name == "00_input_inventory.json":
        return DeletionArtifactClass.INPUT_INVENTORY
    if name == "RUN_MANIFEST.json":
        return DeletionArtifactClass.RUN_MANIFEST
    if name == "RUN_RECOVERY_GUIDE.md":
        return DeletionArtifactClass.RECOVERY_GUIDE
    if name == "RUNTIME_METADATA.json":
        return DeletionArtifactClass.RUNTIME_METADATA
    if name == "RUN_STATE.json":
        return DeletionArtifactClass.RUN_STATE
    if name == "WORK_QUEUE.json":
        return DeletionArtifactClass.WORK_QUEUE
    if name == "EXECUTION_JOB.json":
        return DeletionArtifactClass.EXECUTION_JOB
    if name == "metrics.json":
        return DeletionArtifactClass.METRICS
    if name == "OCR_METADATA.json":
        return DeletionArtifactClass.OCR_METADATA
    if name == "RUN_FAILED.md":
        return DeletionArtifactClass.FAILURE_MARKER
    if name == "RUN_COMPLETE.md":
        return DeletionArtifactClass.COMPLETION_MARKER
    if name.startswith(("05_", "07_")):
        return DeletionArtifactClass.REPORT
    return DeletionArtifactClass.RUN_SCOPED_CONTENT


class WorkspaceDeletionBackend:
    """Reference workspace backend using the existing run lock and layout."""

    def __init__(self, root: Path, run_ref: str, *, operational_metadata_root: Path | None) -> None:
        if operational_metadata_root is None:
            raise KSlideError(ErrorCode.DELETION_INVALID, "Workspace deletion requires an explicit central operational metadata root.")
        self.root = Path(root).expanduser().resolve()
        self.run_ref = _opaque(run_ref, "run reference", strict=True)
        self.run_dir = self.root / ".k-slide-runs" / self.run_ref
        self.scope_ref = "workspace"
        self.operational_layout = StorageLayout.for_service(Path(operational_metadata_root).expanduser())
        self.audit_root = self.operational_layout.root_for(StoragePlane.CENTRAL_NON_CONTENT_OPERATIONAL_TELEMETRY)
        register_workspace_operational_root(self.root, self.audit_root)

    @contextmanager
    def lock(self) -> Iterator[None]:
        with run_lock(self.run_dir, bypass_deletion_fence=True):
            yield

    def audit_path(self, deletion_id: str, *, create_parent: bool = False) -> Path:
        deletion_id = _opaque(deletion_id, "deletion identity", strict=True)
        return self.operational_layout.path(StorageArtifact.DELETION_AUDIT, f"deletions/{deletion_id}.json", create_parent=create_parent)

    def _set_fence(self) -> None:
        from .io import atomic_write_text

        layout = StorageLayout.for_workspace(self.run_dir, bypass_deletion_fence=True)
        layout.scratch_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        atomic_write_text(layout.scratch_root / ".deletion-fence", "active\n", mode=0o600)

    def load_audit(self, deletion_id: str) -> DeletionAudit | None:
        path = self.audit_path(deletion_id)
        if not path.is_file():
            return None
        try:
            return DeletionAudit.from_dict(read_json(path))
        except KSlideError:
            raise
        except (OSError, TypeError, ValueError) as exc:
            raise KSlideError(ErrorCode.STATE_CORRUPT, "Deletion audit record is corrupt or unreadable.") from exc

    def save_audit(self, audit: DeletionAudit) -> None:
        atomic_write_json(self.audit_path(audit.deletion_id, create_parent=True), audit.as_dict(), mode=0o600)

    def _raw_state(self) -> dict[str, Any]:
        path = self.run_dir / "RUN_STATE.json"
        if not path.is_file():
            return {}
        try:
            value = read_json(path)
        except (KSlideError, OSError, TypeError, ValueError) as exc:
            raise KSlideError(ErrorCode.STATE_CORRUPT, "Run state could not be read safely.") from exc
        if not isinstance(value, dict):
            raise KSlideError(ErrorCode.STATE_CORRUPT, "Run state is not an object.")
        return value

    def state(self) -> _BackendState:
        raw = self._raw_state()
        phase = str(raw.get("phase", raw.get("status", "UNKNOWN")))
        job_identity: dict[str, Any] | None = None
        job_lifecycle: OperationalLifecycle | None = None
        job_path = self.run_dir / "EXECUTION_JOB.json"
        active = phase not in {item.value for item in (RunPhase.COMPLETE, RunPhase.FAILED_INPUT, RunPhase.FAILED_RUNTIME, RunPhase.FAILED_NORMALIZATION, RunPhase.FAILED_EXTRACTION, RunPhase.FAILED_SCHEMA, RunPhase.FAILED_INTERNAL)}
        if job_path.is_file():
            try:
                # The coordinator already owns the run lock. Read directly so
                # a PARTIAL audit fence does not block its own retry path.
                job = WorkspaceRunStore(self.run_dir)._read(job_path, f"job-{self.run_ref}")
                job_identity = {"run_ref": job.run_id, "job_ref": job.job_id, "execution_ref": job.execution_id, "store_ref": job.store_ref.store_ref}
                job_lifecycle = job.lifecycle
                active = job.lifecycle in {OperationalLifecycle.QUEUED, OperationalLifecycle.RUNNING, OperationalLifecycle.RETRYING}
            except KSlideError as exc:
                if exc.code is not ErrorCode.EXECUTION_NOT_FOUND:
                    raise
        generation = stable_revision({"scope_ref": self.scope_ref, "run_ref": self.run_ref, "state": {"run_id": raw.get("run_id", self.run_ref), "created_at": raw.get("created_at", ""), "updated_at": raw.get("updated_at", ""), "revision": raw.get("revision", 0)}, "job": job_identity})
        phase_terminal = phase in {item.value for item in (RunPhase.COMPLETE, RunPhase.FAILED_INPUT, RunPhase.FAILED_RUNTIME, RunPhase.FAILED_NORMALIZATION, RunPhase.FAILED_EXTRACTION, RunPhase.FAILED_SCHEMA, RunPhase.FAILED_INTERNAL)}
        canceled = bool(job_identity and job_lifecycle is OperationalLifecycle.CANCELED)
        return _BackendState(generation, active, phase_terminal or canceled, canceled)

    def request_cancellation(self) -> None:
        path = self.run_dir / "EXECUTION_JOB.json"
        if not path.is_file():
            return
        store = WorkspaceRunStore(self.run_dir, allow_deletion_mutation=True)
        job = store._read(path, f"job-{self.run_ref}")
        if job.cancellation.requested or job.lifecycle in {OperationalLifecycle.COMPLETED, OperationalLifecycle.CANCELED, OperationalLifecycle.PROCESSING_FAILED}:
            return
        candidate = replace(job, cancellation=CancellationState(True, False, f"cancel-{job.job_id}", now_utc(), None), revision=job.revision + 1, updated_at=now_utc())
        store._write(candidate)

    def enumerate_targets(self, deletion_id: str) -> tuple[_Candidate, ...]:
        if not self.run_dir.exists():
            return ()
        files = _safe_files(self.run_dir)
        grouped: dict[DeletionArtifactClass, list[Path]] = {}
        for path in files:
            relative = path.relative_to(self.run_dir).as_posix()
            artifact = _class_for_relative(relative)
            grouped.setdefault(artifact, []).append(path)
        sessions = self.root / ".k-slide-runs" / "_sessions"
        if sessions.is_dir():
            for path in _safe_files(sessions):
                try:
                    value = read_json(path)
                except (KSlideError, OSError, TypeError, ValueError):
                    continue
                if isinstance(value, dict) and value.get("run_id") == self.run_ref:
                    artifact = DeletionArtifactClass.SESSION_BINDING
                    grouped.setdefault(artifact, []).append(path)
        return tuple(
            _Candidate(artifact, _target_ref(self.scope_ref, self.run_ref, deletion_id, artifact), paths[0], tuple(paths))
            for artifact, paths in sorted(grouped.items(), key=lambda item: item[0].value)
        )

    def delete_target(self, candidate: _Candidate) -> None:
        paths = candidate.paths or (() if candidate.path is None else (candidate.path,))
        sessions_root = self.root / ".k-slide-runs" / "_sessions"
        for path in paths:
            target_root = self.run_dir if path.is_relative_to(self.run_dir) else sessions_root
            _safe_target(path, target_root)
            if path.exists():
                path.unlink()

    def cleanup_after_targets(self) -> None:
        if self.run_dir.exists():
            for directory, names, _files in os.walk(self.run_dir, topdown=False, followlinks=False):
                if any((Path(directory) / name).is_symlink() for name in names):
                    raise KSlideError(ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT, "Deletion refuses a symbolic-link directory.")
                try:
                    Path(directory).rmdir()
                except OSError:
                    pass
            if self.run_dir.exists():
                raise KSlideError(ErrorCode.DELETION_TARGET_FAILED, "Deletion namespace still contains an unexpected object.")
        sessions = self.root / ".k-slide-runs" / "_sessions"
        if sessions.is_dir():
            for path in _safe_files(sessions):
                try:
                    value = read_json(path)
                except (KSlideError, OSError, TypeError, ValueError):
                    continue
                if isinstance(value, dict) and value.get("run_id") == self.run_ref:
                    if path.is_symlink():
                        raise KSlideError(ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT, "Deletion refuses a symbolic-link session binding.")
                    path.unlink(missing_ok=True)
        StorageLayout.for_workspace(self.run_dir).cleanup_scratch()


class ScopedReferenceDeletionBackend:
    """Reference PaaS backend bound to one exact authorized job identity."""

    def __init__(self, service: Any, *, identity: Any, scope_context: Any) -> None:
        from .paas import AuthorizedScopeContext, DurableJobIdentity

        if not isinstance(scope_context, AuthorizedScopeContext):
            raise _invalid("Deletion requires an authorized scope context.")
        if not isinstance(identity, (DurableJobIdentity, str)):
            raise _invalid("Deletion requires a durable job identity.")
        # Deletion retries must be able to reopen their own fenced record;
        # use the adapter's scope-bound record reader rather than the normal
        # resolver, whose fail-closed fence is for workers and callers.
        if isinstance(identity, DurableJobIdentity):
            if identity.scope_ref != scope_context.scope_ref:
                raise KSlideError(ErrorCode.EXECUTION_CONFLICT, "Authorized scope context does not match the deletion identity.")
            record = service._read_scoped_record(scope_context, identity.job_id)
            if record.identity != identity:
                raise KSlideError(ErrorCode.EXECUTION_CONFLICT, "Deletion identity does not match the authorized scope record.")
            resolved = identity
        else:
            record = service._read_scoped_record(scope_context, identity)
            resolved = record.identity
        self.service = service
        self.identity = resolved
        self.record = record
        self.scope_context = scope_context
        self.scope_ref = str(scope_context.scope_ref)
        self.run_ref = resolved.run_id
        self.scope_root = service._scope_root(scope_context)

    @contextmanager
    def lock(self) -> Iterator[None]:
        with self.service._scope_lock(self.scope_context):
            store = self.service._scoped_store(self.scope_context)
            backend = store._backend
            lock_path = backend._layout.path(StorageArtifact.COORDINATION_LOCK, f"locks/{self.identity.job_id}.lock", create_parent=True)
            with filesystem_lock(lock_path, require_shared=True, reject_symlink=True):
                yield

    def audit_path(self, deletion_id: str, *, create_parent: bool = False) -> Path:
        deletion_id = _opaque(deletion_id, "deletion identity", strict=True)
        layout = StorageLayout.for_scoped_reference(service_root=self.service.root, durable_root=self.scope_root, scope_ref=self.scope_ref, run_ref=self.identity.job_id)
        return layout.path(StorageArtifact.DELETION_AUDIT, f"deletions/{deletion_id}.json", create_parent=create_parent)

    def load_audit(self, deletion_id: str) -> DeletionAudit | None:
        path = self.audit_path(deletion_id)
        if not path.is_file():
            return None
        try:
            return DeletionAudit.from_dict(read_json(path))
        except KSlideError:
            raise
        except (OSError, TypeError, ValueError) as exc:
            raise KSlideError(ErrorCode.STATE_CORRUPT, "Deletion audit record is corrupt or unreadable.") from exc

    def save_audit(self, audit: DeletionAudit) -> None:
        atomic_write_json(self.audit_path(audit.deletion_id, create_parent=True), audit.as_dict(), mode=0o600)

    def _job_if_present(self) -> Any | None:
        backend = self.service._scoped_store(self.scope_context)._backend
        path = backend._path_for(self.identity.job_id)
        if not path.is_file():
            return None
        return backend._read(path, self.identity.job_id)

    def state(self) -> _BackendState:
        job = self._job_if_present()
        if job is None:
            generation = stable_revision(self.record.identity.as_dict())
            return _BackendState(generation, False, True)
        if job.run_id != self.identity.run_id or job.job_id != self.identity.job_id or job.execution_id != self.identity.execution_id:
            raise KSlideError(ErrorCode.EXECUTION_CONFLICT, "Durable deletion identity changed.")
        generation = stable_revision({"identity": self.record.identity.as_dict(), "environment": self.record.environment_identity.as_dict()})
        active = job.lifecycle in {OperationalLifecycle.QUEUED, OperationalLifecycle.RUNNING, OperationalLifecycle.RETRYING}
        return _BackendState(generation, active, not active, job.lifecycle is OperationalLifecycle.CANCELED)

    def request_cancellation(self) -> None:
        backend = self.service._scoped_store(self.scope_context)._backend
        path = backend._path_for(self.identity.job_id)
        if not path.is_file():
            return
        job = backend._read(path, self.identity.job_id)
        if job.cancellation.requested or job.lifecycle in {OperationalLifecycle.COMPLETED, OperationalLifecycle.CANCELED, OperationalLifecycle.PROCESSING_FAILED}:
            return
        candidate = replace(job, cancellation=CancellationState(True, False, f"cancel-{job.job_id}", now_utc(), None), revision=job.revision + 1, updated_at=now_utc())
        backend._write(candidate)

    def _content_root(self) -> Path:
        return self.scope_root / "runs" / self.run_ref

    def enumerate_targets(self, deletion_id: str) -> tuple[_Candidate, ...]:
        grouped: dict[DeletionArtifactClass, list[Path]] = {}
        content_root = self._content_root()
        for path in _safe_files(content_root):
            relative = path.relative_to(content_root).as_posix()
            artifact = _class_for_relative(relative)
            grouped.setdefault(artifact, []).append(path)
        record_path = self.service._scope_record_path(self.scope_context, self.identity.job_id)
        exec_path = self.scope_root / "run-store" / "jobs" / f"{self.identity.job_id}.json"
        for artifact, path in ((DeletionArtifactClass.ADMISSION_RECORD, record_path), (DeletionArtifactClass.EXECUTION_JOB, exec_path)):
            if path.is_file():
                grouped.setdefault(artifact, []).append(path)
            elif path.is_symlink():
                raise KSlideError(ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT, "Deletion refuses a symbolic-link control target.")
        for artifact, path in ((DeletionArtifactClass.ADMISSION_CONTROL, self.service._scope_control_path(self.scope_context)), (DeletionArtifactClass.ADMISSION_QUEUE, self.service._scope_queue_path(self.scope_context))):
            if path.is_file():
                grouped.setdefault(artifact, []).append(path)
            elif path.is_symlink():
                raise KSlideError(ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT, "Deletion refuses a symbolic-link admission target.")
        return tuple(
            _Candidate(
                artifact,
                _target_ref(self.scope_ref, self.run_ref, deletion_id, artifact),
                paths[0],
                tuple(paths),
                artifact in {DeletionArtifactClass.ADMISSION_CONTROL, DeletionArtifactClass.ADMISSION_QUEUE},
            )
            for artifact, paths in sorted(grouped.items(), key=lambda item: (0 if item[0] in {DeletionArtifactClass.ADMISSION_CONTROL, DeletionArtifactClass.ADMISSION_QUEUE} else 1, item[0].value))
        )

    def _invalidate_control(self) -> None:
        raw = self.service._load_scoped_state(self.scope_context)
        entries = tuple(item for item in raw.entries if item.identity.job_id != self.identity.job_id)
        active = raw.active_job_id
        if active == self.identity.job_id:
            active = None
            store = self.service._scoped_store(self.scope_context)
            for entry in entries:
                try:
                    candidate = store.load(entry.identity.job_id)
                except KSlideError as exc:
                    if exc.code is ErrorCode.EXECUTION_NOT_FOUND:
                        continue
                    raise
                if not self.service._terminal_for_admission(candidate):
                    active = entry.identity.job_id
                    break
        if entries != raw.entries or active != raw.active_job_id:
            self.service._persist_scoped_state(replace(raw, revision=raw.revision + 1, entries=entries, active_job_id=active))

    def delete_target(self, candidate: _Candidate) -> None:
        if candidate.control:
            self._invalidate_control()
            return
        paths = candidate.paths or (() if candidate.path is None else (candidate.path,))
        content_root = self._content_root()
        for path in paths:
            target_root = content_root if path.is_relative_to(content_root) else self.scope_root
            _safe_target(path, target_root)
            if path.exists():
                path.unlink()

    def cleanup_after_targets(self) -> None:
        content_root = self._content_root()
        if content_root.exists():
            for directory, names, _files in os.walk(content_root, topdown=False, followlinks=False):
                if any((Path(directory) / name).is_symlink() for name in names):
                    raise KSlideError(ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT, "Deletion refuses a symbolic-link content directory.")
                try:
                    Path(directory).rmdir()
                except OSError:
                    pass
            if content_root.exists():
                raise KSlideError(ErrorCode.DELETION_TARGET_FAILED, "PaaS content namespace still contains an unexpected object.")
        StorageLayout.for_scoped_reference(service_root=self.service.root, durable_root=self.scope_root, scope_ref=self.scope_ref, run_ref=self.identity.job_id).cleanup_scratch()


def _safe_hold(provider: LegalHoldProvider, *, scope_ref: str, run_ref: str) -> LegalHoldDecision:
    try:
        decision = provider.lookup(scope_ref=scope_ref, run_ref=run_ref)
        if not isinstance(decision, LegalHoldDecision):
            raise ValueError("invalid decision")
        if decision.scope_ref != scope_ref or decision.run_ref != run_ref:
            raise ValueError("scope mismatch")
        return decision
    except Exception as exc:
        if isinstance(exc, KSlideError) and exc.code is ErrorCode.LEGAL_HOLD_UNKNOWN:
            raise
        raise KSlideError(ErrorCode.LEGAL_HOLD_UNKNOWN, "Authoritative legal-hold state is unavailable or unverifiable.") from exc


class DeletionCoordinator:
    """One idempotent deletion state machine for explicit and expiry calls."""

    def __init__(self, backend: _DeletionBackend, *, hold_provider: LegalHoldProvider | None, failure_injector: Callable[[_Candidate], bool] | None = None) -> None:
        if hold_provider is None:
            raise KSlideError(ErrorCode.LEGAL_HOLD_UNKNOWN, "An authoritative legal-hold provider is required before deletion.")
        self.backend = backend
        self.hold_provider = hold_provider
        self.failure_injector = failure_injector

    def _request(self, deletion_id: str, reason: DeletionReason) -> DeletionRequest:
        return DeletionRequest(DELETION_CONTRACT_VERSION, _opaque(deletion_id, "deletion identity", strict=True), self.backend.scope_ref, self.backend.run_ref, reason, now_utc())

    def _result(self, request: DeletionRequest, *, state: DeletionState, outcome: DeletionOutcome, dry_run: bool, retry_count: int, error_code: str, targets: tuple[DeletionTargetRecord, ...] = ()) -> DeletionResult:
        return DeletionResult(request, state, outcome, dry_run, retry_count, error_code, targets)

    def run(self, deletion_id: str, *, reason: DeletionReason, dry_run: bool = False) -> DeletionResult:
        request = self._request(deletion_id, reason)
        existing = self.backend.load_audit(request.deletion_id)
        if existing is not None:
            if (existing.scope_ref, existing.run_ref, existing.reason) != (request.scope_ref, request.run_ref, request.reason):
                raise KSlideError(ErrorCode.EXECUTION_CONFLICT, "Deletion identity is already bound to a different scope, run, or reason.")
            if existing.state is DeletionState.COMPLETE:
                if dry_run:
                    return self._result(request, state=DeletionState.PLANNED, outcome=DeletionOutcome.PLANNED, dry_run=True, retry_count=existing.retry_count, error_code="NONE", targets=tuple(replace(item, status=TargetStatus.PLANNED, result_code="NONE") for item in existing.targets))
                return self._result(request, state=existing.state, outcome=existing.outcome, dry_run=dry_run, retry_count=existing.retry_count, error_code=existing.error_code, targets=existing.targets)

        try:
            hold = _safe_hold(self.hold_provider, scope_ref=request.scope_ref, run_ref=request.run_ref)
        except KSlideError as exc:
            if dry_run:
                return self._result(request, state=DeletionState.BLOCKED, outcome=DeletionOutcome.BLOCKED, dry_run=True, retry_count=existing.retry_count if existing else 0, error_code="HOLD_LOOKUP_UNAVAILABLE")
            with self.backend.lock():
                current = self.backend.load_audit(request.deletion_id) or DeletionAudit(DELETION_CONTRACT_VERSION, request.deletion_id, request.scope_ref, request.run_ref, request.reason, "0" * 64, "unknown-authority", "unknown-decision", request.requested_at, request.requested_at, 0, DeletionState.BLOCKED, DeletionOutcome.BLOCKED, "HOLD_LOOKUP_UNAVAILABLE")
                blocked = replace(current, updated_at=now_utc(), state=DeletionState.BLOCKED, outcome=DeletionOutcome.BLOCKED, error_code="HOLD_LOOKUP_UNAVAILABLE", retry_count=current.retry_count + 1)
                self.backend.save_audit(blocked)
                return self._result(request, state=blocked.state, outcome=blocked.outcome, dry_run=False, retry_count=blocked.retry_count, error_code=blocked.error_code, targets=blocked.targets)
        if hold.status is not LegalHoldStatus.RELEASE:
            code = "HOLD_ACTIVE" if hold.status is LegalHoldStatus.HOLD else "HOLD_STATE_UNKNOWN"
            if dry_run:
                return self._result(request, state=DeletionState.BLOCKED, outcome=DeletionOutcome.BLOCKED, dry_run=True, retry_count=existing.retry_count if existing else 0, error_code=code)
            with self.backend.lock():
                current = self.backend.load_audit(request.deletion_id) or DeletionAudit(DELETION_CONTRACT_VERSION, request.deletion_id, request.scope_ref, request.run_ref, request.reason, "0" * 64, hold.authority_ref, hold.decision_ref, request.requested_at, request.requested_at, 0, DeletionState.BLOCKED, DeletionOutcome.BLOCKED, code)
                blocked = replace(current, updated_at=now_utc(), authority_ref=hold.authority_ref, hold_decision_ref=hold.decision_ref, state=DeletionState.BLOCKED, outcome=DeletionOutcome.BLOCKED, error_code=code, retry_count=current.retry_count + 1)
                self.backend.save_audit(blocked)
                return self._result(request, state=blocked.state, outcome=blocked.outcome, dry_run=False, retry_count=blocked.retry_count, error_code=blocked.error_code, targets=blocked.targets)

        with self.backend.lock():
            # Re-read both the hold and the audit at the destructive boundary.
            hold = _safe_hold(self.hold_provider, scope_ref=request.scope_ref, run_ref=request.run_ref)
            if hold.status is not LegalHoldStatus.RELEASE:
                code = "HOLD_ACTIVE" if hold.status is LegalHoldStatus.HOLD else "HOLD_STATE_UNKNOWN"
                if dry_run:
                    return self._result(request, state=DeletionState.BLOCKED, outcome=DeletionOutcome.BLOCKED, dry_run=True, retry_count=existing.retry_count if existing else 0, error_code=code)
                current = self.backend.load_audit(request.deletion_id) or DeletionAudit(DELETION_CONTRACT_VERSION, request.deletion_id, request.scope_ref, request.run_ref, request.reason, "0" * 64, hold.authority_ref, hold.decision_ref, request.requested_at, request.requested_at, 0, DeletionState.BLOCKED, DeletionOutcome.BLOCKED, code)
                blocked = replace(current, updated_at=now_utc(), authority_ref=hold.authority_ref, hold_decision_ref=hold.decision_ref, state=DeletionState.BLOCKED, outcome=DeletionOutcome.BLOCKED, error_code=code, retry_count=current.retry_count + 1)
                self.backend.save_audit(blocked)
                return self._result(request, state=blocked.state, outcome=blocked.outcome, dry_run=False, retry_count=blocked.retry_count, error_code=blocked.error_code, targets=blocked.targets)
            current = self.backend.load_audit(request.deletion_id)
            state = self.backend.state()
            if current is not None and current.target_generation_ref != state.generation_ref and current.targets:
                blocked = replace(current, updated_at=now_utc(), state=DeletionState.BLOCKED, outcome=DeletionOutcome.BLOCKED, error_code="TARGET_IDENTITY_MISMATCH", retry_count=current.retry_count + 1)
                if not dry_run:
                    self.backend.save_audit(blocked)
                return self._result(request, state=blocked.state, outcome=blocked.outcome, dry_run=dry_run, retry_count=blocked.retry_count, error_code=blocked.error_code, targets=blocked.targets)
            if state.active:
                if request.reason is DeletionReason.EXPLICIT:
                    self.backend.request_cancellation()
                    code = "CANCELLATION_REQUESTED"
                else:
                    code = "ACTIVE_RUN"
                if dry_run:
                    return self._result(request, state=DeletionState.BLOCKED, outcome=DeletionOutcome.BLOCKED, dry_run=True, retry_count=current.retry_count if current else 0, error_code=code)
                blocked = replace(current, target_generation_ref=state.generation_ref, authority_ref=hold.authority_ref, hold_decision_ref=hold.decision_ref, updated_at=now_utc(), state=DeletionState.BLOCKED, outcome=DeletionOutcome.BLOCKED, error_code=code, retry_count=(current.retry_count + 1 if current else 1)) if current else DeletionAudit(DELETION_CONTRACT_VERSION, request.deletion_id, request.scope_ref, request.run_ref, request.reason, state.generation_ref, hold.authority_ref, hold.decision_ref, request.requested_at, now_utc(), 1, DeletionState.BLOCKED, DeletionOutcome.BLOCKED, code)
                self.backend.save_audit(blocked)
                return self._result(request, state=blocked.state, outcome=blocked.outcome, dry_run=False, retry_count=blocked.retry_count, error_code=blocked.error_code, targets=blocked.targets)
            if not state.terminal and not (request.reason is DeletionReason.EXPLICIT and state.canceled):
                code = "NONTERMINAL_RUN"
                if dry_run:
                    return self._result(request, state=DeletionState.BLOCKED, outcome=DeletionOutcome.BLOCKED, dry_run=True, retry_count=current.retry_count if current else 0, error_code=code)
                blocked = replace(current, target_generation_ref=state.generation_ref, authority_ref=hold.authority_ref, hold_decision_ref=hold.decision_ref, updated_at=now_utc(), state=DeletionState.BLOCKED, outcome=DeletionOutcome.BLOCKED, error_code=code, retry_count=(current.retry_count + 1 if current else 1)) if current else DeletionAudit(DELETION_CONTRACT_VERSION, request.deletion_id, request.scope_ref, request.run_ref, request.reason, state.generation_ref, hold.authority_ref, hold.decision_ref, request.requested_at, now_utc(), 1, DeletionState.BLOCKED, DeletionOutcome.BLOCKED, code)
                self.backend.save_audit(blocked)
                return self._result(request, state=blocked.state, outcome=blocked.outcome, dry_run=False, retry_count=blocked.retry_count, error_code=blocked.error_code, targets=blocked.targets)
            candidates = self.backend.enumerate_targets(request.deletion_id)
            if dry_run:
                preview = tuple(DeletionTargetRecord(item.target_ref, item.artifact_class, TargetStatus.PLANNED) for item in candidates)
                return self._result(request, state=DeletionState.PLANNED, outcome=DeletionOutcome.PLANNED, dry_run=True, retry_count=current.retry_count if current else 0, error_code="NONE", targets=preview)
            audit = current or DeletionAudit(DELETION_CONTRACT_VERSION, request.deletion_id, request.scope_ref, request.run_ref, request.reason, state.generation_ref, hold.authority_ref, hold.decision_ref, request.requested_at, request.requested_at, 0, DeletionState.PLANNED, DeletionOutcome.PLANNED, "NONE", tuple(DeletionTargetRecord(item.target_ref, item.artifact_class, TargetStatus.PLANNED) for item in candidates))
            if not audit.targets:
                audit = replace(audit, targets=tuple(DeletionTargetRecord(item.target_ref, item.artifact_class, TargetStatus.PLANNED) for item in candidates))
            known = {item.target_ref: item for item in audit.targets}
            added = [item for item in candidates if item.target_ref not in known]
            if added:
                audit = replace(audit, targets=tuple((*audit.targets, *(DeletionTargetRecord(item.target_ref, item.artifact_class, TargetStatus.FAILED, "TARGET_ADDED") for item in added))))
            active_audit = replace(audit, authority_ref=hold.authority_ref, hold_decision_ref=hold.decision_ref, target_generation_ref=state.generation_ref, updated_at=now_utc(), retry_count=audit.retry_count + 1, state=DeletionState.IN_PROGRESS, outcome=DeletionOutcome.IN_PROGRESS, error_code="NONE")
            if isinstance(self.backend, WorkspaceDeletionBackend):
                self.backend._set_fence()
            self.backend.save_audit(active_audit)
            by_ref = {item.target_ref: item for item in candidates}
            target_records = list(active_audit.targets)
            # Ordinary target failures are unfinished and are retried.  A
            # target that appeared after the durable plan is intentionally
            # never adopted by a stale deletion request.
            failed = any(item.status is TargetStatus.FAILED and item.result_code == "TARGET_ADDED" for item in target_records)
            for index, record in enumerate(target_records):
                if record.status in {TargetStatus.DELETED, TargetStatus.ABSENT} or (record.status is TargetStatus.FAILED and record.result_code == "TARGET_ADDED"):
                    continue
                candidate = by_ref.get(record.target_ref)
                if candidate is None:
                    target_records[index] = replace(record, status=TargetStatus.ABSENT, result_code="ALREADY_ABSENT")
                    continue
                try:
                    if self.failure_injector is not None and self.failure_injector(candidate):
                        raise OSError("injected")
                    self.backend.delete_target(candidate)
                    target_records[index] = replace(record, status=TargetStatus.DELETED, result_code="DELETED")
                except KSlideError as exc:
                    code = "PATH_UNSAFE" if exc.code is ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT else "TARGET_DELETE_FAILED"
                    target_records[index] = replace(record, status=TargetStatus.FAILED, result_code=code)
                    failed = True
                    break
                except OSError:
                    target_records[index] = replace(record, status=TargetStatus.FAILED, result_code="TARGET_DELETE_FAILED")
                    failed = True
                    break
            if failed or any(item.status is TargetStatus.FAILED for item in target_records):
                partial = replace(active_audit, targets=tuple(target_records), updated_at=now_utc(), state=DeletionState.PARTIAL, outcome=DeletionOutcome.PARTIAL, error_code="TARGET_DELETE_FAILED")
                self.backend.save_audit(partial)
                return self._result(request, state=partial.state, outcome=partial.outcome, dry_run=False, retry_count=partial.retry_count, error_code=partial.error_code, targets=partial.targets)
            completed = replace(active_audit, targets=tuple(target_records), updated_at=now_utc(), state=DeletionState.IN_PROGRESS, outcome=DeletionOutcome.IN_PROGRESS, error_code="NONE")
            try:
                self.backend.cleanup_after_targets()
            except KSlideError as exc:
                partial = replace(completed, updated_at=now_utc(), state=DeletionState.PARTIAL, outcome=DeletionOutcome.PARTIAL, error_code="TARGET_DELETE_FAILED")
                self.backend.save_audit(partial)
                return self._result(request, state=partial.state, outcome=partial.outcome, dry_run=False, retry_count=partial.retry_count, error_code=partial.error_code, targets=partial.targets)
            final = replace(completed, updated_at=now_utc(), state=DeletionState.COMPLETE, outcome=DeletionOutcome.COMPLETE, error_code="NONE")
            self.backend.save_audit(final)
            return self._result(request, state=final.state, outcome=final.outcome, dry_run=False, retry_count=final.retry_count, error_code=final.error_code, targets=final.targets)


def delete_workspace_run(root: Path, *, run_ref: str, deletion_id: str, scope_context: Any | None = None, reason: DeletionReason = DeletionReason.EXPLICIT, hold_provider: LegalHoldProvider | None = None, operational_metadata_root: Path | None = None, dry_run: bool = False, failure_injector: Callable[[_Candidate], bool] | None = None) -> DeletionResult:
    from .paas import AuthorizedScopeContext

    if not isinstance(scope_context, AuthorizedScopeContext) or scope_context.scope_ref != "workspace":
        raise KSlideError(ErrorCode.EXECUTION_CONFLICT, "Workspace deletion requires an authorized workspace scope context.")
    backend = WorkspaceDeletionBackend(root, run_ref, operational_metadata_root=operational_metadata_root)
    return DeletionCoordinator(backend, hold_provider=hold_provider, failure_injector=failure_injector).run(deletion_id, reason=reason, dry_run=dry_run)


def delete_scoped_run(service: Any, *, identity: Any, scope_context: Any, deletion_id: str, reason: DeletionReason = DeletionReason.EXPLICIT, hold_provider: LegalHoldProvider | None = None, dry_run: bool = False, failure_injector: Callable[[_Candidate], bool] | None = None) -> DeletionResult:
    backend = ScopedReferenceDeletionBackend(service, identity=identity, scope_context=scope_context)
    return DeletionCoordinator(backend, hold_provider=hold_provider, failure_injector=failure_injector).run(deletion_id, reason=reason, dry_run=dry_run)


def _cleanup_telemetry_records(telemetry_root: Path, cutoff: datetime, *, dry_run: bool) -> list[str]:
    telemetry_path = telemetry_root / "events.jsonl"
    if telemetry_path.is_symlink():
        raise KSlideError(ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT, "Central telemetry event record is a symbolic link.")
    if telemetry_path.exists() and not telemetry_path.is_file():
        raise KSlideError(ErrorCode.RETENTION_REFUSED, "Central telemetry event record is not a regular file.")
    if not telemetry_path.is_file():
        return []
    try:
        lines = telemetry_path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise KSlideError(ErrorCode.RETENTION_REFUSED, "Central telemetry event record is unreadable.") from exc
    from .telemetry import TelemetryEvent

    expired: list[str] = []
    retained_lines: list[str] = []
    for line in lines:
        if not line:
            continue
        try:
            event = TelemetryEvent.from_mapping(json.loads(line))
            occurred = datetime.fromisoformat(event.occurred_at.replace("Z", "+00:00")).astimezone(timezone.utc)
        except (KSlideError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise KSlideError(ErrorCode.RETENTION_REFUSED, "Central telemetry contains an invalid typed record.") from exc
        if occurred < cutoff:
            expired.append(str(event.event_id))
        else:
            retained_lines.append(line)
    if expired and not dry_run:
        if retained_lines:
            atomic_write_text(telemetry_path, "\n".join(retained_lines) + "\n", mode=0o600)
        else:
            telemetry_path.unlink()
    return expired


def cleanup_operational_metadata(
    root: Path,
    retention_policy: RetentionPolicy | Mapping[str, Any],
    *,
    operational_metadata_root: Path | None = None,
    now: Any | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Expire central KSA-13 audits and KSA-11 telemetry using one metadata TTL."""

    try:
        policy = retention_policy if isinstance(retention_policy, RetentionPolicy) else RetentionPolicy.from_mapping(retention_policy, require_resolved=True)
        policy.require_resolved()
    except (TypeError, ValueError) as exc:
        raise KSlideError(ErrorCode.RETENTION_INVALID, f"Invalid retention policy for operational-metadata cleanup: {exc}") from exc
    current = now or datetime.now(timezone.utc)
    if not hasattr(current, "astimezone"):
        raise KSlideError(ErrorCode.RETENTION_INVALID, "Operational-metadata cleanup time is invalid.")
    if operational_metadata_root is None:
        raise KSlideError(ErrorCode.DELETION_INVALID, "An explicit central operational metadata root is required.")
    cutoff = current.astimezone(timezone.utc) - timedelta(days=int(policy.operational_metadata_retention_days))
    central = StorageLayout.for_service(Path(operational_metadata_root).expanduser())
    telemetry_root = central.root_for(StoragePlane.CENTRAL_NON_CONTENT_OPERATIONAL_TELEMETRY)
    audit_root = telemetry_root / "deletions"
    expired: list[str] = []
    retained: list[str] = []
    expired_paths: list[Path] = []
    if audit_root.is_symlink():
        raise KSlideError(ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT, "Deletion audit root is a symbolic link.")
    for path in sorted(audit_root.glob("*.json")) if audit_root.is_dir() else ():
        if path.is_symlink():
            raise KSlideError(ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT, "Deletion audit record is a symbolic link.")
        try:
            path.resolve().relative_to(audit_root.resolve())
            audit = DeletionAudit.from_dict(read_json(path))
            updated = datetime.fromisoformat(audit.updated_at.replace("Z", "+00:00")).astimezone(timezone.utc)
        except (OSError, ValueError, TypeError) as exc:
            raise KSlideError(ErrorCode.RETENTION_REFUSED, "Deletion audit record is invalid or outside the central operational root.") from exc
        if audit.state in {DeletionState.IN_PROGRESS, DeletionState.PARTIAL}:
            retained.append(audit.deletion_id)
        elif updated < cutoff:
            expired.append(audit.deletion_id)
            expired_paths.append(path)
        else:
            retained.append(audit.deletion_id)
    telemetry_expired = _cleanup_telemetry_records(telemetry_root, cutoff, dry_run=True)
    if not dry_run:
        telemetry_expired = _cleanup_telemetry_records(telemetry_root, cutoff, dry_run=False)
        for path in expired_paths:
            path.unlink()
    return {
        "status": "PASS",
        "dry_run": dry_run,
        "retention_policy": policy.as_dict(),
        "expired": expired,
        "retained": retained,
        "telemetry_expired": telemetry_expired,
        "cutoff": cutoff.isoformat(),
    }


def cleanup_scoped_operational_metadata(service: Any, *, scope_context: Any, retention_policy: RetentionPolicy | Mapping[str, Any], now: Any | None = None, dry_run: bool = False) -> dict[str, Any]:
    """Expire only one authorized PaaS scope's deletion audits."""

    try:
        policy = retention_policy if isinstance(retention_policy, RetentionPolicy) else RetentionPolicy.from_mapping(retention_policy, require_resolved=True)
        policy.require_resolved()
    except (TypeError, ValueError) as exc:
        raise KSlideError(ErrorCode.RETENTION_INVALID, f"Invalid retention policy for operational-metadata cleanup: {exc}") from exc
    current = now or datetime.now(timezone.utc)
    cutoff = current.astimezone(timezone.utc) - timedelta(days=int(policy.operational_metadata_retention_days))
    audit_root = service._storage.root_for(StoragePlane.CENTRAL_NON_CONTENT_OPERATIONAL_TELEMETRY) / "deletions"
    expired: list[str] = []
    retained: list[str] = []
    expired_paths: list[Path] = []
    if audit_root.is_symlink():
        raise KSlideError(ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT, "Scoped deletion audit root is a symbolic link.")
    for path in sorted(audit_root.glob("*.json")) if audit_root.is_dir() else ():
        if path.is_symlink():
            raise KSlideError(ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT, "Scoped deletion audit record is a symbolic link.")
        audit = DeletionAudit.from_dict(read_json(path))
        if audit.scope_ref != scope_context.scope_ref:
            raise KSlideError(ErrorCode.EXECUTION_CONFLICT, "Scoped deletion audit is outside the authorized scope.")
        updated = datetime.fromisoformat(audit.updated_at.replace("Z", "+00:00")).astimezone(timezone.utc)
        if audit.state in {DeletionState.IN_PROGRESS, DeletionState.PARTIAL}:
            retained.append(audit.deletion_id)
        elif updated < cutoff:
            expired.append(audit.deletion_id)
            expired_paths.append(path)
        else:
            retained.append(audit.deletion_id)
    telemetry_root = service._storage.root_for(StoragePlane.CENTRAL_NON_CONTENT_OPERATIONAL_TELEMETRY)
    telemetry_expired = _cleanup_telemetry_records(telemetry_root, cutoff, dry_run=True)
    if not dry_run:
        telemetry_expired = _cleanup_telemetry_records(telemetry_root, cutoff, dry_run=False)
        for path in expired_paths:
            path.unlink()
    return {"status": "PASS", "dry_run": dry_run, "retention_policy": policy.as_dict(), "expired": expired, "retained": retained, "telemetry_expired": telemetry_expired, "cutoff": cutoff.isoformat()}


__all__ = [
    "DELETION_CONTRACT_VERSION", "DeletionArtifactClass", "DeletionAudit", "DeletionCoordinator", "DeletionOutcome", "DeletionReason", "DeletionRequest", "DeletionResult", "DeletionResultCode", "DeletionState", "DeletionTargetRecord", "LegalHoldDecision", "LegalHoldDecisionType", "LegalHoldProvider", "LegalHoldStatus", "ReferenceLegalHoldProvider", "StaticLegalHoldProvider", "TargetStatus", "cleanup_operational_metadata", "cleanup_scoped_operational_metadata", "delete_scoped_run", "delete_workspace_run",
]


# Compatibility spelling for adapters that use the decision-type name.
LegalHoldDecisionType = LegalHoldStatus
