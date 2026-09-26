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
from enum import Enum
from pathlib import Path
from typing import Any, Iterator, Protocol

from .errors import ErrorCode, KSlideError
from .evidence_ir import stable_revision
from .execution import CancellationState, OperationalLifecycle, WorkspaceRunStore
from .content_support import ControlledSupportDeletionRecord
from .io import atomic_write_json, atomic_write_text, read_json
from .locking import filesystem_lock, run_lock
from .retention_policy import RetentionPolicy
from .state import RunPhase, now_utc
from .storage import StorageArtifact, StorageLayout


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
    SUPPORT_CONTENT = StorageArtifact.SUPPORT_CONTENT.value
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
    # Source-free proofs for the immutable control identities that existed
    # when the deletion was admitted.  These remain usable after the control
    # artifacts themselves have been removed.
    generation_anchors: tuple[tuple[str, str], ...] = ()
    # Scoped PaaS deletion audits additionally bind the complete durable
    # identity so a replay cannot be adopted by a guessed sibling identity.
    identity_ref: str | None = None
    # Source-free support identities are captured before support bytes or
    # metadata are unlinked, so central audit recovery does not depend on the
    # deleted metadata file or process memory.
    support_recovery: tuple[ControlledSupportDeletionRecord, ...] = ()

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
        anchors = [item[0] for item in self.generation_anchors]
        if len(anchors) != len(set(anchors)) or any(
            not isinstance(item, tuple)
            or len(item) != 2
            or not isinstance(item[0], str)
            or not _STRICT_IDENTIFIER.fullmatch(item[0])
            or not isinstance(item[1], str)
            or not _SHA256.fullmatch(item[1])
            for item in self.generation_anchors
        ):
            raise _invalid("Deletion audit generation anchors are invalid.", code=ErrorCode.STATE_CORRUPT)
        if self.identity_ref is not None and not _SHA256.fullmatch(self.identity_ref):
            raise _invalid("Deletion audit identity reference is invalid.", code=ErrorCode.STATE_CORRUPT)
        if not isinstance(self.support_recovery, tuple) or any(not isinstance(item, ControlledSupportDeletionRecord) for item in self.support_recovery):
            raise _invalid("Deletion audit support recovery is invalid.", code=ErrorCode.STATE_CORRUPT)
        support_refs = [item.artifact_ref for item in self.support_recovery]
        if len(support_refs) != len(set(support_refs)) or any(
            item.scope_context.scope_ref != self.scope_ref or item.run_ref != self.run_ref
            for item in self.support_recovery
        ):
            raise _invalid("Deletion audit support recovery identity is invalid.", code=ErrorCode.STATE_CORRUPT)

    def as_dict(self) -> dict[str, Any]:
        value = {
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
            "generation_anchors": {name: reference for name, reference in self.generation_anchors},
        }
        if self.identity_ref is not None:
            value["identity_ref"] = self.identity_ref
        if self.support_recovery:
            value["support_recovery"] = [item.as_dict() for item in self.support_recovery]
        return value

    @classmethod
    def from_dict(cls, value: Any) -> "DeletionAudit":
        required = {"contract_version", "deletion_id", "scope_ref", "run_ref", "reason", "target_generation_ref", "authority_ref", "hold_decision_ref", "requested_at", "updated_at", "retry_count", "state", "outcome", "error_code", "targets"}
        allowed_optional = {"generation_anchors", "identity_ref", "support_recovery"}
        if not isinstance(value, dict) or set(value) - (required | allowed_optional) or not isinstance(value["targets"], list):
            raise _invalid("Deletion audit record is incomplete.", code=ErrorCode.STATE_CORRUPT)
        try:
            targets = tuple(DeletionTargetRecord(item["target_ref"], item["artifact_class"], item["status"], item["result_code"]) for item in value["targets"])
            raw_anchors = value.get("generation_anchors", {})
            if not isinstance(raw_anchors, dict) or any(not isinstance(name, str) or not isinstance(reference, str) for name, reference in raw_anchors.items()):
                raise _invalid("Deletion audit generation anchors are invalid.", code=ErrorCode.STATE_CORRUPT)
            raw_support_recovery = value.get("support_recovery", [])
            if not isinstance(raw_support_recovery, list):
                raise _invalid("Deletion audit support recovery is invalid.", code=ErrorCode.STATE_CORRUPT)
            return cls(
                contract_version=value["contract_version"], deletion_id=value["deletion_id"], scope_ref=value["scope_ref"], run_ref=value["run_ref"],
                reason=value["reason"], target_generation_ref=value["target_generation_ref"], authority_ref=value["authority_ref"], hold_decision_ref=value["hold_decision_ref"],
                requested_at=value["requested_at"], updated_at=value["updated_at"], retry_count=value["retry_count"], state=value["state"], outcome=value["outcome"], error_code=value["error_code"], targets=targets,
                generation_anchors=tuple(sorted(raw_anchors.items())),
                identity_ref=value.get("identity_ref"),
                support_recovery=tuple(ControlledSupportDeletionRecord.from_dict(item) for item in raw_support_recovery),
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
    control: bool = False


@dataclass(frozen=True)
class _BackendState:
    generation_ref: str
    active: bool
    terminal: bool
    canceled: bool = False
    generation_anchors: tuple[tuple[str, str], ...] = ()


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

    def prepare_support_recovery(self, candidate: _Candidate) -> tuple[ControlledSupportDeletionRecord, ...]: ...

    def delete_target(self, candidate: _Candidate, *, support_recovery: tuple[ControlledSupportDeletionRecord, ...] = ()) -> None: ...

    def cleanup_after_targets(self) -> None: ...


def _target_ref(scope_ref: str, run_ref: str, deletion_id: str, artifact: DeletionArtifactClass) -> str:
    """Return an opaque target identity with no business-data preimage."""

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


def _support_recovery_from_metadata(support_dir: Path) -> tuple[ControlledSupportDeletionRecord, ...]:
    from .content_support import prepare_deleted_support_artifacts

    return tuple(ControlledSupportDeletionRecord.from_artifact(item) for item in prepare_deleted_support_artifacts(support_dir))


def _delete_support_content(
    paths: tuple[Path, ...],
    *,
    support_dir: Path,
    target_root: Path,
    service_root: Path,
    support_recovery: tuple[ControlledSupportDeletionRecord, ...] | None = None,
) -> None:
    """Unlink support copies before recording source-free deletion facts."""

    from .content_support import record_deleted_support_artifacts

    if support_dir.is_symlink() or (support_dir.exists() and not support_dir.is_dir()):
        raise KSlideError(ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT, "Controlled support deletion namespace is unsafe.")
    recovery = support_recovery if support_recovery is not None else _support_recovery_from_metadata(support_dir)
    expected = {
        artifact.artifact_ref: (support_dir / f"{artifact.artifact_ref}.zip", support_dir / f"{artifact.artifact_ref}.json")
        for artifact in recovery
    }

    def record_removed() -> None:
        removed = tuple(
            artifact for artifact in recovery
            if all(not path.exists() for path in expected[artifact.artifact_ref])
        )
        if removed:
            record_deleted_support_artifacts(removed, service_root=service_root)

    try:
        # The bundle is removed first so a metadata-unlink failure leaves the
        # source-free typed metadata available for a truthful retry.
        ordered_paths = tuple(sorted(paths, key=lambda item: (item.suffix.casefold() != ".zip", item.as_posix())))
        for path in ordered_paths:
            _safe_target(path, target_root)
            if path.exists():
                path.unlink()
            record_removed()
    except (KSlideError, OSError):
        record_removed()
        raise
    record_removed()


def _class_for_relative(relative: str) -> DeletionArtifactClass:
    top = relative.split("/", 1)[0]
    name = Path(relative).name
    if name == "CONFLICT_REGISTRY.json":
        return DeletionArtifactClass.CANONICAL_IR
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
    if top == "support-content":
        return DeletionArtifactClass.SUPPORT_CONTENT
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

    def __init__(self, root: Path, run_ref: str, *, operational_root: Path | None) -> None:
        self.root = Path(root).expanduser().resolve()
        self.run_ref = _opaque(run_ref, "run reference", strict=True)
        self.run_dir = self.root / ".k-slide-runs" / self.run_ref
        self.scope_ref = "workspace"
        if operational_root is None:
            raise KSlideError(ErrorCode.DELETION_INVALID, "Workspace deletion requires an explicit external operational-metadata root.")
        self.operational_root = Path(operational_root).expanduser()
        if self.operational_root.is_symlink():
            raise KSlideError(ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT, "Operational-metadata root may not be a symbolic link.")
        self._layout = StorageLayout.for_workspace_root(self.root, central_telemetry_root=self.operational_root)

    @contextmanager
    def lock(self) -> Iterator[None]:
        with run_lock(self.run_dir):
            yield

    def audit_path(self, deletion_id: str, *, create_parent: bool = False) -> Path:
        deletion_id = _opaque(deletion_id, "deletion identity", strict=True)
        return self._layout.path(StorageArtifact.DELETION_AUDIT, f"_deletions/workspace/{self.run_ref}/{deletion_id}.json", create_parent=create_parent)

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
        self._set_fence(audit.state in {DeletionState.IN_PROGRESS, DeletionState.PARTIAL})

    def _set_fence(self, active: bool) -> None:
        fence_root = self.root / ".k-slide-runs" / "_deletion-fences"
        fence_path = fence_root / f"{self.run_ref}.json"
        if fence_root.is_symlink() or (fence_root.exists() and not fence_root.is_dir()):
            raise KSlideError(ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT, "Workspace deletion fence root is unsafe.")
        if active:
            fence_root.mkdir(parents=True, exist_ok=True, mode=0o700)
            atomic_write_json(fence_path, {"scope_ref": self.scope_ref, "run_ref": self.run_ref, "state": "IN_PROGRESS"}, mode=0o600)
        else:
            if fence_path.is_symlink():
                raise KSlideError(ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT, "Workspace deletion fence may not be a symbolic link.")
            fence_path.unlink(missing_ok=True)
        state_path = self.run_dir / "RUN_STATE.json"
        if not state_path.is_file() or state_path.is_symlink():
            return
        value = read_json(state_path)
        if not isinstance(value, dict):
            raise KSlideError(ErrorCode.STATE_CORRUPT, "Run state is not an object.")
        desired = "IN_PROGRESS" if active else None
        if value.get("deletion_fence") == desired:
            return
        if active:
            value["deletion_fence"] = "IN_PROGRESS"
        else:
            value.pop("deletion_fence", None)
        atomic_write_json(state_path, value, mode=0o600)

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
        generation_anchors: list[tuple[str, str]] = []
        state_path = self.run_dir / "RUN_STATE.json"
        if state_path.is_file() and not state_path.is_symlink():
            generation_anchors.append(
                (
                    DeletionArtifactClass.RUN_STATE.value,
                    stable_revision(
                        {
                            "run_id": raw.get("run_id", self.run_ref),
                            "created_at": raw.get("created_at", ""),
                            "updated_at": raw.get("updated_at", ""),
                            "revision": raw.get("revision", 0),
                        }
                    ),
                )
            )
        job_path = self.run_dir / "EXECUTION_JOB.json"
        terminal_phases = {item.value for item in (RunPhase.COMPLETE, RunPhase.FAILED_INPUT, RunPhase.FAILED_RUNTIME, RunPhase.FAILED_NORMALIZATION, RunPhase.FAILED_EXTRACTION, RunPhase.FAILED_SCHEMA, RunPhase.FAILED_INTERNAL)}
        active = state_path.is_file() and phase not in terminal_phases
        if job_path.is_file():
            try:
                # The coordinator already owns the run lock. Read directly so
                # a PARTIAL audit fence does not block its own retry path.
                job = WorkspaceRunStore(self.run_dir)._read(job_path, f"job-{self.run_ref}")
                job_identity = {"run_ref": job.run_id, "job_ref": job.job_id, "execution_ref": job.execution_id, "store_ref": job.store_ref.store_ref}
                generation_anchors.append(
                    (
                        DeletionArtifactClass.EXECUTION_JOB.value,
                        stable_revision({"identity": job_identity, "created_at": job.created_at}),
                    )
                )
                job_lifecycle = job.lifecycle
                active = job.lifecycle in {OperationalLifecycle.QUEUED, OperationalLifecycle.RUNNING, OperationalLifecycle.RETRYING}
            except KSlideError as exc:
                if exc.code is not ErrorCode.EXECUTION_NOT_FOUND:
                    raise
        generation = stable_revision({"scope_ref": self.scope_ref, "run_ref": self.run_ref, "state": {"run_id": raw.get("run_id", self.run_ref), "created_at": raw.get("created_at", ""), "updated_at": raw.get("updated_at", ""), "revision": raw.get("revision", 0)}, "job": job_identity})
        phase_terminal = not state_path.exists() or phase in terminal_phases
        canceled = bool(job_identity and job_lifecycle is OperationalLifecycle.CANCELED)
        return _BackendState(generation, active, phase_terminal or canceled, canceled, tuple(sorted(generation_anchors)))

    def request_cancellation(self) -> None:
        path = self.run_dir / "EXECUTION_JOB.json"
        if not path.is_file():
            return
        store = WorkspaceRunStore(self.run_dir)
        job = store._read(path, f"job-{self.run_ref}")
        if job.cancellation.requested or job.lifecycle in {OperationalLifecycle.COMPLETED, OperationalLifecycle.CANCELED, OperationalLifecycle.PROCESSING_FAILED}:
            return
        candidate = replace(job, cancellation=CancellationState(True, False, f"cancel-{job.job_id}", now_utc(), None), revision=job.revision + 1, updated_at=now_utc())
        store._write(candidate)

    def _paths_for_class(self, artifact: DeletionArtifactClass) -> tuple[Path, ...]:
        paths: list[Path] = []
        if self.run_dir.exists():
            paths.extend(
                path for path in _safe_files(self.run_dir)
                if _class_for_relative(path.relative_to(self.run_dir).as_posix()) is artifact
            )
        sessions = self.root / ".k-slide-runs" / "_sessions"
        if sessions.is_dir():
            for path in _safe_files(sessions):
                try:
                    value = read_json(path)
                except (KSlideError, OSError, TypeError, ValueError):
                    continue
                if artifact is DeletionArtifactClass.SESSION_BINDING and isinstance(value, dict) and value.get("run_id") == self.run_ref:
                    paths.append(path)
        return tuple(sorted(paths, key=lambda item: item.as_posix()))

    def enumerate_targets(self, deletion_id: str) -> tuple[_Candidate, ...]:
        classes: set[DeletionArtifactClass] = set()
        if self.run_dir.exists():
            for path in _safe_files(self.run_dir):
                classes.add(_class_for_relative(path.relative_to(self.run_dir).as_posix()))
        sessions = self.root / ".k-slide-runs" / "_sessions"
        if sessions.is_dir() and self._paths_for_class(DeletionArtifactClass.SESSION_BINDING):
            classes.add(DeletionArtifactClass.SESSION_BINDING)
        return tuple(
            _Candidate(artifact, _target_ref(self.scope_ref, self.run_ref, deletion_id, artifact))
            for artifact in sorted(classes, key=lambda item: item.value)
        )

    def prepare_support_recovery(self, candidate: _Candidate) -> tuple[ControlledSupportDeletionRecord, ...]:
        if candidate.artifact_class is not DeletionArtifactClass.SUPPORT_CONTENT:
            return ()
        return _support_recovery_from_metadata(self.run_dir / "support-content")

    def delete_target(self, candidate: _Candidate, *, support_recovery: tuple[ControlledSupportDeletionRecord, ...] = ()) -> None:
        if candidate.artifact_class is DeletionArtifactClass.SUPPORT_CONTENT:
            support_dir = self.run_dir / "support-content"
            _delete_support_content(
                self._paths_for_class(candidate.artifact_class),
                support_dir=support_dir,
                target_root=self.run_dir,
                service_root=self.operational_root,
                support_recovery=support_recovery,
            )
            return
        for path in self._paths_for_class(candidate.artifact_class):
            target_root = self.run_dir if path.is_relative_to(self.run_dir) else self.root / ".k-slide-runs" / "_sessions"
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
        StorageLayout.for_workspace(self.run_dir).cleanup_scratch(allow_deletion=True)


class ScopedReferenceDeletionBackend:
    """Reference PaaS backend bound to one exact authorized job identity."""

    def __init__(self, service: Any, *, identity: Any, scope_context: Any) -> None:
        from .paas import AuthorizedScopeContext, DurableJobIdentity

        if not isinstance(scope_context, AuthorizedScopeContext):
            raise _invalid("Deletion requires an authorized scope context.")
        if not isinstance(identity, (DurableJobIdentity, str)):
            raise _invalid("Deletion requires a durable job identity.")
        self.service = service
        self.scope_context = scope_context
        self.scope_ref = str(scope_context.scope_ref)
        if isinstance(identity, DurableJobIdentity):
            if identity.scope_ref != scope_context.scope_ref:
                raise KSlideError(ErrorCode.EXECUTION_NOT_FOUND, "Durable execution is unavailable.")
            # The admission record is a deletion target.  It is authoritative
            # when present, but it cannot be a prerequisite for reopening a
            # central audit after a partial or complete deletion.
            record_path = service._scope_record_path(scope_context, identity.job_id)
            record = service._read_scoped_record(scope_context, identity.job_id) if record_path.is_file() else None
            if record is not None and record.identity != identity:
                raise KSlideError(ErrorCode.EXECUTION_NOT_FOUND, "Durable execution is unavailable.")
            resolved = identity
        else:
            record = service._read_scoped_record(scope_context, identity)
            resolved = record.identity
        self.identity = resolved
        self.record = record
        self.run_ref = resolved.run_id
        self.scope_root = service._scope_root(scope_context)
        self.identity_ref = stable_revision(resolved.as_dict())
        if record is None:
            audit_dir = self._audit_root() / self.run_ref / resolved.job_id
            if not audit_dir.is_dir() or not any(path.suffix == ".json" for path in audit_dir.iterdir()):
                raise KSlideError(ErrorCode.EXECUTION_NOT_FOUND, "Durable execution is unavailable.")

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
        scope_key = self.service._scope_key(self.scope_context)
        # The job identity is part of the locator.  ``run_ref`` alone is not
        # sufficient: a new durable job may legitimately reuse an external
        # run name after the old control record has been deleted.
        return layout.path(StorageArtifact.DELETION_AUDIT, f"_deletions/{scope_key}/{self.run_ref}/{self.identity.job_id}/{deletion_id}.json", create_parent=create_parent)

    def _audit_root(self) -> Path:
        return self.service._central_operational_root() / "_deletions" / self.service._scope_key(self.scope_context)

    def _read_audit_file(self, path: Path) -> DeletionAudit:
        if path.is_symlink():
            raise KSlideError(ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT, "Deletion audit record is a symbolic link.")
        try:
            return DeletionAudit.from_dict(read_json(path))
        except KSlideError:
            raise
        except (OSError, TypeError, ValueError) as exc:
            raise KSlideError(ErrorCode.STATE_CORRUPT, "Deletion audit record is corrupt or unreadable.") from exc

    def load_audit(self, deletion_id: str) -> DeletionAudit | None:
        path = self.audit_path(deletion_id)
        audit_root = self._audit_root()
        if audit_root.is_symlink():
            raise KSlideError(ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT, "Deletion audit root is a symbolic link.")
        records: list[tuple[Path, DeletionAudit]] = []
        if audit_root.is_dir():
            for candidate in _safe_files(audit_root):
                if candidate.suffix == ".json":
                    records.append((candidate, self._read_audit_file(candidate)))
        expected_identity_dir = path.parent
        requested: DeletionAudit | None = None
        for candidate, audit in records:
            if audit.scope_ref != self.scope_ref:
                raise KSlideError(ErrorCode.EXECUTION_CONFLICT, "Deletion audit is outside the authorized scope.")
            if candidate == path:
                if audit.run_ref != self.run_ref:
                    raise KSlideError(ErrorCode.EXECUTION_CONFLICT, "Deletion audit identity does not match the authorized run.")
                if audit.identity_ref != self.identity_ref:
                    raise KSlideError(ErrorCode.EXECUTION_NOT_FOUND, "Durable execution is unavailable.")
                requested = audit
                continue
            # A different deletion ID for this exact typed identity is not a
            # new operation.  It would otherwise allow a caller to replay
            # after the admission record has been removed.
            if candidate.parent == expected_identity_dir:
                raise KSlideError(ErrorCode.EXECUTION_CONFLICT, "A deletion audit already exists for this durable identity.")
            # Likewise, the same deletion ID bound to another run/job in the
            # authorized scope must not be adopted by this identity.
            if audit.deletion_id == deletion_id:
                raise KSlideError(ErrorCode.EXECUTION_CONFLICT, "Deletion identity is bound to a different durable job.")
        return requested

    def save_audit(self, audit: DeletionAudit) -> None:
        if audit.identity_ref not in {None, self.identity_ref}:
            raise KSlideError(ErrorCode.EXECUTION_NOT_FOUND, "Durable execution is unavailable.")
        if audit.identity_ref is None:
            audit = replace(audit, identity_ref=self.identity_ref)
        atomic_write_json(self.audit_path(audit.deletion_id, create_parent=True), audit.as_dict(), mode=0o600)

    def _job_if_present(self) -> Any | None:
        backend = self.service._scoped_store(self.scope_context)._backend
        path = backend._path_for(self.identity.job_id)
        if not path.is_file():
            return None
        return backend._read(path, self.identity.job_id)

    def state(self) -> _BackendState:
        job = self._job_if_present()
        record_path = self.service._scope_record_path(self.scope_context, self.identity.job_id)
        current_record = self.service._read_scoped_record(self.scope_context, self.identity.job_id) if record_path.is_file() else None
        if current_record is not None and current_record.identity != self.identity:
            raise KSlideError(ErrorCode.EXECUTION_CONFLICT, "Durable deletion identity changed.")
        generation_anchors: list[tuple[str, str]] = []
        if current_record is not None:
            generation_anchors.append(
                (
                    DeletionArtifactClass.ADMISSION_RECORD.value,
                    stable_revision(
                        {
                            "identity": current_record.identity.as_dict(),
                            "environment": current_record.environment_identity.as_dict(),
                            "submitted_at": current_record.submitted_at,
                            "admission_sequence": current_record.admission_sequence,
                        }
                    ),
                )
        )
        if job is None:
            generation = stable_revision((current_record.identity if current_record is not None else self.identity).as_dict())
            return _BackendState(generation, False, True, False, tuple(sorted(generation_anchors)))
        if job.run_id != self.identity.run_id or job.job_id != self.identity.job_id or job.execution_id != self.identity.execution_id:
            raise KSlideError(ErrorCode.EXECUTION_CONFLICT, "Durable deletion identity changed.")
        generation_anchors.append(
            (
                DeletionArtifactClass.EXECUTION_JOB.value,
                stable_revision(
                    {
                        "identity": self.identity.as_dict(),
                        "environment": job.environment_identity.as_dict() if job.environment_identity is not None else None,
                        "created_at": job.created_at,
                    }
                ),
            )
        )
        generation_record = current_record or self.record
        generation = stable_revision(
            {
                "identity": self.identity.as_dict(),
                "environment": generation_record.environment_identity.as_dict() if generation_record is not None else (job.environment_identity.as_dict() if job.environment_identity is not None else None),
            }
        )
        active = job.lifecycle in {OperationalLifecycle.QUEUED, OperationalLifecycle.RUNNING, OperationalLifecycle.RETRYING}
        return _BackendState(generation, active, not active, job.lifecycle is OperationalLifecycle.CANCELED, tuple(sorted(generation_anchors)))

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

    def _paths_for_class(self, artifact: DeletionArtifactClass) -> tuple[Path, ...]:
        paths: list[Path] = []
        content_root = self._content_root()
        if content_root.exists():
            paths.extend(
                path for path in _safe_files(content_root)
                if _class_for_relative(path.relative_to(content_root).as_posix()) is artifact
            )
        record_path = self.service._scope_record_path(self.scope_context, self.identity.job_id)
        exec_path = self.scope_root / "run-store" / "jobs" / f"{self.identity.job_id}.json"
        for candidate_artifact, path in ((DeletionArtifactClass.ADMISSION_RECORD, record_path), (DeletionArtifactClass.EXECUTION_JOB, exec_path)):
            if candidate_artifact is artifact and path.is_file():
                paths.append(path)
            elif path.is_symlink():
                raise KSlideError(ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT, "Deletion refuses a symbolic-link control target.")
        return tuple(sorted(paths, key=lambda item: item.as_posix()))

    def enumerate_targets(self, deletion_id: str) -> tuple[_Candidate, ...]:
        classes: set[DeletionArtifactClass] = set()
        content_root = self._content_root()
        if content_root.exists():
            for path in _safe_files(content_root):
                classes.add(_class_for_relative(path.relative_to(content_root).as_posix()))
        record_path = self.service._scope_record_path(self.scope_context, self.identity.job_id)
        exec_path = self.scope_root / "run-store" / "jobs" / f"{self.identity.job_id}.json"
        for artifact, path in ((DeletionArtifactClass.ADMISSION_RECORD, record_path), (DeletionArtifactClass.EXECUTION_JOB, exec_path)):
            if path.is_file():
                classes.add(artifact)
            elif path.is_symlink():
                raise KSlideError(ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT, "Deletion refuses a symbolic-link control target.")
        for artifact, path in ((DeletionArtifactClass.ADMISSION_CONTROL, self.service._scope_control_path(self.scope_context)), (DeletionArtifactClass.ADMISSION_QUEUE, self.service._scope_queue_path(self.scope_context))):
            if path.is_file():
                classes.add(artifact)
            elif path.is_symlink():
                raise KSlideError(ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT, "Deletion refuses a symbolic-link admission target.")
        return tuple(
            _Candidate(
                artifact,
                _target_ref(self.scope_ref, self.run_ref, deletion_id, artifact),
                control=artifact in {DeletionArtifactClass.ADMISSION_CONTROL, DeletionArtifactClass.ADMISSION_QUEUE},
            )
            for artifact in sorted(classes, key=lambda item: (0 if item in {DeletionArtifactClass.ADMISSION_CONTROL, DeletionArtifactClass.ADMISSION_QUEUE} else 1, item.value))
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

    def prepare_support_recovery(self, candidate: _Candidate) -> tuple[ControlledSupportDeletionRecord, ...]:
        if candidate.artifact_class is not DeletionArtifactClass.SUPPORT_CONTENT:
            return ()
        return _support_recovery_from_metadata(self._content_root() / "support-content")

    def delete_target(self, candidate: _Candidate, *, support_recovery: tuple[ControlledSupportDeletionRecord, ...] = ()) -> None:
        if candidate.control:
            self._invalidate_control()
            return
        if candidate.artifact_class is DeletionArtifactClass.SUPPORT_CONTENT:
            support_dir = self._content_root() / "support-content"
            _delete_support_content(
                self._paths_for_class(candidate.artifact_class),
                support_dir=support_dir,
                target_root=self._content_root(),
                service_root=self.service.root,
                support_recovery=support_recovery,
            )
            return
        content_root = self._content_root()
        for path in self._paths_for_class(candidate.artifact_class):
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


def _generation_matches(state: _BackendState, audit: DeletionAudit) -> bool:
    """Accept only the same immutable generation across deletion retries.

    A missing anchor is safe once the audit proves that the corresponding
    target was part of this deletion.  A newly present anchor must still
    match its source-free proof; this is what rejects a recreated run/control
    record with a reused external name.
    """

    expected = dict(audit.generation_anchors)
    current = dict(state.generation_anchors)
    if expected:
        if set(current) - set(expected):
            return False
        target_status = {item.artifact_class.value: item.status for item in audit.targets}
        for name, reference in expected.items():
            if name in current:
                if current[name] != reference:
                    return False
                continue
            if target_status.get(name) not in {TargetStatus.PLANNED, TargetStatus.DELETED, TargetStatus.ABSENT, TargetStatus.FAILED}:
                return False
        return True

    if state.generation_ref == audit.target_generation_ref:
        return True
    # Audits written before generation anchors were introduced can still be
    # resumed after all of their identity-bearing targets were removed.  A
    # newly recreated anchor remains visible and therefore cannot take this
    # compatibility path.
    if state.generation_anchors:
        return False
    anchor_classes = {DeletionArtifactClass.RUN_STATE.value, DeletionArtifactClass.EXECUTION_JOB.value, DeletionArtifactClass.ADMISSION_RECORD.value}
    recorded = [item for item in audit.targets if item.artifact_class.value in anchor_classes]
    return bool(recorded) and all(item.status in {TargetStatus.PLANNED, TargetStatus.DELETED, TargetStatus.ABSENT, TargetStatus.FAILED} for item in recorded)


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
                # A completed audit is source-free and remains replayable after
                # its targets are gone, but a reused external identity may have
                # produced a new generation in the meantime.  Validate that
                # generation under the backend lock before returning the old
                # outcome; never validate by replaying destructive targets.
                with self.backend.lock():
                    current = self.backend.load_audit(request.deletion_id)
                    if current is not None:
                        state = self.backend.state()
                        if _generation_matches(state, current):
                            return self._result(request, state=current.state, outcome=current.outcome, dry_run=dry_run, retry_count=current.retry_count, error_code=current.error_code, targets=current.targets)
                        blocked = replace(current, updated_at=now_utc(), state=DeletionState.BLOCKED, outcome=DeletionOutcome.BLOCKED, error_code="TARGET_IDENTITY_MISMATCH", retry_count=current.retry_count + 1)
                        if not dry_run:
                            self.backend.save_audit(blocked)
                        return self._result(request, state=blocked.state, outcome=blocked.outcome, dry_run=dry_run, retry_count=blocked.retry_count, error_code=blocked.error_code, targets=blocked.targets)

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
            if current is not None and current.targets and not _generation_matches(state, current):
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
            audit = current or DeletionAudit(DELETION_CONTRACT_VERSION, request.deletion_id, request.scope_ref, request.run_ref, request.reason, state.generation_ref, hold.authority_ref, hold.decision_ref, request.requested_at, request.requested_at, 0, DeletionState.PLANNED, DeletionOutcome.PLANNED, "NONE", tuple(DeletionTargetRecord(item.target_ref, item.artifact_class, TargetStatus.PLANNED) for item in candidates), state.generation_anchors)
            if not audit.targets:
                audit = replace(audit, targets=tuple(DeletionTargetRecord(item.target_ref, item.artifact_class, TargetStatus.PLANNED) for item in candidates))
            if not audit.support_recovery:
                support_candidates = [item for item in candidates if item.artifact_class is DeletionArtifactClass.SUPPORT_CONTENT]
                if support_candidates:
                    support_recovery = self.backend.prepare_support_recovery(support_candidates[0])
                    if support_recovery:
                        audit = replace(audit, support_recovery=support_recovery)
            known = {item.target_ref: item for item in audit.targets}
            added = [item for item in candidates if item.target_ref not in known]
            if added:
                audit = replace(audit, targets=tuple((*audit.targets, *(DeletionTargetRecord(item.target_ref, item.artifact_class, TargetStatus.FAILED, "TARGET_ADDED") for item in added))))
            active_audit = replace(
                audit,
                authority_ref=hold.authority_ref,
                hold_decision_ref=hold.decision_ref,
                # The first durable plan owns the generation for all retries.
                # Live state may legitimately lose its anchors during this
                # same deletion attempt.
                target_generation_ref=audit.target_generation_ref,
                generation_anchors=audit.generation_anchors or state.generation_anchors,
                updated_at=now_utc(),
                retry_count=audit.retry_count + 1,
                state=DeletionState.IN_PROGRESS,
                outcome=DeletionOutcome.IN_PROGRESS,
                error_code="NONE",
            )
            self.backend.save_audit(active_audit)
            by_ref = {item.target_ref: item for item in candidates}
            target_records = list(active_audit.targets)
            # Ordinary target failures are unfinished and are retried.  A
            # target that appeared after the durable plan is intentionally
            # never adopted by a stale deletion request.
            failed = any(item.status is TargetStatus.FAILED and item.result_code == "TARGET_ADDED" for item in target_records)
            for index, record in enumerate(target_records):
                candidate = by_ref.get(record.target_ref)
                support_recovery = audit.support_recovery if record.artifact_class is DeletionArtifactClass.SUPPORT_CONTENT else ()
                if candidate is None and support_recovery and record.artifact_class is DeletionArtifactClass.SUPPORT_CONTENT and record.status is not TargetStatus.DELETED:
                    # The support bytes may already be gone after an audit
                    # writer failure.  Reopen the typed support target from
                    # the durable recovery facts so its final event can be
                    # retried without resurrecting content metadata.
                    candidate = _Candidate(record.artifact_class, record.target_ref)
                if record.status is TargetStatus.FAILED and record.result_code == "TARGET_ADDED":
                    continue
                if record.status in {TargetStatus.DELETED, TargetStatus.ABSENT} and candidate is None:
                    continue
                if candidate is None:
                    target_records[index] = replace(record, status=TargetStatus.ABSENT, result_code="ALREADY_ABSENT")
                    continue
                try:
                    if self.failure_injector is not None and self.failure_injector(candidate):
                        raise OSError("injected")
                    self.backend.delete_target(candidate, support_recovery=support_recovery)
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


def delete_workspace_run(
    root: Path,
    *,
    run_ref: str,
    deletion_id: str,
    scope_context: Any | None = None,
    reason: DeletionReason = DeletionReason.EXPLICIT,
    hold_provider: LegalHoldProvider | None = None,
    dry_run: bool = False,
    failure_injector: Callable[[_Candidate], bool] | None = None,
    operational_root: Path | None = None,
    central_operational_root: Path | None = None,
    audit_root: Path | None = None,
) -> DeletionResult:
    from .paas import AuthorizedScopeContext

    if not isinstance(scope_context, AuthorizedScopeContext) or scope_context.scope_ref != "workspace":
        raise KSlideError(ErrorCode.EXECUTION_CONFLICT, "Workspace deletion requires an authorized workspace scope context.")
    roots = [value for value in (operational_root, central_operational_root, audit_root) if value is not None]
    if len({Path(value).expanduser().resolve() for value in roots}) > 1:
        raise KSlideError(ErrorCode.DELETION_INVALID, "Workspace deletion operational roots disagree.")
    selected_root = roots[0] if roots else None
    if hold_provider is None:
        raise KSlideError(ErrorCode.LEGAL_HOLD_UNKNOWN, "An authoritative legal-hold provider is required before deletion.")
    backend = WorkspaceDeletionBackend(root, run_ref, operational_root=selected_root)
    return DeletionCoordinator(backend, hold_provider=hold_provider, failure_injector=failure_injector).run(deletion_id, reason=reason, dry_run=dry_run)


def delete_scoped_run(service: Any, *, identity: Any, scope_context: Any, deletion_id: str, reason: DeletionReason = DeletionReason.EXPLICIT, hold_provider: LegalHoldProvider | None = None, dry_run: bool = False, failure_injector: Callable[[_Candidate], bool] | None = None) -> DeletionResult:
    if hold_provider is None:
        raise KSlideError(ErrorCode.LEGAL_HOLD_UNKNOWN, "An authoritative legal-hold provider is required before deletion.")
    backend = ScopedReferenceDeletionBackend(service, identity=identity, scope_context=scope_context)
    return DeletionCoordinator(backend, hold_provider=hold_provider, failure_injector=failure_injector).run(deletion_id, reason=reason, dry_run=dry_run)


def _metadata_policy(retention_policy: RetentionPolicy | Mapping[str, Any]) -> RetentionPolicy:
    try:
        policy = retention_policy if isinstance(retention_policy, RetentionPolicy) else RetentionPolicy.from_mapping(retention_policy, require_resolved=True)
        policy.require_resolved()
        return policy
    except (TypeError, ValueError) as exc:
        raise KSlideError(ErrorCode.RETENTION_INVALID, "Invalid retention policy for operational-metadata cleanup.", {"reason": type(exc).__name__}) from exc


def _operational_root(root: Path, *, workspace_namespace: Path | None = None) -> Path:
    value = Path(root).expanduser()
    if value.is_symlink():
        raise KSlideError(ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT, "Operational-metadata root is a symbolic link.")
    resolved = value.resolve()
    if workspace_namespace is not None:
        namespace = Path(workspace_namespace).expanduser().resolve()
        try:
            resolved.relative_to(namespace)
            inside = True
        except ValueError:
            inside = False
        try:
            namespace.relative_to(resolved)
            contains = True
        except ValueError:
            contains = False
        if inside or contains:
            raise KSlideError(ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT, "Operational-metadata root must be external to the workspace content namespace.")
    return resolved


def _safe_operational_path(path: Path, root: Path) -> Path:
    if path.is_symlink() or root.is_symlink():
        raise KSlideError(ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT, "Operational-metadata path is a symbolic link.")
    try:
        relative = path.relative_to(root)
        path.resolve(strict=False).relative_to(root.resolve(strict=False))
    except (OSError, ValueError) as exc:
        raise KSlideError(ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT, "Operational-metadata path escaped its configured root.") from exc
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise KSlideError(ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT, "Operational-metadata path contains a symbolic link.")
    return path


def _audit_files(audit_root: Path, *, scope_ref: str) -> list[tuple[Path, DeletionAudit]]:
    if audit_root.is_symlink():
        raise KSlideError(ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT, "Deletion audit root is a symbolic link.")
    if not audit_root.is_dir():
        return []
    root = audit_root.resolve()
    values: list[tuple[Path, DeletionAudit]] = []
    for path in sorted(audit_root.rglob("*.json"), key=lambda item: item.as_posix()):
        _safe_operational_path(path, root)
        try:
            audit = DeletionAudit.from_dict(read_json(path))
        except (KSlideError, OSError, TypeError, ValueError) as exc:
            if isinstance(exc, KSlideError) and exc.code is ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT:
                raise
            raise KSlideError(ErrorCode.STATE_CORRUPT, "Deletion audit record is corrupt or unreadable.") from exc
        if audit.scope_ref != scope_ref:
            raise KSlideError(ErrorCode.EXECUTION_CONFLICT, "Deletion audit is outside the authorized scope.")
        values.append((path, audit))
    return values


def _cleanup_operational_metadata_at_root(
    operational_root: Path,
    audit_root: Path,
    policy: RetentionPolicy,
    *,
    scope_ref: str,
    hold_provider: LegalHoldProvider,
    now: Any | None,
    dry_run: bool,
) -> dict[str, Any]:
    from datetime import datetime, timedelta, timezone

    current = now or datetime.now(timezone.utc)
    if not hasattr(current, "astimezone"):
        raise KSlideError(ErrorCode.RETENTION_INVALID, "Operational-metadata cleanup time is invalid.")
    cutoff = current.astimezone(timezone.utc) - timedelta(days=int(policy.operational_metadata_retention_days))
    expired: list[str] = []
    retained: list[str] = []
    audit_roots = [audit_root]
    try:
        nested_relative = audit_root.relative_to(operational_root)
    except ValueError:
        nested_relative = None
    if nested_relative is not None:
        nested_audit_root = operational_root / "telemetry" / nested_relative
        if nested_audit_root.is_symlink() or nested_audit_root.is_dir():
            audit_roots.append(nested_audit_root)
    for selected_audit_root in audit_roots:
        for path, audit in _audit_files(selected_audit_root, scope_ref=scope_ref):
            updated = datetime.fromisoformat(audit.updated_at.replace("Z", "+00:00")).astimezone(timezone.utc)
            if updated < cutoff:
                hold = _safe_hold(hold_provider, scope_ref=audit.scope_ref, run_ref=audit.run_ref)
                if hold.status is not LegalHoldStatus.RELEASE:
                    retained.append(audit.deletion_id)
                    continue
                expired.append(audit.deletion_id)
                if not dry_run:
                    _safe_operational_path(path, operational_root)
                    path.unlink()
            else:
                retained.append(audit.deletion_id)

    telemetry_expired: list[str] = []
    telemetry_retained: list[str] = []
    telemetry_paths = [operational_root / "events.jsonl"]
    nested_telemetry_path = operational_root / "telemetry" / "events.jsonl"
    if nested_telemetry_path != telemetry_paths[0] and (nested_telemetry_path.exists() or nested_telemetry_path.is_symlink()):
        telemetry_paths.append(nested_telemetry_path)
    for telemetry_path in telemetry_paths:
        if not (telemetry_path.exists() or telemetry_path.is_symlink()):
            continue
        _safe_operational_path(telemetry_path, operational_root)
        with filesystem_lock(telemetry_path.parent / ".events.lock", require_shared=True, reject_symlink=True):
            try:
                if telemetry_path.stat().st_size > 64 * 1024 * 1024:
                    raise KSlideError(ErrorCode.STATE_CORRUPT, "Central telemetry stream exceeds its byte bound.")
                lines = telemetry_path.read_text(encoding="utf-8").splitlines()
            except (OSError, UnicodeError) as exc:
                raise KSlideError(ErrorCode.STATE_CORRUPT, "Central telemetry records are unreadable.") from exc
            from .telemetry import TelemetryEvent

            kept_lines: list[str] = []
            stream_expired = False
            for line in lines:
                if not line:
                    continue
                try:
                    event = TelemetryEvent.from_mapping(json.loads(line))
                    occurred = datetime.fromisoformat(event.occurred_at.replace("Z", "+00:00")).astimezone(timezone.utc)
                except (KSlideError, TypeError, ValueError, json.JSONDecodeError) as exc:
                    raise KSlideError(ErrorCode.STATE_CORRUPT, "Central telemetry record is malformed or has an invalid timestamp.") from exc
                if occurred < cutoff:
                    held_scope = event.scope_ref or scope_ref
                    held_run = event.run_ref or event.event_id
                    hold = _safe_hold(hold_provider, scope_ref=held_scope, run_ref=held_run)
                    kept = hold.status is not LegalHoldStatus.RELEASE
                    if kept:
                        telemetry_retained.append(str(event.event_id))
                    else:
                        telemetry_expired.append(str(event.event_id))
                        stream_expired = True
                else:
                    telemetry_retained.append(str(event.event_id))
                    kept = True
                if kept:
                    kept_lines.append(json.dumps(event.as_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")))
            if stream_expired and not dry_run:
                atomic_write_text(telemetry_path, "\n".join(kept_lines) + ("\n" if kept_lines else ""), mode=0o600)
    from .content_support import cleanup_support_access_audit

    support_audit = cleanup_support_access_audit(
        operational_root,
        scope_ref=scope_ref,
        cutoff=cutoff,
        hold_lookup=hold_provider.lookup,
        dry_run=dry_run,
    )
    return {
        "status": "PASS",
        "dry_run": dry_run,
        "retention_policy": policy.as_dict(),
        "expired": expired,
        "retained": retained,
        "expired_telemetry": telemetry_expired,
        "retained_telemetry": telemetry_retained,
        "support_access_audit": support_audit,
        "cutoff": cutoff.isoformat(),
    }


def cleanup_operational_metadata(
    root: Path,
    retention_policy: RetentionPolicy | Mapping[str, Any],
    *,
    scope_context: Any | None = None,
    hold_provider: LegalHoldProvider | None = None,
    operational_root: Path | None = None,
    central_operational_root: Path | None = None,
    audit_root: Path | None = None,
    now: Any | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Expire typed deletion audits and central telemetry in the operational plane."""

    from .paas import AuthorizedScopeContext

    policy = _metadata_policy(retention_policy)
    if not isinstance(scope_context, AuthorizedScopeContext) or scope_context.scope_ref != "workspace":
        raise KSlideError(ErrorCode.EXECUTION_CONFLICT, "Operational-metadata cleanup requires an authorized workspace scope context.")
    if hold_provider is None:
        raise KSlideError(ErrorCode.LEGAL_HOLD_UNKNOWN, "An authoritative legal-hold provider is required before retention expiry.")
    roots = [value for value in (operational_root, central_operational_root, audit_root) if value is not None]
    if len({Path(value).expanduser().resolve() for value in roots}) > 1:
        raise KSlideError(ErrorCode.DELETION_INVALID, "Operational-metadata roots disagree.")
    if not roots:
        raise KSlideError(ErrorCode.DELETION_INVALID, "Operational-metadata cleanup requires an explicit external operational root.")
    selected = _operational_root(roots[0], workspace_namespace=Path(root).expanduser().resolve())
    return _cleanup_operational_metadata_at_root(
        selected,
        selected / "_deletions" / "workspace",
        policy,
        scope_ref=scope_context.scope_ref,
        hold_provider=hold_provider,
        now=now,
        dry_run=dry_run,
    )


def cleanup_scoped_operational_metadata(
    service: Any,
    *,
    scope_context: Any,
    retention_policy: RetentionPolicy | Mapping[str, Any],
    hold_provider: LegalHoldProvider | None = None,
    now: Any | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Expire one authorized PaaS scope's audits and the central telemetry stream."""

    from .paas import AuthorizedScopeContext

    policy = _metadata_policy(retention_policy)
    if not isinstance(scope_context, AuthorizedScopeContext):
        raise KSlideError(ErrorCode.EXECUTION_CONFLICT, "Operational-metadata cleanup requires an authorized scope context.")
    if hold_provider is None:
        raise KSlideError(ErrorCode.LEGAL_HOLD_UNKNOWN, "An authoritative legal-hold provider is required before retention expiry.")
    operational = _operational_root(service._central_operational_root())
    return _cleanup_operational_metadata_at_root(
        operational,
        service._scoped_deletion_root(scope_context),
        policy,
        scope_ref=scope_context.scope_ref,
        hold_provider=hold_provider,
        now=now,
        dry_run=dry_run,
    )


__all__ = [
    "DELETION_CONTRACT_VERSION", "DeletionArtifactClass", "DeletionAudit", "DeletionCoordinator", "DeletionOutcome", "DeletionReason", "DeletionRequest", "DeletionResult", "DeletionResultCode", "DeletionState", "DeletionTargetRecord", "LegalHoldDecision", "LegalHoldDecisionType", "LegalHoldProvider", "LegalHoldStatus", "ReferenceLegalHoldProvider", "StaticLegalHoldProvider", "TargetStatus", "cleanup_operational_metadata", "cleanup_scoped_operational_metadata", "delete_scoped_run", "delete_workspace_run",
]


# Compatibility spelling for adapters that use the decision-type name.
LegalHoldDecisionType = LegalHoldStatus
