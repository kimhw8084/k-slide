"""Fail-closed, source-free central operational telemetry."""

from __future__ import annotations

import json
import hashlib
import os
import re
from uuid import UUID, uuid4
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Mapping

from .errors import ErrorCode, KSlideError
from .locking import filesystem_lock
from .io import atomic_write_text
from .storage import StorageArtifact, StorageLayout, StoragePlane


TELEMETRY_SCHEMA_VERSION = "1.0"
_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")
_ALLOWED_FIELDS = {
    "schema_version", "event_type", "event_id", "occurred_at", "deployment_ref", "runtime_ref", "model_ref",
    "run_ref", "worker_ref", "lifecycle", "error_code", "stage", "duration_ms", "count", "resource_units",
    "retry_attempt", "scope_ref", "candidate_ref", "host", "artifact_class", "semantic_outcome",
    "review_category", "issue_category", "issue_report_status",
}
_REFERENCE = re.compile(r"^kslide-ref-v1\.(deployment|runtime|model|run|worker|event|scope|candidate)\.([0-9a-f]{64})$")
_NORMALIZED_ALLOWED_FIELDS = {re.sub(r"[^a-z0-9]", "", field.lower()) for field in _ALLOWED_FIELDS}
MAX_TELEMETRY_EVENT_BYTES = 4096
MAX_TELEMETRY_STREAM_BYTES = 64 * 1024 * 1024
MAX_TELEMETRY_RECORDS = 100_000


class TelemetryEventType(str, Enum):
    LIFECYCLE = "lifecycle"
    ERROR = "error"
    STAGE_TIMING = "stage_timing"
    RESOURCE = "resource"
    RETRY = "retry"
    RUNTIME_BINDING = "runtime_binding"
    ISSUE_REPORT = "issue_report"


class TelemetryReferenceKind(str, Enum):
    DEPLOYMENT = "deployment"
    RUNTIME = "runtime"
    MODEL = "model"
    RUN = "run"
    WORKER = "worker"
    EVENT = "event"
    SCOPE = "scope"
    CANDIDATE = "candidate"


class TelemetryHost(str, Enum):
    CLOUD_VSCODE = "cloud_vscode"
    OPENCODE = "opencode"
    LOCAL_CLI = "local_cli"
    PAAS_WORKER = "paas_worker"


class TelemetryArtifactClass(str, Enum):
    PRESENTATION = "presentation"
    PDF = "pdf"
    IMAGE = "image"
    MIXED = "mixed"
    UNKNOWN = "unknown"


class TelemetrySemanticOutcome(str, Enum):
    PENDING = "PENDING"
    DONE = "DONE"
    NEEDS_REVIEW = "NEEDS_REVIEW"


class TelemetryReviewCategory(str, Enum):
    NONE = "NONE"
    SOURCE_EVIDENCE = "SOURCE_EVIDENCE"
    WORK_UNIT_INCOMPLETE = "WORK_UNIT_INCOMPLETE"
    VERIFICATION_FAILURE = "VERIFICATION_FAILURE"
    UNRESOLVED_CONFLICT = "UNRESOLVED_CONFLICT"
    REQUIRED_ARTIFACT_MISSING = "REQUIRED_ARTIFACT_MISSING"


class TelemetryIssueCategory(str, Enum):
    MEANING_ERROR = "meaning_error"
    NUMBER_ERROR = "number_error"
    OMISSION = "omission"
    FALSE_DONE = "false_done"
    UNNECESSARY_REVIEW = "unnecessary_review"


class TelemetryLifecycle(str, Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    RETRYING = "RETRYING"
    COMPLETED = "COMPLETED"
    CANCELED = "CANCELED"
    PROCESSING_FAILED = "PROCESSING_FAILED"
    STARTED = "STARTED"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    RESUMED = "RESUMED"
    CANCEL_REQUESTED = "CANCEL_REQUESTED"


class TelemetryStage(str, Enum):
    PREPARING = "PREPARING"
    ADMISSION = "ADMISSION"
    NORMALIZING = "NORMALIZING"
    EXTRACTING = "EXTRACTING"
    TRANSLATING = "TRANSLATING"
    VERIFYING = "VERIFYING"
    FINALIZING = "FINALIZING"
    RUNTIME_BINDING = "RUNTIME_BINDING"
    RETRYING = "RETRYING"
    ISSUE_REPORT = "ISSUE_REPORT"


def _reference_kind(value: TelemetryReferenceKind | str) -> TelemetryReferenceKind:
    try:
        return value if isinstance(value, TelemetryReferenceKind) else TelemetryReferenceKind(str(value))
    except ValueError as exc:
        raise KSlideError(ErrorCode.EXECUTION_INVALID, "Telemetry reference kind is unsupported.") from exc


@dataclass(frozen=True)
class TelemetryMachineId:
    """A machine-shaped identity for telemetry subjects without a product type."""

    kind: TelemetryReferenceKind
    value: UUID

    def __post_init__(self) -> None:
        kind = _reference_kind(self.kind)
        if not isinstance(self.value, UUID) or self.value.version != 4:
            raise KSlideError(ErrorCode.EXECUTION_INVALID, "Telemetry machine identity must be a version-four UUID.")
        object.__setattr__(self, "kind", kind)

    @classmethod
    def new(cls, kind: TelemetryReferenceKind | str) -> "TelemetryMachineId":
        return cls(_reference_kind(kind), uuid4())

    @property
    def canonical(self) -> str:
        return f"{self.kind.value}:{self.value}"


@dataclass(frozen=True, init=False)
class TelemetryReference:
    """Canonical opaque telemetry reference.

    ``from_internal`` accepts only a typed, machine-shaped product identity;
    it does not accept arbitrary mappings or content and the input identity is
    never persisted. ``from_identity`` is for existing typed product identity
    objects that expose their canonical ``as_dict`` representation.
    """

    kind: TelemetryReferenceKind
    digest: str

    def __init__(self, kind: TelemetryReferenceKind | str, digest: str) -> None:
        raise KSlideError(
            ErrorCode.EXECUTION_INVALID,
            "Telemetry references must be constructed from a typed identity or canonical persisted value.",
        )

    @classmethod
    def _from_digest(cls, kind: TelemetryReferenceKind | str, digest: str) -> "TelemetryReference":
        kind = _reference_kind(kind)
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise KSlideError(ErrorCode.EXECUTION_INVALID, "Telemetry reference digest is not canonical.")
        value = object.__new__(cls)
        object.__setattr__(value, "kind", kind)
        object.__setattr__(value, "digest", digest)
        return value

    @property
    def canonical(self) -> str:
        return f"kslide-ref-v1.{self.kind.value}.{self.digest}"

    def __str__(self) -> str:
        return self.canonical

    @classmethod
    def from_canonical(cls, value: Any, *, expected_kind: TelemetryReferenceKind | str | None = None) -> "TelemetryReference":
        if not isinstance(value, str):
            raise KSlideError(ErrorCode.EXECUTION_INVALID, "Telemetry references must be canonical opaque strings.")
        match = _REFERENCE.fullmatch(value)
        if match is None:
            raise KSlideError(ErrorCode.EXECUTION_INVALID, "Telemetry reference is not a canonical opaque identity.")
        reference = cls._from_digest(TelemetryReferenceKind(match.group(1)), match.group(2))
        if expected_kind is not None and reference.kind is not _reference_kind(expected_kind):
            raise KSlideError(ErrorCode.EXECUTION_INVALID, "Telemetry reference kind does not match its field.")
        return reference

    @classmethod
    def from_internal(cls, kind: TelemetryReferenceKind | str, identity: TelemetryMachineId) -> "TelemetryReference":
        """Derive a reference from a K-Slide-issued, machine-shaped identity."""

        kind = _reference_kind(kind)
        if type(identity) is not TelemetryMachineId or identity.kind is not kind:
            raise KSlideError(ErrorCode.EXECUTION_INVALID, "Telemetry identity must be a typed machine ID of the requested kind.")
        digest = hashlib.sha256(f"k-slide-telemetry-v1\x00{kind.value}\x00{identity.canonical}".encode("utf-8")).hexdigest()
        return cls._from_digest(kind, digest)

    @classmethod
    def for_transition(
        cls,
        run_ref: "TelemetryReference | str",
        revision: int,
        event_type: "TelemetryEventType",
        *,
        stage: "TelemetryStage | None" = None,
        error_code: ErrorCode | None = None,
        host: "TelemetryHost | str | None" = None,
    ) -> "TelemetryReference":
        """Build a retry-stable event ID from closed engine transition metadata."""

        checked_run = run_ref if type(run_ref) is TelemetryReference else cls.from_canonical(run_ref, expected_kind=TelemetryReferenceKind.RUN)
        if checked_run.kind is not TelemetryReferenceKind.RUN:
            raise KSlideError(ErrorCode.EXECUTION_INVALID, "Telemetry transition requires a run reference.")
        _bounded_int(revision, "transition revision")
        if not isinstance(event_type, TelemetryEventType):
            raise KSlideError(ErrorCode.EXECUTION_INVALID, "Telemetry transition event type must be closed and typed.")
        if stage is not None and not isinstance(stage, TelemetryStage):
            raise KSlideError(ErrorCode.EXECUTION_INVALID, "Telemetry transition stage must be closed and typed.")
        if error_code is not None and not isinstance(error_code, ErrorCode):
            raise KSlideError(ErrorCode.EXECUTION_INVALID, "Telemetry transition error must be a closed K-Slide code.")
        try:
            selected_host = None if host is None else (host if isinstance(host, TelemetryHost) else TelemetryHost(str(host)))
        except ValueError as exc:
            raise KSlideError(ErrorCode.EXECUTION_INVALID, "Telemetry transition host must be a closed host adapter.") from exc
        key = "\x00".join((checked_run.canonical, str(revision), event_type.value, stage.value if stage else "", error_code.value if error_code else "", selected_host.value if selected_host else ""))
        digest = hashlib.sha256(f"k-slide-telemetry-transition-v1\x00{key}".encode("utf-8")).hexdigest()
        return cls._from_digest(TelemetryReferenceKind.EVENT, digest)

    @classmethod
    def from_identity(cls, kind: TelemetryReferenceKind | str, identity: Any) -> "TelemetryReference":
        """Derive a reference from an existing typed identity object."""

        kind = _reference_kind(kind)
        if type(identity) is TelemetryMachineId:
            return cls.from_internal(kind, identity)

        from .environment import RunEnvironmentIdentity
        from .paas import AuthorizedScopeContext, DurableJobIdentity, RuntimeIdentity

        # These relationships are deliberately explicit.  In particular, a
        # scope context is authorization state, not a telemetry subject;
        # RuntimeIdentity is a runtime subject, not a run or model subject.
        if type(identity) is RunEnvironmentIdentity:
            if kind is TelemetryReferenceKind.CANDIDATE:
                return cls._from_digest(kind, identity.candidate_identity)
            if kind is TelemetryReferenceKind.RUNTIME:
                return cls._from_digest(kind, identity.runtime_artifact_identity)
            if kind not in {TelemetryReferenceKind.DEPLOYMENT, TelemetryReferenceKind.MODEL}:
                raise KSlideError(ErrorCode.EXECUTION_INVALID, "Run environment identity does not match the requested telemetry reference kind.")
        identity_relationships = (
            (AuthorizedScopeContext, frozenset({TelemetryReferenceKind.SCOPE})),
            (DurableJobIdentity, frozenset({TelemetryReferenceKind.RUN, TelemetryReferenceKind.SCOPE})),
            (RunEnvironmentIdentity, frozenset({TelemetryReferenceKind.DEPLOYMENT, TelemetryReferenceKind.MODEL})),
            (RuntimeIdentity, frozenset({TelemetryReferenceKind.RUNTIME})),
        )
        value: Mapping[str, Any] | None = None
        for identity_type, allowed_kinds in identity_relationships:
            if type(identity) is identity_type:
                if kind not in allowed_kinds:
                    raise KSlideError(ErrorCode.EXECUTION_INVALID, "Telemetry identity type does not match the requested reference kind.")
                value = identity.as_dict()
                break
        if value is None:
            raise KSlideError(ErrorCode.EXECUTION_INVALID, "Telemetry identity must be a supported typed internal identity, not a caller payload.")
        try:
            canonical = json.dumps(dict(value), ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        except (TypeError, ValueError) as exc:
            raise KSlideError(ErrorCode.EXECUTION_INVALID, "Telemetry identity representation is invalid.") from exc
        digest = hashlib.sha256(f"k-slide-telemetry-v1\x00{kind.value}\x00{canonical}".encode("utf-8")).hexdigest()
        return cls._from_digest(kind, digest)


def _reject_content_tree(value: Any, *, key: str | None = None) -> None:
    """Reject content-shaped values before any serialization or redaction."""

    if key is not None:
        normalized = re.sub(r"[^a-z0-9]", "", key.lower())
        if normalized not in _NORMALIZED_ALLOWED_FIELDS:
            raise KSlideError(ErrorCode.EXECUTION_INVALID, "Telemetry contains an unknown or content-shaped field.")
    if isinstance(value, Mapping):
        for child_key, child_value in value.items():
            if not isinstance(child_key, str):
                raise KSlideError(ErrorCode.EXECUTION_INVALID, "Telemetry field names must be strings.")
            _reject_content_tree(child_value, key=child_key)
    elif isinstance(value, (list, tuple, set)):
        raise KSlideError(ErrorCode.EXECUTION_INVALID, "Telemetry does not accept arbitrary nested collections.")
    elif isinstance(value, (bytes, bytearray, memoryview)):
        raise KSlideError(ErrorCode.EXECUTION_INVALID, "Telemetry does not accept binary values.")


def _reference(value: Any, label: str, kind: TelemetryReferenceKind) -> str:
    try:
        reference = value if type(value) is TelemetryReference else TelemetryReference.from_canonical(value, expected_kind=kind)
        if reference.kind is not kind:
            raise KSlideError(ErrorCode.EXECUTION_INVALID, "Telemetry reference kind does not match its field.")
        return reference.canonical
    except KSlideError:
        raise KSlideError(ErrorCode.EXECUTION_INVALID, f"Telemetry {label} must be a canonical opaque identity.")


def _enum_value(value: Any, label: str, enum_type: type[Enum]) -> str:
    try:
        selected = value if isinstance(value, enum_type) else enum_type(str(value))
    except ValueError as exc:
        raise KSlideError(ErrorCode.EXECUTION_INVALID, f"Telemetry {label} is not an allowed bounded code.") from exc
    return str(selected.value)


def _error_code(value: Any) -> str:
    if isinstance(value, ErrorCode):
        return value.value
    try:
        return ErrorCode(str(value)).value
    except ValueError as exc:
        raise KSlideError(ErrorCode.EXECUTION_INVALID, "Telemetry error code is not an allowed K-Slide error code.") from exc


def _bounded_int(value: Any, label: str, *, maximum: int = 100_000_000_000) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > maximum:
        raise KSlideError(ErrorCode.EXECUTION_INVALID, f"Telemetry {label} is outside the bounded range.")
    return value


@dataclass(frozen=True)
class TelemetryEvent:
    event_type: TelemetryEventType
    event_id: TelemetryReference | str
    occurred_at: str
    deployment_ref: TelemetryReference | str | None = None
    runtime_ref: TelemetryReference | str | None = None
    model_ref: TelemetryReference | str | None = None
    run_ref: TelemetryReference | str | None = None
    worker_ref: TelemetryReference | str | None = None
    lifecycle: TelemetryLifecycle | str | None = None
    error_code: ErrorCode | str | None = None
    stage: TelemetryStage | str | None = None
    duration_ms: int | None = None
    count: int | None = None
    resource_units: int | None = None
    retry_attempt: int | None = None
    scope_ref: TelemetryReference | str | None = None
    candidate_ref: TelemetryReference | str | None = None
    host: TelemetryHost | str | None = None
    artifact_class: TelemetryArtifactClass | str | None = None
    semantic_outcome: TelemetrySemanticOutcome | str | None = None
    review_category: TelemetryReviewCategory | str | None = None
    issue_category: TelemetryIssueCategory | str | None = None
    issue_report_status: str | None = None
    schema_version: str = TELEMETRY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != TELEMETRY_SCHEMA_VERSION:
            raise KSlideError(ErrorCode.EXECUTION_UNSUPPORTED_VERSION, "Unsupported telemetry schema version.")
        try:
            event_type = self.event_type if isinstance(self.event_type, TelemetryEventType) else TelemetryEventType(str(self.event_type))
        except ValueError as exc:
            raise KSlideError(ErrorCode.EXECUTION_INVALID, "Telemetry event type is unsupported.") from exc
        object.__setattr__(self, "event_type", event_type)
        object.__setattr__(self, "event_id", _reference(self.event_id, "event ID", TelemetryReferenceKind.EVENT))
        if not isinstance(self.occurred_at, str) or not _TIMESTAMP.fullmatch(self.occurred_at):
            raise KSlideError(ErrorCode.EXECUTION_INVALID, "Telemetry timestamp is invalid.")
        for field_name, value, label, kind in (
            ("deployment_ref", self.deployment_ref, "deployment reference", TelemetryReferenceKind.DEPLOYMENT),
            ("runtime_ref", self.runtime_ref, "runtime reference", TelemetryReferenceKind.RUNTIME),
            ("model_ref", self.model_ref, "model reference", TelemetryReferenceKind.MODEL),
            ("run_ref", self.run_ref, "run reference", TelemetryReferenceKind.RUN),
            ("worker_ref", self.worker_ref, "worker reference", TelemetryReferenceKind.WORKER),
            ("scope_ref", self.scope_ref, "scope reference", TelemetryReferenceKind.SCOPE),
            ("candidate_ref", self.candidate_ref, "candidate reference", TelemetryReferenceKind.CANDIDATE),
        ):
            if value is not None:
                object.__setattr__(self, field_name, _reference(value, label, kind))
        if self.lifecycle is not None:
            object.__setattr__(self, "lifecycle", _enum_value(self.lifecycle, "lifecycle", TelemetryLifecycle))
        if self.stage is not None:
            object.__setattr__(self, "stage", _enum_value(self.stage, "stage", TelemetryStage))
        if self.error_code is not None:
            object.__setattr__(self, "error_code", _error_code(self.error_code))
        for field_name, value, enum_type in (
            ("host", self.host, TelemetryHost),
            ("artifact_class", self.artifact_class, TelemetryArtifactClass),
            ("semantic_outcome", self.semantic_outcome, TelemetrySemanticOutcome),
            ("review_category", self.review_category, TelemetryReviewCategory),
            ("issue_category", self.issue_category, TelemetryIssueCategory),
        ):
            if value is not None:
                object.__setattr__(self, field_name, _enum_value(value, field_name.replace("_", " "), enum_type))
        if self.issue_report_status is not None and self.issue_report_status != "ALLEGATION":
            raise KSlideError(ErrorCode.EXECUTION_INVALID, "Employee issue reports must remain unadjudicated allegations.")
        if event_type is TelemetryEventType.ISSUE_REPORT:
            if self.issue_category is None or self.issue_report_status != "ALLEGATION" or self.run_ref is None or self.host is None:
                raise KSlideError(ErrorCode.EXECUTION_INVALID, "Employee issue reports require a bounded category, host, run reference, and allegation status.")
            if self.semantic_outcome is None or self.review_category is None:
                raise KSlideError(ErrorCode.EXECUTION_INVALID, "Employee issue reports require engine-derived semantic status and review category.")
        elif self.issue_category is not None or self.issue_report_status is not None:
            raise KSlideError(ErrorCode.EXECUTION_INVALID, "Issue allegation fields are only valid on issue-report events.")
        if self.semantic_outcome == TelemetrySemanticOutcome.DONE.value and self.review_category not in {None, TelemetryReviewCategory.NONE.value}:
            raise KSlideError(ErrorCode.EXECUTION_INVALID, "DONE telemetry cannot carry a review category.")
        if self.semantic_outcome == TelemetrySemanticOutcome.NEEDS_REVIEW.value and self.review_category in {None, TelemetryReviewCategory.NONE.value}:
            raise KSlideError(ErrorCode.EXECUTION_INVALID, "NEEDS_REVIEW telemetry requires a review category.")
        for value, label in (
            (self.duration_ms, "duration"), (self.count, "count"), (self.resource_units, "resource use"),
            (self.retry_attempt, "retry attempt"),
        ):
            if value is not None:
                _bounded_int(value, label)

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "event_type": self.event_type.value,
            "event_id": self.event_id,
            "occurred_at": self.occurred_at,
            **{key: value for key, value in (
                ("deployment_ref", self.deployment_ref), ("runtime_ref", self.runtime_ref), ("model_ref", self.model_ref),
                ("run_ref", self.run_ref), ("worker_ref", self.worker_ref), ("lifecycle", self.lifecycle),
                ("error_code", self.error_code), ("stage", self.stage), ("duration_ms", self.duration_ms),
                ("count", self.count), ("resource_units", self.resource_units), ("retry_attempt", self.retry_attempt),
                ("scope_ref", self.scope_ref), ("candidate_ref", self.candidate_ref), ("host", self.host),
                ("artifact_class", self.artifact_class), ("semantic_outcome", self.semantic_outcome),
                ("review_category", self.review_category), ("issue_category", self.issue_category),
                ("issue_report_status", self.issue_report_status),
            ) if value is not None},
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "TelemetryEvent":
        if not isinstance(value, Mapping):
            raise KSlideError(ErrorCode.EXECUTION_INVALID, "Telemetry event must be an explicit event object.")
        _reject_content_tree(value)
        if set(value) - _ALLOWED_FIELDS or set(value) != _ALLOWED_FIELDS.intersection(value):
            raise KSlideError(ErrorCode.EXECUTION_INVALID, "Telemetry event contains unsupported fields.")
        try:
            return cls(**dict(value))
        except TypeError as exc:
            raise KSlideError(ErrorCode.EXECUTION_INVALID, "Telemetry event has an invalid shape.") from exc


class TelemetryWriteStatus(str, Enum):
    RECORDED = "RECORDED"
    IDEMPOTENT = "IDEMPOTENT"
    CONFLICT = "CONFLICT"
    CAPACITY_LIMIT = "CAPACITY_LIMIT"
    CORRUPT = "CORRUPT"
    UNAVAILABLE = "UNAVAILABLE"


class TelemetryWriter:
    """Reference central telemetry writer; validation errors fail closed.

    Filesystem loss is intentionally non-fatal to run execution.  A caller
    receives ``False`` and can continue from durable state, while malformed
    or content-shaped observations are rejected before I/O.
    """

    def __init__(self, service_root: Path, *, layout: StorageLayout | None = None) -> None:
        self.layout = layout or StorageLayout.for_service(service_root)
        if self.layout.scope_ref is not None:
            raise KSlideError(ErrorCode.EXECUTION_INVALID, "Central telemetry writer may not be scoped to a user/workspace namespace.")
        if self.layout.telemetry_root is None:
            raise KSlideError(ErrorCode.EXECUTION_INVALID, "Central telemetry writer requires an explicitly configured central service root.")

    @property
    def event_path(self) -> Path:
        return self.layout.path(StorageArtifact.TELEMETRY_EVENT, "events.jsonl", create_parent=True)

    def record(self, event: TelemetryEvent | Mapping[str, Any]) -> TelemetryWriteStatus:
        if isinstance(event, TelemetryEvent):
            checked = event
        elif isinstance(event, Mapping):
            checked = TelemetryEvent.from_mapping(event)
        else:
            raise KSlideError(ErrorCode.EXECUTION_INVALID, "Telemetry requires a typed event; arbitrary objects are rejected.")
        line = json.dumps(checked.as_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
        encoded_line = line.encode("utf-8")
        if len(encoded_line) > MAX_TELEMETRY_EVENT_BYTES:
            return TelemetryWriteStatus.CAPACITY_LIMIT
        try:
            event_path = self.event_path
            if event_path.is_symlink():
                return TelemetryWriteStatus.CORRUPT
            lock_path = self.layout.path(StorageArtifact.TELEMETRY_COORDINATION_LOCK, ".events.lock", create_parent=True)
            with filesystem_lock(lock_path, require_shared=True, reject_symlink=True):
                if event_path.exists() and event_path.stat().st_size > MAX_TELEMETRY_STREAM_BYTES:
                    return TelemetryWriteStatus.CAPACITY_LIMIT
                existing_text = event_path.read_text(encoding="utf-8") if event_path.is_file() else ""
                existing_bytes = existing_text.encode("utf-8")
                if len(existing_bytes) > MAX_TELEMETRY_STREAM_BYTES:
                    return TelemetryWriteStatus.CAPACITY_LIMIT
                records: list[TelemetryEvent] = []
                for current_line in existing_text.splitlines():
                    if not current_line:
                        continue
                    try:
                        current = TelemetryEvent.from_mapping(json.loads(current_line))
                    except (KSlideError, TypeError, ValueError, json.JSONDecodeError):
                        return TelemetryWriteStatus.CORRUPT
                    if current.event_id == checked.event_id:
                        prior = current.as_dict()
                        incoming = checked.as_dict()
                        prior.pop("occurred_at", None)
                        incoming.pop("occurred_at", None)
                        return TelemetryWriteStatus.IDEMPOTENT if prior == incoming else TelemetryWriteStatus.CONFLICT
                    records.append(current)
                if len(records) >= MAX_TELEMETRY_RECORDS or len(existing_bytes) + len(encoded_line) > MAX_TELEMETRY_STREAM_BYTES:
                    return TelemetryWriteStatus.CAPACITY_LIMIT
                atomic_write_text(event_path, existing_text + line, mode=0o600)
            return TelemetryWriteStatus.RECORDED
        except (KSlideError, OSError, UnicodeError):
            return TelemetryWriteStatus.UNAVAILABLE

    def write(self, event: TelemetryEvent | Mapping[str, Any]) -> bool:
        return self.record(event) in {TelemetryWriteStatus.RECORDED, TelemetryWriteStatus.IDEMPOTENT}

    def records(self) -> tuple[TelemetryEvent, ...]:
        try:
            if self.event_path.is_symlink() or (self.event_path.exists() and self.event_path.stat().st_size > MAX_TELEMETRY_STREAM_BYTES):
                return ()
            lines = self.event_path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError):
            return ()
        if len(lines) > MAX_TELEMETRY_RECORDS:
            return ()
        values: list[TelemetryEvent] = []
        for line in lines:
            if not line:
                continue
            values.append(TelemetryEvent.from_mapping(json.loads(line)))
        return tuple(values)

    def find(self, event_id: TelemetryReference | str, *, run_ref: TelemetryReference | str) -> TelemetryEvent | None:
        checked_event = _reference(event_id, "event ID", TelemetryReferenceKind.EVENT)
        checked_run = _reference(run_ref, "run reference", TelemetryReferenceKind.RUN)
        event_path = self.event_path
        if event_path.is_symlink():
            raise KSlideError(ErrorCode.STATE_CORRUPT, "Central telemetry stream may not be a symbolic link.")
        lock_path = self.layout.path(StorageArtifact.TELEMETRY_COORDINATION_LOCK, ".events.lock", create_parent=True)
        with filesystem_lock(lock_path, require_shared=True, reject_symlink=True):
            if not event_path.is_file():
                return None
            if event_path.stat().st_size > MAX_TELEMETRY_STREAM_BYTES:
                raise KSlideError(ErrorCode.STATE_CORRUPT, "Central telemetry stream exceeds its byte bound.")
            lines = event_path.read_text(encoding="utf-8").splitlines()
            if len(lines) > MAX_TELEMETRY_RECORDS:
                raise KSlideError(ErrorCode.STATE_CORRUPT, "Central telemetry stream exceeds its record bound.")
            for line in lines:
                if not line:
                    continue
                event = TelemetryEvent.from_mapping(json.loads(line))
                if event.event_id == checked_event and event.run_ref == checked_run and event.event_type is TelemetryEventType.ISSUE_REPORT:
                    return event
        return None


def configured_telemetry_writer() -> TelemetryWriter | None:
    """Build the optional central writer from trusted process configuration."""

    service_root = os.environ.get("KSLIDE_OPERATIONAL_SERVICE_ROOT")
    if not service_root:
        return None
    try:
        return TelemetryWriter(Path(service_root).expanduser())
    except (KSlideError, OSError, ValueError):
        return None


TelemetryErrorCode = ErrorCode


__all__ = [
    "TELEMETRY_SCHEMA_VERSION", "TelemetryArtifactClass", "TelemetryErrorCode", "TelemetryEvent", "TelemetryEventType",
    "TelemetryHost", "TelemetryIssueCategory", "TelemetryLifecycle", "TelemetryMachineId", "TelemetryReference",
    "TelemetryReferenceKind", "TelemetryReviewCategory", "TelemetrySemanticOutcome", "TelemetryStage", "TelemetryWriteStatus",
    "TelemetryWriter", "configured_telemetry_writer",
]
