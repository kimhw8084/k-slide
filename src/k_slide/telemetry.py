"""Fail-closed, source-free central operational telemetry."""

from __future__ import annotations

import json
import hashlib
import re
from uuid import UUID, uuid4
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Mapping

from .errors import ErrorCode, KSlideError
from .locking import filesystem_lock
from .storage import StorageArtifact, StorageLayout, StoragePlane


TELEMETRY_SCHEMA_VERSION = "1.0"
_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")
_ALLOWED_FIELDS = {
    "schema_version", "event_type", "event_id", "occurred_at", "deployment_ref", "runtime_ref", "model_ref",
    "run_ref", "worker_ref", "lifecycle", "error_code", "stage", "duration_ms", "count", "resource_units",
    "retry_attempt",
}
_REFERENCE = re.compile(r"^kslide-ref-v1\.(deployment|runtime|model|run|worker|event)\.([0-9a-f]{64})$")
_NORMALIZED_ALLOWED_FIELDS = {re.sub(r"[^a-z0-9]", "", field.lower()) for field in _ALLOWED_FIELDS}


class TelemetryEventType(str, Enum):
    LIFECYCLE = "lifecycle"
    ERROR = "error"
    STAGE_TIMING = "stage_timing"
    RESOURCE = "resource"
    RETRY = "retry"
    RUNTIME_BINDING = "runtime_binding"


class TelemetryReferenceKind(str, Enum):
    DEPLOYMENT = "deployment"
    RUNTIME = "runtime"
    MODEL = "model"
    RUN = "run"
    WORKER = "worker"
    EVENT = "event"


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


class TelemetryStage(str, Enum):
    ADMISSION = "ADMISSION"
    NORMALIZING = "NORMALIZING"
    EXTRACTING = "EXTRACTING"
    TRANSLATING = "TRANSLATING"
    VERIFYING = "VERIFYING"
    FINALIZING = "FINALIZING"
    RUNTIME_BINDING = "RUNTIME_BINDING"
    RETRYING = "RETRYING"


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
        identity_relationships = (
            (AuthorizedScopeContext, frozenset()),
            (DurableJobIdentity, frozenset({TelemetryReferenceKind.RUN})),
            (RunEnvironmentIdentity, frozenset({TelemetryReferenceKind.DEPLOYMENT})),
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
        ):
            if value is not None:
                object.__setattr__(self, field_name, _reference(value, label, kind))
        if self.lifecycle is not None:
            object.__setattr__(self, "lifecycle", _enum_value(self.lifecycle, "lifecycle", TelemetryLifecycle))
        if self.stage is not None:
            object.__setattr__(self, "stage", _enum_value(self.stage, "stage", TelemetryStage))
        if self.error_code is not None:
            object.__setattr__(self, "error_code", _error_code(self.error_code))
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

    def write(self, event: TelemetryEvent | Mapping[str, Any]) -> bool:
        if isinstance(event, TelemetryEvent):
            checked = event
        elif isinstance(event, Mapping):
            checked = TelemetryEvent.from_mapping(event)
        else:
            raise KSlideError(ErrorCode.EXECUTION_INVALID, "Telemetry requires a typed event; arbitrary objects are rejected.")
        line = json.dumps(checked.as_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
        try:
            event_path = self.event_path
            lock_path = self.layout.path(StorageArtifact.TELEMETRY_COORDINATION_LOCK, ".events.lock", create_parent=True)
            with filesystem_lock(lock_path):
                with event_path.open("a", encoding="utf-8") as handle:
                    handle.write(line)
                    handle.flush()
            return True
        except OSError:
            return False

    record = write

    def records(self) -> tuple[TelemetryEvent, ...]:
        try:
            lines = self.event_path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError):
            return ()
        values: list[TelemetryEvent] = []
        for line in lines:
            if not line:
                continue
            values.append(TelemetryEvent.from_mapping(json.loads(line)))
        return tuple(values)


TelemetryErrorCode = ErrorCode


__all__ = [
    "TELEMETRY_SCHEMA_VERSION", "TelemetryErrorCode", "TelemetryEvent", "TelemetryEventType", "TelemetryLifecycle",
    "TelemetryMachineId", "TelemetryReference", "TelemetryReferenceKind", "TelemetryStage", "TelemetryWriter",
]
