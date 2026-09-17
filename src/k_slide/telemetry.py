"""Fail-closed, source-free central operational telemetry."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Mapping

from .errors import ErrorCode, KSlideError
from .locking import filesystem_lock
from .storage import StorageArtifact, StorageLayout, StoragePlane


TELEMETRY_SCHEMA_VERSION = "1.0"
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_CODE = re.compile(r"^[A-Z][A-Z0-9_.:-]{0,63}$")
_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")
_FORBIDDEN = (
    "accesskey", "access_key", "access-key", "authorization", "bearer", "secret", "token", "password",
    "credential", "source", "content", "prompt", "ocr", "translation", "report", "evidence", "screenshot",
    "image", "binary", "bytes", "filename", "filepath", "filesystem", "path", "exception", "traceback",
    "payload", "metadata", "text", "document", "slide", "workspace", "user",
)
_FORBIDDEN_CODE = ("accesskey", "access_key", "access-key", "authorization", "bearer", "secret", "token", "password", "credential", "source", "content", "prompt", "ocr", "translation", "report", "evidence", "screenshot", "image", "binary", "bytes", "filename", "filepath", "filesystem", "path", "exception", "traceback", "payload", "metadata", "text")
_ALLOWED_FIELDS = {
    "schema_version", "event_type", "event_id", "occurred_at", "deployment_ref", "runtime_ref", "model_ref",
    "run_ref", "worker_ref", "lifecycle", "error_code", "stage", "duration_ms", "count", "resource_units",
    "retry_attempt",
}
_PATH_LIKE = re.compile(r"(?:^[/\\~]|^[A-Za-z]:|://|\.(?:pptx|ppt|pdf|png|jpg|jpeg|webp|json|md|txt|csv|zip)$)", re.IGNORECASE)


class TelemetryEventType(str, Enum):
    LIFECYCLE = "lifecycle"
    ERROR = "error"
    STAGE_TIMING = "stage_timing"
    RESOURCE = "resource"
    RETRY = "retry"
    RUNTIME_BINDING = "runtime_binding"


def _reject_content_tree(value: Any, *, key: str | None = None) -> None:
    """Reject content-shaped values before any serialization or redaction."""

    if key is not None:
        normalized = re.sub(r"[^a-z0-9]", "", key.lower())
        if normalized in {re.sub(r"[^a-z0-9]", "", item) for item in _FORBIDDEN} or normalized not in {re.sub(r"[^a-z0-9]", "", item) for item in _ALLOWED_FIELDS}:
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


def _safe_string(value: Any, label: str, *, code: bool = False) -> str:
    pattern = _CODE if code else _IDENTIFIER
    forbidden = _FORBIDDEN_CODE if code else _FORBIDDEN
    if not isinstance(value, str) or not pattern.fullmatch(value) or _PATH_LIKE.search(value) or any(word in value.lower().replace("_", "") for word in forbidden):
        raise KSlideError(ErrorCode.EXECUTION_INVALID, f"Telemetry {label} is invalid or content-shaped.")
    return value


def _bounded_int(value: Any, label: str, *, maximum: int = 100_000_000_000) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > maximum:
        raise KSlideError(ErrorCode.EXECUTION_INVALID, f"Telemetry {label} is outside the bounded range.")
    return value


@dataclass(frozen=True)
class TelemetryEvent:
    event_type: TelemetryEventType
    event_id: str
    occurred_at: str
    deployment_ref: str | None = None
    runtime_ref: str | None = None
    model_ref: str | None = None
    run_ref: str | None = None
    worker_ref: str | None = None
    lifecycle: str | None = None
    error_code: str | None = None
    stage: str | None = None
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
        _safe_string(self.event_id, "event ID")
        if not isinstance(self.occurred_at, str) or not _TIMESTAMP.fullmatch(self.occurred_at):
            raise KSlideError(ErrorCode.EXECUTION_INVALID, "Telemetry timestamp is invalid.")
        for value, label in (
            (self.deployment_ref, "deployment reference"), (self.runtime_ref, "runtime reference"),
            (self.model_ref, "model reference"), (self.run_ref, "run reference"), (self.worker_ref, "worker reference"),
            (self.lifecycle, "lifecycle"), (self.stage, "stage"),
        ):
            if value is not None:
                _safe_string(value, label)
        if self.error_code is not None:
            _safe_string(self.error_code, "error code", code=True)
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
        if self.layout.scope_ref not in {None, "workspace"}:
            raise KSlideError(ErrorCode.EXECUTION_INVALID, "Central telemetry writer may not be scoped to a user/workspace namespace.")

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


__all__ = ["TELEMETRY_SCHEMA_VERSION", "TelemetryEvent", "TelemetryEventType", "TelemetryWriter"]
