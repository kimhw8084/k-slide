"""Versioned execution/job contract and restartable run-store adapters.

The execution record is operational control metadata only.  ``RunState`` and
``WorkQueue`` remain the engine authorities for semantic phase transitions,
EvidenceIR, and work-unit content.  A store owns one compare-and-set record
which points at those engine revisions and records the last accepted
checkpoint/result marker.
"""

from __future__ import annotations

import re
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from enum import Enum
from pathlib import Path
from threading import RLock
from typing import Any, Iterator, Mapping, Protocol

from . import EXECUTION_CONTRACT_VERSION, RUN_STORE_SCHEMA_VERSION
from .environment import RunEnvironmentIdentity, raise_environment_mismatch
from .errors import ErrorCode, KSlideError
from .evidence_ir import stable_revision
from .io import atomic_write_json, read_json
from .locking import filesystem_lock, run_lock
from .queue import WorkQueue, load_queue
from .state import RunPhase, RunState, load_state, now_utc


_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_PHASE = re.compile(r"^[A-Z][A-Z0-9_.:-]{0,63}$")
_ERROR_CODE = re.compile(r"^[A-Z][A-Z0-9_.:-]{0,63}$")
_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_SAFE_METADATA_KEY = re.compile(r"^[a-z][a-z0-9_.:-]{0,63}$")
_SAFE_METADATA_VALUE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_MAX_RESULT_MARKERS = 256
_MAX_METADATA = 8
_FORBIDDEN_METADATA_WORDS = (
    "access",
    "secret",
    "token",
    "password",
    "credential",
    "source",
    "content",
    "prompt",
    "translation",
    "text",
    "image",
    "path",
    "ocr",
)


def _invalid(message: str, *, code: ErrorCode = ErrorCode.EXECUTION_INVALID) -> KSlideError:
    return KSlideError(code, message)


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise _invalid(f"Execution contract has an invalid {label}.")
    return value


def _phase(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _PHASE.fullmatch(value):
        raise _invalid(f"Execution contract has an invalid {label}.")
    return value


def _error_code(value: Any) -> str:
    if not isinstance(value, str) or not _ERROR_CODE.fullmatch(value) or any(word in value.lower() for word in ("access", "secret", "token", "password", "credential", "source", "content", "prompt", "translation", "text", "image", "path")):
        raise _invalid("Execution retry error code is invalid.")
    return value


def _metadata(value: Mapping[str, Any], label: str) -> dict[str, str]:
    if not isinstance(value, Mapping) or len(value) > _MAX_METADATA:
        raise _invalid(f"Execution {label} metadata is not bounded.")
    result: dict[str, str] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not _SAFE_METADATA_KEY.fullmatch(key) or any(word in key.lower() for word in _FORBIDDEN_METADATA_WORDS):
            raise _invalid(f"Execution {label} metadata contains an unsafe key.")
        if not isinstance(item, str) or not _SAFE_METADATA_VALUE.fullmatch(item) or any(word in item.lower() for word in _FORBIDDEN_METADATA_WORDS):
            raise _invalid(f"Execution {label} metadata contains an unsafe value.")
        result[key] = item
    return result


def _timestamp(value: Any, label: str, *, allow_empty: bool = True) -> None:
    if allow_empty and value == "":
        return
    if value is not None and (not isinstance(value, str) or not _TIMESTAMP.fullmatch(value)):
        raise _invalid(f"Execution {label} timestamp is invalid.")


class ExecutionProfile(str, Enum):
    WORKSPACE_LOCAL = "workspace_local"
    DURABLE = "durable"
    # The reference adapter is test-only, but exercises the durable profile
    # contract rather than introducing a third product execution profile.
    DURABLE_TEST = "durable"


class OperationalLifecycle(str, Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    RETRYING = "RETRYING"
    COMPLETED = "COMPLETED"
    CANCELED = "CANCELED"
    PROCESSING_FAILED = "PROCESSING_FAILED"


class TerminalOutcome(str, Enum):
    NONE = "NONE"
    DONE = "DONE"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    CANCELED = "CANCELED"
    PROCESSING_FAILED = "PROCESSING_FAILED"


class ResumeEligibility(str, Enum):
    ELIGIBLE = "ELIGIBLE"
    NOT_ELIGIBLE = "NOT_ELIGIBLE"


class RetryDisposition(str, Enum):
    NONE = "NONE"
    RETRYABLE = "RETRYABLE"
    NOT_RETRYABLE = "NOT_RETRYABLE"
    EXHAUSTED = "EXHAUSTED"


class FailureClass(str, Enum):
    RETRYABLE = "RETRYABLE"
    NOT_RETRYABLE = "NOT_RETRYABLE"
    SEMANTIC_REPAIR = "SEMANTIC_REPAIR"


class StoreWriteStatus(str, Enum):
    ACCEPTED = "ACCEPTED"
    IDEMPOTENT = "IDEMPOTENT"
    STALE = "STALE"
    CONFLICT = "CONFLICT"


@dataclass(frozen=True)
class RunStoreRef:
    """Opaque caller/platform references; neither value is a filesystem path."""

    scope_ref: str
    store_ref: str

    def __post_init__(self) -> None:
        _identifier(self.scope_ref, "scope reference")
        _identifier(self.store_ref, "store reference")

    def as_dict(self) -> dict[str, str]:
        return {"scope_ref": self.scope_ref, "store_ref": self.store_ref}


@dataclass(frozen=True)
class ProgressSnapshot:
    """Bounded source-free progress, intentionally without source text or paths."""

    engine_stage: str
    completed_work_units: int = 0
    total_work_units: int = 0
    current_work_unit: str | None = None

    def __post_init__(self) -> None:
        _phase(self.engine_stage, "engine stage")
        if not isinstance(self.completed_work_units, int) or not isinstance(self.total_work_units, int):
            raise _invalid("Execution progress counts must be integers.")
        if self.completed_work_units < 0 or self.total_work_units < 0 or self.completed_work_units > self.total_work_units or self.total_work_units > 100_000:
            raise _invalid("Execution progress counts are outside the bounded range.")
        if self.current_work_unit is not None:
            _identifier(self.current_work_unit, "current work-unit reference")

    def as_dict(self) -> dict[str, Any]:
        return {
            "engine_stage": self.engine_stage,
            "completed_work_units": self.completed_work_units,
            "total_work_units": self.total_work_units,
            "current_work_unit": self.current_work_unit,
        }


@dataclass(frozen=True)
class CancellationState:
    requested: bool = False
    acknowledged: bool = False
    request_ref: str | None = None
    requested_at: str | None = None
    acknowledged_at: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.requested, bool) or not isinstance(self.acknowledged, bool):
            raise _invalid("Execution cancellation flags must be boolean.")
        if self.acknowledged and not self.requested:
            raise _invalid("Execution cancellation cannot be acknowledged before it is requested.")
        if self.request_ref is not None:
            _identifier(self.request_ref, "cancellation reference")
        if self.requested and self.request_ref is None:
            raise _invalid("Requested execution cancellation has no reference.")
        _timestamp(self.requested_at, "cancellation request")
        _timestamp(self.acknowledged_at, "cancellation acknowledgement")

    def as_dict(self) -> dict[str, Any]:
        return {
            "requested": self.requested,
            "acknowledged": self.acknowledged,
            "request_ref": self.request_ref,
            "requested_at": self.requested_at,
            "acknowledged_at": self.acknowledged_at,
        }


@dataclass(frozen=True)
class RetryState:
    attempt: int = 0
    max_attempts: int = 3
    disposition: RetryDisposition = RetryDisposition.NONE
    last_error_code: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.attempt, int) or not isinstance(self.max_attempts, int) or self.attempt < 0 or self.max_attempts < 1 or self.attempt > self.max_attempts or self.max_attempts > 32:
            raise _invalid("Execution retry attempts are outside the bounded range.")
        if not isinstance(self.disposition, RetryDisposition):
            try:
                object.__setattr__(self, "disposition", RetryDisposition(str(self.disposition)))
            except ValueError as exc:
                raise _invalid("Execution retry disposition is unsupported.") from exc
        if self.last_error_code is not None:
            _error_code(self.last_error_code)
        if self.disposition is RetryDisposition.EXHAUSTED and self.attempt < self.max_attempts:
            raise _invalid("Exhausted execution retry state is inconsistent.")

    def as_dict(self) -> dict[str, Any]:
        return {
            "attempt": self.attempt,
            "max_attempts": self.max_attempts,
            "disposition": self.disposition.value,
            "last_error_code": self.last_error_code,
        }


@dataclass(frozen=True)
class ResultCommitMarker:
    """A source-free idempotency marker for one committed execution result."""

    operation_id: str
    result_kind: str
    result_sha256: str
    attempt: int = 0
    committed_at: str = ""

    def __post_init__(self) -> None:
        _identifier(self.operation_id, "operation ID")
        _identifier(self.result_kind, "result kind")
        if not _SHA256.fullmatch(self.result_sha256):
            raise _invalid("Execution result marker must contain a SHA-256 result identity.")
        if not isinstance(self.attempt, int) or self.attempt < 0 or self.attempt > 32:
            raise _invalid("Execution result marker attempt is outside the bounded range.")
        _timestamp(self.committed_at, "result commit")

    def as_dict(self) -> dict[str, Any]:
        return {
            "operation_id": self.operation_id,
            "result_kind": self.result_kind,
            "result_sha256": self.result_sha256,
            "attempt": self.attempt,
            "committed_at": self.committed_at,
        }


@dataclass(frozen=True)
class RunCheckpoint:
    """One committed, monotonic resume point for a job."""

    run_id: str
    job_id: str
    execution_id: str
    revision: int
    engine_phase: str
    progress: ProgressSnapshot
    engine_state_revision: int = 0
    queue_revision: str = ""
    resume_eligibility: ResumeEligibility = ResumeEligibility.ELIGIBLE
    metadata: Mapping[str, str] = field(default_factory=dict)
    checkpoint_sha256: str = ""
    schema_version: str = RUN_STORE_SCHEMA_VERSION
    environment_identity_sha256: str = ""

    def __post_init__(self) -> None:
        _identifier(self.run_id, "run ID")
        _identifier(self.job_id, "job ID")
        _identifier(self.execution_id, "execution ID")
        if not isinstance(self.revision, int) or self.revision < 0:
            raise _invalid("Execution checkpoint revision is invalid.")
        _phase(self.engine_phase, "engine phase")
        if not isinstance(self.progress, ProgressSnapshot):
            raise _invalid("Execution checkpoint progress is invalid.")
        if not isinstance(self.engine_state_revision, int) or self.engine_state_revision < 0:
            raise _invalid("Execution engine-state revision is invalid.")
        if self.queue_revision and not (_SHA256.fullmatch(self.queue_revision) or _IDENTIFIER.fullmatch(self.queue_revision)):
            raise _invalid("Execution queue revision is invalid.")
        if not isinstance(self.resume_eligibility, ResumeEligibility):
            try:
                object.__setattr__(self, "resume_eligibility", ResumeEligibility(str(self.resume_eligibility)))
            except ValueError as exc:
                raise _invalid("Execution resume eligibility is unsupported.") from exc
        object.__setattr__(self, "metadata", _metadata(self.metadata or {}, "checkpoint"))
        if self.checkpoint_sha256 and self.checkpoint_sha256 != self.computed_sha256():
            raise _invalid("Execution checkpoint hash does not match its contents.", code=ErrorCode.STATE_CORRUPT)
        if self.environment_identity_sha256 and not _SHA256.fullmatch(self.environment_identity_sha256):
            raise _invalid("Execution checkpoint environment identity is invalid.", code=ErrorCode.STATE_CORRUPT)
        if self.schema_version != RUN_STORE_SCHEMA_VERSION:
            raise _invalid("Unsupported execution checkpoint schema version.", code=ErrorCode.EXECUTION_UNSUPPORTED_VERSION)

    @classmethod
    def initial(cls, *, run_id: str, job_id: str, execution_id: str, total_work_units: int = 0, engine_state_revision: int = 0) -> "RunCheckpoint":
        return cls(
            run_id,
            job_id,
            execution_id,
            0,
            RunPhase.CREATED.value,
            ProgressSnapshot(RunPhase.CREATED.value, 0, total_work_units),
            engine_state_revision=engine_state_revision,
        )

    @classmethod
    def from_dict(cls, value: Any) -> "RunCheckpoint":
        return _checkpoint_from_dict(value)

    def without_hash(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "job_id": self.job_id,
            "execution_id": self.execution_id,
            "revision": self.revision,
            "engine_phase": self.engine_phase,
            "progress": self.progress.as_dict(),
            "engine_state_revision": self.engine_state_revision,
            "queue_revision": self.queue_revision,
            "resume_eligibility": self.resume_eligibility.value,
            "metadata": dict(sorted(self.metadata.items())),
            **({"environment_identity_sha256": self.environment_identity_sha256} if self.environment_identity_sha256 else {}),
        }

    def computed_sha256(self) -> str:
        return stable_revision(self.without_hash())

    def as_dict(self) -> dict[str, Any]:
        value = self.without_hash()
        value["checkpoint_sha256"] = self.checkpoint_sha256 or self.computed_sha256()
        return value


def _checkpoint_from_dict(value: Any) -> RunCheckpoint:
    if not isinstance(value, dict):
        raise _invalid("Execution checkpoint must be an object.", code=ErrorCode.STATE_CORRUPT)
    if value.get("schema_version") != RUN_STORE_SCHEMA_VERSION:
        raise _invalid("Unsupported execution checkpoint schema version.", code=ErrorCode.EXECUTION_UNSUPPORTED_VERSION)
    allowed = {
        "schema_version", "run_id", "job_id", "execution_id", "revision", "engine_phase", "progress",
        "engine_state_revision", "queue_revision", "resume_eligibility", "metadata", "checkpoint_sha256",
    }
    if set(value) not in (allowed, allowed | {"environment_identity_sha256"}):
        raise _invalid("Execution checkpoint fields are unsupported or incomplete.", code=ErrorCode.STATE_CORRUPT)
    progress_value = value["progress"]
    if not isinstance(progress_value, dict) or set(progress_value) != {"engine_stage", "completed_work_units", "total_work_units", "current_work_unit"}:
        raise _invalid("Execution checkpoint progress is invalid.", code=ErrorCode.STATE_CORRUPT)
    progress = ProgressSnapshot(**progress_value)
    try:
        return RunCheckpoint(
            run_id=value["run_id"],
            job_id=value["job_id"],
            execution_id=value["execution_id"],
            revision=value["revision"],
            engine_phase=value["engine_phase"],
            progress=progress,
            engine_state_revision=value.get("engine_state_revision", 0),
            queue_revision=value.get("queue_revision", ""),
            resume_eligibility=ResumeEligibility(value["resume_eligibility"]),
            metadata=value.get("metadata", {}),
            checkpoint_sha256=value["checkpoint_sha256"],
            schema_version=value["schema_version"],
            environment_identity_sha256=value.get("environment_identity_sha256", ""),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise _invalid("Execution checkpoint has an invalid shape.", code=ErrorCode.STATE_CORRUPT) from exc


@dataclass(frozen=True)
class ExecutionJob:
    run_id: str
    job_id: str
    execution_id: str
    profile: ExecutionProfile
    store_ref: RunStoreRef
    lifecycle: OperationalLifecycle
    revision: int
    checkpoint: RunCheckpoint
    cancellation: CancellationState = CancellationState()
    retry: RetryState = RetryState()
    resume_eligibility: ResumeEligibility = ResumeEligibility.ELIGIBLE
    terminal_outcome: TerminalOutcome = TerminalOutcome.NONE
    created_at: str = ""
    updated_at: str = ""
    schema_version: str = EXECUTION_CONTRACT_VERSION
    result_markers: tuple[ResultCommitMarker, ...] = ()
    environment_identity: RunEnvironmentIdentity | None = None

    def __post_init__(self) -> None:
        for value, label in ((self.run_id, "run ID"), (self.job_id, "job ID"), (self.execution_id, "execution ID")):
            _identifier(value, label)
        if not isinstance(self.profile, ExecutionProfile):
            try:
                object.__setattr__(self, "profile", ExecutionProfile(str(self.profile)))
            except ValueError as exc:
                raise _invalid("Execution profile is unsupported.") from exc
        if not isinstance(self.lifecycle, OperationalLifecycle):
            try:
                object.__setattr__(self, "lifecycle", OperationalLifecycle(str(self.lifecycle)))
            except ValueError as exc:
                raise _invalid("Execution lifecycle is unsupported.") from exc
        if not isinstance(self.revision, int) or self.revision < 0:
            raise _invalid("Execution job revision is invalid.")
        if not isinstance(self.store_ref, RunStoreRef) or not isinstance(self.cancellation, CancellationState) or not isinstance(self.retry, RetryState):
            raise _invalid("Execution job control fields are invalid.", code=ErrorCode.STATE_CORRUPT)
        if not isinstance(self.checkpoint, RunCheckpoint) or (self.checkpoint.run_id, self.checkpoint.job_id, self.checkpoint.execution_id) != (self.run_id, self.job_id, self.execution_id):
            raise _invalid("Execution job and checkpoint identities do not match.", code=ErrorCode.STATE_CORRUPT)
        if self.environment_identity is not None and not isinstance(self.environment_identity, RunEnvironmentIdentity):
            raise _invalid("Execution job environment identity is invalid.", code=ErrorCode.STATE_CORRUPT)
        if self.environment_identity is not None:
            expected_environment_sha = self.environment_identity.identity_sha256
            if self.checkpoint.environment_identity_sha256 not in {"", expected_environment_sha}:
                raise _invalid("Execution job and checkpoint environment identities do not match.", code=ErrorCode.STATE_CORRUPT)
            if not self.checkpoint.environment_identity_sha256:
                object.__setattr__(self, "checkpoint", replace(self.checkpoint, environment_identity_sha256=expected_environment_sha))
        if not isinstance(self.resume_eligibility, ResumeEligibility):
            try:
                object.__setattr__(self, "resume_eligibility", ResumeEligibility(str(self.resume_eligibility)))
            except ValueError as exc:
                raise _invalid("Execution resume eligibility is unsupported.") from exc
        if not isinstance(self.terminal_outcome, TerminalOutcome):
            try:
                object.__setattr__(self, "terminal_outcome", TerminalOutcome(str(self.terminal_outcome)))
            except ValueError as exc:
                raise _invalid("Execution terminal outcome is unsupported.") from exc
        _timestamp(self.created_at, "job creation")
        _timestamp(self.updated_at, "job update")
        if self.lifecycle is OperationalLifecycle.CANCELED and (not self.cancellation.acknowledged or self.terminal_outcome is not TerminalOutcome.CANCELED):
            raise _invalid("Canceled execution lifecycle is inconsistent.", code=ErrorCode.STATE_CORRUPT)
        if self.lifecycle is OperationalLifecycle.PROCESSING_FAILED and self.terminal_outcome is not TerminalOutcome.PROCESSING_FAILED:
            raise _invalid("Failed execution lifecycle is inconsistent.", code=ErrorCode.STATE_CORRUPT)
        if self.lifecycle is OperationalLifecycle.COMPLETED and self.terminal_outcome not in {TerminalOutcome.DONE, TerminalOutcome.NEEDS_REVIEW}:
            raise _invalid("Completed execution lifecycle is inconsistent.", code=ErrorCode.STATE_CORRUPT)
        if self.lifecycle in {OperationalLifecycle.QUEUED, OperationalLifecycle.RUNNING, OperationalLifecycle.RETRYING} and self.terminal_outcome is not TerminalOutcome.NONE:
            raise _invalid("Nonterminal execution lifecycle has a terminal outcome.", code=ErrorCode.STATE_CORRUPT)
        if self.lifecycle is OperationalLifecycle.CANCELED and self.terminal_outcome is TerminalOutcome.NEEDS_REVIEW:
            raise _invalid("Canceled execution cannot have a semantic review outcome.", code=ErrorCode.STATE_CORRUPT)
        if not isinstance(self.result_markers, tuple) or any(not isinstance(marker, ResultCommitMarker) for marker in self.result_markers):
            raise _invalid("Execution result markers are invalid.", code=ErrorCode.STATE_CORRUPT)
        if len(self.result_markers) > _MAX_RESULT_MARKERS:
            raise _invalid("Execution result markers exceed the bounded limit.")
        operation_ids = [marker.operation_id for marker in self.result_markers]
        if len(operation_ids) != len(set(operation_ids)):
            raise _invalid("Execution result markers contain duplicate operation IDs.", code=ErrorCode.STATE_CORRUPT)
        if self.schema_version != EXECUTION_CONTRACT_VERSION:
            raise _invalid("Unsupported execution contract version.", code=ErrorCode.EXECUTION_UNSUPPORTED_VERSION)

    @classmethod
    def new(
        cls,
        *,
        run_id: str,
        profile: ExecutionProfile,
        scope_ref: str,
        store_ref: str,
        job_id: str | None = None,
        execution_id: str | None = None,
        total_work_units: int = 0,
        max_attempts: int = 3,
        engine_state_revision: int = 0,
        environment_identity: RunEnvironmentIdentity | None = None,
    ) -> "ExecutionJob":
        job_id = job_id or f"job-{run_id}"
        execution_id = execution_id or f"execution-{run_id}"
        checkpoint = RunCheckpoint.initial(run_id=run_id, job_id=job_id, execution_id=execution_id, total_work_units=total_work_units, engine_state_revision=engine_state_revision)
        timestamp = now_utc()
        return cls(
            run_id,
            job_id,
            execution_id,
            profile,
            RunStoreRef(scope_ref, store_ref),
            OperationalLifecycle.QUEUED,
            0,
            checkpoint,
            retry=RetryState(max_attempts=max_attempts),
            created_at=timestamp,
            updated_at=timestamp,
            environment_identity=environment_identity,
        )

    @classmethod
    def from_dict(cls, value: Any) -> "ExecutionJob":
        return _job_from_dict(value)

    def without_record_hash(self) -> dict[str, Any]:
        value = {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "job_id": self.job_id,
            "execution_id": self.execution_id,
            "profile": self.profile.value,
            "store_ref": self.store_ref.as_dict(),
            "lifecycle": self.lifecycle.value,
            "revision": self.revision,
            "checkpoint": self.checkpoint.as_dict(),
            "cancellation": self.cancellation.as_dict(),
            "retry": self.retry.as_dict(),
            "resume_eligibility": self.resume_eligibility.value,
            "terminal_outcome": self.terminal_outcome.value,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "result_markers": [marker.as_dict() for marker in self.result_markers],
        }
        if self.environment_identity is not None:
            value["environment_identity"] = self.environment_identity.as_dict()
        return value

    def as_dict(self) -> dict[str, Any]:
        value = self.without_record_hash()
        value["record_sha256"] = stable_revision(value)
        return value


def _job_from_dict(value: Any) -> ExecutionJob:
    if not isinstance(value, dict):
        raise _invalid("Execution job must be an object.", code=ErrorCode.STATE_CORRUPT)
    if value.get("schema_version") != EXECUTION_CONTRACT_VERSION:
        raise _invalid("Unsupported execution contract version.", code=ErrorCode.EXECUTION_UNSUPPORTED_VERSION)
    required = {
        "schema_version", "run_id", "job_id", "execution_id", "profile", "store_ref", "lifecycle", "revision",
        "checkpoint", "cancellation", "retry", "resume_eligibility", "terminal_outcome", "created_at", "updated_at",
        "result_markers", "record_sha256",
    }
    if set(value) not in (required, required | {"environment_identity"}):
        raise _invalid("Execution job fields are unsupported or incomplete.", code=ErrorCode.STATE_CORRUPT)
    without_hash = dict(value)
    record_hash = without_hash.pop("record_sha256")
    if not isinstance(record_hash, str) or record_hash != stable_revision(without_hash):
        raise _invalid("Execution job record hash is inconsistent.", code=ErrorCode.STATE_CORRUPT)
    store_value = value["store_ref"]
    cancellation_value = value["cancellation"]
    retry_value = value["retry"]
    if not isinstance(store_value, dict) or set(store_value) != {"scope_ref", "store_ref"}:
        raise _invalid("Execution job store reference is invalid.", code=ErrorCode.STATE_CORRUPT)
    if not isinstance(cancellation_value, dict) or set(cancellation_value) != {"requested", "acknowledged", "request_ref", "requested_at", "acknowledged_at"}:
        raise _invalid("Execution job cancellation state is invalid.", code=ErrorCode.STATE_CORRUPT)
    if not isinstance(retry_value, dict) or set(retry_value) != {"attempt", "max_attempts", "disposition", "last_error_code"}:
        raise _invalid("Execution job retry state is invalid.", code=ErrorCode.STATE_CORRUPT)
    markers_value = value["result_markers"]
    if not isinstance(markers_value, list):
        raise _invalid("Execution job result markers are invalid.", code=ErrorCode.STATE_CORRUPT)
    markers: list[ResultCommitMarker] = []
    for marker_value in markers_value:
        if not isinstance(marker_value, dict) or set(marker_value) != {"operation_id", "result_kind", "result_sha256", "attempt", "committed_at"}:
            raise _invalid("Execution result marker is invalid.", code=ErrorCode.STATE_CORRUPT)
        try:
            markers.append(ResultCommitMarker(**marker_value))
        except (TypeError, ValueError) as exc:
            raise _invalid("Execution result marker has an invalid shape.", code=ErrorCode.STATE_CORRUPT) from exc
    try:
        environment_value = value.get("environment_identity")
        return ExecutionJob(
            run_id=value["run_id"],
            job_id=value["job_id"],
            execution_id=value["execution_id"],
            profile=ExecutionProfile(value["profile"]),
            store_ref=RunStoreRef(**store_value),
            lifecycle=OperationalLifecycle(value["lifecycle"]),
            revision=value["revision"],
            checkpoint=_checkpoint_from_dict(value["checkpoint"]),
            cancellation=CancellationState(**cancellation_value),
            retry=RetryState(disposition=RetryDisposition(retry_value["disposition"]), **{key: item for key, item in retry_value.items() if key != "disposition"}),
            resume_eligibility=ResumeEligibility(value["resume_eligibility"]),
            terminal_outcome=TerminalOutcome(value["terminal_outcome"]),
            created_at=value["created_at"],
            updated_at=value["updated_at"],
            schema_version=value["schema_version"],
            result_markers=tuple(markers),
            environment_identity=None if environment_value is None else RunEnvironmentIdentity.from_dict(environment_value),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise _invalid("Execution job has an invalid shape.", code=ErrorCode.STATE_CORRUPT) from exc


@dataclass(frozen=True)
class StoreWriteResult:
    status: StoreWriteStatus
    job: ExecutionJob

    @property
    def accepted(self) -> bool:
        return self.status in {StoreWriteStatus.ACCEPTED, StoreWriteStatus.IDEMPOTENT}

    @property
    def idempotent(self) -> bool:
        return self.status is StoreWriteStatus.IDEMPOTENT


class RunStore(Protocol):
    """The backend-neutral contract required by either execution profile."""

    def create(self, job: ExecutionJob) -> StoreWriteResult: ...

    def load(self, job_id: str) -> ExecutionJob: ...

    def load_checkpoint(self, job_id: str) -> RunCheckpoint: ...

    def commit_job(self, job: ExecutionJob, *, expected_revision: int) -> StoreWriteResult: ...

    def commit_checkpoint(self, checkpoint: RunCheckpoint, *, expected_revision: int) -> StoreWriteResult: ...

    def commit_step(self, checkpoint: RunCheckpoint, marker: ResultCommitMarker, *, expected_revision: int) -> StoreWriteResult: ...

    def request_cancellation(self, job_id: str, *, expected_revision: int | None = None) -> StoreWriteResult: ...

    def acknowledge_cancellation(self, job_id: str, *, expected_revision: int, safe_boundary: bool) -> StoreWriteResult: ...

    def transition_operational(self, job_id: str, *, expected_revision: int, lifecycle: OperationalLifecycle, terminal_outcome: TerminalOutcome = TerminalOutcome.NONE, resume_eligibility: ResumeEligibility | None = None) -> StoreWriteResult: ...

    def record_retry(self, job_id: str, *, expected_revision: int, error_code: str) -> StoreWriteResult: ...

    def commit_result(self, job_id: str, marker: ResultCommitMarker, *, expected_revision: int) -> StoreWriteResult: ...


def classify_operational_failure(error_code: str | ErrorCode) -> FailureClass:
    """Conservative retry classification without provider/network policy."""

    value = error_code.value if isinstance(error_code, ErrorCode) else str(error_code)
    if value in {ErrorCode.VERIFICATION_FAILED.value, ErrorCode.COMPLETION_BLOCKED.value, ErrorCode.STALE_EVIDENCE.value}:
        return FailureClass.SEMANTIC_REPAIR
    if value in {ErrorCode.INTERNAL.value, ErrorCode.RUNTIME_UNKNOWN.value, ErrorCode.PPTX_CONVERSION_TIMEOUT.value}:
        return FailureClass.RETRYABLE
    return FailureClass.NOT_RETRYABLE


_OPERATIONAL_TRANSITIONS: dict[OperationalLifecycle, frozenset[OperationalLifecycle]] = {
    OperationalLifecycle.QUEUED: frozenset({OperationalLifecycle.RUNNING, OperationalLifecycle.CANCELED, OperationalLifecycle.PROCESSING_FAILED}),
    OperationalLifecycle.RUNNING: frozenset({OperationalLifecycle.RETRYING, OperationalLifecycle.COMPLETED, OperationalLifecycle.CANCELED, OperationalLifecycle.PROCESSING_FAILED}),
    OperationalLifecycle.RETRYING: frozenset({OperationalLifecycle.RUNNING, OperationalLifecycle.RETRYING, OperationalLifecycle.COMPLETED, OperationalLifecycle.CANCELED, OperationalLifecycle.PROCESSING_FAILED}),
    OperationalLifecycle.COMPLETED: frozenset({OperationalLifecycle.RETRYING}),
    OperationalLifecycle.CANCELED: frozenset(),
    OperationalLifecycle.PROCESSING_FAILED: frozenset(),
}


class _FilesystemRunStore:
    def __init__(self, root: Path, *, profile: ExecutionProfile) -> None:
        self.root = Path(root).expanduser().resolve()
        self.profile = profile
        self._mutex = RLock()

    @property
    def job_path(self) -> Path:
        return self.root / "EXECUTION_JOB.json"

    @contextmanager
    def _mutation(self, job_id: str | None = None) -> Iterator[None]:
        with self._mutex:
            yield

    def _path_for(self, job_id: str) -> Path:
        _identifier(job_id, "job ID")
        return self.job_path

    def _read(self, path: Path, job_id: str) -> ExecutionJob:
        try:
            value = read_json(path)
            return _job_from_dict(value)
        except KSlideError as exc:
            if exc.code is ErrorCode.EXECUTION_UNSUPPORTED_VERSION:
                raise
            raise KSlideError(ErrorCode.STATE_CORRUPT, "Execution job state is corrupt or unreadable.", {"job_id": job_id}) from exc
        except (OSError, TypeError, ValueError) as exc:
            raise KSlideError(ErrorCode.STATE_CORRUPT, "Execution job state is corrupt or unreadable.", {"job_id": job_id}) from exc

    def load(self, job_id: str) -> ExecutionJob:
        path = self._path_for(job_id)
        with self._mutation(job_id):
            if not path.is_file():
                raise KSlideError(ErrorCode.EXECUTION_NOT_FOUND, "Execution job does not exist.", {"job_id": job_id})
            job = self._read(path, job_id)
        if job.job_id != job_id or job.profile is not self.profile:
            raise KSlideError(ErrorCode.EXECUTION_CONFLICT, "Execution job identity or profile does not match the adapter.", {"job_id": job_id})
        return job

    def load_checkpoint(self, job_id: str) -> RunCheckpoint:
        return self.load(job_id).checkpoint

    def _write(self, job: ExecutionJob) -> None:
        atomic_write_json(self._path_for(job.job_id), job.as_dict(), mode=0o600)

    def create(self, job: ExecutionJob) -> StoreWriteResult:
        if job.profile is not self.profile:
            raise _invalid("Execution job profile does not match the store adapter.")
        path = self._path_for(job.job_id)
        with self._mutation(job.job_id):
            if path.is_file():
                existing = self._read(path, job.job_id)
                if existing.as_dict() == job.as_dict():
                    return StoreWriteResult(StoreWriteStatus.IDEMPOTENT, existing)
                return StoreWriteResult(StoreWriteStatus.CONFLICT, existing)
            self.root.mkdir(parents=True, exist_ok=True)
            self._write(job)
            return StoreWriteResult(StoreWriteStatus.ACCEPTED, job)

    def commit_job(self, job: ExecutionJob, *, expected_revision: int) -> StoreWriteResult:
        with self._mutation(job.job_id):
            path = self._path_for(job.job_id)
            if not path.is_file():
                raise KSlideError(ErrorCode.EXECUTION_NOT_FOUND, "Execution job does not exist.", {"job_id": job.job_id})
            current = self._read(path, job.job_id)
            if current.as_dict() == job.as_dict():
                return StoreWriteResult(StoreWriteStatus.IDEMPOTENT, current)
            if expected_revision != current.revision:
                return StoreWriteResult(StoreWriteStatus.STALE, current)
            if job.revision != current.revision + 1:
                return StoreWriteResult(StoreWriteStatus.CONFLICT, current)
            if job.profile is not self.profile:
                return StoreWriteResult(StoreWriteStatus.CONFLICT, current)
            if job.environment_identity != current.environment_identity:
                return StoreWriteResult(StoreWriteStatus.CONFLICT, current)
            self._write(job)
        return StoreWriteResult(StoreWriteStatus.ACCEPTED, job)

    @staticmethod
    def _validate_checkpoint_environment(current: ExecutionJob, checkpoint: RunCheckpoint) -> None:
        expected = current.environment_identity.identity_sha256 if current.environment_identity is not None else ""
        if checkpoint.environment_identity_sha256 != expected:
            raise KSlideError(
                ErrorCode.EXECUTION_ENVIRONMENT_MISMATCH,
                "Run checkpoint environment identity is incompatible; commit was refused.",
                {"mismatch_code": "KSLIDE_RUN_ENVIRONMENT_MISMATCH", "mismatch_fields": ["checkpoint_environment_identity"]},
            )

    def commit_checkpoint(self, checkpoint: RunCheckpoint, *, expected_revision: int) -> StoreWriteResult:
        current = self.load(checkpoint.job_id)
        self._validate_checkpoint_environment(current, checkpoint)
        if checkpoint.as_dict() == current.checkpoint.as_dict():
            return StoreWriteResult(StoreWriteStatus.IDEMPOTENT, current)
        if expected_revision != current.revision:
            return StoreWriteResult(StoreWriteStatus.STALE, current)
        if checkpoint.revision != current.checkpoint.revision + 1:
            return StoreWriteResult(StoreWriteStatus.CONFLICT, current)
        normalized = replace(checkpoint, checkpoint_sha256=checkpoint.computed_sha256())
        candidate = replace(current, checkpoint=normalized, revision=current.revision + 1, updated_at=now_utc())
        return self.commit_job(candidate, expected_revision=expected_revision)

    def commit_step(self, checkpoint: RunCheckpoint, marker: ResultCommitMarker, *, expected_revision: int) -> StoreWriteResult:
        current = self.load(checkpoint.job_id)
        self._validate_checkpoint_environment(current, checkpoint)
        existing = next((item for item in current.result_markers if item.operation_id == marker.operation_id), None)
        if existing is not None:
            if existing.as_dict() == marker.as_dict() and current.checkpoint.as_dict() == checkpoint.as_dict():
                return StoreWriteResult(StoreWriteStatus.IDEMPOTENT, current)
            return StoreWriteResult(StoreWriteStatus.CONFLICT, current)
        if expected_revision != current.revision:
            return StoreWriteResult(StoreWriteStatus.STALE, current)
        if checkpoint.revision != current.checkpoint.revision + 1:
            return StoreWriteResult(StoreWriteStatus.CONFLICT, current)
        normalized = replace(checkpoint, checkpoint_sha256=checkpoint.computed_sha256())
        candidate = replace(current, checkpoint=normalized, result_markers=(*current.result_markers, marker), revision=current.revision + 1, updated_at=now_utc())
        return self.commit_job(candidate, expected_revision=expected_revision)

    def request_cancellation(self, job_id: str, *, expected_revision: int | None = None) -> StoreWriteResult:
        current = self.load(job_id)
        if current.cancellation.requested:
            return StoreWriteResult(StoreWriteStatus.IDEMPOTENT, current)
        if current.lifecycle in {OperationalLifecycle.COMPLETED, OperationalLifecycle.CANCELED, OperationalLifecycle.PROCESSING_FAILED}:
            return StoreWriteResult(StoreWriteStatus.CONFLICT, current)
        if expected_revision is not None and expected_revision != current.revision:
            return StoreWriteResult(StoreWriteStatus.STALE, current)
        cancellation = CancellationState(True, False, f"cancel-{current.job_id}", now_utc(), None)
        candidate = replace(current, cancellation=cancellation, revision=current.revision + 1, updated_at=now_utc())
        return self.commit_job(candidate, expected_revision=current.revision)

    def acknowledge_cancellation(self, job_id: str, *, expected_revision: int, safe_boundary: bool) -> StoreWriteResult:
        current = self.load(job_id)
        if current.cancellation.acknowledged:
            return StoreWriteResult(StoreWriteStatus.IDEMPOTENT, current)
        if not current.cancellation.requested:
            return StoreWriteResult(StoreWriteStatus.CONFLICT, current)
        if not safe_boundary:
            return StoreWriteResult(StoreWriteStatus.CONFLICT, current)
        if expected_revision != current.revision:
            return StoreWriteResult(StoreWriteStatus.STALE, current)
        cancellation = replace(current.cancellation, acknowledged=True, acknowledged_at=now_utc())
        candidate = replace(
            current,
            cancellation=cancellation,
            lifecycle=OperationalLifecycle.CANCELED,
            resume_eligibility=ResumeEligibility.NOT_ELIGIBLE,
            terminal_outcome=TerminalOutcome.CANCELED,
            revision=current.revision + 1,
            updated_at=now_utc(),
        )
        return self.commit_job(candidate, expected_revision=current.revision)

    def transition_operational(self, job_id: str, *, expected_revision: int, lifecycle: OperationalLifecycle, terminal_outcome: TerminalOutcome = TerminalOutcome.NONE, resume_eligibility: ResumeEligibility | None = None) -> StoreWriteResult:
        current = self.load(job_id)
        if current.lifecycle is lifecycle and current.terminal_outcome is terminal_outcome:
            return StoreWriteResult(StoreWriteStatus.IDEMPOTENT, current)
        if expected_revision != current.revision:
            return StoreWriteResult(StoreWriteStatus.STALE, current)
        if lifecycle not in _OPERATIONAL_TRANSITIONS[current.lifecycle]:
            return StoreWriteResult(StoreWriteStatus.CONFLICT, current)
        if lifecycle is OperationalLifecycle.COMPLETED and terminal_outcome not in {TerminalOutcome.DONE, TerminalOutcome.NEEDS_REVIEW}:
            return StoreWriteResult(StoreWriteStatus.CONFLICT, current)
        if lifecycle is OperationalLifecycle.PROCESSING_FAILED:
            terminal_outcome = TerminalOutcome.PROCESSING_FAILED
            resume_eligibility = ResumeEligibility.NOT_ELIGIBLE
        candidate = replace(
            current,
            lifecycle=lifecycle,
            terminal_outcome=terminal_outcome,
            resume_eligibility=resume_eligibility or current.resume_eligibility,
            revision=current.revision + 1,
            updated_at=now_utc(),
        )
        return self.commit_job(candidate, expected_revision=current.revision)

    def record_retry(self, job_id: str, *, expected_revision: int, error_code: str) -> StoreWriteResult:
        current = self.load(job_id)
        if current.lifecycle is OperationalLifecycle.PROCESSING_FAILED and current.retry.disposition is RetryDisposition.EXHAUSTED:
            return StoreWriteResult(StoreWriteStatus.IDEMPOTENT, current)
        if current.lifecycle in {OperationalLifecycle.CANCELED, OperationalLifecycle.COMPLETED}:
            return StoreWriteResult(StoreWriteStatus.CONFLICT, current)
        classification = classify_operational_failure(error_code)
        if classification is FailureClass.SEMANTIC_REPAIR:
            raise _invalid("Semantic verification failures use the bounded repair path, not operational retry.")
        if expected_revision != current.revision:
            return StoreWriteResult(StoreWriteStatus.STALE, current)
        normalized_code = _error_code(error_code)
        next_attempt = current.retry.attempt + 1
        if classification is FailureClass.RETRYABLE and next_attempt < current.retry.max_attempts:
            retry = replace(current.retry, attempt=next_attempt, disposition=RetryDisposition.RETRYABLE, last_error_code=normalized_code)
            candidate = replace(current, retry=retry, lifecycle=OperationalLifecycle.RETRYING, revision=current.revision + 1, updated_at=now_utc())
        elif classification is FailureClass.RETRYABLE:
            retry = replace(current.retry, attempt=current.retry.max_attempts, disposition=RetryDisposition.EXHAUSTED, last_error_code=normalized_code)
            candidate = replace(current, retry=retry, lifecycle=OperationalLifecycle.PROCESSING_FAILED, resume_eligibility=ResumeEligibility.NOT_ELIGIBLE, terminal_outcome=TerminalOutcome.PROCESSING_FAILED, revision=current.revision + 1, updated_at=now_utc())
        else:
            retry = replace(current.retry, disposition=RetryDisposition.NOT_RETRYABLE, last_error_code=normalized_code)
            candidate = replace(current, retry=retry, lifecycle=OperationalLifecycle.PROCESSING_FAILED, resume_eligibility=ResumeEligibility.NOT_ELIGIBLE, terminal_outcome=TerminalOutcome.PROCESSING_FAILED, revision=current.revision + 1, updated_at=now_utc())
        return self.commit_job(candidate, expected_revision=current.revision)

    def commit_result(self, job_id: str, marker: ResultCommitMarker, *, expected_revision: int) -> StoreWriteResult:
        current = self.load(job_id)
        for existing in current.result_markers:
            if existing.operation_id == marker.operation_id:
                if existing.as_dict() == marker.as_dict():
                    return StoreWriteResult(StoreWriteStatus.IDEMPOTENT, current)
                return StoreWriteResult(StoreWriteStatus.CONFLICT, current)
        if expected_revision != current.revision:
            return StoreWriteResult(StoreWriteStatus.STALE, current)
        if len(current.result_markers) >= _MAX_RESULT_MARKERS:
            return StoreWriteResult(StoreWriteStatus.CONFLICT, current)
        candidate = replace(current, result_markers=(*current.result_markers, marker), revision=current.revision + 1, updated_at=now_utc())
        return self.commit_job(candidate, expected_revision=current.revision)


class WorkspaceRunStore(_FilesystemRunStore):
    """Workspace-local adapter using atomic replacement and the existing run lock."""

    def __init__(self, run_dir: Path) -> None:
        super().__init__(run_dir, profile=ExecutionProfile.WORKSPACE_LOCAL)

    @contextmanager
    def _mutation(self, job_id: str | None = None) -> Iterator[None]:
        with run_lock(self.root):
            yield


class DurableTestRunStore(_FilesystemRunStore):
    """Deterministic restartable reference adapter, not a PaaS implementation."""

    def __init__(self, backing_root: Path) -> None:
        super().__init__(backing_root, profile=ExecutionProfile.DURABLE)
        self._jobs_root = self.root / "jobs"

    def _path_for(self, job_id: str) -> Path:
        _identifier(job_id, "job ID")
        return self._jobs_root / f"{job_id}.json"

    @property
    def job_path(self) -> Path:
        raise AttributeError("Durable test store uses one file per job")

    @contextmanager
    def _mutation(self, job_id: str | None = None) -> Iterator[None]:
        if job_id is None:
            raise _invalid("Durable execution mutations require a job ID.")
        _identifier(job_id, "job ID")
        lock_path = self.root / ".durable-locks" / f"{job_id}.lock"
        with filesystem_lock(lock_path, require_shared=True, reject_symlink=True):
            yield


DeterministicDurableRunStore = DurableTestRunStore


def run_store_for_profile(profile: ExecutionProfile, root: Path) -> RunStore:
    """Select the execution adapter without changing the engine path."""

    if profile is ExecutionProfile.WORKSPACE_LOCAL:
        return WorkspaceRunStore(root)
    if profile is ExecutionProfile.DURABLE:
        # Keep the durable product profile on the controller/worker boundary.
        # The boundary's default local backend is explicitly a reference
        # adapter; it is not the KSA-06 test adapter exposed above.
        from .paas import ReferencePaaSRunStore

        return ReferencePaaSRunStore(root)
    raise _invalid("Execution profile has no reference run-store adapter.")


@dataclass(frozen=True)
class EngineStepResult:
    checkpoint: RunCheckpoint
    result_marker: ResultCommitMarker | None = None


class EngineStep(Protocol):
    def __call__(self, checkpoint: RunCheckpoint, operation_id: str) -> EngineStepResult: ...


@dataclass(frozen=True)
class ControllerResult:
    status: str
    job: ExecutionJob
    engine_called: bool = False


class ExecutionController:
    """One host-neutral execution boundary for both store profiles."""

    def __init__(self, store: RunStore, *, environment_identity: RunEnvironmentIdentity | None = None) -> None:
        self.store = store
        self.environment_identity = environment_identity

    def run_step(self, job_id: str, *, operation_id: str, step: EngineStep, environment_identity: RunEnvironmentIdentity | None = None) -> ControllerResult:
        _identifier(operation_id, "operation ID")
        job = self.store.load(job_id)
        raise_environment_mismatch(job.environment_identity, environment_identity or self.environment_identity)
        if job.cancellation.requested:
            if not job.cancellation.acknowledged:
                acknowledged = self.store.acknowledge_cancellation(job_id, expected_revision=job.revision, safe_boundary=True)
                if not acknowledged.accepted:
                    return ControllerResult(acknowledged.status.value, acknowledged.job)
                job = acknowledged.job
            return ControllerResult("CANCELED", job)
        marker = next((item for item in job.result_markers if item.operation_id == operation_id), None)
        if marker is not None:
            return ControllerResult("REPLAYED", job)
        if job.resume_eligibility is ResumeEligibility.NOT_ELIGIBLE:
            return ControllerResult("CONFLICT", job)
        if job.lifecycle is OperationalLifecycle.COMPLETED and job.terminal_outcome is TerminalOutcome.NEEDS_REVIEW:
            resumed = self.store.transition_operational(job_id, expected_revision=job.revision, lifecycle=OperationalLifecycle.RETRYING)
            if not resumed.accepted:
                return ControllerResult(resumed.status.value, resumed.job)
            job = resumed.job
        if job.lifecycle is OperationalLifecycle.QUEUED:
            started = self.store.transition_operational(job_id, expected_revision=job.revision, lifecycle=OperationalLifecycle.RUNNING)
            if not started.accepted:
                return ControllerResult(started.status.value, started.job)
            job = started.job
        if job.lifecycle not in {OperationalLifecycle.RUNNING, OperationalLifecycle.RETRYING}:
            return ControllerResult("CONFLICT", job)
        result = step(job.checkpoint, operation_id)
        if not isinstance(result, EngineStepResult):
            raise _invalid("Engine step returned an invalid execution result.")
        checkpoint = result.checkpoint
        if checkpoint.job_id != job.job_id or checkpoint.run_id != job.run_id or checkpoint.execution_id != job.execution_id:
            raise _invalid("Engine step checkpoint identity does not match the execution job.")
        if checkpoint.revision != job.checkpoint.revision + 1:
            raise _invalid("Engine step checkpoint is not the next monotonic revision.")
        if result.result_marker is not None:
            if result.result_marker.operation_id != operation_id:
                raise _invalid("Engine step result marker does not match the operation.")
            committed_step = self.store.commit_step(checkpoint, result.result_marker, expected_revision=job.revision)
            if not committed_step.accepted:
                if committed_step.status is StoreWriteStatus.STALE and any(item.operation_id == operation_id for item in committed_step.job.result_markers):
                    return ControllerResult("REPLAYED", committed_step.job)
                return ControllerResult(committed_step.status.value, committed_step.job)
            return ControllerResult("ACCEPTED", committed_step.job, engine_called=True)
        committed_checkpoint = self.store.commit_checkpoint(checkpoint, expected_revision=job.revision)
        if not committed_checkpoint.accepted:
            return ControllerResult(committed_checkpoint.status.value, committed_checkpoint.job, engine_called=True)
        return ControllerResult("ACCEPTED", committed_checkpoint.job, engine_called=True)


def new_execution_job(
    run_id: str,
    *,
    profile: ExecutionProfile,
    scope_ref: str,
    store_ref: str,
    total_work_units: int = 0,
    max_attempts: int = 3,
    engine_state_revision: int = 0,
    environment_identity: RunEnvironmentIdentity | None = None,
) -> ExecutionJob:
    return ExecutionJob.new(
        run_id=run_id,
        profile=profile,
        scope_ref=scope_ref,
        store_ref=store_ref,
        total_work_units=total_work_units,
        max_attempts=max_attempts,
        engine_state_revision=engine_state_revision,
        environment_identity=environment_identity,
    )


def _operational_for_phase(phase: RunPhase) -> tuple[OperationalLifecycle, TerminalOutcome, ResumeEligibility]:
    if phase is RunPhase.COMPLETE:
        return OperationalLifecycle.COMPLETED, TerminalOutcome.DONE, ResumeEligibility.NOT_ELIGIBLE
    if phase is RunPhase.NEEDS_REVIEW:
        return OperationalLifecycle.COMPLETED, TerminalOutcome.NEEDS_REVIEW, ResumeEligibility.ELIGIBLE
    if phase in {RunPhase.FAILED_INPUT, RunPhase.FAILED_RUNTIME, RunPhase.FAILED_NORMALIZATION, RunPhase.FAILED_EXTRACTION, RunPhase.FAILED_SCHEMA, RunPhase.FAILED_INTERNAL}:
        return OperationalLifecycle.PROCESSING_FAILED, TerminalOutcome.PROCESSING_FAILED, ResumeEligibility.NOT_ELIGIBLE
    if phase is RunPhase.CREATED:
        return OperationalLifecycle.QUEUED, TerminalOutcome.NONE, ResumeEligibility.ELIGIBLE
    if phase in {RunPhase.FAIL_REPAIRABLE, RunPhase.REPAIRING}:
        return OperationalLifecycle.RETRYING, TerminalOutcome.NONE, ResumeEligibility.ELIGIBLE
    return OperationalLifecycle.RUNNING, TerminalOutcome.NONE, ResumeEligibility.ELIGIBLE


def _checkpoint_for_engine(job: ExecutionJob, state: RunState, queue: WorkQueue | None) -> RunCheckpoint:
    total = len(queue.work_units) if queue is not None else state.input_count
    completed = sum(unit.status.value in {"TRANSLATED", "VERIFIED"} for unit in queue.work_units) if queue is not None else 0
    queue_revision = queue.queue_revision if queue is not None else ""
    lifecycle, terminal_outcome, resume_eligibility = _operational_for_phase(state.phase)
    del lifecycle, terminal_outcome
    current_work_unit = state.current_work_unit
    progress = ProgressSnapshot(state.phase.value, completed, total, current_work_unit)
    return replace(
        job.checkpoint,
        revision=job.checkpoint.revision + 1,
        engine_phase=state.phase.value,
        progress=progress,
        engine_state_revision=state.revision,
        queue_revision=queue_revision,
        resume_eligibility=resume_eligibility,
        checkpoint_sha256="",
    )


def sync_workspace_execution(run_dir: Path) -> ExecutionJob:
    """Reflect current engine state into the one workspace execution record."""

    store = WorkspaceRunStore(run_dir)
    state = load_state(run_dir)
    queue: WorkQueue | None
    try:
        queue = load_queue(run_dir)
    except (KSlideError, OSError):
        queue = None
    current = store.load(f"job-{state.run_id}")
    desired_checkpoint = _checkpoint_for_engine(current, state, queue)
    same_checkpoint = all(
        (
            desired_checkpoint.engine_phase == current.checkpoint.engine_phase,
            desired_checkpoint.progress == current.checkpoint.progress,
            desired_checkpoint.engine_state_revision == current.checkpoint.engine_state_revision,
            desired_checkpoint.queue_revision == current.checkpoint.queue_revision,
            desired_checkpoint.resume_eligibility == current.checkpoint.resume_eligibility,
        )
    )
    if not same_checkpoint:
        committed = store.commit_checkpoint(desired_checkpoint, expected_revision=current.revision)
        if not committed.accepted:
            raise KSlideError(ErrorCode.EXECUTION_STALE, "Workspace execution checkpoint changed concurrently; reload before continuing.", {"job_id": current.job_id})
        current = committed.job
    lifecycle, outcome, resume_eligibility = _operational_for_phase(state.phase)
    if (current.lifecycle, current.terminal_outcome, current.resume_eligibility) != (lifecycle, outcome, resume_eligibility):
        committed = store.transition_operational(current.job_id, expected_revision=current.revision, lifecycle=lifecycle, terminal_outcome=outcome, resume_eligibility=resume_eligibility)
        if not committed.accepted:
            raise KSlideError(ErrorCode.EXECUTION_STALE, "Workspace execution lifecycle changed concurrently; reload before continuing.", {"job_id": current.job_id})
        current = committed.job
    return current


def execution_metadata(job: ExecutionJob) -> dict[str, Any]:
    """Return the source-free record used by employee/host status surfaces."""

    value = {
        "contract_version": job.schema_version,
        "run_id": job.run_id,
        "job_id": job.job_id,
        "execution_id": job.execution_id,
        "profile": job.profile.value,
        "lifecycle": job.lifecycle.value,
        "revision": job.revision,
        "checkpoint_revision": job.checkpoint.revision,
        "checkpoint_sha256": job.checkpoint.as_dict()["checkpoint_sha256"],
        "engine_phase": job.checkpoint.engine_phase,
        "progress": job.checkpoint.progress.as_dict(),
        "resume_eligibility": job.resume_eligibility.value,
        "terminal_outcome": job.terminal_outcome.value,
        "cancellation": job.cancellation.as_dict(),
        "retry": job.retry.as_dict(),
        "committed_result_count": len(job.result_markers),
    }
    value["environment_identity"] = job.environment_identity.as_dict() if job.environment_identity is not None else None
    value["environment_identity_sha256"] = job.environment_identity.identity_sha256 if job.environment_identity is not None else None
    return value
