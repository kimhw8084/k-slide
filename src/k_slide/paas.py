"""Platform-neutral durable controller/worker orchestration.

This module owns no engine semantics.  It submits the existing
``ExecutionJob`` contract to a job-service adapter, lets a separately
executable worker claim it, and delegates every checkpoint/result mutation to
the KSA-06 ``RunStore`` contract.  ``ReferencePaaSJobService`` is a
deterministic filesystem adapter for integration tests and local qualification;
an approved company PaaS can implement the small protocols below without
changing the engine or execution record.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Protocol

from . import EXECUTION_CONTRACT_VERSION
from .errors import ErrorCode, KSlideError
from .evidence_ir import stable_revision
from .execution import (
    DurableTestRunStore,
    EngineStepResult,
    ExecutionController,
    ExecutionJob,
    ExecutionProfile,
    FailureClass,
    OperationalLifecycle,
    ResumeEligibility,
    RunCheckpoint,
    RunStore,
    RunStoreRef,
    ResultCommitMarker,
    StoreWriteStatus,
    TerminalOutcome,
    classify_operational_failure,
    execution_metadata,
)
from .io import atomic_write_json, read_json
from .locking import filesystem_lock
from .state import RunPhase, now_utc


PAAS_CONTRACT_VERSION = "1.0"
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}$")
_STRICT_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")
_FORBIDDEN = ("access", "secret", "token", "password", "credential", "source", "content", "prompt")


def _invalid(message: str, *, code: ErrorCode = ErrorCode.EXECUTION_INVALID) -> KSlideError:
    return KSlideError(code, message)


def _safe_identity(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value) or any(word in value.lower() for word in _FORBIDDEN):
        raise _invalid(f"PaaS {label} is invalid.")
    return value


def _strict_identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _STRICT_IDENTIFIER.fullmatch(value) or any(word in value.lower() for word in _FORBIDDEN):
        raise _invalid(f"PaaS {label} is invalid.")
    return value


def _timestamp(value: Any, label: str) -> None:
    if not isinstance(value, str) or not _TIMESTAMP.fullmatch(value):
        raise _invalid(f"PaaS {label} timestamp is invalid.", code=ErrorCode.STATE_CORRUPT)


@dataclass(frozen=True)
class RuntimeIdentity:
    """Exact runtime/semantic identities bound to a durable job.

    The values are opaque deployment references.  They may be digest-qualified
    manifest/model/asset references, but never contain source, credentials, or
    process-only secret material.
    """

    runtime_ref: str
    model_identity: str
    ocr_identity: str
    termbase_identity: str
    engine_contract_version: str = EXECUTION_CONTRACT_VERSION

    def __post_init__(self) -> None:
        _safe_identity(self.runtime_ref, "runtime identity")
        _safe_identity(self.model_identity, "model identity")
        _safe_identity(self.ocr_identity, "OCR identity")
        _safe_identity(self.termbase_identity, "termbase identity")
        _safe_identity(self.engine_contract_version, "engine contract version")
        if self.engine_contract_version != EXECUTION_CONTRACT_VERSION:
            raise _invalid("PaaS runtime is incompatible with the K-Slide execution contract.", code=ErrorCode.EXECUTION_UNSUPPORTED_VERSION)

    def as_dict(self) -> dict[str, str]:
        return {
            "runtime_ref": self.runtime_ref,
            "model_identity": self.model_identity,
            "ocr_identity": self.ocr_identity,
            "termbase_identity": self.termbase_identity,
            "engine_contract_version": self.engine_contract_version,
        }

    @classmethod
    def from_runtime_metadata(cls, runtime_metadata: Any, *, runtime_ref: str, ocr_identity: str, termbase_identity: str) -> "RuntimeIdentity":
        """Project the existing runtime discovery into a safe job binding."""

        model_identity = getattr(runtime_metadata, "reported_model_id", None)
        if not isinstance(model_identity, str) or not model_identity:
            raise _invalid("PaaS submission cannot bind an undiscoverable model identity.", code=ErrorCode.MODEL_UNKNOWN)
        return cls(runtime_ref, model_identity, ocr_identity, termbase_identity)

    @classmethod
    def from_dict(cls, value: Any) -> "RuntimeIdentity":
        if not isinstance(value, dict) or set(value) != {"runtime_ref", "model_identity", "ocr_identity", "termbase_identity", "engine_contract_version"}:
            raise _invalid("PaaS runtime identity is incomplete.", code=ErrorCode.STATE_CORRUPT)
        try:
            return cls(**value)
        except (TypeError, ValueError) as exc:
            raise _invalid("PaaS runtime identity is invalid.", code=ErrorCode.STATE_CORRUPT) from exc


# The longer name makes deployment bindings self-documenting while retaining
# the compact public name for adapter implementations.
PinnedRuntimeIdentity = RuntimeIdentity


@dataclass(frozen=True)
class DurableJobIdentity:
    """Stable, reconnectable identity returned to the interactive host."""

    run_id: str
    job_id: str
    execution_id: str
    scope_ref: str
    store_ref: str
    contract_version: str = PAAS_CONTRACT_VERSION

    def __post_init__(self) -> None:
        for value, label in ((self.run_id, "run ID"), (self.job_id, "job ID"), (self.execution_id, "execution ID")):
            _strict_identifier(value, label)
        RunStoreRef(self.scope_ref, self.store_ref)
        if self.contract_version != PAAS_CONTRACT_VERSION:
            raise _invalid("Unsupported PaaS job identity version.", code=ErrorCode.EXECUTION_UNSUPPORTED_VERSION)

    @classmethod
    def from_job(cls, job: ExecutionJob) -> "DurableJobIdentity":
        return cls(job.run_id, job.job_id, job.execution_id, job.store_ref.scope_ref, job.store_ref.store_ref)

    @classmethod
    def from_dict(cls, value: Any) -> "DurableJobIdentity":
        if not isinstance(value, dict) or set(value) != {"contract_version", "run_id", "job_id", "execution_id", "scope_ref", "store_ref"}:
            raise _invalid("PaaS job identity is incomplete.", code=ErrorCode.STATE_CORRUPT)
        try:
            return cls(**value)
        except (TypeError, ValueError) as exc:
            raise _invalid("PaaS job identity is invalid.", code=ErrorCode.STATE_CORRUPT) from exc

    def as_dict(self) -> dict[str, str]:
        return {
            "contract_version": self.contract_version,
            "run_id": self.run_id,
            "job_id": self.job_id,
            "execution_id": self.execution_id,
            "scope_ref": self.scope_ref,
            "store_ref": self.store_ref,
        }


@dataclass(frozen=True)
class PaaSJobRequest:
    """Source-free controller submission request."""

    run_id: str
    scope_ref: str
    store_ref: str
    runtime_identity: RuntimeIdentity
    total_work_units: int = 0
    max_attempts: int = 3
    engine_state_revision: int = 0
    job_id: str | None = None
    execution_id: str | None = None

    def __post_init__(self) -> None:
        _strict_identifier(self.run_id, "run ID")
        RunStoreRef(self.scope_ref, self.store_ref)
        if not isinstance(self.runtime_identity, RuntimeIdentity):
            raise _invalid("PaaS submission runtime identity is invalid.")
        if not isinstance(self.total_work_units, int) or self.total_work_units < 0 or self.total_work_units > 100_000:
            raise _invalid("PaaS submission work-unit count is outside the bounded range.")
        if not isinstance(self.max_attempts, int) or self.max_attempts < 1 or self.max_attempts > 32:
            raise _invalid("PaaS submission retry limit is outside the bounded range.")
        if not isinstance(self.engine_state_revision, int) or self.engine_state_revision < 0:
            raise _invalid("PaaS submission engine revision is invalid.")
        if self.job_id is not None:
            _strict_identifier(self.job_id, "job ID")
        if self.execution_id is not None:
            _strict_identifier(self.execution_id, "execution ID")


# Alias for deployments that call the object a submission rather than a job.
PaaSJobSubmission = PaaSJobRequest


@dataclass(frozen=True)
class PaaSJobStatus:
    """Source-free status/progress view safe to return after host loss."""

    identity: DurableJobIdentity
    lifecycle: OperationalLifecycle
    terminal_outcome: TerminalOutcome
    resume_eligibility: ResumeEligibility
    revision: int
    checkpoint_revision: int
    checkpoint_sha256: str
    engine_phase: str
    progress: dict[str, Any]
    cancellation: dict[str, Any]
    retry: dict[str, Any]

    @classmethod
    def from_job(cls, job: ExecutionJob) -> "PaaSJobStatus":
        metadata = execution_metadata(job)
        return cls(
            DurableJobIdentity.from_job(job),
            job.lifecycle,
            job.terminal_outcome,
            job.resume_eligibility,
            job.revision,
            job.checkpoint.revision,
            str(metadata["checkpoint_sha256"]),
            job.checkpoint.engine_phase,
            dict(job.checkpoint.progress.as_dict()),
            dict(job.cancellation.as_dict()),
            dict(job.retry.as_dict()),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "contract_version": PAAS_CONTRACT_VERSION,
            "identity": self.identity.as_dict(),
            "operational_state": self.lifecycle.value,
            "terminal_outcome": self.terminal_outcome.value,
            "resume_eligibility": self.resume_eligibility.value,
            "revision": self.revision,
            "checkpoint_revision": self.checkpoint_revision,
            "checkpoint_sha256": self.checkpoint_sha256,
            "engine_phase": self.engine_phase,
            "progress": dict(self.progress),
            "cancellation": dict(self.cancellation),
            "retry": dict(self.retry),
        }


@dataclass(frozen=True)
class PaaSSubmissionReceipt:
    status: StoreWriteStatus
    identity: DurableJobIdentity

    @property
    def job_id(self) -> str:
        return self.identity.job_id

    def as_dict(self) -> dict[str, Any]:
        return {"status": self.status.value, "identity": self.identity.as_dict()}


@dataclass(frozen=True)
class WorkerClaim:
    identity: DurableJobIdentity
    job: ExecutionJob
    claim_ref: str

    def as_dict(self) -> dict[str, Any]:
        return {"claim_ref": self.claim_ref, "status": PaaSJobStatus.from_job(self.job).as_dict()}


@dataclass(frozen=True)
class WorkerResult:
    status: str
    job: ExecutionJob
    engine_called: bool = False
    failure_class: FailureClass | None = None

    def as_dict(self) -> dict[str, Any]:
        value = PaaSJobStatus.from_job(self.job).as_dict()
        value.update({"status": self.status, "engine_called": self.engine_called})
        if self.failure_class is not None:
            value["failure_class"] = self.failure_class.value
        return value


class RunStoreResolver(Protocol):
    """Resolve an opaque store reference to the existing KSA-06 RunStore."""

    def open_store(self, identity: DurableJobIdentity) -> RunStore: ...


class PaaSJobService(Protocol):
    """Narrow adapter contract for an approved durable job service.

    The service owns job dispatch/lifetime and durable identity.  It does not
    receive source content, prompts, results, or AccessKey material.
    """

    def submit(self, job: ExecutionJob, *, runtime_identity: RuntimeIdentity) -> PaaSSubmissionReceipt: ...

    def inspect(self, identity: DurableJobIdentity | str) -> PaaSJobStatus: ...

    def request_cancellation(self, identity: DurableJobIdentity | str) -> PaaSJobStatus: ...

    def claim(self, identity: DurableJobIdentity | str, *, worker_id: str, runtime_identity: RuntimeIdentity) -> WorkerClaim: ...

    def open_store(self, identity: DurableJobIdentity) -> RunStore: ...


class PaaSRunStore:
    """Adapter shell that delegates all state semantics to a RunStore.

    A company implementation supplies its own backend.  The reference
    subclass below delegates to ``DurableTestRunStore`` solely as a
    deterministic integration backend; it is not presented as a live PaaS.
    """

    def __init__(self, backend: RunStore) -> None:
        self._backend = backend

    @property
    def root(self) -> Path:
        return self._backend.root  # type: ignore[attr-defined]

    @property
    def profile(self) -> ExecutionProfile:
        return self._backend.profile  # type: ignore[attr-defined]

    def create(self, job: ExecutionJob):
        return self._backend.create(job)

    def load(self, job_id: str) -> ExecutionJob:
        return self._backend.load(job_id)

    def load_checkpoint(self, job_id: str) -> RunCheckpoint:
        return self._backend.load_checkpoint(job_id)

    def commit_job(self, job: ExecutionJob, *, expected_revision: int):
        return self._backend.commit_job(job, expected_revision=expected_revision)

    def commit_checkpoint(self, checkpoint: RunCheckpoint, *, expected_revision: int):
        return self._backend.commit_checkpoint(checkpoint, expected_revision=expected_revision)

    def commit_step(self, checkpoint: RunCheckpoint, marker: Any, *, expected_revision: int):
        return self._backend.commit_step(checkpoint, marker, expected_revision=expected_revision)

    def request_cancellation(self, job_id: str, *, expected_revision: int | None = None):
        return self._backend.request_cancellation(job_id, expected_revision=expected_revision)

    def acknowledge_cancellation(self, job_id: str, *, expected_revision: int, safe_boundary: bool):
        return self._backend.acknowledge_cancellation(job_id, expected_revision=expected_revision, safe_boundary=safe_boundary)

    def transition_operational(self, job_id: str, *, expected_revision: int, lifecycle: OperationalLifecycle, terminal_outcome: TerminalOutcome = TerminalOutcome.NONE, resume_eligibility: ResumeEligibility | None = None):
        return self._backend.transition_operational(job_id, expected_revision=expected_revision, lifecycle=lifecycle, terminal_outcome=terminal_outcome, resume_eligibility=resume_eligibility)

    def record_retry(self, job_id: str, *, expected_revision: int, error_code: str):
        return self._backend.record_retry(job_id, expected_revision=expected_revision, error_code=error_code)

    def commit_result(self, job_id: str, marker: Any, *, expected_revision: int):
        return self._backend.commit_result(job_id, marker, expected_revision=expected_revision)


class ReferencePaaSRunStore(PaaSRunStore):
    """Deterministic reference backend for the platform-neutral boundary."""

    def __init__(self, backing_root: Path) -> None:
        super().__init__(DurableTestRunStore(backing_root))


@dataclass(frozen=True)
class _PaaSJobRecord:
    identity: DurableJobIdentity
    runtime_identity: RuntimeIdentity
    submitted_at: str
    schema_version: str = PAAS_CONTRACT_VERSION

    def as_dict(self) -> dict[str, Any]:
        value = {
            "schema_version": self.schema_version,
            "identity": self.identity.as_dict(),
            "runtime_identity": self.runtime_identity.as_dict(),
            "submitted_at": self.submitted_at,
        }
        value["record_sha256"] = stable_revision(value)
        return value


def _record_from_dict(value: Any) -> _PaaSJobRecord:
    required = {"schema_version", "identity", "runtime_identity", "submitted_at", "record_sha256"}
    if not isinstance(value, dict) or set(value) != required:
        raise _invalid("PaaS job service record is corrupt.", code=ErrorCode.STATE_CORRUPT)
    without_hash = dict(value)
    record_hash = without_hash.pop("record_sha256")
    if not isinstance(record_hash, str) or record_hash != stable_revision(without_hash):
        raise _invalid("PaaS job service record hash is inconsistent.", code=ErrorCode.STATE_CORRUPT)
    if value["schema_version"] != PAAS_CONTRACT_VERSION:
        raise _invalid("Unsupported PaaS job service record version.", code=ErrorCode.EXECUTION_UNSUPPORTED_VERSION)
    record = _PaaSJobRecord(
        DurableJobIdentity.from_dict(value["identity"]),
        RuntimeIdentity.from_dict(value["runtime_identity"]),
        value["submitted_at"],
    )
    _timestamp(record.submitted_at, "submission")
    return record


class ReferencePaaSJobService(RunStoreResolver):
    """Filesystem job-service adapter used for deterministic integration.

    It deliberately has no lease timeout: a new worker may reattach to an
    active job after a worker/controller process disappears.  Concurrent work
    remains protected by the underlying RunStore CAS contract.
    """

    def __init__(self, service_root: Path) -> None:
        self.root = Path(service_root).expanduser().resolve()
        self._records_root = self.root / "job-service" / "jobs"
        self._store = ReferencePaaSRunStore(self.root / "job-service" / "run-store")

    def _record_path(self, job_id: str) -> Path:
        _strict_identifier(job_id, "job ID")
        return self._records_root / f"{job_id}.json"

    def _record_lock(self, job_id: str):
        return filesystem_lock(self.root / "job-service" / "locks" / f"{job_id}.lock", require_shared=True, reject_symlink=True)

    def _read_record(self, job_id: str) -> _PaaSJobRecord:
        path = self._record_path(job_id)
        if not path.is_file():
            raise KSlideError(ErrorCode.EXECUTION_NOT_FOUND, "Durable PaaS job does not exist.", {"job_id": job_id})
        try:
            value = read_json(path)
        except (OSError, TypeError, ValueError) as exc:
            raise KSlideError(ErrorCode.STATE_CORRUPT, "Durable PaaS job record is corrupt or unreadable.", {"job_id": job_id}) from exc
        except KSlideError as exc:
            raise KSlideError(ErrorCode.STATE_CORRUPT, "Durable PaaS job record is corrupt or unreadable.", {"job_id": job_id}) from exc
        return _record_from_dict(value)

    def _identity(self, identity: DurableJobIdentity | str) -> DurableJobIdentity:
        if isinstance(identity, DurableJobIdentity):
            record = self._read_record(identity.job_id)
            if record.identity != identity:
                raise KSlideError(ErrorCode.EXECUTION_CONFLICT, "Durable PaaS job identity does not match the service record.", {"job_id": identity.job_id})
            return identity
        return self._read_record(identity).identity

    @staticmethod
    def _check_job_identity(job: ExecutionJob, identity: DurableJobIdentity) -> None:
        if DurableJobIdentity.from_job(job) != identity or job.profile is not ExecutionProfile.DURABLE:
            raise KSlideError(ErrorCode.EXECUTION_CONFLICT, "Durable PaaS job identity or profile does not match the service record.", {"job_id": identity.job_id})

    @staticmethod
    def _same_submission(existing: ExecutionJob, candidate: ExecutionJob) -> bool:
        return (
            DurableJobIdentity.from_job(existing) == DurableJobIdentity.from_job(candidate)
            and existing.profile is ExecutionProfile.DURABLE
            and existing.checkpoint.progress.total_work_units == candidate.checkpoint.progress.total_work_units
            and existing.retry.max_attempts == candidate.retry.max_attempts
        )

    def submit(self, job: ExecutionJob, *, runtime_identity: RuntimeIdentity) -> PaaSSubmissionReceipt:
        if job.profile is not ExecutionProfile.DURABLE:
            raise _invalid("PaaS service accepts only the durable execution profile.")
        if not isinstance(runtime_identity, RuntimeIdentity):
            raise _invalid("PaaS submission runtime identity is invalid.")
        identity = DurableJobIdentity.from_job(job)
        path = self._record_path(identity.job_id)
        with self._record_lock(identity.job_id):
            if path.is_file():
                record = self._read_record(identity.job_id)
                if record.identity != identity or record.runtime_identity != runtime_identity:
                    return PaaSSubmissionReceipt(StoreWriteStatus.CONFLICT, record.identity)
                existing = self._store.load(identity.job_id)
                if not self._same_submission(existing, job):
                    return PaaSSubmissionReceipt(StoreWriteStatus.CONFLICT, record.identity)
                return PaaSSubmissionReceipt(StoreWriteStatus.IDEMPOTENT, record.identity)
            stored = self._store.create(job)
            if stored.status is StoreWriteStatus.CONFLICT:
                try:
                    existing = self._store.load(identity.job_id)
                except KSlideError:
                    return PaaSSubmissionReceipt(stored.status, identity)
                if not self._same_submission(existing, job):
                    return PaaSSubmissionReceipt(stored.status, identity)
            record = _PaaSJobRecord(identity, runtime_identity, now_utc())
            atomic_write_json(path, record.as_dict(), mode=0o600)
            return PaaSSubmissionReceipt(StoreWriteStatus.IDEMPOTENT if stored.status is StoreWriteStatus.CONFLICT else stored.status, identity)

    def open_store(self, identity: DurableJobIdentity) -> RunStore:
        self._identity(identity)
        return self._store

    def inspect(self, identity: DurableJobIdentity | str) -> PaaSJobStatus:
        resolved = self._identity(identity)
        job = self._store.load(resolved.job_id)
        self._check_job_identity(job, resolved)
        return PaaSJobStatus.from_job(job)

    def request_cancellation(self, identity: DurableJobIdentity | str) -> PaaSJobStatus:
        resolved = self._identity(identity)
        with self._record_lock(resolved.job_id):
            current = self._store.load(resolved.job_id)
            self._check_job_identity(current, resolved)
            self._store.request_cancellation(resolved.job_id)
        return self.inspect(resolved)

    def claim(self, identity: DurableJobIdentity | str, *, worker_id: str, runtime_identity: RuntimeIdentity) -> WorkerClaim:
        worker_id = _strict_identifier(worker_id, "worker ID")
        resolved = self._identity(identity)
        record = self._read_record(resolved.job_id)
        if record.runtime_identity != runtime_identity:
            raise KSlideError(ErrorCode.EXECUTION_CONFLICT, "Worker runtime identity does not match the durable job binding.", {"job_id": resolved.job_id})
        job = self._store.load(resolved.job_id)
        self._check_job_identity(job, resolved)
        claim_state = "reattach" if job.lifecycle is OperationalLifecycle.RUNNING else "claim"
        claim_ref = _safe_identity(f"{claim_state}-{worker_id}-{stable_revision(resolved.as_dict())[:16]}", "claim reference")
        return WorkerClaim(resolved, job, claim_ref)

    def claim_next(self, *, worker_id: str, runtime_identity: RuntimeIdentity) -> WorkerClaim:
        if not self._records_root.is_dir():
            raise KSlideError(ErrorCode.EXECUTION_NOT_FOUND, "No durable PaaS jobs are queued.")
        for path in sorted(self._records_root.glob("*.json")):
            record = self._read_record(path.stem)
            job = self._store.load(record.identity.job_id)
            if job.lifecycle in {OperationalLifecycle.QUEUED, OperationalLifecycle.RUNNING, OperationalLifecycle.RETRYING}:
                return self.claim(record.identity, worker_id=worker_id, runtime_identity=runtime_identity)
        raise KSlideError(ErrorCode.EXECUTION_NOT_FOUND, "No durable PaaS jobs are queued.")


class PaaSController:
    """Interactive-host facade that never waits for worker completion."""

    def __init__(self, service: PaaSJobService) -> None:
        self.service = service

    def submit(self, request: PaaSJobRequest | None = None, **kwargs: Any) -> PaaSSubmissionReceipt:
        if request is None:
            request = PaaSJobRequest(**kwargs)
        if not isinstance(request, PaaSJobRequest):
            raise _invalid("PaaS controller submission is invalid.")
        job = ExecutionJob.new(
            run_id=request.run_id,
            profile=ExecutionProfile.DURABLE,
            scope_ref=request.scope_ref,
            store_ref=request.store_ref,
            job_id=request.job_id,
            execution_id=request.execution_id,
            total_work_units=request.total_work_units,
            max_attempts=request.max_attempts,
            engine_state_revision=request.engine_state_revision,
        )
        return self.service.submit(job, runtime_identity=request.runtime_identity)

    def status(self, identity: DurableJobIdentity | str) -> PaaSJobStatus:
        return self.service.inspect(identity)

    def reconnect(self, identity: DurableJobIdentity | str) -> PaaSJobStatus:
        return self.status(identity)

    def cancel(self, identity: DurableJobIdentity | str) -> PaaSJobStatus:
        return self.service.request_cancellation(identity)


class WorkerEngine(Protocol):
    """Engine binding supplied by the existing K-Slide runtime."""

    def operation_id(self, job: ExecutionJob) -> str: ...

    def step(self, checkpoint: RunCheckpoint, operation_id: str) -> EngineStepResult: ...


class PaaSWorker:
    """Restartable worker using the existing ExecutionController boundary."""

    def __init__(self, service: PaaSJobService, *, worker_id: str, runtime_identity: RuntimeIdentity, engine: WorkerEngine | Any) -> None:
        self.service = service
        self.worker_id = _strict_identifier(worker_id, "worker ID")
        if not isinstance(runtime_identity, RuntimeIdentity):
            raise _invalid("Worker runtime identity is invalid.")
        self.runtime_identity = runtime_identity
        self.engine = engine

    def _engine_operation_id(self, job: ExecutionJob) -> str:
        operation = getattr(self.engine, "operation_id", None)
        value = operation(job) if callable(operation) else f"{job.execution_id}-step-{job.checkpoint.revision + 1}"
        return _safe_identity(value, "engine operation ID")

    def _engine_step(self, checkpoint: RunCheckpoint, operation_id: str) -> EngineStepResult:
        step = getattr(self.engine, "step", None)
        if callable(step):
            result = step(checkpoint, operation_id)
        elif callable(self.engine):
            result = self.engine(checkpoint, operation_id)
        else:
            raise _invalid("Worker engine binding is not callable.")
        if not isinstance(result, EngineStepResult):
            raise _invalid("Worker engine returned an invalid step result.")
        return result

    @staticmethod
    def _terminal_status(job: ExecutionJob) -> str | None:
        if job.lifecycle is OperationalLifecycle.CANCELED:
            return "CANCELED"
        if job.lifecycle is OperationalLifecycle.PROCESSING_FAILED:
            return "PROCESSING_FAILED"
        if job.lifecycle is OperationalLifecycle.COMPLETED:
            return job.terminal_outcome.value
        return None

    def _reconcile(self, store: RunStore, job: ExecutionJob, *, accepted_status: str = "ACCEPTED", engine_called: bool = True) -> WorkerResult:
        current = store.load(job.job_id)
        if current.cancellation.requested and not current.cancellation.acknowledged:
            acknowledged = store.acknowledge_cancellation(current.job_id, expected_revision=current.revision, safe_boundary=True)
            if acknowledged.accepted:
                return WorkerResult("CANCELED", acknowledged.job, engine_called=engine_called)
            return WorkerResult(acknowledged.status.value, acknowledged.job, engine_called=engine_called)
        if current.lifecycle in {OperationalLifecycle.RUNNING, OperationalLifecycle.RETRYING}:
            if current.checkpoint.engine_phase == RunPhase.COMPLETE.value:
                committed = store.transition_operational(current.job_id, expected_revision=current.revision, lifecycle=OperationalLifecycle.COMPLETED, terminal_outcome=TerminalOutcome.DONE, resume_eligibility=ResumeEligibility.NOT_ELIGIBLE)
                if committed.accepted:
                    return WorkerResult("DONE", committed.job, engine_called=engine_called)
                return WorkerResult(committed.status.value, committed.job, engine_called=engine_called)
            if current.checkpoint.engine_phase == RunPhase.NEEDS_REVIEW.value:
                committed = store.transition_operational(current.job_id, expected_revision=current.revision, lifecycle=OperationalLifecycle.COMPLETED, terminal_outcome=TerminalOutcome.NEEDS_REVIEW, resume_eligibility=ResumeEligibility.ELIGIBLE)
                if committed.accepted:
                    return WorkerResult("NEEDS_REVIEW", committed.job, engine_called=engine_called)
                return WorkerResult(committed.status.value, committed.job, engine_called=engine_called)
        return WorkerResult(accepted_status, current, engine_called=engine_called)

    def _record_failure(self, store: RunStore, job: ExecutionJob, error: KSlideError | Exception) -> WorkerResult:
        current = store.load(job.job_id)
        if current.cancellation.requested and not current.cancellation.acknowledged:
            acknowledged = store.acknowledge_cancellation(current.job_id, expected_revision=current.revision, safe_boundary=True)
            if acknowledged.accepted:
                return WorkerResult("CANCELED", acknowledged.job)
            return WorkerResult(acknowledged.status.value, acknowledged.job)
        if isinstance(error, KSlideError):
            error_code = error.code
        else:
            error_code = ErrorCode.INTERNAL
        failure_class = classify_operational_failure(error_code)
        if failure_class is FailureClass.SEMANTIC_REPAIR:
            return WorkerResult("SEMANTIC_REPAIR", current, failure_class=failure_class)
        if error_code is ErrorCode.EXECUTION_STALE:
            return WorkerResult("STALE", current, failure_class=failure_class)
        try:
            recorded = store.record_retry(current.job_id, expected_revision=current.revision, error_code=error_code.value)
        except KSlideError:
            latest = store.load(current.job_id)
            return WorkerResult("STALE", latest, failure_class=failure_class)
        status = "RETRYING" if recorded.job.lifecycle is OperationalLifecycle.RETRYING else "PROCESSING_FAILED"
        return WorkerResult(status, recorded.job, failure_class=failure_class)

    def run_once(self, identity: DurableJobIdentity | str | None = None) -> WorkerResult:
        if identity is None:
            claim_method = getattr(self.service, "claim_next", None)
            if not callable(claim_method):
                raise _invalid("This PaaS adapter does not support claim-next; provide a job identity.")
            claim = claim_method(worker_id=self.worker_id, runtime_identity=self.runtime_identity)
        else:
            claim = self.service.claim(identity, worker_id=self.worker_id, runtime_identity=self.runtime_identity)
        store = self.service.open_store(claim.identity)
        job = store.load(claim.identity.job_id)
        terminal = self._terminal_status(job)
        if terminal is not None:
            return WorkerResult(terminal, job)
        if job.lifecycle is OperationalLifecycle.COMPLETED and job.terminal_outcome is TerminalOutcome.NEEDS_REVIEW:
            resumed = store.transition_operational(job.job_id, expected_revision=job.revision, lifecycle=OperationalLifecycle.RETRYING)
            if not resumed.accepted:
                return WorkerResult(resumed.status.value, resumed.job)
            job = resumed.job
        if job.lifecycle is OperationalLifecycle.RETRYING:
            started = store.transition_operational(job.job_id, expected_revision=job.revision, lifecycle=OperationalLifecycle.RUNNING)
            if not started.accepted:
                return WorkerResult(started.status.value, started.job)
        try:
            operation_id = self._engine_operation_id(store.load(job.job_id))
            controller = ExecutionController(store)
            result = controller.run_step(job.job_id, operation_id=operation_id, step=self._engine_step)
        except Exception as exc:
            return self._record_failure(store, job, exc)
        if result.status in {"CANCELED", "CONFLICT", "STALE"}:
            return WorkerResult(result.status, result.job, engine_called=result.engine_called)
        return self._reconcile(store, result.job, accepted_status=result.status, engine_called=result.engine_called)

    def run_until_terminal(self, identity: DurableJobIdentity | str | None = None, *, max_steps: int = 100_000) -> WorkerResult:
        if not isinstance(max_steps, int) or max_steps < 1 or max_steps > 100_000:
            raise _invalid("Worker step limit is outside the bounded range.")
        current_identity = identity
        last: WorkerResult | None = None
        for _ in range(max_steps):
            last = self.run_once(current_identity)
            current_identity = last.job.job_id
            if self._terminal_status(last.job) is not None or last.status in {"SEMANTIC_REPAIR", "STALE", "CONFLICT", "STEP_LIMIT"}:
                return last
        if last is None:
            raise _invalid("Worker did not execute a step.")
        return WorkerResult("STEP_LIMIT", last.job, engine_called=last.engine_called, failure_class=last.failure_class)


class ReferenceWorkerEngine:
    """Small deterministic engine adapter used only by the reference worker."""

    def operation_id(self, job: ExecutionJob) -> str:
        return f"{job.execution_id}-step-{job.checkpoint.revision + 1}"

    def step(self, checkpoint: RunCheckpoint, operation_id: str) -> EngineStepResult:
        completed = checkpoint.progress.completed_work_units
        total = checkpoint.progress.total_work_units
        next_completed = min(total, completed + 1)
        phase = RunPhase.COMPLETE.value if next_completed >= total else RunPhase.TRANSLATING.value
        current_unit = None if phase == RunPhase.COMPLETE.value else f"unit-{next_completed + 1:06d}"
        progress = type(checkpoint.progress)(phase, next_completed, total, current_unit)
        next_checkpoint = replace(
            checkpoint,
            revision=checkpoint.revision + 1,
            engine_phase=phase,
            progress=progress,
            resume_eligibility=ResumeEligibility.NOT_ELIGIBLE if phase == RunPhase.COMPLETE.value else ResumeEligibility.ELIGIBLE,
            checkpoint_sha256="",
        )
        marker = ResultCommitMarker(
            operation_id,
            "reference-result",
            stable_revision({"operation_id": operation_id, "checkpoint_revision": next_checkpoint.revision}),
            attempt=0,
            committed_at="",
        )
        return EngineStepResult(next_checkpoint, marker)


__all__ = [
    "PAAS_CONTRACT_VERSION",
    "DurableJobIdentity",
    "PaaSController",
    "PaaSJobRequest",
    "PaaSJobService",
    "PaaSJobStatus",
    "PaaSJobSubmission",
    "PaaSRunStore",
    "PaaSSubmissionReceipt",
    "PinnedRuntimeIdentity",
    "ReferencePaaSJobService",
    "ReferencePaaSRunStore",
    "ReferenceWorkerEngine",
    "RunStoreResolver",
    "RuntimeIdentity",
    "WorkerClaim",
    "WorkerEngine",
    "WorkerResult",
    "PaaSWorker",
]
