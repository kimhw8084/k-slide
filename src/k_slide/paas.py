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
from collections.abc import Mapping
from dataclasses import dataclass, replace
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Protocol

from . import EXECUTION_CONTRACT_VERSION
from .authentication import ApprovedCompanyServiceTransport, CompanyServiceRequest, authenticated_company_service_call
from .errors import ErrorCode, KSlideError
from .evidence_ir import stable_revision
from .environment import RunEnvironmentIdentity, environment_mismatch_fields, raise_environment_mismatch
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
from .storage import STORAGE_PLANE_CONTRACT_VERSION, StorageArtifact, StorageLayout, StoragePlane


PAAS_CONTRACT_VERSION = "1.0"
SCOPED_PAAS_CONTRACT_VERSION = "1.0"
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}$")
_STRICT_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")
_FORBIDDEN = ("access", "secret", "token", "password", "credential", "source", "content", "prompt")


def authenticated_paas_service_call(
    transport: ApprovedCompanyServiceTransport,
    request: CompanyServiceRequest | Mapping[str, Any],
) -> object:
    """Use the common AccessKey boundary for durable/PaaS callers."""

    return authenticated_company_service_call(transport, request)


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
class AuthorizedScopeContext:
    """Deployment-supplied authorization and tenancy context.

    This is deliberately not an authentication implementation.  The
    deployment adapter authenticates the caller and supplies this already
    authorized, opaque context to the controller, worker, or resolver.  The
    reference backend only verifies that the context matches the durable
    scope; it never looks up users or credentials.
    """

    user_ref: str
    workspace_ref: str
    scope_ref: str | None = None

    def __post_init__(self) -> None:
        _safe_identity(self.user_ref, "authorized user reference")
        _safe_identity(self.workspace_ref, "authorized workspace reference")
        scope_ref = self.scope_ref or f"scope-{stable_revision({'user_ref': self.user_ref, 'workspace_ref': self.workspace_ref})[:32]}"
        _safe_identity(scope_ref, "authorized scope reference")
        object.__setattr__(self, "scope_ref", scope_ref)

    @property
    def user_id(self) -> str:
        """Compatibility spelling for deployment adapters."""

        return self.user_ref

    @property
    def workspace_id(self) -> str:
        """Compatibility spelling for deployment adapters."""

        return self.workspace_ref

    def as_dict(self) -> dict[str, str]:
        return {"user_ref": self.user_ref, "workspace_ref": self.workspace_ref, "scope_ref": str(self.scope_ref)}

    @classmethod
    def from_dict(cls, value: Any) -> "AuthorizedScopeContext":
        if not isinstance(value, dict) or set(value) != {"user_ref", "workspace_ref", "scope_ref"}:
            raise _invalid("Authorized scope context is incomplete.", code=ErrorCode.STATE_CORRUPT)
        try:
            return cls(**value)
        except (TypeError, ValueError) as exc:
            raise _invalid("Authorized scope context is invalid.", code=ErrorCode.STATE_CORRUPT) from exc


# These aliases make the boundary readable to deployment adapters that use
# either authorization or tenancy terminology.  They are one context type,
# not separate identity systems.
ScopeContext = AuthorizedScopeContext
AuthorizationContext = AuthorizedScopeContext
PaaSScopeContext = AuthorizedScopeContext
AuthorizedScope = AuthorizedScopeContext
ScopeAuthorization = AuthorizedScopeContext


@dataclass(frozen=True)
class ScopedAdmissionPolicy:
    """Durable admission policy; the production default is one heavy run."""

    max_active_heavy_runs_per_scope: int = 1

    def __post_init__(self) -> None:
        if self.max_active_heavy_runs_per_scope != 1:
            raise _invalid("The KSA-09 reference policy supports exactly one active heavy run per scope.")


@dataclass(frozen=True)
class ScopedArtifactReferences:
    """Opaque, source-free references confined to one authorized scope."""

    scope_ref: str
    store_ref: str
    run_ref: str
    result_ref: str
    evidence_ref: str
    plane: StoragePlane = StoragePlane.DURABLE_USER_WORKSPACE_RUN_DATA
    storage_contract_version: str = STORAGE_PLANE_CONTRACT_VERSION

    def __post_init__(self) -> None:
        _safe_identity(self.scope_ref, "artifact scope reference")
        for value, label in (
            (self.store_ref, "artifact store reference"),
            (self.run_ref, "run reference"),
            (self.result_ref, "result reference"),
            (self.evidence_ref, "evidence reference"),
        ):
            _safe_identity(value, label)
        if not isinstance(self.plane, StoragePlane):
            try:
                object.__setattr__(self, "plane", StoragePlane(str(self.plane)))
            except ValueError as exc:
                raise _invalid("Artifact reference plane is unsupported.") from exc
        if self.plane is not StoragePlane.DURABLE_USER_WORKSPACE_RUN_DATA:
            raise _invalid("Durable artifact references must identify the durable user/workspace run-data plane.")
        if self.storage_contract_version != STORAGE_PLANE_CONTRACT_VERSION:
            raise _invalid("Unsupported storage-plane contract version.", code=ErrorCode.EXECUTION_UNSUPPORTED_VERSION)

    def as_dict(self) -> dict[str, str]:
        return {
            "scope_ref": self.scope_ref,
            "store_ref": self.store_ref,
            "run_ref": self.run_ref,
            "result_ref": self.result_ref,
            "evidence_ref": self.evidence_ref,
            "plane": self.plane.value,
            "storage_contract_version": self.storage_contract_version,
        }

    @classmethod
    def from_dict(cls, value: Any) -> "ScopedArtifactReferences":
        allowed = {"scope_ref", "store_ref", "run_ref", "result_ref", "evidence_ref", "plane", "storage_contract_version"}
        if not isinstance(value, dict) or set(value) - allowed or not {"scope_ref", "store_ref", "run_ref", "result_ref", "evidence_ref"}.issubset(value):
            raise _invalid("Scoped artifact references are incomplete.", code=ErrorCode.STATE_CORRUPT)
        try:
            return cls(**{**value, "plane": value.get("plane", StoragePlane.DURABLE_USER_WORKSPACE_RUN_DATA), "storage_contract_version": value.get("storage_contract_version", STORAGE_PLANE_CONTRACT_VERSION)})
        except (TypeError, ValueError) as exc:
            raise _invalid("Scoped artifact references are invalid.", code=ErrorCode.STATE_CORRUPT) from exc


RunResultEvidenceRefs = ScopedArtifactReferences


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
    environment_identity: RunEnvironmentIdentity | None = None

    def __post_init__(self) -> None:
        _safe_identity(self.runtime_ref, "runtime identity")
        _safe_identity(self.model_identity, "model identity")
        _safe_identity(self.ocr_identity, "OCR identity")
        _safe_identity(self.termbase_identity, "termbase identity")
        _safe_identity(self.engine_contract_version, "engine contract version")
        if self.engine_contract_version != EXECUTION_CONTRACT_VERSION:
            raise _invalid("PaaS runtime is incompatible with the K-Slide execution contract.", code=ErrorCode.EXECUTION_UNSUPPORTED_VERSION)
        if self.environment_identity is not None and not isinstance(self.environment_identity, RunEnvironmentIdentity):
            raise _invalid("PaaS runtime environment identity is invalid.")

    def environment(self) -> RunEnvironmentIdentity:
        if self.environment_identity is None:
            raise KSlideError(
                ErrorCode.EXECUTION_INVALID,
                "PaaS runtime must provide a complete canonical KSA-10 environment identity.",
            )
        return self.environment_identity

    def as_dict(self) -> dict[str, str]:
        return {
            "runtime_ref": self.runtime_ref,
            "model_identity": self.model_identity,
            "ocr_identity": self.ocr_identity,
            "termbase_identity": self.termbase_identity,
            "engine_contract_version": self.engine_contract_version,
        }

    @classmethod
    def from_runtime_metadata(cls, runtime_metadata: Any, *, runtime_ref: str, ocr_identity: str, termbase_identity: str, environment_identity: RunEnvironmentIdentity | None = None) -> "RuntimeIdentity":
        """Project the existing runtime discovery into a safe job binding."""

        model_identity = getattr(runtime_metadata, "reported_model_id", None)
        if not isinstance(model_identity, str) or not model_identity:
            raise _invalid("PaaS submission cannot bind an undiscoverable model identity.", code=ErrorCode.MODEL_UNKNOWN)
        return cls(runtime_ref, model_identity, ocr_identity, termbase_identity, environment_identity=environment_identity)

    @classmethod
    def from_dict(cls, value: Any) -> "RuntimeIdentity":
        fields = {"runtime_ref", "model_identity", "ocr_identity", "termbase_identity", "engine_contract_version"}
        if not isinstance(value, dict) or set(value) not in (fields, fields | {"environment_identity"}):
            raise _invalid("PaaS runtime identity is incomplete.", code=ErrorCode.STATE_CORRUPT)
        try:
            raw = dict(value)
            if "environment_identity" in raw:
                raw["environment_identity"] = RunEnvironmentIdentity.from_dict(raw["environment_identity"])
            return cls(**raw)
        except (TypeError, ValueError) as exc:
            raise _invalid("PaaS runtime identity is invalid.", code=ErrorCode.STATE_CORRUPT) from exc


# The longer name makes deployment bindings self-documenting while retaining
# the compact public name for adapter implementations.
PinnedRuntimeIdentity = RuntimeIdentity


def _same_runtime_identity(left: RuntimeIdentity, right: RuntimeIdentity) -> bool:
    """Compare the legacy worker reference without duplicating the canonical binding."""

    return left.as_dict() == right.as_dict()


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
    scope_context: AuthorizedScopeContext | None = None
    authorization: AuthorizedScopeContext | None = None
    environment_identity: RunEnvironmentIdentity | None = None

    def __post_init__(self) -> None:
        _strict_identifier(self.run_id, "run ID")
        RunStoreRef(self.scope_ref, self.store_ref)
        if not isinstance(self.runtime_identity, RuntimeIdentity):
            raise _invalid("PaaS submission runtime identity is invalid.")
        derived_environment = self.runtime_identity.environment()
        if self.environment_identity is None:
            object.__setattr__(self, "environment_identity", derived_environment)
        elif not isinstance(self.environment_identity, RunEnvironmentIdentity):
            raise _invalid("PaaS submission environment identity is invalid.")
        elif self.environment_identity != derived_environment:
            raise KSlideError(
                ErrorCode.EXECUTION_ENVIRONMENT_MISMATCH,
                "PaaS submission environment identity does not match the runtime binding.",
                {"mismatch_code": "KSLIDE_RUN_ENVIRONMENT_MISMATCH", "mismatch_fields": list(environment_mismatch_fields(self.environment_identity, derived_environment))},
            )
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
        if self.scope_context is not None and not isinstance(self.scope_context, AuthorizedScopeContext):
            raise _invalid("PaaS submission authorization context is invalid.")
        if self.authorization is not None and not isinstance(self.authorization, AuthorizedScopeContext):
            raise _invalid("PaaS submission authorization context is invalid.")
        if self.scope_context is not None and self.authorization is not None and self.scope_context != self.authorization:
            raise _invalid("PaaS submission authorization contexts disagree.")


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
    references: ScopedArtifactReferences | None = None
    environment_identity: dict[str, str] | None = None
    environment_identity_sha256: str | None = None

    @classmethod
    def from_job(cls, job: ExecutionJob, *, references: ScopedArtifactReferences | None = None) -> "PaaSJobStatus":
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
            references,
            job.environment_identity.as_dict() if job.environment_identity is not None else None,
            job.environment_identity.identity_sha256 if job.environment_identity is not None else None,
        )

    def as_dict(self) -> dict[str, Any]:
        value = {
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
        if self.references is not None:
            value["references"] = self.references.as_dict()
        if self.environment_identity is not None:
            value["environment_identity"] = dict(self.environment_identity)
            value["environment_identity_sha256"] = self.environment_identity_sha256
        return value


@dataclass(frozen=True)
class PaaSSubmissionReceipt:
    status: StoreWriteStatus
    identity: DurableJobIdentity
    references: ScopedArtifactReferences | None = None

    @property
    def job_id(self) -> str:
        return self.identity.job_id

    def as_dict(self) -> dict[str, Any]:
        value = {"status": self.status.value, "identity": self.identity.as_dict()}
        if self.references is not None:
            value["references"] = self.references.as_dict()
        return value


@dataclass(frozen=True)
class WorkerClaim:
    identity: DurableJobIdentity
    job: ExecutionJob
    claim_ref: str
    references: ScopedArtifactReferences | None = None

    def as_dict(self) -> dict[str, Any]:
        value = {"claim_ref": self.claim_ref, "status": PaaSJobStatus.from_job(self.job, references=self.references).as_dict()}
        if self.references is not None:
            value["references"] = self.references.as_dict()
        return value


@dataclass(frozen=True)
class WorkerResult:
    status: str
    job: ExecutionJob
    engine_called: bool = False
    failure_class: FailureClass | None = None
    references: ScopedArtifactReferences | None = None

    def as_dict(self) -> dict[str, Any]:
        value = PaaSJobStatus.from_job(self.job, references=self.references).as_dict()
        value.update({"status": self.status, "engine_called": self.engine_called})
        if self.failure_class is not None:
            value["failure_class"] = self.failure_class.value
        return value


class QueueAdmissionState(str, Enum):
    ACTIVE = "ACTIVE"
    QUEUED = "QUEUED"
    TERMINAL = "TERMINAL"


@dataclass(frozen=True)
class PaaSQueueEntry:
    """Source-free queue visibility for one authorized scope."""

    sequence: int
    identity: DurableJobIdentity
    lifecycle: OperationalLifecycle
    admission_state: QueueAdmissionState
    references: ScopedArtifactReferences

    @property
    def active(self) -> bool:
        return self.admission_state is QueueAdmissionState.ACTIVE

    @property
    def job_id(self) -> str:
        return self.identity.job_id

    @property
    def run_id(self) -> str:
        return self.identity.run_id

    def as_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "identity": self.identity.as_dict(),
            "lifecycle": self.lifecycle.value,
            "admission_state": self.admission_state.value,
            "active": self.active,
            "references": self.references.as_dict(),
        }


@dataclass(frozen=True)
class PaaSQueueStatus:
    """Deterministic FIFO view of one user/workspace queue."""

    scope_context: AuthorizedScopeContext
    revision: int
    active_job_id: str | None
    entries: tuple[PaaSQueueEntry, ...]

    @property
    def queued(self) -> tuple[PaaSQueueEntry, ...]:
        return tuple(entry for entry in self.entries if entry.admission_state is QueueAdmissionState.QUEUED)

    @property
    def active(self) -> PaaSQueueEntry | None:
        return next((entry for entry in self.entries if entry.active), None)

    @property
    def active_heavy_job_id(self) -> str | None:
        return self.active_job_id

    @property
    def active_run_id(self) -> str | None:
        active = self.active
        return active.run_id if active is not None else None

    def as_dict(self) -> dict[str, Any]:
        return {
            "contract_version": SCOPED_PAAS_CONTRACT_VERSION,
            "scope": self.scope_context.as_dict(),
            "revision": self.revision,
            "active_job_id": self.active_job_id,
            "active_heavy_job_id": self.active_job_id,
            "active_run_id": self.active_run_id,
            "entries": [entry.as_dict() for entry in self.entries],
        }


class RunStoreResolver(Protocol):
    """Resolve an opaque store reference to the existing KSA-06 RunStore."""

    def open_store(self, identity: DurableJobIdentity, *, scope_context: AuthorizedScopeContext | None = None) -> RunStore: ...


class PaaSJobService(Protocol):
    """Narrow adapter contract for an approved durable job service.

    The service owns job dispatch/lifetime and durable identity.  It does not
    receive source content, prompts, results, or AccessKey material.  Scoped
    production calls must provide ``scope_context``; the optional form is kept
    only for the pre-KSA-09 KSA-08 reference contract.
    """

    def submit(self, job: ExecutionJob, *, runtime_identity: RuntimeIdentity, scope_context: AuthorizedScopeContext | None = None) -> PaaSSubmissionReceipt: ...

    def inspect(self, identity: DurableJobIdentity | str, *, scope_context: AuthorizedScopeContext | None = None) -> PaaSJobStatus: ...

    def request_cancellation(self, identity: DurableJobIdentity | str, *, scope_context: AuthorizedScopeContext | None = None) -> PaaSJobStatus: ...

    def claim(self, identity: DurableJobIdentity | str, *, worker_id: str, runtime_identity: RuntimeIdentity, scope_context: AuthorizedScopeContext | None = None) -> WorkerClaim: ...

    def claim_next(self, *, worker_id: str, runtime_identity: RuntimeIdentity, scope_context: AuthorizedScopeContext | None = None) -> WorkerClaim: ...

    def open_store(self, identity: DurableJobIdentity, *, scope_context: AuthorizedScopeContext | None = None) -> RunStore: ...

    def queue(self, *, scope_context: AuthorizedScopeContext) -> PaaSQueueStatus: ...

    def resolve_references(self, identity: DurableJobIdentity | str, *, scope_context: AuthorizedScopeContext) -> ScopedArtifactReferences: ...

    def resolve_store(self, identity: DurableJobIdentity | str, *, scope_context: AuthorizedScopeContext) -> RunStore: ...

    def resolve_result(self, identity: DurableJobIdentity | str, *, scope_context: AuthorizedScopeContext) -> str: ...

    def resolve_evidence(self, identity: DurableJobIdentity | str, *, scope_context: AuthorizedScopeContext) -> str: ...

    def content_layout(self, identity: DurableJobIdentity | str, *, scope_context: AuthorizedScopeContext) -> StorageLayout: ...

    def delete_run(self, identity: DurableJobIdentity | str, *, deletion_id: str, scope_context: AuthorizedScopeContext, hold_provider: Any | None = None, reason: Any = None, dry_run: bool = False) -> Any: ...


class ScopedPaaSJobService(Protocol):
    """Production-facing adapter boundary with explicit authorization.

    An approved deployment supplies the authorized context and implements
    these operations against company persistence/job services.  K-Slide does
    not define the company's storage API or authentication system.
    """

    def submit(self, job: ExecutionJob, *, runtime_identity: RuntimeIdentity, scope_context: AuthorizedScopeContext) -> PaaSSubmissionReceipt: ...

    def inspect(self, identity: DurableJobIdentity | str, *, scope_context: AuthorizedScopeContext) -> PaaSJobStatus: ...

    def request_cancellation(self, identity: DurableJobIdentity | str, *, scope_context: AuthorizedScopeContext) -> PaaSJobStatus: ...

    def claim(self, identity: DurableJobIdentity | str, *, worker_id: str, runtime_identity: RuntimeIdentity, scope_context: AuthorizedScopeContext) -> WorkerClaim: ...

    def claim_next(self, *, worker_id: str, runtime_identity: RuntimeIdentity, scope_context: AuthorizedScopeContext) -> WorkerClaim: ...

    def open_store(self, identity: DurableJobIdentity, *, scope_context: AuthorizedScopeContext) -> RunStore: ...

    def queue(self, *, scope_context: AuthorizedScopeContext) -> "PaaSQueueStatus": ...

    def resolve_references(self, identity: DurableJobIdentity | str, *, scope_context: AuthorizedScopeContext) -> ScopedArtifactReferences: ...

    def resolve_store(self, identity: DurableJobIdentity | str, *, scope_context: AuthorizedScopeContext) -> RunStore: ...

    def resolve_result(self, identity: DurableJobIdentity | str, *, scope_context: AuthorizedScopeContext) -> str: ...

    def resolve_evidence(self, identity: DurableJobIdentity | str, *, scope_context: AuthorizedScopeContext) -> str: ...

    def content_layout(self, identity: DurableJobIdentity | str, *, scope_context: AuthorizedScopeContext) -> StorageLayout: ...

    def delete_run(self, identity: DurableJobIdentity | str, *, deletion_id: str, scope_context: AuthorizedScopeContext, hold_provider: Any | None = None, reason: Any = None, dry_run: bool = False) -> Any: ...


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

    def __init__(self, backing_root: Path, *, auxiliary_root: Path | None = None) -> None:
        super().__init__(DurableTestRunStore(backing_root, auxiliary_root=auxiliary_root))


@dataclass(frozen=True)
class _ScopedQueueRecord:
    sequence: int
    identity: DurableJobIdentity
    references: ScopedArtifactReferences

    def as_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "identity": self.identity.as_dict(),
            "references": self.references.as_dict(),
        }


@dataclass(frozen=True)
class _ScopedControlState:
    """One scope's durable admission transaction record."""

    scope_context: AuthorizedScopeContext
    revision: int = 0
    next_sequence: int = 1
    active_job_id: str | None = None
    entries: tuple[_ScopedQueueRecord, ...] = ()
    schema_version: str = SCOPED_PAAS_CONTRACT_VERSION

    def without_hash(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "scope": self.scope_context.as_dict(),
            "revision": self.revision,
            "next_sequence": self.next_sequence,
            "active_job_id": self.active_job_id,
            "entries": [entry.as_dict() for entry in self.entries],
        }

    def as_dict(self) -> dict[str, Any]:
        value = self.without_hash()
        value["state_sha256"] = stable_revision(value)
        return value


def _validate_scoped_identity(identity: DurableJobIdentity) -> None:
    _safe_identity(identity.run_id, "durable run ID")
    _safe_identity(identity.job_id, "durable job ID")
    _safe_identity(identity.execution_id, "durable execution ID")
    _safe_identity(identity.scope_ref, "durable scope reference")
    _safe_identity(identity.store_ref, "durable store reference")


def _scoped_queue_record_from_dict(value: Any) -> _ScopedQueueRecord:
    if not isinstance(value, dict) or set(value) != {"sequence", "identity", "references"}:
        raise _invalid("Scoped queue entry is incomplete.", code=ErrorCode.STATE_CORRUPT)
    if not isinstance(value["sequence"], int) or value["sequence"] < 1:
        raise _invalid("Scoped queue entry sequence is invalid.", code=ErrorCode.STATE_CORRUPT)
    try:
        identity = DurableJobIdentity.from_dict(value["identity"])
        references = ScopedArtifactReferences.from_dict(value["references"])
        _validate_scoped_identity(identity)
        if references.scope_ref != identity.scope_ref or references.store_ref != identity.store_ref:
            raise _invalid("Scoped queue references do not match the job identity.", code=ErrorCode.STATE_CORRUPT)
        return _ScopedQueueRecord(value["sequence"], identity, references)
    except KSlideError:
        raise
    except (TypeError, ValueError) as exc:
        raise _invalid("Scoped queue entry is invalid.", code=ErrorCode.STATE_CORRUPT) from exc


def _scoped_control_from_dict(value: Any) -> _ScopedControlState:
    required = {"schema_version", "scope", "revision", "next_sequence", "active_job_id", "entries", "state_sha256"}
    if not isinstance(value, dict) or set(value) != required:
        raise _invalid("Scoped admission state is incomplete.", code=ErrorCode.STATE_CORRUPT)
    without_hash = dict(value)
    state_hash = without_hash.pop("state_sha256")
    if not isinstance(state_hash, str) or state_hash != stable_revision(without_hash):
        raise _invalid("Scoped admission state hash is inconsistent.", code=ErrorCode.STATE_CORRUPT)
    if value["schema_version"] != SCOPED_PAAS_CONTRACT_VERSION:
        raise _invalid("Unsupported scoped admission state version.", code=ErrorCode.EXECUTION_UNSUPPORTED_VERSION)
    if not isinstance(value["revision"], int) or value["revision"] < 0:
        raise _invalid("Scoped admission state revision is invalid.", code=ErrorCode.STATE_CORRUPT)
    if not isinstance(value["next_sequence"], int) or value["next_sequence"] < 1:
        raise _invalid("Scoped admission sequence is invalid.", code=ErrorCode.STATE_CORRUPT)
    try:
        context = AuthorizedScopeContext.from_dict(value["scope"])
        entries = tuple(_scoped_queue_record_from_dict(item) for item in value["entries"])
    except KSlideError:
        raise
    except (TypeError, ValueError) as exc:
        raise _invalid("Scoped admission state is invalid.", code=ErrorCode.STATE_CORRUPT) from exc
    sequences = [entry.sequence for entry in entries]
    job_ids = [entry.identity.job_id for entry in entries]
    if sequences != sorted(sequences) or len(sequences) != len(set(sequences)) or len(job_ids) != len(set(job_ids)):
        raise _invalid("Scoped admission state is not deterministic.", code=ErrorCode.STATE_CORRUPT)
    if any(entry.identity.scope_ref != context.scope_ref for entry in entries):
        raise _invalid("Scoped admission state contains a foreign scope.", code=ErrorCode.STATE_CORRUPT)
    active_job_id = value["active_job_id"]
    if active_job_id is not None:
        _strict_identifier(active_job_id, "active job ID")
        if active_job_id not in job_ids:
            raise _invalid("Scoped admission state points to an unknown active job.", code=ErrorCode.STATE_CORRUPT)
    if value["next_sequence"] <= max(sequences, default=0):
        raise _invalid("Scoped admission sequence is not monotonic.", code=ErrorCode.STATE_CORRUPT)
    return _ScopedControlState(context, value["revision"], value["next_sequence"], active_job_id, entries, value["schema_version"])


@dataclass(frozen=True)
class _ScopedJobRecord:
    identity: DurableJobIdentity
    runtime_identity: RuntimeIdentity
    environment_identity: RunEnvironmentIdentity
    submitted_at: str
    admission_sequence: int
    scope_context: AuthorizedScopeContext
    references: ScopedArtifactReferences
    submission_fingerprint: str | None = None
    schema_version: str = SCOPED_PAAS_CONTRACT_VERSION

    def as_dict(self) -> dict[str, Any]:
        value = {
            "schema_version": self.schema_version,
            "identity": self.identity.as_dict(),
            "runtime_identity": self.runtime_identity.as_dict(),
            "environment_identity": self.environment_identity.as_dict(),
            "submitted_at": self.submitted_at,
            "admission_sequence": self.admission_sequence,
            "scope": self.scope_context.as_dict(),
            "references": self.references.as_dict(),
        }
        if self.submission_fingerprint is not None:
            value["submission_fingerprint"] = self.submission_fingerprint
        value["record_sha256"] = stable_revision(value)
        return value


def _scoped_record_from_dict(value: Any) -> _ScopedJobRecord:
    required = {"schema_version", "identity", "runtime_identity", "environment_identity", "submitted_at", "admission_sequence", "scope", "references", "record_sha256"}
    if not isinstance(value, dict) or set(value) not in (required, required | {"submission_fingerprint"}):
        raise _invalid("Scoped PaaS job record is corrupt.", code=ErrorCode.STATE_CORRUPT)
    without_hash = dict(value)
    record_hash = without_hash.pop("record_sha256")
    if not isinstance(record_hash, str) or record_hash != stable_revision(without_hash):
        raise _invalid("Scoped PaaS job record hash is inconsistent.", code=ErrorCode.STATE_CORRUPT)
    if value["schema_version"] != SCOPED_PAAS_CONTRACT_VERSION:
        raise _invalid("Unsupported scoped PaaS job record version.", code=ErrorCode.EXECUTION_UNSUPPORTED_VERSION)
    if not isinstance(value["admission_sequence"], int) or value["admission_sequence"] < 1:
        raise _invalid("Scoped PaaS job admission sequence is invalid.", code=ErrorCode.STATE_CORRUPT)
    submission_fingerprint = value.get("submission_fingerprint")
    if submission_fingerprint is not None and (not isinstance(submission_fingerprint, str) or not re.fullmatch(r"[0-9a-f]{64}", submission_fingerprint)):
        raise _invalid("Scoped PaaS submission fingerprint is invalid.", code=ErrorCode.STATE_CORRUPT)
    try:
        identity = DurableJobIdentity.from_dict(value["identity"])
        runtime_identity = RuntimeIdentity.from_dict(value["runtime_identity"])
        environment_identity = RunEnvironmentIdentity.from_dict(value["environment_identity"])
        context = AuthorizedScopeContext.from_dict(value["scope"])
        references = ScopedArtifactReferences.from_dict(value["references"])
        _validate_scoped_identity(identity)
        if identity.scope_ref != context.scope_ref or references.scope_ref != context.scope_ref or references.store_ref != identity.store_ref:
            raise _invalid("Scoped PaaS job references do not match its authorized scope.", code=ErrorCode.STATE_CORRUPT)
        record = _ScopedJobRecord(
            identity,
            runtime_identity,
            environment_identity,
            value["submitted_at"],
            value["admission_sequence"],
            context,
            references,
            submission_fingerprint,
            value["schema_version"],
        )
    except KSlideError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise _invalid("Scoped PaaS job record is invalid.", code=ErrorCode.STATE_CORRUPT) from exc
    _timestamp(record.submitted_at, "scoped submission")
    return record


def _scoped_submission_fingerprint(job: ExecutionJob, runtime_identity: RuntimeIdentity) -> str:
    return stable_revision(
        {
            "identity": DurableJobIdentity.from_job(job).as_dict(),
            "runtime_identity": runtime_identity.as_dict(),
            "environment_identity": job.environment_identity.as_dict() if job.environment_identity is not None else runtime_identity.environment().as_dict(),
            "total_work_units": job.checkpoint.progress.total_work_units,
            "max_attempts": job.retry.max_attempts,
            "engine_state_revision": job.checkpoint.engine_state_revision,
        }
    )


class ScopedPaaSRunStore(PaaSRunStore):
    """Least-privilege KSA-06 store view bound to one authorized job."""

    def __init__(self, backend: RunStore, identity: DurableJobIdentity, on_terminal: Callable[[ExecutionJob], None] | None = None, mutation_guard: Callable[[], None] | None = None) -> None:
        super().__init__(backend)
        self._identity = identity
        self._on_terminal = on_terminal
        self._mutation_guard = mutation_guard

    def _guard(self) -> None:
        if self._mutation_guard is not None:
            self._mutation_guard()

    def _bound(self, job_id: str) -> None:
        if job_id != self._identity.job_id:
            raise KSlideError(ErrorCode.EXECUTION_CONFLICT, "Run-store access is outside the authorized job scope.", {"job_id": job_id})

    def _finish(self, result):
        if result.accepted and result.job.lifecycle in {OperationalLifecycle.COMPLETED, OperationalLifecycle.CANCELED, OperationalLifecycle.PROCESSING_FAILED} and self._on_terminal is not None:
            self._on_terminal(result.job)
        return result

    def create(self, job: ExecutionJob):
        self._bound(job.job_id)
        self._guard()
        return self._finish(self._backend.create(job))

    def load(self, job_id: str) -> ExecutionJob:
        self._bound(job_id)
        self._guard()
        job = self._backend.load(job_id)
        if DurableJobIdentity.from_job(job) != self._identity:
            raise KSlideError(ErrorCode.EXECUTION_CONFLICT, "Run-store identity does not match the authorized job scope.", {"job_id": job_id})
        return job

    def load_checkpoint(self, job_id: str) -> RunCheckpoint:
        return self.load(job_id).checkpoint

    def commit_job(self, job: ExecutionJob, *, expected_revision: int):
        self._bound(job.job_id)
        self._guard()
        return self._finish(self._backend.commit_job(job, expected_revision=expected_revision))

    def commit_checkpoint(self, checkpoint: RunCheckpoint, *, expected_revision: int):
        self._bound(checkpoint.job_id)
        self._guard()
        return self._finish(self._backend.commit_checkpoint(checkpoint, expected_revision=expected_revision))

    def commit_step(self, checkpoint: RunCheckpoint, marker: Any, *, expected_revision: int):
        self._bound(checkpoint.job_id)
        self._guard()
        return self._finish(self._backend.commit_step(checkpoint, marker, expected_revision=expected_revision))

    def request_cancellation(self, job_id: str, *, expected_revision: int | None = None):
        self._bound(job_id)
        self._guard()
        return self._finish(self._backend.request_cancellation(job_id, expected_revision=expected_revision))

    def acknowledge_cancellation(self, job_id: str, *, expected_revision: int, safe_boundary: bool):
        self._bound(job_id)
        self._guard()
        return self._finish(self._backend.acknowledge_cancellation(job_id, expected_revision=expected_revision, safe_boundary=safe_boundary))

    def transition_operational(self, job_id: str, *, expected_revision: int, lifecycle: OperationalLifecycle, terminal_outcome: TerminalOutcome = TerminalOutcome.NONE, resume_eligibility: ResumeEligibility | None = None):
        self._bound(job_id)
        self._guard()
        return self._finish(self._backend.transition_operational(job_id, expected_revision=expected_revision, lifecycle=lifecycle, terminal_outcome=terminal_outcome, resume_eligibility=resume_eligibility))

    def record_retry(self, job_id: str, *, expected_revision: int, error_code: str):
        self._bound(job_id)
        self._guard()
        return self._finish(self._backend.record_retry(job_id, expected_revision=expected_revision, error_code=error_code))

    def commit_result(self, job_id: str, marker: Any, *, expected_revision: int):
        self._bound(job_id)
        self._guard()
        return self._finish(self._backend.commit_result(job_id, marker, expected_revision=expected_revision))


@dataclass(frozen=True)
class _PaaSJobRecord:
    identity: DurableJobIdentity
    runtime_identity: RuntimeIdentity
    environment_identity: RunEnvironmentIdentity
    submitted_at: str
    schema_version: str = PAAS_CONTRACT_VERSION

    def as_dict(self) -> dict[str, Any]:
        value = {
            "schema_version": self.schema_version,
            "identity": self.identity.as_dict(),
            "runtime_identity": self.runtime_identity.as_dict(),
            "environment_identity": self.environment_identity.as_dict(),
            "submitted_at": self.submitted_at,
        }
        value["record_sha256"] = stable_revision(value)
        return value


def _record_from_dict(value: Any) -> _PaaSJobRecord:
    required = {"schema_version", "identity", "runtime_identity", "environment_identity", "submitted_at", "record_sha256"}
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
        RunEnvironmentIdentity.from_dict(value["environment_identity"]),
        value["submitted_at"],
    )
    _timestamp(record.submitted_at, "submission")
    return record


class ReferencePaaSJobService(RunStoreResolver):
    """Filesystem job-service adapter used for deterministic integration.

    It deliberately has no lease timeout: a new worker may reattach to an
    active job after a worker/controller process disappears.  Concurrent work
    remains protected by the underlying RunStore CAS contract.  Calls carrying
    ``AuthorizedScopeContext`` use the KSA-09 scoped admission backend; calls
    without it retain the KSA-08 compatibility layout.
    """

    def __init__(self, service_root: Path, *, admission_policy: ScopedAdmissionPolicy | None = None, scope_context: AuthorizedScopeContext | None = None, authorization: AuthorizedScopeContext | None = None) -> None:
        if scope_context is not None and authorization is not None and scope_context != authorization:
            raise _invalid("PaaS service authorization contexts disagree.")
        if scope_context is not None and not isinstance(scope_context, AuthorizedScopeContext):
            raise _invalid("PaaS service authorization context is invalid.")
        if authorization is not None and not isinstance(authorization, AuthorizedScopeContext):
            raise _invalid("PaaS service authorization context is invalid.")
        raw_root = Path(service_root).expanduser()
        if raw_root.exists() and raw_root.is_symlink():
            raise _invalid("PaaS service root may not be a symbolic link.", code=ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT)
        self.root = raw_root.resolve()
        self._storage = StorageLayout.for_service(self.root)
        self._records_root = self._storage.durable_root / "jobs"
        self._store = ReferencePaaSRunStore(self._storage.durable_root / "run-store", auxiliary_root=self.root)
        self._scopes_root = self._storage.durable_root / "scopes"
        self.admission_policy = admission_policy or ScopedAdmissionPolicy()
        self.scope_context = scope_context or authorization

    def _record_path(self, job_id: str) -> Path:
        _strict_identifier(job_id, "job ID")
        return self._storage.path(StorageArtifact.ADMISSION_RECORD, f"jobs/{job_id}.json")

    def _record_lock(self, job_id: str):
        lock_path = self._storage.path(StorageArtifact.COORDINATION_LOCK, f"locks/{job_id}.lock", create_parent=True)
        return filesystem_lock(lock_path, require_shared=True, reject_symlink=True)

    @staticmethod
    def _authorized_context(scope_context: AuthorizedScopeContext | None, scope_ref: str) -> AuthorizedScopeContext | None:
        if scope_context is None:
            return None
        if not isinstance(scope_context, AuthorizedScopeContext):
            raise _invalid("PaaS authorization context is invalid.")
        if scope_context.scope_ref != scope_ref:
            raise KSlideError(ErrorCode.EXECUTION_CONFLICT, "Authorized scope context does not match the requested job scope.")
        return scope_context

    @staticmethod
    def _validate_scoped_job(job: ExecutionJob) -> None:
        if job.profile is not ExecutionProfile.DURABLE:
            raise _invalid("PaaS service accepts only the durable execution profile.")
        _validate_scoped_identity(DurableJobIdentity.from_job(job))
        # This is intentionally a rejection check over the source-free KSA-06
        # record.  It prevents future fields from accidentally carrying source
        # text, prompts, or process-only secret material into this boundary.
        serialized = job.as_dict()
        # The KSA-10 environment contract deliberately contains the
        # source-revision *identity*; it is not source content. Validate the
        # rest of the operational record with the pre-existing denylist.
        serialized.pop("environment_identity", None)
        if any(word in str(serialized).lower() for word in _FORBIDDEN):
            raise _invalid("Durable PaaS control state contains forbidden material.")

    @staticmethod
    def _scope_key(scope_context: AuthorizedScopeContext) -> str:
        return stable_revision({"user_ref": scope_context.user_ref, "workspace_ref": scope_context.workspace_ref, "scope_ref": scope_context.scope_ref})[:40]

    def _scope_root(self, scope_context: AuthorizedScopeContext) -> Path:
        return self._scopes_root / self._scope_key(scope_context)

    def _scope_record_path(self, scope_context: AuthorizedScopeContext, job_id: str) -> Path:
        _strict_identifier(job_id, "job ID")
        layout = StorageLayout.for_scoped_reference(service_root=self.root, durable_root=self._scope_root(scope_context), scope_ref=str(scope_context.scope_ref), run_ref=job_id)
        return layout.path(StorageArtifact.ADMISSION_RECORD, f"jobs/{job_id}.json")

    def _scope_lock(self, scope_context: AuthorizedScopeContext):
        layout = StorageLayout.for_scoped_reference(service_root=self.root, durable_root=self._scope_root(scope_context), scope_ref=str(scope_context.scope_ref), run_ref="scope-lock")
        return filesystem_lock(layout.path(StorageArtifact.COORDINATION_LOCK, "scope.lock", create_parent=True), require_shared=True, reject_symlink=True)

    def _scope_control_path(self, scope_context: AuthorizedScopeContext) -> Path:
        layout = StorageLayout.for_scoped_reference(service_root=self.root, durable_root=self._scope_root(scope_context), scope_ref=str(scope_context.scope_ref), run_ref="admission")
        return layout.path(StorageArtifact.ADMISSION_CONTROL, "admission/CONTROL_STATE.json")

    def _scope_queue_path(self, scope_context: AuthorizedScopeContext) -> Path:
        layout = StorageLayout.for_scoped_reference(service_root=self.root, durable_root=self._scope_root(scope_context), scope_ref=str(scope_context.scope_ref), run_ref="admission")
        return layout.path(StorageArtifact.ADMISSION_QUEUE, "admission/QUEUE.json")

    def _central_operational_root(self) -> Path:
        return self._storage.root_for(StoragePlane.CENTRAL_NON_CONTENT_OPERATIONAL_TELEMETRY)

    def _scoped_deletion_root(self, scope_context: AuthorizedScopeContext) -> Path:
        return self._central_operational_root() / "_deletions" / self._scope_key(scope_context)

    def _deletion_fenced(self, scope_context: AuthorizedScopeContext, run_ref: str) -> None:
        """Reject new claims/resume/result mutations after KSA-13 starts."""

        audit_root = self._scoped_deletion_root(scope_context)
        if audit_root.is_symlink():
            raise KSlideError(ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT, "Scoped deletion audit root is a symbolic link.")
        if not audit_root.is_dir():
            return
        from .deletion import DeletionAudit

        for path in audit_root.rglob("*.json"):
            if path.is_symlink():
                raise KSlideError(ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT, "Scoped deletion audit record is a symbolic link.")
            try:
                audit = DeletionAudit.from_dict(read_json(path))
            except KSlideError as exc:
                raise KSlideError(ErrorCode.STATE_CORRUPT, "Deletion control state is corrupt or unreadable.") from exc
            except (OSError, TypeError, ValueError) as exc:
                raise KSlideError(ErrorCode.STATE_CORRUPT, "Deletion control state is corrupt or unreadable.") from exc
            if audit.scope_ref == scope_context.scope_ref and audit.run_ref == run_ref and audit.state.value in {"IN_PROGRESS", "PARTIAL"}:
                raise KSlideError(ErrorCode.EXECUTION_CONFLICT, "Durable execution is fenced by an active deletion lifecycle.")

    def _scoped_store(self, scope_context: AuthorizedScopeContext) -> ReferencePaaSRunStore:
        return ReferencePaaSRunStore(self._scope_root(scope_context) / "run-store", auxiliary_root=self.root)

    def _scoped_references(self, identity: DurableJobIdentity, scope_context: AuthorizedScopeContext) -> ScopedArtifactReferences:
        scope_key = self._scope_key(scope_context)
        prefix = f"scoped/{scope_key}/jobs/{identity.job_id}"
        return ScopedArtifactReferences(
            identity.scope_ref,
            identity.store_ref,
            f"{prefix}/run/{identity.run_id}",
            f"{prefix}/result",
            f"{prefix}/evidence",
        )

    def _read_scoped_record(self, scope_context: AuthorizedScopeContext, job_id: str) -> _ScopedJobRecord:
        path = self._scope_record_path(scope_context, job_id)
        if not path.is_file():
            raise KSlideError(ErrorCode.EXECUTION_NOT_FOUND, "Durable PaaS job does not exist.", {"job_id": job_id})
        try:
            record = _scoped_record_from_dict(read_json(path))
            if record.identity.job_id != job_id:
                raise _invalid("Scoped durable PaaS job record identity does not match its path.", code=ErrorCode.STATE_CORRUPT)
            return record
        except KSlideError as exc:
            if exc.code is ErrorCode.EXECUTION_UNSUPPORTED_VERSION:
                raise
            raise KSlideError(ErrorCode.STATE_CORRUPT, "Scoped durable PaaS job record is corrupt or unreadable.", {"job_id": job_id}) from exc
        except (OSError, TypeError, ValueError) as exc:
            raise KSlideError(ErrorCode.STATE_CORRUPT, "Scoped durable PaaS job record is corrupt or unreadable.", {"job_id": job_id}) from exc

    def _read_scoped_state_file(self, path: Path) -> _ScopedControlState:
        try:
            return _scoped_control_from_dict(read_json(path))
        except KSlideError:
            raise
        except (OSError, TypeError, ValueError) as exc:
            raise KSlideError(ErrorCode.STATE_CORRUPT, "Scoped admission state is corrupt or unreadable.", {"path": path.name}) from exc

    def _read_scoped_records(self, scope_context: AuthorizedScopeContext) -> dict[str, _ScopedJobRecord]:
        records: dict[str, _ScopedJobRecord] = {}
        jobs_root = self._scope_root(scope_context) / "jobs"
        if jobs_root.is_dir():
            for path in sorted(jobs_root.glob("*.json")):
                record = self._read_scoped_record(scope_context, path.stem)
                if record.scope_context != scope_context:
                    raise KSlideError(ErrorCode.STATE_CORRUPT, "Scoped job record belongs to a different authorized scope.")
                if record.identity.job_id in records:
                    raise KSlideError(ErrorCode.STATE_CORRUPT, "Scoped admission records contain a duplicate job identity.")
                records[record.identity.job_id] = record

        store_jobs_root = self._scope_root(scope_context) / "run-store" / "jobs"
        if store_jobs_root.is_dir():
            for path in sorted(store_jobs_root.glob("*.json")):
                if path.stem not in records:
                    raise KSlideError(ErrorCode.STATE_CORRUPT, "Scoped run-store job has no matching admission record.")

        sequences = [record.admission_sequence for record in records.values()]
        if len(sequences) != len(set(sequences)):
            raise KSlideError(ErrorCode.STATE_CORRUPT, "Scoped admission records do not own unique sequences.")
        return records

    def _recover_scoped_state(self, scope_context: AuthorizedScopeContext) -> _ScopedControlState:
        records = self._read_scoped_records(scope_context)
        entries = tuple(
            sorted(
                (_ScopedQueueRecord(record.admission_sequence, record.identity, record.references) for record in records.values()),
                key=lambda item: (item.sequence, item.identity.job_id),
            )
        )
        return _ScopedControlState(
            scope_context=scope_context,
            entries=entries,
            next_sequence=max((item.sequence for item in entries), default=0) + 1,
        )

    def _load_scoped_state(self, scope_context: AuthorizedScopeContext) -> _ScopedControlState:
        control_path = self._scope_control_path(scope_context)
        queue_path = self._scope_queue_path(scope_context)
        if not control_path.is_file() and not queue_path.is_file():
            return self._recover_scoped_state(scope_context)
        path = control_path if control_path.is_file() else queue_path
        state = self._read_scoped_state_file(path)
        if state.scope_context != scope_context:
            raise KSlideError(ErrorCode.EXECUTION_CONFLICT, "Durable admission state is outside the authorized scope.")
        if control_path.is_file() and queue_path.is_file():
            queue_state = self._read_scoped_state_file(queue_path)
            if queue_state.scope_context != scope_context:
                raise KSlideError(ErrorCode.EXECUTION_CONFLICT, "Durable queue state is outside the authorized scope.")
            if queue_state.as_dict() != state.as_dict():
                # `_persist_scoped_state` writes CONTROL_STATE before QUEUE.
                # A restart between those two atomic replacements therefore
                # deterministically keeps the higher revision and repairs the
                # lagging mirror on the next locked operation.
                if queue_state.revision == state.revision:
                    raise KSlideError(ErrorCode.STATE_CORRUPT, "Scoped control and queue records disagree.")
                state = queue_state if queue_state.revision > state.revision else state
        return state

    def _persist_scoped_state(self, state: _ScopedControlState) -> None:
        value = state.as_dict()
        atomic_write_json(self._scope_control_path(state.scope_context), value, mode=0o600)
        atomic_write_json(self._scope_queue_path(state.scope_context), value, mode=0o600)

    def _persist_scoped_state_if_needed(self, state: _ScopedControlState, raw_state: _ScopedControlState) -> None:
        mirrors_match = False
        try:
            mirrors_match = read_json(self._scope_control_path(state.scope_context)) == read_json(self._scope_queue_path(state.scope_context))
        except KSlideError:
            pass
        if state.as_dict() != raw_state.as_dict() or not mirrors_match:
            self._persist_scoped_state(state)

    @staticmethod
    def _terminal_for_admission(job: ExecutionJob) -> bool:
        return job.lifecycle in {OperationalLifecycle.CANCELED, OperationalLifecycle.PROCESSING_FAILED, OperationalLifecycle.COMPLETED}

    def _normalize_scoped_state(self, state: _ScopedControlState) -> _ScopedControlState:
        store = self._scoped_store(state.scope_context)
        records = self._read_scoped_records(state.scope_context)
        entries_by_job_id: dict[str, _ScopedQueueRecord] = {}
        for entry in state.entries:
            record = records.get(entry.identity.job_id)
            if record is None:
                raise KSlideError(ErrorCode.STATE_CORRUPT, "Scoped queue entry has no matching admission record.")
            if record.identity != entry.identity or record.references != entry.references:
                raise KSlideError(ErrorCode.STATE_CORRUPT, "Scoped queue entry does not match its durable job record.")
            if entry.identity.job_id in entries_by_job_id:
                raise KSlideError(ErrorCode.STATE_CORRUPT, "Scoped queue contains a duplicate job identity.")
            entries_by_job_id[entry.identity.job_id] = entry

        for job_id, record in records.items():
            entry = _ScopedQueueRecord(record.admission_sequence, record.identity, record.references)
            existing = entries_by_job_id.get(job_id)
            if existing is not None:
                if existing != entry:
                    raise KSlideError(ErrorCode.STATE_CORRUPT, "Scoped admission record disagrees with its queue entry.")
                continue
            entries_by_job_id[job_id] = entry

        valid_entries = sorted(entries_by_job_id.values(), key=lambda item: (item.sequence, item.identity.job_id))
        sequences = [entry.sequence for entry in valid_entries]
        if len(sequences) != len(set(sequences)):
            raise KSlideError(ErrorCode.STATE_CORRUPT, "Scoped queue entries do not own unique sequences.")

        jobs: dict[str, ExecutionJob | None] = {}
        for entry in valid_entries:
            try:
                job = store.load(entry.identity.job_id)
            except KSlideError as exc:
                if exc.code is not ErrorCode.EXECUTION_NOT_FOUND:
                    raise
                # The admission record owns the sequence while a retry
                # reconciles a crash between record and KSA-06 store create.
                job = None
            if job is not None:
                self._check_scoped_job(job, entry.identity, records[entry.identity.job_id])
            jobs[entry.identity.job_id] = job

        desired_active: str | None = None
        blocked_by_pending_store = False
        for entry in valid_entries:
            job = jobs[entry.identity.job_id]
            if job is None:
                blocked_by_pending_store = True
                continue
            if blocked_by_pending_store:
                continue
            if desired_active is None and not self._terminal_for_admission(job):
                desired_active = entry.identity.job_id

        next_sequence = max(state.next_sequence, max(sequences, default=0) + 1)
        normalized_entries = tuple(valid_entries)
        if normalized_entries == state.entries and desired_active == state.active_job_id and next_sequence == state.next_sequence:
            return state
        return replace(state, revision=state.revision + 1, active_job_id=desired_active, entries=normalized_entries, next_sequence=next_sequence)

    def _resolve_scoped_identity(self, identity: DurableJobIdentity | str, scope_context: AuthorizedScopeContext) -> tuple[DurableJobIdentity, _ScopedJobRecord]:
        if isinstance(identity, DurableJobIdentity):
            _validate_scoped_identity(identity)
            if identity.scope_ref != scope_context.scope_ref:
                raise KSlideError(ErrorCode.EXECUTION_CONFLICT, "Authorized scope context does not match the requested job scope.")
            record = self._read_scoped_record(scope_context, identity.job_id)
            if record.identity != identity:
                raise KSlideError(ErrorCode.EXECUTION_CONFLICT, "Durable job identity does not match the authorized scope record.")
            return identity, record
        if not isinstance(identity, str):
            raise _invalid("Durable job identity is invalid.")
        record = self._read_scoped_record(scope_context, identity)
        return record.identity, record

    def _check_scoped_job(self, job: ExecutionJob, identity: DurableJobIdentity, record: _ScopedJobRecord) -> None:
        self._validate_scoped_job(job)
        if DurableJobIdentity.from_job(job) != identity or record.identity != identity or record.scope_context.scope_ref != identity.scope_ref:
            raise KSlideError(ErrorCode.EXECUTION_CONFLICT, "Durable job identity does not match the authorized scope record.")
        if job.environment_identity != record.environment_identity:
            raise KSlideError(
                ErrorCode.EXECUTION_ENVIRONMENT_MISMATCH,
                "Durable job environment identity does not match the scope record.",
                {"mismatch_code": "KSLIDE_RUN_ENVIRONMENT_MISMATCH", "mismatch_fields": ["run_environment_identity"]},
            )

    @staticmethod
    def _same_scoped_submission(existing: ExecutionJob, candidate: ExecutionJob, existing_record: _ScopedJobRecord, runtime_identity: RuntimeIdentity) -> bool:
        return (
            ReferencePaaSJobService._same_submission(existing, candidate)
            and _same_runtime_identity(existing_record.runtime_identity, runtime_identity)
            and existing_record.environment_identity == runtime_identity.environment()
            and (existing_record.submission_fingerprint is None or existing_record.submission_fingerprint == _scoped_submission_fingerprint(candidate, runtime_identity))
        )

    @staticmethod
    def _same_scoped_admission(record: _ScopedJobRecord, candidate: ExecutionJob, runtime_identity: RuntimeIdentity) -> bool:
        # A record-only crash window must be reconciled against the immutable
        # source-free submission fingerprint; a legacy record without one
        # cannot safely be interpreted as a new payload.
        return record.environment_identity == runtime_identity.environment() and record.submission_fingerprint is not None and record.submission_fingerprint == _scoped_submission_fingerprint(candidate, runtime_identity)

    def _scoped_status(self, identity: DurableJobIdentity, job: ExecutionJob, references: ScopedArtifactReferences) -> PaaSJobStatus:
        return PaaSJobStatus.from_job(job, references=references)

    def _release_scoped_slot(self, job: ExecutionJob, scope_context: AuthorizedScopeContext) -> None:
        with self._scope_lock(scope_context):
            raw_state = self._load_scoped_state(scope_context)
            state = self._normalize_scoped_state(raw_state)
            if state.active_job_id != job.job_id:
                self._persist_scoped_state_if_needed(state, raw_state)
                return
            next_active: str | None = None
            for entry in state.entries:
                if entry.identity.job_id == job.job_id:
                    continue
                candidate = self._scoped_store(scope_context).load(entry.identity.job_id)
                if not self._terminal_for_admission(candidate):
                    next_active = entry.identity.job_id
                    break
            released = replace(state, revision=state.revision + 1, active_job_id=next_active)
            self._persist_scoped_state(released)

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
            and existing.environment_identity == candidate.environment_identity
        )

    @staticmethod
    def _bind_environment(job: ExecutionJob, runtime_identity: RuntimeIdentity) -> tuple[ExecutionJob, RunEnvironmentIdentity]:
        if not isinstance(runtime_identity, RuntimeIdentity):
            raise _invalid("PaaS submission runtime identity is invalid.")
        environment = runtime_identity.environment()
        if job.environment_identity is None:
            return replace(job, environment_identity=environment), environment
        if job.environment_identity != environment:
            raise KSlideError(
                ErrorCode.EXECUTION_ENVIRONMENT_MISMATCH,
                "PaaS submission environment identity does not match the runtime binding.",
                {"mismatch_code": "KSLIDE_RUN_ENVIRONMENT_MISMATCH", "mismatch_fields": list(environment_mismatch_fields(job.environment_identity, environment))},
            )
        return job, environment

    def submit(self, job: ExecutionJob, *, runtime_identity: RuntimeIdentity, scope_context: AuthorizedScopeContext | None = None) -> PaaSSubmissionReceipt:
        job, environment_identity = self._bind_environment(job, runtime_identity)
        scope_context = scope_context or self.scope_context
        if scope_context is not None:
            return self._submit_scoped(job, runtime_identity=runtime_identity, scope_context=scope_context)
        if job.profile is not ExecutionProfile.DURABLE:
            raise _invalid("PaaS service accepts only the durable execution profile.")
        identity = DurableJobIdentity.from_job(job)
        path = self._record_path(identity.job_id)
        with self._record_lock(identity.job_id):
            if path.is_file():
                record = self._read_record(identity.job_id)
                if record.identity != identity or not _same_runtime_identity(record.runtime_identity, runtime_identity) or record.environment_identity != environment_identity:
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
            record = _PaaSJobRecord(identity, runtime_identity, environment_identity, now_utc())
            atomic_write_json(path, record.as_dict(), mode=0o600)
            return PaaSSubmissionReceipt(StoreWriteStatus.IDEMPOTENT if stored.status is StoreWriteStatus.CONFLICT else stored.status, identity)

    def _submit_scoped(self, job: ExecutionJob, *, runtime_identity: RuntimeIdentity, scope_context: AuthorizedScopeContext) -> PaaSSubmissionReceipt:
        if not isinstance(scope_context, AuthorizedScopeContext):
            raise _invalid("PaaS authorization context is invalid.")
        self._authorized_context(scope_context, job.store_ref.scope_ref)
        job, environment_identity = self._bind_environment(job, runtime_identity)
        self._validate_scoped_job(job)
        identity = DurableJobIdentity.from_job(job)
        references = self._scoped_references(identity, scope_context)
        self._deletion_fenced(scope_context, identity.run_id)
        with self._scope_lock(scope_context):
            raw_state = self._load_scoped_state(scope_context)
            state = self._normalize_scoped_state(raw_state)
            self._persist_scoped_state_if_needed(state, raw_state)
            path = self._scope_record_path(scope_context, identity.job_id)
            backend = self._scoped_store(scope_context)
            if path.is_file():
                record = self._read_scoped_record(scope_context, identity.job_id)
                try:
                    existing = backend.load(identity.job_id)
                except KSlideError as exc:
                    if exc.code is not ErrorCode.EXECUTION_NOT_FOUND:
                        raise
                    if record.identity != identity or not self._same_scoped_admission(record, job, runtime_identity):
                        return PaaSSubmissionReceipt(StoreWriteStatus.CONFLICT, record.identity, record.references)
                    stored = backend.create(job)
                    if stored.status is StoreWriteStatus.CONFLICT:
                        return PaaSSubmissionReceipt(StoreWriteStatus.CONFLICT, record.identity, record.references)
                    entry = _ScopedQueueRecord(record.admission_sequence, identity, record.references)
                    entries = tuple(item for item in state.entries if item.identity.job_id != identity.job_id)
                    reconciled = self._normalize_scoped_state(
                        replace(
                            state,
                            entries=tuple((*entries, entry)),
                            next_sequence=max(state.next_sequence, record.admission_sequence + 1),
                        )
                    )
                    if reconciled.as_dict() != state.as_dict():
                        self._persist_scoped_state(reconciled)
                    return PaaSSubmissionReceipt(StoreWriteStatus.ACCEPTED, identity, references)
                self._check_scoped_job(existing, record.identity, record)
                if not self._same_scoped_submission(existing, job, record, runtime_identity):
                    return PaaSSubmissionReceipt(StoreWriteStatus.CONFLICT, record.identity, record.references)
                return PaaSSubmissionReceipt(StoreWriteStatus.IDEMPOTENT, record.identity, record.references)
            sequence = state.next_sequence
            record = _ScopedJobRecord(
                identity,
                runtime_identity,
                environment_identity,
                now_utc(),
                sequence,
                scope_context,
                references,
                _scoped_submission_fingerprint(job, runtime_identity),
            )
            try:
                orphaned = backend.load(identity.job_id)
            except KSlideError as exc:
                if exc.code is not ErrorCode.EXECUTION_NOT_FOUND:
                    raise
                orphaned = None
            if orphaned is not None:
                # A store file without its admission record can only be an
                # interrupted prior transaction.  Do not overwrite it with a
                # different submission; recovery/repair must remain explicit.
                return PaaSSubmissionReceipt(StoreWriteStatus.CONFLICT, identity, references)
            # The source-free record owns the sequence before the KSA-06 store
            # create. Recovery therefore retains this reservation if a
            # process stops in the interleaving between these two writes.
            atomic_write_json(path, record.as_dict(), mode=0o600)
            stored = backend.create(job)
            if stored.status is StoreWriteStatus.CONFLICT:
                existing = backend.load(identity.job_id)
                existing_record = self._read_scoped_record(scope_context, identity.job_id)
                if self._same_scoped_submission(existing, job, existing_record, runtime_identity):
                    return PaaSSubmissionReceipt(StoreWriteStatus.IDEMPOTENT, existing_record.identity, existing_record.references)
                return PaaSSubmissionReceipt(StoreWriteStatus.CONFLICT, existing_record.identity, existing_record.references)
            entry = _ScopedQueueRecord(sequence, identity, references)
            next_state = self._normalize_scoped_state(
                replace(
                    state,
                    next_sequence=sequence + 1,
                    entries=tuple((*state.entries, entry)),
                )
            )
            self._persist_scoped_state(next_state)
            return PaaSSubmissionReceipt(stored.status, identity, references)

    def open_store(self, identity: DurableJobIdentity, *, scope_context: AuthorizedScopeContext | None = None) -> RunStore:
        scope_context = scope_context or self.scope_context
        if scope_context is not None:
            return self._open_scoped_store(identity, scope_context)
        self._identity(identity)
        return self._store

    def _open_scoped_store(self, identity: DurableJobIdentity | str, scope_context: AuthorizedScopeContext) -> ScopedPaaSRunStore:
        resolved, record = self._resolve_scoped_identity(identity, scope_context)
        backend = self._scoped_store(scope_context)
        job = backend.load(resolved.job_id)
        self._check_scoped_job(job, resolved, record)
        return ScopedPaaSRunStore(
            backend,
            resolved,
            on_terminal=lambda terminal: self._release_scoped_slot(terminal, scope_context),
            mutation_guard=lambda: self._deletion_fenced(scope_context, resolved.run_id),
        )

    def inspect(self, identity: DurableJobIdentity | str, *, scope_context: AuthorizedScopeContext | None = None) -> PaaSJobStatus:
        scope_context = scope_context or self.scope_context
        if scope_context is not None:
            resolved, record = self._resolve_scoped_identity(identity, scope_context)
            job = self._scoped_store(scope_context).load(resolved.job_id)
            self._check_scoped_job(job, resolved, record)
            return self._scoped_status(resolved, job, record.references)
        resolved = self._identity(identity)
        job = self._store.load(resolved.job_id)
        self._check_job_identity(job, resolved)
        return PaaSJobStatus.from_job(job)

    def request_cancellation(self, identity: DurableJobIdentity | str, *, scope_context: AuthorizedScopeContext | None = None) -> PaaSJobStatus:
        scope_context = scope_context or self.scope_context
        if scope_context is not None:
            return self._request_cancellation_scoped(identity, scope_context)
        resolved = self._identity(identity)
        with self._record_lock(resolved.job_id):
            current = self._store.load(resolved.job_id)
            self._check_job_identity(current, resolved)
            self._store.request_cancellation(resolved.job_id)
        return self.inspect(resolved)

    def _request_cancellation_scoped(self, identity: DurableJobIdentity | str, scope_context: AuthorizedScopeContext) -> PaaSJobStatus:
        with self._scope_lock(scope_context):
            resolved, record = self._resolve_scoped_identity(identity, scope_context)
            self._deletion_fenced(scope_context, resolved.run_id)
            store = self._scoped_store(scope_context)
            current = store.load(resolved.job_id)
            self._check_scoped_job(current, resolved, record)
            requested = store.request_cancellation(resolved.job_id)
            if requested.accepted and requested.job.lifecycle is OperationalLifecycle.QUEUED:
                state = self._normalize_scoped_state(self._load_scoped_state(scope_context))
                # A queued overflow has not acquired the heavy slot.  It can
                # be acknowledged at the controller boundary and removed from
                # admission without requiring a worker to claim it.
                if state.active_job_id != resolved.job_id and not requested.job.cancellation.acknowledged:
                    acknowledged = store.acknowledge_cancellation(resolved.job_id, expected_revision=requested.job.revision, safe_boundary=True)
                    if acknowledged.accepted:
                        requested = acknowledged
            if requested.accepted and requested.job.lifecycle in {OperationalLifecycle.CANCELED, OperationalLifecycle.PROCESSING_FAILED, OperationalLifecycle.COMPLETED}:
                # The terminal callback is not attached to this unbound store.
                # Release is performed while the scope lock is held, once.
                normalized = self._normalize_scoped_state(self._load_scoped_state(scope_context))
                if normalized.active_job_id == resolved.job_id:
                    next_active = None
                    for entry in normalized.entries:
                        if entry.identity.job_id == resolved.job_id:
                            continue
                        candidate = store.load(entry.identity.job_id)
                        if not self._terminal_for_admission(candidate):
                            next_active = entry.identity.job_id
                            break
                    self._persist_scoped_state(replace(normalized, revision=normalized.revision + 1, active_job_id=next_active))
                else:
                    raw = self._load_scoped_state(scope_context)
                    if normalized.as_dict() != raw.as_dict():
                        self._persist_scoped_state(normalized)
            return self._scoped_status(resolved, requested.job, record.references)

    def claim(self, identity: DurableJobIdentity | str, *, worker_id: str, runtime_identity: RuntimeIdentity, scope_context: AuthorizedScopeContext | None = None) -> WorkerClaim:
        if not isinstance(runtime_identity, RuntimeIdentity):
            raise _invalid("Worker runtime identity is invalid.")
        runtime_identity.environment()
        scope_context = scope_context or self.scope_context
        if scope_context is not None:
            return self._claim_scoped(identity, worker_id=worker_id, runtime_identity=runtime_identity, scope_context=scope_context)
        worker_id = _strict_identifier(worker_id, "worker ID")
        resolved = self._identity(identity)
        record = self._read_record(resolved.job_id)
        if record.runtime_identity.environment_identity is None and runtime_identity.environment_identity is None:
            if not _same_runtime_identity(record.runtime_identity, runtime_identity):
                raise KSlideError(ErrorCode.EXECUTION_CONFLICT, "Worker runtime identity does not match the durable job binding.", {"job_id": resolved.job_id})
        else:
            raise_environment_mismatch(record.environment_identity, runtime_identity.environment())
        if not _same_runtime_identity(record.runtime_identity, runtime_identity):
            raise KSlideError(ErrorCode.EXECUTION_CONFLICT, "Worker runtime identity does not match the durable job binding.", {"job_id": resolved.job_id})
        job = self._store.load(resolved.job_id)
        self._check_job_identity(job, resolved)
        raise_environment_mismatch(job.environment_identity, runtime_identity.environment())
        claim_state = "reattach" if job.lifecycle is OperationalLifecycle.RUNNING else "claim"
        claim_ref = _safe_identity(f"{claim_state}-{worker_id}-{stable_revision(resolved.as_dict())[:16]}", "claim reference")
        return WorkerClaim(resolved, job, claim_ref)

    def _claim_scoped(self, identity: DurableJobIdentity | str, *, worker_id: str, runtime_identity: RuntimeIdentity, scope_context: AuthorizedScopeContext) -> WorkerClaim:
        worker_id = _strict_identifier(worker_id, "worker ID")
        if not isinstance(runtime_identity, RuntimeIdentity):
            raise _invalid("Worker runtime identity is invalid.")
        runtime_identity.environment()
        with self._scope_lock(scope_context):
            # Resolve and compare the immutable binding before normalization
            # can repair queue mirrors or promote an admission entry.
            resolved, record = self._resolve_scoped_identity(identity, scope_context)
            self._deletion_fenced(scope_context, resolved.run_id)
            if record.runtime_identity.environment_identity is None and runtime_identity.environment_identity is None:
                if not _same_runtime_identity(record.runtime_identity, runtime_identity):
                    raise KSlideError(ErrorCode.EXECUTION_CONFLICT, "Worker runtime identity does not match the durable job binding.", {"job_id": resolved.job_id})
            else:
                raise_environment_mismatch(record.environment_identity, runtime_identity.environment())
            if not _same_runtime_identity(record.runtime_identity, runtime_identity):
                raise KSlideError(ErrorCode.EXECUTION_CONFLICT, "Worker runtime identity does not match the durable job binding.", {"job_id": resolved.job_id})
            job = self._scoped_store(scope_context).load(resolved.job_id)
            self._check_scoped_job(job, resolved, record)
            raise_environment_mismatch(job.environment_identity, runtime_identity.environment())
            raw_state = self._load_scoped_state(scope_context)
            state = self._normalize_scoped_state(raw_state)
            self._persist_scoped_state_if_needed(state, raw_state)
            if job.lifecycle is OperationalLifecycle.COMPLETED and job.terminal_outcome is TerminalOutcome.NEEDS_REVIEW:
                if job.resume_eligibility is not ResumeEligibility.ELIGIBLE:
                    raise KSlideError(ErrorCode.EXECUTION_CONFLICT, "Durable review job is not eligible for explicit resume.")
                if state.active_job_id not in {None, resolved.job_id}:
                    raise KSlideError(ErrorCode.EXECUTION_CONFLICT, "Durable scope already has an active heavy job.")
                for entry in state.entries:
                    if entry.identity.job_id == resolved.job_id:
                        break
                    try:
                        earlier = self._scoped_store(scope_context).load(entry.identity.job_id)
                    except KSlideError as exc:
                        if exc.code is ErrorCode.EXECUTION_NOT_FOUND:
                            raise KSlideError(ErrorCode.EXECUTION_CONFLICT, "Durable review job cannot resume ahead of an unresolved admission.") from exc
                        raise
                    if not self._terminal_for_admission(earlier):
                        raise KSlideError(ErrorCode.EXECUTION_CONFLICT, "Durable review job cannot resume ahead of queued work.")
                resumed = self._scoped_store(scope_context).transition_operational(
                    resolved.job_id,
                    expected_revision=job.revision,
                    lifecycle=OperationalLifecycle.RETRYING,
                )
                if not resumed.accepted:
                    raise KSlideError(ErrorCode.EXECUTION_CONFLICT, "Durable review job changed before explicit resume.")
                job = resumed.job
                state = replace(state, revision=state.revision + 1, active_job_id=resolved.job_id)
                self._persist_scoped_state(state)
            if not self._terminal_for_admission(job) and state.active_job_id != resolved.job_id:
                raise KSlideError(ErrorCode.EXECUTION_CONFLICT, "Durable job is queued behind another job in this scope.")
            claim_state = "reattach" if job.lifecycle is OperationalLifecycle.RUNNING else "claim"
            claim_ref = _safe_identity(f"{claim_state}-{worker_id}-{stable_revision(resolved.as_dict())[:16]}", "claim reference")
            return WorkerClaim(resolved, job, claim_ref, record.references)

    def claim_next(self, *, worker_id: str, runtime_identity: RuntimeIdentity, scope_context: AuthorizedScopeContext | None = None) -> WorkerClaim:
        scope_context = scope_context or self.scope_context
        if scope_context is not None:
            return self._claim_next_scoped(worker_id=worker_id, runtime_identity=runtime_identity, scope_context=scope_context)
        if not self._records_root.is_dir():
            raise KSlideError(ErrorCode.EXECUTION_NOT_FOUND, "No durable PaaS jobs are queued.")
        for path in sorted(self._records_root.glob("*.json")):
            record = self._read_record(path.stem)
            job = self._store.load(record.identity.job_id)
            if job.lifecycle in {OperationalLifecycle.QUEUED, OperationalLifecycle.RUNNING, OperationalLifecycle.RETRYING}:
                return self.claim(record.identity, worker_id=worker_id, runtime_identity=runtime_identity)
        raise KSlideError(ErrorCode.EXECUTION_NOT_FOUND, "No durable PaaS jobs are queued.")

    def _claim_next_scoped(self, *, worker_id: str, runtime_identity: RuntimeIdentity, scope_context: AuthorizedScopeContext) -> WorkerClaim:
        worker_id = _strict_identifier(worker_id, "worker ID")
        if not isinstance(runtime_identity, RuntimeIdentity):
            raise _invalid("Worker runtime identity is invalid.")
        runtime_identity.environment()
        with self._scope_lock(scope_context):
            raw_state = self._load_scoped_state(scope_context)
            state = self._normalize_scoped_state(raw_state)
            if state.active_job_id is None:
                raise KSlideError(ErrorCode.EXECUTION_NOT_FOUND, "No durable PaaS jobs are queued in the authorized scope.")
            record = self._read_scoped_record(scope_context, state.active_job_id)
            job = self._scoped_store(scope_context).load(state.active_job_id)
            self._deletion_fenced(scope_context, record.identity.run_id)
            if self._terminal_for_admission(job):
                next_active = None
                for entry in state.entries:
                    if entry.identity.job_id == state.active_job_id:
                        continue
                    candidate = self._scoped_store(scope_context).load(entry.identity.job_id)
                    if not self._terminal_for_admission(candidate):
                        next_active = entry.identity.job_id
                        break
                state = replace(state, revision=state.revision + 1, active_job_id=next_active)
                if next_active is None:
                    raise KSlideError(ErrorCode.EXECUTION_NOT_FOUND, "No durable PaaS jobs are queued in the authorized scope.")
                record = self._read_scoped_record(scope_context, next_active)
                job = self._scoped_store(scope_context).load(next_active)
            raise_environment_mismatch(record.environment_identity, runtime_identity.environment())
            if not _same_runtime_identity(record.runtime_identity, runtime_identity):
                raise KSlideError(ErrorCode.EXECUTION_CONFLICT, "Worker runtime identity does not match the durable job binding.", {"job_id": record.identity.job_id})
            self._check_scoped_job(job, record.identity, record)
            raise_environment_mismatch(job.environment_identity, runtime_identity.environment())
            self._persist_scoped_state_if_needed(state, raw_state)
            claim_state = "reattach" if job.lifecycle is OperationalLifecycle.RUNNING else "claim"
            claim_ref = _safe_identity(f"{claim_state}-{worker_id}-{stable_revision(record.identity.as_dict())[:16]}", "claim reference")
            return WorkerClaim(record.identity, job, claim_ref, record.references)

    def queue(self, *, scope_context: AuthorizedScopeContext | None = None) -> PaaSQueueStatus:
        scope_context = scope_context or self.scope_context
        if not isinstance(scope_context, AuthorizedScopeContext):
            raise _invalid("PaaS authorization context is required for queue visibility.")
        with self._scope_lock(scope_context):
            raw_state = self._load_scoped_state(scope_context)
            state = self._normalize_scoped_state(raw_state)
            self._persist_scoped_state_if_needed(state, raw_state)
            entries: list[PaaSQueueEntry] = []
            store = self._scoped_store(scope_context)
            for entry in state.entries:
                record = self._read_scoped_record(scope_context, entry.identity.job_id)
                try:
                    job = store.load(entry.identity.job_id)
                except KSlideError as exc:
                    if exc.code is not ErrorCode.EXECUTION_NOT_FOUND:
                        raise
                    # A record-only admission is a reserved FIFO position
                    # awaiting its idempotent KSA-06 store reconciliation.
                    entries.append(PaaSQueueEntry(entry.sequence, entry.identity, OperationalLifecycle.QUEUED, QueueAdmissionState.QUEUED, record.references))
                    continue
                self._check_scoped_job(job, entry.identity, record)
                admission_state = QueueAdmissionState.TERMINAL if self._terminal_for_admission(job) else QueueAdmissionState.ACTIVE if state.active_job_id == entry.identity.job_id else QueueAdmissionState.QUEUED
                entries.append(PaaSQueueEntry(entry.sequence, entry.identity, job.lifecycle, admission_state, record.references))
            return PaaSQueueStatus(scope_context, state.revision, state.active_job_id, tuple(entries))

    # Explicit aliases keep the adapter boundary discoverable without adding
    # another service surface or changing the controller/worker contract.
    queue_status = queue
    inspect_queue = queue
    list_queue = queue

    def resolve_references(self, identity: DurableJobIdentity | str, *, scope_context: AuthorizedScopeContext | None = None) -> ScopedArtifactReferences:
        scope_context = scope_context or self.scope_context
        if not isinstance(scope_context, AuthorizedScopeContext):
            raise _invalid("PaaS authorization context is required for reference resolution.")
        resolved, record = self._resolve_scoped_identity(identity, scope_context)
        job = self._scoped_store(scope_context).load(resolved.job_id)
        self._check_scoped_job(job, resolved, record)
        return record.references

    def resolve_store(self, identity: DurableJobIdentity | str, *, scope_context: AuthorizedScopeContext | None = None) -> RunStore:
        scope_context = scope_context or self.scope_context
        if not isinstance(scope_context, AuthorizedScopeContext):
            raise _invalid("PaaS authorization context is required for store resolution.")
        return self._open_scoped_store(identity, scope_context)

    def resolve_result(self, identity: DurableJobIdentity | str, *, scope_context: AuthorizedScopeContext | None = None) -> str:
        return self.resolve_references(identity, scope_context=scope_context).result_ref

    def resolve_evidence(self, identity: DurableJobIdentity | str, *, scope_context: AuthorizedScopeContext | None = None) -> str:
        return self.resolve_references(identity, scope_context=scope_context).evidence_ref

    def content_layout(self, identity: DurableJobIdentity | str, *, scope_context: AuthorizedScopeContext | None = None) -> StorageLayout:
        """Resolve the exact scoped KSA-11 durable content namespace."""

        scope_context = scope_context or self.scope_context
        if not isinstance(scope_context, AuthorizedScopeContext):
            raise _invalid("PaaS content resolution requires an authorized scope context.")
        resolved, _record = self._resolve_scoped_identity(identity, scope_context)
        scope_root = self._scope_root(scope_context)
        return StorageLayout.for_scoped_reference(
            service_root=self.root,
            durable_root=scope_root / "runs" / resolved.run_id,
            scope_ref=str(scope_context.scope_ref),
            run_ref=resolved.run_id,
            mutation_guard=lambda: self._deletion_fenced(scope_context, resolved.run_id),
        )

    resolve_content_layout = content_layout

    def delete_run(self, identity: DurableJobIdentity | str, *, deletion_id: str, scope_context: AuthorizedScopeContext | None = None, hold_provider: Any | None = None, reason: Any = None, dry_run: bool = False) -> Any:
        """Delete one exact scoped run through the KSA-13 adapter boundary."""

        from .deletion import DeletionReason, delete_scoped_run

        scope_context = scope_context or self.scope_context
        if not isinstance(scope_context, AuthorizedScopeContext):
            raise _invalid("PaaS deletion requires an authorized scope context.")
        return delete_scoped_run(
            self,
            identity=identity,
            scope_context=scope_context,
            deletion_id=deletion_id,
            reason=DeletionReason.EXPLICIT if reason is None else reason,
            hold_provider=hold_provider,
            dry_run=dry_run,
        )

    delete_authorized_run = delete_run

    def cleanup_operational_metadata(self, *, scope_context: AuthorizedScopeContext | None = None, retention_policy: Any, hold_provider: Any | None = None, now: Any | None = None, dry_run: bool = False) -> dict[str, Any]:
        from .deletion import cleanup_scoped_operational_metadata

        scope_context = scope_context or self.scope_context
        if not isinstance(scope_context, AuthorizedScopeContext):
            raise _invalid("Operational-metadata cleanup requires an authorized scope context.")
        return cleanup_scoped_operational_metadata(self, scope_context=scope_context, retention_policy=retention_policy, hold_provider=hold_provider, now=now, dry_run=dry_run)


class PaaSController:
    """Interactive-host facade that never waits for worker completion."""

    def __init__(self, service: PaaSJobService, *, scope_context: AuthorizedScopeContext | None = None, authorization: AuthorizedScopeContext | None = None) -> None:
        self.service = service
        if scope_context is not None and authorization is not None and scope_context != authorization:
            raise _invalid("PaaS controller authorization contexts disagree.")
        self.scope_context = scope_context or authorization or getattr(service, "scope_context", None)

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
            environment_identity=request.environment_identity,
        )
        scope_context = request.scope_context or request.authorization or self.scope_context
        if scope_context is None:
            return self.service.submit(job, runtime_identity=request.runtime_identity)
        return self.service.submit(job, runtime_identity=request.runtime_identity, scope_context=scope_context)

    def status(self, identity: DurableJobIdentity | str) -> PaaSJobStatus:
        if self.scope_context is None:
            return self.service.inspect(identity)
        return self.service.inspect(identity, scope_context=self.scope_context)

    def reconnect(self, identity: DurableJobIdentity | str) -> PaaSJobStatus:
        return self.status(identity)

    def cancel(self, identity: DurableJobIdentity | str) -> PaaSJobStatus:
        if self.scope_context is None:
            return self.service.request_cancellation(identity)
        return self.service.request_cancellation(identity, scope_context=self.scope_context)

    def queue(self) -> PaaSQueueStatus:
        queue_method = getattr(self.service, "queue", None)
        if not callable(queue_method):
            raise _invalid("This PaaS adapter does not expose scoped queue visibility.")
        if self.scope_context is None:
            raise _invalid("PaaS controller authorization context is required for queue visibility.")
        return queue_method(scope_context=self.scope_context)


# Descriptive adapter aliases; these do not introduce a second orchestration
# or company service implementation.
ReferenceScopedPaaSJobService = ReferencePaaSJobService
ReferenceScopedPaaSRunStore = ScopedPaaSRunStore
ScopedQueueStatus = PaaSQueueStatus


class WorkerEngine(Protocol):
    """Engine binding supplied by the existing K-Slide runtime."""

    def operation_id(self, job: ExecutionJob) -> str: ...

    def step(self, checkpoint: RunCheckpoint, operation_id: str) -> EngineStepResult: ...


class PaaSWorker:
    """Restartable worker using the existing ExecutionController boundary."""

    def __init__(self, service: PaaSJobService, *, worker_id: str, runtime_identity: RuntimeIdentity, engine: WorkerEngine | Any, scope_context: AuthorizedScopeContext | None = None, authorization: AuthorizedScopeContext | None = None) -> None:
        self.service = service
        self.worker_id = _strict_identifier(worker_id, "worker ID")
        if not isinstance(runtime_identity, RuntimeIdentity):
            raise _invalid("Worker runtime identity is invalid.")
        runtime_identity.environment()
        self.runtime_identity = runtime_identity
        self.engine = engine
        if scope_context is not None and authorization is not None and scope_context != authorization:
            raise _invalid("PaaS worker authorization contexts disagree.")
        self.scope_context = scope_context or authorization or getattr(service, "scope_context", None)

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

    def _reconcile(self, store: RunStore, job: ExecutionJob, *, accepted_status: str = "ACCEPTED", engine_called: bool = True, references: ScopedArtifactReferences | None = None) -> WorkerResult:
        current = store.load(job.job_id)
        if current.cancellation.requested and not current.cancellation.acknowledged:
            acknowledged = store.acknowledge_cancellation(current.job_id, expected_revision=current.revision, safe_boundary=True)
            if acknowledged.accepted:
                return WorkerResult("CANCELED", acknowledged.job, engine_called=engine_called, references=references)
            return WorkerResult(acknowledged.status.value, acknowledged.job, engine_called=engine_called, references=references)
        if current.lifecycle in {OperationalLifecycle.RUNNING, OperationalLifecycle.RETRYING}:
            if current.checkpoint.engine_phase == RunPhase.COMPLETE.value:
                committed = store.transition_operational(current.job_id, expected_revision=current.revision, lifecycle=OperationalLifecycle.COMPLETED, terminal_outcome=TerminalOutcome.DONE, resume_eligibility=ResumeEligibility.NOT_ELIGIBLE)
                if committed.accepted:
                    return WorkerResult("DONE", committed.job, engine_called=engine_called, references=references)
                return WorkerResult(committed.status.value, committed.job, engine_called=engine_called, references=references)
            if current.checkpoint.engine_phase == RunPhase.NEEDS_REVIEW.value:
                committed = store.transition_operational(current.job_id, expected_revision=current.revision, lifecycle=OperationalLifecycle.COMPLETED, terminal_outcome=TerminalOutcome.NEEDS_REVIEW, resume_eligibility=ResumeEligibility.ELIGIBLE)
                if committed.accepted:
                    return WorkerResult("NEEDS_REVIEW", committed.job, engine_called=engine_called, references=references)
                return WorkerResult(committed.status.value, committed.job, engine_called=engine_called, references=references)
        return WorkerResult(accepted_status, current, engine_called=engine_called, references=references)

    def _record_failure(self, store: RunStore, job: ExecutionJob, error: KSlideError | Exception, *, references: ScopedArtifactReferences | None = None) -> WorkerResult:
        current = store.load(job.job_id)
        if current.cancellation.requested and not current.cancellation.acknowledged:
            acknowledged = store.acknowledge_cancellation(current.job_id, expected_revision=current.revision, safe_boundary=True)
            if acknowledged.accepted:
                return WorkerResult("CANCELED", acknowledged.job, references=references)
            return WorkerResult(acknowledged.status.value, acknowledged.job, references=references)
        if isinstance(error, KSlideError):
            error_code = error.code
        else:
            error_code = ErrorCode.INTERNAL
        failure_class = classify_operational_failure(error_code)
        if failure_class is FailureClass.SEMANTIC_REPAIR:
            return WorkerResult("SEMANTIC_REPAIR", current, failure_class=failure_class, references=references)
        if error_code is ErrorCode.EXECUTION_STALE:
            return WorkerResult("STALE", current, failure_class=failure_class, references=references)
        try:
            recorded = store.record_retry(current.job_id, expected_revision=current.revision, error_code=error_code.value)
        except KSlideError:
            latest = store.load(current.job_id)
            return WorkerResult("STALE", latest, failure_class=failure_class, references=references)
        status = "RETRYING" if recorded.job.lifecycle is OperationalLifecycle.RETRYING else "PROCESSING_FAILED"
        return WorkerResult(status, recorded.job, failure_class=failure_class, references=references)

    def run_once(self, identity: DurableJobIdentity | str | None = None) -> WorkerResult:
        if identity is None:
            claim_method = getattr(self.service, "claim_next", None)
            if not callable(claim_method):
                raise _invalid("This PaaS adapter does not support claim-next; provide a job identity.")
            if self.scope_context is None:
                claim = claim_method(worker_id=self.worker_id, runtime_identity=self.runtime_identity)
            else:
                claim = claim_method(worker_id=self.worker_id, runtime_identity=self.runtime_identity, scope_context=self.scope_context)
        else:
            if self.scope_context is None:
                claim = self.service.claim(identity, worker_id=self.worker_id, runtime_identity=self.runtime_identity)
            else:
                claim = self.service.claim(identity, worker_id=self.worker_id, runtime_identity=self.runtime_identity, scope_context=self.scope_context)
        if self.scope_context is None:
            store = self.service.open_store(claim.identity)
        else:
            store = self.service.open_store(claim.identity, scope_context=self.scope_context)
        job = store.load(claim.identity.job_id)
        raise_environment_mismatch(job.environment_identity, self.runtime_identity.environment())
        terminal = self._terminal_status(job)
        if terminal is not None:
            return WorkerResult(terminal, job, references=claim.references)
        if job.lifecycle is OperationalLifecycle.COMPLETED and job.terminal_outcome is TerminalOutcome.NEEDS_REVIEW:
            resumed = store.transition_operational(job.job_id, expected_revision=job.revision, lifecycle=OperationalLifecycle.RETRYING)
            if not resumed.accepted:
                return WorkerResult(resumed.status.value, resumed.job, references=claim.references)
            job = resumed.job
        if job.lifecycle is OperationalLifecycle.RETRYING:
            started = store.transition_operational(job.job_id, expected_revision=job.revision, lifecycle=OperationalLifecycle.RUNNING)
            if not started.accepted:
                return WorkerResult(started.status.value, started.job, references=claim.references)
        try:
            operation_id = self._engine_operation_id(store.load(job.job_id))
            controller = ExecutionController(store, environment_identity=self.runtime_identity.environment())
            result = controller.run_step(job.job_id, operation_id=operation_id, step=self._engine_step)
        except Exception as exc:
            return self._record_failure(store, job, exc, references=claim.references)
        if result.status in {"CANCELED", "CONFLICT", "STALE"}:
            return WorkerResult(result.status, result.job, engine_called=result.engine_called, references=claim.references)
        return self._reconcile(store, result.job, accepted_status=result.status, engine_called=result.engine_called, references=claim.references)

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
        return WorkerResult("STEP_LIMIT", last.job, engine_called=last.engine_called, failure_class=last.failure_class, references=last.references)


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
    "SCOPED_PAAS_CONTRACT_VERSION",
    "AuthorizedScope",
    "AuthorizedScopeContext",
    "AuthorizationContext",
    "authenticated_paas_service_call",
    "ApprovedCompanyServiceTransport",
    "CompanyServiceRequest",
    "DurableJobIdentity",
    "PaaSScopeContext",
    "PaaSController",
    "PaaSJobRequest",
    "PaaSJobService",
    "PaaSJobStatus",
    "PaaSJobSubmission",
    "PaaSRunStore",
    "PaaSSubmissionReceipt",
    "PaaSQueueEntry",
    "PaaSQueueStatus",
    "PinnedRuntimeIdentity",
    "QueueAdmissionState",
    "ReferencePaaSJobService",
    "ReferencePaaSRunStore",
    "ReferenceScopedPaaSJobService",
    "ReferenceScopedPaaSRunStore",
    "ReferenceWorkerEngine",
    "RunStoreResolver",
    "RunResultEvidenceRefs",
    "ScopeAuthorization",
    "RuntimeIdentity",
    "ScopedArtifactReferences",
    "ScopedAdmissionPolicy",
    "ScopedPaaSJobService",
    "ScopedPaaSRunStore",
    "ScopedQueueStatus",
    "ScopeContext",
    "WorkerClaim",
    "WorkerEngine",
    "WorkerResult",
    "PaaSWorker",
]
