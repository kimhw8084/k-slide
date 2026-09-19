"""Versioned, host-neutral lifecycle and local-input adapter boundary."""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Mapping
from urllib.parse import unquote, urlparse

from .authentication import ApprovedCompanyServiceTransport, CompanyServiceRequest, authenticated_company_service_call
from .egress_policy import EGRESS_CAPABILITY_SCOPED_STORAGE, EGRESS_DATA_CLASS_SOURCE_CONTENT, EGRESS_PURPOSE_STORAGE
from .classification_policy import DEFAULT_CLASSIFICATION, validate_classification_label
from .errors import ErrorCode, KSlideError
from .queue import WorkQueue, WorkUnitStatus
from .redaction import sanitize_operational
from .security import InputArtifact, SUPPORTED_EXTENSIONS, validate_input
from .state import OPERATIONAL_FAILURE_PHASES, RunPhase


HOST_ADAPTER_SCHEMA_VERSION = "1.0"
HOST_ADAPTER_VERSION = "1.0"
HOST_INPUT_KINDS = frozenset({"attachment", "workspace_file"})


def authenticated_host_service_call(
    transport: ApprovedCompanyServiceTransport,
    request: CompanyServiceRequest | Mapping[str, Any],
    *,
    egress_policy: Any | None = None,
    service_identity: str | None = None,
) -> object:
    """Use the common AccessKey boundary for host-neutral callers."""

    if egress_policy is None:
        # Preserve the KSA-14/15 reference-adapter seam. Production callers
        # pass the deployment policy and therefore take the guarded path.
        return authenticated_company_service_call(transport, request)
    return authenticated_company_service_call(
        transport,
        request,
        egress_policy=egress_policy,
        capability_class=EGRESS_CAPABILITY_SCOPED_STORAGE,
        purpose=EGRESS_PURPOSE_STORAGE,
        service_identity=service_identity,
        data_class=EGRESS_DATA_CLASS_SOURCE_CONTENT,
    )


class OperationalState(str, Enum):
    """Host-visible execution lifecycle, separate from semantic outcome."""

    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    RETRYING = "RETRYING"
    COMPLETED = "COMPLETED"
    CANCELED = "CANCELED"
    PROCESSING_FAILED = "PROCESSING_FAILED"


class SemanticOutcome(str, Enum):
    PENDING = "PENDING"
    DONE = "DONE"
    NEEDS_REVIEW = "NEEDS_REVIEW"


@dataclass(frozen=True)
class HostProgress:
    phase: str | None
    completed_work_units: int
    total_work_units: int
    input_count: int | None
    current_work_unit: str | None
    next_action: str | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "phase": self.phase,
            "completed_work_units": self.completed_work_units,
            "total_work_units": self.total_work_units,
            "input_count": self.input_count,
            "current_work_unit": self.current_work_unit,
            "next_action": self.next_action,
        }


@dataclass(frozen=True)
class HostResult:
    adapter_schema_version: str
    adapter_version: str
    operational_state: str | None
    semantic_outcome: str | None
    progress: HostProgress

    def as_dict(self) -> dict[str, Any]:
        return {
            "adapter_schema_version": self.adapter_schema_version,
            "adapter_version": self.adapter_version,
            "operational_state": self.operational_state,
            "semantic_outcome": self.semantic_outcome,
            "progress": self.progress.as_dict(),
        }


@dataclass(frozen=True)
class HostInputReference:
    """Transient host reference; it is never written to a run manifest."""

    source_kind: str
    logical_name: str
    locator: str
    classification: str | None = DEFAULT_CLASSIFICATION

    def __post_init__(self) -> None:
        if self.classification is None:
            object.__setattr__(self, "classification", DEFAULT_CLASSIFICATION)
        else:
            validate_classification_label(self.classification, allow_none=False)

    @classmethod
    def from_mapping(cls, value: Any) -> "HostInputReference":
        if not isinstance(value, dict):
            raise KSlideError(ErrorCode.SCHEMA_INVALID, "Host input reference must be an object.")
        allowed = {"source_kind", "logical_name", "locator", "classification"}
        if set(value) - allowed:
            raise KSlideError(ErrorCode.SCHEMA_INVALID, "Host input reference contains unsupported fields.")
        source_kind = value.get("source_kind")
        logical_name = value.get("logical_name")
        locator = value.get("locator")
        if source_kind not in HOST_INPUT_KINDS:
            raise KSlideError(ErrorCode.INPUT_UNSUPPORTED, "Host input reference kind is not supported.")
        if not isinstance(logical_name, str) or not logical_name.strip() or "\x00" in logical_name or "/" in logical_name or "\\" in logical_name:
            raise KSlideError(ErrorCode.INPUT_UNSUPPORTED, "Host input logical name must be a safe file name.")
        if logical_name in {".", ".."}:
            raise KSlideError(ErrorCode.INPUT_UNSUPPORTED, "Host input logical name is not safe.")
        extension = Path(logical_name).suffix.lower()
        if extension not in SUPPORTED_EXTENSIONS:
            raise KSlideError(ErrorCode.INPUT_UNSUPPORTED, "Host input file type is not supported by K-Slide.", {"extension": extension})
        if not isinstance(locator, str) or not locator.strip() or "\x00" in locator:
            raise KSlideError(ErrorCode.INPUT_NOT_FOUND, "Host input reference is empty.")
        classification = validate_classification_label(value.get("classification")) or DEFAULT_CLASSIFICATION
        return cls(source_kind, logical_name, locator, classification)


@dataclass(frozen=True)
class HostInvocation:
    """Stable invocation envelope shared by OpenCode and future adapters."""

    input_refs: tuple[HostInputReference, ...]
    schema_version: str = HOST_ADAPTER_SCHEMA_VERSION
    adapter_version: str = HOST_ADAPTER_VERSION

    @classmethod
    def from_json(cls, raw: str | None) -> "HostInvocation | None":
        if not raw:
            return None
        try:
            value = json.loads(raw)
        except (TypeError, json.JSONDecodeError) as exc:
            raise KSlideError(ErrorCode.SCHEMA_INVALID, "Host invocation is not valid JSON.") from exc
        if not isinstance(value, dict):
            raise KSlideError(ErrorCode.SCHEMA_INVALID, "Host invocation must be an object.")
        if value.get("schema_version") != HOST_ADAPTER_SCHEMA_VERSION or value.get("adapter_version") != HOST_ADAPTER_VERSION:
            raise KSlideError(ErrorCode.SCHEMA_INVALID, "Unsupported host adapter contract version.")
        raw_refs = value.get("input_refs")
        if not isinstance(raw_refs, list):
            raise KSlideError(ErrorCode.SCHEMA_INVALID, "Host invocation input_refs must be a list.")
        refs = tuple(HostInputReference.from_mapping(item) for item in raw_refs)
        return cls(refs)


def _local_path(reference: HostInputReference, *, approved_root: Path) -> Path:
    if reference.locator.startswith(("\\\\", "//")):
        raise KSlideError(ErrorCode.INPUT_UNSUPPORTED, "Host input reference must use a local file path or file URI.")
    parsed = urlparse(reference.locator)
    if parsed.scheme:
        if parsed.scheme.lower() != "file" or parsed.netloc not in {"", "localhost"}:
            raise KSlideError(ErrorCode.INPUT_UNSUPPORTED, "Host input reference must use a local file path or file URI.")
        if not parsed.path:
            raise KSlideError(ErrorCode.INPUT_NOT_FOUND, "Host file URI does not identify a local file.")
        candidate = Path(unquote(parsed.path))
    else:
        candidate = Path(reference.locator).expanduser()
        if not candidate.is_absolute():
            candidate = approved_root / candidate
    return candidate


def validate_host_inputs(references: Iterable[HostInputReference], *, approved_root: Path) -> list[InputArtifact]:
    """Resolve and validate host references without fetching or persisting them."""

    root = approved_root.expanduser().resolve()
    artifacts: list[InputArtifact] = []
    for reference in references:
        candidate = _local_path(reference, approved_root=root)
        allowed_root = root if reference.source_kind == "workspace_file" else None
        artifacts.append(
            validate_input(
                candidate,
                allowed_root=allowed_root,
                logical_name=reference.logical_name,
                classification=reference.classification if reference.classification is not None else DEFAULT_CLASSIFICATION,
            )
        )
    return artifacts


def phase_contract(phase: RunPhase | None) -> tuple[str | None, str | None]:
    if phase in OPERATIONAL_FAILURE_PHASES:
        return OperationalState.PROCESSING_FAILED.value, None
    if phase == RunPhase.CREATED:
        return OperationalState.QUEUED.value, SemanticOutcome.PENDING.value
    if phase in {RunPhase.FAIL_REPAIRABLE, RunPhase.REPAIRING}:
        return OperationalState.RETRYING.value, SemanticOutcome.PENDING.value
    if phase == RunPhase.COMPLETE:
        return OperationalState.COMPLETED.value, SemanticOutcome.DONE.value
    if phase == RunPhase.NEEDS_REVIEW:
        return OperationalState.COMPLETED.value, SemanticOutcome.NEEDS_REVIEW.value
    if phase == RunPhase.VERIFIED:
        return OperationalState.COMPLETED.value, SemanticOutcome.PENDING.value
    if phase is None:
        return None, None
    return OperationalState.RUNNING.value, SemanticOutcome.PENDING.value


def add_host_contract(value: dict[str, Any], *, phase: RunPhase | None, queue: WorkQueue | None = None, input_count: int | None = None, execution: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Add stable host lifecycle/progress fields while preserving legacy status."""

    operational_state, semantic_outcome = phase_contract(phase)
    if value.get("status") == "PROCESSING_FAILED":
        operational_state, semantic_outcome = OperationalState.PROCESSING_FAILED.value, None
    elif value.get("status") == "NEEDS_REVIEW" and phase not in OPERATIONAL_FAILURE_PHASES:
        operational_state, semantic_outcome = OperationalState.COMPLETED.value, SemanticOutcome.NEEDS_REVIEW.value
    total = len(queue.work_units) if queue is not None else int(input_count or 0)
    completed = 0
    if queue is not None:
        completed = sum(unit.status in {WorkUnitStatus.TRANSLATED, WorkUnitStatus.VERIFIED} for unit in queue.work_units)
    result = dict(value)
    contract = HostResult(
        HOST_ADAPTER_SCHEMA_VERSION,
        HOST_ADAPTER_VERSION,
        operational_state,
        semantic_outcome,
        HostProgress(
            phase.value if phase is not None else None,
            completed,
            total,
            input_count,
            result.get("current_work_unit"),
            result.get("next_action"),
        ),
    )
    for key, item in contract.as_dict().items():
        result.setdefault(key, item)
    if execution is not None:
        result.setdefault("execution", sanitize_operational(dict(execution)))
    return sanitize_operational(result)
