"""Explicit, deployment-authorized content-bearing support diagnostics.

The ordinary support bundle in :mod:`k_slide.support` is intentionally
source-free.  This module is a separate boundary for the exceptional case
where a deployment-owned authority supplies a complete, finite, exact-run
support decision.  It does not authenticate callers, decide company policy,
or transfer content to a support system.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import zipfile
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Protocol

from .authentication import ACCESS_KEY_ENV
from .errors import ErrorCode, KSlideError
from .io import atomic_write_json, atomic_write_text
from .locking import filesystem_lock
from .paas import AuthorizedScopeContext
from .redaction import sanitize_operational
from .storage import StorageArtifact, StorageLayout, StoragePlane, StorageReference


SUPPORT_CONTRACT_VERSION = "1.0"
SUPPORT_AUDIT_SCHEMA_VERSION = "1.0"
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}$")
_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")
_FORBIDDEN_ID_TERMS = (
    "accesskey", "password", "secret", "token", "credential", "bearer", "source", "prompt", "translation",
    "ocr", "report", "image", "text", "korean", "path", "filename",
)
_CONTENT_SUFFIX = re.compile(r"\.(?:png|jpg|jpeg|webp|pdf|pptx|docx|md|json|txt)$", re.IGNORECASE)
_SECRET_ASSIGNMENT = re.compile(
    rb"(?i)(?:access[\s_.:/-]*key|authorization|password|secret|token|credential(?:s)?)\s*[:=]\s*[^\s\r\n,;}\]]+"
)
_SECRET_LABEL = re.compile(rb"(?i)(?:access[\s_.:/-]*key|authorization|password|secret|token|credential(?:s)?)")
_MAX_SELECTIONS = 512
_MAX_ARTIFACT_BYTES = 256 * 1024 * 1024


def _invalid(message: str, *, code: ErrorCode = ErrorCode.SUPPORT_AUTHORIZATION_INVALID) -> KSlideError:
    return KSlideError(code, message)


def _identity(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or not _IDENTIFIER.fullmatch(value)
        or "/" in value
        or "\\" in value
        or ".." in value
        or _CONTENT_SUFFIX.search(value) is not None
        or any(term in value.casefold() for term in _FORBIDDEN_ID_TERMS)
    ):
        raise _invalid(f"Controlled support {label} is invalid.")
    return value


def _timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not _TIMESTAMP.fullmatch(value):
        raise _invalid(f"Controlled support {label} timestamp is invalid.")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError as exc:
        raise _invalid(f"Controlled support {label} timestamp is invalid.") from exc


def _time(value: datetime | None) -> datetime:
    selected = value or datetime.now(timezone.utc)
    if selected.tzinfo is None:
        raise _invalid("Controlled support time must include a timezone.")
    return selected.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


class SupportPurpose(str, Enum):
    INCIDENT_DIAGNOSTIC = "INCIDENT_DIAGNOSTIC"
    DATA_OWNER_REVIEW = "DATA_OWNER_REVIEW"


class SupportDecisionStatus(str, Enum):
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    REVOKED = "REVOKED"


class SupportApprovalStatus(str, Enum):
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    PENDING = "PENDING"


class SupportArtifactClass(str, Enum):
    SOURCE_SNAPSHOT = "source_snapshot"
    NORMALIZED_RENDER = "normalized_render"
    NATIVE_EXTRACTION = "native_extraction"
    REGION_CROP = "region_crop"
    OCR_METADATA = "ocr_metadata"
    EVIDENCE_IR = "evidence_ir"
    TRANSLATION_PATCH = "translation_patch"
    CANONICAL_IR = "canonical_ir"
    REPORT = "report"


_ARTIFACT_FOR_CLASS = {
    SupportArtifactClass.SOURCE_SNAPSHOT: StorageArtifact.SOURCE_SNAPSHOT,
    SupportArtifactClass.NORMALIZED_RENDER: StorageArtifact.NORMALIZED_RENDER,
    SupportArtifactClass.NATIVE_EXTRACTION: StorageArtifact.NATIVE_EXTRACTION,
    SupportArtifactClass.REGION_CROP: StorageArtifact.REGION_CROP,
    SupportArtifactClass.OCR_METADATA: StorageArtifact.OCR_METADATA,
    SupportArtifactClass.EVIDENCE_IR: StorageArtifact.EVIDENCE_IR,
    SupportArtifactClass.TRANSLATION_PATCH: StorageArtifact.TRANSLATION_PATCH,
    SupportArtifactClass.CANONICAL_IR: StorageArtifact.CANONICAL_IR,
    SupportArtifactClass.REPORT: StorageArtifact.REPORT,
}


def _path_matches_class(artifact_class: SupportArtifactClass, relative_path: str) -> bool:
    parts = relative_path.split("/")
    top = parts[0]
    name = parts[-1]
    if artifact_class is SupportArtifactClass.SOURCE_SNAPSHOT:
        return top == "inputs" and len(parts) >= 2
    if artifact_class is SupportArtifactClass.NORMALIZED_RENDER:
        return top == "normalized" and len(parts) >= 2 and name not in {"DOCUMENT_MANIFEST.json", "NORMALIZATION_ERROR.json"}
    if artifact_class is SupportArtifactClass.NATIVE_EXTRACTION:
        return top == "native" and len(parts) >= 2
    if artifact_class is SupportArtifactClass.REGION_CROP:
        return top == "regions" and len(parts) >= 3
    if artifact_class is SupportArtifactClass.OCR_METADATA:
        return relative_path == "OCR_METADATA.json"
    if artifact_class is SupportArtifactClass.EVIDENCE_IR:
        return top == "evidence" and len(parts) >= 2
    if artifact_class is SupportArtifactClass.TRANSLATION_PATCH:
        return top == "translations" and len(parts) >= 2
    if artifact_class is SupportArtifactClass.CANONICAL_IR:
        return top == "ir" and len(parts) >= 2
    if artifact_class is SupportArtifactClass.REPORT:
        return len(parts) == 1 and name.startswith(("05_", "07_"))
    return False


def _artifact_class(value: SupportArtifactClass | str) -> SupportArtifactClass:
    try:
        return value if isinstance(value, SupportArtifactClass) else SupportArtifactClass(str(value))
    except ValueError as exc:
        raise _invalid("Controlled support artifact class is unsupported.") from exc


@dataclass(frozen=True)
class SupportApprovalEvidence:
    approval_ref: str
    status: SupportApprovalStatus

    def __post_init__(self) -> None:
        _identity(self.approval_ref, "approval reference")
        try:
            object.__setattr__(self, "status", self.status if isinstance(self.status, SupportApprovalStatus) else SupportApprovalStatus(str(self.status)))
        except ValueError as exc:
            raise _invalid("Controlled support approval status is unsupported.") from exc

    def as_dict(self) -> dict[str, str]:
        return {"approval_ref": self.approval_ref, "status": self.status.value}


@dataclass(frozen=True)
class SupportAuthorizationDecision:
    """Opaque, deployment-issued authorization for one exact support request."""

    access_request_ref: str
    scope_context: AuthorizedScopeContext
    run_ref: str
    support_subject_ref: str
    support_role_ref: str
    support_capability_ref: str
    purpose: SupportPurpose
    authority_ref: str
    decision_ref: str
    approvals: tuple[SupportApprovalEvidence, ...]
    allowed_artifact_classes: tuple[SupportArtifactClass, ...] = ()
    allowed_references: tuple[StorageReference, ...] = ()
    issued_at: str = ""
    not_before_at: str = ""
    expires_at: str = ""
    status: SupportDecisionStatus = SupportDecisionStatus.APPROVED
    contract_version: str = SUPPORT_CONTRACT_VERSION

    def __post_init__(self) -> None:
        if self.contract_version != SUPPORT_CONTRACT_VERSION:
            raise _invalid("Unsupported controlled support authorization version.")
        if not isinstance(self.scope_context, AuthorizedScopeContext):
            raise _invalid("Controlled support authorization requires an authorized scope context.")
        _identity(self.scope_context.user_ref, "authorized user reference")
        _identity(self.scope_context.workspace_ref, "authorized workspace reference")
        _identity(str(self.scope_context.scope_ref), "authorized scope reference")
        _identity(self.access_request_ref, "access request reference")
        _identity(self.run_ref, "run reference")
        _identity(self.support_subject_ref, "support subject reference")
        _identity(self.support_role_ref, "support role reference")
        _identity(self.support_capability_ref, "support capability reference")
        _identity(self.authority_ref, "authority reference")
        _identity(self.decision_ref, "decision reference")
        try:
            object.__setattr__(self, "purpose", self.purpose if isinstance(self.purpose, SupportPurpose) else SupportPurpose(str(self.purpose)))
            object.__setattr__(self, "status", self.status if isinstance(self.status, SupportDecisionStatus) else SupportDecisionStatus(str(self.status)))
        except ValueError as exc:
            raise _invalid("Controlled support authorization contains an unsupported decision or purpose.") from exc
        if not isinstance(self.approvals, tuple) or not self.approvals or any(not isinstance(item, SupportApprovalEvidence) for item in self.approvals):
            raise _invalid("Controlled support authorization requires approval evidence.")
        if len({item.approval_ref for item in self.approvals}) != len(self.approvals):
            raise _invalid("Controlled support authorization contains duplicate approval evidence.")
        classes = tuple(_artifact_class(item) for item in self.allowed_artifact_classes)
        if len(set(classes)) != len(classes):
            raise _invalid("Controlled support authorization contains duplicate artifact classes.")
        object.__setattr__(self, "allowed_artifact_classes", classes)
        if not classes and not self.allowed_references:
            raise _invalid("Controlled support authorization must name allowed artifact classes or references.")
        references: list[StorageReference] = []
        for reference in self.allowed_references:
            if not isinstance(reference, StorageReference) or reference.plane is not StoragePlane.DURABLE_USER_WORKSPACE_RUN_DATA:
                raise _invalid("Controlled support allowed reference must be durable typed storage.")
            if reference.scope_ref != self.scope_context.scope_ref or reference.run_ref != self.run_ref:
                raise _invalid("Controlled support allowed reference is outside the authorized scope or run.", code=ErrorCode.EXECUTION_CONFLICT)
            if reference.artifact not in _ARTIFACT_FOR_CLASS.values():
                raise _invalid("Controlled support allowed reference is not a content-bearing artifact.")
            references.append(reference)
        if len({(item.artifact, item.relative_path) for item in references}) != len(references):
            raise _invalid("Controlled support authorization contains duplicate references.")
        object.__setattr__(self, "allowed_references", tuple(references))
        issued = _timestamp(self.issued_at, "issued")
        not_before = _timestamp(self.not_before_at, "not-before")
        expires = _timestamp(self.expires_at, "expiry")
        if issued > not_before or not_before >= expires:
            raise _invalid("Controlled support authorization expiry is not finite and ordered.")

    def as_dict(self) -> dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "access_request_ref": self.access_request_ref,
            "scope_context": self.scope_context.as_dict(),
            "run_ref": self.run_ref,
            "support_subject_ref": self.support_subject_ref,
            "support_role_ref": self.support_role_ref,
            "support_capability_ref": self.support_capability_ref,
            "purpose": self.purpose.value,
            "authority_ref": self.authority_ref,
            "decision_ref": self.decision_ref,
            "approvals": [item.as_dict() for item in self.approvals],
            "allowed_artifact_classes": [item.value for item in self.allowed_artifact_classes],
            "allowed_references": [item.as_dict() for item in self.allowed_references],
            "issued_at": self.issued_at,
            "not_before_at": self.not_before_at,
            "expires_at": self.expires_at,
            "status": self.status.value,
        }

    @classmethod
    def from_dict(cls, value: Any) -> "SupportAuthorizationDecision":
        if not isinstance(value, dict):
            raise _invalid("Controlled support authorization must be an object.")
        required = {
            "contract_version", "access_request_ref", "scope_context", "run_ref", "support_subject_ref",
            "support_role_ref", "support_capability_ref", "purpose", "authority_ref", "decision_ref",
            "approvals", "allowed_artifact_classes", "allowed_references", "issued_at", "not_before_at",
            "expires_at", "status",
        }
        if set(value) != required or not isinstance(value["approvals"], list) or not isinstance(value["allowed_references"], list) or not isinstance(value["allowed_artifact_classes"], list):
            raise _invalid("Controlled support authorization is incomplete.")
        try:
            return cls(
                access_request_ref=value["access_request_ref"],
                scope_context=AuthorizedScopeContext.from_dict(value["scope_context"]),
                run_ref=value["run_ref"],
                support_subject_ref=value["support_subject_ref"],
                support_role_ref=value["support_role_ref"],
                support_capability_ref=value["support_capability_ref"],
                purpose=SupportPurpose(value["purpose"]),
                authority_ref=value["authority_ref"],
                decision_ref=value["decision_ref"],
                approvals=tuple(SupportApprovalEvidence(item["approval_ref"], SupportApprovalStatus(item["status"])) for item in value["approvals"]),
                allowed_artifact_classes=tuple(SupportArtifactClass(item) for item in value["allowed_artifact_classes"]),
                allowed_references=tuple(StorageReference.from_dict(item) for item in value["allowed_references"]),
                issued_at=value["issued_at"],
                not_before_at=value["not_before_at"],
                expires_at=value["expires_at"],
                status=SupportDecisionStatus(value["status"]),
                contract_version=value["contract_version"],
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise _invalid("Controlled support authorization is invalid.") from exc


@dataclass(frozen=True)
class SupportContentSelection:
    """One exact typed durable reference selected for a support package."""

    artifact_class: SupportArtifactClass
    reference: StorageReference

    def __post_init__(self) -> None:
        artifact_class = _artifact_class(self.artifact_class)
        object.__setattr__(self, "artifact_class", artifact_class)
        if not isinstance(self.reference, StorageReference) or self.reference.plane is not StoragePlane.DURABLE_USER_WORKSPACE_RUN_DATA:
            raise _invalid("Controlled support selection requires a durable typed storage reference.")
        if self.reference.artifact is not _ARTIFACT_FOR_CLASS[artifact_class]:
            raise _invalid("Controlled support selection class does not match its storage reference.")
        if not _path_matches_class(artifact_class, self.reference.relative_path):
            raise _invalid("Controlled support selection path is not valid for its typed artifact class.", code=ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT)


@dataclass(frozen=True)
class ControlledSupportRequest:
    authorization: SupportAuthorizationDecision
    selections: tuple[SupportContentSelection, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.authorization, SupportAuthorizationDecision):
            raise _invalid("Controlled support request requires a typed authorization decision.")
        if not isinstance(self.selections, tuple) or not self.selections or len(self.selections) > _MAX_SELECTIONS:
            raise _invalid("Controlled support request requires a bounded explicit selection.")
        seen: set[tuple[StorageArtifact, str]] = set()
        allowed_refs = {(item.artifact, item.relative_path) for item in self.authorization.allowed_references}
        for selection in self.selections:
            if not isinstance(selection, SupportContentSelection):
                raise _invalid("Controlled support selection is invalid.")
            reference = selection.reference
            if reference.scope_ref != self.authorization.scope_context.scope_ref or reference.run_ref != self.authorization.run_ref:
                raise _invalid("Controlled support selection is outside the authorized scope or run.", code=ErrorCode.EXECUTION_CONFLICT)
            if selection.artifact_class not in self.authorization.allowed_artifact_classes and (reference.artifact, reference.relative_path) not in allowed_refs:
                raise _invalid("Controlled support selection is not authorized.", code=ErrorCode.SUPPORT_AUTHORIZATION_DENIED)
            key = (reference.artifact, reference.relative_path)
            if key in seen:
                raise _invalid("Controlled support request contains duplicate selections.")
            seen.add(key)

    @property
    def decision(self) -> SupportAuthorizationDecision:
        return self.authorization


class SupportAuthorizationProvider(Protocol):
    """Deployment-owned decision lookup; it must be authoritative per call."""

    production_authoritative: bool

    def resolve(self, *, access_request_ref: str, scope_context: AuthorizedScopeContext, run_ref: str, decision_ref: str) -> SupportAuthorizationDecision: ...


class ReferenceSupportAuthorizationProvider:
    """Deterministic test adapter; never a production authority."""

    production_authoritative = False

    def __init__(self) -> None:
        self._decisions: dict[tuple[str, str, str, str], SupportAuthorizationDecision] = {}

    def add(self, decision: SupportAuthorizationDecision) -> None:
        key = (decision.access_request_ref, str(decision.scope_context.scope_ref), decision.run_ref, decision.decision_ref)
        self._decisions[key] = decision

    def revoke(self, decision_ref: str) -> None:
        matches = [key for key in self._decisions if key[3] == decision_ref]
        if len(matches) != 1:
            raise _invalid("Reference support authorization identity is ambiguous.")
        current = self._decisions[matches[0]]
        from dataclasses import replace

        self._decisions[matches[0]] = replace(current, status=SupportDecisionStatus.REVOKED)

    def resolve(self, *, access_request_ref: str, scope_context: AuthorizedScopeContext, run_ref: str, decision_ref: str) -> SupportAuthorizationDecision:
        key = (access_request_ref, str(scope_context.scope_ref), run_ref, decision_ref)
        decision = self._decisions.get(key)
        if decision is None:
            raise LookupError("support decision unavailable")
        return decision


class SupportAccessLifecycle(str, Enum):
    MATERIALIZED = "MATERIALIZED"
    ACCESSED = "ACCESSED"
    DENIED = "DENIED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    CLEANED = "CLEANED"
    DELETED = "DELETED"


class SupportAccessResult(str, Enum):
    SUCCESS = "SUCCESS"
    DENIED = "DENIED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    CLEANED = "CLEANED"
    DELETED = "DELETED"
    FAILED = "FAILED"


@dataclass(frozen=True)
class SupportAccessAudit:
    occurred_at: str
    lifecycle: SupportAccessLifecycle
    result: SupportAccessResult
    access_request_ref: str
    scope_context: AuthorizedScopeContext
    run_ref: str
    support_subject_ref: str
    support_role_ref: str
    support_capability_ref: str
    purpose: SupportPurpose
    authority_ref: str
    decision_ref: str
    approvals: tuple[SupportApprovalEvidence, ...]
    allowed_artifact_classes: tuple[SupportArtifactClass, ...]
    selected_artifact_classes: tuple[SupportArtifactClass, ...]
    issued_at: str
    not_before_at: str
    expires_at: str
    support_artifact_ref: str | None = None
    schema_version: str = SUPPORT_AUDIT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != SUPPORT_AUDIT_SCHEMA_VERSION:
            raise _invalid("Unsupported support-access audit version.", code=ErrorCode.SUPPORT_AUDIT_FAILED)
        _timestamp(self.occurred_at, "audit")
        _timestamp(self.issued_at, "issued")
        _timestamp(self.not_before_at, "not-before")
        _timestamp(self.expires_at, "expiry")
        try:
            object.__setattr__(self, "lifecycle", self.lifecycle if isinstance(self.lifecycle, SupportAccessLifecycle) else SupportAccessLifecycle(str(self.lifecycle)))
            object.__setattr__(self, "result", self.result if isinstance(self.result, SupportAccessResult) else SupportAccessResult(str(self.result)))
            object.__setattr__(self, "purpose", self.purpose if isinstance(self.purpose, SupportPurpose) else SupportPurpose(str(self.purpose)))
        except ValueError as exc:
            raise _invalid("Support-access audit contains an unsupported bounded code.", code=ErrorCode.SUPPORT_AUDIT_FAILED) from exc
        for value, label in (
            (self.access_request_ref, "access request reference"), (self.run_ref, "run reference"),
            (self.support_subject_ref, "support subject reference"), (self.support_role_ref, "support role reference"),
            (self.support_capability_ref, "support capability reference"), (self.authority_ref, "authority reference"),
            (self.decision_ref, "decision reference"),
        ):
            _identity(value, label)
        if not isinstance(self.scope_context, AuthorizedScopeContext) or not self.approvals:
            raise _invalid("Support-access audit is incomplete.", code=ErrorCode.SUPPORT_AUDIT_FAILED)
        _identity(self.scope_context.user_ref, "authorized user reference")
        _identity(self.scope_context.workspace_ref, "authorized workspace reference")
        _identity(str(self.scope_context.scope_ref), "authorized scope reference")
        if any(not isinstance(item, SupportApprovalEvidence) for item in self.approvals):
            raise _invalid("Support-access audit approval evidence is invalid.", code=ErrorCode.SUPPORT_AUDIT_FAILED)
        object.__setattr__(self, "allowed_artifact_classes", tuple(_artifact_class(item) for item in self.allowed_artifact_classes))
        object.__setattr__(self, "selected_artifact_classes", tuple(_artifact_class(item) for item in self.selected_artifact_classes))
        if self.support_artifact_ref is not None:
            _identity(self.support_artifact_ref, "support artifact reference")

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "occurred_at": self.occurred_at,
            "lifecycle": self.lifecycle.value,
            "result": self.result.value,
            "access_request_ref": self.access_request_ref,
            "scope_ref": self.scope_context.scope_ref,
            "user_ref": self.scope_context.user_ref,
            "workspace_ref": self.scope_context.workspace_ref,
            "run_ref": self.run_ref,
            "support_subject_ref": self.support_subject_ref,
            "support_role_ref": self.support_role_ref,
            "support_capability_ref": self.support_capability_ref,
            "purpose": self.purpose.value,
            "authority_ref": self.authority_ref,
            "decision_ref": self.decision_ref,
            "approvals": [item.as_dict() for item in self.approvals],
            "allowed_artifact_classes": [item.value for item in self.allowed_artifact_classes],
            "selected_artifact_classes": [item.value for item in self.selected_artifact_classes],
            "issued_at": self.issued_at,
            "not_before_at": self.not_before_at,
            "expires_at": self.expires_at,
            **({"support_artifact_ref": self.support_artifact_ref} if self.support_artifact_ref is not None else {}),
        }

    @classmethod
    def from_dict(cls, value: Any) -> "SupportAccessAudit":
        if not isinstance(value, dict):
            raise _invalid("Support-access audit must be an object.", code=ErrorCode.SUPPORT_AUDIT_FAILED)
        allowed = {
            "schema_version", "occurred_at", "lifecycle", "result", "access_request_ref", "scope_ref", "user_ref", "workspace_ref",
            "run_ref", "support_subject_ref", "support_role_ref", "support_capability_ref", "purpose", "authority_ref", "decision_ref",
            "approvals", "allowed_artifact_classes", "selected_artifact_classes", "issued_at", "not_before_at", "expires_at", "support_artifact_ref",
        }
        if set(value) - allowed:
            raise _invalid("Support-access audit contains unsupported fields.", code=ErrorCode.SUPPORT_AUDIT_FAILED)
        try:
            return cls(
                occurred_at=value["occurred_at"], lifecycle=SupportAccessLifecycle(value["lifecycle"]), result=SupportAccessResult(value["result"]),
                access_request_ref=value["access_request_ref"], scope_context=AuthorizedScopeContext(value["user_ref"], value["workspace_ref"], value["scope_ref"]),
                run_ref=value["run_ref"], support_subject_ref=value["support_subject_ref"], support_role_ref=value["support_role_ref"], support_capability_ref=value["support_capability_ref"],
                purpose=SupportPurpose(value["purpose"]), authority_ref=value["authority_ref"], decision_ref=value["decision_ref"],
                approvals=tuple(SupportApprovalEvidence(item["approval_ref"], SupportApprovalStatus(item["status"])) for item in value["approvals"]),
                allowed_artifact_classes=tuple(SupportArtifactClass(item) for item in value["allowed_artifact_classes"]),
                selected_artifact_classes=tuple(SupportArtifactClass(item) for item in value["selected_artifact_classes"]),
                issued_at=value["issued_at"], not_before_at=value["not_before_at"], expires_at=value["expires_at"],
                support_artifact_ref=value.get("support_artifact_ref"), schema_version=value["schema_version"],
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise _invalid("Support-access audit is malformed.", code=ErrorCode.SUPPORT_AUDIT_FAILED) from exc


class SupportAccessAuditWriter:
    """Source-free audit writer for the central operational plane."""

    def __init__(self, service_root: Path | None = None, *, layout: StorageLayout | None = None) -> None:
        if layout is None:
            if service_root is None:
                raise _invalid("Controlled support requires an explicit central audit root.", code=ErrorCode.SUPPORT_AUDIT_FAILED)
            layout = StorageLayout.for_service(service_root)
        if layout.telemetry_root is None:
            raise _invalid("Controlled support requires an explicit central audit root.", code=ErrorCode.SUPPORT_AUDIT_FAILED)
        self.layout = layout

    @property
    def audit_path(self) -> Path:
        return self.layout.path(StorageArtifact.SUPPORT_ACCESS_AUDIT, "support-access-audit.jsonl", create_parent=True)

    def write(self, record: SupportAccessAudit) -> None:
        if not isinstance(record, SupportAccessAudit):
            raise _invalid("Controlled support audit requires a typed record.", code=ErrorCode.SUPPORT_AUDIT_FAILED)
        path = self.audit_path
        lock = self.layout.path(StorageArtifact.TELEMETRY_COORDINATION_LOCK, ".support-access.lock", create_parent=True)
        line = json.dumps(record.as_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
        try:
            with filesystem_lock(lock):
                with path.open("a", encoding="utf-8") as handle:
                    handle.write(line)
                    handle.flush()
                os.chmod(path, 0o600)
        except OSError as exc:
            raise _invalid("Controlled support audit could not be committed.", code=ErrorCode.SUPPORT_AUDIT_FAILED) from exc

    def records(self) -> tuple[SupportAccessAudit, ...]:
        try:
            lines = self.audit_path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError):
            return ()
        return tuple(SupportAccessAudit.from_dict(json.loads(line)) for line in lines if line)


@dataclass(frozen=True)
class ControlledSupportArtifact:
    artifact_ref: str
    reference: StorageReference
    access_request_ref: str
    scope_context: AuthorizedScopeContext
    run_ref: str
    decision_ref: str
    support_subject_ref: str
    support_role_ref: str
    support_capability_ref: str
    purpose: SupportPurpose
    authority_ref: str
    approvals: tuple[SupportApprovalEvidence, ...]
    allowed_artifact_classes: tuple[SupportArtifactClass, ...]
    selection_identity: str
    selected_artifact_classes: tuple[SupportArtifactClass, ...]
    created_at: str
    expires_at: str
    contract_version: str = SUPPORT_CONTRACT_VERSION

    def __post_init__(self) -> None:
        if self.contract_version != SUPPORT_CONTRACT_VERSION:
            raise _invalid("Unsupported controlled support artifact version.")
        _identity(self.artifact_ref, "support artifact reference")
        _identity(self.access_request_ref, "access request reference")
        _identity(self.run_ref, "run reference")
        _identity(self.decision_ref, "decision reference")
        _identity(self.support_subject_ref, "support subject reference")
        _identity(self.support_role_ref, "support role reference")
        _identity(self.support_capability_ref, "support capability reference")
        _identity(self.authority_ref, "authority reference")
        _identity(self.selection_identity, "selection identity")
        if not isinstance(self.scope_context, AuthorizedScopeContext) or self.reference.artifact is not StorageArtifact.SUPPORT_CONTENT or self.reference.plane is not StoragePlane.DURABLE_USER_WORKSPACE_RUN_DATA:
            raise _invalid("Controlled support artifact storage reference is invalid.")
        _identity(self.scope_context.user_ref, "authorized user reference")
        _identity(self.scope_context.workspace_ref, "authorized workspace reference")
        _identity(str(self.scope_context.scope_ref), "authorized scope reference")
        if self.reference.relative_path != f"support-content/{self.artifact_ref}.zip":
            raise _invalid("Controlled support artifact reference is not canonical.", code=ErrorCode.EXECUTION_CONFLICT)
        if self.reference.scope_ref != self.scope_context.scope_ref or self.reference.run_ref != self.run_ref:
            raise _invalid("Controlled support artifact storage reference is outside its scope.", code=ErrorCode.EXECUTION_CONFLICT)
        try:
            object.__setattr__(self, "purpose", self.purpose if isinstance(self.purpose, SupportPurpose) else SupportPurpose(str(self.purpose)))
        except ValueError as exc:
            raise _invalid("Controlled support artifact purpose is invalid.") from exc
        if not self.approvals or any(not isinstance(item, SupportApprovalEvidence) for item in self.approvals):
            raise _invalid("Controlled support artifact approval evidence is invalid.")
        object.__setattr__(self, "allowed_artifact_classes", tuple(_artifact_class(item) for item in self.allowed_artifact_classes))
        object.__setattr__(self, "selected_artifact_classes", tuple(_artifact_class(item) for item in self.selected_artifact_classes))
        _timestamp(self.created_at, "artifact creation")
        _timestamp(self.expires_at, "artifact expiry")

    def as_dict(self) -> dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "artifact_ref": self.artifact_ref,
            "reference": self.reference.as_dict(),
            "access_request_ref": self.access_request_ref,
            "scope_context": self.scope_context.as_dict(),
            "run_ref": self.run_ref,
            "decision_ref": self.decision_ref,
            "support_subject_ref": self.support_subject_ref,
            "support_role_ref": self.support_role_ref,
            "support_capability_ref": self.support_capability_ref,
            "purpose": self.purpose.value,
            "authority_ref": self.authority_ref,
            "approvals": [item.as_dict() for item in self.approvals],
            "allowed_artifact_classes": [item.value for item in self.allowed_artifact_classes],
            "selection_identity": self.selection_identity,
            "selected_artifact_classes": [item.value for item in self.selected_artifact_classes],
            "created_at": self.created_at,
            "expires_at": self.expires_at,
        }

    @classmethod
    def from_dict(cls, value: Any) -> "ControlledSupportArtifact":
        if not isinstance(value, dict):
            raise _invalid("Controlled support artifact metadata is invalid.", code=ErrorCode.SUPPORT_CONTENT_UNAVAILABLE)
        try:
            return cls(
                contract_version=value["contract_version"], artifact_ref=value["artifact_ref"], reference=StorageReference.from_dict(value["reference"]),
                access_request_ref=value["access_request_ref"], scope_context=AuthorizedScopeContext.from_dict(value["scope_context"]), run_ref=value["run_ref"],
                decision_ref=value["decision_ref"], selection_identity=value["selection_identity"],
                support_subject_ref=value["support_subject_ref"], support_role_ref=value["support_role_ref"], support_capability_ref=value["support_capability_ref"],
                purpose=SupportPurpose(value["purpose"]), authority_ref=value["authority_ref"],
                approvals=tuple(SupportApprovalEvidence(item["approval_ref"], SupportApprovalStatus(item["status"])) for item in value["approvals"]),
                allowed_artifact_classes=tuple(SupportArtifactClass(item) for item in value["allowed_artifact_classes"]),
                selected_artifact_classes=tuple(SupportArtifactClass(item) for item in value["selected_artifact_classes"]), created_at=value["created_at"], expires_at=value["expires_at"],
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise _invalid("Controlled support artifact metadata is malformed.", code=ErrorCode.SUPPORT_CONTENT_UNAVAILABLE) from exc


def _selection_identity(selections: Iterable[SupportContentSelection]) -> str:
    payload = [
        {"artifact_class": item.artifact_class.value, "reference": item.reference.as_dict()}
        for item in selections
    ]
    return "selection-" + hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()[:40]


def _artifact_identity(request: ControlledSupportRequest) -> str:
    payload = {
        "access_request_ref": request.decision.access_request_ref,
        "scope_ref": request.decision.scope_context.scope_ref,
        "run_ref": request.decision.run_ref,
        "decision_ref": request.decision.decision_ref,
        "selection_identity": _selection_identity(request.selections),
    }
    return "support-artifact-" + hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()[:40]


def _decision_binding(value: SupportAuthorizationDecision) -> dict[str, Any]:
    raw = value.as_dict()
    raw.pop("status", None)
    return raw


def _provider_decision(request: ControlledSupportRequest, provider: SupportAuthorizationProvider, *, production: bool) -> SupportAuthorizationDecision:
    if production and getattr(provider, "production_authoritative", False) is not True:
        raise _invalid("Reference controlled support authorization is not a production authority.", code=ErrorCode.SUPPORT_AUTHORITY_UNAVAILABLE)
    resolver = getattr(provider, "resolve", None)
    if not callable(resolver):
        raise _invalid("Controlled support authority lookup is unavailable.", code=ErrorCode.SUPPORT_AUTHORITY_UNAVAILABLE)
    try:
        current = resolver(
            access_request_ref=request.decision.access_request_ref,
            scope_context=request.decision.scope_context,
            run_ref=request.decision.run_ref,
            decision_ref=request.decision.decision_ref,
        )
    except Exception as exc:
        raise _invalid("Controlled support authority lookup failed closed.", code=ErrorCode.SUPPORT_AUTHORITY_UNAVAILABLE) from exc
    if not isinstance(current, SupportAuthorizationDecision) or _decision_binding(current) != _decision_binding(request.decision):
        raise _invalid("Controlled support authority returned an ambiguous or mismatched decision.", code=ErrorCode.SUPPORT_AUTHORITY_UNAVAILABLE)
    return current


def _authorize(request: ControlledSupportRequest, provider: SupportAuthorizationProvider, *, now: datetime, production: bool) -> SupportAuthorizationDecision:
    current = _provider_decision(request, provider, production=production)
    if current.status is SupportDecisionStatus.DENIED:
        raise _invalid("Controlled support authorization was denied.", code=ErrorCode.SUPPORT_AUTHORIZATION_DENIED)
    if current.status is SupportDecisionStatus.REVOKED:
        raise KSlideError(ErrorCode.SUPPORT_AUTHORIZATION_REVOKED, "Controlled support authorization was revoked.", {"lifecycle": SupportAccessLifecycle.REVOKED.value})
    issued = _timestamp(current.issued_at, "issued")
    not_before = _timestamp(current.not_before_at, "not-before")
    expires = _timestamp(current.expires_at, "expiry")
    if now < issued or now < not_before:
        raise _invalid("Controlled support authorization is not yet valid.", code=ErrorCode.SUPPORT_AUTHORIZATION_DENIED)
    if now >= expires:
        raise KSlideError(ErrorCode.SUPPORT_AUTHORIZATION_EXPIRED, "Controlled support authorization has expired.", {"lifecycle": SupportAccessLifecycle.EXPIRED.value})
    if any(item.status is not SupportApprovalStatus.APPROVED for item in current.approvals):
        raise _invalid("Controlled support authorization approvals are incomplete.", code=ErrorCode.SUPPORT_AUTHORIZATION_DENIED)
    return current


def _audit_writer(layout: StorageLayout, writer: SupportAccessAuditWriter | None) -> SupportAccessAuditWriter:
    selected = writer
    if selected is None:
        if layout.telemetry_root is None:
            raise _invalid("Controlled support requires an explicit central audit writer.", code=ErrorCode.SUPPORT_AUDIT_FAILED)
        selected = SupportAccessAuditWriter(layout=layout)
    central = selected.layout.telemetry_root
    if central is None:
        raise _invalid("Controlled support requires an explicit central audit writer.", code=ErrorCode.SUPPORT_AUDIT_FAILED)
    durable = layout.durable_root.resolve()
    central = central.resolve()
    try:
        durable.relative_to(central)
        overlaps = True
    except ValueError:
        try:
            central.relative_to(durable)
            overlaps = True
        except ValueError:
            overlaps = False
    if overlaps:
        raise _invalid("Controlled support audit root must be external to workspace content.", code=ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT)
    return selected


def _audit(
    request: ControlledSupportRequest,
    writer: SupportAccessAuditWriter,
    *,
    now: datetime,
    lifecycle: SupportAccessLifecycle,
    result: SupportAccessResult,
    artifact_ref: str | None = None,
) -> None:
    decision = request.decision
    writer.write(
        SupportAccessAudit(
            occurred_at=_iso(now), lifecycle=lifecycle, result=result,
            access_request_ref=decision.access_request_ref, scope_context=decision.scope_context, run_ref=decision.run_ref,
            support_subject_ref=decision.support_subject_ref, support_role_ref=decision.support_role_ref, support_capability_ref=decision.support_capability_ref,
            purpose=decision.purpose, authority_ref=decision.authority_ref, decision_ref=decision.decision_ref, approvals=decision.approvals,
            allowed_artifact_classes=decision.allowed_artifact_classes,
            selected_artifact_classes=tuple(item.artifact_class for item in request.selections),
            issued_at=decision.issued_at, not_before_at=decision.not_before_at, expires_at=decision.expires_at,
            support_artifact_ref=artifact_ref,
        )
    )


def _failure_lifecycle(error: KSlideError) -> tuple[SupportAccessLifecycle, SupportAccessResult]:
    if error.code is ErrorCode.SUPPORT_AUTHORIZATION_EXPIRED:
        return SupportAccessLifecycle.EXPIRED, SupportAccessResult.EXPIRED
    if error.code is ErrorCode.SUPPORT_AUTHORIZATION_REVOKED:
        return SupportAccessLifecycle.REVOKED, SupportAccessResult.REVOKED
    return SupportAccessLifecycle.DENIED, SupportAccessResult.DENIED


def _safe_content_bytes(data: bytes) -> bytes:
    secret = os.environ.get(ACCESS_KEY_ENV)
    if secret:
        data = data.replace(secret.encode("utf-8"), b"__KSLIDE_SECRET__")
    data = _SECRET_ASSIGNMENT.sub(b"__KSLIDE_SECRET__", data)
    data = _SECRET_LABEL.sub(b"__KSLIDE_SECRET__", data)
    return data.replace(b"__KSLIDE_SECRET__", b"[REDACTED_SECRET]")


def _contains_secret_marker(data: bytes) -> bool:
    secret = os.environ.get(ACCESS_KEY_ENV)
    scrubbed = data.replace(b"[REDACTED_SECRET]", b"")
    return bool(_SECRET_LABEL.search(scrubbed)) or bool(secret and secret.encode("utf-8") in scrubbed)


def _read_selected(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise _invalid("Controlled support selected content is unavailable.", code=ErrorCode.SUPPORT_CONTENT_UNAVAILABLE)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            data = handle.read(_MAX_ARTIFACT_BYTES + 1)
    except OSError as exc:
        raise _invalid("Controlled support selected content is unavailable.", code=ErrorCode.SUPPORT_CONTENT_UNAVAILABLE) from exc
    if len(data) > _MAX_ARTIFACT_BYTES:
        raise _invalid("Controlled support selected content exceeds the bounded support limit.", code=ErrorCode.SUPPORT_CONTENT_UNAVAILABLE)
    return _safe_content_bytes(data)


def _resolve_selected(layout: StorageLayout, selection: SupportContentSelection, decision: SupportAuthorizationDecision) -> Path:
    if layout.scope_ref != decision.scope_context.scope_ref or layout.run_ref != decision.run_ref:
        raise _invalid("Controlled support storage layout is outside the authorized run.", code=ErrorCode.EXECUTION_CONFLICT)
    path = layout.resolve(selection.reference, authorized_scope_ref=str(decision.scope_context.scope_ref), expected_plane=StoragePlane.DURABLE_USER_WORKSPACE_RUN_DATA)
    try:
        path.resolve(strict=False).relative_to(layout.durable_root.resolve(strict=False))
    except (OSError, ValueError) as exc:
        raise _invalid("Controlled support selected content escaped its typed storage plane.", code=ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT) from exc
    return path


def _write_private_zip(path: Path, manifest: dict[str, Any], contents: list[tuple[str, bytes]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.close(descriptor)
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("support-manifest.json", json.dumps(sanitize_operational(manifest), ensure_ascii=False, sort_keys=True, indent=2) + "\n")
            for member, data in contents:
                archive.writestr(member, data)
        os.chmod(temporary, 0o600)
        with temporary.open("rb") as handle:
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        temporary.unlink(missing_ok=True)


def _remove_private(path: Path) -> None:
    if path.is_symlink():
        raise _invalid("Controlled support artifact path is unsafe.", code=ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT)
    path.unlink(missing_ok=True)


def _load_artifact(layout: StorageLayout, reference: StorageReference) -> ControlledSupportArtifact:
    if reference.artifact is not StorageArtifact.SUPPORT_CONTENT:
        raise _invalid("Controlled support artifact reference has the wrong artifact class.", code=ErrorCode.SUPPORT_CONTENT_UNAVAILABLE)
    metadata_path = layout.path(StorageArtifact.SUPPORT_CONTENT, f"support-content/{Path(reference.relative_path).stem}.json")
    if metadata_path.is_symlink() or not metadata_path.is_file():
        raise _invalid("Controlled support artifact metadata is unavailable.", code=ErrorCode.SUPPORT_CONTENT_UNAVAILABLE)
    try:
        return ControlledSupportArtifact.from_dict(json.loads(metadata_path.read_text(encoding="utf-8")))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise _invalid("Controlled support artifact metadata is unavailable.", code=ErrorCode.SUPPORT_CONTENT_UNAVAILABLE) from exc


def _selection_matches_artifact(artifact: ControlledSupportArtifact, request: ControlledSupportRequest) -> None:
    if artifact.reference.scope_ref != request.decision.scope_context.scope_ref or artifact.reference.run_ref != request.decision.run_ref:
        raise _invalid("Controlled support artifact is outside the authorized scope or run.", code=ErrorCode.EXECUTION_CONFLICT)
    if artifact.access_request_ref != request.decision.access_request_ref or artifact.decision_ref != request.decision.decision_ref:
        raise _invalid("Controlled support artifact belongs to a different authorization.", code=ErrorCode.EXECUTION_CONFLICT)
    if artifact.artifact_ref != _artifact_identity(request):
        raise _invalid("Controlled support artifact identity does not match the request.", code=ErrorCode.EXECUTION_CONFLICT)
    if artifact.selection_identity != _selection_identity(request.selections):
        raise _invalid("Controlled support artifact selection does not match the request.", code=ErrorCode.EXECUTION_CONFLICT)


def materialize_controlled_support_bundle(
    layout: StorageLayout,
    request: ControlledSupportRequest,
    *,
    authority: SupportAuthorizationProvider,
    audit_writer: SupportAccessAuditWriter | None = None,
    now: datetime | None = None,
    production: bool = False,
) -> ControlledSupportArtifact:
    """Materialize only explicitly selected content after live authorization."""

    if not isinstance(layout, StorageLayout):
        raise _invalid("Controlled support requires a typed storage layout.")
    writer = _audit_writer(layout, audit_writer)
    current_time = _time(now)
    try:
        current = _authorize(request, authority, now=current_time, production=production)
    except KSlideError as exc:
        lifecycle, result = _failure_lifecycle(exc)
        _audit(request, writer, now=current_time, lifecycle=lifecycle, result=result)
        raise exc
    if layout.scope_ref != current.scope_context.scope_ref or layout.run_ref != current.run_ref:
        _audit(request, writer, now=current_time, lifecycle=SupportAccessLifecycle.DENIED, result=SupportAccessResult.DENIED)
        raise _invalid("Controlled support storage layout is outside the authorized run.", code=ErrorCode.EXECUTION_CONFLICT)

    artifact_ref = _artifact_identity(request)
    selection_identity = _selection_identity(request.selections)
    support_dir = layout.ensure_directory(StorageArtifact.SUPPORT_CONTENT, "support-content")
    bundle_reference = layout.reference(StorageArtifact.SUPPORT_CONTENT, f"support-content/{artifact_ref}.zip")
    bundle_path = layout.resolve(bundle_reference, authorized_scope_ref=str(current.scope_context.scope_ref), expected_plane=StoragePlane.DURABLE_USER_WORKSPACE_RUN_DATA)
    metadata_path = layout.path(StorageArtifact.SUPPORT_CONTENT, f"support-content/{artifact_ref}.json", create_parent=True)
    if bundle_path.exists() or metadata_path.exists():
        if not bundle_path.is_file() or not metadata_path.is_file():
            raise _invalid("Controlled support artifact identity is already occupied.", code=ErrorCode.EXECUTION_CONFLICT)
        existing = _load_artifact(layout, bundle_reference)
        _selection_matches_artifact(existing, request)
        _authorize(request, authority, now=_time(now), production=production)
        _audit(request, writer, now=_time(now), lifecycle=SupportAccessLifecycle.MATERIALIZED, result=SupportAccessResult.SUCCESS, artifact_ref=existing.artifact_ref)
        return existing

    content: list[tuple[str, bytes]] = []
    total = 0
    try:
        for index, selection in enumerate(request.selections, start=1):
            _authorize(request, authority, now=_time(now), production=production)
            source_path = _resolve_selected(layout, selection, current)
            data = _read_selected(source_path)
            total += len(data)
            if total > _MAX_ARTIFACT_BYTES:
                raise _invalid("Controlled support selection exceeds the bounded support limit.", code=ErrorCode.SUPPORT_CONTENT_UNAVAILABLE)
            content.append((f"items/{index:04d}-{selection.artifact_class.value}", data))
    except KSlideError as exc:
        lifecycle, result = _failure_lifecycle(exc)
        _audit(request, writer, now=_time(now), lifecycle=lifecycle, result=result)
        raise

    _authorize(request, authority, now=_time(now), production=production)
    manifest = {
        "schema_version": SUPPORT_CONTRACT_VERSION,
        "support_artifact_ref": artifact_ref,
        "access_request_ref": current.access_request_ref,
        "scope_ref": current.scope_context.scope_ref,
        "run_ref": current.run_ref,
        "purpose": current.purpose.value,
        "selected_artifact_classes": [item.artifact_class.value for item in request.selections],
        "item_count": len(content),
        "expires_at": current.expires_at,
    }
    _write_private_zip(bundle_path, manifest, content)
    artifact = ControlledSupportArtifact(
        artifact_ref=artifact_ref, reference=bundle_reference, access_request_ref=current.access_request_ref,
        scope_context=current.scope_context, run_ref=current.run_ref, decision_ref=current.decision_ref,
        support_subject_ref=current.support_subject_ref, support_role_ref=current.support_role_ref, support_capability_ref=current.support_capability_ref,
        purpose=current.purpose, authority_ref=current.authority_ref, approvals=current.approvals,
        allowed_artifact_classes=current.allowed_artifact_classes,
        selection_identity=selection_identity, selected_artifact_classes=tuple(item.artifact_class for item in request.selections),
        created_at=_iso(current_time), expires_at=current.expires_at,
    )
    try:
        _authorize(request, authority, now=_time(now), production=production)
        atomic_write_json(metadata_path, artifact.as_dict(), mode=0o600)
        _authorize(request, authority, now=_time(now), production=production)
        _audit(request, writer, now=_time(now), lifecycle=SupportAccessLifecycle.MATERIALIZED, result=SupportAccessResult.SUCCESS, artifact_ref=artifact_ref)
    except Exception:
        _remove_private(bundle_path)
        _remove_private(metadata_path)
        raise
    return artifact


def read_controlled_support_bundle(
    layout: StorageLayout,
    request: ControlledSupportRequest,
    artifact: ControlledSupportArtifact,
    *,
    authority: SupportAuthorizationProvider,
    audit_writer: SupportAccessAuditWriter | None = None,
    now: datetime | None = None,
    production: bool = False,
) -> bytes:
    """Read a controlled copy only after a fresh authoritative decision check."""

    writer = _audit_writer(layout, audit_writer)
    current_time = _time(now)
    try:
        _authorize(request, authority, now=current_time, production=production)
        _selection_matches_artifact(artifact, request)
        stored = _load_artifact(layout, artifact.reference)
        if stored != artifact:
            raise _invalid("Controlled support artifact metadata does not match the typed artifact.", code=ErrorCode.EXECUTION_CONFLICT)
        resolved = layout.resolve(stored.reference, authorized_scope_ref=str(request.decision.scope_context.scope_ref), expected_plane=StoragePlane.DURABLE_USER_WORKSPACE_RUN_DATA)
        if resolved.is_symlink() or not resolved.is_file():
            raise _invalid("Controlled support artifact is unavailable.", code=ErrorCode.SUPPORT_CONTENT_UNAVAILABLE)
        if resolved.stat().st_size > _MAX_ARTIFACT_BYTES:
            raise _invalid("Controlled support artifact exceeds the bounded support limit.", code=ErrorCode.SUPPORT_CONTENT_UNAVAILABLE)
        data = resolved.read_bytes()
        if _contains_secret_marker(data):
            raise _invalid("Controlled support artifact failed secret-safety validation.", code=ErrorCode.SUPPORT_CONTENT_UNAVAILABLE)
        _authorize(request, authority, now=_time(now), production=production)
        try:
            with zipfile.ZipFile(resolved) as archive:
                names = archive.namelist()
                if names.count("support-manifest.json") != 1 or any(not re.fullmatch(r"items/\d{4}-[a-z_]+", name) for name in names if name != "support-manifest.json"):
                    raise _invalid("Controlled support artifact has an invalid member set.", code=ErrorCode.SUPPORT_CONTENT_UNAVAILABLE)
                for name in names:
                    if _contains_secret_marker(archive.read(name)):
                        raise _invalid("Controlled support artifact failed secret-safety validation.", code=ErrorCode.SUPPORT_CONTENT_UNAVAILABLE)
        except zipfile.BadZipFile as exc:
            raise _invalid("Controlled support artifact is unavailable.", code=ErrorCode.SUPPORT_CONTENT_UNAVAILABLE) from exc
        _audit(request, writer, now=_time(now), lifecycle=SupportAccessLifecycle.ACCESSED, result=SupportAccessResult.SUCCESS, artifact_ref=artifact.artifact_ref)
        return data
    except KSlideError as exc:
        lifecycle, result = _failure_lifecycle(exc)
        _audit(request, writer, now=_time(now), lifecycle=lifecycle, result=result, artifact_ref=artifact.artifact_ref)
        raise


def cleanup_expired_support_content(
    root: Path,
    *,
    scope_context: AuthorizedScopeContext,
    hold_provider: Any,
    operational_root: Path,
    now: datetime | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Remove expired controlled copies without changing ordinary run TTLs."""

    if not isinstance(scope_context, AuthorizedScopeContext) or scope_context.scope_ref != "workspace":
        raise _invalid("Controlled support cleanup requires an authorized workspace scope context.", code=ErrorCode.EXECUTION_CONFLICT)
    if hold_provider is None:
        raise _invalid("Controlled support cleanup requires an authoritative legal-hold provider.", code=ErrorCode.LEGAL_HOLD_UNKNOWN)
    current = _time(now)
    root = Path(root).expanduser().resolve()
    operational_root = Path(operational_root).expanduser().resolve()
    try:
        operational_root.relative_to(root)
        overlaps = True
    except ValueError:
        try:
            root.relative_to(operational_root)
            overlaps = True
        except ValueError:
            overlaps = False
    if overlaps or operational_root == root:
        raise _invalid("Controlled support audit root must be external to workspace content.", code=ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT)
    writer = SupportAccessAuditWriter(service_root=operational_root)
    run_root = root / ".k-slide-runs"
    removed: list[str] = []
    retained: list[str] = []
    planned: list[str] = []
    if not run_root.exists():
        return {"status": "PASS", "dry_run": dry_run, "removed": removed, "planned": planned, "retained": retained}
    if run_root.is_symlink() or not run_root.is_dir():
        raise _invalid("Controlled support cleanup run root is unsafe.", code=ErrorCode.RETENTION_REFUSED)
    for run_dir in sorted(run_root.iterdir(), key=lambda item: item.name):
        if run_dir.name.startswith("_"):
            continue
        if run_dir.is_symlink():
            raise _invalid("Controlled support cleanup refuses symbolic-link runs.", code=ErrorCode.RETENTION_REFUSED)
        if not run_dir.is_dir():
            continue
        layout = StorageLayout.for_workspace(run_dir, central_telemetry_root=operational_root)
        support_dir = run_dir / "support-content"
        if not support_dir.exists():
            continue
        if support_dir.is_symlink() or not support_dir.is_dir():
            raise _invalid("Controlled support cleanup refuses an unsafe support directory.", code=ErrorCode.RETENTION_REFUSED)
        for metadata_path in sorted(support_dir.glob("*.json"), key=lambda item: item.name):
            if metadata_path.is_symlink():
                raise _invalid("Controlled support cleanup refuses symbolic-link support metadata.", code=ErrorCode.RETENTION_REFUSED)
            try:
                artifact = ControlledSupportArtifact.from_dict(json.loads(metadata_path.read_text(encoding="utf-8")))
            except (OSError, UnicodeError, json.JSONDecodeError, KSlideError) as exc:
                raise _invalid("Controlled support metadata is corrupt.", code=ErrorCode.RETENTION_REFUSED) from exc
            if artifact.run_ref != run_dir.name or artifact.scope_context != scope_context:
                raise _invalid("Controlled support metadata is outside the authorized workspace scope.", code=ErrorCode.EXECUTION_CONFLICT)
            if current < _timestamp(artifact.expires_at, "artifact expiry"):
                retained.append(artifact.artifact_ref)
                continue
            try:
                hold = hold_provider.lookup(scope_ref="workspace", run_ref=run_dir.name)
                status = getattr(getattr(hold, "status", None), "value", getattr(hold, "status", None))
                if status not in {"RELEASE", "HOLD", "UNKNOWN"}:
                    raise ValueError("invalid legal-hold decision")
                if status != "RELEASE":
                    retained.append(artifact.artifact_ref)
                    continue
            except Exception as exc:
                raise _invalid("Controlled support cleanup legal-hold lookup failed closed.", code=ErrorCode.LEGAL_HOLD_UNKNOWN) from exc
            if dry_run:
                planned.append(artifact.artifact_ref)
                continue
            bundle_path = layout.resolve(artifact.reference, authorized_scope_ref="workspace", expected_plane=StoragePlane.DURABLE_USER_WORKSPACE_RUN_DATA)
            _remove_private(bundle_path)
            _remove_private(metadata_path)
            removed.append(artifact.artifact_ref)
            # Cleanup audits are constructed directly so cleanup does not
            # manufacture a new authorization or read any source artifact.
            writer.write(
                SupportAccessAudit(
                    occurred_at=_iso(current), lifecycle=SupportAccessLifecycle.CLEANED, result=SupportAccessResult.CLEANED,
                    access_request_ref=artifact.access_request_ref, scope_context=artifact.scope_context, run_ref=artifact.run_ref,
                    support_subject_ref=artifact.support_subject_ref, support_role_ref=artifact.support_role_ref, support_capability_ref=artifact.support_capability_ref,
                    purpose=artifact.purpose, authority_ref=artifact.authority_ref, decision_ref=artifact.decision_ref,
                    approvals=artifact.approvals,
                    allowed_artifact_classes=artifact.allowed_artifact_classes, selected_artifact_classes=artifact.selected_artifact_classes,
                    issued_at=artifact.created_at, not_before_at=artifact.created_at, expires_at=artifact.expires_at,
                    support_artifact_ref=artifact.artifact_ref,
                )
            )
    return {"status": "PASS", "dry_run": dry_run, "removed": removed, "planned": planned, "retained": retained}


def _deleted_support_audit(artifact: ControlledSupportArtifact, *, occurred_at: datetime | None = None) -> SupportAccessAudit:
    return SupportAccessAudit(
        occurred_at=_iso(occurred_at or datetime.now(timezone.utc)), lifecycle=SupportAccessLifecycle.DELETED, result=SupportAccessResult.DELETED,
        access_request_ref=artifact.access_request_ref, scope_context=artifact.scope_context, run_ref=artifact.run_ref,
        support_subject_ref=artifact.support_subject_ref, support_role_ref=artifact.support_role_ref, support_capability_ref=artifact.support_capability_ref,
        purpose=artifact.purpose, authority_ref=artifact.authority_ref, decision_ref=artifact.decision_ref, approvals=artifact.approvals,
        allowed_artifact_classes=artifact.allowed_artifact_classes, selected_artifact_classes=artifact.selected_artifact_classes,
        issued_at=artifact.created_at, not_before_at=artifact.created_at, expires_at=artifact.expires_at, support_artifact_ref=artifact.artifact_ref,
    )


def prepare_deleted_support_artifacts(support_dir: Path) -> tuple[ControlledSupportArtifact, ...]:
    """Snapshot source-free support metadata before the controlled copies are unlinked."""

    if not support_dir.exists():
        return ()
    if support_dir.is_symlink() or not support_dir.is_dir():
        raise _invalid("Controlled support deletion namespace is unsafe.", code=ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT)
    prepared: list[ControlledSupportArtifact] = []
    for metadata_path in sorted(support_dir.glob("*.json"), key=lambda item: item.name):
        if metadata_path.is_symlink():
            raise _invalid("Controlled support deletion metadata is unsafe.", code=ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT)
        try:
            artifact = ControlledSupportArtifact.from_dict(json.loads(metadata_path.read_text(encoding="utf-8")))
        except (OSError, UnicodeError, json.JSONDecodeError, KSlideError) as exc:
            raise _invalid("Controlled support deletion metadata is corrupt.", code=ErrorCode.SUPPORT_AUDIT_FAILED) from exc
        if metadata_path.name != f"{artifact.artifact_ref}.json":
            raise _invalid("Controlled support deletion metadata is not canonical.", code=ErrorCode.SUPPORT_AUDIT_FAILED)
        prepared.append(artifact)
    return tuple(prepared)


def record_deleted_support_artifacts(
    artifacts: Iterable[ControlledSupportArtifact],
    *,
    service_root: Path,
) -> None:
    """Record KSA-13 deletion facts after the corresponding copies are gone."""

    prepared = tuple(artifacts)
    if any(not isinstance(item, ControlledSupportArtifact) for item in prepared):
        raise _invalid("Controlled support deletion audit metadata is invalid.", code=ErrorCode.SUPPORT_AUDIT_FAILED)
    writer = SupportAccessAuditWriter(service_root=service_root)
    for artifact in prepared:
        writer.write(_deleted_support_audit(artifact))


def cleanup_support_access_audit(
    operational_root: Path,
    *,
    scope_ref: str,
    cutoff: datetime,
    hold_lookup: Callable[..., Any],
    dry_run: bool = False,
) -> dict[str, Any]:
    """Apply operational-metadata retention to the support audit stream."""

    root = Path(operational_root).expanduser().resolve()
    paths = [root / "support-access-audit.jsonl", root / "telemetry" / "support-access-audit.jsonl"]
    expired: list[str] = []
    retained: list[str] = []
    for path in paths:
        if not (path.exists() or path.is_symlink()):
            continue
        if path.is_symlink() or not path.resolve(strict=False).is_relative_to(root):
            raise _invalid("Support-access audit path is unsafe.", code=ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT)
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError) as exc:
            raise _invalid("Support-access audit records are unreadable.", code=ErrorCode.SUPPORT_AUDIT_FAILED) from exc
        kept: list[str] = []
        changed = False
        for line in lines:
            if not line:
                continue
            try:
                record = SupportAccessAudit.from_dict(json.loads(line))
            except (KSlideError, TypeError, ValueError, json.JSONDecodeError) as exc:
                raise _invalid("Support-access audit records are malformed.", code=ErrorCode.SUPPORT_AUDIT_FAILED) from exc
            occurred = _timestamp(record.occurred_at, "audit")
            if record.scope_context.scope_ref != scope_ref or occurred >= cutoff:
                retained.append(record.support_artifact_ref or record.access_request_ref)
                kept.append(json.dumps(record.as_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")))
                continue
            try:
                hold = hold_lookup(scope_ref=record.scope_context.scope_ref, run_ref=record.run_ref)
                hold_state = str(getattr(getattr(hold, "status", None), "value", getattr(hold, "status", None)))
                if hold_state not in {"RELEASE", "HOLD", "UNKNOWN"}:
                    raise ValueError("invalid legal-hold decision")
            except Exception as exc:
                raise _invalid("Support-access audit legal-hold lookup failed closed.", code=ErrorCode.LEGAL_HOLD_UNKNOWN) from exc
            if hold_state != "RELEASE":
                retained.append(record.support_artifact_ref or record.access_request_ref)
                kept.append(json.dumps(record.as_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")))
                continue
            changed = True
            expired.append(record.support_artifact_ref or record.access_request_ref)
        if changed and not dry_run:
            atomic_write_text(path, "\n".join(kept) + ("\n" if kept else ""), mode=0o600)
    return {"expired": expired, "retained": retained, "dry_run": dry_run}


__all__ = [
    "ControlledSupportArtifact", "ControlledSupportRequest", "ReferenceSupportAuthorizationProvider", "SupportAccessAudit", "SupportAccessAuditWriter",
    "SupportAccessLifecycle", "SupportAccessResult", "SupportApprovalEvidence", "SupportApprovalStatus", "SupportArtifactClass",
    "SupportAuthorizationDecision", "SupportAuthorizationProvider", "SupportContentSelection", "SupportDecisionStatus", "SupportPurpose",
    "cleanup_expired_support_content", "materialize_controlled_support_bundle", "read_controlled_support_bundle",
    "cleanup_support_access_audit", "prepare_deleted_support_artifacts", "record_deleted_support_artifacts",
]
