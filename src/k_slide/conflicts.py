"""Engine-owned run-level conflict and supersession registry.

Conflict participants are references to existing canonical semantic objects.  This
module never accepts replacement source text as canonical state: the reference
is rebuilt from the current SlideIR and EvidenceIR and compared byte-for-byte
with the stored audit context during verification.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Iterable

from .errors import ErrorCode, KSlideError
from .evidence_ir import EvidenceIR, load_evidence, stable_revision
from .io import atomic_write_json, read_json
from .ir import SlideIR
from .queue import WorkUnitStatus, load_queue
from .security import sha256_file
from .semantics import ProvenanceState, enum_value
from .storage import StorageArtifact, storage_path, workspace_mutation_guard


CONFLICT_REGISTRY_SCHEMA_VERSION = "1.0"
CONFLICT_REGISTRY_FILE = "CONFLICT_REGISTRY.json"
CONFLICT_CONTRACT_VERSION = "1.0"
AUTHORITY_POLICY_VERSION = "1.0"
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class ConflictResolutionState(str, Enum):
    """Closed states for a contradiction at the run level."""

    UNRESOLVED = "unresolved"
    RESOLVED_BY_AUTHORITATIVE_SUPERSESSION = "resolved_by_authoritative_supersession"


class ConflictAssessmentState(str, Enum):
    """Durable run-level conflict assessment states."""

    NOT_ASSESSED = "NOT_ASSESSED"
    ASSESSED_ZERO_CONFLICTS = "ASSESSED_ZERO_CONFLICTS"
    ASSESSED_CONFLICTS = "ASSESSED_CONFLICTS"
    LEGACY_NOT_ASSESSED = "LEGACY_NOT_ASSESSED"


class AssertionKind(str, Enum):
    REGION = "region"
    TABLE_CELL = "table_cell"
    VISUAL_RELATION = "visual_relation"
    EXECUTIVE_CLAIM = "executive_claim"
    NUMERIC_FACT = "numeric_fact"


class SupersessionState(str, Enum):
    """Only an explicitly supported authority may create a supersession."""

    AUTHORITATIVE = "authoritative"


class SupersessionAuthorityBasis(str, Enum):
    EXPLICIT_EVIDENCE = "explicit_evidence"
    CONFIGURED_AUTHORITY = "configured_authority"


def _error(message: str, *, code: ErrorCode = ErrorCode.CONFLICT_INVALID, details: dict[str, Any] | None = None) -> KSlideError:
    return KSlideError(code, message, details or {})


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise _error(f"Conflict {label} is invalid.", code=ErrorCode.SCHEMA_INVALID, details={label: value})
    return value


def _non_empty(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise _error(f"Conflict {label} must be a non-empty string.", code=ErrorCode.SCHEMA_INVALID)
    return value


def _string_tuple(value: Any, label: str, *, non_empty: bool = True) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or any(not isinstance(item, str) or (non_empty and not item) for item in value):
        raise _error(f"Conflict {label} must be an array of strings.", code=ErrorCode.SCHEMA_INVALID)
    return tuple(value)


def _only_fields(value: dict[str, Any], allowed: set[str], label: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise _error(f"Conflict {label} contains unsupported fields.", code=ErrorCode.SCHEMA_INVALID, details={"fields": unknown})


def _stable_id(prefix: str, value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"{prefix}-{hashlib.sha256(encoded).hexdigest()}"


def assertion_id_for(document_id: str, work_unit_id: str, semantic_kind: str, semantic_id: str) -> str:
    """Return the stable identity for one source-backed canonical assertion."""

    return _stable_id("assertion", [document_id, work_unit_id, semantic_kind, semantic_id])


def conflict_id_for(assertion_ids: Iterable[str]) -> str:
    return _stable_id("conflict", ["contradiction", sorted(set(assertion_ids))])


def supersession_id_for(
    conflict_id: str,
    superseding: str,
    superseded: str,
    basis: str,
    authority_refs: Iterable[dict[str, Any]],
    config_id: str | None,
    authority_relation: dict[str, Any] | None = None,
    authority_config_revision: str | None = None,
) -> str:
    refs = sorted(list(authority_refs), key=lambda item: json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    value: list[Any] = [conflict_id, superseding, superseded, basis, refs, config_id]
    if authority_relation is not None or authority_config_revision is not None:
        value.extend([authority_relation, authority_config_revision])
    return _stable_id("supersession", value)


def _authority_relation(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise _error("Supersession authority_relation must be an object.", code=ErrorCode.SCHEMA_INVALID)
    required = {
        "relation_type",
        "superseding_assertion_id",
        "superseded_assertion_id",
        "superseding_evidence_ids",
        "superseded_evidence_ids",
        "authority_evidence_ids",
    }
    _only_fields(value, required, "authority relation")
    if set(value) != required:
        raise _error("Supersession authority_relation is missing required fields.", code=ErrorCode.SCHEMA_INVALID)
    if value.get("relation_type") != "supersedes":
        raise _error("Supersession authority relation type is unsupported.", code=ErrorCode.SCHEMA_INVALID)
    for field in ("superseding_assertion_id", "superseded_assertion_id"):
        _identifier(value.get(field), field)
    if value["superseding_assertion_id"] == value["superseded_assertion_id"]:
        raise _error("Supersession authority relation cannot self-supersede.", code=ErrorCode.SUPERSESSION_INVALID)
    relation = dict(value)
    for field in ("superseding_evidence_ids", "superseded_evidence_ids", "authority_evidence_ids"):
        values = _string_tuple(value.get(field), f"authority_relation.{field}")
        if len(values) != len(set(values)):
            raise _error("Supersession authority relation evidence IDs must be distinct.", code=ErrorCode.SCHEMA_INVALID)
        relation[field] = list(values)
    return relation


@dataclass(frozen=True)
class AssertionReference:
    """A durable pointer to one current canonical semantic object."""

    assertion_id: str
    document_id: str
    work_unit_id: str
    semantic_kind: str
    semantic_id: str
    canonical_ref: dict[str, Any]
    evidence_ref: dict[str, Any]
    location: dict[str, Any]
    provenance: str
    provenance_evidence_ids: tuple[str, ...]
    source_context: dict[str, Any]
    rendered_context: dict[str, Any]
    provenance_reason: str | None = None

    def as_dict(self) -> dict[str, Any]:
        value = {
            "assertion_id": self.assertion_id,
            "document_id": self.document_id,
            "work_unit_id": self.work_unit_id,
            "semantic_kind": self.semantic_kind,
            "semantic_id": self.semantic_id,
            "canonical_ref": self.canonical_ref,
            "evidence_ref": self.evidence_ref,
            "location": self.location,
            "provenance": self.provenance,
            "provenance_evidence_ids": list(self.provenance_evidence_ids),
            "source_context": self.source_context,
            "rendered_context": self.rendered_context,
        }
        if self.provenance_reason is not None:
            value["provenance_reason"] = self.provenance_reason
        return value

    @classmethod
    def from_dict(cls, value: Any) -> "AssertionReference":
        if not isinstance(value, dict):
            raise _error("Conflict participant must be an object.", code=ErrorCode.SCHEMA_INVALID)
        required = {
            "assertion_id", "document_id", "work_unit_id", "semantic_kind", "semantic_id",
            "canonical_ref", "evidence_ref", "location", "provenance", "provenance_evidence_ids",
            "source_context", "rendered_context",
        }
        _only_fields(value, required | {"provenance_reason"}, "participant")
        missing = sorted(required - set(value))
        if missing:
            raise _error("Conflict participant is missing required fields.", code=ErrorCode.SCHEMA_INVALID, details={"fields": missing})
        if any(not isinstance(value.get(field), dict) for field in ("canonical_ref", "evidence_ref", "location", "source_context", "rendered_context")):
            raise _error("Conflict participant reference/context fields must be objects.", code=ErrorCode.SCHEMA_INVALID)
        semantic_kind = value.get("semantic_kind")
        try:
            semantic_kind = AssertionKind(semantic_kind).value
        except ValueError as exc:
            raise _error("Conflict participant has an unsupported semantic kind.", code=ErrorCode.SCHEMA_INVALID) from exc
        provenance = enum_value(value.get("provenance"), ProvenanceState, "conflict participant provenance")
        evidence_ids = _string_tuple(value.get("provenance_evidence_ids"), "provenance_evidence_ids")
        reason = value.get("provenance_reason")
        if reason is not None and (not isinstance(reason, str) or not reason.strip()):
            raise _error("Conflict participant provenance_reason must be non-empty when present.", code=ErrorCode.SCHEMA_INVALID)
        if provenance == ProvenanceState.UNRESOLVED.value and reason is None:
            raise _error("Unresolved conflict participants require provenance_reason.", code=ErrorCode.SCHEMA_INVALID)
        if provenance != ProvenanceState.UNRESOLVED.value and reason is not None:
            raise _error("Only unresolved conflict participants may carry provenance_reason.", code=ErrorCode.SCHEMA_INVALID)
        return cls(
            assertion_id=_identifier(value.get("assertion_id"), "assertion_id"),
            document_id=_identifier(value.get("document_id"), "document_id"),
            work_unit_id=_identifier(value.get("work_unit_id"), "work_unit_id"),
            semantic_kind=semantic_kind,
            semantic_id=_identifier(value.get("semantic_id"), "semantic_id"),
            canonical_ref=dict(value["canonical_ref"]),
            evidence_ref=dict(value["evidence_ref"]),
            location=dict(value["location"]),
            provenance=provenance,
            provenance_evidence_ids=evidence_ids,
            source_context=dict(value["source_context"]),
            rendered_context=dict(value["rendered_context"]),
            provenance_reason=reason,
        )


@dataclass(frozen=True)
class AuthorityEvidenceReference:
    """Exact current EvidenceIR references that establish authority."""

    document_id: str
    work_unit_id: str
    evidence_revision: str
    evidence_ids: tuple[str, ...]
    location: dict[str, Any]
    source_context: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "document_id": self.document_id,
            "work_unit_id": self.work_unit_id,
            "evidence_revision": self.evidence_revision,
            "evidence_ids": list(self.evidence_ids),
            "location": self.location,
            "source_context": self.source_context,
        }

    @classmethod
    def from_dict(cls, value: Any) -> "AuthorityEvidenceReference":
        if not isinstance(value, dict):
            raise _error("Supersession authority evidence must be an object.", code=ErrorCode.SCHEMA_INVALID)
        required = {"document_id", "work_unit_id", "evidence_revision", "evidence_ids", "location", "source_context"}
        _only_fields(value, required, "authority evidence")
        missing = sorted(required - set(value))
        if missing:
            raise _error("Supersession authority evidence is missing required fields.", code=ErrorCode.SCHEMA_INVALID, details={"fields": missing})
        if not isinstance(value.get("location"), dict) or not isinstance(value.get("source_context"), dict):
            raise _error("Supersession authority evidence location/context must be objects.", code=ErrorCode.SCHEMA_INVALID)
        revision = value.get("evidence_revision")
        if not isinstance(revision, str) or not re.fullmatch(r"[a-f0-9]{64}", revision):
            raise _error("Supersession authority evidence revision is invalid.", code=ErrorCode.SCHEMA_INVALID)
        return cls(
            document_id=_identifier(value.get("document_id"), "document_id"),
            work_unit_id=_identifier(value.get("work_unit_id"), "work_unit_id"),
            evidence_revision=revision,
            evidence_ids=_string_tuple(value.get("evidence_ids"), "authority evidence_ids"),
            location=dict(value["location"]),
            source_context=dict(value["source_context"]),
        )


@dataclass(frozen=True)
class Supersession:
    supersession_id: str
    conflict_id: str
    superseding_assertion_id: str
    superseded_assertion_id: str
    state: str = SupersessionState.AUTHORITATIVE.value
    authority_basis: str = SupersessionAuthorityBasis.EXPLICIT_EVIDENCE.value
    authority_evidence: tuple[AuthorityEvidenceReference, ...] = ()
    authority_config_id: str | None = None
    authority_relation: dict[str, Any] | None = None
    authority_config_revision: str | None = None

    def as_dict(self) -> dict[str, Any]:
        value = {
            "supersession_id": self.supersession_id,
            "conflict_id": self.conflict_id,
            "superseding_assertion_id": self.superseding_assertion_id,
            "superseded_assertion_id": self.superseded_assertion_id,
            "state": self.state,
            "authority_basis": self.authority_basis,
            "authority_evidence": [item.as_dict() for item in sorted(self.authority_evidence, key=lambda item: (item.work_unit_id, item.evidence_ids))],
            "authority_config_id": self.authority_config_id,
        }
        if self.authority_relation is not None:
            value["authority_relation"] = self.authority_relation
        if self.authority_config_revision is not None:
            value["authority_config_revision"] = self.authority_config_revision
        return value

    @classmethod
    def from_dict(cls, value: Any) -> "Supersession":
        if not isinstance(value, dict):
            raise _error("Supersession must be an object.", code=ErrorCode.SCHEMA_INVALID)
        required = {
            "supersession_id", "conflict_id", "superseding_assertion_id", "superseded_assertion_id",
            "state", "authority_basis", "authority_evidence", "authority_config_id",
        }
        _only_fields(value, required | {"authority_relation", "authority_config_revision"}, "supersession")
        missing = sorted(required - set(value))
        if missing:
            raise _error("Supersession is missing required fields.", code=ErrorCode.SCHEMA_INVALID, details={"fields": missing})
        try:
            state = SupersessionState(value.get("state")).value
            basis = SupersessionAuthorityBasis(value.get("authority_basis")).value
        except ValueError as exc:
            raise _error("Supersession state or authority basis is unsupported.", code=ErrorCode.SCHEMA_INVALID) from exc
        authority_config_id = value.get("authority_config_id")
        if authority_config_id is not None:
            authority_config_id = _identifier(authority_config_id, "authority_config_id")
        authority_config_revision = value.get("authority_config_revision")
        if authority_config_revision is not None and (not isinstance(authority_config_revision, str) or not re.fullmatch(r"[a-f0-9]{64}", authority_config_revision)):
            raise _error("Supersession authority_config_revision is invalid.", code=ErrorCode.SCHEMA_INVALID)
        evidence = value.get("authority_evidence")
        if not isinstance(evidence, list):
            raise _error("Supersession authority_evidence must be an array.", code=ErrorCode.SCHEMA_INVALID)
        return cls(
            supersession_id=_identifier(value.get("supersession_id"), "supersession_id"),
            conflict_id=_identifier(value.get("conflict_id"), "conflict_id"),
            superseding_assertion_id=_identifier(value.get("superseding_assertion_id"), "superseding_assertion_id"),
            superseded_assertion_id=_identifier(value.get("superseded_assertion_id"), "superseded_assertion_id"),
            state=state,
            authority_basis=basis,
            authority_evidence=tuple(AuthorityEvidenceReference.from_dict(item) for item in evidence),
            authority_config_id=authority_config_id,
            authority_relation=_authority_relation(value.get("authority_relation")),
            authority_config_revision=authority_config_revision,
        )


@dataclass(frozen=True)
class Conflict:
    conflict_id: str
    participants: tuple[AssertionReference, ...]
    resolution_state: str = ConflictResolutionState.UNRESOLVED.value
    supersession_ids: tuple[str, ...] = ()
    conflict_type: str = "contradiction"

    def as_dict(self) -> dict[str, Any]:
        return {
            "conflict_id": self.conflict_id,
            "conflict_type": self.conflict_type,
            "resolution_state": self.resolution_state,
            "participants": [item.as_dict() for item in sorted(self.participants, key=lambda item: item.assertion_id)],
            "supersession_ids": sorted(self.supersession_ids),
        }

    @classmethod
    def from_dict(cls, value: Any) -> "Conflict":
        if not isinstance(value, dict):
            raise _error("Conflict must be an object.", code=ErrorCode.SCHEMA_INVALID)
        required = {"conflict_id", "conflict_type", "resolution_state", "participants", "supersession_ids"}
        _only_fields(value, required, "conflict")
        missing = sorted(required - set(value))
        if missing:
            raise _error("Conflict is missing required fields.", code=ErrorCode.SCHEMA_INVALID, details={"fields": missing})
        try:
            state = ConflictResolutionState(value.get("resolution_state")).value
        except ValueError as exc:
            raise _error("Conflict resolution_state is unsupported.", code=ErrorCode.SCHEMA_INVALID) from exc
        participants = value.get("participants")
        if not isinstance(participants, list):
            raise _error("Conflict participants must be an array.", code=ErrorCode.SCHEMA_INVALID)
        if value.get("conflict_type") != "contradiction":
            raise _error("Conflict type is unsupported.", code=ErrorCode.SCHEMA_INVALID)
        return cls(
            conflict_id=_identifier(value.get("conflict_id"), "conflict_id"),
            conflict_type="contradiction",
            resolution_state=state,
            participants=tuple(AssertionReference.from_dict(item) for item in participants),
            supersession_ids=_string_tuple(value.get("supersession_ids"), "supersession_ids"),
        )


@dataclass(frozen=True)
class ConflictRegistry:
    run_id: str
    conflicts: tuple[Conflict, ...] = ()
    supersessions: tuple[Supersession, ...] = ()
    registry_revision: str = ""
    schema_version: str = CONFLICT_REGISTRY_SCHEMA_VERSION
    assessment_status: str = ""

    def effective_assessment_status(self) -> str:
        if self.assessment_status:
            return ConflictAssessmentState(self.assessment_status).value
        return (
            ConflictAssessmentState.ASSESSED_CONFLICTS.value
            if self.conflicts
            else ConflictAssessmentState.ASSESSED_ZERO_CONFLICTS.value
        )

    def without_revision(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "assessment_status": self.effective_assessment_status(),
            "conflicts": [item.as_dict() for item in sorted(self.conflicts, key=lambda item: item.conflict_id)],
            "supersessions": [item.as_dict() for item in sorted(self.supersessions, key=lambda item: item.supersession_id)],
        }

    def computed_revision(self) -> str:
        return stable_revision(self.without_revision())

    def as_dict(self) -> dict[str, Any]:
        value = self.without_revision()
        value["registry_revision"] = self.registry_revision or self.computed_revision()
        return value

    @classmethod
    def from_dict(cls, value: Any) -> "ConflictRegistry":
        if not isinstance(value, dict):
            raise _error("Conflict registry must be an object.", code=ErrorCode.SCHEMA_INVALID)
        required = {"schema_version", "run_id", "conflicts", "supersessions", "registry_revision"}
        _only_fields(value, required | {"assessment_status"}, "registry")
        missing = sorted(required - set(value))
        if missing:
            raise _error("Conflict registry is missing required fields.", code=ErrorCode.SCHEMA_INVALID, details={"fields": missing})
        if value.get("schema_version") != CONFLICT_REGISTRY_SCHEMA_VERSION:
            raise _error("Unsupported conflict registry schema version.", code=ErrorCode.SCHEMA_INVALID)
        conflicts = value.get("conflicts")
        supersessions = value.get("supersessions")
        if not isinstance(conflicts, list) or not isinstance(supersessions, list):
            raise _error("Conflict registry conflicts and supersessions must be arrays.", code=ErrorCode.SCHEMA_INVALID)
        assessment_status_present = "assessment_status" in value
        registry = cls(
            run_id=_identifier(value.get("run_id"), "run_id"),
            conflicts=tuple(Conflict.from_dict(item) for item in conflicts),
            supersessions=tuple(Supersession.from_dict(item) for item in supersessions),
            registry_revision=_non_empty(value.get("registry_revision"), "registry_revision"),
            schema_version=value.get("schema_version"),
            assessment_status=str(value.get("assessment_status", "")),
        )
        if not assessment_status_present:
            legacy_contents = {key: value[key] for key in ("schema_version", "run_id", "conflicts", "supersessions")}
            if registry.registry_revision != stable_revision(legacy_contents):
                raise _error(
                    "Conflict registry revision does not match its deterministic contents.",
                    code=ErrorCode.STALE_EVIDENCE,
                    details={"expected": stable_revision(legacy_contents), "actual": registry.registry_revision},
                )
            registry = cls(
                run_id=registry.run_id,
                conflicts=registry.conflicts,
                supersessions=registry.supersessions,
                schema_version=registry.schema_version,
                assessment_status=registry.effective_assessment_status(),
            )
            registry = cls(
                run_id=registry.run_id,
                conflicts=registry.conflicts,
                supersessions=registry.supersessions,
                registry_revision=registry.computed_revision(),
                schema_version=registry.schema_version,
                assessment_status=registry.assessment_status,
            )
        if registry.registry_revision != registry.computed_revision():
            raise _error(
                "Conflict registry revision does not match its deterministic contents.",
                code=ErrorCode.STALE_EVIDENCE,
                details={"expected": registry.computed_revision(), "actual": registry.registry_revision},
            )
        registry.validate_structure()
        return registry

    def validate_structure(self) -> None:
        if self.schema_version != CONFLICT_REGISTRY_SCHEMA_VERSION:
            raise _error("Unsupported conflict registry schema version.", code=ErrorCode.SCHEMA_INVALID)
        _identifier(self.run_id, "run_id")
        try:
            assessment_status = self.effective_assessment_status()
        except ValueError as exc:
            raise _error("Conflict registry assessment status is unsupported.", code=ErrorCode.SCHEMA_INVALID) from exc
        expected_assessment_status = (
            ConflictAssessmentState.ASSESSED_CONFLICTS.value
            if self.conflicts
            else ConflictAssessmentState.ASSESSED_ZERO_CONFLICTS.value
        )
        if assessment_status != expected_assessment_status:
            raise _error("Conflict registry assessment status does not match its contents.", code=ErrorCode.CONFLICT_INVALID)
        if self.registry_revision and self.registry_revision != self.computed_revision():
            raise _error("Conflict registry revision does not match its deterministic contents.", code=ErrorCode.STALE_EVIDENCE)
        conflict_ids = [item.conflict_id for item in self.conflicts]
        supersession_ids = [item.supersession_id for item in self.supersessions]
        if len(conflict_ids) != len(set(conflict_ids)):
            raise _error("Conflict registry contains duplicate conflict IDs.")
        if len(supersession_ids) != len(set(supersession_ids)):
            raise _error("Conflict registry contains duplicate supersession IDs.")
        seen_assertions: set[str] = set()
        for conflict in self.conflicts:
            try:
                resolution_state = ConflictResolutionState(conflict.resolution_state).value
            except ValueError as exc:
                raise _error("Conflict resolution_state is unsupported.", code=ErrorCode.SCHEMA_INVALID) from exc
            if conflict.conflict_type != "contradiction":
                raise _error("Conflict type is unsupported.", code=ErrorCode.SCHEMA_INVALID)
            if conflict.conflict_id != conflict_id_for(item.assertion_id for item in conflict.participants):
                raise _error("Conflict ID is not stable for its participants.", details={"conflict_id": conflict.conflict_id})
            if len(conflict.participants) < 2:
                raise _error("Every conflict must retain at least two competing assertions.", details={"conflict_id": conflict.conflict_id})
            ids = [item.assertion_id for item in conflict.participants]
            if len(ids) != len(set(ids)):
                raise _error("Conflict participants must be distinct.", details={"conflict_id": conflict.conflict_id})
            if len({(item.document_id, item.work_unit_id, item.semantic_kind, item.semantic_id) for item in conflict.participants}) != len(ids):
                raise _error("Conflict participants must point to distinct canonical assertions.", details={"conflict_id": conflict.conflict_id})
            for participant in conflict.participants:
                if participant.assertion_id != assertion_id_for(participant.document_id, participant.work_unit_id, participant.semantic_kind, participant.semantic_id):
                    raise _error("Assertion identity is not stable for its canonical source object.", code=ErrorCode.CONFLICT_REFERENCE_INVALID)
            if resolution_state == ConflictResolutionState.UNRESOLVED.value and conflict.supersession_ids:
                raise _error("Unresolved conflict may not carry supersessions.", details={"conflict_id": conflict.conflict_id})
            if resolution_state == ConflictResolutionState.RESOLVED_BY_AUTHORITATIVE_SUPERSESSION.value and not conflict.supersession_ids:
                raise _error("Resolved conflict requires an authoritative supersession.", details={"conflict_id": conflict.conflict_id})
            seen_assertions.update(ids)
        known_conflicts = set(conflict_ids)
        referenced_supersessions = {sid for conflict in self.conflicts for sid in conflict.supersession_ids}
        if referenced_supersessions != set(supersession_ids):
            raise _error("Conflict registry supersession references are not bidirectionally complete.")
        graph: dict[str, set[str]] = {}
        for supersession in self.supersessions:
            try:
                supersession_state = SupersessionState(supersession.state).value
                authority_basis = SupersessionAuthorityBasis(supersession.authority_basis).value
            except ValueError as exc:
                raise _error("Supersession state or authority basis is unsupported.", code=ErrorCode.SCHEMA_INVALID) from exc
            if supersession_state != SupersessionState.AUTHORITATIVE.value:
                raise _error("Only authoritative supersessions may be recorded.", code=ErrorCode.SUPERSESSION_INVALID)
            if supersession.conflict_id not in known_conflicts:
                raise _error("Supersession references an unknown conflict.", code=ErrorCode.SUPERSESSION_INVALID)
            conflict = next(item for item in self.conflicts if item.conflict_id == supersession.conflict_id)
            participant_ids = {item.assertion_id for item in conflict.participants}
            if supersession.superseding_assertion_id == supersession.superseded_assertion_id:
                raise _error("Self-supersession is invalid.", code=ErrorCode.SUPERSESSION_INVALID)
            if {supersession.superseding_assertion_id, supersession.superseded_assertion_id} - participant_ids:
                raise _error("Supersession must reference two assertions in its conflict.", code=ErrorCode.SUPERSESSION_INVALID)
            if authority_basis == SupersessionAuthorityBasis.EXPLICIT_EVIDENCE.value and (not supersession.authority_evidence or supersession.authority_config_id is not None or supersession.authority_config_revision is not None):
                raise _error("Explicit-evidence supersession requires authority evidence and no configured winner.", code=ErrorCode.SUPERSESSION_INVALID)
            if authority_basis == SupersessionAuthorityBasis.CONFIGURED_AUTHORITY.value and (supersession.authority_evidence or supersession.authority_config_id is None):
                raise _error("Configured supersession requires a configured authority identity only.", code=ErrorCode.SUPERSESSION_INVALID)
            expected_supersession_id = supersession_id_for(
                supersession.conflict_id,
                supersession.superseding_assertion_id,
                supersession.superseded_assertion_id,
                authority_basis,
                (item.as_dict() for item in supersession.authority_evidence),
                supersession.authority_config_id,
                supersession.authority_relation,
                supersession.authority_config_revision,
            )
            if supersession.supersession_id != expected_supersession_id:
                raise _error("Supersession identity is not stable for its exact authority references.", code=ErrorCode.SUPERSESSION_INVALID)
            if supersession.authority_relation is not None:
                _authority_relation(supersession.authority_relation)
                relation = supersession.authority_relation
                if relation["superseding_assertion_id"] != supersession.superseding_assertion_id or relation["superseded_assertion_id"] != supersession.superseded_assertion_id:
                    raise _error("Supersession authority relation does not bind the declared assertion pair.", code=ErrorCode.SUPERSESSION_INVALID)
                evidence_ids = sorted({evidence_id for item in supersession.authority_evidence for evidence_id in item.evidence_ids})
                if relation["authority_evidence_ids"] != evidence_ids:
                    raise _error("Supersession authority relation does not bind the exact authority evidence.", code=ErrorCode.SUPERSESSION_INVALID)
            graph.setdefault(supersession.superseding_assertion_id, set()).add(supersession.superseded_assertion_id)
        winners_by_conflict: dict[str, set[str]] = {}
        for supersession in self.supersessions:
            winners_by_conflict.setdefault(supersession.conflict_id, set()).add(supersession.superseding_assertion_id)
        if any(len(winners) > 1 for winners in winners_by_conflict.values()):
            raise _error("A conflict may not have conflicting authoritative winners.", code=ErrorCode.SUPERSESSION_INVALID)
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(node: str) -> None:
            if node in visiting:
                raise _error("Supersession graph contains a cycle.", code=ErrorCode.SUPERSESSION_INVALID)
            if node in visited:
                return
            visiting.add(node)
            for child in sorted(graph.get(node, ())):
                visit(child)
            visiting.remove(node)
            visited.add(node)

        for node in sorted(graph):
            visit(node)

    def validate_against_run(
        self,
        run_dir: Path,
        *,
        configured_authority_ids: Iterable[str] = (),
        authority_policy: dict[str, Any] | None = None,
        strict_authority: bool = False,
    ) -> None:
        """Validate all references against current queue, canonical IR and EvidenceIR."""

        self.validate_structure()
        queue = load_queue(run_dir)
        if self.run_id != queue.run_id:
            raise _error("Conflict registry run_id does not match WORK_QUEUE.json.", details={"expected": queue.run_id, "actual": self.run_id})
        expected_authority = set(configured_authority_ids)
        for conflict in self.conflicts:
            expected_ids = {item.assertion_id for item in conflict.participants}
            for participant in conflict.participants:
                expected = build_assertion_reference(run_dir, participant.work_unit_id, participant.semantic_kind, participant.semantic_id)
                if participant.as_dict() != expected.as_dict():
                    raise _error(
                        "Conflict participant does not match current canonical/evidence state.",
                        code=ErrorCode.CONFLICT_REFERENCE_INVALID,
                        details={"assertion_id": participant.assertion_id, "work_unit_id": participant.work_unit_id},
                    )
            conflict_supersessions = [item for item in self.supersessions if item.conflict_id == conflict.conflict_id]
            for supersession in conflict_supersessions:
                if supersession.state != SupersessionState.AUTHORITATIVE.value:
                    raise _error("Supersession state is not authoritative.", code=ErrorCode.SUPERSESSION_INVALID)
                if supersession.authority_basis == SupersessionAuthorityBasis.EXPLICIT_EVIDENCE.value:
                    if not supersession.authority_evidence or supersession.authority_config_id is not None or supersession.authority_config_revision is not None:
                        raise _error("Explicit-evidence supersession requires authority evidence and no config winner.", code=ErrorCode.SUPERSESSION_INVALID)
                    if strict_authority and supersession.authority_relation is None:
                        raise _error("KSA-23 explicit-evidence supersession requires a typed authority relation.", code=ErrorCode.SUPERSESSION_INVALID)
                elif supersession.authority_basis == SupersessionAuthorityBasis.CONFIGURED_AUTHORITY.value:
                    if supersession.authority_evidence or supersession.authority_config_id not in expected_authority:
                        raise _error("Configured supersession authority is unsupported or unavailable.", code=ErrorCode.SUPERSESSION_INVALID)
                    if strict_authority:
                        if (
                            authority_policy is None
                            or supersession.authority_config_revision != authority_policy_revision(authority_policy)
                            or not _configured_policy_allows(authority_policy, supersession, conflict)
                        ):
                            raise _error("Configured supersession does not match the bound deterministic authority policy.", code=ErrorCode.SUPERSESSION_INVALID)
                else:
                    raise _error("Unknown supersession authority cannot choose a winner.", code=ErrorCode.SUPERSESSION_INVALID)
                for authority in supersession.authority_evidence:
                    expected_authority_ref = build_authority_evidence_reference(run_dir, authority.work_unit_id, authority.evidence_ids)
                    if authority.as_dict() != expected_authority_ref.as_dict():
                        raise _error("Supersession authority evidence is stale or fabricated.", code=ErrorCode.SUPERSESSION_INVALID, details={"work_unit_id": authority.work_unit_id})
                if strict_authority and supersession.authority_basis == SupersessionAuthorityBasis.EXPLICIT_EVIDENCE.value:
                    _validate_explicit_authority_relation(supersession, conflict)
                if supersession.superseding_assertion_id not in expected_ids or supersession.superseded_assertion_id not in expected_ids:
                    raise _error("Supersession points outside its conflict participants.", code=ErrorCode.SUPERSESSION_INVALID)

    def validate(
        self,
        run_dir: Path | None = None,
        *,
        configured_authority_ids: Iterable[str] = (),
        authority_policy: dict[str, Any] | None = None,
        strict_authority: bool = False,
    ) -> None:
        if run_dir is None:
            self.validate_structure()
        else:
            self.validate_against_run(
                run_dir,
                configured_authority_ids=configured_authority_ids,
                authority_policy=authority_policy,
                strict_authority=strict_authority,
            )


def _source_context(evidence: EvidenceIR, evidence_ids: Iterable[str]) -> tuple[dict[str, Any], dict[str, Any]]:
    region_map = {item.region_id: item for item in evidence.regions}
    cell_map = {cell.cell_id: (table, cell) for table in evidence.tables for cell in table.cells}
    facts = {str(item.get("fact_id")): item for item in evidence.numeric_facts if isinstance(item, dict) and item.get("fact_id")}
    items: list[dict[str, Any]] = []
    boxes: list[list[int]] = []
    languages: list[str] = []
    for evidence_id in evidence_ids:
        if evidence_id in region_map:
            region = region_map[evidence_id]
            text = region.selected_literal_candidate
            language = region.language
            bbox = list(region.bbox_px)
        elif evidence_id in cell_map:
            table, cell = cell_map[evidence_id]
            linked = [region_map[item] for item in cell.evidence_region_ids if item in region_map]
            text = cell.source_text
            language = next((item.language for item in linked if item.language), None)
            bbox = list(linked[0].bbox_px) if linked else list(table.bbox_px)
        elif evidence_id in facts:
            fact = facts[evidence_id]
            text = str(fact.get("source_string", ""))
            linked = region_map.get(str(fact.get("source_region_id")))
            language = linked.language if linked else None
            bbox = list(linked.bbox_px) if linked else [0, 0, 0, 0]
        else:
            text = None
            language = None
            bbox = [0, 0, 0, 0]
        item = {"evidence_id": evidence_id, "language": language, "text": text, "bbox_px": bbox}
        items.append(item)
        if language:
            languages.append(language)
        if bbox != [0, 0, 0, 0]:
            boxes.append(bbox)
    language = languages[0] if languages and len(set(languages)) == 1 else ("mixed" if languages else None)
    text_values = [str(item["text"]) for item in items if item.get("text") is not None]
    return (
        {"language": language, "text": " | ".join(text_values), "items": items},
        {"bboxes_px": boxes},
    )


def build_authority_evidence_reference(run_dir: Path, work_unit_id: str, evidence_ids: Iterable[str]) -> AuthorityEvidenceReference:
    queue = load_queue(run_dir)
    unit = queue.get(work_unit_id)
    evidence = load_evidence(run_dir, work_unit_id)
    if unit.evidence_revision and unit.evidence_revision != evidence.evidence_revision:
        raise _error("Authority evidence work-unit binding is stale.", code=ErrorCode.STALE_EVIDENCE)
    ids = tuple(evidence_ids)
    valid_ids = _all_evidence_ids(evidence)
    if not ids or any(item not in valid_ids for item in ids):
        raise _error("Authority evidence references unknown EvidenceIR objects.", code=ErrorCode.CONFLICT_REFERENCE_INVALID)
    context, location_context = _source_context(evidence, ids)
    location = {
        "document_id": unit.document_id,
        "work_unit_id": work_unit_id,
        "source_index": unit.source_index,
        "evidence_ids": list(ids),
        **location_context,
    }
    return AuthorityEvidenceReference(unit.document_id, work_unit_id, evidence.evidence_revision, ids, location, context)


def _all_evidence_ids(evidence: EvidenceIR) -> set[str]:
    return (
        {item.region_id for item in evidence.regions}
        | {item.table_id for item in evidence.tables}
        | {cell.cell_id for table in evidence.tables for cell in table.cells}
        | {str(item.get("fact_id")) for item in evidence.numeric_facts if isinstance(item, dict) and item.get("fact_id")}
        | {str(item.get("element_id")) for item in evidence.visual_elements if isinstance(item, dict) and item.get("element_id")}
    )


def _run_manifest(run_dir: Path) -> dict[str, Any]:
    path = storage_path(run_dir, StorageArtifact.RUN_MANIFEST, "RUN_MANIFEST.json")
    if not path.is_file():
        return {}
    value = read_json(path)
    if not isinstance(value, dict):
        raise _error("RUN_MANIFEST.json must contain an object.", code=ErrorCode.SCHEMA_INVALID)
    return value


def conflict_contract_required(run_dir: Path) -> bool:
    """Return whether this run was created under the KSA-23 assessment contract."""

    contract = _run_manifest(run_dir).get("conflict_registry_contract")
    if contract is None:
        return False
    if not isinstance(contract, dict) or contract.get("schema_version") != CONFLICT_CONTRACT_VERSION or contract.get("assessment_required") is not True:
        raise _error("Conflict registry contract is malformed.", code=ErrorCode.SCHEMA_INVALID)
    return True


_SELECTOR_FIELDS = {"document_id", "work_unit_id", "semantic_kind", "source_index"}
_AUTHORITY_RULE_FIELDS = {"authority_config_id", "priority", "winner_selector", "loser_selector"}


def conflict_authority_policy(run_dir: Path) -> dict[str, Any]:
    """Load and validate the closed, run-bound authority policy."""

    authority = _run_manifest(run_dir).get("conflict_authority")
    if authority is None:
        return {"schema_version": AUTHORITY_POLICY_VERSION, "rules": []}
    if not isinstance(authority, dict):
        raise _error("Conflict authority policy must be an object.", code=ErrorCode.SCHEMA_INVALID)
    if "schema_version" not in authority and set(authority) <= {"configured_authority_ids"}:
        return {"schema_version": AUTHORITY_POLICY_VERSION, "rules": []}
    if authority.get("schema_version") != AUTHORITY_POLICY_VERSION:
        raise _error("Conflict authority policy version is unsupported.", code=ErrorCode.SCHEMA_INVALID)
    if set(authority) - {"schema_version", "rules", "configured_authority_ids"}:
        raise _error("Conflict authority policy contains unsupported fields.", code=ErrorCode.SCHEMA_INVALID)
    rules = authority.get("rules", [])
    if not isinstance(rules, list):
        raise _error("Conflict authority policy rules must be an array.", code=ErrorCode.SCHEMA_INVALID)
    normalized: list[dict[str, Any]] = []
    for rule in rules:
        if not isinstance(rule, dict) or set(rule) != _AUTHORITY_RULE_FIELDS:
            raise _error("Conflict authority policy rules must be closed selector rules.", code=ErrorCode.SCHEMA_INVALID)
        config_id = _identifier(rule.get("authority_config_id"), "authority_config_id")
        priority = rule.get("priority")
        if isinstance(priority, bool) or not isinstance(priority, int):
            raise _error("Conflict authority policy priority must be an integer.", code=ErrorCode.SCHEMA_INVALID)
        selectors: dict[str, dict[str, Any]] = {}
        for name in ("winner_selector", "loser_selector"):
            selector = rule.get(name)
            if not isinstance(selector, dict) or not set(selector) or set(selector) - _SELECTOR_FIELDS:
                raise _error("Conflict authority policy selector is unsupported or empty.", code=ErrorCode.SCHEMA_INVALID)
            clean: dict[str, Any] = {}
            for field, value in selector.items():
                if field in {"document_id", "work_unit_id", "semantic_kind"}:
                    if not isinstance(value, str) or not value:
                        raise _error("Conflict authority policy selector value is invalid.", code=ErrorCode.SCHEMA_INVALID)
                elif isinstance(value, bool) or not isinstance(value, int):
                    raise _error("Conflict authority policy source_index selector is invalid.", code=ErrorCode.SCHEMA_INVALID)
                clean[field] = value
            selectors[name] = clean
        normalized.append({"authority_config_id": config_id, "priority": priority, **selectors})
    configured_ids = authority.get("configured_authority_ids")
    if configured_ids is not None:
        ids = _string_tuple(configured_ids, "configured_authority_ids")
        if set(ids) != {rule["authority_config_id"] for rule in normalized}:
            raise _error("Configured authority IDs must match the closed policy rules.", code=ErrorCode.SCHEMA_INVALID)
    return {"schema_version": AUTHORITY_POLICY_VERSION, "rules": normalized}


def configured_authority_ids(run_dir: Path) -> set[str]:
    policy = conflict_authority_policy(run_dir)
    return {rule["authority_config_id"] for rule in policy["rules"]}


def authority_policy_revision(policy: dict[str, Any]) -> str:
    return stable_revision(policy)


def _selector_matches(selector: dict[str, Any], participant: AssertionReference) -> bool:
    values = {
        "document_id": participant.document_id,
        "work_unit_id": participant.work_unit_id,
        "semantic_kind": participant.semantic_kind,
        "source_index": participant.location.get("source_index"),
    }
    return all(values.get(field) == expected for field, expected in selector.items())


def _configured_policy_allows(policy: dict[str, Any], supersession: Supersession, conflict: Conflict) -> bool:
    participants = {item.assertion_id: item for item in conflict.participants}
    winner = participants.get(supersession.superseding_assertion_id)
    loser = participants.get(supersession.superseded_assertion_id)
    if winner is None or loser is None:
        return False
    rules = [rule for rule in policy.get("rules", []) if rule["authority_config_id"] == supersession.authority_config_id]
    matches = [rule for rule in rules if _selector_matches(rule["winner_selector"], winner) and _selector_matches(rule["loser_selector"], loser)]
    opposite = [rule for rule in rules if _selector_matches(rule["winner_selector"], loser) and _selector_matches(rule["loser_selector"], winner)]
    if not matches or opposite:
        return False
    highest = max(rule["priority"] for rule in matches)
    return sum(rule["priority"] == highest for rule in matches) == 1


def _validate_explicit_authority_relation(supersession: Supersession, conflict: Conflict) -> None:
    relation = _authority_relation(supersession.authority_relation)
    if relation is None:
        raise _error("Explicit-evidence supersession requires a typed authority relation.", code=ErrorCode.SUPERSESSION_INVALID)
    participants = {item.assertion_id: item for item in conflict.participants}
    winner = participants.get(supersession.superseding_assertion_id)
    loser = participants.get(supersession.superseded_assertion_id)
    if winner is None or loser is None:
        raise _error("Supersession authority relation references unknown participants.", code=ErrorCode.SUPERSESSION_INVALID)
    if relation["superseding_assertion_id"] != winner.assertion_id or relation["superseded_assertion_id"] != loser.assertion_id:
        raise _error("Supersession authority relation reverses or omits the declared winner.", code=ErrorCode.SUPERSESSION_INVALID)
    if relation["superseding_evidence_ids"] != sorted(set(winner.provenance_evidence_ids)) or relation["superseded_evidence_ids"] != sorted(set(loser.provenance_evidence_ids)):
        raise _error("Supersession authority relation does not bind the exact competing assertion evidence.", code=ErrorCode.SUPERSESSION_INVALID)
    expected_authority_ids = sorted({evidence_id for item in supersession.authority_evidence for evidence_id in item.evidence_ids})
    if relation["authority_evidence_ids"] != expected_authority_ids:
        raise _error("Supersession authority relation does not bind the exact current authority evidence.", code=ErrorCode.SUPERSESSION_INVALID)
    authority_text = " ".join(str(item.source_context.get("text", "")) for item in supersession.authority_evidence)
    targets = re.findall(r"AUTHORITY_SUPERSEDES\s*[:=]\s*(assertion-[A-Za-z0-9._:-]{1,127})\b", authority_text, re.IGNORECASE)
    if len(targets) != 1:
        raise _error(
            "Explicit authority evidence must contain exactly one engine-verifiable AUTHORITY_SUPERSEDES target.",
            code=ErrorCode.SUPERSESSION_INVALID,
        )
    if targets[0] != winner.assertion_id:
        raise _error("Explicit authority evidence names a different superseding assertion.", code=ErrorCode.SUPERSESSION_INVALID)


def _validate_assertion_provenance(
    provenance: str,
    evidence_ids: list[str],
    evidence: EvidenceIR,
    *,
    semantic_kind: str,
    semantic_id: str,
    reason: str | None,
    unresolved_flag: bool | None = None,
) -> None:
    effective = enum_value(provenance, ProvenanceState, "conflict assertion provenance")
    if not evidence_ids or any(item not in _all_evidence_ids(evidence) for item in evidence_ids):
        raise _error("Conflict assertion provenance cites invalid EvidenceIR objects.", code=ErrorCode.CONFLICT_REFERENCE_INVALID)
    if effective == ProvenanceState.UNRESOLVED.value:
        if not isinstance(reason, str) or not reason.strip():
            raise _error("Unresolved conflict assertion provenance requires a reason.", code=ErrorCode.CONFLICT_REFERENCE_INVALID)
        if unresolved_flag is False:
            raise _error("Conflict assertion unresolved provenance conflicts with unresolved=false.", code=ErrorCode.CONFLICT_REFERENCE_INVALID)
    elif reason is not None:
        raise _error("Resolved conflict assertion provenance may not carry an unresolved reason.", code=ErrorCode.CONFLICT_REFERENCE_INVALID)
    if effective == ProvenanceState.SOURCE_FACT.value and semantic_kind in {AssertionKind.REGION.value, AssertionKind.TABLE_CELL.value} and semantic_id not in evidence_ids:
        raise _error("Source-fact conflict assertions must cite their direct EvidenceIR source ID.", code=ErrorCode.CONFLICT_REFERENCE_INVALID)


def build_assertion_reference(run_dir: Path, work_unit_id: str, semantic_kind: str, semantic_id: str) -> AssertionReference:
    """Build an assertion from current engine artifacts; callers cannot supply its context."""

    try:
        kind = AssertionKind(semantic_kind).value
    except ValueError as exc:
        raise _error("Unsupported conflict assertion kind.", code=ErrorCode.SCHEMA_INVALID) from exc
    queue = load_queue(run_dir)
    unit = queue.get(work_unit_id)
    evidence = load_evidence(run_dir, work_unit_id)
    if unit.evidence_revision and unit.evidence_revision != evidence.evidence_revision:
        raise _error("Conflict assertion work-unit evidence binding is stale.", code=ErrorCode.STALE_EVIDENCE)
    canonical_path = storage_path(run_dir, StorageArtifact.CANONICAL_IR, f"ir/{work_unit_id}.json")
    if not canonical_path.is_file():
        raise _error("Conflict assertion requires current canonical SlideIR.", code=ErrorCode.CONFLICT_REFERENCE_INVALID)
    value = read_json(canonical_path)
    slide = SlideIR.from_dict(value, evidence=evidence)
    if slide.evidence_revision != evidence.evidence_revision:
        raise _error("Conflict assertion points to a stale EvidenceIR revision.", code=ErrorCode.STALE_EVIDENCE)
    canonical_sha = sha256_file(canonical_path)
    semantic_id = _identifier(semantic_id, "semantic_id")
    evidence_ids: list[str]
    rendered_text: str | None
    provenance: str
    provenance_reason: str | None = None
    unresolved_flag: bool | None = None
    json_pointer: str
    location_extra: dict[str, Any] = {}
    if kind == AssertionKind.REGION.value:
        item = next((candidate for candidate in slide.regions if candidate.region_id == semantic_id), None)
        source = next((candidate for candidate in evidence.regions if candidate.region_id == semantic_id), None)
        if item is None or source is None:
            raise _error("Conflict assertion region does not exist in current canonical/evidence state.", code=ErrorCode.CONFLICT_REFERENCE_INVALID)
        evidence_ids = list(item.provenance_evidence_ids)
        rendered_text = item.translation
        provenance = item.provenance or ProvenanceState.SUPPORTED_INTERPRETATION.value
        provenance_reason = item.unresolved_reason
        json_pointer = f"/regions/{next(index for index, candidate in enumerate(slide.regions) if candidate.region_id == semantic_id)}"
    elif kind == AssertionKind.TABLE_CELL.value:
        found = next(((table, cell) for table in slide.tables for cell in table.cells if cell.cell_id == semantic_id), None)
        if found is None:
            raise _error("Conflict assertion table cell does not exist in current canonical state.", code=ErrorCode.CONFLICT_REFERENCE_INVALID)
        table, item = found
        evidence_ids = list(item.provenance_evidence_ids)
        rendered_text = item.translation
        provenance = item.provenance or (ProvenanceState.UNRESOLVED.value if item.unresolved else ProvenanceState.SUPPORTED_INTERPRETATION.value)
        provenance_reason = item.unresolved_reason
        unresolved_flag = item.unresolved
        table_index = next(index for index, candidate in enumerate(slide.tables) if candidate.table_id == table.table_id)
        cell_index = next(index for index, candidate in enumerate(table.cells) if candidate.cell_id == semantic_id)
        json_pointer = f"/tables/{table_index}/cells/{cell_index}"
        location_extra.update({"table_id": table.table_id, "row": item.row, "column": item.column})
    elif kind == AssertionKind.VISUAL_RELATION.value:
        item = next((candidate for candidate in slide.visual_relations if candidate.relation_id == semantic_id), None)
        if item is None:
            raise _error("Conflict assertion visual relation does not exist in current canonical state.", code=ErrorCode.CONFLICT_REFERENCE_INVALID)
        evidence_ids = list(item.evidence)
        rendered_text = item.interpretation
        provenance = item.provenance or ProvenanceState.SUPPORTED_INTERPRETATION.value
        provenance_reason = item.unresolved_reason
        json_pointer = f"/visual_relations/{next(index for index, candidate in enumerate(slide.visual_relations) if candidate.relation_id == semantic_id)}"
    elif kind == AssertionKind.EXECUTIVE_CLAIM.value:
        claims = slide.executive_semantics.get("executive_claims", [])
        item = next((candidate for candidate in claims if isinstance(candidate, dict) and candidate.get("claim_id") == semantic_id), None)
        if item is None:
            raise _error("Conflict assertion executive claim does not exist in current canonical state.", code=ErrorCode.CONFLICT_REFERENCE_INVALID)
        evidence_ids = list(item.get("evidence_ids", []))
        rendered_text = item.get("text")
        provenance = str(item.get("provenance") or ProvenanceState.SUPPORTED_INTERPRETATION.value)
        provenance_reason = item.get("unresolved_reason")
        json_pointer = f"/executive_semantics/executive_claims/{next(index for index, candidate in enumerate(claims) if isinstance(candidate, dict) and candidate.get('claim_id') == semantic_id)}"
    else:
        item = next((candidate for candidate in slide.numeric_facts if candidate.fact_id == semantic_id), None)
        source = next((candidate for candidate in evidence.numeric_facts if isinstance(candidate, dict) and str(candidate.get("fact_id")) == semantic_id), None)
        if item is None or source is None:
            raise _error("Conflict assertion numeric fact does not exist in current canonical/evidence state.", code=ErrorCode.CONFLICT_REFERENCE_INVALID)
        evidence_ids = [semantic_id]
        if item.source_region_id:
            evidence_ids.append(item.source_region_id)
        if item.source_cell_id:
            evidence_ids.append(item.source_cell_id)
        evidence_ids = list(dict.fromkeys(evidence_ids))
        rendered_text = next((candidate.translation for candidate in slide.regions if candidate.region_id == item.source_region_id), None)
        if rendered_text is None:
            rendered_text = next((cell.translation for table in slide.tables for cell in table.cells if cell.cell_id == item.source_cell_id), None)
        provenance = ProvenanceState.SOURCE_FACT.value
        json_pointer = f"/numeric_facts/{next(index for index, candidate in enumerate(slide.numeric_facts) if candidate.fact_id == semantic_id)}"

    if not evidence_ids or any(item not in _all_evidence_ids(evidence) for item in evidence_ids):
        raise _error("Conflict assertion has invalid EvidenceIR references.", code=ErrorCode.CONFLICT_REFERENCE_INVALID)
    _validate_assertion_provenance(
        provenance,
        evidence_ids,
        evidence,
        semantic_kind=kind,
        semantic_id=semantic_id,
        reason=provenance_reason,
        unresolved_flag=unresolved_flag,
    )
    context, location_context = _source_context(evidence, evidence_ids)
    location = {
        "document_id": unit.document_id,
        "work_unit_id": work_unit_id,
        "slide_id": work_unit_id,
        "source_index": unit.source_index,
        "source_object_id": semantic_id,
        "source_kind": kind,
        "evidence_ids": list(evidence_ids),
        **location_context,
        **location_extra,
    }
    canonical_ref = {
        "artifact": "canonical_ir",
        "path": f"ir/{work_unit_id}.json",
        "json_pointer": json_pointer,
        "work_unit_id": work_unit_id,
        "object_kind": kind,
        "object_id": semantic_id,
        "canonical_sha256": canonical_sha,
        "translation_revision": slide.translation_revision,
    }
    evidence_ref = {
        "artifact": "evidence_ir",
        "path": f"evidence/{work_unit_id}.json",
        "work_unit_id": work_unit_id,
        "evidence_revision": evidence.evidence_revision,
        "evidence_ids": list(evidence_ids),
    }
    return AssertionReference(
        assertion_id=assertion_id_for(unit.document_id, work_unit_id, kind, semantic_id),
        document_id=unit.document_id,
        work_unit_id=work_unit_id,
        semantic_kind=kind,
        semantic_id=semantic_id,
        canonical_ref=canonical_ref,
        evidence_ref=evidence_ref,
        location=location,
        provenance=enum_value(provenance, ProvenanceState, "conflict assertion provenance"),
        provenance_evidence_ids=tuple(evidence_ids),
        source_context=context,
        rendered_context={"language": "en", "text": rendered_text or ""},
        provenance_reason=provenance_reason,
    )


def _typed_candidate_keys(candidate_groups: Any) -> list[tuple[tuple[str, str, str], ...]]:
    if candidate_groups is None:
        return []
    if not isinstance(candidate_groups, list):
        raise _error("Conflict candidate_groups must be an array.", code=ErrorCode.SCHEMA_INVALID)
    result: list[tuple[tuple[str, str, str], ...]] = []
    for group in candidate_groups:
        if not isinstance(group, dict) or set(group) != {"assertions"} or not isinstance(group["assertions"], list):
            raise _error("Conflict candidate groups must contain only typed assertion references.", code=ErrorCode.SCHEMA_INVALID)
        keys: list[tuple[str, str, str]] = []
        for reference in group["assertions"]:
            if not isinstance(reference, dict) or set(reference) != {"work_unit_id", "semantic_kind", "semantic_id"}:
                raise _error("Conflict candidate references may contain only canonical object identities.", code=ErrorCode.SCHEMA_INVALID)
            try:
                semantic_kind = AssertionKind(reference["semantic_kind"]).value
            except ValueError as exc:
                raise _error("Conflict candidate reference has an unsupported semantic kind.", code=ErrorCode.SCHEMA_INVALID) from exc
            keys.append((_identifier(reference["work_unit_id"], "work_unit_id"), semantic_kind, _identifier(reference["semantic_id"], "semantic_id")))
        if len(keys) < 2 or len(set(keys)) != len(keys):
            raise _error("Conflict candidate groups require distinct competing assertions.", code=ErrorCode.CONFLICT_INVALID)
        result.append(tuple(sorted(keys)))
    return result


def assess_conflicts(run_dir: Path, *, candidate_groups: Any = None) -> ConflictRegistry:
    """Engine-owned conflict admission for the real K-Slide lifecycle.

    The model may add only canonical object identities.  The engine rebuilds
    every assertion reference and persists either unresolved conflicts or an
    explicit zero-conflict registry.  Ambiguous contradictions are never
    inferred from differing text or a broad executive-claim kind.
    """

    queue = load_queue(run_dir)
    if not queue.work_units or any(unit.status not in {WorkUnitStatus.TRANSLATED, WorkUnitStatus.VERIFIED} for unit in queue.work_units):
        raise _error("Conflict assessment requires every work unit to have a current canonical translation.", code=ErrorCode.CONFLICT_INVALID)
    groups = set(_typed_candidate_keys(candidate_groups))
    current = load_conflict_registry(run_dir)
    if current is not None:
        current.validate_against_run(
            run_dir,
            configured_authority_ids=configured_authority_ids(run_dir),
            authority_policy=conflict_authority_policy(run_dir),
            strict_authority=conflict_contract_required(run_dir),
        )
    conflicts_by_id = {item.conflict_id: item for item in (current.conflicts if current is not None else ())}
    for keys in sorted(groups):
        participants = tuple(build_assertion_reference(run_dir, work_unit_id, semantic_kind, semantic_id) for work_unit_id, semantic_kind, semantic_id in keys)
        conflict = Conflict(conflict_id_for(item.assertion_id for item in participants), participants)
        conflicts_by_id.setdefault(conflict.conflict_id, conflict)
    registry = finalize_registry(
        ConflictRegistry(
            run_id=queue.run_id,
            conflicts=tuple(conflicts_by_id.values()),
            supersessions=current.supersessions if current is not None else (),
        )
    )
    save_conflict_registry(run_dir, registry)
    return registry


def save_conflict_registry(run_dir: Path, registry: ConflictRegistry, *, configured_authority_ids: Iterable[str] = ()) -> None:
    workspace_mutation_guard(run_dir)
    strict = conflict_contract_required(run_dir)
    policy = conflict_authority_policy(run_dir)
    allowed_ids = set(configured_authority_ids) or configured_authority_ids_for_save(run_dir, policy)
    registry.validate_against_run(
        run_dir,
        configured_authority_ids=allowed_ids,
        authority_policy=policy,
        strict_authority=strict,
    )
    atomic_write_json(conflict_registry_path(run_dir), registry.as_dict(), mode=0o600)
    if strict:
        manifest = _run_manifest(run_dir)
        manifest["conflict_assessment"] = {"schema_version": CONFLICT_CONTRACT_VERSION, "status": registry.effective_assessment_status()}
        atomic_write_json(storage_path(run_dir, StorageArtifact.RUN_MANIFEST, "RUN_MANIFEST.json"), manifest, mode=0o600)


def configured_authority_ids_for_save(run_dir: Path, policy: dict[str, Any]) -> set[str]:
    if conflict_contract_required(run_dir):
        return {rule["authority_config_id"] for rule in policy.get("rules", [])}
    return set()


def conflict_registry_path(run_dir: Path) -> Path:
    return storage_path(run_dir, StorageArtifact.CANONICAL_IR, CONFLICT_REGISTRY_FILE)


def load_conflict_registry(run_dir: Path) -> ConflictRegistry | None:
    path = conflict_registry_path(run_dir)
    if not path.is_file():
        return None
    value = read_json(path)
    return ConflictRegistry.from_dict(value)


def conflict_assessment_status(run_dir: Path) -> str:
    """Return the durable assessment state for a run."""

    if not conflict_contract_required(run_dir):
        return ConflictAssessmentState.LEGACY_NOT_ASSESSED.value
    registry = load_conflict_registry(run_dir)
    manifest = _run_manifest(run_dir)
    marker = manifest.get("conflict_assessment")
    if marker is not None:
        if not isinstance(marker, dict) or marker.get("schema_version") != CONFLICT_CONTRACT_VERSION:
            raise _error("Conflict assessment marker is malformed.", code=ErrorCode.SCHEMA_INVALID)
        marker_status = marker.get("status")
        try:
            marker_status = ConflictAssessmentState(marker_status).value
        except ValueError as exc:
            raise _error("Conflict assessment marker status is unsupported.", code=ErrorCode.SCHEMA_INVALID) from exc
        if registry is None:
            if marker_status != ConflictAssessmentState.NOT_ASSESSED.value:
                raise _error("Conflict assessment marker claims assessment without a registry.", code=ErrorCode.STALE_EVIDENCE)
            return marker_status
        if marker_status != registry.effective_assessment_status():
            raise _error("Conflict assessment marker does not match the current registry.", code=ErrorCode.STALE_EVIDENCE)
    if registry is None:
        return ConflictAssessmentState.NOT_ASSESSED.value
    return registry.effective_assessment_status()


def finalize_registry(registry: ConflictRegistry) -> ConflictRegistry:
    """Return a deterministic revisioned copy after structural validation."""

    registry.validate_structure()
    return ConflictRegistry(
        run_id=registry.run_id,
        conflicts=registry.conflicts,
        supersessions=registry.supersessions,
        registry_revision=registry.computed_revision(),
        schema_version=registry.schema_version,
        assessment_status=(
            ConflictAssessmentState.ASSESSED_CONFLICTS.value
            if registry.conflicts
            else ConflictAssessmentState.ASSESSED_ZERO_CONFLICTS.value
        ),
    )


ConflictIR = Conflict
ConflictAssertion = AssertionReference
ConflictState = ConflictResolutionState
SupersessionIR = Supersession
CONFLICT_SCHEMA_VERSION = CONFLICT_REGISTRY_SCHEMA_VERSION


__all__ = [
    "AssertionKind", "AssertionReference", "AuthorityEvidenceReference", "Conflict", "ConflictAssertion", "ConflictIR", "ConflictAssessmentState",
    "ConflictRegistry", "ConflictResolutionState", "ConflictState", "CONFLICT_REGISTRY_FILE", "CONFLICT_REGISTRY_SCHEMA_VERSION", "CONFLICT_SCHEMA_VERSION",
    "Supersession", "SupersessionIR", "SupersessionAuthorityBasis", "SupersessionState",
    "assertion_id_for", "assess_conflicts", "authority_policy_revision", "build_assertion_reference", "build_authority_evidence_reference", "conflict_authority_policy", "conflict_contract_required", "conflict_id_for",
    "conflict_assessment_status", "conflict_registry_path", "finalize_registry", "load_conflict_registry", "save_conflict_registry",
    "supersession_id_for",
]
