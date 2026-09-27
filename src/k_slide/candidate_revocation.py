"""Candidate-bound, source-free revocation and requalification controls.

The reference file provider is for repository qualification only. Production
deployments must install a provider at the explicit typed boundary exposed by
``deployment_candidate_revocation_control``.
"""

from __future__ import annotations

import hashlib
import hmac
import importlib
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

from .io import atomic_write_json, read_json
from .locking import filesystem_lock
from .rollout import RolloutCandidateBinding, RolloutControlError


REVOCATION_SCHEMA_VERSION = "1.0"
REVOCATION_REASON_CATEGORIES = (
    "CRITICAL_SEMANTIC_DEFECT",
    "SECURITY_INCIDENT",
    "PRIVACY_INCIDENT",
    "CREDENTIAL_LEAKAGE",
    "TENANT_ISOLATION_FAILURE",
    "PROVIDER_MODEL_CONFIG_DRIFT",
    "BROKEN_EVIDENCE_IDENTITY",
    "MATERIAL_DATA_USE_POLICY_CHANGE",
    "CRITICAL_VULNERABILITY",
)
_REASON_AUTHORITY = {
    "CRITICAL_SEMANTIC_DEFECT": "quality_authority",
    "SECURITY_INCIDENT": "security_authority",
    "PRIVACY_INCIDENT": "privacy_authority",
    "CREDENTIAL_LEAKAGE": "security_authority",
    "TENANT_ISOLATION_FAILURE": "security_authority",
    "PROVIDER_MODEL_CONFIG_DRIFT": "deployment_authority",
    "BROKEN_EVIDENCE_IDENTITY": "release_authority",
    "MATERIAL_DATA_USE_POLICY_CHANGE": "privacy_authority",
    "CRITICAL_VULNERABILITY": "security_authority",
}
_EVIDENCE_KINDS = {
    "INCIDENT_RECORD",
    "SECURITY_ADVISORY",
    "POLICY_CHANGE_RECORD",
    "EVIDENCE_IDENTITY_RECORD",
    "REQUALIFICATION_ATTESTATION",
}
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_REF = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")


class CandidateRevocationError(RolloutControlError):
    """Invalid, stale, unauthorized, or unavailable candidate revocation state."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _identity(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _HEX64.fullmatch(value):
        raise CandidateRevocationError(f"{label} is malformed")
    return value


def _ref(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _REF.fullmatch(value):
        raise CandidateRevocationError(f"{label} is malformed")
    return value


def _time(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        raise CandidateRevocationError(f"{label} is missing")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CandidateRevocationError(f"{label} is malformed") from exc
    if result.tzinfo is None:
        raise CandidateRevocationError(f"{label} must include a timezone")
    return result.astimezone(timezone.utc)


def _key(value: bytes) -> bytes:
    if not isinstance(value, bytes) or len(value) < 32:
        raise CandidateRevocationError("candidate revocation authority key is unavailable")
    return value


def _sign(payload: dict[str, Any], key: bytes) -> dict[str, Any]:
    signature = hmac.new(_key(key), _canonical(payload), hashlib.sha256).hexdigest()
    return {"payload": payload, "signature": signature}


def _verify(value: Any, key: bytes, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"payload", "signature"} or not isinstance(value["payload"], dict):
        raise CandidateRevocationError(f"{label} is malformed")
    expected = hmac.new(_key(key), _canonical(value["payload"]), hashlib.sha256).hexdigest()
    if not isinstance(value["signature"], str) or not hmac.compare_digest(value["signature"], expected):
        raise CandidateRevocationError(f"{label} is unauthorized or modified")
    return value["payload"]


def _binding_identity(candidate: RolloutCandidateBinding) -> str:
    return hashlib.sha256(_canonical(candidate.as_dict())).hexdigest()


def _directory(root: Path, candidate: RolloutCandidateBinding) -> Path:
    config = Path(root).expanduser().resolve() / ".k-slide-config"
    revocation_root = config / "candidate-revocations"
    if config.is_symlink() or revocation_root.is_symlink():
        raise CandidateRevocationError("candidate revocation state directory is unsafe")
    return revocation_root / _binding_identity(candidate)


def _state_identity(payload: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(payload)).hexdigest()


@dataclass(frozen=True)
class CandidateRevocationStatus:
    candidate_binding: RolloutCandidateBinding
    state_identity: str
    revision: int
    status: str
    active_reason_categories: tuple[str, ...] = ()
    event_identity: str | None = None

    def validate(self, candidate: RolloutCandidateBinding) -> "CandidateRevocationStatus":
        if self.candidate_binding != candidate:
            raise CandidateRevocationError("candidate revocation binding does not match the active candidate")
        _identity(self.state_identity, "candidate revocation state identity")
        if isinstance(self.revision, bool) or not isinstance(self.revision, int) or self.revision < 0:
            raise CandidateRevocationError("candidate revocation revision is malformed")
        if self.status not in {"CLEAR", "REVOKED", "RECOVERED"}:
            raise CandidateRevocationError("candidate revocation status is unsupported")
        if self.revision == 0 and (self.event_identity is not None or self.status != "CLEAR" or self.active_reason_categories):
            raise CandidateRevocationError("candidate revocation genesis state is contradictory")
        if self.revision > 0:
            _identity(self.event_identity, "candidate revocation event identity")
        categories = self.active_reason_categories
        if not isinstance(categories, tuple) or tuple(sorted(set(categories))) != categories or any(item not in REVOCATION_REASON_CATEGORIES for item in categories):
            raise CandidateRevocationError("candidate revocation category set is malformed")
        if (self.status == "REVOKED") != bool(categories) or (self.revision > 0 and self.status == "CLEAR"):
            raise CandidateRevocationError("candidate revocation status and categories contradict")
        return self

    @property
    def revoked(self) -> bool:
        return self.status == "REVOKED"


class CandidateRevocationProvider(Protocol):
    """Typed deployment boundary for exact-candidate revocation state/events.

    A live provider must resolve status only for candidates present in the
    signed rollout binding and normal release contract, authenticate
    actor/authority identities, append events with optimistic concurrency,
    retain immutable history, and route REVOKE or RECOVER through the existing
    signed rollout transition authority.
    """

    def status(self, candidate: RolloutCandidateBinding) -> CandidateRevocationStatus: ...

    def apply_event(self, event: dict[str, Any]) -> CandidateRevocationStatus: ...


def _validate_event(payload: Any, candidate: RolloutCandidateBinding, *, now: datetime) -> dict[str, Any]:
    fields = {
        "schema_version", "action", "candidate_binding", "actor_ref", "authority_ref", "event_id",
        "expected_revision", "revision", "expected_state_identity", "previous_event_identity", "occurred_at",
        "reason_categories", "evidence_reference",
    }
    if not isinstance(payload, dict) or set(payload) != fields or payload.get("schema_version") != REVOCATION_SCHEMA_VERSION:
        raise CandidateRevocationError("candidate revocation event is malformed")
    if RolloutCandidateBinding.from_mapping(payload["candidate_binding"]) != candidate:
        raise CandidateRevocationError("candidate revocation event targets a different candidate")
    action = payload["action"]
    if action not in {"REVOKE", "RECOVER"}:
        raise CandidateRevocationError("candidate revocation action is unsupported")
    _ref(payload["actor_ref"], "candidate revocation actor")
    authority = _ref(payload["authority_ref"], "candidate revocation authority")
    event_id = _ref(payload["event_id"], "candidate revocation event ID")
    if len(event_id) > 55:
        raise CandidateRevocationError("candidate revocation event ID is too long")
    revision = payload["expected_revision"]
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 0:
        raise CandidateRevocationError("candidate revocation expected revision is malformed")
    event_revision = payload["revision"]
    if isinstance(event_revision, bool) or not isinstance(event_revision, int) or event_revision != revision + 1:
        raise CandidateRevocationError("candidate revocation event revision is malformed")
    _identity(payload["expected_state_identity"], "candidate revocation expected state identity")
    previous_event = payload["previous_event_identity"]
    if previous_event is not None:
        _identity(previous_event, "candidate revocation previous event identity")
    if _time(payload["occurred_at"], "candidate revocation timestamp") > now:
        raise CandidateRevocationError("candidate revocation timestamp is in the future")
    categories = payload["reason_categories"]
    if not isinstance(categories, list) or not categories or categories != sorted(set(categories)) or any(item not in REVOCATION_REASON_CATEGORIES for item in categories):
        raise CandidateRevocationError("candidate revocation reason categories are malformed")
    if action == "REVOKE":
        if len(categories) != 1 or authority != _REASON_AUTHORITY[categories[0]]:
            raise CandidateRevocationError("candidate revocation authority is not authorized for its reason")
    elif authority != "qualification_authority":
        raise CandidateRevocationError("candidate recovery authority is unauthorized")
    evidence = payload["evidence_reference"]
    if not isinstance(evidence, dict) or set(evidence) != {"kind", "identity"} or evidence.get("kind") not in _EVIDENCE_KINDS:
        raise CandidateRevocationError("candidate revocation evidence reference is malformed")
    _identity(evidence.get("identity"), "candidate revocation evidence identity")
    if action == "RECOVER" and evidence["kind"] != "REQUALIFICATION_ATTESTATION":
        raise CandidateRevocationError("candidate recovery lacks a requalification evidence reference")
    return payload


def build_candidate_control_event(
    *,
    action: str,
    candidate: RolloutCandidateBinding,
    actor_ref: str,
    authority_ref: str,
    event_id: str,
    expected_revision: int,
    expected_state_identity: str,
    previous_event_identity: str | None,
    occurred_at: str,
    reason_categories: tuple[str, ...] | list[str],
    evidence_kind: str,
    evidence_identity: str,
    key: bytes,
) -> dict[str, Any]:
    """Build a signed, bounded control event; inputs contain identities only."""

    payload = {
        "schema_version": REVOCATION_SCHEMA_VERSION,
        "action": action,
        "candidate_binding": candidate.as_dict(),
        "actor_ref": actor_ref,
        "authority_ref": authority_ref,
        "event_id": event_id,
        "expected_revision": expected_revision,
        "revision": expected_revision + 1,
        "expected_state_identity": expected_state_identity,
        "previous_event_identity": previous_event_identity,
        "occurred_at": occurred_at,
        "reason_categories": sorted(set(reason_categories)),
        "evidence_reference": {"kind": evidence_kind, "identity": evidence_identity},
    }
    _validate_event(payload, candidate, now=_time(occurred_at, "candidate control timestamp"))
    return _sign(payload, key)


def _initial_payload(candidate: RolloutCandidateBinding, now: datetime) -> dict[str, Any]:
    return {
        "schema_version": REVOCATION_SCHEMA_VERSION,
        "candidate_binding": candidate.as_dict(),
        "revision": 0,
        "previous_state_identity": None,
        "event_identity": None,
        "status": "CLEAR",
        "active_reason_categories": [],
        "actor_ref": "deployment_authority",
        "authority_ref": "deployment_authority",
        "updated_at": now.isoformat().replace("+00:00", "Z"),
        "transition_id": "initial",
    }


def _validate_state(payload: Any, candidate: RolloutCandidateBinding) -> dict[str, Any]:
    fields = {
        "schema_version", "candidate_binding", "revision", "previous_state_identity", "event_identity", "status",
        "active_reason_categories", "actor_ref", "authority_ref", "updated_at", "transition_id",
    }
    if not isinstance(payload, dict) or set(payload) != fields or payload.get("schema_version") != REVOCATION_SCHEMA_VERSION:
        raise CandidateRevocationError("candidate revocation state is malformed")
    if RolloutCandidateBinding.from_mapping(payload["candidate_binding"]) != candidate:
        raise CandidateRevocationError("candidate revocation state identity drifted")
    revision = payload["revision"]
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 0:
        raise CandidateRevocationError("candidate revocation state revision is malformed")
    previous = payload["previous_state_identity"]
    event_identity = payload["event_identity"]
    if revision == 0:
        if previous is not None or event_identity is not None or payload["status"] != "CLEAR" or payload["active_reason_categories"]:
            raise CandidateRevocationError("candidate revocation genesis state is contradictory")
    else:
        _identity(previous, "candidate revocation previous state identity")
        _identity(event_identity, "candidate revocation event identity")
    categories = payload["active_reason_categories"]
    if not isinstance(categories, list) or categories != sorted(set(categories)) or any(item not in REVOCATION_REASON_CATEGORIES for item in categories):
        raise CandidateRevocationError("candidate revocation state categories are malformed")
    if payload["status"] not in {"CLEAR", "REVOKED", "RECOVERED"} or (payload["status"] == "REVOKED") != bool(categories) or (revision > 0 and payload["status"] == "CLEAR"):
        raise CandidateRevocationError("candidate revocation state status is contradictory")
    _ref(payload["actor_ref"], "candidate revocation state actor")
    _ref(payload["authority_ref"], "candidate revocation state authority")
    _ref(payload["transition_id"], "candidate revocation state transition ID")
    _time(payload["updated_at"], "candidate revocation state timestamp")
    return payload


def _read_state(root: Path, candidate: RolloutCandidateBinding, key: bytes) -> tuple[dict[str, Any], str]:
    directory = _directory(root, candidate)
    if directory.is_symlink() or (directory.parent.is_symlink()):
        raise CandidateRevocationError("candidate revocation state directory is unsafe")
    try:
        signed_state = read_json(directory / "state.json")
        signed_head = read_json(directory / "head.json")
    except Exception as exc:
        raise CandidateRevocationError("candidate revocation authority state is missing or unreadable") from exc
    state = _validate_state(_verify(signed_state, key, "candidate revocation state"), candidate)
    head = _verify(signed_head, key, "candidate revocation head")
    if set(head) != {"schema_version", "candidate_binding_identity", "revision", "state_identity"} or head.get("schema_version") != REVOCATION_SCHEMA_VERSION:
        raise CandidateRevocationError("candidate revocation head is malformed")
    state_id = _state_identity(state)
    if head != {
        "schema_version": REVOCATION_SCHEMA_VERSION,
        "candidate_binding_identity": _binding_identity(candidate),
        "revision": state["revision"],
        "state_identity": state_id,
    }:
        raise CandidateRevocationError("candidate revocation state is stale or replayed")
    history = directory / "history"
    if history.is_symlink() or not history.is_dir():
        raise CandidateRevocationError("candidate revocation history is missing or unsafe")
    expected = {f"{revision:010d}.json" for revision in range(1, state["revision"] + 1)}
    files = {item.name for item in history.iterdir() if item.is_file() or item.is_symlink()}
    if files != expected or any((history / name).is_symlink() for name in expected):
        raise CandidateRevocationError("candidate revocation history is incomplete or contradictory")
    current_id = None
    categories: set[str] = set()
    last_state_id = None
    last_payload = _initial_payload(candidate, _time(state["updated_at"], "candidate revocation timestamp")) if state["revision"] == 0 else None
    # Genesis is immutable and stored as a signed history anchor.
    try:
        genesis = _verify(read_json(directory / "genesis.json"), key, "candidate revocation genesis")
    except Exception as exc:
        raise CandidateRevocationError("candidate revocation genesis is missing or unreadable") from exc
    _validate_state(genesis, candidate)
    if genesis["revision"] != 0:
        raise CandidateRevocationError("candidate revocation genesis is malformed")
    last_state_id = _state_identity(genesis)
    last_payload = genesis
    for revision in range(1, state["revision"] + 1):
        event = _verify(read_json(history / f"{revision:010d}.json"), key, "candidate revocation history event")
        _validate_event(event, candidate, now=datetime.max.replace(tzinfo=timezone.utc))
        if event["expected_revision"] != revision - 1 or event["revision"] != revision or event["expected_state_identity"] != last_state_id or event["previous_event_identity"] != current_id:
            raise CandidateRevocationError("candidate revocation history chain is stale or conflicting")
        if _time(event["occurred_at"], "candidate revocation timestamp") < _time(last_payload["updated_at"], "candidate revocation prior timestamp"):
            raise CandidateRevocationError("candidate revocation history timestamp moved backwards")
        event_id = hashlib.sha256(_canonical(event)).hexdigest()
        if event["action"] == "REVOKE":
            categories.add(event["reason_categories"][0])
        else:
            if not set(event["reason_categories"]) <= categories:
                raise CandidateRevocationError("candidate recovery history has no matching active revocation")
            categories.difference_update(event["reason_categories"])
        expected_status = "REVOKED" if categories else ("RECOVERED" if event["action"] == "RECOVER" else "CLEAR")
        last_payload = {
            "schema_version": REVOCATION_SCHEMA_VERSION,
            "candidate_binding": candidate.as_dict(),
            "revision": revision,
            "previous_state_identity": last_state_id,
            "event_identity": event_id,
            "status": expected_status,
            "active_reason_categories": sorted(categories),
            "actor_ref": event["actor_ref"],
            "authority_ref": event["authority_ref"],
            "updated_at": event["occurred_at"],
            "transition_id": event["event_id"],
        }
        last_state_id = _state_identity(last_payload)
        current_id = event_id
    if last_payload != state or last_state_id != state_id:
        raise CandidateRevocationError("candidate revocation history does not match current state")
    return state, state_id


def initialize_reference_candidate_revocation(root: Path, candidates: tuple[RolloutCandidateBinding, ...], *, key: bytes, now: datetime | None = None) -> None:
    """Initialize signed, candidate-specific genesis ledgers for a rollout policy."""

    current_time = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    for candidate in {_binding_identity(item): item for item in candidates}.values():
        directory = _directory(root, candidate)
        if directory.exists() or directory.is_symlink():
            raise CandidateRevocationError("candidate revocation authority is already initialized")
        directory.mkdir(parents=True, mode=0o700)
        (directory / "history").mkdir(mode=0o700)
        payload = _initial_payload(candidate, current_time)
        identity = _state_identity(payload)
        head = {
            "schema_version": REVOCATION_SCHEMA_VERSION,
            "candidate_binding_identity": _binding_identity(candidate),
            "revision": 0,
            "state_identity": identity,
        }
        atomic_write_json(directory / "genesis.json", _sign(payload, key), mode=0o600)
        atomic_write_json(directory / "state.json", _sign(payload, key), mode=0o600)
        atomic_write_json(directory / "head.json", _sign(head, key), mode=0o600)


def reference_candidate_revocation_status(root: Path, candidate: RolloutCandidateBinding, *, key: bytes) -> CandidateRevocationStatus:
    state, identity = _read_state(root, candidate, key)
    result = CandidateRevocationStatus(candidate, identity, state["revision"], state["status"], tuple(state["active_reason_categories"]), state["event_identity"])
    return result.validate(candidate)


def record_reference_candidate_event(
    root: Path,
    *,
    event: dict[str, Any],
    key: bytes,
    now: datetime | None = None,
) -> tuple[CandidateRevocationStatus, bool]:
    """CAS-append a signed event. Returns ``(status, was_duplicate)``."""

    signed_event = event
    candidate_payload = _verify(signed_event, key, "candidate revocation event")
    candidate = RolloutCandidateBinding.from_mapping(candidate_payload.get("candidate_binding"))
    current_time = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    payload = _validate_event(candidate_payload, candidate, now=current_time)
    directory = _directory(root, candidate)
    with filesystem_lock(directory / "revocation-control.lock"):
        state, state_id = _read_state(root, candidate, key)
        history = directory / "history"
        for path in history.glob("*.json"):
            existing = _verify(read_json(path), key, "candidate revocation history event")
            if existing.get("event_id") == payload["event_id"]:
                if _canonical(existing) == _canonical(payload):
                    status = CandidateRevocationStatus(candidate, state_id, state["revision"], state["status"], tuple(state["active_reason_categories"]), state["event_identity"])
                    return status.validate(candidate), True
                raise CandidateRevocationError("candidate revocation event ID conflicts with an earlier event")
        if payload["expected_revision"] != state["revision"] or payload["revision"] != state["revision"] + 1 or payload["expected_state_identity"] != state_id or payload["previous_event_identity"] != state["event_identity"]:
            raise CandidateRevocationError("candidate revocation event has a stale revision or conflicting state identity")
        if _time(payload["occurred_at"], "candidate revocation timestamp") < _time(state["updated_at"], "candidate revocation prior timestamp"):
            raise CandidateRevocationError("candidate revocation event timestamp is stale")
        categories = set(state["active_reason_categories"])
        if payload["action"] == "REVOKE":
            categories.add(payload["reason_categories"][0])
        else:
            if not set(payload["reason_categories"]) <= categories:
                raise CandidateRevocationError("candidate recovery lacks a current matching revocation")
            categories.difference_update(payload["reason_categories"])
        event_identity = hashlib.sha256(_canonical(payload)).hexdigest()
        revision = state["revision"] + 1
        next_payload = {
            "schema_version": REVOCATION_SCHEMA_VERSION,
            "candidate_binding": candidate.as_dict(),
            "revision": revision,
            "previous_state_identity": state_id,
            "event_identity": event_identity,
            "status": "REVOKED" if categories else ("RECOVERED" if payload["action"] == "RECOVER" else "CLEAR"),
            "active_reason_categories": sorted(categories),
            "actor_ref": payload["actor_ref"],
            "authority_ref": payload["authority_ref"],
            "updated_at": payload["occurred_at"],
            "transition_id": payload["event_id"],
        }
        next_state_id = _state_identity(next_payload)
        next_head = {
            "schema_version": REVOCATION_SCHEMA_VERSION,
            "candidate_binding_identity": _binding_identity(candidate),
            "revision": revision,
            "state_identity": next_state_id,
        }
        event_path = history / f"{revision:010d}.json"
        if event_path.exists() or event_path.is_symlink():
            raise CandidateRevocationError("candidate revocation history revision already exists")
        atomic_write_json(event_path, signed_event, mode=0o600)
        atomic_write_json(directory / "state.json", _sign(next_payload, key), mode=0o600)
        atomic_write_json(directory / "head.json", _sign(next_head, key), mode=0o600)
    result = CandidateRevocationStatus(candidate, next_state_id, revision, next_payload["status"], tuple(next_payload["active_reason_categories"]), next_payload["event_identity"])
    return result.validate(candidate), False


def apply_reference_candidate_event(
    root: Path,
    *,
    event: dict[str, Any],
    key: bytes,
    now: datetime | None = None,
) -> CandidateRevocationStatus:
    """Persist an authorized event and use existing signed rollout transitions.

    Revocation is durable before DISABLE/ROLLBACK is attempted, so a rollout
    transition conflict cannot reopen admission. Recovery invokes the existing
    RESTORE_CANDIDATE transition only for the exact policy primary candidate.
    """

    candidate_payload = _verify(event, key, "candidate revocation event")
    candidate = RolloutCandidateBinding.from_mapping(candidate_payload.get("candidate_binding"))
    status, duplicate = record_reference_candidate_event(root, event=event, key=key, now=now)
    event_identity = hashlib.sha256(_canonical(candidate_payload)).hexdigest()
    if duplicate and status.event_identity != event_identity:
        return status

    from .rollout import (
        RolloutControlError,
        _policy_payload,
        _state_payload,
        build_transition_command,
        rollout_policy_identity,
        transition_reference_rollout_control,
    )

    directory = Path(root).expanduser().resolve() / ".k-slide-config"
    try:
        policy = read_json(directory / "rollout-policy.json")
        state = read_json(directory / "rollout-state.json")
        head = read_json(directory / "rollout-head.json")
        current_time = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        policy_payload, policy_id = _policy_payload(policy, key, now=current_time)
        current, _state_id = _state_payload(state, key, policy_identity=policy_id, head=head)
    except Exception as exc:
        raise CandidateRevocationError("signed rollout control state is unavailable for revocation transition") from exc
    primary = RolloutCandidateBinding.from_mapping(policy_payload["candidate_binding"])
    rollback = RolloutCandidateBinding.from_mapping(policy_payload["rollback_target_binding"]) if policy_payload["rollback_target_binding"] is not None else None
    active = RolloutCandidateBinding.from_mapping(current["candidate_binding"])
    if candidate_payload["action"] == "REVOKE" and active == candidate:
        fallback = reference_candidate_revocation_status(root, rollback, key=key) if rollback is not None else None
        action = "ROLLBACK" if rollback is not None and fallback is not None and not fallback.revoked else "DISABLE"
        target = rollback if action == "ROLLBACK" else None
        transition_id = "rev-" + candidate_payload["event_id"]
    elif candidate_payload["action"] == "RECOVER" and primary == candidate and rollback is not None and active == rollback:
        action, target = "RESTORE_CANDIDATE", primary
        transition_id = "restore-" + candidate_payload["event_id"]
    else:
        return status
    command = build_transition_command(
        policy_identity=rollout_policy_identity(policy, key=key, now=current_time),
        expected_revision=current["revision"],
        action=action,
        transition_id=transition_id,
        actor_ref=candidate_payload["actor_ref"],
        target_stage=None,
        target_candidate=target,
        key=key,
    )
    try:
        transition_reference_rollout_control(root, command=command, key=key, now=current_time)
    except RolloutControlError as exc:
        # The event remains durable and the admission gate remains closed.
        raise CandidateRevocationError("candidate revocation is recorded; signed rollout transition requires reconciliation") from exc
    return status


class ReferenceFileCandidateRevocationControl:
    """Local signed adapter for qualification; it is not a company control plane."""

    def __init__(self, root: Path, *, key: bytes) -> None:
        self.root = Path(root).expanduser().resolve()
        self.key = _key(key)

    def status(self, candidate: RolloutCandidateBinding) -> CandidateRevocationStatus:
        return reference_candidate_revocation_status(self.root, candidate, key=self.key)

    def apply_event(self, event: dict[str, Any], *, now: datetime | None = None) -> CandidateRevocationStatus:
        return apply_reference_candidate_event(self.root, event=event, key=self.key, now=now)


def deployment_candidate_revocation_control() -> CandidateRevocationProvider | None:
    """Load the explicitly configured live provider; absence is not healthy state."""

    factory_spec = os.environ.get("KSLIDE_CANDIDATE_REVOCATION_CONTROL_FACTORY")
    if not factory_spec:
        return None
    if factory_spec.count(":") != 1:
        raise CandidateRevocationError("candidate revocation adapter configuration is malformed")
    module_name, factory_name = factory_spec.split(":", 1)
    try:
        factory = getattr(importlib.import_module(module_name), factory_name)
        provider = factory()
    except Exception as exc:
        raise CandidateRevocationError("candidate revocation authority is unavailable") from exc
    if not callable(getattr(provider, "status", None)) or not callable(getattr(provider, "apply_event", None)):
        raise CandidateRevocationError("candidate revocation adapter is invalid")
    return provider


def candidate_revocation_status(provider: CandidateRevocationProvider | None, candidate: RolloutCandidateBinding) -> CandidateRevocationStatus:
    if provider is None:
        raise CandidateRevocationError("candidate revocation authority is unavailable")
    try:
        status = provider.status(candidate)
    except CandidateRevocationError:
        raise
    except Exception as exc:
        raise CandidateRevocationError("candidate revocation authority is unavailable or unreadable") from exc
    if not isinstance(status, CandidateRevocationStatus):
        raise CandidateRevocationError("candidate revocation provider returned an invalid typed status")
    return status.validate(candidate)


def candidate_revocation_gate(
    *,
    candidate: RolloutCandidateBinding | None,
    provider: CandidateRevocationProvider | None,
) -> tuple[bool, str]:
    """Release/readiness helper returning a source-free gate result."""

    if candidate is None:
        return False, "exact run environment candidate binding is unavailable"
    try:
        status = candidate_revocation_status(provider, candidate)
    except CandidateRevocationError as exc:
        return False, str(exc)
    if status.revoked:
        return False, "candidate has an active revocation"
    return True, f"revision={status.revision}; state={status.state_identity}"
