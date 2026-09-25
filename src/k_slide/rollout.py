"""Candidate-bound deployment rollout admission controls (KSA-34).

Rollout policy and state are deployment-owned, source-free control data. This
module only gates new admissions; it does not produce release or certification
evidence. Production adapters may implement ``RolloutAdmissionProvider`` over
their deployment control plane. ``ReferenceFileRolloutControl`` is a
deterministic filesystem adapter for tests and local qualification only.
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

from .environment import RunEnvironmentIdentity
from .io import atomic_write_json, read_json
from .locking import filesystem_lock


ROLLOUT_CONTRACT_VERSION = "1.0"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_NAME = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
_STAGES = ("NAMED_COHORT", "PILOT", "CANARY", "PHASED", "FULL")
_ROLLBACK_RULE = "BOUND_RUNS_COMPLETE_OR_STOP_ON_IDENTITY_MISMATCH_V1"


class RolloutControlError(ValueError):
    """Malformed, stale, unauthorized, replayed, or inconsistent rollout state."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _HEX64.fullmatch(value):
        raise RolloutControlError(f"{label} is malformed")
    return value


def _name(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _NAME.fullmatch(value):
        raise RolloutControlError(f"{label} is malformed")
    return value


def _time(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        raise RolloutControlError(f"{label} is missing")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RolloutControlError(f"{label} is malformed") from exc
    if parsed.tzinfo is None:
        raise RolloutControlError(f"{label} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _key(value: bytes) -> bytes:
    if not isinstance(value, bytes) or len(value) < 32:
        raise RolloutControlError("rollout authority key is unavailable")
    return value


def _signature(payload: dict[str, Any], key: bytes) -> str:
    return hmac.new(_key(key), _canonical(payload), hashlib.sha256).hexdigest()


def _signed(payload: dict[str, Any], key: bytes) -> dict[str, Any]:
    return {"payload": payload, "signature": _signature(payload, key)}


def _verify_signed(value: Any, key: bytes, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"payload", "signature"} or not isinstance(value["payload"], dict):
        raise RolloutControlError(f"{label} is malformed")
    expected = _signature(value["payload"], key)
    if not isinstance(value["signature"], str) or not hmac.compare_digest(value["signature"], expected):
        raise RolloutControlError(f"{label} is unauthorized or modified")
    return value["payload"]


@dataclass(frozen=True)
class RolloutCandidateBinding:
    """The existing KSA-10/KSA-33 candidate and full execution identity."""

    subject_git_sha: str
    deployment_fingerprint: str
    run_environment_identity_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.subject_git_sha, str) or not _HEX40.fullmatch(self.subject_git_sha):
            raise RolloutControlError("candidate subject is malformed")
        _digest(self.deployment_fingerprint, "candidate deployment fingerprint")
        _digest(self.run_environment_identity_sha256, "candidate environment identity")

    @classmethod
    def from_environment(cls, environment: RunEnvironmentIdentity) -> "RolloutCandidateBinding":
        return cls(environment.kslide_source_revision, environment.candidate_identity, environment.identity_sha256)

    @classmethod
    def from_mapping(cls, value: Any) -> "RolloutCandidateBinding":
        if not isinstance(value, dict) or set(value) != {"subject_git_sha", "deployment_fingerprint", "run_environment_identity_sha256"}:
            raise RolloutControlError("candidate binding is malformed")
        try:
            return cls(**value)
        except (TypeError, ValueError) as exc:
            raise RolloutControlError("candidate binding is malformed") from exc

    def as_dict(self) -> dict[str, str]:
        return {
            "subject_git_sha": self.subject_git_sha,
            "deployment_fingerprint": self.deployment_fingerprint,
            "run_environment_identity_sha256": self.run_environment_identity_sha256,
        }


@dataclass(frozen=True)
class RolloutAdmission:
    status: str
    reason_code: str
    candidate_binding: RolloutCandidateBinding
    policy_identity: str | None = None
    policy_version: str | None = None
    state_revision: int | None = None
    stage: str | None = None
    cohort_id: str | None = None
    rollback_rule: str = _ROLLBACK_RULE

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": ROLLOUT_CONTRACT_VERSION,
            "status": self.status,
            "reason_code": self.reason_code,
            "candidate_binding": self.candidate_binding.as_dict(),
            "policy_identity": self.policy_identity,
            "policy_version": self.policy_version,
            "state_revision": self.state_revision,
            "stage": self.stage,
            "cohort_id": self.cohort_id,
            "rollback_rule": self.rollback_rule,
        }


class RolloutAdmissionProvider(Protocol):
    """Deployment boundary that resolves authorized cohort membership."""

    def admit(self, candidate: RolloutCandidateBinding) -> RolloutAdmission: ...


def _policy_payload(value: Any, key: bytes, *, now: datetime) -> tuple[dict[str, Any], str]:
    payload = _verify_signed(value, key, "rollout policy")
    required = {
        "schema_version", "policy_id", "policy_version", "policy_revision", "issued_at", "expires_at",
        "candidate_binding", "rollback_target_binding", "stage_cohorts", "rollback_rule",
    }
    if set(payload) != required or payload.get("schema_version") != ROLLOUT_CONTRACT_VERSION:
        raise RolloutControlError("rollout policy has missing, unsupported, or contradictory fields")
    _name(payload["policy_id"], "rollout policy ID")
    if payload["policy_version"] != ROLLOUT_CONTRACT_VERSION:
        raise RolloutControlError("rollout policy version is unsupported")
    revision = payload["policy_revision"]
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
        raise RolloutControlError("rollout policy revision is malformed")
    if _time(payload["issued_at"], "rollout policy issue time") > now or _time(payload["expires_at"], "rollout policy expiry") <= now:
        raise RolloutControlError("rollout policy is stale or not yet active")
    RolloutCandidateBinding.from_mapping(payload["candidate_binding"])
    rollback = payload["rollback_target_binding"]
    if rollback is not None:
        RolloutCandidateBinding.from_mapping(rollback)
        if rollback == payload["candidate_binding"]:
            raise RolloutControlError("rollback target contradicts the active candidate")
    if payload["rollback_rule"] != _ROLLBACK_RULE:
        raise RolloutControlError("rollout rollback rule is unsupported")
    stages = payload["stage_cohorts"]
    if not isinstance(stages, dict) or set(stages) != set(_STAGES):
        raise RolloutControlError("rollout stages are incomplete")
    previous: set[str] = set()
    for stage in _STAGES:
        cohorts = stages[stage]
        if not isinstance(cohorts, list) or not cohorts:
            raise RolloutControlError("rollout stage has no named cohorts")
        normalized = [_name(item, "rollout cohort ID") for item in cohorts]
        current = set(normalized)
        if len(current) != len(normalized) or normalized != sorted(normalized):
            raise RolloutControlError("rollout cohort list is duplicated or unordered")
        if stage == "NAMED_COHORT" and len(current) != 1:
            raise RolloutControlError("named-cohort stage must admit exactly one cohort")
        if previous and not previous < current:
            raise RolloutControlError("rollout stages must define deliberate strict expansion")
        previous = current
    identity = hashlib.sha256(_canonical(payload)).hexdigest()
    return payload, identity


def rollout_policy_identity(policy: dict[str, Any], *, key: bytes, now: datetime | None = None) -> str:
    """Return the verified, versioned identity bound by state and admission."""

    _payload, identity = _policy_payload(policy, key, now=(now or datetime.now(timezone.utc)).astimezone(timezone.utc))
    return identity


def build_rollout_policy(
    *,
    policy_id: str,
    candidate: RolloutCandidateBinding,
    rollback_target: RolloutCandidateBinding | None,
    stage_cohorts: dict[str, list[str]],
    issued_at: str,
    expires_at: str,
    key: bytes,
    policy_revision: int = 1,
) -> dict[str, Any]:
    """Create a signed deployment policy document for adapters and fixtures."""

    payload = {
        "schema_version": ROLLOUT_CONTRACT_VERSION,
        "policy_id": policy_id,
        "policy_version": ROLLOUT_CONTRACT_VERSION,
        "policy_revision": policy_revision,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "candidate_binding": candidate.as_dict(),
        "rollback_target_binding": rollback_target.as_dict() if rollback_target is not None else None,
        "stage_cohorts": stage_cohorts,
        "rollback_rule": _ROLLBACK_RULE,
    }
    _policy_payload(_signed(payload, key), key, now=_time(issued_at, "policy issue time"))
    return _signed(payload, key)


def initial_rollout_state(policy: dict[str, Any], *, key: bytes, now: datetime | None = None) -> dict[str, Any]:
    current_time = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    payload, identity = _policy_payload(policy, key, now=current_time)
    state = {
        "schema_version": ROLLOUT_CONTRACT_VERSION,
        "policy_identity": identity,
        "revision": 1,
        "previous_state_identity": None,
        "candidate_binding": payload["candidate_binding"],
        "actor_ref": "deployment_authority",
        "transitioned_at": current_time.isoformat().replace("+00:00", "Z"),
        "stage": "DISABLED",
        "admissions_enabled": False,
        "admitted_cohorts": [],
        "rollback_rule": payload["rollback_rule"],
        "transition_id": "initial",
        "transition_action": "INITIALIZE",
    }
    return _signed(state, key)


def _state_payload(value: Any, key: bytes, *, policy_identity: str, head: Any) -> tuple[dict[str, Any], str]:
    state = _verify_signed(value, key, "rollout state")
    required = {
        "schema_version", "policy_identity", "revision", "previous_state_identity", "candidate_binding", "actor_ref", "transitioned_at",
        "stage", "admissions_enabled", "admitted_cohorts", "rollback_rule", "transition_id", "transition_action",
    }
    if set(state) != required or state.get("schema_version") != ROLLOUT_CONTRACT_VERSION:
        raise RolloutControlError("rollout state is malformed")
    if state["policy_identity"] != policy_identity or state["rollback_rule"] != _ROLLBACK_RULE:
        raise RolloutControlError("rollout state policy identity or rollback rule drifted")
    revision = state["revision"]
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
        raise RolloutControlError("rollout state revision is malformed")
    previous_identity = state["previous_state_identity"]
    if revision == 1:
        if state["transition_action"] != "INITIALIZE" or previous_identity is not None:
            raise RolloutControlError("initial rollout state is contradictory")
    elif not isinstance(previous_identity, str) or not _HEX64.fullmatch(previous_identity):
        raise RolloutControlError("rollout state transition chain is malformed")
    candidate = RolloutCandidateBinding.from_mapping(state["candidate_binding"])
    stage = state["stage"]
    cohorts = state["admitted_cohorts"]
    if not isinstance(cohorts, list) or any(not isinstance(item, str) for item in cohorts) or cohorts != sorted(set(cohorts)):
        raise RolloutControlError("rollout state cohort set is malformed")
    if stage == "DISABLED":
        if state["admissions_enabled"] is not False or cohorts:
            raise RolloutControlError("disabled rollout state is contradictory")
    elif stage not in _STAGES or state["admissions_enabled"] is not True:
        raise RolloutControlError("rollout stage and admission control contradict each other")
    _name(state["transition_id"], "rollout transition ID")
    _name(state["actor_ref"], "rollout actor reference")
    _time(state["transitioned_at"], "rollout transition time")
    action = state["transition_action"]
    if action not in {"INITIALIZE", "SET_STAGE", "DISABLE", "ROLLBACK", "RESTORE_CANDIDATE"}:
        raise RolloutControlError("rollout transition action is unsupported")
    if action == "INITIALIZE" and (revision != 1 or stage != "DISABLED"):
        raise RolloutControlError("initial rollout state is contradictory")
    if action == "INITIALIZE" and state["actor_ref"] != "deployment_authority":
        raise RolloutControlError("initial rollout authority is contradictory")
    if action in {"DISABLE", "ROLLBACK", "RESTORE_CANDIDATE"} and stage != "DISABLED":
        raise RolloutControlError("closed rollout transition is contradictory")
    if action == "SET_STAGE" and stage not in _STAGES:
        raise RolloutControlError("stage rollout transition is contradictory")
    identity = hashlib.sha256(_canonical(state)).hexdigest()
    if not isinstance(head, dict) or set(head) != {"payload", "signature"}:
        raise RolloutControlError("rollout head is malformed")
    head_payload = _verify_signed(head, key, "rollout head")
    if set(head_payload) != {"schema_version", "revision", "state_identity"} or head_payload["schema_version"] != ROLLOUT_CONTRACT_VERSION:
        raise RolloutControlError("rollout head is malformed")
    if head_payload["revision"] != revision or head_payload["state_identity"] != identity:
        raise RolloutControlError("rollout state is stale or replayed")
    return state, identity


def build_transition_command(
    *,
    policy_identity: str,
    expected_revision: int,
    action: str,
    transition_id: str,
    actor_ref: str,
    target_stage: str | None,
    target_candidate: RolloutCandidateBinding | None,
    key: bytes,
) -> dict[str, Any]:
    """Build an authorized deployment mutation request for the control plane."""

    payload = {
        "schema_version": ROLLOUT_CONTRACT_VERSION,
        "policy_identity": policy_identity,
        "expected_revision": expected_revision,
        "action": action,
        "transition_id": transition_id,
        "actor_ref": actor_ref,
        "target_stage": target_stage,
        "target_candidate_binding": target_candidate.as_dict() if target_candidate is not None else None,
    }
    return _signed(payload, key)


def apply_rollout_transition(
    *,
    policy: dict[str, Any],
    state: dict[str, Any],
    head: dict[str, Any],
    command: dict[str, Any],
    key: bytes,
    now: datetime | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Validate a signed explicit stage/disable/rollback mutation."""

    current_time = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    policy_payload, policy_identity = _policy_payload(policy, key, now=current_time)
    current, state_identity = _state_payload(state, key, policy_identity=policy_identity, head=head)
    current_candidate = RolloutCandidateBinding.from_mapping(current["candidate_binding"])
    if current_candidate.as_dict() not in (policy_payload["candidate_binding"], policy_payload["rollback_target_binding"]):
        raise RolloutControlError("rollout state candidate is not authorized by policy")
    if current["stage"] != "DISABLED" and current["admitted_cohorts"] != policy_payload["stage_cohorts"].get(current["stage"]):
        raise RolloutControlError("rollout stage and named cohort state contradict policy")
    command_payload = _verify_signed(command, key, "rollout transition")
    expected = {
        "schema_version", "policy_identity", "expected_revision", "action", "transition_id", "actor_ref",
        "target_stage", "target_candidate_binding",
    }
    if set(command_payload) != expected or command_payload["schema_version"] != ROLLOUT_CONTRACT_VERSION:
        raise RolloutControlError("rollout transition is malformed")
    if command_payload["policy_identity"] != policy_identity or command_payload["expected_revision"] != current["revision"]:
        raise RolloutControlError("rollout transition is stale, unauthorized, or replayed")
    _name(command_payload["transition_id"], "rollout transition ID")
    _name(command_payload["actor_ref"], "rollout actor reference")
    action = command_payload["action"]
    target_candidate = current["candidate_binding"]
    stage = current["stage"]
    enabled = current["admissions_enabled"]
    cohorts = current["admitted_cohorts"]
    if action == "DISABLE":
        if command_payload["target_stage"] is not None or command_payload["target_candidate_binding"] is not None:
            raise RolloutControlError("disable transition has contradictory targets")
        stage, enabled, cohorts = "DISABLED", False, []
    elif action == "SET_STAGE":
        target_stage = command_payload["target_stage"]
        if target_stage not in _STAGES or command_payload["target_candidate_binding"] is not None:
            raise RolloutControlError("stage transition has an invalid target")
        stage, enabled = target_stage, True
        cohorts = policy_payload["stage_cohorts"][target_stage]
    elif action == "ROLLBACK":
        rollback = policy_payload["rollback_target_binding"]
        requested = command_payload["target_candidate_binding"]
        if command_payload["target_stage"] is not None or rollback is None or requested != rollback:
            raise RolloutControlError("rollback target does not match the previously authorized candidate")
        if RolloutCandidateBinding.from_mapping(current["candidate_binding"]).as_dict() != policy_payload["candidate_binding"]:
            raise RolloutControlError("rollback target does not match the active authorized candidate")
        target_candidate, stage, enabled, cohorts = rollback, "DISABLED", False, []
    elif action == "RESTORE_CANDIDATE":
        primary = policy_payload["candidate_binding"]
        rollback = policy_payload["rollback_target_binding"]
        requested = command_payload["target_candidate_binding"]
        if command_payload["target_stage"] is not None or rollback is None or requested != primary or current["candidate_binding"] != rollback:
            raise RolloutControlError("restore target does not match the previously authorized candidate")
        target_candidate, stage, enabled, cohorts = primary, "DISABLED", False, []
    else:
        raise RolloutControlError("rollout transition action is unsupported")
    next_state = {
        "schema_version": ROLLOUT_CONTRACT_VERSION,
        "policy_identity": policy_identity,
        "revision": current["revision"] + 1,
        "previous_state_identity": state_identity,
        "candidate_binding": target_candidate,
        "actor_ref": command_payload["actor_ref"],
        "transitioned_at": current_time.isoformat().replace("+00:00", "Z"),
        "stage": stage,
        "admissions_enabled": enabled,
        "admitted_cohorts": cohorts,
        "rollback_rule": _ROLLBACK_RULE,
        "transition_id": command_payload["transition_id"],
        "transition_action": action,
    }
    signed_state = _signed(next_state, key)
    next_identity = hashlib.sha256(_canonical(next_state)).hexdigest()
    signed_head = _signed({"schema_version": ROLLOUT_CONTRACT_VERSION, "revision": next_state["revision"], "state_identity": next_identity}, key)
    return signed_state, signed_head


class ReferenceFileRolloutControl:
    """Signed local reference adapter; not company persistence or IAM."""

    def __init__(self, root: Path, *, key: bytes, cohort_id: str, now: datetime | None = None) -> None:
        self.root = Path(root).expanduser().resolve()
        if (self.root / ".k-slide-config").is_symlink():
            raise RolloutControlError("rollout control directory is unsafe")
        self.key = _key(key)
        self.cohort_id = _name(cohort_id, "deployment-resolved cohort ID")
        self.now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)

    def _read(self, name: str) -> Any:
        path = self.root / ".k-slide-config" / name
        if path.is_symlink() or not path.is_file():
            raise RolloutControlError("rollout control document is missing or unsafe")
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise RolloutControlError("rollout control document is unreadable or malformed") from exc

    def admit(self, candidate: RolloutCandidateBinding) -> RolloutAdmission:
        policy, state, head = self._read("rollout-policy.json"), self._read("rollout-state.json"), self._read("rollout-head.json")
        payload, policy_identity = _policy_payload(policy, self.key, now=self.now)
        current, state_identity = _state_payload(state, self.key, policy_identity=policy_identity, head=head)
        _verify_reference_history(
            self.root / ".k-slide-config",
            key=self.key,
            policy_identity=policy_identity,
            latest_state=current,
            latest_identity=state_identity,
        )
        active = RolloutCandidateBinding.from_mapping(current["candidate_binding"])
        if candidate != active:
            raise RolloutControlError("runtime candidate does not match the authorized rollout candidate")
        policy_candidate = payload["candidate_binding"]
        rollback_candidate = payload["rollback_target_binding"]
        if active.as_dict() not in (policy_candidate, rollback_candidate):
            raise RolloutControlError("rollout state candidate is not authorized by policy")
        if current["transition_action"] == "ROLLBACK" and active.as_dict() != rollback_candidate:
            raise RolloutControlError("rollback state does not select its authorized target")
        if current["transition_action"] == "RESTORE_CANDIDATE" and active.as_dict() != policy_candidate:
            raise RolloutControlError("restored state does not select its authorized candidate")
        stage = current["stage"]
        if not current["admissions_enabled"] or stage == "DISABLED":
            return RolloutAdmission("DENIED", "ADMISSIONS_DISABLED", candidate, policy_identity, payload["policy_version"], current["revision"], stage, self.cohort_id)
        admitted = current["admitted_cohorts"]
        if admitted != payload["stage_cohorts"][stage] or self.cohort_id not in admitted:
            return RolloutAdmission("DENIED", "COHORT_NOT_ADMITTED", candidate, policy_identity, payload["policy_version"], current["revision"], stage, self.cohort_id)
        return RolloutAdmission("ADMITTED", "COHORT_ADMITTED", candidate, policy_identity, payload["policy_version"], current["revision"], stage, self.cohort_id)


def validate_rollout_admission(value: Any, candidate: RolloutCandidateBinding) -> RolloutAdmission:
    """Check deployment adapter results before they become durable evidence."""

    if not isinstance(value, RolloutAdmission) or value.candidate_binding != candidate:
        raise RolloutControlError("rollout admission binding is invalid")
    if value.status not in {"ADMITTED", "DENIED", "REJECTED"}:
        raise RolloutControlError("rollout admission status is invalid")
    allowed_reasons = {"COHORT_ADMITTED", "COHORT_NOT_ADMITTED", "ADMISSIONS_DISABLED", "CONTROL_INVALID", "AUTHORITY_UNAVAILABLE"}
    if value.reason_code not in allowed_reasons:
        raise RolloutControlError("rollout admission reason is invalid")
    if value.status == "ADMITTED" and value.reason_code != "COHORT_ADMITTED":
        raise RolloutControlError("rollout admission result is contradictory")
    if value.status == "DENIED" and value.reason_code not in {"COHORT_NOT_ADMITTED", "ADMISSIONS_DISABLED"}:
        raise RolloutControlError("rollout denial result is contradictory")
    if value.status == "REJECTED" and value.reason_code not in {"CONTROL_INVALID", "AUTHORITY_UNAVAILABLE"}:
        raise RolloutControlError("rollout rejection result is contradictory")
    _name(value.cohort_id, "rollout admission cohort ID")
    if value.policy_identity is not None:
        _digest(value.policy_identity, "rollout policy identity")
    if value.policy_version not in (None, ROLLOUT_CONTRACT_VERSION):
        raise RolloutControlError("rollout admission policy version is unsupported")
    if value.state_revision is not None and (isinstance(value.state_revision, bool) or not isinstance(value.state_revision, int) or value.state_revision < 1):
        raise RolloutControlError("rollout admission state revision is invalid")
    if value.stage not in (None, "DISABLED", *_STAGES):
        raise RolloutControlError("rollout admission stage is invalid")
    if value.rollback_rule != _ROLLBACK_RULE:
        raise RolloutControlError("rollout admission rollback rule is unsupported")
    if value.status in {"ADMITTED", "DENIED"}:
        if value.policy_identity is None or value.policy_version is None or value.state_revision is None or value.stage is None:
            raise RolloutControlError("rollout admission is missing its authorized policy or state identity")
        _name(value.cohort_id, "rollout admission cohort ID")
        if value.status == "ADMITTED" and value.stage not in _STAGES:
            raise RolloutControlError("admitted rollout result has no enabled stage")
        if value.reason_code == "ADMISSIONS_DISABLED" and value.stage != "DISABLED":
            raise RolloutControlError("disabled rollout result has a contradictory stage")
        if value.reason_code == "COHORT_NOT_ADMITTED" and value.stage == "DISABLED":
            raise RolloutControlError("cohort denial has a contradictory disabled stage")
    return value


def deployment_rollout_control() -> RolloutAdmissionProvider | None:
    """Load a process-configured deployment adapter; never inspect tool args."""

    factory_spec = os.environ.get("KSLIDE_ROLLOUT_CONTROL_FACTORY")
    if not factory_spec:
        return None
    if factory_spec.count(":") != 1:
        raise RolloutControlError("deployment rollout adapter configuration is malformed")
    module_name, factory_name = factory_spec.split(":", 1)
    if not module_name or not factory_name:
        raise RolloutControlError("deployment rollout adapter configuration is malformed")
    try:
        factory = getattr(importlib.import_module(module_name), factory_name)
        adapter = factory()
    except Exception as exc:
        raise RolloutControlError("deployment rollout authority is unavailable") from exc
    if not callable(getattr(adapter, "admit", None)):
        raise RolloutControlError("deployment rollout adapter is invalid")
    return adapter


def managed_candidate_environment(environment: RunEnvironmentIdentity) -> bool:
    """Reference compatibility remains explicit and separate from managed runs."""

    return environment.ocr_provider != "reference"


def _history_path(directory: Path, revision: int) -> Path:
    return directory / "rollout-history" / f"{revision:010d}.json"


def _verify_reference_history(
    directory: Path,
    *,
    key: bytes,
    policy_identity: str,
    latest_state: dict[str, Any],
    latest_identity: str,
) -> None:
    history_dir = directory / "rollout-history"
    if history_dir.is_symlink() or not history_dir.is_dir():
        raise RolloutControlError("rollout transition history is missing or unsafe")
    revision = latest_state["revision"]
    history_files = tuple(history_dir.glob("*.json"))
    expected_names = {f"{item:010d}.json" for item in range(1, revision + 1)}
    if len(history_files) != revision or {path.name for path in history_dir.iterdir()} != expected_names:
        raise RolloutControlError("rollout transition history is incomplete or replayed")
    previous_identity: str | None = None
    previous_time: datetime | None = None
    last_payload: dict[str, Any] | None = None
    for expected_revision in range(1, revision + 1):
        path = _history_path(directory, expected_revision)
        if path.is_symlink() or not path.is_file():
            raise RolloutControlError("rollout transition history is incomplete or unsafe")
        try:
            value = read_json(path)
            payload = _verify_signed(value, key, "rollout transition history")
        except Exception as exc:
            raise RolloutControlError("rollout transition history is unreadable or unauthorized") from exc
        if payload.get("policy_identity") != policy_identity or payload.get("revision") != expected_revision:
            raise RolloutControlError("rollout transition history is stale or inconsistent")
        if payload.get("previous_state_identity") != previous_identity:
            raise RolloutControlError("rollout transition history chain is inconsistent")
        transitioned_at = _time(payload.get("transitioned_at"), "rollout transition time")
        if previous_time is not None and transitioned_at < previous_time:
            raise RolloutControlError("rollout transition history time is inconsistent")
        previous_time = transitioned_at
        previous_identity = hashlib.sha256(_canonical(payload)).hexdigest()
        last_payload = payload
    if previous_identity != latest_identity or last_payload != latest_state:
        raise RolloutControlError("rollout transition history does not match current state")


def initialize_reference_rollout_control(root: Path, *, policy: dict[str, Any], key: bytes, now: datetime | None = None) -> None:
    """Create the local reference policy, state, and monotonic head once."""

    root = Path(root).expanduser().resolve()
    directory = root / ".k-slide-config"
    if directory.is_symlink():
        raise RolloutControlError("rollout control directory is unsafe")
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    paths = tuple(directory / name for name in ("rollout-policy.json", "rollout-state.json", "rollout-head.json"))
    history_dir = directory / "rollout-history"
    with filesystem_lock(directory / "rollout-control.lock"):
        if any(path.exists() or path.is_symlink() for path in paths) or history_dir.exists() or history_dir.is_symlink():
            raise RolloutControlError("rollout control is already initialized")
        state = initial_rollout_state(policy, key=key, now=now)
        state_payload = _verify_signed(state, key, "initial rollout state")
        head = _signed(
            {
                "schema_version": ROLLOUT_CONTRACT_VERSION,
                "revision": state_payload["revision"],
                "state_identity": hashlib.sha256(_canonical(state_payload)).hexdigest(),
            },
            key,
        )
        atomic_write_json(paths[0], policy, mode=0o600)
        atomic_write_json(paths[1], state, mode=0o600)
        atomic_write_json(paths[2], head, mode=0o600)
        history_dir.mkdir(mode=0o700)
        atomic_write_json(_history_path(directory, 1), state, mode=0o600)


def transition_reference_rollout_control(root: Path, *, command: dict[str, Any], key: bytes, now: datetime | None = None) -> int:
    """Apply a signed CAS transition to the local reference adapter."""

    root = Path(root).expanduser().resolve()
    directory = root / ".k-slide-config"
    if directory.is_symlink():
        raise RolloutControlError("rollout control directory is unsafe")
    policy_path, state_path, head_path = (directory / name for name in ("rollout-policy.json", "rollout-state.json", "rollout-head.json"))
    with filesystem_lock(directory / "rollout-control.lock"):
        if any(path.is_symlink() for path in (policy_path, state_path, head_path)):
            raise RolloutControlError("rollout control state is unsafe")
        try:
            policy, state, head = read_json(policy_path), read_json(state_path), read_json(head_path)
        except Exception as exc:
            raise RolloutControlError("rollout control state is missing or unreadable") from exc
        payload, policy_identity = _policy_payload(policy, key, now=(now or datetime.now(timezone.utc)).astimezone(timezone.utc))
        current, state_identity = _state_payload(state, key, policy_identity=policy_identity, head=head)
        _verify_reference_history(directory, key=key, policy_identity=policy_identity, latest_state=current, latest_identity=state_identity)
        next_state, next_head = apply_rollout_transition(policy=policy, state=state, head=head, command=command, key=key, now=now)
        # A crash between these two writes makes the state fail closed until an
        # authorized control-plane reconciliation. The signed head is the
        # reference adapter's monotonic replay anchor.
        next_revision = _verify_signed(next_state, key, "rollout state")["revision"]
        history_path = _history_path(directory, next_revision)
        if history_path.exists() or history_path.is_symlink():
            raise RolloutControlError("rollout transition history revision already exists")
        atomic_write_json(history_path, next_state, mode=0o600)
        atomic_write_json(state_path, next_state, mode=0o600)
        atomic_write_json(head_path, next_head, mode=0o600)
        return next_revision
