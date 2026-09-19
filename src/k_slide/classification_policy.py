"""Fail-closed classification admission for configured inference routes.

This contract intentionally contains no document-derived values.  A policy is
deployment-owned metadata: it binds one exact inference route, one exact
version, one semantic policy hash, and one policy identity to exact
classification labels.  The reference constructor is a test adapter only;
it is never loaded for a candidate/runtime-derived production environment.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from .errors import ErrorCode, KSlideError


CLASSIFICATION_POLICY_SCHEMA_VERSION = "1.0"
DEFAULT_CLASSIFICATION = "company_confidential"
INFERENCE_DATA_USE_POLICY_FILENAME = "inference-data-use-policy.json"
REFERENCE_ROUTE_IDENTITY = "reference"
REFERENCE_POLICY_VERSION = "1.0"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IDENTITY = re.compile(r"^[A-Za-z][A-Za-z0-9_.:/@+-]{0,255}$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,127}$")
_LABEL = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,127}$")
_POLICY_FIELDS = frozenset(
    {
        "schema_version",
        "inference_route_identity",
        "policy_version",
        "policy_hash",
        "policy_identity",
        "classification_rules",
    }
)


def _policy_error(message: str, *, details: Mapping[str, Any] | None = None) -> KSlideError:
    return KSlideError(ErrorCode.CLASSIFICATION_POLICY_INVALID, message, dict(details or {}))


def validate_classification_label(value: Any, *, allow_none: bool = True) -> str | None:
    """Validate without case folding, trimming, ranking, or other normalization."""

    if value is None and allow_none:
        return None
    if not isinstance(value, str) or not _LABEL.fullmatch(value):
        raise KSlideError(ErrorCode.CLASSIFICATION_UNKNOWN, "Input classification is unknown or unsupported.")
    return value


def _identity(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _IDENTITY.fullmatch(value):
        raise _policy_error(f"Inference data-use policy {label} is malformed.")
    return value


def _policy_version(value: Any) -> str:
    if not isinstance(value, str) or not _VERSION.fullmatch(value):
        raise _policy_error("Inference data-use policy version is malformed.")
    return value


def _hash(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _semantic_payload(*, route: str, version: str, rules: Mapping[str, bool]) -> dict[str, Any]:
    return {
        "schema_version": CLASSIFICATION_POLICY_SCHEMA_VERSION,
        "inference_route_identity": route,
        "policy_version": version,
        "classification_rules": {key: rules[key] for key in sorted(rules)},
    }


def policy_hash_for_mapping(*, inference_route_identity: str, policy_version: str, classification_rules: Mapping[str, bool]) -> str:
    """Return the exact semantic hash expected by ``InferenceDataUsePolicy``."""

    route = _identity(inference_route_identity, "route identity")
    version = _policy_version(policy_version)
    rules = _validated_rules(classification_rules)
    return _hash(_canonical_bytes(_semantic_payload(route=route, version=version, rules=rules)))


def policy_identity_for_mapping(*, inference_route_identity: str, policy_version: str, policy_hash: str) -> str:
    route = _identity(inference_route_identity, "route identity")
    version = _policy_version(policy_version)
    if not isinstance(policy_hash, str) or not _SHA256.fullmatch(policy_hash):
        raise _policy_error("Inference data-use policy hash is malformed.")
    return _hash(_canonical_bytes({"inference_route_identity": route, "policy_version": version, "policy_hash": policy_hash}))


def _validated_rules(value: Any) -> dict[str, bool]:
    if not isinstance(value, Mapping) or not value:
        raise _policy_error("Inference data-use policy classification rules are unresolved.")
    rules: dict[str, bool] = {}
    for raw_label, approved in value.items():
        try:
            label = validate_classification_label(raw_label, allow_none=False)
        except KSlideError as exc:
            raise _policy_error("Inference data-use policy classification rules contain a malformed label.") from exc
        if not isinstance(approved, bool):
            raise _policy_error("Inference data-use policy classification rules are malformed.")
        if label in rules:
            raise _policy_error("Inference data-use policy contains duplicate classification labels.")
        rules[label] = approved
    return rules


@dataclass(frozen=True)
class InferenceDataUsePolicy:
    """Exact route/data-use policy used by the engine admission boundary."""

    inference_route_identity: str
    policy_version: str
    policy_hash: str
    policy_identity: str
    classification_rules: tuple[tuple[str, bool], ...]
    reference_adapter: bool = False
    schema_version: str = CLASSIFICATION_POLICY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != CLASSIFICATION_POLICY_SCHEMA_VERSION:
            raise _policy_error("Unsupported inference data-use policy schema.")
        route = _identity(self.inference_route_identity, "route identity")
        version = _policy_version(self.policy_version)
        if not isinstance(self.policy_hash, str) or not _SHA256.fullmatch(self.policy_hash):
            raise _policy_error("Inference data-use policy hash is malformed.")
        if not isinstance(self.policy_identity, str) or not _SHA256.fullmatch(self.policy_identity):
            raise _policy_error("Inference data-use policy identity is malformed.")
        rules = _validated_rules(dict(self.classification_rules))
        expected_hash = policy_hash_for_mapping(inference_route_identity=route, policy_version=version, classification_rules=rules)
        if self.policy_hash != expected_hash:
            raise _policy_error("Inference data-use policy hash does not match its exact rules.")
        expected_identity = policy_identity_for_mapping(inference_route_identity=route, policy_version=version, policy_hash=self.policy_hash)
        if self.policy_identity != expected_identity:
            raise _policy_error("Inference data-use policy identity does not match its exact route and hash.")
        object.__setattr__(self, "classification_rules", tuple(sorted(rules.items())))

    @classmethod
    def from_mapping(cls, value: Any, *, reference_adapter: bool = False) -> "InferenceDataUsePolicy":
        if not isinstance(value, Mapping) or set(value) != _POLICY_FIELDS:
            raise _policy_error("Inference data-use policy is missing required fields or contains unsupported fields.")
        route = _identity(value.get("inference_route_identity"), "route identity")
        version = _policy_version(value.get("policy_version"))
        rules = _validated_rules(value.get("classification_rules"))
        raw_hash = value.get("policy_hash")
        raw_identity = value.get("policy_identity")
        if not isinstance(raw_hash, str) or not _SHA256.fullmatch(raw_hash):
            raise _policy_error("Inference data-use policy hash is malformed.")
        if not isinstance(raw_identity, str) or not _SHA256.fullmatch(raw_identity):
            raise _policy_error("Inference data-use policy identity is malformed.")
        return cls(route, version, raw_hash, raw_identity, tuple(rules.items()), reference_adapter=reference_adapter, schema_version=str(value["schema_version"]))

    @classmethod
    def reference(cls, *, route_identity: str = REFERENCE_ROUTE_IDENTITY) -> "InferenceDataUsePolicy":
        route = _identity(route_identity, "route identity")
        rules = {DEFAULT_CLASSIFICATION: True}
        policy_hash = policy_hash_for_mapping(inference_route_identity=route, policy_version=REFERENCE_POLICY_VERSION, classification_rules=rules)
        return cls(
            route,
            REFERENCE_POLICY_VERSION,
            policy_hash,
            policy_identity_for_mapping(inference_route_identity=route, policy_version=REFERENCE_POLICY_VERSION, policy_hash=policy_hash),
            tuple(rules.items()),
            reference_adapter=True,
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "inference_route_identity": self.inference_route_identity,
            "policy_version": self.policy_version,
            "policy_hash": self.policy_hash,
            "policy_identity": self.policy_identity,
            "classification_rules": {label: approved for label, approved in self.classification_rules},
        }

    def approved(self, classification: str) -> bool:
        validate_classification_label(classification, allow_none=False)
        rules = dict(self.classification_rules)
        if classification not in rules:
            raise KSlideError(ErrorCode.CLASSIFICATION_UNKNOWN, "Input classification is unknown or unsupported.")
        return rules[classification]

    @property
    def classifications(self) -> tuple[str, ...]:
        return tuple(label for label, _approved in self.classification_rules)


@dataclass(frozen=True)
class ClassificationAdmission:
    """Source-free durable admission metadata."""

    classifications: tuple[str, ...]
    inference_route_identity: str
    policy_version: str
    policy_hash: str
    policy_identity: str
    status: str = "ADMITTED"

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": CLASSIFICATION_POLICY_SCHEMA_VERSION,
            "status": self.status,
            "classifications": list(self.classifications),
            "inference_route_identity": self.inference_route_identity,
            "policy_version": self.policy_version,
            "policy_hash": self.policy_hash,
            "policy_identity": self.policy_identity,
        }


def load_inference_data_use_policy(
    root: Path,
    *,
    route_identity: str,
    policy: InferenceDataUsePolicy | Mapping[str, Any] | None = None,
    allow_reference_adapter: bool = False,
) -> InferenceDataUsePolicy:
    """Load only deployment configuration or an explicitly supplied adapter."""

    route = _identity(route_identity, "route identity")
    if policy is not None:
        resolved = policy if isinstance(policy, InferenceDataUsePolicy) else InferenceDataUsePolicy.from_mapping(policy)
    else:
        path = root.expanduser().resolve() / ".k-slide-config" / INFERENCE_DATA_USE_POLICY_FILENAME
        if not path.is_file() or path.is_symlink():
            if allow_reference_adapter and route == REFERENCE_ROUTE_IDENTITY:
                resolved = InferenceDataUsePolicy.reference(route_identity=route)
            else:
                raise _policy_error("Inference data-use policy is missing.")
        else:
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                raise _policy_error("Inference data-use policy is malformed or unresolved.") from exc
            resolved = InferenceDataUsePolicy.from_mapping(value)
    if resolved.inference_route_identity != route:
        raise KSlideError(ErrorCode.CLASSIFICATION_POLICY_ROUTE_MISMATCH, "Inference data-use policy does not match the configured inference route.")
    return resolved


def admit_classifications(classifications: Iterable[str | None], policy: InferenceDataUsePolicy) -> ClassificationAdmission:
    """Admit every document independently; no severity ordering is applied."""

    labels: list[str] = []
    for index, raw_label in enumerate(classifications, start=1):
        label = raw_label if raw_label is not None else DEFAULT_CLASSIFICATION
        validate_classification_label(label, allow_none=False)
        labels.append(label)
        try:
            approved = policy.approved(label)
        except KSlideError as exc:
            raise KSlideError(exc.code, exc.message, {"input_index": index}) from exc
        if not approved:
            raise KSlideError(ErrorCode.CLASSIFICATION_NOT_APPROVED, "Input classification is not approved for the configured inference route.", {"input_index": index})
    return ClassificationAdmission(tuple(labels), policy.inference_route_identity, policy.policy_version, policy.policy_hash, policy.policy_identity)


def policy_completeness(value: Any) -> tuple[bool, str]:
    """Return a source-free readiness result for certification callers."""

    try:
        if isinstance(value, InferenceDataUsePolicy):
            policy = value
        else:
            policy = InferenceDataUsePolicy.from_mapping(value)
    except KSlideError as exc:
        return False, exc.message
    if policy.reference_adapter:
        return False, "reference policy adapter is non-authoritative"
    return True, "resolved"


__all__ = [
    "CLASSIFICATION_POLICY_SCHEMA_VERSION",
    "DEFAULT_CLASSIFICATION",
    "INFERENCE_DATA_USE_POLICY_FILENAME",
    "REFERENCE_ROUTE_IDENTITY",
    "InferenceDataUsePolicy",
    "ClassificationAdmission",
    "admit_classifications",
    "load_inference_data_use_policy",
    "policy_completeness",
    "policy_hash_for_mapping",
    "policy_identity_for_mapping",
    "validate_classification_label",
]
