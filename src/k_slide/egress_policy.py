"""Versioned, deployment-owned default-deny egress policy.

The policy contains only opaque deployment identities and bounded capability
metadata.  It never contains an endpoint, host, credential, source value, or
content-derived identity.  Network enforcement itself remains an external
deployment certification concern; this module is the in-process admission
boundary that must run before an injected transport is called.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from .errors import ErrorCode, KSlideError


EGRESS_POLICY_SCHEMA_VERSION = "1.0"
EGRESS_POLICY_FILENAME = "egress-policy.json"
EGRESS_DEFAULT_ACTION = "deny"

EGRESS_CAPABILITY_INFERENCE_ROUTE = "inference_route"
EGRESS_CAPABILITY_DURABLE_JOB_CONTROL = "durable_job_control"
EGRESS_CAPABILITY_SCOPED_STORAGE = "scoped_storage"
EGRESS_CAPABILITY_NON_CONTENT_TELEMETRY = "non_content_telemetry"
EGRESS_CAPABILITY_CLASSES = (
    EGRESS_CAPABILITY_INFERENCE_ROUTE,
    EGRESS_CAPABILITY_DURABLE_JOB_CONTROL,
    EGRESS_CAPABILITY_SCOPED_STORAGE,
    EGRESS_CAPABILITY_NON_CONTENT_TELEMETRY,
)

EGRESS_PURPOSE_INFERENCE = "model_inference"
EGRESS_PURPOSE_JOB_CONTROL = "job_control"
EGRESS_PURPOSE_STORAGE = "scoped_storage"
EGRESS_PURPOSE_TELEMETRY = "non_content_telemetry"

EGRESS_DATA_CLASS_SOURCE_CONTENT = "source_content"
EGRESS_DATA_CLASS_OPERATIONAL_METADATA = "operational_metadata"
EGRESS_DATA_CLASS_NON_CONTENT = "non_content"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IDENTITY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,127}$")
_FORBIDDEN_IDENTITY_MARKERS = (
    "access",
    "credential",
    "password",
    "prompt",
    "secret",
    "source_text",
    "token",
)

OPENCODE_ROUTE_CANONICALIZATION_VERSION = "k-slide-opencode-route-v1"
_CAPABILITY_FIELDS = frozenset({"capability_class", "purpose", "service_identity", "route_identity", "endpoint_identity", "data_class"})
_POLICY_FIELDS = frozenset({"schema_version", "policy_version", "policy_hash", "policy_identity", "default_action", "capabilities"})


def _policy_error(message: str, *, code: ErrorCode = ErrorCode.EGRESS_POLICY_INVALID) -> KSlideError:
    return KSlideError(code, message)


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _hash(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def opencode_route_identity(*, provider_id: Any, model_id: Any, api_id: Any, api_npm: Any, api_url: Any) -> str:
    """Hash the complete resolved OpenCode v1.3.9 API route.

    This is deliberately a small language-neutral wire format.  Each route
    component is encoded as UTF-8 and length-prefixed in bytes, so Python and
    TypeScript/Bun can derive the same source-free identity without storing
    the endpoint URL itself.
    """

    values = (
        ("providerID", provider_id),
        ("modelID", model_id),
        ("api.id", api_id),
        ("api.npm", api_npm),
        ("api.url", api_url),
    )
    lines = [OPENCODE_ROUTE_CANONICALIZATION_VERSION]
    for label, value in values:
        if not isinstance(value, str) or not value or "\x00" in value or "\r" in value or "\n" in value:
            raise _policy_error("OpenCode route material is malformed.")
        encoded = value.encode("utf-8")
        lines.append(f"{label}={len(encoded)}:{value}")
    return _hash(("\n".join(lines) + "\n").encode("utf-8"))


def _identity(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or not _IDENTITY.fullmatch(value)
        or "://" in value
        or value.startswith(("/", "\\"))
        or any(marker in value.casefold() for marker in _FORBIDDEN_IDENTITY_MARKERS)
    ):
        raise _policy_error(f"Egress policy {label} is malformed.")
    return value


def _version(value: Any) -> str:
    if not isinstance(value, str) or not _VERSION.fullmatch(value):
        raise _policy_error("Egress policy version is malformed.")
    return value


def _capability_class(value: Any) -> str:
    if value not in EGRESS_CAPABILITY_CLASSES:
        raise _policy_error("Egress policy contains an unknown capability class.", code=ErrorCode.EGRESS_CAPABILITY_DENIED)
    return str(value)


def _purpose(value: Any, capability_class: str) -> str:
    expected = {
        EGRESS_CAPABILITY_INFERENCE_ROUTE: EGRESS_PURPOSE_INFERENCE,
        EGRESS_CAPABILITY_DURABLE_JOB_CONTROL: EGRESS_PURPOSE_JOB_CONTROL,
        EGRESS_CAPABILITY_SCOPED_STORAGE: EGRESS_PURPOSE_STORAGE,
        EGRESS_CAPABILITY_NON_CONTENT_TELEMETRY: EGRESS_PURPOSE_TELEMETRY,
    }[capability_class]
    if value != expected:
        raise _policy_error("Egress policy capability purpose is not the closed purpose for its class.")
    return expected


def _data_class(value: Any, capability_class: str) -> str:
    expected = {
        EGRESS_CAPABILITY_INFERENCE_ROUTE: EGRESS_DATA_CLASS_SOURCE_CONTENT,
        EGRESS_CAPABILITY_DURABLE_JOB_CONTROL: EGRESS_DATA_CLASS_OPERATIONAL_METADATA,
        EGRESS_CAPABILITY_SCOPED_STORAGE: EGRESS_DATA_CLASS_SOURCE_CONTENT,
        EGRESS_CAPABILITY_NON_CONTENT_TELEMETRY: EGRESS_DATA_CLASS_NON_CONTENT,
    }[capability_class]
    if value != expected:
        raise _policy_error("Egress policy capability data class is not allowed for its class.")
    return expected


def _semantic_capability(value: Mapping[str, Any]) -> dict[str, str | None]:
    if set(value) != _CAPABILITY_FIELDS:
        if "endpoint_identity" not in value:
            raise _policy_error("Egress policy endpoint identity is missing.")
        raise _policy_error("Egress policy capability has missing or unsupported fields.")
    capability_class = _capability_class(value.get("capability_class"))
    purpose = _purpose(value.get("purpose"), capability_class)
    service_identity = _identity(value.get("service_identity"), "service identity")
    route_raw = value.get("route_identity")
    if capability_class == EGRESS_CAPABILITY_INFERENCE_ROUTE:
        route_identity = _identity(route_raw, "route identity")
    elif route_raw is None:
        route_identity = None
    else:
        raise _policy_error("Only the inference capability may declare a route identity.")
    endpoint_raw = value.get("endpoint_identity")
    if capability_class == EGRESS_CAPABILITY_INFERENCE_ROUTE:
        if not isinstance(endpoint_raw, str) or not _SHA256.fullmatch(endpoint_raw):
            raise _policy_error("Egress policy endpoint identity is malformed.")
        endpoint_identity = endpoint_raw
    elif endpoint_raw is None:
        endpoint_identity = None
    else:
        raise _policy_error("Only the inference capability may declare an endpoint identity.")
    data_class = _data_class(value.get("data_class"), capability_class)
    return {
        "capability_class": capability_class,
        "purpose": purpose,
        "service_identity": service_identity,
        "route_identity": route_identity,
        "endpoint_identity": endpoint_identity,
        "data_class": data_class,
    }


def _semantic_payload(*, policy_version: str, capabilities: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    normalized = sorted(
        (_semantic_capability(item) for item in capabilities),
        key=lambda item: str(item["capability_class"]),
    )
    return {
        "schema_version": EGRESS_POLICY_SCHEMA_VERSION,
        "policy_version": policy_version,
        "default_action": EGRESS_DEFAULT_ACTION,
        "capabilities": normalized,
    }


def egress_policy_hash_for_mapping(*, policy_version: str, capabilities: Iterable[Mapping[str, Any]]) -> str:
    """Return the exact semantic hash for one default-deny policy."""

    version = _version(policy_version)
    values = list(capabilities)
    return _hash(_canonical_bytes(_semantic_payload(policy_version=version, capabilities=values)))


def egress_policy_identity_for_mapping(*, policy_version: str, policy_hash: str) -> str:
    version = _version(policy_version)
    if not isinstance(policy_hash, str) or not _SHA256.fullmatch(policy_hash):
        raise _policy_error("Egress policy hash is malformed.")
    return _hash(_canonical_bytes({"schema_version": EGRESS_POLICY_SCHEMA_VERSION, "policy_version": version, "policy_hash": policy_hash}))


@dataclass(frozen=True)
class EgressCapability:
    capability_class: str
    purpose: str
    service_identity: str
    route_identity: str | None
    endpoint_identity: str | None
    data_class: str

    @classmethod
    def from_mapping(cls, value: Any) -> "EgressCapability":
        if not isinstance(value, Mapping):
            raise _policy_error("Egress capability is not an object.")
        normalized = _semantic_capability(value)
        return cls(
            capability_class=str(normalized["capability_class"]),
            purpose=str(normalized["purpose"]),
            service_identity=str(normalized["service_identity"]),
            route_identity=normalized["route_identity"],
            endpoint_identity=normalized["endpoint_identity"],
            data_class=str(normalized["data_class"]),
        )

    def as_dict(self) -> dict[str, str | None]:
        return {
            "capability_class": self.capability_class,
            "purpose": self.purpose,
            "service_identity": self.service_identity,
            "route_identity": self.route_identity,
            "endpoint_identity": self.endpoint_identity,
            "data_class": self.data_class,
        }


@dataclass(frozen=True)
class EgressPolicy:
    policy_version: str
    policy_hash: str
    policy_identity: str
    capabilities: tuple[EgressCapability, ...]
    reference_adapter: bool = False
    schema_version: str = EGRESS_POLICY_SCHEMA_VERSION
    default_action: str = EGRESS_DEFAULT_ACTION

    def __post_init__(self) -> None:
        if self.schema_version != EGRESS_POLICY_SCHEMA_VERSION:
            raise _policy_error("Unsupported egress policy schema.")
        version = _version(self.policy_version)
        if self.default_action != EGRESS_DEFAULT_ACTION:
            raise _policy_error("Egress policy must be default-deny.")
        if not isinstance(self.policy_hash, str) or not _SHA256.fullmatch(self.policy_hash):
            raise _policy_error("Egress policy hash is malformed.")
        if not isinstance(self.policy_identity, str) or not _SHA256.fullmatch(self.policy_identity):
            raise _policy_error("Egress policy identity is malformed.")
        capabilities = tuple(self.capabilities)
        if len(capabilities) != len(EGRESS_CAPABILITY_CLASSES):
            raise _policy_error("Egress policy must explicitly declare every capability class.")
        classes = tuple(item.capability_class for item in capabilities)
        if set(classes) != set(EGRESS_CAPABILITY_CLASSES):
            raise _policy_error("Egress policy must declare each capability class exactly once.")
        records = [item.as_dict() for item in sorted(capabilities, key=lambda item: item.capability_class)]
        expected_hash = egress_policy_hash_for_mapping(policy_version=version, capabilities=records)
        if self.policy_hash != expected_hash:
            raise _policy_error("Egress policy hash does not match its capabilities.")
        expected_identity = egress_policy_identity_for_mapping(policy_version=version, policy_hash=self.policy_hash)
        if self.policy_identity != expected_identity:
            raise _policy_error("Egress policy identity does not match its version and hash.")
        object.__setattr__(self, "policy_version", version)
        object.__setattr__(self, "capabilities", tuple(sorted(capabilities, key=lambda item: item.capability_class)))

    @classmethod
    def from_mapping(cls, value: Any, *, reference_adapter: bool = False) -> "EgressPolicy":
        if not isinstance(value, Mapping) or set(value) != _POLICY_FIELDS:
            raise _policy_error("Egress policy has missing required fields or unsupported fields.")
        raw_capabilities = value.get("capabilities")
        if not isinstance(raw_capabilities, list):
            raise _policy_error("Egress policy capabilities are unresolved.")
        capabilities = tuple(EgressCapability.from_mapping(item) for item in raw_capabilities)
        policy_hash = value.get("policy_hash")
        policy_identity = value.get("policy_identity")
        default_action = value.get("default_action")
        if not isinstance(policy_hash, str) or not isinstance(policy_identity, str) or not isinstance(default_action, str):
            raise _policy_error("Egress policy identity or default action is malformed.")
        policy = cls(
            policy_version=_version(value.get("policy_version")),
            policy_hash=policy_hash,
            policy_identity=policy_identity,
            capabilities=capabilities,
            reference_adapter=reference_adapter,
            schema_version=str(value.get("schema_version")),
            default_action=default_action,
        )
        return policy

    @classmethod
    def reference(cls) -> "EgressPolicy":
        capabilities = tuple(
            EgressCapability(
                capability_class=capability_class,
                purpose={
                    EGRESS_CAPABILITY_INFERENCE_ROUTE: EGRESS_PURPOSE_INFERENCE,
                    EGRESS_CAPABILITY_DURABLE_JOB_CONTROL: EGRESS_PURPOSE_JOB_CONTROL,
                    EGRESS_CAPABILITY_SCOPED_STORAGE: EGRESS_PURPOSE_STORAGE,
                    EGRESS_CAPABILITY_NON_CONTENT_TELEMETRY: EGRESS_PURPOSE_TELEMETRY,
                }[capability_class],
                service_identity="reference-adapter",
                route_identity="reference" if capability_class == EGRESS_CAPABILITY_INFERENCE_ROUTE else None,
                endpoint_identity=opencode_route_identity(
                    provider_id="reference",
                    model_id="reference",
                    api_id="reference",
                    api_npm="reference",
                    api_url="reference",
                ) if capability_class == EGRESS_CAPABILITY_INFERENCE_ROUTE else None,
                data_class={
                    EGRESS_CAPABILITY_INFERENCE_ROUTE: EGRESS_DATA_CLASS_SOURCE_CONTENT,
                    EGRESS_CAPABILITY_DURABLE_JOB_CONTROL: EGRESS_DATA_CLASS_OPERATIONAL_METADATA,
                    EGRESS_CAPABILITY_SCOPED_STORAGE: EGRESS_DATA_CLASS_SOURCE_CONTENT,
                    EGRESS_CAPABILITY_NON_CONTENT_TELEMETRY: EGRESS_DATA_CLASS_NON_CONTENT,
                }[capability_class],
            )
            for capability_class in EGRESS_CAPABILITY_CLASSES
        )
        policy_version = "1.0"
        records = [item.as_dict() for item in capabilities]
        policy_hash = egress_policy_hash_for_mapping(policy_version=policy_version, capabilities=records)
        return cls(
            policy_version=policy_version,
            policy_hash=policy_hash,
            policy_identity=egress_policy_identity_for_mapping(policy_version=policy_version, policy_hash=policy_hash),
            capabilities=capabilities,
            reference_adapter=True,
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "policy_version": self.policy_version,
            "policy_hash": self.policy_hash,
            "policy_identity": self.policy_identity,
            "default_action": self.default_action,
            "capabilities": [item.as_dict() for item in self.capabilities],
        }

    def capability(self, capability_class: str) -> EgressCapability:
        for capability in self.capabilities:
            if capability.capability_class == capability_class:
                return capability
        raise _policy_error("Egress capability is not allowlisted.", code=ErrorCode.EGRESS_CAPABILITY_DENIED)

    def authorize(
        self,
        capability_class: str,
        purpose: str,
        *,
        route_identity: str | None = None,
        endpoint_identity: str | None = None,
        service_identity: str | None = None,
        data_class: str | None = None,
    ) -> EgressCapability:
        """Authorize one engine-selected use before transport invocation."""

        if capability_class not in EGRESS_CAPABILITY_CLASSES:
            raise _policy_error("Egress capability is unknown or denied.", code=ErrorCode.EGRESS_CAPABILITY_DENIED)
        capability = self.capability(capability_class)
        if capability.purpose != purpose:
            raise _policy_error("Egress capability purpose is not allowlisted.", code=ErrorCode.EGRESS_CAPABILITY_DENIED)
        if capability.route_identity is None and route_identity is not None:
            raise _policy_error("Egress capability does not accept a route identity.", code=ErrorCode.EGRESS_ROUTE_MISMATCH)
        if capability.route_identity is not None and capability.route_identity != route_identity:
            raise _policy_error("Egress route identity is not allowlisted.", code=ErrorCode.EGRESS_ROUTE_MISMATCH)
        if capability.endpoint_identity is None and endpoint_identity is not None:
            raise _policy_error("Egress capability does not accept an endpoint identity.", code=ErrorCode.EGRESS_ROUTE_MISMATCH)
        if capability.endpoint_identity is not None and capability.endpoint_identity != endpoint_identity:
            raise _policy_error("Egress endpoint identity is not allowlisted.", code=ErrorCode.EGRESS_ROUTE_MISMATCH)
        if capability.service_identity != service_identity:
            raise _policy_error("Egress service identity is not allowlisted.", code=ErrorCode.EGRESS_ROUTE_MISMATCH)
        if capability.data_class != data_class:
            raise _policy_error("Egress data class is not allowlisted.", code=ErrorCode.EGRESS_CAPABILITY_DENIED)
        return capability


def load_egress_policy(root: Path, *, allow_reference_adapter: bool = False) -> EgressPolicy:
    """Load only the deployment-owned policy; absence is default deny."""

    path = root.expanduser().resolve() / ".k-slide-config" / EGRESS_POLICY_FILENAME
    if not path.is_file() or path.is_symlink():
        if allow_reference_adapter:
            return EgressPolicy.reference()
        raise _policy_error("Egress policy is missing.")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise _policy_error("Egress policy is malformed or unresolved.") from exc
    return EgressPolicy.from_mapping(value)


def policy_completeness(value: Any) -> tuple[bool, str]:
    """Return an authoritative readiness result without proving live network enforcement."""

    try:
        policy = value if isinstance(value, EgressPolicy) else EgressPolicy.from_mapping(value)
    except KSlideError as exc:
        return False, exc.message
    if policy.reference_adapter:
        return False, "reference policy adapter is non-authoritative"
    return True, "resolved"


REFERENCE_EGRESS_POLICY = EgressPolicy.reference()


__all__ = [
    "EGRESS_POLICY_SCHEMA_VERSION",
    "EGRESS_POLICY_FILENAME",
    "EGRESS_DEFAULT_ACTION",
    "EGRESS_CAPABILITY_INFERENCE_ROUTE",
    "EGRESS_CAPABILITY_DURABLE_JOB_CONTROL",
    "EGRESS_CAPABILITY_SCOPED_STORAGE",
    "EGRESS_CAPABILITY_NON_CONTENT_TELEMETRY",
    "EGRESS_CAPABILITY_CLASSES",
    "EGRESS_PURPOSE_INFERENCE",
    "EGRESS_PURPOSE_JOB_CONTROL",
    "EGRESS_PURPOSE_STORAGE",
    "EGRESS_PURPOSE_TELEMETRY",
    "EGRESS_DATA_CLASS_SOURCE_CONTENT",
    "EGRESS_DATA_CLASS_OPERATIONAL_METADATA",
    "EGRESS_DATA_CLASS_NON_CONTENT",
    "EgressCapability",
    "EgressPolicy",
    "REFERENCE_EGRESS_POLICY",
    "OPENCODE_ROUTE_CANONICALIZATION_VERSION",
    "opencode_route_identity",
    "egress_policy_hash_for_mapping",
    "egress_policy_identity_for_mapping",
    "load_egress_policy",
    "policy_completeness",
]
