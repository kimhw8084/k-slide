"""Secret-free company authentication readiness and call boundary.

K-Slide does not own company login, credential provisioning, storage, or
wire transport. An approved caller may require the pre-provisioned
``AccessKey`` from the current process environment when an injected approved
company-service boundary is actually used. This module keeps the raw key out
of K-Slide state and metadata.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field, fields, is_dataclass
from typing import Any, Protocol

from .errors import ErrorCode, KSlideError


ACCESS_KEY_ENV = "AccessKey"
_MISSING = object()
_OPERATION = re.compile(r"^[A-Za-z][A-Za-z0-9_.:/-]{0,127}$")
_URL_VALUE = re.compile(r"(?i)(?:[a-z][a-z0-9+.-]*://|//)")
_REQUEST_KEY_MARKERS = (
    "accesskey",
    "access_key",
    "api_key",
    "authorization",
    "auth_header",
    "header",
    "headers",
    "secret",
    "token",
    "password",
    "credential",
    "url",
    "uri",
    "endpoint",
    "destination",
    "redirect",
    "base_url",
    "host",
    "port",
    "scheme",
    "transport",
)


@dataclass(frozen=True)
class AuthenticationReadiness:
    """Non-secret authentication readiness information."""

    ready: bool
    reason: str

    def as_dict(self) -> dict[str, object]:
        return {"ready": self.ready, "reason": self.reason}


class ApprovedCompanyServiceTransport(Protocol):
    """Deployment-injected binding to an already-approved company service.

    The transport owns the endpoint, protocol, and wire-level credential
    placement. K-Slide deliberately has no URL, header, bearer, LDAP, or
    token-exchange configuration here. ``access_key`` is a dedicated
    ephemeral call argument and is never part of ``request``.
    """

    def call(self, request: "CompanyServiceRequest", *, access_key: str) -> object: ...


class CompanyServiceAuthenticationRejected(Exception):
    """Explicit deployment-adapter signal for an invalid/rejected AccessKey."""

    def __init__(self, *_adapter_details: object, **_ignored: object) -> None:
        # Do not accept or retain adapter-provided reason text. The boundary
        # maps this signal to its own fixed, secret-free operational error.
        super().__init__("Company service authentication was rejected.")


# Short spelling for deployment adapters and deterministic test doubles.
AuthenticationRejected = CompanyServiceAuthenticationRejected


def _request_key_is_unsafe(key: str) -> bool:
    normalized = key.casefold().replace("-", "_").replace(" ", "_")
    return any(marker in normalized for marker in _REQUEST_KEY_MARKERS)


def _normalize_request_value(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, str)):
        if isinstance(value, str) and _URL_VALUE.search(value):
            raise KSlideError(ErrorCode.SCHEMA_INVALID, "Company-service request contains an unsupported destination value.")
        return value
    if isinstance(value, float):
        if not (-float("inf") < value < float("inf")):
            raise KSlideError(ErrorCode.SCHEMA_INVALID, "Company-service request contains a non-finite value.")
        return value
    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str) or not key or _request_key_is_unsafe(key):
                raise KSlideError(ErrorCode.SCHEMA_INVALID, "Company-service request contains an unsupported field.")
            normalized[key] = _normalize_request_value(item)
        return normalized
    if isinstance(value, (list, tuple)):
        return [_normalize_request_value(item) for item in value]
    raise KSlideError(ErrorCode.SCHEMA_INVALID, "Company-service request must contain only serializable values.")


def _contains_secret(value: Any, secret: str) -> bool:
    """Inspect supported response/request containers without invoking repr()."""

    if isinstance(value, str):
        return secret in value
    if isinstance(value, Mapping):
        return any(_contains_secret(key, secret) or _contains_secret(item, secret) for key, item in value.items())
    if isinstance(value, (list, tuple, set, frozenset)):
        return any(_contains_secret(item, secret) for item in value)
    if is_dataclass(value) and not isinstance(value, type):
        return any(_contains_secret(getattr(value, field.name), secret) for field in fields(value))
    return False


@dataclass(frozen=True)
class CompanyServiceRequest:
    """Serializable ordinary data for one approved company-service call.

    A request has no destination or credential fields. This prevents a
    caller-controlled URL or payload value from becoming a transport target.
    """

    operation: str
    payload: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.operation, str) or not _OPERATION.fullmatch(self.operation) or _URL_VALUE.search(self.operation):
            raise KSlideError(ErrorCode.SCHEMA_INVALID, "Company-service operation is invalid.")
        if not isinstance(self.payload, Mapping):
            raise KSlideError(ErrorCode.SCHEMA_INVALID, "Company-service request payload must be an object.")
        normalized = _normalize_request_value(self.payload)
        try:
            json.dumps(normalized, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
        except (TypeError, ValueError) as exc:
            raise KSlideError(ErrorCode.SCHEMA_INVALID, "Company-service request is not serializable.") from exc
        object.__setattr__(self, "payload", normalized)

    @classmethod
    def from_mapping(cls, value: Any) -> "CompanyServiceRequest":
        if not isinstance(value, Mapping) or set(value) != {"operation", "payload"}:
            raise KSlideError(ErrorCode.SCHEMA_INVALID, "Company-service request must contain operation and payload.")
        return cls(value["operation"], value["payload"])

    def as_dict(self) -> dict[str, Any]:
        # The normalized payload is JSON-safe, but return a fresh JSON-shaped
        # copy so adapter mutation cannot alter the caller's request object.
        return {"operation": self.operation, "payload": json.loads(json.dumps(self.payload, ensure_ascii=False, allow_nan=False))}


def _authentication_failure(reason: str) -> KSlideError:
    return KSlideError(
        ErrorCode.AUTHENTICATION_FAILED,
        "Approved company-service authentication failed.",
        {"phase": "authentication", "reason": reason},
    )


def authenticated_company_service_call(
    transport: ApprovedCompanyServiceTransport,
    request: CompanyServiceRequest | Mapping[str, Any],
) -> object:
    """Call an injected approved service with an ephemeral process AccessKey.

    ``require_access_key()`` is intentionally called only after request and
    transport validation, immediately before the authenticated call. The
    process environment is the only production credential authority; the
    optional mapping seam on ``require_access_key`` remains for its existing
    deterministic unit tests and is not exposed here.
    """

    ordinary_request = request if isinstance(request, CompanyServiceRequest) else CompanyServiceRequest.from_mapping(request)
    call = getattr(transport, "call", None)
    if not callable(call):
        raise _authentication_failure("transport_unavailable")

    access_key = require_access_key()
    try:
        if _contains_secret(ordinary_request.as_dict(), access_key):
            raise _authentication_failure("request_separation")
        try:
            response = call(ordinary_request, access_key=access_key)
        except CompanyServiceAuthenticationRejected:
            raise _authentication_failure("rejected") from None
        except KSlideError as exc:
            if exc.code is ErrorCode.AUTHENTICATION_FAILED:
                raise _authentication_failure("rejected") from None
            raise _authentication_failure("transport_failed") from None
        except Exception:
            # Do not expose adapter exception text. Transport failures are
            # operational failures and never semantic NEEDS_REVIEW.
            raise _authentication_failure("transport_failed") from None
        if _contains_secret(response, access_key):
            raise _authentication_failure("response_separation")
        try:
            json.dumps(response, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
        except (TypeError, ValueError):
            raise _authentication_failure("response_not_serializable") from None
        return response
    finally:
        # Keep the raw value's lifetime bounded to the actual service call.
        del access_key


def authentication_readiness(environment: Mapping[str, object] | None = None) -> AuthenticationReadiness:
    """Check only format-independent readiness of a process-provisioned key."""

    values = os.environ if environment is None else environment
    value = values.get(ACCESS_KEY_ENV, _MISSING)
    if value is _MISSING:
        return AuthenticationReadiness(False, "missing")
    if not isinstance(value, str):
        return AuthenticationReadiness(False, "unusable")
    if value == "":
        return AuthenticationReadiness(False, "empty")
    return AuthenticationReadiness(True, "available")


def require_access_key(environment: Mapping[str, object] | None = None) -> str:
    """Return an in-memory AccessKey or fail with a secret-free auth error.

    The returned value is intentionally not persisted by this module. Callers
    are responsible for using it only for an approved in-memory service
    request once such transport is present.
    """

    values = os.environ if environment is None else environment
    readiness = authentication_readiness(values)
    if not readiness.ready:
        raise KSlideError(
            ErrorCode.AUTHENTICATION_FAILED,
            "Company authentication is unavailable; configure a nonempty AccessKey in the process environment.",
            {"phase": "authentication", "reason": readiness.reason},
        )
    return values[ACCESS_KEY_ENV]  # type: ignore[return-value]
