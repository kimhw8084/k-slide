"""Secret-free company authentication readiness boundary.

K-Slide does not own company login, credential provisioning, storage, or
transport. An approved caller may require the pre-provisioned ``AccessKey``
from the current process environment when a future company service boundary
is actually used. This module only validates readiness and never serializes
the key into K-Slide state or metadata.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass

from .errors import ErrorCode, KSlideError


ACCESS_KEY_ENV = "AccessKey"
_MISSING = object()


@dataclass(frozen=True)
class AuthenticationReadiness:
    """Non-secret authentication readiness information."""

    ready: bool
    reason: str

    def as_dict(self) -> dict[str, object]:
        return {"ready": self.ready, "reason": self.reason}


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
