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


@dataclass(frozen=True)
class AuthenticationReadiness:
    """Non-secret authentication readiness information."""

    ready: bool
    reason: str

    def as_dict(self) -> dict[str, object]:
        return {"ready": self.ready, "reason": self.reason}


def authentication_readiness(environment: Mapping[str, str] | None = None) -> AuthenticationReadiness:
    """Check the process-provisioned AccessKey without returning its value."""

    values = os.environ if environment is None else environment
    value = values.get(ACCESS_KEY_ENV)
    if value is None:
        return AuthenticationReadiness(False, "missing")
    if not isinstance(value, str):
        return AuthenticationReadiness(False, "unusable")
    if not value.strip():
        return AuthenticationReadiness(False, "empty")
    if value != value.strip():
        return AuthenticationReadiness(False, "unusable")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        return AuthenticationReadiness(False, "unusable")
    return AuthenticationReadiness(True, "available")


def require_access_key(environment: Mapping[str, str] | None = None) -> str:
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
            "Company authentication is unavailable; configure a valid AccessKey in the process environment.",
            {"phase": "authentication", "reason": readiness.reason},
        )
    return values[ACCESS_KEY_ENV]
