"""Secret-free company authentication readiness boundary.

K-Slide does not own company login, credential provisioning, storage, or
transport. An approved caller may require the pre-provisioned ``AccessKey``
from the current process environment when a future company service boundary
is actually used. This module only validates readiness and never serializes
the key into K-Slide state or metadata.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass

from .errors import ErrorCode, KSlideError


ACCESS_KEY_ENV = "AccessKey"
ACCESS_KEY_TOKEN_PATTERN = r"[A-Za-z0-9._~+/=-]+"
ACCESS_KEY_VALUE_RE = re.compile(rf"(?:bearer\s+{ACCESS_KEY_TOKEN_PATTERN}|{ACCESS_KEY_TOKEN_PATTERN})", re.IGNORECASE)


@dataclass(frozen=True)
class AuthenticationReadiness:
    """Non-secret authentication readiness information."""

    ready: bool
    reason: str

    def as_dict(self) -> dict[str, object]:
        return {"ready": self.ready, "reason": self.reason}


def authentication_readiness(environment: Mapping[str, str] | None = None) -> AuthenticationReadiness:
    """Check a process-provisioned AccessKey without returning its value.

    The bounded representation contract is an opaque token made from the
    URL-safe/base64-safe alphabet, optionally prefixed by ``Bearer ``. The
    contract deliberately excludes diagnostic delimiters and line breaks so a
    value accepted here can be fully masked in assignment-style diagnostics.
    """

    values = os.environ if environment is None else environment
    value = values.get(ACCESS_KEY_ENV)
    if value is None:
        return AuthenticationReadiness(False, "missing")
    if not isinstance(value, str):
        return AuthenticationReadiness(False, "unusable")
    if not value.strip():
        return AuthenticationReadiness(False, "empty")
    if not ACCESS_KEY_VALUE_RE.fullmatch(value):
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
