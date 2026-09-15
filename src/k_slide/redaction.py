"""Content-safe redaction for diagnostics and support metadata.

Run artifacts intentionally contain the source reconstruction.  This module
is for diagnostics/support output only; it prevents credentials, home paths,
and obvious document/model content fields from being copied into support
bundles or public evaluation metadata.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .authentication import ACCESS_KEY_ENV

_ACCESS_KEY_NAME = r"access[\s_-]?(?:key|token)"
_GENERIC_SECRET_NAME = r"(?:api[\s_-]?key|auth(?:orization)?|password|secret|cookie|private[\s_-]?key)"
_SECRET_NAME = rf"(?:{_ACCESS_KEY_NAME}|{_GENERIC_SECRET_NAME})"
_SECRET_KEY = re.compile(_SECRET_NAME, re.IGNORECASE)
_CONTENT_KEYS = {
    "text",
    "english",
    "source_text",
    "translated_text",
    "prompt",
    "content",
    "final_text",
    "source_candidates",
    "ocr_candidates",
}
_BEARER = re.compile(r"(?i)(\bbearer\s+)[A-Za-z0-9._~+/=-]+")
_ASSIGNMENT = re.compile(rf"(?i)(\b{_GENERIC_SECRET_NAME}\b['\"]?\s*[:=]\s*['\"]?)((?:bearer\s+)?[^\s,;\"']+)")
_URL_CREDENTIALS = re.compile(r"(?i)(https?://)([^/@\s]+):([^/@\s]+)@")
_REDACTED_VALUE = "[REDACTED]"


def _secret_values(values: Iterable[str]) -> tuple[str, ...]:
    candidates = [value for value in values if isinstance(value, str) and value]
    process_access_key = os.environ.get(ACCESS_KEY_ENV)
    if process_access_key:
        candidates.append(process_access_key)
    return tuple(dict.fromkeys(sorted(candidates, key=len, reverse=True)))


def redact_text(value: str, *, roots: tuple[Path, ...] = (), secret_values: Iterable[str] = ()) -> str:
    """Redact credentials and local absolute paths without logging content."""

    result = value
    for secret in _secret_values(secret_values):
        result = result.replace(secret, _REDACTED_VALUE)
    home = str(Path.home())
    if home:
        result = result.replace(home, "$HOME")
    for root in roots:
        try:
            result = result.replace(str(root.resolve()), "$KSLIDE_ROOT")
        except OSError:
            continue
    result = _ASSIGNMENT.sub(r"\1[REDACTED]", result)
    result = _BEARER.sub(r"\1[REDACTED]", result)
    result = _URL_CREDENTIALS.sub(r"\1[REDACTED]@", result)
    return result


def sanitize_operational(value: Any, *, roots: tuple[Path, ...] = (), secret_values: Iterable[str] = ()) -> Any:
    """Sanitize operational/error metadata at an external output boundary.

    Callers must not use this for source-owned evidence or translated business
    content. Those payloads have a separate model-facing/output contract.
    """

    return redact_value(value, roots=roots, secret_values=secret_values)


def redact_value(value: Any, *, roots: tuple[Path, ...] = (), key: str | None = None, secret_values: Iterable[str] = ()) -> Any:
    """Recursively redact a JSON-compatible diagnostic value."""

    return _redact_value(value, roots=roots, key=key, secrets=_secret_values(secret_values))


def _redact_value(value: Any, *, roots: tuple[Path, ...], key: str | None, secrets: tuple[str, ...]) -> Any:
    if key and _SECRET_KEY.search(key):
        return "[REDACTED_SECRET]"
    if key and key.lower() in _CONTENT_KEYS:
        return "[REDACTED_CONTENT]"
    if isinstance(value, str):
        return redact_text(value, roots=roots, secret_values=secrets)
    if isinstance(value, dict):
        return {
            redact_text(str(name), roots=roots, secret_values=secrets): _redact_value(item, roots=roots, key=str(name), secrets=secrets)
            for name, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_value(item, roots=roots, key=None, secrets=secrets) for item in value]
    if isinstance(value, tuple):
        return [_redact_value(item, roots=roots, key=None, secrets=secrets) for item in value]
    return value


def redact_json(value: Any, *, roots: tuple[Path, ...] = (), secret_values: Iterable[str] = ()) -> str:
    return json.dumps(redact_value(value, roots=roots, secret_values=secret_values), ensure_ascii=False, indent=2) + "\n"


def redact_environment(value: dict[str, str]) -> dict[str, str]:
    """Return a safe environment subset for diagnostic metadata."""

    allowed = {"PATH", "LANG", "LC_ALL", "PYTHONPATH", "KSLIDE_VERSION", "OPENCODE_VERSION"}
    return sanitize_operational({key: str(item) for key, item in value.items() if key in allowed})
