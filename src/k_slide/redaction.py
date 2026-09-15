"""Content-safe redaction for diagnostics and support metadata.

Run artifacts intentionally contain the source reconstruction.  This module
is for diagnostics/support output only; it prevents credentials, home paths,
and obvious document/model content fields from being copied into support
bundles or public evaluation metadata.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .authentication import ACCESS_KEY_TOKEN_PATTERN, ACCESS_KEY_VALUE_RE

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
_BEARER = re.compile(rf"(?i)(\bbearer\s+){ACCESS_KEY_TOKEN_PATTERN}")
_ACCESS_KEY_ASSIGNMENT = re.compile(
    rf"(?i)(\b{_ACCESS_KEY_NAME}\b['\"]?\s*[:=]\s*['\"]?)({ACCESS_KEY_VALUE_RE.pattern})"
)
_ASSIGNMENT = re.compile(rf"(?i)(\b{_GENERIC_SECRET_NAME}\b['\"]?\s*[:=]\s*['\"]?)((?:bearer\s+)?[^\s,;\"']+)")
_URL_CREDENTIALS = re.compile(r"(?i)(https?://)([^/@\s]+):([^/@\s]+)@")


def redact_text(value: str, *, roots: tuple[Path, ...] = ()) -> str:
    """Redact credentials and local absolute paths without logging content."""

    result = value
    home = str(Path.home())
    if home:
        result = result.replace(home, "$HOME")
    for root in roots:
        try:
            result = result.replace(str(root.resolve()), "$KSLIDE_ROOT")
        except OSError:
            continue
    result = _ACCESS_KEY_ASSIGNMENT.sub(r"\1[REDACTED]", result)
    result = _ASSIGNMENT.sub(r"\1[REDACTED]", result)
    result = _BEARER.sub(r"\1[REDACTED]", result)
    result = _URL_CREDENTIALS.sub(r"\1[REDACTED]@", result)
    return result


def sanitize_operational(value: Any, *, roots: tuple[Path, ...] = ()) -> Any:
    """Sanitize operational/error metadata at an external output boundary.

    Callers must not use this for source-owned evidence or translated business
    content. Those payloads have a separate model-facing/output contract.
    """

    return redact_value(value, roots=roots)


def redact_value(value: Any, *, roots: tuple[Path, ...] = (), key: str | None = None) -> Any:
    """Recursively redact a JSON-compatible diagnostic value."""

    if key and _SECRET_KEY.search(key):
        return "[REDACTED_SECRET]"
    if key and key.lower() in _CONTENT_KEYS:
        return "[REDACTED_CONTENT]"
    if isinstance(value, str):
        return redact_text(value, roots=roots)
    if isinstance(value, dict):
        return {str(name): redact_value(item, roots=roots, key=str(name)) for name, item in value.items()}
    if isinstance(value, list):
        return [redact_value(item, roots=roots) for item in value]
    if isinstance(value, tuple):
        return [redact_value(item, roots=roots) for item in value]
    return value


def redact_json(value: Any, *, roots: tuple[Path, ...] = ()) -> str:
    return json.dumps(redact_value(value, roots=roots), ensure_ascii=False, indent=2) + "\n"


def redact_environment(value: dict[str, str]) -> dict[str, str]:
    """Return a safe environment subset for diagnostic metadata."""

    allowed = {"PATH", "LANG", "LC_ALL", "PYTHONPATH", "KSLIDE_VERSION", "OPENCODE_VERSION"}
    return {key: redact_text(str(item)) for key, item in value.items() if key in allowed}
