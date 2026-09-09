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


_SECRET_KEY = re.compile(r"(?:api[_-]?key|access[_-]?token|auth(?:orization)?|password|secret|cookie|private[_-]?key)", re.IGNORECASE)
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
_ASSIGNMENT = re.compile(r"(?i)(\b(?:api[_-]?key|access[_-]?token|authorization|password|secret)\b\s*[:=]\s*)((?:bearer\s+)?[^\s,;]+)")
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
    result = _BEARER.sub(r"\1[REDACTED]", result)
    result = _ASSIGNMENT.sub(r"\1[REDACTED]", result)
    result = _URL_CREDENTIALS.sub(r"\1[REDACTED]@", result)
    return result


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
