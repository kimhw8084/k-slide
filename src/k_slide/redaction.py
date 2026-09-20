"""Content-safe redaction for diagnostics and support metadata.

Run artifacts intentionally contain the source reconstruction.  This module
is for diagnostics/support output only; it prevents credentials, home paths,
and obvious document/model content fields from being copied into support
bundles or public evaluation metadata.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

_ACCESS_KEY_NAME = r"access[\s_.:/-]*(?:key|token)"
_GENERIC_SECRET_NAME = r"(?:token(?![_A-Za-z0-9])|api[\s_.:/-]*key|auth(?:orization)?|password|secret|cookie|private[\s_.:/-]*key|credential(?:s)?)"
_SECRET_NAME = rf"(?:{_ACCESS_KEY_NAME}|{_GENERIC_SECRET_NAME})"
_SECRET_KEY = re.compile(rf"(?<![A-Za-z0-9]){_SECRET_NAME}(?![A-Za-z0-9])", re.IGNORECASE)
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
_ASSIGNMENT = re.compile(rf"(?i)(?P<prefix>\b{_SECRET_NAME}\b\s*[\"']?\s*[:=]\s*)")
_URL_CREDENTIALS = re.compile(r"(?i)(https?://)([^/@\s]+):([^/@\s]+)@")
_REDACTED_VALUE = "[REDACTED]"
_REDACTED_UNSAFE_DIAGNOSTIC = "[REDACTED_UNSAFE_DIAGNOSTIC]"


class CredentialExposureError(ValueError):
    """Raised when an operational diagnostic cannot be persisted safely."""


def _secret_values(values: Iterable[str]) -> tuple[str, ...]:
    """Return only caller-supplied secret values.

    The process AccessKey is intentionally not added here. Treating an
    ambient short/common value as a global substring authority can corrupt
    unrelated operational prose and source-like business text.
    """

    candidates = [value for value in values if isinstance(value, str) and value]
    return tuple(dict.fromkeys(sorted(candidates, key=len, reverse=True)))


def _is_secret_key(key: str) -> bool:
    """Recognize secret-bearing field names without matching ordinary tokens."""

    # Governed terminology identities are opaque, source-free deployment
    # references. They are not credentials and must remain re-derivable in
    # candidate/run metadata; the authority boundary is still external.
    if key.lower() in {"authorization_identity", "governance_identity", "policy_identity", "order_identity", "core_identity"}:
        return False
    return _SECRET_KEY.search(key) is not None


def _redact_assignments(value: str) -> str:
    """Redact labelled assignments without guessing credential syntax.

    A quoted value has an explicit boundary. For an unquoted value, the
    format is deliberately unknown, so the remainder of that bounded
    diagnostic line is redacted instead of inventing a token grammar.
    """

    result: list[str] = []
    cursor = 0
    while cursor < len(value):
        match = _ASSIGNMENT.search(value, cursor)
        if match is None:
            result.append(value[cursor:])
            break
        result.append(value[cursor:match.end()])
        start = match.end()
        quote = value[start] if start < len(value) and value[start] in "\"'`" else None
        line_end = value.find("\n", start)
        if line_end < 0:
            line_end = len(value)
        if quote is not None:
            close = value.find(quote, start + 1, line_end)
            if close >= 0:
                result.append(quote + _REDACTED_VALUE + quote)
                cursor = close + 1
                continue
        result.append(_REDACTED_VALUE)
        cursor = line_end
    return "".join(result)


def _assignment_free_text(value: str) -> str:
    """Return only text outside labelled credential assignments."""

    result: list[str] = []
    cursor = 0
    while cursor < len(value):
        match = _ASSIGNMENT.search(value, cursor)
        if match is None:
            result.append(value[cursor:])
            break
        result.append(value[cursor:match.start()])
        start = match.end()
        quote = value[start] if start < len(value) and value[start] in "\"'`" else None
        line_end = value.find("\n", start)
        if line_end < 0:
            line_end = len(value)
        if quote is not None:
            close = value.find(quote, start + 1, line_end)
            if close >= 0:
                cursor = close + 1
                continue
        cursor = line_end
    return "".join(result)


def redact_text(value: str, *, roots: tuple[Path, ...] = (), secret_values: Iterable[str] = ()) -> str:
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
    unlabelled = _assignment_free_text(result)
    result = _redact_assignments(result)
    result = _BEARER.sub(r"\1[REDACTED]", result)
    result = _URL_CREDENTIALS.sub(r"\1[REDACTED]@", result)
    unlabelled = _BEARER.sub(r"\1[REDACTED]", unlabelled)
    unlabelled = _URL_CREDENTIALS.sub(r"\1[REDACTED]@", unlabelled)
    if any(secret in unlabelled for secret in _secret_values(secret_values)):
        # A caller-provided secret value is usable only as provenance for this
        # bounded free-form field.  It is never a license to rewrite matching
        # substrings inside otherwise meaningful operational text.
        return _REDACTED_UNSAFE_DIAGNOSTIC
    return result


def sanitize_operational(value: Any, *, roots: tuple[Path, ...] = (), secret_values: Iterable[str] = ()) -> Any:
    """Sanitize operational/error metadata at an external output boundary.

    Callers must not use this for source-owned evidence or translated business
    content. Those payloads have a separate model-facing/output contract.
    """

    return redact_value(value, roots=roots, secret_values=secret_values)


def redact_value(value: Any, *, roots: tuple[Path, ...] = (), key: str | None = None, secret_values: Iterable[str] = ()) -> Any:
    """Recursively redact a JSON-compatible diagnostic value."""

    secrets = _secret_values(secret_values)
    return _redact_value(value, roots=roots, key=key, secrets=secrets)


def _redact_value(value: Any, *, roots: tuple[Path, ...], key: str | None, secrets: tuple[str, ...]) -> Any:
    if key and _is_secret_key(key):
        return "[REDACTED_SECRET]"
    if key and key.lower() in _CONTENT_KEYS:
        return "[REDACTED_CONTENT]"
    if isinstance(value, str):
        return redact_text(value, roots=roots, secret_values=secrets)
    if isinstance(value, dict):
        return {
            str(name): _redact_value(item, roots=roots, key=str(name), secrets=secrets)
            for name, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_value(item, roots=roots, key=None, secrets=secrets) for item in value]
    if isinstance(value, tuple):
        return [_redact_value(item, roots=roots, key=None, secrets=secrets) for item in value]
    return value


def redact_credentials(value: Any, *, roots: tuple[Path, ...] = (), secret_values: Iterable[str] = ()) -> Any:
    """Redact credentials while preserving non-secret diagnostic/content fields."""

    secrets = _secret_values(secret_values)

    def visit(item: Any, key: str | None = None) -> Any:
        if key and _is_secret_key(key):
            return "[REDACTED_SECRET]"
        if isinstance(item, str):
            return redact_text(item, roots=roots, secret_values=secrets)
        if isinstance(item, dict):
            return {
                str(name): visit(child, str(name))
                for name, child in item.items()
            }
        if isinstance(item, list):
            return [visit(child) for child in item]
        if isinstance(item, tuple):
            return [visit(child) for child in item]
        return item

    return visit(value)


def redact_json(value: Any, *, roots: tuple[Path, ...] = (), secret_values: Iterable[str] = ()) -> str:
    return json.dumps(redact_value(value, roots=roots, secret_values=secret_values), ensure_ascii=False, indent=2) + "\n"


def redact_environment(value: dict[str, str]) -> dict[str, str]:
    """Return a safe environment subset for diagnostic metadata."""

    allowed = {"PATH", "LANG", "LC_ALL", "PYTHONPATH", "KSLIDE_VERSION", "OPENCODE_VERSION"}
    return sanitize_operational({key: str(item) for key, item in value.items() if key in allowed})


def safe_diagnostic_text(value: str, *, roots: tuple[Path, ...] = (), secret_values: Iterable[str] = ()) -> str:
    """Return text safe for operational persistence, or fail closed.

    Labelled assignments and explicitly provenance-bound secret values are
    sanitized normally. Ambient process values are not a credential authority
    for generic text because ordinary prose can contain the same value.
    """

    return redact_text(value, roots=roots, secret_values=secret_values)


def safe_diagnostic_text_or_placeholder(value: str, *, roots: tuple[Path, ...] = (), secret_values: Iterable[str] = ()) -> str:
    """Return a persisted diagnostic line, or a fixed safe placeholder."""

    try:
        lines: list[str] = []
        for line in value.splitlines(keepends=True):
            safe = safe_diagnostic_text(line, roots=roots, secret_values=secret_values)
            if safe == _REDACTED_UNSAFE_DIAGNOSTIC:
                body = line.rstrip("\r\n")
                safe = _REDACTED_UNSAFE_DIAGNOSTIC + line[len(body):]
            lines.append(safe)
        return "".join(lines) or safe_diagnostic_text(value, roots=roots, secret_values=secret_values)
    except CredentialExposureError:
        return _REDACTED_UNSAFE_DIAGNOSTIC


def safe_operational_json(value: Any, *, roots: tuple[Path, ...] = (), secret_values: Iterable[str] = ()) -> str:
    """Serialize operational data using structural/provenance redaction."""

    safe = sanitize_operational(value, roots=roots, secret_values=secret_values)
    return json.dumps(safe, ensure_ascii=False, indent=2) + "\n"


def safe_credential_json(value: Any, *, roots: tuple[Path, ...] = (), secret_values: Iterable[str] = ()) -> str:
    """Serialize captured diagnostics without ambient substring matching."""

    safe = redact_credentials(value, roots=roots, secret_values=secret_values)
    return json.dumps(safe, ensure_ascii=False, indent=2) + "\n"
