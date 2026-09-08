"""Stable, user-safe K-Slide errors."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ErrorCode(str, Enum):
    INPUT_NOT_FOUND = "KSLIDE_INPUT_NOT_FOUND"
    INPUT_UNSUPPORTED = "KSLIDE_INPUT_UNSUPPORTED"
    INPUT_CORRUPT = "KSLIDE_INPUT_CORRUPT"
    INPUT_EMPTY = "KSLIDE_INPUT_EMPTY"
    INPUT_TYPE_MISMATCH = "KSLIDE_INPUT_TYPE_MISMATCH"
    INPUT_TOO_LARGE = "KSLIDE_INPUT_TOO_LARGE"
    INPUT_ARCHIVE_UNSAFE = "KSLIDE_INPUT_ARCHIVE_UNSAFE"
    PATH_OUTSIDE_ALLOWED_ROOT = "KSLIDE_PATH_OUTSIDE_ALLOWED_ROOT"
    RUN_NOT_FOUND = "KSLIDE_RUN_NOT_FOUND"
    STATE_CORRUPT = "KSLIDE_STATE_CORRUPT"
    INVALID_TRANSITION = "KSLIDE_INVALID_STATE_TRANSITION"
    SCHEMA_INVALID = "KSLIDE_SCHEMA_INVALID"
    VERIFICATION_FAILED = "KSLIDE_VERIFICATION_FAILED"
    COMPLETION_BLOCKED = "KSLIDE_COMPLETION_BLOCKED"
    INSTALL_COLLISION = "KSLIDE_INSTALL_COLLISION"
    INSTALL_INVALID = "KSLIDE_INSTALL_INVALID"
    RUNTIME_UNKNOWN = "KSLIDE_RUNTIME_UNKNOWN"
    MODEL_UNKNOWN = "KSLIDE_MODEL_UNKNOWN"
    PDF_RENDER_UNAVAILABLE = "KSLIDE_PDF_RENDER_UNAVAILABLE"
    PPTX_RENDER_UNAVAILABLE = "KSLIDE_PPTX_RENDER_UNAVAILABLE"
    OCR_UNAVAILABLE = "KSLIDE_OCR_UNAVAILABLE"
    INTERNAL = "KSLIDE_INTERNAL"


@dataclass
class KSlideError(Exception):
    """An error that can be shown without exposing raw internals."""

    code: ErrorCode
    message: str
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        super().__init__(self.message)

    def as_dict(self) -> dict[str, Any]:
        return {"code": self.code.value, "message": self.message, "details": self.details}
