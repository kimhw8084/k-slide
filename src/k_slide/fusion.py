"""Deterministic native/OCR literal evidence fusion."""

from __future__ import annotations

from difflib import SequenceMatcher
from typing import Any


def _text(value: Any) -> str:
    return str(value.get("text", "")).strip() if isinstance(value, dict) else str(value).strip()


def fuse_literal_evidence(native_candidates: list[dict[str, Any]], ocr_candidates: list[dict[str, Any]]) -> tuple[str | None, float | None, str]:
    native = next((_text(item) for item in native_candidates if _text(item)), None)
    ocr = next((_text(item) for item in sorted(ocr_candidates, key=lambda item: float(item.get("confidence", 0.0)), reverse=True) if _text(item)), None)
    if native and ocr:
        agreement = SequenceMatcher(None, native, ocr).ratio()
        if agreement >= 0.90:
            return native, 1.0, "HIGH_AGREEMENT"
        if agreement >= 0.60:
            return native, 0.75, "MEDIUM_AGREEMENT"
        return native, 0.5, "DISAGREEMENT"
    if native:
        return native, 1.0, "NATIVE_ONLY"
    if ocr:
        confidence = max((float(item.get("confidence")) for item in ocr_candidates if item.get("confidence") is not None), default=0.0)
        return ocr, confidence, "OCR_ONLY" if confidence >= 0.80 else "LOW_CONFIDENCE"
    return None, None, "NO_LITERAL_EVIDENCE"
