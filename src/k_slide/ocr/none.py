"""Explicit no-OCR provider for local-first deployments without an OCR runtime."""

from __future__ import annotations

from pathlib import Path

from .base import OCRResult


class NoneOCRProvider:
    name = "none"
    version = "1"

    def extract(self, image: Path, *, language_hints: tuple[str, ...] = ("ko", "en")) -> OCRResult:
        return OCRResult(provider=self.name, provider_version=self.version, language_hints=language_hints, metadata={"status": "not_configured", "image": image.name})
