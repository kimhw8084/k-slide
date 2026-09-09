"""Provider-neutral OCR result contracts."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol


@dataclass(frozen=True)
class OCRRegion:
    text: str
    bbox_px: tuple[int, int, int, int]
    confidence: float | None = None
    reading_order: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class OCRResult:
    provider: str
    provider_version: str
    language_hints: tuple[str, ...] = ()
    regions: tuple[OCRRegion, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)


class OCRProvider(Protocol):
    name: str
    version: str

    def extract(self, image: Path, *, language_hints: tuple[str, ...] = ("ko", "en")) -> OCRResult:
        ...
