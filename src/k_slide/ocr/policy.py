"""Managed OCR selection for normal runs and reproducible evaluations."""

from __future__ import annotations

import importlib.util
import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from ..errors import ErrorCode, KSlideError
from .base import OCRProvider
from .none import NoneOCRProvider


class OCRProviderPolicy(str, Enum):
    NONE = "none"
    PADDLE = "paddle"
    AUTO = "auto"


@dataclass(frozen=True)
class OCRProviderSelection:
    requested: str
    effective: str
    version: str
    provider: OCRProvider
    reason: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "ocr_policy_requested": self.requested,
            "ocr_provider_effective": self.effective,
            "ocr_provider_version": self.version,
            "ocr_reason": self.reason,
        }


def _parse_policy_file(path: Path) -> str | None:
    try:
        text = path.read_text(encoding="utf-8")
        if path.suffix == ".json":
            value = json.loads(text)
            value = value.get("ocr_provider", value.get("ocr_policy")) if isinstance(value, dict) else value
            return str(value).strip().lower() if value is not None else None
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].strip()
            if line.startswith("ocr_provider:") or line.startswith("ocr_policy:"):
                return line.split(":", 1)[1].strip().strip("'\"").lower()
    except (OSError, json.JSONDecodeError, ValueError):
        return None
    return None


def load_ocr_policy(root: Path | None = None) -> OCRProviderPolicy:
    root = (root or Path.cwd()).resolve()
    config_dir = root / ".k-slide-config"
    for name in ("ocr.local.json", "ocr.local.yaml", "ocr.local.yml"):
        value = _parse_policy_file(config_dir / name)
        if value:
            try:
                return OCRProviderPolicy(value)
            except ValueError as exc:
                raise KSlideError(ErrorCode.SCHEMA_INVALID, "Unsupported OCR provider policy.", {"policy": value}) from exc
    return OCRProviderPolicy.AUTO


def _paddle_available() -> bool:
    return importlib.util.find_spec("paddleocr") is not None and importlib.util.find_spec("paddle") is not None


def create_ocr_provider(policy: OCRProviderPolicy | str = OCRProviderPolicy.AUTO) -> OCRProviderSelection:
    try:
        requested = OCRProviderPolicy(policy).value
    except ValueError as exc:
        raise KSlideError(ErrorCode.SCHEMA_INVALID, "Unsupported OCR provider policy.", {"policy": str(policy)}) from exc
    if requested == OCRProviderPolicy.NONE.value:
        provider = NoneOCRProvider()
        return OCRProviderSelection(requested, provider.name, provider.version, provider, "explicitly disabled")
    if requested == OCRProviderPolicy.PADDLE.value and not _paddle_available():
        raise KSlideError(ErrorCode.OCR_PROVIDER_UNAVAILABLE, "PaddleOCR/PaddlePaddle is required by the selected OCR policy.")
    if requested in {OCRProviderPolicy.PADDLE.value, OCRProviderPolicy.AUTO.value} and _paddle_available():
        try:
            from .paddle import PaddleOCRProvider

            provider = PaddleOCRProvider()
            return OCRProviderSelection(requested, provider.name, provider.version, provider, None)
        except KSlideError:
            if requested == OCRProviderPolicy.PADDLE.value:
                raise
        except Exception as exc:
            if requested == OCRProviderPolicy.PADDLE.value:
                raise KSlideError(ErrorCode.OCR_PROVIDER_UNAVAILABLE, "PaddleOCR could not be initialized.", {"reason": str(exc)}) from exc
    provider = NoneOCRProvider()
    return OCRProviderSelection(requested, provider.name, provider.version, provider, "PaddleOCR unavailable; using NoneOCRProvider")
