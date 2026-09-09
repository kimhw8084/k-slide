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
    fallback: bool = False
    fallback_code: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "ocr_policy_requested": self.requested,
            "ocr_provider_effective": self.effective,
            "ocr_provider_version": self.version,
            "ocr_reason": self.reason,
            "ocr_fallback": self.fallback,
            "ocr_fallback_code": self.fallback_code,
        }


def _parse_policy_file(path: Path) -> str | None:
    text = path.read_text(encoding="utf-8")
    if not text.strip():
        raise KSlideError(ErrorCode.CONFIG_INVALID, "OCR configuration is empty.", {"path": str(path)})
    if path.suffix == ".json":
        try:
            value = json.loads(text)
        except json.JSONDecodeError as exc:
            raise KSlideError(ErrorCode.CONFIG_INVALID, "OCR JSON configuration is malformed.", {"path": str(path), "reason": str(exc)}) from exc
        if not isinstance(value, dict) or not ("ocr_provider" in value or "ocr_policy" in value):
            raise KSlideError(ErrorCode.CONFIG_INVALID, "OCR configuration must define ocr_provider.", {"path": str(path)})
        selected = value.get("ocr_provider", value.get("ocr_policy"))
        if not isinstance(selected, str) or not selected.strip():
            raise KSlideError(ErrorCode.CONFIG_INVALID, "OCR provider policy must be a non-empty string.", {"path": str(path)})
        return selected.strip().lower()
    selected: str | None = None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if ":" not in line:
            raise KSlideError(ErrorCode.CONFIG_INVALID, "OCR YAML configuration is malformed.", {"path": str(path), "line": raw})
        key, value = (item.strip() for item in line.split(":", 1))
        if key in {"ocr_provider", "ocr_policy"}:
            if selected is not None:
                raise KSlideError(ErrorCode.CONFIG_INVALID, "OCR configuration defines the provider more than once.", {"path": str(path)})
            selected = value.strip("'\"").strip().lower()
    if selected is None or not selected:
        raise KSlideError(ErrorCode.CONFIG_INVALID, "OCR YAML configuration must define ocr_provider.", {"path": str(path)})
    return selected


def load_ocr_policy(root: Path | None = None) -> OCRProviderPolicy:
    root = (root or Path.cwd()).resolve()
    config_dir = root / ".k-slide-config"
    for name in ("ocr.local.json", "ocr.local.yaml", "ocr.local.yml"):
        path = config_dir / name
        if not path.is_file():
            continue
        value = _parse_policy_file(path)
        try:
            return OCRProviderPolicy(value)
        except ValueError as exc:
            raise KSlideError(ErrorCode.CONFIG_INVALID, "Unsupported OCR provider policy.", {"path": str(path), "policy": value}) from exc
    return OCRProviderPolicy.AUTO


def _paddle_available() -> bool:
    return importlib.util.find_spec("paddleocr") is not None and importlib.util.find_spec("paddle") is not None


def create_ocr_provider(policy: OCRProviderPolicy | str = OCRProviderPolicy.AUTO) -> OCRProviderSelection:
    try:
        requested = OCRProviderPolicy(policy).value
    except ValueError as exc:
        raise KSlideError(ErrorCode.CONFIG_INVALID, "Unsupported OCR provider policy.", {"policy": str(policy)}) from exc
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
        except KSlideError as exc:
            if requested == OCRProviderPolicy.PADDLE.value:
                raise
            fallback_code = exc.code.value
            provider = NoneOCRProvider()
            return OCRProviderSelection(requested, provider.name, provider.version, provider, "PaddleOCR initialization failed; using NoneOCRProvider", True, fallback_code)
        except Exception as exc:
            if requested == OCRProviderPolicy.PADDLE.value:
                raise KSlideError(ErrorCode.OCR_PROVIDER_UNAVAILABLE, "PaddleOCR could not be initialized.", {"reason": str(exc)}) from exc
            provider = NoneOCRProvider()
            return OCRProviderSelection(requested, provider.name, provider.version, provider, "PaddleOCR initialization failed; using NoneOCRProvider", True, ErrorCode.OCR_PROVIDER_UNAVAILABLE.value)
    provider = NoneOCRProvider()
    return OCRProviderSelection(requested, provider.name, provider.version, provider, "PaddleOCR unavailable; using NoneOCRProvider", True, ErrorCode.OCR_PROVIDER_UNAVAILABLE.value)
