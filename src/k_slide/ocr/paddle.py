"""Optional PaddleOCR adapter; imported only when explicitly selected."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

from ..errors import ErrorCode, KSlideError
from .base import OCRRegion, OCRResult


class PaddleOCRProvider:
    name = "paddle"

    def __init__(self, *, lang: str = "korean") -> None:
        if importlib.util.find_spec("paddleocr") is None:
            raise KSlideError(ErrorCode.OCR_UNAVAILABLE, "PaddleOCR is not installed.")
        self.lang = lang
        import paddleocr
        self.version = str(getattr(paddleocr, "__version__", "unknown"))
        self._engine = paddleocr.PaddleOCR(use_doc_orientation_classify=False, use_doc_unwarping=False, use_textline_orientation=False, lang=lang)

    def extract(self, image: Path, *, language_hints: tuple[str, ...] = ("ko", "en")) -> OCRResult:
        try:
            output = self._engine.predict(str(image))
        except Exception as exc:
            raise KSlideError(ErrorCode.OCR_UNAVAILABLE, "PaddleOCR failed to process the image.", {"image": image.name, "reason": str(exc)}) from exc
        regions: list[OCRRegion] = []
        for item in output or []:
            data = _result_mapping(item)
            text_values = data.get("rec_texts", data.get("text", []))
            scores = data.get("rec_scores", data.get("scores", []))
            boxes = data.get("rec_boxes", data.get("boxes", data.get("dt_polys", [])))
            text_values = _as_list(text_values)
            scores = _as_list(scores)
            boxes = _as_list(boxes)
            for index, text in enumerate(text_values):
                box = boxes[index] if index < len(boxes) else [0, 0, 0, 0]
                bbox = _bbox(box)
                if bbox is None:
                    continue
                try:
                    confidence = float(scores[index]) if index < len(scores) and scores[index] is not None else None
                except (TypeError, ValueError):
                    confidence = None
                regions.append(OCRRegion(str(text), bbox, confidence, index))
        return OCRResult(self.name, self.version, language_hints, tuple(regions))


def _result_mapping(value: Any) -> dict[str, Any]:
    """Accept the common PaddleOCR 3.x result wrappers without trusting shape."""

    if isinstance(value, dict):
        data: Any = value
    else:
        data = getattr(value, "json", None)
        try:
            data = data() if callable(data) else data
        except Exception:
            data = None
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except json.JSONDecodeError:
                data = None
        if not isinstance(data, dict):
            data = getattr(value, "data", {})
    while isinstance(data, dict) and isinstance(data.get("res"), dict):
        data = data["res"]
    return data if isinstance(data, dict) else {}


def _bbox(value: Any) -> tuple[int, int, int, int] | None:
    if not isinstance(value, (list, tuple)) or not value:
        return None
    if len(value) == 4 and all(isinstance(item, (int, float)) for item in value):
        left, top, right, bottom = (int(item) for item in value)
        return (min(left, right), min(top, bottom), max(left, right), max(top, bottom))
    points = [point for point in value if isinstance(point, (list, tuple)) and len(point) >= 2 and all(isinstance(item, (int, float)) for item in point[:2])]
    if not points:
        return None
    xs = [int(point[0]) for point in points]
    ys = [int(point[1]) for point in points]
    return (min(xs), min(ys), max(xs), max(ys))


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    tolist = getattr(value, "tolist", None)
    if callable(tolist):
        converted = tolist()
        return converted if isinstance(converted, list) else [converted]
    return [value]
