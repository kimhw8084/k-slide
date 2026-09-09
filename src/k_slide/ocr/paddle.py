"""Optional PaddleOCR adapter; imported only when explicitly selected."""

from __future__ import annotations

import importlib.util
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
            data: dict[str, Any] = item if isinstance(item, dict) else getattr(item, "json", lambda: {})()
            text_values = data.get("rec_texts", data.get("text", []))
            scores = data.get("rec_scores", data.get("scores", []))
            boxes = data.get("rec_boxes", data.get("boxes", []))
            for index, text in enumerate(text_values if isinstance(text_values, list) else [text_values]):
                box = boxes[index] if index < len(boxes) else [0, 0, 0, 0]
                if len(box) == 4 and isinstance(box[0], (int, float)):
                    bbox = tuple(int(value) for value in box)
                else:
                    xs = [int(point[0]) for point in box]
                    ys = [int(point[1]) for point in box]
                    bbox = (min(xs), min(ys), max(xs), max(ys))
                confidence = float(scores[index]) if index < len(scores) else None
                regions.append(OCRRegion(str(text), bbox, confidence, index))
        return OCRResult(self.name, self.version, language_hints, tuple(regions))
