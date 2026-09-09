"""Optional PaddleOCR adapter; imported only when explicitly selected."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
from typing import Any

from ..errors import ErrorCode, KSlideError
from .base import OCRRegion, OCRResult


class PaddleOCRProvider:
    name = "paddle"

    def __init__(self, *, lang: str = "korean", ocr_version: str = "PP-OCRv5", det_model_dir: str | None = None, rec_model_dir: str | None = None, paddlex_config: str | None = None) -> None:
        if importlib.util.find_spec("paddleocr") is None:
            raise KSlideError(ErrorCode.OCR_UNAVAILABLE, "PaddleOCR is not installed.")
        self.lang = os.environ.get("KSLIDE_PADDLE_LANG", lang)
        import paddleocr
        paddle_version = "unknown"
        try:
            import paddle

            paddle_version = str(getattr(paddle, "__version__", "unknown"))
        except ImportError:
            raise KSlideError(ErrorCode.OCR_UNAVAILABLE, "PaddlePaddle is not installed.")
        self.paddleocr_version = str(getattr(paddleocr, "__version__", "unknown"))
        self.paddle_version = paddle_version
        self.ocr_version = os.environ.get("KSLIDE_PADDLE_OCR_VERSION", ocr_version)
        self.det_model_name = os.environ.get("KSLIDE_PADDLE_DET_MODEL_NAME", "PP-OCRv5_mobile_det")
        self.rec_model_name = os.environ.get("KSLIDE_PADDLE_REC_MODEL_NAME", "korean_PP-OCRv5_mobile_rec")
        configured_config = paddlex_config or os.environ.get("KSLIDE_PADDLEX_CONFIG")
        configured_det = det_model_dir or os.environ.get("KSLIDE_PADDLE_DET_MODEL_DIR")
        configured_rec = rec_model_dir or os.environ.get("KSLIDE_PADDLE_REC_MODEL_DIR")
        require_local = os.environ.get("KSLIDE_PADDLE_REQUIRE_LOCAL_ASSETS", "0").lower() in {"1", "true", "yes"}
        if require_local and not configured_config and not (configured_det and configured_rec):
            raise KSlideError(ErrorCode.OCR_UNAVAILABLE, "Offline PaddleOCR requires a local paddlex config or detector/recognizer model directories.")
        kwargs: dict[str, Any] = {"use_doc_orientation_classify": False, "use_doc_unwarping": False, "use_textline_orientation": False}
        if configured_config:
            config_path = Path(configured_config)
            if not config_path.is_file():
                raise KSlideError(ErrorCode.OCR_UNAVAILABLE, "Configured PaddleX OCR pipeline file is missing.", {"path": str(config_path)})
            kwargs["paddlex_config"] = str(config_path)
        else:
            kwargs.update({"lang": self.lang, "ocr_version": self.ocr_version, "text_detection_model_name": self.det_model_name, "text_recognition_model_name": self.rec_model_name})
            if configured_det:
                kwargs["text_detection_model_dir"] = configured_det
            if configured_rec:
                kwargs["text_recognition_model_dir"] = configured_rec
        self.asset_config = {"ocr_version": self.ocr_version, "language": self.lang, "detector_model": self.det_model_name, "recognizer_model": self.rec_model_name, "paddlex_config": configured_config, "detector_model_dir": configured_det, "recognizer_model_dir": configured_rec, "offline_assets_required": require_local}
        self.version = f"paddleocr={self.paddleocr_version};paddle={self.paddle_version};ocr={self.ocr_version};rec={self.rec_model_name}"
        try:
            self._engine = paddleocr.PaddleOCR(**kwargs)
        except Exception as exc:
            raise KSlideError(ErrorCode.OCR_UNAVAILABLE, "PaddleOCR could not be initialized with the configured local assets.", {"reason": str(exc), "asset_config": self.asset_config}) from exc

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
