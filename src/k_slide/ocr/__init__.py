"""Optional local OCR provider adapters."""

from .base import OCRProvider, OCRResult, OCRRegion
from .none import NoneOCRProvider

__all__ = ["OCRProvider", "OCRResult", "OCRRegion", "NoneOCRProvider"]
