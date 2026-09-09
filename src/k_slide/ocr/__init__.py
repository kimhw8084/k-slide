"""Optional local OCR provider adapters."""

from .base import OCRProvider, OCRResult, OCRRegion
from .none import NoneOCRProvider
from .policy import OCRProviderPolicy, OCRProviderSelection, create_ocr_provider, load_ocr_policy

__all__ = ["OCRProvider", "OCRResult", "OCRRegion", "NoneOCRProvider", "OCRProviderPolicy", "OCRProviderSelection", "create_ocr_provider", "load_ocr_policy"]
