"""Self-test for the heavyweight LibreOffice/Paddle evaluation image."""

from __future__ import annotations

import importlib.util
import json
import importlib.metadata
import platform
import shutil
import subprocess
import tempfile
from pathlib import Path


def _command_version(command: str) -> str | None:
    path = shutil.which(command)
    if not path:
        return None
    try:
        result = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return (result.stdout or result.stderr).strip() or None


def _package_version(name: str) -> str | None:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return None


def _font_check() -> dict[str, object]:
    try:
        from evals.fonts import discover_korean_font

        info = discover_korean_font()
        return {"status": "PASS", "family": info.family, "path": info.path}
    except Exception as exc:
        return {"status": "FAIL", "reason": str(exc)}


def _libreoffice_roundtrip(*, required: bool = False) -> dict[str, object]:
    if not (_command_version("libreoffice") or _command_version("soffice")):
        return {"status": "FAIL" if required else "BLOCKED", "reason": "LibreOffice/soffice is unavailable."}
    if not all(importlib.util.find_spec(name) for name in ("fitz", "pptx", "PIL")):
        return {"status": "FAIL" if required else "BLOCKED", "reason": "PyMuPDF, python-pptx, and Pillow are required."}
    try:
        from evals.deck_scenarios import deck_scenarios
        from evals.generator import generate_deck_pptx
        from k_slide.ingest import prepare_run
        from k_slide.normalization import normalize_run

        with tempfile.TemporaryDirectory(prefix="k-slide-heavy-pptx-") as directory:
            root = Path(directory)
            source = root / "roundtrip.pptx"
            if not generate_deck_pptx(deck_scenarios()[0].slides, source):
                return {"status": "FAIL", "reason": "Synthetic PPTX generation failed."}
            run = prepare_run(root / "workspace", explicit_paths=[str(source)])
            normalized = normalize_run(run)
            units = [unit for document in normalized.documents for unit in document.units]
            renders = [run / unit.canonical_render_path for unit in units]
            valid = len(units) == 3 and all(path.is_file() and path.stat().st_size > 0 for path in renders)
            return {"status": "PASS" if valid else "FAIL", "slide_count": len(units), "render_count": len(renders), "render_dimensions": [[unit.width_px, unit.height_px] for unit in units]}
    except Exception as exc:
        return {"status": "FAIL", "reason": str(exc)}


def _paddle_ocr_roundtrip(*, required: bool = False) -> dict[str, object]:
    missing = [name for name, module in (("PaddleOCR", "paddleocr"), ("PaddlePaddle", "paddle"), ("Pillow", "PIL")) if importlib.util.find_spec(module) is None]
    if missing:
        return {"status": "FAIL" if required else "BLOCKED", "reason": f"Unavailable: {', '.join(missing)}."}
    try:
        from PIL import Image, ImageDraw
        from evals.fonts import discover_korean_font, load_font
        from k_slide.ocr.policy import OCRProviderPolicy, create_ocr_provider

        font_info = discover_korean_font()
        with tempfile.TemporaryDirectory(prefix="k-slide-heavy-ocr-") as directory:
            image_path = Path(directory) / "korean-smoke.png"
            image = Image.new("RGB", (1600, 900), "white")
            draw = ImageDraw.Draw(image)
            font = load_font(42, font_info)
            for index, text in enumerate(("운영 검토 필요", "3.2조원", "+2.3%p", "검토 후 추진 예정")):
                draw.text((80, 100 + index * 150), text, fill="black", font=font)
            image.save(image_path)
            selection = create_ocr_provider(OCRProviderPolicy.PADDLE)
            result = selection.provider.extract(image_path)
            texts = " ".join(region.text for region in result.regions)
            expected = ("검토", "3.2", "%p")
            found = sum(term in texts for term in expected)
            boxes_valid = all(region.bbox_px[2] > region.bbox_px[0] and region.bbox_px[3] > region.bbox_px[1] for region in result.regions)
            return {"status": "PASS" if result.regions and found >= 1 and boxes_valid else "FAIL", "region_count": len(result.regions), "expected_key_recall": found / len(expected), "boxes_valid": boxes_valid, "provider": result.provider, "version": result.provider_version, "requested_policy": selection.requested, "effective_provider": selection.effective}
    except Exception as exc:
        return {"status": "FAIL", "reason": str(exc)}


def main(*, required: bool = False, networkless: bool = False) -> int:
    def available(module: str) -> str:
        return "PASS" if importlib.util.find_spec(module) else ("FAIL" if required else "BLOCKED")

    checks: dict[str, object] = {
        "python": {"status": "PASS"},
        "libreoffice": {"status": "PASS" if _command_version("libreoffice") or _command_version("soffice") else ("FAIL" if required else "BLOCKED")},
        "pillow": {"status": available("PIL")},
        "pymupdf": {"status": available("fitz")},
        "python_pptx": {"status": available("pptx")},
        "paddleocr": {"status": available("paddleocr")},
        "paddlepaddle": {"status": available("paddle")},
        "korean_font": _font_check(),
    }
    checks["runtime_provenance"] = {
        "python_version": platform.python_version(),
        "paddle_version": _package_version("paddlepaddle"),
        "paddleocr_version": _package_version("paddleocr"),
        "libreoffice_version": _command_version("libreoffice") or _command_version("soffice"),
    }
    # A small real OCR load check is intentionally separate from package import.
    if checks["paddleocr"].get("status") == "PASS" and checks["pillow"].get("status") == "PASS":
        try:
            from k_slide.ocr.policy import OCRProviderPolicy, create_ocr_provider

            selection = create_ocr_provider(OCRProviderPolicy.PADDLE)
            checks["paddle_load"] = {"status": "PASS", "provider": selection.effective, "version": selection.version, "requested_policy": selection.requested}
        except Exception as exc:
            checks["paddle_load"] = {"status": "FAIL", "reason": str(exc)}
    else:
        missing = [name for name, module in (("PaddleOCR", "paddleocr"), ("Pillow", "PIL")) if importlib.util.find_spec(module) is None]
        checks["paddle_load"] = {"status": "FAIL" if required else "BLOCKED", "reason": f"Unavailable: {', '.join(missing)}."}
    checks["libreoffice_roundtrip"] = _libreoffice_roundtrip(required=required)
    checks["paddle_ocr_roundtrip"] = _paddle_ocr_roundtrip(required=required)
    checks["network"] = {"network_required": not networkless, "networkless_asserted": networkless}
    print(json.dumps(checks, ensure_ascii=False, indent=2))
    if required:
        required_checks = ("libreoffice", "paddleocr", "paddlepaddle", "korean_font", "paddle_load", "libreoffice_roundtrip", "paddle_ocr_roundtrip")
        return 0 if all(checks.get(name, {}).get("status") == "PASS" for name in required_checks) else 1
    status_values = [value.get("status") for value in checks.values() if isinstance(value, dict) and "status" in value]
    return 0 if all(status in {"PASS", "BLOCKED"} for status in status_values) else 1


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="K-Slide heavy runtime doctor")
    parser.add_argument("--required", action="store_true", help="fail when heavy dependencies or round trips are unavailable")
    parser.add_argument("--networkless", action="store_true", help="record that this check is expected to run without network; the container boundary enforces this")
    args = parser.parse_args()
    raise SystemExit(main(required=args.required, networkless=args.networkless))
