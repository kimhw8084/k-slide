"""Self-test for the heavyweight LibreOffice/Paddle evaluation image."""

from __future__ import annotations

import importlib.util
import json
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


def _font_check() -> dict[str, object]:
    try:
        from evals.fonts import discover_korean_font

        info = discover_korean_font()
        return {"status": "PASS", "family": info.family, "path": info.path}
    except Exception as exc:
        return {"status": "FAIL", "reason": str(exc)}


def main() -> int:
    checks: dict[str, object] = {
        "python": {"status": "PASS"},
        "libreoffice": {"status": "PASS" if _command_version("libreoffice") or _command_version("soffice") else "FAIL"},
        "pillow": {"status": "PASS" if importlib.util.find_spec("PIL") else "FAIL"},
        "pymupdf": {"status": "PASS" if importlib.util.find_spec("fitz") else "FAIL"},
        "python_pptx": {"status": "PASS" if importlib.util.find_spec("pptx") else "FAIL"},
        "paddleocr": {"status": "PASS" if importlib.util.find_spec("paddleocr") else "FAIL"},
        "paddlepaddle": {"status": "PASS" if importlib.util.find_spec("paddle") else "FAIL"},
        "korean_font": _font_check(),
    }
    # A small real OCR load check is intentionally separate from package import.
    if checks["paddleocr"].get("status") == "PASS" and checks["pillow"].get("status") == "PASS":
        try:
            from k_slide.ocr.paddle import PaddleOCRProvider

            provider = PaddleOCRProvider()
            checks["paddle_load"] = {"status": "PASS", "provider": provider.name, "version": provider.version}
        except Exception as exc:
            checks["paddle_load"] = {"status": "FAIL", "reason": str(exc)}
    else:
        checks["paddle_load"] = {"status": "BLOCKED", "reason": "PaddleOCR/Pillow unavailable"}
    print(json.dumps(checks, ensure_ascii=False, indent=2))
    return 0 if all(value.get("status") in {"PASS", "BLOCKED"} for value in checks.values() if isinstance(value, dict)) else 1


if __name__ == "__main__":
    raise SystemExit(main())
