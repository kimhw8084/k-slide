"""Capability-oriented diagnostics."""

from __future__ import annotations

import importlib.util
import os
import tempfile
import shutil
from pathlib import Path
from typing import Any

from . import __version__
from .runtime import discover_runtime
from .security import validate_input
from .ocr.policy import create_ocr_provider, load_ocr_policy
from .production import production_checks
from .redaction import redact_value


def _check(label: str, status: str, detail: str) -> dict[str, str]:
    return {"label": label, "status": status, "detail": detail}


def diagnose(root: Path, *, engine_root: Path | None = None, opencode_root: Path | None = None, production: bool = False) -> dict[str, Any]:
    root = root.resolve()
    default_engine = root / ".k-slide-engine" if (root / ".k-slide-engine").is_dir() else root
    engine_root = (engine_root or default_engine).resolve()
    opencode_root = (opencode_root or (root / ".opencode")).resolve()
    runtime = discover_runtime(root)
    checks: list[dict[str, str]] = []
    required = [
        opencode_root / "commands" / "k-slide.md",
        opencode_root / "agents" / "k-slide.md",
        opencode_root / "skills" / "k-slide" / "SKILL.md",
        opencode_root / "tools" / "kslide.ts",
        engine_root / "src" / "k_slide" / "cli.py",
    ]
    checks.append(_check("K-Slide source tree", "PASS" if all(path.is_file() for path in required) else "FAIL", "Required command, agent, skill, tools, and core files"))
    checks.append(_check("Python runtime", "PASS", os.sys.executable))
    checks.append(_check("OpenCode executable", "PASS" if runtime.opencode_path else "WARN", runtime.opencode_version or "not discovered"))
    checks.append(_check("OpenCode config", "PASS" if runtime.opencode_config_path else "WARN", runtime.opencode_config_path or "not discovered"))
    model_status = "PASS" if runtime.model_compatibility == "production_candidate" else "WARN"
    checks.append(_check("Model identity", model_status, runtime.reported_model_id or "not discovered"))
    checks.append(_check("Model compatibility", model_status, runtime.model_compatibility))
    vision_status = "PASS" if runtime.vision_support is True or (production and runtime.vision_support is None) else "WARN"
    vision_detail = "feature-detected" if runtime.vision_support is not None else ("candidate-bound production evidence is evaluated below" if production else "not proven")
    checks.append(_check("Vision support", vision_status, vision_detail))
    image_status = "FAIL"
    image_detail = "install K-Slide core dependencies for image normalization"
    if importlib.util.find_spec("PIL"):
        try:
            from PIL import Image

            with tempfile.NamedTemporaryFile(suffix=".png", dir=root, delete=False) as handle:
                image_path = Path(handle.name)
            try:
                Image.new("RGB", (8, 8), "white").save(image_path, format="PNG")
                with Image.open(image_path) as image:
                    image.load()
                image_status = "PASS"
                image_detail = "Pillow decode smoke test passed"
            finally:
                image_path.unlink(missing_ok=True)
        except (ImportError, OSError, ValueError) as exc:
            image_detail = f"Pillow is installed but decode smoke test failed: {exc}"
    checks.append(_check("Image decoder", image_status, image_detail))
    checks.append(_check("PDF extraction/rendering", "PASS" if importlib.util.find_spec("fitz") else "WARN", "PyMuPDF available" if importlib.util.find_spec("fitz") else "install k-slide[pdf] for PDF normalization"))
    checks.append(_check("PPTX extraction", "PASS" if importlib.util.find_spec("pptx") else "WARN", "python-pptx available" if importlib.util.find_spec("pptx") else "install k-slide[pptx] for native PPTX extraction"))
    office_binary = shutil.which("libreoffice") or shutil.which("soffice")
    pptx_render_status = "PASS" if office_binary and importlib.util.find_spec("fitz") else "WARN"
    pptx_render_detail = office_binary or "LibreOffice/soffice not discovered"
    if not importlib.util.find_spec("fitz"):
        pptx_render_detail += "; PyMuPDF is required for rendered pages"
    checks.append(_check("PPTX rendering", pptx_render_status, pptx_render_detail))
    try:
        ocr_policy = load_ocr_policy(root)
        selection = create_ocr_provider(ocr_policy)
        ocr_status = "PASS" if selection.effective != "none" or ocr_policy.value == "none" else "WARN"
        checks.append(_check("OCR policy", ocr_status, f"requested={selection.requested}; effective={selection.effective}; version={selection.version}; {selection.reason or 'provider initialized'}"))
        checks.append(_check("Korean OCR", "PASS" if selection.effective == "paddle" else "WARN", f"effective provider: {selection.effective}"))
    except Exception as exc:
        checks.append(_check("OCR policy", "FAIL", str(exc)))
    try:
        root.joinpath(".k-slide-runs").mkdir(parents=True, exist_ok=True, mode=0o700)
        with tempfile.NamedTemporaryFile(prefix=".doctor-", dir=root / ".k-slide-runs", delete=True) as handle:
            handle.write(b"k-slide")
            handle.flush()
        checks.append(_check("Writable run directory", "PASS", str(root / ".k-slide-runs")))
    except OSError as exc:
        checks.append(_check("Writable run directory", "FAIL", str(exc)))
    try:
        if importlib.util.find_spec("PIL"):
            from PIL import Image

            with tempfile.NamedTemporaryFile(suffix=".png", dir=root, delete=False) as handle:
                image_path = Path(handle.name)
            try:
                Image.new("RGB", (8, 8), "white").save(image_path, format="PNG")
                validate_input(image_path)
            finally:
                image_path.unlink(missing_ok=True)
            checks.append(_check("Input validation", "PASS", "valid PNG decode and content validation smoke test passed"))
        else:
            checks.append(_check("Input validation", "WARN", "Pillow unavailable; header-only validation is not treated as a capability pass"))
    except Exception as exc:
        checks.append(_check("Input validation", "FAIL", str(exc)))
    if production:
        checks.extend(production_checks(root, runtime))
    overall = "FAIL" if any(item["status"] == "FAIL" for item in checks) else ("WARN" if any(item["status"] == "WARN" for item in checks) else "PASS")
    result = {"k_slide_version": __version__, "mode": "production" if production else "development", "overall": overall, "runtime": runtime.as_dict(), "checks": checks}
    return redact_value(result, roots=(root,)) if production else result
