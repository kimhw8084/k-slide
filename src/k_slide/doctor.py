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
from .redaction import CredentialExposureError, safe_diagnostic_text, sanitize_operational
from .storage import StorageLayout, StoragePlane


def _check(label: str, status: str, detail: str) -> dict[str, str]:
    return {"label": label, "status": status, "detail": detail}


def _safe_exception_detail(exc: Exception) -> str:
    try:
        return safe_diagnostic_text(str(exc))
    except CredentialExposureError:
        return f"{type(exc).__name__} (diagnostic detail omitted safely)"


def diagnose(root: Path, *, engine_root: Path | None = None, opencode_root: Path | None = None, production: bool = False) -> dict[str, Any]:
    root = root.resolve()
    storage = StorageLayout.for_workspace_root(root)
    durable_root = storage.ensure_root(StoragePlane.DURABLE_USER_WORKSPACE_RUN_DATA)
    scratch_root = storage.ensure_root(StoragePlane.EPHEMERAL_PROCESSING_SCRATCH)
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
    runtime_manifest = engine_root / "runtime" / "runtime-manifest.json"
    source_available = all(path.is_file() for path in required)
    source_detail = "Required command, agent, skill, tools, and core files" if source_available else (
        "Installed runtime artifact is present" if runtime_manifest.is_file() else "Required command, agent, skill, tools, and core files"
    )
    checks.append(_check("K-Slide source tree", "PASS" if source_available or runtime_manifest.is_file() else "FAIL", source_detail))
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

            with tempfile.NamedTemporaryFile(suffix=".png", dir=scratch_root, delete=False) as handle:
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
            image_detail = f"Pillow is installed but decode smoke test failed: {_safe_exception_detail(exc)}"
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
        checks.append(_check("OCR policy", "FAIL", _safe_exception_detail(exc)))
    try:
        # A scratch probe cannot establish whether normal run creation can
        # write the durable authority. Probe the actual durable root and
        # remove the file before reporting success.
        if durable_root.stat().st_mode & 0o222 == 0:
            raise PermissionError("durable run root has no write permission")
        probe_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(prefix=".doctor-", dir=durable_root, delete=False) as handle:
                probe_path = Path(handle.name)
                handle.write(b"k-slide")
                handle.flush()
        finally:
            if probe_path is not None:
                probe_path.unlink(missing_ok=True)
        if probe_path is None or probe_path.exists():
            raise OSError("durable run writability probe was not removed")
        checks.append(_check("Writable run directory", "PASS", str(root / ".k-slide-runs")))
    except OSError as exc:
        checks.append(_check("Writable run directory", "FAIL", _safe_exception_detail(exc)))
    try:
        if importlib.util.find_spec("PIL"):
            from PIL import Image

            with tempfile.NamedTemporaryFile(suffix=".png", dir=scratch_root, delete=False) as handle:
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
        checks.append(_check("Input validation", "FAIL", _safe_exception_detail(exc)))
    if production:
        checks.extend(production_checks(root, runtime))
    overall = "FAIL" if any(item["status"] == "FAIL" for item in checks) else ("WARN" if any(item["status"] == "WARN" for item in checks) else "PASS")
    result = {"k_slide_version": __version__, "mode": "production" if production else "development", "overall": overall, "runtime": runtime.as_dict(), "checks": checks}
    return sanitize_operational(result, roots=(root,))
