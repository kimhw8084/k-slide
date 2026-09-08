"""Capability-oriented diagnostics."""

from __future__ import annotations

import importlib.util
import os
import tempfile
from pathlib import Path
from typing import Any

from . import __version__
from .runtime import discover_runtime
from .security import validate_input


def _check(label: str, status: str, detail: str) -> dict[str, str]:
    return {"label": label, "status": status, "detail": detail}


def diagnose(root: Path, *, engine_root: Path | None = None, opencode_root: Path | None = None) -> dict[str, Any]:
    root = root.resolve()
    default_engine = root / ".k-slide-engine" if (root / ".k-slide-engine").is_dir() else root
    engine_root = (engine_root or default_engine).resolve()
    opencode_root = (opencode_root or (root / ".opencode")).resolve()
    runtime = discover_runtime()
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
    checks.append(_check("Vision support", "PASS" if runtime.vision_support is True else "WARN", "feature-detected" if runtime.vision_support is not None else "not proven"))
    checks.append(_check("PDF extraction/rendering", "PASS" if importlib.util.find_spec("fitz") else "WARN", "PyMuPDF available" if importlib.util.find_spec("fitz") else "install k-slide[pdf] for PDF normalization"))
    checks.append(_check("PPTX extraction", "PASS" if importlib.util.find_spec("pptx") else "WARN", "python-pptx available" if importlib.util.find_spec("pptx") else "install k-slide[pptx] for native PPTX extraction"))
    checks.append(_check("PPTX rendering", "WARN", "headless office renderer is not yet configured"))
    checks.append(_check("Korean OCR", "PASS" if importlib.util.find_spec("paddleocr") else "WARN", "PaddleOCR available" if importlib.util.find_spec("paddleocr") else "optional OCR backend not installed"))
    try:
        root.joinpath(".k-slide-runs").mkdir(parents=True, exist_ok=True, mode=0o700)
        with tempfile.NamedTemporaryFile(prefix=".doctor-", dir=root / ".k-slide-runs", delete=True) as handle:
            handle.write(b"k-slide")
            handle.flush()
        checks.append(_check("Writable run directory", "PASS", str(root / ".k-slide-runs")))
    except OSError as exc:
        checks.append(_check("Writable run directory", "FAIL", str(exc)))
    try:
        with tempfile.NamedTemporaryFile(suffix=".png", dir=root, delete=True) as handle:
            handle.write(b"\x89PNG\r\n\x1a\nsynthetic")
            handle.flush()
            validate_input(Path(handle.name))
        checks.append(_check("Input magic validation", "PASS", "synthetic PNG header accepted"))
    except Exception as exc:
        checks.append(_check("Input magic validation", "FAIL", str(exc)))
    overall = "FAIL" if any(item["status"] == "FAIL" for item in checks) else ("WARN" if any(item["status"] == "WARN" for item in checks) else "PASS")
    return {"k_slide_version": __version__, "overall": overall, "runtime": runtime.as_dict(), "checks": checks}
