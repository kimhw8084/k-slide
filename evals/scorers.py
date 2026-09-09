"""Content-free hard checks for generated engine evaluation artifacts."""

from __future__ import annotations

from pathlib import Path
from typing import Any


def score_artifact(path: Path, scenario: Any) -> dict[str, Any]:
    result: dict[str, Any] = {"scenario_id": scenario.scenario_id, "category": scenario.category, "artifact": str(path), "hard_pass": path.is_file() and path.stat().st_size > 0, "failures": []}
    if not result["hard_pass"]:
        result["failures"].append("artifact_missing_or_empty")
        return result
    try:
        from PIL import Image

        with Image.open(path) as image:
            result["width"], result["height"] = image.size
            result["format"] = image.format
            if image.width < 640 or image.height < 360:
                result["hard_pass"] = False
                result["failures"].append("render_too_small")
    except ImportError:
        result["format"] = "uninspected"
        result["warnings"] = ["Pillow unavailable for visual inspection"]
    return result
