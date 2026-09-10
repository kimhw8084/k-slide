"""OpenCode and model capability discovery."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from functools import lru_cache
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from . import __version__


@dataclass(frozen=True)
class RuntimeMetadata:
    kslide_version: str
    opencode_version: str | None
    opencode_path: str | None
    opencode_config_path: str | None
    provider: str | None
    reported_model_id: str | None
    model_family: str | None
    model_size: str | None
    instruction_tuned_status: str
    vision_support: bool | None
    thinking_support: bool | None
    provider_backend: str | None
    quantization_or_dtype: str | None
    context_configuration: dict[str, Any]
    image_preprocessing_settings: dict[str, Any]
    model_compatibility: str
    discovery_warnings: list[str]
    model_revision: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@lru_cache(maxsize=4)
def _version(executable: str | None) -> str | None:
    if not executable:
        return None
    try:
        result = subprocess.run([executable, "--version"], capture_output=True, text=True, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    output = (result.stdout or result.stderr).strip()
    match = re.search(r"(\d+\.\d+\.\d+)", output)
    return match.group(1) if match else output or None


def _config_path() -> Path | None:
    explicit = os.environ.get("KSLIDE_OPENCODE_CONFIG")
    candidates = [Path(explicit)] if explicit else []
    xdg = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    candidates.append(xdg / "opencode" / "opencode.json")
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def _read_config(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    try:
        text = path.read_text(encoding="utf-8")
        text = re.sub(r"//[^\n]*", "", text)
        text = re.sub(r",\s*([}\]])", r"\1", text)
        value = json.loads(text)
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


@lru_cache(maxsize=4)
def _effective_config(executable: str | None) -> dict[str, Any]:
    """Prefer OpenCode's effective config report over one guessed config file."""

    if not executable:
        return {}
    try:
        result = subprocess.run([executable, "debug", "config"], capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return {}
    output = (result.stdout or "").strip()
    start, end = output.find("{"), output.rfind("}")
    if start < 0 or end <= start:
        return {}
    try:
        value = json.loads(output[start : end + 1])
    except json.JSONDecodeError:
        return {}
    return value if isinstance(value, dict) else {}


def _model_details(model_id: str | None) -> dict[str, Any]:
    normalized = (model_id or "").lower().strip()
    is_gemma4 = "gemma-4" in normalized or "gemma4" in normalized
    exact_it = bool(re.search(r"(?:^|/)gemma-4-31b-it$", normalized)) or normalized.endswith("gemma-4-31b-it")
    base_31b = bool(re.search(r"(?:^|/)gemma-4-31b$", normalized)) or normalized.endswith("gemma-4-31b")
    if exact_it:
        compatibility = "production_candidate"
        tuned = "instruction_tuned"
        warnings: list[str] = []
    elif base_31b:
        compatibility = "non_instruction_tuned_warning"
        tuned = "base_or_ambiguous"
        warnings = ["Gemma 4 31B base/ambiguous checkpoint is not production-certified."]
    elif model_id:
        compatibility = "different_model_warning"
        tuned = "unknown"
        warnings = [f"Active runtime model is {model_id}, not the Gemma 4 31B-it production target."]
    else:
        compatibility = "unknown_model_warning"
        tuned = "unknown"
        warnings = ["No active model identity was discoverable."]
    return {
        "model_family": "Gemma 4" if is_gemma4 else (model_id.split("/", 1)[1].split(":", 1)[0] if model_id and "/" in model_id else (model_id.split(":", 1)[0] if model_id else None)),
        "model_size": "31B" if "31b" in normalized else None,
        "instruction_tuned_status": tuned,
        # Model naming is not proof that the active provider accepts image
        # inputs. A multimodal smoke test/provider capability report is needed.
        "vision_support": None,
        "thinking_support": None,
        "model_compatibility": compatibility,
        "warnings": warnings,
    }


def discover_runtime() -> RuntimeMetadata:
    executable = shutil.which("opencode")
    path = _config_path()
    config = _effective_config(executable) or _read_config(path)
    reported_model = os.environ.get("KSLIDE_MODEL") or os.environ.get("OPENCODE_MODEL") or config.get("model")
    provider = reported_model.split("/", 1)[0] if isinstance(reported_model, str) and "/" in reported_model else None
    provider_config = config.get("provider", {}).get(provider, {}) if provider and isinstance(config.get("provider"), dict) else {}
    if not isinstance(provider_config, dict):
        provider_config = {}
    details = _model_details(reported_model if isinstance(reported_model, str) else None)
    return RuntimeMetadata(
        kslide_version=__version__,
        opencode_version=_version(executable),
        opencode_path=executable,
        opencode_config_path=str(path) if path else None,
        provider=provider,
        reported_model_id=reported_model if isinstance(reported_model, str) else None,
        model_family=details["model_family"],
        model_size=details["model_size"],
        instruction_tuned_status=details["instruction_tuned_status"],
        vision_support=details["vision_support"],
        thinking_support=details["thinking_support"],
        provider_backend=provider_config.get("npm") if isinstance(provider_config.get("npm"), str) else None,
        quantization_or_dtype=None,
        context_configuration={"source": "not_exposed_by_runtime"},
        image_preprocessing_settings={"source": "not_yet_configured"},
        model_compatibility=details["model_compatibility"],
        discovery_warnings=details["warnings"],
        model_revision=provider_config.get("revision") if isinstance(provider_config.get("revision"), str) else None,
    )
