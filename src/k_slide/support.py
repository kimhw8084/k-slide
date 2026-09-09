"""Generate source-free support bundles for administrators.

Support bundles intentionally exclude source snapshots, renders, crops,
EvidenceIR, translations, reports, and raw OpenCode transcripts.  They carry
only sanitized operational metadata needed to diagnose a failed run.
"""

from __future__ import annotations

import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__
from .errors import ErrorCode, KSlideError
from .redaction import redact_value
from .runtime import discover_runtime


_STATE_KEYS = {
    "phase",
    "run_id",
    "input_count",
    "current_work_unit",
    "next_action",
    "updated_at",
    "created_at",
    "error_code",
    "failure_code",
}
_MANIFEST_KEYS = {
    "run_id",
    "schema_version",
    "kslide_version",
    "input_count",
    "created_at",
    "updated_at",
    "source_hashes",
    "runtime",
    "ocr_policy_requested",
    "ocr_provider_effective",
    "ocr_provider_version",
    "ocr_fallback",
    "timings",
}
_RUNTIME_KEYS = {
    "kslide_version",
    "opencode_version",
    "provider",
    "reported_model_id",
    "ocr_policy_requested",
    "ocr_provider_effective",
    "ocr_provider_version",
    "ocr_fallback",
    "ocr_fallback_code",
    "normalizer_version",
    "evidence_revision",
}


def _read_object(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _select(value: dict[str, Any] | None, keys: set[str]) -> dict[str, Any]:
    if not value:
        return {}
    return {key: value[key] for key in keys if key in value}


def _queue_summary(path: Path) -> dict[str, Any]:
    value = _read_object(path)
    if not value:
        return {"available": False}
    units = value.get("work_units")
    if not isinstance(units, list):
        return {"available": True, "queue_revision": value.get("queue_revision"), "unit_count": None}
    counts: dict[str, int] = {}
    repair_attempts = 0
    translation_attempts = 0
    for unit in units:
        if not isinstance(unit, dict):
            continue
        status = str(unit.get("status", "UNKNOWN"))
        counts[status] = counts.get(status, 0) + 1
        repair_attempts += int(unit.get("repair_attempts", 0) or 0)
        translation_attempts += int(unit.get("translation_attempts", 0) or 0)
    return {
        "available": True,
        "queue_revision": value.get("queue_revision"),
        "unit_count": len(units),
        "status_counts": counts,
        "repair_attempts": repair_attempts,
        "translation_attempts": translation_attempts,
    }


def _run_summary(run: Path) -> dict[str, Any]:
    state = _select(_read_object(run / "RUN_STATE.json"), _STATE_KEYS)
    manifest = _select(_read_object(run / "RUN_MANIFEST.json"), _MANIFEST_KEYS)
    runtime = _select(_read_object(run / "RUNTIME_METADATA.json"), _RUNTIME_KEYS)
    return {
        "run_id": run.name,
        "state": state,
        "manifest": manifest,
        "runtime": runtime,
        "queue": _queue_summary(run / "WORK_QUEUE.json"),
        "artifacts": {
            name: (run / name).is_file()
            for name in ("RUN_STATE.json", "RUN_MANIFEST.json", "RUNTIME_METADATA.json", "WORK_QUEUE.json", "RUN_COMPLETE.md", "RUN_FAILED.md")
        },
    }


def build_support_bundle(root: Path, output: Path) -> dict[str, Any]:
    """Write a zip bundle containing only sanitized operational metadata."""

    root = root.expanduser().resolve()
    output = output.expanduser().resolve()
    run_root = root / ".k-slide-runs"
    if not run_root.is_dir() or run_root.is_symlink():
        raise KSlideError(ErrorCode.SUPPORT_BUNDLE_INVALID, "The K-Slide run root is unavailable or unsafe.")
    if output.exists():
        raise KSlideError(ErrorCode.SUPPORT_BUNDLE_INVALID, "Support bundle output already exists.", {"path": str(output)})
    output.parent.mkdir(parents=True, exist_ok=True)
    runs = []
    for run in sorted(run_root.iterdir()):
        if run.is_symlink() or not run.is_dir():
            continue
        runs.append(_run_summary(run))
    payload = {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "k_slide_version": __version__,
        "runtime": discover_runtime().as_dict(),
        "run_root": ".k-slide-runs",
        "runs": runs,
        "excluded": ["input snapshots", "normalized renders", "crops", "EvidenceIR", "translations", "reports", "raw OpenCode events"],
    }
    safe_payload = redact_value(payload, roots=(root,))
    content = json.dumps(safe_payload, ensure_ascii=False, indent=2) + "\n"
    with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("support-metadata.json", content)
    output.chmod(0o600)
    return {"status": "PASS", "output": str(output), "run_count": len(runs), "source_content_included": False}

