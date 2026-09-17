"""Materialize the configured PaddleOCR models into the canonical asset tree."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from pathlib import Path
from typing import Any


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _materialized_files(root: Path) -> list[dict[str, Any]]:
    files: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise RuntimeError(f"OCR asset tree contains a symlink: {path.relative_to(root)}")
        if path.is_file() and path.name != "manifest.json":
            files.append({"path": path.relative_to(root).as_posix(), "sha256": _hash_file(path), "bytes": path.stat().st_size})
    return files


def _set_selected_model_dirs(config: dict[str, Any], *, root: Path, detector: str, recognizer: str) -> dict[str, str]:
    modules = config.get("SubModules")
    if not isinstance(modules, dict):
        raise RuntimeError("exported PaddleX configuration has no SubModules")
    selected: dict[str, str] = {}
    for role, key, name in (("detector", "TextDetection", detector), ("recognizer", "TextRecognition", recognizer)):
        module = modules.get(key)
        if not isinstance(module, dict) or module.get("model_name") != name:
            raise RuntimeError(f"exported PaddleX configuration selected an unexpected {role} model")
        model_dir = root / "models" / name
        if not model_dir.is_dir() or not any(item.is_file() for item in model_dir.rglob("*")):
            raise RuntimeError(f"selected {role} model was not materialized: {name}")
        module["model_dir"] = str(model_dir)
        selected[f"{role}_model"] = str(module["model_name"])
        selected[f"{role}_model_dir"] = model_dir.relative_to(root).as_posix()
    return selected


def _remove_hoster_cache(root: Path) -> None:
    """Drop downloader bookkeeping that is not consumed by Paddle inference."""

    for cache in sorted(root.rglob(".cache"), reverse=True):
        if cache.is_dir() and not cache.is_symlink():
            shutil.rmtree(cache)


def main() -> int:
    root = Path(os.environ.get("KSLIDE_OCR_ASSET_ROOT", "/opt/k-slide-ocr-assets")).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    detector = os.environ.get("KSLIDE_PADDLE_DET_MODEL_NAME", "PP-OCRv5_mobile_det").strip()
    recognizer = os.environ.get("KSLIDE_PADDLE_REC_MODEL_NAME", "korean_PP-OCRv5_mobile_rec").strip()
    if not detector or not recognizer:
        raise RuntimeError("configured PaddleOCR detector and recognizer names are required")

    # PaddleX 3.7.2 reads PADDLE_PDX_CACHE_HOME at import time. Keep that
    # cache outside the portable tree, then copy only the two selected model
    # directories into the tree that is hashed and shipped.
    cache_root = root / ".paddlex-cache"
    shutil.rmtree(cache_root, ignore_errors=True)
    shutil.rmtree(root / "models", ignore_errors=True)
    os.environ["PADDLE_PDX_CACHE_HOME"] = str(cache_root)
    os.environ["PADDLEX_HOME"] = str(cache_root)

    import yaml
    from paddleocr import PaddleOCR

    pipeline = PaddleOCR(
        text_detection_model_name=detector,
        text_recognition_model_name=recognizer,
        use_doc_orientation_classify=False,
        use_doc_unwarping=False,
        use_textline_orientation=False,
    )
    try:
        cache_models = cache_root / "official_models"
        root_models = root / "models"
        root_models.mkdir(parents=True, exist_ok=True)
        for name in (detector, recognizer):
            source = cache_models / name
            target = root_models / name
            if source.is_symlink() or not source.is_dir():
                raise RuntimeError(f"PaddleX did not materialize the selected model locally: {name}")
            shutil.copytree(source, target, symlinks=False)
        _remove_hoster_cache(root_models)

        config_path = root / "PaddleOCR.yaml"
        temporary_config = root / ".PaddleOCR.exported.yaml"
        export = getattr(pipeline, "export_paddlex_config_to_yaml", None)
        if not callable(export):
            raise RuntimeError("Installed PaddleOCR does not expose export_paddlex_config_to_yaml")
        export(str(temporary_config))
        config = yaml.safe_load(temporary_config.read_text(encoding="utf-8"))
        if not isinstance(config, dict):
            raise RuntimeError("PaddleOCR exported an invalid pipeline configuration")
        model_identity = _set_selected_model_dirs(config, root=root, detector=detector, recognizer=recognizer)
        config_path.write_text(yaml.safe_dump(config, allow_unicode=True, sort_keys=True), encoding="utf-8")
        temporary_config.unlink(missing_ok=True)
    finally:
        close = getattr(pipeline, "close", None)
        if callable(close):
            close()

    # Prove the exported config itself can initialize the exact local models;
    # no official-model resolver is allowed to run for this second load.
    os.environ["PADDLE_PDX_DISABLE_MODEL_SOURCE_CHECK"] = "1"
    local_pipeline = PaddleOCR(
        paddlex_config=str(config_path),
        text_detection_model_name=detector,
        text_recognition_model_name=recognizer,
        use_doc_orientation_classify=False,
        use_doc_unwarping=False,
        use_textline_orientation=False,
    )
    close = getattr(local_pipeline, "close", None)
    if callable(close):
        close()
    shutil.rmtree(cache_root, ignore_errors=True)

    manifest = {
        "provider": "paddle",
        "asset_provenance": "development-prefetch",
        "asset_status": "DEVELOPMENT_ONLY",
        "paddleocr_version": getattr(__import__("paddleocr"), "__version__", "unknown"),
        "paddle_version": getattr(__import__("paddle"), "__version__", "unknown"),
        "ocr_version": os.environ.get("KSLIDE_PADDLE_OCR_VERSION", "PP-OCRv5"),
        "language": os.environ.get("KSLIDE_PADDLE_LANG", "korean"),
        "detector_model": model_identity["detector_model"],
        "recognizer_model": model_identity["recognizer_model"],
        "paddlex_config": "PaddleOCR.yaml",
        "model_identity": model_identity,
        "files": _materialized_files(root),
    }
    manifest_path = root / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    from k_slide.certification import validate_ocr_asset_manifest

    validate_ocr_asset_manifest(manifest_path, asset_root=root, require_model_identity=True)
    print(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
