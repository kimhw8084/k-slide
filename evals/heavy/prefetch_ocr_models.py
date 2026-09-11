"""Materialize the configured PaddleOCR assets during image build."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> int:
    root = Path(os.environ.get("KSLIDE_OCR_ASSET_ROOT", "/opt/k-slide-ocr-assets"))
    root.mkdir(parents=True, exist_ok=True)
    config_path = root / "PaddleOCR.yaml"
    from paddleocr import PaddleOCR

    pipeline = PaddleOCR(
        ocr_version=os.environ.get("KSLIDE_PADDLE_OCR_VERSION", "PP-OCRv5"),
        lang=os.environ.get("KSLIDE_PADDLE_LANG", "korean"),
        use_doc_orientation_classify=False,
        use_doc_unwarping=False,
        use_textline_orientation=False,
    )
    export = getattr(pipeline, "export_paddlex_config_to_yaml", None)
    if not callable(export):
        raise RuntimeError("Installed PaddleOCR does not expose export_paddlex_config_to_yaml")
    export(str(config_path))
    if not config_path.is_file() or config_path.stat().st_size == 0:
        raise RuntimeError("PaddleOCR did not materialize a local pipeline configuration")
    manifest = {
        "provider": "paddle",
        "paddleocr_version": getattr(__import__("paddleocr"), "__version__", "unknown"),
        "paddle_version": getattr(__import__("paddle"), "__version__", "unknown"),
        "ocr_version": os.environ.get("KSLIDE_PADDLE_OCR_VERSION", "PP-OCRv5"),
        "language": os.environ.get("KSLIDE_PADDLE_LANG", "korean"),
        "detector_model": os.environ.get("KSLIDE_PADDLE_DET_MODEL_NAME", "PP-OCRv5_mobile_det"),
        "recognizer_model": os.environ.get("KSLIDE_PADDLE_REC_MODEL_NAME", "korean_PP-OCRv5_mobile_rec"),
        # Asset manifests are copied between the preparation host, the image,
        # and the installed build.  Absolute paths would make the identity
        # machine-specific and could point OCR at a different tree.
        "paddlex_config": config_path.relative_to(root).as_posix(),
        "files": [],
    }
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.name != "manifest.json":
            manifest["files"].append({"path": path.relative_to(root).as_posix(), "sha256": _hash_file(path), "bytes": path.stat().st_size})
    manifest_path = root / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    from k_slide.certification import validate_ocr_asset_manifest

    validate_ocr_asset_manifest(manifest_path, asset_root=root)
    print(json.dumps(manifest, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
