FROM python:3.11-slim

ARG PRODUCTION_LOCK=.k-slide-config/production-requirements.lock

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/opt/k-slide:/opt/k-slide/src \
    KSLIDE_OCR_ASSET_ROOT=/opt/k-slide/ocr \
    PADDLEX_HOME=/opt/k-slide/ocr/paddlex \
    KSLIDE_PADDLEX_CONFIG=/opt/k-slide/ocr/PaddleOCR.yaml \
    KSLIDE_PADDLE_REQUIRE_LOCAL_ASSETS=1 \
    KSLIDE_PADDLE_OCR_VERSION=PP-OCRv5 \
    KSLIDE_PADDLE_LANG=korean \
    KSLIDE_PADDLE_DET_MODEL_NAME=PP-OCRv5_mobile_det \
    KSLIDE_PADDLE_REC_MODEL_NAME=korean_PP-OCRv5_mobile_rec

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libreoffice \
        fonts-noto-cjk \
        fonts-nanum \
        ca-certificates \
        libgl1 \
        libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

COPY . /opt/k-slide
WORKDIR /opt/k-slide

RUN test -f "/opt/k-slide/${PRODUCTION_LOCK}" \
    && python -m pip install --no-cache-dir -r "/opt/k-slide/${PRODUCTION_LOCK}" \
    && PYTHONPATH=/opt/k-slide/src:/opt/k-slide python - <<'PY'
import json
from pathlib import Path

from k_slide.certification import installed_dependency_inventory, load_dependency_inventory

expected = load_dependency_inventory(Path("/opt/k-slide/.k-slide-config/production-dependency-inventory.json"))
actual = installed_dependency_inventory()
if actual != expected:
    raise SystemExit(json.dumps({"expected": expected, "actual": actual}, sort_keys=True))
PY

RUN mkdir -p /opt/k-slide/ocr \
    && if [ -f /opt/k-slide/ocr/manifest.json ]; then \
         PYTHONPATH=/opt/k-slide/src:/opt/k-slide python -c 'from pathlib import Path; from k_slide.certification import validate_ocr_asset_manifest; validate_ocr_asset_manifest(Path("/opt/k-slide/ocr/manifest.json"), asset_root=Path("/opt/k-slide/ocr"))'; \
       else \
         python -m evals.heavy.prefetch_ocr_models; \
       fi

ENTRYPOINT ["python", "-m", "evals.heavy.doctor"]
