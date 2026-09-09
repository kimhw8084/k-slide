FROM python:3.11-slim

ARG PADDLEPADDLE_VERSION=3.0.0
ARG PADDLEOCR_VERSION=3.0.3

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/opt/k-slide:/opt/k-slide/src \
    KSLIDE_OCR_ASSET_ROOT=/opt/k-slide-ocr-assets \
    PADDLEX_HOME=/opt/k-slide-ocr-assets/paddlex \
    KSLIDE_PADDLEX_CONFIG=/opt/k-slide-ocr-assets/PaddleOCR.yaml \
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

RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir \
        "Pillow>=10,<13" \
        "PyMuPDF>=1.24,<2" \
        "python-pptx>=0.6.23,<2" \
        "paddlepaddle==${PADDLEPADDLE_VERSION}" \
        "paddleocr==${PADDLEOCR_VERSION}"

RUN mkdir -p /opt/k-slide-ocr-assets \
    && python -m evals.heavy.prefetch_ocr_models

ENTRYPOINT ["python", "-m", "evals.heavy.doctor"]
