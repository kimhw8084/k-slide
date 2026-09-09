FROM python:3.11-slim

ARG PADDLEPADDLE_VERSION=3.0.0
ARG PADDLEOCR_VERSION=3.0.3

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/opt/k-slide/src

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

ENTRYPOINT ["python", "-m", "evals.heavy.doctor"]
