# syntax=docker/dockerfile:1.7

FROM --platform=linux/amd64 docker.io/library/python:3.11-slim@sha256:d1053354624536b044162aaab1e418bd000ea35184fb1ae098ab3166b1072e72 AS kslide-wheel

WORKDIR /build
COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m pip wheel --disable-pip-version-check --no-cache-dir --no-deps --no-build-isolation --wheel-dir /wheel .

FROM --platform=linux/amd64 docker.io/library/python:3.11-slim@sha256:d1053354624536b044162aaab1e418bd000ea35184fb1ae098ab3166b1072e72

ARG PRODUCTION_LOCK=deploy/runtime/production-requirements.lock
ARG PRODUCTION_INVENTORY=deploy/runtime/production-dependency-inventory.json
ARG SYSTEM_PACKAGE_MANIFEST=deploy/runtime/system-packages-linux-amd64.json
ARG OCR_ASSET_MODE=certifying
ARG ALLOW_DEVELOPMENT_OCR_PREFETCH=0
ARG KSLIDE_SOURCE_REVISION
ARG KSLIDE_SOURCE_TREE_SHA256

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    KSLIDE_OCR_ASSET_ROOT=/opt/k-slide/ocr \
    PADDLEX_HOME=/opt/k-slide/ocr/paddlex \
    KSLIDE_PADDLEX_CONFIG=/opt/k-slide/ocr/PaddleOCR.yaml \
    KSLIDE_PADDLE_REQUIRE_LOCAL_ASSETS=1 \
    KSLIDE_PADDLE_OCR_VERSION=PP-OCRv5 \
    KSLIDE_PADDLE_LANG=korean \
    KSLIDE_PADDLE_DET_MODEL_NAME=PP-OCRv5_mobile_det \
    KSLIDE_PADDLE_REC_MODEL_NAME=korean_PP-OCRv5_mobile_rec \
    PYTHONPATH=/opt/k-slide-tools

WORKDIR /opt/k-slide

COPY ${SYSTEM_PACKAGE_MANIFEST} /opt/k-slide/runtime/system-packages.json

RUN set -eux; \
    test "$KSLIDE_SOURCE_REVISION" != ""; \
    test "$KSLIDE_SOURCE_TREE_SHA256" != ""; \
    printf '%s\n' \
      'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/20260824T000000Z trixie main' \
      'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/20260824T000000Z trixie-security main' \
      > /etc/apt/sources.list; \
    rm -f /etc/apt/sources.list.d/debian.sources; \
    apt-get update; \
    python - <<'PY'
import json
import shutil
import subprocess
from pathlib import Path

manifest = json.loads(Path("/opt/k-slide/runtime/system-packages.json").read_text(encoding="utf-8"))
packages = [f"{item['name']}={item['version']}" for item in manifest["packages"]]
subprocess.run(["apt-get", "install", "-y", "--no-install-recommends", *packages], check=True)
for item in manifest["packages"]:
    result = subprocess.run(["dpkg-query", "-W", "-f=${Version}", item["name"]], capture_output=True, text=True, check=True)
    actual = result.stdout.strip()
    if actual != item["version"]:
        raise SystemExit(f"system package drift: {item['name']} expected={item['version']} actual={actual}")
subprocess.run(["apt-get", "clean"], check=True)
shutil.rmtree("/var/lib/apt/lists", ignore_errors=True)
Path("/var/lib/apt/lists").mkdir(parents=True, exist_ok=True)
shutil.rmtree("/var/cache/apt", ignore_errors=True)
Path("/var/cache/apt").mkdir(parents=True, exist_ok=True)
PY

COPY ${PRODUCTION_LOCK} /opt/k-slide/runtime/inputs/production.lock
COPY ${PRODUCTION_INVENTORY} /opt/k-slide/runtime/inputs/production-inventory.json
COPY --from=kslide-wheel /wheel/k_slide-*.whl /tmp/
RUN python -m pip install --disable-pip-version-check --no-cache-dir --no-deps /tmp/k_slide-*.whl \
    && rm -f /tmp/k_slide-*.whl \
    && python -c 'import k_slide; print(k_slide.__version__)'

RUN set -eux; \
    python -m pip install --disable-pip-version-check --no-cache-dir --no-deps -r /opt/k-slide/runtime/inputs/production.lock; \
    python -m k_slide.runtime_artifact verify-dependencies --lock /opt/k-slide/runtime/inputs/production.lock --inventory /opt/k-slide/runtime/inputs/production-inventory.json; \
    python -c 'from k_slide.certification import installed_dependency_inventory; installed_dependency_inventory()'

RUN mkdir -p /opt/k-slide/ocr /opt/k-slide/runtime /opt/k-slide-tools/evals/heavy
COPY deploy/runtime/ocr-context/ /opt/k-slide/ocr/
COPY evals/__init__.py evals/fonts.py evals/scenarios.py evals/deck_scenarios.py evals/generator.py /opt/k-slide-tools/evals/
COPY evals/heavy/doctor.py /opt/k-slide-tools/evals/heavy/doctor.py
COPY evals/heavy/prefetch_ocr_models.py /tmp/k-slide-prefetch-ocr.py
RUN rm -f /opt/k-slide/ocr/.keep; \
    if test -f /opt/k-slide/ocr/manifest.json; then \
      python -c 'from pathlib import Path; from k_slide.certification import validate_ocr_asset_manifest; validate_ocr_asset_manifest(Path("/opt/k-slide/ocr/manifest.json"), asset_root=Path("/opt/k-slide/ocr"))'; \
    elif test "$OCR_ASSET_MODE" = "development" && test "$ALLOW_DEVELOPMENT_OCR_PREFETCH" = "1"; then \
      python /tmp/k-slide-prefetch-ocr.py; \
    else \
      echo 'KSA-07 runtime builds require a verified portable OCR asset manifest; development prefetch is opt-in only.' >&2; \
      exit 2; \
    fi; \
    rm -f /tmp/k-slide-prefetch-ocr.py

RUN python -m k_slide.runtime_artifact emit \
      --output-root /opt/k-slide/runtime \
      --lock /opt/k-slide/runtime/inputs/production.lock \
      --inventory /opt/k-slide/runtime/inputs/production-inventory.json \
      --system-manifest /opt/k-slide/runtime/system-packages.json \
      --ocr-root /opt/k-slide/ocr \
      --source-revision "$KSLIDE_SOURCE_REVISION" \
      --source-tree-sha256 "$KSLIDE_SOURCE_TREE_SHA256"

RUN useradd --system --uid 10001 --create-home --home-dir /home/kslide kslide \
    && mkdir -p /workspace /tmp/k-slide \
    && chown -R kslide:kslide /opt/k-slide /opt/k-slide-tools /home/kslide /workspace /tmp/k-slide

WORKDIR /workspace
USER kslide

ENTRYPOINT ["k-slide"]
CMD ["doctor", "--json"]
