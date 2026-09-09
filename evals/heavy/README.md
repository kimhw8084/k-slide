# Heavy document evaluation environment

This tier is separate from fast PR CI. It is intended for a managed runner or
container with:

```text
LibreOffice/soffice in headless mode
PyMuPDF
python-pptx
Pillow
PaddlePaddle 3.x
PaddleOCR 3.x
an open-source Korean font package
```

The current development machine does not have LibreOffice or PaddleOCR, so
their integration is capability-gated and not claimed as locally executed.
Before promoting this environment, record the exact tested versions in the
evaluation summary and run native PPTX conversion plus actual Korean OCR.

Reproducible container:

```bash
docker build -f evals/heavy/Dockerfile -t k-slide-heavy .
docker run --rm k-slide-heavy
```

The doctor performs real round-trip checks when those dependencies are
available: a generated Korean PPTX is rendered through the K-Slide conversion
path, and a generated Korean image is passed through the actual PaddleOCR
adapter. Package import success alone is not sufficient. After OCR assets are
prefetched in an approved image, run the doctor with `--network none` where
the deployment permits it to verify local-only runtime behavior.

The Dockerfile pins the initial CPU-tested target versions as build arguments;
update them only after the self-test and record the resulting versions in the
evaluation report. The current development machine has not built this image,
so this repository does not claim that heavy integration has executed locally.

The image build runs `evals.heavy.prefetch_ocr_models`, exports a local
PaddleX pipeline configuration, and writes an OCR asset manifest. The managed
runtime then sets `KSLIDE_PADDLE_REQUIRE_LOCAL_ASSETS=1`; it will fail instead
of downloading model weights during document processing. The configured
recognizer is the Korean `korean_PP-OCRv5_mobile_rec` model and the detector
is `PP-OCRv5_mobile_det`, subject to the pinned PaddleOCR runtime.

Required-image checks use:

```bash
docker run --rm --network none \
  -v "$PWD/heavy-out:/out" \
  k-slide-heavy --required --networkless
```

The manual GitHub workflow mounts its engine output under `${RUNNER_TEMP}` and
uploads that host directory, so results remain available after the container
exits. Local/development doctor mode reports missing heavy capabilities as
`BLOCKED`; required image mode reports them as `FAIL`.

Suggested bootstrap on Ubuntu:

```bash
apt-get update
apt-get install -y libreoffice fonts-noto-cjk
python -m pip install -e ".[pdf,pptx,ocr-paddle]"
```

Use an isolated Office profile, explicit subprocess argv, a timeout, and a
network-restricted worker. Do not run this tier with confidential material on
public GitHub-hosted runners.
