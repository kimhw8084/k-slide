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
production_env="$(mktemp -d)"
python -m venv "$production_env"
"$production_env/bin/python" -m pip install --disable-pip-version-check --no-input -r constraints-production.txt
PYTHONPATH=src:. "$production_env/bin/python" - <<'PY'
import json
from pathlib import Path
from k_slide.certification import dependency_lock_text, installed_dependency_inventory

config = Path(".k-slide-config")
config.mkdir(parents=True, exist_ok=True)
inventory = installed_dependency_inventory()
(config / "production-dependency-inventory.json").write_text(json.dumps(inventory, sort_keys=True, indent=2) + "\n", encoding="utf-8")
(config / "production-requirements.lock").write_text(dependency_lock_text(inventory), encoding="utf-8")
PY
docker build --build-arg PRODUCTION_LOCK=.k-slide-config/production-requirements.lock -f evals/heavy/Dockerfile -t k-slide-heavy .
docker run --rm k-slide-heavy
```

The doctor performs real round-trip checks when those dependencies are
available: a generated Korean PPTX is rendered through the K-Slide conversion
path, and a generated Korean image is passed through the actual PaddleOCR
adapter. Package import success alone is not sufficient. After OCR assets are
prefetched in an approved image, run the doctor with `--network none` where
the deployment permits it to verify local-only runtime behavior.

The Dockerfile installs the exact private lock and fails the build unless the
image's installed package inventory equals the staged canonical inventory.
The lock and inventory are ignored release artifacts; never commit them or
place confidential candidate material in the Docker build context. The current
development machine has not built this image, so this repository does not claim
that heavy integration has executed locally.

For a certifying run, an approved private preparation environment uses
`evals.build_certification_bundle` to package explicitly named resolved
candidate, exact production lock, optional private termbase overlay, and OCR
assets. The public repository does not upload or store that plaintext bundle as
its own Actions artifact. Hosted security/heavy workflows require protected
private-source repository/workflow/token configuration and verify authoritative
private-repository metadata, producer run status/workflow, producer revision,
artifact ownership, expiry, and archive digest before download. Missing
private-source configuration is fail-closed; local or self-hosted preparation
is the supported alternative until that source exists. The bundle separately
carries the public K-Slide `target_subject_git_sha`, which
`evals.materialize_certification_bundle` verifies along with per-file hashes,
portable OCR manifest/assets, and safe relative paths before
materializing the files under `.k-slide-config` with restrictive permissions.
The public development workflow has no private bundle and therefore cannot
produce candidate-bound production evidence.

The heavy workflow freezes the production subject under its production venv,
builds the image from that exact lock, verifies the image inventory, and then
invokes `evals.freeze_production_dependencies --retain-only`. Retention opens
the frozen inventory/lock and built-image inventory without discovering or
rewriting packages. The heavy adapter re-derives equality from those retained
sources; it does not trust a one-time Docker build assertion.

The image build uses the candidate's portable `ocr/manifest.json` and exact
asset tree when a certifying bundle is present; its selected PaddleX
configuration is always the manifest's `PaddleOCR.yaml` entry and is verified
again inside the evaluation image. Only a non-certifying development image may
run `evals.heavy.prefetch_ocr_models`. The prefetcher
exports a local PaddleX pipeline configuration and writes a relative OCR asset
manifest. The managed runtime then sets `KSLIDE_PADDLE_REQUIRE_LOCAL_ASSETS=1`; it will fail instead
of downloading model weights during document processing. The configured
recognizer is the Korean `korean_PP-OCRv5_mobile_rec` model and the detector
is `PP-OCRv5_mobile_det`, subject to the pinned PaddleOCR runtime.

Required-image checks use:

```bash
docker run --rm --network none \
  -v "$PWD/heavy-out:/out" \
  k-slide-heavy --required --networkless
```

The manual GitHub workflow mounts its engine output under `${RUNNER_TEMP}`,
copies the required doctor/engine results and image inventory into one private
evidence directory, and uploads only that retained evidence. Local/development
doctor mode reports missing heavy capabilities as `BLOCKED`; required image
mode reports them as `FAIL`.

Suggested bootstrap on Ubuntu:

```bash
apt-get update
apt-get install -y libreoffice fonts-noto-cjk
python -m pip install -e ".[pdf,pptx,ocr-paddle]"
```

Use an isolated Office profile, explicit subprocess argv, a timeout, and a
network-restricted worker. Do not run this tier with confidential material on
public GitHub-hosted runners.
