# Heavy document verification

Heavy verification consumes the canonical K-Slide runtime artifact. The image
definition is [`deploy/runtime/Dockerfile`](../../deploy/runtime/Dockerfile),
and the only supported build/inspection entrypoint is:

```bash
PYTHONPATH=src:. python scripts/build_runtime_artifact.py build \
  --ocr-root /path/to/approved/ocr \
  --output /tmp/k-slide-runtime-artifact \
  --image k-slide-runtime:local
```

The build is explicitly `linux/amd64` and uses the digest-qualified Python
3.11 slim base recorded by `k_slide.runtime_artifact`. Debian packages are
resolved only from the dated Debian snapshot and are verified against
`deploy/runtime/system-packages-linux-amd64.json`; LibreOffice and the Korean
font package identities are therefore part of the image subject. The committed
`production-requirements.lock` and
`production-dependency-inventory.json` are the exact Python dependency
subject. An approved private bundle may supply replacement copies through the
build command, but it must still satisfy the same lock/inventory equality.

The OCR directory must contain the portable `manifest.json` plus every listed
asset. The manifest and `PaddleOCR.yaml` hashes are verified during the image
build and again by the emitted runtime manifest. A development-only
`--allow-development-ocr-prefetch` mode exists for capability work; it marks
the artifact `DEVELOPMENT_ONLY` and is not KSA-07 candidate evidence.

The image's product surface is the installed `k-slide` command. Its default
command is a doctor smoke check, while a future workspace worker can invoke
`k-slide prepare` or another supported command without rebuilding Python or
system dependencies. The heavy doctor is available from the same image:

```bash
docker run --rm --network none \
  --read-only --tmpfs /tmp --tmpfs /home/kslide \
  -v "$PWD/workspace:/workspace" \
  k-slide-runtime:local \
  python -m evals.heavy.doctor --required --networkless
```

The build command emits `runtime-manifest.json`, `runtime-sbom.json`, and
`artifact-identity.json`. The manifest records the source revision/tree
subject, platform, base digest, Python/LibreOffice/font facts, exact
dependency and OCR identities, and the CycloneDX SBOM hash. A local Docker
image is recorded as a `local-image-id`; it is not relabelled as a registry
digest. OCI config/history are inspected for secret metadata. No registry push
is required.

The current candidate/certification distinction remains in force. A verified
runtime artifact is an input to later candidate and production gates; it does
not certify the Gemma route, durable worker/controller, queue/storage/tenant
isolation, endpoint transport, retention, governance, rollout, or production
certification. Those remain later KSA packages.
