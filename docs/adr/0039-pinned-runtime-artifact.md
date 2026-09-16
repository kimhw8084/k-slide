# ADR 0039: Canonical pinned runtime artifact

## Status

KSA-07 BUILD boundary; independent audit and later production gates remain
open.

## Decision

K-Slide has one heavy/runtime image definition at
`deploy/runtime/Dockerfile`. `scripts/build_runtime_artifact.py` creates a
source-only context, builds it for the explicitly supported `linux/amd64`
platform, and verifies the resulting image. The base is identified by a
digest-qualified Python 3.11 slim reference. Debian packages are installed at
exact versions from the dated snapshot recorded in
`system-packages-linux-amd64.json` and are checked with `dpkg-query`.

The Python subject is the repository's existing canonical dependency
inventory/lock model. The runtime lock and inventory are committed public-safe
inputs for the supported target, while an approved private bundle may replace
them only when the same equality checks pass. K-Slide is built as a wheel from
the checked-out source and installed without a writable checkout in the final
image.

The OCR asset manifest and all listed files are copied as an explicit build
input. Runtime startup requires the local PaddleX configuration and asset
hashes; no runtime package/model/font download is permitted. Development
prefetch is opt-in and marks the image `DEVELOPMENT_ONLY`.

The image writes a source-free runtime manifest and a deterministic CycloneDX
1.5 SBOM. The manifest binds the source revision/tree identity, base/platform,
Python/LibreOffice/font facts, exact dependency lock/inventory hashes,
Paddle/PaddleOCR versions, OCR manifest/config hashes, SBOM hash, and a
canonical build-input identity. The build verifier adds the exact local image
ID or real registry digest after inspecting the built image; a local ID is never
called a registry digest.

The image runs as the non-root `kslide` user. Workspace/run storage and
temporary/cache locations are supplied by the caller. Product execution and
heavy doctor use the same image subject, preserving
`BENCHMARKED PATH = USER PATH = PRODUCTION PATH`.

## Consequences

The canonical build requires an approved portable OCR bundle for a candidate
artifact. The repository can still exercise Docker and dependency/system
identity controls with the explicit development-only prefetch mode, but that
does not remove the heavy doctor, networkless OCR, or later certification
gates. KSA-08/09/10/14 and release/certification remain outside this ADR.
