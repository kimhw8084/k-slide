from __future__ import annotations

import hashlib

from k_slide.environment import RunEnvironmentIdentity
from k_slide.paas import RuntimeIdentity


def reference_environment(seed: str = "a") -> RunEnvironmentIdentity:
    def digest(label: str) -> str:
        return hashlib.sha256(f"{label}-{seed}".encode("utf-8")).hexdigest()

    return RunEnvironmentIdentity.legacy_reference(
        runtime_ref=f"runtime-reference-{seed}",
        model_identity=f"model-reference-{seed}",
        ocr_identity=f"ocr-reference-{seed}",
        termbase_identity=f"termbase-reference-{seed}",
        source_revision=digest("source")[:40],
    )


def reference_runtime(seed: str = "a") -> RuntimeIdentity:
    environment = reference_environment(seed)
    return RuntimeIdentity(
        runtime_ref=environment.runtime_image_identity,
        model_identity=environment.effective_model_identity,
        ocr_identity=environment.ocr_asset_identity,
        termbase_identity=environment.termbase_identity,
        environment_identity=environment,
    )
