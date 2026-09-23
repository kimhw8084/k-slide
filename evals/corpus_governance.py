"""Repository wrapper for the deterministic public synthetic corpus."""

from __future__ import annotations

from typing import Any, Iterable

from k_slide.corpus_governance import (
    CORPUS_GOVERNANCE_SCHEMA_VERSION,
    build_manifest,
    canonical_corpus_identity,
    manifest_identity,
    sha256_bytes,
    canonical_bytes,
)


PUBLIC_SYNTHETIC_SET_ID = "public-synthetic-visual-corpus"


def public_synthetic_manifest(scenarios: Iterable[Any] | None = None) -> dict[str, Any]:
    from .scenarios import CORPUS_GENERATOR_VERSION, DATASET_VERSION, _corpus_fingerprint, scenario_specs

    selected = list(scenarios if scenarios is not None else scenario_specs())
    if not selected:
        raise ValueError("public synthetic corpus is empty")
    corpus_fingerprint = _corpus_fingerprint(selected)
    items = []
    for scenario in selected:
        item = scenario.as_dict() if hasattr(scenario, "as_dict") else dict(scenario)
        source = {
            "title_ko": item.get("title_ko"),
            "body_ko": item.get("body_ko"),
            "seed": item.get("seed"),
            "category": item.get("category"),
            "visual_kind": item.get("visual_kind"),
            "compound": item.get("compound"),
        }
        items.append({
            "item_id": item["scenario_id"],
            "source_sha256": sha256_bytes(canonical_bytes(source)),
            "gold_sha256": sha256_bytes(canonical_bytes(item.get("gold"))),
            "state": "active",
        })
    provenance_hash = sha256_bytes(canonical_bytes({
        "dataset_version": DATASET_VERSION,
        "generator_version": CORPUS_GENERATOR_VERSION,
        "corpus_fingerprint": corpus_fingerprint,
    }))
    return build_manifest(
        set_id=PUBLIC_SYNTHETIC_SET_ID,
        role="public_synthetic_regression",
        version=DATASET_VERSION,
        state="active",
        items=items,
        provenance={"authority": "repository_generator", "record_sha256": provenance_hash},
    )


def public_synthetic_set_identity(scenarios: Iterable[Any] | None = None) -> dict[str, Any]:
    return manifest_identity(public_synthetic_manifest(scenarios))


def public_synthetic_corpus_identity(scenarios: Iterable[Any] | None = None) -> dict[str, Any]:
    return canonical_corpus_identity({
        "schema_version": CORPUS_GOVERNANCE_SCHEMA_VERSION,
        "sets": [public_synthetic_set_identity(scenarios)],
    })
