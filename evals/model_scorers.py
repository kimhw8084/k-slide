"""Semantic scorers for real TranslationPatch results.

The functions score structured meaning, not exact English strings. They are
usable by an approved Gemma/OpenCode runner and remain dormant when no model is
available.
"""

from __future__ import annotations

import re
from typing import Any

from k_slide.numeric import numeric_fact_matches


_HANGUL = re.compile(r"[\uac00-\ud7a3]")


def score_translation_patch(scenario: Any, evidence: Any, patch: dict[str, Any]) -> dict[str, Any]:
    source_regions = {region.region_id: region for region in evidence.regions if region.required_for_translation}
    translated_regions = {item.get("region_id"): item for item in patch.get("regions", []) if isinstance(item, dict)}
    coverage = sum(region_id in translated_regions or translated_regions.get(region_id, {}).get("unresolved") for region_id in source_regions) / max(1, len(source_regions))
    expected_commitment = scenario.gold.get("commitment")
    observed_commitments = {item.get("commitment_status") for item in translated_regions.values()}
    modality = 1.0 if not expected_commitment or expected_commitment in observed_commitments else 0.0
    english_values = [str(item.get("english", "")) for item in translated_regions.values()]
    residual_hangul = [value for value in english_values if _HANGUL.search(value)]
    numeric_results = []
    for fact in evidence.numeric_facts:
        translated_text = " ".join(english_values)
        numeric_results.append(numeric_fact_matches(fact, translated_text)[0])
    claims = patch.get("executive_claims", [])
    known_ids = set(source_regions) | {item.get("element_id") for item in evidence.visual_elements} | {table.table_id for table in evidence.tables} | {cell.cell_id for table in evidence.tables for cell in table.cells}
    unsupported_claims = [claim for claim in claims if not set(claim.get("evidence_ids", [])) & known_ids]
    return {
        "coverage": coverage,
        "numeric_fidelity": sum(numeric_results) / len(numeric_results) if numeric_results else 1.0,
        "modality": modality,
        "residual_hangul": len(residual_hangul),
        "unsupported_executive_claims": len(unsupported_claims),
        "critical_failures": [
            code
            for code, condition in (
                ("SILENT_REGION_OMISSION", coverage < 1.0),
                ("CRITICAL_NUMERIC_MISMATCH", any(not item for item in numeric_results)),
                ("CRITICAL_MODALITY_MISMATCH", modality < 1.0),
                ("UNEXPECTED_HANGUL", bool(residual_hangul)),
                ("UNSUPPORTED_EXECUTIVE_CLAIM", bool(unsupported_claims)),
            )
            if condition
        ],
    }
