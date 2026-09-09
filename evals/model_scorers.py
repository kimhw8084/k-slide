"""Source-local semantic scorers for TranslationPatch model results.

These scorers intentionally reject deck-wide coincidence. Numbers, modality,
table cells, and claims must remain attached to the source object that created
the fact.
"""

from __future__ import annotations

import re
from typing import Any

from k_slide.numeric import numeric_fact_matches


_HANGUL = re.compile(r"[\uac00-\ud7a3]")
_APPROVED_HANGUL_CONTEXT = ("source quote", "proper name", "do not translate", "unresolved")


def _patch_regions(patch: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {str(item.get("region_id")): item for item in patch.get("regions", []) if isinstance(item, dict) and item.get("region_id")}


def _patch_cells(patch: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(cell.get("cell_id")): cell
        for table in patch.get("tables", [])
        if isinstance(table, dict)
        for cell in table.get("cells", [])
        if isinstance(cell, dict) and cell.get("cell_id")
    }


def _fact_text(fact: dict[str, Any], regions: dict[str, dict[str, Any]], cells: dict[str, dict[str, Any]]) -> str:
    source_cell = fact.get("source_cell_id")
    if source_cell and source_cell in cells:
        return str(cells[source_cell].get("english", ""))
    source_region = fact.get("source_region_id") or fact.get("source_object_id")
    if source_region and source_region in regions:
        return str(regions[source_region].get("english", ""))
    return ""


def _source_local_numeric_score(evidence: Any, patch: dict[str, Any]) -> tuple[list[bool], list[dict[str, Any]]]:
    regions = _patch_regions(patch)
    cells = _patch_cells(patch)
    results: list[bool] = []
    details: list[dict[str, Any]] = []
    for fact in evidence.numeric_facts:
        text = _fact_text(fact, regions, cells)
        matched, reason = numeric_fact_matches(fact, text)
        results.append(matched)
        details.append({"fact_id": fact.get("fact_id"), "source_object_id": fact.get("source_object_id"), "target_text": text, "matched": matched, "reason": reason})
    return results, details


def _modality_score(scenario: Any, evidence: Any, regions: dict[str, dict[str, Any]]) -> tuple[float, dict[str, Any]]:
    expected = scenario.gold.get("modality") or {}
    expected_commitment = expected.get("commitment") or scenario.gold.get("commitment")
    expected_speech = expected.get("speech_act") or scenario.gold.get("speech_act")
    if not expected_commitment and not expected_speech:
        return 1.0, {"checked": False}
    source_hint = str(expected.get("source_text", ""))
    candidates = []
    for region in evidence.regions:
        source = str(getattr(region, "selected_literal_candidate", "") or "")
        if not source_hint or source_hint in source:
            candidate = regions.get(region.region_id)
            if candidate:
                candidates.append(candidate)
    if not candidates:
        candidates = list(regions.values())
    passed = any(item.get("commitment_status") == expected_commitment and (not expected_speech or item.get("speech_act") == expected_speech) for item in candidates)
    return float(passed), {"expected_commitment": expected_commitment, "expected_speech_act": expected_speech, "candidate_count": len(candidates), "source_hint": source_hint}


def _hangul_surfaces(patch: dict[str, Any]) -> dict[str, list[str]]:
    surfaces: dict[str, list[str]] = {"regions": [], "table_cells": [], "visual_interpretations": [], "executive_claims": []}
    for item in patch.get("regions", []):
        if isinstance(item, dict) and _HANGUL.search(str(item.get("english", ""))) and not item.get("unresolved"):
            surfaces["regions"].append(str(item.get("region_id")))
    for table in patch.get("tables", []):
        for item in table.get("cells", []) if isinstance(table, dict) else []:
            if isinstance(item, dict) and _HANGUL.search(str(item.get("english", ""))) and not item.get("unresolved"):
                surfaces["table_cells"].append(str(item.get("cell_id")))
    for key in ("visual_interpretations", "executive_claims"):
        for item in patch.get(key, []):
            if isinstance(item, dict) and _HANGUL.search(str(item.get("interpretation", item.get("text", "")))):
                surfaces[key].append(str(item.get("relation_id", item.get("claim_id", "unknown"))))
    return surfaces


def _claim_score(scenario: Any, evidence: Any, patch: dict[str, Any]) -> tuple[int, list[str]]:
    expected = scenario.gold.get("executive_claims", [])
    if not expected:
        return 0, []
    known = {region.region_id for region in evidence.regions} | {element.get("element_id") for element in evidence.visual_elements} | {table.table_id for table in evidence.tables} | {cell.cell_id for table in evidence.tables for cell in table.cells}
    failures: list[str] = []
    claims = patch.get("executive_claims", [])
    for gold in expected:
        matching = [claim for claim in claims if claim.get("kind") == gold.get("kind")]
        if not matching:
            failures.append(f"MISSING_{gold.get('kind', 'claim').upper()}")
            continue
        claim = matching[0]
        if not set(claim.get("evidence_ids", [])) & known:
            failures.append("UNSUPPORTED_EXECUTIVE_CLAIM")
        expected_phrases = [str(value).lower() for value in gold.get("acceptable_phrases", [])]
        if expected_phrases and not any(phrase in str(claim.get("text", "")).lower() for phrase in expected_phrases):
            failures.append(f"WRONG_{gold.get('kind', 'claim').upper()}_SEMANTICS")
    return len(failures), failures


def score_translation_patch(scenario: Any, evidence: Any, patch: dict[str, Any]) -> dict[str, Any]:
    source_regions = {region.region_id: region for region in evidence.regions if region.required_for_translation}
    translated_regions = _patch_regions(patch)
    coverage = sum(region_id in translated_regions and (not translated_regions[region_id].get("unresolved") or bool(translated_regions[region_id].get("unresolved_reason"))) for region_id in source_regions) / max(1, len(source_regions))
    numeric_results, numeric_details = _source_local_numeric_score(evidence, patch)
    modality, modality_detail = _modality_score(scenario, evidence, translated_regions)
    hangul = _hangul_surfaces(patch)
    claim_failures, claim_failure_codes = _claim_score(scenario, evidence, patch)
    unsupported_claims = sum(not set(claim.get("evidence_ids", [])) & ({region.region_id for region in evidence.regions} | {element.get("element_id") for element in evidence.visual_elements}) for claim in patch.get("executive_claims", []) if isinstance(claim, dict))
    table_cells = _patch_cells(patch)
    table_failures: list[str] = []
    for table in evidence.tables:
        patch_table = next((item for item in patch.get("tables", []) if isinstance(item, dict) and item.get("table_id") == table.table_id), None)
        if patch_table is None and table.required_for_translation:
            table_failures.append(f"MISSING_TABLE:{table.table_id}")
            continue
        if patch_table is not None:
            expected = {cell.cell_id for cell in table.cells if cell.required_for_translation}
            actual = {cell.get("cell_id") for cell in patch_table.get("cells", []) if isinstance(cell, dict)}
            table_failures.extend(f"MISSING_CELL:{cell_id}" for cell_id in sorted(expected - actual))
    relation_expected = len((scenario.gold.get("process") or {}).get("relations", []))
    relation_observed = len(patch.get("visual_interpretations", []))
    critical = list(claim_failure_codes)
    if coverage < 1.0:
        critical.append("SILENT_REGION_OMISSION")
    if any(not item for item in numeric_results):
        critical.append("CRITICAL_NUMERIC_MISMATCH")
    if modality < 1.0:
        critical.append("CRITICAL_MODALITY_MISMATCH")
    if any(hangul.values()):
        critical.append("UNEXPECTED_HANGUL")
    if unsupported_claims:
        critical.append("UNSUPPORTED_EXECUTIVE_CLAIM")
    if table_failures:
        critical.append("TABLE_CELL_SEMANTIC_FAILURE")
    if relation_expected and relation_observed < relation_expected:
        critical.append("VISUAL_RELATION_OMISSION")
    return {
        "coverage": coverage,
        "numeric_fidelity": sum(numeric_results) / len(numeric_results) if numeric_results else 1.0,
        "numeric_details": numeric_details,
        "modality": modality,
        "modality_detail": modality_detail,
        "table_cell_fidelity": 0.0 if table_failures else 1.0,
        "table_failures": table_failures,
        "visual_relation_recall": relation_observed / max(1, relation_expected) if relation_expected else 1.0,
        "residual_hangul": sum(len(values) for values in hangul.values()),
        "hangul_by_surface": hangul,
        "unsupported_executive_claims": unsupported_claims,
        "executive_claim_failures": claim_failure_codes,
        "critical_failures": sorted(set(critical)),
    }
