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
    if not expected:
        return 1.0, {"checked": False}
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
        return 0.0, {"failure": "SCORER_SOURCE_BINDING_FAILURE", "expected_commitment": expected_commitment, "source_hint": source_hint}
    passed = len(candidates) == 1 and candidates[0].get("commitment_status") == expected_commitment and (not expected_speech or candidates[0].get("speech_act") == expected_speech)
    return float(passed), {"expected_commitment": expected_commitment, "expected_speech_act": expected_speech, "candidate_count": len(candidates), "source_hint": source_hint, "source_bound": len(candidates) == 1}


def _hangul_surfaces(patch: dict[str, Any], known_evidence_ids: set[str]) -> dict[str, list[str]]:
    surfaces: dict[str, list[str]] = {"regions": [], "table_cells": [], "visual_interpretations": [], "executive_claims": []}
    def retained(item: dict[str, Any]) -> bool:
        retention = item.get("hangul_retention")
        if not isinstance(retention, dict):
            return False
        reason = str(retention.get("reason", "")).lower()
        evidence_id = retention.get("evidence_id")
        return any(value in reason for value in _APPROVED_HANGUL_CONTEXT) and evidence_id in known_evidence_ids
    for item in patch.get("regions", []):
        if isinstance(item, dict) and _HANGUL.search(str(item.get("english", ""))) and not item.get("unresolved") and not retained(item):
            surfaces["regions"].append(str(item.get("region_id")))
    for table in patch.get("tables", []):
        for item in table.get("cells", []) if isinstance(table, dict) else []:
            if isinstance(item, dict) and _HANGUL.search(str(item.get("english", ""))) and not item.get("unresolved") and not retained(item):
                surfaces["table_cells"].append(str(item.get("cell_id")))
    for key in ("visual_interpretations", "executive_claims"):
        for item in patch.get(key, []):
            if isinstance(item, dict) and _HANGUL.search(str(item.get("interpretation", item.get("text", "")))) and not retained(item):
                surfaces[key].append(str(item.get("relation_id", item.get("claim_id", "unknown"))))
    return surfaces


def _table_semantic_failures(scenario: Any, evidence: Any, patch: dict[str, Any]) -> tuple[list[str], list[str]]:
    """Check row/column headers and status cells locally, not by text presence."""

    expected_terms = {
        "항목": ("item", "category", "metric"),
        "매출": ("revenue", "sales"),
        "영업이익": ("operating profit", "operating income"),
        "투자": ("investment",),
        "증감": ("change", "variance", "increase", "decrease"),
        "검토": ("review", "under review", "consideration"),
    }
    failures: list[str] = []
    checked: list[str] = []
    gold_roles = (scenario.gold.get("table") or {}).get("header_roles", [])
    for table in evidence.tables:
        patch_table = next((value for value in patch.get("tables", []) if value.get("table_id") == table.table_id), None)
        if not patch_table:
            continue
        cell_map = {str(cell.get("cell_id")): cell for cell in patch_table.get("cells", []) if isinstance(cell, dict)}
        for source_cell in table.cells:
            source = str(source_cell.source_text or "").strip()
            role = next((item for item in gold_roles if item.get("row") == source_cell.row and item.get("column") == source_cell.column), None)
            acceptable = tuple(role.get("acceptable", [])) if role else expected_terms.get(source)
            if not acceptable:
                continue
            translated = str(cell_map.get(source_cell.cell_id, {}).get("english", "")).lower()
            checked.append(source_cell.cell_id)
            if not any(str(term).lower() in translated for term in acceptable):
                failures.append(f"WRONG_TABLE_HEADER_OR_STATUS:{source_cell.cell_id}")
    return failures, checked


def _chart_semantic_score(scenario: Any, evidence: Any, patch: dict[str, Any]) -> tuple[float, list[str]]:
    chart = scenario.gold.get("chart") or {}
    if not chart:
        return 1.0, []
    chart_elements = [item for item in getattr(evidence, "visual_elements", ()) if isinstance(item, dict) and (item.get("kind") == "chart" or item.get("chart"))]
    if chart_elements:
        from .gold_binding import bind_gold_roles

        binding = bind_gold_roles(scenario, evidence)
        chart_id = str(chart.get("chart_id") or "chart")
        expected_element = binding.bindings.get(chart_id)
        if not expected_element:
            return 0.0, ["SCORER_SOURCE_BINDING_FAILURE"]
        claims = [
            item for item in patch.get("visual_interpretations", [])
            if isinstance(item, dict)
            and isinstance(item.get("chart_claim"), dict)
            and item["chart_claim"].get("chart_element_id") == expected_element
            and item["chart_claim"].get("kind") == "trend"
        ]
        if not claims:
            return 0.0, ["CHART_TREND_UNSUPPORTED"]
        observed = claims[0]
        if expected_element not in observed.get("evidence_ids", []) or expected_element not in observed.get("source_element_ids", []):
            return 0.0, ["SCORER_SOURCE_BINDING_FAILURE"]
        expected_trend = chart.get("trend")
        direction = (observed.get("chart_claim") or {}).get("direction")
        if direction != expected_trend:
            if direction in {"increasing", "decreasing"} and expected_trend in {"increasing", "decreasing"}:
                return 0.0, ["CRITICAL_TREND_REVERSAL"]
            return 0.0, ["CHART_TREND_UNSUPPORTED"]
        return 1.0, []
    text = " ".join(str(item.get("interpretation", "")) for item in patch.get("visual_interpretations", []) if isinstance(item, dict)).lower()
    failures: list[str] = []
    directions = {
        "increasing": ("increas", "grow", "upward", "rise", "positive", "trend"),
        "decreasing": ("declin", "decreas", "fall", "downward", "down", "negative", "trend"),
        "flat": ("flat", "stable", "unchanged", "constant"),
    }
    opposites = {
        "increasing": ("declin", "decreas", "fall", "downward", "down", "negative"),
        "decreasing": ("increas", "grow", "upward", "rise", "positive"),
        "flat": ("declin", "decreas", "fall", "downward", "down", "increas", "grow", "upward", "rise"),
    }
    expected = chart.get("trend")
    if expected in directions:
        if any(word in text for word in opposites[expected]):
            failures.append("CRITICAL_TREND_REVERSAL")
        elif not any(word in text for word in directions[expected]):
            failures.append("CHART_TREND_UNSUPPORTED")
    return (0.0 if failures else 1.0), failures


def _process_relation_score(scenario: Any, evidence: Any, patch: dict[str, Any]) -> tuple[float, list[str]]:
    from .gold_binding import bind_process_relations

    expected, binding = bind_process_relations(scenario, evidence)
    if binding.failures:
        return 0.0, [*binding.failures, "PROCESS_RELATION_MISMATCH"]
    if not expected:
        return 1.0, []
    observed = [item for item in patch.get("visual_interpretations", []) if isinstance(item, dict)]
    matched = 0
    for relation in expected:
        found = any(
            item.get("source_element_ids", [])[:2] == [relation.get("from"), relation.get("to")]
            and item.get("relation_type", "") == relation.get("type")
            for item in observed
        )
        matched += int(found)
    failures = [] if matched == len(expected) else ["PROCESS_RELATION_MISMATCH"]
    return matched / len(expected), failures


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
    region_items = [item for item in patch.get("regions", []) if isinstance(item, dict)]
    region_ids = [str(item.get("region_id", "")) for item in region_items]
    translated_regions = _patch_regions(patch)
    invalid_regions = [region_id for region_id in source_regions if region_id not in translated_regions or (translated_regions[region_id].get("unresolved") and not translated_regions[region_id].get("unresolved_reason"))]
    duplicate_region_ids = sorted({region_id for region_id in region_ids if region_ids.count(region_id) > 1})
    coverage = (len(source_regions) - len(invalid_regions)) / max(1, len(source_regions))
    numeric_results, numeric_details = _source_local_numeric_score(evidence, patch)
    modality, modality_detail = _modality_score(scenario, evidence, translated_regions)
    known_ids = set(getattr(evidence, "required_source_ids", ())) | {region.region_id for region in getattr(evidence, "regions", ())}
    hangul = _hangul_surfaces(patch, known_ids)
    claim_failures, claim_failure_codes = _claim_score(scenario, evidence, patch)
    known_claim_evidence_ids = (
        {region.region_id for region in evidence.regions}
        | {element.get("element_id") for element in evidence.visual_elements}
        | {table.table_id for table in evidence.tables}
        | {cell.cell_id for table in evidence.tables for cell in table.cells}
    )
    unsupported_claims = sum(not set(claim.get("evidence_ids", [])) & known_claim_evidence_ids for claim in patch.get("executive_claims", []) if isinstance(claim, dict))
    table_cells = _patch_cells(patch)
    table_failures: list[str] = []
    table_structure: list[dict[str, Any]] = []
    patch_tables = [item for item in patch.get("tables", []) if isinstance(item, dict)]
    patch_table_ids = [str(item.get("table_id", "")) for item in patch_tables]
    expected_table_ids = [table.table_id for table in evidence.tables if table.required_for_translation]
    if len(patch_table_ids) != len(set(patch_table_ids)) or set(patch_table_ids) != set(expected_table_ids):
        table_failures.append("TABLE_CARDINALITY_MISMATCH")
    for table in evidence.tables:
        if not table.required_for_translation:
            continue
        patch_table = next((item for item in patch_tables if item.get("table_id") == table.table_id), None)
        expected = {cell.cell_id for cell in table.cells if cell.required_for_translation}
        actual_items = [cell for cell in patch_table.get("cells", []) if isinstance(cell, dict)] if patch_table else []
        actual_ids = [str(cell.get("cell_id", "")) for cell in actual_items]
        missing = sorted(expected - set(actual_ids))
        extra = sorted(set(actual_ids) - expected)
        duplicated = sorted({cell_id for cell_id in actual_ids if actual_ids.count(cell_id) > 1})
        if missing or extra or duplicated:
            table_failures.append("TABLE_CARDINALITY_MISMATCH")
        table_structure.append({
            "table_id": table.table_id,
            "expected_cell_ids": sorted(expected),
            "observed_cell_ids": sorted(actual_ids),
            "missing_cell_ids": missing,
            "extra_cell_ids": extra,
            "duplicate_cell_ids": duplicated,
        })
        if patch_table is None and table.required_for_translation:
            table_failures.append(f"MISSING_TABLE:{table.table_id}")
            continue
        if patch_table is not None:
            table_failures.extend(f"MISSING_CELL:{cell_id}" for cell_id in missing)
    table_header_failures, table_header_checked = _table_semantic_failures(scenario, evidence, patch)
    chart_score, chart_failures = _chart_semantic_score(scenario, evidence, patch)
    process_score, process_failures = _process_relation_score(scenario, evidence, patch)
    unresolved_ids = sorted({
        str(item.get("region_id")) for item in patch.get("regions", [])
        if isinstance(item, dict) and item.get("unresolved") and item.get("region_id")
    } | {
        str(item.get("cell_id")) for table in patch_tables for item in table.get("cells", [])
        if isinstance(item, dict) and item.get("unresolved") and item.get("cell_id")
    })
    unresolved_count = len(unresolved_ids)
    material_unresolved_ids = sorted(
        region.region_id for region in evidence.regions
        if region.required_for_translation and getattr(region, "recovery_status", None) == "NEEDS_REVIEW"
    )
    materially_unresolved = sorted(set(material_unresolved_ids) & set(unresolved_ids))
    false_resolved_material = sorted(set(material_unresolved_ids) - set(unresolved_ids))
    unnecessary_unresolved = sorted(set(unresolved_ids) - set(material_unresolved_ids))
    required_count = len(source_regions) + sum(len(table.cells) for table in evidence.tables if table.required_for_translation)
    allowed_unresolved = bool(scenario.gold.get("allowed_unresolved", False))
    expected_unresolved_max = int(scenario.gold.get("expected_unresolved_max", 1 if allowed_unresolved else 0))
    unexpected_unresolved = int(unresolved_count > expected_unresolved_max or (unresolved_count > 0 and not allowed_unresolved))
    critical = list(claim_failure_codes)
    if coverage < 1.0:
        critical.append("SILENT_REGION_OMISSION")
    if any(not item for item in numeric_results):
        critical.append("CRITICAL_NUMERIC_MISMATCH")
    if modality < 1.0:
        critical.append("CRITICAL_MODALITY_MISMATCH")
    if modality_detail.get("failure") == "SCORER_SOURCE_BINDING_FAILURE":
        critical.append("SCORER_SOURCE_BINDING_FAILURE")
    if any(hangul.values()):
        critical.append("UNEXPECTED_HANGUL")
    if unsupported_claims:
        critical.append("UNSUPPORTED_EXECUTIVE_CLAIM")
    if table_failures:
        critical.append("TABLE_CELL_SEMANTIC_FAILURE")
    if "TABLE_CARDINALITY_MISMATCH" in table_failures:
        critical.append("TABLE_CARDINALITY_MISMATCH")
    if table_header_failures:
        critical.append("TABLE_HEADER_SEMANTIC_FAILURE")
    critical.extend(chart_failures)
    critical.extend(process_failures)
    if process_score < 1.0:
        critical.append("VISUAL_RELATION_OMISSION")
    if false_resolved_material:
        critical.append("MATERIAL_UNRESOLVED_MISSED")
    if duplicate_region_ids:
        critical.append("SCORER_SOURCE_BINDING_FAILURE")
    semantic_fidelity = min(coverage, sum(numeric_results) / len(numeric_results) if numeric_results else 1.0, modality, 0.0 if table_failures else 1.0, process_score if (scenario.gold.get("process") or {}).get("relations") else chart_score if scenario.gold.get("chart") else 1.0)
    hard_gate_evidence = {
        "missing_required_region_ids": sorted(invalid_regions),
        "numeric_mismatch_fact_ids": sorted(str(item.get("fact_id")) for item in numeric_details if not item.get("matched")),
        "modality_score": modality,
        "modality_source_binding_failure": modality_detail.get("failure") == "SCORER_SOURCE_BINDING_FAILURE",
        "hangul_violation_count": sum(len(values) for values in hangul.values()),
        "executive_claim_failure_codes": sorted(set(claim_failure_codes)),
        "unsupported_claim_count": unsupported_claims,
        "duplicate_region_ids": duplicate_region_ids,
        "table_cardinality_mismatch": "TABLE_CARDINALITY_MISMATCH" in table_failures,
        "table_failure_codes": sorted(set(table_failures)),
        "table_header_failure_ids": sorted(set(table_header_failures)),
        "chart_failure_codes": sorted(set(chart_failures)),
        "process_failure_codes": sorted(set(process_failures)),
        "material_unresolved_required_ids": material_unresolved_ids,
        "material_unresolved_observed_ids": materially_unresolved,
    }
    return {
        "coverage": coverage,
        "numeric_fidelity": sum(numeric_results) / len(numeric_results) if numeric_results else 1.0,
        "numeric_details": numeric_details,
        "modality": modality,
        "modality_detail": modality_detail,
        "table_cell_fidelity": 0.0 if table_failures else 1.0,
        "table_failures": table_failures,
        "table_header_failures": table_header_failures,
        "table_header_checked": table_header_checked,
        "chart_semantic_score": chart_score,
        "process_relation_score": process_score,
        "visual_relation_recall": process_score if (scenario.gold.get("process") or {}).get("relations") else chart_score if scenario.gold.get("chart") else 1.0,
        "residual_hangul": sum(len(values) for values in hangul.values()),
        "hangul_by_surface": hangul,
        "unsupported_executive_claims": unsupported_claims,
        "executive_claim_failures": claim_failure_codes,
        "unresolved_count": unresolved_count,
        "unresolved_region_rate": unresolved_count / max(1, required_count),
        "unexpected_unresolved": unexpected_unresolved,
        "unexpected_unresolved_rate": float(unexpected_unresolved),
        "unresolved_ids": unresolved_ids,
        "material_unresolved_required_ids": material_unresolved_ids,
        "material_unresolved_observed_ids": materially_unresolved,
        "material_unresolved_false_negative_ids": false_resolved_material,
        "unresolved_false_positive_ids": unnecessary_unresolved,
        "material_unresolved_recall": len(materially_unresolved) / len(material_unresolved_ids) if material_unresolved_ids else 1.0,
        "unresolved_precision": len(materially_unresolved) / len(unresolved_ids) if unresolved_ids else 1.0,
        "source_backed_semantic_fidelity": semantic_fidelity,
        "table_structure_evidence": table_structure,
        "hard_gate_evidence": hard_gate_evidence,
        "critical_failures": sorted(set(critical)),
    }


def score_deck_consistency(patches: list[dict[str, Any]], gold: dict[str, Any]) -> dict[str, Any]:
    """Score locked terminology across all translated work units."""

    locked = str(gold.get("locked_term", "")).strip()
    if not locked:
        return {"term_consistency_recall": 1.0, "inconsistent_alternate_count": 0, "critical_failures": []}
    surfaces: list[str] = []
    for patch in patches:
        surfaces.extend(str(item.get("english", "")) for item in patch.get("regions", []) if isinstance(item, dict))
        surfaces.extend(str(cell.get("english", "")) for table in patch.get("tables", []) if isinstance(table, dict) for cell in table.get("cells", []) if isinstance(cell, dict))
        surfaces.extend(str(item.get("text", item.get("interpretation", ""))) for item in patch.get("executive_claims", []) + patch.get("visual_interpretations", []) if isinstance(item, dict))
    applicable = [
        text
        for text in surfaces
        if locked in text or "platform" in text.lower() or "system" in text.lower() or "플랫폼" in text
    ]
    # Locked terminology includes spelling/casing. A casing-only alternate is
    # still a consistency defect for enterprise names and product terms.
    inconsistent = [text for text in applicable if locked not in text]
    return {
        "term_consistency_recall": (len(applicable) - len(inconsistent)) / len(applicable) if applicable else 1.0,
        "inconsistent_alternate_count": len(inconsistent),
        "critical_failures": ["CROSS_SLIDE_TERM_INCONSISTENCY"] if inconsistent else [],
    }
