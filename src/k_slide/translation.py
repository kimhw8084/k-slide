"""Strict model-owned TranslationPatch and engine-controlled EvidenceIR merge."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any

from .errors import ErrorCode, KSlideError
from .evidence_ir import RISKY_LITERAL_STATES, EvidenceIR, stable_revision
from .ir import CoverageEntry, NumericFact, SlideIR, TableCell, TableIR, TextRegion, VisualRelation
from .modality import classify_source_language, decision_bearing_status, english_modality_mismatch, executive_modality_mismatch, modality_mismatch, required_english_mismatch, source_english_spans
from .semantics import ClaimKind, CommitmentStatus, CoverageStatus, ProvenanceState, RelationDirection, RelationType, SpeechAct, Uncertainty, enum_value
from .translation_contract import (
    CELL_OPTIONAL_FIELDS,
    CLAIM_OPTIONAL_FIELDS,
    REGION_OPTIONAL_FIELDS,
    RELATION_OPTIONAL_FIELDS,
    ROOT_OPTIONAL_FIELDS,
    TRANSLATION_PATCH_SCHEMA_VERSION,
)

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_MODEL_REGION_FIELDS = set(REGION_OPTIONAL_FIELDS) | {"region_id", "english", "term_ids", "unresolved"}
_MODEL_CELL_FIELDS = set(CELL_OPTIONAL_FIELDS) | {"cell_id", "english", "unresolved"}
_MODEL_TABLE_FIELDS = {"table_id", "cells"}
_MODEL_RELATION_FIELDS = set(RELATION_OPTIONAL_FIELDS) | {"relation_id", "interpretation", "evidence_ids", "chart_claim"}
_MODEL_CLAIM_FIELDS = set(CLAIM_OPTIONAL_FIELDS) | {"claim_id", "kind", "text", "evidence_ids", "uncertainty"}


def _id(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise KSlideError(ErrorCode.SCHEMA_INVALID, f"Unsafe {label} identifier.", {label: value})
    return value


def _only_fields(value: dict[str, Any], allowed: set[str], label: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise KSlideError(ErrorCode.SCHEMA_INVALID, f"TranslationPatch contains source-owned or unknown {label} fields.", {"fields": unknown})


def _string_list(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise KSlideError(ErrorCode.SCHEMA_INVALID, f"{label} must be an array of strings.")
    return tuple(value)


def _optional_string(value: Any, label: str) -> str | None:
    if not isinstance(value, str):
        raise KSlideError(ErrorCode.SCHEMA_INVALID, f"{label} must be a string when present.")
    return value


def _optional_present(value: dict[str, Any], key: str, label: str) -> str | None:
    return _optional_string(value[key], label) if key in value else None


def _boolean(value: Any, label: str, default: bool = False) -> bool:
    if not isinstance(value, bool):
        raise KSlideError(ErrorCode.SCHEMA_INVALID, f"{label} must be a boolean.")
    return value


def _require_fields(value: dict[str, Any], required: set[str], label: str) -> None:
    missing = sorted(required - set(value))
    if missing:
        raise KSlideError(ErrorCode.SCHEMA_INVALID, f"TranslationPatch {label} is missing required fields.", {"fields": missing})


def _hangul_retention(value: Any, label: str) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict) or not isinstance(value.get("reason"), str) or not value.get("reason", "").strip() or not isinstance(value.get("evidence_id"), str):
        raise KSlideError(ErrorCode.SCHEMA_INVALID, f"{label} must contain a reason and evidence_id.")
    return dict(value)


def _provenance(value: Any, label: str) -> str | None:
    if value is None:
        return None
    return enum_value(value, ProvenanceState, label)


def _valid_evidence_ids(evidence: EvidenceIR) -> set[str]:
    return (
        {region.region_id for region in evidence.regions}
        | {table.table_id for table in evidence.tables}
        | {cell.cell_id for table in evidence.tables for cell in table.cells}
        | {str(item.get("fact_id")) for item in evidence.numeric_facts if isinstance(item, dict) and item.get("fact_id")}
        | {str(item.get("element_id")) for item in evidence.visual_elements if isinstance(item, dict) and item.get("element_id")}
    )


def _source_evidence_texts(evidence: EvidenceIR) -> dict[str, str]:
    texts: dict[str, str] = {}
    for region in evidence.regions:
        if isinstance(region.selected_literal_candidate, str):
            texts[region.region_id] = region.selected_literal_candidate
    for table in evidence.tables:
        cell_texts = [cell.source_text for cell in table.cells if isinstance(cell.source_text, str)]
        texts[table.table_id] = "\n".join(cell_texts)
        for cell in table.cells:
            if isinstance(cell.source_text, str):
                texts[cell.cell_id] = cell.source_text
    for fact in evidence.numeric_facts:
        if not isinstance(fact, dict) or not fact.get("fact_id"):
            continue
        source_id = fact.get("source_cell_id") or fact.get("source_region_id")
        if source_id in texts:
            texts[str(fact["fact_id"])] = texts[str(source_id)]
        elif isinstance(fact.get("source_string"), str):
            texts[str(fact["fact_id"])] = fact["source_string"]

    def string_values(value: Any) -> list[str]:
        if isinstance(value, str):
            return [value]
        if isinstance(value, dict):
            return [item for nested in value.values() for item in string_values(nested)]
        if isinstance(value, (list, tuple)):
            return [item for nested in value for item in string_values(nested)]
        return []

    for element in evidence.visual_elements:
        element_id = element.get("element_id") if isinstance(element, dict) else None
        if element_id:
            texts[str(element_id)] = "\n".join(string_values(element))
    return texts


def _require_rendered_english(text: str | None, retention: Any, source_texts: dict[str, str], evidence_ids: tuple[str, ...], label: str) -> None:
    mismatch = required_english_mismatch(text, retention, source_texts, evidence_ids)
    if mismatch:
        raise KSlideError(ErrorCode.REQUIRED_ENGLISH, f"Rendered {label} must use English or cite explicitly retained source text.", {"target": label})


def _executive_source_texts(evidence: EvidenceIR, evidence_ids: tuple[str, ...], source_texts: dict[str, str] | None = None) -> tuple[str, ...]:
    source_texts = source_texts if source_texts is not None else _source_evidence_texts(evidence)
    return tuple(source_texts[item] for item in evidence_ids if item in source_texts)


def _validate_provenance(
    state: str | None,
    evidence_ids: tuple[str, ...],
    evidence: EvidenceIR,
    *,
    label: str,
    unresolved: bool | None = None,
    unresolved_reason: str | None = None,
    direct_source_id: str | None = None,
    source_fact_allowed: bool = True,
    semantic_evidence_allowed: bool = True,
) -> str:
    effective = state or (ProvenanceState.UNRESOLVED.value if unresolved else ProvenanceState.SUPPORTED_INTERPRETATION.value)
    enum_value(effective, ProvenanceState, f"{label} provenance")
    if unresolved is not None and effective == ProvenanceState.UNRESOLVED.value and not unresolved:
        raise KSlideError(ErrorCode.SCHEMA_INVALID, f"{label} unresolved state must set unresolved=true.")
    if unresolved is not None and effective != ProvenanceState.UNRESOLVED.value and unresolved:
        raise KSlideError(ErrorCode.SCHEMA_INVALID, f"{label} unresolved=true conflicts with provenance state.")
    if effective == ProvenanceState.UNRESOLVED.value and not isinstance(unresolved_reason, str):
        raise KSlideError(ErrorCode.SCHEMA_INVALID, f"{label} unresolved provenance requires a reason.")
    if effective == ProvenanceState.UNRESOLVED.value and not unresolved_reason.strip():
        raise KSlideError(ErrorCode.SCHEMA_INVALID, f"{label} unresolved provenance requires a non-empty reason.")
    if effective != ProvenanceState.UNRESOLVED.value and unresolved_reason is not None:
        raise KSlideError(ErrorCode.SCHEMA_INVALID, f"{label} has a reason outside unresolved provenance.")
    if not evidence_ids:
        raise KSlideError(ErrorCode.CLAIM_UNSUPPORTED, f"{label} provenance must cite at least one evidence ID.")
    valid_ids = _valid_evidence_ids(evidence)
    foreign = sorted(set(evidence_ids) - valid_ids)
    if foreign:
        raise KSlideError(ErrorCode.UNKNOWN_SOURCE_ELEMENT, f"{label} provenance references unknown evidence.", {"evidence_ids": foreign})
    if effective == ProvenanceState.SOURCE_FACT.value:
        if not source_fact_allowed:
            raise KSlideError(ErrorCode.SCHEMA_INVALID, f"{label} cannot be marked source_fact.")
        if direct_source_id is not None and direct_source_id not in evidence_ids:
            raise KSlideError(ErrorCode.CLAIM_UNSUPPORTED, f"{label} source_fact must cite its engine source ID.")
    if effective != ProvenanceState.UNRESOLVED.value and not semantic_evidence_allowed:
        raise KSlideError(ErrorCode.CLAIM_UNSUPPORTED, f"{label} cites literal evidence that is absent or still requires recovery.")
    return effective


def _region_literal_usable(region: Any) -> bool:
    return bool(
        isinstance(region.selected_literal_candidate, str)
        and region.selected_literal_candidate.strip()
        and region.evidence_state not in RISKY_LITERAL_STATES
        and region.recovery_status in {"NOT_REQUIRED", "RECOVERED"}
    )


def _cell_literal_usable(cell: Any, region_map: dict[str, Any]) -> bool:
    if _structural_blank(cell):
        return True
    if isinstance(cell.source_text, str) and cell.source_text.strip():
        return True
    return bool(cell.evidence_region_ids) and all(
        region_id in region_map and _region_literal_usable(region_map[region_id])
        for region_id in cell.evidence_region_ids
    )


def _semantic_evidence_usable(evidence: EvidenceIR, evidence_ids: tuple[str, ...] | list[str], *, direct_source_id: str | None = None) -> bool:
    regions = {region.region_id: region for region in evidence.regions}
    cells = {cell.cell_id: cell for table in evidence.tables for cell in table.cells}
    facts = {str(item.get("fact_id")): item for item in evidence.numeric_facts if isinstance(item, dict) and item.get("fact_id")}
    for evidence_id in evidence_ids:
        region = regions.get(evidence_id)
        if region is not None and not _region_literal_usable(region):
            if region.translation_disposition != "NOT_APPLICABLE_NATIVE_VISUAL" or evidence_id == direct_source_id:
                return False
        cell = cells.get(evidence_id)
        if cell is not None and not _cell_literal_usable(cell, regions):
            return False
        fact = facts.get(evidence_id)
        if fact is not None:
            if fact.get("source_region_id") in regions and not _region_literal_usable(regions[str(fact["source_region_id"]) ]):
                return False
            source_cell_id = fact.get("source_cell_id")
            if source_cell_id in cells and not _cell_literal_usable(cells[str(source_cell_id)], regions):
                return False
    if direct_source_id in regions:
        return _region_literal_usable(regions[direct_source_id])
    if direct_source_id in cells:
        return _cell_literal_usable(cells[direct_source_id], regions)
    return True


def _validate_table_cell_evidence_binding(
    cell_id: str,
    table: Any,
    evidence_ids: tuple[str, ...],
    *,
    label: str,
) -> None:
    cell = next((candidate for candidate in table.cells if candidate.cell_id == cell_id), None)
    if cell is None:
        raise KSlideError(ErrorCode.UNKNOWN_TABLE_CELL, f"{label} is not the current EvidenceIR table cell.", {"cell_id": cell_id, "table_id": table.table_id})
    allowed = {cell.cell_id, table.table_id, *cell.evidence_region_ids, *cell.numeric_fact_ids}
    foreign = sorted(set(evidence_ids) - allowed)
    if foreign:
        raise KSlideError(ErrorCode.UNKNOWN_SOURCE_ELEMENT, f"{label} provenance references evidence outside the bound table cell.", {"cell_id": cell_id, "evidence_ids": foreign})
    if cell.cell_id not in evidence_ids:
        raise KSlideError(ErrorCode.CLAIM_UNSUPPORTED, f"{label} provenance must cite its exact EvidenceIR cell ID.", {"cell_id": cell_id})


def _region_source_language(source: Any) -> str:
    return source.language or classify_source_language(source.selected_literal_candidate)


def _cell_source_language(source: Any) -> str:
    return source.source_language or classify_source_language(source.source_text)


def _structural_blank(source: Any) -> bool:
    return source.cell_state in {"blank", "merge_continuation"} or source.is_blank is True or (source.source_text == "" and source.cell_state not in {"nonblank", "merge_origin"} and source.is_blank is not False)


def _chart_elements(evidence: EvidenceIR, source_element_ids: tuple[str, ...]) -> list[dict[str, Any]]:
    requested = set(source_element_ids)
    return [
        item for item in evidence.visual_elements
        if isinstance(item, dict) and item.get("element_id") in requested and item.get("kind") == "chart" and isinstance(item.get("chart"), dict)
    ]


def _connector_geometry_direction(connector: dict[str, Any], elements: dict[str, dict[str, Any]]) -> str | None:
    start = elements.get(str(connector.get("from_element_id")))
    end = elements.get(str(connector.get("to_element_id")))
    if not start or not end:
        return None
    try:
        start_box = [float(value) for value in start["bbox_px"]]
        end_box = [float(value) for value in end["bbox_px"]]
        start_center = ((start_box[0] + start_box[2]) / 2, (start_box[1] + start_box[3]) / 2)
        end_center = ((end_box[0] + end_box[2]) / 2, (end_box[1] + end_box[3]) / 2)
    except (KeyError, TypeError, ValueError):
        return None
    dx = end_center[0] - start_center[0]
    dy = end_center[1] - start_center[1]
    if abs(dx) >= abs(dy) and dx != 0:
        return "left_to_right" if dx > 0 else "right_to_left"
    if dy != 0:
        return "top_to_bottom" if dy > 0 else "bottom_to_top"
    return "none"


def _direction_evidence(connector: dict[str, Any]) -> str | None:
    """Return arrow-derived direction; stCxn/endCxn only prove connectivity."""

    explicit = connector.get("direction_evidence")
    if explicit is not None:
        return explicit if explicit in {"start_to_end", "end_to_start", "bidirectional", "undirected", "ambiguous"} else "ambiguous"
    if "start_arrow_type" not in connector and "end_arrow_type" not in connector:
        return None
    start_type = connector.get("start_arrow_type", "none")
    end_type = connector.get("end_arrow_type", "none")
    if not isinstance(start_type, str) or not isinstance(end_type, str):
        return "ambiguous"
    no_arrow = {"", "none", "noarrow", "nil"}
    start_arrow = start_type.casefold() not in no_arrow
    end_arrow = end_type.casefold() not in no_arrow
    if start_arrow and end_arrow:
        return "bidirectional"
    if end_arrow:
        return "start_to_end"
    if start_arrow:
        return "end_to_start"
    return "undirected"


def _source_fact_connector_relation(relation: dict[str, Any], evidence: EvidenceIR) -> bool:
    source_ids = tuple(relation.get("source_element_ids", []))
    elements = {str(item.get("element_id")): item for item in evidence.visual_elements if isinstance(item, dict) and item.get("element_id")}
    for connector_id in source_ids:
        connector_element = elements.get(connector_id)
        connector = connector_element.get("connector") if connector_element else None
        if not isinstance(connector, dict):
            continue
        start = str(connector.get("from_element_id", ""))
        end = str(connector.get("to_element_id", ""))
        if not start or not end or start not in source_ids or end not in source_ids:
            continue
        arrow_direction = _direction_evidence(connector)
        if arrow_direction not in {"start_to_end", "end_to_start", "bidirectional"}:
            continue
        if arrow_direction == "start_to_end":
            expected_endpoints = (start, end)
            expected_direction = _connector_geometry_direction(connector, elements)
        elif arrow_direction == "end_to_start":
            expected_endpoints = (end, start)
            expected_direction = _connector_geometry_direction({**connector, "from_element_id": end, "to_element_id": start}, elements)
        else:
            expected_endpoints = (start, end)
            expected_direction = "bidirectional"
        if arrow_direction == "bidirectional" and source_ids[:2] not in {expected_endpoints, (end, start)}:
            continue
        if arrow_direction != "bidirectional" and source_ids[:2] != expected_endpoints:
            continue
        if relation.get("direction") != expected_direction:
            continue
        return True
    return False


def _chart_points(series: dict[str, Any]) -> list[dict[str, Any]]:
    points = series.get("points")
    if isinstance(points, list):
        return [point for point in points if isinstance(point, dict)]
    values = series.get("values")
    if isinstance(values, list):
        return [{"point_index": index, "value": value, "is_blank": value is None} for index, value in enumerate(values)]
    return []


def _chart_series(chart: dict[str, Any], claim: dict[str, Any], *, other: bool = False) -> dict[str, Any]:
    index_key = "other_series_index" if other else "series_index"
    name_key = "other_series_name" if other else "series_name"
    index = claim.get(index_key)
    name = claim.get(name_key)
    if isinstance(index, bool) or not isinstance(index, int) or index < 0 or not isinstance(name, str):
        raise KSlideError(ErrorCode.CHART_INTERPRETATION_MISMATCH, "Chart claim must identify an exact series index and name.")
    series = next((item for item in chart.get("series", []) if isinstance(item, dict) and item.get("series_index") == index), None)
    if series is None or series.get("name") != name:
        raise KSlideError(ErrorCode.CHART_INTERPRETATION_MISMATCH, "Chart claim identifies the wrong engine series.", {"series_index": index, "series_name": name})
    return series


def _chart_point(chart: dict[str, Any], claim: dict[str, Any], series: dict[str, Any], *, allow_blank: bool = False) -> dict[str, Any]:
    point_index = claim.get("point_index")
    category = claim.get("category")
    categories = chart.get("categories", [])
    if isinstance(point_index, bool) or not isinstance(point_index, int) or point_index < 0 or point_index >= len(categories) or not isinstance(category, str) or categories[point_index] != category:
        raise KSlideError(ErrorCode.CHART_INTERPRETATION_MISMATCH, "Chart claim category/order does not match engine evidence.")
    point = next((item for item in _chart_points(series) if item.get("point_index") == point_index), None)
    if point is None:
        raise KSlideError(ErrorCode.CHART_INTERPRETATION_MISMATCH, "Chart claim point identity is not present in engine evidence.")
    blank = point.get("is_blank") is True or point.get("value") is None
    if blank and not allow_blank:
        raise KSlideError(ErrorCode.CHART_INTERPRETATION_MISMATCH, "Chart claim cannot treat a blank/null point as numeric data.")
    return point


def _chart_numeric_point(chart: dict[str, Any], claim: dict[str, Any], series: dict[str, Any]) -> dict[str, Any]:
    point = _chart_point(chart, claim, series)
    value = point.get("value")
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise KSlideError(ErrorCode.CHART_INTERPRETATION_MISMATCH, "Chart claim requires an engine numeric point.")
    return point


def _validate_chart_claim(claim: Any, charts: list[dict[str, Any]]) -> None:
    if not isinstance(claim, dict):
        raise KSlideError(ErrorCode.SCHEMA_INVALID, "chart_claim must be an object.")
    allowed = {"chart_element_id", "kind", "series_index", "series_name", "point_index", "category", "value", "is_blank", "direction", "ranking", "rank", "other_series_index", "other_series_name", "operator"}
    _only_fields(claim, allowed, "chart claim")
    chart_id = claim.get("chart_element_id")
    kind = claim.get("kind")
    if not isinstance(chart_id, str) or kind not in {"trend", "point_value", "ranking", "comparison"}:
        raise KSlideError(ErrorCode.SCHEMA_INVALID, "chart_claim requires an engine chart and closed claim kind.")
    common = {"chart_element_id", "kind", "series_index", "series_name"}
    fields_by_kind = {
        "trend": common | {"direction"},
        "point_value": common | {"point_index", "category", "value", "is_blank"},
        "ranking": common | {"point_index", "category", "ranking", "rank"},
        "comparison": common | {"point_index", "category", "other_series_index", "other_series_name", "operator"},
    }
    unsupported_fields = sorted(set(claim) - fields_by_kind[kind])
    if unsupported_fields:
        raise KSlideError(ErrorCode.SCHEMA_INVALID, "Chart claim contains fields outside its closed claim kind.", {"fields": unsupported_fields})
    chart_element = next((item for item in charts if item.get("element_id") == chart_id), None)
    if chart_element is None:
        raise KSlideError(ErrorCode.CHART_INTERPRETATION_MISMATCH, "Chart claim does not identify a cited engine chart.", {"element_id": chart_id})
    chart = chart_element["chart"]
    series = _chart_series(chart, claim)
    if kind == "trend":
        if claim.get("direction") not in {"increasing", "decreasing", "flat"}:
            raise KSlideError(ErrorCode.SCHEMA_INVALID, "Trend chart claims require increasing, decreasing, or flat direction.")
        values = [point.get("value") for point in _chart_points(series)]
        if len(values) < 2 or any(not isinstance(value, (int, float)) or isinstance(value, bool) for value in values):
            raise KSlideError(ErrorCode.CHART_INTERPRETATION_MISMATCH, "Chart trend is unsupported because the named series contains blank/null points.")
        if all(left == right for left, right in zip(values, values[1:])):
            actual = "flat"
        elif all(left <= right for left, right in zip(values, values[1:])):
            actual = "increasing"
        elif all(left >= right for left, right in zip(values, values[1:])):
            actual = "decreasing"
        else:
            raise KSlideError(ErrorCode.CHART_INTERPRETATION_MISMATCH, "Chart trend is non-monotonic and cannot support a closed one-way trend claim.")
        if claim["direction"] != actual:
            raise KSlideError(ErrorCode.CHART_INTERPRETATION_MISMATCH, "Chart claim reverses or misstates the named series trend.", {"expected": actual, "actual": claim["direction"]})
        return
    if kind == "point_value":
        required = {"point_index", "category"}
        if not required.issubset(claim):
            raise KSlideError(ErrorCode.SCHEMA_INVALID, "Point-value chart claims require an exact category and point index.")
        point = _chart_point(chart, claim, series, allow_blank=True)
        expected_blank = point.get("is_blank") is True or point.get("value") is None
        claimed_blank = claim.get("is_blank", False)
        if not isinstance(claimed_blank, bool):
            raise KSlideError(ErrorCode.SCHEMA_INVALID, "Chart point blank state must be boolean.")
        if claimed_blank != expected_blank:
            raise KSlideError(ErrorCode.CHART_INTERPRETATION_MISMATCH, "Chart claim misstates the engine blank/null state.")
        if expected_blank:
            if "value" in claim:
                raise KSlideError(ErrorCode.CHART_INTERPRETATION_MISMATCH, "Blank/null chart points cannot claim a numeric value.")
        else:
            value = claim.get("value")
            if not isinstance(value, (int, float)) or isinstance(value, bool) or float(value) != float(point["value"]):
                raise KSlideError(ErrorCode.CHART_INTERPRETATION_MISMATCH, "Chart claim value is not the engine value for the named category.")
        return
    if kind == "ranking":
        required = {"point_index", "category", "ranking", "rank"}
        if not required.issubset(claim) or claim.get("ranking") not in {"highest", "lowest"} or isinstance(claim.get("rank"), bool) or not isinstance(claim.get("rank"), int) or claim["rank"] < 1:
            raise KSlideError(ErrorCode.SCHEMA_INVALID, "Ranking chart claims require an exact category, rank, and highest/lowest direction.")
        values: list[tuple[float, int]] = []
        for candidate in chart.get("series", []):
            candidate_point = _chart_point(chart, {**claim, "series_index": candidate.get("series_index"), "series_name": candidate.get("name")}, candidate, allow_blank=True)
            if candidate_point.get("is_blank") is True or candidate_point.get("value") is None:
                continue
            values.append((float(candidate_point["value"]), int(candidate["series_index"])))
        if not values or len({value for value, _index in values}) != len(values):
            raise KSlideError(ErrorCode.CHART_INTERPRETATION_MISMATCH, "Chart ranking is unsupported because values are blank or tied.")
        values.sort(key=lambda item: item[0], reverse=claim["ranking"] == "highest")
        expected = values[claim["rank"] - 1][1] if claim["rank"] <= len(values) else None
        if expected != series.get("series_index"):
            raise KSlideError(ErrorCode.CHART_INTERPRETATION_MISMATCH, "Chart claim ranking is not supported by engine values.")
        return
    required = {"point_index", "category", "other_series_index", "other_series_name", "operator"}
    if not required.issubset(claim) or claim.get("operator") not in {"greater_than", "less_than", "equal_to"}:
        raise KSlideError(ErrorCode.SCHEMA_INVALID, "Comparison chart claims require two exact series, category, point, and operator.")
    other = _chart_series(chart, claim, other=True)
    if other.get("series_index") == series.get("series_index"):
        raise KSlideError(ErrorCode.CHART_INTERPRETATION_MISMATCH, "Chart comparison requires two distinct series.")
    left = float(_chart_numeric_point(chart, claim, series)["value"])
    right = float(_chart_numeric_point(chart, {**claim, "series_index": other.get("series_index"), "series_name": other.get("name")}, other)["value"])
    actual = "greater_than" if left > right else "less_than" if left < right else "equal_to"
    if claim["operator"] != actual:
        raise KSlideError(ErrorCode.CHART_INTERPRETATION_MISMATCH, "Chart comparison is not supported by engine values.")


def _validate_chart_interpretation(relation: dict[str, Any], charts: list[dict[str, Any]]) -> None:
    """Validate only the closed chart claim; free prose is interpretation."""

    claim = relation.get("chart_claim")
    if claim is not None:
        _validate_chart_claim(claim, charts)


@dataclass(frozen=True)
class TranslationRegionPatch:
    region_id: str
    english: str
    commitment_status: str | None = None
    speech_act: str | None = None
    term_ids: tuple[str, ...] = ()
    unresolved: bool = False
    unresolved_reason: str | None = None
    hangul_retention: dict[str, Any] | None = None
    provenance: str | None = None
    evidence_ids: tuple[str, ...] | None = None

    def as_dict(self) -> dict[str, Any]:
        value = {key: item for key, item in asdict(self).items() if item is not None}
        value["term_ids"] = list(self.term_ids)
        if self.evidence_ids is not None:
            value["evidence_ids"] = list(self.evidence_ids)
        return value


@dataclass(frozen=True)
class TranslationCellPatch:
    cell_id: str
    english: str
    commitment_status: str | None = None
    speech_act: str | None = None
    unresolved: bool = False
    unresolved_reason: str | None = None
    hangul_retention: dict[str, Any] | None = None
    provenance: str | None = None
    evidence_ids: tuple[str, ...] | None = None

    def as_dict(self) -> dict[str, Any]:
        value = {key: item for key, item in asdict(self).items() if item is not None}
        if self.evidence_ids is not None:
            value["evidence_ids"] = list(self.evidence_ids)
        return value


@dataclass(frozen=True)
class TranslationTablePatch:
    table_id: str
    cells: tuple[TranslationCellPatch, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {"table_id": self.table_id, "cells": [cell.as_dict() for cell in self.cells]}


@dataclass(frozen=True)
class TranslationPatch:
    work_unit_id: str
    evidence_revision: str
    regions: tuple[TranslationRegionPatch, ...] = ()
    tables: tuple[TranslationTablePatch, ...] = ()
    visual_interpretations: tuple[dict[str, Any], ...] = ()
    executive_claims: tuple[dict[str, Any], ...] = ()
    repair_revision: str | None = None
    schema_version: str = TRANSLATION_PATCH_SCHEMA_VERSION

    def as_dict(self) -> dict[str, Any]:
        value = {
            "schema_version": self.schema_version,
            "work_unit_id": self.work_unit_id,
            "evidence_revision": self.evidence_revision,
            "regions": [region.as_dict() for region in self.regions],
            "tables": [table.as_dict() for table in self.tables],
            "visual_interpretations": list(self.visual_interpretations),
            "executive_claims": list(self.executive_claims),
        }
        if self.repair_revision is not None:
            value["repair_revision"] = self.repair_revision
        return value

    def revision(self) -> str:
        return stable_revision(self.as_dict(), excluded={"repair_revision"})

    def validate_against(self, evidence: EvidenceIR) -> None:
        if self.schema_version != TRANSLATION_PATCH_SCHEMA_VERSION:
            raise KSlideError(ErrorCode.SCHEMA_INVALID, "Unsupported TranslationPatch schema version.")
        if self.work_unit_id != evidence.work_unit_id:
            raise KSlideError(ErrorCode.UNKNOWN_WORK_UNIT, "TranslationPatch work unit does not match current evidence.", {"expected": evidence.work_unit_id, "actual": self.work_unit_id})
        if self.evidence_revision != evidence.evidence_revision:
            raise KSlideError(ErrorCode.STALE_EVIDENCE, "TranslationPatch references stale EvidenceIR.", {"expected": evidence.evidence_revision, "actual": self.evidence_revision})
        if not re.fullmatch(r"[a-f0-9]{64}", self.evidence_revision):
            raise KSlideError(ErrorCode.SCHEMA_INVALID, "TranslationPatch evidence_revision must be a SHA-256 hex revision.")
        source_texts = _source_evidence_texts(evidence)
        region_map = {region.region_id: region for region in evidence.regions}
        table_map = {table.table_id: table for table in evidence.tables}
        valid_source_ids = (
            set(region_map)
            | set(table_map)
            | {cell.cell_id for table in evidence.tables for cell in table.cells}
            | {str(item.get("fact_id")) for item in evidence.numeric_facts if isinstance(item, dict) and item.get("fact_id")}
            | {str(item.get("element_id")) for item in evidence.visual_elements if isinstance(item, dict) and item.get("element_id")}
        )
        seen_regions: set[str] = set()
        for patch in self.regions:
            _id(patch.region_id, "region_id")
            if patch.region_id in seen_regions:
                raise KSlideError(ErrorCode.SCHEMA_INVALID, "TranslationPatch contains duplicate regions.")
            seen_regions.add(patch.region_id)
            if patch.region_id not in region_map:
                raise KSlideError(ErrorCode.UNKNOWN_REGION, "TranslationPatch references an unknown region.", {"region_id": patch.region_id})
            source = region_map[patch.region_id]
            if source.translation_disposition == "NOT_APPLICABLE_NATIVE_VISUAL":
                raise KSlideError(ErrorCode.CLAIM_UNSUPPORTED, "The engine preserves this native non-text object through its typed visual or table evidence; the model may not assign text semantics.", {"region_id": patch.region_id})
            source_text = source.selected_literal_candidate
            source_language = _region_source_language(source)
            recovery_required = source.evidence_state in RISKY_LITERAL_STATES or source.recovery_status == "NEEDS_REVIEW"
            recovery_reason = source.recovery_reason or "Required source text could not be recovered from the retained evidence."
            if not isinstance(patch.english, str) or (not recovery_required and not patch.english.strip() and source_text is not None and source_text.strip()):
                raise KSlideError(ErrorCode.SCHEMA_INVALID, "Every translated region needs non-empty English.", {"region_id": patch.region_id})
            if recovery_required and (patch.provenance != ProvenanceState.UNRESOLVED.value or not patch.unresolved or patch.english != ""):
                raise KSlideError(ErrorCode.CLAIM_UNSUPPORTED, "Unrecovered literal evidence must remain empty and unresolved; the model cannot transcribe or complete it.", {"region_id": patch.region_id, "evidence_state": source.evidence_state})
            if patch.unresolved and not patch.unresolved_reason:
                if not recovery_required:
                    raise KSlideError(ErrorCode.SCHEMA_INVALID, "Unresolved regions require an explicit reason.", {"region_id": patch.region_id})
            if patch.commitment_status is not None:
                enum_value(patch.commitment_status, CommitmentStatus, "commitment_status")
            if patch.speech_act is not None:
                enum_value(patch.speech_act, SpeechAct, "speech_act")
            evidence_ids = tuple(patch.evidence_ids if patch.evidence_ids is not None else (patch.region_id,))
            if decision_bearing_status(patch.commitment_status) and (patch.evidence_ids is None or patch.region_id not in evidence_ids):
                raise KSlideError(ErrorCode.CLAIM_UNSUPPORTED, "Decision-bearing commitment classifications require explicit direct evidence linkage.", {"region_id": patch.region_id})
            if not recovery_required:
                mismatch = modality_mismatch(source_text, patch.commitment_status, patch.speech_act)
                if mismatch:
                    raise KSlideError(ErrorCode.MODALITY_MISMATCH, mismatch, {"region_id": patch.region_id})
                english_mismatch = english_modality_mismatch(source_text, patch.english, patch.commitment_status, require_status_marker=True)
                if english_mismatch:
                    raise KSlideError(ErrorCode.MODALITY_MISMATCH, english_mismatch, {"region_id": patch.region_id})
                if source_language == "en" and source_text is not None and patch.english != source_text:
                    raise KSlideError(ErrorCode.CLAIM_UNSUPPORTED, "Pure-English source regions must preserve literal source text.", {"region_id": patch.region_id})
                protected_spans = source.source_english_spans or source_english_spans(source_text)
                missing_spans = [span for span in protected_spans if span not in patch.english]
                if missing_spans:
                    raise KSlideError(ErrorCode.CLAIM_UNSUPPORTED, "Mixed-language source-English spans must survive translation.", {"region_id": patch.region_id, "spans": missing_spans})
            _validate_provenance(
                patch.provenance,
                evidence_ids,
                evidence,
                label=f"Region {patch.region_id}",
                unresolved=patch.unresolved,
                unresolved_reason=patch.unresolved_reason or (recovery_reason if recovery_required else None),
                direct_source_id=patch.region_id,
                source_fact_allowed=not recovery_required,
                semantic_evidence_allowed=not recovery_required,
            )
            if patch.hangul_retention is not None and patch.hangul_retention.get("evidence_id") not in valid_source_ids:
                raise KSlideError(ErrorCode.UNKNOWN_SOURCE_ELEMENT, "Hangul retention references unknown evidence.", {"region_id": patch.region_id})
            retention_evidence_id = patch.hangul_retention.get("evidence_id") if patch.hangul_retention else None
            if retention_evidence_id is not None and retention_evidence_id not in evidence_ids:
                raise KSlideError(ErrorCode.CLAIM_UNSUPPORTED, "Hangul retention must cite evidence bound to its rendered region.", {"region_id": patch.region_id})
            region_provenance = patch.provenance or (ProvenanceState.UNRESOLVED.value if patch.unresolved else ProvenanceState.SUPPORTED_INTERPRETATION.value)
            _require_rendered_english(
                (recovery_reason if recovery_required else patch.unresolved_reason) if region_provenance == ProvenanceState.UNRESOLVED.value else patch.english,
                patch.hangul_retention,
                source_texts,
                evidence_ids,
                f"region {patch.region_id}",
            )
        required_regions = {region.region_id for region in evidence.regions if region.required_for_translation}
        missing_regions = sorted(required_regions - seen_regions)
        if missing_regions:
            raise KSlideError(ErrorCode.EVIDENCE_INCOMPLETE, "TranslationPatch omitted required source regions; submit an explicit unresolved entry instead.", {"region_ids": missing_regions})
        seen_tables: set[str] = set()
        for table_patch in self.tables:
            if table_patch.table_id in seen_tables:
                raise KSlideError(ErrorCode.SCHEMA_INVALID, "TranslationPatch contains duplicate tables.")
            seen_tables.add(table_patch.table_id)
            table = table_map.get(table_patch.table_id)
            if table is None:
                raise KSlideError(ErrorCode.UNKNOWN_TABLE, "TranslationPatch references an unknown table.", {"table_id": table_patch.table_id})
            cells = {cell.cell_id: cell for cell in table.cells}
            evidence_region_map = {region.region_id: region for region in evidence.regions}
            seen_cells: set[str] = set()
            for cell_patch in table_patch.cells:
                if cell_patch.cell_id in seen_cells:
                    raise KSlideError(ErrorCode.SCHEMA_INVALID, "TranslationPatch contains duplicate table cells.", {"cell_id": cell_patch.cell_id})
                seen_cells.add(cell_patch.cell_id)
                if cell_patch.cell_id not in cells:
                    raise KSlideError(ErrorCode.UNKNOWN_TABLE_CELL, "TranslationPatch references an unknown table cell.", {"cell_id": cell_patch.cell_id})
                source_cell = cells[cell_patch.cell_id]
                source_language = _cell_source_language(source_cell)
                structural_blank = _structural_blank(source_cell)
                recovery_required = not _cell_literal_usable(source_cell, evidence_region_map)
                recovery_region = next((evidence_region_map[item] for item in source_cell.evidence_region_ids if item in evidence_region_map and evidence_region_map[item].evidence_state in RISKY_LITERAL_STATES), None)
                recovery_reason = (recovery_region.recovery_reason if recovery_region else None) or "Required table-cell literal could not be recovered from the retained evidence."
                if not cell_patch.english.strip() and not structural_blank and not recovery_required:
                    raise KSlideError(ErrorCode.SCHEMA_INVALID, "Every nonblank translated table cell needs non-empty English.", {"cell_id": cell_patch.cell_id})
                if recovery_required and (cell_patch.provenance != ProvenanceState.UNRESOLVED.value or not cell_patch.unresolved or cell_patch.english != ""):
                    raise KSlideError(ErrorCode.CLAIM_UNSUPPORTED, "A table cell without trustworthy literal evidence must remain empty and unresolved.", {"cell_id": cell_patch.cell_id})
                if structural_blank and cell_patch.english != "":
                    raise KSlideError(ErrorCode.CLAIM_UNSUPPORTED, "Blank and merge-continuation table cells cannot receive invented content.", {"cell_id": cell_patch.cell_id})
                if cell_patch.unresolved and not cell_patch.unresolved_reason:
                    if not recovery_required:
                        raise KSlideError(ErrorCode.SCHEMA_INVALID, "Unresolved table cells require an explicit reason.", {"cell_id": cell_patch.cell_id})
                if cell_patch.commitment_status is not None:
                    enum_value(cell_patch.commitment_status, CommitmentStatus, "table-cell commitment_status")
                if cell_patch.speech_act is not None:
                    enum_value(cell_patch.speech_act, SpeechAct, "table-cell speech_act")
                if not recovery_required:
                    mismatch = modality_mismatch(source_cell.source_text, cell_patch.commitment_status, cell_patch.speech_act)
                    if mismatch:
                        raise KSlideError(ErrorCode.MODALITY_MISMATCH, mismatch, {"cell_id": cell_patch.cell_id})
                    english_mismatch = english_modality_mismatch(source_cell.source_text, cell_patch.english, cell_patch.commitment_status, require_status_marker=True)
                    if english_mismatch:
                        raise KSlideError(ErrorCode.MODALITY_MISMATCH, english_mismatch, {"cell_id": cell_patch.cell_id})
                    if source_language == "en" and source_cell.source_text is not None and cell_patch.english != source_cell.source_text:
                        raise KSlideError(ErrorCode.CLAIM_UNSUPPORTED, "Pure-English table cells must preserve literal source text.", {"cell_id": cell_patch.cell_id})
                    protected_spans = source_cell.source_english_spans or source_english_spans(source_cell.source_text)
                    missing_spans = [span for span in protected_spans if span not in cell_patch.english]
                    if missing_spans:
                        raise KSlideError(ErrorCode.CLAIM_UNSUPPORTED, "Mixed-language table source-English spans must survive translation.", {"cell_id": cell_patch.cell_id, "spans": missing_spans})
                evidence_ids = tuple(cell_patch.evidence_ids if cell_patch.evidence_ids is not None else (cell_patch.cell_id,))
                _validate_table_cell_evidence_binding(cell_patch.cell_id, table, evidence_ids, label=f"Table cell {cell_patch.cell_id}")
                _validate_provenance(
                    cell_patch.provenance,
                    evidence_ids,
                    evidence,
                    label=f"Table cell {cell_patch.cell_id}",
                    unresolved=cell_patch.unresolved,
                    unresolved_reason=cell_patch.unresolved_reason or (recovery_reason if recovery_required else None),
                    direct_source_id=cell_patch.cell_id,
                    source_fact_allowed=not recovery_required,
                    semantic_evidence_allowed=not recovery_required,
                )
                if cell_patch.hangul_retention is not None and cell_patch.hangul_retention.get("evidence_id") not in valid_source_ids:
                    raise KSlideError(ErrorCode.UNKNOWN_SOURCE_ELEMENT, "Hangul retention references unknown evidence.", {"cell_id": cell_patch.cell_id})
                if cell_patch.hangul_retention is not None and cell_patch.hangul_retention.get("evidence_id") not in evidence_ids:
                    raise KSlideError(ErrorCode.CLAIM_UNSUPPORTED, "Hangul retention must cite evidence bound to its rendered table cell.", {"cell_id": cell_patch.cell_id})
                cell_state = cell_patch.provenance or (ProvenanceState.UNRESOLVED.value if cell_patch.unresolved else ProvenanceState.SUPPORTED_INTERPRETATION.value)
                _require_rendered_english(
                    (recovery_reason if recovery_required else cell_patch.unresolved_reason) if cell_state == ProvenanceState.UNRESOLVED.value else cell_patch.english,
                    cell_patch.hangul_retention,
                    source_texts,
                    evidence_ids,
                    f"table cell {cell_patch.cell_id}",
                )
            missing_cells = sorted(cell_id for cell_id, cell in cells.items() if cell.required_for_translation and cell_id not in seen_cells)
            if missing_cells:
                raise KSlideError(ErrorCode.EVIDENCE_INCOMPLETE, "TranslationPatch omitted required table cells.", {"cell_ids": missing_cells})
        required_tables = {table.table_id for table in evidence.tables if table.required_for_translation}
        if required_tables - seen_tables:
            raise KSlideError(ErrorCode.EVIDENCE_INCOMPLETE, "TranslationPatch omitted required tables.", {"table_ids": sorted(required_tables - seen_tables)})
        for relation in self.visual_interpretations:
            _only_fields(relation, _MODEL_RELATION_FIELDS, "visual interpretation")
            _id(relation.get("relation_id"), "relation_id")
            evidence_ids = _string_list(relation.get("evidence_ids", []), "visual interpretation evidence_ids")
            source_element_ids = _string_list(relation.get("source_element_ids", []), "visual interpretation source_element_ids")
            if not _semantic_evidence_usable(evidence, evidence_ids):
                raise KSlideError(ErrorCode.CLAIM_UNSUPPORTED, "Visual interpretations cannot use literal evidence that is absent or still requires recovery.", {"relation_id": relation.get("relation_id")})
            unknown_elements = sorted(set(source_element_ids) - valid_source_ids)
            if unknown_elements:
                raise KSlideError(ErrorCode.UNKNOWN_SOURCE_ELEMENT, "Visual interpretation references unknown source elements.", {"source_element_ids": unknown_elements})
            charts = _chart_elements(evidence, source_element_ids)
            for chart in charts:
                if chart.get("element_id") not in evidence_ids:
                    raise KSlideError(ErrorCode.CLAIM_UNSUPPORTED, "Chart interpretations must cite the current engine chart evidence ID.", {"element_id": chart.get("element_id")})
            chart_claim = relation.get("chart_claim")
            if chart_claim is not None:
                if not charts or not isinstance(chart_claim, dict) or chart_claim.get("chart_element_id") not in source_element_ids or chart_claim.get("chart_element_id") not in evidence_ids:
                    raise KSlideError(ErrorCode.CLAIM_UNSUPPORTED, "Chart claims must cite and identify the exact engine chart element.")
            source_fact_allowed = _source_fact_connector_relation(relation, evidence)
            if charts:
                source_fact_allowed = isinstance(chart_claim, dict)
            _validate_provenance(
                relation.get("provenance"),
                evidence_ids,
                evidence,
                label=f"Visual interpretation {relation.get('relation_id')}",
                unresolved_reason=relation.get("unresolved_reason"),
                source_fact_allowed=source_fact_allowed,
                semantic_evidence_allowed=True,
            )
            if relation.get("relation_type") is not None:
                enum_value(relation.get("relation_type"), RelationType, "relation_type")
            if relation.get("direction") is not None:
                enum_value(relation.get("direction"), RelationDirection, "direction")
            retention = relation.get("hangul_retention")
            if retention is not None and (not isinstance(retention, dict) or retention.get("evidence_id") not in valid_source_ids):
                raise KSlideError(ErrorCode.UNKNOWN_SOURCE_ELEMENT, "Hangul retention references unknown evidence.")
            if retention is not None and retention.get("evidence_id") not in evidence_ids:
                raise KSlideError(ErrorCode.CLAIM_UNSUPPORTED, "Hangul retention must cite evidence bound to its visual interpretation.")
            relation_state = relation.get("provenance") or ProvenanceState.SUPPORTED_INTERPRETATION.value
            _require_rendered_english(
                relation.get("unresolved_reason") if relation_state == ProvenanceState.UNRESOLVED.value else relation.get("interpretation"),
                retention,
                source_texts,
                evidence_ids,
                f"visual interpretation {relation.get('relation_id')}",
            )
            if charts:
                _validate_chart_interpretation(relation, charts)
        seen_claims: set[str] = set()
        for claim in self.executive_claims:
            _only_fields(claim, _MODEL_CLAIM_FIELDS, "executive claim")
            claim_id = _id(claim.get("claim_id"), "claim_id")
            if claim_id in seen_claims:
                raise KSlideError(ErrorCode.SCHEMA_INVALID, "TranslationPatch contains duplicate executive claims.", {"claim_id": claim_id})
            seen_claims.add(claim_id)
            if not isinstance(claim.get("text"), str) or not claim["text"].strip():
                raise KSlideError(ErrorCode.SCHEMA_INVALID, "Executive claims need non-empty text.", {"claim_id": claim_id})
            enum_value(claim.get("kind"), ClaimKind, "executive claim kind")
            enum_value(claim.get("uncertainty"), Uncertainty, "executive claim uncertainty")
            evidence_ids = _string_list(claim.get("evidence_ids", []), "executive claim evidence_ids")
            if not _semantic_evidence_usable(evidence, evidence_ids):
                raise KSlideError(ErrorCode.CLAIM_UNSUPPORTED, "Executive claims cannot use literal evidence that is absent or still requires recovery.", {"claim_id": claim_id})
            _validate_provenance(
                claim.get("provenance"),
                evidence_ids,
                evidence,
                label=f"Executive claim {claim_id}",
                unresolved_reason=claim.get("unresolved_reason"),
                semantic_evidence_allowed=True,
            )
            claim_provenance = claim.get("provenance") or ProvenanceState.SUPPORTED_INTERPRETATION.value
            modality_issue = executive_modality_mismatch(
                _executive_source_texts(evidence, evidence_ids, source_texts),
                claim.get("text"),
                claim_kind=claim.get("kind"),
                provenance=claim.get("provenance"),
            )
            if modality_issue:
                raise KSlideError(ErrorCode.MODALITY_MISMATCH, modality_issue, {"claim_id": claim_id})
            retention = claim.get("hangul_retention")
            if retention is not None and (not isinstance(retention, dict) or retention.get("evidence_id") not in valid_source_ids):
                raise KSlideError(ErrorCode.UNKNOWN_SOURCE_ELEMENT, "Hangul retention references unknown evidence.", {"claim_id": claim_id})
            if retention is not None and retention.get("evidence_id") not in evidence_ids:
                raise KSlideError(ErrorCode.CLAIM_UNSUPPORTED, "Hangul retention must cite evidence bound to its executive claim.", {"claim_id": claim_id})
            _require_rendered_english(
                claim.get("unresolved_reason") if claim_provenance == ProvenanceState.UNRESOLVED.value else claim.get("text"),
                retention,
                source_texts,
                evidence_ids,
                f"executive claim {claim_id}",
            )


def parse_translation_patch(value: dict[str, Any]) -> TranslationPatch:
    if not isinstance(value, dict):
        raise KSlideError(ErrorCode.SCHEMA_INVALID, "TranslationPatch must be an object.")
    allowed = {"schema_version", "work_unit_id", "evidence_revision", "regions", "tables", "visual_interpretations", "executive_claims", "repair_revision"}
    _only_fields(value, allowed, "payload")
    _require_fields(value, {"schema_version", "work_unit_id", "evidence_revision", "regions", "tables", "visual_interpretations", "executive_claims"}, "payload")
    regions_value = value.get("regions", [])
    tables_value = value.get("tables", [])
    if not isinstance(regions_value, list) or not isinstance(tables_value, list):
        raise KSlideError(ErrorCode.SCHEMA_INVALID, "TranslationPatch regions and tables must be arrays.")
    regions: list[TranslationRegionPatch] = []
    for item in regions_value:
        if not isinstance(item, dict):
            raise KSlideError(ErrorCode.SCHEMA_INVALID, "TranslationPatch region must be an object.")
        _require_fields(item, {"region_id", "english", "term_ids", "unresolved"}, "region")
        _only_fields(item, _MODEL_REGION_FIELDS, "region")
        english = item.get("english", "")
        if not isinstance(english, str):
            raise KSlideError(ErrorCode.SCHEMA_INVALID, "region english must be a string.")
        regions.append(TranslationRegionPatch(
            region_id=_id(item.get("region_id"), "region_id"),
            english=english,
            commitment_status=_optional_present(item, "commitment_status", "commitment_status"),
            speech_act=_optional_present(item, "speech_act", "speech_act"),
            term_ids=_string_list(item.get("term_ids", []), "term_ids"),
            unresolved=_boolean(item.get("unresolved"), "unresolved"),
            unresolved_reason=_optional_present(item, "unresolved_reason", "unresolved_reason"),
            hangul_retention=_hangul_retention(item.get("hangul_retention"), "region hangul_retention"),
            provenance=_provenance(item.get("provenance"), "region provenance"),
            evidence_ids=_string_list(item["evidence_ids"], "region evidence_ids") if "evidence_ids" in item else None,
        ))
    tables: list[TranslationTablePatch] = []
    for item in tables_value:
        if not isinstance(item, dict):
            raise KSlideError(ErrorCode.SCHEMA_INVALID, "TranslationPatch table must be an object.")
        _only_fields(item, _MODEL_TABLE_FIELDS, "table")
        cells_value = item.get("cells", [])
        if not isinstance(cells_value, list):
            raise KSlideError(ErrorCode.SCHEMA_INVALID, "TranslationPatch table cells must be an array.")
        cells: list[TranslationCellPatch] = []
        for cell in cells_value:
            if not isinstance(cell, dict):
                raise KSlideError(ErrorCode.SCHEMA_INVALID, "TranslationPatch cell must be an object.")
            _require_fields(cell, {"cell_id", "english", "unresolved"}, "table cell")
            _only_fields(cell, _MODEL_CELL_FIELDS, "table cell")
            english = cell.get("english", "")
            if not isinstance(english, str):
                raise KSlideError(ErrorCode.SCHEMA_INVALID, "table cell english must be a string.")
            cells.append(TranslationCellPatch(
                cell_id=_id(cell.get("cell_id"), "cell_id"),
                english=english,
                commitment_status=_optional_present(cell, "commitment_status", "table-cell commitment_status"),
                speech_act=_optional_present(cell, "speech_act", "table-cell speech_act"),
                unresolved=_boolean(cell.get("unresolved"), "unresolved"),
                unresolved_reason=_optional_present(cell, "unresolved_reason", "unresolved_reason"),
                hangul_retention=_hangul_retention(cell.get("hangul_retention"), "table cell hangul_retention"),
                provenance=_provenance(cell.get("provenance"), "table cell provenance"),
                evidence_ids=_string_list(cell["evidence_ids"], "table cell evidence_ids") if "evidence_ids" in cell else None,
            ))
        tables.append(TranslationTablePatch(table_id=_id(item.get("table_id"), "table_id"), cells=tuple(cells)))
    visual = value.get("visual_interpretations", [])
    if not isinstance(visual, list) or any(not isinstance(item, dict) for item in visual):
        raise KSlideError(ErrorCode.SCHEMA_INVALID, "visual_interpretations must be an array of objects.")
    for relation in visual:
        _require_fields(relation, {"relation_id", "interpretation", "evidence_ids"}, "visual interpretation")
        _only_fields(relation, _MODEL_RELATION_FIELDS, "visual interpretation")
        _id(relation.get("relation_id"), "relation_id")
        if not isinstance(relation.get("interpretation"), str):
            raise KSlideError(ErrorCode.SCHEMA_INVALID, "visual interpretation must be a string.")
        _string_list(relation.get("evidence_ids", []), "visual interpretation evidence_ids")
        _string_list(relation.get("source_element_ids", []), "visual interpretation source_element_ids")
        _provenance(relation.get("provenance"), "visual interpretation provenance")
        if "unresolved_reason" in relation:
            _optional_string(relation["unresolved_reason"], "visual interpretation unresolved_reason")
        if relation.get("relation_type") is not None:
            enum_value(relation.get("relation_type"), RelationType, "relation_type")
        if relation.get("direction") is not None:
            enum_value(relation.get("direction"), RelationDirection, "direction")
        if "chart_claim" in relation and relation["chart_claim"] is not None and not isinstance(relation["chart_claim"], dict):
            raise KSlideError(ErrorCode.SCHEMA_INVALID, "visual interpretation chart_claim must be an object.")
        _hangul_retention(relation.get("hangul_retention"), "visual interpretation hangul_retention")
    executive_claims = value.get("executive_claims", [])
    if not isinstance(executive_claims, list) or any(not isinstance(item, dict) for item in executive_claims):
        raise KSlideError(ErrorCode.SCHEMA_INVALID, "executive_claims must be an array of objects.")
    for claim in executive_claims:
        _require_fields(claim, {"claim_id", "kind", "text", "evidence_ids", "uncertainty"}, "executive claim")
        _only_fields(claim, _MODEL_CLAIM_FIELDS, "executive claim")
        _hangul_retention(claim.get("hangul_retention"), "executive claim hangul_retention")
        _provenance(claim.get("provenance"), "executive claim provenance")
        if "unresolved_reason" in claim:
            _optional_string(claim["unresolved_reason"], "executive claim unresolved_reason")
    evidence_revision = value.get("evidence_revision")
    schema_version = value.get("schema_version")
    if not isinstance(evidence_revision, str):
        raise KSlideError(ErrorCode.SCHEMA_INVALID, "evidence_revision must be a string.")
    if not isinstance(schema_version, str):
        raise KSlideError(ErrorCode.SCHEMA_INVALID, "schema_version must be a string.")
    return TranslationPatch(
        work_unit_id=_id(value.get("work_unit_id"), "work_unit_id"),
        evidence_revision=evidence_revision,
        regions=tuple(regions),
        tables=tuple(tables),
        visual_interpretations=tuple(visual),
        executive_claims=tuple(executive_claims),
        repair_revision=_optional_present(value, "repair_revision", "repair_revision"),
        schema_version=schema_version,
    )


def merge_evidence_patch(evidence: EvidenceIR, patch: TranslationPatch, *, runtime_metadata: dict[str, Any] | None = None, translation_revision: str | None = None) -> SlideIR:
    patch.validate_against(evidence)
    region_patches = {item.region_id: item for item in patch.regions}
    table_patches = {item.table_id: item for item in patch.tables}
    regions: list[TextRegion] = []
    for source in evidence.regions:
        if source.translation_disposition == "NOT_APPLICABLE_NATIVE_VISUAL":
            continue
        item = region_patches[source.region_id]
        provenance = item.provenance or (ProvenanceState.UNRESOLVED.value if item.unresolved else ProvenanceState.SUPPORTED_INTERPRETATION.value)
        recovery_required = source.evidence_state in RISKY_LITERAL_STATES or source.recovery_status == "NEEDS_REVIEW"
        unresolved_reason = source.recovery_reason if recovery_required else item.unresolved_reason
        provenance_evidence_ids = list(item.evidence_ids if item.evidence_ids is not None else (source.region_id,))
        regions.append(TextRegion(
            region_id=source.region_id,
            bbox=list(source.bbox_px),
            reading_order=source.reading_order,
            region_type=source.region_type,
            native_source_text=source.selected_literal_candidate,
            ocr_candidates=list(source.ocr_candidates),
            selected_source_text=source.selected_literal_candidate,
            source_language=source.language,
            source_english_spans=list(source.source_english_spans),
            source_confidence=source.literal_confidence,
            translation="" if recovery_required else (source.selected_literal_candidate if _region_source_language(source) == "en" and source.selected_literal_candidate is not None else item.english),
            evidence_sources=provenance_evidence_ids,
            provenance=provenance,
            provenance_evidence_ids=provenance_evidence_ids,
            term_matches=list(item.term_ids),
            numeric_fact_ids=list(source.numeric_fact_ids),
            commitment_status=item.commitment_status,
            speech_act=item.speech_act,
            hangul_retention=item.hangul_retention,
            unresolved_reason=unresolved_reason,
        ))
    tables: list[TableIR] = []
    for source_table in evidence.tables:
        table_patch = table_patches[source_table.table_id]
        cell_patches = {item.cell_id: item for item in table_patch.cells}
        cells = []
        for cell in source_table.cells:
            patch_cell = cell_patches[cell.cell_id]
            provenance = patch_cell.provenance or (ProvenanceState.UNRESOLVED.value if patch_cell.unresolved else ProvenanceState.SUPPORTED_INTERPRETATION.value)
            recovery_required = not _cell_literal_usable(cell, {region.region_id: region for region in evidence.regions})
            recovery_region = next((region for region in evidence.regions if region.region_id in cell.evidence_region_ids and region.evidence_state in RISKY_LITERAL_STATES), None)
            unresolved_reason = (recovery_region.recovery_reason if recovery_region else None) if recovery_required else patch_cell.unresolved_reason
            provenance_evidence_ids = list(patch_cell.evidence_ids if patch_cell.evidence_ids is not None else (cell.cell_id,))
            cells.append(TableCell(
                cell_id=cell.cell_id,
                row=cell.row,
                column=cell.column,
                source_text=cell.source_text,
                translation="" if recovery_required else (cell.source_text if _cell_source_language(cell) == "en" and cell.source_text is not None else patch_cell.english),
                rowspan=cell.rowspan,
                colspan=cell.colspan,
                source_language=cell.source_language,
                source_english_spans=list(cell.source_english_spans),
                cell_state=cell.cell_state,
                is_merge_origin=cell.is_merge_origin,
                is_spanned=cell.is_spanned,
                is_blank=cell.is_blank,
                is_header=cell.is_header,
                evidence_region_ids=list(cell.evidence_region_ids),
                numeric_fact_ids=list(cell.numeric_fact_ids),
                unresolved=patch_cell.unresolved,
                unresolved_reason=unresolved_reason,
                provenance=provenance,
                provenance_evidence_ids=provenance_evidence_ids,
                commitment_status=patch_cell.commitment_status,
                speech_act=patch_cell.speech_act,
                hangul_retention=patch_cell.hangul_retention,
            ))
        tables.append(TableIR(table_id=source_table.table_id, bbox=list(source_table.bbox_px), row_count=source_table.row_count, column_count=source_table.column_count, headers=list(source_table.headers), header_rows=list(source_table.header_rows), header_columns=list(source_table.header_columns), unit=source_table.unit, source_notes=list(source_table.source_notes), cells=cells))
    numeric_facts = [NumericFact(**item) for item in evidence.numeric_facts if isinstance(item, dict)]
    relations = [VisualRelation(
        relation_id=str(item["relation_id"]),
        source_element_ids=list(item.get("source_element_ids", [])),
        relation_type=str(item.get("relation_type", "unknown")),
        direction=item.get("direction"),
        interpretation=item.get("interpretation"),
        chart_claim=dict(item["chart_claim"]) if isinstance(item.get("chart_claim"), dict) else None,
        evidence=list(item.get("evidence_ids", [])),
        provenance=str(item.get("provenance") or ProvenanceState.SUPPORTED_INTERPRETATION.value),
        unresolved_reason=item.get("unresolved_reason"),
        hangul_retention=dict(item["hangul_retention"]) if isinstance(item.get("hangul_retention"), dict) else None,
    ) for item in patch.visual_interpretations]
    claims: list[dict[str, Any]] = []
    for item in patch.executive_claims:
        claim = dict(item)
        claim["provenance"] = str(claim.get("provenance") or ProvenanceState.SUPPORTED_INTERPRETATION.value)
        claim["evidence_ids"] = list(claim.get("evidence_ids", []))
        claims.append(claim)
    coverage: list[CoverageEntry] = []
    for source_id in evidence.required_source_ids:
        status = CoverageStatus.TRANSLATED.value
        note = None
        if source_id in region_patches and region_patches[source_id].unresolved:
            status = "unresolved"
            source_region = next((region for region in evidence.regions if region.region_id == source_id), None)
            note = source_region.recovery_reason if source_region and source_region.recovery_status == "NEEDS_REVIEW" else region_patches[source_id].unresolved_reason
        else:
            if source_id in {item.get("element_id") for item in evidence.visual_elements} or source_id in {table.table_id for table in evidence.tables}:
                status = CoverageStatus.INTENTIONALLY_PRESERVED.value
            for table_patch in patch.tables:
                for cell_patch in table_patch.cells:
                    if cell_patch.cell_id == source_id and cell_patch.unresolved:
                        status = "unresolved"
                        source_cell = next((cell for table in evidence.tables for cell in table.cells if cell.cell_id == source_id), None)
                        recovery_region = next((region for region in evidence.regions if source_cell and region.region_id in source_cell.evidence_region_ids and region.recovery_status == "NEEDS_REVIEW"), None)
                        note = recovery_region.recovery_reason if recovery_region else cell_patch.unresolved_reason
        coverage.append(CoverageEntry(source_id=source_id, status=status, evidence_ids=[source_id], note=note))
    unresolved_items = []
    for item in patch.regions:
        if not item.unresolved:
            continue
        source = next(region for region in evidence.regions if region.region_id == item.region_id)
        recovery_required = source.evidence_state in RISKY_LITERAL_STATES or source.recovery_status == "NEEDS_REVIEW"
        if recovery_required:
            unresolved_items.append({
                "region_id": item.region_id,
                "provenance": ProvenanceState.UNRESOLVED.value,
                "evidence_ids": list(item.evidence_ids if item.evidence_ids is not None else (item.region_id,)),
                "reason": source.recovery_reason or "Required source text could not be recovered from the retained evidence.",
                "recovery_status": source.recovery_status,
                "impact": "Required source text and dependent numeric or decision claims remain unavailable.",
                "recommended_action": "Review the retained original crop and source document, resolve the extraction problem, then prepare a fresh run.",
                "location": {"document_id": evidence.document_id, "work_unit_id": evidence.work_unit_id, "bbox_px": list(source.bbox_px), "crop_original_path": source.crop_original_path, "crop_model_path": source.crop_model_path},
            })
        else:
            unresolved_items.append({"region_id": item.region_id, "provenance": ProvenanceState.UNRESOLVED.value, "evidence_ids": list(item.evidence_ids if item.evidence_ids is not None else (item.region_id,)), "reason": item.unresolved_reason or "Model marked unresolved."})
    for table in patch.tables:
        evidence_table = next(candidate for candidate in evidence.tables if candidate.table_id == table.table_id)
        for cell_patch in table.cells:
            if not cell_patch.unresolved:
                continue
            source_cell = next(cell for cell in evidence_table.cells if cell.cell_id == cell_patch.cell_id)
            if not _cell_literal_usable(source_cell, {region.region_id: region for region in evidence.regions}):
                recovery_region = next((region for region in evidence.regions if region.region_id in source_cell.evidence_region_ids and region.evidence_state in RISKY_LITERAL_STATES), None)
                unresolved_items.append({
                    "cell_id": cell_patch.cell_id,
                    "provenance": ProvenanceState.UNRESOLVED.value,
                    "evidence_ids": list(cell_patch.evidence_ids if cell_patch.evidence_ids is not None else (cell_patch.cell_id,)),
                    "reason": (recovery_region.recovery_reason if recovery_region else None) or "Required table-cell literal could not be recovered from the retained evidence.",
                    "recovery_status": "NEEDS_REVIEW",
                    "impact": "Required table content and dependent numeric or decision claims remain unavailable.",
                    "recommended_action": "Review the retained table crop and source document, resolve the extraction problem, then prepare a fresh run.",
                    "location": {"document_id": evidence.document_id, "work_unit_id": evidence.work_unit_id, "table_id": evidence_table.table_id, "cell_id": cell_patch.cell_id, "evidence_region_ids": list(source_cell.evidence_region_ids)},
                })
            else:
                unresolved_items.append({"cell_id": cell_patch.cell_id, "provenance": ProvenanceState.UNRESOLVED.value, "evidence_ids": list(cell_patch.evidence_ids if cell_patch.evidence_ids is not None else (cell_patch.cell_id,)), "reason": cell_patch.unresolved_reason or "Model marked unresolved."})
    unresolved_items += [
        {"relation_id": str(item["relation_id"]), "provenance": ProvenanceState.UNRESOLVED.value, "evidence_ids": list(item.get("evidence_ids", [])), "reason": item.get("unresolved_reason") or "Model marked unresolved."}
        for item in patch.visual_interpretations if item.get("provenance") == ProvenanceState.UNRESOLVED.value
    ] + [
        {"claim_id": str(item["claim_id"]), "provenance": ProvenanceState.UNRESOLVED.value, "evidence_ids": list(item.get("evidence_ids", [])), "reason": item.get("unresolved_reason") or "Model marked unresolved."}
        for item in patch.executive_claims if item.get("provenance") == ProvenanceState.UNRESOLVED.value
    ]
    return SlideIR(
        slide_id=evidence.work_unit_id,
        source={**evidence.source, "evidence_revision": evidence.evidence_revision},
        regions=regions,
        tables=tables,
        visual_elements=list(evidence.visual_elements),
        visual_relations=relations,
        numeric_facts=numeric_facts,
        native_evidence=list(evidence.native_evidence),
        unresolved=unresolved_items,
        coverage=coverage,
        executive_semantics={"executive_claims": claims, "translation_revision": translation_revision or patch.revision(), "model_runtime": runtime_metadata or {}},
        evidence_revision=evidence.evidence_revision,
        translation_revision=translation_revision or patch.revision(),
        model_runtime=runtime_metadata or {},
    )
