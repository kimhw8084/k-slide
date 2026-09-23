"""Engine-owned, immutable source evidence for one translation work unit."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any

from . import EVIDENCE_IR_SCHEMA_VERSION
from .errors import ErrorCode, KSlideError
from .io import atomic_write_json, read_json
from .modality import LANGUAGE_VALUES, classify_source_language
from .storage import StorageArtifact, storage_path, workspace_mutation_guard

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_TABLE_CELL_STATES = frozenset({"nonblank", "blank", "merge_origin", "merge_continuation", "unknown"})
RISKY_LITERAL_STATES = frozenset({"DISAGREEMENT", "LOW_CONFIDENCE", "NO_LITERAL_EVIDENCE"})
LITERAL_EVIDENCE_STATES = frozenset({"HIGH_AGREEMENT", "MEDIUM_AGREEMENT", "NATIVE_ONLY", "OCR_ONLY", "DISAGREEMENT", "LOW_CONFIDENCE", "NO_LITERAL_EVIDENCE", "HIGH_CONFIDENCE"})


def _identifier(value: str, label: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise KSlideError(ErrorCode.SCHEMA_INVALID, f"Unsafe {label} identifier.", {label: value})
    return value


def stable_revision(value: dict[str, Any], *, excluded: set[str] | None = None) -> str:
    payload = dict(value)
    for key in excluded or set():
        payload.pop(key, None)
    serialized = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()


@dataclass(frozen=True)
class EvidenceRegion:
    region_id: str
    bbox_px: tuple[int, int, int, int] = (0, 0, 0, 0)
    bbox_normalized: tuple[float, float, float, float] = (0.0, 0.0, 0.0, 0.0)
    reading_order: int = 0
    region_type: str = "UNKNOWN"
    native_text_candidates: tuple[dict[str, Any], ...] = ()
    ocr_candidates: tuple[dict[str, Any], ...] = ()
    selected_literal_candidate: str | None = None
    literal_confidence: float | None = None
    evidence_state: str | None = None
    language: str | None = None
    source_english_spans: tuple[str, ...] = ()
    crop_original_path: str | None = None
    crop_model_path: str | None = None
    numeric_fact_ids: tuple[str, ...] = ()
    table_id: str | None = None
    visual_element_ids: tuple[str, ...] = ()
    required_for_translation: bool = True
    translation_disposition: str = "REQUIRED"
    disposition_policy: str | None = None
    disposition_evidence_ids: tuple[str, ...] = ()
    recovery_status: str | None = None
    recovery_attempts: int = 0
    recovery_reason: str | None = None

    def __post_init__(self) -> None:
        # Direct in-memory EvidenceIR fixtures predating evidence-state fusion
        # contain an already selected engine literal but no candidate list.
        # Treat that as native-only for compatibility. Persisted records with
        # an omitted state are migrated conservatively in from_dict below.
        state = self.evidence_state
        if state is None:
            state = "NATIVE_ONLY" if self.selected_literal_candidate and not self.native_text_candidates and not self.ocr_candidates else ("NO_LITERAL_EVIDENCE" if not self.selected_literal_candidate else "NATIVE_ONLY")
            object.__setattr__(self, "evidence_state", state)
        if self.recovery_status is None:
            risky = state in RISKY_LITERAL_STATES
            object.__setattr__(self, "recovery_status", "NEEDS_REVIEW" if risky else "NOT_REQUIRED")
            if risky and not self.recovery_reason:
                object.__setattr__(self, "recovery_reason", "No trustworthy literal evidence is available after bounded engine recovery.")

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["bbox_px"] = list(self.bbox_px)
        value["bbox_normalized"] = list(self.bbox_normalized)
        value["native_text_candidates"] = list(self.native_text_candidates)
        value["ocr_candidates"] = list(self.ocr_candidates)
        value["numeric_fact_ids"] = list(self.numeric_fact_ids)
        value["visual_element_ids"] = list(self.visual_element_ids)
        value["source_english_spans"] = list(self.source_english_spans)
        value["disposition_evidence_ids"] = list(self.disposition_evidence_ids)
        return value

    def validate_recovery_contract(self) -> None:
        if self.evidence_state not in LITERAL_EVIDENCE_STATES:
            raise KSlideError(ErrorCode.SCHEMA_INVALID, "Evidence region has an unknown literal evidence state.", {"region_id": self.region_id})
        risky = self.evidence_state in RISKY_LITERAL_STATES
        if self.translation_disposition == "NOT_APPLICABLE_NATIVE_VISUAL":
            if self.required_for_translation or self.disposition_policy != "native-nontext-visual-v1" or self.disposition_evidence_ids != (self.region_id,):
                raise KSlideError(ErrorCode.SCHEMA_INVALID, "A not-applicable text disposition requires the closed engine visual-preservation policy and source binding.", {"region_id": self.region_id})
            if self.selected_literal_candidate is not None or self.recovery_status != "NOT_REQUIRED" or self.recovery_attempts != 0 or self.recovery_reason is not None:
                raise KSlideError(ErrorCode.SCHEMA_INVALID, "A native visual-preservation disposition cannot erase literal or recovery evidence.", {"region_id": self.region_id})
            return
        if self.translation_disposition != "REQUIRED" or not self.required_for_translation or self.disposition_policy is not None or self.disposition_evidence_ids:
            raise KSlideError(ErrorCode.SCHEMA_INVALID, "Evidence regions remain required; extraction cannot create a decorative or not-applicable exemption.", {"region_id": self.region_id})
        if not isinstance(self.recovery_attempts, int) or isinstance(self.recovery_attempts, bool) or self.recovery_attempts not in {0, 1}:
            raise KSlideError(ErrorCode.SCHEMA_INVALID, "Literal recovery is bounded to one engine crop re-extraction.", {"region_id": self.region_id})
        if risky:
            if self.recovery_status != "NEEDS_REVIEW" or not isinstance(self.recovery_reason, str) or not self.recovery_reason.strip():
                raise KSlideError(ErrorCode.SCHEMA_INVALID, "Risky literal evidence must remain in engine-owned NEEDS_REVIEW recovery state.", {"region_id": self.region_id})
            return
        if not isinstance(self.selected_literal_candidate, str) or not self.selected_literal_candidate.strip():
            raise KSlideError(ErrorCode.SCHEMA_INVALID, "Literal evidence without a selected source candidate cannot be semantically eligible.", {"region_id": self.region_id})
        if self.evidence_state == "OCR_ONLY" and (
            not isinstance(self.literal_confidence, (int, float))
            or isinstance(self.literal_confidence, bool)
            or not 0.80 <= self.literal_confidence <= 1.0
        ):
            raise KSlideError(ErrorCode.SCHEMA_INVALID, "OCR-only literal evidence must meet the engine confidence threshold.", {"region_id": self.region_id})
        if self.recovery_status == "NOT_REQUIRED":
            if self.recovery_attempts != 0 or self.recovery_reason is not None:
                raise KSlideError(ErrorCode.SCHEMA_INVALID, "A region without recovery must not claim recovery evidence.", {"region_id": self.region_id})
            return
        if self.recovery_status != "RECOVERED" or self.recovery_attempts != 1:
            raise KSlideError(ErrorCode.SCHEMA_INVALID, "A recovered literal must cite one durable engine crop re-extraction.", {"region_id": self.region_id})
        selected = self.selected_literal_candidate
        recovery_candidates = [
            item for item in self.ocr_candidates
            if isinstance(item, dict)
            and item.get("recovery_pass") == 1
            and item.get("text") == selected
            and item.get("trust_eligible", True) is not False
            and isinstance(item.get("crop_sha256"), str)
            and re.fullmatch(r"[a-f0-9]{64}", item["crop_sha256"])
            and isinstance(item.get("provider"), str)
            and item.get("provider")
        ]
        if not isinstance(selected, str) or not selected.strip() or not recovery_candidates:
            raise KSlideError(ErrorCode.SCHEMA_INVALID, "Recovered literal lacks its durable crop OCR candidate.", {"region_id": self.region_id})
        if not any(
            isinstance(item.get("confidence"), (int, float))
            and not isinstance(item.get("confidence"), bool)
            and 0.80 <= item["confidence"] <= 1.0
            for item in recovery_candidates
        ):
            raise KSlideError(ErrorCode.SCHEMA_INVALID, "Recovered literal lacks a high-confidence crop OCR confirmation.", {"region_id": self.region_id})


@dataclass(frozen=True)
class EvidenceTableCell:
    cell_id: str
    row: int
    column: int
    rowspan: int = 1
    colspan: int = 1
    source_text: str | None = None
    source_language: str | None = None
    source_english_spans: tuple[str, ...] = ()
    cell_state: str = "unknown"
    is_merge_origin: bool | None = None
    is_spanned: bool | None = None
    is_blank: bool | None = None
    is_header: bool | None = None
    evidence_region_ids: tuple[str, ...] = ()
    numeric_fact_ids: tuple[str, ...] = ()
    required_for_translation: bool = True

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["evidence_region_ids"] = list(self.evidence_region_ids)
        value["numeric_fact_ids"] = list(self.numeric_fact_ids)
        value["source_english_spans"] = list(self.source_english_spans)
        return value


@dataclass(frozen=True)
class EvidenceTable:
    table_id: str
    bbox_px: tuple[int, int, int, int] = (0, 0, 0, 0)
    row_count: int = 0
    column_count: int = 0
    headers: tuple[str, ...] = ()
    header_rows: tuple[int, ...] = ()
    header_columns: tuple[int, ...] = ()
    unit: str | None = None
    source_notes: tuple[str, ...] = ()
    cells: tuple[EvidenceTableCell, ...] = ()
    required_for_translation: bool = True

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["bbox_px"] = list(self.bbox_px)
        value["headers"] = list(self.headers)
        value["header_rows"] = list(self.header_rows)
        value["header_columns"] = list(self.header_columns)
        value["source_notes"] = list(self.source_notes)
        value["cells"] = [cell.as_dict() for cell in self.cells]
        return value


@dataclass(frozen=True)
class EvidenceIR:
    document_id: str
    work_unit_id: str
    source: dict[str, Any]
    regions: tuple[EvidenceRegion, ...] = ()
    tables: tuple[EvidenceTable, ...] = ()
    numeric_facts: tuple[dict[str, Any], ...] = ()
    visual_elements: tuple[dict[str, Any], ...] = ()
    native_evidence: tuple[dict[str, Any], ...] = ()
    required_source_ids: tuple[str, ...] = ()
    evidence_revision: str = ""

    def without_revision(self) -> dict[str, Any]:
        return {
            "schema_version": EVIDENCE_IR_SCHEMA_VERSION,
            "document_id": self.document_id,
            "work_unit_id": self.work_unit_id,
            "source": self.source,
            "regions": [region.as_dict() for region in self.regions],
            "tables": [table.as_dict() for table in self.tables],
            "numeric_facts": list(self.numeric_facts),
            "visual_elements": list(self.visual_elements),
            "native_evidence": list(self.native_evidence),
            "required_source_ids": list(self.required_source_ids),
        }

    def computed_revision(self) -> str:
        return stable_revision(self.without_revision())

    def as_dict(self) -> dict[str, Any]:
        value = self.without_revision()
        value["evidence_revision"] = self.evidence_revision or self.computed_revision()
        return value

    def validate(self) -> None:
        _identifier(self.document_id, "document_id")
        _identifier(self.work_unit_id, "work_unit_id")
        region_ids = [_identifier(region.region_id, "region_id") for region in self.regions]
        if len(region_ids) != len(set(region_ids)):
            raise KSlideError(ErrorCode.SCHEMA_INVALID, "EvidenceIR contains duplicate region IDs.")
        table_ids = [_identifier(table.table_id, "table_id") for table in self.tables]
        if len(table_ids) != len(set(table_ids)):
            raise KSlideError(ErrorCode.SCHEMA_INVALID, "EvidenceIR contains duplicate table IDs.")
        numeric_values = [str(item.get("fact_id")) for item in self.numeric_facts if isinstance(item, dict) and item.get("fact_id")]
        numeric_ids = set(numeric_values)
        if len(numeric_values) != len(numeric_ids):
            raise KSlideError(ErrorCode.DUPLICATE_SOURCE_ID, "EvidenceIR contains duplicate numeric fact IDs.")
        visual_ids = {str(item.get("element_id")) for item in self.visual_elements if isinstance(item, dict) and item.get("element_id")}
        if len(visual_ids) != sum(1 for item in self.visual_elements if isinstance(item, dict) and item.get("element_id")):
            raise KSlideError(ErrorCode.DUPLICATE_SOURCE_ID, "EvidenceIR contains duplicate visual element IDs.")
        known = set(region_ids) | set(table_ids) | numeric_ids | visual_ids
        language_policy_bound = self.source.get("source_language_policy") == "unicode-script-v1"
        for source_id in self.required_source_ids:
            _identifier(source_id, "required_source_id")
        for region in self.regions:
            region.validate_recovery_contract()
            if region.language is not None and region.language not in LANGUAGE_VALUES:
                raise KSlideError(ErrorCode.SCHEMA_INVALID, "Evidence region has an unsupported source language.", {"region_id": region.region_id, "language": region.language})
            if language_policy_bound and region.language is not None and region.selected_literal_candidate is not None:
                expected_language = classify_source_language(region.selected_literal_candidate)
                if region.language != expected_language:
                    raise KSlideError(ErrorCode.SCHEMA_INVALID, "Evidence region source language does not match deterministic script classification.", {"region_id": region.region_id, "expected": expected_language, "actual": region.language})
            if any(not isinstance(span, str) or not span for span in region.source_english_spans):
                raise KSlideError(ErrorCode.SCHEMA_INVALID, "Evidence region source-English spans must be non-empty strings.", {"region_id": region.region_id})
            if language_policy_bound and region.language != "mixed" and region.source_english_spans:
                raise KSlideError(ErrorCode.SCHEMA_INVALID, "Source-English spans are only valid for mixed-language evidence.", {"region_id": region.region_id})
            if region.language == "mixed" and region.selected_literal_candidate is not None:
                missing = [span for span in region.source_english_spans if span not in region.selected_literal_candidate]
                if missing:
                    raise KSlideError(ErrorCode.SCHEMA_INVALID, "Evidence region source-English spans are not present in its literal source.", {"region_id": region.region_id, "spans": missing})
            for fact_id in region.numeric_fact_ids:
                if fact_id not in numeric_ids:
                    raise KSlideError(ErrorCode.SCHEMA_INVALID, "Evidence region references an unknown numeric fact.", {"fact_id": fact_id})
            if region.table_id and region.table_id not in table_ids:
                raise KSlideError(ErrorCode.SCHEMA_INVALID, "Evidence region references an unknown table.", {"table_id": region.table_id})
            if region.translation_disposition == "NOT_APPLICABLE_NATIVE_VISUAL":
                if region.region_id not in self.required_source_ids:
                    raise KSlideError(ErrorCode.SCHEMA_INVALID, "Native visual-preservation disposition must remain accounted for in required source coverage.", {"region_id": region.region_id})
                native = next((item for item in self.native_evidence if isinstance(item, dict) and item.get("source_id") == region.region_id), None)
                matching_visuals = [item for item in self.visual_elements if isinstance(item, dict) and (item.get("element_id") == region.region_id or item.get("source_id") == region.region_id)]
                visual = next((item for item in matching_visuals if isinstance(item, dict) and item.get("kind") == "chart"), None) if isinstance(native, dict) and str(native.get("shape_type", "")).casefold() == "chart" else next((item for item in matching_visuals if isinstance(item, dict)), None)
                shape_type = str(native.get("shape_type", "")).casefold() if isinstance(native, dict) else ""
                if native is None or visual is None or str(native.get("text") or "").strip():
                    raise KSlideError(ErrorCode.SCHEMA_INVALID, "Not-applicable text disposition lacks an exact native non-text visual source.", {"region_id": region.region_id})
                represented = False
                if shape_type == "group":
                    children = [item for item in self.native_evidence if isinstance(item, dict) and str(item.get("source_id", "")).startswith(region.region_id + "-")]
                    represented = visual.get("kind") == "shape" and bool(children) and all(any(element.get("element_id") == child.get("source_id") for element in self.visual_elements if isinstance(element, dict)) for child in children)
                elif shape_type in {"line", "connector"}:
                    represented = visual.get("kind") == "connector" and isinstance(visual.get("connector"), dict)
                elif shape_type == "chart":
                    represented = visual.get("kind") == "chart" and isinstance(visual.get("chart"), dict) and visual.get("chart") == native.get("chart")
                elif shape_type == "table":
                    represented = visual.get("kind") == "shape" and any(table.table_id == f"{region.region_id}-table" for table in self.tables)
                if not represented:
                    raise KSlideError(ErrorCode.SCHEMA_INVALID, "Not-applicable text disposition is not fully preserved by a matching engine visual/table object.", {"region_id": region.region_id, "shape_type": shape_type})
        for table in self.tables:
            cell_ids = [_identifier(cell.cell_id, "cell_id") for cell in table.cells]
            if len(cell_ids) != len(set(cell_ids)):
                raise KSlideError(ErrorCode.SCHEMA_INVALID, "Evidence table contains duplicate cell IDs.", {"table_id": table.table_id})
            if table.row_count < 1 or table.column_count < 1:
                raise KSlideError(ErrorCode.SCHEMA_INVALID, "Evidence table dimensions must be positive.", {"table_id": table.table_id})
            if any(row < 0 or row >= table.row_count for row in table.header_rows) or any(column < 0 or column >= table.column_count for column in table.header_columns):
                raise KSlideError(ErrorCode.SCHEMA_INVALID, "Evidence table header coordinates are out of range.", {"table_id": table.table_id})
            if any(not isinstance(note, str) or not note.strip() for note in table.source_notes):
                raise KSlideError(ErrorCode.SCHEMA_INVALID, "Evidence table source notes must be non-empty strings.", {"table_id": table.table_id})
            for cell in table.cells:
                if cell.row < 0 or cell.column < 0 or cell.row >= table.row_count or cell.column >= table.column_count:
                    raise KSlideError(ErrorCode.SCHEMA_INVALID, "Evidence table cell is out of range.", {"cell_id": cell.cell_id})
                if cell.rowspan < 1 or cell.colspan < 1 or cell.row + cell.rowspan > table.row_count or cell.column + cell.colspan > table.column_count:
                    raise KSlideError(ErrorCode.SCHEMA_INVALID, "Evidence table cell span exceeds table dimensions.", {"cell_id": cell.cell_id})
                if cell.cell_state not in _TABLE_CELL_STATES:
                    raise KSlideError(ErrorCode.SCHEMA_INVALID, "Evidence table cell has an unsupported structural state.", {"cell_id": cell.cell_id, "cell_state": cell.cell_state})
                if cell.is_blank is True and cell.source_text not in (None, ""):
                    raise KSlideError(ErrorCode.SCHEMA_INVALID, "A blank EvidenceIR cell cannot contain source text.", {"cell_id": cell.cell_id})
                if cell.source_language is not None and cell.source_language not in LANGUAGE_VALUES:
                    raise KSlideError(ErrorCode.SCHEMA_INVALID, "Evidence table cell has an unsupported source language.", {"cell_id": cell.cell_id, "language": cell.source_language})
                if language_policy_bound and cell.source_language is not None and cell.source_text is not None:
                    expected_language = classify_source_language(cell.source_text)
                    if cell.source_language != expected_language:
                        raise KSlideError(ErrorCode.SCHEMA_INVALID, "Evidence table cell source language does not match deterministic script classification.", {"cell_id": cell.cell_id, "expected": expected_language, "actual": cell.source_language})
                if any(not isinstance(span, str) or not span for span in cell.source_english_spans):
                    raise KSlideError(ErrorCode.SCHEMA_INVALID, "Evidence table source-English spans must be non-empty strings.", {"cell_id": cell.cell_id})
                if language_policy_bound and cell.source_language != "mixed" and cell.source_english_spans:
                    raise KSlideError(ErrorCode.SCHEMA_INVALID, "Source-English spans are only valid for mixed-language table cells.", {"cell_id": cell.cell_id})
                if cell.source_language == "mixed" and cell.source_text is not None:
                    missing = [span for span in cell.source_english_spans if span not in cell.source_text]
                    if missing:
                        raise KSlideError(ErrorCode.SCHEMA_INVALID, "Evidence table source-English spans are not present in its literal source.", {"cell_id": cell.cell_id, "spans": missing})
                for fact_id in cell.numeric_fact_ids:
                    if fact_id not in numeric_ids:
                        raise KSlideError(ErrorCode.SCHEMA_INVALID, "Evidence cell references an unknown numeric fact.", {"fact_id": fact_id})
                for region_id in cell.evidence_region_ids:
                    if region_id not in region_ids:
                        raise KSlideError(ErrorCode.SCHEMA_INVALID, "Evidence cell references an unknown region.", {"region_id": region_id})
        for element in self.visual_elements:
            if not isinstance(element, dict) or not element.get("element_id"):
                raise KSlideError(ErrorCode.SCHEMA_INVALID, "Evidence visual elements require stable engine IDs.")
            kind = element.get("kind")
            if not isinstance(kind, str) or not kind:
                raise KSlideError(ErrorCode.SCHEMA_INVALID, "Evidence visual element requires a non-empty kind.", {"element_id": element.get("element_id")})
            bbox = element.get("bbox_px")
            if bbox is not None and (not isinstance(bbox, (list, tuple)) or len(bbox) != 4):
                raise KSlideError(ErrorCode.SCHEMA_INVALID, "Evidence visual element geometry must be a four-value bbox.", {"element_id": element.get("element_id")})
            if kind == "connector":
                connector = element.get("connector")
                if not isinstance(connector, dict) or connector.get("from_element_id") not in visual_ids or connector.get("to_element_id") not in visual_ids:
                    raise KSlideError(ErrorCode.SCHEMA_INVALID, "Evidence connector endpoints must cite current visual elements.", {"element_id": element.get("element_id")})
                direction_evidence = connector.get("direction_evidence")
                if direction_evidence is not None and direction_evidence not in {"start_to_end", "end_to_start", "bidirectional", "undirected", "ambiguous"}:
                    raise KSlideError(ErrorCode.SCHEMA_INVALID, "Evidence connector direction evidence is not a closed value.", {"element_id": element.get("element_id")})
                for arrow_key in ("start_arrow_type", "end_arrow_type"):
                    if arrow_key in connector and not isinstance(connector[arrow_key], str):
                        raise KSlideError(ErrorCode.SCHEMA_INVALID, "Evidence connector arrowhead properties must be strings.", {"element_id": element.get("element_id")})
            if kind == "chart":
                chart = element.get("chart")
                if not isinstance(chart, dict) or not isinstance(chart.get("chart_type"), str) or not isinstance(chart.get("categories", []), list) or not isinstance(chart.get("series", []), list):
                    raise KSlideError(ErrorCode.SCHEMA_INVALID, "Evidence chart structure is not typed and closed.", {"element_id": element.get("element_id")})
                series_names: list[str] = []
                for series_index, series in enumerate(chart["series"]):
                    if not isinstance(series, dict) or isinstance(series.get("series_index", series_index), bool) or series.get("series_index", series_index) != series_index or not isinstance(series.get("name", ""), str) or series.get("name", "") in series_names:
                        raise KSlideError(ErrorCode.SCHEMA_INVALID, "Evidence chart series is invalid.", {"element_id": element.get("element_id")})
                    series_names.append(series.get("name", ""))
                    points = series.get("points", [])
                    if not isinstance(points, list):
                        raise KSlideError(ErrorCode.SCHEMA_INVALID, "Evidence chart points must be an array.", {"element_id": element.get("element_id")})
                    if chart.get("categories") and points and len(points) != len(chart["categories"]):
                        raise KSlideError(ErrorCode.SCHEMA_INVALID, "Evidence chart point cardinality does not match category order.", {"element_id": element.get("element_id")})
                    for point_index, point in enumerate(points):
                        if not isinstance(point, dict) or isinstance(point.get("point_index", point_index), bool) or point.get("point_index", point_index) != point_index or not isinstance(point.get("is_blank"), bool) or (point.get("value") is not None and (not isinstance(point.get("value"), (int, float)) or isinstance(point.get("value"), bool))) or (point.get("value") is None) != point.get("is_blank"):
                            raise KSlideError(ErrorCode.SCHEMA_INVALID, "Evidence chart point order or value type is invalid.", {"element_id": element.get("element_id")})
                if "series_order" in chart and chart["series_order"] != [series.get("name", "") for series in chart["series"]]:
                    raise KSlideError(ErrorCode.SCHEMA_INVALID, "Evidence chart series order does not match typed series facts.", {"element_id": element.get("element_id")})
        if not set(self.required_source_ids).issubset(known | {cell.cell_id for table in self.tables for cell in table.cells}):
            raise KSlideError(ErrorCode.SCHEMA_INVALID, "EvidenceIR required source IDs contain unknown objects.")
        region_by_id = {region.region_id: region for region in self.regions}
        cell_by_id = {cell.cell_id: cell for table in self.tables for cell in table.cells}
        for fact in self.numeric_facts:
            if not isinstance(fact, dict):
                continue
            source_region_id = fact.get("source_region_id")
            source_cell_id = fact.get("source_cell_id")
            region = region_by_id.get(str(source_region_id)) if source_region_id else None
            cell = cell_by_id.get(str(source_cell_id)) if source_cell_id else None
            if (region and region.evidence_state in RISKY_LITERAL_STATES) or (cell and not isinstance(cell.source_text, str)):
                raise KSlideError(ErrorCode.SCHEMA_INVALID, "Numeric facts cannot be derived from unresolved or absent literal evidence.", {"fact_id": fact.get("fact_id")})
        expected = self.computed_revision()
        if self.evidence_revision and self.evidence_revision != expected:
            raise KSlideError(ErrorCode.STALE_EVIDENCE, "EvidenceIR revision does not match its immutable content.", {"expected": expected, "actual": self.evidence_revision})

    def with_revision(self) -> "EvidenceIR":
        self.validate()
        return EvidenceIR(
            document_id=self.document_id,
            work_unit_id=self.work_unit_id,
            source=self.source,
            regions=self.regions,
            tables=self.tables,
            numeric_facts=self.numeric_facts,
            visual_elements=self.visual_elements,
            native_evidence=self.native_evidence,
            required_source_ids=self.required_source_ids,
            evidence_revision=self.computed_revision(),
        )

    def validate_without_revision(self) -> None:
        self.validate()

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "EvidenceIR":
        if value.get("schema_version") != EVIDENCE_IR_SCHEMA_VERSION:
            raise KSlideError(ErrorCode.SCHEMA_INVALID, "Unsupported EvidenceIR schema version.")
        regions = tuple(
            EvidenceRegion(
                region_id=item["region_id"],
                bbox_px=tuple(item.get("bbox_px", (0, 0, 0, 0))),
                bbox_normalized=tuple(item.get("bbox_normalized", (0.0, 0.0, 0.0, 0.0))),
                reading_order=int(item.get("reading_order", 0)),
                region_type=str(item.get("region_type", "UNKNOWN")),
                native_text_candidates=tuple(item.get("native_text_candidates", [])),
                ocr_candidates=tuple(item.get("ocr_candidates", [])),
                selected_literal_candidate=item.get("selected_literal_candidate"),
                literal_confidence=item.get("literal_confidence"),
                evidence_state=str(item.get("evidence_state", "NO_LITERAL_EVIDENCE")),
                language=item.get("language"),
                source_english_spans=tuple(item.get("source_english_spans", [])),
                crop_original_path=item.get("crop_original_path"),
                crop_model_path=item.get("crop_model_path"),
                numeric_fact_ids=tuple(item.get("numeric_fact_ids", [])),
                table_id=item.get("table_id"),
                visual_element_ids=tuple(item.get("visual_element_ids", [])),
                required_for_translation=bool(item.get("required_for_translation", True)),
                translation_disposition=str(item.get("translation_disposition", "REQUIRED")),
                disposition_policy=item.get("disposition_policy"),
                disposition_evidence_ids=tuple(item.get("disposition_evidence_ids", [])),
                recovery_status=item.get("recovery_status"),
                recovery_attempts=item.get("recovery_attempts", 0),
                recovery_reason=item.get("recovery_reason"),
            )
            for item in value.get("regions", [])
        )
        tables = tuple(
            EvidenceTable(
                table_id=item["table_id"],
                bbox_px=tuple(item.get("bbox_px", (0, 0, 0, 0))),
                row_count=int(item.get("row_count", 0)),
                column_count=int(item.get("column_count", 0)),
                headers=tuple(item.get("headers", [])),
                header_rows=tuple(int(value) for value in item.get("header_rows", [])),
                header_columns=tuple(int(value) for value in item.get("header_columns", [])),
                unit=item.get("unit"),
                source_notes=tuple(item.get("source_notes", [])),
                cells=tuple(
                    EvidenceTableCell(
                        cell_id=cell["cell_id"],
                        row=int(cell["row"]),
                        column=int(cell["column"]),
                        rowspan=int(cell.get("rowspan", 1)),
                        colspan=int(cell.get("colspan", 1)),
                        source_text=cell.get("source_text"),
                        source_language=cell.get("source_language"),
                        source_english_spans=tuple(cell.get("source_english_spans", [])),
                        cell_state=str(cell.get("cell_state", "unknown")),
                        is_merge_origin=cell.get("is_merge_origin"),
                        is_spanned=cell.get("is_spanned"),
                        is_blank=cell.get("is_blank"),
                        is_header=cell.get("is_header"),
                        evidence_region_ids=tuple(cell.get("evidence_region_ids", [])),
                        numeric_fact_ids=tuple(cell.get("numeric_fact_ids", [])),
                        required_for_translation=bool(cell.get("required_for_translation", True)),
                    )
                    for cell in item.get("cells", [])
                ),
                required_for_translation=bool(item.get("required_for_translation", True)),
            )
            for item in value.get("tables", [])
        )
        result = cls(
            document_id=value["document_id"],
            work_unit_id=value["work_unit_id"],
            source=dict(value.get("source", {})),
            regions=regions,
            tables=tables,
            numeric_facts=tuple(value.get("numeric_facts", [])),
            visual_elements=tuple(value.get("visual_elements", [])),
            native_evidence=tuple(value.get("native_evidence", [])),
            required_source_ids=tuple(value.get("required_source_ids", [])),
            evidence_revision=str(value.get("evidence_revision", "")),
        )
        result.validate()
        return result


def evidence_path(run_dir: Any, work_unit_id: str) -> Any:
    return storage_path(run_dir, StorageArtifact.EVIDENCE_IR, f"evidence/{work_unit_id}.json")


def save_evidence(run_dir: Any, evidence: EvidenceIR) -> None:
    workspace_mutation_guard(run_dir)
    evidence.validate()
    atomic_write_json(evidence_path(run_dir, evidence.work_unit_id), evidence.as_dict(), mode=0o600)


def load_evidence(run_dir: Any, work_unit_id: str) -> EvidenceIR:
    value = read_json(evidence_path(run_dir, work_unit_id))
    if not isinstance(value, dict):
        raise KSlideError(ErrorCode.STATE_CORRUPT, "EvidenceIR must contain an object.")
    return EvidenceIR.from_dict(value)
