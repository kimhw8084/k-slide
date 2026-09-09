"""Versioned, serializable SlideIR primitives."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from . import SLIDE_IR_SCHEMA_VERSION


@dataclass
class TextRegion:
    region_id: str
    bbox: list[float] = field(default_factory=list)
    reading_order: int = 0
    region_type: str = "text"
    native_source_text: str | None = None
    ocr_candidates: list[dict[str, Any]] = field(default_factory=list)
    selected_source_text: str | None = None
    source_language: str | None = None
    source_confidence: float | None = None
    translation: str | None = None
    translation_confidence: float | None = None
    evidence_sources: list[str] = field(default_factory=list)
    term_matches: list[str] = field(default_factory=list)
    numeric_fact_ids: list[str] = field(default_factory=list)
    commitment_status: str | None = None
    speech_act: str | None = None
    unresolved_reason: str | None = None


@dataclass
class TableCell:
    row: int
    column: int
    source_text: str | None = None
    translation: str | None = None
    rowspan: int = 1
    colspan: int = 1
    evidence_region_ids: list[str] = field(default_factory=list)
    numeric_fact_ids: list[str] = field(default_factory=list)
    unresolved: bool = False


@dataclass
class TableIR:
    table_id: str
    bbox: list[float] = field(default_factory=list)
    row_count: int = 0
    column_count: int = 0
    headers: list[str] = field(default_factory=list)
    cells: list[TableCell] = field(default_factory=list)
    unresolved_reason: str | None = None


@dataclass
class NumericFact:
    fact_id: str
    source_region_id: str | None
    source_string: str
    source_object_id: str | None = None
    source_table_id: str | None = None
    source_cell_id: str | None = None
    raw_value: float | None = None
    canonical_value: float | None = None
    scale_factor: float | None = None
    source_unit: str | None = None
    semantic_quantity: str | None = None
    currency: str | None = None
    time_period: str | None = None
    direction: str | None = None
    approximation: str | None = None


@dataclass
class VisualRelation:
    relation_id: str
    source_element_ids: list[str] = field(default_factory=list)
    relation_type: str = "unknown"
    direction: str | None = None
    interpretation: str | None = None
    confidence: float | None = None
    evidence: list[str] = field(default_factory=list)


@dataclass
class CoverageEntry:
    source_id: str
    status: str
    severity: str = "INFO"
    evidence_ids: list[str] = field(default_factory=list)
    note: str | None = None


@dataclass
class SlideIR:
    slide_id: str
    source: dict[str, Any] = field(default_factory=dict)
    regions: list[TextRegion] = field(default_factory=list)
    tables: list[TableIR] = field(default_factory=list)
    visual_elements: list[dict[str, Any]] = field(default_factory=list)
    visual_relations: list[VisualRelation] = field(default_factory=list)
    numeric_facts: list[NumericFact] = field(default_factory=list)
    entities: list[dict[str, Any]] = field(default_factory=list)
    terms: list[dict[str, Any]] = field(default_factory=list)
    native_evidence: list[dict[str, Any]] = field(default_factory=list)
    unresolved: list[dict[str, Any]] = field(default_factory=list)
    coverage: list[CoverageEntry] = field(default_factory=list)
    executive_semantics: dict[str, Any] = field(default_factory=dict)
    evidence_revision: str | None = None
    translation_revision: str | None = None
    model_runtime: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["schema_version"] = SLIDE_IR_SCHEMA_VERSION
        return value

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "SlideIR":
        regions = [TextRegion(**item) for item in value.get("regions", [])]
        tables: list[TableIR] = []
        for item in value.get("tables", []):
            cells = [TableCell(**cell) for cell in item.get("cells", [])]
            tables.append(TableIR(**{**item, "cells": cells}))
        relations = [VisualRelation(**item) for item in value.get("visual_relations", [])]
        facts = [NumericFact(**item) for item in value.get("numeric_facts", [])]
        coverage = [CoverageEntry(**item) for item in value.get("coverage", [])]
        return cls(
            slide_id=str(value["slide_id"]),
            source=dict(value.get("source", {})),
            regions=regions,
            tables=tables,
            visual_elements=list(value.get("visual_elements", [])),
            visual_relations=relations,
            numeric_facts=facts,
            entities=list(value.get("entities", [])),
            terms=list(value.get("terms", [])),
            native_evidence=list(value.get("native_evidence", [])),
            unresolved=list(value.get("unresolved", [])),
            coverage=coverage,
            executive_semantics=dict(value.get("executive_semantics", {})),
            evidence_revision=value.get("evidence_revision") or value.get("source", {}).get("evidence_revision"),
            translation_revision=value.get("translation_revision"),
            model_runtime=dict(value.get("model_runtime", value.get("executive_semantics", {}).get("model_runtime", {}))),
        )
