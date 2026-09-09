"""Strict model-owned TranslationPatch and engine-controlled EvidenceIR merge."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any

from .errors import ErrorCode, KSlideError
from .evidence_ir import EvidenceIR, stable_revision
from .ir import CoverageEntry, NumericFact, SlideIR, TableCell, TableIR, TextRegion, VisualRelation
from .semantics import ClaimKind, CommitmentStatus, CoverageStatus, RelationDirection, RelationType, SpeechAct, Uncertainty, enum_value
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
_MODEL_RELATION_FIELDS = set(RELATION_OPTIONAL_FIELDS) | {"relation_id", "interpretation", "evidence_ids"}
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

    def as_dict(self) -> dict[str, Any]:
        value = {key: item for key, item in asdict(self).items() if item is not None}
        value["term_ids"] = list(self.term_ids)
        return value


@dataclass(frozen=True)
class TranslationCellPatch:
    cell_id: str
    english: str
    unresolved: bool = False
    unresolved_reason: str | None = None
    hangul_retention: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        return {key: item for key, item in asdict(self).items() if item is not None}


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
        region_map = {region.region_id: region for region in evidence.regions}
        table_map = {table.table_id: table for table in evidence.tables}
        valid_source_ids = (
            set(region_map)
            | set(table_map)
            | {cell.cell_id for table in evidence.tables for cell in table.cells}
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
            if not isinstance(patch.english, str) or not patch.english.strip():
                raise KSlideError(ErrorCode.SCHEMA_INVALID, "Every translated region needs non-empty English.", {"region_id": patch.region_id})
            if patch.unresolved and not patch.unresolved_reason:
                raise KSlideError(ErrorCode.SCHEMA_INVALID, "Unresolved regions require an explicit reason.", {"region_id": patch.region_id})
            if patch.commitment_status is not None:
                enum_value(patch.commitment_status, CommitmentStatus, "commitment_status")
            if patch.speech_act is not None:
                enum_value(patch.speech_act, SpeechAct, "speech_act")
            if patch.hangul_retention is not None and patch.hangul_retention.get("evidence_id") not in valid_source_ids:
                raise KSlideError(ErrorCode.UNKNOWN_SOURCE_ELEMENT, "Hangul retention references unknown evidence.", {"region_id": patch.region_id})
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
            seen_cells: set[str] = set()
            for cell_patch in table_patch.cells:
                if cell_patch.cell_id in seen_cells:
                    raise KSlideError(ErrorCode.SCHEMA_INVALID, "TranslationPatch contains duplicate table cells.", {"cell_id": cell_patch.cell_id})
                seen_cells.add(cell_patch.cell_id)
                if cell_patch.cell_id not in cells:
                    raise KSlideError(ErrorCode.UNKNOWN_TABLE_CELL, "TranslationPatch references an unknown table cell.", {"cell_id": cell_patch.cell_id})
                if not cell_patch.english.strip():
                    raise KSlideError(ErrorCode.SCHEMA_INVALID, "Every translated table cell needs non-empty English.", {"cell_id": cell_patch.cell_id})
                if cell_patch.unresolved and not cell_patch.unresolved_reason:
                    raise KSlideError(ErrorCode.SCHEMA_INVALID, "Unresolved table cells require an explicit reason.", {"cell_id": cell_patch.cell_id})
                if cell_patch.hangul_retention is not None and cell_patch.hangul_retention.get("evidence_id") not in valid_source_ids:
                    raise KSlideError(ErrorCode.UNKNOWN_SOURCE_ELEMENT, "Hangul retention references unknown evidence.", {"cell_id": cell_patch.cell_id})
            missing_cells = sorted(cell_id for cell_id, cell in cells.items() if cell.required_for_translation and cell_id not in seen_cells)
            if missing_cells:
                raise KSlideError(ErrorCode.EVIDENCE_INCOMPLETE, "TranslationPatch omitted required table cells.", {"cell_ids": missing_cells})
        required_tables = {table.table_id for table in evidence.tables if table.required_for_translation}
        if required_tables - seen_tables:
            raise KSlideError(ErrorCode.EVIDENCE_INCOMPLETE, "TranslationPatch omitted required tables.", {"table_ids": sorted(required_tables - seen_tables)})
        for relation in self.visual_interpretations:
            _only_fields(relation, _MODEL_RELATION_FIELDS, "visual interpretation")
            _id(relation.get("relation_id"), "relation_id")
            if not isinstance(relation.get("evidence_ids", []), list):
                raise KSlideError(ErrorCode.SCHEMA_INVALID, "Visual interpretation evidence_ids must be an array.")
            if not set(relation.get("evidence_ids", [])).issubset(set(evidence.required_source_ids)):
                raise KSlideError(ErrorCode.UNKNOWN_REGION, "Visual interpretation references unknown evidence.")
            source_element_ids = _string_list(relation.get("source_element_ids", []), "visual interpretation source_element_ids")
            unknown_elements = sorted(set(source_element_ids) - valid_source_ids)
            if unknown_elements:
                raise KSlideError(ErrorCode.UNKNOWN_SOURCE_ELEMENT, "Visual interpretation references unknown source elements.", {"source_element_ids": unknown_elements})
            if relation.get("relation_type") is not None:
                enum_value(relation.get("relation_type"), RelationType, "relation_type")
            if relation.get("direction") is not None:
                enum_value(relation.get("direction"), RelationDirection, "direction")
            retention = relation.get("hangul_retention")
            if retention is not None and (not isinstance(retention, dict) or retention.get("evidence_id") not in valid_source_ids):
                raise KSlideError(ErrorCode.UNKNOWN_SOURCE_ELEMENT, "Hangul retention references unknown evidence.")
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
            if not evidence_ids:
                raise KSlideError(ErrorCode.CLAIM_UNSUPPORTED, "Every executive claim must cite at least one evidence ID.", {"claim_id": claim_id})
            if not set(evidence_ids).issubset(set(evidence.required_source_ids)):
                raise KSlideError(ErrorCode.UNKNOWN_REGION, "Executive claim references unknown evidence.", {"claim_id": claim_id})
            retention = claim.get("hangul_retention")
            if retention is not None and (not isinstance(retention, dict) or retention.get("evidence_id") not in valid_source_ids):
                raise KSlideError(ErrorCode.UNKNOWN_SOURCE_ELEMENT, "Hangul retention references unknown evidence.", {"claim_id": claim_id})


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
            cells.append(TranslationCellPatch(cell_id=_id(cell.get("cell_id"), "cell_id"), english=english, unresolved=_boolean(cell.get("unresolved"), "unresolved"), unresolved_reason=_optional_present(cell, "unresolved_reason", "unresolved_reason"), hangul_retention=_hangul_retention(cell.get("hangul_retention"), "table cell hangul_retention")))
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
        if relation.get("relation_type") is not None:
            enum_value(relation.get("relation_type"), RelationType, "relation_type")
        if relation.get("direction") is not None:
            enum_value(relation.get("direction"), RelationDirection, "direction")
        _hangul_retention(relation.get("hangul_retention"), "visual interpretation hangul_retention")
    executive_claims = value.get("executive_claims", [])
    if not isinstance(executive_claims, list) or any(not isinstance(item, dict) for item in executive_claims):
        raise KSlideError(ErrorCode.SCHEMA_INVALID, "executive_claims must be an array of objects.")
    for claim in executive_claims:
        _require_fields(claim, {"claim_id", "kind", "text", "evidence_ids", "uncertainty"}, "executive claim")
        _only_fields(claim, _MODEL_CLAIM_FIELDS, "executive claim")
        _hangul_retention(claim.get("hangul_retention"), "executive claim hangul_retention")
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
        item = region_patches[source.region_id]
        regions.append(TextRegion(
            region_id=source.region_id,
            bbox=list(source.bbox_px),
            reading_order=source.reading_order,
            region_type=source.region_type,
            native_source_text=source.selected_literal_candidate,
            ocr_candidates=list(source.ocr_candidates),
            selected_source_text=source.selected_literal_candidate,
            source_language=source.language,
            source_confidence=source.literal_confidence,
            translation=item.english,
            evidence_sources=[source.region_id],
            term_matches=list(item.term_ids),
            numeric_fact_ids=list(source.numeric_fact_ids),
            commitment_status=item.commitment_status,
            speech_act=item.speech_act,
            unresolved_reason=item.unresolved_reason,
        ))
    tables: list[TableIR] = []
    for source_table in evidence.tables:
        table_patch = table_patches[source_table.table_id]
        cell_patches = {item.cell_id: item for item in table_patch.cells}
        cells = [TableCell(row=cell.row, column=cell.column, source_text=cell.source_text, translation=cell_patches[cell.cell_id].english, rowspan=cell.rowspan, colspan=cell.colspan, evidence_region_ids=list(cell.evidence_region_ids), numeric_fact_ids=list(cell.numeric_fact_ids), unresolved=cell_patches[cell.cell_id].unresolved) for cell in source_table.cells]
        tables.append(TableIR(table_id=source_table.table_id, bbox=list(source_table.bbox_px), row_count=source_table.row_count, column_count=source_table.column_count, headers=list(source_table.headers), cells=cells))
    numeric_facts = [NumericFact(**item) for item in evidence.numeric_facts if isinstance(item, dict)]
    relations = [VisualRelation(relation_id=str(item["relation_id"]), source_element_ids=list(item.get("source_element_ids", [])), relation_type=str(item.get("relation_type", "unknown")), direction=item.get("direction"), interpretation=item.get("interpretation"), evidence=list(item.get("evidence_ids", []))) for item in patch.visual_interpretations]
    coverage: list[CoverageEntry] = []
    for source_id in evidence.required_source_ids:
        status = CoverageStatus.TRANSLATED.value
        note = None
        if source_id in region_patches and region_patches[source_id].unresolved:
            status = "unresolved"
            note = region_patches[source_id].unresolved_reason
        else:
            if source_id in {item.get("element_id") for item in evidence.visual_elements} or source_id in {table.table_id for table in evidence.tables}:
                status = CoverageStatus.INTENTIONALLY_PRESERVED.value
            for table_patch in patch.tables:
                for cell_patch in table_patch.cells:
                    if cell_patch.cell_id == source_id and cell_patch.unresolved:
                        status = "unresolved"
                        note = cell_patch.unresolved_reason
        coverage.append(CoverageEntry(source_id=source_id, status=status, evidence_ids=[source_id], note=note))
    return SlideIR(
        slide_id=evidence.work_unit_id,
        source={**evidence.source, "evidence_revision": evidence.evidence_revision},
        regions=regions,
        tables=tables,
        visual_elements=list(evidence.visual_elements),
        visual_relations=relations,
        numeric_facts=numeric_facts,
        native_evidence=list(evidence.native_evidence),
        unresolved=[{"region_id": item.region_id, "reason": item.unresolved_reason or "Model marked unresolved."} for item in patch.regions if item.unresolved] + [{"cell_id": cell.cell_id, "reason": cell.unresolved_reason or "Model marked unresolved."} for table in patch.tables for cell in table.cells if cell.unresolved],
        coverage=coverage,
        executive_semantics={"executive_claims": list(patch.executive_claims), "translation_revision": translation_revision or patch.revision(), "model_runtime": runtime_metadata or {}},
        evidence_revision=evidence.evidence_revision,
        translation_revision=translation_revision or patch.revision(),
        model_runtime=runtime_metadata or {},
    )
