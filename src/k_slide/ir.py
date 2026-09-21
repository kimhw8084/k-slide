"""Versioned, serializable SlideIR primitives."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from . import SLIDE_IR_SCHEMA_VERSION
from .errors import ErrorCode, KSlideError
from .semantics import ProvenanceState


def _migrate_unresolved_items(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    result: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        migrated = dict(item)
        source_id = migrated.get("region_id") or migrated.get("cell_id") or migrated.get("relation_id") or migrated.get("claim_id")
        migrated.setdefault("provenance", ProvenanceState.UNRESOLVED.value)
        migrated.setdefault("evidence_ids", list(migrated.get("provenance_evidence_ids") or ([source_id] if source_id else [])))
        migrated.setdefault("reason", migrated.get("unresolved_reason") or "Legacy unresolved item.")
        result.append(migrated)
    return result


def _migrate_executive_semantics(value: Any, unresolved: dict[str, dict[str, Any]]) -> dict[str, Any]:
    result = dict(value) if isinstance(value, dict) else {}
    claims: list[dict[str, Any]] = []
    for item in result.get("executive_claims", []):
        if not isinstance(item, dict):
            continue
        claim = dict(item)
        claim_id = str(claim.get("claim_id", ""))
        legacy = unresolved.get(claim_id)
        claim.setdefault("provenance", ProvenanceState.UNRESOLVED.value if legacy else ProvenanceState.SUPPORTED_INTERPRETATION.value)
        claim.setdefault("evidence_ids", list(claim.get("provenance_evidence_ids") or ([claim_id] if claim_id else [])))
        if claim["provenance"] == ProvenanceState.UNRESOLVED.value:
            claim.setdefault("unresolved_reason", (legacy or {}).get("reason") or "Legacy unresolved item.")
        claims.append(claim)
    result["executive_claims"] = claims
    return result


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
    provenance: str | None = None
    provenance_evidence_ids: list[str] = field(default_factory=list)
    term_matches: list[str] = field(default_factory=list)
    numeric_fact_ids: list[str] = field(default_factory=list)
    commitment_status: str | None = None
    speech_act: str | None = None
    unresolved_reason: str | None = None


@dataclass
class TableCell:
    cell_id: str
    row: int
    column: int
    source_text: str | None = None
    translation: str | None = None
    rowspan: int = 1
    colspan: int = 1
    evidence_region_ids: list[str] = field(default_factory=list)
    numeric_fact_ids: list[str] = field(default_factory=list)
    unresolved: bool = False
    unresolved_reason: str | None = None
    provenance: str | None = None
    provenance_evidence_ids: list[str] = field(default_factory=list)


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
    provenance: str | None = None
    unresolved_reason: str | None = None


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
    def from_dict(cls, value: dict[str, Any], evidence: Any | None = None) -> "SlideIR":
        if not isinstance(value, dict):
            raise KSlideError(ErrorCode.SCHEMA_INVALID, "SlideIR must be an object.")

        def legacy_cell_id(table_value: dict[str, Any], cell_value: dict[str, Any], evidence: Any | None) -> str:
            table_id = table_value.get("table_id")
            if evidence is None:
                raise KSlideError(
                    ErrorCode.LEGACY_TABLE_CELL_MIGRATION_REQUIRED,
                    "Legacy SlideIR table cells without cell_id require the bound EvidenceIR for migration.",
                    {"table_id": table_id},
                )
            evidence_tables = [table for table in getattr(evidence, "tables", ()) if table.table_id == table_id]
            if len(evidence_tables) != 1:
                raise KSlideError(
                    ErrorCode.LEGACY_TABLE_CELL_MIGRATION_REQUIRED,
                    "Legacy SlideIR table cell cannot be bound to exactly one current EvidenceIR table.",
                    {"table_id": table_id},
                )
            required = ("row", "column")
            if any(key not in cell_value or isinstance(cell_value.get(key), bool) or not isinstance(cell_value.get(key), int) for key in required):
                raise KSlideError(
                    ErrorCode.LEGACY_TABLE_CELL_MIGRATION_REQUIRED,
                    "Legacy SlideIR table cell lacks deterministic structural coordinates.",
                    {"table_id": table_id},
                )

            def same(field: str, candidate: Any) -> bool:
                if field not in cell_value:
                    return True
                expected = cell_value[field]
                actual = getattr(candidate, field)
                if field in {"evidence_region_ids", "numeric_fact_ids"}:
                    try:
                        return tuple(expected) == tuple(actual)
                    except TypeError:
                        return False
                return expected == actual

            candidates = [
                candidate
                for candidate in evidence_tables[0].cells
                if all(same(field, candidate) for field in ("row", "column", "rowspan", "colspan", "source_text", "evidence_region_ids", "numeric_fact_ids"))
            ]
            identity_hints = cell_value.get("provenance_evidence_ids") or cell_value.get("evidence_ids") or []
            if identity_hints:
                try:
                    candidates = [candidate for candidate in candidates if candidate.cell_id in set(identity_hints)]
                except TypeError:
                    candidates = []
            if len(candidates) != 1:
                raise KSlideError(
                    ErrorCode.LEGACY_TABLE_CELL_MIGRATION_REQUIRED,
                    "Legacy SlideIR table cell does not resolve to exactly one current EvidenceIR cell.",
                    {"table_id": table_id, "row": cell_value.get("row"), "column": cell_value.get("column")},
                )
            return candidates[0].cell_id

        legacy_unresolved = {
            str(item.get("region_id") or item.get("cell_id") or item.get("relation_id") or item.get("claim_id")): item
            for item in value.get("unresolved", [])
            if isinstance(item, dict) and (item.get("region_id") or item.get("cell_id") or item.get("relation_id") or item.get("claim_id"))
        }

        def region_value(item: dict[str, Any]) -> dict[str, Any]:
            region_id = str(item["region_id"])
            unresolved = legacy_unresolved.get(region_id)
            provenance = item.get("provenance")
            is_unresolved = bool(item.get("unresolved")) or bool(item.get("unresolved_reason")) or bool(unresolved)
            if provenance is None:
                provenance = ProvenanceState.UNRESOLVED.value if is_unresolved else ProvenanceState.SUPPORTED_INTERPRETATION.value
            if "provenance_evidence_ids" in item:
                evidence_ids = item["provenance_evidence_ids"]
            elif "evidence_ids" in item:
                evidence_ids = item["evidence_ids"]
            else:
                evidence_ids = item.get("evidence_sources") or [region_id]
            result = dict(item)
            result.pop("unresolved", None)
            result.pop("evidence_ids", None)
            result["provenance"] = provenance
            result["provenance_evidence_ids"] = list(evidence_ids)
            if provenance == ProvenanceState.UNRESOLVED.value and not result.get("unresolved_reason"):
                result["unresolved_reason"] = (unresolved or {}).get("reason") or (unresolved or {}).get("unresolved_reason") or "Legacy unresolved item."
            return result

        def cell_value(table_item: dict[str, Any], item: dict[str, Any]) -> dict[str, Any]:
            if not isinstance(item, dict):
                raise KSlideError(ErrorCode.SCHEMA_INVALID, "SlideIR table cell must be an object.")
            result = dict(item)
            if "cell_id" not in result or result.get("cell_id") is None:
                result["cell_id"] = legacy_cell_id(table_item, result, evidence)
            elif not isinstance(result["cell_id"], str) or not result["cell_id"]:
                raise KSlideError(ErrorCode.SCHEMA_INVALID, "SlideIR table cell_id must be a non-empty string.")
            cell_id = result["cell_id"]
            unresolved = legacy_unresolved.get(cell_id)
            provenance = result.get("provenance")
            is_unresolved = bool(result.get("unresolved")) or bool(unresolved)
            if provenance is None:
                provenance = ProvenanceState.UNRESOLVED.value if is_unresolved else ProvenanceState.SUPPORTED_INTERPRETATION.value
            if "provenance_evidence_ids" in result:
                evidence_ids = result["provenance_evidence_ids"]
            elif "evidence_ids" in result:
                evidence_ids = result["evidence_ids"]
            else:
                evidence_ids = [cell_id]
            result.pop("evidence_ids", None)
            result["provenance"] = provenance
            result["provenance_evidence_ids"] = list(evidence_ids)
            if provenance == ProvenanceState.UNRESOLVED.value and not result.get("unresolved_reason"):
                result["unresolved_reason"] = (unresolved or {}).get("reason") or (unresolved or {}).get("unresolved_reason") or "Legacy unresolved item."
            return result

        def relation_value(item: dict[str, Any]) -> dict[str, Any]:
            relation_id = str(item["relation_id"])
            unresolved = legacy_unresolved.get(relation_id)
            result = dict(item)
            result.setdefault("provenance", ProvenanceState.UNRESOLVED.value if unresolved else ProvenanceState.SUPPORTED_INTERPRETATION.value)
            result.setdefault("evidence", list(item.get("evidence", [])))
            if result["provenance"] == ProvenanceState.UNRESOLVED.value:
                result.setdefault("unresolved_reason", (unresolved or {}).get("reason") or "Legacy unresolved item.")
            return result

        regions = [TextRegion(**region_value(item)) for item in value.get("regions", [])]
        tables: list[TableIR] = []
        for item in value.get("tables", []):
            if not isinstance(item, dict):
                raise KSlideError(ErrorCode.SCHEMA_INVALID, "SlideIR table must be an object.")
            cells = [TableCell(**cell_value(item, cell)) for cell in item.get("cells", [])]
            tables.append(TableIR(**{**item, "cells": cells}))
        relations = [VisualRelation(**relation_value(item)) for item in value.get("visual_relations", [])]
        facts = [NumericFact(**item) for item in value.get("numeric_facts", [])]
        coverage = [CoverageEntry(**item) for item in value.get("coverage", [])]
        migrated_unresolved = _migrate_unresolved_items(value.get("unresolved", []))
        unresolved_ids = {
            str(item.get("region_id") or item.get("cell_id") or item.get("relation_id") or item.get("claim_id"))
            for item in migrated_unresolved
        }
        for region in regions:
            if region.provenance == ProvenanceState.UNRESOLVED.value and region.region_id not in unresolved_ids:
                migrated_unresolved.append({"region_id": region.region_id, "provenance": ProvenanceState.UNRESOLVED.value, "evidence_ids": list(region.provenance_evidence_ids), "reason": region.unresolved_reason or "Legacy unresolved item."})
                unresolved_ids.add(region.region_id)
        for table in tables:
            for cell in table.cells:
                if cell.provenance == ProvenanceState.UNRESOLVED.value and cell.cell_id not in unresolved_ids:
                    migrated_unresolved.append({"cell_id": cell.cell_id, "provenance": ProvenanceState.UNRESOLVED.value, "evidence_ids": list(cell.provenance_evidence_ids), "reason": cell.unresolved_reason or "Legacy unresolved item."})
                    unresolved_ids.add(cell.cell_id)
        for relation in relations:
            if relation.provenance == ProvenanceState.UNRESOLVED.value and relation.relation_id not in unresolved_ids:
                migrated_unresolved.append({"relation_id": relation.relation_id, "provenance": ProvenanceState.UNRESOLVED.value, "evidence_ids": list(relation.evidence), "reason": relation.unresolved_reason or "Legacy unresolved item."})
                unresolved_ids.add(relation.relation_id)
        migrated_semantics = _migrate_executive_semantics(value.get("executive_semantics", {}), legacy_unresolved)
        for claim in migrated_semantics.get("executive_claims", []):
            claim_id = str(claim.get("claim_id", ""))
            if claim.get("provenance") == ProvenanceState.UNRESOLVED.value and claim_id and claim_id not in unresolved_ids:
                migrated_unresolved.append({"claim_id": claim_id, "provenance": ProvenanceState.UNRESOLVED.value, "evidence_ids": list(claim.get("evidence_ids", [])), "reason": claim.get("unresolved_reason") or "Legacy unresolved item."})
                unresolved_ids.add(claim_id)
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
            unresolved=migrated_unresolved,
            coverage=coverage,
            executive_semantics=migrated_semantics,
            evidence_revision=value.get("evidence_revision") or value.get("source", {}).get("evidence_revision"),
            translation_revision=value.get("translation_revision"),
            model_runtime=dict(value.get("model_runtime", value.get("executive_semantics", {}).get("model_runtime", {}))),
        )
