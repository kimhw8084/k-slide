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

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


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
    evidence_state: str = "NO_LITERAL_EVIDENCE"
    language: str | None = None
    crop_original_path: str | None = None
    crop_model_path: str | None = None
    numeric_fact_ids: tuple[str, ...] = ()
    table_id: str | None = None
    visual_element_ids: tuple[str, ...] = ()
    required_for_translation: bool = True

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["bbox_px"] = list(self.bbox_px)
        value["bbox_normalized"] = list(self.bbox_normalized)
        value["native_text_candidates"] = list(self.native_text_candidates)
        value["ocr_candidates"] = list(self.ocr_candidates)
        value["numeric_fact_ids"] = list(self.numeric_fact_ids)
        value["visual_element_ids"] = list(self.visual_element_ids)
        return value


@dataclass(frozen=True)
class EvidenceTableCell:
    cell_id: str
    row: int
    column: int
    rowspan: int = 1
    colspan: int = 1
    source_text: str | None = None
    evidence_region_ids: tuple[str, ...] = ()
    numeric_fact_ids: tuple[str, ...] = ()
    required_for_translation: bool = True

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["evidence_region_ids"] = list(self.evidence_region_ids)
        value["numeric_fact_ids"] = list(self.numeric_fact_ids)
        return value


@dataclass(frozen=True)
class EvidenceTable:
    table_id: str
    bbox_px: tuple[int, int, int, int] = (0, 0, 0, 0)
    row_count: int = 0
    column_count: int = 0
    headers: tuple[str, ...] = ()
    cells: tuple[EvidenceTableCell, ...] = ()
    required_for_translation: bool = True

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["bbox_px"] = list(self.bbox_px)
        value["headers"] = list(self.headers)
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
        known = set(region_ids) | set(table_ids) | numeric_ids | visual_ids
        for source_id in self.required_source_ids:
            _identifier(source_id, "required_source_id")
        for region in self.regions:
            for fact_id in region.numeric_fact_ids:
                if fact_id not in numeric_ids:
                    raise KSlideError(ErrorCode.SCHEMA_INVALID, "Evidence region references an unknown numeric fact.", {"fact_id": fact_id})
            if region.table_id and region.table_id not in table_ids:
                raise KSlideError(ErrorCode.SCHEMA_INVALID, "Evidence region references an unknown table.", {"table_id": region.table_id})
        for table in self.tables:
            cell_ids = [_identifier(cell.cell_id, "cell_id") for cell in table.cells]
            if len(cell_ids) != len(set(cell_ids)):
                raise KSlideError(ErrorCode.SCHEMA_INVALID, "Evidence table contains duplicate cell IDs.", {"table_id": table.table_id})
            if table.row_count < 1 or table.column_count < 1:
                raise KSlideError(ErrorCode.SCHEMA_INVALID, "Evidence table dimensions must be positive.", {"table_id": table.table_id})
            for cell in table.cells:
                if cell.row < 0 or cell.column < 0 or cell.row >= table.row_count or cell.column >= table.column_count:
                    raise KSlideError(ErrorCode.SCHEMA_INVALID, "Evidence table cell is out of range.", {"cell_id": cell.cell_id})
                for fact_id in cell.numeric_fact_ids:
                    if fact_id not in numeric_ids:
                        raise KSlideError(ErrorCode.SCHEMA_INVALID, "Evidence cell references an unknown numeric fact.", {"fact_id": fact_id})
                for region_id in cell.evidence_region_ids:
                    if region_id not in region_ids:
                        raise KSlideError(ErrorCode.SCHEMA_INVALID, "Evidence cell references an unknown region.", {"region_id": region_id})
        if not set(self.required_source_ids).issubset(known | {cell.cell_id for table in self.tables for cell in table.cells}):
            raise KSlideError(ErrorCode.SCHEMA_INVALID, "EvidenceIR required source IDs contain unknown objects.")
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
                crop_original_path=item.get("crop_original_path"),
                crop_model_path=item.get("crop_model_path"),
                numeric_fact_ids=tuple(item.get("numeric_fact_ids", [])),
                table_id=item.get("table_id"),
                visual_element_ids=tuple(item.get("visual_element_ids", [])),
                required_for_translation=bool(item.get("required_for_translation", True)),
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
                cells=tuple(
                    EvidenceTableCell(
                        cell_id=cell["cell_id"],
                        row=int(cell["row"]),
                        column=int(cell["column"]),
                        rowspan=int(cell.get("rowspan", 1)),
                        colspan=int(cell.get("colspan", 1)),
                        source_text=cell.get("source_text"),
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
    return run_dir / "evidence" / f"{work_unit_id}.json"


def save_evidence(run_dir: Any, evidence: EvidenceIR) -> None:
    evidence.validate()
    atomic_write_json(evidence_path(run_dir, evidence.work_unit_id), evidence.as_dict(), mode=0o600)


def load_evidence(run_dir: Any, work_unit_id: str) -> EvidenceIR:
    value = read_json(evidence_path(run_dir, work_unit_id))
    if not isinstance(value, dict):
        raise KSlideError(ErrorCode.STATE_CORRUPT, "EvidenceIR must contain an object.")
    return EvidenceIR.from_dict(value)
