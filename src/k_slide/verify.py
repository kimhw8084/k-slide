"""Deterministic validation and completion ownership."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from . import SCHEMA_VERSION
from .errors import ErrorCode, KSlideError
from .io import atomic_write_json, atomic_write_text, read_json
from .ir import SlideIR
from .state import RunPhase, RunState, load_state, save_state


class Severity(str, Enum):
    INFO = "INFO"
    MINOR = "MINOR"
    MAJOR = "MAJOR"
    CRITICAL = "CRITICAL"


@dataclass
class VerificationIssue:
    code: str
    severity: Severity
    message: str
    target: str | None = None
    evidence_ids: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["severity"] = self.severity.value
        return value


@dataclass
class VerificationResult:
    status: str
    run_id: str
    issues: list[VerificationIssue] = field(default_factory=list)
    checked_slides: int = 0
    checked_regions: int = 0
    critical_count: int = 0
    unaccounted_count: int = 0

    @property
    def passed(self) -> bool:
        return self.status == "PASS" and self.critical_count == 0 and self.unaccounted_count == 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "status": self.status,
            "run_id": self.run_id,
            "issues": [issue.as_dict() for issue in self.issues],
            "checked_slides": self.checked_slides,
            "checked_regions": self.checked_regions,
            "critical_count": self.critical_count,
            "unaccounted_count": self.unaccounted_count,
        }


def _issue(result: VerificationResult, code: str, severity: Severity, message: str, *, target: str | None = None) -> None:
    result.issues.append(VerificationIssue(code, severity, message, target))
    if severity is Severity.CRITICAL:
        result.critical_count += 1


def _validate_slide(path: Path, result: VerificationResult) -> None:
    try:
        value = read_json(path)
        if not isinstance(value, dict) or value.get("schema_version") != SCHEMA_VERSION:
            _issue(result, "KSLIDE_SCHEMA_INVALID", Severity.CRITICAL, "SlideIR schema version is missing or unsupported.", target=path.name)
            return
        slide = SlideIR.from_dict(value)
        result.checked_slides += 1
        result.checked_regions += len(slide.regions)
        region_ids = [region.region_id for region in slide.regions]
        if len(region_ids) != len(set(region_ids)):
            _issue(result, "KSLIDE_DUPLICATE_REGION", Severity.CRITICAL, "SlideIR contains duplicate region IDs.", target=slide.slide_id)
        coverage_ids = {entry.source_id for entry in slide.coverage}
        for region_id in region_ids:
            if region_id not in coverage_ids:
                result.unaccounted_count += 1
                _issue(result, "KSLIDE_COVERAGE_GAP", Severity.CRITICAL, "A source region has no coverage ledger entry.", target=region_id)
        for table in slide.tables:
            if table.row_count < 1 or table.column_count < 1:
                _issue(result, "KSLIDE_TABLE_SHAPE_INVALID", Severity.CRITICAL, "Table dimensions must be positive.", target=table.table_id)
            for cell in table.cells:
                if cell.row < 0 or cell.column < 0 or cell.row >= table.row_count or cell.column >= table.column_count:
                    _issue(result, "KSLIDE_TABLE_CELL_OUT_OF_RANGE", Severity.CRITICAL, "Table cell is outside declared dimensions.", target=table.table_id)
        for item in slide.unresolved:
            if not item.get("reason") and not item.get("unresolved_reason"):
                _issue(result, "KSLIDE_UNRESOLVED_UNDISCLOSED", Severity.CRITICAL, "Unresolved evidence lacks a reason.", target=slide.slide_id)
    except (KSlideError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        _issue(result, "KSLIDE_SCHEMA_INVALID", Severity.CRITICAL, f"Could not validate SlideIR: {exc}", target=path.name)


def verify_run(run_dir: Path) -> VerificationResult:
    state = load_state(run_dir)
    result = VerificationResult(status="PASS", run_id=state.run_id)
    if state.phase in {RunPhase.TRANSLATED, RunPhase.REPAIRING}:
        state.transition(RunPhase.VERIFYING, next_action="Deterministic verification in progress")
        save_state(run_dir, state)
    elif state.phase not in {RunPhase.VERIFYING, RunPhase.VERIFIED}:
        _issue(result, "KSLIDE_PHASE_NOT_VERIFIABLE", Severity.CRITICAL, "Run is not in a translation/verification phase.", target=state.phase.value)
    ir_dir = run_dir / "ir"
    files = sorted(ir_dir.glob("*.json")) if ir_dir.is_dir() else []
    if not files:
        _issue(result, "KSLIDE_NO_CANONICAL_IR", Severity.CRITICAL, "No canonical SlideIR output exists yet.")
    for path in files:
        _validate_slide(path, result)
    if not (run_dir / "05_final_report.md").is_file():
        _issue(result, "KSLIDE_REPORT_MISSING", Severity.CRITICAL, "Source-faithful final report is missing.")
    if not (run_dir / "07_unresolved_items.md").is_file():
        _issue(result, "KSLIDE_REVIEW_ARTIFACT_MISSING", Severity.CRITICAL, "Unresolved-item disclosure is missing.")
    result.status = "PASS" if not result.issues else "FAIL"
    if state.phase == RunPhase.VERIFYING:
        state.transition(RunPhase.VERIFIED if result.passed else RunPhase.FAIL_REPAIRABLE, next_action=None if result.passed else "Repair exact verification targets")
        save_state(run_dir, state)
    atomic_write_json(run_dir / "verification" / "summary.json", result.as_dict(), mode=0o600)
    lines = ["# K-Slide Verification", "", f"Status: **{result.status}**", f"Run: `{state.run_id}`", ""]
    lines.append(f"Critical issues: {result.critical_count}")
    lines.append(f"Unaccounted source items: {result.unaccounted_count}")
    if result.issues:
        lines.extend(["", "## Issues"])
        lines.extend(f"- **{issue.severity.value}** `{issue.code}`: {issue.message}" + (f" (`{issue.target}`)" if issue.target else "") for issue in result.issues)
    lines.extend(["", "## Completion policy", "", "`RUN_COMPLETE.md` is created only by deterministic finalization after this verifier passes.", ""])
    atomic_write_text(run_dir / "06_verification.md", "\n".join(lines))
    return result


def finalize_run(run_dir: Path) -> VerificationResult:
    state = load_state(run_dir)
    result_path = run_dir / "verification" / "summary.json"
    if not result_path.is_file():
        result = verify_run(run_dir)
    else:
        value = read_json(result_path)
        issues = [VerificationIssue(item["code"], Severity(item["severity"]), item["message"], item.get("target"), item.get("evidence_ids", [])) for item in value.get("issues", [])]
        result = VerificationResult(value.get("status", "FAIL"), state.run_id, issues, int(value.get("checked_slides", 0)), int(value.get("checked_regions", 0)), int(value.get("critical_count", 0)), int(value.get("unaccounted_count", 0)))
    if state.phase != RunPhase.VERIFIED or not result.passed:
        raise KSlideError(ErrorCode.COMPLETION_BLOCKED, "K-Slide cannot finalize because deterministic verification has not passed.", {"phase": state.phase.value, "verification": result.as_dict()})
    atomic_write_text(run_dir / "RUN_COMPLETE.md", "# DONE\n\nK-Slide deterministic verification passed.\n")
    state.transition(RunPhase.COMPLETE, next_action=None)
    save_state(run_dir, state)
    return result


def validate_translation_payload(value: dict[str, Any]) -> None:
    if value.get("schema_version") != SCHEMA_VERSION:
        raise KSlideError(ErrorCode.SCHEMA_INVALID, "Translation payload has an unsupported schema version.")
    slide_id = value.get("slide_id")
    if not isinstance(slide_id, str) or not re.fullmatch(r"[A-Za-z0-9._-]+", slide_id):
        raise KSlideError(ErrorCode.SCHEMA_INVALID, "Translation payload has an unsafe slide ID.")
    regions = value.get("regions")
    if not isinstance(regions, list):
        raise KSlideError(ErrorCode.SCHEMA_INVALID, "Translation payload regions must be an array.")
    region_ids: list[str] = []
    for region in regions:
        if not isinstance(region, dict) or not isinstance(region.get("region_id"), str) or not isinstance(region.get("english"), str):
            raise KSlideError(ErrorCode.SCHEMA_INVALID, "Every translated region needs region_id and english.")
        region_ids.append(region["region_id"])
    if len(region_ids) != len(set(region_ids)):
        raise KSlideError(ErrorCode.SCHEMA_INVALID, "Translation payload contains duplicate region IDs.")
    for field_name in ("tables", "visual_relations", "numeric_facts", "coverage", "unresolved"):
        if not isinstance(value.get(field_name, []), list):
            raise KSlideError(ErrorCode.SCHEMA_INVALID, f"{field_name} must be an array.")
    for table in value.get("tables", []):
        if not isinstance(table, dict) or not isinstance(table.get("table_id"), str) or not isinstance(table.get("cells", []), list):
            raise KSlideError(ErrorCode.SCHEMA_INVALID, "Every table needs table_id and a cells array.")
        for cell in table["cells"]:
            if not isinstance(cell, dict):
                raise KSlideError(ErrorCode.SCHEMA_INVALID, "Every table cell must be an object.")


def canonicalize_translation_payload(value: dict[str, Any]) -> dict[str, Any]:
    """Convert the bounded Gemma response into canonical SlideIR."""

    validate_translation_payload(value)
    regions: list[dict[str, Any]] = []
    unresolved: list[dict[str, Any]] = list(value.get("unresolved", []))
    for region in value.get("regions", []):
        canonical = {
            "region_id": region["region_id"],
            "bbox": list(region.get("bbox", [])),
            "reading_order": int(region.get("reading_order", 0)),
            "region_type": str(region.get("region_type", "text")),
            "native_source_text": region.get("native_source_text"),
            "ocr_candidates": list(region.get("ocr_candidates", [])),
            "selected_source_text": region.get("selected_source_text"),
            "source_language": region.get("source_language"),
            "source_confidence": region.get("source_confidence"),
            "translation": region["english"],
            "translation_confidence": region.get("translation_confidence"),
            "evidence_sources": list(region.get("evidence_ids", [])),
            "term_matches": list(region.get("term_ids", [])),
            "numeric_fact_ids": list(region.get("numeric_fact_ids", [])),
            "commitment_status": region.get("commitment_status"),
            "speech_act": region.get("speech_act"),
            "unresolved_reason": region.get("unresolved_reason"),
        }
        regions.append(canonical)
        if region.get("unresolved"):
            unresolved.append({"region_id": region["region_id"], "reason": region.get("unresolved_reason") or "Model marked unresolved."})
    tables: list[dict[str, Any]] = []
    for table in value.get("tables", []):
        cells = []
        for cell in table.get("cells", []):
            cells.append({
                "row": int(cell.get("row", 0)),
                "column": int(cell.get("column", 0)),
                "source_text": cell.get("source_text"),
                "translation": cell.get("english", cell.get("translation")),
                "rowspan": int(cell.get("rowspan", 1)),
                "colspan": int(cell.get("colspan", 1)),
                "evidence_region_ids": list(cell.get("evidence_ids", cell.get("evidence_region_ids", []))),
                "numeric_fact_ids": list(cell.get("numeric_fact_ids", [])),
                "unresolved": bool(cell.get("unresolved", False)),
            })
        tables.append({
            "table_id": str(table["table_id"]),
            "bbox": list(table.get("bbox", [])),
            "row_count": int(table.get("row_count", 0)),
            "column_count": int(table.get("column_count", 0)),
            "headers": list(table.get("headers", [])),
            "cells": cells,
            "unresolved_reason": table.get("unresolved_reason"),
        })
    return {
        "schema_version": SCHEMA_VERSION,
        "slide_id": value["slide_id"],
        "source": dict(value.get("source", {})),
        "regions": regions,
        "tables": tables,
        "visual_elements": list(value.get("visual_elements", [])),
        "visual_relations": list(value.get("visual_relations", [])),
        "numeric_facts": list(value.get("numeric_facts", [])),
        "entities": list(value.get("entities", [])),
        "terms": list(value.get("terms", [])),
        "unresolved": unresolved,
        "coverage": list(value.get("coverage", [])),
        "executive_semantics": dict(value.get("slide_takeaway", value.get("executive_semantics", {}))),
    }
