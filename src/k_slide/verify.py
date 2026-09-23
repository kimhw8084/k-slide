"""Deterministic validation, stale-state detection, and completion ownership."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from . import VERIFICATION_SCHEMA_VERSION
from .completion import ensure_completion_artifacts
from .conflicts import (
    ConflictResolutionState,
    conflict_authority_policy,
    conflict_assessment_status,
    conflict_contract_required,
    configured_authority_ids,
    conflict_registry_path,
    load_conflict_registry,
)
from .environment import RunEnvironmentIdentity, resolve_run_termbase
from .errors import ErrorCode, KSlideError
from .evidence_ir import RISKY_LITERAL_STATES, load_evidence
from .io import atomic_write_json, atomic_write_text, read_json
from .ir import SlideIR
from .locking import run_lock
from .numeric import numeric_fact_matches
from .policy import COMPLETION_POLICY
from .queue import WorkQueue, WorkUnitStatus, load_queue, save_queue
from .rendering import render_run
from .security import sha256_file
from .semantics import CommitmentStatus, ProvenanceState, SpeechAct, enum_value
from .state import RunPhase, load_state, save_state
from .storage import StorageArtifact, storage_path, workspace_mutation_guard
from .terminology import Termbase, load_effective_termbase
from .modality import classify_source_language, decision_bearing_status, english_modality_mismatch, executive_modality_mismatch, modality_mismatch, required_english_mismatch
from .translation import _cell_literal_usable, _chart_elements, _executive_source_texts, _semantic_evidence_usable, _source_evidence_texts, _source_fact_connector_relation, _validate_chart_interpretation


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
    scope: str = "WORK_UNIT_TRANSLATION_FAILURE"

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
    checked_work_units: int = 0
    critical_count: int = 0
    unaccounted_count: int = 0
    queue_revision: str | None = None
    unit_status: dict[str, str] = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        return self.status == "PASS" and self.critical_count == 0 and self.unaccounted_count == 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": VERIFICATION_SCHEMA_VERSION,
            "status": self.status,
            "run_id": self.run_id,
            "issues": [issue.as_dict() for issue in self.issues],
            "checked_slides": self.checked_slides,
            "checked_regions": self.checked_regions,
            "checked_work_units": self.checked_work_units,
            "critical_count": self.critical_count,
            "unaccounted_count": self.unaccounted_count,
            "queue_revision": self.queue_revision,
            "unit_status": dict(sorted(self.unit_status.items())),
        }


def _issue(result: VerificationResult, code: str, severity: Severity, message: str, *, target: str | None = None, evidence_ids: list[str] | None = None, scope: str = "WORK_UNIT_TRANSLATION_FAILURE") -> None:
    result.issues.append(VerificationIssue(code, severity, message, target, evidence_ids or [], scope))
    if severity is Severity.CRITICAL:
        result.critical_count += 1


def _evidence_ids(evidence: Any) -> set[str]:
    return (
        {region.region_id for region in evidence.regions}
        | {table.table_id for table in evidence.tables}
        | {cell.cell_id for table in evidence.tables for cell in table.cells}
        | {str(item.get("fact_id")) for item in evidence.numeric_facts if isinstance(item, dict) and item.get("fact_id")}
        | {str(item.get("element_id")) for item in evidence.visual_elements if isinstance(item, dict) and item.get("element_id")}
    )


def _check_table_cell_binding(result: VerificationResult, table: Any, cell: Any, evidence: Any, *, target: str) -> None:
    evidence_table = next((candidate for candidate in evidence.tables if candidate.table_id == table.table_id), None)
    if evidence_table is None:
        _issue(result, "KSLIDE_TABLE_CELL_ID_MISMATCH", Severity.CRITICAL, "Canonical table is not present in the current EvidenceIR.", target=target)
        return
    evidence_cell = next((candidate for candidate in evidence_table.cells if candidate.cell_id == cell.cell_id), None)
    if evidence_cell is None:
        _issue(result, "KSLIDE_TABLE_CELL_ID_MISMATCH", Severity.CRITICAL, "Canonical table cell_id is not the exact current EvidenceIR cell identity.", target=target, evidence_ids=[cell.cell_id])
        return
    for field in ("row", "column", "rowspan", "colspan", "source_text", "source_language", "source_english_spans", "cell_state", "is_merge_origin", "is_spanned", "is_blank", "is_header", "evidence_region_ids", "numeric_fact_ids"):
        actual = getattr(cell, field)
        expected = getattr(evidence_cell, field)
        if field in {"evidence_region_ids", "numeric_fact_ids", "source_english_spans"}:
            actual = tuple(actual)
            expected = tuple(expected)
        if actual != expected:
            _issue(result, "KSLIDE_TABLE_CELL_ID_MISMATCH", Severity.CRITICAL, "Canonical table cell geometry or engine evidence does not match its EvidenceIR cell identity.", target=target, evidence_ids=[cell.cell_id])
            break
    allowed = {evidence_cell.cell_id, evidence_table.table_id, *evidence_cell.evidence_region_ids, *evidence_cell.numeric_fact_ids}
    if not isinstance(cell.provenance_evidence_ids, list) or evidence_cell.cell_id not in cell.provenance_evidence_ids:
        _issue(result, "KSLIDE_PROVENANCE_EVIDENCE_REQUIRED", Severity.CRITICAL, "Table cell provenance must cite the exact EvidenceIR cell ID.", target=target, evidence_ids=[evidence_cell.cell_id])
    else:
        foreign = sorted(set(cell.provenance_evidence_ids) - allowed)
        if foreign:
            _issue(result, "KSLIDE_PROVENANCE_FOREIGN_EVIDENCE", Severity.CRITICAL, "Table cell provenance cites evidence outside the bound EvidenceIR cell.", target=target, evidence_ids=foreign)


def _check_required_english(
    result: VerificationResult,
    text: str | None,
    retention: Any,
    evidence_ids: Any,
    evidence: Any,
    *,
    target: str,
    source_texts: dict[str, str] | None = None,
) -> None:
    allowed_ids = tuple(evidence_ids) if isinstance(evidence_ids, list) else ()
    source_texts = source_texts if source_texts is not None else _source_evidence_texts(evidence)
    mismatch = required_english_mismatch(text, retention, source_texts, allowed_ids)
    if mismatch:
        _issue(result, ErrorCode.REQUIRED_ENGLISH.value, Severity.CRITICAL, mismatch, target=target, evidence_ids=list(allowed_ids))


def _check_source_literal_and_modality(result: VerificationResult, slide: SlideIR, evidence: Any, *, run_dir: Path | None = None, source_texts: dict[str, str] | None = None) -> None:
    # KSA-23 conflict fixtures may deliberately replace rendered context text
    # after merge so the conflict registry can retain a competing assertion.
    # That legacy surface has no KSA-24 language-policy marker and remains
    # readable; current normalized runs and standalone evidence stay strict.
    legacy_conflict_surface = bool(run_dir and conflict_registry_path(run_dir).is_file() and evidence.source.get("source_language_policy") != "unicode-script-v1")
    language_policy_bound = not legacy_conflict_surface
    regions = {region.region_id: region for region in slide.regions}
    for source in evidence.regions:
        region = regions.get(source.region_id)
        if region is None:
            continue
        source_text = source.selected_literal_candidate
        recovery_required = source.evidence_state in RISKY_LITERAL_STATES or source.recovery_status == "NEEDS_REVIEW"
        language = source.language or classify_source_language(source_text)
        if region.native_source_text != source.selected_literal_candidate or region.selected_source_text != source.selected_literal_candidate or tuple(region.bbox) != tuple(source.bbox_px) or region.reading_order != source.reading_order or region.region_type != source.region_type:
            _issue(result, "KSLIDE_SOURCE_LITERAL_CHANGED", Severity.CRITICAL, "Canonical source literal or region geometry changed after engine merge.", target=source.region_id, evidence_ids=[source.region_id])
        if source.language is not None and region.source_language != source.language:
            _issue(result, "KSLIDE_SOURCE_LANGUAGE_CHANGED", Severity.CRITICAL, "Canonical source-language identity changed after engine merge.", target=source.region_id, evidence_ids=[source.region_id])
        if list(source.source_english_spans) != list(region.source_english_spans):
            _issue(result, "KSLIDE_SOURCE_ENGLISH_SPAN_CHANGED", Severity.CRITICAL, "Canonical protected source-English spans changed after engine merge.", target=source.region_id, evidence_ids=[source.region_id])
        if not recovery_required and language_policy_bound and language == "en" and source_text is not None and region.translation != source_text:
            _issue(result, "KSLIDE_SOURCE_ENGLISH_CHANGED", Severity.CRITICAL, "Pure-English source text was changed in canonical output.", target=source.region_id, evidence_ids=[source.region_id])
        spans = list(source.source_english_spans)
        missing = [] if recovery_required else [span for span in spans if span not in (region.translation or "")]
        if missing:
            _issue(result, "KSLIDE_SOURCE_ENGLISH_SPAN_MISSING", Severity.CRITICAL, "Engine-protected source-English span is missing from canonical output.", target=source.region_id, evidence_ids=[source.region_id])
        mismatch = None if recovery_required else modality_mismatch(source_text, region.commitment_status, region.speech_act, language_bound=language_policy_bound)
        if mismatch:
            _issue(result, ErrorCode.MODALITY_MISMATCH.value, Severity.CRITICAL, mismatch, target=source.region_id, evidence_ids=[source.region_id])
        english_mismatch = None if recovery_required else english_modality_mismatch(source_text, region.translation, region.commitment_status, language_bound=language_policy_bound, require_status_marker=True)
        if english_mismatch:
            _issue(result, ErrorCode.MODALITY_MISMATCH.value, Severity.CRITICAL, english_mismatch, target=source.region_id, evidence_ids=[source.region_id])
        if decision_bearing_status(region.commitment_status) and source.region_id not in region.provenance_evidence_ids:
            _issue(result, "KSLIDE_PROVENANCE_EVIDENCE_REQUIRED", Severity.CRITICAL, "Decision-bearing commitment classification must cite its direct source region.", target=source.region_id, evidence_ids=[source.region_id])

    evidence_tables = {table.table_id: table for table in evidence.tables}
    for table in slide.tables:
        source_table = evidence_tables.get(table.table_id)
        if source_table is None:
            _issue(result, ErrorCode.TABLE_STRUCTURE_MISMATCH.value, Severity.CRITICAL, "Canonical table is missing from current EvidenceIR.", target=table.table_id)
            continue
        structural_fields = ("row_count", "column_count", "headers", "header_rows", "header_columns", "unit", "source_notes")
        for field in structural_fields:
            actual = getattr(table, field)
            expected = getattr(source_table, field)
            if isinstance(actual, list):
                actual = tuple(actual)
            if isinstance(expected, tuple):
                expected = tuple(expected)
            if actual != expected:
                _issue(result, ErrorCode.TABLE_STRUCTURE_MISMATCH.value, Severity.CRITICAL, "Canonical table dimensions, header semantics, units, or source notes changed.", target=table.table_id)
                break
        source_cells = {cell.cell_id: cell for cell in source_table.cells}
        for cell in table.cells:
            source_cell = source_cells.get(cell.cell_id)
            if source_cell is None:
                continue
            source_language = source_cell.source_language or classify_source_language(source_cell.source_text)
            if language_policy_bound and source_language == "en" and source_cell.source_text is not None and cell.translation != source_cell.source_text:
                _issue(result, "KSLIDE_SOURCE_ENGLISH_CHANGED", Severity.CRITICAL, "Pure-English table source text was changed in canonical output.", target=cell.cell_id, evidence_ids=[cell.cell_id])
            if source_cell.cell_state in {"blank", "merge_continuation"} or source_cell.is_blank is True or source_cell.source_text in (None, ""):
                if cell.translation != "":
                    _issue(result, ErrorCode.TABLE_STRUCTURE_MISMATCH.value, Severity.CRITICAL, "Canonical blank or merge-continuation cell contains invented content.", target=cell.cell_id, evidence_ids=[cell.cell_id])
            spans = list(source_cell.source_english_spans)
            if any(span not in (cell.translation or "") for span in spans):
                _issue(result, "KSLIDE_SOURCE_ENGLISH_SPAN_MISSING", Severity.CRITICAL, "Engine-protected table source-English span is missing from canonical output.", target=cell.cell_id, evidence_ids=[cell.cell_id])
            rendered_cell_text = cell.unresolved_reason if cell.provenance == ProvenanceState.UNRESOLVED.value else cell.translation
            _check_required_english(result, rendered_cell_text, cell.hangul_retention, cell.provenance_evidence_ids, evidence, target=cell.cell_id, source_texts=source_texts)
            try:
                if cell.commitment_status is not None:
                    enum_value(cell.commitment_status, CommitmentStatus, "table-cell commitment_status")
                if cell.speech_act is not None:
                    enum_value(cell.speech_act, SpeechAct, "table-cell speech_act")
            except KSlideError:
                _issue(result, "KSLIDE_SCHEMA_INVALID", Severity.CRITICAL, "Canonical table-cell commitment metadata is outside the closed contract.", target=cell.cell_id, evidence_ids=[cell.cell_id])
            if language_policy_bound:
                mismatch = modality_mismatch(source_cell.source_text, cell.commitment_status, cell.speech_act)
                if mismatch:
                    _issue(result, ErrorCode.MODALITY_MISMATCH.value, Severity.CRITICAL, mismatch, target=cell.cell_id, evidence_ids=[cell.cell_id])
                english_mismatch = english_modality_mismatch(source_cell.source_text, cell.translation, cell.commitment_status, require_status_marker=True)
                if english_mismatch:
                    _issue(result, ErrorCode.MODALITY_MISMATCH.value, Severity.CRITICAL, english_mismatch, target=cell.cell_id, evidence_ids=[cell.cell_id])


def _check_visual_evidence(result: VerificationResult, slide: SlideIR, evidence: Any, *, source_texts: dict[str, str] | None = None) -> None:
    if slide.visual_elements != list(evidence.visual_elements):
        _issue(result, ErrorCode.VISUAL_RELATION_MISMATCH.value, Severity.CRITICAL, "Canonical visual elements do not exactly match current engine visual evidence.", target=slide.slide_id)
    valid_ids = {str(item.get("element_id")) for item in evidence.visual_elements if isinstance(item, dict) and item.get("element_id")}
    for relation in slide.visual_relations:
        rendered_text = relation.unresolved_reason if relation.provenance == ProvenanceState.UNRESOLVED.value else relation.interpretation
        _check_required_english(result, rendered_text, relation.hangul_retention, relation.evidence, evidence, target=relation.relation_id, source_texts=source_texts)
        unknown = sorted(set(relation.source_element_ids) - valid_ids)
        if unknown:
            _issue(result, ErrorCode.VISUAL_RELATION_MISMATCH.value, Severity.CRITICAL, "Visual relation references a fabricated engine element.", target=relation.relation_id, evidence_ids=unknown)
        relation_value = {"source_element_ids": relation.source_element_ids, "direction": relation.direction, "provenance": relation.provenance, "chart_claim": relation.chart_claim}
        source_fact_allowed = _source_fact_connector_relation(relation_value, evidence)
        charts = _chart_elements(evidence, tuple(relation.source_element_ids))
        if charts:
            chart_claim = relation.chart_claim
            source_fact_allowed = isinstance(chart_claim, dict) and chart_claim.get("chart_element_id") in relation.source_element_ids and chart_claim.get("chart_element_id") in relation.evidence
            if isinstance(chart_claim, dict) and (chart_claim.get("chart_element_id") not in relation.source_element_ids or chart_claim.get("chart_element_id") not in relation.evidence):
                _issue(result, ErrorCode.CLAIM_UNSUPPORTED.value, Severity.CRITICAL, "Canonical chart claim does not cite its exact engine chart evidence.", target=relation.relation_id, evidence_ids=relation.evidence)
        if relation.provenance == ProvenanceState.SOURCE_FACT.value and not source_fact_allowed:
            _issue(result, ErrorCode.VISUAL_RELATION_MISMATCH.value, Severity.CRITICAL, "Source-factual visual relation is not proven by an engine connector edge.", target=relation.relation_id, evidence_ids=relation.evidence)
        if charts:
            try:
                _validate_chart_interpretation({"interpretation": relation.interpretation or "", "chart_claim": relation.chart_claim}, charts)
            except KSlideError as exc:
                _issue(result, exc.code.value, Severity.CRITICAL, exc.message, target=relation.relation_id, evidence_ids=relation.evidence)


def _check_provenance(
    result: VerificationResult,
    *,
    state: Any,
    evidence_ids: Any,
    evidence: Any,
    target: str,
    reason: Any = None,
    source_id: str | None = None,
    source_fact_allowed: bool = True,
    semantic_evidence_allowed: bool = True,
    unresolved_flag: bool | None = None,
) -> str | None:
    try:
        effective = enum_value(state, ProvenanceState, f"{target} provenance")
    except KSlideError:
        _issue(result, "KSLIDE_PROVENANCE_INVALID", Severity.CRITICAL, "Semantic item has an invalid provenance state.", target=target)
        return None
    if not isinstance(evidence_ids, list) or not evidence_ids or any(not isinstance(item, str) or not item for item in evidence_ids):
        _issue(result, "KSLIDE_PROVENANCE_EVIDENCE_REQUIRED", Severity.CRITICAL, "Semantic item provenance must cite at least one engine evidence ID.", target=target)
    else:
        valid = _evidence_ids(evidence)
        foreign = sorted(set(evidence_ids) - valid)
        if foreign:
            _issue(result, "KSLIDE_PROVENANCE_FOREIGN_EVIDENCE", Severity.CRITICAL, "Semantic item provenance cites evidence outside the current EvidenceIR.", target=target, evidence_ids=foreign)
    if effective == ProvenanceState.UNRESOLVED.value:
        if not isinstance(reason, str) or not reason.strip():
            _issue(result, "KSLIDE_PROVENANCE_INCONSISTENT", Severity.CRITICAL, "Unresolved provenance requires a non-empty reason.", target=target)
        if unresolved_flag is False:
            _issue(result, "KSLIDE_PROVENANCE_INCONSISTENT", Severity.CRITICAL, "Unresolved provenance conflicts with a resolved semantic flag.", target=target)
    else:
        if reason is not None:
            _issue(result, "KSLIDE_PROVENANCE_INCONSISTENT", Severity.CRITICAL, "Only unresolved provenance may carry an unresolved reason.", target=target)
        if unresolved_flag is True:
            _issue(result, "KSLIDE_PROVENANCE_INCONSISTENT", Severity.CRITICAL, "Resolved provenance conflicts with unresolved=true.", target=target)
    if effective == ProvenanceState.SOURCE_FACT.value:
        if not source_fact_allowed:
            _issue(result, "KSLIDE_PROVENANCE_INCONSISTENT", Severity.CRITICAL, "This semantic item cannot be a source_fact.", target=target)
        elif source_id is not None and (not isinstance(evidence_ids, list) or source_id not in evidence_ids):
            _issue(result, "KSLIDE_PROVENANCE_INCONSISTENT", Severity.CRITICAL, "source_fact must cite its direct engine source ID.", target=target, evidence_ids=[source_id])
    if effective != ProvenanceState.UNRESOLVED.value and not semantic_evidence_allowed:
        _issue(result, "KSLIDE_LITERAL_RECOVERY_REQUIRED", Severity.CRITICAL, "Resolved semantic content cites literal evidence that is absent or still requires recovery.", target=target, evidence_ids=evidence_ids if isinstance(evidence_ids, list) else [])
    return effective


def _validate_canonical_provenance(
    result: VerificationResult,
    slide: SlideIR,
    evidence: Any,
    work_unit_id: str,
    raw_slide: dict[str, Any] | None = None,
    *,
    source_texts: dict[str, str] | None = None,
) -> None:
    unresolved_refs: set[str] = set()
    for item in slide.unresolved:
        source_id = item.get("region_id") or item.get("cell_id") or item.get("relation_id") or item.get("claim_id")
        if source_id:
            unresolved_refs.add(str(source_id))
        _check_provenance(
            result,
            state=item.get("provenance"),
            evidence_ids=item.get("evidence_ids", []),
            evidence=evidence,
            target=str(source_id or work_unit_id),
            reason=item.get("reason") or item.get("unresolved_reason"),
        )
    expected_unresolved: set[str] = set()
    unresolved_by_source = {
        str(item.get("region_id") or item.get("cell_id") or item.get("relation_id") or item.get("claim_id")): item
        for item in slide.unresolved if isinstance(item, dict)
    }
    for region in slide.regions:
        source_region = next((candidate for candidate in evidence.regions if candidate.region_id == region.region_id), None)
        recovery_required = source_region is not None and (source_region.evidence_state in RISKY_LITERAL_STATES or source_region.recovery_status == "NEEDS_REVIEW")
        state = _check_provenance(
            result,
            state=region.provenance,
            evidence_ids=region.provenance_evidence_ids,
            evidence=evidence,
            target=region.region_id,
            reason=region.unresolved_reason,
            source_id=region.region_id,
            source_fact_allowed=not recovery_required,
            semantic_evidence_allowed=_semantic_evidence_usable(evidence, region.provenance_evidence_ids, direct_source_id=region.region_id),
        )
        if recovery_required:
            unresolved = unresolved_by_source.get(region.region_id, {})
            if state != ProvenanceState.UNRESOLVED.value or (region.translation or "").strip():
                _issue(result, "KSLIDE_LITERAL_RECOVERY_REQUIRED", Severity.CRITICAL, "A region without trustworthy literal recovery must remain empty and unresolved.", target=region.region_id, evidence_ids=[region.region_id])
            if unresolved.get("reason") != source_region.recovery_reason or not all(isinstance(unresolved.get(key), str) and unresolved.get(key).strip() for key in ("impact", "recommended_action")) or not isinstance(unresolved.get("location"), dict):
                _issue(result, "KSLIDE_RECOVERY_RECORD_INCOMPLETE", Severity.CRITICAL, "Unresolved recovery must preserve its engine reason, impact, location, and recommended action.", target=region.region_id, evidence_ids=[region.region_id])
        if state == ProvenanceState.UNRESOLVED.value:
            expected_unresolved.add(region.region_id)
    for table in slide.tables:
        for cell in table.cells:
            _check_table_cell_binding(result, table, cell, evidence, target=cell.cell_id)
            evidence_region_map = {region.region_id: region for region in evidence.regions}
            recovery_required = not _cell_literal_usable(next((candidate for source_table in evidence.tables for candidate in source_table.cells if candidate.cell_id == cell.cell_id), cell), evidence_region_map)
            state = _check_provenance(
                result,
                state=cell.provenance,
                evidence_ids=cell.provenance_evidence_ids,
                evidence=evidence,
                target=cell.cell_id,
                reason=cell.unresolved_reason,
                source_id=cell.cell_id,
                source_fact_allowed=not recovery_required,
                semantic_evidence_allowed=_semantic_evidence_usable(evidence, cell.provenance_evidence_ids, direct_source_id=cell.cell_id, allow_structural_blank=True),
                unresolved_flag=cell.unresolved,
            )
            if recovery_required and (state != ProvenanceState.UNRESOLVED.value or (cell.translation or "").strip()):
                _issue(result, "KSLIDE_LITERAL_RECOVERY_REQUIRED", Severity.CRITICAL, "A table cell without trustworthy literal evidence must remain empty and unresolved.", target=cell.cell_id, evidence_ids=[cell.cell_id])
            if state == ProvenanceState.UNRESOLVED.value:
                expected_unresolved.add(cell.cell_id)
    for relation in slide.visual_relations:
        if not _semantic_evidence_usable(evidence, relation.evidence, allow_typed_visual=True):
            _issue(result, "KSLIDE_LITERAL_RECOVERY_REQUIRED", Severity.CRITICAL, "Visual interpretation references literal evidence that is absent or still requires recovery.", target=relation.relation_id, evidence_ids=relation.evidence)
        source_fact_allowed = _source_fact_connector_relation(
            {
                "source_element_ids": relation.source_element_ids,
                "direction": relation.direction,
                "chart_claim": relation.chart_claim,
            },
            evidence,
        )
        if _chart_elements(evidence, tuple(relation.source_element_ids)):
            source_fact_allowed = relation.chart_claim is not None
        state = _check_provenance(
            result,
            state=relation.provenance,
            evidence_ids=relation.evidence,
            evidence=evidence,
            target=relation.relation_id,
            reason=relation.unresolved_reason,
            source_fact_allowed=source_fact_allowed,
            semantic_evidence_allowed=_semantic_evidence_usable(evidence, relation.evidence, allow_typed_visual=True),
        )
        if state == ProvenanceState.UNRESOLVED.value:
            expected_unresolved.add(relation.relation_id)
    for claim in slide.executive_semantics.get("executive_claims", []):
        if not isinstance(claim, dict):
            _issue(result, "KSLIDE_PROVENANCE_INVALID", Severity.CRITICAL, "Executive semantic item is not an object.", target=work_unit_id)
            continue
        claim_id = str(claim.get("claim_id", ""))
        state = _check_provenance(
            result,
            state=claim.get("provenance"),
            evidence_ids=claim.get("evidence_ids", []),
            evidence=evidence,
            target=claim_id or work_unit_id,
            reason=claim.get("unresolved_reason"),
            semantic_evidence_allowed=_semantic_evidence_usable(evidence, claim.get("evidence_ids", [])),
        )
        if state == ProvenanceState.UNRESOLVED.value and claim_id:
            expected_unresolved.add(claim_id)
        rendered_text = claim.get("unresolved_reason") if state == ProvenanceState.UNRESOLVED.value else claim.get("text")
        evidence_ids = claim.get("evidence_ids", [])
        if not _semantic_evidence_usable(evidence, evidence_ids if isinstance(evidence_ids, list) else []):
            _issue(result, "KSLIDE_LITERAL_RECOVERY_REQUIRED", Severity.CRITICAL, "Executive claim references literal evidence that is absent or still requires recovery.", target=claim_id or work_unit_id, evidence_ids=evidence_ids if isinstance(evidence_ids, list) else [])
        _check_required_english(result, rendered_text, claim.get("hangul_retention"), evidence_ids, evidence, target=claim_id or work_unit_id, source_texts=source_texts)
        if evidence.source.get("source_language_policy") == "unicode-script-v1":
            sources = _executive_source_texts(evidence, tuple(item for item in evidence_ids if isinstance(item, str)), source_texts) if isinstance(evidence_ids, list) else ()
            raw_semantics = (raw_slide or {}).get("executive_semantics")
            raw_claims = raw_semantics.get("executive_claims", []) if isinstance(raw_semantics, dict) else []
            if not isinstance(raw_claims, list):
                raw_claims = []
            raw_claim = next((item for item in raw_claims if isinstance(item, dict) and item.get("claim_id") == claim_id), {})
            modality_issue = executive_modality_mismatch(
                sources,
                claim.get("text"),
                claim_kind=claim.get("kind"),
                provenance=raw_claim.get("provenance"),
            )
            if modality_issue:
                _issue(result, ErrorCode.MODALITY_MISMATCH.value, Severity.CRITICAL, modality_issue, target=claim_id or work_unit_id, evidence_ids=list(evidence_ids) if isinstance(evidence_ids, list) else [])
    missing = sorted(expected_unresolved - unresolved_refs)
    extra = sorted(unresolved_refs - expected_unresolved)
    if missing:
        _issue(result, "KSLIDE_PROVENANCE_UNRESOLVED_SURFACE_GAP", Severity.CRITICAL, "Unresolved semantic items are missing from the unresolved surface.", target=work_unit_id, evidence_ids=missing)
    if extra:
        _issue(result, "KSLIDE_PROVENANCE_INCONSISTENT", Severity.CRITICAL, "Unresolved surface contains a semantic item that is not unresolved in canonical state.", target=work_unit_id, evidence_ids=extra)


def _validate_slide(run_dir: Path, work_unit_id: str, result: VerificationResult, *, expected_termbase_identity: RunEnvironmentIdentity | None = None, termbase: Termbase | None = None, termbase_authority: Any | None = None) -> None:
    path = storage_path(run_dir, StorageArtifact.CANONICAL_IR, f"ir/{work_unit_id}.json")
    try:
        value = read_json(path)
        if not isinstance(value, dict) or value.get("schema_version") != "1.0":
            _issue(result, "KSLIDE_SCHEMA_INVALID", Severity.CRITICAL, "SlideIR schema version is missing or unsupported.", target=work_unit_id)
            return
        evidence = load_evidence(run_dir, work_unit_id)
        source_texts = _source_evidence_texts(evidence)
        slide = SlideIR.from_dict(value, evidence=evidence)
        result.checked_slides += 1
        result.checked_regions += len(slide.regions)
        if slide.evidence_revision != evidence.evidence_revision:
            _issue(result, ErrorCode.STALE_EVIDENCE.value, Severity.CRITICAL, "SlideIR is linked to a stale EvidenceIR revision.", target=work_unit_id)
        _validate_canonical_provenance(result, slide, evidence, work_unit_id, value, source_texts=source_texts)
        _check_source_literal_and_modality(result, slide, evidence, run_dir=run_dir, source_texts=source_texts)
        _check_visual_evidence(result, slide, evidence, source_texts=source_texts)
        source_regions = {region.region_id for region in evidence.regions if region.required_for_translation}
        translated_regions = {region.region_id for region in slide.regions}
        missing = sorted(source_regions - translated_regions)
        if missing:
            result.unaccounted_count += len(missing)
            _issue(result, "KSLIDE_EVIDENCE_COVERAGE_GAP", Severity.CRITICAL, "Canonical SlideIR omitted engine-defined source regions.", target=work_unit_id, evidence_ids=missing)
        coverage_ids = {entry.source_id for entry in slide.coverage}
        missing_coverage = sorted(set(evidence.required_source_ids) - coverage_ids)
        if missing_coverage:
            result.unaccounted_count += len(missing_coverage)
            _issue(result, "KSLIDE_COVERAGE_GAP", Severity.CRITICAL, "Canonical coverage does not account for required engine evidence.", target=work_unit_id, evidence_ids=missing_coverage)
        for table in slide.tables:
            if table.row_count < 1 or table.column_count < 1:
                _issue(result, "KSLIDE_TABLE_SHAPE_INVALID", Severity.CRITICAL, "Table dimensions must be positive.", target=table.table_id)
            evidence_table = next((candidate for candidate in evidence.tables if candidate.table_id == table.table_id), None)
            if evidence_table is not None:
                canonical_cell_ids = [cell.cell_id for cell in table.cells]
                evidence_cell_ids = [cell.cell_id for cell in evidence_table.cells]
                if len(canonical_cell_ids) != len(set(canonical_cell_ids)) or set(canonical_cell_ids) != set(evidence_cell_ids):
                    _issue(result, ErrorCode.TABLE_STRUCTURE_MISMATCH.value, Severity.CRITICAL, "Canonical table cell inventory does not match the engine-owned cell inventory.", target=table.table_id, evidence_ids=evidence_cell_ids)
            for cell in table.cells:
                if cell.row < 0 or cell.column < 0 or cell.row >= table.row_count or cell.column >= table.column_count:
                    _issue(result, "KSLIDE_TABLE_CELL_OUT_OF_RANGE", Severity.CRITICAL, "Table cell is outside declared dimensions.", target=table.table_id)
                if cell.rowspan < 1 or cell.colspan < 1 or cell.row + cell.rowspan > table.row_count or cell.column + cell.colspan > table.column_count:
                    _issue(result, ErrorCode.TABLE_STRUCTURE_MISMATCH.value, Severity.CRITICAL, "Table cell span exceeds current table dimensions.", target=cell.cell_id, evidence_ids=[cell.cell_id])
        facts = {fact.fact_id: fact for fact in slide.numeric_facts}
        evidence_facts = {str(item.get("fact_id")): item for item in evidence.numeric_facts if isinstance(item, dict) and item.get("fact_id")}
        if set(facts) != set(evidence_facts):
            _issue(result, ErrorCode.NUMERIC_MISMATCH.value, Severity.CRITICAL, "Canonical numeric fact inventory does not match engine-owned numeric evidence.", target=work_unit_id, evidence_ids=sorted(set(facts) ^ set(evidence_facts)))
        for fact_id, fact in facts.items():
            expected_fact = evidence_facts.get(fact_id)
            if expected_fact is None:
                continue
            actual_fact = asdict(fact)
            if any(actual_fact.get(field) != expected_fact.get(field) for field in actual_fact):
                _issue(result, ErrorCode.NUMERIC_MISMATCH.value, Severity.CRITICAL, "Canonical numeric fact changed an engine-owned value or unit binding.", target=fact_id, evidence_ids=[fact_id])
        region_text = {region.region_id: region.translation or "" for region in slide.regions}
        cell_text = {cell.cell_id: cell.translation or "" for table in slide.tables for cell in table.cells}
        for fact in facts.values():
            target_text = cell_text.get(fact.source_cell_id or "") or region_text.get(fact.source_region_id or "")
            if not target_text:
                _issue(result, ErrorCode.NUMERIC_MISMATCH.value, Severity.CRITICAL, "Source numeric fact has no translated target text.", target=fact.fact_id, evidence_ids=[fact.source_region_id or fact.source_cell_id or fact.fact_id])
                continue
            table_unit = next((table.unit for table in evidence.tables if table.table_id == fact.source_table_id), None)
            matched, reason = numeric_fact_matches(asdict(fact), target_text, table_unit=table_unit)
            if not matched:
                _issue(result, ErrorCode.NUMERIC_MISMATCH.value, Severity.CRITICAL, reason, target=fact.fact_id, evidence_ids=[fact.source_region_id or fact.source_cell_id or fact.fact_id])
        if slide.unresolved:
            for item in slide.unresolved:
                _issue(result, "KSLIDE_UNRESOLVED_REQUIRED", Severity.CRITICAL, "A required source item remains unresolved; final certification is blocked.", target=work_unit_id, evidence_ids=[str(item.get("region_id") or item.get("cell_id") or work_unit_id)])
        for region in slide.regions:
            rendered_text = region.unresolved_reason if region.provenance == ProvenanceState.UNRESOLVED.value else region.translation
            _check_required_english(result, rendered_text, region.hangul_retention, region.provenance_evidence_ids, evidence, target=region.region_id, source_texts=source_texts)
        if termbase is None:
            try:
                termbase = load_effective_termbase(run_dir.parent.parent, authority=termbase_authority)
            except (KSlideError, KeyError, TypeError, ValueError, json.JSONDecodeError, OSError):
                if expected_termbase_identity is not None and expected_termbase_identity.ocr_provider != "reference":
                    _issue(result, "KSLIDE_TERMBASE_BINDING_MISMATCH", Severity.CRITICAL, "Bound governed terminology is unavailable or drifted.", target=work_unit_id, scope="RUN_LEVEL_POLICY_FAILURE")
                    return
                raise
        if expected_termbase_identity is not None and expected_termbase_identity.ocr_provider != "reference":
            actual_identity = termbase.binding_identity or {}
            if actual_identity.get("hash") != expected_termbase_identity.termbase_identity or actual_identity.get("version") != expected_termbase_identity.termbase_version:
                _issue(result, "KSLIDE_TERMBASE_BINDING_MISMATCH", Severity.CRITICAL, "Current governed terminology does not match the immutable run binding.", target=work_unit_id, scope="RUN_LEVEL_POLICY_FAILURE")
                return
        for source_region in evidence.regions:
            source_text = source_region.selected_literal_candidate or ""
            translated = region_text.get(source_region.region_id, "")
            for term in termbase.records:
                if term.status == "LOCKED" and term.source in source_text and term.default and term.default.lower() not in translated.lower():
                    _issue(result, "KSLIDE_LOCKED_TERM_MISMATCH", Severity.MAJOR, f"Locked term `{term.source}` must use `{term.default}`.", target=source_region.region_id, evidence_ids=[source_region.region_id])
        for item in slide.unresolved:
            if not item.get("reason") and not item.get("unresolved_reason"):
                _issue(result, "KSLIDE_UNRESOLVED_UNDISCLOSED", Severity.CRITICAL, "Unresolved evidence lacks a reason.", target=work_unit_id)
    except KSlideError as exc:
        _issue(result, exc.code.value, Severity.CRITICAL, exc.message, target=work_unit_id)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError, OSError):
        _issue(result, "KSLIDE_SCHEMA_INVALID", Severity.CRITICAL, "Could not validate SlideIR safely.", target=work_unit_id)


def _configured_conflict_authority_ids(run_dir: Path) -> set[str]:
    path = storage_path(run_dir, StorageArtifact.RUN_MANIFEST, "RUN_MANIFEST.json")
    if not path.is_file():
        return set()
    try:
        value = read_json(path)
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        return set()
    authority = value.get("conflict_authority", {}) if isinstance(value, dict) else {}
    configured = authority.get("configured_authority_ids", []) if isinstance(authority, dict) else []
    ids = {item for item in configured if isinstance(item, str) and item}
    try:
        ids.update(configured_authority_ids(run_dir))
    except KSlideError:
        pass
    return ids


def _validate_conflict_registry(run_dir: Path, result: VerificationResult) -> None:
    """Validate conflict coverage, preserving legacy absence semantics."""

    try:
        assessment_status = conflict_assessment_status(run_dir)
    except KSlideError as exc:
        _issue(result, "KSLIDE_CONFLICT_REGISTRY_INVALID", Severity.CRITICAL, exc.message, target="RUN_MANIFEST.json", scope="RUN_LEVEL_POLICY_FAILURE")
        return
    if assessment_status == "NOT_ASSESSED":
        _issue(
            result,
            "KSLIDE_CONFLICT_ASSESSMENT_REQUIRED",
            Severity.CRITICAL,
            "KSA-23 runs require durable conflict assessment before verification and finalization.",
            target="CONFLICT_REGISTRY.json",
            scope="RUN_LEVEL_POLICY_FAILURE",
        )
        return
    if not conflict_registry_path(run_dir).is_file():
        if conflict_contract_required(run_dir):
            _issue(
                result,
                "KSLIDE_CONFLICT_REGISTRY_INVALID",
                Severity.CRITICAL,
                "An assessed KSA-23 run is missing its conflict registry.",
                target="CONFLICT_REGISTRY.json",
                scope="RUN_LEVEL_POLICY_FAILURE",
            )
        return
    try:
        registry = load_conflict_registry(run_dir)
        if registry is None:
            return
        registry.validate_against_run(
            run_dir,
            configured_authority_ids=_configured_conflict_authority_ids(run_dir),
            authority_policy=conflict_authority_policy(run_dir),
            strict_authority=conflict_contract_required(run_dir),
        )
    except KSlideError as exc:
        code = exc.code.value
        if exc.code in {ErrorCode.SCHEMA_INVALID, ErrorCode.CONFLICT_INVALID, ErrorCode.STALE_EVIDENCE}:
            code = "KSLIDE_CONFLICT_REGISTRY_INVALID"
        _issue(result, code, Severity.CRITICAL, exc.message, target="CONFLICT_REGISTRY.json", scope="RUN_LEVEL_POLICY_FAILURE")
        return
    except (KeyError, TypeError, ValueError, json.JSONDecodeError, OSError):
        _issue(result, "KSLIDE_CONFLICT_REGISTRY_INVALID", Severity.CRITICAL, "Conflict registry could not be validated safely.", target="CONFLICT_REGISTRY.json", scope="RUN_LEVEL_POLICY_FAILURE")
        return
    unresolved = [item.conflict_id for item in registry.conflicts if item.resolution_state == ConflictResolutionState.UNRESOLVED.value]
    if unresolved:
        _issue(
            result,
            "KSLIDE_CONFLICT_UNRESOLVED",
            Severity.CRITICAL,
            "Run-level source contradictions remain unresolved; no authoritative supersession is recorded.",
            target="CONFLICT_REGISTRY.json",
            evidence_ids=sorted(unresolved),
            scope="RUN_LEVEL_POLICY_FAILURE",
        )


def _verify_unlocked(run_dir: Path, *, environment_identity: RunEnvironmentIdentity | None = None, termbase: Termbase | None = None, termbase_authority: Any | None = None) -> VerificationResult:
    state = load_state(run_dir)
    result = VerificationResult(status="PASS", run_id=state.run_id)
    try:
        queue = load_queue(run_dir)
        result.queue_revision = queue.queue_revision
    except (KSlideError, OSError) as exc:
        _issue(result, "KSLIDE_WORK_QUEUE_INVALID", Severity.CRITICAL, "Work queue could not be loaded safely.", target="WORK_QUEUE.json")
        queue = WorkQueue(run_id=state.run_id)
    result.checked_work_units = len(queue.work_units)
    if not queue.work_units:
        _issue(result, "KSLIDE_NO_WORK_UNITS", Severity.CRITICAL, "No engine-defined work units exist.", scope="RUN_LEVEL_POLICY_FAILURE")
    for unit in queue.work_units:
        before = len(result.issues)
        if unit.status is WorkUnitStatus.NEEDS_REVIEW:
            result.unit_status[unit.work_unit_id] = "NEEDS_REVIEW"
            _issue(result, "KSLIDE_REVIEW_REQUIRED", Severity.CRITICAL, "Work unit requires human review or a bounded repair before final certification.", target=unit.work_unit_id, scope="RUN_LEVEL_POLICY_FAILURE")
            continue
        if unit.status in {WorkUnitStatus.TRANSLATED, WorkUnitStatus.VERIFIED}:
            if not storage_path(run_dir, StorageArtifact.CANONICAL_IR, f"ir/{unit.work_unit_id}.json").is_file():
                _issue(result, "KSLIDE_IR_MISSING", Severity.CRITICAL, "Translated work unit has no canonical SlideIR.", target=unit.work_unit_id, scope="WORK_UNIT_TRANSLATION_FAILURE")
            else:
                if unit.canonical_ir_sha256 and sha256_file(storage_path(run_dir, StorageArtifact.CANONICAL_IR, f"ir/{unit.work_unit_id}.json")) != unit.canonical_ir_sha256:
                    _issue(result, "KSLIDE_CANONICAL_IR_CHANGED", Severity.CRITICAL, "Canonical SlideIR changed after engine merge.", target=unit.work_unit_id, scope="WORK_UNIT_TRANSLATION_FAILURE")
                _validate_slide(run_dir, unit.work_unit_id, result, expected_termbase_identity=environment_identity, termbase=termbase, termbase_authority=termbase_authority)
            result.unit_status[unit.work_unit_id] = "PASS" if len(result.issues) == before else "FAIL_REPAIRABLE"
        else:
            result.unit_status[unit.work_unit_id] = "INCOMPLETE"
            _issue(result, "KSLIDE_WORK_UNIT_INCOMPLETE", Severity.CRITICAL, "Work unit is not translated or explicitly reviewable.", target=unit.work_unit_id, scope="RUN_LEVEL_POLICY_FAILURE")
    _validate_conflict_registry(run_dir, result)
    # 06_verification.md is generated by this verifier, so it cannot be a
    # prerequisite for the verifier that writes it. The remaining artifacts
    # must already exist before a run can pass.
    missing = [name for name in COMPLETION_POLICY.precompletion_artifacts if name != "06_verification.md" and not storage_path(run_dir, StorageArtifact.REPORT if name.startswith(("05_", "07_")) else StorageArtifact.VERIFICATION, name).is_file()]
    for name in missing:
        _issue(result, "KSLIDE_REQUIRED_ARTIFACT_MISSING", Severity.CRITICAL, "Required pre-completion artifact is missing.", target=name, scope="RUN_LEVEL_ARTIFACT_FAILURE")
    result.status = "PASS" if not result.issues else "FAIL"
    return result


def _persist_verification(run_dir: Path, result: VerificationResult) -> None:
    atomic_write_json(storage_path(run_dir, StorageArtifact.VERIFICATION, "verification/summary.json", create_parent=True), result.as_dict(), mode=0o600)
    lines = ["# K-Slide Verification", "", f"Status: **{result.status}**", f"Run: `{result.run_id}`", "", f"Work units checked: {result.checked_work_units}", f"Critical issues: {result.critical_count}", f"Unaccounted source items: {result.unaccounted_count}"]
    if result.unit_status:
        lines.extend(["", "## Work-unit status", ""])
        lines.extend(f"- `{work_unit_id}`: **{status}**" for work_unit_id, status in sorted(result.unit_status.items()))
    if result.issues:
        lines.extend(["", "## Issues"])
        lines.extend(f"- **{issue.severity.value}** `{issue.code}` [{issue.scope}]: {issue.message}" + (f" (`{issue.target}`)" if issue.target else "") for issue in result.issues)
    lines.extend(["", "## Completion policy", "", f"Policy version: `{COMPLETION_POLICY.version}`", "", "`RUN_COMPLETE.md` is created only by deterministic finalization after current verification passes.", ""])
    atomic_write_text(storage_path(run_dir, StorageArtifact.VERIFICATION, "06_verification.md", create_parent=True), "\n".join(lines))


def verify_run(run_dir: Path, *, environment_identity: RunEnvironmentIdentity | None = None, termbase_authority: Any | None = None) -> VerificationResult:
    from .execution import ensure_workspace_environment_compatible

    _, effective_environment = ensure_workspace_environment_compatible(run_dir, environment_identity=environment_identity)
    effective_termbase = resolve_run_termbase(run_dir.parent.parent, environment_identity=effective_environment, termbase_authority=termbase_authority)
    with run_lock(run_dir):
        state = load_state(run_dir)
        if state.phase == RunPhase.COMPLETE:
            workspace_mutation_guard(run_dir)
            sentinel = storage_path(run_dir, StorageArtifact.COMPLETION_MARKER, "RUN_COMPLETE.md")
            sentinel.unlink(missing_ok=True)
            state.transition(RunPhase.VERIFYING, next_action="Re-verifying current artifacts")
            save_state(run_dir, state)
        elif state.phase in {RunPhase.TRANSLATED, RunPhase.TRANSLATING, RunPhase.REPAIRING, RunPhase.NEEDS_REVIEW, RunPhase.VERIFIED}:
            if state.phase != RunPhase.VERIFYING:
                state.transition(RunPhase.VERIFYING, next_action="Deterministic verification in progress")
                save_state(run_dir, state)
        else:
            result = VerificationResult(status="FAIL", run_id=state.run_id)
            _issue(result, "KSLIDE_PHASE_NOT_VERIFIABLE", Severity.CRITICAL, "Run is not in a translation/verification phase.", target=state.phase.value)
            _persist_verification(run_dir, result)
            return result
        if any(storage_path(run_dir, StorageArtifact.CANONICAL_IR, "ir").glob("*.json")):
            render_run(run_dir)
        result = _verify_unlocked(run_dir, environment_identity=effective_environment, termbase=effective_termbase)
        try:
            queue = load_queue(run_dir)
            for unit in queue.work_units:
                unit_result = result.unit_status.get(unit.work_unit_id)
                if unit_result == "PASS":
                    unit.verification_status = "PASS"
                    unit.status = WorkUnitStatus.VERIFIED
                    unit.revision += 1
                elif unit_result == "FAIL_REPAIRABLE":
                    unit.verification_status = "FAIL"
                    unit.status = WorkUnitStatus.VERIFY_FAILED
                    unit.revision += 1
            save_queue(run_dir, queue)
        except (KSlideError, OSError):
            pass
        if result.passed:
            state.transition(RunPhase.VERIFIED, next_action="Finalize after current verification")
        else:
            state.transition(RunPhase.FAIL_REPAIRABLE, next_action="Repair exact verification targets")
        save_state(run_dir, state)
        _persist_verification(run_dir, result)
        return result


def finalize_run(run_dir: Path, *, environment_identity: RunEnvironmentIdentity | None = None, termbase_authority: Any | None = None) -> VerificationResult:
    from .execution import ensure_workspace_environment_compatible

    _, effective_environment = ensure_workspace_environment_compatible(run_dir, environment_identity=environment_identity)
    effective_termbase = resolve_run_termbase(run_dir.parent.parent, environment_identity=effective_environment, termbase_authority=termbase_authority)
    with run_lock(run_dir):
        state = load_state(run_dir)
        if state.phase == RunPhase.COMPLETE:
            workspace_mutation_guard(run_dir)
            storage_path(run_dir, StorageArtifact.COMPLETION_MARKER, "RUN_COMPLETE.md").unlink(missing_ok=True)
            state.transition(RunPhase.VERIFYING, next_action="Re-verifying current artifacts")
            save_state(run_dir, state)
        elif state.phase != RunPhase.VERIFYING:
            state.transition(RunPhase.VERIFYING, next_action="Re-verifying current artifacts")
            save_state(run_dir, state)
        if any(storage_path(run_dir, StorageArtifact.CANONICAL_IR, "ir").glob("*.json")):
            render_run(run_dir)
        result = _verify_unlocked(run_dir, environment_identity=effective_environment, termbase=effective_termbase)
        _persist_verification(run_dir, result)
        if not result.passed:
            state = load_state(run_dir)
            state.transition(RunPhase.FAIL_REPAIRABLE, next_action="Repair exact verification targets")
            save_state(run_dir, state)
            raise KSlideError(ErrorCode.COMPLETION_BLOCKED, "K-Slide cannot finalize because current deterministic verification has not passed.", {"verification": result.as_dict()})
        ensure_completion_artifacts(run_dir, include_sentinel=False)
        atomic_write_text(storage_path(run_dir, StorageArtifact.COMPLETION_MARKER, "RUN_COMPLETE.md", create_parent=True), "# DONE\n\nK-Slide deterministic verification passed against the current artifacts.\n")
        missing = COMPLETION_POLICY.missing(run_dir, include_sentinel=True)
        if missing:
            raise KSlideError(ErrorCode.COMPLETION_BLOCKED, "Completion artifacts are incomplete.", {"missing": missing})
        state = load_state(run_dir)
        state.transition(RunPhase.VERIFIED, next_action="Create deterministic completion sentinel")
        state.transition(RunPhase.COMPLETE, next_action=None)
        save_state(run_dir, state)
        return result


# Kept as a narrow compatibility validator for callers that still import the v0.1 name.
def validate_translation_payload(value: dict[str, Any]) -> None:
    from .translation import parse_translation_patch

    parse_translation_patch(value)


def canonicalize_translation_payload(value: dict[str, Any]) -> dict[str, Any]:
    """Compatibility shim: return only the validated model patch, never canonical source state."""

    from .translation import parse_translation_patch

    return parse_translation_patch(value).as_dict()
