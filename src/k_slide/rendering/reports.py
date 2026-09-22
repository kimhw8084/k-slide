"""Render user-facing reports without asking the model to rewrite canonical state."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..conflicts import ConflictAssessmentState, ConflictResolutionState, conflict_assessment_status, load_conflict_registry, conflict_registry_path
from ..evidence_ir import load_evidence
from ..errors import KSlideError
from ..io import atomic_write_text, read_json
from ..ir import SlideIR
from ..queue import WorkUnitStatus, load_queue
from ..semantics import ProvenanceState
from ..storage import StorageArtifact, storage_path


def _manifest_names(run_dir: Path) -> dict[str, str]:
    try:
        value = read_json(storage_path(run_dir, StorageArtifact.RUN_MANIFEST, "RUN_MANIFEST.json"))
    except (OSError, ValueError, TypeError):
        return {}
    inputs = value.get("inputs", []) if isinstance(value, dict) else []
    names: dict[str, str] = {}
    for index, item in enumerate(inputs, start=1):
        if isinstance(item, dict):
            input_id = f"source-{index:03d}"
            names[input_id] = str(item.get("source_name", input_id))
    return names


def _status(queue: Any) -> str:
    statuses = {unit.status for unit in queue.work_units}
    if WorkUnitStatus.NEEDS_REVIEW in statuses:
        return "NEEDS REVIEW"
    if all(status in {WorkUnitStatus.TRANSLATED, WorkUnitStatus.VERIFIED} for status in statuses) and statuses:
        return "VERIFIED CANDIDATE"
    return "IN PROGRESS"


def _provenance_label(state: Any) -> str:
    state = state.value if isinstance(state, ProvenanceState) else str(state)
    return {
        "source_fact": "SOURCE FACT",
        "supported_interpretation": "SUPPORTED INTERPRETATION",
        "unresolved": "UNRESOLVED",
    }.get(str(state), "UNRESOLVED")


def _semantic_text(text: Any, state: Any, reason: Any = None) -> str:
    state = state.value if isinstance(state, ProvenanceState) else str(state)
    label = _provenance_label(state)
    if str(state) == "unresolved":
        return f"[{label}: {reason or 'Evidence is unresolved.'}]"
    return f"[{label}] {text or '[unreadable]'}"


def _table_markdown(table: Any) -> list[str]:
    lines = [f"#### Table `{table.table_id}`", "", f"Dimensions: `{table.row_count} × {table.column_count}`"]
    if table.header_rows or table.header_columns:
        lines.append(f"Header coordinates: rows `{', '.join(str(value + 1) for value in table.header_rows) or 'none'}`; columns `{', '.join(str(value + 1) for value in table.header_columns) or 'none'}`")
    else:
        lines.append("Header semantics: not proven by native source structure.")
    if table.unit:
        lines.append(f"Unit: `{table.unit}`")
    if table.source_notes:
        lines.append("Source notes / footnotes:")
        lines.extend(f"- {note}" for note in table.source_notes)
    lines.append("")
    if not table.cells:
        return lines + ["_No source cells were extracted._", ""]
    lines.extend(["| Row | Column | Span | Header | Cell state | Source | English | Provenance | Status |", "| ---: | ---: | ---: | --- | --- | --- | --- | --- | --- |"])
    for cell in sorted(table.cells, key=lambda item: (item.row, item.column)):
        status = "unresolved" if cell.unresolved else "translated"
        english = _semantic_text(cell.translation, cell.provenance, cell.unresolved_reason)
        header = "yes" if cell.is_header is True else ("no" if cell.is_header is False else "unknown")
        source = cell.source_text or ""
        lines.append(f"| {cell.row + 1} | {cell.column + 1} | {cell.rowspan}×{cell.colspan} | {header} | {cell.cell_state} | {source} | {english} | {_provenance_label(cell.provenance)} | {status} |")
    lines.append("")
    return lines


def _unit_sections(run_dir: Path, unit: Any, source_name: str) -> tuple[list[str], list[dict[str, Any]], list[dict[str, Any]]]:
    ir_path = storage_path(run_dir, StorageArtifact.CANONICAL_IR, f"ir/{unit.work_unit_id}.json")
    if not ir_path.is_file():
        return [f"## {unit.document_id} — {unit.work_unit_id}", "", "_Translation not submitted yet._", ""], [], []
    evidence = load_evidence(run_dir, unit.work_unit_id)
    slide = SlideIR.from_dict(read_json(ir_path), evidence=evidence)
    lines = [f"## {unit.document_id} — {unit.work_unit_id}", "", f"Source document: `{source_name}`", f"Source index: `{unit.source_index + 1}`", "", "### English Reconstruction", ""]
    for region in sorted(slide.regions, key=lambda item: item.reading_order):
        lines.append(f"- {_semantic_text(region.translation, region.provenance, region.unresolved_reason)}")
    if not slide.regions:
        lines.append("_No text regions were extracted._")
    lines.extend(["", "### Tables", ""])
    for table in slide.tables:
        lines.extend(_table_markdown(table))
    if not slide.tables:
        lines.append("_No tables were extracted._\n")
    lines.extend(["### Visual / Process Meaning", ""])
    relations = slide.visual_relations
    if relations:
        lines.extend(f"- `{relation.relation_id}` ({', '.join(relation.source_element_ids) or 'no explicit elements'}; direction: {relation.direction or 'unknown'}): {_semantic_text(relation.interpretation, relation.provenance, relation.unresolved_reason)}" for relation in relations)
    else:
        context = next((item for item in evidence.visual_elements if item.get("kind") == "context_image"), None)
        lines.append(f"- Whole-work-unit visual context is preserved at `{context.get('path')}`." if context else "- No structured visual relationship was extracted.")
    charts = [item for item in evidence.visual_elements if item.get("kind") == "chart" and isinstance(item.get("chart"), dict)]
    if charts:
        lines.extend(["", "### Source Chart Facts", ""])
        for item in charts:
            chart = item["chart"]
            lines.append(f"- `{item.get('element_id')}`: type `{chart.get('chart_type', 'unknown')}`, title `{chart.get('title') or ''}`, categories `{', '.join(str(value) for value in chart.get('categories', []))}`.")
            if chart.get("axis_labels") or chart.get("unit_labels"):
                lines.append(f"  - Axes/units: {chart.get('axis_labels', {})}; {chart.get('unit_labels', {})}")
            for series in chart.get("series", []):
                points = series.get("points", series.get("values", [])) if isinstance(series, dict) else []
                lines.append(f"  - Series `{series.get('name', '')}`: {points}")
    lines.extend(["", "### Important Korean Business Terms", ""])
    term_lines = [term for region in slide.regions for term in region.term_matches]
    lines.extend(f"- `{term}`" for term in sorted(set(term_lines))) or lines.append("_No termbase matches recorded._")
    lines.extend(["", "### Executive Context", ""])
    claims = slide.executive_semantics.get("executive_claims", [])
    if claims:
        lines.extend(f"- **{_provenance_label(claim.get('provenance'))} · {claim.get('kind', 'other')}**: {_semantic_text(claim.get('text'), claim.get('provenance'), claim.get('unresolved_reason'))} _(uncertainty: {claim.get('uncertainty', 'unknown')}; evidence: {', '.join(claim.get('evidence_ids', []))})_" for claim in claims)
    else:
        lines.append("_No evidence-backed executive claims recorded._")
    unresolved = list(slide.unresolved)
    lines.extend(["", "### Unresolved / Unreadable", ""])
    if unresolved:
        lines.extend(f"- `{item.get('region_id', item.get('cell_id', item.get('relation_id', item.get('claim_id', 'unknown'))))}`: **UNRESOLVED** — {item.get('reason', item.get('unresolved_reason', 'Unresolved source evidence.'))} _(evidence: {', '.join(item.get('evidence_ids', []))})_" for item in unresolved)
    else:
        lines.append("None.")
    lines.extend(["", "### Coverage", "", "| Source ID | Status | Note |", "| --- | --- | --- |"])
    for coverage in slide.coverage:
        lines.append(f"| `{coverage.source_id}` | {coverage.status} | {coverage.note or ''} |")
    lines.append("")
    review_items: list[dict[str, Any]] = []
    for item in unresolved:
        source_id = item.get("region_id") or item.get("cell_id") or item.get("relation_id") or item.get("claim_id")
        region = next((candidate for candidate in evidence.regions if candidate.region_id == source_id), None)
        review_items.append({"work_unit_id": unit.work_unit_id, "source_id": source_id, "reason": item.get("reason") or item.get("unresolved_reason"), "evidence_ids": item.get("evidence_ids", []), "severity": "MAJOR", "crop_path": region.crop_original_path if region else None, "recommended_action": "Review the source crop and submit a targeted repair."})
    return lines, claims, review_items


def _conflict_sections(run_dir: Path) -> tuple[list[str], list[str]]:
    """Render every competing assertion and keep authority metadata separate."""

    path = conflict_registry_path(run_dir)
    if not path.is_file():
        try:
            status = conflict_assessment_status(run_dir)
        except (KSlideError, KeyError, TypeError, ValueError, OSError):
            status = None
        if status == ConflictAssessmentState.NOT_ASSESSED.value:
            return [
                "## Conflict Registry",
                "",
                "Conflict assessment: **NOT_ASSESSED**. A KSA-23 run must complete the typed engine assessment before verification or finalization.",
                "",
            ], []
        return [
            "## Conflict Registry",
            "",
            "Conflict registry: **not present**. Legacy artifacts remain readable; conflict coverage is not assessed and absence is not evidence that no conflicts exist.",
            "",
        ], []
    try:
        registry = load_conflict_registry(run_dir)
    except (KSlideError, KeyError, TypeError, ValueError, OSError):
        return [
            "## Conflict Registry",
            "",
            "Conflict registry: **present but unreadable**. Deterministic verification must repair or review `CONFLICT_REGISTRY.json`.",
            "",
        ], ["Conflict registry present but unreadable."]
    if registry is None:
        return ["## Conflict Registry", "", "Conflict registry: **not present**; conflict coverage is not assessed.", ""], []
    lines = ["## Conflict Registry", "", "Conflict registry: **present**", f"Registry revision: `{registry.registry_revision}`", ""]
    summary: list[str] = []
    if not registry.conflicts:
        lines.extend(["Registry is present and contains no recorded conflicts.", ""])
        return lines, summary
    for conflict in sorted(registry.conflicts, key=lambda item: item.conflict_id):
        state = "UNRESOLVED" if conflict.resolution_state == ConflictResolutionState.UNRESOLVED.value else "RESOLVED BY AUTHORITATIVE SUPERSESSION"
        lines.extend([f"### Conflict `{conflict.conflict_id}` — **{state}**", "", "Every competing assertion is retained:", ""])
        summary.append(f"{conflict.conflict_id}: {state}")
        for participant in sorted(conflict.participants, key=lambda item: item.assertion_id):
            location = participant.location
            location_text = "/".join(
                item for item in (
                    f"document={participant.document_id}",
                    f"work-unit={participant.work_unit_id}",
                    f"slide={location.get('slide_id', participant.work_unit_id)}",
                    f"source={participant.semantic_kind}:{participant.semantic_id}",
                    f"table={location.get('table_id')} row={location.get('row')} column={location.get('column')}" if location.get("table_id") is not None else None,
                ) if item is not None
            )
            source = participant.source_context
            rendered = participant.rendered_context
            lines.extend([
                f"- Assertion `{participant.assertion_id}` — {location_text}",
                f"  - Provenance: **{_provenance_label(participant.provenance)}**; evidence: `{', '.join(participant.provenance_evidence_ids)}`",
                f"  - Source ({source.get('language') or 'unknown'}): `{source.get('text', '')}`",
                f"  - Rendered English: `{rendered.get('text', '')}`",
                f"  - Canonical: `{participant.canonical_ref.get('path')}#{participant.canonical_ref.get('json_pointer')}`; SHA-256 `{participant.canonical_ref.get('canonical_sha256')}`",
                f"  - Evidence: `{participant.evidence_ref.get('path')}` revision `{participant.evidence_ref.get('evidence_revision')}`",
            ])
        supersessions = [item for item in registry.supersessions if item.conflict_id == conflict.conflict_id]
        lines.extend(["", "Authoritative supersession (metadata only; no competing assertion is deleted or rewritten):", ""])
        if supersessions:
            for supersession in sorted(supersessions, key=lambda item: item.supersession_id):
                evidence_ids = "; ".join(", ".join(ref.evidence_ids) for ref in supersession.authority_evidence)
                basis = f"configured authority `{supersession.authority_config_id}`" if supersession.authority_basis == "configured_authority" else f"explicit evidence `{evidence_ids}`"
                lines.append(f"- `{supersession.superseding_assertion_id}` supersedes `{supersession.superseded_assertion_id}` — **{supersession.state}**, basis: {basis}.")
        else:
            lines.append("- None recorded; authority remains unknown and the conflict remains unresolved.")
        lines.append("")
    return lines, summary


def render_run(run_dir: Path) -> dict[str, str]:
    queue = load_queue(run_dir)
    names = _manifest_names(run_dir)
    final_lines = ["# K-Slide English Reconstruction", "", f"Status: **{_status(queue)}**", f"Run: `{queue.run_id}`", f"Work units: `{len(queue.work_units)}`", ""]
    brief_lines = ["# K-Slide Executive Brief", "", f"Status: **{_status(queue)}**", ""]
    review_items: list[dict[str, Any]] = []
    all_claims: list[dict[str, Any]] = []
    for unit in sorted(queue.work_units, key=lambda item: (item.document_id, item.source_index, item.work_unit_id)):
        sections, claims, unresolved = _unit_sections(run_dir, unit, names.get(unit.source_input_id, unit.source_input_id))
        final_lines.extend(sections)
        all_claims.extend([{**claim, "work_unit_id": unit.work_unit_id} for claim in claims])
        review_items.extend(unresolved)
    conflict_lines, conflict_summary = _conflict_sections(run_dir)
    final_lines.extend(conflict_lines)
    final_lines.extend(["## Coverage Summary", "", f"Translated/processed work units: `{sum(unit.status in {WorkUnitStatus.TRANSLATED, WorkUnitStatus.VERIFIED} for unit in queue.work_units)}` / `{len(queue.work_units)}`", f"Review items: `{len(review_items)}`", ""])
    for claim in all_claims:
        brief_lines.append(f"- **{_provenance_label(claim.get('provenance'))} · {claim.get('kind', 'other')}** ({claim.get('work_unit_id')}): {_semantic_text(claim.get('text'), claim.get('provenance'), claim.get('unresolved_reason'))} _(evidence: {', '.join(claim.get('evidence_ids', []))})_")
    if not all_claims:
        brief_lines.append("No evidence-backed executive claims are available yet.")
    brief_lines.extend(["", "## Conflicts and authoritative supersession", ""])
    if conflict_summary:
        brief_lines.extend(f"- {item}" for item in conflict_summary)
    elif conflict_registry_path(run_dir).is_file():
        brief_lines.append("Conflict registry is present and contains no recorded conflicts.")
    else:
        brief_lines.append("Conflict registry is not present; conflict coverage is not assessed and absence is not evidence that no conflicts exist.")
    unresolved_lines = ["# K-Slide Unresolved Items", ""]
    if not review_items:
        unresolved_lines.append("No unresolved items.")
    else:
        for item in review_items:
            unresolved_lines.extend([f"## {item['work_unit_id']} — `{item['source_id']}`", "", "- Provenance: **UNRESOLVED**", f"- Evidence: {', '.join(item.get('evidence_ids', [])) or '[missing]' }", f"- Severity: {item['severity']}", f"- Reason: {item['reason']}", f"- Crop: `{item.get('crop_path') or '[not available]'}`", f"- Recommended action: {item['recommended_action']}", ""])
    atomic_write_text(storage_path(run_dir, StorageArtifact.REPORT, "05_final_report.md", create_parent=True), "\n".join(final_lines) + "\n")
    atomic_write_text(storage_path(run_dir, StorageArtifact.REPORT, "05_executive_brief.md", create_parent=True), "\n".join(brief_lines) + "\n")
    atomic_write_text(storage_path(run_dir, StorageArtifact.REPORT, "07_unresolved_items.md", create_parent=True), "\n".join(unresolved_lines) + "\n")
    return {"final_report": str(storage_path(run_dir, StorageArtifact.REPORT, "05_final_report.md")), "executive_brief": str(storage_path(run_dir, StorageArtifact.REPORT, "05_executive_brief.md")), "unresolved": str(storage_path(run_dir, StorageArtifact.REPORT, "07_unresolved_items.md"))}
