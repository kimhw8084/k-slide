"""Render user-facing reports without asking the model to rewrite canonical state."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..evidence_ir import load_evidence
from ..io import atomic_write_text, read_json
from ..ir import SlideIR
from ..queue import WorkUnitStatus, load_queue


def _manifest_names(run_dir: Path) -> dict[str, str]:
    try:
        value = read_json(run_dir / "RUN_MANIFEST.json")
    except (OSError, ValueError, TypeError):
        return {}
    inputs = value.get("inputs", []) if isinstance(value, dict) else []
    names: dict[str, str] = {}
    for index, item in enumerate(inputs, start=1):
        if isinstance(item, dict):
            input_id = f"source-{index:03d}"
            names[input_id] = str(item.get("source_name", item.get("source_path", input_id)))
    return names


def _status(queue: Any) -> str:
    statuses = {unit.status for unit in queue.work_units}
    if WorkUnitStatus.NEEDS_REVIEW in statuses:
        return "NEEDS REVIEW"
    if all(status in {WorkUnitStatus.TRANSLATED, WorkUnitStatus.VERIFIED} for status in statuses) and statuses:
        return "VERIFIED CANDIDATE"
    return "IN PROGRESS"


def _table_markdown(table: Any) -> list[str]:
    lines = [f"#### Table `{table.table_id}`", ""]
    if not table.cells:
        return lines + ["_No source cells were extracted._", ""]
    lines.extend(["| Row | Column | Source | English | Status |", "| ---: | ---: | --- | --- | --- |"])
    for cell in sorted(table.cells, key=lambda item: (item.row, item.column)):
        status = "unresolved" if cell.unresolved else "translated"
        lines.append(f"| {cell.row + 1} | {cell.column + 1} | {cell.source_text or ''} | {cell.translation or ''} | {status} |")
    lines.append("")
    return lines


def _unit_sections(run_dir: Path, unit: Any, source_name: str) -> tuple[list[str], list[dict[str, Any]], list[dict[str, Any]]]:
    ir_path = run_dir / "ir" / f"{unit.work_unit_id}.json"
    if not ir_path.is_file():
        return [f"## {unit.document_id} — {unit.work_unit_id}", "", "_Translation not submitted yet._", ""], [], []
    slide = SlideIR.from_dict(read_json(ir_path))
    evidence = load_evidence(run_dir, unit.work_unit_id)
    lines = [f"## {unit.document_id} — {unit.work_unit_id}", "", f"Source document: `{source_name}`", f"Source index: `{unit.source_index + 1}`", "", "### English Reconstruction", ""]
    for region in sorted(slide.regions, key=lambda item: item.reading_order):
        lines.append(f"- {region.translation or '[unreadable]'}")
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
        lines.extend(f"- {relation.interpretation or '[unresolved visual relationship]'}" for relation in relations)
    else:
        context = next((item for item in evidence.visual_elements if item.get("kind") == "context_image"), None)
        lines.append(f"- Whole-work-unit visual context is preserved at `{context.get('path')}`." if context else "- No structured visual relationship was extracted.")
    lines.extend(["", "### Important Korean Business Terms", ""])
    term_lines = [term for region in slide.regions for term in region.term_matches]
    lines.extend(f"- `{term}`" for term in sorted(set(term_lines))) or lines.append("_No termbase matches recorded._")
    lines.extend(["", "### Executive Context", ""])
    claims = slide.executive_semantics.get("executive_claims", [])
    if claims:
        lines.extend(f"- **{claim.get('kind', 'other')}**: {claim.get('text', '')} _(uncertainty: {claim.get('uncertainty', 'unknown')}; evidence: {', '.join(claim.get('evidence_ids', []))})_" for claim in claims)
    else:
        lines.append("_No evidence-backed executive claims recorded._")
    unresolved = list(slide.unresolved)
    lines.extend(["", "### Unresolved / Unreadable", ""])
    if unresolved:
        lines.extend(f"- `{item.get('region_id', item.get('cell_id', 'unknown'))}`: {item.get('reason', 'Unresolved source evidence.')}" for item in unresolved)
    else:
        lines.append("None.")
    lines.extend(["", "### Coverage", "", "| Source ID | Status | Note |", "| --- | --- | --- |"])
    for coverage in slide.coverage:
        lines.append(f"| `{coverage.source_id}` | {coverage.status} | {coverage.note or ''} |")
    lines.append("")
    review_items: list[dict[str, Any]] = []
    for item in unresolved:
        source_id = item.get("region_id") or item.get("cell_id")
        region = next((candidate for candidate in evidence.regions if candidate.region_id == source_id), None)
        review_items.append({"work_unit_id": unit.work_unit_id, "source_id": source_id, "reason": item.get("reason"), "severity": "MAJOR", "crop_path": region.crop_original_path if region else None, "recommended_action": "Review the source crop and submit a targeted repair."})
    return lines, claims, review_items


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
    final_lines.extend(["## Coverage Summary", "", f"Translated/processed work units: `{sum(unit.status in {WorkUnitStatus.TRANSLATED, WorkUnitStatus.VERIFIED} for unit in queue.work_units)}` / `{len(queue.work_units)}`", f"Review items: `{len(review_items)}`", ""])
    for claim in all_claims:
        brief_lines.append(f"- **{claim.get('kind', 'other')}** ({claim.get('work_unit_id')}): {claim.get('text', '')} _(evidence: {', '.join(claim.get('evidence_ids', []))})_")
    if not all_claims:
        brief_lines.append("No evidence-backed executive claims are available yet.")
    unresolved_lines = ["# K-Slide Unresolved Items", ""]
    if not review_items:
        unresolved_lines.append("No unresolved items.")
    else:
        for item in review_items:
            unresolved_lines.extend([f"## {item['work_unit_id']} — `{item['source_id']}`", "", f"- Severity: {item['severity']}", f"- Reason: {item['reason']}", f"- Crop: `{item.get('crop_path') or '[not available]'}`", f"- Recommended action: {item['recommended_action']}", ""])
    atomic_write_text(run_dir / "05_final_report.md", "\n".join(final_lines) + "\n")
    atomic_write_text(run_dir / "05_executive_brief.md", "\n".join(brief_lines) + "\n")
    atomic_write_text(run_dir / "07_unresolved_items.md", "\n".join(unresolved_lines) + "\n")
    return {"final_report": str(run_dir / "05_final_report.md"), "executive_brief": str(run_dir / "05_executive_brief.md"), "unresolved": str(run_dir / "07_unresolved_items.md")}
