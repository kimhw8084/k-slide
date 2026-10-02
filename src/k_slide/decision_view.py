"""Deterministic Decision View and host presentation artifacts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .conflicts import ConflictAssessmentState, ConflictResolutionState, conflict_assessment_status, conflict_registry_path, load_conflict_registry
from .evidence_ir import load_evidence
from .errors import KSlideError
from .io import atomic_write_json, atomic_write_text, read_json
from .ir import SlideIR
from .queue import load_queue
from .storage import StorageArtifact, storage_path


DECISION_VIEW_SCHEMA_VERSION = "1.0"
PRESENTATION_DESCRIPTOR_SCHEMA_VERSION = "1.0"
EVIDENCE_DRILLDOWN_SCHEMA_VERSION = "1.0"

SECTION_KINDS: dict[str, frozenset[str]] = {
    "key_takeaway": frozenset({"takeaway"}),
    "decisions_and_asks": frozenset({"decision_status", "decision_or_ask", "next_step"}),
    "key_numbers": frozenset({"key_number"}),
    "risks_and_dependencies": frozenset({"risk", "dependency"}),
    "timing_and_owners": frozenset({"timing", "owner"}),
}


def _run_relative_path(run_dir: Path, value: Any) -> str | None:
    if isinstance(value, Path):
        candidate = value
    elif isinstance(value, str) and value.strip():
        candidate = Path(value)
    else:
        return None
    if not candidate.is_absolute():
        candidate = run_dir / candidate
    try:
        resolved = candidate.resolve(strict=False)
        return resolved.relative_to(run_dir.resolve()).as_posix()
    except (OSError, ValueError):
        return None


def _source_name_map(run_dir: Path) -> dict[str, str]:
    try:
        manifest = read_json(storage_path(run_dir, StorageArtifact.RUN_MANIFEST, "RUN_MANIFEST.json"))
    except (KSlideError, OSError, ValueError, TypeError):
        return {}
    inputs = manifest.get("inputs", []) if isinstance(manifest, dict) else []
    return {
        f"source-{index:03d}": str(item.get("source_name", f"source-{index:03d}"))
        for index, item in enumerate(inputs, start=1)
        if isinstance(item, dict)
    }


def _canonical_state_sha256(run_dir: Path, queue: Any) -> str:
    paths = [
        storage_path(run_dir, StorageArtifact.WORK_QUEUE, "WORK_QUEUE.json"),
        storage_path(run_dir, StorageArtifact.RUN_MANIFEST, "RUN_MANIFEST.json"),
        storage_path(run_dir, StorageArtifact.VERIFICATION, "verification/summary.json"),
    ]
    for unit in queue.work_units:
        paths.extend((
            storage_path(run_dir, StorageArtifact.EVIDENCE_IR, f"evidence/{unit.work_unit_id}.json"),
            storage_path(run_dir, StorageArtifact.CANONICAL_IR, f"ir/{unit.work_unit_id}.json"),
        ))
    registry_path = conflict_registry_path(run_dir)
    if registry_path.is_file():
        paths.append(registry_path)
    state = []
    for path in sorted(set(paths), key=lambda value: value.as_posix()):
        if not path.is_file():
            continue
        relative = _run_relative_path(run_dir, path)
        payload = path.read_bytes()
        state.append({"path": relative or path.name, "sha256": hashlib.sha256(payload).hexdigest()})
    encoded = json.dumps(state, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _verification_snapshot(run_dir: Path) -> dict[str, Any]:
    path = storage_path(run_dir, StorageArtifact.VERIFICATION, "verification/summary.json")
    if not path.is_file():
        return {
            "state": "NOT_RUN",
            "checked_work_units": 0,
            "issue_count": 0,
            "critical_issue_count": 0,
            "unaccounted_count": 0,
            "artifact_path": "verification/summary.json",
        }
    try:
        value = read_json(path)
    except (KSlideError, OSError, ValueError, TypeError):
        value = None
    if not isinstance(value, dict):
        return {
            "state": "INVALID",
            "checked_work_units": 0,
            "issue_count": 0,
            "critical_issue_count": 0,
            "unaccounted_count": 0,
            "artifact_path": "verification/summary.json",
        }
    issues = value.get("issues", [])
    return {
        "state": "PASS" if value.get("status") == "PASS" else "FAIL",
        "checked_work_units": int(value.get("checked_work_units", 0)) if isinstance(value.get("checked_work_units", 0), int) else 0,
        "issue_count": len(issues) if isinstance(issues, list) else 0,
        "critical_issue_count": int(value.get("critical_count", 0)) if isinstance(value.get("critical_count", 0), int) else 0,
        "unaccounted_count": int(value.get("unaccounted_count", 0)) if isinstance(value.get("unaccounted_count", 0), int) else 0,
        "artifact_path": "verification/summary.json",
    }


def _evidence_locations(run_dir: Path, evidence: Any, *, source_name: str, source_index: int) -> dict[str, dict[str, Any]]:
    evidence_path = _run_relative_path(run_dir, storage_path(run_dir, StorageArtifact.EVIDENCE_IR, f"evidence/{evidence.work_unit_id}.json"))
    regions = {item.region_id: item for item in evidence.regions}
    tables = {item.table_id: item for item in evidence.tables}
    cells = {cell.cell_id: (table, cell) for table in evidence.tables for cell in table.cells}
    facts = {str(item.get("fact_id")): item for item in evidence.numeric_facts if isinstance(item, dict) and item.get("fact_id")}
    visual = {
        str(item.get("element_id")): item
        for item in evidence.visual_elements
        if isinstance(item, dict) and item.get("element_id")
    }
    locations: dict[str, dict[str, Any]] = {}

    def add(identifier: str, *, semantic_kind: str, bbox: Any = None, crop: Any = None, detail: str | None = None) -> None:
        region_id = identifier if identifier in regions else None
        if identifier in cells:
            table, cell = cells[identifier]
            bbox = bbox or table.bbox_px
            region_id = next(iter(cell.evidence_region_ids), None)
            detail = detail or f"table {table.table_id}, row {cell.row + 1}, column {cell.column + 1}"
        elif identifier in tables:
            table = tables[identifier]
            bbox = bbox or table.bbox_px
            region_id = next((cell.evidence_region_ids[0] for cell in table.cells if cell.evidence_region_ids), None)
            detail = detail or f"table {table.table_id}"
        elif identifier in facts:
            fact = facts[identifier]
            region_id = fact.get("source_region_id") or None
            if not region_id and fact.get("source_cell_id") in cells:
                _, cell = cells[fact["source_cell_id"]]
                region_id = next(iter(cell.evidence_region_ids), None)
            detail = detail or f"numeric fact {identifier}"
        elif identifier in visual:
            item = visual[identifier]
            region_id = item.get("source_id") or item.get("region_id") or None
            bbox = bbox or item.get("bbox_px") or item.get("bbox")
            detail = detail or f"visual element {identifier}"
        region = regions.get(str(region_id)) if region_id else None
        if region is not None:
            bbox = bbox or region.bbox_px
            crop = crop or region.crop_model_path or region.crop_original_path
            detail = detail or f"region {region.region_id}"
        locations[identifier] = {
            "evidence_id": identifier,
            "human_reference": f"{source_name}, slide {source_index + 1}, {detail or semantic_kind.replace('_', ' ')}",
            "work_unit_id": evidence.work_unit_id,
            "semantic_kind": semantic_kind,
            "evidence_ir_path": evidence_path,
            "bbox_px": list(bbox) if isinstance(bbox, (list, tuple)) else None,
            "crop_path": _run_relative_path(run_dir, crop),
        }

    for region in evidence.regions:
        add(region.region_id, semantic_kind="region", bbox=region.bbox_px, crop=region.crop_model_path or region.crop_original_path)
    for table in evidence.tables:
        add(table.table_id, semantic_kind="table", bbox=table.bbox_px)
        for cell in table.cells:
            add(cell.cell_id, semantic_kind="table_cell", bbox=table.bbox_px)
    for fact in evidence.numeric_facts:
        if isinstance(fact, dict) and fact.get("fact_id"):
            add(str(fact["fact_id"]), semantic_kind="numeric_fact")
    for item in evidence.visual_elements:
        if isinstance(item, dict) and item.get("element_id"):
            add(str(item["element_id"]), semantic_kind="visual_element")
    return locations


def _item_from_claim(claim: dict[str, Any], *, work_unit_id: str, evidence_locations: dict[str, dict[str, Any]]) -> dict[str, Any]:
    evidence_ids = list(dict.fromkeys(str(value) for value in claim.get("evidence_ids", []) if isinstance(value, str)))
    provenance = claim.get("provenance", "unresolved")
    reason = claim.get("unresolved_reason")
    unresolved = provenance == "unresolved" or bool(reason)
    semantic_id = str(claim.get("claim_id", "unknown"))
    return {
        "item_id": f"{work_unit_id}:{semantic_id}",
        "kind": str(claim.get("kind", "other")),
        "text": str(claim.get("text") or ""),
        "provenance": provenance,
        "uncertainty": claim.get("uncertainty", "high" if unresolved else "unknown"),
        "unresolved": unresolved,
        "unresolved_reason": reason,
        "evidence_ids": evidence_ids,
        "source_refs": [evidence_locations.get(value, {
            "evidence_id": value,
            "human_reference": f"Evidence {value} (canonical source link unavailable)",
            "work_unit_id": work_unit_id,
            "semantic_kind": "unknown",
            "evidence_ir_path": None,
            "bbox_px": None,
            "crop_path": None,
        }) for value in evidence_ids],
        "canonical_ref": {"work_unit_id": work_unit_id, "semantic_kind": "executive_claim", "semantic_id": semantic_id},
    }


def _conflict_items(run_dir: Path) -> list[dict[str, Any]]:
    path = conflict_registry_path(run_dir)
    if not path.is_file():
        return []
    try:
        registry = load_conflict_registry(run_dir)
    except Exception:
        return [{
            "item_id": "conflict-registry:unreadable",
            "kind": "conflict_registry",
            "text": "Conflict registry is present but could not be read safely.",
            "provenance": "unresolved",
            "uncertainty": "high",
            "unresolved": True,
            "unresolved_reason": "Conflict registry validation failed.",
            "evidence_ids": [],
            "source_refs": [],
            "canonical_ref": {"artifact_path": _run_relative_path(run_dir, path)},
        }]
    if registry is None:
        return []
    result: list[dict[str, Any]] = []
    for conflict in sorted(registry.conflicts, key=lambda item: item.conflict_id):
        evidence_ids = sorted({
            identifier
            for participant in conflict.participants
            for identifier in participant.provenance_evidence_ids
        })
        unresolved = conflict.resolution_state == ConflictResolutionState.UNRESOLVED.value
        assertions = [
            {
                "assertion_id": participant.assertion_id,
                "work_unit_id": participant.work_unit_id,
                "text": str(participant.rendered_context.get("text", "")),
                "evidence_ids": list(participant.provenance_evidence_ids),
                "canonical_path": _run_relative_path(run_dir, participant.canonical_ref.get("path")),
            }
            for participant in sorted(conflict.participants, key=lambda item: item.assertion_id)
        ]
        result.append({
            "item_id": f"conflict:{conflict.conflict_id}",
            "kind": "conflict",
            "text": "Competing assertions are retained." if unresolved else "Competing assertions remain recorded with authoritative supersession.",
            "provenance": "unresolved" if unresolved else "supported_interpretation",
            "uncertainty": "high" if unresolved else "medium",
            "unresolved": unresolved,
            "unresolved_reason": "Authority has not been established." if unresolved else None,
            "evidence_ids": evidence_ids,
            "source_refs": [{
                "evidence_id": identifier,
                "human_reference": f"Conflict {conflict.conflict_id}, evidence {identifier}",
                "work_unit_id": None,
                "semantic_kind": "conflict_participant",
                "evidence_ir_path": None,
                "bbox_px": None,
                "crop_path": None,
            } for identifier in evidence_ids],
            "canonical_ref": {"artifact_path": _run_relative_path(run_dir, path), "conflict_id": conflict.conflict_id},
            "assertions": assertions,
        })
    return result


def _sections(items_by_unit: list[tuple[str, list[dict[str, Any]]]], queue: Any, source_names: dict[str, str], run_dir: Path, review_items: list[dict[str, Any]]) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    claims: list[dict[str, Any]] = []
    unresolved: list[dict[str, Any]] = []
    document_context: list[dict[str, Any]] = []
    units_by_source: dict[str, list[str]] = {}
    unit_map = {unit.work_unit_id: unit for unit in queue.work_units}
    for work_unit_id, items in items_by_unit:
        unit = unit_map[work_unit_id]
        units_by_source.setdefault(unit.source_input_id, []).append(work_unit_id)
        claims.extend(items)
        unresolved.extend(item for item in items if item["unresolved"])
    for source_id in sorted(units_by_source):
        document_context.append({
            "source_id": source_id,
            "display_name": source_names.get(source_id, source_id),
            "work_units": sorted(units_by_source[source_id]),
            "source_inventory_ref": {"artifact_path": "RUN_MANIFEST.json", "source_id": source_id},
        })
    sections: dict[str, Any] = {
        "material_context": {
            "state": "established" if document_context else "not_established",
            "documents": document_context,
            "work_unit_count": len(queue.work_units),
            "coverage": "available in the English Reconstruction artifact",
        },
    }
    for section, kinds in SECTION_KINDS.items():
        values = [item for item in claims if item["kind"] in kinds]
        sections[section] = {"state": "items_present" if values else "not_established", "items": values}
    unresolved_ids = {item["item_id"] for item in unresolved}
    for review in review_items:
        work_unit_id = str(review.get("work_unit_id", "unknown"))
        source_id = str(review.get("source_id", "unknown"))
        item_id = f"{work_unit_id}:{source_id}"
        if item_id in unresolved_ids:
            continue
        evidence_ids = list(dict.fromkeys(str(value) for value in review.get("evidence_ids", []) if isinstance(value, str)))
        source_name = source_names.get(next((unit.source_input_id for unit in queue.work_units if unit.work_unit_id == work_unit_id), ""), "source")
        evidence_path = _run_relative_path(run_dir, storage_path(run_dir, StorageArtifact.EVIDENCE_IR, f"evidence/{work_unit_id}.json"))
        crop_path = _run_relative_path(run_dir, review.get("crop_path"))
        unresolved.append({
            "item_id": item_id,
            "kind": "unresolved_source_item",
            "text": str(review.get("reason") or "Source evidence is unresolved."),
            "provenance": "unresolved",
            "uncertainty": "high",
            "unresolved": True,
            "unresolved_reason": str(review.get("reason") or "Source evidence is unresolved."),
            "evidence_ids": evidence_ids,
            "source_refs": [{
                "evidence_id": identifier,
                "human_reference": f"{source_name}, {work_unit_id}, evidence {identifier}",
                "work_unit_id": work_unit_id,
                "semantic_kind": "unresolved_source_item",
                "evidence_ir_path": evidence_path,
                "bbox_px": None,
                "crop_path": crop_path,
            } for identifier in evidence_ids],
            "canonical_ref": {"work_unit_id": work_unit_id, "semantic_kind": "unresolved_source_item", "semantic_id": source_id},
        })
        unresolved_ids.add(item_id)
    for unit in queue.work_units:
        if unit.status.value != "NEEDS_REVIEW":
            continue
        item_id = f"{unit.work_unit_id}:work_unit_review"
        if item_id in unresolved_ids:
            continue
        unresolved.append({
            "item_id": item_id,
            "kind": "work_unit_review",
            "text": "This work unit requires human review or explicit repair.",
            "provenance": "unresolved",
            "uncertainty": "high",
            "unresolved": True,
            "unresolved_reason": "The engine work queue marks this work unit NEEDS_REVIEW.",
            "evidence_ids": [],
            "source_refs": [],
            "canonical_ref": {"work_unit_id": unit.work_unit_id, "semantic_kind": "work_unit_status", "semantic_id": "NEEDS_REVIEW"},
        })
        unresolved_ids.add(item_id)
    conflicts = _conflict_items(run_dir)
    if conflicts:
        conflict_state = "conflicts_present"
    else:
        try:
            assessment = conflict_assessment_status(run_dir)
        except (KSlideError, KeyError, TypeError, ValueError, OSError):
            assessment = ConflictAssessmentState.LEGACY_NOT_ASSESSED.value
        conflict_state = "none_recorded" if assessment == ConflictAssessmentState.ASSESSED_ZERO_CONFLICTS.value else "not_assessed"
    sections["conflicts"] = {
        "state": conflict_state,
        "items": conflicts,
    }
    unresolved.extend(item for item in conflicts if item["unresolved"])
    if conflict_state == "not_assessed":
        unresolved.append({
            "item_id": "conflicts:not_assessed",
            "kind": "conflict_assessment",
            "text": "Conflict assessment has not been completed; absence of a registry is not evidence that no conflicts exist.",
            "provenance": "unresolved",
            "uncertainty": "high",
            "unresolved": True,
            "unresolved_reason": "Conflict coverage is not assessed.",
            "evidence_ids": [],
            "source_refs": [],
            "canonical_ref": {"artifact_path": "RUN_MANIFEST.json", "semantic_kind": "conflict_assessment"},
        })
    sections["unresolved_warnings"] = {
        "state": "warnings_present" if unresolved else "none_recorded",
        "items": unresolved,
    }
    return sections, claims, unresolved


def _markdown_view(value: dict[str, Any]) -> str:
    labels = (
        ("material_context", "Material / context"),
        ("key_takeaway", "Key takeaway"),
        ("decisions_and_asks", "Decisions / asks"),
        ("key_numbers", "Key numbers"),
        ("risks_and_dependencies", "Risks / dependencies"),
        ("timing_and_owners", "Timing / owners"),
        ("conflicts", "Competing assertions"),
        ("unresolved_warnings", "Unresolved warnings"),
    )
    verification = value["verification"]
    lines = ["# Decision View", "", f"Contract: `{value['schema_version']}`", "", "## Verification", "", f"- State: **{verification['state']}**", f"- Work units checked: `{verification['checked_work_units']}`", f"- Issues: `{verification['issue_count']}` (critical: `{verification['critical_issue_count']}`; unaccounted: `{verification['unaccounted_count']}`)", ""]
    for key, label in labels:
        section = value["sections"][key]
        lines.extend([f"## {label}", ""])
        if key == "material_context":
            documents = section["documents"]
            if documents:
                for document in documents:
                    lines.append(f"- `{document['display_name']}` — {len(document['work_units'])} work unit(s).")
            else:
                lines.append("Not established.")
        elif key == "conflicts" and section["state"] == "not_assessed":
            lines.append("Conflict coverage has not been assessed.")
        elif section["items"]:
            for item in section["items"]:
                text = item["text"] or item.get("unresolved_reason") or "Unresolved source evidence."
                refs = "; ".join(source["human_reference"] for source in item["source_refs"]) or "canonical conflict record"
                status = " · UNRESOLVED" if item["unresolved"] else ""
                lines.append(f"- {text} ({item['provenance']}; uncertainty: {item['uncertainty']}{status}; source: {refs}).")
        else:
            lines.append("Not established." if section["state"] == "not_established" else "None recorded.")
        lines.append("")
    lines.extend(["## Follow-on artifacts", "", "- Faithful English reconstruction: `05_final_report.md`", "- Review disclosure: `07_unresolved_items.md`", "- Evidence drill-down: `08_evidence_drilldown.json`", ""])
    return "\n".join(lines)


def _build_drilldown(run_dir: Path, queue: Any, source_names: dict[str, str], item_by_unit: dict[str, list[dict[str, Any]]], items: list[dict[str, Any]]) -> dict[str, Any]:
    sources: list[dict[str, Any]] = []
    for unit in sorted(queue.work_units, key=lambda item: (item.document_id, item.source_index, item.work_unit_id)):
        evidence_path = storage_path(run_dir, StorageArtifact.EVIDENCE_IR, f"evidence/{unit.work_unit_id}.json")
        source_name = source_names.get(unit.source_input_id, unit.source_input_id)
        evidence_ids: set[str] = set()
        crops: set[str] = set()
        if evidence_path.is_file():
            evidence = load_evidence(run_dir, unit.work_unit_id)
            locations = _evidence_locations(run_dir, evidence, source_name=source_name, source_index=unit.source_index)
            evidence_ids.update(locations)
            crops.update(value["crop_path"] for value in locations.values() if value.get("crop_path"))
        sources.append({
            "document_id": unit.document_id,
            "work_unit_id": unit.work_unit_id,
            "source_index": unit.source_index,
            "source_name": source_name,
            "evidence_ir_path": _run_relative_path(run_dir, evidence_path),
            "translation_ir_path": _run_relative_path(run_dir, storage_path(run_dir, StorageArtifact.CANONICAL_IR, f"ir/{unit.work_unit_id}.json")),
            "evidence_ids": sorted(evidence_ids),
            "crop_paths": sorted(crops),
            "decision_item_ids": sorted({item["item_id"] for item in item_by_unit.get(unit.work_unit_id, [])}),
        })
    return {
        "schema_version": EVIDENCE_DRILLDOWN_SCHEMA_VERSION,
        "run_id": queue.run_id,
        "sources": sources,
        "items": [
            {
                "item_id": item["item_id"],
                "canonical_ref": item["canonical_ref"],
                "evidence_ids": item["evidence_ids"],
                "source_refs": item["source_refs"],
            }
            for item in items
        ],
    }


def _presentation_descriptor(run_dir: Path, run_id: str, canonical_state_sha256: str) -> dict[str, Any]:
    artifacts = [
        {"action_id": "decision_view", "label": "Decision View", "role": "first_view", "identity": "decision-view.v1", "path": "05_decision_view.md", "html_path": "05_decision_view.html", "structured_path": "05_decision_view.json", "media_type": "text/markdown"},
        {"action_id": "reconstruction", "label": "Faithful English Reconstruction", "role": "follow_on", "identity": "english-reconstruction.v1", "path": "05_final_report.md", "media_type": "text/markdown"},
        {"action_id": "review_disclosure", "label": "Review / Unresolved Disclosure", "role": "follow_on", "identity": "review-disclosure.v1", "path": "07_unresolved_items.md", "media_type": "text/markdown"},
        {"action_id": "evidence_drilldown", "label": "Evidence Drill-down", "role": "follow_on", "identity": "evidence-drilldown.v1", "path": "08_evidence_drilldown.json", "media_type": "application/json"},
    ]
    hashes: dict[str, str] = {}
    for item in artifacts:
        path = storage_path(run_dir, StorageArtifact.REPORT, item["path"])
        if path.is_file():
            item["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    for key, name in (
        ("decision_view_json", "05_decision_view.json"),
        ("decision_view_markdown", "05_decision_view.md"),
        ("decision_view_html", "05_decision_view.html"),
        ("reconstruction", "05_final_report.md"),
        ("review_disclosure", "07_unresolved_items.md"),
        ("evidence_drilldown", "08_evidence_drilldown.json"),
    ):
        path = storage_path(run_dir, StorageArtifact.REPORT, name)
        hashes[key] = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else ""
    return {
        "schema_version": PRESENTATION_DESCRIPTOR_SCHEMA_VERSION,
        "run_id": run_id,
        "canonical_state_sha256": canonical_state_sha256,
        "actions": artifacts,
        "artifact_sha256": hashes,
        "lifecycle_field": "operational_state",
        "semantic_outcome_field": "semantic_outcome",
    }


def render_decision_view(run_dir: Path, *, items_by_unit: list[tuple[str, list[dict[str, Any]]]] | None = None, review_items: list[dict[str, Any]] | None = None) -> dict[str, str]:
    queue = load_queue(run_dir)
    source_names = _source_name_map(run_dir)
    review_items = review_items or []
    if items_by_unit is None:
        items_by_unit = []
        for unit in sorted(queue.work_units, key=lambda item: (item.document_id, item.source_index, item.work_unit_id)):
            ir_path = storage_path(run_dir, StorageArtifact.CANONICAL_IR, f"ir/{unit.work_unit_id}.json")
            if not ir_path.is_file():
                items_by_unit.append((unit.work_unit_id, []))
                continue
            evidence = load_evidence(run_dir, unit.work_unit_id)
            slide = SlideIR.from_dict(read_json(ir_path), evidence=evidence)
            locations = _evidence_locations(run_dir, evidence, source_name=source_names.get(unit.source_input_id, unit.source_input_id), source_index=unit.source_index)
            claims = [
                _item_from_claim(claim, work_unit_id=unit.work_unit_id, evidence_locations=locations)
                for claim in slide.executive_semantics.get("executive_claims", [])
            ]
            items_by_unit.append((unit.work_unit_id, claims))
    sections, _, unresolved = _sections(items_by_unit, queue, source_names, run_dir, review_items)
    canonical_state_sha256 = _canonical_state_sha256(run_dir, queue)
    value = {
        "schema_version": DECISION_VIEW_SCHEMA_VERSION,
        "run_id": queue.run_id,
        "canonical_state_sha256": canonical_state_sha256,
        "verification": _verification_snapshot(run_dir),
        "sections": sections,
        "artifact_contract": {
            "reconstruction": "05_final_report.md",
            "review_disclosure": "07_unresolved_items.md",
            "evidence_drilldown": "08_evidence_drilldown.json",
            "presentation_descriptor": "09_presentation.json",
        },
        "unresolved_warning_count": len(unresolved),
    }
    all_view_items = [
        item
        for section in sections.values()
        if isinstance(section, dict) and isinstance(section.get("items"), list)
        for item in section["items"]
    ]
    item_by_unit: dict[str, list[dict[str, Any]]] = {work_unit_id: [] for work_unit_id, _ in items_by_unit}
    for item in all_view_items:
        work_unit_id = item.get("canonical_ref", {}).get("work_unit_id")
        if isinstance(work_unit_id, str):
            item_by_unit.setdefault(work_unit_id, []).append(item)
    drilldown = _build_drilldown(run_dir, queue, source_names, item_by_unit, all_view_items)
    drilldown["canonical_state_sha256"] = canonical_state_sha256
    drilldown["items"] = [
        {
            "item_id": item["item_id"],
            "canonical_ref": item["canonical_ref"],
            "evidence_ids": item["evidence_ids"],
            "source_refs": item["source_refs"],
        }
        for index, item in enumerate(all_view_items)
        if item["item_id"] not in {candidate["item_id"] for candidate in all_view_items[:index]}
    ]
    view_json = storage_path(run_dir, StorageArtifact.REPORT, "05_decision_view.json", create_parent=True)
    view_markdown = storage_path(run_dir, StorageArtifact.REPORT, "05_decision_view.md", create_parent=True)
    drilldown_path = storage_path(run_dir, StorageArtifact.REPORT, "08_evidence_drilldown.json", create_parent=True)
    presentation_path = storage_path(run_dir, StorageArtifact.REPORT, "09_presentation.json", create_parent=True)
    atomic_write_json(view_json, value, mode=0o600)
    atomic_write_text(view_markdown, _markdown_view(value), mode=0o600)
    atomic_write_json(drilldown_path, drilldown, mode=0o600)
    from .rendering.decision_html import decision_html

    html_path = storage_path(run_dir, StorageArtifact.REPORT, "05_decision_view.html", create_parent=True)
    atomic_write_text(html_path, decision_html(run_dir, value), mode=0o600)
    atomic_write_json(presentation_path, _presentation_descriptor(run_dir, queue.run_id, canonical_state_sha256), mode=0o600)
    return {
        "decision_view": str(view_markdown),
        "decision_view_html": str(html_path),
        "decision_view_contract": str(view_json),
        "evidence_drilldown": str(drilldown_path),
        "presentation_descriptor": str(presentation_path),
    }


def read_presentation(run_dir: Path) -> dict[str, Any]:
    """Return the exact shared engine-owned host presentation descriptor."""

    path = storage_path(run_dir, StorageArtifact.REPORT, "09_presentation.json")
    value = read_json(path)
    queue = load_queue(run_dir)
    if not isinstance(value, dict) or value.get("schema_version") != PRESENTATION_DESCRIPTOR_SCHEMA_VERSION or value.get("run_id") != queue.run_id:
        raise ValueError("Presentation descriptor is missing or has an unsupported version.")
    if value.get("canonical_state_sha256") != _canonical_state_sha256(run_dir, queue):
        raise ValueError("Presentation descriptor is stale for the current canonical run state.")
    expected = _presentation_descriptor(run_dir, queue.run_id, value["canonical_state_sha256"])
    if value != expected:
        raise ValueError("Presentation descriptor or one of its linked artifacts is stale.")
    return value
