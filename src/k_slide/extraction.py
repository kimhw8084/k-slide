"""Build immutable EvidenceIR from normalized renders and native extraction."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .documents import NormalizationResult
from .errors import ErrorCode, KSlideError
from .evidence_ir import EvidenceIR, EvidenceRegion, EvidenceTable, EvidenceTableCell, save_evidence
from .io import atomic_write_json, read_json
from .locking import run_lock
from .normalization import _load_normalization_result
from .numeric import extract_numeric_facts
from .fusion import fuse_literal_evidence
from .ocr.none import NoneOCRProvider
from .queue import WorkUnitStatus, load_queue, save_queue
from .runtime import discover_runtime
from .state import RunPhase, load_state, save_state


def _crop_regions(run_dir: Path, unit: Any, native_items: list[dict[str, Any]]) -> list[EvidenceRegion]:
    try:
        from PIL import Image
    except ImportError as exc:
        raise KSlideError(ErrorCode.IMAGE_DECODE_FAILED, "Pillow is required for deterministic region crops.") from exc
    render_path = run_dir / unit.canonical_render_path
    try:
        image = Image.open(render_path).convert("RGB")
    except Exception as exc:
        raise KSlideError(ErrorCode.IMAGE_DECODE_FAILED, "Normalized render could not be opened for region cropping.", {"work_unit_id": unit.work_unit_id, "reason": str(exc)}) from exc
    width, height = image.size
    regions: list[EvidenceRegion] = []
    items = native_items or [{"source_id": f"{unit.work_unit_id}-region-001", "text": None, "bbox_px": [0, 0, width, height], "region_type": "IMAGE"}]
    for order, item in enumerate(items, start=1):
        bbox = item.get("bbox_px", [0, 0, width, height])
        if len(bbox) != 4:
            bbox = [0, 0, width, height]
        left, top, right, bottom = [max(0, int(value)) for value in bbox]
        right = min(width, max(right, left + 1))
        bottom = min(height, max(bottom, top + 1))
        left = min(left, width - 1)
        top = min(top, height - 1)
        pad_x = max(1, int((right - left) * 0.10))
        pad_y = max(1, int((bottom - top) * 0.10))
        crop_box = (max(0, left - pad_x), max(0, top - pad_y), min(width, right + pad_x), min(height, bottom + pad_y))
        region_id = str(item.get("source_id", f"{unit.work_unit_id}-region-{order:03d}"))
        original_path = run_dir / "regions" / unit.work_unit_id / f"{region_id}.png"
        model_path = run_dir / "regions" / unit.work_unit_id / f"{region_id}-model.png"
        original_path.parent.mkdir(parents=True, exist_ok=True)
        crop = image.crop(crop_box)
        crop.save(original_path, format="PNG")
        model_crop = crop
        if max(crop.size) < 900:
            scale = 900 / max(crop.size)
            model_crop = crop.resize((max(1, int(crop.width * scale)), max(1, int(crop.height * scale))), Image.Resampling.LANCZOS)
        model_crop.save(model_path, format="PNG")
        text = item.get("text")
        native_candidates = ({"text": str(text), "confidence": 1.0, "source": "native"},) if text else ()
        normalized = (crop_box[0] / width, crop_box[1] / height, crop_box[2] / width, crop_box[3] / height)
        regions.append(EvidenceRegion(region_id=region_id, bbox_px=crop_box, bbox_normalized=normalized, reading_order=order, region_type=str(item.get("region_type", "TEXT" if text else "IMAGE")), native_text_candidates=native_candidates, selected_literal_candidate=str(text) if text else None, literal_confidence=1.0 if text else None, language="ko" if text else None, crop_original_path=str(original_path.relative_to(run_dir)), crop_model_path=str(model_path.relative_to(run_dir)), required_for_translation=True))
    return regions


def _unit_native(run_dir: Path, unit: Any) -> list[dict[str, Any]]:
    path = run_dir / unit.native_evidence_path
    if not path.is_file():
        return []
    value = read_json(path)
    if isinstance(value, dict) and isinstance(value.get("objects"), list):
        return [item for item in value["objects"] if isinstance(item, dict)]
    if isinstance(value, dict) and isinstance(value.get("blocks"), list):
        items: list[dict[str, Any]] = []
        for block in value["blocks"]:
            if block.get("type") != 0:
                continue
            lines = block.get("lines", [])
            text = "\n".join(span.get("text", "") for line in lines for span in line.get("spans", []))
            if text.strip():
                bbox = block.get("bbox", [0, 0, 1, 1])
                if unit.render_dpi:
                    scale = float(unit.render_dpi) / 72.0
                    bbox = [round(float(value) * scale) for value in bbox]
                items.append({"source_id": f"{unit.work_unit_id}-block-{len(items) + 1:03d}", "text": text, "bbox_px": bbox, "region_type": "BODY_TEXT"})
        return items
    if isinstance(value, dict) and isinstance(value.get("regions"), list):
        return [item for item in value["regions"] if isinstance(item, dict)]
    return []


def _tables(unit: Any, native_items: list[dict[str, Any]]) -> tuple[EvidenceTable, ...]:
    tables: list[EvidenceTable] = []
    for item in native_items:
        table_value = item.get("table")
        if not isinstance(table_value, dict):
            continue
        table_id = f"{item.get('source_id', f'{unit.work_unit_id}-table-001')}-table"
        cells = tuple(EvidenceTableCell(cell_id=str(cell["cell_id"]), row=int(cell["row"]), column=int(cell["column"]), source_text=cell.get("text"), required_for_translation=True) for cell in table_value.get("cells", []) if isinstance(cell, dict) and "cell_id" in cell)
        tables.append(EvidenceTable(table_id=table_id, row_count=int(table_value.get("row_count", 0)), column_count=int(table_value.get("column_count", 0)), cells=cells))
    return tuple(tables)


def extract_run(run_dir: Path, *, ocr_provider: Any | None = None) -> list[EvidenceIR]:
    with run_lock(run_dir):
        state = load_state(run_dir)
        if state.phase not in {RunPhase.NORMALIZED, RunPhase.EXTRACTING, RunPhase.EXTRACTED}:
            raise KSlideError(ErrorCode.INVALID_TRANSITION, "Run is not ready for evidence extraction.", {"phase": state.phase.value})
        if state.phase != RunPhase.EXTRACTING:
            state.transition(RunPhase.EXTRACTING, next_action="Generate immutable source EvidenceIR")
            save_state(run_dir, state)
        normalized = _load_normalization_result(run_dir)
        provider = ocr_provider or NoneOCRProvider()
        evidence_values: list[EvidenceIR] = []
        queue = load_queue(run_dir)
        for document in normalized.documents:
            for unit in document.units:
                native_items = _unit_native(run_dir, unit)
                regions = _crop_regions(run_dir, unit, native_items)
                try:
                    ocr_result = provider.extract(run_dir / unit.canonical_render_path)
                except KSlideError:
                    raise
                except (OSError, ValueError) as exc:
                    raise KSlideError(ErrorCode.OCR_UNAVAILABLE, "Configured OCR provider failed.", {"work_unit_id": unit.work_unit_id, "reason": str(exc)}) from exc
                ocr_by_region: dict[str, list[dict[str, Any]]] = {region.region_id: [] for region in regions}
                for ocr_region in ocr_result.regions:
                    for region in regions:
                        if ocr_region.bbox_px[2] > region.bbox_px[0] and ocr_region.bbox_px[0] < region.bbox_px[2] and ocr_region.bbox_px[3] > region.bbox_px[1] and ocr_region.bbox_px[1] < region.bbox_px[3]:
                            ocr_by_region[region.region_id].append({"text": ocr_region.text, "confidence": ocr_region.confidence, "bbox_px": list(ocr_region.bbox_px), "provider": ocr_result.provider})
                fused_regions: list[EvidenceRegion] = []
                facts: list[dict[str, Any]] = []
                for region in regions:
                    candidates = ocr_by_region[region.region_id]
                    selected, confidence, evidence_state = fuse_literal_evidence(list(region.native_text_candidates), candidates)
                    updated = EvidenceRegion(**{**region.__dict__, "ocr_candidates": tuple(candidates), "selected_literal_candidate": selected, "literal_confidence": confidence, "evidence_state": evidence_state})
                    fused_regions.append(updated)
                regions = fused_regions
                for region in regions:
                    facts.extend(extract_numeric_facts(region.selected_literal_candidate, source_region_id=region.region_id))
                fact_ids = {fact["fact_id"] for fact in facts}
                regions = [EvidenceRegion(**{**region.__dict__, "numeric_fact_ids": tuple(fact_id for fact_id in fact_ids if fact_id.startswith(region.region_id + "-"))}) for region in regions]
                tables = _tables(unit, native_items)
                required_source_ids = [region.region_id for region in regions]
                required_source_ids.extend(table.table_id for table in tables)
                required_source_ids.extend(cell.cell_id for table in tables for cell in table.cells if cell.required_for_translation)
                evidence = EvidenceIR(document.document_id, unit.work_unit_id, {"input_id": unit.input_id, "input_sha256": document.source_sha256, "page_or_slide_index": unit.source_index, "width_px": unit.width_px, "height_px": unit.height_px, "canonical_render_sha256": unit.render_sha256, "canonical_render_path": unit.canonical_render_path}, tuple(regions), tables, tuple(facts), (), tuple(unit.native_evidence), tuple(required_source_ids)).with_revision()
                save_evidence(run_dir, evidence)
                evidence_values.append(evidence)
                queue_unit = queue.get(unit.work_unit_id)
                queue_unit.status = WorkUnitStatus.READY
                queue_unit.evidence_revision = evidence.evidence_revision
                queue_unit.updated_at = state.updated_at
                queue_unit.revision += 1
        save_queue(run_dir, queue)
        state = load_state(run_dir)
        state.current_work_unit = None
        state.transition(RunPhase.EXTRACTED, next_action="Schedule the next bounded translation work unit")
        save_state(run_dir, state)
        atomic_write_json(run_dir / "metrics.json", {"work_unit_count": len(evidence_values), "regions_detected": sum(len(item.regions) for item in evidence_values), "native_regions": sum(sum(1 for region in item.regions if region.native_text_candidates) for item in evidence_values), "numeric_facts": sum(len(item.numeric_facts) for item in evidence_values), "ocr_provider": provider.name}, mode=0o600)
        return evidence_values
