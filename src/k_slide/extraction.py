"""Build immutable EvidenceIR from normalized renders and native extraction."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .documents import NormalizationResult
from .errors import ErrorCode, KSlideError
from .evidence_ir import EvidenceIR, EvidenceRegion, EvidenceTable, EvidenceTableCell, save_evidence
from .io import atomic_write_json, atomic_write_text, read_json
from .locking import run_lock
from .normalization import _load_normalization_result
from .numeric import extract_numeric_facts
from .fusion import fuse_literal_evidence
from .ocr.policy import OCRProviderPolicy, OCRProviderSelection, create_ocr_provider, load_ocr_policy
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
    items = native_items or [{"source_id": f"{unit.work_unit_id}-region-001", "text": None, "bbox_px": [0, 0, width, height], "region_type": "IMAGE", "evidence_source": "visual"}]
    items = sorted(items, key=lambda item: (int((item.get("bbox_px") or [0, 0, 0, 0])[1]), int((item.get("bbox_px") or [0, 0, 0, 0])[0]), str(item.get("source_id", ""))))
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
        native_source = item.get("evidence_source", "native") == "native"
        native_candidates = ({"text": str(text), "confidence": 1.0, "source": "native"},) if text and native_source else ()
        normalized = (crop_box[0] / width, crop_box[1] / height, crop_box[2] / width, crop_box[3] / height)
        regions.append(EvidenceRegion(region_id=region_id, bbox_px=crop_box, bbox_normalized=normalized, reading_order=order, region_type=str(item.get("region_type", "TEXT" if text else "IMAGE")), native_text_candidates=native_candidates, selected_literal_candidate=str(text) if text and native_source else None, literal_confidence=1.0 if text and native_source else None, language="ko" if text else None, crop_original_path=str(original_path.relative_to(run_dir)), crop_model_path=str(model_path.relative_to(run_dir)), required_for_translation=True))
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


def _tables(unit: Any, native_items: list[dict[str, Any]]) -> tuple[tuple[EvidenceTable, ...], list[dict[str, Any]]]:
    tables: list[EvidenceTable] = []
    facts: list[dict[str, Any]] = []
    for item in native_items:
        table_value = item.get("table")
        if not isinstance(table_value, dict):
            continue
        table_id = f"{item.get('source_id', f'{unit.work_unit_id}-table-001')}-table"
        raw_cells = [cell for cell in table_value.get("cells", []) if isinstance(cell, dict) and "cell_id" in cell]
        cell_values: list[EvidenceTableCell] = []
        for cell in raw_cells:
            cell_id = str(cell["cell_id"])
            cell_facts = extract_numeric_facts(cell.get("text"), source_object_id=cell_id, source_table_id=table_id, source_cell_id=cell_id)
            facts.extend(cell_facts)
            cell_values.append(EvidenceTableCell(cell_id=cell_id, row=int(cell["row"]), column=int(cell["column"]), rowspan=int(cell.get("rowspan", 1) or 1), colspan=int(cell.get("colspan", 1) or 1), source_text=cell.get("text"), numeric_fact_ids=tuple(item["fact_id"] for item in cell_facts), required_for_translation=True))
        cells = tuple(cell_values)
        tables.append(EvidenceTable(table_id=table_id, row_count=int(table_value.get("row_count", 0)), column_count=int(table_value.get("column_count", 0)), cells=cells))
    return tuple(tables), facts


def _extract_run_locked(run_dir: Path, *, ocr_provider: Any | None = None, ocr_policy: OCRProviderPolicy | str | None = None) -> list[EvidenceIR]:
    with run_lock(run_dir):
        state = load_state(run_dir)
        if state.phase not in {RunPhase.NORMALIZED, RunPhase.EXTRACTING, RunPhase.EXTRACTED}:
            raise KSlideError(ErrorCode.INVALID_TRANSITION, "Run is not ready for evidence extraction.", {"phase": state.phase.value})
        if state.phase is RunPhase.EXTRACTED:
            queue = load_queue(run_dir)
            cached: list[EvidenceIR] = []
            try:
                for unit in queue.work_units:
                    cached.append(load_evidence(run_dir, unit.work_unit_id))
                if cached and len(cached) == len(queue.work_units):
                    return cached
            except (KSlideError, OSError, ValueError):
                pass
        if state.phase != RunPhase.EXTRACTING:
            state.transition(RunPhase.EXTRACTING, next_action="Generate immutable source EvidenceIR")
            save_state(run_dir, state)
        normalized = _load_normalization_result(run_dir)
        if ocr_provider is not None:
            selection = OCRProviderSelection(
                requested="explicit",
                effective=getattr(ocr_provider, "name", "custom"),
                version=str(getattr(ocr_provider, "version", "unknown")),
                provider=ocr_provider,
            )
        else:
            requested_policy = ocr_policy or load_ocr_policy(run_dir.parents[1])
            try:
                selection = create_ocr_provider(requested_policy)
            except KSlideError as exc:
                atomic_write_json(
                    run_dir / "OCR_METADATA.json",
                    {
                        "ocr_policy_requested": str(getattr(requested_policy, "value", requested_policy)),
                        "ocr_provider_effective": None,
                        "ocr_provider_version": None,
                        "ocr_reason": exc.code.value,
                    },
                    mode=0o600,
                )
                raise
        provider = selection.provider
        atomic_write_json(run_dir / "OCR_METADATA.json", selection.as_dict(), mode=0o600)
        evidence_values: list[EvidenceIR] = []
        queue = load_queue(run_dir)
        for document in normalized.documents:
            for unit in document.units:
                native_items = _unit_native(run_dir, unit)
                try:
                    ocr_result = provider.extract(run_dir / unit.canonical_render_path)
                except KSlideError:
                    raise
                except (OSError, ValueError) as exc:
                    raise KSlideError(ErrorCode.OCR_UNAVAILABLE, "Configured OCR provider failed.", {"work_unit_id": unit.work_unit_id, "reason": str(exc)}) from exc
                if not native_items and ocr_result.regions:
                    native_items = [
                        {
                            "source_id": f"{unit.work_unit_id}-ocr-{index:04d}",
                            "text": region.text,
                            "bbox_px": list(region.bbox_px),
                            "region_type": str(region.metadata.get("region_type", "TEXT")),
                            "evidence_source": "ocr",
                        }
                        for index, region in enumerate(sorted(ocr_result.regions, key=lambda item: (item.bbox_px[1], item.bbox_px[0], item.reading_order)), start=1)
                        if region.text.strip()
                    ]
                regions = _crop_regions(run_dir, unit, native_items)
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
                tables, table_facts = _tables(unit, native_items)
                facts.extend(table_facts)
                required_source_ids = [region.region_id for region in regions]
                required_source_ids.extend(table.table_id for table in tables)
                required_source_ids.extend(cell.cell_id for table in tables for cell in table.cells if cell.required_for_translation)
                context_id = f"{unit.work_unit_id}-visual-context"
                visual_values: list[dict[str, Any]] = [{"element_id": context_id, "kind": "context_image", "path": unit.canonical_render_path, "sha256": unit.render_sha256, "bbox_px": [0, 0, unit.width_px, unit.height_px], "required": True}]
                for native_item in native_items:
                    chart = native_item.get("chart") if isinstance(native_item, dict) else None
                    if isinstance(chart, dict) and native_item.get("source_id"):
                        visual_values.append({"element_id": f"{native_item['source_id']}-chart", "kind": "chart", "source_id": native_item["source_id"], "chart": chart, "bbox_px": list(native_item.get("bbox_px", [0, 0, unit.width_px, unit.height_px])), "required": True})
                visual_elements = tuple(visual_values)
                required_source_ids.append(context_id)
                source = {"input_id": unit.input_id, "document_id": document.document_id, "input_sha256": document.source_sha256, "page_or_slide_index": unit.source_index, "width_px": unit.width_px, "height_px": unit.height_px, "canonical_render_sha256": unit.render_sha256, "canonical_render_path": unit.canonical_render_path, "context_image_path": unit.canonical_render_path, "context_image_sha256": unit.render_sha256, "ocr_policy_requested": selection.requested, "ocr_provider_effective": selection.effective, "ocr_provider_version": selection.version}
                evidence = EvidenceIR(document.document_id, unit.work_unit_id, source, tuple(regions), tables, tuple(facts), visual_elements, tuple(unit.native_evidence), tuple(required_source_ids)).with_revision()
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
        atomic_write_json(run_dir / "metrics.json", {"work_unit_count": len(evidence_values), "regions_detected": sum(len(item.regions) for item in evidence_values), "native_regions": sum(sum(1 for region in item.regions if region.native_text_candidates) for item in evidence_values), "numeric_facts": sum(len(item.numeric_facts) for item in evidence_values), "ocr_policy_requested": selection.requested, "ocr_provider": provider.name, "ocr_provider_effective": selection.effective, "ocr_provider_version": selection.version, "ocr_reason": selection.reason}, mode=0o600)
        return evidence_values


def extract_run(run_dir: Path, *, ocr_provider: Any | None = None, ocr_policy: OCRProviderPolicy | str | None = None) -> list[EvidenceIR]:
    """Run extraction and leave a resumable, fail-closed failure record."""

    try:
        return _extract_run_locked(run_dir, ocr_provider=ocr_provider, ocr_policy=ocr_policy)
    except Exception as exc:
        try:
            with run_lock(run_dir):
                state = load_state(run_dir)
                if state.phase is RunPhase.EXTRACTING:
                    code = exc.code.value if isinstance(exc, KSlideError) else ErrorCode.NORMALIZATION_FAILED.value
                    message = exc.message if isinstance(exc, KSlideError) else "Evidence extraction failed safely."
                    state.transition(RunPhase.FAILED_EXTRACTION, next_action="Fix the extraction capability or source file and retry", error_code=code, error_message=message)
                    save_state(run_dir, state)
                    details = exc.as_dict() if isinstance(exc, KSlideError) else {"code": code, "message": message, "details": {"reason": str(exc)}}
                    atomic_write_json(run_dir / "evidence" / "EXTRACTION_ERROR.json", details, mode=0o600)
                    atomic_write_text(run_dir / "RUN_FAILED.md", f"# FAILED\n\n{message}\n\nError code: `{code}`\n")
        except (KSlideError, OSError):
            pass
        raise
