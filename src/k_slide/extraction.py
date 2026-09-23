"""Build immutable EvidenceIR from normalized renders and native extraction."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from .documents import NormalizationResult
from .classification_policy import DEFAULT_CLASSIFICATION
from .environment import RunEnvironmentIdentity
from .errors import ErrorCode, KSlideError
from .evidence_ir import RISKY_LITERAL_STATES, EvidenceIR, EvidenceRegion, EvidenceTable, EvidenceTableCell, save_evidence
from .io import atomic_write_json, atomic_write_text, read_json
from .locking import run_lock
from .normalization import _derive_table_unit, _load_normalization_result, _table_header_cell, _table_unit_labels
from .numeric import extract_numeric_facts
from .fusion import fuse_literal_evidence
from .ocr.policy import OCRProviderPolicy, OCRProviderSelection, create_ocr_provider, load_ocr_policy
from .queue import WorkUnitStatus, load_queue, save_queue
from .runtime import discover_runtime
from .storage import StorageArtifact, storage_path
from .state import RunPhase, load_state, save_state
from .redaction import safe_diagnostic_text_or_placeholder
from .modality import classify_source_language, source_english_spans


CROP_PADDING = 0.10
MODEL_CROP_MIN_DIMENSION = 900


def _crop_regions(run_dir: Path, unit: Any, native_items: list[dict[str, Any]]) -> list[EvidenceRegion]:
    try:
        from PIL import Image
    except ImportError as exc:
        raise KSlideError(ErrorCode.IMAGE_DECODE_FAILED, "Pillow is required for deterministic region crops.") from exc
    render_path = storage_path(run_dir, StorageArtifact.NORMALIZED_RENDER, unit.canonical_render_path)
    try:
        image = Image.open(render_path).convert("RGB")
    except Exception as exc:
        raise KSlideError(ErrorCode.IMAGE_DECODE_FAILED, "Normalized render could not be opened for region cropping.", {"work_unit_id": unit.work_unit_id, "reason": type(exc).__name__}) from exc
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
        pad_x = max(1, int((right - left) * CROP_PADDING))
        pad_y = max(1, int((bottom - top) * CROP_PADDING))
        crop_box = (max(0, left - pad_x), max(0, top - pad_y), min(width, right + pad_x), min(height, bottom + pad_y))
        region_id = str(item.get("source_id", f"{unit.work_unit_id}-region-{order:03d}"))
        original_path = storage_path(run_dir, StorageArtifact.REGION_CROP, f"regions/{unit.work_unit_id}/{region_id}.png", create_parent=True)
        model_path = storage_path(run_dir, StorageArtifact.REGION_CROP, f"regions/{unit.work_unit_id}/{region_id}-model.png", create_parent=True)
        original_path.parent.mkdir(parents=True, exist_ok=True)
        crop = image.crop(crop_box)
        crop.save(original_path, format="PNG")
        original_path.chmod(0o600)
        model_crop = crop
        if max(crop.size) < MODEL_CROP_MIN_DIMENSION:
            scale = MODEL_CROP_MIN_DIMENSION / max(crop.size)
            model_crop = crop.resize((max(1, int(crop.width * scale)), max(1, int(crop.height * scale))), Image.Resampling.LANCZOS)
        model_crop.save(model_path, format="PNG")
        model_path.chmod(0o600)
        text = item.get("text")
        native_source = item.get("evidence_source", "native") == "native"
        native_candidates = ({"text": str(text), "confidence": 1.0, "source": "native"},) if text and native_source else ()
        normalized = (crop_box[0] / width, crop_box[1] / height, crop_box[2] / width, crop_box[3] / height)
        durable_root = Path(run_dir).resolve()
        literal = str(text) if text is not None and native_source else None
        language = classify_source_language(literal)
        regions.append(EvidenceRegion(region_id=region_id, bbox_px=crop_box, bbox_normalized=normalized, reading_order=order, region_type=str(item.get("region_type", "TEXT" if text else "IMAGE")), native_text_candidates=native_candidates, selected_literal_candidate=literal, literal_confidence=1.0 if literal is not None else None, language=language, source_english_spans=source_english_spans(literal), crop_original_path=str(original_path.relative_to(durable_root)), crop_model_path=str(model_path.relative_to(durable_root)), required_for_translation=True))
    return regions


def _unit_native(run_dir: Path, unit: Any) -> list[dict[str, Any]]:
    path = storage_path(run_dir, StorageArtifact.NATIVE_EXTRACTION, unit.native_evidence_path)
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


def _native_nontext_visual_policy(region_id: str, native_items: list[dict[str, Any]]) -> bool:
    """Recognize only native objects with a separate typed engine representation."""

    item = next((candidate for candidate in native_items if str(candidate.get("source_id", "")) == region_id), None)
    if item is None or str(item.get("text") or "").strip():
        return False
    shape_type = str(item.get("shape_type", "")).casefold()
    if shape_type == "group":
        return any(str(candidate.get("source_id", "")).startswith(region_id + "-") for candidate in native_items)
    if shape_type in {"line", "connector"}:
        return isinstance(item.get("connector"), dict)
    if shape_type == "chart":
        return isinstance(item.get("chart"), dict)
    if shape_type == "table":
        return isinstance(item.get("table"), dict)
    return False


def _bind_table_unit(fact: dict[str, Any], unit: str | None) -> None:
    """Bind a native table unit to otherwise unit-less numeric cell facts."""

    if not unit or fact.get("raw_value") is None:
        return
    normalized = unit.casefold()
    existing_unit = str(fact.get("source_unit") or "").casefold()
    currency_only = existing_unit in {"usd", "krw", "eur", "jpy", "$", "€", "¥", "₩"}
    if existing_unit and not currency_only:
        return
    factor = 1.0
    if "trillion" in normalized or "조" in normalized:
        factor = 10**12
    elif "billion" in normalized:
        factor = 10**9
    elif "억" in normalized:
        factor = 10**8
    elif "million" in normalized or "백만" in normalized:
        factor = 10**6
    elif "thousand" in normalized or "천" in normalized:
        factor = 10**3
    elif "만원" in normalized or re.search(r"(?<![조억])만(?![원])", normalized):
        factor = 10**4
    currency = next((value for value in ("USD", "KRW", "EUR", "JPY") if value.casefold() in normalized), None)
    fact["source_unit"] = unit
    fact["scale_factor"] = float(fact.get("scale_factor") or 1.0) * factor
    fact["canonical_value"] = float(fact["raw_value"]) * fact["scale_factor"]
    if currency:
        fact["currency"] = currency
        fact["semantic_quantity"] = "currency"
    elif "%" in normalized or "percent" in normalized:
        fact["semantic_quantity"] = "percentage_point" if "point" in normalized else "percentage"


def _tables(unit: Any, native_items: list[dict[str, Any]]) -> tuple[tuple[EvidenceTable, ...], list[dict[str, Any]]]:
    tables: list[EvidenceTable] = []
    facts: list[dict[str, Any]] = []
    for item in native_items:
        table_value = item.get("table")
        if not isinstance(table_value, dict):
            continue
        table_id = f"{item.get('source_id', f'{unit.work_unit_id}-table-001')}-table"
        unit_value = table_value.get("unit", table_value.get("units", table_value.get("unit_label")))
        raw_cells = [cell for cell in table_value.get("cells", []) if isinstance(cell, dict) and "cell_id" in cell]
        if isinstance(unit_value, (list, tuple)):
            explicit_units = [str(value).strip() for value in unit_value if str(value).strip()]
            unit_text = explicit_units[0] if len(explicit_units) == 1 else None
        else:
            unit_text = str(unit_value).strip() if isinstance(unit_value, str) and unit_value.strip() else None
        if unit_text and len({value.casefold() for value in _table_unit_labels(unit_text)}) > 1:
            unit_text = None
        if unit_text is None:
            unit_text = _derive_table_unit(table_value, raw_cells)
        row_count = int(table_value.get("row_count", 0))
        column_count = int(table_value.get("column_count", 0))
        expected_coordinates = {(row, column) for row in range(row_count) for column in range(column_count)}
        actual_coordinates = {(cell.get("row"), cell.get("column")) for cell in raw_cells}
        if row_count < 1 or column_count < 1 or len(raw_cells) != row_count * column_count or actual_coordinates != expected_coordinates:
            raise KSlideError(ErrorCode.SCHEMA_INVALID, "Native table extraction did not preserve exact row/column cardinality.", {"table_id": table_id})
        cell_values: list[EvidenceTableCell] = []
        for cell in raw_cells:
            cell_id = str(cell["cell_id"])
            raw_text = cell.get("text")
            is_spanned = bool(cell.get("is_spanned", False))
            is_origin = bool(cell.get("is_merge_origin", False))
            is_blank = False if is_spanned else (bool(cell.get("is_blank", False)) or not isinstance(raw_text, str) or not raw_text.strip())
            text = None if is_spanned else ("" if is_blank else raw_text)
            cell_facts = extract_numeric_facts(text, source_object_id=cell_id, source_table_id=table_id, source_cell_id=cell_id)
            if not _table_header_cell(table_value, cell):
                for fact in cell_facts:
                    _bind_table_unit(fact, unit_text)
            facts.extend(cell_facts)
            state = "merge_continuation" if is_spanned else ("merge_origin" if is_origin else ("blank" if is_blank else str(cell.get("cell_state") or "nonblank")))
            cell_values.append(EvidenceTableCell(
                cell_id=cell_id,
                row=int(cell["row"]),
                column=int(cell["column"]),
                rowspan=int(cell.get("rowspan", 1) or 1),
                colspan=int(cell.get("colspan", 1) or 1),
                source_text=text,
                source_language=classify_source_language(text),
                source_english_spans=source_english_spans(text),
                cell_state=state,
                is_merge_origin=is_origin,
                is_spanned=is_spanned,
                is_blank=is_blank,
                is_header=cell.get("is_header"),
                numeric_fact_ids=tuple(item["fact_id"] for item in cell_facts),
                required_for_translation=True,
            ))
        cells = tuple(cell_values)
        header_rows_value = table_value.get("header_rows", [0] if table_value.get("first_row_header") is True else [])
        header_columns_value = table_value.get("header_columns", [0] if table_value.get("first_column_header") is True else [])
        header_rows = tuple(int(value) for value in header_rows_value if isinstance(value, int) and not isinstance(value, bool))
        header_columns = tuple(int(value) for value in header_columns_value if isinstance(value, int) and not isinstance(value, bool))
        headers_value = table_value.get("headers")
        if not isinstance(headers_value, list):
            headers_value = [cell.get("text") for cell in raw_cells if cell.get("is_header") is True and cell.get("text")]
        headers = tuple(str(value) for value in headers_value if isinstance(value, str))
        notes_value = table_value.get("source_notes", table_value.get("footnotes", table_value.get("notes", [])))
        if isinstance(notes_value, str):
            notes = (notes_value,) if notes_value.strip() else ()
        elif isinstance(notes_value, (list, tuple)):
            notes = tuple(str(value) for value in notes_value if isinstance(value, str) and value.strip())
        else:
            notes = ()
        tables.append(EvidenceTable(table_id=table_id, row_count=row_count, column_count=column_count, headers=headers, header_rows=header_rows, header_columns=header_columns, unit=unit_text, source_notes=notes, cells=cells))
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
                    storage_path(run_dir, StorageArtifact.OCR_METADATA, "OCR_METADATA.json", create_parent=True),
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
        atomic_write_json(storage_path(run_dir, StorageArtifact.OCR_METADATA, "OCR_METADATA.json", create_parent=True), selection.as_dict(), mode=0o600)
        evidence_values: list[EvidenceIR] = []
        queue = load_queue(run_dir)
        run_manifest = read_json(storage_path(run_dir, StorageArtifact.RUN_MANIFEST, "RUN_MANIFEST.json"))
        input_classifications = {
            str(item.get("snapshot_id")): str(item.get("classification", DEFAULT_CLASSIFICATION))
            for item in (run_manifest.get("inputs", []) if isinstance(run_manifest, dict) else [])
            if isinstance(item, dict) and item.get("snapshot_id")
        }
        for document in normalized.documents:
            for unit in document.units:
                native_items = _unit_native(run_dir, unit)
                try:
                    ocr_result = provider.extract(storage_path(run_dir, StorageArtifact.NORMALIZED_RENDER, unit.canonical_render_path))
                except KSlideError:
                    raise
                except (OSError, ValueError) as exc:
                    raise KSlideError(ErrorCode.OCR_UNAVAILABLE, "Configured OCR provider failed.", {"work_unit_id": unit.work_unit_id, "reason": type(exc).__name__}) from exc
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
                    initial_selected = selected
                    initial_evidence_state = evidence_state
                    recovery_attempts = 0
                    recovery_status = "NOT_REQUIRED"
                    recovery_reason = None
                    native_visual_not_applicable = selected is None and _native_nontext_visual_policy(region.region_id, native_items)
                    if evidence_state in RISKY_LITERAL_STATES and not native_visual_not_applicable:
                        recovery_status = "NEEDS_REVIEW"
                        recovery_reason = "No trustworthy literal evidence is available after bounded engine recovery."
                        if region.crop_original_path:
                            recovery_attempts = 1
                            crop_path = storage_path(run_dir, StorageArtifact.REGION_CROP, region.crop_original_path)
                            try:
                                recovery_result = provider.extract(crop_path)
                                try:
                                    from PIL import Image

                                    with Image.open(crop_path) as crop_image:
                                        crop_width, crop_height = crop_image.size
                                except Exception:
                                    crop_width = crop_height = 0
                                crop_sha256 = hashlib.sha256(crop_path.read_bytes()).hexdigest()
                                for item in recovery_result.regions:
                                    text = str(item.text).strip()
                                    if not text:
                                        continue
                                    x0, y0, x1, y1 = item.bbox_px
                                    edge_margin = max(2, int(min(crop_width, crop_height) * 0.005)) if crop_width and crop_height else 2
                                    touches_edge = bool(crop_width and crop_height and (x0 <= edge_margin or y0 <= edge_margin or x1 >= crop_width - edge_margin or y1 >= crop_height - edge_margin))
                                    candidates.append({
                                        "text": text,
                                        "confidence": item.confidence,
                                        "bbox_px": list(item.bbox_px),
                                        "provider": recovery_result.provider,
                                        "provider_version": recovery_result.provider_version,
                                        "recovery_pass": 1,
                                        "crop_sha256": crop_sha256,
                                        "trust_eligible": not touches_edge,
                                        "touches_crop_boundary": touches_edge,
                                    })
                                recovered_selected, recovered_confidence, recovered_state = fuse_literal_evidence(list(region.native_text_candidates), candidates)
                                crop_corroborates_selected = any(
                                    item.get("recovery_pass") == 1
                                    and item.get("trust_eligible", True) is not False
                                    and item.get("text") == recovered_selected
                                    and isinstance(item.get("confidence"), (int, float))
                                    and not isinstance(item.get("confidence"), bool)
                                    and 0.80 <= item["confidence"] <= 1.0
                                    for item in candidates
                                )
                                recovery_state_trusted = recovered_state in {"HIGH_AGREEMENT", "OCR_ONLY"}
                                low_confidence_repeats_exact_literal = initial_evidence_state != "LOW_CONFIDENCE" or recovered_selected == initial_selected
                                if recovery_state_trusted and crop_corroborates_selected and low_confidence_repeats_exact_literal:
                                    selected, confidence, evidence_state = recovered_selected, recovered_confidence, recovered_state
                                    recovery_status = "RECOVERED"
                                    recovery_reason = None
                                else:
                                    recovery_reason = "A bounded crop re-extraction did not produce a trustworthy complete literal."
                            except Exception as exc:
                                recovery_reason = f"A bounded crop re-extraction failed safely ({type(exc).__name__})."
                    updated = EvidenceRegion(**{
                        **region.__dict__,
                        "ocr_candidates": tuple(candidates),
                        "selected_literal_candidate": selected,
                        "literal_confidence": confidence,
                        "evidence_state": evidence_state,
                        "language": classify_source_language(selected),
                        "source_english_spans": source_english_spans(selected),
                        "required_for_translation": not native_visual_not_applicable,
                        "translation_disposition": "NOT_APPLICABLE_NATIVE_VISUAL" if native_visual_not_applicable else "REQUIRED",
                        "disposition_policy": "native-nontext-visual-v1" if native_visual_not_applicable else None,
                        "disposition_evidence_ids": (region.region_id,) if native_visual_not_applicable else (),
                        "recovery_status": recovery_status,
                        "recovery_attempts": recovery_attempts,
                        "recovery_reason": recovery_reason,
                    })
                    fused_regions.append(updated)
                regions = fused_regions
                for region in regions:
                    if region.evidence_state not in RISKY_LITERAL_STATES:
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
                    if not isinstance(native_item, dict) or not native_item.get("source_id"):
                        continue
                    source_id = str(native_item["source_id"])
                    shape_type = str(native_item.get("shape_type", "shape"))
                    kind = "connector" if isinstance(native_item.get("connector"), dict) else ("chart" if isinstance(native_item.get("chart"), dict) else "shape")
                    visual: dict[str, Any] = {
                        "element_id": source_id if kind != "chart" else f"{source_id}-chart",
                        "kind": kind,
                        "source_id": source_id,
                        "shape_type": shape_type,
                        "bbox_px": list(native_item.get("bbox_px", [0, 0, unit.width_px, unit.height_px])),
                        "required": True,
                    }
                    if native_item.get("text") is not None:
                        visual["source_text"] = native_item.get("text")
                    if kind == "chart":
                        visual["chart"] = native_item["chart"]
                    if kind == "connector":
                        visual["connector"] = native_item["connector"]
                    visual_values.append(visual)
                    if kind == "chart":
                        # Preserve the shape identity as a separate stable node
                        # so chart geometry and chart facts cannot be replaced by
                        # a model-authored relation endpoint.
                        visual_values.append({"element_id": source_id, "kind": "shape", "source_id": source_id, "shape_type": shape_type, "bbox_px": list(native_item.get("bbox_px", [0, 0, unit.width_px, unit.height_px])), "required": True})
                visual_elements = tuple(visual_values)
                required_source_ids.append(context_id)
                source = {"input_id": unit.input_id, "document_id": document.document_id, "classification": input_classifications.get(unit.input_id, DEFAULT_CLASSIFICATION), "input_sha256": document.source_sha256, "page_or_slide_index": unit.source_index, "width_px": unit.width_px, "height_px": unit.height_px, "canonical_render_sha256": unit.render_sha256, "canonical_render_path": unit.canonical_render_path, "context_image_path": unit.canonical_render_path, "context_image_sha256": unit.render_sha256, "source_language_policy": "unicode-script-v1", "ocr_policy_requested": selection.requested, "ocr_provider_effective": selection.effective, "ocr_provider_version": selection.version}
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
        atomic_write_json(storage_path(run_dir, StorageArtifact.METRICS, "metrics.json", create_parent=True), {"work_unit_count": len(evidence_values), "regions_detected": sum(len(item.regions) for item in evidence_values), "native_regions": sum(sum(1 for region in item.regions if region.native_text_candidates) for item in evidence_values), "numeric_facts": sum(len(item.numeric_facts) for item in evidence_values), "ocr_policy_requested": selection.requested, "ocr_provider": provider.name, "ocr_provider_effective": selection.effective, "ocr_provider_version": selection.version, "ocr_reason": selection.reason}, mode=0o600)
        return evidence_values


def extract_run(
    run_dir: Path,
    *,
    ocr_provider: Any | None = None,
    ocr_policy: OCRProviderPolicy | str | None = None,
    environment_identity: RunEnvironmentIdentity | None = None,
) -> list[EvidenceIR]:
    """Run extraction and leave a resumable, fail-closed failure record."""

    from .execution import ensure_workspace_environment_compatible

    ensure_workspace_environment_compatible(run_dir, environment_identity=environment_identity)
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
                    details = exc.as_dict() if isinstance(exc, KSlideError) else {"code": code, "message": message, "details": {"reason": type(exc).__name__}}
                    atomic_write_json(storage_path(run_dir, StorageArtifact.EXTRACTION_ERROR, "evidence/EXTRACTION_ERROR.json", create_parent=True), details, mode=0o600)
                    atomic_write_text(storage_path(run_dir, StorageArtifact.FAILURE_MARKER, "RUN_FAILED.md", create_parent=True), f"# FAILED\n\n{safe_diagnostic_text_or_placeholder(message)}\n\nError code: `{code}`\n")
        except (KSlideError, OSError):
            pass
        raise
