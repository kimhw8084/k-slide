"""Deterministic image/PDF/PPTX normalization with explicit capability failures."""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .documents import DocumentUnit, NormalizationResult, NormalizedDocument
from .errors import ErrorCode, KSlideError
from .evidence_ir import stable_revision
from .io import atomic_write_json, atomic_write_text, read_json
from .locking import run_lock
from .queue import WorkUnit, WorkUnitStatus, WorkQueue, load_queue, save_queue
from .security import sha256_file
from .state import RunPhase, load_state, save_state

RENDER_DPI = 220.0
MAX_IMAGE_PIXELS = 120_000_000
MAX_IMAGE_WIDTH = 20_000
MAX_IMAGE_HEIGHT = 20_000
MAX_DOCUMENTS_PER_RUN = 32
MAX_UNITS_PER_RUN = 500
MAX_PAGES_PER_PDF = 200
MAX_SLIDES_PER_PPTX = 200
MAX_TOTAL_RENDER_PIXELS = 500_000_000
MAX_NORMALIZED_BYTES = 2_000_000_000


def _json_safe(value: Any) -> Any:
    """Keep PDF layout metadata serializable without persisting image bytes."""

    if isinstance(value, bytes):
        return {"byte_length": len(value), "omitted": True}
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items() if key not in {"image", "mask"}}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return value


def _snapshot_inputs(run_dir: Path) -> list[tuple[str, Path, dict[str, Any]]]:
    manifest = read_json(run_dir / "RUN_MANIFEST.json")
    values = manifest.get("inputs", []) if isinstance(manifest, dict) else []
    results: list[tuple[str, Path, dict[str, Any]]] = []
    for index, item in enumerate(values, start=1):
        extension = str(item.get("extension", "")).lower()
        source = next((path for path in (run_dir / "inputs").glob(f"source-{index:03d}.*") if path.is_file()), None)
        if source is None:
            raise KSlideError(ErrorCode.INPUT_NOT_FOUND, "Immutable input snapshot is missing.", {"input_id": f"source-{index:03d}"})
        results.append((f"source-{index:03d}", source, {**item, "extension": extension}))
    return results


def _normalize_image(run_dir: Path, input_id: str, source: Path, index: int, document_id: str) -> list[DocumentUnit]:
    if importlib.util.find_spec("PIL") is None:
        raise KSlideError(ErrorCode.IMAGE_DECODE_FAILED, "Pillow is required to decode and normalize image inputs.", {"input": source.name, "extra": "pip install k-slide"})
    from PIL import Image, ImageOps, UnidentifiedImageError
    DecompressionBombError = getattr(Image, "DecompressionBombError", OSError)

    try:
        with Image.open(source) as image:
            image = ImageOps.exif_transpose(image)
            width, height = image.size
            if width < 1 or height < 1 or width > MAX_IMAGE_WIDTH or height > MAX_IMAGE_HEIGHT or width * height > MAX_IMAGE_PIXELS:
                raise KSlideError(ErrorCode.INPUT_TOO_LARGE, "Decoded image dimensions exceed K-Slide safety limits.", {"width": width, "height": height, "max_pixels": MAX_IMAGE_PIXELS})
            if image.mode not in {"RGB", "RGBA"}:
                image = image.convert("RGBA" if "A" in image.getbands() else "RGB")
            work_unit_id = f"{document_id}-image-0001"
            render = run_dir / "normalized" / f"{work_unit_id}.png"
            image.save(render, format="PNG", optimize=True)
    except KSlideError:
        raise
    except (OSError, UnidentifiedImageError, DecompressionBombError, ValueError) as exc:
        raise KSlideError(ErrorCode.IMAGE_DECODE_FAILED, "Image could not be decoded safely.", {"input": source.name, "reason": str(exc)}) from exc
    native_path = run_dir / "native" / f"{work_unit_id}.json"
    atomic_write_json(native_path, {"provider": "image_decoder", "regions": []}, mode=0o600)
    return [DocumentUnit(work_unit_id, document_id, input_id, index - 1, "image", width, height, str(render.relative_to(run_dir)), sha256_file(render), str(native_path.relative_to(run_dir)), ())]


def _pdf_units(run_dir: Path, input_id: str, source: Path, document_id: str, source_index: int) -> list[DocumentUnit]:
    if importlib.util.find_spec("fitz") is None:
        raise KSlideError(ErrorCode.PDF_RENDER_UNAVAILABLE, "PyMuPDF is required to normalize PDF pages.", {"input": source.name, "extra": "pip install k-slide[pdf]"})
    import fitz

    try:
        document = fitz.open(source)
    except Exception as exc:
        raise KSlideError(ErrorCode.NORMALIZATION_FAILED, "PDF could not be opened.", {"input": source.name, "reason": str(exc)}) from exc
    if document.is_encrypted:
        document.close()
        raise KSlideError(ErrorCode.PDF_ENCRYPTED, "Password-protected PDFs are not accepted by the local normalizer.", {"input": source.name})
    if document.page_count < 1:
        document.close()
        raise KSlideError(ErrorCode.NORMALIZATION_FAILED, "PDF contains no pages.", {"input": source.name})
    if document.page_count > MAX_PAGES_PER_PDF:
        page_count = document.page_count
        document.close()
        raise KSlideError(ErrorCode.RESOURCE_LIMIT, "PDF page count exceeds the configured safety limit.", {"input": source.name, "pages": page_count, "max_pages": MAX_PAGES_PER_PDF})
    units: list[DocumentUnit] = []
    try:
        for page_index in range(document.page_count):
            page = document.load_page(page_index)
            rect = page.rect
            matrix = fitz.Matrix(RENDER_DPI / 72.0, RENDER_DPI / 72.0)
            pixmap = page.get_pixmap(matrix=matrix, alpha=False)
            work_unit_id = f"{document_id}-page-{page_index + 1:04d}"
            render = run_dir / "normalized" / f"{work_unit_id}.png"
            pixmap.save(str(render))
            native = page.get_text("dict")
            native_path = run_dir / "native" / f"{work_unit_id}.json"
            safe_blocks = _json_safe(native.get("blocks", []))
            atomic_write_json(native_path, {"provider": "pymupdf", "page_index": page_index, "blocks": safe_blocks}, mode=0o600)
            units.append(DocumentUnit(work_unit_id, document_id, input_id, page_index, "page", pixmap.width, pixmap.height, str(render.relative_to(run_dir)), sha256_file(render), str(native_path.relative_to(run_dir)), tuple(safe_blocks), RENDER_DPI))
    finally:
        document.close()
    return units


def _shape_bbox(shape: Any, width_emu: int, height_emu: int, width_px: int, height_px: int) -> tuple[int, int, int, int]:
    """Map PPTX EMU geometry into the canonical render pixel space."""

    x = round(int(getattr(shape, "left", 0)) / max(width_emu, 1) * width_px)
    y = round(int(getattr(shape, "top", 0)) / max(height_emu, 1) * height_px)
    w = round(int(getattr(shape, "width", width_emu)) / max(width_emu, 1) * width_px)
    h = round(int(getattr(shape, "height", height_emu)) / max(height_emu, 1) * height_px)
    return x, y, max(x + w, x + 1), max(y + h, y + 1)


def _iter_shapes(shapes: Any, prefix: str = "") -> list[tuple[str, Any]]:
    """Traverse grouped PPTX shapes with stable source numbering."""

    result: list[tuple[str, Any]] = []
    for index, shape in enumerate(shapes, start=1):
        source_index = f"{prefix}{index:03d}"
        result.append((source_index, shape))
        children = getattr(shape, "shapes", None)
        if children is not None:
            result.extend(_iter_shapes(children, f"{source_index}-"))
    return result


def _chart_metadata(shape: Any) -> dict[str, Any] | None:
    if not getattr(shape, "has_chart", False):
        return None
    chart = shape.chart
    value: dict[str, Any] = {"chart_type": str(getattr(chart, "chart_type", "unknown"))}
    try:
        value["title"] = chart.chart_title.text_frame.text if chart.has_title else None
    except (AttributeError, ValueError):
        value["title"] = None
    series_values: list[dict[str, Any]] = []
    for series in getattr(chart, "series", []):
        item: dict[str, Any] = {"name": str(getattr(series, "name", ""))}
        try:
            item["values"] = [float(number) if number is not None else None for number in series.values]
        except (AttributeError, TypeError, ValueError):
            item["values"] = []
        series_values.append(item)
    value["series"] = series_values
    try:
        value["categories"] = [str(category) for category in chart.plots[0].categories]
    except (AttributeError, IndexError, TypeError):
        value["categories"] = []
    return value


def _pptx_native(source: Path, run_dir: Path, input_id: str, document_id: str, rendered_pages: list[Path]) -> list[DocumentUnit]:
    if importlib.util.find_spec("pptx") is None:
        raise KSlideError(ErrorCode.NORMALIZATION_FAILED, "python-pptx is required to extract PPTX structure.", {"input": source.name, "extra": "pip install k-slide[pptx]"})
    from pptx import Presentation

    try:
        presentation = Presentation(str(source))
    except Exception as exc:
        raise KSlideError(ErrorCode.NORMALIZATION_FAILED, "PPTX could not be parsed.", {"input": source.name, "reason": str(exc)}) from exc
    slide_width_emu = int(presentation.slide_width)
    slide_height_emu = int(presentation.slide_height)
    units: list[DocumentUnit] = []
    if len(rendered_pages) != len(presentation.slides):
        raise KSlideError(ErrorCode.RENDER_COUNT_MISMATCH, "PPTX render page count does not match slide count.", {"slides": len(presentation.slides), "renders": len(rendered_pages)})
    if len(presentation.slides) > MAX_SLIDES_PER_PPTX:
        raise KSlideError(ErrorCode.RESOURCE_LIMIT, "PPTX slide count exceeds the configured safety limit.", {"input": source.name, "slides": len(presentation.slides), "max_slides": MAX_SLIDES_PER_PPTX})
    for slide_index, slide in enumerate(presentation.slides):
        work_unit_id = f"{document_id}-slide-{slide_index + 1:04d}"
        render = rendered_pages[slide_index]
        try:
            from PIL import Image

            # The rendered PNG dimensions are authoritative for crop geometry.
            with Image.open(render) as rendered_image:
                render_width, render_height = rendered_image.size
        except (ImportError, OSError) as exc:
            raise KSlideError(ErrorCode.PPTX_RENDER_UNAVAILABLE, "Unable to inspect the canonical PPTX render dimensions.", {"input": source.name}) from exc
        objects: list[dict[str, Any]] = []
        for shape_index, shape in _iter_shapes(slide.shapes):
            item: dict[str, Any] = {"source_id": f"{work_unit_id}-shape-{shape_index}", "shape_type": str(getattr(shape, "shape_type", "unknown")), "bbox_px": list(_shape_bbox(shape, slide_width_emu, slide_height_emu, render_width, render_height))}
            if getattr(shape, "has_text_frame", False):
                item["text"] = "\n".join(paragraph.text for paragraph in shape.text_frame.paragraphs)
            if getattr(shape, "has_table", False):
                table = shape.table
                cells = []
                for row_index in range(len(table.rows)):
                    for column_index in range(len(table.columns)):
                        cell = table.cell(row_index, column_index)
                        cells.append({"cell_id": f"{work_unit_id}-table-{shape_index}-r{row_index + 1:02d}-c{column_index + 1:02d}", "row": row_index, "column": column_index, "text": cell.text, "rowspan": int(getattr(cell, "span_height", 1) or 1), "colspan": int(getattr(cell, "span_width", 1) or 1), "is_merge_origin": bool(getattr(cell, "is_merge_origin", False)), "is_spanned": bool(getattr(cell, "is_spanned", False))})
                item["table"] = {"row_count": len(table.rows), "column_count": len(table.columns), "cells": cells}
            chart = _chart_metadata(shape)
            if chart is not None:
                item["chart"] = chart
            objects.append(item)
        native_path = run_dir / "native" / f"{work_unit_id}.json"
        atomic_write_json(native_path, {"provider": "python-pptx", "slide_index": slide_index, "slide_width_px": render_width, "slide_height_px": render_height, "objects": objects}, mode=0o600)
        units.append(DocumentUnit(work_unit_id, document_id, input_id, slide_index, "slide", render_width, render_height, str(render.relative_to(run_dir)), sha256_file(render), str(native_path.relative_to(run_dir)), tuple(objects)))
    return units


def _render_pptx(source: Path, run_dir: Path, document_id: str) -> list[Path]:
    binary = shutil.which("libreoffice") or shutil.which("soffice")
    if not binary:
        raise KSlideError(ErrorCode.PPTX_RENDER_UNAVAILABLE, "LibreOffice/soffice is required to render PPTX slides.", {"input": source.name})
    with tempfile.TemporaryDirectory(prefix="k-slide-office-") as temporary:
        output = Path(temporary) / "out"
        profile = Path(temporary) / "profile"
        output.mkdir()
        profile.mkdir()
        command = [binary, "--headless", f"-env:UserInstallation=file://{profile}", "--convert-to", "pdf", "--outdir", str(output), str(source)]
        try:
            subprocess.run(command, cwd=temporary, env={"PATH": os.environ.get("PATH", ""), "HOME": temporary, "LANG": "C.UTF-8"}, capture_output=True, text=True, timeout=120, check=True)
        except subprocess.TimeoutExpired as exc:
            raise KSlideError(ErrorCode.PPTX_CONVERSION_TIMEOUT, "PPTX rendering timed out.", {"input": source.name}) from exc
        except (OSError, subprocess.CalledProcessError) as exc:
            raise KSlideError(ErrorCode.PPTX_RENDER_UNAVAILABLE, "PPTX could not be rendered by the available Office converter.", {"input": source.name, "reason": str(exc)}) from exc
        pdf = output / f"{source.stem}.pdf"
        if not pdf.is_file():
            raise KSlideError(ErrorCode.PPTX_RENDER_UNAVAILABLE, "PPTX converter produced no PDF output.", {"input": source.name})
        if importlib.util.find_spec("fitz") is None:
            raise KSlideError(ErrorCode.PPTX_RENDER_UNAVAILABLE, "PyMuPDF is required to render converted PPTX pages.", {"input": source.name})
        import fitz
        document = fitz.open(pdf)
        try:
            renders: list[Path] = []
            for index, page in enumerate(document):
                render = run_dir / "normalized" / f"{document_id}-slide-{index + 1:04d}.png"
                page.get_pixmap(matrix=fitz.Matrix(RENDER_DPI / 72, RENDER_DPI / 72), alpha=False).save(str(render))
                renders.append(render)
            return renders
        finally:
            document.close()


def normalize_run(run_dir: Path) -> NormalizationResult:
    """Normalize immutable run inputs and replace the initial queue with document units."""

    with run_lock(run_dir):
        state = load_state(run_dir)
        if state.phase not in {RunPhase.INPUT_VALIDATED, RunPhase.FAILED_NORMALIZATION}:
            if state.phase in {RunPhase.NORMALIZED, RunPhase.EXTRACTED, RunPhase.TRANSLATING, RunPhase.TRANSLATED, RunPhase.VERIFYING, RunPhase.VERIFIED, RunPhase.COMPLETE}:
                return _load_normalization_result(run_dir)
            raise KSlideError(ErrorCode.INVALID_TRANSITION, "Run is not ready for normalization.", {"phase": state.phase.value})
        state.transition(RunPhase.NORMALIZING, next_action="Normalize immutable document inputs")
        save_state(run_dir, state)
        documents: list[NormalizedDocument] = []
        warnings: list[str] = []
        try:
            snapshots = _snapshot_inputs(run_dir)
            if len(snapshots) > MAX_DOCUMENTS_PER_RUN:
                raise KSlideError(ErrorCode.RESOURCE_LIMIT, "Input count exceeds the configured safety limit.", {"documents": len(snapshots), "max_documents": MAX_DOCUMENTS_PER_RUN})
            for input_id, source, metadata in snapshots:
                document_id = f"doc-{input_id.split('-')[-1]}"
                extension = str(metadata.get("extension", source.suffix)).lower()
                if extension in {".png", ".jpg", ".jpeg", ".webp"}:
                    units = _normalize_image(run_dir, input_id, source, int(input_id.split("-")[-1]), document_id)
                elif extension == ".pdf":
                    units = _pdf_units(run_dir, input_id, source, document_id, int(input_id.split("-")[-1]))
                elif extension == ".pptx":
                    rendered = _render_pptx(source, run_dir, document_id)
                    units = _pptx_native(source, run_dir, input_id, document_id, rendered)
                else:
                    raise KSlideError(ErrorCode.INPUT_UNSUPPORTED, "Unsupported normalized input type.", {"extension": extension})
                documents.append(NormalizedDocument(document_id, input_id, str(metadata.get("kind", "unknown")), str(metadata.get("sha256", "")), tuple(units)))
            units = [unit for document in documents for unit in document.units]
            document_ids = [document.document_id for document in documents]
            if len(document_ids) != len(set(document_ids)):
                raise KSlideError(ErrorCode.DUPLICATE_DOCUMENT_ID, "Normalization generated duplicate document IDs.", {"document_ids": document_ids})
            if len(units) > MAX_UNITS_PER_RUN:
                raise KSlideError(ErrorCode.RESOURCE_LIMIT, "Page/slide count exceeds the configured safety limit.", {"units": len(units), "max_units": MAX_UNITS_PER_RUN})
            total_pixels = sum(unit.width_px * unit.height_px for unit in units)
            if total_pixels > MAX_TOTAL_RENDER_PIXELS:
                raise KSlideError(ErrorCode.RESOURCE_LIMIT, "Total normalized render pixels exceed the configured safety limit.", {"pixels": total_pixels, "max_pixels": MAX_TOTAL_RENDER_PIXELS})
            normalized_bytes = sum((run_dir / unit.canonical_render_path).stat().st_size for unit in units if (run_dir / unit.canonical_render_path).is_file())
            if normalized_bytes > MAX_NORMALIZED_BYTES:
                raise KSlideError(ErrorCode.RESOURCE_LIMIT, "Normalized render bytes exceed the configured safety limit.", {"bytes": normalized_bytes, "max_bytes": MAX_NORMALIZED_BYTES})
            result = NormalizationResult(tuple(documents), tuple(warnings), {"render_dpi": RENDER_DPI, "max_image_pixels": MAX_IMAGE_PIXELS})
            atomic_write_json(run_dir / "normalized" / "DOCUMENT_MANIFEST.json", result.as_dict(), mode=0o600)
            now = state.updated_at
            queue = WorkQueue(run_id=state.run_id, work_units=[WorkUnit(unit.work_unit_id, unit.document_id, unit.input_id, unit.source_index, unit.kind, WorkUnitStatus.NORMALIZED, created_at=now, updated_at=now) for unit in units])
            save_queue(run_dir, queue)
            state.input_count = len(units)
            state.transition(RunPhase.NORMALIZED, next_action="Extract native evidence and generate regions")
            save_state(run_dir, state)
            return result
        except KSlideError as exc:
            state = load_state(run_dir)
            state.transition(RunPhase.FAILED_NORMALIZATION, next_action="Fix the normalization capability or source file and retry", error_code=exc.code.value, error_message=exc.message)
            save_state(run_dir, state)
            atomic_write_json(run_dir / "normalized" / "NORMALIZATION_ERROR.json", exc.as_dict(), mode=0o600)
            atomic_write_text(run_dir / "RUN_FAILED.md", f"# FAILED\n\n{exc.message}\n\nError code: `{exc.code.value}`\n")
            raise
        except (ImportError, OSError, RuntimeError, ValueError) as exc:
            error = KSlideError(ErrorCode.NORMALIZATION_FAILED, "Document normalization failed safely.", {"reason": str(exc)})
            state = load_state(run_dir)
            state.transition(RunPhase.FAILED_NORMALIZATION, next_action="Fix the normalization capability or source file and retry", error_code=error.code.value, error_message=error.message)
            save_state(run_dir, state)
            atomic_write_json(run_dir / "normalized" / "NORMALIZATION_ERROR.json", error.as_dict(), mode=0o600)
            atomic_write_text(run_dir / "RUN_FAILED.md", f"# FAILED\n\n{error.message}\n\nError code: `{error.code.value}`\n")
            raise error from exc


def _load_normalization_result(run_dir: Path) -> NormalizationResult:
    value = read_json(run_dir / "normalized" / "DOCUMENT_MANIFEST.json")
    documents: list[NormalizedDocument] = []
    for item in value.get("documents", []):
        units = tuple(DocumentUnit(**{**unit, "native_evidence": tuple(unit.get("native_evidence", [])), "warnings": tuple(unit.get("warnings", []))}) for unit in item.get("units", []))
        documents.append(NormalizedDocument(item["document_id"], item["input_id"], item["kind"], item["source_sha256"], units))
    return NormalizationResult(tuple(documents), tuple(value.get("warnings", [])), dict(value.get("capabilities", {})))
