"""Qualified artifact and engine-evidence scorers.

These scores intentionally stop before translation quality. They measure what
the deterministic ingestion pipeline can prove about a generated artifact.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable


_ENGINE_FAILURE_CLASSES = {
    "KSLIDE_PPTX_RENDER_UNAVAILABLE": "CAPABILITY_BLOCK",
    "KSLIDE_OCR_UNAVAILABLE": "CAPABILITY_BLOCK",
    "KSLIDE_PDF_RENDER_UNAVAILABLE": "CAPABILITY_BLOCK",
    "ENGINE_NORMALIZATION": "NORMALIZATION_FAILURE",
    "ENGINE_WORK_UNIT_COUNT": "LAYOUT_FAILURE",
    "table_missing_or_dimensions_mismatch": "TABLE_EXTRACTION_FAILURE",
    "required_table_cell_missing": "TABLE_EXTRACTION_FAILURE",
    "ENGINE_ID_COLLISION": "ID_INTEGRITY_FAILURE",
    "ENGINE_EVIDENCE_MISSING": "VISUAL_EVIDENCE_FAILURE",
}


def _failure_classes(codes: Iterable[str]) -> list[str]:
    classes: set[str] = set()
    for code in codes:
        classes.add(_ENGINE_FAILURE_CLASSES.get(code, "ARTIFACT_FAILURE" if code == "ARTIFACT_GENERATION" else "ENGINE_EXTRACTION"))
    return sorted(classes)


def score_artifact(path: Path, scenario: Any) -> dict[str, Any]:
    result: dict[str, Any] = {
        "scenario_id": scenario.scenario_id,
        "category": scenario.category,
        "artifact": str(path),
        "artifact_generation_pass": path.is_file() and path.stat().st_size > 0,
        "failures": [],
    }
    if not result["artifact_generation_pass"]:
        result["failures"].append("artifact_missing_or_empty")
        return result
    if path.suffix.lower() in {".png", ".jpg", ".jpeg", ".webp"}:
        try:
            from PIL import Image

            with Image.open(path) as image:
                result["width"], result["height"] = image.size
                result["format"] = image.format
                if image.width < 640 or image.height < 360:
                    result["artifact_generation_pass"] = False
                    result["failures"].append("render_too_small")
        except ImportError:
            result["format"] = "uninspected"
            result["warnings"] = ["Pillow unavailable for visual inspection"]
        except (OSError, ValueError):
            result["artifact_generation_pass"] = False
            result["failures"].append("image_decode_failed")
        return result
    if path.suffix.lower() == ".pdf":
        try:
            import fitz

            with fitz.open(path) as document:
                result["format"] = "PDF"
                result["page_count"] = document.page_count
                result["artifact_generation_pass"] = document.page_count > 0
        except ImportError:
            result["format"] = "PDF_uninspected"
            result["warnings"] = ["PyMuPDF unavailable for PDF inspection"]
        except (OSError, ValueError):
            result["artifact_generation_pass"] = False
            result["failures"].append("pdf_open_failed")
        return result
    if path.suffix.lower() == ".pptx":
        try:
            from zipfile import ZipFile

            with ZipFile(path) as archive:
                result["format"] = "PPTX"
                result["slide_xml_count"] = len([name for name in archive.namelist() if name.startswith("ppt/slides/slide") and name.endswith(".xml")])
                result["artifact_generation_pass"] = result["slide_xml_count"] > 0
        except (OSError, ValueError):
            result["artifact_generation_pass"] = False
            result["failures"].append("pptx_archive_invalid")
        return result
    result["artifact_generation_pass"] = False
    result["failures"].append("unsupported_artifact_suffix")
    return result


def _source_strings(evidence: Iterable[Any]) -> set[str]:
    values: set[str] = set()
    for item in evidence:
        for fact in item.numeric_facts:
            source = fact.get("source_string")
            if source:
                values.add(str(source).replace(" ", ""))
        for region in item.regions:
            if region.selected_literal_candidate:
                values.add(str(region.selected_literal_candidate).replace(" ", ""))
        for table in item.tables:
            for cell in table.cells:
                if cell.source_text:
                    values.add(str(cell.source_text).replace(" ", ""))
    return values


def _expected_numeric_strings(scenario: Any) -> list[str]:
    return [str(value) for value in scenario.gold.get("numeric_facts", [])]


def _unique_ids(evidence: Iterable[Any]) -> bool:
    seen: set[str] = set()
    for item in evidence:
        values = [region.region_id for region in item.regions]
        values += [table.table_id for table in item.tables]
        values += [cell.cell_id for table in item.tables for cell in table.cells]
        values += [str(fact.get("fact_id")) for fact in item.numeric_facts]
        values += [str(element.get("element_id")) for element in item.visual_elements]
        if len(values) != len(set(values)) or seen.intersection(values):
            return False
        seen.update(values)
    return True


def score_engine_case(scenario: Any, *, artifact_result: dict[str, Any], normalized: Any | None, evidence: list[Any] | None, run_dir: Path | None, error: str | None = None) -> dict[str, Any]:
    """Score one scenario/format case after its own engine run."""

    evidence = evidence or []
    expected_regions = int(scenario.gold.get("expected_region_min", scenario.gold.get("visible_items", 1)))
    actual_regions = sum(len(item.regions) for item in evidence)
    work_units = sum(len(document.units) for document in normalized.documents) if normalized is not None else 0
    expected_table = scenario.gold.get("table")
    actual_tables = [table for item in evidence for table in item.tables]
    table_pass = True
    table_failures: list[str] = []
    if expected_table:
        matching = next((table for table in actual_tables if table.row_count == expected_table["row_count"] and table.column_count == expected_table["column_count"]), None)
        if matching is None:
            table_pass = False
            table_failures.append("table_missing_or_dimensions_mismatch")
        else:
            actual_cells = {(cell.row, cell.column, cell.source_text) for cell in matching.cells}
            expected_cells = {(cell["row"], cell["column"], cell["source"]) for cell in expected_table.get("required_cells", [])}
            if not expected_cells.issubset(actual_cells):
                table_pass = False
                table_failures.append("required_table_cell_missing")
    expected_numbers = _expected_numeric_strings(scenario)
    source_values = _source_strings(evidence)
    numeric_found = sum(1 for value in expected_numbers if value.replace(" ", "") in source_values)
    numeric_recall = numeric_found / len(expected_numbers) if expected_numbers else 1.0
    context_count = sum(1 for item in evidence for element in item.visual_elements if element.get("kind") == "context_image" and element.get("required") is True)
    media_plan_pass = False
    if run_dir is not None and evidence:
        try:
            from k_slide.cli import _evidence, _next

            _next(run_dir.parents[1], run_dir.name, None)
            packet = _evidence(run_dir.parents[1], run_dir.name, None)
            media = packet.get("model_media_plan", {})
            context = media.get("context_image", {})
            media_plan_pass = bool(context.get("required")) and Path(run_dir.parents[1] / str(context.get("path", ""))).is_file() and all(Path(run_dir.parents[1] / item["path"]).is_file() for item in media.get("required_crops", []))
        except (KeyError, OSError, TypeError, ValueError):
            media_plan_pass = False
    scores = {
        "work_unit_count": 1.0 if work_units == 1 else 0.0,
        "region_coverage": min(1.0, actual_regions / max(1, expected_regions)),
        "table_structure": 1.0 if table_pass else 0.0,
        "numeric_fact_recall": numeric_recall,
        "visual_context": 1.0 if context_count >= 1 else 0.0,
        "context_media_plan": 1.0 if media_plan_pass else 0.0,
        "unique_ids": 1.0 if _unique_ids(evidence) else 0.0,
    }
    critical_failures: list[str] = []
    if not artifact_result.get("artifact_generation_pass"):
        critical_failures.append("ARTIFACT_GENERATION")
    if error:
        critical_failures.append(error)
    if normalized is None:
        critical_failures.append("ENGINE_NORMALIZATION")
    if normalized is not None and scores["work_unit_count"] < 1:
        critical_failures.append("ENGINE_WORK_UNIT_COUNT")
    if evidence and scores["unique_ids"] < 1:
        critical_failures.append("ENGINE_ID_COLLISION")
    if expected_table and not table_pass:
        critical_failures.extend(table_failures)
    failure_classes = _failure_classes(critical_failures)
    if error and error not in critical_failures:
        failure_classes = sorted(set(failure_classes + [_ENGINE_FAILURE_CLASSES.get(error, "ENGINE_EXTRACTION")]))
    return {
        "scenario_id": scenario.scenario_id,
        "category": scenario.category,
        "split": scenario.split,
        "artifact": artifact_result,
        "normalization_pass": normalized is not None,
        "evidence_generation_pass": bool(evidence),
        "scores": scores,
        "critical_failures": sorted(set(critical_failures)),
        "failure_classes": failure_classes,
        "error": error,
        "run_id": run_dir.name if run_dir is not None else None,
    }


def aggregate_engine_scores(results: list[dict[str, Any]]) -> dict[str, Any]:
    keys = ("work_unit_count", "region_coverage", "table_structure", "numeric_fact_recall", "visual_context", "context_media_plan", "unique_ids")
    from collections import Counter

    failure_classes = Counter(classification for item in results for classification in item.get("failure_classes", []))
    return {
        "case_count": len(results),
        "artifact_generation_pass_rate": sum(bool(item["artifact"].get("artifact_generation_pass")) for item in results) / len(results) if results else 0.0,
        "engine_normalization_pass_rate": sum(bool(item.get("normalization_pass")) for item in results) / len(results) if results else 0.0,
        "evidence_generation_pass_rate": sum(bool(item.get("evidence_generation_pass")) for item in results) / len(results) if results else 0.0,
        "critical_failure_count": sum(len(item.get("critical_failures", [])) for item in results),
        "failure_classes": dict(sorted(failure_classes.items())),
        "mean_scores": {key: sum(float(item["scores"].get(key, 0.0)) for item in results) / len(results) if results else 0.0 for key in keys},
    }
