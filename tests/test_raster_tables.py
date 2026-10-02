from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from PIL import Image, ImageDraw

from k_slide.errors import KSlideError
from k_slide.extraction import extract_run
from k_slide.ingest import prepare_run
from k_slide.normalization import normalize_run
from k_slide.ocr.base import OCRRegion, OCRResult
from k_slide.translation import parse_translation_patch
from tests.reference_fixtures import reference_environment


CELLS = [("Item", (30, 30, 80, 45)), ("Value", (220, 30, 275, 45)),
         ("Revenue", (30, 100, 100, 115)), ("100", (220, 100, 260, 115))]


class FixtureOCR:
    name, version = "grid-fixture", "1"

    def __init__(self, cells):
        self.cells = cells

    def extract(self, image, *, language_hints=("ko", "en")):
        with Image.open(image) as source:
            sx, sy = source.width / 400, source.height / 160
        return OCRResult(self.name, self.version, language_hints, tuple(
            OCRRegion(text, tuple(round(value * (sx if i % 2 == 0 else sy)) for i, value in enumerate(box)), .99, index)
            for index, (text, box) in enumerate(self.cells)))


class RasterTableTests(unittest.TestCase):
    def _extract(self, root, *, cells=CELLS, ocr_cells=None, merged=False, pdf=False):
        image = Image.new("RGB", (400, 160), "white")
        draw = ImageDraw.Draw(image)
        for x in (10, 200, 390):
            draw.line((x, 80 if merged and x == 200 else 10, x, 150), fill="black", width=2)
        for y in (10, 80, 150):
            draw.line((10, y, 390, y), fill="black", width=2)
        for text, box in cells:
            draw.text(box[:2], text, fill="black")
        source = root / "table.png"
        image.save(source)
        if pdf:
            import fitz
            document = fitz.open()
            page = document.new_page(width=400, height=160)
            page.insert_image(page.rect, filename=str(source))
            source = root / "table.pdf"
            document.save(source)
            document.close()
        environment = reference_environment("grid")
        run = prepare_run(root, explicit_paths=[str(source)], environment_identity=environment)
        normalize_run(run, environment_identity=environment)
        return extract_run(run, ocr_provider=FixtureOCR(cells if ocr_cells is None else ocr_cells), environment_identity=environment)[0]

    def test_visible_png_and_pdf_table_cannot_accept_empty_table_patch(self):
        for pdf in (False, True):
            with self.subTest(pdf=pdf), tempfile.TemporaryDirectory() as directory:
                evidence = self._extract(Path(directory), pdf=pdf)
                self.assertEqual(len(evidence.tables), 1)
                table = evidence.tables[0]
                self.assertEqual((table.row_count, table.column_count), (2, 2))
                self.assertEqual([cell.source_text for cell in table.cells], [item[0] for item in CELLS])
                self.assertEqual(evidence.source["layout_review_reasons"], [])
                self.assertTrue(all(cell.evidence_region_ids for cell in table.cells))
                self.assertTrue(all(cell.cell_id.startswith(evidence.work_unit_id) for cell in table.cells))
                patch = parse_translation_patch({
                    "schema_version": "1.0", "work_unit_id": evidence.work_unit_id,
                    "evidence_revision": evidence.evidence_revision,
                    "regions": [{"region_id": region.region_id, "english": region.selected_literal_candidate,
                                 "term_ids": [], "unresolved": False, "provenance": "source_fact",
                                 "evidence_ids": [region.region_id]} for region in evidence.regions],
                    "tables": [], "visual_interpretations": [], "executive_claims": [],
                })
                with self.assertRaises(KSlideError):
                    patch.validate_against(evidence)

    def test_blank_cell_is_not_an_unreadable_cell(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = self._extract(Path(directory), cells=CELLS[:-1])
            self.assertTrue(evidence.tables[0].cells[-1].is_blank)
            self.assertEqual(evidence.tables[0].cells[-1].source_text, "")
            self.assertEqual(evidence.source["layout_review_reasons"], [])
        with tempfile.TemporaryDirectory() as directory:
            evidence = self._extract(Path(directory), ocr_cells=CELLS[:-1])
            cell = evidence.tables[0].cells[-1]
            self.assertFalse(cell.is_blank)
            self.assertEqual(cell.cell_state, "unknown")
            self.assertIsNone(cell.source_text)
            self.assertTrue(evidence.source["layout_review_reasons"])

    def test_merged_header_preserves_every_coordinate(self):
        with tempfile.TemporaryDirectory() as directory:
            cells = [CELLS[0], *CELLS[2:]]
            evidence = self._extract(Path(directory), cells=cells, merged=True)
            table = evidence.tables[0]
            self.assertEqual(len(table.cells), 4)
            self.assertEqual(table.cells[0].colspan, 2)
            self.assertTrue(table.cells[0].is_merge_origin)
            self.assertTrue(table.cells[1].is_spanned)
            self.assertEqual(table.cells[1].cell_state, "merge_continuation")
            self.assertEqual(evidence.source["layout_review_reasons"], [])


if __name__ == "__main__":
    unittest.main()
