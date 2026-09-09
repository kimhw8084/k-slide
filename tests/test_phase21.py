from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from k_slide.errors import ErrorCode, KSlideError
from k_slide.installer import install
from k_slide.numeric import extract_numeric_facts, numeric_fact_matches
from k_slide.ocr.paddle import _bbox, _result_mapping
from k_slide.ocr.base import OCRRegion, OCRResult
from k_slide.ingest import prepare_run
from k_slide.normalization import normalize_run
from k_slide.extraction import extract_run
from k_slide.cli import _evidence, _next
from evals.scenarios import scenario_specs
from evals.model_scorers import score_translation_patch
from evals.opencode_runner import OpenCodeEvalRunner
from k_slide.queue import WorkQueue, WorkUnit, save_queue
from k_slide.semantics import CommitmentStatus, SpeechAct, enum_value


class Phase21ContractTests(unittest.TestCase):
    def test_public_synthetic_corpus_has_one_hundred_specs(self) -> None:
        scenarios = scenario_specs()
        self.assertEqual(len(scenarios), 100)
        self.assertEqual(len({scenario.scenario_id for scenario in scenarios}), 100)
        self.assertEqual({scenario.split for scenario in scenarios}, {"development", "validation", "held_out"})
        self.assertEqual(sum(scenario.split == "development" for scenario in scenarios), 60)
        self.assertEqual(sum(scenario.split == "validation" for scenario in scenarios), 20)
        self.assertEqual(sum(scenario.split == "held_out" for scenario in scenarios), 20)
        self.assertGreaterEqual(sum(scenario.compound for scenario in scenarios if scenario.split == "held_out"), 5)

    def test_visual_categories_have_visual_gold_not_only_labels(self) -> None:
        scenarios = scenario_specs()
        table = next(item for item in scenarios if item.category == "financial_table")
        chart = next(item for item in scenarios if item.category == "chart")
        process = next(item for item in scenarios if item.category == "process_diagram")
        self.assertEqual(table.visual_kind, "table")
        self.assertEqual(table.gold["table"]["row_count"], 4)
        self.assertEqual(chart.gold["chart"]["chart_type"], "line")
        self.assertEqual(len(chart.gold["chart"]["categories"]), 4)
        self.assertEqual(len(process.gold["process"]["relations"]), 4)

    def test_duplicate_work_unit_ids_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            queue = WorkQueue("run-1", [WorkUnit("same", "doc-1", "source-1", 0), WorkUnit("same", "doc-1", "source-1", 1)])
            with self.assertRaises(KSlideError) as raised:
                save_queue(Path(directory), queue)
            self.assertEqual(raised.exception.code, ErrorCode.DUPLICATE_WORK_UNIT_ID)

    def test_scale_and_percentage_point_semantics_are_preserved(self) -> None:
        facts = extract_numeric_facts("매출 3.2조원, 영업이익 500억원, 성장률 +2.3%p")
        self.assertEqual([fact["canonical_value"] for fact in facts], [3.2e12, 5.0e10, 2.3])
        self.assertTrue(numeric_fact_matches(facts[0], "Revenue: KRW 3.2 trillion")[0])
        self.assertTrue(numeric_fact_matches(facts[1], "Operating profit: KRW 50 billion")[0])
        self.assertTrue(numeric_fact_matches(facts[2], "Margin: +2.3 percentage points")[0])
        self.assertFalse(numeric_fact_matches(facts[2], "Margin: +2.3%")[0])

    def test_paddle_result_contract_variants_normalize(self) -> None:
        class Result:
            def json(self):
                return {"res": {"rec_texts": ["검토"], "rec_scores": [0.91], "dt_polys": [[[1, 2], [11, 2], [11, 12], [1, 12]]]}}

        mapping = _result_mapping(Result())
        self.assertEqual(mapping["rec_texts"], ["검토"])
        self.assertEqual(_bbox(mapping["dt_polys"][0]), (1, 2, 11, 12))
        self.assertEqual(_result_mapping({"rec_texts": ["계획"]})["rec_texts"], ["계획"])

    def test_semantic_scorer_does_not_accept_unsupported_claims(self) -> None:
        class Region:
            region_id = "r1"
            required_for_translation = True

        class Evidence:
            regions = (Region(),)
            numeric_facts = ()
            tables = ()
            visual_elements = ({"element_id": "ctx"},)

        scenario = next(item for item in scenario_specs() if item.category == "cross_slide_consistency")
        score = score_translation_patch(scenario, Evidence(), {"regions": [{"region_id": "r1", "english": "AI Platform", "commitment_status": "under_review"}], "executive_claims": [{"claim_id": "c1", "text": "Unsupported", "evidence_ids": ["missing"]}]})
        self.assertEqual(score["unsupported_executive_claims"], 1)

    def test_opencode_runner_uses_real_slash_command_surface(self) -> None:
        runner = OpenCodeEvalRunner(model="ollama/qwen3:14b")
        command = runner.command(Path("/tmp/k-slide-e2e-workspace"))
        if command:
            self.assertIn("run", command)
            self.assertIn("--format", command)
            self.assertIn("json", command)
            self.assertIn("--command", command)
            self.assertIn("k-slide", command)

    def test_semantic_enums_reject_freeform_values(self) -> None:
        self.assertEqual(enum_value("under_review", CommitmentStatus, "status"), "under_review")
        self.assertEqual(enum_value("dependency", SpeechAct, "speech"), "dependency")
        with self.assertRaises(KSlideError):
            enum_value("confirmed-ish", CommitmentStatus, "status")

    def test_corpus_generator_requires_verified_korean_font_and_makes_real_visuals(self) -> None:
        import importlib.util

        if importlib.util.find_spec("PIL") is None:
            self.skipTest("Pillow is optional")
        try:
            from evals.fonts import discover_korean_font
            from evals.generator import generate_artifacts
        except ImportError:
            self.skipTest("Pillow is optional")
        scenario_set = [item for item in scenario_specs() if item.category in {"financial_table", "chart", "process_diagram"}][:3]
        with tempfile.TemporaryDirectory() as directory:
            try:
                font = discover_korean_font()
            except RuntimeError as exc:
                self.fail(f"evaluation environment lacks a verified Korean font: {exc}")
            self.assertTrue(font.path)
            counts = generate_artifacts(scenario_set, Path(directory), formats=("png", "pptx"))
            self.assertEqual(counts["png"], 3)
            png_paths = list(Path(directory).glob("scenario-*/default/png/source.png"))
            self.assertEqual(len(png_paths), 3)
            self.assertTrue(all(path.stat().st_size > 0 for path in png_paths))

    def test_installer_refuses_modified_owned_file(self) -> None:
        source_root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "host"
            install(source_root, target)
            command = target / ".opencode" / "commands" / "k-slide.md"
            command.write_text(command.read_text() + "\nlocal change\n", encoding="utf-8")
            with self.assertRaises(KSlideError) as raised:
                install(source_root, target)
            self.assertEqual(raised.exception.code, ErrorCode.INSTALL_LOCAL_MODIFICATION)

    def test_image_and_pdf_multi_input_ids_are_unique(self) -> None:
        try:
            from PIL import Image
            import fitz
        except ImportError:
            self.skipTest("Pillow and PyMuPDF are optional")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = []
            for name, color in (("a.png", "red"), ("b.png", "blue")):
                path = root / name
                Image.new("RGB", (320, 180), color).save(path)
                paths.append(str(path))
            pdf_path = root / "report.pdf"
            document = fitz.open()
            document.new_page(width=320, height=180)
            document.new_page(width=320, height=180)
            document.save(pdf_path)
            document.close()
            paths.append(str(pdf_path))
            run = prepare_run(root, explicit_paths=paths)
            result = normalize_run(run)
            unit_ids = [unit.work_unit_id for document in result.documents for unit in document.units]
            render_paths = [unit.canonical_render_path for document in result.documents for unit in document.units]
            self.assertEqual(len(unit_ids), len(set(unit_ids)))
            self.assertEqual(len(render_paths), len(set(render_paths)))
            self.assertTrue(any(identifier.startswith("doc-001-image") for identifier in unit_ids))
            self.assertTrue(any(identifier.startswith("doc-003-page") for identifier in unit_ids))

    def test_ocr_regions_and_context_media_plan_are_engine_owned(self) -> None:
        try:
            from PIL import Image
        except ImportError:
            self.skipTest("Pillow is optional")

        class FakeOCR:
            name = "fake"
            version = "1"

            def extract(self, image: Path, *, language_hints=("ko", "en")):
                return OCRResult(self.name, self.version, language_hints, (OCRRegion("제목", (10, 10, 150, 50), 0.99, 0), OCRRegion("검토 필요", (10, 70, 240, 110), 0.60, 1)))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "slide.png"
            Image.new("RGB", (320, 180), "white").save(source)
            run = prepare_run(root, explicit_paths=[str(source)])
            normalize_run(run)
            evidence = extract_run(run, ocr_provider=FakeOCR())[0]
            self.assertGreaterEqual(len(evidence.regions), 2)
            self.assertTrue(any(item.get("kind") == "context_image" for item in evidence.visual_elements))
            self.assertEqual(_next(root, run.name, None)["status"], "READY")
            media = _evidence(root, run.name, None)["model_media_plan"]
            self.assertTrue(media["context_image"]["required"])
            self.assertTrue(str(media["context_image"]["path"]).startswith(".k-slide-runs/"))
            self.assertGreaterEqual(len(media["required_crops"]), 1)


if __name__ == "__main__":
    unittest.main()
