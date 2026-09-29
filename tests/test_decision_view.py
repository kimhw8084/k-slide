from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from k_slide.conflicts import (
    AssertionKind,
    Conflict,
    ConflictRegistry,
    build_assertion_reference,
    conflict_id_for,
    finalize_registry,
    save_conflict_registry,
)
from k_slide.decision_view import read_presentation
from k_slide.evidence_ir import EvidenceIR, EvidenceRegion, save_evidence
from k_slide.host_adapter import HostInvocation, add_host_contract
from k_slide.io import atomic_write_json, read_json
from k_slide.queue import WorkQueue, WorkUnit, WorkUnitStatus, load_queue, save_queue
from k_slide.rendering.reports import render_run
from k_slide.semantics import ProvenanceState
from k_slide.state import RunPhase
from k_slide.storage import StorageArtifact, storage_path
from k_slide.translation import merge_evidence_patch, parse_translation_patch


class DecisionViewTests(unittest.TestCase):
    def _run(self, root: Path, *, needs_review: bool = False) -> tuple[Path, EvidenceIR]:
        root.mkdir(parents=True, exist_ok=True)
        run = root / "run"
        run.mkdir()
        atomic_write_json(storage_path(run, StorageArtifact.RUN_MANIFEST, "RUN_MANIFEST.json", create_parent=True), {
            "inputs": [{"snapshot_id": "source-001", "source_name": "quarterly-review.png", "sha256": "a" * 64}],
        })
        queue = WorkQueue(run_id="run", work_units=[WorkUnit(
            "doc-slide-001", "doc", "source-001", 0,
            status=WorkUnitStatus.NEEDS_REVIEW if needs_review else WorkUnitStatus.TRANSLATED,
        )])
        save_queue(run, queue)
        crop = run / "regions" / "doc-slide-001-r001.png"
        crop.parent.mkdir(parents=True)
        crop.write_bytes(b"fixture crop")
        evidence = EvidenceIR(
            "doc",
            "doc-slide-001",
            {"slide_number": 1},
            regions=(
                EvidenceRegion("doc-slide-001-r001", (1, 2, 40, 20), (0.01, 0.02, 0.4, 0.2), selected_literal_candidate="핵심 목표", crop_model_path="regions/doc-slide-001-r001.png"),
                EvidenceRegion("doc-slide-001-r002", (1, 22, 40, 40), (0.01, 0.22, 0.4, 0.4), selected_literal_candidate="10%", crop_original_path="regions/doc-slide-001-r001.png"),
                EvidenceRegion("doc-slide-001-r003", (1, 42, 40, 60), (0.01, 0.42, 0.4, 0.6), selected_literal_candidate="미확인"),
            ),
            required_source_ids=("doc-slide-001-r001", "doc-slide-001-r002", "doc-slide-001-r003"),
        ).with_revision()
        save_evidence(run, evidence)
        patch = parse_translation_patch({
            "schema_version": "1.0",
            "work_unit_id": evidence.work_unit_id,
            "evidence_revision": evidence.evidence_revision,
            "regions": [
                {"region_id": "doc-slide-001-r001", "english": "Core target", "commitment_status": "target", "term_ids": [], "unresolved": False, "provenance": "source_fact", "evidence_ids": ["doc-slide-001-r001"]},
                {"region_id": "doc-slide-001-r002", "english": "10%", "term_ids": [], "unresolved": False, "provenance": "source_fact", "evidence_ids": ["doc-slide-001-r002"]},
                {"region_id": "doc-slide-001-r003", "english": "Unreadable", "term_ids": [], "unresolved": True, "unresolved_reason": "The source assertion is unreadable.", "provenance": "unresolved", "evidence_ids": ["doc-slide-001-r003"]},
            ],
            "tables": [],
            "visual_interpretations": [],
            "executive_claims": [
                {"claim_id": "claim-takeaway", "kind": "takeaway", "text": "The plan targets 10% growth.", "evidence_ids": ["doc-slide-001-r001", "doc-slide-001-r002"], "uncertainty": "low", "provenance": "supported_interpretation"},
                {"claim_id": "claim-decision", "kind": "decision_or_ask", "text": "Approve the target scope.", "evidence_ids": ["doc-slide-001-r001"], "uncertainty": "medium", "provenance": "supported_interpretation"},
                {"claim_id": "claim-number", "kind": "key_number", "text": "10% growth target.", "evidence_ids": ["doc-slide-001-r002"], "uncertainty": "low", "provenance": "source_fact"},
                {"claim_id": "claim-risk", "kind": "risk", "text": "Delivery remains uncertain.", "evidence_ids": ["doc-slide-001-r003"], "uncertainty": "high", "provenance": "unresolved", "unresolved_reason": "The source assertion is unreadable."},
                {"claim_id": "claim-dependency", "kind": "dependency", "text": "Approval is required.", "evidence_ids": ["doc-slide-001-r001"], "uncertainty": "medium", "provenance": "supported_interpretation"},
                {"claim_id": "claim-time", "kind": "timing", "text": "Target timing is Q4.", "evidence_ids": ["doc-slide-001-r002"], "uncertainty": "medium", "provenance": "supported_interpretation"},
                {"claim_id": "claim-owner", "kind": "owner", "text": "Owner: Operations.", "evidence_ids": ["doc-slide-001-r001"], "uncertainty": "medium", "provenance": "source_fact"},
            ],
        })
        slide = merge_evidence_patch(evidence, patch)
        atomic_write_json(storage_path(run, StorageArtifact.CANONICAL_IR, "ir/doc-slide-001.json", create_parent=True), slide.as_dict())
        return run, evidence

    def _validate_schema(self, name: str, value: dict) -> None:
        schema_path = Path(__file__).resolve().parents[1] / "schemas" / name
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(value)

    def test_decision_view_is_deterministic_closed_and_evidence_linked(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run, _ = self._run(Path(directory))
            render_run(run)
            names = ("05_decision_view.json", "05_decision_view.md", "08_evidence_drilldown.json", "09_presentation.json")
            first = {name: storage_path(run, StorageArtifact.REPORT, name).read_bytes() for name in names}
            render_run(run)
            second = {name: storage_path(run, StorageArtifact.REPORT, name).read_bytes() for name in names}
            self.assertEqual(first, second)

            view = read_json(storage_path(run, StorageArtifact.REPORT, "05_decision_view.json"))
            descriptor = read_presentation(run)
            drilldown = read_json(storage_path(run, StorageArtifact.REPORT, "08_evidence_drilldown.json"))
            self._validate_schema("decision-view.v1.schema.json", view)
            self._validate_schema("presentation-descriptor.v1.schema.json", descriptor)
            self._validate_schema("evidence-drilldown.v1.schema.json", drilldown)
            sections = view["sections"]
            self.assertEqual(view["verification"]["state"], "NOT_RUN")
            self.assertEqual(sections["material_context"]["documents"][0]["display_name"], "quarterly-review.png")
            self.assertEqual(sections["key_takeaway"]["items"][0]["text"], "The plan targets 10% growth.")
            self.assertEqual(sections["decisions_and_asks"]["items"][0]["kind"], "decision_or_ask")
            self.assertEqual(sections["key_numbers"]["items"][0]["evidence_ids"], ["doc-slide-001-r002"])
            self.assertEqual({item["kind"] for item in sections["risks_and_dependencies"]["items"]}, {"risk", "dependency"})
            self.assertEqual({item["kind"] for item in sections["timing_and_owners"]["items"]}, {"timing", "owner"})
            self.assertEqual(sections["conflicts"]["state"], "not_assessed")
            self.assertEqual(sections["unresolved_warnings"]["state"], "warnings_present")
            self.assertIn("doc-slide-001-r003", sections["unresolved_warnings"]["items"][0]["evidence_ids"])
            for section_name in ("key_takeaway", "decisions_and_asks", "key_numbers", "risks_and_dependencies", "timing_and_owners"):
                for item in sections[section_name]["items"]:
                    self.assertIn(item["provenance"], {value.value for value in ProvenanceState})
                    self.assertTrue(item["evidence_ids"])
                    self.assertEqual({ref["evidence_id"] for ref in item["source_refs"]}, set(item["evidence_ids"]))
                    self.assertTrue(all(ref["evidence_ir_path"] == "evidence/doc-slide-001.json" for ref in item["source_refs"]))
            number = sections["key_numbers"]["items"][0]
            self.assertEqual(number["source_refs"][0]["crop_path"], "regions/doc-slide-001-r001.png")
            self.assertEqual(descriptor["actions"][0]["action_id"], "decision_view")
            self.assertEqual([item["action_id"] for item in descriptor["actions"][1:]], ["reconstruction", "review_disclosure", "evidence_drilldown"])
            self.assertIn(number["item_id"], [item["item_id"] for item in drilldown["items"]])

    def test_empty_sections_are_explicit_and_review_cannot_become_done(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = root / "run"
            run.mkdir()
            atomic_write_json(storage_path(run, StorageArtifact.RUN_MANIFEST, "RUN_MANIFEST.json", create_parent=True), {"inputs": []})
            save_queue(run, WorkQueue(run_id="run", work_units=[WorkUnit("doc-slide-001", "doc", "source-001", 0, status=WorkUnitStatus.NEEDS_REVIEW)]))
            render_run(run)
            view = read_json(storage_path(run, StorageArtifact.REPORT, "05_decision_view.json"))
            for name in ("key_takeaway", "decisions_and_asks", "key_numbers", "risks_and_dependencies", "timing_and_owners"):
                self.assertEqual(view["sections"][name], {"state": "not_established", "items": []})
            warnings = view["sections"]["unresolved_warnings"]["items"]
            self.assertEqual({item["kind"] for item in warnings}, {"work_unit_review", "conflict_assessment"})
            review_warning = next(item for item in warnings if item["kind"] == "work_unit_review")
            self.assertTrue(review_warning["unresolved"])
            review_contract = add_host_contract({"status": "NEEDS_REVIEW", "run_id": "run"}, phase=RunPhase.NEEDS_REVIEW)
            self.assertEqual(review_contract["semantic_outcome"], "NEEDS_REVIEW")
            self.assertNotEqual(review_contract["semantic_outcome"], "DONE")

    def test_conflicting_assertions_remain_explicit_and_link_to_both_sources(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run, evidence_a = self._run(Path(directory))
            work_unit_id = "doc-slide-002"
            evidence_b = EvidenceIR(
                "doc",
                work_unit_id,
                {"slide_number": 2},
                regions=(EvidenceRegion("doc-slide-002-r001", (2, 2, 30, 30), (0.02, 0.02, 0.3, 0.3), selected_literal_candidate="계획 지연"),),
                required_source_ids=("doc-slide-002-r001",),
            ).with_revision()
            save_evidence(run, evidence_b)
            patch_b = parse_translation_patch({
                "schema_version": "1.0",
                "work_unit_id": work_unit_id,
                "evidence_revision": evidence_b.evidence_revision,
                "regions": [{"region_id": "doc-slide-002-r001", "english": "The planned work is delayed", "commitment_status": "planned", "term_ids": [], "unresolved": False, "provenance": "source_fact", "evidence_ids": ["doc-slide-002-r001"]}],
                "tables": [],
                "visual_interpretations": [],
                "executive_claims": [{"claim_id": "claim-takeaway-2", "kind": "takeaway", "text": "The plan is delayed.", "evidence_ids": ["doc-slide-002-r001"], "uncertainty": "low", "provenance": "supported_interpretation"}],
            })
            slide_b = merge_evidence_patch(evidence_b, patch_b)
            atomic_write_json(storage_path(run, StorageArtifact.CANONICAL_IR, f"ir/{work_unit_id}.json", create_parent=True), slide_b.as_dict())
            queue = load_queue(run)
            queue.work_units.append(WorkUnit(work_unit_id, "doc", "source-002", 1, status=WorkUnitStatus.TRANSLATED))
            save_queue(run, queue)
            atomic_write_json(storage_path(run, StorageArtifact.RUN_MANIFEST, "RUN_MANIFEST.json"), {
                "inputs": [
                    {"snapshot_id": "source-001", "source_name": "quarterly-review.png", "sha256": "a" * 64},
                    {"snapshot_id": "source-002", "source_name": "supplement.png", "sha256": "b" * 64},
                ],
            })
            first = build_assertion_reference(run, evidence_a.work_unit_id, AssertionKind.EXECUTIVE_CLAIM.value, "claim-takeaway")
            second = build_assertion_reference(run, work_unit_id, AssertionKind.EXECUTIVE_CLAIM.value, "claim-takeaway-2")
            conflict = Conflict(conflict_id_for((first.assertion_id, second.assertion_id)), (first, second))
            save_conflict_registry(run, finalize_registry(ConflictRegistry("run", (conflict,))))
            render_run(run)
            view = read_json(storage_path(run, StorageArtifact.REPORT, "05_decision_view.json"))
            conflict_view = view["sections"]["conflicts"]["items"][0]
            self.assertTrue(conflict_view["unresolved"])
            self.assertEqual({item["text"] for item in conflict_view["assertions"]}, {"The plan targets 10% growth.", "The plan is delayed."})
            self.assertEqual(set(conflict_view["evidence_ids"]), {"doc-slide-001-r001", "doc-slide-001-r002", "doc-slide-002-r001"})
            warning_ids = {item["item_id"] for item in view["sections"]["unresolved_warnings"]["items"]}
            self.assertIn(conflict_view["item_id"], warning_ids)

    def test_presentation_rejects_stale_canonical_state_and_modified_follow_on(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run, _ = self._run(Path(directory))
            verification = storage_path(run, StorageArtifact.VERIFICATION, "verification/summary.json", create_parent=True)
            atomic_write_json(verification, {"status": "PASS", "checked_work_units": 1, "issues": [], "critical_count": 0, "unaccounted_count": 0})
            render_run(run)
            read_presentation(run)
            atomic_write_json(verification, {"status": "FAIL", "checked_work_units": 1, "issues": [{"code": "KSLIDE_FIXTURE"}], "critical_count": 1, "unaccounted_count": 0})
            with self.assertRaisesRegex(ValueError, "stale"):
                read_presentation(run)
            render_run(run)
            queue = load_queue(run)
            queue.work_units[0].revision += 1
            save_queue(run, queue)
            with self.assertRaisesRegex(ValueError, "stale"):
                read_presentation(run)
            render_run(run)
            report = storage_path(run, StorageArtifact.REPORT, "07_unresolved_items.md")
            report.write_text(report.read_text(encoding="utf-8") + "tampered\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "stale"):
                read_presentation(run)

    def test_opencode_and_vscode_host_invocations_share_order_and_lifecycle_contract(self) -> None:
        opencode = HostInvocation.from_json(json.dumps({
            "schema_version": "1.0",
            "adapter_version": "1.0",
            "input_refs": [
                {"source_kind": "workspace_file", "logical_name": "b.png", "locator": "/workspace/b.png"},
                {"source_kind": "workspace_file", "logical_name": "a.png", "locator": "/workspace/a.png"},
            ],
        }))
        vscode = HostInvocation.from_json(json.dumps({
            "schema_version": "1.0",
            "adapter_version": "1.0",
            "input_refs": [
                {"source_kind": "workspace_file", "logical_name": "a.png", "locator": "/workspace/a.png"},
                {"source_kind": "workspace_file", "logical_name": "b.png", "locator": "/workspace/b.png"},
            ],
        }))
        self.assertEqual(opencode.input_refs, vscode.input_refs)
        for phase, expected in ((RunPhase.COMPLETE, "DONE"), (RunPhase.NEEDS_REVIEW, "NEEDS_REVIEW")):
            opencode_contract = add_host_contract({"status": phase.value}, phase=phase)
            vscode_contract = add_host_contract({"status": phase.value}, phase=phase)
            self.assertEqual(opencode_contract, vscode_contract)
            self.assertEqual(opencode_contract["semantic_outcome"], expected)


if __name__ == "__main__":
    unittest.main()
