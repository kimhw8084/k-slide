from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from k_slide.conflicts import (
    AssertionKind,
    assess_conflicts,
    conflict_assessment_status,
    authority_policy_revision,
    Conflict,
    ConflictRegistry,
    ConflictResolutionState,
    Supersession,
    SupersessionAuthorityBasis,
    build_assertion_reference,
    build_authority_evidence_reference,
    conflict_id_for,
    conflict_contract_required,
    conflict_registry_path,
    finalize_registry,
    load_conflict_registry,
    save_conflict_registry,
    supersession_id_for,
    assertion_id_for,
)
from k_slide.errors import ErrorCode, KSlideError
from k_slide.evidence_ir import EvidenceIR, EvidenceRegion, EvidenceTable, EvidenceTableCell, save_evidence
from k_slide.io import atomic_write_json
from k_slide.modality import classify_source_language
from k_slide.queue import WorkQueue, WorkUnit, WorkUnitStatus, load_queue, save_queue
from k_slide.rendering.reports import render_run
from k_slide.storage import StorageArtifact, storage_path
from k_slide.translation import merge_evidence_patch, parse_translation_patch
from k_slide.terminology import Termbase
from k_slide.verify import VerificationResult, _validate_conflict_registry, finalize_run, verify_run


class KSA23ConflictTests(unittest.TestCase):
    def _patch(self, evidence: EvidenceIR, *, claim_text: str, claim_kind: str = "takeaway") -> dict[str, object]:
        return {
            "schema_version": "1.0",
            "work_unit_id": evidence.work_unit_id,
            "evidence_revision": evidence.evidence_revision,
            "regions": [
                {
                    "region_id": region.region_id,
                    "english": region.selected_literal_candidate or "Source",
                    "term_ids": [],
                    "unresolved": False,
                    "provenance": "source_fact",
                    "evidence_ids": [region.region_id],
                    **({
                        "hangul_retention": {
                            "reason": "Keep the fixture's Korean assertion text alongside the English test context.",
                            "evidence_id": region.region_id,
                        }
                    } if classify_source_language(region.selected_literal_candidate) in {"ko", "mixed"} else {}),
                }
                for region in evidence.regions
            ],
            "tables": [],
            "visual_interpretations": [],
            "executive_claims": [
                {
                    "claim_id": f"{evidence.work_unit_id}-claim",
                    "kind": claim_kind,
                    "text": claim_text,
                    "evidence_ids": [evidence.regions[0].region_id],
                    "uncertainty": "low",
                    "provenance": "supported_interpretation",
                }
            ],
        }

    def _unit(
        self,
        run: Path,
        *,
        unit_id: str,
        document_id: str,
        source_index: int,
        source_text: str,
        language: str,
        claim_text: str,
        authority_text: str | None = None,
        claim_kind: str = "takeaway",
    ) -> EvidenceIR:
        regions = [EvidenceRegion(f"{unit_id}-r1", selected_literal_candidate=source_text, language=language)]
        if authority_text is not None:
            regions.append(EvidenceRegion(f"{unit_id}-authority", selected_literal_candidate=authority_text, language=language))
        evidence = EvidenceIR(
            document_id,
            unit_id,
            {"slide_number": source_index + 1},
            regions=tuple(regions),
            required_source_ids=tuple(region.region_id for region in regions),
        ).with_revision()
        save_evidence(run, evidence)
        patch = parse_translation_patch(self._patch(evidence, claim_text=claim_text, claim_kind=claim_kind))
        slide = merge_evidence_patch(evidence, patch)
        atomic_write_json(storage_path(run, StorageArtifact.CANONICAL_IR, f"ir/{unit_id}.json", create_parent=True), slide.as_dict(), mode=0o600)
        return evidence

    def _typed_kind_run(self, kind: str) -> tuple[Path, EvidenceIR, EvidenceIR, str, str]:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        run = Path(directory.name) / "run"
        run.mkdir()
        evidences: list[EvidenceIR] = []
        for index, (document_id, language) in enumerate((("doc-ko", "ko"), ("doc-en", "en")), start=1):
            unit_id = f"{document_id}-slide-001"
            region_id = f"{unit_id}-r1"
            cell_id = f"{unit_id}-table-1-r0-c0"
            fact_id = f"{unit_id}-fact-1"
            visual_id = f"{unit_id}-visual-1"
            region = EvidenceRegion(
                region_id,
                selected_literal_candidate="매출 10억원" if language == "ko" else "Revenue KRW 10 million",
                language=language,
                numeric_fact_ids=(fact_id,) if kind == "numeric_fact" else (),
            )
            tables = (
                EvidenceTable(
                    f"{unit_id}-table-1",
                    row_count=1,
                    column_count=1,
                    cells=(EvidenceTableCell(cell_id, 0, 0, source_text="매출" if language == "ko" else "Revenue", evidence_region_ids=(region_id,)),),
                ),
            ) if kind == "table_cell" else ()
            numeric_facts = ({
                "fact_id": fact_id,
                "source_region_id": region_id,
                "source_string": "10억원" if language == "ko" else "KRW 10 million",
                "raw_value": 10,
                "canonical_value": 1000000000,
                "scale_factor": 100000000,
                "source_unit": "억원" if language == "ko" else "KRW million",
                "semantic_quantity": "currency",
                "currency": "KRW",
            },) if kind == "numeric_fact" else ()
            visual_elements = ({"element_id": visual_id, "kind": "bar", "required": True},) if kind == "visual_relation" else ()
            required_ids = [region_id]
            if kind == "table_cell":
                required_ids.append(cell_id)
            if kind == "numeric_fact":
                required_ids.append(fact_id)
            if kind == "visual_relation":
                required_ids.append(visual_id)
            evidence = EvidenceIR(
                document_id,
                unit_id,
                {"slide_number": index},
                regions=(region,),
                tables=tables,
                numeric_facts=numeric_facts,
                visual_elements=visual_elements,
                required_source_ids=tuple(required_ids),
            ).with_revision()
            save_evidence(run, evidence)
            regions = [{"region_id": region_id, "english": "Revenue KRW 10 million", "term_ids": [], "unresolved": False, "provenance": "source_fact", "evidence_ids": [region_id]}]
            tables_patch = [{"table_id": f"{unit_id}-table-1", "cells": [{"cell_id": cell_id, "english": "Revenue", "unresolved": False, "provenance": "source_fact", "evidence_ids": [cell_id]}]}] if kind == "table_cell" else []
            visual_patch = [{"relation_id": f"{unit_id}-relation-1", "interpretation": "The bar increases.", "evidence_ids": [region_id], "source_element_ids": [visual_id], "relation_type": "highlights", "direction": "left_to_right", "provenance": "supported_interpretation"}] if kind == "visual_relation" else []
            claims = [{"claim_id": f"{unit_id}-claim", "kind": "key_number", "text": "Revenue is KRW 10 million.", "evidence_ids": [region_id], "uncertainty": "low", "provenance": "supported_interpretation"}] if kind == "executive_claim" else []
            patch = parse_translation_patch({"schema_version": "1.0", "work_unit_id": unit_id, "evidence_revision": evidence.evidence_revision, "regions": regions, "tables": tables_patch, "visual_interpretations": visual_patch, "executive_claims": claims})
            slide = merge_evidence_patch(evidence, patch)
            atomic_write_json(storage_path(run, StorageArtifact.CANONICAL_IR, f"ir/{unit_id}.json", create_parent=True), slide.as_dict(), mode=0o600)
            evidences.append(evidence)
        save_queue(run, WorkQueue("run-ksa23-typed", [WorkUnit(item.work_unit_id, item.document_id, f"source-{index:03d}", index - 1, status=WorkUnitStatus.TRANSLATED) for index, item in enumerate(evidences, start=1)]))
        atomic_write_json(storage_path(run, StorageArtifact.RUN_MANIFEST, "RUN_MANIFEST.json", create_parent=True), {"inputs": [{"source_name": "ko.pptx"}, {"source_name": "en.pptx"}]})
        ids = {
            "region": (f"{evidences[0].work_unit_id}-r1", f"{evidences[1].work_unit_id}-r1"),
            "table_cell": (f"{evidences[0].work_unit_id}-table-1-r0-c0", f"{evidences[1].work_unit_id}-table-1-r0-c0"),
            "visual_relation": (f"{evidences[0].work_unit_id}-relation-1", f"{evidences[1].work_unit_id}-relation-1"),
            "executive_claim": (f"{evidences[0].work_unit_id}-claim", f"{evidences[1].work_unit_id}-claim"),
            "numeric_fact": (f"{evidences[0].work_unit_id}-fact-1", f"{evidences[1].work_unit_id}-fact-1"),
        }[kind]
        return run, evidences[0], evidences[1], ids[0], ids[1]

    def _run(self, *, two_documents: bool = True, authority_text: bool = False, claim_kind: str = "owner", workspace_layout: bool = False) -> tuple[Path, EvidenceIR, EvidenceIR]:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        workspace = Path(directory.name)
        run = workspace / ".k-slide-runs" / "run" if workspace_layout else workspace / "run"
        run.mkdir(parents=True)
        evidence_a = self._unit(
            run,
            unit_id="doc-a-slide-001",
            document_id="doc-a",
            source_index=0,
            source_text="책임자는 김 과장이다.",
            language="ko",
            claim_text="The owner is Manager Kim.",
            authority_text=(
                "공식 정정: AUTHORITY_SUPERSEDES: "
                + assertion_id_for(
                    "doc-b" if two_documents else "doc-a",
                    "doc-b-slide-001" if two_documents else "doc-a-slide-002",
                    AssertionKind.EXECUTIVE_CLAIM.value,
                    ("doc-b-slide-001" if two_documents else "doc-a-slide-002") + "-claim",
                )
            ) if authority_text else None,
            claim_kind=claim_kind,
        )
        evidence_b = self._unit(
            run,
            unit_id="doc-b-slide-001" if two_documents else "doc-a-slide-002",
            document_id="doc-b" if two_documents else "doc-a",
            source_index=0 if two_documents else 1,
            source_text="Owner: Director Park.",
            language="en",
            claim_text="The owner is Director Park.",
            claim_kind=claim_kind,
        )
        save_queue(
            run,
            WorkQueue(
                run_id="run-ksa23",
                work_units=[
                    WorkUnit("doc-a-slide-001", "doc-a", "source-001", 0, status=WorkUnitStatus.TRANSLATED),
                    WorkUnit(evidence_b.work_unit_id, evidence_b.document_id, "source-002", evidence_b.source["slide_number"] - 1, status=WorkUnitStatus.TRANSLATED),
                ],
            ),
        )
        atomic_write_json(storage_path(run, StorageArtifact.RUN_MANIFEST, "RUN_MANIFEST.json", create_parent=True), {"inputs": [{"source_name": "a.pptx"}, {"source_name": "b.pptx"}]})
        return run, evidence_a, evidence_b

    def _conflict(self, run: Path, evidence_a: EvidenceIR, evidence_b: EvidenceIR) -> tuple[Conflict, object, object]:
        first = build_assertion_reference(run, evidence_a.work_unit_id, AssertionKind.EXECUTIVE_CLAIM.value, f"{evidence_a.work_unit_id}-claim")
        second = build_assertion_reference(run, evidence_b.work_unit_id, AssertionKind.EXECUTIVE_CLAIM.value, f"{evidence_b.work_unit_id}-claim")
        conflict_id = conflict_id_for((first.assertion_id, second.assertion_id))
        return Conflict(conflict_id, (first, second)), first, second

    def test_korean_english_cross_document_conflict_retains_exact_context_and_locations(self) -> None:
        run, evidence_a, evidence_b = self._run()
        conflict, first, second = self._conflict(run, evidence_a, evidence_b)
        registry = finalize_registry(ConflictRegistry("run-ksa23", (conflict,)))
        save_conflict_registry(run, registry)
        loaded = load_conflict_registry(run)
        self.assertIsNotNone(loaded)
        assert loaded is not None
        loaded.validate_against_run(run)
        self.assertEqual(loaded.conflicts[0].resolution_state, ConflictResolutionState.UNRESOLVED.value)
        self.assertEqual(first.source_context["language"], "ko")
        self.assertEqual(first.source_context["text"], "책임자는 김 과장이다.")
        self.assertEqual(second.source_context["language"], "en")
        self.assertEqual(first.location["document_id"], "doc-a")
        self.assertEqual(second.location["document_id"], "doc-b")
        self.assertEqual(first.canonical_ref["json_pointer"], "/executive_semantics/executive_claims/0")

    def test_same_document_cross_slide_locations_are_distinct(self) -> None:
        run, evidence_a, evidence_b = self._run(two_documents=False)
        conflict, first, second = self._conflict(run, evidence_a, evidence_b)
        self.assertEqual(first.document_id, second.document_id)
        self.assertNotEqual(first.work_unit_id, second.work_unit_id)
        self.assertNotEqual(first.location["source_index"], second.location["source_index"])
        finalize_registry(ConflictRegistry("run-ksa23", (conflict,))).validate_against_run(run)

    def test_numeric_date_status_and_owner_claims_use_existing_closed_claim_model(self) -> None:
        for kind in ("key_number", "timing", "decision_status", "owner"):
            run, evidence_a, evidence_b = self._run(claim_kind=kind)
            first = build_assertion_reference(run, evidence_a.work_unit_id, AssertionKind.EXECUTIVE_CLAIM.value, f"{evidence_a.work_unit_id}-claim")
            self.assertEqual(first.semantic_kind, "executive_claim")
            self.assertEqual(first.rendered_context["text"], "The owner is Manager Kim.")
            self.assertEqual(parse_translation_patch(self._patch(evidence_a, claim_text="The owner is Manager Kim.", claim_kind=kind)).executive_claims[0]["kind"], kind)

    def test_evidence_backed_authoritative_supersession_is_separate_and_keeps_both_claims(self) -> None:
        run, evidence_a, evidence_b = self._run(authority_text=True)
        conflict, first, second = self._conflict(run, evidence_a, evidence_b)
        authority = build_authority_evidence_reference(run, evidence_a.work_unit_id, (f"{evidence_a.work_unit_id}-authority",))
        supersession_id = supersession_id_for(conflict.conflict_id, second.assertion_id, first.assertion_id, "explicit_evidence", (authority.as_dict(),), None)
        supersession = Supersession(
            supersession_id,
            conflict.conflict_id,
            second.assertion_id,
            first.assertion_id,
            authority_basis=SupersessionAuthorityBasis.EXPLICIT_EVIDENCE.value,
            authority_evidence=(authority,),
        )
        resolved = Conflict(conflict.conflict_id, conflict.participants, ConflictResolutionState.RESOLVED_BY_AUTHORITATIVE_SUPERSESSION.value, (supersession_id,))
        registry = finalize_registry(ConflictRegistry("run-ksa23", (resolved,), (supersession,)))
        save_conflict_registry(run, registry)
        loaded = load_conflict_registry(run)
        self.assertEqual(loaded, registry)
        assert loaded is not None
        loaded.validate_against_run(run)
        self.assertEqual({item.rendered_context["text"] for item in loaded.conflicts[0].participants}, {"The owner is Manager Kim.", "The owner is Director Park."})
        render_run(run)
        report = storage_path(run, StorageArtifact.REPORT, "05_final_report.md").read_text(encoding="utf-8")
        brief = storage_path(run, StorageArtifact.REPORT, "05_executive_brief.md").read_text(encoding="utf-8")
        self.assertIn("Every competing assertion is retained", report)
        self.assertIn("The owner is Manager Kim.", report)
        self.assertIn("The owner is Director Park.", report)
        self.assertIn("authoritative", report)
        self.assertIn("RESOLVED BY AUTHORITATIVE SUPERSESSION", brief)

    def test_configured_authority_is_deterministic_and_not_model_confidence(self) -> None:
        run, evidence_a, evidence_b = self._run()
        atomic_write_json(
            storage_path(run, StorageArtifact.RUN_MANIFEST, "RUN_MANIFEST.json", create_parent=True),
            {"inputs": [{"source_name": "a.pptx"}, {"source_name": "b.pptx"}], "conflict_authority": {"configured_authority_ids": ["policy-v1"]}},
        )
        conflict, first, second = self._conflict(run, evidence_a, evidence_b)
        supersession_id = supersession_id_for(conflict.conflict_id, second.assertion_id, first.assertion_id, "configured_authority", (), "policy-v1")
        supersession = Supersession(
            supersession_id,
            conflict.conflict_id,
            second.assertion_id,
            first.assertion_id,
            authority_basis=SupersessionAuthorityBasis.CONFIGURED_AUTHORITY.value,
            authority_config_id="policy-v1",
        )
        resolved = Conflict(conflict.conflict_id, conflict.participants, ConflictResolutionState.RESOLVED_BY_AUTHORITATIVE_SUPERSESSION.value, (supersession_id,))
        registry = finalize_registry(ConflictRegistry("run-ksa23", (resolved,), (supersession,)))
        save_conflict_registry(run, registry, configured_authority_ids={"policy-v1"})
        result = VerificationResult(status="PASS", run_id="run-ksa23")
        _validate_conflict_registry(run, result)
        self.assertFalse(result.issues)

    def test_unknown_authority_stays_unresolved_and_blocks_run_completion_surface(self) -> None:
        run, evidence_a, evidence_b = self._run()
        conflict, _, _ = self._conflict(run, evidence_a, evidence_b)
        registry = finalize_registry(ConflictRegistry("run-ksa23", (conflict,)))
        save_conflict_registry(run, registry)
        result = VerificationResult(status="PASS", run_id="run-ksa23")
        _validate_conflict_registry(run, result)
        self.assertIn("KSLIDE_CONFLICT_UNRESOLVED", {issue.code for issue in result.issues})
        render_run(run)
        report = storage_path(run, StorageArtifact.REPORT, "05_final_report.md").read_text(encoding="utf-8")
        self.assertIn("authority remains unknown", report)
        self.assertIn("The owner is Manager Kim.", report)
        self.assertIn("The owner is Director Park.", report)

    def test_model_or_manual_repair_of_competing_context_is_rejected(self) -> None:
        run, evidence_a, evidence_b = self._run()
        conflict, first, second = self._conflict(run, evidence_a, evidence_b)
        tampered_participant = replace(first, rendered_context={"language": "en", "text": "The owner is Director Park."})
        tampered_conflict = Conflict(conflict.conflict_id, (tampered_participant, second))
        registry = finalize_registry(ConflictRegistry("run-ksa23", (tampered_conflict,)))
        with self.assertRaises(KSlideError) as raised:
            registry.validate_against_run(run)
        self.assertEqual(raised.exception.code, ErrorCode.CONFLICT_REFERENCE_INVALID)

    def test_dangling_foreign_and_stale_references_fail_closed(self) -> None:
        run, evidence_a, evidence_b = self._run()
        conflict, first, second = self._conflict(run, evidence_a, evidence_b)
        foreign = replace(first, semantic_id="foreign-claim", assertion_id=assertion_id_for(first.document_id, first.work_unit_id, first.semantic_kind, "foreign-claim"))
        foreign_conflict = Conflict(conflict_id_for((foreign.assertion_id, second.assertion_id)), (foreign, second))
        registry = finalize_registry(ConflictRegistry("run-ksa23", (foreign_conflict,)))
        with self.assertRaises(KSlideError):
            registry.validate_against_run(run)
        stale = replace(first, evidence_ref={**first.evidence_ref, "evidence_revision": "f" * 64})
        stale_conflict = Conflict(conflict.conflict_id, (stale, second))
        stale_registry = finalize_registry(ConflictRegistry("run-ksa23", (stale_conflict,)))
        with self.assertRaises(KSlideError) as raised:
            stale_registry.validate_against_run(run)
        self.assertEqual(raised.exception.code, ErrorCode.CONFLICT_REFERENCE_INVALID)

    def test_self_conflicting_winners_and_cycles_are_rejected(self) -> None:
        run, evidence_a, evidence_b = self._run()
        conflict, first, second = self._conflict(run, evidence_a, evidence_b)
        self_ref = Supersession("sup-self", conflict.conflict_id, first.assertion_id, first.assertion_id)
        with self.assertRaises(KSlideError):
            finalize_registry(ConflictRegistry("run-ksa23", (Conflict(conflict.conflict_id, conflict.participants, ConflictResolutionState.RESOLVED_BY_AUTHORITATIVE_SUPERSESSION.value, ("sup-self",)),), (self_ref,)))
        cycle_a = Supersession("sup-a", conflict.conflict_id, first.assertion_id, second.assertion_id)
        cycle_b = Supersession("sup-b", conflict.conflict_id, second.assertion_id, first.assertion_id)
        with self.assertRaises(KSlideError):
            finalize_registry(ConflictRegistry("run-ksa23", (Conflict(conflict.conflict_id, conflict.participants, ConflictResolutionState.RESOLVED_BY_AUTHORITATIVE_SUPERSESSION.value, ("sup-a", "sup-b")),), (cycle_a, cycle_b)))
        with self.assertRaises(KSlideError) as raised:
            Supersession.from_dict({
                "supersession_id": "sup-confidence",
                "conflict_id": conflict.conflict_id,
                "superseding_assertion_id": first.assertion_id,
                "superseded_assertion_id": second.assertion_id,
                "state": "authoritative",
                "authority_basis": "explicit_evidence",
                "authority_evidence": [],
                "authority_config_id": None,
                "confidence": 0.99,
            })
        self.assertEqual(raised.exception.code, ErrorCode.SCHEMA_INVALID)

    def test_conflict_registry_schema_matches_deterministic_artifact(self) -> None:
        run, evidence_a, evidence_b = self._run()
        conflict, _, _ = self._conflict(run, evidence_a, evidence_b)
        registry = finalize_registry(ConflictRegistry("run-ksa23", (conflict,)))
        schema = json.loads((Path(__file__).resolve().parents[1] / "schemas" / "conflict-registry.schema.json").read_text(encoding="utf-8"))
        try:
            import jsonschema
        except ImportError:
            jsonschema = None
        if jsonschema is not None:
            jsonschema.validate(registry.as_dict(), schema)

    def test_legacy_absence_is_readable_but_not_claimed_as_no_conflicts_and_round_trip_is_deterministic(self) -> None:
        run, evidence_a, evidence_b = self._run()
        self.assertIsNone(load_conflict_registry(run))
        render_run(run)
        report = storage_path(run, StorageArtifact.REPORT, "05_final_report.md").read_text(encoding="utf-8")
        self.assertIn("conflict coverage is not assessed", report)
        conflict, _, _ = self._conflict(run, evidence_a, evidence_b)
        registry = finalize_registry(ConflictRegistry("run-ksa23", (conflict,)))
        save_conflict_registry(run, registry)
        first_bytes = conflict_registry_path(run).read_bytes()
        resumed = load_conflict_registry(run)
        assert resumed is not None
        save_conflict_registry(run, resumed)
        self.assertEqual(first_bytes, conflict_registry_path(run).read_bytes())
        self.assertEqual(resumed.as_dict(), registry.as_dict())

    def test_ksa23_contract_requires_engine_assessment_and_distinguishes_zero(self) -> None:
        run, _, _ = self._run(claim_kind="takeaway")
        manifest_path = storage_path(run, StorageArtifact.RUN_MANIFEST, "RUN_MANIFEST.json")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["conflict_registry_contract"] = {"schema_version": "1.0", "assessment_required": True}
        manifest["conflict_authority"] = {"schema_version": "1.0", "rules": []}
        atomic_write_json(manifest_path, manifest)
        self.assertTrue(conflict_contract_required(run))
        result = VerificationResult(status="PASS", run_id="run-ksa23")
        _validate_conflict_registry(run, result)
        self.assertIn("KSLIDE_CONFLICT_ASSESSMENT_REQUIRED", {issue.code for issue in result.issues})

        registry = assess_conflicts(run, candidate_groups=[])
        self.assertEqual(registry.conflicts, ())
        result = VerificationResult(status="PASS", run_id="run-ksa23")
        _validate_conflict_registry(run, result)
        self.assertFalse(result.issues)

    def test_engine_assessment_admits_typed_candidates_without_model_context(self) -> None:
        run, evidence_a, evidence_b = self._run(claim_kind="takeaway")
        first_id = f"{evidence_a.work_unit_id}-claim"
        second_id = f"{evidence_b.work_unit_id}-claim"
        registry = assess_conflicts(
            run,
            candidate_groups=[{
                "assertions": [
                    {"work_unit_id": evidence_a.work_unit_id, "semantic_kind": "executive_claim", "semantic_id": first_id},
                    {"work_unit_id": evidence_b.work_unit_id, "semantic_kind": "executive_claim", "semantic_id": second_id},
                ]
            }],
        )
        self.assertEqual(len(registry.conflicts), 1)
        self.assertEqual(registry.conflicts[0].participants[0].rendered_context["language"], "en")
        with self.assertRaises(KSlideError) as raised:
            assess_conflicts(run, candidate_groups=[{"assertions": [{"work_unit_id": evidence_a.work_unit_id, "semantic_kind": "executive_claim", "semantic_id": first_id, "source_context": "forged"}, {"work_unit_id": evidence_b.work_unit_id, "semantic_kind": "executive_claim", "semantic_id": second_id}]}])
        self.assertEqual(raised.exception.code, ErrorCode.SCHEMA_INVALID)

    def test_typed_canonical_references_admit_cross_document_and_cross_slide_contradictions(self) -> None:
        for two_documents in (True, False):
            with self.subTest(two_documents=two_documents):
                run, evidence_a, evidence_b = self._run(two_documents=two_documents)
                registry = assess_conflicts(
                    run,
                    candidate_groups=[{
                        "assertions": [
                            {"work_unit_id": evidence_a.work_unit_id, "semantic_kind": "region", "semantic_id": f"{evidence_a.work_unit_id}-r1"},
                            {"work_unit_id": evidence_b.work_unit_id, "semantic_kind": "region", "semantic_id": f"{evidence_b.work_unit_id}-r1"},
                        ]
                    }],
                )
                self.assertEqual(len(registry.conflicts), 1)
                participants = registry.conflicts[0].participants
                self.assertEqual({item.location["source_index"] for item in participants}, {0, 1} if not two_documents else {0})
                if two_documents:
                    self.assertEqual({item.document_id for item in participants}, {evidence_a.document_id, evidence_b.document_id})

    def test_broad_claim_kind_and_different_text_do_not_admit_unrelated_objects(self) -> None:
        for kind, first_text, second_text in (
            ("owner", "Project Alpha owner: Manager Kim.", "Project Beta owner: Director Park."),
            ("timing", "Project Alpha milestone: Q2.", "Project Beta milestone: Q4."),
            ("key_number", "Project Alpha revenue: KRW 10m.", "Project Beta users: 20k."),
        ):
            with self.subTest(kind=kind):
                run, evidence_a, evidence_b = self._run(claim_kind=kind)
                for unit_id, text in ((evidence_a.work_unit_id, first_text), (evidence_b.work_unit_id, second_text)):
                    path = storage_path(run, StorageArtifact.CANONICAL_IR, f"ir/{unit_id}.json")
                    value = json.loads(path.read_text(encoding="utf-8"))
                    value["executive_semantics"]["executive_claims"][0]["text"] = text
                    atomic_write_json(path, value)
                registry = assess_conflicts(run, candidate_groups=[])
                self.assertEqual(registry.assessment_status, "ASSESSED_ZERO_CONFLICTS")

    def test_typed_candidate_admission_supports_every_canonical_assertion_kind(self) -> None:
        for kind in ("region", "table_cell", "visual_relation", "executive_claim", "numeric_fact"):
            with self.subTest(kind=kind):
                run, evidence_a, evidence_b, first_id, second_id = self._typed_kind_run(kind)
                registry = assess_conflicts(
                    run,
                    candidate_groups=[{
                        "assertions": [
                            {"work_unit_id": evidence_a.work_unit_id, "semantic_kind": kind, "semantic_id": first_id},
                            {"work_unit_id": evidence_b.work_unit_id, "semantic_kind": kind, "semantic_id": second_id},
                        ]
                    }],
                )
                self.assertEqual(len(registry.conflicts), 1)

    def test_new_run_lifecycle_keeps_assessment_required_until_typed_stage(self) -> None:
        from unittest.mock import patch

        from k_slide.cli import _conflict_assess, _next, _submit
        from k_slide.state import RunPhase, RunState, save_state

        run, evidence_a, evidence_b = self._run(workspace_layout=True)
        manifest_path = storage_path(run, StorageArtifact.RUN_MANIFEST, "RUN_MANIFEST.json")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["conflict_registry_contract"] = {"schema_version": "1.0", "assessment_required": True}
        manifest["conflict_authority"] = {"schema_version": "1.0", "rules": []}
        manifest["conflict_assessment"] = {"schema_version": "1.0", "status": "NOT_ASSESSED"}
        atomic_write_json(manifest_path, manifest)
        queue = load_queue(run)
        queue.get(evidence_a.work_unit_id).status = WorkUnitStatus.TRANSLATING
        queue.get(evidence_b.work_unit_id).status = WorkUnitStatus.TRANSLATED
        save_queue(run, queue)
        save_state(run, RunState("run-ksa23", "standard", RunPhase.TRANSLATING, current_work_unit=evidence_a.work_unit_id))
        translation_payload = self._patch(evidence_a, claim_text="The owner is Manager Kim.")
        translation_payload["regions"][0]["english"] = "The owner is Manager Kim."
        payload = json.dumps(translation_payload, ensure_ascii=False)
        with patch("k_slide.cli.ensure_workspace_environment_compatible", return_value=(None, None)):
            self.assertEqual(_submit(run.parent.parent, run.name, payload, None)["status"], "ACCEPTED")
            self.assertEqual(_next(run.parent.parent, run.name, None)["status"], "CONFLICT_ASSESSMENT_REQUIRED")
            self.assertEqual(conflict_assessment_status(run), "NOT_ASSESSED")
        blocked = VerificationResult(status="PASS", run_id="run-ksa23")
        _validate_conflict_registry(run, blocked)
        self.assertIn("KSLIDE_CONFLICT_ASSESSMENT_REQUIRED", {issue.code for issue in blocked.issues})
        with patch("k_slide.cli.ensure_workspace_environment_compatible", return_value=(None, None)):
            assessed = _conflict_assess(run.parent.parent, run.name, '{"schema_version":"1.0","candidate_groups":[]}', None)
        self.assertEqual(assessed["status"], "ASSESSED_ZERO_CONFLICTS")
        self.assertEqual(conflict_assessment_status(run), "ASSESSED_ZERO_CONFLICTS")
        with patch("k_slide.cli.ensure_workspace_environment_compatible", return_value=(None, None)):
            self.assertEqual(_next(run.parent.parent, run.name, None)["status"], "ALL_TRANSLATED")
        with patch("k_slide.execution.ensure_workspace_environment_compatible", return_value=(None, None)), patch("k_slide.verify.resolve_run_termbase", return_value=Termbase("1.0")):
            self.assertTrue(verify_run(run).passed)

    def test_ksa23_explicit_relation_binds_exact_competing_evidence(self) -> None:
        run, evidence_a, evidence_b = self._run(authority_text=True)
        manifest_path = storage_path(run, StorageArtifact.RUN_MANIFEST, "RUN_MANIFEST.json")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["conflict_registry_contract"] = {"schema_version": "1.0", "assessment_required": True}
        manifest["conflict_authority"] = {"schema_version": "1.0", "rules": []}
        atomic_write_json(manifest_path, manifest)
        conflict, first, second = self._conflict(run, evidence_a, evidence_b)
        authority = build_authority_evidence_reference(run, evidence_a.work_unit_id, (f"{evidence_a.work_unit_id}-authority",))
        relation = {
            "relation_type": "supersedes",
            "superseding_assertion_id": second.assertion_id,
            "superseded_assertion_id": first.assertion_id,
            "superseding_evidence_ids": sorted(second.provenance_evidence_ids),
            "superseded_evidence_ids": sorted(first.provenance_evidence_ids),
            "authority_evidence_ids": sorted(authority.evidence_ids),
        }
        supersession_id = supersession_id_for(conflict.conflict_id, second.assertion_id, first.assertion_id, "explicit_evidence", (authority.as_dict(),), None, relation)
        supersession = Supersession(
            supersession_id,
            conflict.conflict_id,
            second.assertion_id,
            first.assertion_id,
            authority_basis=SupersessionAuthorityBasis.EXPLICIT_EVIDENCE.value,
            authority_evidence=(authority,),
            authority_relation=relation,
        )
        resolved = Conflict(conflict.conflict_id, conflict.participants, ConflictResolutionState.RESOLVED_BY_AUTHORITATIVE_SUPERSESSION.value, (supersession_id,))
        save_conflict_registry(run, finalize_registry(ConflictRegistry("run-ksa23", (resolved,), (supersession,))))
        reversed_relation = {
            **relation,
            "superseding_assertion_id": first.assertion_id,
            "superseded_assertion_id": second.assertion_id,
            "superseding_evidence_ids": sorted(first.provenance_evidence_ids),
            "superseded_evidence_ids": sorted(second.provenance_evidence_ids),
        }
        reversed_id = supersession_id_for(conflict.conflict_id, first.assertion_id, second.assertion_id, "explicit_evidence", (authority.as_dict(),), None, reversed_relation)
        reversed_supersession = Supersession(
            reversed_id,
            conflict.conflict_id,
            first.assertion_id,
            second.assertion_id,
            authority_basis=SupersessionAuthorityBasis.EXPLICIT_EVIDENCE.value,
            authority_evidence=(authority,),
            authority_relation=reversed_relation,
        )
        reversed_registry = finalize_registry(ConflictRegistry("run-ksa23", (replace(resolved, supersession_ids=(reversed_id,)),), (reversed_supersession,)))
        with self.assertRaises(KSlideError) as raised:
            save_conflict_registry(run, reversed_registry)
        self.assertEqual(raised.exception.code, ErrorCode.SUPERSESSION_INVALID)
        unrelated = build_authority_evidence_reference(run, evidence_a.work_unit_id, (f"{evidence_a.work_unit_id}-r1",))
        bad_relation = {**relation, "authority_evidence_ids": sorted(unrelated.evidence_ids)}
        bad_id = supersession_id_for(conflict.conflict_id, second.assertion_id, first.assertion_id, "explicit_evidence", (unrelated.as_dict(),), None, bad_relation)
        bad = Supersession(
            bad_id,
            conflict.conflict_id,
            second.assertion_id,
            first.assertion_id,
            authority_basis=SupersessionAuthorityBasis.EXPLICIT_EVIDENCE.value,
            authority_evidence=(unrelated,),
            authority_relation=bad_relation,
        )
        bad_registry = finalize_registry(ConflictRegistry("run-ksa23", (replace(resolved, supersession_ids=(bad_id,)),), (bad,)))
        with self.assertRaises(KSlideError) as raised:
            save_conflict_registry(run, bad_registry)
        self.assertEqual(raised.exception.code, ErrorCode.SUPERSESSION_INVALID)

    def test_ksa23_configured_policy_recomputes_direction_and_rejects_reversal(self) -> None:
        run, evidence_a, evidence_b = self._run()
        manifest_path = storage_path(run, StorageArtifact.RUN_MANIFEST, "RUN_MANIFEST.json")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["conflict_registry_contract"] = {"schema_version": "1.0", "assessment_required": True}
        manifest["conflict_authority"] = {
            "schema_version": "1.0",
            "rules": [{"authority_config_id": "policy-v1", "priority": 10, "winner_selector": {"document_id": "doc-b"}, "loser_selector": {"document_id": "doc-a"}}],
        }
        atomic_write_json(manifest_path, manifest)
        policy_revision = authority_policy_revision({"schema_version": "1.0", "rules": manifest["conflict_authority"]["rules"]})
        conflict, first, second = self._conflict(run, evidence_a, evidence_b)
        supersession_id = supersession_id_for(conflict.conflict_id, second.assertion_id, first.assertion_id, "configured_authority", (), "policy-v1", None, policy_revision)
        supersession = Supersession(supersession_id, conflict.conflict_id, second.assertion_id, first.assertion_id, authority_basis=SupersessionAuthorityBasis.CONFIGURED_AUTHORITY.value, authority_config_id="policy-v1", authority_config_revision=policy_revision)
        resolved = Conflict(conflict.conflict_id, conflict.participants, ConflictResolutionState.RESOLVED_BY_AUTHORITATIVE_SUPERSESSION.value, (supersession_id,))
        save_conflict_registry(run, finalize_registry(ConflictRegistry("run-ksa23", (resolved,), (supersession,))))
        reverse_id = supersession_id_for(conflict.conflict_id, first.assertion_id, second.assertion_id, "configured_authority", (), "policy-v1", None, policy_revision)
        reverse = Supersession(reverse_id, conflict.conflict_id, first.assertion_id, second.assertion_id, authority_basis=SupersessionAuthorityBasis.CONFIGURED_AUTHORITY.value, authority_config_id="policy-v1", authority_config_revision=policy_revision)
        reversed_registry = finalize_registry(ConflictRegistry("run-ksa23", (Conflict(conflict.conflict_id, conflict.participants, ConflictResolutionState.RESOLVED_BY_AUTHORITATIVE_SUPERSESSION.value, (reverse_id,)),), (reverse,)))
        with self.assertRaises(KSlideError) as raised:
            save_conflict_registry(run, reversed_registry)
        self.assertEqual(raised.exception.code, ErrorCode.SUPERSESSION_INVALID)

    def _runtime_contract(self, run: Path, *, rules: list[dict[str, object]]) -> None:
        manifest_path = storage_path(run, StorageArtifact.RUN_MANIFEST, "RUN_MANIFEST.json")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["conflict_registry_contract"] = {"schema_version": "1.0", "assessment_required": True}
        manifest["conflict_authority"] = {"schema_version": "1.0", "rules": rules}
        manifest["conflict_assessment"] = {"schema_version": "1.0", "status": "NOT_ASSESSED"}
        atomic_write_json(manifest_path, manifest)

    def _runtime_state(self, run: Path) -> None:
        from k_slide.state import RunPhase, RunState, save_state

        save_state(run, RunState("run-ksa23", "standard", RunPhase.TRANSLATED, input_count=2))

    def _runtime_english(self, run: Path, *evidences: EvidenceIR) -> None:
        for evidence in evidences:
            path = storage_path(run, StorageArtifact.CANONICAL_IR, f"ir/{evidence.work_unit_id}.json")
            value = json.loads(path.read_text(encoding="utf-8"))
            for region in value.get("regions", []):
                region["translation"] = "Source evidence"
            atomic_write_json(path, value)

    def _runtime_candidate_group(self, evidence_a: EvidenceIR, evidence_b: EvidenceIR) -> list[dict[str, object]]:
        return [{"assertions": [
            {"work_unit_id": evidence_a.work_unit_id, "semantic_kind": "executive_claim", "semantic_id": f"{evidence_a.work_unit_id}-claim"},
            {"work_unit_id": evidence_b.work_unit_id, "semantic_kind": "executive_claim", "semantic_id": f"{evidence_b.work_unit_id}-claim"},
        ]}]

    def test_runtime_configured_authority_resolves_and_finalizes_without_model_winner(self) -> None:
        from k_slide.cli import _conflict_assess, _conflict_resolve
        from unittest.mock import patch

        run, evidence_a, evidence_b = self._run(workspace_layout=True)
        self._runtime_contract(run, rules=[{"authority_config_id": "policy-v1", "priority": 10, "winner_selector": {"document_id": "doc-b"}, "loser_selector": {"document_id": "doc-a"}}])
        self._runtime_state(run)
        self._runtime_english(run, evidence_a, evidence_b)
        root = run.parent.parent
        with patch("k_slide.cli.ensure_workspace_environment_compatible", return_value=(None, None)):
            assessed = _conflict_assess(root, run.name, json.dumps({"schema_version": "1.0", "candidate_groups": self._runtime_candidate_group(evidence_a, evidence_b)}), None)
            conflict_id = assessed["unresolved_conflict_ids"][0]
            resolved = _conflict_resolve(root, run.name, json.dumps({"schema_version": "1.0", "conflict_id": conflict_id}), None)
        self.assertEqual(resolved["status"], "RESOLVED")
        registry = load_conflict_registry(run)
        assert registry is not None
        conflict = registry.conflicts[0]
        supersession = registry.supersessions[0]
        self.assertEqual(supersession.superseding_assertion_id, next(item.assertion_id for item in conflict.participants if item.document_id == "doc-b"))
        self.assertEqual(supersession.authority_config_id, "policy-v1")
        original_registry = conflict_registry_path(run).read_bytes()
        with patch("k_slide.cli.ensure_workspace_environment_compatible", return_value=(None, None)):
            self.assertEqual(_conflict_resolve(root, run.name, json.dumps({"schema_version": "1.0", "conflict_id": conflict_id}), None)["status"], "RESOLVED")
        self.assertEqual(original_registry, conflict_registry_path(run).read_bytes())
        with patch("k_slide.cli.ensure_workspace_environment_compatible", return_value=(None, None)), self.assertRaises(KSlideError) as raised:
            _conflict_resolve(root, run.name, json.dumps({"schema_version": "1.0", "conflict_id": conflict_id, "superseding_assertion_id": "caller-choice"}), None)
        self.assertEqual(raised.exception.code, ErrorCode.SCHEMA_INVALID)
        with patch("k_slide.cli.ensure_workspace_environment_compatible", return_value=(None, None)), self.assertRaises(KSlideError) as raised:
            _conflict_resolve(root, run.name, json.dumps({"schema_version": "1.0", "conflict_id": conflict_id, "authority_evidence": None}), None)
        self.assertEqual(raised.exception.code, ErrorCode.SCHEMA_INVALID)
        manifest_path = storage_path(run, StorageArtifact.RUN_MANIFEST, "RUN_MANIFEST.json")
        original_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self._runtime_contract(run, rules=[{"authority_config_id": "policy-v1", "priority": 10, "winner_selector": {"document_id": "doc-a"}, "loser_selector": {"document_id": "doc-b"}}])
        with patch("k_slide.cli.ensure_workspace_environment_compatible", return_value=(None, None)), self.assertRaises(KSlideError) as raised:
            _conflict_resolve(root, run.name, json.dumps({"schema_version": "1.0", "conflict_id": conflict_id}), None)
        self.assertEqual(raised.exception.code, ErrorCode.SUPERSESSION_INVALID)
        atomic_write_json(manifest_path, original_manifest)
        render_run(run)
        with patch("k_slide.execution.ensure_workspace_environment_compatible", return_value=(None, None)), patch("k_slide.verify.resolve_run_termbase", return_value=Termbase("1.0")):
            verification = verify_run(run)
            self.assertTrue(verification.passed, verification.as_dict())
            finalize_run(run)
        self.assertTrue(storage_path(run, StorageArtifact.COMPLETION_MARKER, "RUN_COMPLETE.md").is_file())

    def test_runtime_explicit_authority_derives_direction_and_is_idempotent(self) -> None:
        from k_slide.cli import _conflict_assess, _conflict_resolve
        from unittest.mock import patch

        run, evidence_a, evidence_b = self._run(workspace_layout=True, authority_text=True)
        self._runtime_contract(run, rules=[])
        self._runtime_state(run)
        self._runtime_english(run, evidence_a, evidence_b)
        root = run.parent.parent
        with patch("k_slide.cli.ensure_workspace_environment_compatible", return_value=(None, None)):
            assessed = _conflict_assess(root, run.name, json.dumps({"schema_version": "1.0", "candidate_groups": self._runtime_candidate_group(evidence_a, evidence_b)}), None)
        conflict_id = assessed["unresolved_conflict_ids"][0]
        payload = {
            "schema_version": "1.0",
            "conflict_id": conflict_id,
            "authority_evidence": [{"work_unit_id": evidence_a.work_unit_id, "evidence_ids": [f"{evidence_a.work_unit_id}-authority"]}],
        }
        with patch("k_slide.cli.ensure_workspace_environment_compatible", return_value=(None, None)):
            resolved = _conflict_resolve(root, run.name, json.dumps(payload), None)
        self.assertEqual(resolved["status"], "RESOLVED")
        registry = load_conflict_registry(run)
        assert registry is not None
        self.assertEqual(registry.supersessions[0].superseding_assertion_id, next(item.assertion_id for item in registry.conflicts[0].participants if item.document_id == "doc-b"))
        original_registry = conflict_registry_path(run).read_bytes()
        with patch("k_slide.cli.ensure_workspace_environment_compatible", return_value=(None, None)):
            self.assertEqual(_conflict_resolve(root, run.name, json.dumps(payload), None)["status"], "RESOLVED")
        self.assertEqual(original_registry, conflict_registry_path(run).read_bytes())
        with patch("k_slide.cli.ensure_workspace_environment_compatible", return_value=(None, None)), self.assertRaises(KSlideError) as raised:
            _conflict_resolve(root, run.name, json.dumps({**payload, "superseding_assertion_id": "caller-choice"}), None)
        self.assertEqual(raised.exception.code, ErrorCode.SCHEMA_INVALID)
        render_run(run)
        with patch("k_slide.execution.ensure_workspace_environment_compatible", return_value=(None, None)), patch("k_slide.verify.resolve_run_termbase", return_value=Termbase("1.0")):
            verification = verify_run(run)
            self.assertTrue(verification.passed, verification.as_dict())
            finalize_run(run)
        self.assertTrue(storage_path(run, StorageArtifact.COMPLETION_MARKER, "RUN_COMPLETE.md").is_file())

    def test_runtime_authority_fail_closed_for_ambiguous_config_and_invalid_explicit_evidence(self) -> None:
        from k_slide.cli import _conflict_assess, _conflict_resolve
        from unittest.mock import patch

        run, evidence_a, evidence_b = self._run(workspace_layout=True)
        self._runtime_contract(run, rules=[
            {"authority_config_id": "policy-a", "priority": 10, "winner_selector": {"document_id": "doc-b"}, "loser_selector": {"document_id": "doc-a"}},
            {"authority_config_id": "policy-b", "priority": 10, "winner_selector": {"document_id": "doc-b"}, "loser_selector": {"document_id": "doc-a"}},
        ])
        self._runtime_state(run)
        self._runtime_english(run, evidence_a, evidence_b)
        root = run.parent.parent
        with patch("k_slide.cli.ensure_workspace_environment_compatible", return_value=(None, None)):
            assessed = _conflict_assess(root, run.name, json.dumps({"schema_version": "1.0", "candidate_groups": self._runtime_candidate_group(evidence_a, evidence_b)}), None)
        conflict_id = assessed["unresolved_conflict_ids"][0]
        with patch("k_slide.cli.ensure_workspace_environment_compatible", return_value=(None, None)):
            self.assertEqual(_conflict_resolve(root, run.name, json.dumps({"schema_version": "1.0", "conflict_id": conflict_id}), None)["status"], "UNRESOLVED")
        registry = load_conflict_registry(run)
        assert registry is not None
        self.assertEqual(registry.conflicts[0].resolution_state, ConflictResolutionState.UNRESOLVED.value)
        with patch("k_slide.cli.ensure_workspace_environment_compatible", return_value=(None, None)), self.assertRaises(KSlideError) as raised:
            _conflict_resolve(root, run.name, json.dumps({"schema_version": "1.0", "conflict_id": conflict_id, "authority_evidence": [{"work_unit_id": evidence_a.work_unit_id, "evidence_ids": [f"{evidence_a.work_unit_id}-r1"]}]}), None)
        self.assertEqual(raised.exception.code, ErrorCode.SUPERSESSION_INVALID)

    def test_runtime_explicit_authority_rejects_foreign_and_stale_evidence(self) -> None:
        from k_slide.cli import _conflict_assess, _conflict_resolve
        from unittest.mock import patch

        run, evidence_a, evidence_b = self._run(workspace_layout=True, authority_text=True)
        self._runtime_contract(run, rules=[])
        self._runtime_state(run)
        self._runtime_english(run, evidence_a, evidence_b)
        root = run.parent.parent
        with patch("k_slide.cli.ensure_workspace_environment_compatible", return_value=(None, None)):
            assessed = _conflict_assess(root, run.name, json.dumps({"schema_version": "1.0", "candidate_groups": self._runtime_candidate_group(evidence_a, evidence_b)}), None)
        conflict_id = assessed["unresolved_conflict_ids"][0]
        foreign_payload = {"schema_version": "1.0", "conflict_id": conflict_id, "authority_evidence": [{"work_unit_id": "foreign-unit", "evidence_ids": ["foreign-evidence"]}]}
        with patch("k_slide.cli.ensure_workspace_environment_compatible", return_value=(None, None)), self.assertRaises(KSlideError) as raised:
            _conflict_resolve(root, run.name, json.dumps(foreign_payload), None)
        self.assertEqual(raised.exception.code, ErrorCode.UNKNOWN_WORK_UNIT)
        queue = load_queue(run)
        queue.get(evidence_a.work_unit_id).evidence_revision = "f" * 64
        save_queue(run, queue)
        valid_payload = {"schema_version": "1.0", "conflict_id": conflict_id, "authority_evidence": [{"work_unit_id": evidence_a.work_unit_id, "evidence_ids": [f"{evidence_a.work_unit_id}-authority"]}]}
        with patch("k_slide.cli.ensure_workspace_environment_compatible", return_value=(None, None)), self.assertRaises(KSlideError) as raised:
            _conflict_resolve(root, run.name, json.dumps(valid_payload), None)
        self.assertEqual(raised.exception.code, ErrorCode.STALE_EVIDENCE)


if __name__ == "__main__":
    unittest.main()
