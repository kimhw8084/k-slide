from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from k_slide.bilingual_adjudication import build_internal_bilingual_payload
from k_slide.certification import (
    EVIDENCE_SCHEMA_VERSION,
    EvidenceValidationError,
    candidate_deployment_fingerprint,
    load_evidence,
    validate_evidence_payload,
    write_evidence,
)
from tests.bilingual_review_fixtures import (
    _seal,
    make_candidate,
    make_private_manifest,
    make_review_contract,
)


def _payload(*, disagreement_index: int | None = None, adjudicate: bool = True, ai_assistance: bool = False):
    manifest = make_private_manifest(item_count=3)
    candidate = make_candidate(manifest)
    deployment = candidate_deployment_fingerprint(candidate)
    contract = make_review_contract(
        subject=candidate["subject_git_sha"],
        deployment=deployment,
        manifest=manifest,
        disagreement_index=disagreement_index,
        adjudicate=adjudicate,
        ai_assistance=ai_assistance,
    )
    return build_internal_bilingual_payload(contract), candidate, manifest


class KSA29BilingualAdjudicationTests(unittest.TestCase):
    def _assert_rejected(self, payload: dict, candidate: dict | None = None) -> None:
        if isinstance(payload.get("review_contract"), dict):
            canonical = json.dumps(payload["review_contract"], ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
            payload["attestation_id"] = hashlib.sha256(canonical).hexdigest()
        with self.assertRaises(EvidenceValidationError):
            validate_evidence_payload("internal_bilingual", payload)
        if candidate is not None:
            with tempfile.TemporaryDirectory() as directory:
                with self.assertRaises(EvidenceValidationError):
                    write_evidence(
                        Path(directory) / "evidence.json",
                        evidence_type="internal_bilingual",
                        subject_git_sha=candidate["subject_git_sha"],
                        deployment_fingerprint=candidate_deployment_fingerprint(candidate),
                        payload=payload,
                        generated_at="2026-09-23T00:00:00Z",
                        candidate_spec=candidate,
                    )

    def test_valid_paired_reviews_and_exact_adjudication_derive_metrics(self):
        payload, candidate, _manifest = _payload(disagreement_index=3, ai_assistance=True)
        validate_evidence_payload("internal_bilingual", payload)
        self.assertEqual(payload["artifact_count"], 50)
        self.assertEqual(payload["work_unit_count"], 200)
        contract = payload["review_contract"]
        self.assertEqual(len(contract["review_records"]), 400)
        self.assertEqual(len(contract["adjudication_records"]), 1)
        decision = next(item for item in contract["truth_unit_decisions"] if item["agreement_status"] == "disagreement")
        self.assertEqual(decision["authoritative_outcome"], "correct")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bilingual.json"
            deployment = candidate_deployment_fingerprint(candidate)
            write_evidence(path, evidence_type="internal_bilingual", subject_git_sha=candidate["subject_git_sha"], deployment_fingerprint=deployment, payload=payload, generated_at="2026-09-23T00:00:00Z", candidate_spec=candidate)
            loaded = load_evidence(path, expected_type="internal_bilingual", subject_git_sha=candidate["subject_git_sha"], deployment_fingerprint=deployment, candidate_spec=candidate, require_candidate_spec=True)
            self.assertEqual(loaded["payload"], payload)

    def test_one_review_is_insufficient(self):
        payload, _candidate, _manifest = _payload()
        payload["review_contract"]["review_records"].pop()
        self._assert_rejected(payload)

    def test_duplicate_reviewer_identity_fails(self):
        payload, _candidate, _manifest = _payload()
        contract = payload["review_contract"]
        pair = [record for record in contract["review_records"] if record["work_unit_id"] == contract["work_units"][0]["work_unit_id"]]
        pair[1]["reviewer_id"] = pair[0]["reviewer_id"]
        _seal(pair[1], "review_record_sha256")
        contract["review_records"].sort(key=lambda item: item["review_record_id"])
        payload["attestation_id"] = "f" * 64
        self._assert_rejected(payload)

    def test_duplicate_or_replayed_review_record_fails(self):
        for replay in ("record_id", "artifact_hash"):
            with self.subTest(replay=replay):
                payload, _candidate, _manifest = _payload()
                contract = payload["review_contract"]
                first, second = contract["review_records"][:2]
                if replay == "record_id":
                    second["review_record_id"] = first["review_record_id"]
                else:
                    second["review_artifact_sha256"] = first["review_artifact_sha256"]
                _seal(second, "review_record_sha256")
                contract["review_records"].sort(key=lambda item: item["review_record_id"])
                self._assert_rejected(payload)

    def test_candidate_corpus_item_and_policy_replay_bindings_fail(self):
        binding_fields = (
            "subject_git_sha",
            "deployment_fingerprint",
            "corpus_set_identity_sha256",
            "corpus_item_id",
            "corpus_item_identity_sha256",
            "policy_identity_sha256",
        )
        for field in binding_fields:
            with self.subTest(field=field):
                payload, _candidate, _manifest = _payload()
                record = payload["review_contract"]["review_records"][0]
                if field == "corpus_item_id":
                    record[field] = "fixture-item-unrelated"
                elif field in {"subject_git_sha", "corpus_item_identity_sha256", "deployment_fingerprint", "corpus_set_identity_sha256", "policy_identity_sha256"}:
                    record[field] = "f" * (40 if field == "subject_git_sha" else 64)
                _seal(record, "review_record_sha256")
                self._assert_rejected(payload)

    def test_evidence_replayed_across_candidate_corpus_fails(self):
        payload, original_candidate, _manifest = _payload()
        other_manifest = make_private_manifest(item_count=4)
        other_candidate = make_candidate(other_manifest)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.json"
            write_evidence(path, evidence_type="internal_bilingual", subject_git_sha=original_candidate["subject_git_sha"], deployment_fingerprint=candidate_deployment_fingerprint(original_candidate), payload=payload, generated_at="2026-09-23T00:00:00Z", candidate_spec=original_candidate)
            with self.assertRaises(EvidenceValidationError):
                load_evidence(path, expected_type="internal_bilingual", candidate_spec=other_candidate, require_candidate_spec=True)

    def test_unresolved_disagreement_fails_even_when_summary_claims_pass(self):
        manifest = make_private_manifest(item_count=3)
        candidate = make_candidate(manifest)
        contract = make_review_contract(subject=candidate["subject_git_sha"], deployment=candidate_deployment_fingerprint(candidate), manifest=manifest, disagreement_index=0, adjudicate=False)
        with self.assertRaises(ValueError):
            build_internal_bilingual_payload(contract)

    def test_malformed_and_unrelated_adjudications_fail(self):
        payload, _candidate, _manifest = _payload(disagreement_index=0)
        record = payload["review_contract"]["adjudication_records"][0]
        record["review_record_refs"][0]["review_record_sha256"] = "f" * 64
        _seal(record, "adjudication_record_sha256")
        self._assert_rejected(payload)

        payload, _candidate, _manifest = _payload()
        unrelated, _candidate2, _manifest2 = _payload(disagreement_index=0)
        payload["review_contract"]["adjudication_records"] = unrelated["review_contract"]["adjudication_records"]
        self._assert_rejected(payload)

    def test_ai_only_ai_as_reviewer_and_ai_overriding_human_fail(self):
        payload, _candidate, _manifest = _payload()
        pair = [record for record in payload["review_contract"]["review_records"] if record["work_unit_id"] == payload["review_contract"]["work_units"][0]["work_unit_id"]]
        for record in pair:
            record["reviewer_kind"] = "ai_only"
            record["decision_authority"] = "ai_review"
            _seal(record, "review_record_sha256")
        self._assert_rejected(payload)

        payload, _candidate, _manifest = _payload()
        record = payload["review_contract"]["review_records"][0]
        record["reviewer_kind"] = "ai_model"
        _seal(record, "review_record_sha256")
        self._assert_rejected(payload)

        payload, _candidate, _manifest = _payload(disagreement_index=0)
        adjudication = payload["review_contract"]["adjudication_records"][0]
        adjudication["adjudicator_kind"] = "ai_model"
        adjudication["decision_authority"] = "ai_authority"
        _seal(adjudication, "adjudication_record_sha256")
        self._assert_rejected(payload)

    def test_ai_assistance_is_allowed_only_as_non_authoritative_provenance(self):
        payload, _candidate, _manifest = _payload(ai_assistance=True)
        validate_evidence_payload("internal_bilingual", payload)
        assistance = payload["review_contract"]["ai_assistance_records"][0]
        assistance["authority"] = "authoritative"
        _seal(assistance, "assistance_record_sha256")
        self._assert_rejected(payload)

    def test_summary_tampering_and_legacy_aggregate_only_attestation_fail(self):
        payload, _candidate, _manifest = _payload()
        payload["overall_noncritical_semantic_fidelity"] = 1.0
        self._assert_rejected(payload)
        legacy = {
            "attestation_id": "internal-test", "artifact_count": 50, "work_unit_count": 200,
            "critical_business_meaning_errors": 0, "critical_numeric_date_unit_errors": 0,
            "critical_modality_escalations": 0, "critical_table_mapping_errors": 0,
            "critical_trend_reversals": 0, "unsupported_critical_executive_claims": 0,
            "overall_noncritical_semantic_fidelity": 1.0, "unresolved_precision": 1.0,
            "material_unresolved_recall": 1.0, "locked_terminology": 1.0,
            "quality_policy": {"schema_version": "1.0"}, "quality_policy_identity": "f" * 64,
        }
        with self.assertRaises(EvidenceValidationError):
            validate_evidence_payload("internal_bilingual", legacy)

    def test_source_free_output_contains_only_opaque_review_data(self):
        payload, candidate, _manifest = _payload(ai_assistance=True)
        private_values = ("PRIVATE_SOURCE_SENTINEL", "PRIVATE_GOLD_SENTINEL", "PRIVATE_COMMENT_SENTINEL", "private/reviewer/name.txt")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.json"
            write_evidence(path, evidence_type="internal_bilingual", subject_git_sha=candidate["subject_git_sha"], deployment_fingerprint=candidate_deployment_fingerprint(candidate), payload=payload, generated_at="2026-09-23T00:00:00Z", candidate_spec=candidate)
            serialized = path.read_text(encoding="utf-8")
            for value in private_values:
                self.assertNotIn(value, serialized)

        leaked = copy.deepcopy(payload)
        leaked["review_contract"]["work_units"][0]["source_text"] = "PRIVATE_SOURCE_SENTINEL"
        self._assert_rejected(leaked)

    def test_predecessor_internal_bilingual_envelope_is_stale(self):
        payload, candidate, _manifest = _payload()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.json"
            deployment = candidate_deployment_fingerprint(candidate)
            write_evidence(path, evidence_type="internal_bilingual", subject_git_sha=candidate["subject_git_sha"], deployment_fingerprint=deployment, payload=payload, generated_at="2026-09-23T00:00:00Z", candidate_spec=candidate)
            envelope = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(envelope["schema_version"], EVIDENCE_SCHEMA_VERSION)
            envelope["schema_version"] = "2.5"
            path.write_text(json.dumps(envelope) + "\n", encoding="utf-8")
            with self.assertRaises(EvidenceValidationError):
                load_evidence(path, expected_type="internal_bilingual", candidate_spec=candidate, require_candidate_spec=True)


if __name__ == "__main__":
    unittest.main()
