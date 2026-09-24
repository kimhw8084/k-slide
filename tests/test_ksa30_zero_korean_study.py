from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from decimal import Decimal
from pathlib import Path

from k_slide.certification import (
    EVIDENCE_SCHEMA_VERSION,
    EvidenceValidationError,
    candidate_deployment_fingerprint,
    load_evidence,
    validate_evidence_payload,
    write_evidence,
)
from k_slide.zero_korean_study import (
    ZERO_KOREAN_ANALYSIS_PLAN,
    ZERO_KOREAN_STUDY_CONTRACT_VERSION,
    ZERO_KOREAN_STUDY_PROTOCOL,
    ZeroKoreanStudyError,
    _derive_results,
    _fmt,
    _passes_non_inferiority,
    _required_per_arm,
    _seal_outcome_record,
    _sha256,
    validate_zero_korean_authority_binding,
    validate_zero_korean_study_payload,
)
from tests.bilingual_review_fixtures import make_private_manifest, make_review_contract
from tests.zero_korean_study_fixtures import zero_korean_payload
from k_slide.bilingual_adjudication import build_internal_bilingual_payload


def _fixture():
    subject = "a" * 40
    manifest = make_private_manifest()
    candidate = {
        "subject_git_sha": subject,
        "corpus_identity": {"schema_version": "1.0", "sets": []},
    }
    # The human-study evidence binds the same candidate identity as the KSA-29
    # review; corpus readiness belongs to the release candidate fixture.
    deployment = candidate_deployment_fingerprint(candidate)
    contract = make_review_contract(subject=subject, deployment=deployment, manifest=manifest)
    bilingual = build_internal_bilingual_payload(contract)
    return candidate, bilingual, zero_korean_payload(candidate, bilingual), deployment


def _reseal(payload):
    payload["outcome_records"].sort(key=lambda row: row["outcome_record_id"])
    payload["derived_results"] = _derive_results(payload["participants"], payload["outcome_records"])
    payload["attestation_id"] = _sha256({key: value for key, value in payload.items() if key != "attestation_id"})
    return payload


def _change_outcome(row, outcome, scoring_outcomes=None, adjudication=None):
    scores = scoring_outcomes or [outcome, outcome]
    reviewer_ids = [review["reviewer_id"] for review in row["scoring_reviews"]]
    return _seal_outcome_record(
        subject_git_sha=row["subject_git_sha"],
        deployment_fingerprint=row["deployment_fingerprint"],
        condition=row["condition"],
        participant_id=row["participant_id"],
        question_id=row["question_id"],
        question_set_identity=row["question_set_identity"],
        expert_english_gold_identity=row["expert_english_gold_identity"],
        scoring_reviews=[{"reviewer_id": reviewer_ids[i], "outcome": scores[i]} for i in range(2)],
        adjudication=adjudication,
    )


class KSA30ZeroKoreanStudyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.candidate, cls.bilingual, cls.payload, cls.deployment = _fixture()

    def test_frozen_power_calculation_is_deterministic_and_uses_85_per_arm(self):
        self.assertEqual(_required_per_arm(ZERO_KOREAN_ANALYSIS_PLAN), 85)
        self.assertEqual(_required_per_arm(copy.deepcopy(ZERO_KOREAN_ANALYSIS_PLAN)), 85)
        self.assertEqual(self.payload["derived_results"]["required_analyzable_participants_per_arm"], 85)
        self.assertEqual(self.payload["derived_results"]["one_sided_97_5_percent_lower_bound"], "0.000000000000")
        higher_variance = copy.deepcopy(ZERO_KOREAN_ANALYSIS_PLAN)
        higher_variance["assumed_kslide_participant_score_sd"] = "0.20"
        self.assertGreater(_required_per_arm(higher_variance), 85)
        self.assertFalse(_passes_non_inferiority(Decimal("-0.05")))
        self.assertTrue(_passes_non_inferiority(Decimal("-0.0499999999999999999999")))
        self.assertEqual(_fmt(Decimal("0.1234567890125")), "0.123456789013")
        self.assertEqual(_fmt(Decimal("-0.0000000000004")), "0.000000000000")

    def test_complete_source_free_study_passes_and_binds_ksa29_truth(self):
        validate_zero_korean_study_payload(self.payload)
        validate_evidence_payload("zero_korean_comprehension", self.payload)
        validate_zero_korean_authority_binding(self.payload, self.bilingual)
        self.assertEqual(self.payload["study_contract_version"], ZERO_KOREAN_STUDY_CONTRACT_VERSION)
        self.assertTrue(self.payload["derived_results"]["study_pass"])
        self.assertEqual(self.payload["derived_results"]["arms"]["kslide_output"]["analyzable_participants"], 85)

    def test_missing_expert_reference_arm_fails_closed(self):
        payload = copy.deepcopy(self.payload)
        removed = {item["participant_id"] for item in payload["participants"] if item["condition"] == "expert_english_reference"}
        payload["participants"] = [item for item in payload["participants"] if item["condition"] != "expert_english_reference"]
        payload["outcome_records"] = [item for item in payload["outcome_records"] if item["participant_id"] not in removed]
        with self.assertRaises(ZeroKoreanStudyError):
            validate_zero_korean_study_payload(payload)

    def test_margin_and_unfrozen_power_assumptions_fail(self):
        altered_margin = copy.deepcopy(self.payload)
        altered_margin["analysis_plan"]["non_inferiority_margin"] = "0.050"
        with self.assertRaises(ZeroKoreanStudyError):
            validate_zero_korean_study_payload(altered_margin)
        missing_assumption = copy.deepcopy(self.payload)
        del missing_assumption["analysis_plan"]["assumed_reference_participant_score_sd"]
        with self.assertRaises(ZeroKoreanStudyError):
            validate_zero_korean_study_payload(missing_assumption)
        altered_alpha = copy.deepcopy(self.payload)
        altered_alpha["analysis_plan"]["alpha_one_sided"] = "0.05"
        with self.assertRaises(ZeroKoreanStudyError):
            validate_zero_korean_study_payload(altered_alpha)

    def test_underpowered_arms_and_declared_sample_count_fail(self):
        payload = copy.deepcopy(self.payload)
        removed_ids = set()
        for condition in ("kslide_output", "expert_english_reference"):
            selected = next(item["participant_id"] for item in payload["participants"] if item["condition"] == condition)
            removed_ids.add(selected)
        payload["participants"] = [item for item in payload["participants"] if item["participant_id"] not in removed_ids]
        payload["outcome_records"] = [item for item in payload["outcome_records"] if item["participant_id"] not in removed_ids]
        _reseal(payload)
        with self.assertRaisesRegex(ZeroKoreanStudyError, "sample size"):
            validate_zero_korean_study_payload(payload)
        declared = copy.deepcopy(self.payload)
        declared["analysis_plan"]["required_analyzable_participants_per_arm"] = 84
        with self.assertRaises(ZeroKoreanStudyError):
            validate_zero_korean_study_payload(declared)
        with self.assertRaisesRegex(ZeroKoreanStudyError, "frozen power-calculated target"):
            zero_korean_payload(self.candidate, self.bilingual, participants_per_arm=86)

    def test_duplicate_participant_and_replayed_outcome_identities_fail(self):
        duplicate_participant = copy.deepcopy(self.payload)
        duplicate_participant["participants"].append(copy.deepcopy(duplicate_participant["participants"][0]))
        duplicate_participant["participants"].sort(key=lambda row: row["participant_id"])
        with self.assertRaises(ZeroKoreanStudyError):
            validate_zero_korean_study_payload(duplicate_participant)
        replayed = copy.deepcopy(self.payload)
        replayed["outcome_records"].append(copy.deepcopy(replayed["outcome_records"][0]))
        replayed["outcome_records"].sort(key=lambda row: row["outcome_record_id"])
        with self.assertRaises(ZeroKoreanStudyError):
            validate_zero_korean_study_payload(replayed)

    def test_wrong_candidate_protocol_question_or_gold_binding_fails(self):
        wrong_candidate = copy.deepcopy(self.payload)
        wrong_candidate["outcome_records"][0]["subject_git_sha"] = "b" * 40
        with self.assertRaises(ZeroKoreanStudyError):
            validate_zero_korean_study_payload(wrong_candidate)
        wrong_protocol = copy.deepcopy(self.payload)
        wrong_protocol["outcome_records"][0]["protocol_identity"] = "f" * 64
        with self.assertRaises(ZeroKoreanStudyError):
            validate_zero_korean_study_payload(wrong_protocol)
        wrong_question = copy.deepcopy(self.payload)
        wrong_question["outcome_records"][0]["question_id"] = "q-invented-v1"
        with self.assertRaises(ZeroKoreanStudyError):
            validate_zero_korean_study_payload(wrong_question)
        wrong_gold = copy.deepcopy(self.payload)
        wrong_gold["outcome_records"][0]["expert_english_gold_identity"] = "f" * 64
        with self.assertRaises(ZeroKoreanStudyError):
            validate_zero_korean_study_payload(wrong_gold)

    def test_any_serious_misleading_outcome_fails_even_with_passing_ni(self):
        payload = copy.deepcopy(self.payload)
        row = payload["outcome_records"][0]
        payload["outcome_records"][0] = _change_outcome(row, "serious_misleading")
        _reseal(payload)
        self.assertTrue(payload["derived_results"]["non_inferiority_pass"])
        self.assertEqual(payload["derived_results"]["serious_misleading_outcome_count"], 1)
        with self.assertRaisesRegex(ZeroKoreanStudyError, "serious misleading"):
            validate_zero_korean_study_payload(payload)

    def test_human_scoring_disagreements_require_bilingual_adjudication(self):
        payload = copy.deepcopy(self.payload)
        index = 0
        row = payload["outcome_records"][index]
        reviewer_ids = [review["reviewer_id"] for review in row["scoring_reviews"]]
        with self.assertRaisesRegex(ZeroKoreanStudyError, "disagreement"):
            _seal_outcome_record(
                subject_git_sha=row["subject_git_sha"], deployment_fingerprint=row["deployment_fingerprint"],
                condition=row["condition"], participant_id=row["participant_id"], question_id=row["question_id"],
                question_set_identity=row["question_set_identity"], expert_english_gold_identity=row["expert_english_gold_identity"],
                scoring_reviews=[
                    {"reviewer_id": reviewer_ids[0], "outcome": "correct"},
                    {"reviewer_id": reviewer_ids[1], "outcome": "incorrect_noncritical"},
                ],
                adjudication=None,
            )
        payload["outcome_records"][index] = _seal_outcome_record(
            subject_git_sha=row["subject_git_sha"], deployment_fingerprint=row["deployment_fingerprint"],
            condition=row["condition"], participant_id=row["participant_id"], question_id=row["question_id"],
            question_set_identity=row["question_set_identity"], expert_english_gold_identity=row["expert_english_gold_identity"],
            scoring_reviews=[
                {"reviewer_id": reviewer_ids[0], "outcome": "correct"},
                {"reviewer_id": reviewer_ids[1], "outcome": "incorrect_noncritical"},
            ],
            adjudication={"adjudicator_id": hashlib.sha256(b"independent-bilingual-adjudicator").hexdigest(), "resolution_outcome": "correct"},
        )
        _reseal(payload)
        validate_zero_korean_study_payload(payload)
        self.assertEqual(payload["outcome_records"][0]["adjudication"]["decision_authority"], "human_adjudication")

    def test_ai_scoring_identity_is_rejected(self):
        payload = copy.deepcopy(self.payload)
        review = payload["outcome_records"][0]["scoring_reviews"][0]
        review["reviewer_kind"] = "ai_model"
        review["review_record_sha256"] = _sha256({key: value for key, value in review.items() if key != "review_record_sha256"})
        payload["outcome_records"][0]["outcome_record_sha256"] = _sha256({key: value for key, value in payload["outcome_records"][0].items() if key != "outcome_record_sha256"})
        _reseal(payload)
        with self.assertRaisesRegex(ZeroKoreanStudyError, "not human-authoritative"):
            validate_zero_korean_study_payload(payload)

    def test_failed_statistical_noninferiority_fails_with_high_absolute_average(self):
        payload = copy.deepcopy(self.payload)
        candidate_ids = [item["participant_id"] for item in payload["participants"] if item["condition"] == "kslide_output"][:34]
        for index, row in enumerate(payload["outcome_records"]):
            if row["participant_id"] in candidate_ids and row["question_id"] == "q-trend-v1":
                payload["outcome_records"][index] = _change_outcome(row, "incorrect_noncritical")
        _reseal(payload)
        self.assertEqual(payload["derived_results"]["arms"]["kslide_output"]["overall_comprehension"], "0.950000000000")
        self.assertTrue(payload["derived_results"]["absolute_safety_pass"])
        self.assertFalse(payload["derived_results"]["non_inferiority_pass"])
        with self.assertRaisesRegex(ZeroKoreanStudyError, "non-inferiority"):
            validate_zero_korean_study_payload(payload)

    def test_absolute_critical_and_overall_floors_fail_independently(self):
        critical_failure = copy.deepcopy(self.payload)
        index = next(i for i, row in enumerate(critical_failure["outcome_records"]) if row["condition"] == "kslide_output" and row["question_id"] == "q-risk-v1")
        row = critical_failure["outcome_records"][index]
        critical_failure["outcome_records"][index] = _change_outcome(row, "incorrect_noncritical")
        _reseal(critical_failure)
        self.assertTrue(critical_failure["derived_results"]["non_inferiority_pass"])
        self.assertFalse(critical_failure["derived_results"]["absolute_safety_pass"])
        with self.assertRaisesRegex(ZeroKoreanStudyError, "absolute"):
            validate_zero_korean_study_payload(critical_failure)

        comprehension_failure = copy.deepcopy(self.payload)
        noncritical_ids = {
            condition: [item["participant_id"] for item in comprehension_failure["participants"] if item["condition"] == condition][:35]
            for condition in ("kslide_output", "expert_english_reference")
        }
        for index, row in enumerate(comprehension_failure["outcome_records"]):
            if row["question_id"] == "q-trend-v1" and row["participant_id"] in noncritical_ids[row["condition"]]:
                comprehension_failure["outcome_records"][index] = _change_outcome(row, "incorrect_noncritical")
        _reseal(comprehension_failure)
        self.assertTrue(comprehension_failure["derived_results"]["non_inferiority_pass"])
        self.assertEqual(comprehension_failure["derived_results"]["arms"]["kslide_output"]["overall_comprehension"], "0.948529411765")
        self.assertFalse(comprehension_failure["derived_results"]["absolute_safety_pass"])
        with self.assertRaisesRegex(ZeroKoreanStudyError, "absolute"):
            validate_zero_korean_study_payload(comprehension_failure)

    def test_summary_tampering_legacy_aggregate_and_private_fields_fail(self):
        summary = copy.deepcopy(self.payload)
        summary["derived_results"]["serious_misleading_outcome_count"] = 1
        with self.assertRaises(ZeroKoreanStudyError):
            validate_zero_korean_study_payload(summary)
        legacy = {"attestation_id": "human-test", "users": 10, "answers": 100, "critical_question_accuracy": 1.0, "overall_comprehension": 0.95, "critical_misunderstanding": 0}
        with self.assertRaises(EvidenceValidationError):
            validate_evidence_payload("zero_korean_comprehension", legacy)
        unsupported = copy.deepcopy(self.payload)
        unsupported["employee_name"] = "PRIVATE_NAME"
        with self.assertRaises(ZeroKoreanStudyError):
            validate_zero_korean_study_payload(unsupported)
        leaked_answer = copy.deepcopy(self.payload)
        leaked_answer["outcome_records"][0]["answer_text"] = "PRIVATE_ANSWER_SENTINEL"
        with self.assertRaises(ZeroKoreanStudyError):
            validate_zero_korean_study_payload(leaked_answer)
        leaked_participant = copy.deepcopy(self.payload)
        leaked_participant["participants"][0]["participant_id"] = "person@example.com"
        with self.assertRaises(ZeroKoreanStudyError):
            validate_zero_korean_study_payload(leaked_participant)

    def test_candidate_bound_envelope_and_predecessor_are_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "zero-korean.json"
            write_evidence(path, evidence_type="zero_korean_comprehension", subject_git_sha=self.candidate["subject_git_sha"], deployment_fingerprint=self.deployment, payload=self.payload, generated_at="2026-09-24T00:00:00Z", candidate_spec=self.candidate)
            envelope = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(envelope["schema_version"], EVIDENCE_SCHEMA_VERSION)
            loaded = load_evidence(path, expected_type="zero_korean_comprehension", subject_git_sha=self.candidate["subject_git_sha"], deployment_fingerprint=self.deployment, candidate_spec=self.candidate, require_candidate_spec=True)
            self.assertEqual(loaded["payload"]["attestation_id"], self.payload["attestation_id"])
            envelope["schema_version"] = "2.5"
            path.write_text(json.dumps(envelope) + "\n", encoding="utf-8")
            with self.assertRaises(EvidenceValidationError):
                load_evidence(path, expected_type="zero_korean_comprehension", candidate_spec=self.candidate, require_candidate_spec=True)
            envelope["schema_version"] = EVIDENCE_SCHEMA_VERSION
            envelope["payload"] = {"attestation_id": "human-test", "users": 10, "answers": 100, "critical_question_accuracy": 1.0, "overall_comprehension": 0.95, "critical_misunderstanding": 0}
            path.write_text(json.dumps(envelope) + "\n", encoding="utf-8")
            with self.assertRaises(EvidenceValidationError):
                load_evidence(path, expected_type="zero_korean_comprehension", candidate_spec=self.candidate, require_candidate_spec=True)

    def test_wrong_ksa29_item_or_question_authority_fails(self):
        payload = copy.deepcopy(self.payload)
        payload["truth_authority"]["reviewed_output_artifact_sha256"] = "f" * 64
        with self.assertRaises(ZeroKoreanStudyError):
            validate_zero_korean_authority_binding(payload, self.bilingual)
        wrong_candidate_authority = copy.deepcopy(self.bilingual)
        wrong_candidate_authority["review_contract"]["subject_git_sha"] = "b" * 40
        with self.assertRaises(ZeroKoreanStudyError):
            validate_zero_korean_authority_binding(self.payload, wrong_candidate_authority)


if __name__ == "__main__":
    unittest.main()
