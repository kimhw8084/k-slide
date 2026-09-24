"""Source-free synthetic fixtures for the KSA-30 study contract."""

from __future__ import annotations

import hashlib

from k_slide.bilingual_adjudication import canonical_bytes
from k_slide.certification import candidate_deployment_fingerprint
from k_slide.zero_korean_study import ZERO_KOREAN_STUDY_PROTOCOL, build_zero_korean_study_payload


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def zero_korean_payload(candidate: dict, bilingual_payload: dict, *, participants_per_arm: int = 85) -> dict:
    """Create a deterministic, passing, source-free synthetic study ledger."""

    contract = bilingual_payload["review_contract"]
    work = contract["work_units"][0]
    item_identity = hashlib.sha256(canonical_bytes({
        "item_id": work["item_id"],
        "source_sha256": work["source_sha256"],
        "gold_sha256": work["gold_sha256"],
    })).hexdigest()
    authority = {
        "bilingual_review_attestation_id": bilingual_payload["attestation_id"],
        "bilingual_review_contract_sha256": bilingual_payload["attestation_id"],
        "corpus_set_identity_sha256": hashlib.sha256(canonical_bytes(contract["corpus_set_identity"])).hexdigest(),
        "corpus_item_identity_sha256": item_identity,
        "reviewed_output_artifact_id": work["artifact_id"],
        "reviewed_output_artifact_sha256": work["artifact_sha256"],
        "expert_english_gold_identity": work["gold_sha256"],
        "question_set_identity": work["gold_sha256"],
    }
    conditions = ("kslide_output", "expert_english_reference")
    participants = []
    outcomes = []
    for condition in conditions:
        for index in range(participants_per_arm):
            participant_id = _digest(f"synthetic-zero-korean-participant:{condition}:{index}")
            participants.append({"participant_id": participant_id, "condition": condition})
            for question in ZERO_KOREAN_STUDY_PROTOCOL["questions"]:
                outcomes.append({
                    "condition": condition,
                    "participant_id": participant_id,
                    "question_id": question["question_id"],
                    "scoring_reviews": [
                        {"reviewer_id": _digest("synthetic-human-scorer-1"), "outcome": "correct"},
                        {"reviewer_id": _digest("synthetic-human-scorer-2"), "outcome": "correct"},
                    ],
                    "adjudication": None,
                })
    return build_zero_korean_study_payload(
        subject_git_sha=candidate["subject_git_sha"],
        deployment_fingerprint=candidate_deployment_fingerprint(candidate),
        truth_authority=authority,
        participants=participants,
        outcomes=outcomes,
    )
