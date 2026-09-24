"""Frozen, source-free KSA-30 zero-Korean study evidence contract."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from decimal import Decimal, ROUND_CEILING, ROUND_HALF_UP, localcontext
from fractions import Fraction
from typing import Any


ZERO_KOREAN_STUDY_CONTRACT_VERSION = "1.0"
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_CONDITION_KSLIDE = "kslide_output"
_CONDITION_REFERENCE = "expert_english_reference"
_CONDITIONS = (_CONDITION_KSLIDE, _CONDITION_REFERENCE)
_OUTCOMES = frozenset({"correct", "incorrect_noncritical", "serious_misleading", "unanswered"})
_SCORE_SCALE = Decimal("0.000000000001")


class ZeroKoreanStudyError(ValueError):
    """The zero-Korean study contract or evidence is invalid."""


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _HEX64.fullmatch(value) is None:
        raise ZeroKoreanStudyError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _protocol() -> dict[str, Any]:
    return {
        "schema_version": ZERO_KOREAN_STUDY_CONTRACT_VERSION,
        "study_design": "randomized_balanced_parallel_conditions",
        "conditions": [
            {
                "condition": _CONDITION_KSLIDE,
                "definition": "The exact English report artifact produced by the bound K-Slide candidate.",
                "source_visibility": "english_output_only_no_original_korean",
            },
            {
                "condition": _CONDITION_REFERENCE,
                "definition": "The human-authored expert-English report for the same source, approved as bilingual-reviewed gold.",
                "source_visibility": "expert_english_output_only_no_original_korean",
            },
        ],
        "eligibility": {
            "population": "employees_approved_for_the_study_in_the_company_environment",
            "english_reading_proficiency": "participant_confirms_sufficient_english_reading_proficiency",
            "korean_reading_ability": "participant_confirms_unable_to_read_korean",
            "prior_exposure": "exclude_before_randomization_if_previously_exposed_to_the_bound_report_or_involved_in_its_preparation_or_review",
            "consent": "informed_consent_required_before_randomization",
        },
        "assignment": {
            "unit": "individual_participant",
            "method": "concealed_computer_generated_permuted_blocks_of_four_with_final_balanced_two_participant_block_when_total_target_is_170",
            "allocation_ratio": {"kslide_output": 1, "expert_english_reference": 1},
            "parallel_only": True,
            "crossover": False,
            "one_condition_per_participant": True,
            "condition_presentation": "same_neutral_view_and_no_condition_label",
        },
        "analysis_population": {
            "population": "all_eligible_randomized_participants_by_assigned_condition_intention_to_treat",
            "analysis_unit": "participant",
            "analyzable_participant_definition": "randomized_participant_with_exactly_one_closed_outcome_code_for_each_of_the_eight_questions; unanswered_is_a_closed_zero_score",
            "participant_independence": "one_unique_employee_per_opaque_participant_id_and_one_randomized_condition",
            "question_dependence": "repeated_question_outcomes_are_aggregated_to_one_participant_score_and_are_not_independent_sample_size_units",
            "clustering_assumption": "no_between_participant_clusters_or_cluster_adjustment; individual assignment and independence are required",
        },
        "sample_size_control": {
            "enrollment_target": "exactly_the_power_calculated_n_per_arm",
            "interim_analyses": False,
            "outcome_driven_extension_or_replacement": False,
            "stopping_rule": "stop_when_the_frozen_equal_arm_target_is_reached; any_target_change_requires_a_new_protocol_before_new_results",
        },
        "questions": [
            {"question_id": "q-decision-status-v1", "category": "decision_status", "critical": True},
            {"question_id": "q-timing-v1", "category": "timing", "critical": True},
            {"question_id": "q-key-numbers-v1", "category": "key_numbers", "critical": True},
            {"question_id": "q-risk-v1", "category": "risk", "critical": True},
            {"question_id": "q-dependency-v1", "category": "dependency", "critical": True},
            {"question_id": "q-trend-v1", "category": "trend", "critical": False},
            {"question_id": "q-owner-v1", "category": "owner", "critical": False},
            {"question_id": "q-next-step-v1", "category": "next_step", "critical": False},
        ],
        "scoring": {
            "outcome_codes": ["correct", "incorrect_noncritical", "serious_misleading", "unanswered"],
            "correct": "The response matches the approved bilingual-reviewed expert-English gold for the requested question.",
            "incorrect_noncritical": "The response is wrong, incomplete, or unsupported but does not meet the serious-misleading rule.",
            "serious_misleading_rule_id": "SMO-1",
            "serious_misleading_rule": "A response is serious_misleading if a reasonable employee could be led to a materially unsafe, unlawful, financially material, operationally irreversible, or materially wrong decision because it fabricates, reverses, or materially misstates a source fact; for a critical question, a material error about decision status, timing, key numbers, risk, or dependency is serious. A bilingual human scorer applies this rule against approved gold; disagreements require a bilingual human adjudicator.",
            "unanswered": "No answer, blank answer, or unavailable answer; scored as incorrect with score zero and retained in the assigned arm.",
            "scorer_contract": "exactly_two_distinct_independent_human_scorers_per_participant_question; both blinded_to_condition_and_participant_identity; every_disagreement_requires_a_distinct_human_bilingual_adjudicator",
            "authority": "independent_human_scoring_with_human_bilingual_adjudication; AI may not author gold, score outcomes, adjudicate, or substitute for participants or the expert-English reference",
        },
        "exclusions": {
            "before_randomization_only": [
                "ineligible_on_the_frozen_screen",
                "consent_declined",
                "duplicate_employee_or_prior_randomization",
                "prior_exposure_or_preparation_involvement",
            ],
            "after_randomization": "no_participant_or_outcome_exclusions; no outlier removal; all randomized participants remain in the assigned arm",
        },
        "missing_data": {
            "missing_question": "record_unanswered_and_score_zero",
            "missing_participant_responses": "emit_one_unanswered_outcome_for_each_missing_question",
            "withdrawal_after_randomization": "retain_only_the_opaque_assignment_and_unanswered_outcomes_where_approved_consent_and_company_policy_allow; otherwise_the_study_cannot_qualify",
            "imputation": "none",
        },
        "primary_endpoint": {
            "name": "participant_mean_fraction_correct",
            "participant_score": "number_of_correct_answers_divided_by_all_eight_frozen_questions; all other outcome codes score zero",
            "contrast": "mean_kslide_output_score_minus_mean_expert_english_reference_score",
            "non_inferiority_margin": "0.05",
            "decision_rule": "pass_only_if_the_predeclared_one_sided_lower_confidence_bound_is_strictly_greater_than_minus_0.05",
        },
        "absolute_safety_floors": {
            "apply_independently_to_each_arm": True,
            "critical_question_accuracy": "1.0",
            "overall_comprehension": "at_least_0.95",
            "critical_misunderstanding_count": 0,
            "serious_misleading_outcome_count": 0,
            "compensation": "non_inferiority_cannot_compensate_for_any_absolute_safety_failure",
        },
        "truth_authority": {
            "requirement": "the_question_set_and_expert_english_gold_are_the_exact_gold_artifact_bound_to_a_valid_KSA-29_bilingual_human_review_for_the_exact_candidate_output",
            "original_korean_employee_facing": False,
        },
    }


def _required_per_arm(assumptions: dict[str, Any]) -> int:
    """Deterministic normal-approximation NI sample size for 1:1 allocation."""

    try:
        margin = Decimal(assumptions["non_inferiority_margin"])
        alpha_z = Decimal(assumptions["z_one_sided_alpha"])
        power_z = Decimal(assumptions["z_target_power"])
        sd_candidate = Decimal(assumptions["assumed_kslide_participant_score_sd"])
        sd_reference = Decimal(assumptions["assumed_reference_participant_score_sd"])
        candidate_mean = Decimal(assumptions["assumed_kslide_participant_score_mean"])
        reference_mean = Decimal(assumptions["assumed_reference_participant_score_mean"])
        planning_difference = Decimal(assumptions["planning_effect_difference"])
        ratio = assumptions["allocation_ratio"]
        if ratio != {"kslide_output": 1, "expert_english_reference": 1}:
            raise ZeroKoreanStudyError("zero-Korean power calculation requires the frozen 1:1 allocation ratio")
        if planning_difference != candidate_mean - reference_mean:
            raise ZeroKoreanStudyError("zero-Korean planning effect disagrees with its assumed arm means")
        distance = margin + planning_difference
        if margin <= 0 or distance <= 0 or sd_candidate <= 0 or sd_reference <= 0:
            raise ZeroKoreanStudyError("zero-Korean power assumptions are invalid")
    except (KeyError, TypeError, ValueError, ArithmeticError) as exc:
        if isinstance(exc, ZeroKoreanStudyError):
            raise
        raise ZeroKoreanStudyError("zero-Korean power assumptions are incomplete") from exc
    with localcontext() as context:
        context.prec = 50
        variance_sum = sd_candidate * sd_candidate + sd_reference * sd_reference
        raw_n = ((alpha_z + power_z) ** 2) * variance_sum / (distance * distance)
        return int(raw_n.to_integral_value(rounding=ROUND_CEILING))


def _analysis_plan() -> dict[str, Any]:
    assumptions = {
        "primary_endpoint": "participant_mean_fraction_correct",
        "contrast": "kslide_output_minus_expert_english_reference",
        "non_inferiority_margin": "0.05",
        "alpha_one_sided": "0.025",
        "confidence_convention": "97.5_percent_one_sided_lower_bound_equivalent_to_the_lower_bound_of_a_two_sided_95_percent_interval",
        "target_power": "0.90",
        "z_one_sided_alpha": "1.959963984540054",
        "z_target_power": "1.281551565544600",
        "allocation_ratio": {"kslide_output": 1, "expert_english_reference": 1},
        "assumed_reference_participant_score_mean": "0.95",
        "assumed_kslide_participant_score_mean": "0.95",
        "assumed_reference_participant_score_sd": "0.10",
        "assumed_kslide_participant_score_sd": "0.10",
        "planning_effect_difference": "0.00",
        "analysis_unit": "participant_mean_fraction_correct",
        "repeated_questions": "aggregate_within_participant_before_arm_analysis",
        "participant_independence": "independent_unique_participants_randomized_to_one_arm; no_cluster_adjustment",
        "sample_size_method": "normal_approximation_for_difference_of_independent_means_with_frozen_participant_level_standard_deviations",
        "sample_size_formula": "ceil(((z_1-alpha+z_power)^2*(sd_kslide^2+sd_reference^2))/(margin+assumed_effect_difference)^2)",
        "inference_method": "two_independent_arm_Welch_standard_error_with_predeclared_normal_97.5_percent_one_sided_lower_bound",
        "missing_data_method": "unanswered_questions_score_zero_in_the_randomized_participant_score; no_imputation_or_post_randomization_exclusion",
        "required_analyzable_participants_per_arm": 0,
    }
    assumptions["required_analyzable_participants_per_arm"] = _required_per_arm(assumptions)
    return assumptions


ZERO_KOREAN_STUDY_PROTOCOL = _protocol()
ZERO_KOREAN_ANALYSIS_PLAN = _analysis_plan()
ZERO_KOREAN_PROTOCOL_IDENTITY = _sha256(ZERO_KOREAN_STUDY_PROTOCOL)
ZERO_KOREAN_ANALYSIS_PLAN_IDENTITY = _sha256(ZERO_KOREAN_ANALYSIS_PLAN)


def _question_map() -> dict[str, dict[str, Any]]:
    return {item["question_id"]: item for item in ZERO_KOREAN_STUDY_PROTOCOL["questions"]}


def _record_identity(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "subject_git_sha": row["subject_git_sha"],
        "deployment_fingerprint": row["deployment_fingerprint"],
        "protocol_identity": row["protocol_identity"],
        "condition": row["condition"],
        "participant_id": row["participant_id"],
        "question_id": row["question_id"],
    }


def _review_binding(row: dict[str, Any]) -> dict[str, Any]:
    return {
        **_record_identity(row),
        "question_category": row["question_category"],
        "question_set_identity": row["question_set_identity"],
        "expert_english_gold_identity": row["expert_english_gold_identity"],
    }


def _seal_score_review(binding: dict[str, Any], reviewer_id: str, outcome: str) -> dict[str, Any]:
    _digest(reviewer_id, "opaque human scorer identity")
    if outcome not in _OUTCOMES:
        raise ZeroKoreanStudyError("zero-Korean human scoring review has an unsupported outcome")
    review = {
        **binding,
        "reviewer_id": reviewer_id,
        "reviewer_kind": "independent_human_scorer",
        "decision_authority": "human_scoring",
        "decision_basis": "approved_bilingual_gold_comparison",
        "outcome": outcome,
    }
    review["review_record_id"] = _sha256({**binding, "reviewer_id": reviewer_id})
    review["review_record_sha256"] = _sha256(review)
    return review


def _seal_adjudication(binding: dict[str, Any], reviews: list[dict[str, Any]], adjudicator_id: str, outcome: str) -> dict[str, Any]:
    _digest(adjudicator_id, "opaque human bilingual adjudicator identity")
    if outcome not in _OUTCOMES:
        raise ZeroKoreanStudyError("zero-Korean human adjudication has an unsupported outcome")
    refs = [
        {"review_record_id": row["review_record_id"], "review_record_sha256": row["review_record_sha256"]}
        for row in reviews
    ]
    adjudication = {
        **binding,
        "adjudicator_id": adjudicator_id,
        "adjudicator_kind": "human_bilingual_adjudicator",
        "decision_authority": "human_adjudication",
        "review_record_refs": refs,
        "resolution_outcome": outcome,
    }
    adjudication["adjudication_record_id"] = _sha256({
        **binding,
        "adjudicator_id": adjudicator_id,
        "review_record_refs": refs,
    })
    adjudication["adjudication_record_sha256"] = _sha256(adjudication)
    return adjudication


def _seal_outcome_record(
    *,
    subject_git_sha: str,
    deployment_fingerprint: str,
    condition: str,
    participant_id: str,
    question_id: str,
    question_set_identity: str,
    expert_english_gold_identity: str,
    scoring_reviews: list[dict[str, str]],
    adjudication: dict[str, str] | None,
) -> dict[str, Any]:
    question = _question_map().get(question_id)
    if question is None or condition not in _CONDITIONS:
        raise ZeroKoreanStudyError("zero-Korean outcome contains an unsupported condition or question")
    row = {
        "subject_git_sha": subject_git_sha,
        "deployment_fingerprint": deployment_fingerprint,
        "protocol_identity": ZERO_KOREAN_PROTOCOL_IDENTITY,
        "condition": condition,
        "participant_id": participant_id,
        "question_id": question_id,
        "question_category": question["category"],
        "question_set_identity": question_set_identity,
        "expert_english_gold_identity": expert_english_gold_identity,
    }
    if not isinstance(scoring_reviews, list) or len(scoring_reviews) != 2:
        raise ZeroKoreanStudyError("every zero-Korean outcome requires exactly two human scoring reviews")
    if any(not isinstance(item, dict) or set(item) != {"reviewer_id", "outcome"} for item in scoring_reviews):
        raise ZeroKoreanStudyError("zero-Korean raw scoring review has an unsupported source-free shape")
    binding = _review_binding(row)
    reviews = sorted(
        [_seal_score_review(binding, item["reviewer_id"], item["outcome"]) for item in scoring_reviews],
        key=lambda item: item["review_record_id"],
    )
    if reviews[0]["reviewer_id"] == reviews[1]["reviewer_id"]:
        raise ZeroKoreanStudyError("zero-Korean outcome requires two distinct human scorers")
    if reviews[0]["outcome"] == reviews[1]["outcome"]:
        if adjudication is not None:
            raise ZeroKoreanStudyError("zero-Korean human adjudication is unsupported when scorers agree")
        outcome = reviews[0]["outcome"]
        sealed_adjudication = None
    else:
        if not isinstance(adjudication, dict) or set(adjudication) != {"adjudicator_id", "resolution_outcome"}:
            raise ZeroKoreanStudyError("every zero-Korean scoring disagreement requires human bilingual adjudication")
        if adjudication["adjudicator_id"] in {reviews[0]["reviewer_id"], reviews[1]["reviewer_id"]}:
            raise ZeroKoreanStudyError("zero-Korean adjudicator must be independent of both scorers")
        outcome = adjudication["resolution_outcome"]
        sealed_adjudication = _seal_adjudication(binding, reviews, adjudication["adjudicator_id"], outcome)
    row["outcome"] = outcome
    row["scoring_reviews"] = reviews
    row["adjudication"] = sealed_adjudication
    row["outcome_record_id"] = _sha256(_record_identity(row))
    row["outcome_record_sha256"] = _sha256(row)
    return row


def _fmt(value: Decimal) -> str:
    with localcontext() as context:
        context.prec = 50
        rounded = value.quantize(_SCORE_SCALE, rounding=ROUND_HALF_UP)
    if rounded == 0:
        rounded = Decimal(0).quantize(_SCORE_SCALE)
    return format(rounded, "f")


def _fraction_decimal(value: Fraction) -> Decimal:
    return Decimal(value.numerator) / Decimal(value.denominator)


def _passes_non_inferiority(lower_bound: Decimal) -> bool:
    return lower_bound > -Decimal("0.05")


def _derive_results(participants: list[dict[str, str]], rows: list[dict[str, Any]]) -> dict[str, Any]:
    questions = _question_map()
    question_ids = set(questions)
    by_participant: dict[str, list[dict[str, Any]]] = {row["participant_id"]: [] for row in participants}
    outcomes_by_arm: dict[str, list[dict[str, Any]]] = {condition: [] for condition in _CONDITIONS}
    for row in rows:
        by_participant[row["participant_id"]].append(row)
        outcomes_by_arm[row["condition"]].append(row)

    participant_scores: dict[str, list[Fraction]] = {condition: [] for condition in _CONDITIONS}
    for participant in participants:
        response_rows = by_participant[participant["participant_id"]]
        score = Fraction(sum(row["outcome"] == "correct" for row in response_rows), len(question_ids))
        participant_scores[participant["condition"]].append(score)

    arm_summary: dict[str, Any] = {}
    total_serious = 0
    for condition in _CONDITIONS:
        arm_rows = outcomes_by_arm[condition]
        counts = {outcome: sum(row["outcome"] == outcome for row in arm_rows) for outcome in sorted(_OUTCOMES)}
        total = len(arm_rows)
        critical_rows = [row for row in arm_rows if questions[row["question_id"]]["critical"]]
        critical_correct = sum(row["outcome"] == "correct" for row in critical_rows)
        critical_misunderstanding = len(critical_rows) - critical_correct
        overall = Decimal(counts["correct"]) / Decimal(total)
        critical_accuracy = Decimal(critical_correct) / Decimal(len(critical_rows))
        safety = critical_accuracy == 1 and overall >= Decimal("0.95") and critical_misunderstanding == 0
        total_serious += counts["serious_misleading"]
        arm_summary[condition] = {
            "analyzable_participants": len(participant_scores[condition]),
            "question_outcomes": counts,
            "overall_comprehension": _fmt(overall),
            "critical_question_accuracy": _fmt(critical_accuracy),
            "critical_misunderstanding_count": critical_misunderstanding,
            "absolute_safety_pass": safety,
        }

    required_n = _required_per_arm(ZERO_KOREAN_ANALYSIS_PLAN)
    eligible_n = {condition: len(participant_scores[condition]) for condition in _CONDITIONS}
    if any(eligible_n[condition] == 0 for condition in _CONDITIONS):
        raise ZeroKoreanStudyError("both zero-Korean study conditions must contain participants")
    with localcontext() as context:
        context.prec = 50
        means = {condition: sum(participant_scores[condition], Fraction()) / eligible_n[condition] for condition in _CONDITIONS}
        variances: dict[str, Fraction] = {}
        for condition in _CONDITIONS:
            values = participant_scores[condition]
            if len(values) < 2:
                raise ZeroKoreanStudyError("each zero-Korean condition requires at least two analyzable participants")
            mean = means[condition]
            variances[condition] = sum(((score - mean) ** 2 for score in values), Fraction()) / (len(values) - 1)
        mean_difference = _fraction_decimal(means[_CONDITION_KSLIDE] - means[_CONDITION_REFERENCE])
        variance_of_difference = (
            _fraction_decimal(variances[_CONDITION_KSLIDE]) / Decimal(eligible_n[_CONDITION_KSLIDE])
            + _fraction_decimal(variances[_CONDITION_REFERENCE]) / Decimal(eligible_n[_CONDITION_REFERENCE])
        )
        standard_error = variance_of_difference.sqrt()
        z_critical = Decimal(ZERO_KOREAN_ANALYSIS_PLAN["z_one_sided_alpha"])
        lower_bound = mean_difference - z_critical * standard_error
        non_inferiority_pass = _passes_non_inferiority(lower_bound)
        safety_pass = all(arm_summary[condition]["absolute_safety_pass"] for condition in _CONDITIONS)
        sample_size_pass = all(eligible_n[condition] >= required_n for condition in _CONDITIONS)
        serious_pass = total_serious == 0
        return {
            "required_analyzable_participants_per_arm": required_n,
            "arms": arm_summary,
            "participant_mean_scores": {condition: _fmt(_fraction_decimal(means[condition])) for condition in _CONDITIONS},
            "kslide_minus_reference_mean_difference": _fmt(mean_difference),
            "welch_standard_error": _fmt(standard_error),
            "one_sided_97_5_percent_lower_bound": _fmt(lower_bound),
            "non_inferiority_pass": non_inferiority_pass,
            "serious_misleading_outcome_count": total_serious,
            "serious_misleading_rule_pass": serious_pass,
            "absolute_safety_pass": safety_pass,
            "sample_size_sufficient": sample_size_pass,
            "fixed_enrollment_target_met": all(eligible_n[condition] == required_n for condition in _CONDITIONS),
            "study_pass": non_inferiority_pass and serious_pass and safety_pass and sample_size_pass and all(eligible_n[condition] == required_n for condition in _CONDITIONS),
        }


def build_zero_korean_study_payload(
    *,
    subject_git_sha: str,
    deployment_fingerprint: str,
    truth_authority: dict[str, str],
    participants: list[dict[str, str]],
    outcomes: list[dict[str, str]],
) -> dict[str, Any]:
    """Build source-free release evidence from the frozen participant ledger."""

    protocol_id = ZERO_KOREAN_PROTOCOL_IDENTITY
    if not isinstance(subject_git_sha, str) or _HEX40.fullmatch(subject_git_sha) is None:
        raise ZeroKoreanStudyError("zero-Korean subject_git_sha is malformed")
    _digest(deployment_fingerprint, "zero-Korean deployment fingerprint")
    participants_copy = copy.deepcopy(participants)
    if not isinstance(participants_copy, list):
        raise ZeroKoreanStudyError("zero-Korean participant assignments must be a list")
    sealed_participants = sorted(participants_copy, key=lambda row: row.get("participant_id", "") if isinstance(row, dict) else "")
    authority = copy.deepcopy(truth_authority)
    rows: list[dict[str, Any]] = []
    for item in outcomes:
        if not isinstance(item, dict) or set(item) != {"condition", "participant_id", "question_id", "scoring_reviews", "adjudication"}:
            raise ZeroKoreanStudyError("zero-Korean raw outcome has an unsupported shape")
        rows.append(_seal_outcome_record(
            subject_git_sha=subject_git_sha,
            deployment_fingerprint=deployment_fingerprint,
            condition=item["condition"],
            participant_id=item["participant_id"],
            question_id=item["question_id"],
            question_set_identity=authority["question_set_identity"],
            expert_english_gold_identity=authority["expert_english_gold_identity"],
            scoring_reviews=item["scoring_reviews"],
            adjudication=item["adjudication"],
        ))
    rows.sort(key=lambda row: row["outcome_record_id"])
    payload: dict[str, Any] = {
        "study_contract_version": ZERO_KOREAN_STUDY_CONTRACT_VERSION,
        "subject_git_sha": subject_git_sha,
        "deployment_fingerprint": deployment_fingerprint,
        "protocol": copy.deepcopy(ZERO_KOREAN_STUDY_PROTOCOL),
        "protocol_identity": protocol_id,
        "analysis_plan": copy.deepcopy(ZERO_KOREAN_ANALYSIS_PLAN),
        "analysis_plan_identity": ZERO_KOREAN_ANALYSIS_PLAN_IDENTITY,
        "truth_authority": authority,
        "participants": sealed_participants,
        "outcome_records": rows,
    }
    payload["derived_results"] = _derive_results(sealed_participants, rows)
    payload["attestation_id"] = _sha256(payload)
    validate_zero_korean_study_payload(payload)
    return payload


def validate_zero_korean_study_payload(payload: Any) -> None:
    """Strictly validate contract identity, records, derived results, and gates."""

    required = {
        "study_contract_version", "subject_git_sha", "deployment_fingerprint",
        "protocol", "protocol_identity", "analysis_plan", "analysis_plan_identity",
        "truth_authority", "participants", "outcome_records", "derived_results", "attestation_id",
    }
    if not isinstance(payload, dict) or set(payload) != required:
        raise ZeroKoreanStudyError("zero-Korean evidence has an unsupported or incomplete source-free shape")
    if payload["study_contract_version"] != ZERO_KOREAN_STUDY_CONTRACT_VERSION:
        raise ZeroKoreanStudyError("zero-Korean study contract version is stale")
    if not isinstance(payload["subject_git_sha"], str) or _HEX40.fullmatch(payload["subject_git_sha"]) is None:
        raise ZeroKoreanStudyError("zero-Korean subject_git_sha is malformed")
    _digest(payload["deployment_fingerprint"], "zero-Korean deployment fingerprint")
    if payload["protocol"] != ZERO_KOREAN_STUDY_PROTOCOL or payload["protocol_identity"] != ZERO_KOREAN_PROTOCOL_IDENTITY:
        raise ZeroKoreanStudyError("zero-Korean protocol is altered or stale")
    if payload["analysis_plan"] != ZERO_KOREAN_ANALYSIS_PLAN or payload["analysis_plan_identity"] != ZERO_KOREAN_ANALYSIS_PLAN_IDENTITY:
        raise ZeroKoreanStudyError("zero-Korean analysis plan is altered or stale")
    # Recompute the power count independently from the declared frozen count.
    recomputed_n = _required_per_arm(payload["analysis_plan"])
    if payload["analysis_plan"].get("required_analyzable_participants_per_arm") != recomputed_n:
        raise ZeroKoreanStudyError("zero-Korean declared sample size disagrees with recalculated power")

    authority_fields = {
        "bilingual_review_attestation_id", "bilingual_review_contract_sha256",
        "corpus_set_identity_sha256", "corpus_item_identity_sha256",
        "reviewed_output_artifact_id", "reviewed_output_artifact_sha256",
        "expert_english_gold_identity", "question_set_identity",
    }
    authority = payload["truth_authority"]
    if not isinstance(authority, dict) or set(authority) != authority_fields:
        raise ZeroKoreanStudyError("zero-Korean bilingual truth authority has an unsupported shape")
    for field in authority_fields:
        _digest(authority[field], f"zero-Korean {field}")
    if authority["bilingual_review_attestation_id"] != authority["bilingual_review_contract_sha256"]:
        raise ZeroKoreanStudyError("zero-Korean bilingual authority contract identity is inconsistent")
    if authority["question_set_identity"] != authority["expert_english_gold_identity"]:
        raise ZeroKoreanStudyError("zero-Korean question set is not bound to the approved expert-English gold")

    participants = payload["participants"]
    if not isinstance(participants, list) or participants != sorted(participants, key=lambda row: row.get("participant_id", "") if isinstance(row, dict) else ""):
        raise ZeroKoreanStudyError("zero-Korean participant assignments are malformed or unsorted")
    participant_by_id: dict[str, str] = {}
    for participant in participants:
        if not isinstance(participant, dict) or set(participant) != {"participant_id", "condition"}:
            raise ZeroKoreanStudyError("zero-Korean participant record has an unsupported shape")
        participant_id = _digest(participant["participant_id"], "opaque participant identity")
        if participant["condition"] not in _CONDITIONS or participant_id in participant_by_id:
            raise ZeroKoreanStudyError("zero-Korean participant is duplicated or assigned to an unsupported condition")
        participant_by_id[participant_id] = participant["condition"]
    participant_counts = {condition: sum(value == condition for value in participant_by_id.values()) for condition in _CONDITIONS}
    if participant_counts[_CONDITION_KSLIDE] != participant_counts[_CONDITION_REFERENCE]:
        raise ZeroKoreanStudyError("zero-Korean randomized allocation is not balanced 1:1")
    for condition in _CONDITIONS:
        if participant_counts[condition] < 2:
            raise ZeroKoreanStudyError("both zero-Korean study conditions require analyzable participants")

    records = payload["outcome_records"]
    if not isinstance(records, list) or records != sorted(records, key=lambda row: row.get("outcome_record_id", "") if isinstance(row, dict) else ""):
        raise ZeroKoreanStudyError("zero-Korean outcome records are malformed or unsorted")
    record_fields = {
        "subject_git_sha", "deployment_fingerprint", "protocol_identity", "condition",
        "participant_id", "question_id", "question_category", "question_set_identity",
        "expert_english_gold_identity", "outcome", "outcome_record_id", "outcome_record_sha256",
        "scoring_reviews", "adjudication",
    }
    seen_ids: set[str] = set()
    seen_answers: set[tuple[str, str, str]] = set()
    participant_questions: dict[str, set[str]] = {participant_id: set() for participant_id in participant_by_id}
    questions = _question_map()
    for row in records:
        if not isinstance(row, dict) or set(row) != record_fields:
            raise ZeroKoreanStudyError("zero-Korean outcome record has an unsupported shape")
        if row["subject_git_sha"] != payload["subject_git_sha"] or row["deployment_fingerprint"] != payload["deployment_fingerprint"]:
            raise ZeroKoreanStudyError("zero-Korean outcome record is bound to a different candidate")
        if row["protocol_identity"] != ZERO_KOREAN_PROTOCOL_IDENTITY:
            raise ZeroKoreanStudyError("zero-Korean outcome record is bound to another protocol")
        condition, participant_id, question_id = row["condition"], row["participant_id"], row["question_id"]
        question = questions.get(question_id)
        if condition not in _CONDITIONS or participant_id not in participant_by_id or participant_by_id[participant_id] != condition:
            raise ZeroKoreanStudyError("zero-Korean outcome record has a foreign participant or condition")
        if question is None or row["question_category"] != question["category"]:
            raise ZeroKoreanStudyError("zero-Korean outcome question identity or category is invalid")
        if row["question_set_identity"] != authority["question_set_identity"] or row["expert_english_gold_identity"] != authority["expert_english_gold_identity"]:
            raise ZeroKoreanStudyError("zero-Korean outcome is bound to the wrong question or gold authority")
        if row["outcome"] not in _OUTCOMES:
            raise ZeroKoreanStudyError("zero-Korean outcome code is unsupported")
        binding = _review_binding(row)
        reviews = row["scoring_reviews"]
        if not isinstance(reviews, list) or len(reviews) != 2 or reviews != sorted(reviews, key=lambda item: item.get("review_record_id", "") if isinstance(item, dict) else ""):
            raise ZeroKoreanStudyError("zero-Korean outcome requires two sorted human scoring reviews")
        review_fields = set(binding) | {
            "reviewer_id", "reviewer_kind", "decision_authority", "decision_basis", "outcome",
            "review_record_id", "review_record_sha256",
        }
        reviewer_ids: set[str] = set()
        review_refs: list[dict[str, str]] = []
        review_outcomes: list[str] = []
        for review in reviews:
            if not isinstance(review, dict) or set(review) != review_fields or any(review.get(key) != value for key, value in binding.items()):
                raise ZeroKoreanStudyError("zero-Korean scoring review is unsupported or bound to another outcome")
            reviewer_id = _digest(review["reviewer_id"], "opaque human scorer identity")
            review_id = _digest(review["review_record_id"], "zero-Korean human scoring review identity")
            review_sha = _digest(review["review_record_sha256"], "zero-Korean human scoring review hash")
            expected_review_id = _sha256({**binding, "reviewer_id": reviewer_id})
            expected_review_sha = _sha256({key: value for key, value in review.items() if key != "review_record_sha256"})
            if (
                review["reviewer_kind"] != "independent_human_scorer"
                or review["decision_authority"] != "human_scoring"
                or review["decision_basis"] != "approved_bilingual_gold_comparison"
                or review["outcome"] not in _OUTCOMES
                or review_id != expected_review_id
                or review_sha != expected_review_sha
                or review_id in seen_ids
            ):
                raise ZeroKoreanStudyError("zero-Korean scoring review is altered, replayed, or not human-authoritative")
            reviewer_ids.add(reviewer_id)
            seen_ids.add(review_id)
            review_refs.append({"review_record_id": review_id, "review_record_sha256": review_sha})
            review_outcomes.append(review["outcome"])
        if len(reviewer_ids) != 2:
            raise ZeroKoreanStudyError("zero-Korean outcome requires two distinct human scorers")
        adjudication = row["adjudication"]
        if review_outcomes[0] == review_outcomes[1]:
            if adjudication is not None or row["outcome"] != review_outcomes[0]:
                raise ZeroKoreanStudyError("zero-Korean authoritative outcome disagrees with matching human reviews")
        else:
            adjudication_fields = set(binding) | {
                "adjudicator_id", "adjudicator_kind", "decision_authority", "review_record_refs",
                "resolution_outcome", "adjudication_record_id", "adjudication_record_sha256",
            }
            if not isinstance(adjudication, dict) or set(adjudication) != adjudication_fields or any(adjudication.get(key) != value for key, value in binding.items()):
                raise ZeroKoreanStudyError("zero-Korean scoring disagreement lacks bound human adjudication")
            adjudicator_id = _digest(adjudication["adjudicator_id"], "opaque bilingual adjudicator identity")
            adjudication_id = _digest(adjudication["adjudication_record_id"], "zero-Korean adjudication identity")
            adjudication_sha = _digest(adjudication["adjudication_record_sha256"], "zero-Korean adjudication hash")
            expected_adjudication_id = _sha256({**binding, "adjudicator_id": adjudicator_id, "review_record_refs": review_refs})
            expected_adjudication_sha = _sha256({key: value for key, value in adjudication.items() if key != "adjudication_record_sha256"})
            if (
                adjudicator_id in reviewer_ids
                or adjudication["adjudicator_kind"] != "human_bilingual_adjudicator"
                or adjudication["decision_authority"] != "human_adjudication"
                or adjudication["review_record_refs"] != review_refs
                or adjudication["resolution_outcome"] not in _OUTCOMES
                or row["outcome"] != adjudication["resolution_outcome"]
                or adjudication_id != expected_adjudication_id
                or adjudication_sha != expected_adjudication_sha
                or adjudication_id in seen_ids
            ):
                raise ZeroKoreanStudyError("zero-Korean human adjudication is altered, replayed, or inconsistent")
            seen_ids.add(adjudication_id)
        identity = _record_identity(row)
        expected_id = _sha256(identity)
        expected_sha = _sha256({key: value for key, value in row.items() if key != "outcome_record_sha256"})
        record_id = _digest(row["outcome_record_id"], "zero-Korean outcome record identity")
        record_sha = _digest(row["outcome_record_sha256"], "zero-Korean outcome record hash")
        key = (condition, participant_id, question_id)
        if record_id != expected_id or record_sha != expected_sha or record_id in seen_ids or key in seen_answers:
            raise ZeroKoreanStudyError("zero-Korean outcome record is altered, duplicated, or replayed")
        seen_ids.add(record_id)
        seen_answers.add(key)
        participant_questions[participant_id].add(question_id)
    expected_question_ids = set(questions)
    if len(records) != len(participants) * len(expected_question_ids) or any(items != expected_question_ids for items in participant_questions.values()):
        raise ZeroKoreanStudyError("every randomized participant must have exactly one closed outcome for each frozen question")

    expected_results = _derive_results(participants, records)
    if payload["derived_results"] != expected_results:
        raise ZeroKoreanStudyError("zero-Korean editable summary disagrees with participant/question outcome records")
    if expected_results["sample_size_sufficient"] is not True:
        raise ZeroKoreanStudyError("zero-Korean study arms do not meet the power-calculated analyzable sample size")
    if expected_results["fixed_enrollment_target_met"] is not True:
        raise ZeroKoreanStudyError("zero-Korean study enrollment does not match the frozen power-calculated target")
    if expected_results["non_inferiority_pass"] is not True:
        raise ZeroKoreanStudyError("zero-Korean study fails its predeclared non-inferiority bound")
    if expected_results["serious_misleading_rule_pass"] is not True:
        raise ZeroKoreanStudyError("zero-Korean study contains a serious misleading outcome")
    if expected_results["absolute_safety_pass"] is not True:
        raise ZeroKoreanStudyError("zero-Korean study fails an absolute comprehension safety floor")
    expected_attestation = _sha256({key: value for key, value in payload.items() if key != "attestation_id"})
    if _digest(payload["attestation_id"], "zero-Korean attestation identity") != expected_attestation:
        raise ZeroKoreanStudyError("zero-Korean attestation identity does not match the frozen study evidence")


def validate_zero_korean_candidate_binding(
    payload: dict[str, Any],
    *,
    subject_git_sha: str,
    deployment_fingerprint: str,
    candidate_spec: dict[str, Any] | None,
) -> None:
    if payload.get("subject_git_sha") != subject_git_sha or payload.get("deployment_fingerprint") != deployment_fingerprint:
        raise ZeroKoreanStudyError("zero-Korean study evidence does not match its candidate envelope")
    if not isinstance(candidate_spec, dict) or candidate_spec.get("subject_git_sha") != subject_git_sha:
        raise ZeroKoreanStudyError("zero-Korean study evidence requires its exact candidate specification")


def validate_zero_korean_authority_binding(payload: dict[str, Any], bilingual_payload: dict[str, Any]) -> None:
    """Require the study gold and K-Slide artifact to be KSA-29 human-reviewed."""

    from .bilingual_adjudication import canonical_bytes, validate_internal_bilingual_payload

    try:
        validate_internal_bilingual_payload(bilingual_payload)
    except ValueError as exc:
        raise ZeroKoreanStudyError("zero-Korean study requires valid KSA-29 bilingual human-review evidence") from exc
    authority = payload.get("truth_authority", {})
    contract = bilingual_payload["review_contract"]
    if (
        authority.get("bilingual_review_attestation_id") != bilingual_payload.get("attestation_id")
        or authority.get("bilingual_review_contract_sha256") != hashlib.sha256(canonical_bytes(contract)).hexdigest()
        or authority.get("corpus_set_identity_sha256") != hashlib.sha256(canonical_bytes(contract["corpus_set_identity"])).hexdigest()
    ):
        raise ZeroKoreanStudyError("zero-Korean truth authority does not match the supplied KSA-29 attestation")
    if contract.get("subject_git_sha") != payload.get("subject_git_sha") or contract.get("deployment_fingerprint") != payload.get("deployment_fingerprint"):
        raise ZeroKoreanStudyError("zero-Korean truth authority is for a different candidate")

    matched = False
    for work in contract["work_units"]:
        item_identity = hashlib.sha256(canonical_bytes({
            "item_id": work["item_id"],
            "source_sha256": work["source_sha256"],
            "gold_sha256": work["gold_sha256"],
        })).hexdigest()
        if (
            item_identity == authority.get("corpus_item_identity_sha256")
            and work.get("artifact_id") == authority.get("reviewed_output_artifact_id")
            and work.get("artifact_sha256") == authority.get("reviewed_output_artifact_sha256")
            and work.get("gold_sha256") == authority.get("expert_english_gold_identity")
            and work.get("gold_sha256") == authority.get("question_set_identity")
        ):
            matched = True
            break
    if not matched:
        raise ZeroKoreanStudyError("zero-Korean K-Slide output, expert-English gold, or question set is not the exact KSA-29 reviewed item")
