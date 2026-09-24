"""Closed, source-free bilingual review and adjudication evidence contract."""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from typing import Any

from .corpus_governance import (
    CorpusGovernanceError,
    canonical_manifest,
    canonical_set_identity,
    manifest_identity,
    require_set_purpose,
)
from .quality_policy import (
    QUALITY_POLICY_IDENTITY,
    policy_identity_record,
)


BILINGUAL_REVIEW_SCHEMA_VERSION = "1.0"
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_METRICS = frozenset({
    "critical_business_meaning_errors",
    "critical_numeric_date_unit_errors",
    "critical_modality_escalations",
    "critical_table_mapping_errors",
    "critical_trend_reversals",
    "unsupported_critical_executive_claims",
    "overall_noncritical_semantic_fidelity",
    "unresolved_precision",
    "material_unresolved_recall",
    "locked_terminology",
})
_CRITICAL_METRICS = frozenset({
    "critical_business_meaning_errors",
    "critical_numeric_date_unit_errors",
    "critical_modality_escalations",
    "critical_table_mapping_errors",
    "critical_trend_reversals",
    "unsupported_critical_executive_claims",
})
_RATE_METRICS = _METRICS - _CRITICAL_METRICS
_OUTCOMES = frozenset({"correct", "incorrect"})
_CONTRACT_FIELDS = {
    "schema_version", "subject_git_sha", "deployment_fingerprint",
    "evaluation_purpose", "corpus_set_identity", "corpus_manifest",
    "policy_identity", "work_units", "review_records",
    "adjudication_records", "ai_assistance_records", "truth_unit_decisions",
}
_WORK_UNIT_FIELDS = {
    "item_id", "source_sha256", "gold_sha256", "work_unit_id",
    "artifact_id", "artifact_sha256", "truth_units",
}
_TRUTH_UNIT_FIELDS = {"truth_unit_id", "metric"}
_BINDING_FIELDS = {
    "subject_git_sha", "deployment_fingerprint", "corpus_set_identity_sha256",
    "evaluation_purpose", "corpus_item_id", "corpus_item_identity_sha256",
    "policy_identity_sha256", "work_unit_id", "artifact_id", "artifact_sha256",
}
_REVIEW_FIELDS = _BINDING_FIELDS | {
    "review_record_id", "review_record_sha256", "review_artifact_id",
    "review_artifact_sha256", "reviewer_id", "reviewer_kind",
    "decision_authority", "decision_basis", "ai_assistance_ids",
    "truth_unit_outcomes",
}
_REVIEW_OUTCOME_FIELDS = {"truth_unit_id", "metric", "outcome"}
_ADJUDICATION_FIELDS = _BINDING_FIELDS | {
    "adjudication_record_id", "adjudication_record_sha256",
    "adjudication_artifact_id", "adjudication_artifact_sha256",
    "adjudicator_id", "adjudicator_kind", "decision_authority",
    "truth_unit_id", "metric", "review_record_refs", "resolution_outcome",
}
_REVIEW_REF_FIELDS = {"review_record_id", "review_record_sha256"}
_ASSISTANCE_FIELDS = _BINDING_FIELDS | {
    "assistance_record_id", "assistance_record_sha256",
    "assistance_artifact_id", "assistance_artifact_sha256",
    "review_record_id", "assistance_kind", "authority",
}
_DECISION_FIELDS = {
    "item_id", "work_unit_id", "truth_unit_id", "metric",
    "review_record_refs", "agreement_status", "adjudication_record_id",
    "authoritative_outcome",
}


class BilingualAdjudicationError(ValueError):
    """A bilingual review ledger is malformed, incomplete, or unbound."""


def _fail(message: str) -> None:
    raise BilingualAdjudicationError(message)


def _hash(value: Any, label: str) -> str:
    if not isinstance(value, str) or _HEX64.fullmatch(value) is None:
        _fail(f"{label} must be a lowercase SHA-256 digest")
    return value


def _id(value: Any, label: str) -> str:
    return _hash(value, label)


def _record_digest(value: dict[str, Any], digest_field: str, label: str) -> str:
    supplied = _hash(value.get(digest_field), label)
    body = {key: item for key, item in value.items() if key != digest_field}
    expected = hashlib.sha256(canonical_bytes(body)).hexdigest()
    if supplied != expected:
        _fail(f"{label} does not match its canonical record")
    return supplied


def canonical_bytes(value: Any) -> bytes:
    import json

    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _ordered(values: Any, key: Any, label: str) -> list[Any]:
    if not isinstance(values, list) or values != sorted(values, key=key):
        _fail(f"{label} must be a deterministically sorted list")
    return values


def _corpus_item_identity(item_id: str, source_sha256: str, gold_sha256: str) -> str:
    return hashlib.sha256(canonical_bytes({
        "item_id": item_id,
        "source_sha256": source_sha256,
        "gold_sha256": gold_sha256,
    })).hexdigest()


def _validate_shape(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        _fail(f"{label} has an unsupported shape")
    return value


def _binding_for(contract: dict[str, Any], work: dict[str, Any]) -> dict[str, Any]:
    corpus_identity = contract["corpus_set_identity"]
    policy = contract["policy_identity"]
    return {
        "subject_git_sha": contract["subject_git_sha"],
        "deployment_fingerprint": contract["deployment_fingerprint"],
        "corpus_set_identity_sha256": hashlib.sha256(canonical_bytes(corpus_identity)).hexdigest(),
        "evaluation_purpose": contract["evaluation_purpose"],
        "corpus_item_id": work["item_id"],
        "corpus_item_identity_sha256": _corpus_item_identity(work["item_id"], work["source_sha256"], work["gold_sha256"]),
        "policy_identity_sha256": policy["identity_sha256"],
        "work_unit_id": work["work_unit_id"],
        "artifact_id": work["artifact_id"],
        "artifact_sha256": work["artifact_sha256"],
    }


def _validate_contract(contract: Any) -> tuple[dict[str, int | float], list[dict[str, Any]]]:
    contract = _validate_shape(contract, _CONTRACT_FIELDS, "bilingual review contract")
    if contract.get("schema_version") != BILINGUAL_REVIEW_SCHEMA_VERSION:
        _fail("unsupported bilingual review contract version")
    subject = contract.get("subject_git_sha")
    deployment = contract.get("deployment_fingerprint")
    if not isinstance(subject, str) or _HEX40.fullmatch(subject) is None:
        _fail("bilingual review candidate subject is malformed")
    _hash(deployment, "bilingual review deployment fingerprint")
    if contract.get("evaluation_purpose") != "private_evaluation":
        _fail("bilingual review purpose must be private_evaluation")
    try:
        manifest = canonical_manifest(contract.get("corpus_manifest"))
        set_identity = canonical_set_identity(contract.get("corpus_set_identity"))
        expected_identity = manifest_identity(manifest)
        consumed_identity = require_set_purpose(set_identity, contract.get("evaluation_purpose"))
    except CorpusGovernanceError as exc:
        raise BilingualAdjudicationError("bilingual review corpus binding is invalid") from exc
    if manifest["role"] != "private_representative" or consumed_identity != expected_identity:
        _fail("bilingual review manifest and governed set identity disagree")
    if contract["policy_identity"] != policy_identity_record():
        _fail("bilingual review policy identity is stale")

    manifest_items = {item["item_id"]: item for item in manifest["items"] if item["state"] == "active"}
    work_units = _ordered(contract.get("work_units"), lambda item: (str(item.get("item_id", "")), str(item.get("work_unit_id", ""))) if isinstance(item, dict) else ("", ""), "bilingual work units")
    if len(work_units) < 200:
        _fail("bilingual review sample has fewer than 200 work units")
    work_by_id: dict[str, dict[str, Any]] = {}
    truth_by_id: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {}
    artifact_bindings: dict[str, tuple[str, str]] = {}
    for raw_work in work_units:
        work = _validate_shape(raw_work, _WORK_UNIT_FIELDS, "bilingual work unit")
        item_id = work.get("item_id")
        item = manifest_items.get(item_id) if isinstance(item_id, str) else None
        if item is None or item["source_sha256"] != work.get("source_sha256") or item["gold_sha256"] != work.get("gold_sha256"):
            _fail("bilingual work unit does not bind an active governed corpus item")
        _id(work.get("work_unit_id"), "work unit identity")
        _id(work.get("artifact_id"), "reviewed output artifact identity")
        _hash(work.get("artifact_sha256"), "reviewed output artifact hash")
        if work["work_unit_id"] in work_by_id:
            _fail("bilingual work unit identity is duplicated or replayed")
        artifact_binding = (item_id, work["artifact_sha256"])
        previous_artifact = artifact_bindings.setdefault(work["artifact_id"], artifact_binding)
        if previous_artifact != artifact_binding:
            _fail("reviewed output artifact is replayed across governed items")
        work_by_id[work["work_unit_id"]] = work
        artifact_bindings[work["artifact_id"]] = artifact_binding
        truth_units = _ordered(work.get("truth_units"), lambda item: str(item.get("truth_unit_id", "")) if isinstance(item, dict) else "", "truth units")
        if not truth_units:
            _fail("bilingual work unit has no decision-critical truth units")
        for raw_truth in truth_units:
            truth = _validate_shape(raw_truth, _TRUTH_UNIT_FIELDS, "decision-critical truth unit")
            truth_id = _id(truth.get("truth_unit_id"), "truth-unit identity")
            if not isinstance(truth.get("metric"), str) or truth["metric"] not in _METRICS or truth_id in truth_by_id:
                _fail("truth-unit identity or metric is duplicate or unsupported")
            truth_by_id[truth_id] = (work, truth)
    if len(artifact_bindings) < 50:
        _fail("bilingual review sample has fewer than 50 distinct output artifacts")
    if set(metric for _work, truth in truth_by_id.values() for metric in (truth["metric"],)) != _METRICS:
        _fail("bilingual review sample lacks a decision-critical metric category")

    records = _ordered(contract.get("review_records"), lambda item: str(item.get("review_record_id", "")) if isinstance(item, dict) else "", "bilingual review records")
    if len(records) != len(work_units) * 2:
        _fail("each bilingual work unit requires exactly two independent review records")
    records_by_work: dict[str, list[dict[str, Any]]] = defaultdict(list)
    records_by_id: dict[str, dict[str, Any]] = {}
    outcomes_by_record: dict[str, dict[str, str]] = {}
    reviewer_by_record: dict[str, str] = {}
    review_artifact_ids: set[str] = set()
    review_artifact_hashes: set[str] = set()
    review_hashes: set[str] = set()
    for raw_record in records:
        record = _validate_shape(raw_record, _REVIEW_FIELDS, "bilingual review record")
        record_id = _id(record.get("review_record_id"), "review record identity")
        digest = _record_digest(record, "review_record_sha256", "review record hash")
        artifact_id = _id(record.get("review_artifact_id"), "review artifact identity")
        artifact_hash = _hash(record.get("review_artifact_sha256"), "review artifact hash")
        reviewer = _id(record.get("reviewer_id"), "reviewer identity")
        if record_id in records_by_id or digest in review_hashes or artifact_id in review_artifact_ids or artifact_hash in review_artifact_hashes:
            _fail("bilingual review record is duplicate, copied, or replayed")
        if record.get("reviewer_kind") != "independent_bilingual_human" or record.get("decision_authority") != "human_review" or record.get("decision_basis") != "direct_source_gold_comparison":
            _fail("bilingual review record is not an authoritative independent human review")
        work = work_by_id.get(record.get("work_unit_id"))
        if work is None or any(record.get(key) != value for key, value in _binding_for(contract, work).items()):
            _fail("bilingual review record is bound to another candidate, corpus item, policy, artifact, or work unit")
        outcomes = _ordered(record.get("truth_unit_outcomes"), lambda item: item.get("truth_unit_id", "") if isinstance(item, dict) else "", "review truth-unit outcomes")
        expected = {item["truth_unit_id"]: item["metric"] for item in work["truth_units"]}
        actual: dict[str, str] = {}
        for raw_outcome in outcomes:
            outcome = _validate_shape(raw_outcome, _REVIEW_OUTCOME_FIELDS, "review truth-unit outcome")
            truth_id = _id(outcome.get("truth_unit_id"), "reviewed truth-unit identity")
            if truth_id in actual or outcome.get("metric") != expected.get(truth_id) or not isinstance(outcome.get("outcome"), str) or outcome["outcome"] not in _OUTCOMES:
                _fail("review record contains a duplicate, unrelated, or invalid truth-unit outcome")
            actual[truth_id] = outcome["outcome"]
        if set(actual) != set(expected):
            _fail("review record does not cover the exact work-unit truth inventory")
        assistance_ids = record.get("ai_assistance_ids")
        if not isinstance(assistance_ids, list) or any(not isinstance(item, str) or _HEX64.fullmatch(item) is None for item in assistance_ids) or assistance_ids != sorted(set(assistance_ids)):
            _fail("review AI-assistance references must be unique and sorted")
        records_by_work[work["work_unit_id"]].append(record)
        records_by_id[record_id] = record
        outcomes_by_record[record_id] = actual
        reviewer_by_record[record_id] = reviewer
        review_artifact_ids.add(artifact_id)
        review_artifact_hashes.add(artifact_hash)
        review_hashes.add(digest)
    for work_id, pair in records_by_work.items():
        if len(pair) != 2 or reviewer_by_record[pair[0]["review_record_id"]] == reviewer_by_record[pair[1]["review_record_id"]] or pair[0]["review_record_id"] == pair[1]["review_record_id"]:
            _fail("each work unit requires two distinct reviewers and review records")

    assistance_records = _ordered(contract.get("ai_assistance_records"), lambda item: str(item.get("assistance_record_id", "")) if isinstance(item, dict) else "", "AI assistance records")
    assistance_ids: set[str] = set()
    assistance_artifacts: set[str] = set()
    assistance_hashes: set[str] = set()
    assistance_record_hashes: set[str] = set()
    assistance_by_review: dict[str, list[str]] = defaultdict(list)
    for raw_assistance in assistance_records:
        assistance = _validate_shape(raw_assistance, _ASSISTANCE_FIELDS, "AI assistance record")
        assistance_id = _id(assistance.get("assistance_record_id"), "AI assistance identity")
        assistance_record_hash = _record_digest(assistance, "assistance_record_sha256", "AI assistance record hash")
        artifact_id = _id(assistance.get("assistance_artifact_id"), "AI assistance artifact identity")
        artifact_hash = _hash(assistance.get("assistance_artifact_sha256"), "AI assistance artifact hash")
        if assistance_id in assistance_ids or assistance_record_hash in assistance_record_hashes or artifact_id in assistance_artifacts or artifact_hash in assistance_hashes:
            _fail("AI assistance record or artifact is duplicated or replayed")
        if not isinstance(assistance.get("assistance_kind"), str) or assistance["assistance_kind"] not in {"translation_suggestion", "terminology_suggestion", "comparison_suggestion"} or assistance.get("authority") != "non_authoritative_assistance":
            _fail("AI assistance may only be recorded as non-authoritative provenance")
        review = records_by_id.get(assistance.get("review_record_id"))
        if review is None:
            _fail("AI assistance must reference an exact human review record")
        work = work_by_id[review["work_unit_id"]]
        if any(assistance.get(key) != value for key, value in _binding_for(contract, work).items()):
            _fail("AI assistance is bound to another candidate, corpus item, policy, artifact, or work unit")
        assistance_ids.add(assistance_id)
        assistance_artifacts.add(artifact_id)
        assistance_hashes.add(artifact_hash)
        assistance_record_hashes.add(assistance_record_hash)
        assistance_by_review[review["review_record_id"]].append(assistance_id)
    for record in records:
        if record["ai_assistance_ids"] != sorted(assistance_by_review.get(record["review_record_id"], [])):
            _fail("review AI-assistance references do not match non-authoritative provenance")

    adjudications = _ordered(contract.get("adjudication_records"), lambda item: str(item.get("adjudication_record_id", "")) if isinstance(item, dict) else "", "bilingual adjudication records")
    adjudications_by_truth: dict[str, dict[str, Any]] = {}
    adjudication_ids: set[str] = set()
    adjudication_artifact_ids: set[str] = set()
    adjudication_artifact_hashes: set[str] = set()
    adjudication_hashes: set[str] = set()
    records_for_truth: dict[str, list[tuple[dict[str, Any], str]]] = defaultdict(list)
    for work in work_units:
        for truth in work["truth_units"]:
            for record in records_by_work[work["work_unit_id"]]:
                records_for_truth[truth["truth_unit_id"]].append((record, outcomes_by_record[record["review_record_id"]][truth["truth_unit_id"]]))
    decisions: list[dict[str, Any]] = []
    expected_adjudications: set[str] = set()
    metrics_outcomes: dict[str, list[str]] = defaultdict(list)
    for truth_id, (work, truth) in sorted(truth_by_id.items()):
        pair = sorted(records_for_truth[truth_id], key=lambda entry: entry[0]["review_record_id"])
        refs = [{"review_record_id": record["review_record_id"], "review_record_sha256": record["review_record_sha256"]} for record, _outcome in pair]
        agreement = pair[0][1] == pair[1][1]
        status = "agreement" if agreement else "disagreement"
        adjudication = None
        if not agreement:
            expected_adjudications.add(truth_id)
            adjudication = next((item for item in adjudications if isinstance(item, dict) and item.get("truth_unit_id") == truth_id), None)
            if adjudication is None:
                _fail("unresolved reviewer disagreement blocks authoritative bilingual truth")
            _validate_shape(adjudication, _ADJUDICATION_FIELDS, "bilingual adjudication record")
            adjudication_id = _id(adjudication.get("adjudication_record_id"), "adjudication record identity")
            digest = _record_digest(adjudication, "adjudication_record_sha256", "adjudication record hash")
            artifact_id = _id(adjudication.get("adjudication_artifact_id"), "adjudication artifact identity")
            artifact_hash = _hash(adjudication.get("adjudication_artifact_sha256"), "adjudication artifact hash")
            if adjudication_id in adjudication_ids or digest in adjudication_hashes or artifact_id in adjudication_artifact_ids or artifact_hash in adjudication_artifact_hashes:
                _fail("adjudication record or artifact is duplicated or replayed")
            if adjudication.get("adjudicator_id") is None:
                _fail("adjudication provenance is missing")
            _id(adjudication.get("adjudicator_id"), "adjudicator identity")
            if adjudication.get("adjudicator_kind") != "human_bilingual_adjudicator" or adjudication.get("decision_authority") != "human_adjudication":
                _fail("only a provenance-bearing human adjudication may resolve disagreement")
            if any(adjudication.get(key) != value for key, value in _binding_for(contract, work).items()):
                _fail("adjudication is bound to another candidate, corpus item, policy, artifact, or work unit")
            if adjudication.get("metric") != truth["metric"] or adjudication.get("review_record_refs") != refs:
                _fail("adjudication does not cite the exact conflicting reviews and truth unit")
            resolution = adjudication.get("resolution_outcome")
            if not isinstance(resolution, str) or resolution not in _OUTCOMES:
                _fail("adjudication outcome is not a closed authoritative resolution")
            adjudications_by_truth[truth_id] = adjudication
            adjudication_ids.add(adjudication_id)
            adjudication_hashes.add(digest)
            adjudication_artifact_ids.add(artifact_id)
            adjudication_artifact_hashes.add(artifact_hash)
        else:
            resolution = pair[0][1]
        decisions.append({
            "item_id": work["item_id"],
            "work_unit_id": work["work_unit_id"],
            "truth_unit_id": truth_id,
            "metric": truth["metric"],
            "review_record_refs": refs,
            "agreement_status": status,
            "adjudication_record_id": adjudication["adjudication_record_id"] if adjudication is not None else None,
            "authoritative_outcome": resolution,
        })
        metrics_outcomes[truth["metric"]].append(resolution)
    if set(adjudications_by_truth) != expected_adjudications or len(adjudications) != len(expected_adjudications):
        _fail("adjudication set contains missing, malformed, or unrelated records")
    decisions.sort(key=lambda item: (item["item_id"], item["work_unit_id"], item["truth_unit_id"]))
    supplied_decisions = contract.get("truth_unit_decisions")
    if supplied_decisions != decisions:
        _fail("truth-unit agreement and adjudication summary is incomplete or tampered")

    if set(metrics_outcomes) != _METRICS or any(not metrics_outcomes[metric] for metric in _RATE_METRICS):
        _fail("bilingual truth does not cover every required quality metric")
    derived: dict[str, int | float] = {}
    for metric in sorted(_CRITICAL_METRICS):
        derived[metric] = sum(outcome == "incorrect" for outcome in metrics_outcomes[metric])
    for metric in sorted(_RATE_METRICS):
        values = metrics_outcomes[metric]
        derived[metric] = sum(outcome == "correct" for outcome in values) / len(values)
    return derived, decisions


def build_internal_bilingual_payload(review_contract: dict[str, Any]) -> dict[str, Any]:
    """Derive the release payload from a source-free paired-review ledger."""

    metrics, _decisions = _validate_contract(review_contract)
    work_units = review_contract["work_units"]
    payload = {
        "attestation_id": hashlib.sha256(canonical_bytes(review_contract)).hexdigest(),
        "review_contract_version": BILINGUAL_REVIEW_SCHEMA_VERSION,
        "review_contract": review_contract,
        "corpus_set_identity": review_contract["corpus_set_identity"],
        "evaluation_purpose": review_contract["evaluation_purpose"],
        "artifact_count": len({item["artifact_id"] for item in work_units}),
        "work_unit_count": len(work_units),
        **metrics,
        "quality_policy": policy_identity_record(),
        "quality_policy_identity": QUALITY_POLICY_IDENTITY,
    }
    validate_internal_bilingual_payload(payload)
    return payload


def validate_internal_bilingual_payload(payload: Any) -> None:
    fields = {
        "attestation_id", "review_contract_version", "review_contract",
        "corpus_set_identity", "evaluation_purpose", "artifact_count", "work_unit_count", "quality_policy",
        "quality_policy_identity", *_METRICS,
    }
    payload = _validate_shape(payload, fields, "internal bilingual evidence")
    _id(payload.get("attestation_id"), "bilingual attestation identity")
    if payload.get("review_contract_version") != BILINGUAL_REVIEW_SCHEMA_VERSION:
        _fail("internal bilingual evidence has a stale review contract")
    if payload.get("quality_policy") != policy_identity_record() or payload.get("quality_policy_identity") != QUALITY_POLICY_IDENTITY:
        _fail("internal bilingual evidence quality-policy identity is missing or stale")
    metrics, _decisions = _validate_contract(payload.get("review_contract"))
    contract = payload["review_contract"]
    if payload.get("attestation_id") != hashlib.sha256(canonical_bytes(contract)).hexdigest():
        _fail("internal bilingual attestation identity does not match its review set")
    if payload.get("corpus_set_identity") != contract.get("corpus_set_identity") or payload.get("evaluation_purpose") != contract.get("evaluation_purpose"):
        _fail("internal bilingual evidence summary disagrees with the review contract binding")
    expected_artifacts = len({item["artifact_id"] for item in contract["work_units"]})
    expected_work_units = len(contract["work_units"])
    if payload.get("artifact_count") != expected_artifacts or payload.get("work_unit_count") != expected_work_units:
        _fail("internal bilingual sample counts disagree with the complete review set")
    for metric, expected in metrics.items():
        actual = payload.get(metric)
        if isinstance(actual, bool) or not isinstance(actual, (int, float)) or abs(float(actual) - float(expected)) > 1e-12:
            _fail("internal bilingual aggregate metrics disagree with reviewer and adjudication records")
