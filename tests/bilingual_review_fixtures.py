"""Synthetic source-free fixtures for the KSA-29 bilingual evidence contract."""

from __future__ import annotations

import hashlib
from typing import Any

from evals.corpus_governance import public_synthetic_manifest
from k_slide.bilingual_adjudication import canonical_bytes
from k_slide.corpus_governance import build_manifest, manifest_identity
from k_slide.quality_policy import QUALITY_POLICY_IDENTITY, policy_identity_record


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _seal(record: dict[str, Any], digest_field: str) -> dict[str, Any]:
    record[digest_field] = hashlib.sha256(canonical_bytes({key: value for key, value in record.items() if key != digest_field})).hexdigest()
    return record


def make_private_manifest(*, item_count: int = 1) -> dict[str, Any]:
    items = [{
        "item_id": f"fixture-item-{index:04d}",
        "source_sha256": _digest(f"synthetic-source-{index}"),
        "gold_sha256": _digest(f"synthetic-gold-{index}"),
        "state": "active",
    } for index in range(item_count)]
    return build_manifest(
        set_id="fixture-private-representative",
        role="private_representative",
        version="fixture-v1",
        state="active",
        items=items,
        provenance={"authority": "approved_private_evaluation", "record_sha256": _digest("fixture-private-authority")},
    )


def make_candidate(private_manifest: dict[str, Any], *, subject: str = "a" * 40) -> dict[str, Any]:
    public = public_synthetic_manifest()
    high_risk = build_manifest(
        set_id="fixture-frozen-high-risk",
        role="frozen_high_risk",
        version="fixture-v1",
        state="frozen",
        items=[{"item_id": "fixture-high-risk-0001", "source_sha256": _digest("high-source"), "gold_sha256": _digest("high-gold"), "state": "active"}],
        provenance={"authority": "evaluation_governance", "record_sha256": _digest("high-authority")},
    )
    held_out = build_manifest(
        set_id="fixture-sealed-held-out",
        role="sealed_held_out",
        version="fixture-v1",
        state="sealed",
        items=[{"item_id": "fixture-sealed-0001", "source_sha256": _digest("sealed-source"), "gold_sha256": _digest("sealed-gold"), "state": "active"}],
        provenance={"authority": "evaluation_governance", "record_sha256": _digest("sealed-authority")},
    )
    manifests = [public, private_manifest, high_risk, held_out]
    return {"subject_git_sha": subject, "corpus_identity": {"schema_version": "1.0", "sets": [manifest_identity(item) for item in manifests]}}


def make_review_contract(
    *,
    subject: str,
    deployment: str,
    manifest: dict[str, Any],
    disagreement_index: int | None = None,
    adjudicate: bool = True,
    ai_assistance: bool = False,
    fail_metric: str | None = None,
) -> dict[str, Any]:
    identity = manifest_identity(manifest)
    active_items = [item for item in manifest["items"] if item["state"] == "active"]
    metrics_by_work: list[list[tuple[str, str]]] = [[("locked_terminology", "incorrect" if index == 0 else "correct")] for index in range(200)]
    metrics_by_work[0].append(("overall_noncritical_semantic_fidelity", "incorrect"))
    for index in range(1, 100):
        metrics_by_work[index].append(("overall_noncritical_semantic_fidelity", "correct"))
    metrics_by_work[100].append(("unresolved_precision", "incorrect"))
    for index in range(101, 120):
        metrics_by_work[index].append(("unresolved_precision", "correct"))
    for index in range(120, 140):
        metrics_by_work[index].append(("material_unresolved_recall", "correct"))
    for index, metric in enumerate((
        "critical_business_meaning_errors",
        "critical_numeric_date_unit_errors",
        "critical_modality_escalations",
        "critical_table_mapping_errors",
        "critical_trend_reversals",
        "unsupported_critical_executive_claims",
    ), start=140):
        metrics_by_work[index].append((metric, "correct"))
    if fail_metric == "overall_noncritical_semantic_fidelity":
        metrics_by_work[1][1] = ("overall_noncritical_semantic_fidelity", "incorrect")
    elif fail_metric == "unresolved_precision":
        metrics_by_work[101].append(("unresolved_precision", "incorrect"))
    elif fail_metric == "material_unresolved_recall":
        metrics_by_work[120].append(("material_unresolved_recall", "incorrect"))
    elif fail_metric == "locked_terminology":
        metrics_by_work[1][0] = ("locked_terminology", "incorrect")
    elif fail_metric is not None:
        raise ValueError("unsupported fixture quality metric")

    work_units: list[dict[str, Any]] = []
    reviews: list[dict[str, Any]] = []
    assistance: list[dict[str, Any]] = []
    truth_records: dict[str, tuple[str, str, str, dict[str, Any], list[dict[str, Any]]]] = {}
    truth_index = 0
    for work_index, truth_specs in enumerate(metrics_by_work):
        artifact_index = work_index // 4
        item = active_items[artifact_index % len(active_items)]
        work_id = _digest(f"work-unit-{work_index}")
        artifact_id = _digest(f"output-artifact-id-{artifact_index}")
        artifact_hash = _digest(f"output-artifact-bytes-{artifact_index}")
        truths = []
        truth_indices: dict[str, int] = {}
        base_by_truth: dict[str, str] = {}
        for metric, base in truth_specs:
            truth_id = _digest(f"truth-unit-{truth_index}")
            truths.append({"truth_unit_id": truth_id, "metric": metric})
            truth_indices[truth_id] = truth_index
            base_by_truth[truth_id] = base
            truth_index += 1
        work = {
            "item_id": item["item_id"],
            "source_sha256": item["source_sha256"],
            "gold_sha256": item["gold_sha256"],
            "work_unit_id": work_id,
            "artifact_id": artifact_id,
            "artifact_sha256": artifact_hash,
            "truth_units": sorted(truths, key=lambda truth: truth["truth_unit_id"]),
        }
        work_units.append(work)
        record_pair: list[dict[str, Any]] = []
        reviewer_outcome_maps: list[dict[str, str]] = []
        for reviewer_index in range(2):
            reviewer_outcomes: dict[str, str] = {}
            for truth in work["truth_units"]:
                outcome = base_by_truth[truth["truth_unit_id"]]
                if reviewer_index == 0 and disagreement_index == truth_indices[truth["truth_unit_id"]]:
                    outcome = "incorrect" if base == "correct" else "correct"
                reviewer_outcomes[truth["truth_unit_id"]] = outcome
            reviewer_outcome_maps.append(reviewer_outcomes)
            reviewer_id = _digest(f"reviewer-{reviewer_index}")
            review_id = _digest(f"review-record-{work_index}-{reviewer_index}")
            review_artifact_id = _digest(f"review-artifact-id-{work_index}-{reviewer_index}")
            review_artifact_hash = _digest(f"review-artifact-bytes-{work_index}-{reviewer_index}")
            assistance_ids: list[str] = []
            if ai_assistance and work_index == 0 and reviewer_index == 0:
                assistance_id = _digest("ai-assistance-record-0")
                assistance_ids = [assistance_id]
            corpus_item_hash = hashlib.sha256(canonical_bytes({"item_id": item["item_id"], "source_sha256": item["source_sha256"], "gold_sha256": item["gold_sha256"]})).hexdigest()
            binding = {
                "subject_git_sha": subject,
                "deployment_fingerprint": deployment,
                "corpus_set_identity_sha256": hashlib.sha256(canonical_bytes(identity)).hexdigest(),
                "evaluation_purpose": "private_evaluation",
                "corpus_item_id": item["item_id"],
                "corpus_item_identity_sha256": corpus_item_hash,
                "policy_identity_sha256": QUALITY_POLICY_IDENTITY,
                "work_unit_id": work_id,
                "artifact_id": artifact_id,
                "artifact_sha256": artifact_hash,
            }
            record = {
                "review_record_id": review_id,
                "review_artifact_id": review_artifact_id,
                "review_artifact_sha256": review_artifact_hash,
                "reviewer_id": reviewer_id,
                "reviewer_kind": "independent_bilingual_human",
                "decision_authority": "human_review",
                "decision_basis": "direct_source_gold_comparison",
                **binding,
                "ai_assistance_ids": assistance_ids,
                "truth_unit_outcomes": [{"truth_unit_id": truth["truth_unit_id"], "metric": truth["metric"], "outcome": reviewer_outcomes[truth["truth_unit_id"]]} for truth in work["truth_units"]],
            }
            _seal(record, "review_record_sha256")
            record_pair.append(record)
            if assistance_ids:
                assistance_record = {
                    "assistance_record_id": assistance_ids[0],
                    "assistance_artifact_id": _digest("ai-artifact-id-0"),
                    "assistance_artifact_sha256": _digest("ai-artifact-bytes-0"),
                    "review_record_id": review_id,
                    "assistance_kind": "translation_suggestion",
                    "authority": "non_authoritative_assistance",
                    **binding,
                }
                _seal(assistance_record, "assistance_record_sha256")
                assistance.append(assistance_record)
        reviews.extend(record_pair)
        for truth in work["truth_units"]:
            first = reviewer_outcome_maps[0][truth["truth_unit_id"]]
            second = reviewer_outcome_maps[1][truth["truth_unit_id"]]
            truth_records[truth["truth_unit_id"]] = (truth["metric"], first, second, work, record_pair)

    reviews.sort(key=lambda item: item["review_record_id"])
    assistance.sort(key=lambda item: item["assistance_record_id"])
    adjudications: list[dict[str, Any]] = []
    decision_rows: list[dict[str, Any]] = []
    for truth_id, (metric, first, second, work, pair_holder) in sorted(truth_records.items()):
        pair = sorted(pair_holder, key=lambda item: item["review_record_id"])
        refs = [{"review_record_id": item["review_record_id"], "review_record_sha256": item["review_record_sha256"]} for item in pair]
        is_disagreement = first != second
        adj_id: str | None = None
        resolved = first
        if is_disagreement and adjudicate:
            adj_id = _digest(f"adjudication-record-{truth_id}")
            adj_artifact_id = _digest(f"adjudication-artifact-id-{truth_id}")
            adj_artifact_hash = _digest(f"adjudication-artifact-bytes-{truth_id}")
            item = next(value for value in active_items if value["item_id"] == work["item_id"])
            binding = {
                "subject_git_sha": subject,
                "deployment_fingerprint": deployment,
                "corpus_set_identity_sha256": hashlib.sha256(canonical_bytes(identity)).hexdigest(),
                "evaluation_purpose": "private_evaluation",
                "corpus_item_id": item["item_id"],
                "corpus_item_identity_sha256": hashlib.sha256(canonical_bytes({"item_id": item["item_id"], "source_sha256": item["source_sha256"], "gold_sha256": item["gold_sha256"]})).hexdigest(),
                "policy_identity_sha256": QUALITY_POLICY_IDENTITY,
                "work_unit_id": work["work_unit_id"],
                "artifact_id": work["artifact_id"],
                "artifact_sha256": work["artifact_sha256"],
            }
            adjudication = {
                "adjudication_record_id": adj_id,
                "adjudication_artifact_id": adj_artifact_id,
                "adjudication_artifact_sha256": adj_artifact_hash,
                "adjudicator_id": _digest("opaque-adjudicator-1"),
                "adjudicator_kind": "human_bilingual_adjudicator",
                "decision_authority": "human_adjudication",
                **binding,
                "truth_unit_id": truth_id,
                "metric": metric,
                "review_record_refs": refs,
                "resolution_outcome": second,
            }
            _seal(adjudication, "adjudication_record_sha256")
            adjudications.append(adjudication)
            resolved = second
        decision_rows.append({
            "item_id": work["item_id"],
            "work_unit_id": work["work_unit_id"],
            "truth_unit_id": truth_id,
            "metric": metric,
            "review_record_refs": refs,
            "agreement_status": "disagreement" if is_disagreement else "agreement",
            "adjudication_record_id": adj_id,
            "authoritative_outcome": resolved if not is_disagreement or adjudicate else None,
        })
    adjudications.sort(key=lambda item: item["adjudication_record_id"])
    decision_rows.sort(key=lambda item: (item["item_id"], item["work_unit_id"], item["truth_unit_id"]))
    return {
        "schema_version": "1.0",
        "subject_git_sha": subject,
        "deployment_fingerprint": deployment,
        "evaluation_purpose": "private_evaluation",
        "corpus_set_identity": identity,
        "corpus_manifest": manifest,
        "policy_identity": policy_identity_record(),
        "work_units": sorted(work_units, key=lambda item: (item["item_id"], item["work_unit_id"])),
        "review_records": reviews,
        "adjudication_records": adjudications,
        "ai_assistance_records": assistance,
        "truth_unit_decisions": decision_rows,
    }
