from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from evals.corpus_governance import public_synthetic_manifest
from evals.scenarios import (
    DATASET_VERSION,
    EXPECTED_CORPUS_FINGERPRINT_V1,
    EXPECTED_HELD_OUT_FINGERPRINT_V1,
    scenario_specs,
    split_manifest,
)
from k_slide.certification import (
    EvidenceValidationError,
    candidate_completeness,
    candidate_deployment_fingerprint,
    canonical_corpus_identity,
    validate_model_evidence_corpus_binding,
)
from k_slide.corpus_governance import (
    ACCESS_CLASS_BY_ROLE,
    ALLOWED_PURPOSES_BY_ROLE,
    CORPUS_ROLES,
    CorpusGovernanceError,
    apply_contamination_report,
    build_manifest,
    canonical_bytes,
    canonical_corpus_identity as canonical_governed_identity,
    canonical_manifest,
    cross_set_overlaps,
    is_complete_corpus_identity,
    item_fingerprint,
    load_manifest,
    manifest_identity,
    require_set_purpose,
    validate_contamination_report,
    validate_corpus_bundle,
    validate_role_purpose,
    validate_transition,
)


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _manifest(role: str, *, version: str = "v1", state: str | None = None, items: list[dict] | None = None, set_id: str | None = None, predecessor: dict | None = None):
    state = state or {
        "public_synthetic_regression": "active",
        "private_representative": "active",
        "frozen_high_risk": "frozen",
        "sealed_held_out": "sealed",
    }.get(role, "active")
    items = items or [{"item_id": "opaque-1", "source_sha256": _hash(f"{role}-source"), "gold_sha256": _hash(f"{role}-gold"), "state": "active"}]
    authority = {
        "public_synthetic_regression": "repository_generator",
        "private_representative": "approved_private_evaluation",
        "frozen_high_risk": "evaluation_governance",
        "sealed_held_out": "evaluation_governance",
    }.get(role, "evaluation_governance")
    return build_manifest(
        set_id=set_id or f"set-{role}", role=role, version=version, state=state,
        items=items,
        provenance={"authority": authority, "record_sha256": _hash(f"record-{role}-{version}")},
        predecessor=predecessor,
    )


def _complete_identity(*, sealed: dict | None = None, high_risk: dict | None = None, private: dict | None = None):
    public = manifest_identity(public_synthetic_manifest())
    private = manifest_identity(private or _manifest("private_representative"))
    high_risk = manifest_identity(high_risk or _manifest("frozen_high_risk"))
    sealed = manifest_identity(sealed or _manifest("sealed_held_out"))
    return canonical_governed_identity({"schema_version": "1.0", "sets": [public, private, high_risk, sealed]}, require_complete=True)


class KSA26CorpusGovernanceTests(unittest.TestCase):
    def test_closed_roles_purposes_and_access_classes(self):
        self.assertEqual(CORPUS_ROLES, tuple(ALLOWED_PURPOSES_BY_ROLE))
        self.assertEqual(len(ACCESS_CLASS_BY_ROLE), 4)
        for role, purposes in ALLOWED_PURPOSES_BY_ROLE.items():
            for purpose in purposes:
                validate_role_purpose(role, purpose)
        with self.assertRaises(CorpusGovernanceError):
            validate_role_purpose("held_out", "promotion")
        with self.assertRaises(CorpusGovernanceError):
            validate_role_purpose("sealed_held_out", "development")

    def test_public_synthetic_wrapper_preserves_legacy_fingerprints_and_membership(self):
        split = split_manifest()
        wrapped = canonical_manifest(public_synthetic_manifest())
        self.assertEqual(DATASET_VERSION, "1.0")
        self.assertEqual(split["corpus_fingerprint"], EXPECTED_CORPUS_FINGERPRINT_V1)
        self.assertEqual(split["held_out_fingerprint"], EXPECTED_HELD_OUT_FINGERPRINT_V1)
        self.assertEqual(len(wrapped["items"]), 100)
        self.assertEqual({item["item_id"] for item in wrapped["items"]}, {item.scenario_id for item in scenario_specs()})
        self.assertEqual(split["governed_set_identity"], manifest_identity(wrapped))
        self.assertEqual(split["governed_set_identity"]["role"], "public_synthetic_regression")
        self.assertNotEqual(split["governed_set_identity"]["role"], "sealed_held_out")

    def test_manifest_fingerprint_is_canonical_ordered_and_content_sensitive(self):
        base_items = [
            {"item_id": "opaque-b", "source_sha256": _hash("source-b"), "gold_sha256": _hash("gold-b"), "state": "active"},
            {"item_id": "opaque-a", "source_sha256": _hash("source-a"), "gold_sha256": _hash("gold-a"), "state": "active"},
        ]
        first = _manifest("private_representative", items=base_items)
        reordered = _manifest("private_representative", items=list(reversed(base_items)))
        self.assertEqual(first, reordered)
        changed_source = copy.deepcopy(base_items)
        changed_source[0]["source_sha256"] = _hash("changed-source")
        changed_gold = copy.deepcopy(base_items)
        changed_gold[0]["gold_sha256"] = _hash("changed-gold")
        self.assertNotEqual(first["manifest_fingerprint"], _manifest("private_representative", items=changed_source)["manifest_fingerprint"])
        self.assertNotEqual(first["manifest_fingerprint"], _manifest("private_representative", items=changed_gold)["manifest_fingerprint"])
        self.assertNotEqual(first["manifest_fingerprint"], _manifest("private_representative", version="v2", items=base_items)["manifest_fingerprint"])
        role_changed = _manifest("frozen_high_risk", items=base_items)
        self.assertNotEqual(first["manifest_fingerprint"], role_changed["manifest_fingerprint"])

    def test_candidate_fingerprint_binds_all_four_set_identities(self):
        identity = _complete_identity()
        changed = copy.deepcopy(identity)
        changed["sets"][3] = manifest_identity(_manifest("sealed_held_out", version="v2"))
        self.assertNotEqual(candidate_deployment_fingerprint({"corpus_identity": identity}), candidate_deployment_fingerprint({"corpus_identity": changed}))
        source_changed = copy.deepcopy(identity)
        private = _manifest("private_representative", version="v1", items=[{"item_id": "opaque-1", "source_sha256": _hash("updated-source"), "gold_sha256": _hash("private_representative-gold"), "state": "active"}])
        source_changed["sets"][1] = manifest_identity(private)
        self.assertNotEqual(candidate_deployment_fingerprint({"corpus_identity": identity}), candidate_deployment_fingerprint({"corpus_identity": source_changed}))
        self.assertTrue(is_complete_corpus_identity(identity))
        self.assertFalse(is_complete_corpus_identity({"schema_version": "1.0", "sets": identity["sets"][:1]}))
        self.assertEqual(canonical_corpus_identity({"version": "1.0", "corpus_fingerprint": "a" * 64, "held_out_fingerprint": "b" * 64})["version"], "1.0")

    def test_candidate_certification_completeness_fails_for_legacy_and_partial_identity(self):
        legacy = {"version": "1.0", "corpus_fingerprint": "a" * 64, "held_out_fingerprint": "b" * 64}
        missing = candidate_completeness({"corpus_identity": legacy}, "SYNTHETIC_PRODUCTION_CANDIDATE")
        self.assertIn("corpus_identity.governed_sets", missing)
        self.assertTrue(candidate_completeness({"corpus_identity": legacy}, "DEVELOPMENT") == [])

    def test_private_manifest_synthetic_metadata_is_valid_without_source_bytes(self):
        manifest = _manifest("private_representative")
        identity = manifest_identity(manifest)
        self.assertEqual(identity["access_class"], "approved_private_evaluation")
        self.assertEqual(set(identity), {"schema_version", "set_id", "role", "version", "state", "manifest_fingerprint", "item_count", "active_item_count", "provenance", "access_class"})
        self.assertNotIn("source", canonical_bytes(identity).decode())

    def test_frozen_high_risk_mutation_requires_new_version_and_predecessor(self):
        original = _manifest("frozen_high_risk")
        changed_items = [
            {**original["items"][0], "state": "retired"},
            {"item_id": "opaque-2", "source_sha256": _hash("changed"), "gold_sha256": _hash("changed-gold"), "state": "active"},
        ]
        same_version = _manifest("frozen_high_risk", items=changed_items)
        with self.assertRaises(CorpusGovernanceError):
            validate_transition(original, same_version)
        versioned = _manifest("frozen_high_risk", version="v2", items=changed_items, predecessor={"set_id": original["set_id"], "version": original["version"], "manifest_fingerprint": original["manifest_fingerprint"]})
        self.assertEqual(validate_transition(original, versioned), versioned)

    def test_sealed_held_out_purpose_and_contaminated_state_fail_closed(self):
        sealed = manifest_identity(_manifest("sealed_held_out"))
        with self.assertRaises(CorpusGovernanceError):
            require_set_purpose(sealed, "development")
        contaminated = _manifest("sealed_held_out", state="contaminated", items=[{"item_id": "opaque-1", "source_sha256": _hash("sealed_held_out-source"), "gold_sha256": _hash("sealed_held_out-gold"), "state": "contaminated"}])
        with self.assertRaises(CorpusGovernanceError):
            require_set_purpose(manifest_identity(contaminated), "promotion")

    def test_contamination_report_invalidates_identity_and_records_a_transition(self):
        original = _manifest("sealed_held_out")
        report = {"schema_version": "1.0", "set_id": original["set_id"], "version": original["version"], "items": [{"item_id": "opaque-1", "source_sha256": original["items"][0]["source_sha256"], "gold_sha256": original["items"][0]["gold_sha256"], "context": "prompt_selection"}]}
        self.assertEqual(validate_contamination_report(report, set_identity=manifest_identity(original)), ["opaque-1"])
        with self.assertRaises(CorpusGovernanceError):
            require_set_purpose(manifest_identity(original), "promotion", contamination_report=report)
        contaminated = apply_contamination_report(original, report, new_version="v2")
        self.assertEqual(contaminated["state"], "contaminated")
        self.assertEqual(contaminated["items"][0]["state"], "contaminated")
        self.assertEqual(contaminated["predecessor"]["manifest_fingerprint"], original["manifest_fingerprint"])

    def test_retirement_preserves_history_and_changes_identity(self):
        original = _manifest("sealed_held_out", items=[
            {"item_id": "opaque-a", "source_sha256": _hash("a-source"), "gold_sha256": _hash("a-gold"), "state": "active"},
            {"item_id": "opaque-b", "source_sha256": _hash("b-source"), "gold_sha256": _hash("b-gold"), "state": "active"},
        ])
        items = [dict(item) for item in original["items"]]
        items[0]["state"] = "retired"
        retired = _manifest("sealed_held_out", version="v2", items=items, predecessor={"set_id": original["set_id"], "version": original["version"], "manifest_fingerprint": original["manifest_fingerprint"]})
        validated = validate_transition(original, retired)
        self.assertEqual(validated["items"][0]["source_sha256"], original["items"][0]["source_sha256"])
        self.assertNotEqual(manifest_identity(original), manifest_identity(retired))
        with self.assertRaises(CorpusGovernanceError):
            require_set_purpose(manifest_identity(_manifest("sealed_held_out", state="retired", items=[{**item, "state": "retired"} for item in original["items"]])), "promotion")

    def test_replacement_links_retired_item_and_rejects_same_bytes_resurrection(self):
        original = _manifest("sealed_held_out")
        contaminated = _manifest("sealed_held_out", version="v2", state="contaminated", items=[{**original["items"][0], "state": "contaminated"}], predecessor={"set_id": original["set_id"], "version": original["version"], "manifest_fingerprint": original["manifest_fingerprint"]})
        validate_transition(original, contaminated)
        replacement_item = {"item_id": "opaque-replacement", "source_sha256": _hash("replacement-source"), "gold_sha256": _hash("replacement-gold"), "state": "active", "replacement_of": {"set_id": contaminated["set_id"], "version": contaminated["version"], "item_id": "opaque-1"}}
        replacement = _manifest("sealed_held_out", version="v3", items=[*contaminated["items"], replacement_item], predecessor={"set_id": contaminated["set_id"], "version": contaminated["version"], "manifest_fingerprint": contaminated["manifest_fingerprint"]})
        self.assertEqual(validate_transition(contaminated, replacement), replacement)
        reused = {**replacement_item, "item_id": "opaque-resurrection", "source_sha256": original["items"][0]["source_sha256"], "gold_sha256": original["items"][0]["gold_sha256"]}
        with self.assertRaises(CorpusGovernanceError):
            _manifest("sealed_held_out", version="v3", items=[*contaminated["items"], reused], predecessor={"set_id": contaminated["set_id"], "version": contaminated["version"], "manifest_fingerprint": contaminated["manifest_fingerprint"]})

    def test_renamed_duplicate_is_detected_by_content_hash_overlap(self):
        first = _manifest("private_representative", set_id="private-one")
        second = _manifest("frozen_high_risk", set_id="high-risk", items=[{"item_id": "renamed", "source_sha256": first["items"][0]["source_sha256"], "gold_sha256": first["items"][0]["gold_sha256"], "state": "active"}])
        overlaps = cross_set_overlaps([first, second])
        self.assertTrue(any(item["identity_kind"] == "source_sha256" for item in overlaps))
        self.assertTrue(any(item["identity_kind"] == "gold_sha256" for item in overlaps))
        self.assertEqual(item_fingerprint(first["items"][0]["source_sha256"], first["items"][0]["gold_sha256"]), item_fingerprint(second["items"][0]["source_sha256"], second["items"][0]["gold_sha256"]))

    def test_public_split_held_out_cannot_be_sealed_evidence(self):
        public = split_manifest()["governed_set_identity"]
        self.assertEqual(public["role"], "public_synthetic_regression")
        with self.assertRaises(CorpusGovernanceError):
            require_set_purpose(public, "promotion")

    def test_candidate_evidence_identity_mismatch_and_stale_version_fail(self):
        candidate_identity = _complete_identity(sealed=_manifest("sealed_held_out", version="v2"))
        candidate = {"corpus_identity": candidate_identity}
        old_heldout = manifest_identity(_manifest("sealed_held_out", version="v1"))
        payload = {"corpus_set_identity": old_heldout, "evaluation_purpose": "promotion"}
        with self.assertRaises(EvidenceValidationError):
            validate_model_evidence_corpus_binding("model_held_out", payload, candidate)
        correct = manifest_identity(_manifest("sealed_held_out", version="v2"))
        validate_model_evidence_corpus_binding("model_held_out", {"corpus_set_identity": correct, "evaluation_purpose": "promotion"}, candidate)
        high_risk_identity = _manifest("frozen_high_risk", version="v2")
        newer_candidate = {"corpus_identity": _complete_identity(high_risk=high_risk_identity)}
        stale_high_risk = manifest_identity(_manifest("frozen_high_risk", version="v1"))
        with self.assertRaises(EvidenceValidationError):
            validate_model_evidence_corpus_binding("model_high_risk_stability", {"corpus_set_identity": stale_high_risk, "evaluation_purpose": "comparison"}, newer_candidate)

    def test_high_risk_and_held_out_evidence_require_role_purpose_pairs(self):
        public = manifest_identity(public_synthetic_manifest())
        with self.assertRaises(EvidenceValidationError):
            validate_model_evidence_corpus_binding("model_held_out", {"corpus_set_identity": public, "evaluation_purpose": "promotion"}, _complete_identity())
        with self.assertRaises(EvidenceValidationError):
            validate_model_evidence_corpus_binding("model_high_risk_stability", {"corpus_set_identity": manifest_identity(_manifest("frozen_high_risk")), "evaluation_purpose": "development"}, _complete_identity())

    def test_unknown_fields_bad_hashes_duplicate_ids_roles_and_boolean_counts_fail(self):
        original = _manifest("private_representative")
        bad_fingerprint = {**original, "manifest_fingerprint": "A" * 64}
        with self.assertRaises(CorpusGovernanceError):
            canonical_manifest(bad_fingerprint)
        with self.assertRaises(CorpusGovernanceError):
            _manifest("private_representative", items=[original["items"][0], original["items"][0]])
        with self.assertRaises(CorpusGovernanceError):
            _manifest("unknown_role")
        with self.assertRaises(CorpusGovernanceError):
            build_manifest(set_id="bad-state", role="sealed_held_out", version="v1", state="active-ish", items=original["items"], provenance=original["provenance"])
        with self.assertRaises(CorpusGovernanceError):
            _manifest("private_representative", items=[{"item_id": "invalid-hash", "source_sha256": "bad", "gold_sha256": _hash("gold"), "state": "active"}])
        identity = manifest_identity(original)
        with self.assertRaises(CorpusGovernanceError):
            canonical_governed_identity({"schema_version": "1.0", "sets": [identity, identity]})
        with self.assertRaises(CorpusGovernanceError):
            require_set_purpose(identity, "tuning")
        with self.assertRaises(CorpusGovernanceError):
            from k_slide.corpus_governance import canonical_set_identity
            canonical_set_identity({**identity, "item_count": True})

    def test_private_manifest_loader_requires_canonical_serialization_and_rejects_symlinks(self):
        manifest = _manifest("private_representative")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            path = root / "manifest.json"
            path.write_bytes(canonical_bytes(manifest) + b"\n")
            self.assertEqual(load_manifest(path), manifest)
            moved = root / "moved" / "manifest.json"
            moved.parent.mkdir()
            moved.write_bytes(canonical_bytes(manifest) + b"\n")
            self.assertEqual(manifest_identity(load_manifest(moved)), manifest_identity(load_manifest(path)))
            with self.assertRaises(CorpusGovernanceError):
                load_manifest(root / ".." / root.name / path.name)
            noncanonical = root / "noncanonical.json"
            noncanonical.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
            with self.assertRaises(CorpusGovernanceError):
                load_manifest(noncanonical)
            link = root / "linked.json"
            link.symlink_to(path)
            with self.assertRaises(CorpusGovernanceError):
                load_manifest(link)

    def test_canonical_identity_excludes_paths_and_rejects_them_as_unknown_metadata(self):
        identity = _complete_identity()
        fingerprint = candidate_deployment_fingerprint({"corpus_identity": identity})
        relocated_identity = copy.deepcopy(identity)
        self.assertEqual(candidate_deployment_fingerprint({"corpus_identity": relocated_identity}), fingerprint)
        with self.assertRaises(EvidenceValidationError):
            canonical_corpus_identity({**identity, "local_path": "/private/corpus"})

    def test_governed_bundle_revalidates_transition_history_and_active_overlap(self):
        previous = _manifest("frozen_high_risk")
        replacement_items = [
            {**previous["items"][0], "state": "retired"},
            {"item_id": "new-risk-item", "source_sha256": _hash("new-source"), "gold_sha256": _hash("new-gold"), "state": "active"},
        ]
        successor = _manifest("frozen_high_risk", version="v2", items=replacement_items, predecessor={"set_id": previous["set_id"], "version": previous["version"], "manifest_fingerprint": previous["manifest_fingerprint"]})
        rest = [_manifest("private_representative"), _manifest("sealed_held_out"), public_synthetic_manifest()]
        with self.assertRaises(CorpusGovernanceError):
            validate_corpus_bundle([*rest, successor])
        bundle = validate_corpus_bundle([*rest, successor], history=[previous])
        self.assertEqual({item["role"] for item in bundle}, set(CORPUS_ROLES))
        active = next(item for item in successor["items"] if item["state"] == "active")
        overlap = _manifest("sealed_held_out", set_id="overlap", items=[{"item_id": "renamed", "source_sha256": active["source_sha256"], "gold_sha256": _hash("elsewhere"), "state": "active"}])
        with self.assertRaises(CorpusGovernanceError):
            validate_corpus_bundle([rest[0], rest[2], successor, overlap], history=[previous])

    def test_retired_public_membership_remains_permanent_sealed_exposure(self):
        source = _hash("public-source-ever-visible")
        public = _manifest("public_synthetic_regression", state="retired", items=[{
            "item_id": "old-public-id", "source_sha256": source, "gold_sha256": _hash("public-gold"), "state": "retired",
        }])
        sealed = _manifest("sealed_held_out", set_id="renamed-sealed-set", items=[{
            "item_id": "renamed-private-id", "source_sha256": source, "gold_sha256": _hash("new-gold"), "state": "active",
        }])
        bundle = [public, _manifest("private_representative"), _manifest("frozen_high_risk"), sealed]
        self.assertTrue(any(item["identity_kind"] == "source_sha256" for item in cross_set_overlaps(bundle)))
        with self.assertRaises(CorpusGovernanceError):
            validate_corpus_bundle(bundle)

    def test_private_history_exposure_survives_rename_set_and_version_changes(self):
        old_source = _hash("retired-private-source")
        old_gold = _hash("retired-private-gold")
        previous = _manifest("private_representative", set_id="prior-private-set", version="v8", state="retired", items=[{
            "item_id": "old-private-id", "source_sha256": old_source, "gold_sha256": old_gold, "state": "retired",
        }])
        history = [{
            "manifest": previous,
            "exposure_contexts": [{"item_id": "old-private-id", "context": "prompt_selection"}],
        }]
        current_public = public_synthetic_manifest()
        current_private = _manifest("private_representative", set_id="current-private-set")
        current_high = _manifest("frozen_high_risk")
        for label, source, gold, expected_kind in (
            ("source-only", old_source, _hash("different-gold"), "source_sha256"),
            ("gold-only", _hash("different-source"), old_gold, "gold_sha256"),
            ("pair", old_source, old_gold, "item_fingerprint"),
        ):
            with self.subTest(label=label):
                sealed = _manifest("sealed_held_out", set_id="new-sealed-set", version="new-version", items=[{
                    "item_id": "renamed-item", "source_sha256": source, "gold_sha256": gold, "state": "active",
                }])
                overlaps = cross_set_overlaps([current_public, current_private, current_high, sealed], history=history)
                self.assertTrue(any(item["identity_kind"] == expected_kind for item in overlaps))
                with self.assertRaises(CorpusGovernanceError):
                    validate_corpus_bundle([current_public, current_private, current_high, sealed], history=history)

    def test_unrelated_retired_private_history_does_not_invalidate_sealed_membership(self):
        previous = _manifest("private_representative", set_id="old-private", state="retired", items=[{
            "item_id": "old-item", "source_sha256": _hash("old-unrelated-source"), "gold_sha256": _hash("old-unrelated-gold"), "state": "retired",
        }])
        history = [{"manifest": previous, "exposure_contexts": [{"item_id": "old-item", "context": "training"}]}]
        bundle = [
            public_synthetic_manifest(),
            _manifest("private_representative"),
            _manifest("frozen_high_risk"),
            _manifest("sealed_held_out"),
        ]
        self.assertEqual({item["role"] for item in validate_corpus_bundle(bundle, history=history)}, set(CORPUS_ROLES))

    def test_contaminated_held_out_history_accepts_only_distinct_linked_replacement(self):
        original = _manifest("sealed_held_out", set_id="sealed-lineage")
        report = {
            "schema_version": "1.0",
            "set_id": original["set_id"],
            "version": original["version"],
            "items": [{"item_id": "opaque-1", "source_sha256": original["items"][0]["source_sha256"], "gold_sha256": original["items"][0]["gold_sha256"], "context": "prompt_selection"}],
        }
        contaminated = apply_contamination_report(original, report, new_version="v2")
        replacement = {"item_id": "linked-replacement", "source_sha256": _hash("replacement-source-distinct"), "gold_sha256": _hash("replacement-gold-distinct"), "state": "active", "replacement_of": {"set_id": contaminated["set_id"], "version": contaminated["version"], "item_id": "opaque-1"}}
        current = _manifest("sealed_held_out", set_id=original["set_id"], version="v3", items=[*contaminated["items"], replacement], predecessor={"set_id": contaminated["set_id"], "version": contaminated["version"], "manifest_fingerprint": contaminated["manifest_fingerprint"]})
        bundle = [public_synthetic_manifest(), _manifest("private_representative"), _manifest("frozen_high_risk"), current]
        validated = validate_corpus_bundle(bundle, history=[original, contaminated])
        self.assertEqual(next(item for item in validated if item["role"] == "sealed_held_out"), current)

    def test_history_ambiguous_versions_remain_rejected(self):
        original = _manifest("frozen_high_risk", set_id="same-history-set", version="v1")
        ambiguous = _manifest("frozen_high_risk", set_id="same-history-set", version="v1", items=[{
            "item_id": "different-item", "source_sha256": _hash("different-history-source"), "gold_sha256": _hash("different-history-gold"), "state": "active",
        }])
        successor = _manifest("frozen_high_risk", set_id="same-history-set", version="v2", items=[
            {**original["items"][0], "state": "retired"},
            {"item_id": "new-item", "source_sha256": _hash("new-history-source"), "gold_sha256": _hash("new-history-gold"), "state": "active"},
        ], predecessor={"set_id": original["set_id"], "version": original["version"], "manifest_fingerprint": original["manifest_fingerprint"]})
        bundle = [public_synthetic_manifest(), _manifest("private_representative"), _manifest("sealed_held_out"), successor]
        with self.assertRaises(CorpusGovernanceError):
            validate_corpus_bundle(bundle, history=[original, ambiguous])

    def test_history_transition_cycle_is_rejected(self):
        from unittest.mock import patch
        import k_slide.corpus_governance as governance

        first = {
            "set_id": "cycle-set", "version": "v1", "role": "private_representative",
            "manifest_fingerprint": "a" * 64,
            "predecessor": {"set_id": "cycle-set", "version": "v2", "manifest_fingerprint": "b" * 64},
            "items": [],
        }
        second = {
            "set_id": "cycle-set", "version": "v2", "role": "private_representative",
            "manifest_fingerprint": "b" * 64,
            "predecessor": {"set_id": "cycle-set", "version": "v1", "manifest_fingerprint": "a" * 64},
            "items": [],
        }
        with patch.object(governance, "canonical_manifest", side_effect=lambda value: value), patch.object(governance, "validate_transition", return_value=None):
            with self.assertRaisesRegex(CorpusGovernanceError, "transition cycle"):
                validate_corpus_bundle([second], history=[first], require_complete=False)


if __name__ == "__main__":
    unittest.main()
