from __future__ import annotations

import copy
import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from evals.release import _candidate_spec_for_release, _champion, _load_prior_recertification_inputs, build_release_manifest
from k_slide.certification import (
    EvidenceValidationError,
    canonical_bytes,
    canonical_candidate_factors,
    candidate_deployment_fingerprint,
    canonical_dependency_inventory,
    certification_fingerprint,
    dependency_inventory_hash,
    load_evidence,
    write_evidence,
)
from k_slide.evidence_adapters import build_machine_evidence
from k_slide.model_policy import load_model_policy
from k_slide.recertification import (
    MODEL_PROMOTION_EVIDENCE,
    build_champion_promotion,
    build_recertification_record,
    candidate_change_impact,
    champion_document_from_promotion,
    dependency_projection_identity,
    recertification_exemption_identities,
    validate_champion_promotion,
    validate_recertification_record,
)
from k_slide.production import ReleaseState
from tests.test_certification_closure import (
    _candidate_model_sources,
    _candidate_spec,
    _heavy_sources,
    _runtime_sources,
    _sha,
    _write,
)


def _content_identity(value: dict, field: str) -> str:
    return hashlib.sha256(canonical_bytes({key: item for key, item in value.items() if key != field})).hexdigest()


def _change(candidate: dict, field: str, value):
    updated = copy.deepcopy(candidate)
    updated[field] = value
    behavior_aliases = {
        "requested_model": "model",
        "provider": "provider",
        "prompt_version": "prompt_version",
        "generation_settings": "generation_settings",
        "vision_settings": "vision_settings",
        "context_configuration": "context_configuration",
        "image_preprocessing_settings": "image_preprocessing_settings",
        "normalization_behavior": "normalization_behavior",
        "repair_policy": "repair_policy",
        "ocr_provider": "ocr_provider",
        "termbase_hash": "termbase_hash",
    }
    if field in behavior_aliases:
        updated.setdefault("behavior_configuration", {})[behavior_aliases[field]] = value
    return updated


class KSA31PromotionRecertificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temporary.name)
        (cls.root / "evals").mkdir()
        cls.subject = "a" * 40
        cls.candidate = _candidate_spec(
            cls.subject,
            ocr_provider="paddle",
            asset_manifest="manifest.json",
            asset_hash="b" * 64,
        )
        cls.candidate["inference_route_identity"] = "test-inference-route"
        cls.candidate["inference_endpoint_identity"] = "c" * 64
        cls.candidate["resolved_dependency_set_sha256"] = "d" * 64
        cls.deployment = candidate_deployment_fingerprint(cls.candidate)
        cls.policy = load_model_policy()
        cls.records = {}
        for evidence_type, split, repeats in (
            ("model_validation", "validation", 3),
            ("model_high_risk_stability", "validation", 5),
            ("model_held_out", "held_out", 3),
        ):
            folder = cls.root / evidence_type
            folder.mkdir()
            sources = _candidate_model_sources(
                folder,
                split=split,
                repeats=repeats,
                subject=cls.subject,
                deployment=cls.deployment,
                candidate=cls.candidate,
            )
            path = folder / "evidence.json"
            build_machine_evidence(
                path,
                evidence_type=evidence_type,
                subject_git_sha=cls.subject,
                deployment_fingerprint=cls.deployment,
                sources=sources,
                candidate_spec=cls.candidate,
            )
            cls.records[evidence_type] = load_evidence(
                path,
                expected_type=evidence_type,
                subject_git_sha=cls.subject,
                deployment_fingerprint=cls.deployment,
                candidate_spec=cls.candidate,
                require_candidate_spec=True,
            )
        cls.promotion = build_champion_promotion(
            cls.candidate,
            cls.records,
            policy=cls.policy,
            state="FROZEN_PROMOTED",
        )

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_closed_champion_state_and_legacy_minimal_frozen_record_fail(self):
        champion_path = self.root / "evals" / "champion.json"
        champion_path.parent.mkdir(exist_ok=True)
        for value, expected in (
            ({"schema_version": "1.0", "status": "FROZEN", "model": "google/gemma-4-31b-it"}, "closed promotion state"),
            ({"schema_version": "1.0", "status": "PENDING", "model": "google/gemma-4-31b-it"}, "closed promotion state"),
        ):
            _write(champion_path, value)
            _value, _hash, blockers = _champion(
                self.root,
                records=self.records,
                policy=self.policy,
                deployment_fp=self.deployment,
                candidate_spec=self.candidate,
            )
            self.assertTrue(any(expected in item for item in blockers), blockers)

    def test_valid_promotion_binds_candidate_and_all_three_authoritative_evidence_identities(self):
        self.assertEqual(self.promotion["contract_version"], "1.0")
        self.assertEqual(self.promotion["candidate_subject_git_sha"], self.subject)
        self.assertEqual(self.promotion["candidate_deployment_fingerprint"], self.deployment)
        self.assertEqual(set(self.promotion["evidence"]), {"model_validation", "model_high_risk_stability", "model_held_out"})
        for evidence_type, record in self.records.items():
            self.assertEqual(self.promotion["evidence"][evidence_type]["evidence_identity"], record["evidence_identity"])
            self.assertEqual(self.promotion["evidence"][evidence_type]["envelope_sha256"], record["envelope_sha256"])
            self.assertEqual(self.promotion["evidence"][evidence_type]["deployment_fingerprint"], self.deployment)
        champion_path = self.root / "evals" / "champion.json"
        _write(champion_path, champion_document_from_promotion(self.promotion))
        champion_value, _hash, blockers = _champion(
            self.root,
            records=self.records,
            policy=self.policy,
            deployment_fp=self.deployment,
            candidate_spec=self.candidate,
        )
        self.assertIsNotNone(champion_value)
        self.assertEqual(blockers, [])
        validated = validate_champion_promotion(self.promotion, self.candidate, self.records, policy=self.policy)
        self.assertEqual(validated["promotion_identity"], self.promotion["promotion_identity"])

    def test_promotion_rejects_wrong_candidate_dimensions_and_evidence_identity(self):
        mutations = (
            ("subject_git_sha", "d" * 40),
            ("requested_model", "other/gemma"),
            ("effective_model", "other/gemma"),
            ("provider", "alternate-provider"),
            ("provider_backend", "alternate-backend"),
            ("model_revision", "revision-2"),
            ("quantization_or_dtype", "int8"),
            ("inference_route_identity", "alternate-route"),
            ("inference_endpoint_identity", "e" * 64),
            ("prompt_version", "translation/v2"),
            ("generation_settings", {"temperature": 0.2}),
            ("vision_settings", {"enabled": False}),
            ("context_configuration", {"bounded_work_unit": False}),
            ("image_preprocessing_settings", {"dpi": 221}),
            ("normalization_behavior", {"render_dpi": 221}),
            ("repair_policy", {"max_auto_repairs_per_unit": 3}),
            ("kslide_version", "9.9.9"),
            ("opencode_version", "9.9.9"),
            ("python_version", "3.12.0"),
            ("ocr_provider", "none"),
            ("ocr_asset_manifest_sha256", "f" * 64),
            ("termbase_hash", "f" * 64),
            ("resolved_dependency_set_sha256", "f" * 64),
        )
        for field, changed in mutations:
            with self.subTest(field=field):
                candidate = copy.deepcopy(self.candidate)
                candidate[field] = changed
                with self.assertRaises(EvidenceValidationError):
                    validate_champion_promotion(self.promotion, candidate, self.records, policy=self.policy)
        changed_corpus = copy.deepcopy(self.candidate)
        changed_corpus["corpus_identity"] = {"version": "changed", "corpus_fingerprint": "1" * 64}
        with self.assertRaises(EvidenceValidationError):
            validate_champion_promotion(self.promotion, changed_corpus, self.records, policy=self.policy)
        forged_records = copy.deepcopy(self.records)
        forged_records["model_held_out"]["evidence_identity"] = "0" * 64
        with self.assertRaises(EvidenceValidationError):
            build_champion_promotion(self.candidate, forged_records, policy=self.policy)

    def test_edited_promotion_record_and_editable_summary_fail_closed(self):
        forged = copy.deepcopy(self.promotion)
        forged["candidate_factors_sha256"] = "0" * 64
        with self.assertRaises(EvidenceValidationError):
            validate_champion_promotion(forged, self.candidate, self.records, policy=self.policy)
        forged = copy.deepcopy(self.promotion)
        forged["candidate_factors_sha256"] = "0" * 64
        forged["promotion_identity"] = _content_identity(forged, "promotion_identity")
        with self.assertRaises(EvidenceValidationError):
            validate_champion_promotion(forged, self.candidate, self.records, policy=self.policy)
        forged = copy.deepcopy(self.promotion)
        forged["candidate_deployment_fingerprint"] = "0" * 64
        forged["promotion_identity"] = _content_identity(forged, "promotion_identity")
        with self.assertRaises(EvidenceValidationError):
            validate_champion_promotion(forged, self.candidate, self.records, policy=self.policy)
        forged = copy.deepcopy(self.promotion)
        forged["evidence"]["model_held_out"]["envelope_sha256"] = "0" * 64
        forged["promotion_identity"] = _content_identity(forged, "promotion_identity")
        with self.assertRaises(EvidenceValidationError):
            validate_champion_promotion(forged, self.candidate, self.records, policy=self.policy)
        summary = champion_document_from_promotion(self.promotion)
        summary["behavior_configuration_hash"] = "0" * 64
        path = self.root / "evals" / "champion.json"
        _write(path, summary)
        champion_value, _hash, blockers = _champion(
            self.root,
            records=self.records,
            policy=self.policy,
            deployment_fp=self.deployment,
            candidate_spec=self.candidate,
        )
        self.assertTrue(any("summary behavior_configuration_hash" in item for item in blockers), blockers)

    def test_material_change_policy_scopes_affected_evidence_and_invalidates_champion(self):
        model_change = _change(self.candidate, "provider", "alternate-provider")
        impact = candidate_change_impact(self.candidate, model_change)
        self.assertTrue(impact["champion_affected"])
        self.assertEqual(set(impact["affected_evidence"]), {"runtime", "model_validation", "model_high_risk_stability", "model_held_out", "internal_bilingual", "zero_korean_comprehension", "reliability", "model_data_policy", "governance", "pilot_canary"})
        ocr_change = copy.deepcopy(self.candidate)
        ocr_change["ocr_asset_manifest_sha256"] = "9" * 64
        ocr_impact = candidate_change_impact(self.candidate, ocr_change)
        self.assertIn("heavy_runtime", ocr_impact["affected_evidence"])
        self.assertIn("model_held_out", ocr_impact["affected_evidence"])
        self.assertNotIn("security", ocr_impact["affected_evidence"])
        termbase_change = _change(self.candidate, "termbase_hash", "8" * 64)
        termbase_impact = candidate_change_impact(self.candidate, termbase_change)
        self.assertIn("model_validation", termbase_impact["affected_evidence"])
        self.assertIn("internal_bilingual", termbase_impact["affected_evidence"])
        dependency_change = copy.deepcopy(self.candidate)
        dependency_change["resolved_dependency_set_sha256"] = "7" * 64
        dependency_impact = candidate_change_impact(self.candidate, dependency_change)
        self.assertIn("security", dependency_impact["affected_evidence"])
        self.assertIn("heavy_runtime", dependency_impact["affected_evidence"])
        corpus_change = copy.deepcopy(self.candidate)
        corpus_change["corpus_identity"] = {"version": "changed", "corpus_fingerprint": "6" * 64}
        corpus_impact = candidate_change_impact(self.candidate, corpus_change)
        self.assertIn("model_validation", corpus_impact["affected_evidence"])
        self.assertNotIn("security", corpus_impact["affected_evidence"])
        runtime_change = copy.deepcopy(self.candidate)
        runtime_change["runtime_artifact_identity"] = {"sha256": "5" * 64}
        runtime_impact = candidate_change_impact(self.candidate, runtime_change)
        self.assertIn("model_validation", runtime_impact["affected_evidence"])
        self.assertIn("security", runtime_impact["affected_evidence"])
        unknown = copy.deepcopy(self.candidate)
        unknown["future_runtime_dimension"] = "unsafe"
        with self.assertRaises(EvidenceValidationError):
            candidate_change_impact(self.candidate, unknown)

    def test_subject_transition_stales_champion_but_only_policy_attestation_can_cross(self):
        old_records: dict[str, dict] = {}
        policy_path = self.root / "subject-policy.json"
        write_evidence(
            policy_path,
            evidence_type="model_data_policy",
            subject_git_sha=self.subject,
            deployment_fingerprint=self.deployment,
            payload={"attestation_id": "subject-independent-policy", "approved_for_internal_artifacts": True},
            generated_at="2026-09-24T00:00:00Z",
            candidate_spec=self.candidate,
        )
        old_records["model_data_policy"] = load_evidence(
            policy_path,
            expected_type="model_data_policy",
            subject_git_sha=self.subject,
            deployment_fingerprint=self.deployment,
            candidate_spec=self.candidate,
            require_candidate_spec=True,
        )
        changed = copy.deepcopy(self.candidate)
        changed["subject_git_sha"] = "e" * 40
        impact = candidate_change_impact(self.candidate, changed)
        self.assertTrue(impact["champion_affected"])
        self.assertNotEqual(impact["old_deployment_fingerprint"], impact["new_deployment_fingerprint"])
        champion_path = self.root / "evals" / "champion.json"
        _write(champion_path, champion_document_from_promotion(self.promotion))
        _value, _hash, champion_blockers = _champion(
            self.root,
            records=self.records,
            policy=self.policy,
            deployment_fp=candidate_deployment_fingerprint(changed),
            candidate_spec=changed,
        )
        self.assertTrue(champion_blockers)
        for evidence_type in (
            "runtime",
            "heavy_runtime",
            "security",
            *MODEL_PROMOTION_EVIDENCE,
            "internal_bilingual",
            "zero_korean_comprehension",
            "reliability",
            "pilot_canary",
            "governance",
        ):
            self.assertIn(evidence_type, impact["affected_evidence"])
        self.assertNotIn("model_data_policy", impact["affected_evidence"])
        recertification = build_recertification_record(
            self.candidate,
            changed,
            old_records,
            ["model_data_policy"],
            prior_release_manifest_sha256="9" * 64,
        )
        exemption = recertification["exemptions"][0]
        self.assertEqual(exemption["old_dependency_projection_identity"], exemption["new_dependency_projection_identity"])
        self.assertEqual(exemption["evidence_identity"], old_records["model_data_policy"]["evidence_identity"])
        with self.assertRaises(EvidenceValidationError):
            build_recertification_record(
                self.candidate,
                changed,
                {"model_validation": self.records["model_validation"]},
                ["model_validation"],
                prior_release_manifest_sha256="9" * 64,
            )

    def test_end_to_end_internal_release_bridges_immutable_model_evidence(self):
        from k_slide.bilingual_adjudication import build_internal_bilingual_payload
        from tests.bilingual_review_fixtures import make_review_contract
        from tests.zero_korean_study_fixtures import zero_korean_payload

        subject = "a" * 40
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / ".k-slide-config"
            config.mkdir()
            shutil.copytree(Path.cwd() / "prompts", root / "prompts")
            shutil.copytree(Path.cwd() / "termbase", root / "termbase")
            shutil.copytree(Path.cwd() / ".opencode" / "agents", root / ".opencode" / "agents")
            shutil.copyfile(Path.cwd() / "constraints-production.txt", root / "constraints-production.txt")
            asset_folder = root / "ocr"
            asset_folder.mkdir()
            (asset_folder / "PaddleOCR.yaml").write_text("pipeline: test\n", encoding="utf-8")
            (asset_folder / "alternate.yaml").write_text("pipeline: alternate\n", encoding="utf-8")
            (asset_folder / "weights.bin").write_bytes(b"test-paddle-weights")
            asset_manifest = asset_folder / "manifest.json"
            _write(asset_manifest, {
                "provider": "paddle",
                "paddlex_config": "PaddleOCR.yaml",
                "files": [
                    {"path": name, "sha256": _sha(asset_folder / name)}
                    for name in ("PaddleOCR.yaml", "alternate.yaml", "weights.bin")
                ],
            })
            inventory = canonical_dependency_inventory(
                [{"name": name, "version": "1.0"} for name in ("Pillow", "PyMuPDF", "python-pptx", "paddlepaddle", "paddleocr")]
            )
            _write(config / "production-dependency-inventory.json", inventory)
            candidate = _candidate_spec(
                subject,
                ocr_provider="paddle",
                asset_manifest="ocr/manifest.json",
                asset_hash=_sha(asset_manifest),
                root=root,
            )
            candidate["constraints_sha256"] = _sha(root / "constraints-production.txt")
            candidate["resolved_dependency_set_sha256"] = dependency_inventory_hash(inventory)
            old_candidate_path = _write(config / "old-candidate.json", candidate)
            policy = load_model_policy(root)
            split = __import__("evals.scenarios", fromlist=["split_manifest"]).split_manifest()
            candidate, _ = _candidate_spec_for_release(
                root,
                candidate_profile=old_candidate_path,
                subject_sha=subject,
                model=None,
                policy=policy,
                corpus=split,
                require_identity=True,
            )
            self.assertEqual(candidate["resolved_dependency_set_sha256"], dependency_inventory_hash(inventory))
            old_deployment = candidate_deployment_fingerprint(candidate)
            old_paths: dict[str, Path] = {}
            old_records: dict[str, dict] = {}

            runtime_folder = root / "runtime"
            runtime_folder.mkdir()
            runtime_path = runtime_folder / "evidence.json"
            build_machine_evidence(
                runtime_path,
                evidence_type="runtime",
                subject_git_sha=subject,
                deployment_fingerprint=old_deployment,
                sources=_runtime_sources(runtime_folder, provider="google", ocr_provider="paddle"),
                root=root,
                candidate_spec=candidate,
            )
            old_paths["runtime"] = runtime_path

            heavy_folder = root / "heavy_runtime"
            heavy_folder.mkdir()
            heavy_path = heavy_folder / "evidence.json"
            build_machine_evidence(
                heavy_path,
                evidence_type="heavy_runtime",
                subject_git_sha=subject,
                deployment_fingerprint=old_deployment,
                sources=_heavy_sources(
                    heavy_folder,
                    full=True,
                    subject=subject,
                    deployment=old_deployment,
                    ocr_manifest=asset_manifest,
                    ocr_context={
                        "status": "PASS",
                        "runtime_verified": True,
                        "after_engine": True,
                        "manifest_sha256": _sha(asset_manifest),
                        "files": [
                            {"path": name, "sha256": _sha(asset_folder / name)}
                            for name in ("PaddleOCR.yaml", "alternate.yaml", "weights.bin")
                        ],
                        "paddlex_config": "PaddleOCR.yaml",
                        "paddlex_config_sha256": _sha(asset_folder / "PaddleOCR.yaml"),
                        "offline_assets_required": True,
                    },
                ),
                root=root,
                candidate_spec=candidate,
            )
            old_paths["heavy_runtime"] = heavy_path

            bilingual_manifest = None
            for evidence_type, model_split, repeats in (
                ("model_validation", "validation", 3),
                ("model_high_risk_stability", "validation", 5),
                ("model_held_out", "held_out", 3),
            ):
                folder = root / evidence_type
                folder.mkdir()
                sources = _candidate_model_sources(
                    folder,
                    split=model_split,
                    repeats=repeats,
                    subject=subject,
                    deployment=old_deployment,
                    candidate=candidate,
                )
                if evidence_type == "model_validation":
                    bilingual_manifest = json.loads(sources["experiment_manifest"].read_text(encoding="utf-8"))["corpus_manifest"]
                path = folder / "evidence.json"
                build_machine_evidence(
                    path,
                    evidence_type=evidence_type,
                    subject_git_sha=subject,
                    deployment_fingerprint=old_deployment,
                    sources=sources,
                    root=root,
                    candidate_spec=candidate,
                )
                old_paths[evidence_type] = path

            if bilingual_manifest is None:
                self.fail("model validation fixture did not provide the governed review corpus")
            bilingual_payload = build_internal_bilingual_payload(
                make_review_contract(subject=subject, deployment=old_deployment, manifest=bilingual_manifest)
            )
            zero_payload = zero_korean_payload(candidate, bilingual_payload)
            payloads = {
                "internal_bilingual": bilingual_payload,
                "zero_korean_comprehension": zero_payload,
                "model_data_policy": {"attestation_id": "old-policy", "approved_for_internal_artifacts": True},
            }
            for evidence_type, payload in payloads.items():
                folder = root / evidence_type
                folder.mkdir()
                path = folder / "evidence.json"
                write_evidence(
                    path,
                    evidence_type=evidence_type,
                    subject_git_sha=subject,
                    deployment_fingerprint=old_deployment,
                    payload=payload,
                    generated_at="2026-09-24T00:00:00Z",
                    candidate_spec=candidate,
                )
                old_paths[evidence_type] = path

            for evidence_type, path in old_paths.items():
                old_records[evidence_type] = load_evidence(
                    path,
                    expected_type=evidence_type,
                    subject_git_sha=subject,
                    deployment_fingerprint=old_deployment,
                    repository_root=root,
                    candidate_spec=candidate,
                    require_candidate_spec=True,
                )

            (root / "evals").mkdir()
            old_promotion = build_champion_promotion(
                candidate,
                {key: value for key, value in old_records.items() if key in MODEL_PROMOTION_EVIDENCE},
                policy=policy,
                root=root,
                state="FROZEN_PROMOTED",
            )
            _write(root / "evals" / "champion.json", champion_document_from_promotion(old_promotion))
            prior_release = build_release_manifest(
                root,
                requested_state=ReleaseState.INTERNAL_VALIDATED.value,
                subject_sha=subject,
                candidate_profile=old_candidate_path,
                evidence_paths=old_paths,
            )
            self.assertEqual(prior_release["release_state"], ReleaseState.INTERNAL_VALIDATED.value, prior_release.get("blocking_reasons"))
            prior_manifest_path = root / "release" / "prior.json"
            prior_manifest_path.parent.mkdir()
            _write(prior_manifest_path, prior_release)

            new_candidate = copy.deepcopy(candidate)
            new_candidate["retention_policy"]["operational_metadata_retention_days"] += 1
            new_candidate_path = _write(config / "new-candidate.json", new_candidate)
            new_candidate, _ = _candidate_spec_for_release(
                root,
                candidate_profile=new_candidate_path,
                subject_sha=subject,
                model=None,
                policy=policy,
                corpus=split,
                require_identity=True,
            )
            self.assertNotEqual(candidate_deployment_fingerprint(new_candidate), old_deployment)
            self.assertEqual(
                candidate_change_impact(candidate, new_candidate)["affected_evidence"],
                {"model_data_policy": ["retention_policy"], "governance": ["retention_policy"], "pilot_canary": ["retention_policy"]},
            )

            carry_types = (
                "runtime",
                "heavy_runtime",
                "model_validation",
                "model_high_risk_stability",
                "internal_bilingual",
                "zero_korean_comprehension",
            )
            recertification, carried, _carried_paths, _ = _load_prior_recertification_inputs(
                root,
                prior_release_manifest=Path("release/prior.json"),
                carry_forward_evidence=carry_types,
                candidate=new_candidate,
            )
            self.assertEqual(set(carried), set(carry_types))
            replacement_held_out_folder = root / "replacement-model-held-out"
            replacement_held_out_folder.mkdir()
            replacement_held_out_sources = _candidate_model_sources(
                replacement_held_out_folder,
                split="held_out",
                repeats=3,
                subject=subject,
                deployment=candidate_deployment_fingerprint(new_candidate),
                candidate=new_candidate,
            )
            replacement_held_out_path = replacement_held_out_folder / "evidence.json"
            build_machine_evidence(
                replacement_held_out_path,
                evidence_type="model_held_out",
                subject_git_sha=subject,
                deployment_fingerprint=candidate_deployment_fingerprint(new_candidate),
                sources=replacement_held_out_sources,
                root=root,
                candidate_spec=new_candidate,
            )
            replacement_held_out = load_evidence(
                replacement_held_out_path,
                expected_type="model_held_out",
                subject_git_sha=subject,
                deployment_fingerprint=candidate_deployment_fingerprint(new_candidate),
                repository_root=root,
                candidate_spec=new_candidate,
                require_candidate_spec=True,
            )
            promotion_records = {**carried, "model_held_out": replacement_held_out}
            new_promotion = build_champion_promotion(
                new_candidate,
                promotion_records,
                policy=policy,
                root=root,
                state="FROZEN_PROMOTED",
                recertification=recertification,
                prior_records=carried,
            )
            self.assertEqual(new_promotion["contract_version"], "1.1")
            _write(root / "evals" / "champion.json", champion_document_from_promotion(new_promotion))

            replacement_folder = root / "replacement-model-data-policy"
            replacement_folder.mkdir()
            replacement_path = replacement_folder / "evidence.json"
            write_evidence(
                replacement_path,
                evidence_type="model_data_policy",
                subject_git_sha=subject,
                deployment_fingerprint=candidate_deployment_fingerprint(new_candidate),
                payload={"attestation_id": "new-policy", "approved_for_internal_artifacts": True},
                generated_at="2026-09-24T00:01:00Z",
                candidate_spec=new_candidate,
            )

            # The predecessor promotion cannot use the old envelopes at the new boundary.
            _write(root / "evals" / "champion.json", champion_document_from_promotion(old_promotion))
            unbridged = build_release_manifest(
                root,
                requested_state=ReleaseState.INTERNAL_VALIDATED.value,
                subject_sha=subject,
                candidate_profile=new_candidate_path,
                evidence_paths={
                    "model_data_policy": replacement_path,
                    "model_held_out": replacement_held_out_path,
                },
                prior_release_manifest=Path("release/prior.json"),
                carry_forward_evidence=carry_types,
            )
            self.assertNotEqual(unbridged["release_state"], ReleaseState.INTERNAL_VALIDATED.value)
            self.assertTrue(unbridged.get("blocking_reasons"))

            _write(root / "evals" / "champion.json", champion_document_from_promotion(new_promotion))
            new_release = build_release_manifest(
                root,
                requested_state=ReleaseState.INTERNAL_VALIDATED.value,
                subject_sha=subject,
                candidate_profile=new_candidate_path,
                evidence_paths={
                    "model_data_policy": replacement_path,
                    "model_held_out": replacement_held_out_path,
                },
                prior_release_manifest=Path("release/prior.json"),
                carry_forward_evidence=carry_types,
            )
            self.assertEqual(new_release["release_state"], ReleaseState.INTERNAL_VALIDATED.value, new_release.get("blocking_reasons"))
            self.assertNotIn("blocking_reasons", new_release)
            self.assertEqual(new_release["deployment_fingerprint"], candidate_deployment_fingerprint(new_candidate))
            self.assertEqual(new_release["evidence_hashes"]["model_validation"], old_records["model_validation"]["evidence_identity"])
            self.assertEqual(new_release["evidence_hashes"]["model_held_out"], replacement_held_out["evidence_identity"])
            self.assertEqual(new_release["evidence_envelope_hashes"]["model_held_out"], replacement_held_out["envelope_sha256"])
            self.assertNotEqual(new_release["evidence_hashes"]["model_data_policy"], old_records["model_data_policy"]["evidence_identity"])
            self.assertEqual(new_release["promotion_identity"], new_promotion["promotion_identity"])
            self.assertEqual(new_release["recertification"]["recertification_identity"], recertification["recertification_identity"])
            self.assertEqual(new_promotion["carried_model_evidence"]["model_validation"]["evidence_identity"], old_records["model_validation"]["evidence_identity"])
            self.assertEqual(set(new_promotion["carried_model_evidence"]), {"model_validation", "model_high_risk_stability"})
            exemptions_by_type = {item["evidence_type"]: item for item in recertification["exemptions"]}
            self.assertEqual(new_promotion["carried_model_evidence"]["model_validation"]["exemption_identity"], exemptions_by_type["model_validation"]["exemption_identity"])
            self.assertNotEqual(prior_release["deployment_fingerprint"], new_release["deployment_fingerprint"])
            freshness_promotion = validate_champion_promotion(
                new_promotion,
                new_candidate,
                {"model_held_out": replacement_held_out},
                policy=policy,
                root=root,
                recertification=recertification,
                prior_records=carried,
            )
            self.assertEqual(freshness_promotion["promotion_identity"], new_release["promotion_identity"])
            expected_fingerprint = certification_fingerprint(
                deployment=new_release["deployment_fingerprint"],
                evidence_hashes=new_release["evidence_hashes"],
                release_state=new_release["release_state"],
                champion_hash=new_release["champion_hash"],
                candidate_identity=new_release["candidate_identity"],
                promotion_identity=new_release["promotion_identity"],
                recertification_identity=recertification["recertification_identity"],
                exemption_identities=recertification_exemption_identities(recertification),
            )
            self.assertEqual(new_release["certification_fingerprint"], expected_fingerprint)
            changed_candidate = copy.deepcopy(new_candidate)
            changed_candidate["retention_policy"]["operational_metadata_retention_days"] += 1
            with self.assertRaises(EvidenceValidationError):
                validate_champion_promotion(
                    new_promotion,
                    changed_candidate,
                    {"model_held_out": replacement_held_out},
                    policy=policy,
                    root=root,
                    recertification=recertification,
                    prior_records=carried,
                )

            forged = copy.deepcopy(recertification)
            forged["exemptions"][0]["new_dependency_projection_identity"] = "0" * 64
            forged["exemptions"][0]["exemption_identity"] = _content_identity(forged["exemptions"][0], "exemption_identity")
            forged["recertification_identity"] = _content_identity(forged, "recertification_identity")
            with self.assertRaises(EvidenceValidationError):
                validate_champion_promotion(
                    new_promotion,
                    new_candidate,
                    carried,
                    policy=policy,
                    root=root,
                    recertification=forged,
                    prior_records=carried,
                )

            deleted = copy.deepcopy(recertification)
            deleted["exemptions"] = [item for item in deleted["exemptions"] if item["evidence_type"] != "model_validation"]
            deleted["recertification_identity"] = _content_identity(deleted, "recertification_identity")
            with self.assertRaises(EvidenceValidationError):
                validate_champion_promotion(
                    new_promotion,
                    new_candidate,
                    carried,
                    policy=policy,
                    root=root,
                    recertification=deleted,
                    prior_records=carried,
                )

            old_manifest_bytes = prior_manifest_path.read_bytes()
            edited_manifest = json.loads(old_manifest_bytes.decode("utf-8"))
            edited_manifest["generated_at"] = "2026-09-24T00:02:00+00:00"
            _write(prior_manifest_path, edited_manifest)
            changed_recertification, changed_carried, _changed_paths, _ = _load_prior_recertification_inputs(
                root,
                prior_release_manifest=Path("release/prior.json"),
                carry_forward_evidence=carry_types,
                candidate=new_candidate,
            )
            with self.assertRaises(EvidenceValidationError):
                validate_champion_promotion(
                    new_promotion,
                    new_candidate,
                    changed_carried,
                    policy=policy,
                    root=root,
                    recertification=changed_recertification,
                    prior_records=changed_carried,
                )
            prior_manifest_path.write_bytes(old_manifest_bytes)

            carried_model_path = Path(carried["model_validation"]["path"])
            old_envelope = carried_model_path.read_bytes()
            carried_model_path.write_bytes(old_envelope + b" ")
            with self.assertRaises(EvidenceValidationError):
                validate_champion_promotion(
                    new_promotion,
                    new_candidate,
                    carried,
                    policy=policy,
                    root=root,
                    recertification=recertification,
                    prior_records=carried,
                )
            carried_model_path.write_bytes(old_envelope)

    def test_unaffected_evidence_requires_projection_bound_exemption_and_affected_evidence_is_rejected(self):
        runtime_dir = self.root / "runtime-old"
        runtime_dir.mkdir()
        runtime_sources = _runtime_sources(runtime_dir, provider="google", ocr_provider="paddle")
        runtime_path = runtime_dir / "evidence.json"
        build_machine_evidence(
            runtime_path,
            evidence_type="runtime",
            subject_git_sha=self.subject,
            deployment_fingerprint=self.deployment,
            sources=runtime_sources,
            candidate_spec=self.candidate,
        )
        runtime = load_evidence(
            runtime_path,
            expected_type="runtime",
            subject_git_sha=self.subject,
            deployment_fingerprint=self.deployment,
            candidate_spec=self.candidate,
            require_candidate_spec=True,
        )
        old_records = {"runtime": runtime}
        changed = copy.deepcopy(self.candidate)
        changed["retention_policy"]["operational_metadata_retention_days"] = 61
        impact = candidate_change_impact(self.candidate, changed)
        self.assertNotIn("runtime", impact["affected_evidence"])
        self.assertIn("model_data_policy", impact["affected_evidence"])
        recertification = build_recertification_record(
            self.candidate,
            changed,
            old_records,
            ["runtime"],
            prior_release_manifest_sha256="1" * 64,
        )
        checked = validate_recertification_record(recertification, changed, old_records)
        exemption = checked["exemptions"][0]
        self.assertEqual(exemption["old_dependency_projection_identity"], dependency_projection_identity(self.candidate, "runtime"))
        self.assertEqual(exemption["new_dependency_projection_identity"], dependency_projection_identity(changed, "runtime"))
        self.assertEqual(exemption["outcome"], "CARRY_FORWARD")
        self.assertEqual(checked["prior_certification_status"], "STALE_FOR_NEW_CANDIDATE")
        with self.assertRaises(EvidenceValidationError):
            build_recertification_record(
                self.candidate,
                changed,
                old_records,
                ["model_validation"],
                prior_release_manifest_sha256="1" * 64,
            )
        with self.assertRaises(EvidenceValidationError):
            build_recertification_record(
                self.candidate,
                changed,
                old_records,
                ["model_data_policy"],
                prior_release_manifest_sha256="1" * 64,
            )

    def test_projection_hash_tampering_replay_and_prior_evidence_rebinding_fail(self):
        runtime_dir = self.root / "runtime-replay"
        runtime_dir.mkdir()
        source = _runtime_sources(runtime_dir, provider="google", ocr_provider="paddle")
        path = runtime_dir / "evidence.json"
        build_machine_evidence(path, evidence_type="runtime", subject_git_sha=self.subject, deployment_fingerprint=self.deployment, sources=source, candidate_spec=self.candidate)
        runtime = load_evidence(path, expected_type="runtime", subject_git_sha=self.subject, deployment_fingerprint=self.deployment, candidate_spec=self.candidate, require_candidate_spec=True)
        old_records = {"runtime": runtime}
        changed = copy.deepcopy(self.candidate)
        changed["retention_policy"]["operational_metadata_retention_days"] = 62
        recertification = build_recertification_record(self.candidate, changed, old_records, ["runtime"], prior_release_manifest_sha256="2" * 64)
        forged = copy.deepcopy(recertification)
        forged["exemptions"][0]["new_dependency_projection_identity"] = "f" * 64
        forged["exemptions"][0]["exemption_identity"] = _content_identity(forged["exemptions"][0], "exemption_identity")
        forged["recertification_identity"] = _content_identity(forged, "recertification_identity")
        with self.assertRaises(EvidenceValidationError):
            validate_recertification_record(forged, changed, old_records)
        replay = copy.deepcopy(changed)
        replay["provider"] = "another-provider"
        with self.assertRaises(EvidenceValidationError):
            validate_recertification_record(recertification, replay, old_records)
        forged_prior = {"runtime": {**runtime, "envelope_sha256": "0" * 64}}
        with self.assertRaises(EvidenceValidationError):
            validate_recertification_record(recertification, changed, forged_prior)
        freeform = copy.deepcopy(recertification)
        freeform["exemptions"][0]["waiver_reason"] = "the owner says it is harmless"
        with self.assertRaises(EvidenceValidationError):
            validate_recertification_record(freeform, changed, old_records)

    def test_new_candidate_invalidates_old_champion_and_fingerprint_binds_recertification(self):
        champion_path = self.root / "evals" / "champion.json"
        champion_path.parent.mkdir(exist_ok=True)
        _write(champion_path, champion_document_from_promotion(self.promotion))
        changed = _change(self.candidate, "generation_settings", {"temperature": 0.2})
        _value, _hash, blockers = _champion(
            self.root,
            records=self.records,
            policy=self.policy,
            deployment_fp=candidate_deployment_fingerprint(changed),
            candidate_spec=changed,
        )
        self.assertTrue(blockers)
        first = certification_fingerprint(
            deployment=candidate_deployment_fingerprint(changed),
            evidence_hashes={"runtime": "a" * 64},
            release_state="GEMMA_EVAL_READY",
            candidate_identity=candidate_deployment_fingerprint(changed),
            promotion_identity=None,
            recertification_identity="b" * 64,
            exemption_identities={"runtime": "c" * 64},
        )
        second = certification_fingerprint(
            deployment=candidate_deployment_fingerprint(changed),
            evidence_hashes={"runtime": "a" * 64},
            release_state="GEMMA_EVAL_READY",
            candidate_identity=candidate_deployment_fingerprint(changed),
            promotion_identity="e" * 64,
            recertification_identity="b" * 64,
            exemption_identities={"runtime": "d" * 64},
        )
        self.assertNotEqual(first, second)
        promoted = certification_fingerprint(
            deployment=candidate_deployment_fingerprint(changed),
            evidence_hashes={"runtime": "a" * 64},
            release_state="GEMMA_EVAL_READY",
            candidate_identity=candidate_deployment_fingerprint(changed),
            promotion_identity="d" * 64,
            recertification_identity="b" * 64,
            exemption_identities={"runtime": "c" * 64},
        )
        self.assertNotEqual(first, promoted)
        self.assertEqual(recertification_exemption_identities(None), {})

    def test_changed_authoritative_evidence_needs_new_candidate_bound_replacement(self):
        changed = copy.deepcopy(self.candidate)
        changed["retention_policy"]["operational_metadata_retention_days"] = 63
        deployment = candidate_deployment_fingerprint(changed)
        runtime_dir = self.root / "runtime-synthetic-recertification"
        runtime_dir.mkdir()
        runtime_sources = _runtime_sources(runtime_dir, provider="google", ocr_provider="paddle")
        runtime_path = runtime_dir / "evidence.json"
        build_machine_evidence(
            runtime_path,
            evidence_type="runtime",
            subject_git_sha=self.subject,
            deployment_fingerprint=self.deployment,
            sources=runtime_sources,
            candidate_spec=self.candidate,
        )
        prior_runtime = load_evidence(
            runtime_path,
            expected_type="runtime",
            subject_git_sha=self.subject,
            deployment_fingerprint=self.deployment,
            candidate_spec=self.candidate,
            require_candidate_spec=True,
        )
        old_policy_path = self.root / "old-model-data-policy.json"
        write_evidence(
            old_policy_path,
            evidence_type="model_data_policy",
            subject_git_sha=self.subject,
            deployment_fingerprint=self.deployment,
            payload={"attestation_id": "old-policy", "approved_for_internal_artifacts": True},
            generated_at="2026-09-23T00:00:00Z",
            candidate_spec=self.candidate,
        )
        old_policy = load_evidence(
            old_policy_path,
            expected_type="model_data_policy",
            subject_git_sha=self.subject,
            deployment_fingerprint=self.deployment,
            candidate_spec=self.candidate,
            require_candidate_spec=True,
        )
        prior_records = {"runtime": prior_runtime, "model_data_policy": old_policy}
        recertification = build_recertification_record(
            self.candidate,
            changed,
            prior_records,
            ["runtime"],
            prior_release_manifest_sha256="3" * 64,
        )
        checked = validate_recertification_record(recertification, changed, prior_records)
        self.assertEqual([item["evidence_type"] for item in checked["exemptions"]], ["runtime"])
        self.assertEqual(checked["affected_evidence"]["model_data_policy"], ["retention_policy"])
        self.assertEqual(prior_runtime["candidate_spec"]["subject_git_sha"], self.subject)
        with self.assertRaises(EvidenceValidationError):
            build_recertification_record(
                self.candidate,
                changed,
                prior_records,
                ["model_data_policy"],
                prior_release_manifest_sha256="3" * 64,
            )
        prior_manifest_path = self.root / "prior-release.json"
        _write(prior_manifest_path, {
            "release_state": "INTERNAL_VALIDATED",
            "subject_git_sha": self.subject,
            "deployment_fingerprint": self.deployment,
            "candidate_spec": canonical_candidate_factors(self.candidate),
            "evidence_hashes": {"runtime": prior_runtime["evidence_identity"]},
            "evidence_envelope_hashes": {"runtime": prior_runtime["envelope_sha256"]},
            "evidence_paths": {"runtime": runtime_path.relative_to(self.root).as_posix()},
        })
        loaded_recert, carried, carried_paths, loaded_prior_path = _load_prior_recertification_inputs(
            self.root,
            prior_release_manifest=prior_manifest_path,
            carry_forward_evidence=["runtime"],
            candidate=changed,
        )
        self.assertEqual(loaded_prior_path, prior_manifest_path)
        self.assertEqual(set(carried), {"runtime"})
        self.assertEqual(carried_paths["runtime"], runtime_path)
        validate_recertification_record(
            loaded_recert,
            changed,
            carried,
            expected_prior_release_manifest_sha256=_sha(prior_manifest_path),
        )
        evidence_path = self.root / "replacement-model-data-policy.json"
        write_evidence(
            evidence_path,
            evidence_type="model_data_policy",
            subject_git_sha=self.subject,
            deployment_fingerprint=deployment,
            payload={"attestation_id": "replacement-policy", "approved_for_internal_artifacts": True},
            generated_at="2026-09-24T00:00:00Z",
            candidate_spec=changed,
        )
        replacement = load_evidence(
            evidence_path,
            expected_type="model_data_policy",
            subject_git_sha=self.subject,
            deployment_fingerprint=deployment,
            candidate_spec=changed,
            require_candidate_spec=True,
        )
        self.assertEqual(replacement["candidate_spec"]["retention_policy"], changed["retention_policy"])
        current_evidence = {
            "runtime": prior_runtime["evidence_identity"],
            "model_data_policy": replacement["evidence_identity"],
        }
        self.assertNotEqual(current_evidence["model_data_policy"], old_policy["evidence_identity"])
        self.assertNotIn("model_data_policy", recertification_exemption_identities(None))


if __name__ == "__main__":
    unittest.main()
