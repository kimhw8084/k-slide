from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from evals.certification import load_model_policy
from evals.release import derive_release_state, main as release_main
from k_slide.errors import KSlideError
from k_slide.certification import (
    EvidenceValidationError,
    build_deployment_factors,
    certification_fingerprint,
    deployment_fingerprint,
    load_evidence,
)
from k_slide.production import _asset_manifest_status


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class CertificationClosureTests(unittest.TestCase):
    def test_evidence_requires_envelope_and_exact_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.json"
            result_path = Path(directory) / "runtime-result.json"
            result_path.write_text(json.dumps({"complete": True}), encoding="utf-8")
            envelope = {
                "schema_version": "1.0",
                "evidence_type": "runtime",
                "status": "PASS",
                "subject_git_sha": "a" * 40,
                "deployment_fingerprint": "b" * 64,
                "generated_at": "2026-09-09T00:00:00Z",
                "payload": {"runtime_pass": True, "required_media_compliance": True, "run_complete": True, "result_path": result_path.name, "result_sha256": _sha(result_path)},
            }
            path.write_text(json.dumps(envelope), encoding="utf-8")
            loaded = load_evidence(path, expected_type="runtime", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64)
            self.assertEqual(loaded["evidence_type"], "runtime")
            with self.assertRaises(EvidenceValidationError):
                load_evidence(path, expected_type="heavy_runtime", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64)
            envelope["subject_git_sha"] = "c" * 40
            path.write_text(json.dumps(envelope), encoding="utf-8")
            with self.assertRaises(EvidenceValidationError):
                load_evidence(path, expected_type="runtime", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64)

    def test_evidence_status_only_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "status.json"
            path.write_text(json.dumps({"status": "PASS"}), encoding="utf-8")
            with self.assertRaises(EvidenceValidationError):
                load_evidence(path)

    def test_release_state_is_evidence_derived(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subject = "a" * 40
            factors = build_deployment_factors(root, subject_git_sha=subject, model_policy=load_model_policy(root))
            deployment = deployment_fingerprint(factors)
            records = {}
            state, blockers = derive_release_state("RUNTIME_READY", records=records, root=root, policy=load_model_policy(root), deployment_fp=deployment)
            self.assertEqual(state, "DEVELOPMENT")
            self.assertTrue(blockers)
            runtime = root / "runtime.json"
            (root / "runtime-result.json").write_text(json.dumps({"complete": True}), encoding="utf-8")
            runtime.write_text(json.dumps({
                "schema_version": "1.0", "evidence_type": "runtime", "status": "PASS",
                "subject_git_sha": subject, "deployment_fingerprint": deployment,
                "generated_at": "2026-09-09T00:00:00Z",
                "payload": {"runtime_pass": True, "required_media_compliance": True, "run_complete": True, "result_path": "runtime-result.json", "result_sha256": _sha(root / "runtime-result.json")},
            }), encoding="utf-8")
            records["runtime"] = load_evidence(runtime, expected_type="runtime", subject_git_sha=subject, deployment_fingerprint=deployment)
            state, blockers = derive_release_state("RUNTIME_READY", records=records, root=root, policy=load_model_policy(root), deployment_fp=deployment)
            self.assertEqual(state, "RUNTIME_READY")
            self.assertEqual(blockers, [])

    def test_deployment_and_certification_fingerprints_change_with_material_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = build_deployment_factors(root, subject_git_sha="a" * 40, model_policy=load_model_policy(root))
            second = build_deployment_factors(root, subject_git_sha="b" * 40, model_policy=load_model_policy(root))
            self.assertNotEqual(deployment_fingerprint(first), deployment_fingerprint(second))
            deployment = deployment_fingerprint(first)
            self.assertNotEqual(
                certification_fingerprint(deployment=deployment, evidence_hashes={"runtime": "a" * 64}, release_state="RUNTIME_READY"),
                certification_fingerprint(deployment=deployment, evidence_hashes={"runtime": "b" * 64}, release_state="RUNTIME_READY"),
            )

    def test_approved_prefix_is_not_model_policy_approval(self):
        policy = load_model_policy(Path.cwd())
        self.assertFalse(policy.approved(requested="approved:internal", effective="approved:internal"))

    def test_production_checks_use_model_policy_not_prefix(self):
        from k_slide.production import production_checks
        from k_slide.runtime import RuntimeMetadata

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / ".k-slide-config"
            config.mkdir()
            (config / "production-profile.json").write_text(json.dumps({
                "schema_version": "1.0", "release_state": "PRODUCTION_CERTIFIED", "opencode_version": "1.3.9",
                "requested_model": "approved:internal", "effective_model": "approved:internal", "ocr_provider": "paddle",
                "ocr_asset_manifest": "manifest.json", "python_version": "3.11", "paddle_version": "3.0.0",
                "paddleocr_version": "3.0.3", "libreoffice_version": "25", "retention_days": 30,
                "tenant_isolation": "workspace_per_session", "network_egress": "approved_inference_only",
                "subject_git_sha": "a" * 40, "deployment_fingerprint": "b" * 64,
                "certification_fingerprint": "c" * 64, "release_manifest": "manifest.json",
                "release_manifest_sha256": "d" * 64, "model_data_attestation": "attestation-1",
            }), encoding="utf-8")
            runtime = RuntimeMetadata(
                kslide_version="0.3.5", opencode_version="1.3.9", opencode_path=None, opencode_config_path=None,
                provider="internal", reported_model_id="approved:internal", model_family=None, model_size=None,
                instruction_tuned_status="unknown", vision_support=True, thinking_support=None, provider_backend=None,
                quantization_or_dtype=None, context_configuration={}, image_preprocessing_settings={},
                model_compatibility="production_candidate", discovery_warnings=[],
            )
            checks = production_checks(root, runtime)
            policy_check = next(item for item in checks if item["label"] == "Requested/effective model policy")
            self.assertEqual(policy_check["status"], "FAIL")
            freshness = next(item for item in checks if item["label"] == "Certification freshness")
            self.assertEqual(freshness["detail"], "CERTIFICATION_STALE")

    def test_asset_manifest_requires_content_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            asset = root / "weights.bin"
            asset.write_bytes(b"weights-v1")
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps({"provider": "paddle", "files": [{"path": "weights.bin", "sha256": _sha(asset)}]}), encoding="utf-8")
            self.assertEqual(_asset_manifest_status(manifest)[0], True)
            asset.write_bytes(b"tampered")
            self.assertEqual(_asset_manifest_status(manifest)[0], False)

    def test_asset_manifest_rejects_symlink_escape(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            target = Path(outside) / "weights.bin"
            target.write_bytes(b"private")
            link = root / "weights.bin"
            link.symlink_to(target)
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps({"provider": "paddle", "files": [{"path": "weights.bin", "sha256": _sha(target)}]}), encoding="utf-8")
            self.assertEqual(_asset_manifest_status(manifest)[0], False)

    def test_production_profile_rejects_unenforced_resource_limits(self):
        from k_slide.production import ProductionProfile

        value = {
            "release_state": "DEVELOPMENT", "opencode_version": "1.3.9",
            "requested_model": "google/gemma-4-31b-it", "effective_model": "google/gemma-4-31b-it",
            "ocr_provider": "paddle", "ocr_asset_manifest": "manifest.json",
            "python_version": "3.11", "paddle_version": "3.0.0", "paddleocr_version": "3.0.3",
            "libreoffice_version": "25", "retention_days": 30,
            "tenant_isolation": "workspace_per_session", "network_egress": "approved_inference_only",
            "subject_git_sha": "UNSET", "deployment_fingerprint": "UNSET",
            "certification_fingerprint": "UNSET", "release_manifest": "UNSET",
            "release_manifest_sha256": "UNSET", "model_data_attestation": "UNSET",
            "resource_limits": {"run_seconds": 1},
        }
        with self.assertRaises(KSlideError):
            ProductionProfile.from_mapping(value)

    def test_release_cli_blocks_requested_certified_without_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "manifest.json"
            result = release_main(["--root", str(root), "--output", str(output), "--requested-state", "PRODUCTION_CERTIFIED", "--require-certified"])
            self.assertEqual(result, 2)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
