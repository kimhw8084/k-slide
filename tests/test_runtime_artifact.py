from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from k_slide.certification import EvidenceValidationError, candidate_completeness, candidate_deployment_fingerprint, dependency_inventory_hash, load_dependency_inventory, sha256_file
from k_slide.runtime_artifact import (
    BASE_IMAGE_DIGEST,
    RUNTIME_ARTIFACT_NAME,
    build_runtime_manifest,
    build_runtime_sbom,
    canonical_json_bytes,
    load_system_package_manifest,
    system_package_manifest_hash,
    validate_runtime_manifest,
)


ROOT = Path(__file__).resolve().parents[1]


class RuntimeArtifactContractTests(unittest.TestCase):
    def _manifest(self) -> tuple[dict, dict, dict]:
        system = load_system_package_manifest(ROOT / "deploy/runtime/system-packages-linux-amd64.json")
        inventory = load_dependency_inventory(ROOT / "deploy/runtime/production-dependency-inventory.json")
        dependency_hash = dependency_inventory_hash(inventory)
        system_hash = system_package_manifest_hash(system)
        sbom = build_runtime_sbom(inventory=inventory, system_packages=system["packages"], kslide_version="0.3.5", source_revision="a" * 40, system_package_hash=system_hash)
        sbom_bytes = canonical_json_bytes(sbom)
        with tempfile.NamedTemporaryFile() as handle:
            handle.write(sbom_bytes)
            handle.flush()
            sbom_hash = sha256_file(Path(handle.name))
        ocr = {"sha256": "b" * 64, "file_count": 2, "paddlex_config": "PaddleOCR.yaml", "paddlex_config_sha256": "c" * 64, "asset_provenance": "certifying-bundle", "libreoffice_version": "25.2.3"}
        manifest = build_runtime_manifest(
            source_revision="a" * 40,
            source_tree_sha256="d" * 64,
            python_version="3.11.16",
            kslide_version="0.3.5",
            base_image_digest=BASE_IMAGE_DIGEST,
            system_manifest=system,
            system_packages=system["packages"],
            lock_sha256=sha256_file(ROOT / "deploy/runtime/production-requirements.lock"),
            inventory_sha256=dependency_hash,
            package_count=len(inventory["packages"]),
            paddle_version="3.0.0",
            paddleocr_version="3.7.0",
            ocr_identity=ocr,
            sbom_sha256=sbom_hash,
            sbom_dependency_sha256=dependency_hash,
        )
        return manifest, sbom, system

    def test_canonical_inputs_are_digest_and_snapshot_pinned(self) -> None:
        manifest, _sbom, system = self._manifest()
        self.assertIn("@sha256:", manifest["base_image"]["ref"])
        self.assertEqual(manifest["supported_platform"], "linux/amd64")
        self.assertTrue(system["snapshot"]["uri"].startswith("https://snapshot.debian.org/"))
        self.assertEqual(manifest["libreoffice_version"], "25.2.3")
        self.assertEqual(manifest["font_packages"], [item for item in system["packages"] if item["name"].startswith("fonts-")])

    def test_manifest_rederives_dependency_sbom_and_ocr_identity(self) -> None:
        manifest, sbom, system = self._manifest()
        validate_runtime_manifest(
            manifest,
            expected_source_revision="a" * 40,
            expected_inventory_sha256=manifest["python_dependency_inventory_sha256"],
            expected_lock_sha256=manifest["python_dependency_lock_sha256"],
            expected_ocr_manifest_sha256=manifest["ocr_asset_manifest"]["sha256"],
            expected_sbom_sha256=manifest["sbom"]["sha256"],
            expected_system_manifest=system,
        )
        self.assertEqual(sbom["metadata"]["component"]["properties"][0]["value"], manifest["python_dependency_inventory_sha256"])
        self.assertNotIn("release_state", manifest)
        self.assertNotIn("certification_fingerprint", manifest)
        self.assertEqual(manifest["artifact_name"], RUNTIME_ARTIFACT_NAME)

    def test_manifest_rejects_unknown_or_mismatched_runtime_subjects(self) -> None:
        manifest, _sbom, system = self._manifest()
        cases = []
        unknown = copy.deepcopy(manifest)
        unknown["unexpected"] = True
        cases.append(unknown)
        bad_hash = copy.deepcopy(manifest)
        bad_hash["python_dependency_lock_sha256"] = "not-a-hash"
        cases.append(bad_hash)
        wrong_source = copy.deepcopy(manifest)
        wrong_source["source_revision"] = "e" * 40
        cases.append(wrong_source)
        bad_dependency = copy.deepcopy(manifest)
        bad_dependency["sbom"]["dependency_set_sha256"] = "e" * 64
        cases.append(bad_dependency)
        bad_ocr = copy.deepcopy(manifest)
        bad_ocr["ocr_asset_manifest"]["sha256"] = "e" * 64
        cases.append(bad_ocr)
        for candidate in cases:
            with self.subTest(candidate=candidate):
                with self.assertRaises(EvidenceValidationError):
                    validate_runtime_manifest(candidate, expected_source_revision="a" * 40, expected_system_manifest=system)

    def test_manifest_rejects_secret_or_source_content_fields(self) -> None:
        manifest, _sbom, system = self._manifest()
        leaked = copy.deepcopy(manifest)
        leaked["product_runtime"]["source_text"] = "confidential"
        with self.assertRaises(EvidenceValidationError):
            validate_runtime_manifest(leaked, expected_system_manifest=system)

    def test_product_and_heavy_commands_share_one_runtime_subject(self) -> None:
        manifest, _sbom, _system = self._manifest()
        self.assertEqual(manifest["product_runtime"]["entrypoint"], ["k-slide"])
        self.assertEqual(manifest["product_runtime"]["heavy_doctor_command"], ["python", "-m", "evals.heavy.doctor"])
        self.assertTrue(manifest["product_runtime"]["run_as_non_root"])

    def test_certification_can_bind_runtime_identity_without_turning_it_into_certification_state(self) -> None:
        manifest, _sbom, _system = self._manifest()
        candidate = {"candidate_spec_version": "1.1", "subject_git_sha": "a" * 40, "kslide_version": "0.3.5", "runtime_artifact_identity": manifest["artifact_identity"], "runtime_artifact_manifest_sha256": "e" * 64, "runtime_sbom_sha256": manifest["sbom"]["sha256"]}
        fingerprint = candidate_deployment_fingerprint(candidate)
        changed = dict(candidate, runtime_artifact_identity={"kind": "canonical-build-inputs", "sha256": "f" * 64})
        self.assertNotEqual(fingerprint, candidate_deployment_fingerprint(changed))
        self.assertEqual(candidate_completeness(candidate, "DEVELOPMENT"), [])
        self.assertNotIn("release_state", candidate)


if __name__ == "__main__":
    unittest.main()
