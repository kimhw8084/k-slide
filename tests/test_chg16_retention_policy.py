from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

from k_slide.certification import candidate_completeness, candidate_deployment_fingerprint, load_candidate_spec
from k_slide.errors import ErrorCode, KSlideError
from k_slide.production import ProductionProfile, production_checks
from k_slide.retention import cleanup_expired_runs
from k_slide.retention_policy import RetentionPolicy


def _policy(content: int | str = 14, metadata: int | str = 45) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "content_retention_days": content,
        "operational_metadata_retention_days": metadata,
    }


def _profile(policy: dict[str, object]) -> dict[str, object]:
    return {
        "schema_version": "1.1",
        "release_state": "DEVELOPMENT",
        "opencode_version": "UNSET",
        "requested_model": "UNSET",
        "effective_model": "UNSET",
        "ocr_provider": "none",
        "ocr_asset_manifest": "UNSET",
        "python_version": "UNSET",
        "paddle_version": "UNSET",
        "paddleocr_version": "UNSET",
        "libreoffice_version": "UNSET",
        "retention_policy": policy,
        "tenant_isolation": "UNSET",
        "network_egress": "UNSET",
        "subject_git_sha": "UNSET",
        "deployment_fingerprint": "UNSET",
        "certification_fingerprint": "UNSET",
        "release_manifest": "UNSET",
        "release_manifest_sha256": "UNSET",
        "model_data_attestation": "UNSET",
    }


class CHG16RetentionPolicyTests(unittest.TestCase):
    def test_policy_is_split_and_survives_profile_serialization(self) -> None:
        policy = RetentionPolicy.from_mapping(_policy(7, 91), require_resolved=True)
        profile = ProductionProfile.from_mapping(_profile(policy.as_dict()))
        self.assertEqual(profile.retention_policy.content_retention_days, 7)
        self.assertEqual(profile.retention_policy.operational_metadata_retention_days, 91)
        self.assertEqual(ProductionProfile.from_mapping(profile.as_dict()).as_dict()["retention_policy"], _policy(7, 91))

    def test_absent_policy_has_no_implicit_duration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "candidate.yaml"
            path.write_text('schema_version: "1.1"\ncandidate_spec_version: "1.1"\n', encoding="utf-8")
            candidate = load_candidate_spec(path)
        self.assertNotIn("retention_policy", candidate)
        missing = candidate_completeness(candidate, "PRODUCTION_CERTIFIED")
        self.assertIn("retention_policy.content_retention_days", missing)
        self.assertIn("retention_policy.operational_metadata_retention_days", missing)

    def test_legacy_single_field_fails_closed_without_auto_split(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "candidate.json"
            path.write_text(json.dumps({"schema_version": "1.0", "retention_days": 30}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "legacy retention_days"):
                load_candidate_spec(path)
        with self.assertRaises(KSlideError) as raised:
            ProductionProfile.from_mapping({**_profile(_policy(30, 30)), "schema_version": "1.0", "retention_days": 30})
        self.assertEqual(raised.exception.code, ErrorCode.PRODUCTION_PROFILE_INVALID)

    def test_split_values_remain_distinct_and_change_identity_independently(self) -> None:
        base = {"candidate_spec_version": "1.1", "subject_git_sha": "a" * 40, "retention_policy": _policy(7, 91)}
        first = candidate_deployment_fingerprint(base)
        self.assertNotEqual(first, candidate_deployment_fingerprint({**base, "retention_policy": _policy(8, 91)}))
        self.assertNotEqual(first, candidate_deployment_fingerprint({**base, "retention_policy": _policy(7, 92)}))
        self.assertEqual(RetentionPolicy.from_mapping(base["retention_policy"]).as_dict(), _policy(7, 91))

    def test_missing_or_unresolved_component_blocks_production_and_doctor_labels_both_planes(self) -> None:
        candidate = {"retention_policy": _policy(14, "UNSET")}
        missing = candidate_completeness(candidate, "PRODUCTION_CERTIFIED")
        self.assertIn("retention_policy.operational_metadata_retention_days", missing)
        with self.assertRaises(KSlideError):
            ProductionProfile.from_mapping(_profile(_policy(14, "UNSET")))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / ".k-slide-config"
            config.mkdir()
            (config / "production-profile.json").write_text(json.dumps(_profile(_policy(14, "UNSET"))), encoding="utf-8")
            checks = production_checks(root, SimpleNamespace(kslide_version="0.3.5", opencode_version="UNSET", reported_model_id="UNSET", vision_support=None))
        labels = {item["label"]: item for item in checks}
        self.assertIn("Content retention policy", labels)
        self.assertIn("Operational-metadata retention policy", labels)
        self.assertEqual(labels["Content retention policy"]["status"], "PASS")
        self.assertEqual(labels["Operational-metadata retention policy"]["status"], "FAIL")

    def test_cleanup_uses_content_only_and_rejects_ad_hoc_duration(self) -> None:
        now = datetime(2026, 9, 17, tzinfo=timezone.utc)
        for metadata_days in (1, 100):
            with self.subTest(metadata_days=metadata_days), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                run_root = root / ".k-slide-runs"
                run_root.mkdir(mode=0o700)
                for name, phase in (("active", "TRANSLATING"), ("terminal", "COMPLETE")):
                    run = run_root / name
                    run.mkdir(mode=0o700)
                    (run / "RUN_STATE.json").write_text(json.dumps({"phase": phase, "updated_at": (now - timedelta(days=10)).isoformat()}), encoding="utf-8")
                result = cleanup_expired_runs(root, _policy(5, metadata_days), now=now)
                self.assertEqual({item["run_id"] for item in result["removed"]}, {"terminal"})
                self.assertTrue((run_root / "active").is_dir())
                with self.assertRaises(KSlideError) as raised:
                    cleanup_expired_runs(root, 5)  # type: ignore[arg-type]
                self.assertEqual(raised.exception.code, ErrorCode.RETENTION_INVALID)

    def test_tracked_examples_do_not_supply_product_default(self) -> None:
        root = Path(__file__).resolve().parents[1]
        for relative in ("evals/production-candidate.yaml", "evals/production-candidate.example.yaml", "deploy/production-profile.example.json"):
            text = (root / relative).read_text(encoding="utf-8")
            self.assertNotIn("retention_days: 30", text)
            self.assertNotIn('"retention_days": 30', text)


if __name__ == "__main__":
    unittest.main()
