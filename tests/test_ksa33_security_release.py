from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from evals.build_security_release_context import _verify_runtime_source_archive
from k_slide.certification import load_evidence
from k_slide.egress_policy import egress_policy_hash_for_mapping, egress_policy_identity_for_mapping
from k_slide.evidence_adapters import AdapterError, build_machine_evidence
from k_slide.runtime_artifact import source_tree_sha256
from k_slide.security_release import candidate_tree_sha256, canonical_bytes, sha256
from evals.security_reports import SecurityReportError, sanitize_gitleaks, sanitize_pip_audit, sanitize_semgrep, sanitize_trivy
from tests.test_certification_closure import PINNED_PRODUCTION_PYTHON_VERSION, _security_sources, _write


SUBJECT = "a" * 40
TREE = "d" * 64
DEPLOYMENT = "b" * 64


class KSA33SecurityReleaseEvidenceTests(unittest.TestCase):
    def test_git_tree_object_id_has_a_domain_separated_sha256_binding(self):
        tree_oid = "a" * 40
        self.assertEqual(candidate_tree_sha256(tree_oid), sha256(b"k-slide.git-tree-oid.v1\0" + tree_oid.encode("ascii")))
        with self.assertRaises(ValueError):
            candidate_tree_sha256("a" * 64)

    def test_runtime_source_archive_must_match_the_candidate_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory)
            source = archive / "src" / "app.py"
            source.parent.mkdir()
            source.write_text("candidate source\n", encoding="utf-8")
            files = [Path("src/app.py")]
            candidate_hash = source_tree_sha256(archive, paths=[item.as_posix() for item in files])
            _verify_runtime_source_archive(archive, files, candidate_hash)
            source.write_text("replayed source\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                _verify_runtime_source_archive(archive, files, candidate_hash)

    def _sources(self, root: Path, **kwargs):
        return _security_sources(root, subject=SUBJECT, deployment=DEPLOYMENT, **kwargs)

    def _build(self, root: Path, sources: dict[str, Path], *, subject: str = SUBJECT, deployment: str = DEPLOYMENT, candidate_spec=None):
        evidence = root / "security.evidence.json"
        build_machine_evidence(
            evidence,
            evidence_type="security",
            subject_git_sha=subject,
            deployment_fingerprint=deployment,
            sources=sources,
            candidate_spec=candidate_spec,
        )
        return load_evidence(
            evidence,
            expected_type="security",
            subject_git_sha=subject,
            deployment_fingerprint=deployment,
            candidate_spec=candidate_spec,
        )

    def test_clean_candidate_evidence_rederives_and_keeps_live_company_controls_unqualified(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = self._sources(root)
            result = self._build(root, sources)
            proof = result["payload"]["security_release"]
            self.assertEqual(proof["candidate_subject_sha"], SUBJECT)
            self.assertEqual(proof["candidate_tree_sha256"], TREE)
            self.assertEqual(proof["company_iam_status"], "UNQUALIFIED")
            self.assertEqual(proof["company_network_egress_status"], "UNQUALIFIED")
            self.assertEqual(proof["company_deployed_runtime_status"], "UNQUALIFIED")
            self.assertEqual(proof["vulnerability_finding_count"], 0)
            schema = json.loads(Path("schemas/security-release-evidence.schema.json").read_text(encoding="utf-8"))
            Draft202012Validator.check_schema(schema)
            Draft202012Validator(schema).validate(proof)
            disposition_schema = json.loads(Path("schemas/vulnerability-dispositions.schema.json").read_text(encoding="utf-8"))
            Draft202012Validator.check_schema(disposition_schema)
            Draft202012Validator(disposition_schema).validate(json.loads(sources["vulnerability_dispositions"].read_text(encoding="utf-8")))

    def test_security_evidence_fixtures_use_pinned_python_311_independent_of_test_host(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = self._sources(root)
            context = json.loads(sources["security_release_context"].read_text(encoding="utf-8"))
            self.assertEqual(PINNED_PRODUCTION_PYTHON_VERSION, "3.11.13")
            self.assertEqual(context["runtime"]["python_version"], PINNED_PRODUCTION_PYTHON_VERSION)
            self.assertEqual(context["runner"]["python_version"], "3.11.13")
            self._build(root, sources)

    def test_security_evidence_rejects_a_non_311_production_runtime_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = self._sources(root)
            context = json.loads(sources["security_release_context"].read_text(encoding="utf-8"))
            context["runtime"]["python_version"] = "3.12.9"
            _write(sources["security_release_context"], context)
            with self.assertRaises(AdapterError):
                self._build(root, sources)

    def test_candidate_sha_tree_and_fingerprint_replay_fail_closed(self):
        for field, value in (("subject_git_sha", "f" * 40), ("source_tree_sha256", "e" * 64), ("deployment_fingerprint", "c" * 64)):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                sources = self._sources(root)
                context = json.loads(sources["security_release_context"].read_text(encoding="utf-8"))
                context["candidate"][field] = value
                if field == "source_tree_sha256":
                    context["runtime"]["source_tree_sha256"] = value
                _write(sources["security_release_context"], context)
                with self.assertRaises(AdapterError):
                    self._build(root, sources)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = self._sources(root)
            dispositions = json.loads(sources["vulnerability_dispositions"].read_text(encoding="utf-8"))
            dispositions["candidate_binding"] = {"subject_git_sha": SUBJECT, "source_tree_sha256": "e" * 64, "deployment_fingerprint": DEPLOYMENT}
            _write(sources["vulnerability_dispositions"], dispositions)
            with self.assertRaises(AdapterError):
                self._build(root, sources)

    def test_scanner_report_hash_and_pinned_version_mismatch_fail_closed(self):
        for change in ("hash", "version"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                sources = self._sources(root)
                context = json.loads(sources["security_release_context"].read_text(encoding="utf-8"))
                if change == "hash":
                    context["scanners"][0]["report_sha256"] = "f" * 64
                else:
                    context["scanners"][0]["version"] = "2.9.1"
                _write(sources["security_release_context"], context)
                with self.assertRaises(AdapterError):
                    self._build(root, sources)

    def test_stale_or_wrong_attempt_scanner_results_fail_closed(self):
        for mutate in (
            lambda context: context["scanners"][0].update(finished_at="2025-12-31T20:00:00Z"),
            lambda context: context["scanners"][0].update(run_attempt=2),
        ):
            with self.subTest(mutate=mutate), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                sources = self._sources(root)
                context = json.loads(sources["security_release_context"].read_text(encoding="utf-8"))
                mutate(context)
                _write(sources["security_release_context"], context)
                with self.assertRaises(AdapterError):
                    self._build(root, sources)

    def test_scanner_failure_missing_scanner_and_malformed_evidence_fail_closed(self):
        for change in ("failure", "missing", "malformed"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                sources = self._sources(root)
                context = json.loads(sources["security_release_context"].read_text(encoding="utf-8"))
                if change == "failure":
                    context["scanners"][3]["status"] = "FAIL"
                elif change == "missing":
                    context["scanners"].pop()
                else:
                    context["unexpected"] = True
                _write(sources["security_release_context"], context)
                with self.assertRaises(AdapterError):
                    self._build(root, sources)

    def test_wrong_runtime_image_or_base_image_identity_fails_closed(self):
        for field, value in (("image_digest", "sha256:" + "c" * 64), ("base_image", "python:latest"), ("python_version", "3.12.0")):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                sources = self._sources(root)
                context = json.loads(sources["security_release_context"].read_text(encoding="utf-8"))
                context["runtime"][field] = value
                _write(sources["security_release_context"], context)
                with self.assertRaises(AdapterError):
                    self._build(root, sources)

    def test_secret_leakage_and_non_source_free_privacy_claim_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = self._sources(root)
            context = json.loads(sources["security_release_context"].read_text(encoding="utf-8"))
            context["privacy"]["access_key_values_persisted"] = True
            _write(sources["security_release_context"], context)
            with self.assertRaises(AdapterError):
                self._build(root, sources)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = self._sources(root)
            canary = "KSA33-ACCESSKEY-DO-NOT-PERSIST"
            _write(sources["gitleaks"], [{"redacted": f"AccessKey={canary}"}])
            with self.assertRaises(AdapterError):
                self._build(root, sources)
            self.assertFalse((root / "security.evidence.json").exists())

    def test_egress_policy_mismatch_fails_even_when_policy_remains_well_formed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = self._sources(root)
            policy = json.loads(sources["release_egress_policy"].read_text(encoding="utf-8"))
            policy["capabilities"][0]["service_identity"] = "changed-inference-service"
            policy["policy_hash"] = egress_policy_hash_for_mapping(policy_version=policy["policy_version"], capabilities=policy["capabilities"])
            policy["policy_identity"] = egress_policy_identity_for_mapping(policy_version=policy["policy_version"], policy_hash=policy["policy_hash"])
            _write(sources["release_egress_policy"], policy)
            with self.assertRaises(AdapterError):
                self._build(root, sources)

    def test_cross_run_control_result_fails_and_ksa17_tests_are_required(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = self._sources(root)
            context = json.loads(sources["security_release_context"].read_text(encoding="utf-8"))
            next(item for item in context["controls"] if item["id"] == "KSA-17")["run_id"] = "2"
            _write(sources["security_release_context"], context)
            with self.assertRaises(AdapterError):
                self._build(root, sources)

    def test_dependency_vulnerability_cannot_be_omitted_and_disposition_is_candidate_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = self._sources(root, vulnerable=True)
            with self.assertRaises(AdapterError):
                self._build(root, sources)

            finding = {"scanner": "pip_audit", "package": "pillow", "version": "1.0", "vulnerability_id": "CVE-TEST", "severity": "UNKNOWN"}
            identity = sha256(canonical_bytes(finding))
            disposition = {
                "finding_identity_sha256": identity,
                "disposition": "not_affected",
                "reason_code": "upstream_disputed",
                "evidence_sha256": "c" * 64,
                "expires_at": "2026-01-20T00:00:00Z",
                "approval_owner": "kimhw8084",
            }
            record = {"schema_version": "1.0", "policy_id": "kimhw8084-k-slide-security-release", "candidate_binding": {"subject_git_sha": SUBJECT, "source_tree_sha256": TREE, "deployment_fingerprint": DEPLOYMENT}, "dispositions": [disposition]}
            disposition_schema = json.loads(Path("schemas/vulnerability-dispositions.schema.json").read_text(encoding="utf-8"))
            Draft202012Validator(disposition_schema).validate(record)
            _write(sources["vulnerability_dispositions"], record)
            result = self._build(root, sources)
            self.assertEqual(result["payload"]["security_release"]["vulnerability_disposition_count"], 1)

            context = json.loads(sources["security_release_context"].read_text(encoding="utf-8"))
            context["candidate"]["source_tree_sha256"] = "e" * 64
            context["runtime"]["source_tree_sha256"] = "e" * 64
            _write(sources["security_release_context"], context)
            with self.assertRaises(AdapterError):
                self._build(root, sources)

    def test_low_severity_container_vulnerability_requires_valid_expiring_disposition(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = self._sources(root)
            scan = json.loads(sources["container_scan"].read_text(encoding="utf-8"))
            scan["scanned_classes"] = ["lang-pkgs", "os-pkgs"]
            scan["vulnerabilities"] = [{"package": "libfoo", "version": "1.0", "vulnerability_id": "CVE-2026-1234", "severity": "MEDIUM", "fixed_version": "1.1"}]
            _write(sources["container_scan"], scan)
            context = json.loads(sources["security_release_context"].read_text(encoding="utf-8"))
            scanner = next(item for item in context["scanners"] if item["id"] == "trivy")
            scanner["finding_count"] = 1
            scanner["report_sha256"] = sha256(sources["container_scan"].read_bytes())
            _write(sources["security_release_context"], context)
            with self.assertRaises(AdapterError):
                self._build(root, sources)

            finding = {"scanner": "trivy", "package": "libfoo", "version": "1.0", "vulnerability_id": "CVE-2026-1234", "severity": "MEDIUM"}
            disposition = {"finding_identity_sha256": sha256(canonical_bytes(finding)), "disposition": "accepted_risk", "reason_code": "temporary_low_severity_exception", "evidence_sha256": "e" * 64, "expires_at": "2026-01-20T00:00:00Z", "approval_owner": "kimhw8084"}
            record = {"schema_version": "1.0", "policy_id": "kimhw8084-k-slide-security-release", "candidate_binding": {"subject_git_sha": SUBJECT, "source_tree_sha256": TREE, "deployment_fingerprint": DEPLOYMENT}, "dispositions": [disposition]}
            _write(sources["vulnerability_dispositions"], record)
            result = self._build(root, sources)
            self.assertEqual(result["payload"]["security_release"]["unresolved_vulnerability_count"], 0)

            record["dispositions"][0]["expires_at"] = "2026-03-01T00:00:00Z"
            _write(sources["vulnerability_dispositions"], record)
            with self.assertRaises(AdapterError):
                self._build(root, sources)

    def test_scanner_report_projection_drops_secret_paths_and_source_payloads(self):
        canary = "AKIA" + ("Z" * 16)
        with self.assertRaises(SecurityReportError):
            sanitize_pip_audit({"dependencies": [{"name": "libfoo", "version": "1.0"}]})
        self.assertEqual(sanitize_gitleaks([{"Secret": canary, "File": "private/customer.pptx", "Line": 4}]), [{"finding": True}])
        semgrep = sanitize_semgrep({"results": [{"path": "private/customer.py", "start": {"line": 4}, "extra": {"message": canary, "lines": "private payload", "metadata": {"severity": "HIGH"}}}], "errors": []})
        self.assertEqual(semgrep, {"results": [{"extra": {"metadata": {"severity": "HIGH"}}}], "errors": []})
        target_digest = "sha256:" + "a" * 64
        raw_report = {"SchemaVersion": 2, "Metadata": {"ImageID": target_digest}, "Results": [{"Class": "os-pkgs", "Packages": [{"Name": "libfoo", "Version": "1.0"}], "Errors": [], "Vulnerabilities": [{"PkgName": "libfoo", "InstalledVersion": "1.0", "VulnerabilityID": "CVE-2026-1234", "Severity": "MEDIUM", "FixedVersion": "1.1", "Title": canary, "PrimaryURL": "https://internal.invalid"}]}, {"Class": "lang-pkgs", "Packages": [{"Name": "pillow", "Version": "1.0"}], "Errors": [], "Vulnerabilities": []}]}
        trivy = sanitize_trivy(raw_report, target_image_digest=target_digest, database={"UpdatedAt": "2026-01-01T00:00:00Z", "Version": 1})
        serialized = json.dumps(trivy)
        self.assertNotIn(canary, serialized)
        self.assertNotIn("internal.invalid", serialized)
        self.assertEqual(trivy["vulnerabilities"][0]["vulnerability_id"], "CVE-2026-1234")
        with self.assertRaises(SecurityReportError):
            sanitize_trivy({**raw_report, "Metadata": {"ImageID": "sha256:" + "b" * 64}}, target_image_digest=target_digest, database={"UpdatedAt": "2026-01-01T00:00:00Z", "Version": 1})
        # Trivy omits empty findings arrays. Package inventory for every class
        # is the completeness proof that makes this safe to interpret as zero.
        omitted_inventory = json.loads(json.dumps(raw_report))
        omitted_inventory["Results"][0]["Vulnerabilities"] = []
        del omitted_inventory["Results"][0]["Vulnerabilities"]
        del omitted_inventory["Results"][1]["Vulnerabilities"]
        self.assertEqual(
            sanitize_trivy(omitted_inventory, target_image_digest=target_digest, database={"UpdatedAt": "2026-01-01T00:00:00Z", "Version": 1})["vulnerabilities"],
            [],
        )
        omitted_inventory = json.loads(json.dumps(raw_report))
        del omitted_inventory["Results"][1]["Packages"]
        with self.assertRaises(SecurityReportError):
            sanitize_trivy(omitted_inventory, target_image_digest=target_digest, database={"UpdatedAt": "2026-01-01T00:00:00Z", "Version": 1})


if __name__ == "__main__":
    unittest.main()
