from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from evals.release import derive_release_state, main as release_main
from k_slide.certification import (
    EvidenceValidationError,
    build_deployment_factors,
    certification_fingerprint,
    deployment_fingerprint,
    load_evidence,
    write_evidence,
)
from k_slide.evidence_adapters import AdapterError, build_machine_evidence
from k_slide.model_policy import load_model_policy
from k_slide.production import _asset_manifest_status


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write(path: Path, value: object) -> Path:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


def _runtime_sources(root: Path) -> dict[str, Path]:
    _write(root / "diagnostic.json", {"levels": [{"level": name, "status": "PASS"} for name in ("level1a_pure_opencode", "level1_plain_opencode", "level2_explicit_model", "level3_k_slide_agent")]})
    contract = {"status": "PASS", "kslide_complete": True, "run_complete": True, "required_media_compliance": True, "forbidden_tool_attempts": []}
    _write(root / "simple.json", contract)
    _write(root / "three.json", {**contract, "expected_units": 3, "artifact_units": 3})
    _write(root / "five.json", {**contract, "expected_units": 5, "artifact_units": 5})
    return {"diagnostic_ladder": root / "diagnostic.json", "simple_run": root / "simple.json", "three_slide": root / "three.json", "five_slide": root / "five.json"}


def _doctor(networkless: bool = False) -> dict[str, object]:
    value = {key: {"status": "PASS"} for key in ("libreoffice", "pymupdf", "python_pptx", "pillow", "paddleocr", "paddlepaddle", "korean_font", "paddle_load", "libreoffice_roundtrip", "paddle_ocr_roundtrip")}
    value["network"] = {"networkless_asserted": networkless, "network_required": not networkless}
    return value


def _heavy_sources(root: Path, *, full: bool = False) -> dict[str, Path]:
    _write(root / "doctor.json", _doctor())
    _write(root / "networkless.json", _doctor(networkless=True))
    engine = {"engine": {"critical_failure_count": 0, "capability_block_count": 0, "artifact_generation_pass_rate": 1.0, "engine_normalization_pass_rate": 1.0, "evidence_generation_pass_rate": 1.0}}
    _write(root / "representative.json", engine)
    sources = {"required_doctor": root / "doctor.json", "networkless_doctor": root / "networkless.json", "representative_engine": root / "representative.json"}
    if full:
        _write(root / "full.json", engine)
        sources["full_engine"] = root / "full.json"
    return sources


def _model_sources(root: Path, split: str = "validation", critical: int = 0, repeats: int = 3) -> dict[str, Path]:
    rows = []
    categories = ("financial_table", "modality_decision_state", "chart", "process_diagram", "visual_degradation", "simple_mixed_text")
    for category in categories:
        for repeat in range(1, repeats + 1):
            rows.append({"scenario_id": category, "category": category, "split": split, "format": "png", "repeat": repeat, "semantic_scored": True, "quality_metrics_authoritative": True, "semantic": {"critical_failures": (["CRITICAL"] if critical else []), "unresolved_region_rate": 0.0, "unexpected_unresolved_rate": 0.0}, "media_by_work_unit": {"u1": {"media_sequence_valid": True}}, "opencode": {"model": "google/gemma-4-31b-it", "diagnostics": {"effective_model": "google/gemma-4-31b-it"}}})
    (root / "results.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    summary = {"model": "google/gemma-4-31b-it", "requested_model": "google/gemma-4-31b-it", "split": split, "quality_metrics_authoritative": True, "corpus_fingerprint": "698b471fa9dffe9f79af40a61c3546d6455889b90063a02bc2e270b90402f7ac", "held_out_fingerprint": "c2dee1ba1b03fead1a6641cfa8c7ceea27eb51b0ed80c0879c07bc3ee29bcc4e"}
    _write(root / "summary.json", summary)
    _write(root / "experiment.json", {"model": "google/gemma-4-31b-it", "split": split, "repetitions": repeats, "configuration_hash": "c" * 64, "corpus_fingerprint": summary["corpus_fingerprint"], "held_out_fingerprint": summary["held_out_fingerprint"]})
    return {"model_summary": root / "summary.json", "experiment_manifest": root / "experiment.json", "results_jsonl": root / "results.jsonl"}


def _security_sources(root: Path, *, vulnerable: bool = False) -> dict[str, Path]:
    _write(root / "pip-audit.json", {"dependencies": [{"name": "demo", "vulns": ([{"id": "CVE-TEST"}] if vulnerable else [])}]})
    _write(root / "gitleaks.json", [])
    _write(root / "semgrep.json", {"results": []})
    _write(root / "scanner-exits.json", {"pip_audit": 0, "gitleaks": 0, "semgrep": 0})
    return {"pip_audit": root / "pip-audit.json", "gitleaks": root / "gitleaks.json", "semgrep": root / "semgrep.json", "scanner_exits": root / "scanner-exits.json"}


def _reliability_sources(root: Path) -> dict[str, Path]:
    _write(root / "failure.json", {"status": "PASS", "resume_pass": True})
    _write(root / "concurrency.json", {"status": "PASS", "concurrent_runs": 5})
    _write(root / "large.json", {"status": "PASS", "fifty_slide_pass": True})
    _write(root / "slo.json", {"status": "PASS", "slo_pass": True})
    return {"failure_injection": root / "failure.json", "concurrency": root / "concurrency.json", "large_deck": root / "large.json", "performance_slo": root / "slo.json"}


class CertificationClosureTests(unittest.TestCase):
    def test_machine_evidence_is_derived_and_exactly_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = _runtime_sources(root)
            envelope = root / "runtime.evidence.json"
            build_machine_evidence(envelope, evidence_type="runtime", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources)
            loaded = load_evidence(envelope, expected_type="runtime", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64)
            self.assertEqual(loaded["evidence_type"], "runtime")
            self.assertEqual(len(loaded["sources"]), 4)
            with self.assertRaises(EvidenceValidationError):
                load_evidence(envelope, expected_type="heavy_runtime", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64)

    def test_contradictory_machine_payload_fails_even_with_correct_source_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            envelope = root / "runtime.evidence.json"
            build_machine_evidence(envelope, evidence_type="runtime", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=_runtime_sources(root))
            value = json.loads(envelope.read_text(encoding="utf-8"))
            value["payload"]["runtime_pass"] = False
            envelope.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(EvidenceValidationError):
                load_evidence(envelope, expected_type="runtime", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64)

    def test_result_tamper_and_envelope_tamper_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            envelope = root / "runtime.evidence.json"
            build_machine_evidence(envelope, evidence_type="runtime", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=_runtime_sources(root))
            (root / "simple.json").write_text("{}", encoding="utf-8")
            with self.assertRaises(EvidenceValidationError):
                load_evidence(envelope, expected_type="runtime", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64)
            build_machine_evidence(envelope, evidence_type="runtime", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=_runtime_sources(root))
            value = json.loads(envelope.read_text(encoding="utf-8"))
            value["payload"]["five_slide_pass"] = False
            envelope.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(EvidenceValidationError):
                load_evidence(envelope, expected_type="runtime", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64)

    def test_wrong_result_type_and_missing_sources_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "runtime.json", evidence_type="runtime", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources={"model_summary": root / "missing"})

    def test_heavy_evidence_requires_networkless_and_representation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "heavy.json"
            build_machine_evidence(path, evidence_type="heavy_runtime", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=_heavy_sources(root))
            self.assertTrue(load_evidence(path, expected_type="heavy_runtime")["payload"]["networkless_pass"])

    def test_model_validation_rejects_critical_result(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "validation.json", evidence_type="model_validation", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=_model_sources(root, critical=1), root=Path.cwd())

    def test_model_validation_rejects_wrong_split_and_non_target_model(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "wrong-split.json", evidence_type="model_validation", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=_model_sources(root, split="held_out"), root=Path.cwd())
            sources = _model_sources(root)
            for path in sources.values():
                text = path.read_text(encoding="utf-8")
                path.write_text(text.replace("google/gemma-4-31b-it", "qwen/qwen3"), encoding="utf-8")
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "wrong-model.json", evidence_type="model_validation", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources, root=Path.cwd())

    def test_high_risk_insufficient_repeats_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "high-risk.json", evidence_type="model_high_risk_stability", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=_model_sources(root, repeats=4), root=Path.cwd())

    def test_security_evidence_is_derived_from_scanner_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "security.json"
            build_machine_evidence(path, evidence_type="security", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=_security_sources(root))
            self.assertTrue(load_evidence(path, expected_type="security")["payload"]["secret_scan_pass"])
            _security_sources(root, vulnerable=True)
            with self.assertRaises(EvidenceValidationError):
                load_evidence(path, expected_type="security")

    def test_reliability_requires_actual_concurrency_result(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "reliability.json"
            build_machine_evidence(path, evidence_type="reliability", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=_reliability_sources(root))
            self.assertEqual(load_evidence(path, expected_type="reliability")["payload"]["concurrent_runs"], 5)

    def test_governance_requires_authoritative_api_not_codeowners_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "governance.json"
            _write(source, {"source_kind": "codeowners", "codeowners_pass": True, "branch_protection_pass": True, "required_ci_pass": True, "review_required": True})
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "governance-envelope.json", evidence_type="governance", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources={"governance_api": source})

    def test_temporary_runtime_heavy_chain_derives_gemma_eval_ready(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subject = "a" * 40
            deployment = deployment_fingerprint(build_deployment_factors(root, subject_git_sha=subject, model_policy=load_model_policy(root)))
            runtime_path = root / "runtime-envelope.json"
            heavy_path = root / "heavy-envelope.json"
            build_machine_evidence(runtime_path, evidence_type="runtime", subject_git_sha=subject, deployment_fingerprint=deployment, sources=_runtime_sources(root))
            build_machine_evidence(heavy_path, evidence_type="heavy_runtime", subject_git_sha=subject, deployment_fingerprint=deployment, sources=_heavy_sources(root))
            records = {"runtime": load_evidence(runtime_path, expected_type="runtime", subject_git_sha=subject, deployment_fingerprint=deployment), "heavy_runtime": load_evidence(heavy_path, expected_type="heavy_runtime", subject_git_sha=subject, deployment_fingerprint=deployment)}
            state, blockers = derive_release_state("GEMMA_EVAL_READY", records=records, root=root, policy=load_model_policy(root), deployment_fp=deployment)
            self.assertEqual(state, "GEMMA_EVAL_READY")
            self.assertEqual(blockers, [])

    def test_temporary_machine_and_attestation_chain_derives_internal_validated(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subject = "a" * 40
            deployment = deployment_fingerprint(build_deployment_factors(root, subject_git_sha=subject, model_policy=load_model_policy(root)))
            records = {}
            for evidence_type, source_factory in (("runtime", _runtime_sources), ("heavy_runtime", _heavy_sources)):
                folder = root / evidence_type
                folder.mkdir()
                sources = source_factory(folder, full=evidence_type == "heavy_runtime") if evidence_type == "heavy_runtime" else source_factory(folder)
                envelope = folder / "evidence.json"
                build_machine_evidence(envelope, evidence_type=evidence_type, subject_git_sha=subject, deployment_fingerprint=deployment, sources=sources)
                records[evidence_type] = load_evidence(envelope, expected_type=evidence_type, subject_git_sha=subject, deployment_fingerprint=deployment, repository_root=root)
            model_records = {}
            for evidence_type, split, repeats in (("model_validation", "validation", 3), ("model_high_risk_stability", "validation", 5), ("model_held_out", "held_out", 3)):
                folder = root / evidence_type
                folder.mkdir()
                source = _model_sources(folder, split=split, repeats=repeats)
                if evidence_type == "model_held_out":
                    summary = json.loads((folder / "summary.json").read_text(encoding="utf-8"))
                    _write(folder / "summary.json", {**summary, "corpus_fingerprint": "698b471fa9dffe9f79af40a61c3546d6455889b90063a02bc2e270b90402f7ac", "held_out_fingerprint": "c2dee1ba1b03fead1a6641cfa8c7ceea27eb51b0ed80c0879c07bc3ee29bcc4e"})
                envelope = folder / "evidence.json"
                build_machine_evidence(envelope, evidence_type=evidence_type, subject_git_sha=subject, deployment_fingerprint=deployment, sources=source, root=Path.cwd())
                model_records[evidence_type] = load_evidence(envelope, expected_type=evidence_type, subject_git_sha=subject, deployment_fingerprint=deployment, repository_root=Path.cwd())
            (root / "evals").mkdir()
            _write(root / "evals" / "champion.json", {"status": "FROZEN", "model": "google/gemma-4-31b-it", "effective_model": "google/gemma-4-31b-it", "deployment_fingerprint": deployment, "config_hash": "c" * 64})
            records.update(model_records)
            payloads = {
                "internal_bilingual": {"attestation_id": "internal-test", "artifact_count": 50, "work_unit_count": 200, "critical_business_meaning_errors": 0, "critical_numeric_date_unit_errors": 0, "critical_modality_escalations": 0, "critical_table_mapping_errors": 0, "critical_trend_reversals": 0, "unsupported_critical_executive_claims": 0, "overall_noncritical_semantic_fidelity": 0.99, "locked_terminology": 0.999},
                "zero_korean_comprehension": {"attestation_id": "human-test", "users": 10, "answers": 100, "critical_question_accuracy": 1.0, "overall_comprehension": 0.95, "critical_misunderstanding": 0},
                "model_data_policy": {"attestation_id": "policy-test", "approved_for_internal_artifacts": True},
            }
            for evidence_type, payload in payloads.items():
                folder = root / evidence_type
                folder.mkdir()
                path = folder / "evidence.json"
                write_evidence(path, evidence_type=evidence_type, subject_git_sha=subject, deployment_fingerprint=deployment, payload=payload, generated_at="2026-09-09T00:00:00Z")
                records[evidence_type] = load_evidence(path, expected_type=evidence_type, subject_git_sha=subject, deployment_fingerprint=deployment, repository_root=root)
            state, blockers = derive_release_state("INTERNAL_VALIDATED", records=records, root=root, policy=load_model_policy(root), deployment_fp=deployment)
            self.assertEqual(state, "INTERNAL_VALIDATED")
            self.assertEqual(blockers, [])

    def test_deterministic_evidence_identity_excludes_generated_at(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = _runtime_sources(root)
            first = root / "first.json"
            second = root / "second.json"
            build_machine_evidence(first, evidence_type="runtime", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources, generated_at="2026-01-01T00:00:00Z")
            build_machine_evidence(second, evidence_type="runtime", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources, generated_at="2026-01-02T00:00:00Z")
            self.assertEqual(load_evidence(first)["evidence_identity"], load_evidence(second)["evidence_identity"])

    def test_deployment_and_certification_fingerprints_change_with_material_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = build_deployment_factors(root, subject_git_sha="a" * 40, model_policy=load_model_policy(root))
            second = build_deployment_factors(root, subject_git_sha="b" * 40, model_policy=load_model_policy(root))
            self.assertNotEqual(deployment_fingerprint(first), deployment_fingerprint(second))
            deployment = deployment_fingerprint(first)
            self.assertNotEqual(certification_fingerprint(deployment=deployment, evidence_hashes={"runtime": "a" * 64}, release_state="RUNTIME_READY"), certification_fingerprint(deployment=deployment, evidence_hashes={"runtime": "b" * 64}, release_state="RUNTIME_READY"))

    def test_approved_prefix_is_not_model_policy_approval(self):
        self.assertFalse(load_model_policy(Path.cwd()).approved(requested="approved:internal", effective="approved:internal"))

    def test_production_checks_reject_wrong_model_identity(self):
        from k_slide.production import production_checks
        from k_slide.runtime import RuntimeMetadata

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".k-slide-config").mkdir()
            _write(root / ".k-slide-config" / "production-profile.json", {"schema_version": "1.0", "release_state": "PRODUCTION_CERTIFIED", "opencode_version": "1.3.9", "requested_model": "approved:internal", "effective_model": "approved:internal", "ocr_provider": "paddle", "ocr_asset_manifest": "manifest.json", "python_version": "3.11", "paddle_version": "3.0.0", "paddleocr_version": "3.0.3", "libreoffice_version": "25", "retention_days": 30, "tenant_isolation": "workspace_per_session", "network_egress": "approved_inference_only", "subject_git_sha": "a" * 40, "deployment_fingerprint": "b" * 64, "certification_fingerprint": "c" * 64, "release_manifest": "manifest.json", "release_manifest_sha256": "d" * 64, "model_data_attestation": "attestation-1"})
            runtime = RuntimeMetadata(kslide_version="0.3.5", opencode_version="1.3.9", opencode_path=None, opencode_config_path=None, provider="internal", reported_model_id="approved:internal", model_family=None, model_size=None, instruction_tuned_status="unknown", vision_support=True, thinking_support=None, provider_backend=None, quantization_or_dtype=None, context_configuration={}, image_preprocessing_settings={}, model_compatibility="production_candidate", discovery_warnings=[])
            policy_check = next(item for item in production_checks(root, runtime) if item["label"] == "Requested/effective model policy")
            self.assertEqual(policy_check["status"], "FAIL")

    def test_asset_manifest_requires_content_hash_and_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            asset = root / "weights.bin"
            asset.write_bytes(b"weights-v1")
            manifest = root / "manifest.json"
            _write(manifest, {"provider": "paddle", "files": [{"path": "weights.bin", "sha256": _sha(asset)}]})
            self.assertTrue(_asset_manifest_status(manifest)[0])
            asset.write_bytes(b"tampered")
            self.assertFalse(_asset_manifest_status(manifest)[0])
            target = Path(outside) / "private.bin"
            target.write_bytes(b"private")
            asset.unlink()
            asset.symlink_to(target)
            self.assertFalse(_asset_manifest_status(manifest)[0])

    def test_release_cli_blocks_requested_certified_without_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "manifest.json"
            result = release_main(["--root", str(root), "--output", str(output), "--requested-state", "PRODUCTION_CERTIFIED", "--require-certified"])
            self.assertEqual(result, 2)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
