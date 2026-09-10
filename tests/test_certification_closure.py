from __future__ import annotations

import hashlib
import json
import platform
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from evals.release import build_production_sbom, build_release_manifest, derive_release_state, main as release_main
from evals.experiments import behavior_configuration_hash, experiment_plan, experiment_plan_hash
from evals.scenarios import PROTECTED_CATEGORIES, scenario_specs
from k_slide.certification import (
    EvidenceValidationError,
    NOT_APPLICABLE_VALUE,
    NOT_EXPOSED_VALUE,
    build_deployment_factors,
    canonical_dependency_inventory,
    candidate_completeness,
    candidate_deployment_fingerprint,
    canonical_candidate_factors,
    certification_fingerprint,
    dependency_lock_text,
    deployment_fingerprint,
    effective_termbase_identity,
    load_candidate_spec,
    load_evidence,
    resolve_candidate_spec,
    dependency_inventory_hash,
    load_dependency_lock,
    repository_schema_versions,
    validate_cyclonedx_1_5,
    write_evidence,
)
from k_slide.evidence_adapters import AdapterError, build_machine_evidence, enforce_security_scanners
from k_slide.model_policy import load_model_policy
from k_slide.production import ProductionProfile, _asset_manifest_status, _manifest_and_fingerprint_status


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


TEST_PYTHON_VERSION = platform.python_version()


def _write(path: Path, value: object) -> Path:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


def _runtime_sources(root: Path, *, provider: str = "google", ocr_provider: str = "none") -> dict[str, Path]:
    _write(root / "diagnostic.json", {"levels": [{"level": name, "status": "PASS"} for name in ("level1a_pure_opencode", "level1_plain_opencode", "level2_explicit_model", "level3_k_slide_agent")], "runtime_provenance": {"opencode_version": "1.3.9", "python_version": TEST_PYTHON_VERSION, "provider": provider, "ocr_provider": ocr_provider}})
    contract = {"status": "PASS", "kslide_complete": True, "run_complete": True, "required_media_compliance": True, "forbidden_tool_attempts": []}
    _write(root / "simple.json", contract)
    _write(root / "three.json", {**contract, "expected_units": 3, "artifact_units": 3})
    _write(root / "five.json", {**contract, "expected_units": 5, "artifact_units": 5})
    return {"diagnostic_ladder": root / "diagnostic.json", "simple_run": root / "simple.json", "three_slide": root / "three.json", "five_slide": root / "five.json"}


def _doctor(networkless: bool = False) -> dict[str, object]:
    value = {key: {"status": "PASS"} for key in ("libreoffice", "pymupdf", "python_pptx", "pillow", "paddleocr", "paddlepaddle", "korean_font", "paddle_load", "libreoffice_roundtrip", "paddle_ocr_roundtrip")}
    value["network"] = {"networkless_asserted": networkless, "network_required": not networkless}
    value["runtime_provenance"] = {"python_version": TEST_PYTHON_VERSION, "paddle_version": "3.0.0", "paddleocr_version": "3.0.3", "libreoffice_version": "25.2.3"}
    return value


def _heavy_sources(root: Path, *, full: bool = False, subject: str | None = None, deployment: str | None = None) -> dict[str, Path]:
    _write(root / "doctor.json", _doctor())
    _write(root / "networkless.json", _doctor(networkless=True))
    engine = {"engine": {"critical_failure_count": 0, "capability_block_count": 0, "artifact_generation_pass_rate": 1.0, "engine_normalization_pass_rate": 1.0, "evidence_generation_pass_rate": 1.0}}
    _write(root / "representative.json", engine)
    packages = canonical_dependency_inventory([{"name": name, "version": "1.0"} for name in ("Pillow", "PyMuPDF", "python-pptx", "paddlepaddle", "paddleocr")])
    _write(root / "production-inventory.json", packages)
    (root / "production.lock").write_text(dependency_lock_text(packages), encoding="utf-8")
    _write(root / "built-image-inventory.json", packages)
    dependency_hash = dependency_inventory_hash(packages)
    context = {"schema_version": "1.0", "dependency_subject": "production-env", "expected_dependency_set_sha256": dependency_hash, "frozen_dependency_set_sha256": dependency_hash, "built_image_dependency_set_sha256": dependency_hash, "production_lock_sha256": _sha(root / "production.lock")}
    if subject is not None:
        context["subject_git_sha"] = subject
    if deployment is not None:
        context["deployment_fingerprint"] = deployment
    _write(root / "dependency-context.json", context)
    sources = {"required_doctor": root / "doctor.json", "networkless_doctor": root / "networkless.json", "representative_engine": root / "representative.json", "production_inventory": root / "production-inventory.json", "production_lock": root / "production.lock", "built_image_inventory": root / "built-image-inventory.json", "dependency_context": root / "dependency-context.json"}
    if full:
        _write(root / "full.json", engine)
        sources["full_engine"] = root / "full.json"
    return sources


def _model_sources(root: Path, split: str = "validation", critical: int = 0, repeats: int = 3, *, subject: str = "a" * 40, deployment: str = "b" * 64) -> dict[str, Path]:
    rows = []
    frozen = scenario_specs()
    high_risk = repeats >= 4
    if high_risk:
        selected = []
        for category in PROTECTED_CATEGORIES:
            selected.append(next(item for item in frozen if item.category == category and item.split == split))
    else:
        selected = [item for item in frozen if item.split == split]
    scenario_ids = [item.scenario_id for item in selected]
    formats = ["png"]
    for scenario in selected:
        for repeat in range(1, repeats + 1):
            rows.append({"scenario_id": scenario.scenario_id, "category": scenario.category, "split": split, "format": "png", "repeat": repeat, "subject_git_sha": subject, "deployment_fingerprint": deployment, "effective_model": "google/gemma-4-31b-it", "semantic_scored": True, "quality_metrics_authoritative": True, "semantic": {"critical_failures": (["CRITICAL"] if critical else []), "unresolved_region_rate": 0.0, "unexpected_unresolved_rate": 0.0, "term_consistency_recall": 1.0}, "media_by_work_unit": {"u1": {"media_sequence_valid": True}}, "opencode": {"model": "google/gemma-4-31b-it", "runtime_version": "1.3.9", "media_compliance": {"planned": True, "required_count": 1, "read_count": 1, "required_context_image_read": True, "media_sequence_valid": True}, "diagnostics": {"effective_model": "google/gemma-4-31b-it", "model_identity_proven": True}}})
    (root / "results.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    behavior = {"model": "google/gemma-4-31b-it", "ocr_provider": "none", "prompt_version": "test-v1", "generation_settings": {"temperature": 0}}
    behavior_hash = behavior_configuration_hash(behavior)
    plan = experiment_plan(split=split, scenario_ids=scenario_ids, formats=formats, repetitions=repeats, categories=(), timeout=180, mode="quality")
    plan_hash = experiment_plan_hash(plan)
    critical_count = len(rows) if critical else 0
    summary = {"model": "google/gemma-4-31b-it", "requested_model": "google/gemma-4-31b-it", "effective_model": "google/gemma-4-31b-it", "split": split, "quality_metrics_authoritative": True, "locked_terminology_recall": 1.0, "unexpected_unresolved_rate": 0.0, "critical_failure_count": critical_count, "required_media_compliance": True, "case_count": len(rows), "semantic_scored_case_count": len(rows), "repetitions": repeats, "subject_git_sha": subject, "deployment_fingerprint": deployment, "behavior_configuration_hash": behavior_hash, "configuration_hash": behavior_hash, "experiment_plan_hash": plan_hash, "corpus_fingerprint": "698b471fa9dffe9f79af40a61c3546d6455889b90063a02bc2e270b90402f7ac", "held_out_fingerprint": "c2dee1ba1b03fead1a6641cfa8c7ceea27eb51b0ed80c0879c07bc3ee29bcc4e"}
    _write(root / "summary.json", summary)
    experiment = {"model": "google/gemma-4-31b-it", "effective_model": "google/gemma-4-31b-it", "split": split, "repetitions": repeats, "scenario_ids": scenario_ids, "formats": formats, "categories": [], "configuration": behavior, "behavior_configuration": behavior, "behavior_configuration_hash": behavior_hash, "configuration_hash": behavior_hash, "experiment_plan": plan, "experiment_plan_hash": plan_hash, "subject_git_sha": subject, "deployment_fingerprint": deployment, "corpus_fingerprint": summary["corpus_fingerprint"], "held_out_fingerprint": summary["held_out_fingerprint"]}
    if high_risk:
        experiment["high_risk_categories"] = list(PROTECTED_CATEGORIES)
    _write(root / "experiment.json", experiment)
    return {"model_summary": root / "summary.json", "experiment_manifest": root / "experiment.json", "results_jsonl": root / "results.jsonl"}


def _security_sources(root: Path, *, vulnerable: bool = False, constraints_hash: str = "c" * 64) -> dict[str, Path]:
    packages = [{"name": name, "version": "1.0"} for name in ("Pillow", "PyMuPDF", "python-pptx", "paddlepaddle", "paddleocr")]
    inventory = canonical_dependency_inventory(packages)
    _write(root / "dependency-inventory.json", inventory)
    (root / "production-requirements.lock").write_text(dependency_lock_text(inventory), encoding="utf-8")
    build_production_sbom(root, root / "production-sbom.json", inventory_path=root / "dependency-inventory.json")
    validate_cyclonedx_1_5(json.loads((root / "production-sbom.json").read_text(encoding="utf-8")))
    _write(root / "pip-audit.json", {"dependencies": [{"name": name, "version": "1.0", "vulns": ([{"id": "CVE-TEST"}] if vulnerable and name == "Pillow" else [])} for name in ("Pillow", "PyMuPDF", "python-pptx", "paddlepaddle", "paddleocr")]})
    _write(root / "gitleaks.json", [])
    _write(root / "semgrep.json", {"results": [], "errors": []})
    _write(root / "scanner-exits.json", {"pip_audit": 0, "gitleaks": 0, "semgrep": 0})
    versions = {"Pillow": "1.0", "PyMuPDF": "1.0", "python-pptx": "1.0", "paddlepaddle": "1.0", "paddleocr": "1.0"}
    ruleset = Path.cwd() / "security" / "semgrep-production.yml"
    ruleset_hash = _sha(ruleset) if ruleset.is_file() else "a" * 64
    staged_ruleset = root / "semgrep-production.yml"
    if ruleset.is_file():
        staged_ruleset.write_bytes(ruleset.read_bytes())
    else:
        staged_ruleset.write_text("rules: []\n", encoding="utf-8")
    inventory_sha = dependency_inventory_hash(inventory)
    _write(root / "audit-context.json", {"schema_version": "1.0", "audited_dependency_subject": "production-env", "audited_dependency_set_sha256": inventory_sha, "resolved_dependency_set_sha256": inventory_sha, "resolved_dependency_lock_sha256": _sha(root / "production-requirements.lock"), "production_sbom_sha256": _sha(root / "production-sbom.json"), "candidate_constraints_sha256": constraints_hash, "audited_dependency_names": list(versions), "constraint_versions": versions, "pip_audit_version": "pip-audit 2.9.0", "semgrep_version": "semgrep 1.89.0", "semgrep_ruleset_identity": "security/semgrep-production.yml", "semgrep_ruleset_sha256": ruleset_hash})
    return {"pip_audit": root / "pip-audit.json", "gitleaks": root / "gitleaks.json", "semgrep": root / "semgrep.json", "scanner_exits": root / "scanner-exits.json", "audit_context": root / "audit-context.json", "semgrep_ruleset": staged_ruleset, "dependency_inventory": root / "dependency-inventory.json", "production_lock": root / "production-requirements.lock", "production_sbom": root / "production-sbom.json"}


def _reliability_sources(root: Path) -> dict[str, Path]:
    _write(root / "failure.json", {"status": "PASS", "timeout_recovery_pass": True, "resume_pass": True})
    _write(root / "concurrency.json", {"status": "PASS", "concurrency_pass": True, "concurrent_runs": 5})
    _write(root / "large.json", {"status": "PASS", "fifty_slide_pass": True})
    _write(root / "slo.json", {"status": "PASS", "slo_pass": True})
    return {"failure_injection": root / "failure.json", "concurrency": root / "concurrency.json", "large_deck": root / "large.json", "performance_slo": root / "slo.json"}


def _candidate_spec(subject: str, *, ocr_provider: str = "none", effective_model: str = "google/gemma-4-31b-it", asset_manifest: str = "UNSET", asset_hash: str = "UNSET", root: Path | None = None) -> dict[str, object]:
    target = "google/gemma-4-31b-it"
    behavior = {
        "model": target,
        "ocr_provider": ocr_provider,
        "prompt_version": "translation/v1",
        "generation_settings": {"temperature": 0.1},
        "normalization_behavior": {"render_dpi": 220},
        "repair_policy": {"max_auto_repairs_per_unit": 2},
    }
    split = __import__("evals.scenarios", fromlist=["split_manifest"]).split_manifest()
    candidate = {
        "candidate_spec_version": "1.0",
        "subject_git_sha": subject,
        "kslide_version": "0.3.5",
        "opencode_version": "1.3.9",
        "requested_model": target,
        "effective_model": effective_model,
        "provider": "google",
        "provider_backend": NOT_EXPOSED_VALUE,
        "model_revision": NOT_EXPOSED_VALUE,
        "quantization_or_dtype": NOT_EXPOSED_VALUE,
        "vision_settings": {"enabled": True},
        "context_configuration": {"bounded_work_unit": True},
        "image_preprocessing_settings": {"dpi": 220},
        "prompt_identity": {"version": "translation/v1", "hash": "UNSET"},
        "generation_settings": {"temperature": 0.1},
        "ocr_provider": ocr_provider,
        "ocr_asset_manifest": asset_manifest,
        "ocr_asset_manifest_sha256": asset_hash,
        "normalization_behavior": {"render_dpi": 220},
        "repair_policy": {"max_auto_repairs_per_unit": 2},
        "python_version": TEST_PYTHON_VERSION,
        "paddle_version": "3.0.0",
        "paddleocr_version": "3.0.3",
        "libreoffice_version": "25.2.3",
        "termbase_identity": {"version": "1.0", "hash": "UNSET"},
        "termbase_version": "1.0",
        "termbase_hash": "UNSET",
        "model_policy": load_model_policy().as_dict(),
        "schema_versions": {"evidence_ir": "1.0", "translation_patch": "1.0", "slide_ir": "1.0"},
        "retention_days": 30,
        "tenant_isolation": "workspace_per_session",
        "network_egress": "approved_inference_only",
        "corpus_identity": {"version": "1.0", "corpus_fingerprint": split["corpus_fingerprint"], "held_out_fingerprint": split["held_out_fingerprint"]},
        "constraints_sha256": "UNSET",
        "behavior_configuration": behavior,
    }
    return resolve_candidate_spec(candidate, root=root or Path.cwd(), subject_git_sha=subject, model_policy=load_model_policy(), corpus=candidate["corpus_identity"])  # type: ignore[arg-type]


def _candidate_model_sources(root: Path, *, split: str, repeats: int, subject: str, deployment: str, candidate: dict[str, object]) -> dict[str, Path]:
    sources = _model_sources(root, split=split, repeats=repeats, subject=subject, deployment=deployment)
    behavior = candidate["behavior_configuration"]
    behavior_hash = behavior_configuration_hash(behavior)  # type: ignore[arg-type]
    factors = canonical_candidate_factors(candidate)  # type: ignore[arg-type]
    summary_path = sources["model_summary"]
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary.update({"candidate_spec": factors, "effective_model": candidate["effective_model"], "behavior_configuration_hash": behavior_hash, "configuration_hash": behavior_hash})
    _write(summary_path, summary)
    experiment_path = sources["experiment_manifest"]
    experiment = json.loads(experiment_path.read_text(encoding="utf-8"))
    experiment.update({"candidate_spec": factors, "candidate_identity_status": "FINAL", "effective_model": candidate["effective_model"], "behavior_configuration": behavior, "configuration": behavior, "behavior_configuration_hash": behavior_hash, "configuration_hash": behavior_hash, "execution_runtime_provenance": {"opencode_version": candidate["opencode_version"], "provider": candidate["provider"], "ocr_provider": candidate["ocr_provider"]}})
    _write(experiment_path, experiment)
    rows_path = sources["results_jsonl"]
    rows = [json.loads(line) for line in rows_path.read_text(encoding="utf-8").splitlines()]
    for row in rows:
        row.update({"subject_git_sha": subject, "deployment_fingerprint": deployment, "effective_model": candidate["effective_model"]})
    rows_path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    return sources


class CertificationClosureTests(unittest.TestCase):
    def test_repository_execution_binding_rejects_wrong_material_behavior(self):
        base = _candidate_spec("a" * 40)
        cases = (
            ("generation_settings", {"temperature": 0.2}),
            ("image_preprocessing_settings", {"dpi": 221}),
            ("vision_settings", {"enabled": False}),
            ("repair_policy", {"max_auto_repairs_per_unit": 3}),
            ("normalization_behavior", {"render_dpi": 221}),
            ("prompt_version", "translation/v2"),
            ("termbase_version", "2.0"),
        )
        for field, value in cases:
            with self.subTest(field=field):
                candidate = json.loads(json.dumps(base))
                candidate[field] = value
                if field in {"generation_settings", "repair_policy", "normalization_behavior"}:
                    candidate["behavior_configuration"][field] = value
                with self.assertRaises(EvidenceValidationError):
                    resolve_candidate_spec(candidate, root=Path.cwd(), subject_git_sha="a" * 40, model_policy=load_model_policy(), corpus=candidate["corpus_identity"], require_sources=True)
        metadata_only = json.loads(json.dumps(base))
        metadata_only["behavior_configuration"]["provider_defaults_frozen"] = True
        with self.assertRaises(EvidenceValidationError):
            resolve_candidate_spec(metadata_only, root=Path.cwd(), subject_git_sha="a" * 40, model_policy=load_model_policy(), corpus=metadata_only["corpus_identity"], require_sources=True)
        metadata_only = json.loads(json.dumps(base))
        metadata_only["behavior_configuration"]["thinking"] = True
        with self.assertRaises(EvidenceValidationError):
            resolve_candidate_spec(metadata_only, root=Path.cwd(), subject_git_sha="a" * 40, model_policy=load_model_policy(), corpus=metadata_only["corpus_identity"], require_sources=True)
        unresolved_image = json.loads(json.dumps(base))
        unresolved_image["image_preprocessing_settings"] = {"source": "not_yet_configured"}
        with self.assertRaises(EvidenceValidationError):
            resolve_candidate_spec(unresolved_image, root=Path.cwd(), subject_git_sha="a" * 40, model_policy=load_model_policy(), corpus=unresolved_image["corpus_identity"], require_sources=True)

    def test_schema_identity_is_derived_and_explicit_drift_is_rejected(self):
        candidate = _candidate_spec("a" * 40)
        candidate["schema_versions"] = {}
        resolved = resolve_candidate_spec(candidate, root=Path.cwd(), subject_git_sha="a" * 40, model_policy=load_model_policy(), corpus=candidate["corpus_identity"])
        self.assertEqual(resolved["schema_versions"], repository_schema_versions())
        for value in ({"evidence_ir": "9.0", "translation_patch": "1.0", "slide_ir": "1.0"}, {"evidence_ir": "1.0", "translation_patch": "1.0"}):
            with self.subTest(value=value), self.assertRaises(EvidenceValidationError):
                resolve_candidate_spec({**candidate, "schema_versions": value}, root=Path.cwd(), subject_git_sha="a" * 40, model_policy=load_model_policy(), corpus=candidate["corpus_identity"])

    def test_effective_termbase_identity_includes_private_semantics_and_is_path_independent(self):
        core = {"version": "1.0", "records": [{"term_id": "core", "source": "검토", "preferred": {"default": "under review"}, "status": "PREFERRED", "scope": ["modality"]}]}
        overlay = {"version": "1.0", "records": [{"term_id": "private", "source": "고도화", "preferred": {"default": "enhancement"}, "status": "LOCKED", "scope": ["corporate"]}]}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "termbase").mkdir()
            _write(root / "termbase" / "core.json", core)
            (root / ".k-slide-config").mkdir()
            _write(root / ".k-slide-config" / "termbase.local.json", overlay)
            first = effective_termbase_identity(root)
            self.assertIsNotNone(first)
            moved = root / "moved"
            (moved / "termbase").mkdir(parents=True)
            _write(moved / "termbase" / "core.json", core)
            (moved / ".k-slide-config").mkdir()
            _write(moved / ".k-slide-config" / "termbase.local.json", overlay)
            self.assertEqual(first, effective_termbase_identity(moved))
            overlay["records"][0]["preferred"]["default"] = "upgrade"
            _write(root / ".k-slide-config" / "termbase.local.json", overlay)
            changed = effective_termbase_identity(root)
            self.assertNotEqual(first, changed)
            overlay["records"][0]["status"] = "PREFERRED"
            _write(root / ".k-slide-config" / "termbase.local.json", overlay)
            self.assertNotEqual(changed, effective_termbase_identity(root))
            (root / ".k-slide-config" / "termbase.local.json").unlink()
            self.assertNotEqual(first, effective_termbase_identity(root))
            conflicting = {"version": "1.0", "records": [{"source": "검토", "preferred": {"default": "review"}, "status": "LOCKED"}]}
            _write(root / ".k-slide-config" / "termbase.local.json", conflicting)
            _write(root / "termbase" / "core.json", {**core, "records": [{**core["records"][0], "status": "LOCKED"}]})
            with self.assertRaises(EvidenceValidationError):
                effective_termbase_identity(root)

    def test_effective_termbase_hash_is_bound_by_candidate_resolution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "termbase").mkdir()
            (root / "termbase" / "core.json").write_bytes((Path.cwd() / "termbase" / "core.json").read_bytes())
            candidate = _candidate_spec("a" * 40, root=root)
            before = effective_termbase_identity(root)
            self.assertEqual(candidate["termbase_hash"], before["hash"])
            (root / ".k-slide-config").mkdir()
            _write(root / ".k-slide-config" / "termbase.local.json", {"version": "1.0", "records": [{"source": "비공개", "preferred": {"default": "private"}, "status": "PREFERRED"}]})
            after = effective_termbase_identity(root)
            self.assertNotEqual(before, after)
            candidate["termbase_hash"] = "a" * 64
            with self.assertRaises(EvidenceValidationError):
                resolve_candidate_spec(candidate, root=root, subject_git_sha="a" * 40, model_policy=load_model_policy(), corpus=candidate["corpus_identity"])

    def test_production_completeness_rejects_unset_fields_even_with_valid_shape(self):
        candidate = _candidate_spec("a" * 40, ocr_provider="paddle")
        candidate["ocr_asset_manifest"] = "ocr/manifest.json"
        candidate["ocr_asset_manifest_sha256"] = "a" * 64
        candidate["resolved_dependency_set_sha256"] = "b" * 64
        candidate["behavior_configuration"]["ocr_provider"] = "paddle"
        self.assertEqual(candidate_completeness(candidate, "PRODUCTION_CERTIFIED"), [])
        for field in ("opencode_version", "effective_model", "paddle_version", "paddleocr_version", "libreoffice_version", "prompt_identity", "termbase_hash", "constraints_sha256", "resolved_dependency_set_sha256"):
            mutated = json.loads(json.dumps(candidate))
            if field == "prompt_identity":
                mutated[field]["hash"] = "UNSET"
            else:
                mutated[field] = "UNSET"
            self.assertIn(field, candidate_completeness(mutated, "PRODUCTION_CERTIFIED"), field)

    def test_exact_runtime_versions_and_libreoffice_parser(self):
        from k_slide.certification import canonical_exact_version, parse_libreoffice_version

        with self.assertRaises(EvidenceValidationError):
            canonical_exact_version("3.11", "python_version")
        self.assertEqual(canonical_exact_version(TEST_PYTHON_VERSION, "python_version"), TEST_PYTHON_VERSION)
        self.assertEqual(parse_libreoffice_version("LibreOffice 25.2.3.1 40(Build:1)"), "25.2.3.1")
        self.assertIsNone(parse_libreoffice_version("LibreOffice 25.2"))
        from k_slide.runtime import _version as runtime_version
        with patch("k_slide.runtime.subprocess.run", return_value=SimpleNamespace(returncode=0, stdout="OpenCode 1.3.9.1\n", stderr="")):
            runtime_version.cache_clear()
            self.assertEqual(runtime_version("/usr/bin/opencode"), "1.3.9.1")
            runtime_version.cache_clear()

    def test_security_binds_inventory_sbom_and_production_subject(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = _security_sources(root)
            evidence = root / "security.json"
            build_machine_evidence(evidence, evidence_type="security", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources)
            self.assertEqual(load_evidence(evidence, expected_type="security")["payload"]["resolved_dependency_set_sha256"], dependency_inventory_hash(json.loads((root / "dependency-inventory.json").read_text(encoding="utf-8"))))
            inventory = json.loads((root / "dependency-inventory.json").read_text(encoding="utf-8"))
            inventory["packages"][0]["version"] = "2.0"
            _write(root / "dependency-inventory.json", inventory)
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "changed-inventory.json", evidence_type="security", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources)
            sources = _security_sources(root)
            sbom = json.loads((root / "production-sbom.json").read_text(encoding="utf-8"))
            sbom["components"][0]["version"] = "2.0"
            _write(root / "production-sbom.json", sbom)
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "changed-sbom.json", evidence_type="security", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources)
            sources = _security_sources(root)
            context = json.loads((root / "audit-context.json").read_text(encoding="utf-8"))
            context["audited_dependency_subject"] = "scanner-environment"
            _write(root / "audit-context.json", context)
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "scanner-only.json", evidence_type="security", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources)
            context["audited_dependency_subject"] = "runner-environment"
            _write(root / "audit-context.json", context)
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "runner-only.json", evidence_type="security", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources)

    def test_security_workflow_layout_is_portable_and_all_sources_are_reverified(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "evidence"
            root.mkdir()
            sources = _security_sources(root)
            evidence = root / "security.evidence.json"
            build_machine_evidence(evidence, evidence_type="security", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources)
            loaded = load_evidence(evidence, expected_type="security", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64)
            self.assertEqual(loaded["payload"]["resolved_dependency_lock_sha256"], _sha(root / "production-requirements.lock"))
            self.assertEqual(load_dependency_lock(root / "production-requirements.lock")["packages"], json.loads((root / "dependency-inventory.json").read_text(encoding="utf-8"))["packages"])
            outside = root.parent / "outside.json"
            outside.write_text((root / "production-requirements.lock").read_text(encoding="utf-8"), encoding="utf-8")
            unsafe = dict(sources)
            unsafe["production_lock"] = outside
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "unsafe.json", evidence_type="security", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=unsafe)

    def test_reloaded_evidence_rejects_symlinked_source_even_inside_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "evidence"
            root.mkdir()
            evidence = root / "security.evidence.json"
            build_machine_evidence(evidence, evidence_type="security", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=_security_sources(root))
            source = root / "production-lock-link"
            source.symlink_to(root / "production-requirements.lock")
            value = json.loads(evidence.read_text(encoding="utf-8"))
            for item in value["sources"]:
                if item["role"] == "production_lock":
                    item["path"] = source.name
            evidence.write_text(json.dumps(value) + "\n", encoding="utf-8")
            with self.assertRaises(EvidenceValidationError):
                load_evidence(evidence, expected_type="security")

    def test_security_rejects_empty_audit_lock_drift_and_nonstandard_sbom(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = _security_sources(root)
            _write(root / "pip-audit.json", {"dependencies": []})
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "empty-audit.json", evidence_type="security", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources)
            sources = _security_sources(root)
            _write(root / "scanner-exits.json", {"pip_audit": 0, "gitleaks": 0, "semgrep": 0, "unexpected": 0})
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "extra-exit.json", evidence_type="security", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources)
            sources = _security_sources(root)
            (root / "production-requirements.lock").write_text("Pillow==2.0\n", encoding="utf-8")
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "lock-drift.json", evidence_type="security", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources)
            sources = _security_sources(root)
            sbom = json.loads((root / "production-sbom.json").read_text(encoding="utf-8"))
            sbom["complete"] = True
            _write(root / "production-sbom.json", sbom)
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "invalid-sbom.json", evidence_type="security", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources)

    def test_dependency_inventory_rejects_scanner_environment_tools(self):
        with self.assertRaises(EvidenceValidationError):
            canonical_dependency_inventory([{"name": "pip-audit", "version": "2.9.0"}, {"name": "semgrep", "version": "1.89.0"}, {"name": "Pillow", "version": "1.0"}])
        inventory = canonical_dependency_inventory([{"name": "pip", "version": "24.0"}, {"name": "setuptools", "version": "70.0"}, {"name": "Pillow", "version": "1.0"}])
        self.assertEqual(inventory["packages"], [{"name": "pillow", "version": "1.0"}])

    def test_security_constraints_identity_mismatch_is_rejected(self):
        candidate = _candidate_spec("a" * 40)
        deployment = candidate_deployment_fingerprint(candidate)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = _security_sources(root, constraints_hash=str(candidate["constraints_sha256"]))
            context = json.loads((root / "audit-context.json").read_text(encoding="utf-8"))
            context["candidate_constraints_sha256"] = "d" * 64
            _write(root / "audit-context.json", context)
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "security.json", evidence_type="security", subject_git_sha="a" * 40, deployment_fingerprint=deployment, sources=sources, candidate_spec=candidate)

    def test_candidate_completeness_resolves_repository_inputs_and_keeps_states_practical(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "prompts").mkdir()
            (root / "prompts" / "system.txt").write_text("prompt-v1\n", encoding="utf-8")
            (root / "termbase").mkdir()
            (root / "termbase" / "terms.json").write_text("{}\n", encoding="utf-8")
            (root / "constraints-production.txt").write_bytes((Path.cwd() / "constraints-production.txt").read_bytes())
            candidate = {
                "subject_git_sha": "a" * 40,
                "kslide_version": "UNSET",
                "opencode_version": "1.0.0",
                "prompt_identity": {"hash": "UNSET"},
                "termbase_identity": {"hash": "UNSET"},
                "termbase_hash": "UNSET",
                "constraints_sha256": "UNSET",
                "model_policy": {},
                "corpus_identity": {},
            }
            from k_slide.certification import resolve_candidate_spec
            resolved = resolve_candidate_spec(candidate, root=root, subject_git_sha=candidate["subject_git_sha"], model_policy=load_model_policy(), corpus={"version": "v1", "corpus_fingerprint": "c" * 64, "held_out_fingerprint": "d" * 64})
            self.assertNotEqual(resolved["prompt_identity"]["hash"], "UNSET")
            self.assertNotEqual(resolved["termbase_identity"]["hash"], "UNSET")
            self.assertEqual(resolved["constraints_sha256"], _sha(root / "constraints-production.txt"))
            self.assertEqual(candidate_completeness(resolved, "RUNTIME_READY"), [])
            self.assertIn("effective_model", candidate_completeness(resolved, "SYNTHETIC_PRODUCTION_CANDIDATE"))
            mismatched = {**candidate, "constraints_sha256": "a" * 64}
            with self.assertRaises(EvidenceValidationError):
                resolve_candidate_spec(mismatched, root=root, subject_git_sha=candidate["subject_git_sha"], model_policy=load_model_policy(), corpus={"version": "v1", "corpus_fingerprint": "c" * 64, "held_out_fingerprint": "d" * 64})
            resolved.update({"provider_backend": NOT_EXPOSED_VALUE, "model_revision": NOT_APPLICABLE_VALUE, "quantization_or_dtype": NOT_EXPOSED_VALUE})
            self.assertNotIn("provider_backend", candidate_completeness(resolved, "PRODUCTION_CERTIFIED"))

    def test_incomplete_candidate_blocks_before_certified_manifest_for_each_required_field(self):
        production_fields = ("opencode_version", "effective_model", "paddle_version", "libreoffice_version", "constraints_sha256", "ocr_asset_manifest_sha256", "prompt_identity", "termbase_hash")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "manifest.json").write_text("{}\n", encoding="utf-8")
            base = _candidate_spec("a" * 40, ocr_provider="paddle", asset_manifest="manifest.json", asset_hash=_sha(root / "manifest.json"), root=root)
            for field in production_fields:
                candidate = json.loads(json.dumps(base))
                if field == "prompt_identity":
                    candidate[field]["hash"] = "UNSET"
                else:
                    candidate[field] = "UNSET"
                candidate_path = root / f"candidate-{field}.json"
                _write(candidate_path, candidate)
                output = root / f"release-{field}.json"
                profile = root / f"profile-{field}.json"
                result = release_main(["--root", str(root), "--output", str(output), "--requested-state", "PRODUCTION_CERTIFIED", "--candidate-profile", str(candidate_path), "--certified-profile-output", str(profile)])
                self.assertEqual(result, 2, field)
                self.assertFalse(output.exists(), field)
                self.assertFalse(profile.exists(), field)

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

    def test_reliability_missing_substantive_proof_fails_closed(self):
        cases = (
            ("failure.json", "timeout_recovery_pass", None),
            ("failure.json", "resume_pass", None),
            ("concurrency.json", "concurrency_pass", None),
            ("concurrency.json", "concurrent_runs", 4),
            ("large.json", "fifty_slide_pass", None),
            ("slo.json", "slo_pass", None),
        )
        for filename, key, replacement in cases:
            with self.subTest(filename=filename, key=key), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                sources = _reliability_sources(root)
                value = json.loads((root / filename).read_text(encoding="utf-8"))
                if replacement is None:
                    value.pop(key, None)
                else:
                    value[key] = replacement
                _write(root / filename, value)
                with self.assertRaises(AdapterError):
                    build_machine_evidence(root / "reliability.json", evidence_type="reliability", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources)

    def test_reliability_false_substantive_proof_fails_closed(self):
        for filename, key in (("failure.json", "timeout_recovery_pass"), ("failure.json", "resume_pass"), ("concurrency.json", "concurrency_pass"), ("large.json", "fifty_slide_pass"), ("slo.json", "slo_pass")):
            with self.subTest(filename=filename, key=key), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                sources = _reliability_sources(root)
                value = json.loads((root / filename).read_text(encoding="utf-8"))
                value[key] = False
                _write(root / filename, value)
                with self.assertRaises(AdapterError):
                    build_machine_evidence(root / "reliability.json", evidence_type="reliability", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources)

    def test_high_risk_does_not_cherry_pick_best_format(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = _model_sources(root, repeats=5)
            rows = [json.loads(line) for line in (root / "results.jsonl").read_text(encoding="utf-8").splitlines()]
            failing = dict(rows[0])
            failing["format"] = "pdf"
            failing["semantic"] = {**failing["semantic"], "critical_failures": ["CRITICAL"]}
            rows.extend([{**failing, "repeat": repeat} for repeat in range(1, 6)])
            (root / "results.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
            experiment = json.loads((root / "experiment.json").read_text(encoding="utf-8"))
            experiment["formats"] = ["png", "pdf"]
            _write(root / "experiment.json", experiment)
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "high-risk.json", evidence_type="model_high_risk_stability", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources, root=Path.cwd())

    def test_high_risk_declared_group_missing_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = _model_sources(root, repeats=5)
            experiment = json.loads((root / "experiment.json").read_text(encoding="utf-8"))
            experiment["formats"] = ["png", "pdf"]
            _write(root / "experiment.json", experiment)
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "high-risk.json", evidence_type="model_high_risk_stability", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources, root=Path.cwd())

    def test_validation_and_held_out_safety_metrics_are_gated(self):
        for split, evidence_type, field, value in (
            ("validation", "model_validation", "locked_terminology_recall", 0.994),
            ("validation", "model_validation", "unexpected_unresolved_rate", 0.01),
            ("held_out", "model_held_out", "locked_terminology_recall", 0.994),
            ("held_out", "model_held_out", "unexpected_unresolved_rate", 0.01),
        ):
            with self.subTest(split=split, field=field), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                sources = _model_sources(root, split=split, repeats=3)
                rows = [json.loads(line) for line in (root / "results.jsonl").read_text(encoding="utf-8").splitlines()]
                for row in rows:
                    row["semantic"][field] = value
                (root / "results.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
                summary = json.loads((root / "summary.json").read_text(encoding="utf-8"))
                summary[field] = value
                _write(root / "summary.json", summary)
                with self.assertRaises(AdapterError):
                    build_machine_evidence(root / "model.json", evidence_type=evidence_type, subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources, root=Path.cwd())

    def test_validation_locked_terminology_boundary_is_inclusive(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = _model_sources(root, repeats=3)
            rows = [json.loads(line) for line in (root / "results.jsonl").read_text(encoding="utf-8").splitlines()]
            for row in rows:
                row["semantic"]["term_consistency_recall"] = 0.995
            (root / "results.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
            summary = json.loads((root / "summary.json").read_text(encoding="utf-8"))
            summary["locked_terminology_recall"] = 0.995
            _write(root / "summary.json", summary)
            path = root / "validation.json"
            build_machine_evidence(path, evidence_type="model_validation", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources, root=Path.cwd())
            self.assertEqual(load_evidence(path, expected_type="model_validation")["payload"]["locked_terminology_recall"], 0.995)

    def test_model_summary_and_rows_safety_metrics_must_agree(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = _model_sources(root, repeats=3)
            summary = json.loads((root / "summary.json").read_text(encoding="utf-8"))
            summary["locked_terminology_recall"] = 0.995
            _write(root / "summary.json", summary)
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "validation.json", evidence_type="model_validation", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources, root=Path.cwd())

    def test_security_evidence_is_derived_from_scanner_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "security.json"
            build_machine_evidence(path, evidence_type="security", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=_security_sources(root))
            self.assertTrue(load_evidence(path, expected_type="security")["payload"]["secret_scan_pass"])
            _security_sources(root, vulnerable=True)
            with self.assertRaises(EvidenceValidationError):
                load_evidence(path, expected_type="security")

    def test_security_evidence_binds_the_production_dependency_subject(self):
        subject = "a" * 40
        candidate = _candidate_spec(subject)
        deployment = candidate_deployment_fingerprint(candidate)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = _security_sources(root, constraints_hash=str(candidate["constraints_sha256"]))
            evidence = root / "security.json"
            build_machine_evidence(evidence, evidence_type="security", subject_git_sha=subject, deployment_fingerprint=deployment, sources=sources, candidate_spec=candidate)
            self.assertEqual(load_evidence(evidence, expected_type="security", candidate_spec=candidate, subject_git_sha=subject, deployment_fingerprint=deployment)["payload"]["audited_dependency_set_sha256"], dependency_inventory_hash(json.loads((root / "dependency-inventory.json").read_text(encoding="utf-8"))))
            context = json.loads((root / "audit-context.json").read_text(encoding="utf-8"))
            context["audited_dependency_set_sha256"] = "d" * 64
            _write(root / "audit-context.json", context)
            with self.assertRaises(EvidenceValidationError):
                load_evidence(evidence, expected_type="security", candidate_spec=candidate, subject_git_sha=subject, deployment_fingerprint=deployment)
            context["audited_dependency_set_sha256"] = str(candidate["constraints_sha256"])
            context.pop("semgrep_ruleset_sha256")
            _write(root / "audit-context.json", context)
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "missing-ruleset.json", evidence_type="security", subject_git_sha=subject, deployment_fingerprint=deployment, sources=sources, candidate_spec=candidate)

    def test_release_rejects_external_evidence_paths_and_keeps_relative_paths(self):
        subject = "a" * 40
        candidate = _candidate_spec(subject)
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside_directory:
            root = Path(directory)
            candidate_path = root / "candidate.json"
            _write(candidate_path, candidate)
            outside = Path(outside_directory)
            sources = _runtime_sources(outside)
            evidence = outside / "runtime.evidence.json"
            deployment = candidate_deployment_fingerprint(candidate)
            build_machine_evidence(evidence, evidence_type="runtime", subject_git_sha=subject, deployment_fingerprint=deployment, sources=sources, candidate_spec=candidate)
            with self.assertRaises(EvidenceValidationError):
                build_release_manifest(root, requested_state="DEVELOPMENT", subject_sha=subject, candidate_profile=candidate_path, evidence_paths={"runtime": evidence})
            inside = root / "evidence"
            inside.mkdir()
            inside_sources = _runtime_sources(inside)
            inside_evidence = inside / "runtime.evidence.json"
            build_machine_evidence(inside_evidence, evidence_type="runtime", subject_git_sha=subject, deployment_fingerprint=deployment, sources=inside_sources, candidate_spec=candidate)
            manifest = build_release_manifest(root, requested_state="DEVELOPMENT", subject_sha=subject, candidate_profile=candidate_path, evidence_paths={"runtime": inside_evidence})
            self.assertEqual(manifest["evidence_paths"]["runtime"], "evidence/runtime.evidence.json")

    def test_model_policy_requires_explicit_alias_targets_and_exact_canonical_ids(self):
        from k_slide.model_policy import ModelPolicy
        target = "google/gemma-4-31b-it"
        alternate = "provider/gemma-4-31b-it-r2"
        policy = ModelPolicy.from_mapping({"approved_model_ids": [target, alternate], "approved_aliases": ["private/gemma"], "approved_alias_targets": {"private/gemma": [target]}})
        self.assertTrue(policy.approved(requested=target, effective=target))
        self.assertFalse(policy.approved(requested=target, effective=alternate))
        self.assertTrue(policy.approved(requested="private/gemma", effective=target))
        self.assertFalse(policy.approved(requested="private/gemma", effective=alternate))
        self.assertFalse(policy.approved(requested="missing/gemma", effective=target))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".k-slide-config").mkdir()
            (root / ".k-slide-config" / "model-policy.local.yaml").write_text(
                "approved_model_ids:\n  - google/gemma-4-31b-it\napproved_aliases:\n  - private/gemma\napproved_alias_targets:\n  private/gemma:\n    - google/gemma-4-31b-it\n",
                encoding="utf-8",
            )
            yaml_policy = __import__("k_slide.model_policy", fromlist=["load_model_policy"]).load_model_policy(root)
            self.assertTrue(yaml_policy.approved(requested="private/gemma", effective=target))

    def test_isolated_opencode_runner_keeps_outer_authoritative_policy(self):
        from evals.opencode_runner import OpenCodeEvalRunner
        from k_slide.model_policy import ModelPolicy

        target = "google/gemma-4-31b-it"
        policy = ModelPolicy.from_mapping({"approved_model_ids": [target], "approved_aliases": ["private/gemma"], "approved_alias_targets": {"private/gemma": [target]}})
        runner = OpenCodeEvalRunner(model="private/gemma", opencode="/missing/opencode", policy=policy, policy_root=Path("/missing/isolated-policy"))
        self.assertIs(runner.policy, policy)
        self.assertTrue(runner.policy.approved(requested="private/gemma", effective=target))

    def test_certifying_model_runner_requires_frozen_policy_approved_effective_model(self):
        from evals.model_eval import ModelEvaluationRunner
        from k_slide.model_policy import ModelPolicy

        target = "google/gemma-4-31b-it"
        alternate = "provider/gemma-4-31b-it-r2"
        policy = ModelPolicy.from_mapping({"approved_model_ids": [target, alternate]})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate_path = root / "candidate.json"
            candidate = _candidate_spec("a" * 40, effective_model=alternate)
            candidate["model_policy"] = policy.as_dict()
            _write(candidate_path, candidate)
            result = ModelEvaluationRunner(
                model=target,
                output=root / "run",
                split="validation",
                repeats=3,
                candidate_profile=candidate_path,
                model_policy=policy,
            ).run()
            self.assertEqual(result["status"], "CANDIDATE_PROFILE_BLOCKED")

    def test_security_scanner_failure_is_not_a_clean_scan(self):
        for scanner in ("pip_audit", "gitleaks", "semgrep"):
            with self.subTest(scanner=scanner), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                sources = _security_sources(root)
                exits = {**json.loads((root / "scanner-exits.json").read_text(encoding="utf-8")), scanner: 1}
                _write(root / "scanner-exits.json", exits)
                with self.assertRaises(AdapterError):
                    build_machine_evidence(root / "security.json", evidence_type="security", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources)

    def test_security_missing_gitleaks_report_is_not_an_empty_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = _security_sources(root)
            (root / "gitleaks.json").unlink()
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "security.json", evidence_type="security", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources)

    def test_security_scanner_enforcement_is_independent_from_candidate_eligibility(self):
        from evals.enforce_security import main as enforce_main

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = _security_sources(root)
            args = [f"--{role.replace('_', '-') if role != 'scanner_exits' else 'scanner-exits'}" for role in ("pip_audit", "gitleaks", "semgrep", "scanner_exits")]
            paths = [str(sources[role]) for role in ("pip_audit", "gitleaks", "semgrep", "scanner_exits")]
            self.assertEqual(enforce_main(sum(([arg, path] for arg, path in zip(args, paths)), [])), 0)
            _write(root / "pip-audit.json", {"dependencies": [{"name": "Pillow", "version": "1.0", "vulns": [{"id": "CVE-TEST"}]}]})
            with self.assertRaises(AdapterError):
                enforce_security_scanners({key: sources[key] for key in ("pip_audit", "gitleaks", "semgrep", "scanner_exits")})
            (root / "gitleaks.json").unlink()
            with self.assertRaises(AdapterError):
                enforce_security_scanners({key: sources[key] for key in ("pip_audit", "gitleaks", "semgrep", "scanner_exits")})

    def test_private_certification_bundle_materializes_bytes_and_rejects_unsafe_layout(self):
        from evals.materialize_certification_bundle import materialize

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "bundle"
            target = root / "checkout"
            bundle.mkdir()
            subject = "a" * 40
            candidate_path = bundle / "candidate.json"
            lock_path = bundle / "production.lock"
            candidate = {"candidate_spec_version": "1.0", "subject_git_sha": subject, "requested_model": "google/gemma-4-31b-it"}
            _write(candidate_path, candidate)
            inventory = canonical_dependency_inventory([{"name": "Pillow", "version": "1.0"}])
            lock_path.write_text(dependency_lock_text(inventory), encoding="utf-8")
            manifest = {"schema_version": "1.0", "subject_git_sha": subject, "files": [{"role": "candidate_profile", "path": "candidate.json", "target": ".k-slide-config/production-candidate.json", "sha256": _sha(candidate_path)}, {"role": "production_dependency_lock", "path": "production.lock", "target": ".k-slide-config/production-requirements.lock", "sha256": _sha(lock_path)}]}
            manifest_path = _write(bundle / "certification-bundle.json", manifest)
            result = materialize(bundle_root=bundle, manifest_path=manifest_path, output_root=target, subject_git_sha=subject)
            self.assertEqual(result["status"], "PASS")
            self.assertEqual(_sha(target / ".k-slide-config" / "production-candidate.json"), _sha(candidate_path))
            manifest["files"][0]["path"] = "../candidate.json"
            _write(bundle / "certification-bundle.json", manifest)
            with self.assertRaises(EvidenceValidationError):
                materialize(bundle_root=bundle, manifest_path=manifest_path, output_root=root / "unsafe", subject_git_sha=subject)

    def test_isolated_model_runner_materializes_and_verifies_private_termbase_before_inference(self):
        from evals.opencode_runner import OpenCodeEvalRunner
        from k_slide.installer import install

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".k-slide-config").mkdir()
            overlay = {"version": "1.0", "records": [{"term_id": "private-1", "source": "사내어", "preferred": {"default": "internal term"}, "status": "LOCKED", "scope": ["corporate"]}]}
            _write(root / ".k-slide-config" / "termbase.local.json", overlay)
            identity = effective_termbase_identity(root)
            self.assertIsNotNone(identity)
            runner = OpenCodeEvalRunner(model="google/gemma-4-31b-it", candidate_spec={"termbase_identity": identity}, candidate_root=root, opencode="/missing/opencode")
            workspace = root / "workspace"
            install(Path.cwd(), workspace, scope="project")
            copied = runner._prepare_candidate_termbase(workspace)
            self.assertIsNotNone(copied)
            self.assertEqual(effective_termbase_identity(workspace), identity)
            copied.unlink()
            _write(root / ".k-slide-config" / "termbase.local.json", {**overlay, "records": [{**overlay["records"][0], "preferred": {"default": "changed"}}]})
            with self.assertRaises(EvidenceValidationError):
                runner._prepare_candidate_termbase(workspace)

    def test_isolated_model_runner_blocks_termbase_mismatch_before_opencode_process(self):
        from evals.opencode_runner import OpenCodeEvalRunner
        from k_slide.installer import install

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".k-slide-config").mkdir()
            overlay = {"version": "1.0", "records": [{"term_id": "private-2", "source": "계약", "preferred": {"default": "agreement"}, "status": "PREFERRED"}]}
            overlay_path = root / ".k-slide-config" / "termbase.local.json"
            _write(overlay_path, overlay)
            identity = effective_termbase_identity(root)
            _write(overlay_path, {**overlay, "records": [{**overlay["records"][0], "preferred": {"default": "contract"}}]})
            fake = root / "opencode"
            fake.write_text("#!/bin/sh\nprintf '1.3.9\\n'\n", encoding="utf-8")
            fake.chmod(0o755)
            runner = OpenCodeEvalRunner(model="google/gemma-4-31b-it", opencode=str(fake), candidate_spec={"termbase_identity": identity}, candidate_root=root)
            workspace = root / "workspace"
            install(Path.cwd(), workspace, scope="project")
            with patch("k_slide.installer.install"), patch("evals.opencode_runner._version", return_value="1.3.9"), patch("evals.opencode_runner.subprocess.Popen") as popen:
                result = runner.run(workspace=workspace)
            self.assertEqual(result.status, "CANDIDATE_CONFIG_BLOCKED")
            popen.assert_not_called()

    def test_security_workflow_captures_exit_codes_without_text_mutation_or_clean_fallback(self):
        workflow = (Path(__file__).resolve().parents[2] / ".github" / "workflows" / "k-slide-security.yml").read_text(encoding="utf-8")
        self.assertIn("pip-audit.exit", workflow)
        self.assertIn("gitleaks.exit", workflow)
        self.assertIn("semgrep.exit", workflow)
        self.assertIn("Assemble scanner exit codes", workflow)
        self.assertIn("Enforce scanner results", workflow)
        self.assertIn("certification_bundle_run_id", workflow)
        self.assertIn("actions/download-artifact@v4", workflow)
        self.assertIn("materialize_certification_bundle", workflow)
        self.assertIn("-r constraints-production.txt", workflow)
        self.assertIn("security/semgrep-production.yml", workflow)
        self.assertIn("audit_context", workflow)
        self.assertIn("candidate_profile", workflow)
        self.assertIn("production_site", workflow)
        self.assertIn("evidence/production-requirements.lock", workflow)
        self.assertNotIn("--path \"$RUNNER_TEMP/k-slide-security/production-env\"", workflow)
        self.assertIn("production_evidence_eligible", workflow)
        self.assertIn("NOT_CERTIFYING", workflow)
        self.assertNotIn('description: "Private resolved candidate profile path', workflow)
        self.assertNotIn("production_dependency_lock:\n", workflow)
        self.assertNotIn("sed -i", workflow)
        self.assertNotIn("printf '[]\\n'", workflow)

    def test_heavy_evidence_rederives_retained_dependency_subject(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = _heavy_sources(root)
            build_machine_evidence(root / "heavy.json", evidence_type="heavy_runtime", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources)
            _write(root / "built-image-inventory.json", canonical_dependency_inventory([{"name": "Pillow", "version": "2.0"}]))
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "changed-heavy.json", evidence_type="heavy_runtime", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources)

    def test_heavy_dependency_context_is_retained_from_lock_and_image_inventory(self):
        from evals.freeze_production_dependencies import retain_heavy_dependency_context

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = _heavy_sources(root)
            context_path = root / "retained-context.json"
            context = retain_heavy_dependency_context(inventory_path=sources["production_inventory"], lock_path=sources["production_lock"], built_image_inventory_path=sources["built_image_inventory"], output=context_path, subject_git_sha="a" * 40, deployment_fingerprint="b" * 64)
            self.assertEqual(context["expected_dependency_set_sha256"], dependency_inventory_hash(json.loads(sources["production_inventory"].read_text(encoding="utf-8"))))
            self.assertEqual(json.loads(context_path.read_text(encoding="utf-8"))["dependency_subject"], "production-env")

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
            candidate = _candidate_spec(subject, ocr_provider="paddle", asset_manifest="manifest.json", asset_hash="a" * 64)
            runtime_path = root / "runtime-envelope.json"
            heavy_path = root / "heavy-envelope.json"
            build_machine_evidence(runtime_path, evidence_type="runtime", subject_git_sha=subject, deployment_fingerprint=deployment, sources=_runtime_sources(root))
            build_machine_evidence(heavy_path, evidence_type="heavy_runtime", subject_git_sha=subject, deployment_fingerprint=deployment, sources=_heavy_sources(root))
            records = {"runtime": load_evidence(runtime_path, expected_type="runtime", subject_git_sha=subject, deployment_fingerprint=deployment), "heavy_runtime": load_evidence(heavy_path, expected_type="heavy_runtime", subject_git_sha=subject, deployment_fingerprint=deployment)}
            state, blockers = derive_release_state("GEMMA_EVAL_READY", records=records, root=root, policy=load_model_policy(root), deployment_fp=deployment, candidate_spec=candidate)
            self.assertEqual(state, "GEMMA_EVAL_READY")
            self.assertEqual(blockers, [])

    def test_temporary_machine_and_attestation_chain_derives_internal_validated(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subject = "a" * 40
            deployment = deployment_fingerprint(build_deployment_factors(root, subject_git_sha=subject, model_policy=load_model_policy(root)))
            candidate = _candidate_spec(subject, ocr_provider="paddle", asset_manifest="manifest.json", asset_hash="a" * 64)
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
                source = _model_sources(folder, split=split, repeats=repeats, subject=subject, deployment=deployment)
                if evidence_type == "model_held_out":
                    summary = json.loads((folder / "summary.json").read_text(encoding="utf-8"))
                    _write(folder / "summary.json", {**summary, "corpus_fingerprint": "698b471fa9dffe9f79af40a61c3546d6455889b90063a02bc2e270b90402f7ac", "held_out_fingerprint": "c2dee1ba1b03fead1a6641cfa8c7ceea27eb51b0ed80c0879c07bc3ee29bcc4e"})
                envelope = folder / "evidence.json"
                build_machine_evidence(envelope, evidence_type=evidence_type, subject_git_sha=subject, deployment_fingerprint=deployment, sources=source, root=Path.cwd())
                model_records[evidence_type] = load_evidence(envelope, expected_type=evidence_type, subject_git_sha=subject, deployment_fingerprint=deployment, repository_root=Path.cwd())
            (root / "evals").mkdir()
            _write(root / "evals" / "champion.json", {"status": "FROZEN", "model": "google/gemma-4-31b-it", "effective_model": "google/gemma-4-31b-it", "deployment_fingerprint": deployment, "config_hash": model_records["model_validation"]["payload"]["behavior_configuration_hash"]})
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
            state, blockers = derive_release_state("INTERNAL_VALIDATED", records=records, root=root, policy=load_model_policy(root), deployment_fp=deployment, candidate_spec=candidate)
            self.assertEqual(state, "INTERNAL_VALIDATED")
            self.assertEqual(blockers, [])

            for evidence_type, source_factory in (("security", _security_sources), ("reliability", _reliability_sources)):
                folder = root / evidence_type
                folder.mkdir()
                source = source_factory(folder)
                path = folder / "evidence.json"
                build_machine_evidence(path, evidence_type=evidence_type, subject_git_sha=subject, deployment_fingerprint=deployment, sources=source, root=Path.cwd())
                records[evidence_type] = load_evidence(path, expected_type=evidence_type, subject_git_sha=subject, deployment_fingerprint=deployment, repository_root=Path.cwd())
            governance_folder = root / "governance"
            governance_folder.mkdir()
            governance_source = governance_folder / "governance.json"
            _write(governance_source, {"source_kind": "github_api", "codeowners_pass": True, "branch_protection_pass": True, "required_ci_pass": True, "review_required": True})
            governance_path = governance_folder / "evidence.json"
            build_machine_evidence(governance_path, evidence_type="governance", subject_git_sha=subject, deployment_fingerprint=deployment, sources={"governance_api": governance_source}, root=Path.cwd())
            records["governance"] = load_evidence(governance_path, expected_type="governance", subject_git_sha=subject, deployment_fingerprint=deployment, repository_root=Path.cwd())
            pilot_path = root / "pilot.json"
            write_evidence(pilot_path, evidence_type="pilot_canary", subject_git_sha=subject, deployment_fingerprint=deployment, payload={"attestation_id": "pilot-test", "users": 5, "artifacts": 50, "critical_confirmed_errors": 0, "cross_user_exposure": 0, "security_incidents": 0, "silent_incomplete_output": 0}, generated_at="2026-09-09T00:00:00Z")
            records["pilot_canary"] = load_evidence(pilot_path, expected_type="pilot_canary", subject_git_sha=subject, deployment_fingerprint=deployment, repository_root=root)
            (root / ".k-slide-config").mkdir()
            _write(root / ".k-slide-config" / "production-sbom.json", {"bomFormat": "CycloneDX", "complete": True, "metadata": {}, "components": [{"name": "k-slide"}]})
            state, blockers = derive_release_state("PRODUCTION_CERTIFIED", records=records, root=root, policy=load_model_policy(root), deployment_fp=deployment, candidate_spec=candidate)
            self.assertEqual(state, "INTERNAL_VALIDATED")
            self.assertTrue(any("candidate field is unresolved" in item for item in blockers))

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

    def test_deployment_identity_excludes_certification_metadata_and_experiment_controls(self):
        from evals.experiments import behavior_configuration_hash, experiment_plan, experiment_plan_hash

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            behavior = {"model": "google/gemma-4-31b-it", "ocr_provider": "none", "prompt_version": "test-v1", "generation_settings": {"temperature": 0}}
            self.assertEqual(behavior_configuration_hash(behavior), behavior_configuration_hash({**behavior, "repetitions": 99, "split": "held_out", "limit": 1}))
            plan3 = experiment_plan(split="validation", scenario_ids=["scenario-0022"], formats=["png"], repetitions=3, categories=["modality_decision_state"], timeout=180, mode="quality")
            plan5 = experiment_plan(split="validation", scenario_ids=["scenario-0022"], formats=["png"], repetitions=5, categories=["modality_decision_state"], timeout=180, mode="quality")
            self.assertNotEqual(experiment_plan_hash(plan3), experiment_plan_hash(plan5))
            base = {"requested_model": behavior["model"], "effective_model": behavior["model"], "ocr_provider": "none", "behavior_configuration": behavior, "release_state": "DEVELOPMENT", "model_data_attestation": "UNSET", "release_manifest": "candidate.json", "release_manifest_sha256": "a" * 64}
            changed_metadata = {**base, "release_state": "PRODUCTION_CERTIFIED", "model_data_attestation": "policy-1", "release_manifest": "other.json", "release_manifest_sha256": "b" * 64}
            first = deployment_fingerprint(build_deployment_factors(root, subject_git_sha="a" * 40, profile=base, model_policy=load_model_policy(root), corpus={"version": "1.0", "corpus_fingerprint": "c" * 64, "held_out_fingerprint": "d" * 64}))
            second = deployment_fingerprint(build_deployment_factors(root, subject_git_sha="a" * 40, profile=changed_metadata, model_policy=load_model_policy(root), corpus={"version": "1.0", "corpus_fingerprint": "c" * 64, "held_out_fingerprint": "d" * 64}))
            self.assertEqual(first, second)
            material = {**base, "behavior_configuration": {**behavior, "prompt_version": "test-v2"}}
            self.assertNotEqual(first, deployment_fingerprint(build_deployment_factors(root, subject_git_sha="a" * 40, profile=material, model_policy=load_model_policy(root), corpus={"version": "1.0", "corpus_fingerprint": "c" * 64, "held_out_fingerprint": "d" * 64})))

    def test_candidate_spec_allowlist_aliases_and_material_behavior(self):
        subject = "a" * 40
        base = _candidate_spec(subject)
        first = candidate_deployment_fingerprint(base)
        metadata = {**base, "release_state": "PRODUCTION_CERTIFIED", "certification_fingerprint": "c" * 64, "release_manifest": "/tmp/release.json", "release_manifest_sha256": "d" * 64, "generated_at": "now", "split": "held_out", "repetitions": 99, "limit": 1}
        self.assertEqual(first, candidate_deployment_fingerprint(metadata))
        ambient_a = SimpleNamespace(as_dict=lambda: {"provider": "github", "reported_model_id": "runner-a"})
        ambient_b = SimpleNamespace(as_dict=lambda: {"provider": "local", "reported_model_id": "runner-b"})
        self.assertEqual(
            candidate_deployment_fingerprint(build_deployment_factors(Path.cwd(), candidate_spec=base, runtime=ambient_a)),
            candidate_deployment_fingerprint(build_deployment_factors(Path.cwd(), candidate_spec=base, runtime=ambient_b)),
        )
        changed_repair = {**base, "repair_policy": {"max_auto_repairs_per_unit": 3}, "behavior_configuration": {**base["behavior_configuration"], "repair_policy": {"max_auto_repairs_per_unit": 3}}}
        changed_normalization = {**base, "normalization_behavior": {"render_dpi": 221}, "behavior_configuration": {**base["behavior_configuration"], "normalization_behavior": {"render_dpi": 221}}}
        changed_prompt = {**base, "prompt_identity": {"version": "translation/v2", "hash": "q" * 64}, "behavior_configuration": {**base["behavior_configuration"], "prompt_identity": {"version": "translation/v2", "hash": "q" * 64}}}
        changed_generation = {**base, "generation_settings": {"temperature": 0.2}, "behavior_configuration": {**base["behavior_configuration"], "generation_settings": {"temperature": 0.2}}}
        changed_ocr = {**base, "ocr_provider": "paddle", "behavior_configuration": {**base["behavior_configuration"], "ocr_provider": "paddle"}}
        self.assertNotEqual(first, candidate_deployment_fingerprint(changed_repair))
        self.assertNotEqual(first, candidate_deployment_fingerprint(changed_normalization))
        self.assertNotEqual(first, candidate_deployment_fingerprint(changed_prompt))
        self.assertNotEqual(first, candidate_deployment_fingerprint(changed_generation))
        self.assertNotEqual(first, candidate_deployment_fingerprint(changed_ocr))
        alias = {**base}
        alias.pop("repair_policy")
        alias["repair"] = {"max_auto_repairs_per_unit": 2}
        alias_behavior = {**base["behavior_configuration"]}
        alias_behavior.pop("repair_policy")
        alias_behavior["repair"] = {"max_auto_repairs_per_unit": 2}
        alias["behavior_configuration"] = alias_behavior
        self.assertEqual(first, candidate_deployment_fingerprint(alias))
        self.assertNotEqual(behavior_configuration_hash({"repair": {"max_auto_repairs_per_unit": 2}}), behavior_configuration_hash({"repair": {"max_auto_repairs_per_unit": 3}}))

    def test_candidate_profile_absent_malformed_and_unknown_fields_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(EvidenceValidationError):
                load_candidate_spec(root / "missing.json", root=root, require_identity=True)
            malformed = root / "malformed.json"
            malformed.write_text("{", encoding="utf-8")
            with self.assertRaises(EvidenceValidationError):
                load_candidate_spec(malformed, root=root, require_identity=True)
            unknown = root / "unknown.json"
            _write(unknown, {**_candidate_spec("a" * 40), "behavior_configuration": {"unclassified_runtime_switch": True}})
            with self.assertRaises(EvidenceValidationError):
                load_candidate_spec(unknown, root=root, require_identity=True)
            top_level_unknown = root / "top-level-unknown.json"
            _write(top_level_unknown, {**_candidate_spec("a" * 40), "new_runtime_switch": True})
            with self.assertRaises(EvidenceValidationError):
                load_candidate_spec(top_level_unknown, root=root, require_identity=True)

    def test_certification_engine_split_requires_candidate_profile(self):
        from evals.run_engine_eval import main as engine_main

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "engine"
            self.assertEqual(engine_main(["--output", str(output), "--split", "validation", "--limit", "0"]), 2)
            self.assertEqual(json.loads((output / "summary.json").read_text(encoding="utf-8"))["status"], "CANDIDATE_PROFILE_BLOCKED")

    def test_effective_model_identity_is_required_and_mixed_models_are_rejected(self):
        from k_slide.model_policy import ModelPolicy

        target = "google/gemma-4-31b-it"
        alternate = "provider/gemma-4-31b-it-r2"
        alias_policy = ModelPolicy(approved_model_ids=(target,), approved_aliases=("private/gemma",), approved_alias_targets=(("private/gemma", (target,)),))
        self.assertTrue(alias_policy.approved(requested="private/gemma", effective=target))
        self.assertEqual(alias_policy.canonical_effective(requested="private/gemma", effective=target), target)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".k-slide-config").mkdir()
            _write(root / ".k-slide-config" / "model-policy.local.json", {"approved_model_ids": [target, alternate]})
            sources = _model_sources(root, repeats=3)
            rows = [json.loads(line) for line in (root / "results.jsonl").read_text(encoding="utf-8").splitlines()]
            rows[0]["opencode"]["diagnostics"]["effective_model"] = alternate
            (root / "results.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "mixed.json", evidence_type="model_validation", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources, root=root)
            rows[0]["opencode"]["diagnostics"].pop("effective_model")
            (root / "results.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "missing-effective.json", evidence_type="model_validation", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources, root=root)
            candidate = _candidate_spec("a" * 40)
            candidate["model_policy"] = {"approved_model_ids": [target, alternate]}
            changed = {**candidate, "effective_model": alternate}
            self.assertNotEqual(candidate_deployment_fingerprint(candidate), candidate_deployment_fingerprint(changed))

    def test_validation_and_high_risk_effective_models_must_match(self):
        from evals.release import _champion

        target = "google/gemma-4-31b-it"
        alternate = "provider/gemma-4-31b-it-r2"
        subject = "a" * 40
        deployment = "b" * 64
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".k-slide-config").mkdir()
            _write(root / ".k-slide-config" / "model-policy.local.json", {"approved_model_ids": [target, alternate]})
            records = {}
            for evidence_type, repeats in (("model_validation", 3), ("model_high_risk_stability", 5)):
                folder = root / evidence_type
                folder.mkdir()
                sources = _model_sources(folder, repeats=repeats, subject=subject, deployment=deployment)
                if evidence_type == "model_high_risk_stability":
                    rows = [json.loads(line) for line in sources["results_jsonl"].read_text(encoding="utf-8").splitlines()]
                    for row in rows:
                        row["effective_model"] = alternate
                        row["opencode"]["diagnostics"]["effective_model"] = alternate
                    sources["results_jsonl"].write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
                    for name in ("summary.json", "experiment.json"):
                        path = folder / name
                        value = json.loads(path.read_text(encoding="utf-8"))
                        value["effective_model"] = alternate
                        _write(path, value)
                envelope = folder / "evidence.json"
                if evidence_type == "model_high_risk_stability":
                    with self.assertRaises(AdapterError):
                        build_machine_evidence(envelope, evidence_type=evidence_type, subject_git_sha=subject, deployment_fingerprint=deployment, sources=sources, root=root)
                    return
                build_machine_evidence(envelope, evidence_type=evidence_type, subject_git_sha=subject, deployment_fingerprint=deployment, sources=sources, root=root)
                records[evidence_type] = load_evidence(envelope, expected_type=evidence_type, subject_git_sha=subject, deployment_fingerprint=deployment, repository_root=root)
            (root / "evals").mkdir()
            _write(root / "evals" / "champion.json", {"status": "FROZEN", "model": target, "effective_model": target, "deployment_fingerprint": deployment, "config_hash": records["model_validation"]["payload"]["behavior_configuration_hash"]})
            _champ, _hash, blockers = _champion(root, records=records, policy=load_model_policy(root), deployment_fp=deployment)
            self.assertIn("model evidence effective identities disagree", blockers)

    def test_real_model_runner_high_risk_output_is_adapter_consumable(self):
        from evals.model_eval import ModelEvaluationRunner

        target = "google/gemma-4-31b-it"
        subject = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate = _candidate_spec(subject)
            candidate_path = root / "candidate.json"
            _write(candidate_path, candidate)

            class FakeOpenCode:
                def run(self, **_kwargs):
                    return SimpleNamespace(
                        status="PASS",
                        reason=None,
                        runtime_version="1.3.9",
                        kslide_complete=True,
                        media_compliance={"work_units": {"u1": {"media_sequence_valid": True}}},
                        diagnostics={"effective_model": target, "model_identity_proven": True},
                        as_dict=lambda: {"status": "PASS", "mode": "quality", "model": target, "runtime_version": "1.3.9", "media_compliance": {"planned": True, "required_count": 1, "read_count": 1, "required_context_image_read": True, "media_sequence_valid": True}, "diagnostics": {"effective_model": target, "model_identity_proven": True}},
                    )

            scored = {"coverage": 1.0, "numeric_fidelity": 1.0, "modality": 1.0, "table_cell_fidelity": 1.0, "visual_relation_recall": 1.0, "critical_failures": [], "unresolved_region_rate": 0.0, "unexpected_unresolved_rate": 0.0}
            consistency = {"term_consistency_recall": 1.0, "inconsistent_alternate_count": 0, "critical_failures": []}
            runtime = SimpleNamespace(as_dict=lambda: {"opencode_version": "1.3.9", "python_version": TEST_PYTHON_VERSION, "provider": "google", "ocr_provider": "none"})
            with patch("evals.model_eval.generate_artifacts"), patch("evals.model_eval.OpenCodeEvalRunner", return_value=FakeOpenCode()), patch("evals.model_eval.discover_runtime", return_value=runtime), patch("evals.model_eval._latest_run", return_value=None), patch("evals.model_eval.collect_run_artifacts", return_value=[{"work_unit_id": "u1", "evidence": {}, "patch": {}, "slide_ir": None}]), patch("evals.model_eval._engine_gate", return_value=("PASS", [])), patch("evals.model_eval._work_unit_contract", return_value=(True, [])), patch("evals.model_eval.score_translation_patch", return_value=scored), patch("evals.model_eval.score_deck_consistency", return_value=consistency):
                output = root / "high-risk"
                result = ModelEvaluationRunner(model=target, output=output, split="validation", repeats=5, mode="quality", candidate_profile=candidate_path, high_risk=True).run()
            self.assertEqual(result["effective_model"], target)
            experiment = json.loads((output / "experiment.json").read_text(encoding="utf-8"))
            self.assertEqual(set(experiment["high_risk_categories"]), set(PROTECTED_CATEGORIES))
            evidence = output / "evidence.json"
            loaded_candidate = load_candidate_spec(candidate_path, root=Path.cwd(), require_identity=True)
            finalized_candidate = {**loaded_candidate, **experiment["candidate_spec"]}
            self.assertEqual(candidate_deployment_fingerprint(finalized_candidate), experiment["deployment_fingerprint"], msg=json.dumps({"loaded": canonical_candidate_factors(loaded_candidate), "runner": experiment["candidate_spec"]}, sort_keys=True))
            build_machine_evidence(evidence, evidence_type="model_high_risk_stability", subject_git_sha=subject, deployment_fingerprint=experiment["deployment_fingerprint"], sources={"model_summary": output / "summary.json", "experiment_manifest": output / "experiment.json", "results_jsonl": output / "results.jsonl"}, root=Path.cwd(), candidate_spec=loaded_candidate)
            self.assertEqual(load_evidence(evidence, expected_type="model_high_risk_stability")["payload"]["repetitions"], 5)

    def test_runtime_engine_security_model_release_share_candidate_fingerprint(self):
        from evals.opencode_diagnostics import run_diagnostic_ladder
        from evals.run_engine_eval import main as engine_main

        subject = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate = _candidate_spec(subject)
            candidate_path = root / "candidate.json"
            _write(candidate_path, candidate)
            loaded = load_candidate_spec(candidate_path, root=Path.cwd(), require_identity=True)
            expected = candidate_deployment_fingerprint(loaded)
            diagnostic = run_diagnostic_ladder(model=loaded["requested_model"], output=root / "diagnostic", opencode="/missing/opencode", candidate_profile=candidate_path)
            self.assertEqual(diagnostic["deployment_fingerprint"], expected)
            engine_output = root / "engine"
            self.assertEqual(engine_main(["--output", str(engine_output), "--split", "development", "--limit", "0", "--candidate-profile", str(candidate_path)]), 0)
            self.assertEqual(json.loads((engine_output / "summary.json").read_text(encoding="utf-8"))["deployment_fingerprint"], expected)
            security_folder = root / "security"
            security_folder.mkdir()
            security_sources = _security_sources(security_folder, constraints_hash=str(loaded["constraints_sha256"]))
            security_path = security_folder / "evidence.json"
            build_machine_evidence(security_path, evidence_type="security", subject_git_sha=subject, deployment_fingerprint=expected, sources=security_sources, root=Path.cwd(), candidate_spec=loaded)
            self.assertEqual(json.loads(security_path.read_text(encoding="utf-8"))["deployment_fingerprint"], expected)
            release = build_release_manifest(Path.cwd(), requested_state="DEVELOPMENT", subject_sha=subject, candidate_profile=candidate_path)
            self.assertEqual(release["deployment_fingerprint"], expected)

    def test_complete_release_materializes_profile_and_detects_candidate_staleness(self):
        subject = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
        target = "google/gemma-4-31b-it"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            asset_dir = root / "ocr"
            asset_dir.mkdir()
            (asset_dir / "weights.bin").write_bytes(b"local-paddle-weights")
            asset_hash = _sha(asset_dir / "weights.bin")
            asset_manifest = asset_dir / "manifest.json"
            _write(asset_manifest, {"provider": "paddle", "files": [{"path": "weights.bin", "sha256": asset_hash}]})
            (root / "prompts").mkdir()
            (root / "prompts" / "translation").mkdir()
            (root / "prompts" / "translation" / "v1.md").write_bytes((Path.cwd() / "prompts" / "translation" / "v1.md").read_bytes())
            (root / ".opencode" / "agents").mkdir(parents=True)
            (root / ".opencode" / "agents" / "k-slide.md").write_bytes((Path.cwd() / ".opencode" / "agents" / "k-slide.md").read_bytes())
            (root / "termbase").mkdir()
            (root / "termbase" / "core.json").write_bytes((Path.cwd() / "termbase" / "core.json").read_bytes())
            (root / "constraints-production.txt").write_bytes((Path.cwd() / "constraints-production.txt").read_bytes())
            inventory = canonical_dependency_inventory([{"name": name, "version": "1.0"} for name in ("Pillow", "PyMuPDF", "python-pptx", "paddlepaddle", "paddleocr")])
            (root / ".k-slide-config").mkdir()
            _write(root / ".k-slide-config" / "production-dependency-inventory.json", inventory)
            candidate = _candidate_spec(subject, ocr_provider="paddle", asset_manifest="ocr/manifest.json", asset_hash=_sha(asset_manifest), root=root)
            candidate_dir = root / ".k-slide-config"
            candidate_dir.mkdir(exist_ok=True)
            candidate_path = candidate_dir / "production-candidate.json"
            _write(candidate_path, candidate)
            candidate = load_candidate_spec(candidate_path, root=root, require_identity=True)
            deployment = candidate_deployment_fingerprint(candidate)
            records: dict[str, dict[str, object]] = {}
            for evidence_type, factory, full in (("runtime", _runtime_sources, False), ("heavy_runtime", _heavy_sources, True)):
                folder = root / evidence_type
                folder.mkdir()
                sources = factory(folder, full=full, subject=subject, deployment=deployment) if evidence_type == "heavy_runtime" else factory(folder, provider=str(candidate["provider"]), ocr_provider=str(candidate["ocr_provider"]))
                path = folder / "evidence.json"
                build_machine_evidence(path, evidence_type=evidence_type, subject_git_sha=subject, deployment_fingerprint=deployment, sources=sources, root=root, candidate_spec=candidate)
                records[evidence_type] = load_evidence(path, expected_type=evidence_type, subject_git_sha=subject, deployment_fingerprint=deployment, repository_root=root, candidate_spec=candidate, require_candidate_spec=True)
            for evidence_type, split, repeats in (("model_validation", "validation", 3), ("model_high_risk_stability", "validation", 5), ("model_held_out", "held_out", 3)):
                folder = root / evidence_type
                folder.mkdir()
                sources = _candidate_model_sources(folder, split=split, repeats=repeats, subject=subject, deployment=deployment, candidate=candidate)
                path = folder / "evidence.json"
                build_machine_evidence(path, evidence_type=evidence_type, subject_git_sha=subject, deployment_fingerprint=deployment, sources=sources, root=root, candidate_spec=candidate)
                records[evidence_type] = load_evidence(path, expected_type=evidence_type, subject_git_sha=subject, deployment_fingerprint=deployment, repository_root=root, candidate_spec=candidate, require_candidate_spec=True)
            (root / "evals").mkdir()
            _write(root / "evals" / "champion.json", {"status": "FROZEN", "model": target, "effective_model": target, "deployment_fingerprint": deployment, "config_hash": records["model_validation"]["payload"]["behavior_configuration_hash"]})
            attestations = {
                "internal_bilingual": {"attestation_id": "internal-test", "artifact_count": 50, "work_unit_count": 200, "critical_business_meaning_errors": 0, "critical_numeric_date_unit_errors": 0, "critical_modality_escalations": 0, "critical_table_mapping_errors": 0, "critical_trend_reversals": 0, "unsupported_critical_executive_claims": 0, "overall_noncritical_semantic_fidelity": 0.99, "locked_terminology": 0.999},
                "zero_korean_comprehension": {"attestation_id": "human-test", "users": 10, "answers": 100, "critical_question_accuracy": 1.0, "overall_comprehension": 0.95, "critical_misunderstanding": 0},
                "model_data_policy": {"attestation_id": "policy-test", "approved_for_internal_artifacts": True},
            }
            for evidence_type, payload in attestations.items():
                folder = root / evidence_type
                folder.mkdir()
                path = folder / "evidence.json"
                write_evidence(path, evidence_type=evidence_type, subject_git_sha=subject, deployment_fingerprint=deployment, payload=payload, generated_at="2026-09-10T00:00:00Z", candidate_spec=candidate)
                records[evidence_type] = load_evidence(path, expected_type=evidence_type, subject_git_sha=subject, deployment_fingerprint=deployment, repository_root=root, candidate_spec=candidate, require_candidate_spec=True)
            for evidence_type, factory in (("security", _security_sources), ("reliability", _reliability_sources)):
                folder = root / evidence_type
                folder.mkdir()
                path = folder / "evidence.json"
                source_values = factory(folder, constraints_hash=str(candidate["constraints_sha256"])) if evidence_type == "security" else factory(folder)
                build_machine_evidence(path, evidence_type=evidence_type, subject_git_sha=subject, deployment_fingerprint=deployment, sources=source_values, root=root, candidate_spec=candidate)
                records[evidence_type] = load_evidence(path, expected_type=evidence_type, subject_git_sha=subject, deployment_fingerprint=deployment, repository_root=root, candidate_spec=candidate, require_candidate_spec=True)
            governance_folder = root / "governance"
            governance_folder.mkdir()
            governance_source = governance_folder / "governance.json"
            _write(governance_source, {"source_kind": "github_api", "codeowners_pass": True, "branch_protection_pass": True, "required_ci_pass": True, "review_required": True})
            governance_path = governance_folder / "evidence.json"
            build_machine_evidence(governance_path, evidence_type="governance", subject_git_sha=subject, deployment_fingerprint=deployment, sources={"governance_api": governance_source}, root=root, candidate_spec=candidate)
            records["governance"] = load_evidence(governance_path, expected_type="governance", subject_git_sha=subject, deployment_fingerprint=deployment, repository_root=root, candidate_spec=candidate, require_candidate_spec=True)
            pilot_folder = root / "pilot_canary"
            pilot_folder.mkdir()
            pilot_path = pilot_folder / "evidence.json"
            write_evidence(pilot_path, evidence_type="pilot_canary", subject_git_sha=subject, deployment_fingerprint=deployment, payload={"attestation_id": "pilot-test", "users": 5, "artifacts": 50, "critical_confirmed_errors": 0, "cross_user_exposure": 0, "security_incidents": 0, "silent_incomplete_output": 0}, generated_at="2026-09-10T00:00:00Z", candidate_spec=candidate)
            records["pilot_canary"] = load_evidence(pilot_path, expected_type="pilot_canary", subject_git_sha=subject, deployment_fingerprint=deployment, repository_root=root, candidate_spec=candidate, require_candidate_spec=True)
            sbom_folder = root / ".k-slide-config"
            security_sbom = json.loads((root / "security" / "production-sbom.json").read_text(encoding="utf-8"))
            _write(sbom_folder / "production-sbom.json", security_sbom)
            evidence_paths = {key: root / key / "evidence.json" for key in records}
            manifest_path = root / "release" / "manifest.json"
            profile_path = sbom_folder / "production-profile.json"
            release_args = ["--root", str(root), "--output", str(manifest_path), "--requested-state", "PRODUCTION_CERTIFIED", "--require-certified", "--candidate-profile", str(candidate_path), "--certified-profile-output", str(profile_path)]
            for option, evidence_type in (("--runtime-evidence", "runtime"), ("--heavy-runtime-evidence", "heavy_runtime"), ("--validation-evidence", "model_validation"), ("--high-risk-evidence", "model_high_risk_stability"), ("--held-out-evidence", "model_held_out")):
                release_args.extend([option, str(evidence_paths[evidence_type])])
            for option, evidence_type in (("--internal-bilingual-attestation", "internal_bilingual"), ("--zero-korean-attestation", "zero_korean_comprehension"), ("--model-data-policy-attestation", "model_data_policy"), ("--security-attestation", "security"), ("--reliability-attestation", "reliability"), ("--governance-attestation", "governance"), ("--pilot-attestation", "pilot_canary")):
                release_args.extend([option, str(evidence_paths[evidence_type])])
            self.assertEqual(release_main(release_args), 0)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(manifest["release_state"], "PRODUCTION_CERTIFIED")
            self.assertEqual(manifest["deployment_fingerprint"], deployment)
            self.assertNotIn("blocking_reasons", manifest)
            profile = json.loads(profile_path.read_text(encoding="utf-8"))
            self.assertEqual(profile["release_manifest_sha256"], _sha(manifest_path))
            self.assertEqual(ProductionProfile.from_mapping(profile).deployment_fingerprint, deployment)
            from k_slide.installer import install
            install(Path.cwd(), root, scope="project")
            shutil.rmtree(root / "prompts")
            shutil.rmtree(root / "termbase")
            (root / "constraints-production.txt").unlink()
            (root / ".k-slide-runs").mkdir(exist_ok=True)
            (root / ".k-slide-runs").chmod(0o700)
            (root / ".opencode" / "opencode.json").write_text(json.dumps({"model": target}) + "\n", encoding="utf-8")
            (root / ".k-slide-config" / "ocr.local.json").write_text(json.dumps({"ocr_provider": "paddle"}) + "\n", encoding="utf-8")
            from k_slide.runtime import discover_runtime
            from k_slide.doctor import diagnose
            from k_slide.production import production_checks
            package_versions = {"paddlepaddle": "3.0.0", "paddleocr": "3.0.3"}
            production_inventory = canonical_dependency_inventory([{"name": name, "version": version} for name, version in {"Pillow": "1.0", "PyMuPDF": "1.0", "python-pptx": "1.0", "paddlepaddle": "1.0", "paddleocr": "1.0"}.items()])
            inventory_patch = patch("k_slide.production.installed_dependency_inventory", return_value=production_inventory)
            inventory_patch.start()
            self.addCleanup(inventory_patch.stop)
            with patch("k_slide.runtime.shutil.which", side_effect=lambda name: f"/usr/bin/{name}"), patch("k_slide.runtime._config_path", return_value=root / ".opencode" / "opencode.json"), patch("k_slide.runtime._effective_config", return_value={"model": target}), patch("k_slide.runtime._version", return_value="1.3.9"), patch("k_slide.runtime._command_product_version", return_value="25.2.3"), patch("k_slide.runtime._package_version", side_effect=lambda name: package_versions.get(name)), patch("k_slide.doctor.importlib.util.find_spec", return_value=object()), patch("k_slide.doctor.create_ocr_provider", return_value=SimpleNamespace(requested="paddle", effective="paddle", version="3.0.3", reason=None)), patch("k_slide.production.shutil.which", return_value="/usr/bin/libreoffice"), patch("k_slide.production.importlib.util.find_spec", return_value=object()), patch("k_slide.production.importlib.metadata.version", side_effect=lambda name: package_versions[name]), patch("k_slide.production._version_from_command", return_value="25.2.3"), patch("k_slide.production.create_ocr_provider", return_value=SimpleNamespace(effective="paddle", version="3.0.3")), patch.dict("os.environ", {"KSLIDE_PADDLE_REQUIRE_LOCAL_ASSETS": "1"}):
                runtime = discover_runtime(root)
                doctor_result = diagnose(root, production=True)
            self.assertEqual(doctor_result["overall"], "PASS", msg=json.dumps([item for item in doctor_result["checks"] if item["status"] != "PASS"], indent=2))
            from dataclasses import replace
            with patch("k_slide.production.shutil.which", return_value="/usr/bin/libreoffice"), patch("k_slide.production.importlib.util.find_spec", return_value=object()), patch("k_slide.production.importlib.metadata.version", side_effect=lambda name: {"paddlepaddle": "3.0.0", "paddleocr": "3.0.3"}[name]), patch("k_slide.production._version_from_command", return_value="25.2.3"), patch("k_slide.production.create_ocr_provider", return_value=SimpleNamespace(effective="paddle", version="3.0.3")), patch.dict("os.environ", {"KSLIDE_PADDLE_REQUIRE_LOCAL_ASSETS": "1"}):
                wrong_model_checks = production_checks(root, replace(runtime, reported_model_id="google/gemma-4-31b-it-other"))
            self.assertEqual(next(item for item in wrong_model_checks if item["label"] == "Vision capability")["status"], "FAIL")
            changed_results: list[tuple[Path, str]] = []
            for model_folder in ("model_validation", "model_high_risk_stability", "model_held_out"):
                result_path = root / model_folder / "results.jsonl"
                original_results = result_path.read_text(encoding="utf-8")
                rows = [json.loads(line) for line in original_results.splitlines()]
                rows[0]["opencode"]["media_compliance"]["required_context_image_read"] = False
                result_path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
                changed_results.append((result_path, original_results))
            with patch("k_slide.production.shutil.which", return_value="/usr/bin/libreoffice"), patch("k_slide.production.importlib.util.find_spec", return_value=object()), patch("k_slide.production.importlib.metadata.version", side_effect=lambda name: {"paddlepaddle": "3.0.0", "paddleocr": "3.0.3"}[name]), patch("k_slide.production._version_from_command", return_value="25.2.3"), patch("k_slide.production.create_ocr_provider", return_value=SimpleNamespace(effective="paddle", version="3.0.3")), patch.dict("os.environ", {"KSLIDE_PADDLE_REQUIRE_LOCAL_ASSETS": "1"}):
                missing_vision_checks = production_checks(root, runtime)
            self.assertEqual(next(item for item in missing_vision_checks if item["label"] == "Vision capability")["status"], "FAIL")
            for result_path, original_results in changed_results:
                result_path.write_text(original_results, encoding="utf-8")
            with patch("k_slide.production.shutil.which", return_value="/usr/bin/libreoffice"), patch("k_slide.production.importlib.util.find_spec", return_value=object()), patch("k_slide.production.importlib.metadata.version", side_effect=lambda name: {"paddlepaddle": "3.0.4", "paddleocr": "3.0.3"}[name]), patch("k_slide.production._version_from_command", return_value="25.2.3"), patch("k_slide.production.create_ocr_provider", return_value=SimpleNamespace(effective="paddle", version="3.0.3")), patch.dict("os.environ", {"KSLIDE_PADDLE_REQUIRE_LOCAL_ASSETS": "1"}):
                dependency_checks = production_checks(root, replace(runtime, paddle_version="3.0.4"))
            self.assertEqual(next(item for item in dependency_checks if item["label"] == "Paddle version")["status"], "FAIL")
            asset_path = asset_dir / "weights.bin"
            original_asset = asset_path.read_bytes()
            asset_path.write_bytes(b"tampered-weights")
            with patch("k_slide.production.shutil.which", return_value="/usr/bin/libreoffice"), patch("k_slide.production.importlib.util.find_spec", return_value=object()), patch("k_slide.production.importlib.metadata.version", side_effect=lambda name: {"paddlepaddle": "3.0.0", "paddleocr": "3.0.3"}[name]), patch("k_slide.production._version_from_command", return_value="25.2.3"), patch("k_slide.production.create_ocr_provider", return_value=SimpleNamespace(effective="paddle", version="3.0.3")), patch.dict("os.environ", {"KSLIDE_PADDLE_REQUIRE_LOCAL_ASSETS": "1"}):
                asset_checks = production_checks(root, runtime)
            self.assertEqual(next(item for item in asset_checks if item["label"] == "OCR asset manifest")["status"], "FAIL")
            asset_path.write_bytes(original_asset)
            manifest_bytes = manifest_path.read_bytes()
            manifest_path.write_bytes(manifest_bytes + b"\n")
            with patch("k_slide.production.shutil.which", return_value="/usr/bin/libreoffice"), patch("k_slide.production.importlib.util.find_spec", return_value=object()), patch("k_slide.production.importlib.metadata.version", side_effect=lambda name: {"paddlepaddle": "3.0.0", "paddleocr": "3.0.3"}[name]), patch("k_slide.production._version_from_command", return_value="25.2.3"), patch("k_slide.production.create_ocr_provider", return_value=SimpleNamespace(effective="paddle", version="3.0.3")), patch.dict("os.environ", {"KSLIDE_PADDLE_REQUIRE_LOCAL_ASSETS": "1"}):
                manifest_checks = production_checks(root, runtime)
            self.assertEqual(next(item for item in manifest_checks if item["label"] == "Release manifest hash")["status"], "FAIL")
            manifest_path.write_bytes(manifest_bytes)
            evidence_file = root / "model_validation" / "evidence.json"
            evidence_bytes = evidence_file.read_bytes()
            evidence_file.write_bytes(evidence_bytes + b"\n")
            with patch("k_slide.production.shutil.which", return_value="/usr/bin/libreoffice"), patch("k_slide.production.importlib.util.find_spec", return_value=object()), patch("k_slide.production.importlib.metadata.version", side_effect=lambda name: {"paddlepaddle": "3.0.0", "paddleocr": "3.0.3"}[name]), patch("k_slide.production._version_from_command", return_value="25.2.3"), patch("k_slide.production.create_ocr_provider", return_value=SimpleNamespace(effective="paddle", version="3.0.3")), patch.dict("os.environ", {"KSLIDE_PADDLE_REQUIRE_LOCAL_ASSETS": "1"}):
                evidence_checks = production_checks(root, runtime)
            self.assertEqual(next(item for item in evidence_checks if item["label"] == "Evidence model_validation envelope hash")["status"], "FAIL")
            evidence_file.write_bytes(evidence_bytes)
            fingerprint_checks = _manifest_and_fingerprint_status(root, ProductionProfile.from_mapping(profile), SimpleNamespace())
            self.assertEqual(next(item for item in fingerprint_checks if item["label"] == "Deployment fingerprint")["status"], "PASS")
            self.assertEqual(next(item for item in fingerprint_checks if item["label"] == "Certification freshness")["status"], "PASS")
            stale_candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
            stale_candidate["repair_policy"]["max_auto_repairs_per_unit"] = 3
            stale_candidate["behavior_configuration"]["repair_policy"]["max_auto_repairs_per_unit"] = 3
            _write(candidate_path, stale_candidate)
            stale_checks = _manifest_and_fingerprint_status(root, ProductionProfile.from_mapping(profile), SimpleNamespace())
            self.assertEqual(next(item for item in stale_checks if item["label"] == "Candidate source identity")["status"], "FAIL")
            self.assertEqual(next(item for item in stale_checks if item["label"] == "Certification freshness")["status"], "FAIL")

    def test_model_identity_composes_across_validation_high_risk_and_held_out(self):
        subject = "a" * 40
        deployment = "b" * 64
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            records = {}
            for evidence_type, split, repeats in (("model_validation", "validation", 3), ("model_high_risk_stability", "validation", 5), ("model_held_out", "held_out", 3)):
                folder = root / evidence_type
                folder.mkdir()
                sources = _model_sources(folder, split=split, repeats=repeats, subject=subject, deployment=deployment)
                envelope = folder / "evidence.json"
                build_machine_evidence(envelope, evidence_type=evidence_type, subject_git_sha=subject, deployment_fingerprint=deployment, sources=sources, root=Path.cwd())
                records[evidence_type] = load_evidence(envelope, expected_type=evidence_type, subject_git_sha=subject, deployment_fingerprint=deployment, repository_root=Path.cwd())
            payloads = [records[item]["payload"] for item in ("model_validation", "model_high_risk_stability", "model_held_out")]
            self.assertEqual({item["behavior_configuration_hash"] for item in payloads}, {payloads[0]["behavior_configuration_hash"]})
            self.assertEqual(len({item["experiment_plan_hash"] for item in payloads}), 3)

    def test_actual_model_runner_separates_behavior_and_experiment_identity(self):
        from evals.model_eval import ModelEvaluationRunner

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "n3"
            second = root / "n5"
            ModelEvaluationRunner(model="ollama/qwen3:14b", output=first, split="validation", repeats=3, limit=0).run()
            ModelEvaluationRunner(model="ollama/qwen3:14b", output=second, split="validation", repeats=5, limit=0).run()
            left = json.loads((first / "experiment.json").read_text(encoding="utf-8"))
            right = json.loads((second / "experiment.json").read_text(encoding="utf-8"))
            self.assertEqual(left["deployment_fingerprint"], right["deployment_fingerprint"])
            self.assertEqual(left["behavior_configuration_hash"], right["behavior_configuration_hash"])
            self.assertNotEqual(left["experiment_plan_hash"], right["experiment_plan_hash"])

    def test_validation_and_held_out_partial_matrices_are_rejected(self):
        for split, evidence_type in (("validation", "model_validation"), ("held_out", "model_held_out")):
            with self.subTest(split=split), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                sources = _model_sources(root, split=split, repeats=3)
                rows = [json.loads(line) for line in (root / "results.jsonl").read_text(encoding="utf-8").splitlines()]
                (root / "results.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows[:-1]), encoding="utf-8")
                with self.assertRaises(AdapterError):
                    build_machine_evidence(root / "partial.json", evidence_type=evidence_type, subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources, root=Path.cwd())

    def test_high_risk_real_ids_require_exact_declared_groups_and_repeats(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = _model_sources(root, repeats=5)
            rows = [json.loads(line) for line in (root / "results.jsonl").read_text(encoding="utf-8").splitlines()]
            rows[0]["repeat"] = 2
            (root / "results.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "duplicate-repeat.json", evidence_type="model_high_risk_stability", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources, root=Path.cwd())

    def test_high_risk_failing_group_cannot_be_ignored(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = _model_sources(root, repeats=5)
            rows = [json.loads(line) for line in (root / "results.jsonl").read_text(encoding="utf-8").splitlines()]
            target = next(row for row in rows if row["category"] == "financial_table")
            target["semantic"]["critical_failures"] = ["NUMERIC"]
            summary = json.loads((root / "summary.json").read_text(encoding="utf-8"))
            summary["critical_failure_count"] = 1
            _write(root / "summary.json", summary)
            (root / "results.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "failing-group.json", evidence_type="model_high_risk_stability", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources, root=Path.cwd())

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
