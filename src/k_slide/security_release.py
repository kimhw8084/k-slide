"""Closed, candidate-bound security release evidence for the existing security gate."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .egress_policy import EgressPolicy
from .runtime_artifact import BASE_IMAGE_DIGEST, BASE_IMAGE_NAME, BASE_IMAGE_TAG, SUPPORTED_PLATFORM


SECURITY_RELEASE_CONTRACT_VERSION = "1.0"
SECURITY_RELEASE_POLICY = {
    "schema_version": "1.0",
    "contract": {"id": "k-slide.candidate-security-release-evidence", "version": "1.0"},
    "policy": {"id": "kimhw8084-k-slide-security-release", "version": "1.0"},
    "max_scanner_age_minutes": 120,
    "max_vulnerability_database_age_hours": 48,
    "max_vulnerability_exception_days": 30,
    "scanners": [
        {"id": "pip_audit", "version": "2.9.0", "subject": "production_dependency_lock"},
        {"id": "gitleaks", "version": "8.24.2", "subject": "candidate_source_tree"},
        {"id": "semgrep", "version": "1.89.0", "subject": "candidate_source_tree"},
        {"id": "trivy", "version": "0.74.0", "archive_sha256": "2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a", "subject": "pinned_runtime_image"},
    ],
    "required_controls": [
        {"id": "KSA-15", "test_module": "tests.test_chg16_accesskey_nonleakage", "source_path": "tests/test_chg16_accesskey_nonleakage.py"},
        {"id": "KSA-17", "test_module": "tests.test_chg17_run_scope_authorization", "source_path": "tests/test_chg17_run_scope_authorization.py"},
        {"id": "KSA-18", "test_module": "tests.test_chg18_default_deny_egress", "source_path": "tests/test_chg18_default_deny_egress.py"},
        {"id": "KSA-21", "test_module": "tests.test_ksa21_adversarial_security", "source_path": "tests/test_ksa21_adversarial_security.py"},
        {"id": "KSA-32", "test_module": "tests.test_ksa32_release_governance", "source_path": "tests/test_ksa32_release_governance.py"},
    ],
    "vulnerability_dispositions": {
        "allowed": ["accepted_risk", "not_affected"],
        "accepted_risk_severities": ["LOW", "MEDIUM"],
        "reason_codes": ["upstream_disputed", "unreachable_vulnerable_code", "platform_not_affected", "temporary_low_severity_exception"],
        "approval_owner": "kimhw8084",
    },
    "company_environment_status": {
        "iam": "UNQUALIFIED",
        "network_egress": "UNQUALIFIED",
        "deployed_runtime_identity": "UNQUALIFIED",
    },
}
_POLICY_PATH = Path(__file__).resolve().parents[2] / "security" / "release-security-policy.json"
_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_SEVERITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"})


class SecurityReleaseEvidenceError(ValueError):
    """Security release inputs are incomplete, stale, ambiguous, or inconsistent."""


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def candidate_tree_sha256(tree_oid: str) -> str:
    """Derive a SHA-256 binding from the exact Git tree object identity."""
    if not isinstance(tree_oid, str) or not _HEX40.fullmatch(tree_oid):
        raise SecurityReleaseEvidenceError("candidate Git tree identity is malformed")
    return sha256(b"k-slide.git-tree-oid.v1\0" + tree_oid.encode("ascii"))


def _expect(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise SecurityReleaseEvidenceError(f"{label} has missing or unsupported fields")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _HEX64.fullmatch(value):
        raise SecurityReleaseEvidenceError(f"{label} is malformed")
    return value


def _utc(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        raise SecurityReleaseEvidenceError(f"{label} is missing")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SecurityReleaseEvidenceError(f"{label} is malformed") from exc
    if result.tzinfo is None:
        raise SecurityReleaseEvidenceError(f"{label} must include a timezone")
    return result.astimezone(timezone.utc)


def load_pinned_security_policy(path: Path | None = None) -> dict[str, Any]:
    source = path or _POLICY_PATH
    try:
        policy = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SecurityReleaseEvidenceError("security release policy is missing or malformed") from exc
    if policy != SECURITY_RELEASE_POLICY:
        raise SecurityReleaseEvidenceError("security release policy is not the pinned KSA-33 policy")
    return policy


def _finding_identity(record: dict[str, Any]) -> str:
    return sha256(canonical_bytes(record))


def _normalized_findings(pip: dict[str, Any], trivy: dict[str, Any]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    dependencies = pip.get("dependencies")
    if not isinstance(dependencies, list) or not dependencies:
        raise SecurityReleaseEvidenceError("dependency scan has no complete dependency inventory")
    for dependency in dependencies:
        if not isinstance(dependency, dict) or not isinstance(dependency.get("vulns"), list):
            raise SecurityReleaseEvidenceError("dependency scan omitted a package vulnerability inventory")
        for vuln in dependency["vulns"]:
            vuln_id = str(vuln.get("id") or "").strip().upper()
            if not vuln_id:
                raise SecurityReleaseEvidenceError("pip-audit vulnerability has no advisory identity")
            findings.append({
                "scanner": "pip_audit",
                "package": str(dependency["name"]).casefold().replace("_", "-"),
                "version": str(dependency["version"]),
                "vulnerability_id": vuln_id,
                "severity": "UNKNOWN",
            })
    vulnerabilities = trivy.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise SecurityReleaseEvidenceError("container scan has no complete vulnerability inventory")
    for vuln in vulnerabilities:
        row = _expect(vuln, {"package", "version", "vulnerability_id", "severity", "fixed_version"}, "container vulnerability")
        severity = str(row["severity"]).upper()
        if severity not in _SEVERITIES:
            raise SecurityReleaseEvidenceError("container vulnerability severity is invalid")
        if not all(isinstance(row[key], str) and row[key] for key in ("package", "version", "vulnerability_id")):
            raise SecurityReleaseEvidenceError("container vulnerability identity is incomplete")
        findings.append({
            "scanner": "trivy",
            "package": row["package"].casefold(),
            "version": row["version"],
            "vulnerability_id": row["vulnerability_id"].upper(),
            "severity": severity,
        })
    return sorted(findings, key=lambda item: (item["scanner"], item["package"], item["version"], item["vulnerability_id"], item["severity"]))


def _validate_dispositions(
    *,
    findings: list[dict[str, str]],
    source: Any,
    captured_at: datetime,
    subject: str,
    tree_sha256: str,
    deployment: str,
    policy: dict[str, Any],
) -> list[dict[str, Any]]:
    doc = _expect(source, {"schema_version", "policy_id", "candidate_binding", "dispositions"}, "vulnerability disposition source")
    if doc["schema_version"] != "1.0" or doc["policy_id"] != policy["policy"]["id"] or not isinstance(doc["dispositions"], list):
        raise SecurityReleaseEvidenceError("vulnerability disposition source is not policy-bound")
    binding = doc["candidate_binding"]
    if not doc["dispositions"]:
        if binding is not None:
            _expect(binding, {"subject_git_sha", "source_tree_sha256", "deployment_fingerprint"}, "empty disposition candidate binding")
            if binding != {"subject_git_sha": subject, "source_tree_sha256": tree_sha256, "deployment_fingerprint": deployment}:
                raise SecurityReleaseEvidenceError("empty vulnerability disposition source is replayed from another candidate")
    else:
        binding = _expect(binding, {"subject_git_sha", "source_tree_sha256", "deployment_fingerprint"}, "vulnerability disposition candidate binding")
        if binding != {"subject_git_sha": subject, "source_tree_sha256": tree_sha256, "deployment_fingerprint": deployment}:
            raise SecurityReleaseEvidenceError("vulnerability dispositions are replayed from another candidate")
    expected = {_finding_identity(item): item for item in findings}
    seen: set[str] = set()
    normalized: list[dict[str, Any]] = []
    allowed = set(policy["vulnerability_dispositions"]["allowed"])
    reasons = set(policy["vulnerability_dispositions"]["reason_codes"])
    for raw in doc["dispositions"]:
        row = _expect(raw, {"finding_identity_sha256", "disposition", "reason_code", "evidence_sha256", "expires_at", "approval_owner"}, "vulnerability disposition")
        identity = _digest(row["finding_identity_sha256"], "vulnerability finding identity")
        if identity not in expected or identity in seen:
            raise SecurityReleaseEvidenceError("vulnerability dispositions are omitted, duplicated, or unrelated")
        seen.add(identity)
        finding = expected[identity]
        disposition = row["disposition"]
        reason = row["reason_code"]
        if disposition not in allowed or reason not in reasons:
            raise SecurityReleaseEvidenceError("vulnerability disposition is not allowed by policy")
        _digest(row["evidence_sha256"], "vulnerability disposition evidence identity")
        if row["approval_owner"] != policy["vulnerability_dispositions"]["approval_owner"]:
            raise SecurityReleaseEvidenceError("vulnerability disposition has no eligible approval owner")
        expiry = _utc(row["expires_at"], "vulnerability disposition expiry")
        if expiry <= captured_at or expiry > captured_at + timedelta(days=policy["max_vulnerability_exception_days"]):
            raise SecurityReleaseEvidenceError("vulnerability disposition is stale or exceeds its policy window")
        if disposition == "accepted_risk":
            if finding["severity"] not in set(policy["vulnerability_dispositions"]["accepted_risk_severities"]):
                raise SecurityReleaseEvidenceError("severity is not eligible for accepted-risk disposition")
            if reason != "temporary_low_severity_exception":
                raise SecurityReleaseEvidenceError("accepted-risk disposition has an invalid reason code")
        elif reason == "temporary_low_severity_exception":
            raise SecurityReleaseEvidenceError("not-affected disposition has an invalid reason code")
        normalized.append({
            **finding,
            "finding_identity_sha256": identity,
            "disposition": disposition,
            "reason_code": reason,
            "evidence_sha256": row["evidence_sha256"],
            "expires_at": expiry.isoformat().replace("+00:00", "Z"),
            "approval_owner": row["approval_owner"],
            "candidate_subject_sha": subject,
            "candidate_tree_sha256": tree_sha256,
            "deployment_fingerprint": deployment,
        })
    if seen != set(expected):
        raise SecurityReleaseEvidenceError("every vulnerability finding requires an explicit disposition")
    return sorted(normalized, key=lambda item: item["finding_identity_sha256"])


def derive_security_release_evidence(
    *,
    context: Any,
    policy_source: Path,
    disposition_source: Any,
    egress_source: Any,
    pip_audit: dict[str, Any],
    gitleaks: Any,
    semgrep: dict[str, Any],
    trivy: dict[str, Any],
    scanner_source_hashes: dict[str, str],
    subject_git_sha: str,
    deployment_fingerprint: str,
    candidate_spec: dict[str, Any] | None,
    repository_root: Path | None = None,
) -> dict[str, Any]:
    policy = load_pinned_security_policy(policy_source)
    value = _expect(context, {"schema_version", "contract", "candidate", "run", "runner", "runtime", "egress_policy", "scanners", "controls", "privacy", "company_environment"}, "security release context")
    if value["schema_version"] != "1.0" or value["contract"] != policy["contract"]:
        raise SecurityReleaseEvidenceError("security release context has the wrong contract")
    candidate = _expect(value["candidate"], {"subject_git_sha", "source_tree_sha256", "deployment_fingerprint", "candidate_spec_identity_sha256"}, "candidate binding")
    if candidate["subject_git_sha"] != subject_git_sha or candidate["deployment_fingerprint"] != deployment_fingerprint:
        raise SecurityReleaseEvidenceError("security release context belongs to another candidate")
    if not isinstance(candidate["subject_git_sha"], str) or not _HEX40.fullmatch(candidate["subject_git_sha"]):
        raise SecurityReleaseEvidenceError("candidate subject SHA is malformed")
    tree_sha256 = _digest(candidate["source_tree_sha256"], "candidate source tree identity")
    candidate_spec_identity = _digest(candidate["candidate_spec_identity_sha256"], "candidate specification identity")
    if candidate_spec is not None:
        from .certification import canonical_candidate_factors

        if candidate_spec.get("subject_git_sha") != subject_git_sha or candidate_spec_identity != sha256(canonical_bytes(canonical_candidate_factors(candidate_spec))):
            raise SecurityReleaseEvidenceError("candidate specification identity does not match its evidence binding")
    _digest(deployment_fingerprint, "candidate deployment fingerprint")

    run = _expect(value["run"], {"workflow", "run_id", "run_attempt", "captured_at"}, "security workflow run")
    if run["workflow"] != "K-Slide security evidence" or not isinstance(run["run_id"], str) or not run["run_id"].isdigit() or int(run["run_id"]) < 1:
        raise SecurityReleaseEvidenceError("security workflow run identity is missing or invalid")
    if isinstance(run["run_attempt"], bool) or not isinstance(run["run_attempt"], int) or run["run_attempt"] < 1:
        raise SecurityReleaseEvidenceError("security workflow attempt is missing or invalid")
    captured_at = _utc(run["captured_at"], "security evidence capture time")

    runner = _expect(value["runner"], {"image", "image_version", "python_version"}, "security runner identity")
    if runner["image"] != "ubuntu-24.04" or not isinstance(runner["image_version"], str) or not runner["image_version"] or not isinstance(runner["python_version"], str) or not re.fullmatch(r"3\.11\.[0-9]+", runner["python_version"]):
        raise SecurityReleaseEvidenceError("security runner identity is not pinned or complete")

    runtime = _expect(value["runtime"], {"artifact_identity_sha256", "manifest_sha256", "sbom_sha256", "dependency_lock_sha256", "image_digest", "base_image", "platform", "source_revision", "source_tree_sha256", "python_version"}, "runtime image proof")
    for key in ("artifact_identity_sha256", "manifest_sha256", "sbom_sha256", "dependency_lock_sha256"):
        _digest(runtime[key], f"runtime {key}")
    image_match = re.fullmatch(r"sha256:[0-9a-f]{64}", str(runtime["image_digest"]))
    if not image_match or runtime["base_image"] != f"{BASE_IMAGE_NAME}:{BASE_IMAGE_TAG}@{BASE_IMAGE_DIGEST}" or runtime["platform"] != SUPPORTED_PLATFORM:
        raise SecurityReleaseEvidenceError("runtime image is not the pinned K-Slide image")
    if runtime["source_revision"] != subject_git_sha:
        raise SecurityReleaseEvidenceError("runtime image is bound to another source revision")
    _digest(runtime["source_tree_sha256"], "runtime source tree identity")
    if not isinstance(runtime["python_version"], str) or not re.fullmatch(r"3\.11\.[0-9]+", runtime["python_version"]):
        raise SecurityReleaseEvidenceError("runtime Python identity is malformed or unsupported")
    if candidate_spec is not None:
        identity = candidate_spec.get("runtime_artifact_identity")
        expected_artifact = identity.get("sha256") if isinstance(identity, dict) else identity
        if expected_artifact not in (None, "", "UNSET") and expected_artifact != runtime["artifact_identity_sha256"]:
            raise SecurityReleaseEvidenceError("runtime artifact identity disagrees with the candidate")
        for field, key in (("runtime_artifact_manifest_sha256", "manifest_sha256"), ("runtime_sbom_sha256", "sbom_sha256"), ("python_version", "python_version")):
            if candidate_spec.get(field) not in (None, "", "UNSET") and candidate_spec.get(field) != runtime[key]:
                raise SecurityReleaseEvidenceError("runtime identity disagrees with the candidate")

    egress = EgressPolicy.from_mapping(egress_source)
    if egress.reference_adapter:
        raise SecurityReleaseEvidenceError("reference egress policy cannot qualify security evidence")
    egress_binding = _expect(value["egress_policy"], {"version", "hash", "identity", "default_action"}, "candidate egress policy binding")
    if egress_binding != {"version": egress.policy_version, "hash": egress.policy_hash, "identity": egress.policy_identity, "default_action": egress.default_action}:
        raise SecurityReleaseEvidenceError("captured egress policy does not match the candidate policy")
    if candidate_spec is not None:
        if candidate_spec.get("network_egress") != "default_deny":
            raise SecurityReleaseEvidenceError("egress policy identity disagrees with the candidate")
        egress_fields = (candidate_spec.get("egress_policy_version"), candidate_spec.get("egress_policy_hash"), candidate_spec.get("egress_policy_identity"))
        if all(item not in (None, "", "UNSET") for item in egress_fields) and egress_fields != (egress.policy_version, egress.policy_hash, egress.policy_identity):
            raise SecurityReleaseEvidenceError("egress policy identity disagrees with the candidate")

    scanner_rows = value["scanners"]
    if not isinstance(scanner_rows, list) or len(scanner_rows) != len(policy["scanners"]):
        raise SecurityReleaseEvidenceError("required scanner evidence is incomplete")
    scanner_by_id: dict[str, dict[str, Any]] = {}
    report_roles = {"pip_audit": "pip_audit", "gitleaks": "gitleaks", "semgrep": "semgrep", "trivy": "container_scan"}
    for scanner, expected in zip(scanner_rows, policy["scanners"]):
        row = _expect(scanner, {"id", "version", "status", "exit_code", "report_sha256", "finished_at", "run_id", "run_attempt", "finding_count", "error_count", "subject_identity"}, "scanner result")
        if row["id"] != expected["id"] or row["id"] in scanner_by_id or row["version"] != expected["version"]:
            raise SecurityReleaseEvidenceError("scanner is missing, duplicated, or not pinned")
        if row["status"] != "PASS" or isinstance(row["exit_code"], bool) or not isinstance(row["exit_code"], int):
            raise SecurityReleaseEvidenceError("scanner failed or was unavailable")
        _digest(row["report_sha256"], f"{row['id']} report identity")
        expected_source_hash = scanner_source_hashes.get(report_roles[row["id"]])
        if expected_source_hash is None or row["report_sha256"] != expected_source_hash:
            raise SecurityReleaseEvidenceError("scanner result hash disagrees with its minimized report")
        if row["run_id"] != run["run_id"] or row["run_attempt"] != run["run_attempt"]:
            raise SecurityReleaseEvidenceError("scanner result is stale or belongs to another workflow attempt")
        finished = _utc(row["finished_at"], f"{row['id']} completion time")
        if finished > captured_at or captured_at - finished > timedelta(minutes=policy["max_scanner_age_minutes"]):
            raise SecurityReleaseEvidenceError("scanner result is stale or postdates evidence capture")
        for count_key in ("finding_count", "error_count"):
            if isinstance(row[count_key], bool) or not isinstance(row[count_key], int) or row[count_key] < 0:
                raise SecurityReleaseEvidenceError("scanner finding counts are malformed")
        if row["id"] == "pip_audit":
            if row["exit_code"] not in ({0, 1} if row["finding_count"] > 0 else {0}):
                raise SecurityReleaseEvidenceError("dependency scanner did not complete with an explainable result")
            expected_subject = runtime["dependency_lock_sha256"]
        elif row["id"] in {"gitleaks", "semgrep"}:
            if row["exit_code"] != 0:
                raise SecurityReleaseEvidenceError("secret or static scanner failed")
            expected_subject = tree_sha256
        else:
            if row["exit_code"] != 0:
                raise SecurityReleaseEvidenceError("container scanner failed")
            expected_subject = runtime["image_digest"]
        if row["subject_identity"] != expected_subject:
            raise SecurityReleaseEvidenceError("scanner result covered the wrong subject")
        if row["id"] == "trivy" and row["subject_identity"] != runtime["image_digest"]:
            raise SecurityReleaseEvidenceError("container scanner covered the wrong image")
        scanner_by_id[row["id"]] = row
    if set(scanner_by_id) != {item["id"] for item in policy["scanners"]}:
        raise SecurityReleaseEvidenceError("one or more required scanners are unavailable")

    trivy = _expect(trivy, {"schema_version", "target_image_digest", "scanned_classes", "scanned_class_package_counts", "database_updated_at", "database_version", "database_schema_version", "error_count", "vulnerabilities"}, "container scan result")
    if trivy.get("schema_version") != "1.0" or trivy.get("target_image_digest") != runtime["image_digest"]:
        raise SecurityReleaseEvidenceError("container scan is malformed or covers another image")
    if trivy.get("scanned_classes") != ["lang-pkgs", "os-pkgs"]:
        raise SecurityReleaseEvidenceError("container scan did not cover both OS and language package subjects")
    package_counts = trivy.get("scanned_class_package_counts")
    if not isinstance(package_counts, dict) or set(package_counts) != {"lang-pkgs", "os-pkgs"} or any(isinstance(count, bool) or not isinstance(count, int) or count < 1 for count in package_counts.values()):
        raise SecurityReleaseEvidenceError("container scan package inventory is incomplete")
    db_updated_at = _utc(trivy.get("database_updated_at"), "Trivy database update time")
    if db_updated_at > captured_at or captured_at - db_updated_at > timedelta(hours=policy["max_vulnerability_database_age_hours"]):
        raise SecurityReleaseEvidenceError("Trivy vulnerability database is stale")
    for key in ("database_version", "database_schema_version"):
        if isinstance(trivy.get(key), bool) or not isinstance(trivy.get(key), int) or trivy[key] < 1:
            raise SecurityReleaseEvidenceError("Trivy database identity is incomplete")
    trivy_errors = trivy.get("error_count")
    if isinstance(trivy_errors, bool) or not isinstance(trivy_errors, int) or trivy_errors < 0:
        raise SecurityReleaseEvidenceError("Trivy error count is malformed")
    counts = {
        "pip_audit": sum(len(item.get("vulns", [])) for item in pip_audit.get("dependencies", []) if isinstance(item, dict)),
        "gitleaks": len(gitleaks),
        "semgrep": len(semgrep.get("results", [])),
        "trivy": len(trivy.get("vulnerabilities", [])),
    }
    errors = {"pip_audit": 0, "gitleaks": 0, "semgrep": len(semgrep.get("errors", [])), "trivy": trivy_errors}
    for scanner_id, scanner in scanner_by_id.items():
        if scanner["finding_count"] != counts[scanner_id] or scanner["error_count"] != errors[scanner_id]:
            raise SecurityReleaseEvidenceError("scanner summary disagrees with its minimized report")
    if counts["gitleaks"] or counts["semgrep"] or errors["semgrep"] or errors["trivy"]:
        raise SecurityReleaseEvidenceError("secret, static-analysis, or image scanner findings/errors remain")

    controls = value["controls"]
    if not isinstance(controls, list) or len(controls) != len(policy["required_controls"]):
        raise SecurityReleaseEvidenceError("required security control test results are incomplete")
    root = (repository_root or _REPOSITORY_ROOT).expanduser().resolve()
    commit_tree: str | None = None
    if repository_root is not None:
        try:
            commit_tree = subprocess.check_output(
                ["git", "-C", str(root), "rev-parse", f"{subject_git_sha}^{{tree}}"],
                stderr=subprocess.DEVNULL,
                text=True,
            ).strip()
        except (OSError, subprocess.CalledProcessError):
            commit_tree = None
        if commit_tree is not None and candidate_tree_sha256(commit_tree) != tree_sha256:
            raise SecurityReleaseEvidenceError("candidate source tree SHA does not match the candidate commit")
    if not all((root / item["source_path"]).is_file() for item in policy["required_controls"]):
        if commit_tree is not None:
            raise SecurityReleaseEvidenceError("candidate repository is missing required security control tests")
        root = _REPOSITORY_ROOT
    control_results: list[dict[str, Any]] = []
    seen_controls: set[str] = set()
    for result, required in zip(controls, policy["required_controls"]):
        row = _expect(result, {"id", "status", "tests_run", "tests_failed", "tests_skipped", "source_sha256", "run_id", "run_attempt"}, "security control result")
        if row["id"] != required["id"] or row["id"] in seen_controls or row["status"] != "PASS":
            raise SecurityReleaseEvidenceError("required security control is missing or failed")
        seen_controls.add(row["id"])
        if row["run_id"] != run["run_id"] or row["run_attempt"] != run["run_attempt"]:
            raise SecurityReleaseEvidenceError("security control result belongs to another workflow attempt")
        if any(isinstance(row[key], bool) or not isinstance(row[key], int) or row[key] < 0 for key in ("tests_run", "tests_failed", "tests_skipped")) or row["tests_run"] <= row["tests_skipped"] or row["tests_failed"] != 0:
            raise SecurityReleaseEvidenceError("security control test counts are incomplete or failed")
        source_hash = _digest(row["source_sha256"], "security control source identity")
        source_path = root / required["source_path"]
        if not source_path.is_file() or source_path.is_symlink() or hashlib.sha256(source_path.read_bytes()).hexdigest() != source_hash:
            raise SecurityReleaseEvidenceError("security control test source does not match this candidate tree")
        control_results.append({"id": row["id"], "status": "PASS", "tests_run": row["tests_run"], "tests_skipped": row["tests_skipped"], "source_sha256": source_hash, "run_id": row["run_id"], "run_attempt": row["run_attempt"]})
    if seen_controls != {item["id"] for item in policy["required_controls"]}:
        raise SecurityReleaseEvidenceError("required security controls are incomplete")

    privacy = _expect(value["privacy"], {"raw_scanner_payloads_persisted", "source_document_content_persisted", "access_key_values_persisted", "accesskey_nonleakage_test_pass"}, "security evidence privacy declaration")
    if privacy != {"raw_scanner_payloads_persisted": False, "source_document_content_persisted": False, "access_key_values_persisted": False, "accesskey_nonleakage_test_pass": True}:
        raise SecurityReleaseEvidenceError("security evidence violates the source-free or secret-free boundary")
    company = _expect(value["company_environment"], {"iam", "network_egress", "deployed_runtime_identity"}, "company environment qualification")
    if company != policy["company_environment_status"]:
        raise SecurityReleaseEvidenceError("repository evidence cannot qualify live company controls")

    findings = _normalized_findings(pip_audit, trivy)
    finding_ids = [_finding_identity(item) for item in findings]
    if len(finding_ids) != len(set(finding_ids)):
        raise SecurityReleaseEvidenceError("scanner results contain duplicate vulnerability findings")
    dispositions = _validate_dispositions(
        findings=findings,
        source=disposition_source,
        captured_at=captured_at,
        subject=subject_git_sha,
        tree_sha256=tree_sha256,
        deployment=deployment_fingerprint,
        policy=policy,
    )
    unresolved = sum(1 for item in dispositions if item["disposition"] not in {"accepted_risk", "not_affected"})
    return {
        "contract_version": SECURITY_RELEASE_CONTRACT_VERSION,
        "contract_identity_sha256": sha256(canonical_bytes(policy["contract"])),
        "policy_id": policy["policy"]["id"],
        "policy_version": policy["policy"]["version"],
        "policy_identity_sha256": sha256(canonical_bytes(policy)),
        "candidate_subject_sha": subject_git_sha,
        "candidate_tree_sha256": tree_sha256,
        "deployment_fingerprint": deployment_fingerprint,
        "candidate_spec_identity_sha256": candidate_spec_identity,
        "security_run_id": run["run_id"],
        "security_run_attempt": run["run_attempt"],
        "security_captured_at": captured_at.isoformat().replace("+00:00", "Z"),
        "runner_image": runner["image"],
        "runner_image_version": runner["image_version"],
        "runner_python_version": runner["python_version"],
        "runtime_artifact_identity_sha256": runtime["artifact_identity_sha256"],
        "runtime_manifest_sha256": runtime["manifest_sha256"],
        "runtime_sbom_sha256": runtime["sbom_sha256"],
        "runtime_dependency_lock_sha256": runtime["dependency_lock_sha256"],
        "runtime_image_digest": runtime["image_digest"],
        "runtime_source_tree_sha256": runtime["source_tree_sha256"],
        "runtime_base_image": runtime["base_image"],
        "runtime_platform": runtime["platform"],
        "container_package_counts": package_counts,
        "egress_policy_version": egress.policy_version,
        "egress_policy_hash": egress.policy_hash,
        "egress_policy_identity": egress.policy_identity,
        "egress_default_action": egress.default_action,
        "scanner_results": [
            {
                "id": key,
                "version": scanner_by_id[key]["version"],
                "status": scanner_by_id[key]["status"],
                "exit_code": scanner_by_id[key]["exit_code"],
                "report_sha256": scanner_by_id[key]["report_sha256"],
                "finished_at": scanner_by_id[key]["finished_at"],
                "run_id": scanner_by_id[key]["run_id"],
                "run_attempt": scanner_by_id[key]["run_attempt"],
                "finding_count": counts[key],
                "error_count": errors[key],
                "subject_identity": scanner_by_id[key]["subject_identity"],
            }
            for key in sorted(scanner_by_id)
        ],
        "required_control_results": control_results,
        "vulnerability_finding_count": len(findings),
        "vulnerability_disposition_count": len(dispositions),
        "vulnerability_dispositions": dispositions,
        "unresolved_vulnerability_count": unresolved,
        "dependency_audit_pass": True,
        "secret_scan_pass": True,
        "static_scan_pass": True,
        "container_scan_pass": True,
        "repository_security_pass": True,
        "source_document_content_persisted": False,
        "raw_scanner_payloads_persisted": False,
        "access_key_values_persisted": False,
        "company_iam_status": "UNQUALIFIED",
        "company_network_egress_status": "UNQUALIFIED",
        "company_deployed_runtime_status": "UNQUALIFIED",
    }


__all__ = [
    "SECURITY_RELEASE_CONTRACT_VERSION",
    "SECURITY_RELEASE_POLICY",
    "SecurityReleaseEvidenceError",
    "derive_security_release_evidence",
    "load_pinned_security_policy",
    "candidate_tree_sha256",
    "canonical_bytes",
    "sha256",
]
