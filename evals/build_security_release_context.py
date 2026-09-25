"""Capture closed, candidate-bound metadata for minimized security reports."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from k_slide.certification import canonical_candidate_factors
from k_slide.egress_policy import EgressPolicy
from k_slide.runtime_artifact import source_tree_sha256
from k_slide.security_release import SECURITY_RELEASE_POLICY, candidate_tree_sha256, canonical_bytes
from scripts.build_runtime_artifact import _source_files


def _json(path: Path) -> Any:
    if path.is_symlink() or not path.is_file():
        raise ValueError("required security release input is unavailable")
    return json.loads(path.read_text(encoding="utf-8"))


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _verify_runtime_source_archive(source_tree: Path, source_files: list[Path], runtime_source_hash: Any) -> None:
    if not source_files:
        raise ValueError("candidate runtime source inventory is empty")
    for relative in source_files:
        source_file = source_tree / relative
        if source_file.is_symlink() or not source_file.is_file():
            raise ValueError("candidate runtime source archive is incomplete")
    archived_source_hash = source_tree_sha256(source_tree, paths=[item.as_posix() for item in source_files])
    if runtime_source_hash != archived_source_hash:
        raise ValueError("runtime artifact source tree does not match the exact candidate Git archive")


def _version(raw: Any, expected: str, name: str) -> str:
    matches = re.findall(r"(?<![0-9.])v?(\d+\.\d+\.\d+)(?![0-9.])", raw) if isinstance(raw, str) else []
    if expected not in matches:
        raise ValueError(f"{name} version does not match the pinned policy")
    return expected


def build_context(*, root: Path, source_tree: Path, evidence: Path, runtime: Path, identity_path: Path, egress_path: Path, controls_path: Path, exits_path: Path, finished_path: Path, versions_path: Path, output: Path, runner_image_version: str, run_id: str, run_attempt: int) -> dict[str, Any]:
    root = root.resolve()
    identity = _json(identity_path)
    candidate = identity.get("candidate_spec")
    subject = identity.get("subject_git_sha")
    deployment = identity.get("deployment_fingerprint")
    if not isinstance(candidate, dict) or not isinstance(subject, str) or not isinstance(deployment, str):
        raise ValueError("candidate identity is incomplete")
    tree_oid = subprocess.check_output(["git", "-C", str(root), "rev-parse", f"{subject}^{{tree}}"], text=True).strip()
    head_tree_oid = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD^{tree}"], text=True).strip()
    if tree_oid != head_tree_oid:
        raise ValueError("checked-out candidate tree does not match the source revision")
    tree_sha = candidate_tree_sha256(tree_oid)
    if not run_id.isdigit() or int(run_id) < 1 or run_attempt < 1:
        raise ValueError("workflow run identity is incomplete")

    manifest_path = runtime / "runtime-manifest.json"
    sbom_path = runtime / "runtime-sbom.json"
    artifact_path = runtime / "artifact-identity.json"
    manifest = _json(manifest_path)
    artifact = _json(artifact_path)
    source_tree = source_tree.expanduser().resolve()
    source_files = _source_files(root)
    _verify_runtime_source_archive(source_tree, source_files, manifest.get("source_tree_sha256"))
    image_identity = artifact.get("image_identity")
    if not isinstance(image_identity, dict) or image_identity.get("kind") not in {"registry-digest", "local-image-id"}:
        raise ValueError("runtime image does not have an immutable identity")
    image_digest = image_identity.get("value")
    artifact_core = manifest.get("artifact_identity")
    if not isinstance(artifact_core, dict) or not isinstance(artifact_core.get("sha256"), str):
        raise ValueError("runtime artifact identity is incomplete")
    base = manifest.get("base_image")
    if not isinstance(base, dict) or not isinstance(base.get("ref"), str):
        raise ValueError("runtime base image identity is incomplete")
    if (
        artifact.get("runtime_manifest_sha256") != _sha(manifest_path)
        or artifact.get("sbom_sha256") != _sha(sbom_path)
        or artifact.get("source_revision") != subject
        or artifact.get("supported_platform") != manifest.get("supported_platform")
        or artifact.get("base_image_digest") != str(base.get("digest", "")).removeprefix("sha256:")
    ):
        raise ValueError("runtime artifact identity disagrees with its manifest, SBOM, or candidate")
    dependency_lock = root / ".k-slide-config" / "production-requirements.lock"
    if not dependency_lock.is_file():
        dependency_lock = root / "constraints-production.txt"
    lock_hash = _sha(dependency_lock)

    egress_doc = _json(egress_path)
    egress = EgressPolicy.from_mapping(egress_doc)
    if egress.reference_adapter:
        raise ValueError("reference egress policy cannot qualify security evidence")
    scanner_docs = {
        "pip_audit": _json(evidence / "pip-audit.json"),
        "gitleaks": _json(evidence / "gitleaks.json"),
        "semgrep": _json(evidence / "semgrep.json"),
        "trivy": _json(evidence / "container-scan.json"),
    }
    exits = _json(exits_path)
    finished = _json(finished_path)
    versions = _json(versions_path)
    if set(exits) != {"pip_audit", "gitleaks", "semgrep", "trivy"} or set(finished) != set(exits) or set(versions) != set(exits):
        raise ValueError("scanner execution metadata is incomplete")
    policy_scanners = {row["id"]: row for row in SECURITY_RELEASE_POLICY["scanners"]}
    report_paths = {key: evidence / filename for key, filename in {"pip_audit": "pip-audit.json", "gitleaks": "gitleaks.json", "semgrep": "semgrep.json", "trivy": "container-scan.json"}.items()}
    findings = {
        "pip_audit": sum(len(row.get("vulns", [])) for row in scanner_docs["pip_audit"].get("dependencies", [])),
        "gitleaks": len(scanner_docs["gitleaks"]),
        "semgrep": len(scanner_docs["semgrep"].get("results", [])),
        "trivy": len(scanner_docs["trivy"].get("vulnerabilities", [])),
    }
    errors = {
        "pip_audit": 0,
        "gitleaks": 0,
        "semgrep": len(scanner_docs["semgrep"].get("errors", [])),
        "trivy": scanner_docs["trivy"].get("error_count"),
    }
    subjects = {"pip_audit": lock_hash, "gitleaks": tree_sha, "semgrep": tree_sha, "trivy": image_digest}
    scanner_rows = []
    for scanner_id, expected in policy_scanners.items():
        scanner_rows.append({
            "id": scanner_id,
            "version": _version(versions[scanner_id], expected["version"], scanner_id),
            "status": "PASS" if exits[scanner_id] in (0, 1) and (scanner_id == "pip_audit" or exits[scanner_id] == 0) else "FAIL",
            "exit_code": exits[scanner_id],
            "report_sha256": _sha(report_paths[scanner_id]),
            "finished_at": finished[scanner_id],
            "run_id": run_id,
            "run_attempt": run_attempt,
            "finding_count": findings[scanner_id],
            "error_count": errors[scanner_id],
            "subject_identity": subjects[scanner_id],
        })

    controls = _json(controls_path)
    context = {
        "schema_version": "1.0",
        "contract": SECURITY_RELEASE_POLICY["contract"],
        "candidate": {
            "subject_git_sha": subject,
            "source_tree_sha256": tree_sha,
            "deployment_fingerprint": deployment,
            "candidate_spec_identity_sha256": hashlib.sha256(canonical_bytes(canonical_candidate_factors(candidate))).hexdigest(),
        },
        "run": {
            "workflow": "K-Slide security evidence",
            "run_id": run_id,
            "run_attempt": run_attempt,
            "captured_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        },
        "runner": {"image": "ubuntu-24.04", "image_version": runner_image_version, "python_version": platform.python_version()},
        "runtime": {
            "artifact_identity_sha256": artifact_core["sha256"],
            "manifest_sha256": _sha(manifest_path),
            "sbom_sha256": _sha(sbom_path),
            "dependency_lock_sha256": lock_hash,
            "image_digest": image_digest,
            "base_image": base["ref"],
            "platform": manifest.get("supported_platform"),
            "source_revision": manifest.get("source_revision"),
            "source_tree_sha256": manifest.get("source_tree_sha256"),
            "python_version": manifest.get("python_version"),
        },
        "egress_policy": {"version": egress.policy_version, "hash": egress.policy_hash, "identity": egress.policy_identity, "default_action": egress.default_action},
        "scanners": scanner_rows,
        "controls": controls,
        "privacy": {"raw_scanner_payloads_persisted": False, "source_document_content_persisted": False, "access_key_values_persisted": False, "accesskey_nonleakage_test_pass": any(row.get("id") == "KSA-15" and row.get("status") == "PASS" for row in controls)},
        "company_environment": SECURITY_RELEASE_POLICY["company_environment_status"],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(context, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    return context


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Bind minimized scanner reports and control results to one candidate")
    for name in ("source-tree", "evidence", "runtime", "identity", "egress", "controls", "exits", "finished", "versions", "output"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--runner-image-version", default=os.environ.get("ImageVersion", ""))
    parser.add_argument("--run-id", default=os.environ.get("GITHUB_RUN_ID", ""))
    parser.add_argument("--run-attempt", type=int, default=int(os.environ.get("GITHUB_RUN_ATTEMPT", "0")))
    args = parser.parse_args(argv)
    try:
        build_context(root=args.root, source_tree=args.source_tree, evidence=args.evidence, runtime=args.runtime, identity_path=args.identity, egress_path=args.egress, controls_path=args.controls, exits_path=args.exits, finished_path=args.finished, versions_path=args.versions, output=args.output, runner_image_version=args.runner_image_version, run_id=args.run_id, run_attempt=args.run_attempt)
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
        print(json.dumps({"status": "FAIL", "reason": f"Candidate security context capture failed ({type(exc).__name__})."}, sort_keys=True))
        return 2
    print(json.dumps({"status": "PASS", "scanner_count": 4, "candidate_bound": True}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
