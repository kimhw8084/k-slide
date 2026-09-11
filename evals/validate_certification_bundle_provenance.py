"""Validate authoritative provenance for a private certification bundle.

The public K-Slide repository never treats a same-repository Actions artifact
as private.  Hosted certification callers must obtain the run and artifact
metadata from an approved private source repository, then verify the archive
digest before materializing any of its files.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any


class BundleProvenanceError(ValueError):
    """Raised when authoritative private-source metadata is insufficient."""


def _text(value: Any, label: str) -> str:
    result = str(value or "").strip()
    if not result:
        raise BundleProvenanceError(f"bundle provenance {label} is missing")
    return result


def _digest(value: Any, label: str) -> str:
    result = _text(value, label).lower()
    if result.startswith("sha256:"):
        result = result[7:]
    if len(result) != 64 or set(result) - set("0123456789abcdef"):
        raise BundleProvenanceError(f"bundle provenance {label} is not a SHA-256 digest")
    return result


def _run_repository(run: dict[str, Any]) -> str:
    repository = run.get("repository")
    if isinstance(repository, dict):
        return str(repository.get("full_name") or "").strip()
    return str(run.get("repository_full_name") or "").strip()


def _not_expired(artifact: dict[str, Any]) -> bool:
    if artifact.get("expired") is not False:
        return False
    raw = artifact.get("expires_at")
    if not raw:
        raise BundleProvenanceError("bundle artifact expiry metadata is missing")
    try:
        expires = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError as exc:
        raise BundleProvenanceError("bundle artifact expiry metadata is malformed") from exc
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    return expires > datetime.now(timezone.utc)


def validate_provenance(*, run: dict[str, Any], artifacts: dict[str, Any], expected_run_id: str, expected_artifact_name: str, expected_source_repository: str, expected_workflow_id: str, expected_workflow_path: str, subject_git_sha: str, expected_digest: str, public_repository: str) -> dict[str, Any]:
    source_repository = _text(expected_source_repository, "source repository")
    if source_repository.casefold() == _text(public_repository, "public repository").casefold():
        raise BundleProvenanceError("public-repository Actions artifacts are not an approved private transport")
    if str(run.get("id") or "") != _text(expected_run_id, "run id"):
        raise BundleProvenanceError("bundle source run id does not match the requested run")
    if _run_repository(run) != source_repository:
        raise BundleProvenanceError("bundle source repository does not match the approved private repository")
    if str(run.get("workflow_id") or "") != _text(expected_workflow_id, "workflow id"):
        raise BundleProvenanceError("bundle source workflow id is not approved")
    if str(run.get("path") or "") != _text(expected_workflow_path, "workflow path"):
        raise BundleProvenanceError("bundle source workflow path is not approved")
    if str(run.get("status") or "") != "completed" or str(run.get("conclusion") or "") != "success":
        raise BundleProvenanceError("bundle source workflow run did not complete successfully")
    subject = _text(subject_git_sha, "subject SHA").lower()
    if len(subject) != 40 or set(subject) - set("0123456789abcdef"):
        raise BundleProvenanceError("bundle provenance subject SHA is invalid")
    if str(run.get("head_sha") or "").lower() != subject:
        raise BundleProvenanceError("bundle source workflow subject does not match the certification subject")
    requested_name = _text(expected_artifact_name, "artifact name")
    records = artifacts.get("artifacts") if isinstance(artifacts, dict) else None
    if not isinstance(records, list):
        raise BundleProvenanceError("bundle source artifact listing is malformed")
    matches = [item for item in records if isinstance(item, dict) and item.get("name") == requested_name]
    if len(matches) != 1:
        raise BundleProvenanceError("approved bundle artifact is missing or ambiguous")
    artifact = matches[0]
    workflow_run = artifact.get("workflow_run")
    if not isinstance(workflow_run, dict) or str(workflow_run.get("id") or "") != str(run["id"]):
        raise BundleProvenanceError("bundle artifact does not belong to the declared workflow run")
    if not _not_expired(artifact):
        raise BundleProvenanceError("bundle artifact is expired")
    digest = _digest(artifact.get("digest"), "artifact digest")
    if digest != _digest(expected_digest, "expected artifact digest"):
        raise BundleProvenanceError("bundle artifact digest does not match the expected immutable digest")
    artifact_id = artifact.get("id")
    if isinstance(artifact_id, bool) or not isinstance(artifact_id, int) or artifact_id <= 0:
        raise BundleProvenanceError("bundle artifact id is missing")
    return {
        "status": "PASS",
        "source_repository": source_repository,
        "source_workflow_id": int(run["workflow_id"]),
        "source_workflow_path": str(run["path"]),
        "source_run_id": int(run["id"]),
        "subject_git_sha": str(run["head_sha"]),
        "artifact_id": artifact_id,
        "artifact_name": requested_name,
        "artifact_digest": digest,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate authoritative private certification bundle provenance")
    parser.add_argument("--run-json", required=True)
    parser.add_argument("--artifacts-json", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--artifact-name", required=True)
    parser.add_argument("--source-repository", required=True)
    parser.add_argument("--workflow-id", required=True)
    parser.add_argument("--workflow-path", required=True)
    parser.add_argument("--subject-sha", required=True)
    parser.add_argument("--artifact-sha256", required=True)
    parser.add_argument("--public-repository", required=True)
    args = parser.parse_args(argv)
    try:
        run = json.loads(Path(args.run_json).read_text(encoding="utf-8"))
        artifacts = json.loads(Path(args.artifacts_json).read_text(encoding="utf-8"))
        if not isinstance(run, dict):
            raise BundleProvenanceError("workflow run metadata is malformed")
        result = validate_provenance(run=run, artifacts=artifacts, expected_run_id=args.run_id, expected_artifact_name=args.artifact_name, expected_source_repository=args.source_repository, expected_workflow_id=args.workflow_id, expected_workflow_path=args.workflow_path, subject_git_sha=args.subject_sha, expected_digest=args.artifact_sha256, public_repository=args.public_repository)
    except (OSError, UnicodeError, json.JSONDecodeError, BundleProvenanceError) as exc:
        print(json.dumps({"status": "BLOCKED", "reason": str(exc)}, ensure_ascii=False))
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
