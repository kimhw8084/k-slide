"""Compare two clean runtime builds without redefining their image identity."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


def _read(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} is not a JSON object")
    return value


def _canonical(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def compare(first_root: Path, second_root: Path) -> dict[str, Any]:
    first_identity = _read(first_root / "artifact-identity.json")
    second_identity = _read(second_root / "artifact-identity.json")
    first_manifest = _read(first_root / "runtime-manifest.json")
    second_manifest = _read(second_root / "runtime-manifest.json")
    first_sbom = (first_root / "runtime-sbom.json").read_bytes()
    second_sbom = (second_root / "runtime-sbom.json").read_bytes()
    first_image = first_identity.get("image_identity")
    second_image = second_identity.get("image_identity")
    if not isinstance(first_image, dict) or not isinstance(second_image, dict):
        raise ValueError("both builds must retain an actual image identity")
    first_content = dict(first_manifest)
    second_content = dict(second_manifest)
    first_content.pop("image_identity", None)
    second_content.pop("image_identity", None)
    content_equal = _canonical(first_content) == _canonical(second_content)
    sbom_equal = first_sbom == second_sbom
    artifact_equal = first_manifest.get("artifact_identity") == second_manifest.get("artifact_identity")
    build_inputs_equal = first_manifest.get("build_inputs_sha256") == second_manifest.get("build_inputs_sha256")
    stable = content_equal and sbom_equal and artifact_equal and build_inputs_equal
    image_equal = first_image == second_image
    explanation = (
        "Docker produced the same image identity and canonical runtime content."
        if image_equal and stable
        else "Docker image identities differ, but canonical runtime manifest, SBOM, build-input, and artifact identities are stable."
        if stable
        else "Canonical runtime content drift is unexplained; the reproducibility gate fails closed."
    )
    return {
        "status": "PASS" if stable else "FAIL",
        "image_identities": {"first": first_image, "second": second_image},
        "image_identity_equal": image_equal,
        "canonical_content_identity": {
            "artifact_identity": first_manifest.get("artifact_identity"),
            "build_inputs_sha256": first_manifest.get("build_inputs_sha256"),
            "runtime_manifest_without_image_sha256": _sha256(_canonical(first_content)),
            "runtime_sbom_sha256": _sha256(first_sbom),
        },
        "comparisons": {"canonical_runtime_manifest_equal": content_equal, "runtime_sbom_equal": sbom_equal, "artifact_identity_equal": artifact_equal, "build_inputs_equal": build_inputs_equal},
        "explanation": explanation,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify clean-build runtime reproducibility")
    parser.add_argument("--first-artifact", type=Path, required=True)
    parser.add_argument("--second-artifact", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = compare(args.first_artifact.expanduser().resolve(), args.second_artifact.expanduser().resolve())
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        result = {"status": "FAIL", "reason": str(exc), "explanation": "Reproducibility evidence is incomplete; the gate fails closed."}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result.get("status") == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
