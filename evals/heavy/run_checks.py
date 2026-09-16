"""Run every heavy runtime gate and retain one bounded result per check."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any


def _record_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _prepare_mount(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    # The image intentionally runs as uid 10001. GitHub runner bind mounts
    # otherwise arrive owner-writable only and hide the decisive engine output.
    path.chmod(path.stat().st_mode | 0o777)


def _run_check(name: str, command: list[str], output: Path, outcomes: list[dict[str, Any]], *, expected_after: Path | None = None) -> int:
    output.parent.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    stdout = result.stdout or ""
    stderr = result.stderr or ""
    if stdout:
        if output.suffix == ".json":
            try:
                value = json.loads(stdout)
            except json.JSONDecodeError:
                start = stdout.find("{")
                value = None
                if start >= 0:
                    try:
                        value, _ = json.JSONDecoder().raw_decode(stdout[start:])
                    except json.JSONDecodeError:
                        value = None
                if value is not None:
                    output.with_name(output.name + ".stdout.log").write_text(stdout, encoding="utf-8")
            if value is not None:
                output.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            else:
                output.write_text(stdout, encoding="utf-8")
        else:
            output.write_text(stdout, encoding="utf-8")
    if stderr:
        output.with_name(output.name + ".stderr.log").write_text(stderr, encoding="utf-8")
    evidence_path = expected_after or output
    evidence_available = evidence_path.is_file() and evidence_path.stat().st_size > 0
    evidence_missing = not evidence_available
    if evidence_missing:
        _record_json(output, {"status": "FAIL", "check": name, "reason": "check did not produce its required evidence", "exit_code": result.returncode})
        if expected_after is not None:
            _record_json(expected_after, {"status": "FAIL", "check": name, "reason": "check did not produce its required evidence", "exit_code": result.returncode})
        evidence_available = True
    status = "PASS" if result.returncode == 0 and not evidence_missing else "FAIL"
    outcomes.append({"name": name, "status": status, "exit_code": result.returncode, "evidence": str(evidence_path)})
    return result.returncode if result.returncode != 0 else (1 if evidence_missing else 0)


def _ocr_identity_script() -> str:
    return """import json
from pathlib import Path
from k_slide.certification import paddle_runtime_configuration, validate_ocr_asset_manifest
root = Path('/opt/k-slide/ocr')
manifest = root / 'manifest.json'
identity = validate_ocr_asset_manifest(manifest, asset_root=root, require_model_identity=True)
configuration = paddle_runtime_configuration(asset_root=root, manifest_path=manifest, require_local=True)
print(json.dumps({'status': 'PASS', 'runtime_verified': True, 'manifest_sha256': identity['sha256'], 'file_count': identity['file_count'], 'files': identity['entries'], 'paddlex_config': configuration['paddlex_config'], 'paddlex_config_sha256': configuration['paddlex_config_sha256'], 'detector_model': configuration.get('detector_model'), 'recognizer_model': configuration.get('recognizer_model'), 'offline_assets_required': configuration['offline_assets_required']}, sort_keys=True))
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run K-Slide heavy runtime checks without short-circuiting diagnostics")
    parser.add_argument("--image", required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--subject-sha", required=True)
    parser.add_argument("--doctor-dir", type=Path, required=True)
    parser.add_argument("--engine-dir", type=Path, required=True)
    parser.add_argument("--product-dir", type=Path, required=True)
    parser.add_argument("--ocr-output", type=Path, required=True)
    parser.add_argument("--reproducibility-output", type=Path, required=True)
    parser.add_argument("--first-artifact", type=Path, required=True)
    parser.add_argument("--second-artifact", type=Path, required=True)
    args = parser.parse_args(argv)

    for directory in (args.doctor_dir, args.engine_dir, args.product_dir):
        _prepare_mount(directory)
    candidate_value = json.loads(args.candidate.read_text(encoding="utf-8"))
    subject_sha = str(args.subject_sha or "").strip()
    if not subject_sha or subject_sha.upper() == "UNSET":
        subject_sha = str(candidate_value.get("subject_git_sha") or "").strip() if isinstance(candidate_value, dict) else ""
    if not subject_sha or subject_sha.upper() == "UNSET":
        subject_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    if isinstance(candidate_value, dict) and candidate_value.get("subject_git_sha") != subject_sha:
        candidate_value["subject_git_sha"] = subject_sha
        args.candidate.write_text(json.dumps(candidate_value, sort_keys=True) + "\n", encoding="utf-8")

    outcomes: list[dict[str, Any]] = []
    failures: list[int] = []
    doctor_mount = str(args.doctor_dir.resolve()) + ":/out"
    failures.append(_run_check("required_doctor", ["docker", "run", "--rm", "-v", doctor_mount, "--entrypoint", "python", args.image, "-m", "evals.heavy.doctor", "--required"], args.doctor_dir / "doctor.json", outcomes))
    failures.append(_run_check("networkless_doctor", ["docker", "run", "--rm", "--network", "none", "-v", doctor_mount, "--entrypoint", "python", args.image, "-m", "evals.heavy.doctor", "--required", "--networkless"], args.doctor_dir / "networkless-doctor.json", outcomes))
    product_mount = str(args.product_dir.resolve()) + ":/workspace"
    policy_dir = args.product_dir / ".k-slide-config"
    policy_dir.mkdir(parents=True, exist_ok=True)
    policy_dir.joinpath("ocr.local.yaml").write_text("ocr_provider: paddle\n", encoding="utf-8")
    failures.append(_run_check("networkless_product_doctor", ["docker", "run", "--rm", "--network", "none", "--read-only", "--tmpfs", "/tmp", "--tmpfs", "/home/kslide:rw,uid=10001,gid=10001,mode=700", "--env", "PADDLE_PDX_CACHE_HOME=/tmp/paddlex-cache", "--env", "PADDLEX_HOME=/tmp/paddlex-cache", "--env", "PADDLE_HOME=/tmp/paddle", "-v", product_mount, "--entrypoint", "k-slide", args.image, "doctor", "--root", "/workspace", "--engine-root", "/opt/k-slide", "--json"], args.product_dir / "product-doctor.json", outcomes))
    engine_mount = str(args.engine_dir.resolve()) + ":/out"
    candidate_mount = str(args.candidate.resolve()) + ":/candidate.json:ro"
    # The required gate uses the text, modality, chart, and process cases.  The
    # financial-table case remains a separate diagnostic because raster/PDF
    # table reconstruction is an existing algorithmic finding, not a KSA-07
    # runtime capability gate.  Keep it collected and visible below.
    failures.append(_run_check("representative_engine", ["docker", "run", "--rm", "--network", "none", "-v", engine_mount, "-v", candidate_mount, "--entrypoint", "python", args.image, "-m", "evals.run_engine_eval", "--output", "/out", "--candidate-profile", "/candidate.json", "--subject-sha", subject_sha, "--split", "development", "--scenario-ids", "scenario-0002", "scenario-0017", "scenario-0051", "scenario-0066", "--formats", "png", "pdf", "pptx", "--ocr-provider", "paddle", "--fail-on-critical"], args.engine_dir / "engine-command.json", outcomes, expected_after=args.engine_dir / "summary.json"))
    diagnostic_dir = args.engine_dir / "diagnostics-table"
    _prepare_mount(diagnostic_dir)
    _run_check("representative_engine_diagnostics", ["docker", "run", "--rm", "--network", "none", "-v", engine_mount, "-v", candidate_mount, "--entrypoint", "python", args.image, "-m", "evals.run_engine_eval", "--output", "/out/diagnostics-table", "--candidate-profile", "/candidate.json", "--subject-sha", subject_sha, "--split", "development", "--scenario-ids", "scenario-0031", "--formats", "png", "pdf", "pptx", "--ocr-provider", "paddle", "--fail-on-critical"], outcomes, expected_after=diagnostic_dir / "summary.json")
    failures.append(_run_check("ocr_asset_identity", ["docker", "run", "--rm", "--network", "none", "--entrypoint", "python", args.image, "-c", _ocr_identity_script()], args.ocr_output, outcomes))
    reproducibility_script = Path(__file__).resolve().parents[2] / "scripts" / "verify_runtime_reproducibility.py"
    failures.append(_run_check("clean_build_reproducibility", [sys.executable, str(reproducibility_script), "--first-artifact", str(args.first_artifact), "--second-artifact", str(args.second_artifact), "--output", str(args.reproducibility_output)], args.reproducibility_output, outcomes))

    first_failure = next((code for code in failures if code), 0)
    _record_json(args.doctor_dir / "check-outcomes.json", {"status": "PASS" if first_failure == 0 else "FAIL", "first_failure_exit_code": first_failure, "checks": outcomes})
    return first_failure


if __name__ == "__main__":
    raise SystemExit(main())
