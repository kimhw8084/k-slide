"""Reduce runner-only scanner reports to source-free evidence projections."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


class SecurityReportError(ValueError):
    """A scanner report is incomplete or malformed."""


_PACKAGE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+._-]{0,255}$")
_PACKAGE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+._:~-]{0,127}$")
_ADVISORY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


def _safe_identity(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise SecurityReportError(f"scanner report contains an unsafe {label} identity")
    return value


def _read(path: Path) -> Any:
    if path.is_symlink() or not path.is_file():
        raise SecurityReportError("a required scanner report is unavailable")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SecurityReportError("a required scanner report is malformed") from exc


def sanitize_pip_audit(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or not isinstance(value.get("dependencies"), list) or not value["dependencies"]:
        raise SecurityReportError("dependency scan has no complete dependency inventory")
    packages: list[dict[str, Any]] = []
    for dependency in value["dependencies"]:
        if not isinstance(dependency, dict):
            raise SecurityReportError("dependency scan contains an incomplete package identity")
        name = _safe_identity(dependency.get("name"), _PACKAGE_NAME, "package")
        version = _safe_identity(dependency.get("version"), _PACKAGE_VERSION, "package version")
        if "vulns" not in dependency:
            raise SecurityReportError("dependency scan omitted a package vulnerability inventory")
        vulnerabilities = dependency["vulns"]
        if not isinstance(vulnerabilities, list):
            raise SecurityReportError("dependency scan vulnerability inventory is malformed")
        safe_vulns = []
        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                raise SecurityReportError("dependency scan finding has no advisory identity")
            vuln_id = _safe_identity(vulnerability.get("id"), _ADVISORY_ID, "advisory")
            aliases = vulnerability.get("aliases", [])
            fixes = vulnerability.get("fix_versions", [])
            if not isinstance(aliases, list) or not isinstance(fixes, list):
                raise SecurityReportError("dependency scan finding is malformed")
            safe_aliases = sorted({_safe_identity(item, _ADVISORY_ID, "advisory alias") for item in aliases})
            safe_fixes = sorted({_safe_identity(item, _PACKAGE_VERSION, "fixed version") for item in fixes})
            safe_vulns.append({"id": vuln_id, "aliases": safe_aliases, "fix_versions": safe_fixes})
        packages.append({"name": name, "version": version, "vulns": safe_vulns})
    return {"dependencies": sorted(packages, key=lambda item: (item["name"].casefold(), item["version"]))}


def sanitize_gitleaks(value: Any) -> list[dict[str, bool]]:
    if not isinstance(value, list):
        raise SecurityReportError("secret scan report is malformed")
    return [{"finding": True} for _ in value]


def sanitize_semgrep(value: Any) -> dict[str, list[dict[str, Any]]]:
    if not isinstance(value, dict) or not isinstance(value.get("results"), list) or not isinstance(value.get("errors"), list):
        raise SecurityReportError("static security scan report is malformed")
    results = []
    for finding in value["results"]:
        if not isinstance(finding, dict):
            raise SecurityReportError("static security finding is malformed")
        extra = finding.get("extra") if isinstance(finding.get("extra"), dict) else {}
        metadata = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
        severity = str(metadata.get("severity") or "UNKNOWN").upper()
        if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"}:
            severity = "UNKNOWN"
        results.append({"extra": {"metadata": {"severity": severity}}})
    errors = value["errors"]
    return {"results": results, "errors": [{"error": "SCAN_ERROR"} for _ in errors]}


def sanitize_trivy(value: Any, *, target_image_digest: str, database: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("SchemaVersion") != 2 or not isinstance(value.get("Results"), list):
        raise SecurityReportError("container scan report is malformed or unsupported")
    metadata = value.get("Metadata")
    if not isinstance(metadata, dict) or metadata.get("ImageID") != target_image_digest:
        raise SecurityReportError("container scan report image identity does not match the pinned runtime")
    if not isinstance(database, dict):
        raise SecurityReportError("container scanner vulnerability database is unavailable")
    classes: set[str] = set()
    class_package_counts = {"lang-pkgs": 0, "os-pkgs": 0}
    vulnerabilities: list[dict[str, str]] = []
    error_count = 0
    for result in value["Results"]:
        if not isinstance(result, dict) or result.get("Class") not in class_package_counts:
            raise SecurityReportError("container scan result entry is malformed")
        package_class = result["Class"]
        classes.add(package_class)
        if "Packages" not in result or not isinstance(result["Packages"], list):
            raise SecurityReportError("container scan omitted its package inventory")
        for package in result["Packages"]:
            if not isinstance(package, dict):
                raise SecurityReportError("container package inventory is malformed")
            _safe_identity(package.get("Name"), _PACKAGE_NAME, "container package")
            _safe_identity(package.get("Version"), _PACKAGE_VERSION, "container package version")
        class_package_counts[package_class] += len(result["Packages"])
        # Trivy omits empty Errors/Vulnerabilities arrays. The full, nonempty
        # Packages inventory below is required so that an absent finding list
        # can only mean the scanner completed this package class with no hits.
        errors = result.get("Errors", [])
        vulns = result.get("Vulnerabilities", [])
        if errors is None:
            errors = []
        if vulns is None:
            vulns = []
        if not isinstance(errors, list) or not isinstance(vulns, list):
            raise SecurityReportError("container scan result inventory is malformed")
        error_count += len(errors)
        for item in vulns:
            if not isinstance(item, dict):
                raise SecurityReportError("container vulnerability entry is malformed")
            package_name = _safe_identity(item.get("PkgName"), _PACKAGE_NAME, "container package")
            installed_version = _safe_identity(item.get("InstalledVersion"), _PACKAGE_VERSION, "container package version")
            vulnerability_id = _safe_identity(item.get("VulnerabilityID"), _ADVISORY_ID, "container advisory")
            severity_raw = item.get("Severity")
            if not isinstance(severity_raw, str) or not severity_raw:
                raise SecurityReportError("container vulnerability identity is incomplete")
            severity = severity_raw.upper()
            if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}:
                severity = "UNKNOWN"
            vulnerabilities.append({
                "package": package_name,
                "version": installed_version,
                "vulnerability_id": vulnerability_id,
                "severity": severity,
                "fixed_version": _safe_identity(item.get("FixedVersion"), _PACKAGE_VERSION, "fixed version") if item.get("FixedVersion") else "",
            })
    if classes != {"lang-pkgs", "os-pkgs"} or any(count < 1 for count in class_package_counts.values()):
        raise SecurityReportError("container scan did not identify both OS and language packages")
    updated = database.get("UpdatedAt")
    version = database.get("Version")
    if not isinstance(updated, str) or isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise SecurityReportError("container scanner database identity is malformed")
    database_schema = value.get("SchemaVersion")
    return {
        "schema_version": "1.0",
        "target_image_digest": target_image_digest,
        "scanned_classes": sorted(classes),
        "scanned_class_package_counts": class_package_counts,
        "database_updated_at": updated,
        "database_version": version,
        "database_schema_version": database_schema,
        "error_count": error_count,
        "vulnerabilities": sorted(vulnerabilities, key=lambda item: (item["package"].casefold(), item["version"], item["vulnerability_id"])) ,
    }


def sanitize_reports(*, raw_root: Path, output_root: Path, target_image_digest: str) -> dict[str, Path]:
    raw_root = raw_root.expanduser().resolve()
    output_root = output_root.expanduser().resolve()
    values = {
        "pip-audit.json": sanitize_pip_audit(_read(raw_root / "pip-audit.json")),
        "gitleaks.json": sanitize_gitleaks(_read(raw_root / "gitleaks.json")),
        "semgrep.json": sanitize_semgrep(_read(raw_root / "semgrep.json")),
        "container-scan.json": sanitize_trivy(
            _read(raw_root / "trivy.json"),
            target_image_digest=target_image_digest,
            database=_read(raw_root / "trivy-db-metadata.json"),
        ),
    }
    output_root.mkdir(parents=True, exist_ok=True)
    result: dict[str, Path] = {}
    for filename, value in values.items():
        target = output_root / filename
        target.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
        result[filename] = target
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Persist minimized, source-free security scanner projections")
    parser.add_argument("--raw-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--image-digest", required=True)
    args = parser.parse_args(argv)
    try:
        outputs = sanitize_reports(raw_root=args.raw_root, output_root=args.output_root, target_image_digest=args.image_digest)
    except (OSError, SecurityReportError, ValueError) as exc:
        print(json.dumps({"status": "FAIL", "reason": f"Scanner report reduction failed ({type(exc).__name__})."}, sort_keys=True))
        return 2
    print(json.dumps({"status": "PASS", "reports": sorted(outputs)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
