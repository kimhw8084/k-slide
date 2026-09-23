"""External, source-free execution contract for governed model-evaluation sets."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from k_slide.certification import EvidenceValidationError, safe_relative_path
from k_slide.corpus_governance import (
    CORPUS_ROLES,
    CorpusGovernanceError,
    canonical_bytes,
    canonical_manifest,
    canonical_set_identity,
    manifest_identity,
    require_set_purpose,
    validate_corpus_bundle,
    validate_contamination_report,
    validate_role_purpose,
)
from .certification import CATEGORY_POLICY


SUPPORTED_FORMATS = frozenset({"png", "jpg", "jpeg", "webp", "pdf", "pptx"})
CASE_DESCRIPTOR_SCHEMA_VERSION = "1.0"
_GOLD_CASE_FIELDS = {"item_id", "role", "set_id", "version", "category", "protected_group"}
_GOLD_WRAPPER_FIELDS = {"schema_version", "case", "gold"}
_CASE_FIELDS = {"item_id", "category", "protected_group", "artifacts", "gold_path"}


class GovernedCaseError(EvidenceValidationError):
    """An external governed-case descriptor or its local material is invalid."""


@dataclass(frozen=True)
class GovernedCase:
    scenario: Any
    artifacts: dict[str, Path]
    matrix_item: dict[str, Any]


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def case_matrix_fingerprint(value: Any) -> str:
    return _sha256_bytes(canonical_bytes(value))


def case_matrix_item_fingerprint(value: Any) -> str:
    return _sha256_bytes(canonical_bytes(value))


def governed_source_identity(artifact_hashes: dict[str, str]) -> str:
    """Bind the exact format-to-artifact byte hashes without persisting paths."""

    normalized = {str(name).lower(): digest for name, digest in artifact_hashes.items()}
    return _sha256_bytes(canonical_bytes({"artifacts": normalized}))


def _read_json_file(path: Path, label: str) -> tuple[Any, bytes]:
    raw_path = path.expanduser()
    if ".." in raw_path.parts:
        raise GovernedCaseError(f"{label} path contains traversal")
    absolute = raw_path.absolute()
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        if current.is_symlink():
            raise GovernedCaseError(f"{label} is missing or symlinked")
    resolved = absolute.resolve()
    if not resolved.is_file():
        raise GovernedCaseError(f"{label} is missing or symlinked")
    try:
        raw = resolved.read_bytes()
        return json.loads(raw.decode("utf-8")), raw
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise GovernedCaseError(f"{label} is malformed or unreadable") from exc


def _read_manifest_list(path: Path, label: str) -> list[dict[str, Any]]:
    value, raw = _read_json_file(path, label)
    if not isinstance(value, list):
        raise GovernedCaseError(f"{label} must contain a JSON list")
    canonical = [canonical_manifest(item) for item in value]
    if raw != canonical_bytes(canonical) + b"\n":
        raise GovernedCaseError(f"{label} serialization is not canonical")
    return canonical


def _read_history_list(path: Path | None, label: str) -> list[Any]:
    if path is None:
        return []
    value, raw = _read_json_file(path, label)
    if not isinstance(value, list):
        raise GovernedCaseError(f"{label} must contain a JSON list")
    canonical: list[Any] = []
    for item in value:
        if isinstance(item, dict) and set(item) == {"manifest", "exposure_contexts"}:
            canonical.append({"manifest": canonical_manifest(item.get("manifest")), "exposure_contexts": item.get("exposure_contexts")})
        else:
            canonical.append(canonical_manifest(item))
    if raw != canonical_bytes(canonical) + b"\n":
        raise GovernedCaseError(f"{label} serialization is not canonical")
    return canonical


def _outside_repo(path: Path, repo_root: Path, label: str) -> Path:
    absolute = path.expanduser().absolute()
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        if current.is_symlink():
            raise GovernedCaseError(f"{label} contains a symlink")
    resolved = absolute.resolve()
    if not resolved.is_dir():
        raise GovernedCaseError(f"{label} is unavailable")
    try:
        resolved.relative_to(repo_root.resolve())
    except ValueError:
        return resolved
    raise GovernedCaseError(f"{label} must be outside the public repository")


def _validate_gold_contract(category: str, gold: Any, role: str) -> dict[str, Any]:
    if not isinstance(gold, dict):
        raise GovernedCaseError("governed case gold contract must be an object")
    required = {"visible_items", "expected_region_min", "visual_elements"}
    if not required <= set(gold):
        raise GovernedCaseError("governed case gold contract lacks semantic coverage metadata")
    if not isinstance(gold.get("visible_items"), int) or isinstance(gold.get("visible_items"), bool) or gold["visible_items"] < 1:
        raise GovernedCaseError("governed case visible_items must be a positive integer")
    if not isinstance(gold.get("expected_region_min"), int) or isinstance(gold.get("expected_region_min"), bool) or gold["expected_region_min"] < 1:
        raise GovernedCaseError("governed case expected_region_min must be a positive integer")
    visual_elements = gold.get("visual_elements")
    if not isinstance(visual_elements, list) or not visual_elements or any(not isinstance(item, str) or not item for item in visual_elements):
        raise GovernedCaseError("governed case visual_elements must be a non-empty string list")
    for field in ("numeric_facts", "required_terms"):
        values = gold.get(field)
        if values is not None and (not isinstance(values, list) or any(not isinstance(item, str) or not item for item in values)):
            raise GovernedCaseError(f"governed case {field} must be a string list")
    if "allowed_unresolved" in gold and not isinstance(gold["allowed_unresolved"], bool):
        raise GovernedCaseError("governed case allowed_unresolved must be boolean")
    unresolved_max = gold.get("expected_unresolved_max")
    if unresolved_max is not None and (not isinstance(unresolved_max, int) or isinstance(unresolved_max, bool) or unresolved_max < 0):
        raise GovernedCaseError("governed case expected_unresolved_max must be a non-negative integer")
    locked_term = gold.get("locked_term")
    if locked_term is not None and (not isinstance(locked_term, str) or not locked_term.strip()):
        raise GovernedCaseError("governed case locked_term must be a non-empty string")
    executive_claims = gold.get("executive_claims")
    if executive_claims is not None and (
        not isinstance(executive_claims, list)
        or any(
            not isinstance(item, dict)
            or not isinstance(item.get("kind"), str)
            or not isinstance(item.get("acceptable_phrases", []), list)
            or any(not isinstance(phrase, str) or not phrase for phrase in item.get("acceptable_phrases", []))
            for item in executive_claims
        )
    ):
        raise GovernedCaseError("governed case executive_claims contract is malformed")
    if category not in CATEGORY_POLICY:
        raise GovernedCaseError("governed case category is outside the closed semantic policy")
    if category == "modality_decision_state":
        modality = gold.get("modality")
        if not isinstance(modality, dict) or not all(isinstance(modality.get(key), str) and modality[key] for key in ("source_text", "commitment", "speech_act")):
            raise GovernedCaseError("governed modality gold contract is incomplete")
    elif category == "financial_table":
        table = gold.get("table")
        if not isinstance(table, dict) or not isinstance(table.get("required_cells"), list) or not table["required_cells"] or not isinstance(table.get("header_roles"), list):
            raise GovernedCaseError("governed table gold contract is incomplete")
        for field in ("row_count", "column_count"):
            value = table.get(field)
            if value is not None and (not isinstance(value, int) or isinstance(value, bool) or value < 1):
                raise GovernedCaseError("governed table dimensions must be positive integers")
        for field in ("required_cells", "header_roles"):
            for item in table[field]:
                if not isinstance(item, dict) or not isinstance(item.get("row"), int) or isinstance(item.get("row"), bool) or item["row"] < 0 or not isinstance(item.get("column"), int) or isinstance(item.get("column"), bool) or item["column"] < 0:
                    raise GovernedCaseError("governed table cell coordinates are malformed")
                if field == "header_roles" and (
                    not isinstance(item.get("acceptable"), list)
                    or any(not isinstance(value, str) or not value for value in item["acceptable"])
                ):
                    raise GovernedCaseError("governed table semantic roles are malformed")
                if "source" in item and not isinstance(item["source"], str):
                    raise GovernedCaseError("governed table source binding is malformed")
    elif category == "chart":
        chart = gold.get("chart")
        if not isinstance(chart, dict) or not isinstance(chart.get("trend"), str) or not chart["trend"]:
            raise GovernedCaseError("governed chart gold contract is incomplete")
    elif category in {"process_diagram", "state_resume"}:
        process = gold.get("process")
        if not isinstance(process, dict) or not isinstance(process.get("nodes"), list) or not isinstance(process.get("relations"), list):
            raise GovernedCaseError("governed process gold contract is incomplete")
        if not process["nodes"] or any(
            not isinstance(node, dict)
            or not isinstance(node.get("id", node.get("role")), str)
            or not node.get("id", node.get("role"))
            or not isinstance(node.get("source_text", node.get("label")), str)
            or not node.get("source_text", node.get("label"))
            for node in process["nodes"]
        ) or any(
            not isinstance(relation, dict)
            or not all(isinstance(relation.get(key), str) and relation[key] for key in ("from", "to", "type"))
            for relation in process["relations"]
        ):
            raise GovernedCaseError("governed process semantic contract is malformed")
    elif category == "cross_slide_consistency" and not isinstance(gold.get("locked_term"), str):
        raise GovernedCaseError("governed consistency gold contract is incomplete")
    elif category == "prompt_injection" and gold.get("prompt_injection_is_data") is not True:
        raise GovernedCaseError("governed prompt-injection data policy is missing")
    if role == "frozen_high_risk" and category not in __import__("evals.scenarios", fromlist=["PROTECTED_CATEGORIES"]).PROTECTED_CATEGORIES:
        raise GovernedCaseError("governed high-risk case is outside the protected-category policy")
    return gold


def load_governed_external_cases(
    *,
    manifest_path: Path,
    bundle_path: Path,
    history_path: Path | None,
    evaluation_purpose: str,
    artifact_root: Path,
    descriptor_path: str | Path,
    formats: tuple[str, ...],
    contamination_report_path: Path | None,
    repo_root: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[Any], dict[str, Any] | None, list[GovernedCase], dict[str, Any]]:
    """Validate manifests, descriptors, all artifacts, and gold before any model call."""

    try:
        root = _outside_repo(artifact_root, repo_root, "governed artifact root")
        manifest_value, manifest_raw = _read_json_file(manifest_path.expanduser(), "governed evaluated manifest")
        manifest = canonical_manifest(manifest_value)
        if manifest_raw != canonical_bytes(manifest) + b"\n":
            raise GovernedCaseError("governed evaluated manifest serialization is not canonical")
        evaluated_identity = manifest_identity(manifest)
        validate_role_purpose(evaluated_identity["role"], evaluation_purpose)
        require_set_purpose(evaluated_identity, evaluation_purpose)
        if evaluated_identity["role"] == "public_synthetic_regression":
            raise GovernedCaseError("governed external mode accepts only private, frozen high-risk, or sealed roles")
        bundle_values = _read_manifest_list(bundle_path.expanduser(), "governed manifest bundle")
        history_values = _read_history_list(history_path.expanduser() if history_path is not None else None, "governed manifest history")
        bundle = validate_corpus_bundle(bundle_values, history=history_values, require_complete=True)
        bundled = {item["role"]: manifest_identity(item) for item in bundle}
        public_manifest = next(item for item in bundle if item["role"] == "public_synthetic_regression")
        public_item_ids = {item["item_id"] for item in public_manifest["items"]}
        public_gold_hashes = {item["gold_sha256"] for item in public_manifest["items"]}
        if bundled.get(evaluated_identity["role"]) != evaluated_identity:
            raise GovernedCaseError("evaluated manifest is not the exact candidate-bound bundle member")
        public_generator_manifests = (
            root / "CORPUS_MANIFEST.json",
            root / "artifacts" / "CORPUS_MANIFEST.json",
            root / "specs" / "MANIFEST.json",
        )
        for public_generator_manifest in public_generator_manifests:
            if public_generator_manifest.is_file():
                generated_metadata, _ = _read_json_file(public_generator_manifest, "artifact provenance")
                generated_fields = set(generated_metadata) if isinstance(generated_metadata, dict) else set()
                artifact_manifest = {"scenario_count", "formats", "variants"} <= generated_fields
                corpus_manifest = {"generator_version", "scenario_count", "splits"} <= generated_fields
                generated_artifact_manifest = {"generator_version", "scenario_count", "formats"} <= generated_fields
                if artifact_manifest or corpus_manifest or generated_artifact_manifest:
                    raise GovernedCaseError("public synthetic generated artifacts cannot be used for governed authority")
        report: dict[str, Any] | None = None
        if evaluated_identity["role"] == "sealed_held_out":
            if contamination_report_path is None:
                raise GovernedCaseError("sealed held-out requires a contamination report")
            report_value, report_raw = _read_json_file(contamination_report_path.expanduser(), "sealed contamination report")
            validate_contamination_report(report_value, set_identity=evaluated_identity, manifest=manifest)
            if report_raw != canonical_bytes(report_value) + b"\n":
                raise GovernedCaseError("sealed contamination report serialization is not canonical")
            if report_value["items"]:
                raise GovernedCaseError("sealed held-out contamination report is non-empty")
            report = report_value
        elif contamination_report_path is not None:
            raise GovernedCaseError("contamination reports are accepted only for sealed held-out")

        descriptor_file = safe_relative_path(root, descriptor_path, label="governed case descriptor", require_file=True)
        descriptor, _descriptor_raw = _read_json_file(descriptor_file, "governed case descriptor")
        if not isinstance(descriptor, dict) or set(descriptor) != {"schema_version", "corpus_set_identity", "cases"}:
            raise GovernedCaseError("governed case descriptor has an unsupported shape")
        if descriptor.get("schema_version") != CASE_DESCRIPTOR_SCHEMA_VERSION or canonical_set_identity(descriptor.get("corpus_set_identity")) != evaluated_identity:
            raise GovernedCaseError("governed case descriptor role or set identity does not match the evaluated manifest")
        raw_cases = descriptor.get("cases")
        if not isinstance(raw_cases, list) or not raw_cases:
            raise GovernedCaseError("governed case descriptor has no cases")
        manifest_items = {item["item_id"]: item for item in manifest["items"]}
        seen: set[str] = set()
        cases: list[GovernedCase] = []
        matrix: list[dict[str, Any]] = []
        expected_split = "held_out" if evaluated_identity["role"] == "sealed_held_out" else "validation"
        for raw_case in raw_cases:
            if not isinstance(raw_case, dict) or set(raw_case) != _CASE_FIELDS:
                raise GovernedCaseError("governed case descriptor entry has an unsupported shape")
            item_id = raw_case.get("item_id")
            if not isinstance(item_id, str) or not item_id or item_id in seen:
                raise GovernedCaseError("governed case descriptor has a duplicate or invalid item ID")
            if evaluated_identity["role"] != "public_synthetic_regression" and item_id in public_item_ids:
                raise GovernedCaseError("governed case cannot borrow a public synthetic scenario ID")
            item = manifest_items.get(item_id)
            if item is None or item["state"] != "active":
                raise GovernedCaseError("governed case descriptor references unknown or inactive membership")
            seen.add(item_id)
            category = raw_case.get("category")
            protected_group = raw_case.get("protected_group")
            if not isinstance(category, str) or category not in CATEGORY_POLICY:
                raise GovernedCaseError("governed case category is outside the closed semantic policy")
            if protected_group is not None and (not isinstance(protected_group, str) or protected_group not in CATEGORY_POLICY):
                raise GovernedCaseError("governed case protected group is invalid")
            if evaluated_identity["role"] == "frozen_high_risk" and protected_group != category:
                raise GovernedCaseError("high-risk case must bind its protected group to its category")
            raw_artifacts = raw_case.get("artifacts")
            if not isinstance(raw_artifacts, dict) or not raw_artifacts or set(raw_artifacts) - SUPPORTED_FORMATS:
                raise GovernedCaseError("governed case artifacts must map supported formats to local files")
            if any(not isinstance(key, str) or key != key.lower() for key in raw_artifacts):
                raise GovernedCaseError("governed artifact format names must be lowercase")
            artifact_paths: dict[str, Path] = {}
            artifact_hashes: dict[str, str] = {}
            for format_name, relative_path in raw_artifacts.items():
                if not isinstance(relative_path, str):
                    raise GovernedCaseError("governed artifact path must be relative")
                path = safe_relative_path(root, relative_path, label="governed artifact", require_file=True)
                digest = _sha256_bytes(path.read_bytes())
                artifact_paths[format_name] = path
                artifact_hashes[format_name] = digest
            if governed_source_identity(artifact_hashes) != item["source_sha256"]:
                raise GovernedCaseError("governed case artifact identity does not match its manifest item")
            if not set(formats) <= set(artifact_paths):
                raise GovernedCaseError("governed case is missing a requested artifact format")
            gold_relative = raw_case.get("gold_path")
            if not isinstance(gold_relative, str):
                raise GovernedCaseError("governed gold path must be relative")
            gold_path = safe_relative_path(root, gold_relative, label="governed gold", require_file=True)
            gold_value, gold_raw = _read_json_file(gold_path, "governed gold")
            if _sha256_bytes(gold_raw) != item["gold_sha256"]:
                raise GovernedCaseError("governed gold identity does not match its manifest item")
            if gold_raw != canonical_bytes(gold_value) + b"\n":
                raise GovernedCaseError("governed gold serialization is not canonical")
            if not isinstance(gold_value, dict) or set(gold_value) != _GOLD_WRAPPER_FIELDS or gold_value.get("schema_version") != CASE_DESCRIPTOR_SCHEMA_VERSION:
                raise GovernedCaseError("governed gold wrapper has an unsupported shape")
            gold_case = gold_value.get("case")
            expected_case = {
                "item_id": item_id,
                "role": evaluated_identity["role"],
                "set_id": evaluated_identity["set_id"],
                "version": evaluated_identity["version"],
                "category": category,
                "protected_group": protected_group,
            }
            if not isinstance(gold_case, dict) or set(gold_case) != _GOLD_CASE_FIELDS or gold_case != expected_case:
                raise GovernedCaseError("governed gold identity/category does not match its descriptor and manifest")
            gold = _validate_gold_contract(category, gold_value.get("gold"), evaluated_identity["role"])
            gold_contract_sha256 = _sha256_bytes(canonical_bytes(gold))
            if evaluated_identity["role"] != "public_synthetic_regression" and gold_contract_sha256 in public_gold_hashes:
                raise GovernedCaseError("governed case cannot borrow a public synthetic gold contract")
            matrix_item = {
                "item_id": item_id,
                "category": category,
                "protected_group": protected_group,
                "split": expected_split,
                "source_sha256": item["source_sha256"],
                "gold_sha256": item["gold_sha256"],
                "gold_contract_sha256": gold_contract_sha256,
                "formats": sorted(artifact_paths),
            }
            cases.append(GovernedCase(SimpleNamespace(scenario_id=item_id, category=category, split=expected_split, gold=gold), artifact_paths, matrix_item))
            matrix.append(matrix_item)
        active_ids = {item["item_id"] for item in manifest["items"] if item["state"] == "active"}
        if seen != active_ids:
            raise GovernedCaseError("case descriptor must cover exact active manifest membership")
        if not set(formats) or any(item not in SUPPORTED_FORMATS for item in formats):
            raise GovernedCaseError("requested format set is invalid")
        if evaluated_identity["role"] in {"private_representative", "sealed_held_out"} and not cases:
            raise GovernedCaseError("authoritative governed set has no active cases")
        if evaluated_identity["role"] == "frozen_high_risk":
            protected = set(__import__("evals.scenarios", fromlist=["PROTECTED_CATEGORIES"]).PROTECTED_CATEGORIES)
            if {item["category"] for item in matrix} != protected:
                raise GovernedCaseError("frozen high-risk membership lacks the complete protected-category coverage")
        matrix.sort(key=lambda item: item["item_id"])
        identity_descriptor = {
            "schema_version": CASE_DESCRIPTOR_SCHEMA_VERSION,
            "role": evaluated_identity["role"],
            "set_id": evaluated_identity["set_id"],
            "version": evaluated_identity["version"],
            "manifest_fingerprint": evaluated_identity["manifest_fingerprint"],
            "case_matrix_sha256": case_matrix_fingerprint(matrix),
        }
        # Source path inputs are intentionally kept in the returned local-only
        # lookup objects and never copied into experiment/evidence records.
        return manifest, bundle, history_values, report, cases, identity_descriptor
    except CorpusGovernanceError as exc:
        raise GovernedCaseError(f"governed corpus contract is invalid ({type(exc).__name__})") from exc
