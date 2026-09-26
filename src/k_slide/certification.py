"""Evidence-bound release certification primitives.

This module is intentionally dependency-free.  It is imported by the runtime
doctor as well as the evaluation/release tooling so a production state cannot
be created by changing a label or by supplying an unbound attestation string.
"""

from __future__ import annotations

import hashlib
import json
import math
import subprocess
import ast
import os
import re
import uuid
from pathlib import Path
from typing import Any, Iterable

from .errors import KSlideError
from .resource_budget import ResourceBudget
from .retention_policy import RetentionPolicy, RETENTION_POLICY_FIELD
from .bilingual_adjudication import (
    BilingualAdjudicationError,
    validate_internal_bilingual_payload,
)
from .zero_korean_study import (
    ZeroKoreanStudyError,
    validate_zero_korean_authority_binding,
    validate_zero_korean_candidate_binding,
    validate_zero_korean_study_payload,
)
from .corpus_governance import (
    CorpusGovernanceError,
    canonical_corpus_identity as canonical_governed_corpus_identity,
    is_certification_corpus_ready,
    require_set_purpose,
    set_identity_for_role,
)


# 2.6 makes bilingual evidence require paired KSA-29 reviews and adjudication;
# predecessor envelopes are stale under the shared evidence-schema contract.
# KSA-30 uses its own strict payload-contract version within this envelope, so
# the shared schema need not advance and KSA-29 contract 1.0 stays unchanged.
EVIDENCE_SCHEMA_VERSION = "2.6"
EVIDENCE_TYPES = (
    "runtime",
    "heavy_runtime",
    "model_validation",
    "model_high_risk_stability",
    "model_held_out",
    "internal_bilingual",
    "zero_korean_comprehension",
    "security",
    "reliability",
    "model_data_policy",
    "pilot_canary",
    "governance",
)
MACHINE_EVIDENCE_TYPES = {
    "runtime",
    "heavy_runtime",
    "model_validation",
    "model_high_risk_stability",
    "model_held_out",
    "security",
    "reliability",
    "governance",
}
_HEX64 = set("0123456789abcdef")

# Candidate identity is a source-free deployment contract.  These are the
# only fields that may affect the deployment fingerprint.  Paths are accepted
# as lookup hints but their content hash, never the path, is fingerprinted.
CANDIDATE_SPEC_SCHEMA_VERSION = "1.1"
DEPENDENCY_INVENTORY_SCHEMA_VERSION = "1.0"
UNSET_VALUE = "UNSET"
# Runtime discovery already uses ``not_exposed_by_runtime`` for structured
# fields.  These scalar values make the same distinction explicit in a
# frozen candidate specification; they are valid only for provider metadata
# that the deployment actually cannot expose.
NOT_EXPOSED_VALUE = "NOT_EXPOSED"
NOT_APPLICABLE_VALUE = "NOT_APPLICABLE"
PROVIDER_DEFAULTS_FROZEN = "provider_defaults_frozen"
PADDLE_OCR_CONFIG = "PaddleOCR.yaml"
_UNRESOLVED_VALUE_MARKERS = frozenset({UNSET_VALUE, "NOT_YET_CONFIGURED"})
CANDIDATE_INPUT_FIELDS = (
    "candidate_spec_version",
    "subject_git_sha",
    "kslide_version",
    "opencode_version",
    "requested_model",
    "effective_model",
    "provider",
    "provider_backend",
    "model_revision",
    "quantization_or_dtype",
    "vision_settings",
    "context_configuration",
    "image_preprocessing_settings",
    "prompt_identity",
    "prompt_version",
    "prompt_hash",
    "generation_settings",
    "ocr_provider",
    "ocr_asset_manifest",
    "ocr_asset_manifest_sha256",
    "normalization_behavior",
    "repair_policy",
    "python_version",
    "paddle_version",
    "paddleocr_version",
    "libreoffice_version",
    "termbase_identity",
    "termbase_governance",
    "termbase_version",
    "termbase_hash",
    "model_policy",
    "inference_route_identity",
    "inference_endpoint_identity",
    "inference_data_use_policy",
    "egress_policy_version",
    "egress_policy_hash",
    "egress_policy_identity",
    "schema_versions",
    RETENTION_POLICY_FIELD,
    "resource_budget",
    "tenant_isolation",
    "network_egress",
    "corpus_identity",
    "constraints_sha256",
    "resolved_dependency_set_sha256",
    "runtime_artifact_identity",
    "runtime_artifact_manifest_sha256",
    "runtime_sbom_sha256",
    "opencode_bootstrap_identity",
    "opencode_models_identity",
    "behavior_configuration",
)

# These fields are outputs of certification and are deliberately ignored when
# a certified profile is used as the source of candidate inputs.
CERTIFICATION_OUTPUT_FIELDS = frozenset({
    "release_state",
    "deployment_fingerprint",
    "certification_fingerprint",
    "release_manifest",
    "release_manifest_sha256",
    "model_data_attestation",
    "attestations",
    "evidence_paths",
    "evidence_hashes",
    "evidence_envelope_hashes",
    "champion_hash",
    "generated_at",
    "report_generated_from_sha",
    "blocking_reasons",
})

_BEHAVIOR_FIELDS = frozenset({
    "model",
    "provider",
    "prompt_version",
    "prompt_hash",
    "prompt_identity",
    "generation",
    "generation_settings",
    "temperature",
    "top_p",
    "top_k",
    "thinking",
    "reasoning",
    "visual_budget",
    "visual_detail",
    "vision",
    "vision_settings",
    "context_configuration",
    "image_preprocessing_settings",
    "ocr_provider",
    "normalization",
    "normalization_behavior",
    "repair_policy",
    "termbase_version",
    "termbase_hash",
    "evidence_ir_schema",
    "translation_patch_schema",
    "slide_ir_schema",
})
_EXPERIMENT_ONLY_FIELDS = frozenset({
    "split",
    "scenario_ids",
    "formats",
    "repetitions",
    "repeats",
    "categories",
    "category_filter",
    "scenario_filter",
    "limit",
    "timeout",
    "evaluation_timeout",
    "mode",
    "output",
    "output_path",
    "filters",
})
_BEHAVIOR_ALIASES = {
    "generation": "generation_settings",
    "repair": "repair_policy",
    "normalization": "normalization_behavior",
    "vision": "vision_settings",
}
_CANDIDATE_ALIASES = {"model": "requested_model", "model_id": "requested_model", "inference_data_policy": "inference_data_use_policy", **_BEHAVIOR_ALIASES}

_CANDIDATE_COMPLETENESS_FIELDS: dict[str, tuple[str, ...]] = {
    "RUNTIME_READY": ("subject_git_sha", "kslide_version", "opencode_version"),
    "GEMMA_EVAL_READY": (
        "subject_git_sha", "kslide_version", "opencode_version", "ocr_provider",
        "python_version", "paddle_version", "paddleocr_version", "libreoffice_version",
        "ocr_asset_manifest", "ocr_asset_manifest_sha256",
    ),
    "SYNTHETIC_PRODUCTION_CANDIDATE": (
        "subject_git_sha", "kslide_version", "opencode_version", "requested_model", "effective_model", "provider",
        "vision_settings", "context_configuration", "image_preprocessing_settings", "prompt_identity",
        "generation_settings", "normalization_behavior", "repair_policy", "ocr_provider", "model_policy",
        "schema_versions", "corpus_identity", "behavior_configuration",
    ),
    "INTERNAL_VALIDATED": (
        "subject_git_sha", "kslide_version", "opencode_version", "requested_model", "effective_model", "provider",
        "vision_settings", "context_configuration", "image_preprocessing_settings", "prompt_identity",
        "generation_settings", "normalization_behavior", "repair_policy", "ocr_provider", "model_policy",
        "schema_versions", "corpus_identity", "behavior_configuration",
    ),
}
_PRODUCTION_COMPLETENESS_FIELDS = (
    "subject_git_sha", "kslide_version", "opencode_version", "requested_model", "effective_model", "provider",
    "provider_backend", "model_revision", "quantization_or_dtype", "vision_settings", "context_configuration",
    "image_preprocessing_settings", "prompt_identity", "generation_settings", "ocr_provider", "ocr_asset_manifest",
    "ocr_asset_manifest_sha256", "normalization_behavior", "repair_policy", "python_version", "paddle_version",
    "paddleocr_version", "libreoffice_version", "termbase_identity", "termbase_version", "termbase_hash", "model_policy",
    "schema_versions", RETENTION_POLICY_FIELD, "tenant_isolation", "network_egress", "corpus_identity", "constraints_sha256",
    "resolved_dependency_set_sha256", "behavior_configuration", "resource_budget",
)
_OPTIONAL_PROVIDER_METADATA = frozenset({"provider_backend", "model_revision", "quantization_or_dtype"})
_NOT_EXPOSED_SOURCES = frozenset({"not_exposed_by_runtime", "not_exposed"})
_NOT_APPLICABLE_SOURCES = frozenset({"not_applicable", "not_applicable_by_runtime"})
_NON_DEPLOYED_BASE_PACKAGES = frozenset({"k-slide", "pip", "setuptools", "wheel"})
_SCANNER_PACKAGES = frozenset({"pip-audit", "semgrep", "cyclonedx-bom", "cyclonedx-python-lib"})


def repository_schema_versions() -> dict[str, str]:
    """Return schema identities from the code that actually owns them."""

    from . import EVIDENCE_IR_SCHEMA_VERSION, SLIDE_IR_SCHEMA_VERSION
    from .translation_contract import TRANSLATION_PATCH_SCHEMA_VERSION

    return {
        "evidence_ir": EVIDENCE_IR_SCHEMA_VERSION,
        "translation_patch": TRANSLATION_PATCH_SCHEMA_VERSION,
        "slide_ir": SLIDE_IR_SCHEMA_VERSION,
    }


def canonical_package_name(name: Any) -> str:
    return re.sub(r"[-_.]+", "-", str(name or "").strip()).lower()


def explicit_unavailable_value(value: Any) -> str | None:
    """Return the explicit unavailable marker, never for an unknown value."""

    if isinstance(value, str):
        normalized = value.strip().upper()
        if normalized in {NOT_EXPOSED_VALUE, NOT_APPLICABLE_VALUE}:
            return normalized
        source = value.strip().lower()
        if source in _NOT_EXPOSED_SOURCES:
            return NOT_EXPOSED_VALUE
        if source in _NOT_APPLICABLE_SOURCES:
            return NOT_APPLICABLE_VALUE
    if isinstance(value, dict):
        status = str(value.get("status") or "").strip().upper()
        if status in {NOT_EXPOSED_VALUE, NOT_APPLICABLE_VALUE}:
            return status
        source = str(value.get("source") or "").strip().lower()
        if source in _NOT_EXPOSED_SOURCES:
            return NOT_EXPOSED_VALUE
        if source in _NOT_APPLICABLE_SOURCES:
            return NOT_APPLICABLE_VALUE
    return None


_EXACT_VERSION = re.compile(r"^\d+\.\d+\.\d+(?:\.\d+)?$")


def canonical_exact_version(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not _EXACT_VERSION.fullmatch(text):
        raise EvidenceValidationError(f"{label} must be an exact semantic version")
    return text


def parse_libreoffice_version(output: str | None) -> str | None:
    if not output:
        return None
    match = re.search(r"(?<!\d)(\d+\.\d+\.\d+(?:\.\d+)?)(?!\d)", output)
    return match.group(1) if match else None


def canonical_dependency_inventory(packages: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Normalize the exact deployed Python package/version set."""

    records: dict[str, str] = {}
    for item in packages:
        if not isinstance(item, dict):
            raise EvidenceValidationError("dependency inventory contains a non-object package")
        name = canonical_package_name(item.get("name"))
        version = str(item.get("version") or "").strip()
        if not name or not version:
            raise EvidenceValidationError("dependency inventory package name/version is missing")
        if name in _SCANNER_PACKAGES:
            raise EvidenceValidationError(f"scanner package {name} is not part of the production dependency subject")
        if name in _NON_DEPLOYED_BASE_PACKAGES:
            continue
        if name in records:
            if records[name] != version:
                raise EvidenceValidationError(f"dependency inventory contains conflicting versions for {name}")
            raise EvidenceValidationError(f"dependency inventory contains a duplicate package: {name}")
        records[name] = version
    return {
        "schema_version": DEPENDENCY_INVENTORY_SCHEMA_VERSION,
        "packages": [{"name": name, "version": records[name]} for name in sorted(records)],
    }


def installed_dependency_inventory() -> dict[str, Any]:
    """Return the canonical package set visible to this Python interpreter."""

    from importlib.metadata import distributions

    return canonical_dependency_inventory(
        [{"name": item.metadata.get("Name"), "version": item.version} for item in distributions()]
    )


def dependency_lock_text(inventory: dict[str, Any]) -> str:
    """Serialize a deterministic exact lock for the deployed package set."""

    canonical = canonical_dependency_inventory(inventory.get("packages", []))
    if not canonical["packages"]:
        raise EvidenceValidationError("production dependency inventory is empty")
    return "".join(f"{item['name']}=={item['version']}\n" for item in canonical["packages"])


def load_dependency_lock(path: Path) -> dict[str, Any]:
    """Load the exact requirements lock used to build the production image."""

    if path.is_symlink() or not path.is_file():
        raise EvidenceValidationError(f"production dependency lock is missing or symlinked: {path.name}")
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise EvidenceValidationError(f"production dependency lock is unreadable: {path.name}") from exc
    packages: list[dict[str, str]] = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        name, separator, version = line.partition("==")
        if not separator or not name.strip() or not version.strip() or " @ " in line or line.startswith(("-", "--")):
            raise EvidenceValidationError("production dependency lock contains an unsupported requirement")
        packages.append({"name": name.strip(), "version": version.strip()})
    inventory = canonical_dependency_inventory(packages)
    if not inventory["packages"]:
        raise EvidenceValidationError("production dependency lock is empty")
    return inventory


def cyclonedx_dependency_set_hash(value: dict[str, Any]) -> str | None:
    metadata = value.get("metadata") if isinstance(value, dict) else None
    component = metadata.get("component") if isinstance(metadata, dict) else None
    properties = component.get("properties") if isinstance(component, dict) else None
    if not isinstance(properties, list):
        return None
    for item in properties:
        if isinstance(item, dict) and item.get("name") == "k-slide:dependency-set-sha256" and isinstance(item.get("value"), str):
            return item["value"].lower()
    return None


def validate_cyclonedx_1_5(value: dict[str, Any]) -> None:
    """Validate the strict CycloneDX 1.5 shape emitted by K-Slide."""

    if not isinstance(value, dict) or set(value) - {"bomFormat", "specVersion", "serialNumber", "version", "metadata", "components"}:
        raise EvidenceValidationError("production SBOM has non-CycloneDX root fields")
    if value.get("bomFormat") != "CycloneDX" or value.get("specVersion") != "1.5" or not isinstance(value.get("version"), int) or isinstance(value.get("version"), bool) or value["version"] < 1:
        raise EvidenceValidationError("production SBOM is not CycloneDX 1.5")
    serial = str(value.get("serialNumber") or "")
    if not serial.startswith("urn:uuid:"):
        raise EvidenceValidationError("production SBOM serialNumber is invalid")
    try:
        uuid.UUID(serial.removeprefix("urn:uuid:"))
    except (ValueError, AttributeError):
        raise EvidenceValidationError("production SBOM serialNumber is invalid")
    metadata = value.get("metadata")
    if not isinstance(metadata, dict) or set(metadata) - {"timestamp", "component"}:
        raise EvidenceValidationError("production SBOM metadata is not a supported CycloneDX 1.5 object")
    if "timestamp" in metadata and (not isinstance(metadata["timestamp"], str) or not metadata["timestamp"].strip()):
        raise EvidenceValidationError("production SBOM metadata timestamp is invalid")
    application = metadata.get("component")
    if not isinstance(application, dict) or set(application) - {"type", "name", "version", "properties"}:
        raise EvidenceValidationError("production SBOM application component is invalid")
    if application.get("type") != "application" or not isinstance(application.get("name"), str) or not isinstance(application.get("version"), str):
        raise EvidenceValidationError("production SBOM application component is incomplete")
    properties = application.get("properties")
    if not isinstance(properties, list) or any(not isinstance(item, dict) or not isinstance(item.get("name"), str) or not isinstance(item.get("value"), str) for item in properties):
        raise EvidenceValidationError("production SBOM properties are invalid")
    components = value.get("components")
    if not isinstance(components, list) or not components:
        raise EvidenceValidationError("production SBOM has no components")
    seen_components: set[str] = set()
    for component in components:
        if not isinstance(component, dict) or set(component) - {"type", "name", "version"}:
            raise EvidenceValidationError("production SBOM contains an invalid component")
        if component.get("type") not in {"library", "operating-system"} or not isinstance(component.get("name"), str) or not component["name"] or not isinstance(component.get("version"), str) or not component["version"]:
            raise EvidenceValidationError("production SBOM component name/version is invalid")
        component_name = canonical_package_name(component["name"])
        if component_name in seen_components:
            raise EvidenceValidationError("production SBOM contains a duplicate component")
        seen_components.add(component_name)
    dependency_hash = cyclonedx_dependency_set_hash(value)
    if dependency_hash is None or len(dependency_hash) != 64 or set(dependency_hash) - _HEX64:
        raise EvidenceValidationError("production SBOM has no valid dependency-set identity")


def dependency_inventory_hash(inventory: dict[str, Any]) -> str:
    packages = inventory.get("packages") if isinstance(inventory, dict) else None
    if not isinstance(packages, list):
        raise EvidenceValidationError("dependency inventory packages are missing")
    canonical = canonical_dependency_inventory(packages)
    if inventory.get("schema_version", DEPENDENCY_INVENTORY_SCHEMA_VERSION) != DEPENDENCY_INVENTORY_SCHEMA_VERSION:
        raise EvidenceValidationError("unsupported dependency inventory schema")
    return sha256_bytes(canonical_bytes(canonical))


def load_dependency_inventory(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise EvidenceValidationError(f"dependency inventory is missing or symlinked: {path.name}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EvidenceValidationError(f"dependency inventory is malformed: {path.name}") from exc
    if not isinstance(value, dict):
        raise EvidenceValidationError("dependency inventory must be an object")
    canonical = canonical_dependency_inventory(value.get("packages", []))
    if value.get("schema_version", DEPENDENCY_INVENTORY_SCHEMA_VERSION) != DEPENDENCY_INVENTORY_SCHEMA_VERSION:
        raise EvidenceValidationError("unsupported dependency inventory schema")
    if value.get("packages") != canonical["packages"]:
        raise EvidenceValidationError("dependency inventory is not canonically ordered")
    return canonical


def _agent_frontmatter(root: Path) -> dict[str, Any] | None:
    """Read only the public frontmatter used by the production agent."""

    path = root / ".opencode" / "agents" / "k-slide.md"
    if path.is_symlink() or not path.is_file():
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return None
    if not lines or lines[0].strip() != "---":
        return None
    values: dict[str, Any] = {}
    for line in lines[1:]:
        if line.strip() == "---":
            return values
        key, separator, raw = line.partition(":")
        if separator and key.strip() and raw.strip():
            values[key.strip()] = _parse_scalar(raw)
    return None


def _source_path(root: Path, relative: str) -> Path:
    """Locate repository-owned inputs in a source checkout or installed build."""

    root = root.expanduser().resolve()
    for base in (root, root / ".k-slide-engine"):
        candidate = base / relative
        if candidate.exists() and not candidate.is_symlink():
            return candidate
    return root / relative


def effective_termbase_identity(root: Path, *, termbase_authority: Any | None = None) -> dict[str, Any] | None:
    """Return the source-free governed termbase identity, never its paths."""

    from .terminology import load_effective_termbase

    try:
        termbase = load_effective_termbase(root, authority=termbase_authority)
    except Exception as exc:
        raise EvidenceValidationError(f"effective termbase could not be resolved ({type(exc).__name__})") from exc
    identity = termbase.binding_identity
    if not isinstance(identity, dict) or not identity.get("hash"):
        raise EvidenceValidationError("effective termbase did not produce a governed identity")
    return json.loads(json.dumps(identity, ensure_ascii=False, sort_keys=True))


def _repository_termbase_version(root: Path) -> str | None:
    identity = effective_termbase_identity(root)
    return identity.get("version") if identity else None


def repository_execution_configuration(root: Path) -> dict[str, Any]:
    """Describe behavior fixed by the checked-in production execution path."""

    root = root.expanduser().resolve()
    from .normalization import RENDER_DPI
    from .policy import MAX_AUTO_REPAIRS_PER_UNIT
    from .extraction import CROP_PADDING, MODEL_CROP_MIN_DIMENSION

    agent_path = root / ".opencode" / "agents" / "k-slide.md"
    frontmatter = _agent_frontmatter(root)
    generation = {}
    if frontmatter is not None and isinstance(frontmatter.get("temperature"), (int, float)) and not isinstance(frontmatter.get("temperature"), bool):
        generation = {"temperature": float(frontmatter["temperature"])}
    prompt_root = _source_path(root, "prompts")
    prompt_tree = _tree_hash(prompt_root)
    prompt_identity: dict[str, Any] = {}
    if prompt_tree is not None:
        prompt_identity["hash"] = prompt_tree
    if agent_path.is_file() and not agent_path.is_symlink():
        prompt_identity["agent_sha256"] = sha256_file(agent_path)
    if (prompt_root / "translation" / "v1.md").is_file():
        prompt_identity["version"] = "translation/v1"
    return {
        "prompt_identity": prompt_identity,
        "generation_settings": generation,
        "vision_settings": {
            "enabled": True,
            "context_image_required": True,
            "risk_crops_required": True,
        },
        "context_configuration": {
            "bounded_work_unit": True,
            "context_image_required": True,
            "required_source_regions": True,
        },
        "image_preprocessing_settings": {
            "dpi": int(RENDER_DPI),
            "render_dpi": float(RENDER_DPI),
            "crop_padding": float(CROP_PADDING),
            "model_crop_min_dimension": int(MODEL_CROP_MIN_DIMENSION),
            "context_image": "canonical_render",
        },
        "normalization_behavior": {
            "render_dpi": float(RENDER_DPI),
        },
        "repair_policy": {"max_auto_repairs_per_unit": MAX_AUTO_REPAIRS_PER_UNIT},
    }

# Deployment identity is deliberately an allowlist.  Sampling controls and
# certification outputs must never become part of the behavior identity merely
# because a caller added another field to its experiment manifest/profile.
DEPLOYMENT_PROFILE_FIELDS = (
    "kslide_version",
    "opencode_version",
    "requested_model",
    "effective_model",
    "ocr_provider",
    "python_version",
    "paddle_version",
    "paddleocr_version",
    "libreoffice_version",
    RETENTION_POLICY_FIELD,
    "tenant_isolation",
    "network_egress",
    "inference_endpoint_identity",
    "egress_policy_version",
    "egress_policy_hash",
    "egress_policy_identity",
    "runtime_artifact_identity",
    "runtime_artifact_manifest_sha256",
    "runtime_sbom_sha256",
    "opencode_bootstrap_identity",
    "opencode_models_identity",
    "normalization_behavior",
    "repair_policy",
    "generation_settings",
    "vision_settings",
    "behavior_configuration",
)
DEPLOYMENT_RUNTIME_FIELDS = (
    "opencode_version",
    "provider",
    "reported_model_id",
    "model_family",
    "model_size",
    "instruction_tuned_status",
    "vision_support",
    "thinking_support",
    "provider_backend",
    "quantization_or_dtype",
    "context_configuration",
    "image_preprocessing_settings",
    "ocr_provider",
)


class EvidenceValidationError(ValueError):
    """Raised when evidence is missing, malformed, stale, or insufficient."""


def _parse_scalar(raw: str) -> Any:
    value = raw.strip()
    if not value:
        return {}
    if value in {"null", "NULL", "~"}:
        return None
    if value.lower() in {"true", "false"}:
        return value.lower() == "true"
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        try:
            return ast.literal_eval(value)
        except (SyntaxError, ValueError):
            return value.strip("'\"")


def _parse_candidate_yaml(text: str) -> dict[str, Any]:
    """Parse the small mapping-only YAML contract without a YAML dependency."""

    root: dict[str, Any] = {}
    stack: list[tuple[int, Any]] = [(-1, root)]
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        line = raw.strip()
        while stack and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1]
        if line.startswith("- "):
            if not isinstance(parent, list):
                raise ValueError("candidate YAML list has no list parent")
            parent.append(_parse_scalar(line[2:]))
            continue
        key, separator, raw_value = line.partition(":")
        if not separator or not key.strip():
            raise ValueError("candidate YAML requires mapping entries")
        key = key.strip()
        value = _parse_scalar(raw_value)
        if raw_value.strip() == "":
            value = {}
        if not isinstance(parent, dict):
            raise ValueError("candidate YAML parent is not a mapping")
        parent[key] = value
        if raw_value.strip() == "":
            stack.append((indent, value))
    return root


def _load_candidate_mapping(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise EvidenceValidationError(f"candidate profile is missing or symlinked: {path.name}")
    try:
        text = path.read_text(encoding="utf-8")
        value = json.loads(text) if path.suffix.lower() == ".json" else _parse_candidate_yaml(text)
    except (OSError, UnicodeError, json.JSONDecodeError, SyntaxError, TypeError, ValueError) as exc:
        raise EvidenceValidationError(f"candidate profile is unreadable or malformed: {path.name}") from exc
    if not isinstance(value, dict):
        raise EvidenceValidationError("candidate profile must be an object")
    return value


def _canonical_behavior_configuration(configuration: dict[str, Any] | None, *, model: str | None = None, ocr_provider: str | None = None, strict: bool = False) -> dict[str, Any]:
    source = dict(configuration or {})
    normalized: dict[str, Any] = {}
    for raw_key, raw_value in source.items():
        key = _BEHAVIOR_ALIASES.get(str(raw_key), str(raw_key))
        if key in _EXPERIMENT_ONLY_FIELDS:
            continue
        if key not in _BEHAVIOR_FIELDS:
            if strict:
                raise EvidenceValidationError(f"unknown behavior configuration field: {raw_key}")
            continue
        if key in normalized and normalized[key] != raw_value:
            raise EvidenceValidationError(f"conflicting behavior configuration aliases: {raw_key}")
        normalized[key] = raw_value
    if model is not None:
        normalized["model"] = model
    if ocr_provider is not None:
        normalized["ocr_provider"] = ocr_provider
    return {key: normalized[key] for key in sorted(normalized)}


def canonical_behavior_configuration(configuration: dict[str, Any] | None, *, model: str | None = None, ocr_provider: str | None = None, strict: bool = False) -> dict[str, Any]:
    """Canonicalize the material behavior contract, including repository aliases."""

    return _canonical_behavior_configuration(configuration, model=model, ocr_provider=ocr_provider, strict=strict)


def _validate_candidate_schema_version(value: dict[str, Any]) -> None:
    declared = value.get("candidate_spec_version")
    if declared is None:
        declared = value.get("schema_version")
    nested = value.get("candidate_spec")
    if declared is None and isinstance(nested, dict):
        declared = nested.get("candidate_spec_version") or nested.get("schema_version")
    if declared is not None and str(declared) != CANDIDATE_SPEC_SCHEMA_VERSION:
        raise EvidenceValidationError(f"unsupported candidate specification schema: {declared}")


def _normalize_candidate_mapping(value: dict[str, Any], *, strict: bool = False) -> dict[str, Any]:
    source_value = dict(value.get("candidate_spec") or {}) if isinstance(value.get("candidate_spec"), dict) else {}
    source_value.update(value)
    if "retention_days" in source_value:
        raise EvidenceValidationError(
            "legacy retention_days is unsupported; explicitly supply "
            "retention_policy.content_retention_days and "
            "retention_policy.operational_metadata_retention_days"
        )
    _validate_candidate_schema_version(value)
    normalized: dict[str, Any] = {}
    for raw_key, raw_value in source_value.items():
        if raw_key == "candidate_spec":
            continue
        key = _CANDIDATE_ALIASES.get(str(raw_key), str(raw_key))
        if key in _EXPERIMENT_ONLY_FIELDS:
            continue
        if key in CERTIFICATION_OUTPUT_FIELDS or key in {"schema_version", "status", "certification", "note"}:
            continue
        if key not in CANDIDATE_INPUT_FIELDS:
            if strict:
                raise EvidenceValidationError(f"unknown candidate profile field: {raw_key}")
            continue
        if key in normalized and normalized[key] != raw_value:
            if _is_unset(normalized[key]):
                normalized[key] = raw_value
            elif _is_unset(raw_value):
                continue
            else:
                raise EvidenceValidationError(f"conflicting candidate profile aliases: {raw_key}")
        normalized[key] = raw_value
    behavior = dict(normalized.get("behavior_configuration") or {})
    for key in _BEHAVIOR_FIELDS | set(_BEHAVIOR_ALIASES):
        if key in source_value:
            canonical = _BEHAVIOR_ALIASES.get(key, key)
            if canonical in behavior and behavior[canonical] != source_value[key]:
                if _is_unset(behavior[canonical]):
                    behavior[canonical] = source_value[key]
                elif _is_unset(source_value[key]):
                    continue
                else:
                    raise EvidenceValidationError(f"conflicting candidate behavior aliases: {key}")
            else:
                behavior[canonical] = source_value[key]
    if "requested_model" in normalized:
        behavior.setdefault("model", normalized["requested_model"])
    if "ocr_provider" in normalized:
        behavior.setdefault("ocr_provider", normalized["ocr_provider"])
    normalized["behavior_configuration"] = _canonical_behavior_configuration(behavior, strict=strict)
    if RETENTION_POLICY_FIELD in normalized:
        try:
            normalized[RETENTION_POLICY_FIELD] = RetentionPolicy.from_mapping(normalized[RETENTION_POLICY_FIELD]).as_dict()
        except (TypeError, ValueError) as exc:
            raise EvidenceValidationError(f"retention policy is invalid ({type(exc).__name__})") from exc
    if isinstance(normalized.get("model_policy"), dict):
        from .model_policy import ModelPolicy

        normalized["model_policy"] = ModelPolicy.from_mapping(normalized["model_policy"]).as_dict()
    if isinstance(normalized.get("inference_data_use_policy"), dict):
        from .classification_policy import InferenceDataUsePolicy

        data_policy = InferenceDataUsePolicy.from_mapping(normalized["inference_data_use_policy"])
        if normalized.get("inference_route_identity") != data_policy.inference_route_identity:
            raise EvidenceValidationError("candidate inference route and data-use policy disagree")
        normalized["inference_data_use_policy"] = data_policy.as_dict()
    if isinstance(normalized.get("corpus_identity"), dict):
        normalized["corpus_identity"] = canonical_corpus_identity(normalized["corpus_identity"])
    return normalized


def load_candidate_spec(path: Path, *, root: Path | None = None, require_identity: bool = False, strict: bool | None = None) -> dict[str, Any]:
    """Load one explicit public-safe candidate deployment specification."""

    path = path.expanduser().resolve()
    raw_value = _load_candidate_mapping(path)
    nested_value = raw_value.get("candidate_spec") if isinstance(raw_value.get("candidate_spec"), dict) else {}
    declared_version = str(raw_value.get("candidate_spec_version") or raw_value.get("schema_version") or nested_value.get("candidate_spec_version") or nested_value.get("schema_version") or "")
    value = _normalize_candidate_mapping(raw_value, strict=require_identity if strict is None else strict)
    value.setdefault("schema_version", declared_version or CANDIDATE_SPEC_SCHEMA_VERSION)
    value.setdefault("candidate_spec_version", declared_version or CANDIDATE_SPEC_SCHEMA_VERSION)
    if declared_version != CANDIDATE_SPEC_SCHEMA_VERSION:
        raise EvidenceValidationError(f"unsupported candidate specification schema: {declared_version}")
    if root is not None and value.get("ocr_asset_manifest_sha256") is None:
        raw_manifest = _load_candidate_mapping(path).get("ocr_asset_manifest")
        if raw_manifest and not str(raw_manifest).startswith("UNSET"):
            try:
                value["ocr_asset_manifest_sha256"] = sha256_file(_resolve_candidate_path(root, str(raw_manifest)))
            except EvidenceValidationError as exc:
                if require_identity:
                    raise EvidenceValidationError("candidate OCR asset manifest is unavailable") from exc
    if require_identity:
        for field in ("subject_git_sha", "requested_model"):
            if not str(value.get(field) or "") or str(value[field]).upper() == "UNSET":
                raise EvidenceValidationError(f"candidate profile must declare {field}")
    return value


def _is_unset(value: Any) -> bool:
    return value is None or (isinstance(value, str) and value.strip().upper() in _UNRESOLVED_VALUE_MARKERS)


def _resolved_value(value: Any, *, field: str, allow_not_exposed: bool = False, _nested: bool = False) -> bool:
    if _is_unset(value):
        return False
    unavailable = explicit_unavailable_value(value)
    if unavailable is not None:
        return allow_not_exposed and field in _OPTIONAL_PROVIDER_METADATA
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, dict):
        if not value:
            return _nested
        if field == "generation_settings" and value.get("source") == PROVIDER_DEFAULTS_FROZEN:
            settings = value.get("settings")
            return value.get("resolved") is True and isinstance(settings, dict) and bool(settings) and all(_resolved_value(item, field=field, _nested=True) for item in settings.values())
        return all(_resolved_value(item, field=field, allow_not_exposed=False, _nested=True) for item in value.values())
    if isinstance(value, (list, tuple, set)):
        return all(_resolved_value(item, field=field, allow_not_exposed=False, _nested=True) for item in value)
    return True


def _nested_hash(value: Any) -> str | None:
    if not isinstance(value, dict):
        return None
    for key in ("hash", "sha256", "tree_sha256"):
        raw = value.get(key)
        if not _is_unset(raw):
            return str(raw)
    return None


def _bind_value(result: dict[str, Any], field: str, actual: Any) -> None:
    if actual is None:
        return
    current = result.get(field)
    if _is_unset(current):
        result[field] = actual
    elif current != actual:
        raise EvidenceValidationError(f"candidate {field} disagrees with deterministic repository input")


def _bind_nested_hash(result: dict[str, Any], field: str, actual: str | None) -> None:
    if actual is None:
        return
    current_value = result.get(field)
    if not _is_unset(current_value) and not isinstance(current_value, dict):
        raise EvidenceValidationError(f"candidate {field} must be an object")
    current = _nested_hash(current_value)
    if current is not None and current.lower() != actual.lower():
        raise EvidenceValidationError(f"candidate {field} disagrees with deterministic repository input")
    if current is None:
        nested = dict(current_value or {})
        nested["hash"] = actual
        result[field] = nested


def _bind_execution_mapping(result: dict[str, Any], field: str, actual: dict[str, Any]) -> None:
    """Bind a source-derived mapping while permitting only partial declarations."""

    current = result.get(field)
    if _is_unset(current) or current == {}:
        result[field] = dict(actual)
        return
    if not isinstance(current, dict):
        raise EvidenceValidationError(f"candidate {field} must be an object")
    for key, value in current.items():
        if _is_unset(value):
            continue
        if key not in actual or actual[key] != value:
            raise EvidenceValidationError(f"candidate {field} disagrees with executable production behavior")
    result[field] = dict(actual)


def resolve_candidate_spec(candidate_spec: dict[str, Any], *, root: Path, subject_git_sha: str | None = None, model_policy: Any | None = None, corpus: dict[str, Any] | None = None, require_sources: bool = False, termbase_authority: Any | None = None) -> dict[str, Any]:
    """Resolve repository-owned candidate inputs once before certification.

    Explicit values are never overwritten.  When an immutable repository
    source is present, an explicit digest must match it.  Certification
    callers set ``require_sources`` so a declared digest cannot stand in for
    an unavailable local source.
    """

    root = root.expanduser().resolve()
    result = _normalize_candidate_mapping(dict(candidate_spec), strict=True)
    result.setdefault("candidate_spec_version", CANDIDATE_SPEC_SCHEMA_VERSION)
    from . import __version__

    _bind_value(result, "kslide_version", __version__)
    _bind_value(result, "subject_git_sha", subject_git_sha)
    constraints = _source_path(root, "constraints-production.txt")
    if constraints.is_file() and not constraints.is_symlink():
        _bind_value(result, "constraints_sha256", sha256_file(constraints))
    elif require_sources and not _is_unset(result.get("constraints_sha256")):
        raise EvidenceValidationError("candidate constraints-production.txt is unavailable for verification")
    inventory_candidates = (
        root / ".k-slide-config" / "production-dependency-inventory.json",
        root / "production-dependency-inventory.json",
    )
    inventory_path = next((path for path in inventory_candidates if path.is_file() and not path.is_symlink()), None)
    inventory = None
    if inventory_path is not None:
        inventory = load_dependency_inventory(inventory_path)
        _bind_value(result, "resolved_dependency_set_sha256", dependency_inventory_hash(inventory))
    elif require_sources and not _is_unset(result.get("resolved_dependency_set_sha256")):
        raise EvidenceValidationError("production dependency inventory is unavailable for verification")
    lock_candidates = (
        root / ".k-slide-config" / "production-requirements.lock",
        root / "production-requirements.lock",
    )
    lock_path = next((path for path in lock_candidates if path.is_file() and not path.is_symlink()), None)
    if lock_path is not None:
        lock_inventory = load_dependency_lock(lock_path)
        if inventory_path is not None and lock_inventory != inventory:
            raise EvidenceValidationError("production dependency lock disagrees with the canonical inventory")
        if inventory_path is None:
            _bind_value(result, "resolved_dependency_set_sha256", dependency_inventory_hash(lock_inventory))
    prompt_hash = _tree_hash(_source_path(root, "prompts"))
    if require_sources and prompt_hash is None and (not _is_unset(result.get("prompt_hash")) or _nested_hash(result.get("prompt_identity")) is not None):
        raise EvidenceValidationError("candidate prompt tree is unavailable for verification")
    _bind_nested_hash(result, "prompt_identity", prompt_hash)
    if prompt_hash is not None:
        _bind_value(result, "prompt_hash", prompt_hash)
    declared_authority = termbase_authority if termbase_authority is not None else result.get("termbase_governance")
    termbase_identity = effective_termbase_identity(root, termbase_authority=declared_authority)
    termbase_hash = termbase_identity.get("hash") if termbase_identity else None
    if require_sources and termbase_hash is None and (not _is_unset(result.get("termbase_hash")) or _nested_hash(result.get("termbase_identity")) is not None):
        raise EvidenceValidationError("candidate termbase is unavailable for verification")
    if termbase_identity is not None:
        current_identity = result.get("termbase_identity")
        if current_identity is not None and not _is_unset(current_identity) and not isinstance(current_identity, dict):
            raise EvidenceValidationError("candidate termbase_identity must be an object")
        if isinstance(current_identity, dict):
            for key in ("version", "hash", "schema_version", "governance_identity", "policy_identity", "authorization_identity", "order_identity", "core_identity", "core", "overlays", "overlay_order"):
                declared = current_identity.get(key)
                if not _is_unset(declared) and declared != termbase_identity.get(key):
                    raise EvidenceValidationError("candidate termbase_identity disagrees with effective terminology")
        result["termbase_identity"] = dict(termbase_identity)
    if termbase_hash is not None:
        _bind_value(result, "termbase_hash", termbase_hash)
    termbase_version = termbase_identity.get("version") if termbase_identity else None
    if termbase_version is not None:
        _bind_value(result, "termbase_version", termbase_version)
        identity = dict(result.get("termbase_identity") or {})
        _bind_value(identity, "version", termbase_version)
        result["termbase_identity"] = identity
    if model_policy is not None:
        actual_policy = model_policy.as_dict() if hasattr(model_policy, "as_dict") else model_policy
        current_policy = result.get("model_policy")
        from .model_policy import ModelPolicy

        if isinstance(actual_policy, dict):
            actual_policy = ModelPolicy.from_mapping(actual_policy).as_dict()
        if isinstance(current_policy, dict):
            current_policy = ModelPolicy.from_mapping(current_policy).as_dict()
        if _is_unset(current_policy) or current_policy == {}:
            result["model_policy"] = actual_policy
        elif current_policy != actual_policy:
            raise EvidenceValidationError("candidate model_policy disagrees with authoritative policy")
        else:
            result["model_policy"] = current_policy
    egress_path = root / ".k-slide-config" / "egress-policy.json"
    declared_egress = any(not _is_unset(result.get(field)) for field in ("egress_policy_version", "egress_policy_hash", "egress_policy_identity", "inference_endpoint_identity"))
    if egress_path.is_file() and not egress_path.is_symlink():
        from .egress_policy import load_egress_policy

        egress_policy = load_egress_policy(root)
        for field, actual in (
            ("egress_policy_version", egress_policy.policy_version),
            ("egress_policy_hash", egress_policy.policy_hash),
            ("egress_policy_identity", egress_policy.policy_identity),
            ("inference_endpoint_identity", egress_policy.capability("inference_route").endpoint_identity),
        ):
            _bind_value(result, field, actual)
        data_policy = result.get("inference_data_use_policy")
        if isinstance(data_policy, dict):
            inference = egress_policy.capability("inference_route")
            if inference.route_identity != data_policy.get("inference_route_identity"):
                raise EvidenceValidationError("candidate egress inference route disagrees with inference data-use policy")
            if not _is_unset(result.get("inference_route_identity")) and inference.route_identity != result.get("inference_route_identity"):
                raise EvidenceValidationError("candidate egress inference route disagrees with candidate route identity")
        elif not _is_unset(result.get("inference_route_identity")):
            if egress_policy.capability("inference_route").route_identity != result.get("inference_route_identity"):
                raise EvidenceValidationError("candidate egress inference route disagrees with candidate route identity")
    elif require_sources and declared_egress:
        raise EvidenceValidationError("candidate egress policy is unavailable for verification")
    elif declared_egress and any(_is_unset(result.get(field)) for field in ("egress_policy_version", "egress_policy_hash", "egress_policy_identity", "inference_endpoint_identity")):
        raise EvidenceValidationError("candidate egress policy identity is incomplete")
    bootstrap_path = root / ".k-slide-config" / "opencode-bootstrap.json"
    declared_bootstrap = any(not _is_unset(result.get(field)) for field in ("opencode_bootstrap_identity", "opencode_models_identity"))
    if bootstrap_path.is_file() and not bootstrap_path.is_symlink():
        from .opencode_bootstrap import load_bootstrap_manifest

        bootstrap = load_bootstrap_manifest(bootstrap_path)
        models_identity = sha256_bytes(canonical_bytes(bootstrap.models_identity))
        _bind_value(result, "opencode_bootstrap_identity", bootstrap.identity)
        _bind_value(result, "opencode_models_identity", models_identity)
    elif require_sources and declared_bootstrap:
        raise EvidenceValidationError("candidate OpenCode bootstrap identity is unavailable for verification")
    elif declared_bootstrap and any(_is_unset(result.get(field)) for field in ("opencode_bootstrap_identity", "opencode_models_identity")):
        raise EvidenceValidationError("candidate OpenCode bootstrap identity is incomplete")
    if corpus is not None:
        actual_corpus = canonical_corpus_identity(corpus)
        current_corpus = result.get("corpus_identity")
        if _is_unset(current_corpus) or current_corpus == {} or current_corpus == canonical_corpus_identity(None):
            result["corpus_identity"] = actual_corpus
        else:
            current_identity = canonical_corpus_identity(current_corpus)
            if current_identity.get("schema_version") == "1.0" and actual_corpus.get("schema_version") == "1.0":
                expected_sets = {item["role"]: item for item in current_identity["sets"]}
                actual_sets = {item["role"]: item for item in actual_corpus["sets"]}
                if not actual_sets or any(expected_sets.get(role) != identity for role, identity in actual_sets.items()):
                    raise EvidenceValidationError("candidate corpus identity disagrees with frozen corpus")
            elif current_identity.get("schema_version") == "1.0":
                governed = corpus.get("governed_set_identity") if isinstance(corpus, dict) else None
                public_identity = next((item for item in current_identity["sets"] if item["role"] == "public_synthetic_regression"), None)
                try:
                    actual_public_identity = canonical_governed_corpus_identity({"schema_version": "1.0", "sets": [governed]})["sets"][0] if governed is not None else None
                except CorpusGovernanceError as exc:
                    raise EvidenceValidationError("frozen public corpus identity is malformed") from exc
                if actual_public_identity is None or public_identity != actual_public_identity:
                    raise EvidenceValidationError("candidate corpus identity disagrees with frozen corpus")
            elif actual_corpus.get("schema_version") == "1.0":
                legacy = {
                    "version": corpus.get("version") or corpus.get("corpus_version") or corpus.get("dataset_version"),
                    "corpus_fingerprint": corpus.get("corpus_fingerprint"),
                    "held_out_fingerprint": corpus.get("held_out_fingerprint") or corpus.get("heldout_fingerprint"),
                } if isinstance(corpus, dict) else canonical_corpus_identity(None)
                if current_identity != legacy:
                    raise EvidenceValidationError("candidate corpus identity disagrees with frozen corpus")
            elif current_identity != actual_corpus:
                raise EvidenceValidationError("candidate corpus identity disagrees with frozen corpus")
    raw_manifest = result.get("ocr_asset_manifest")
    if not _is_unset(raw_manifest):
        if require_sources and result.get("ocr_provider") == "paddle" and str(raw_manifest) != "ocr/manifest.json":
            raise EvidenceValidationError("certifying Paddle candidates must use the canonical ocr/manifest.json path")
        manifest = _resolve_candidate_path(root, str(raw_manifest))
        if manifest.is_file() and not manifest.is_symlink():
            expected_manifest = result.get("ocr_asset_manifest_sha256")
            if require_sources:
                asset_identity = validate_ocr_asset_manifest(manifest, expected_sha256=None if _is_unset(expected_manifest) else str(expected_manifest))
                _bind_value(result, "ocr_asset_manifest_sha256", asset_identity["sha256"])
            else:
                _bind_value(result, "ocr_asset_manifest_sha256", sha256_file(manifest))
        elif require_sources:
            raise EvidenceValidationError("candidate OCR asset manifest is unavailable for verification")
    execution = repository_execution_configuration(root)
    if require_sources and not execution["generation_settings"]:
        raise EvidenceValidationError("production OpenCode agent frontmatter is unavailable for verification")
    for field in ("generation_settings", "vision_settings", "context_configuration", "image_preprocessing_settings", "normalization_behavior", "repair_policy"):
        actual = execution[field]
        if actual:
            _bind_execution_mapping(result, field, actual)
    actual_prompt = execution["prompt_identity"]
    if actual_prompt:
        _bind_execution_mapping(result, "prompt_identity", actual_prompt)
        if actual_prompt.get("version") is not None:
            _bind_value(result, "prompt_version", actual_prompt["version"])
    actual_schema = repository_schema_versions()
    declared_schema = result.get("schema_versions")
    if _is_unset(declared_schema) or declared_schema == {}:
        result["schema_versions"] = actual_schema
    elif declared_schema != actual_schema:
        raise EvidenceValidationError("candidate schema_versions disagree with repository schema constants")
    behavior = dict(result.get("behavior_configuration") or {})
    for field, actual in (("prompt_hash", prompt_hash), ("termbase_hash", termbase_hash)):
        if actual is not None and field in behavior:
            if _is_unset(behavior[field]):
                behavior[field] = actual
            elif behavior[field] != actual:
                raise EvidenceValidationError(f"candidate behavior {field} disagrees with deterministic repository input")
    execution_behavior = {
        "model": result.get("requested_model"),
        "provider": result.get("provider"),
        "prompt_identity": result.get("prompt_identity"),
        "prompt_version": (result.get("prompt_identity") or {}).get("version") if isinstance(result.get("prompt_identity"), dict) else result.get("prompt_version"),
        "prompt_hash": (result.get("prompt_identity") or {}).get("hash") if isinstance(result.get("prompt_identity"), dict) else result.get("prompt_hash"),
        "generation_settings": result.get("generation_settings"),
        "vision_settings": result.get("vision_settings"),
        "context_configuration": result.get("context_configuration"),
        "image_preprocessing_settings": result.get("image_preprocessing_settings"),
        "normalization_behavior": result.get("normalization_behavior"),
        "repair_policy": result.get("repair_policy"),
        "ocr_provider": result.get("ocr_provider"),
        "termbase_version": result.get("termbase_version"),
        "termbase_hash": result.get("termbase_hash"),
        "evidence_ir_schema": (result.get("schema_versions") or {}).get("evidence_ir") if isinstance(result.get("schema_versions"), dict) else None,
        "translation_patch_schema": (result.get("schema_versions") or {}).get("translation_patch") if isinstance(result.get("schema_versions"), dict) else None,
        "slide_ir_schema": (result.get("schema_versions") or {}).get("slide_ir") if isinstance(result.get("schema_versions"), dict) else None,
    }
    if isinstance(result.get("generation_settings"), dict) and "temperature" in result["generation_settings"]:
        execution_behavior["temperature"] = result["generation_settings"]["temperature"]
    for raw_key, declared in behavior.items():
        key = _BEHAVIOR_ALIASES.get(str(raw_key), str(raw_key))
        if key not in execution_behavior:
            raise EvidenceValidationError(f"candidate behavior {raw_key} has no executable production proof")
        actual = execution_behavior[key]
        if _is_unset(declared):
            continue
        if isinstance(actual, dict) and isinstance(declared, dict):
            # Validate the declaration itself against the executable value.
            # Passing ``execution_behavior`` here would compare the actual
            # mapping with itself and allow a contradictory nested declaration
            # to survive canonicalization.
            _bind_execution_mapping({key: declared}, key, actual)
        elif declared != actual:
            raise EvidenceValidationError(f"candidate behavior {raw_key} disagrees with executable production behavior")
    for key, value in execution_behavior.items():
        if value is not None and value != {}:
            behavior[key] = value
    result["behavior_configuration"] = _canonical_behavior_configuration(behavior, strict=True)
    return result


def _hash_field_resolved(candidate: dict[str, Any], field: str, nested_field: str | None = None) -> bool:
    value = candidate.get(field)
    if not _resolved_value(value, field=field):
        return False
    raw = _nested_hash(value) if nested_field else value
    if raw is None:
        return False
    try:
        _require_hex(raw, field)
    except EvidenceValidationError:
        return False
    return True


def _governed_termbase_identity_resolved(value: Any) -> bool:
    """Require governance provenance in addition to the effective hash."""

    if not isinstance(value, dict):
        return False
    required = ("schema_version", "governance_identity", "policy_identity", "authorization_identity", "order_identity", "version", "hash", "effective_hash", "core", "overlays", "overlay_order")
    if any(_is_unset(value.get(key)) for key in required):
        return False
    try:
        _require_hex(str(value["hash"]), "termbase_identity.hash")
        _require_hex(str(value["effective_hash"]), "termbase_identity.effective_hash")
    except EvidenceValidationError:
        return False
    core = value.get("core")
    if not isinstance(core, dict) or any(_is_unset(core.get(key)) for key in ("identity", "version", "sha256", "scope", "scope_ref")):
        return False
    try:
        _require_hex(str(core["sha256"]), "termbase_identity.core.sha256")
    except EvidenceValidationError:
        return False
    overlays = value.get("overlays")
    order = value.get("overlay_order")
    if not isinstance(overlays, list) or not isinstance(order, list):
        return False
    if len(overlays) != len(order):
        return False
    for overlay in overlays:
        if not isinstance(overlay, dict) or any(_is_unset(overlay.get(key)) for key in ("identity", "version", "sha256", "scope", "scope_ref", "order", "authorization_identity")):
            return False
        try:
            _require_hex(str(overlay["sha256"]), "termbase_identity.overlay.sha256")
        except EvidenceValidationError:
            return False
    return True


def _retention_policy_missing(candidate_spec: dict[str, Any]) -> list[str]:
    if "retention_days" in candidate_spec:
        return ["retention_policy.migration_required"]
    raw_policy = candidate_spec.get(RETENTION_POLICY_FIELD)
    if not isinstance(raw_policy, dict):
        return [
            f"{RETENTION_POLICY_FIELD}.content_retention_days",
            f"{RETENTION_POLICY_FIELD}.operational_metadata_retention_days",
        ]
    try:
        policy = RetentionPolicy.from_mapping(raw_policy)
    except (TypeError, ValueError):
        return [RETENTION_POLICY_FIELD]
    missing: list[str] = []
    if not isinstance(policy.content_retention_days, int):
        missing.append(f"{RETENTION_POLICY_FIELD}.content_retention_days")
    if not isinstance(policy.operational_metadata_retention_days, int):
        missing.append(f"{RETENTION_POLICY_FIELD}.operational_metadata_retention_days")
    return missing


def candidate_completeness(candidate_spec: dict[str, Any], state: str) -> list[str]:
    """Return unresolved candidate inputs for a requested release state."""

    if state in {"DEVELOPMENT", "CERTIFICATION_STALE"}:
        return []
    fields = _CANDIDATE_COMPLETENESS_FIELDS.get(state, _PRODUCTION_COMPLETENESS_FIELDS)
    missing: list[str] = []
    for field in fields:
        allow_not_exposed = field in _OPTIONAL_PROVIDER_METADATA
        if field == RETENTION_POLICY_FIELD:
            missing.extend(_retention_policy_missing(candidate_spec))
            continue
        if field == "resource_budget":
            try:
                budget = ResourceBudget.from_dict(candidate_spec.get(field))
                valid = budget.environment == "production"
            except KSlideError:
                valid = False
            if not valid:
                missing.append(field)
            continue
        if field == "subject_git_sha":
            raw_subject = str(candidate_spec.get(field) or "")
            valid = len(raw_subject) == 40 and not (set(raw_subject.lower()) - set("0123456789abcdef"))
        elif field == "prompt_identity":
            identity = candidate_spec.get(field)
            identity_version = identity.get("version") if isinstance(identity, dict) else None
            valid = _hash_field_resolved(candidate_spec, field, nested_field="hash") and (
                _resolved_value(identity_version, field=field) or _resolved_value(candidate_spec.get("prompt_version"), field=field)
            )
        elif field in {"ocr_asset_manifest_sha256", "constraints_sha256", "termbase_hash", "resolved_dependency_set_sha256"}:
            valid = _hash_field_resolved(candidate_spec, field)
        elif field == "termbase_identity":
            valid = _governed_termbase_identity_resolved(candidate_spec.get(field))
        elif field in {"kslide_version", "opencode_version", "paddle_version", "paddleocr_version", "python_version", "libreoffice_version"}:
            try:
                canonical_exact_version(candidate_spec.get(field), field)
                valid = True
            except EvidenceValidationError:
                valid = False
        elif field == "schema_versions":
            valid = candidate_spec.get(field) == repository_schema_versions()
        else:
            valid = _resolved_value(candidate_spec.get(field), field=field, allow_not_exposed=allow_not_exposed)
        if not valid:
            missing.append(field)
    if state in {"GEMMA_EVAL_READY", "SYNTHETIC_PRODUCTION_CANDIDATE"} and candidate_spec.get("ocr_provider") == "paddle":
        for field in ("ocr_asset_manifest", "ocr_asset_manifest_sha256"):
            if field not in missing and not _resolved_value(candidate_spec.get(field), field=field):
                missing.append(field)
    if state in {"SYNTHETIC_PRODUCTION_CANDIDATE", "INTERNAL_VALIDATED", "PILOT_APPROVED", "PRODUCTION_CERTIFIED"} and not is_certification_corpus_ready(candidate_spec.get("corpus_identity")):
        missing.append("corpus_identity.governed_sets")
    if state == "PRODUCTION_CERTIFIED" and candidate_spec.get("ocr_provider") != "paddle":
        missing.append("ocr_provider")
    if state == "PRODUCTION_CERTIFIED":
        if candidate_spec.get("tenant_isolation") != "workspace_per_session":
            missing.append("tenant_isolation")
        if candidate_spec.get("network_egress") != "default_deny":
            missing.append("network_egress")
        if not _resolved_value(candidate_spec.get("egress_policy_version"), field="egress_policy_version"):
            missing.append("egress_policy_version")
        for field in ("egress_policy_hash", "egress_policy_identity"):
            if not _hash_field_resolved(candidate_spec, field):
                missing.append(field)
        if not _hash_field_resolved(candidate_spec, "inference_endpoint_identity"):
            missing.append("inference_endpoint_identity")
    return sorted(set(missing))


def _resolve_candidate_path(root: Path, raw: str) -> Path:
    path = Path(raw).expanduser()
    return path if path.is_absolute() else root.expanduser().resolve() / path


def canonical_candidate_factors(candidate_spec: dict[str, Any]) -> dict[str, Any]:
    """Return the explicit, path/timestamp-free candidate identity factors."""

    normalized = _normalize_candidate_mapping(dict(candidate_spec), strict=True)
    factors = {key: normalized.get(key) for key in CANDIDATE_INPUT_FIELDS if key in normalized and key not in {"ocr_asset_manifest", "ocr_asset_manifest_sha256", "termbase_governance"}}
    factors["ocr_asset_manifest_sha256"] = normalized.get("ocr_asset_manifest_sha256")
    factors["candidate_spec_version"] = str(normalized.get("candidate_spec_version", candidate_spec.get("schema_version", CANDIDATE_SPEC_SCHEMA_VERSION)))
    return factors


def candidate_deployment_fingerprint(candidate_spec: dict[str, Any]) -> str:
    return sha256_bytes(canonical_bytes(canonical_candidate_factors(candidate_spec)))


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    if not path.is_file() or path.is_symlink():
        raise EvidenceValidationError(f"file is missing or symlinked: {path.name}")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def safe_relative_path(root: Path, raw: str | Path, *, label: str, require_file: bool = False) -> Path:
    """Resolve a path below ``root`` without permitting symlink traversal.

    ``Path.resolve()`` alone is insufficient here: it would hide an ancestor
    symlink that happens to resolve back inside the trusted root.  Walk every
    component first, then perform the containment check on the resolved path.
    """

    trusted_root = root.expanduser().absolute()
    if trusted_root.is_symlink():
        raise EvidenceValidationError(f"trusted root for {label} is symlinked")
    relative = Path(raw).expanduser()
    if relative.is_absolute() or not relative.parts or relative == Path(".") or any(part in {"", ".", ".."} for part in relative.parts):
        raise EvidenceValidationError(f"{label} must be a relative path without traversal")
    current = trusted_root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise EvidenceValidationError(f"{label} traverses a symlink")
    resolved = (trusted_root / relative).resolve()
    try:
        resolved.relative_to(trusted_root.resolve())
    except ValueError as exc:
        raise EvidenceValidationError(f"{label} escapes the trusted root") from exc
    if require_file and (resolved.is_symlink() or not resolved.is_file()):
        raise EvidenceValidationError(f"{label} is missing or not a regular file")
    # Preserve the trusted-root spelling so callers can create portable
    # relative descriptors even on platforms where /var is an alias for
    # /private/var.  All safety checks above used the resolved target.
    return trusted_root / relative


def safe_path_under(root: Path, raw: str | Path, *, label: str, require_file: bool = False) -> Path:
    """Resolve an absolute or relative path under ``root`` safely."""

    trusted_root = root.expanduser().absolute()
    value = Path(raw).expanduser()
    if value.is_absolute():
        try:
            value = value.relative_to(trusted_root)
        except ValueError as exc:
            raise EvidenceValidationError(f"{label} must be inside the trusted root") from exc
    return safe_relative_path(trusted_root, value, label=label, require_file=require_file)


def _selected_paddlex_models(config_path: Path, *, asset_root: Path, require_local: bool) -> dict[str, str]:
    """Read selected model names and bind their directories to the asset tree."""

    try:
        import yaml
    except ImportError as exc:
        raise EvidenceValidationError("PyYAML is required to validate the PaddleX configuration") from exc
    try:
        value = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise EvidenceValidationError("OCR PaddleX configuration is unreadable") from exc
    if not isinstance(value, dict):
        raise EvidenceValidationError("OCR PaddleX configuration must be a mapping")
    modules = value.get("SubModules")
    if not isinstance(modules, dict):
        if require_local:
            raise EvidenceValidationError("OCR PaddleX configuration has no selected text models")
        return {}
    selected: dict[str, str] = {}
    for role, key in (("detector", "TextDetection"), ("recognizer", "TextRecognition")):
        module = modules.get(key)
        if not isinstance(module, dict) or not isinstance(module.get("model_name"), str) or not module["model_name"].strip():
            raise EvidenceValidationError(f"OCR PaddleX configuration has no selected {role} model")
        selected[f"{role}_model"] = module["model_name"].strip()
        raw_dir = module.get("model_dir")
        if not require_local:
            continue
        if not isinstance(raw_dir, str) or not raw_dir.strip():
            raise EvidenceValidationError(f"OCR PaddleX configuration has no local {role} model directory")
        model_dir = Path(raw_dir).expanduser()
        if not model_dir.is_absolute():
            model_dir = config_path.parent / model_dir
        model_dir = safe_path_under(asset_root, model_dir, label=f"OCR {role} model directory")
        if model_dir.is_symlink() or not model_dir.is_dir():
            raise EvidenceValidationError(f"OCR {role} model directory is not a local directory")
        files = [item for item in model_dir.rglob("*") if item.is_file()]
        if not files or any(item.is_symlink() for item in model_dir.rglob("*")):
            raise EvidenceValidationError(f"OCR {role} model directory has no complete local model files")
        selected[f"{role}_model_dir"] = model_dir.relative_to(asset_root).as_posix()
    return selected


def validate_ocr_asset_manifest(path: Path, *, expected_sha256: str | None = None, asset_root: Path | None = None, verify_files: bool = True, require_model_identity: bool = False) -> dict[str, Any]:
    """Validate a portable, exact Paddle asset tree and return its identity."""

    manifest = safe_path_under(path.parent, path, label="OCR asset manifest", require_file=True)
    actual_manifest_hash = sha256_file(manifest)
    if expected_sha256 is not None and actual_manifest_hash != str(expected_sha256).lower():
        raise EvidenceValidationError("OCR asset manifest hash does not match the expected candidate identity")
    try:
        value = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EvidenceValidationError("OCR asset manifest is unreadable") from exc
    if not isinstance(value, dict) or value.get("provider") != "paddle":
        raise EvidenceValidationError("OCR asset manifest is not a Paddle manifest")
    files = value.get("files")
    if not isinstance(files, list) or not files:
        raise EvidenceValidationError("OCR asset manifest has no materialized files")
    root = (asset_root or manifest.parent).expanduser().absolute()
    try:
        manifest.relative_to(root)
    except ValueError as exc:
        raise EvidenceValidationError("OCR asset manifest is outside its asset root") from exc
    seen: set[str] = set()
    for item in files:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            raise EvidenceValidationError("OCR asset manifest contains an invalid file entry")
        relative = Path(item["path"])
        if relative.is_absolute() or not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
            raise EvidenceValidationError("OCR asset manifest paths must be portable and relative")
        key = relative.as_posix()
        if key in seen:
            raise EvidenceValidationError("OCR asset manifest contains duplicate files")
        seen.add(key)
        expected = str(item.get("sha256") or "").lower()
        if len(expected) != 64 or set(expected) - _HEX64:
            raise EvidenceValidationError(f"OCR asset manifest hash is invalid: {key}")
        asset = safe_relative_path(root, relative, label=f"OCR asset {key}", require_file=verify_files)
        if verify_files:
            if sha256_file(asset) != expected:
                raise EvidenceValidationError(f"OCR asset hash mismatch: {key}")
            if "bytes" in item and (isinstance(item["bytes"], bool) or not isinstance(item["bytes"], int) or item["bytes"] != asset.stat().st_size):
                raise EvidenceValidationError(f"OCR asset size mismatch: {key}")
    config = value.get("paddlex_config")
    if not isinstance(config, str) or config != PADDLE_OCR_CONFIG:
        raise EvidenceValidationError(f"OCR PaddleX configuration must be the canonical {PADDLE_OCR_CONFIG} path")
    config_path = safe_relative_path(root, config, label="OCR PaddleX configuration", require_file=verify_files)
    config_entry = next((item for item in files if item.get("path") == config), None)
    if not isinstance(config_entry, dict):
        raise EvidenceValidationError("OCR PaddleX configuration is not represented in the asset manifest")
    config_hash = str(config_entry.get("sha256") or "").lower()
    if len(config_hash) != 64 or set(config_hash) - _HEX64:
        raise EvidenceValidationError("OCR PaddleX configuration hash is invalid")
    if verify_files and sha256_file(config_path) != config_hash:
        raise EvidenceValidationError("OCR PaddleX configuration hash does not match the selected file")
    declared_model_identity = value.get("model_identity")
    # Basic manifest consumers run in the lightweight test/install surface,
    # where PaddleX and PyYAML are intentionally absent. Parse and bind the
    # selected model tree only for the strict runtime path or when the
    # manifest explicitly declares a model identity to validate.
    model_identity = (
        _selected_paddlex_models(config_path, asset_root=root, require_local=require_model_identity)
        if require_model_identity or isinstance(declared_model_identity, dict)
        else {}
    )
    if require_model_identity and not isinstance(declared_model_identity, dict):
        raise EvidenceValidationError("OCR asset manifest does not declare the selected model identity")
    if isinstance(declared_model_identity, dict) and model_identity and declared_model_identity != model_identity:
        raise EvidenceValidationError("OCR asset manifest model identity does not match the selected configuration")
    if model_identity:
        for field in ("detector_model", "recognizer_model"):
            declared = value.get(field)
            if declared is not None and declared != model_identity[field]:
                raise EvidenceValidationError(f"OCR asset manifest {field} does not match the selected configuration")
    provenance = value.get("asset_provenance")
    if provenance is not None and provenance not in {"certifying-bundle", "development-prefetch"}:
        raise EvidenceValidationError("OCR asset provenance is invalid")
    if provenance == "development-prefetch" and value.get("asset_status") != "DEVELOPMENT_ONLY":
        raise EvidenceValidationError("development-prefetched OCR assets must remain DEVELOPMENT_ONLY")
    if verify_files:
        listed = {manifest.relative_to(root).as_posix(), *seen}
        actual_files: set[str] = set()
        for item in root.rglob("*"):
            if item.is_symlink():
                raise EvidenceValidationError("OCR asset root contains a symlink")
            if item.is_file():
                actual_files.add(item.relative_to(root).as_posix())
        if actual_files - listed:
            raise EvidenceValidationError("OCR asset root contains unlisted files")
    entries = [{"path": item["path"], "sha256": str(item["sha256"]).lower(), **({"bytes": item["bytes"]} if "bytes" in item else {})} for item in files]
    return {"sha256": actual_manifest_hash, "file_count": len(files), "files": sorted(seen), "entries": sorted(entries, key=lambda item: item["path"]), "paddlex_config": config, "paddlex_config_sha256": config_hash, **({"model_identity": model_identity} if model_identity else {})}


def paddle_runtime_configuration(*, asset_root: Path, manifest_path: Path | None = None, configured_config: str | None = None, require_local: bool | None = None) -> dict[str, Any]:
    """Resolve the exact Paddle config selected by the running OCR provider."""

    root = asset_root.expanduser().absolute()
    local_required = require_local if require_local is not None else os.environ.get("KSLIDE_PADDLE_REQUIRE_LOCAL_ASSETS", "0").lower() in {"1", "true", "yes"}
    raw_config = configured_config or os.environ.get("KSLIDE_PADDLEX_CONFIG")
    manifest = manifest_path or root / "manifest.json"
    if raw_config is None:
        if local_required or manifest.is_file() or manifest.is_symlink():
            raw_config = PADDLE_OCR_CONFIG
        else:
            return {"paddlex_config": None, "paddlex_config_sha256": None, "offline_assets_required": False, "asset_manifest_sha256": None}
    config_path = Path(raw_config).expanduser()
    if config_path.is_absolute():
        config_path = safe_path_under(root, config_path, label="selected PaddleX configuration", require_file=True)
    else:
        config_path = safe_relative_path(root, config_path, label="selected PaddleX configuration", require_file=True)
    relative = config_path.relative_to(root)
    if relative.as_posix() != PADDLE_OCR_CONFIG:
        raise EvidenceValidationError(f"selected PaddleX configuration must be {PADDLE_OCR_CONFIG}")
    manifest_identity: dict[str, Any] | None = None
    if manifest.is_file() or manifest.is_symlink():
        try:
            raw_manifest_value = json.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            raw_manifest_value = {}
        strict_model_identity = local_required and isinstance(raw_manifest_value, dict) and isinstance(raw_manifest_value.get("model_identity"), dict)
        manifest_identity = validate_ocr_asset_manifest(manifest, asset_root=root, verify_files=True, require_model_identity=strict_model_identity)
        if manifest_identity["paddlex_config"] != relative.as_posix() or manifest_identity["paddlex_config_sha256"] != sha256_file(config_path):
            raise EvidenceValidationError("selected PaddleX configuration does not match the asset manifest")
    declared_model_identity = manifest_identity.get("model_identity") if manifest_identity else None
    # Older non-runtime fixtures may carry a generic pipeline config and a
    # manifest without model identity. Keep those fixtures readable while the
    # strict artifact build/verification path still requires the identity.
    model_identity = declared_model_identity if isinstance(declared_model_identity, dict) else (
        {} if manifest_identity else _selected_paddlex_models(config_path, asset_root=root, require_local=local_required)
    )
    return {"paddlex_config": relative.as_posix(), "paddlex_config_sha256": sha256_file(config_path), "offline_assets_required": bool(local_required), "asset_manifest_sha256": manifest_identity["sha256"] if manifest_identity else None, **model_identity}


def _require_hex(value: Any, label: str) -> str:
    text = str(value or "")
    if len(text) != 64 or set(text.lower()) - _HEX64:
        raise EvidenceValidationError(f"{label} must be a SHA-256 hex digest")
    return text.lower()


def _is_true(value: Any) -> bool:
    return value is True


def _positive_int(value: Any, minimum: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= minimum


def validate_evidence_payload(evidence_type: str, payload: dict[str, Any]) -> None:
    """Validate substantive pass criteria for one evidence class."""

    if not isinstance(payload, dict) or not payload:
        raise EvidenceValidationError(f"{evidence_type} evidence has no payload")
    requirements: dict[str, tuple[str, ...]] = {
        "runtime": ("runtime_pass", "required_media_compliance", "run_complete", "simple_pass", "three_slide_pass", "five_slide_pass"),
        "heavy_runtime": ("heavy_pass", "networkless_pass", "representative_engine_pass", "full_engine_pass", "unexpected_capability_blocks", "dependency_subject", "resolved_dependency_set_sha256", "resolved_dependency_lock_sha256", "built_image_dependency_set_sha256"),
        "model_validation": ("split", "requested_model", "effective_model", "target_model_approved", "quality_metrics_authoritative", "critical_failure_count", "hard_gate_failure_count", "hard_gate_failure_types", "hard_gate_pass", "noncritical_floor_pass", "noncritical_semantic_required_count", "noncritical_semantic_correct_count", "noncritical_semantic_equivalence", "material_unresolved_recall", "unresolved_precision", "quality_policy", "quality_policy_identity", "repetitions", "configuration_hash", "behavior_configuration_hash", "experiment_plan_hash", "scenario_ids", "formats", "required_media_compliance", "vision_input_proven", "locked_terminology_recall", "unexpected_unresolved_rate", "corpus_set_identity", "evaluation_purpose"),
        "model_high_risk_stability": ("requested_model", "effective_model", "target_model_approved", "quality_metrics_authoritative", "critical_failure_count", "hard_gate_failure_count", "hard_gate_failure_types", "hard_gate_pass", "noncritical_floor_pass", "noncritical_semantic_required_count", "noncritical_semantic_correct_count", "noncritical_semantic_equivalence", "material_unresolved_recall", "unresolved_precision", "quality_policy", "quality_policy_identity", "locked_terminology_recall", "required_media_compliance", "worst_critical_frequency", "repetitions", "configuration_hash", "behavior_configuration_hash", "experiment_plan_hash", "scenario_ids", "formats", "required_group_coverage", "group_critical_frequency", "category_coverage", "vision_input_proven", "corpus_set_identity", "evaluation_purpose"),
        "model_held_out": ("split", "requested_model", "effective_model", "target_model_approved", "quality_metrics_authoritative", "critical_failure_count", "hard_gate_failure_count", "hard_gate_failure_types", "hard_gate_pass", "noncritical_floor_pass", "noncritical_semantic_required_count", "noncritical_semantic_correct_count", "noncritical_semantic_equivalence", "material_unresolved_recall", "unresolved_precision", "quality_policy", "quality_policy_identity", "configuration_hash", "behavior_configuration_hash", "experiment_plan_hash", "scenario_ids", "formats", "corpus_fingerprint", "held_out_fingerprint", "required_media_compliance", "vision_input_proven", "locked_terminology_recall", "unexpected_unresolved_rate", "corpus_set_identity", "evaluation_purpose", "contamination_report_sha256"),
        "internal_bilingual": ("attestation_id", "artifact_count", "work_unit_count", "critical_business_meaning_errors", "critical_numeric_date_unit_errors", "critical_modality_escalations", "critical_table_mapping_errors", "critical_trend_reversals", "unsupported_critical_executive_claims", "overall_noncritical_semantic_fidelity", "unresolved_precision", "material_unresolved_recall", "quality_policy", "quality_policy_identity", "locked_terminology", "review_contract_version", "review_contract", "corpus_set_identity", "evaluation_purpose"),
        "zero_korean_comprehension": (
            "attestation_id", "study_contract_version", "subject_git_sha", "deployment_fingerprint",
            "protocol", "protocol_identity", "analysis_plan", "analysis_plan_identity",
            "truth_authority", "participants", "outcome_records", "derived_results",
        ),
        "security": ("dependency_audit_pass", "secret_scan_pass", "static_scan_pass", "container_scan_pass", "security_release", "unresolved_high_findings", "unresolved_critical_findings", "secret_findings", "audited_dependency_set_sha256", "resolved_dependency_set_sha256", "resolved_dependency_lock_sha256", "production_sbom_sha256", "candidate_constraints_sha256", "pip_audit_version", "semgrep_version", "semgrep_ruleset_identity", "semgrep_ruleset_sha256"),
        "reliability": ("timeout_recovery_pass", "resume_pass", "fifty_slide_pass", "concurrency_pass", "slo_pass", "concurrent_runs"),
        "model_data_policy": ("attestation_id", "approved_for_internal_artifacts"),
        "pilot_canary": ("attestation_id", "users", "artifacts", "critical_confirmed_errors", "cross_user_exposure", "security_incidents", "silent_incomplete_output"),
        "governance": (
            "governance_contract_version", "governance_contract_identity",
            "governance_policy_id", "governance_policy_version", "governance_policy_identity",
            "repository_identity_sha256", "release_subject_sha", "pull_request_number",
            "pull_request_head_sha", "pull_request_base_sha", "pull_request_merge_commit_sha",
            "candidate_deployment_fingerprint", "candidate_spec_identity_sha256",
            "protection_mechanism", "review_pass", "codeowners_pass", "required_check_pass",
            "required_status_checks_strict", "pass_codes",
        ),
    }
    missing = [key for key in requirements.get(evidence_type, ()) if key not in payload]
    if missing:
        raise EvidenceValidationError(f"{evidence_type} evidence is missing payload fields: {', '.join(missing)}")
    from .quality_policy import QUALITY_FLOORS, QUALITY_POLICY_IDENTITY, policy_identity_record, validate_policy_identity

    model_evidence_types = {"model_validation", "model_high_risk_stability", "model_held_out"}
    if evidence_type in model_evidence_types:
        try:
            validate_policy_identity(payload.get("quality_policy"))
        except ValueError as exc:
            raise EvidenceValidationError("model evidence quality-policy identity is missing or stale") from exc
        if payload.get("quality_policy_identity") != QUALITY_POLICY_IDENTITY:
            raise EvidenceValidationError("model evidence quality-policy hash is inconsistent")
        finding_types = payload.get("hard_gate_failure_types")
        if not isinstance(finding_types, list) or any(not isinstance(item, str) or not item for item in finding_types):
            raise EvidenceValidationError("model evidence hard-gate findings are malformed")
        if payload.get("critical_failure_count") != 0 or payload.get("hard_gate_failure_count") != 0 or finding_types or payload.get("hard_gate_pass") is not True:
            raise EvidenceValidationError("model evidence has a non-compensable hard-gate failure")
        if payload.get("noncritical_floor_pass") is not True:
            raise EvidenceValidationError("model evidence fails one or more non-critical quality floors")
        required = payload.get("noncritical_semantic_required_count")
        correct = payload.get("noncritical_semantic_correct_count")
        if not _positive_int(required, 0) or not _positive_int(correct, 0) or correct > required:
            raise EvidenceValidationError("model evidence non-critical semantic assertion counts are malformed")
        derived_equivalence = correct / required if required else 1.0
        metric = payload.get("noncritical_semantic_equivalence")
        if isinstance(metric, bool) or not isinstance(metric, (int, float)) or not math.isfinite(metric) or abs(float(metric) - derived_equivalence) > 1e-12:
            raise EvidenceValidationError("model evidence non-critical semantic rate disagrees with assertion counts")
        for field, floor in (
            ("noncritical_semantic_equivalence", QUALITY_FLOORS["noncritical_semantic_equivalence_min"]),
            ("material_unresolved_recall", QUALITY_FLOORS["material_unresolved_recall_min"]),
            ("unresolved_precision", QUALITY_FLOORS["unresolved_precision_min"]),
            ("locked_terminology_recall", QUALITY_FLOORS["locked_terminology_recall_min"]),
        ):
            value = payload.get(field)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or float(value) < floor:
                raise EvidenceValidationError(f"model evidence fails the {field} quality floor")
    if evidence_type == "internal_bilingual":
        try:
            validate_internal_bilingual_payload(payload)
        except BilingualAdjudicationError as exc:
            raise EvidenceValidationError(f"internal bilingual review contract is invalid ({type(exc).__name__})") from exc
        try:
            validate_policy_identity(payload.get("quality_policy"))
        except ValueError as exc:
            raise EvidenceValidationError("internal bilingual evidence quality-policy identity is missing or stale") from exc
        if payload.get("quality_policy_identity") != QUALITY_POLICY_IDENTITY:
            raise EvidenceValidationError("internal bilingual evidence quality-policy hash is inconsistent")
        for field, floor in (
            ("overall_noncritical_semantic_fidelity", QUALITY_FLOORS["noncritical_semantic_equivalence_min"]),
            ("unresolved_precision", QUALITY_FLOORS["unresolved_precision_min"]),
            ("material_unresolved_recall", QUALITY_FLOORS["material_unresolved_recall_min"]),
            ("locked_terminology", QUALITY_FLOORS["locked_terminology_recall_min"]),
        ):
            value = payload.get(field)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or float(value) < floor:
                raise EvidenceValidationError(f"internal bilingual evidence fails the {field} quality floor")
    model_corpus_contracts = {
        "model_validation": ("private_representative", "private_evaluation"),
        "model_high_risk_stability": ("frozen_high_risk", "comparison"),
        "model_held_out": ("sealed_held_out", "promotion"),
    }
    if evidence_type in model_corpus_contracts:
        role, purpose = model_corpus_contracts[evidence_type]
        try:
            identity = require_set_purpose(payload["corpus_set_identity"], payload["evaluation_purpose"])
        except CorpusGovernanceError as exc:
            raise EvidenceValidationError(f"{evidence_type} corpus governance is ineligible ({type(exc).__name__})") from exc
        if identity["role"] != role or payload["evaluation_purpose"] != purpose:
            raise EvidenceValidationError(f"{evidence_type} evidence used the wrong governed corpus role or purpose")
    if evidence_type == "runtime":
        if not all(_is_true(payload[key]) for key in ("runtime_pass", "required_media_compliance", "run_complete")):
            raise EvidenceValidationError("runtime evidence does not prove the complete OpenCode lifecycle")
    elif evidence_type == "heavy_runtime":
        if not all(_is_true(payload[key]) for key in ("heavy_pass", "networkless_pass", "representative_engine_pass")):
            raise EvidenceValidationError("heavy runtime evidence does not prove required offline capabilities")
    elif evidence_type == "model_validation":
        if payload["split"] != "validation" or not _is_true(payload["target_model_approved"]) or not _is_true(payload["quality_metrics_authoritative"]):
            raise EvidenceValidationError("validation evidence is not authoritative target-model evidence")
        if payload["critical_failure_count"] != 0 or not _positive_int(payload["repetitions"], 3):
            raise EvidenceValidationError("validation evidence fails critical/repetition gates")
        if not _is_true(payload["vision_input_proven"]):
            raise EvidenceValidationError("validation evidence does not prove multimodal execution")
        if float(payload["locked_terminology_recall"]) < QUALITY_FLOORS["locked_terminology_recall_min"]:
            raise EvidenceValidationError("validation evidence fails the locked-terminology floor")
    elif evidence_type == "model_high_risk_stability":
        coverage = payload["required_group_coverage"]
        frequencies = payload["group_critical_frequency"]
        if not isinstance(coverage, dict) or not coverage or not isinstance(frequencies, dict) or set(coverage) != set(frequencies):
            raise EvidenceValidationError("high-risk evidence has incomplete repeated-group coverage")
        if any(not _positive_int(value, 5) for value in coverage.values()) or any(float(value) != 0 for value in frequencies.values()):
            raise EvidenceValidationError("high-risk evidence has an under-repeated or failing group")
        categories = payload["category_coverage"]
        if not isinstance(categories, dict) or any(not _positive_int(value, 1) for value in categories.values()):
            raise EvidenceValidationError("high-risk evidence has incomplete protected-category coverage")
        if not _is_true(payload["target_model_approved"]) or not _is_true(payload["quality_metrics_authoritative"]) or not _is_true(payload["vision_input_proven"]) or not _is_true(payload["required_media_compliance"]) or payload["critical_failure_count"] != 0 or payload["worst_critical_frequency"] != 0 or not _positive_int(payload["repetitions"], 5):
            raise EvidenceValidationError("high-risk stability evidence fails target, critical-frequency, or repetition gates")
    elif evidence_type == "model_held_out":
        if payload["split"] != "held_out" or not _is_true(payload["target_model_approved"]) or not _is_true(payload["quality_metrics_authoritative"]):
            raise EvidenceValidationError("held-out evidence is not authoritative target-model evidence")
        if payload["critical_failure_count"] != 0:
            raise EvidenceValidationError("held-out evidence fails critical gate")
        if payload.get("contamination_report_sha256") is not None:
            digest = payload["contamination_report_sha256"]
            if not isinstance(digest, str) or len(digest) != 64 or set(digest) - _HEX64:
                raise EvidenceValidationError("held-out contamination report identity is malformed")
        if not _is_true(payload["required_media_compliance"]) or not _is_true(payload["vision_input_proven"]) or float(payload["locked_terminology_recall"]) < QUALITY_FLOORS["locked_terminology_recall_min"]:
            raise EvidenceValidationError("held-out evidence fails media, vision, or terminology gates")
    elif evidence_type == "internal_bilingual":
        if not str(payload["attestation_id"]) or payload["attestation_id"] == "UNSET" or not _positive_int(payload["artifact_count"], 50) or not _positive_int(payload["work_unit_count"], 200):
            raise EvidenceValidationError("internal bilingual sample/attestation is insufficient")
        critical = ("critical_business_meaning_errors", "critical_numeric_date_unit_errors", "critical_modality_escalations", "critical_table_mapping_errors", "critical_trend_reversals", "unsupported_critical_executive_claims")
        if any(payload[key] != 0 for key in critical) or float(payload["overall_noncritical_semantic_fidelity"]) < QUALITY_FLOORS["noncritical_semantic_equivalence_min"] or float(payload["unresolved_precision"]) < QUALITY_FLOORS["unresolved_precision_min"] or float(payload["material_unresolved_recall"]) < QUALITY_FLOORS["material_unresolved_recall_min"] or float(payload["locked_terminology"]) < QUALITY_FLOORS["locked_terminology_recall_min"]:
            raise EvidenceValidationError("internal bilingual quality gates failed")
    elif evidence_type == "zero_korean_comprehension":
        try:
            validate_zero_korean_study_payload(payload)
        except ZeroKoreanStudyError as exc:
            raise EvidenceValidationError(f"zero-Korean study contract is invalid ({type(exc).__name__})") from exc
    elif evidence_type == "security":
        security_release = payload.get("security_release")
        if not isinstance(security_release, dict) or security_release.get("contract_version") != "1.0":
            raise EvidenceValidationError("security evidence has no supported KSA-33 release contract")
        if not all(_is_true(payload[key]) for key in ("dependency_audit_pass", "secret_scan_pass", "static_scan_pass", "container_scan_pass")) or any(payload[key] != 0 for key in ("unresolved_high_findings", "unresolved_critical_findings", "secret_findings")):
            raise EvidenceValidationError("security evidence has failed or unresolved findings")
        if security_release.get("unresolved_vulnerability_count") != 0 or security_release.get("repository_security_pass") is not True:
            raise EvidenceValidationError("security evidence has unresolved or unqualified repository findings")
    elif evidence_type == "reliability":
        if not all(_is_true(payload[key]) for key in ("timeout_recovery_pass", "resume_pass", "fifty_slide_pass", "concurrency_pass", "slo_pass")) or not _positive_int(payload["concurrent_runs"], 5):
            raise EvidenceValidationError("reliability evidence fails recovery, load, or SLO gates")
    elif evidence_type == "model_data_policy":
        if not str(payload["attestation_id"]) or payload["attestation_id"] == "UNSET" or not _is_true(payload["approved_for_internal_artifacts"]):
            raise EvidenceValidationError("model-data policy approval is missing")
    elif evidence_type == "pilot_canary":
        if not str(payload["attestation_id"]) or payload["attestation_id"] == "UNSET" or not _positive_int(payload["users"], 5) or not _positive_int(payload["artifacts"], 50):
            raise EvidenceValidationError("pilot sample/attestation is insufficient")
        if any(payload[key] != 0 for key in ("critical_confirmed_errors", "cross_user_exposure", "security_incidents", "silent_incomplete_output")):
            raise EvidenceValidationError("pilot safety gate failed")
    elif evidence_type == "governance":
        from .release_governance import ReleaseGovernanceError, validate_governance_payload

        try:
            validate_governance_payload(payload)
        except ReleaseGovernanceError as exc:
            raise EvidenceValidationError(f"repository governance payload is invalid ({exc})") from exc


def validate_model_evidence_corpus_binding(evidence_type: str, payload: dict[str, Any], candidate_spec: dict[str, Any] | None) -> None:
    contracts = {
        "internal_bilingual": ("private_representative", "private_evaluation"),
        "model_validation": ("private_representative", "private_evaluation"),
        "model_high_risk_stability": ("frozen_high_risk", "comparison"),
        "model_held_out": ("sealed_held_out", "promotion"),
    }
    if evidence_type not in contracts:
        return
    if not isinstance(candidate_spec, dict):
        raise EvidenceValidationError("certification evidence requires its candidate corpus identity")
    role, purpose = contracts[evidence_type]
    candidate_identity = canonical_corpus_identity(candidate_spec.get("corpus_identity"))
    if not is_certification_corpus_ready(candidate_identity):
        raise EvidenceValidationError("certification candidate does not bind four eligible governed corpus roles")
    try:
        expected = set_identity_for_role(candidate_identity, role)
        consumed = require_set_purpose(payload.get("corpus_set_identity"), payload.get("evaluation_purpose"))
    except (CorpusGovernanceError, StopIteration) as exc:
        raise EvidenceValidationError("evidence corpus identity or purpose is invalid") from exc
    if payload.get("evaluation_purpose") != purpose or consumed != expected:
        raise EvidenceValidationError("evidence corpus identity does not match candidate-bound role and purpose")


def validate_internal_bilingual_evidence_binding(
    payload: dict[str, Any],
    *,
    candidate_spec: dict[str, Any] | None,
    subject_git_sha: str,
    deployment_fingerprint: str,
) -> None:
    """Bind every private bilingual review to its enclosing candidate envelope."""

    contract = payload.get("review_contract") if isinstance(payload, dict) else None
    if not isinstance(contract, dict):
        raise EvidenceValidationError("internal bilingual evidence has no review contract")
    if contract.get("subject_git_sha") != subject_git_sha or contract.get("deployment_fingerprint") != deployment_fingerprint:
        raise EvidenceValidationError("internal bilingual reviews do not match the evidence candidate")
    if payload.get("corpus_set_identity") != contract.get("corpus_set_identity") or payload.get("evaluation_purpose") != contract.get("evaluation_purpose"):
        raise EvidenceValidationError("internal bilingual evidence summary does not match its review contract")
    if not isinstance(candidate_spec, dict):
        raise EvidenceValidationError("internal bilingual evidence requires its candidate specification")
    validate_model_evidence_corpus_binding("internal_bilingual", payload, candidate_spec)


def load_evidence(path: Path, *, expected_type: str | None = None, subject_git_sha: str | None = None, deployment_fingerprint: str | None = None, repository_root: Path | None = None, candidate_spec: dict[str, Any] | None = None, require_candidate_spec: bool = False) -> dict[str, Any]:
    """Load and validate one immutable evidence envelope."""

    path = path.expanduser()
    if path.is_symlink() or not path.is_file():
        raise EvidenceValidationError(f"evidence file is missing or symlinked: {path.name}")
    path = path.resolve()
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EvidenceValidationError(f"evidence file is unreadable or malformed: {path.name}") from exc
    if not isinstance(value, dict):
        raise EvidenceValidationError("evidence envelope must be an object")
    if value.get("schema_version") != EVIDENCE_SCHEMA_VERSION:
        raise EvidenceValidationError("unsupported evidence schema version")
    evidence_type = value.get("evidence_type")
    if evidence_type not in EVIDENCE_TYPES:
        raise EvidenceValidationError("unknown evidence type")
    if expected_type and evidence_type != expected_type:
        raise EvidenceValidationError(f"expected {expected_type} evidence, found {evidence_type}")
    if value.get("status") != "PASS":
        raise EvidenceValidationError(f"evidence status is not PASS: {value.get('status')}")
    if subject_git_sha and value.get("subject_git_sha") != subject_git_sha:
        raise EvidenceValidationError("evidence subject_git_sha does not match candidate")
    evidence_fp = value.get("deployment_fingerprint")
    _require_hex(evidence_fp, "deployment_fingerprint")
    embedded_candidate = value.get("candidate_spec")
    if evidence_type == "zero_korean_comprehension" and (not isinstance(embedded_candidate, dict) or not isinstance(candidate_spec, dict)):
        raise EvidenceValidationError("zero-Korean study evidence requires its exact embedded and expected candidate specifications")
    if require_candidate_spec and not isinstance(embedded_candidate, dict):
        raise EvidenceValidationError("evidence is not bound to a candidate specification")
    if embedded_candidate is not None:
        if not isinstance(embedded_candidate, dict) or candidate_deployment_fingerprint(embedded_candidate) != evidence_fp:
            raise EvidenceValidationError("evidence candidate specification is inconsistent")
        if embedded_candidate.get("subject_git_sha") != value.get("subject_git_sha"):
            raise EvidenceValidationError("evidence candidate subject does not match envelope subject")
    if candidate_spec is not None:
        if candidate_deployment_fingerprint(candidate_spec) != evidence_fp:
            raise EvidenceValidationError("evidence deployment_fingerprint does not match candidate specification")
        if embedded_candidate is None and require_candidate_spec:
            raise EvidenceValidationError("evidence is not bound to the expected candidate specification")
        if isinstance(embedded_candidate, dict) and canonical_candidate_factors(embedded_candidate) != canonical_candidate_factors(candidate_spec):
            raise EvidenceValidationError("evidence candidate specification does not match expected candidate")
    if deployment_fingerprint and evidence_fp != deployment_fingerprint:
        raise EvidenceValidationError("evidence deployment_fingerprint does not match candidate")
    if not str(value.get("generated_at") or ""):
        raise EvidenceValidationError("evidence generated_at is missing")
    payload = value.get("payload")
    if evidence_type in MACHINE_EVIDENCE_TYPES:
        from .evidence_adapters import AdapterError, verify_machine_envelope

        try:
            verified = verify_machine_envelope(path, value, subject_git_sha=subject_git_sha, deployment_fingerprint=deployment_fingerprint, root=repository_root, candidate_spec=candidate_spec)
        except AdapterError as exc:
            raise EvidenceValidationError(f"machine evidence adapter rejected the envelope ({type(exc).__name__})") from exc
        if payload != verified["payload"]:
            raise EvidenceValidationError("machine evidence payload is not the adapter-derived payload")
        validate_evidence_payload(str(evidence_type), payload)
        if candidate_spec is not None or embedded_candidate is not None or require_candidate_spec:
            validate_model_evidence_corpus_binding(str(evidence_type), payload, candidate_spec or embedded_candidate)
        identity = evidence_identity(value, sources=verified["sources"])
        return {**value, "path": str(path), "sha256": sha256_file(path), "envelope_sha256": sha256_file(path), "evidence_identity": identity}
    validate_evidence_payload(str(evidence_type), payload)
    if evidence_type == "internal_bilingual":
        validate_internal_bilingual_evidence_binding(
            payload,
            candidate_spec=candidate_spec or embedded_candidate,
            subject_git_sha=str(value.get("subject_git_sha") or ""),
            deployment_fingerprint=evidence_fp,
        )
    elif evidence_type == "zero_korean_comprehension":
        try:
            validate_zero_korean_candidate_binding(
                payload,
                subject_git_sha=str(value.get("subject_git_sha") or ""),
                deployment_fingerprint=evidence_fp,
                candidate_spec=candidate_spec or embedded_candidate,
            )
        except ZeroKoreanStudyError as exc:
            raise EvidenceValidationError(f"zero-Korean candidate binding is invalid ({type(exc).__name__})") from exc
    elif candidate_spec is not None or embedded_candidate is not None or require_candidate_spec:
        validate_model_evidence_corpus_binding(str(evidence_type), payload, candidate_spec or embedded_candidate)
    physical = sha256_file(path)
    return {**value, "path": str(path), "sha256": physical, "envelope_sha256": physical, "evidence_identity": evidence_identity(value)}


def write_evidence(path: Path, *, evidence_type: str, subject_git_sha: str, deployment_fingerprint: str, payload: dict[str, Any], generated_at: str, attestation_id: str | None = None, candidate_spec: dict[str, Any] | None = None) -> Path:
    """Write a source-free envelope after validating its substantive payload."""

    if evidence_type not in EVIDENCE_TYPES:
        raise EvidenceValidationError("unknown evidence type")
    if evidence_type in MACHINE_EVIDENCE_TYPES:
        raise EvidenceValidationError("machine evidence must be derived from source results by evidence_adapters")
    validate_evidence_payload(evidence_type, payload)
    if evidence_type == "internal_bilingual":
        if candidate_spec is None:
            raise EvidenceValidationError("internal bilingual evidence requires its candidate specification")
        if candidate_spec.get("subject_git_sha") != subject_git_sha or candidate_deployment_fingerprint(candidate_spec) != deployment_fingerprint:
            raise EvidenceValidationError("candidate specification does not match bilingual evidence identity")
        validate_internal_bilingual_evidence_binding(
            payload,
            candidate_spec=candidate_spec,
            subject_git_sha=subject_git_sha,
            deployment_fingerprint=deployment_fingerprint,
        )
    elif evidence_type == "zero_korean_comprehension":
        if candidate_spec is None:
            raise EvidenceValidationError("zero-Korean study evidence requires its candidate specification")
        try:
            validate_zero_korean_candidate_binding(
                payload,
                subject_git_sha=subject_git_sha,
                deployment_fingerprint=deployment_fingerprint,
                candidate_spec=candidate_spec,
            )
        except ZeroKoreanStudyError as exc:
            raise EvidenceValidationError(f"zero-Korean candidate binding is invalid ({type(exc).__name__})") from exc
    envelope: dict[str, Any] = {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "evidence_type": evidence_type,
        "status": "PASS",
        "subject_git_sha": subject_git_sha,
        "deployment_fingerprint": _require_hex(deployment_fingerprint, "deployment_fingerprint"),
        "generated_at": generated_at,
        "payload": payload,
    }
    if candidate_spec is not None:
        if candidate_spec.get("subject_git_sha") != subject_git_sha or candidate_deployment_fingerprint(candidate_spec) != deployment_fingerprint:
            raise EvidenceValidationError("candidate specification does not match evidence identity")
        envelope["candidate_spec"] = canonical_candidate_factors(candidate_spec)
    if attestation_id is not None:
        envelope["attestation_id"] = attestation_id
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(envelope, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return path


def _tree_hash(root: Path) -> str | None:
    if not root.is_dir():
        return None
    entries: list[dict[str, str]] = []
    for item in sorted(root.rglob("*")):
        if item.is_symlink():
            # A symlink could hide an unbounded or mutable source from the
            # candidate identity.  Treat the tree as unavailable instead of
            # hashing only the visible regular files.
            return None
        if not item.is_file():
            continue
        path = item
        entries.append({"path": path.relative_to(root).as_posix(), "sha256": sha256_file(path)})
    return sha256_bytes(canonical_bytes(entries))


def _git_sha(root: Path) -> str | None:
    try:
        result = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout.strip() if result.returncode == 0 else None


def _manifest_hash(profile: dict[str, Any], root: Path) -> str | None:
    raw = profile.get("ocr_asset_manifest")
    if not raw or str(raw).startswith("UNSET"):
        return None
    path = Path(str(raw)).expanduser()
    if not path.is_absolute():
        path = root / path
    try:
        return sha256_file(path)
    except EvidenceValidationError:
        return None


def canonical_corpus_identity(corpus: dict[str, Any] | None) -> dict[str, Any]:
    """Canonicalize governed identities and explicitly read the legacy shape."""

    value = corpus or {}
    if not isinstance(value, dict):
        raise EvidenceValidationError("corpus identity must be a mapping")
    governed: dict[str, Any] | None = None
    if "sets" in value:
        governed = value
    elif value.get("schema_version") == "1.0" and "set_id" in value:
        governed = {"schema_version": "1.0", "sets": [value]}
    elif isinstance(value.get("corpus_identity"), dict):
        return canonical_corpus_identity(value["corpus_identity"])
    elif isinstance(value.get("governed_set_identity"), dict) and not any(
        key in value for key in ("version", "corpus_version", "dataset_version", "corpus_fingerprint", "held_out_fingerprint", "heldout_fingerprint")
    ):
        governed = {"schema_version": "1.0", "sets": [value["governed_set_identity"]]}
    if governed is not None:
        try:
            return canonical_governed_corpus_identity(governed)
        except CorpusGovernanceError as exc:
            raise EvidenceValidationError(f"governed corpus identity is invalid ({type(exc).__name__})") from exc
    return {
        "version": value.get("version") or value.get("corpus_version") or value.get("dataset_version"),
        "corpus_fingerprint": value.get("corpus_fingerprint"),
        "held_out_fingerprint": value.get("held_out_fingerprint") or value.get("heldout_fingerprint"),
    }


def canonical_behavior_profile(profile: dict[str, Any] | None) -> dict[str, Any]:
    """Select and normalize material behavior fields from a candidate profile."""

    value = dict(profile or {})
    material = {key: value.get(key) for key in DEPLOYMENT_PROFILE_FIELDS if key in value and key != "behavior_configuration"}
    behavior = dict(value.get("behavior_configuration") or {})
    for key in _BEHAVIOR_FIELDS | set(_BEHAVIOR_ALIASES):
        if key in value:
            canonical = _BEHAVIOR_ALIASES.get(key, key)
            if canonical in behavior and behavior[canonical] != value[key]:
                raise EvidenceValidationError(f"conflicting behavior configuration aliases: {key}")
            behavior[canonical] = value[key]
    if behavior:
        material["behavior_configuration"] = _canonical_behavior_configuration(behavior)
    return material


def build_deployment_factors(root: Path, *, subject_git_sha: str | None = None, runtime: Any | None = None, profile: dict[str, Any] | None = None, model_policy: Any | None = None, corpus: dict[str, Any] | None = None, candidate_spec: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build the canonical candidate identity; ``runtime`` is provenance only.

    ``runtime`` remains in the signature for source compatibility, but it is
    intentionally not fingerprinted.  Callers that certify a deployment must
    pass the same explicit candidate specification to every producer.
    """

    root = root.expanduser().resolve()
    from . import __version__

    if candidate_spec is not None:
        source = dict(candidate_spec)
    else:
        source = dict(profile or {})
        source.setdefault("kslide_version", __version__)
        source.setdefault("subject_git_sha", subject_git_sha or _git_sha(root) or "UNSET")
        if model_policy is not None:
            source.setdefault("model_policy", model_policy.as_dict() if hasattr(model_policy, "as_dict") else model_policy)
        if corpus is not None:
            source.setdefault("corpus_identity", canonical_corpus_identity(corpus))
        source.setdefault("prompt_identity", {"tree_sha256": _tree_hash(_source_path(root, "prompts"))})
        source.setdefault("termbase_identity", effective_termbase_identity(root) or {})
        source.setdefault("schema_versions", repository_schema_versions())
        constraints = _source_path(root, "constraints-production.txt")
        source.setdefault("constraints_sha256", sha256_file(constraints) if constraints.is_file() else None)
        if source.get("ocr_asset_manifest_sha256") is None:
            source["ocr_asset_manifest_sha256"] = _manifest_hash(source, root)
    return canonical_candidate_factors(source)


def deployment_fingerprint(factors: dict[str, Any]) -> str:
    return sha256_bytes(canonical_bytes(factors))


def certification_fingerprint(*, deployment: str, evidence_hashes: dict[str, str], release_state: str, champion_hash: str | None = None, candidate_identity: str | None = None, promotion_identity: str | None = None, recertification_identity: str | None = None, exemption_identities: dict[str, str] | None = None) -> str:
    value = {"deployment_fingerprint": deployment, "evidence_hashes": dict(sorted(evidence_hashes.items())), "release_state": release_state, "champion_hash": champion_hash}
    if candidate_identity is not None or promotion_identity is not None or recertification_identity is not None or exemption_identities:
        value.update({
            "fingerprint_contract_version": "2.0",
            "candidate_identity": candidate_identity or deployment,
            "promotion_identity": promotion_identity,
            "recertification_identity": recertification_identity,
            "exemption_identities": dict(sorted((exemption_identities or {}).items())),
        })
    return sha256_bytes(canonical_bytes(value))


def evidence_hashes(records: Iterable[dict[str, Any]]) -> dict[str, str]:
    return {str(item["evidence_type"]): str(item.get("evidence_identity") or item["sha256"]) for item in records}


def evidence_identity(envelope: dict[str, Any], *, sources: list[dict[str, str]] | None = None) -> str:
    """Stable evidence identity excluding packaging metadata such as timestamps."""

    identity = {
        "schema_version": envelope.get("schema_version"),
        "evidence_type": envelope.get("evidence_type"),
        "adapter_version": envelope.get("adapter_version"),
        "subject_git_sha": envelope.get("subject_git_sha"),
        "deployment_fingerprint": envelope.get("deployment_fingerprint"),
        "sources": sorted(
            [{"role": item.get("role"), "sha256": item.get("sha256")} for item in (sources if sources is not None else envelope.get("sources", []))],
            key=lambda item: item.get("role", ""),
        ),
        "payload": envelope.get("payload"),
    }
    return sha256_bytes(canonical_bytes(identity))
