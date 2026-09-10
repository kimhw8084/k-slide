"""Evidence-bound release certification primitives.

This module is intentionally dependency-free.  It is imported by the runtime
doctor as well as the evaluation/release tooling so a production state cannot
be created by changing a label or by supplying an unbound attestation string.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import ast
from pathlib import Path
from typing import Any, Iterable


EVIDENCE_SCHEMA_VERSION = "2.2"
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
CANDIDATE_SPEC_SCHEMA_VERSION = "1.0"
UNSET_VALUE = "UNSET"
# Runtime discovery already uses ``not_exposed_by_runtime`` for structured
# fields.  These scalar values make the same distinction explicit in a
# frozen candidate specification; they are valid only for provider metadata
# that the deployment actually cannot expose.
NOT_EXPOSED_VALUE = "NOT_EXPOSED"
NOT_APPLICABLE_VALUE = "NOT_APPLICABLE"
PROVIDER_DEFAULTS_FROZEN = "provider_defaults_frozen"
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
    "termbase_version",
    "termbase_hash",
    "model_policy",
    "schema_versions",
    "retention_days",
    "tenant_isolation",
    "network_egress",
    "corpus_identity",
    "constraints_sha256",
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
_BEHAVIOR_ALIASES = {"repair": "repair_policy", "normalization": "normalization_behavior", "vision": "vision_settings"}
_CANDIDATE_ALIASES = {"model": "requested_model", "model_id": "requested_model", **_BEHAVIOR_ALIASES}

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
}
_PRODUCTION_COMPLETENESS_FIELDS = (
    "subject_git_sha", "kslide_version", "opencode_version", "requested_model", "effective_model", "provider",
    "provider_backend", "model_revision", "quantization_or_dtype", "vision_settings", "context_configuration",
    "image_preprocessing_settings", "prompt_identity", "generation_settings", "ocr_provider", "ocr_asset_manifest",
    "ocr_asset_manifest_sha256", "normalization_behavior", "repair_policy", "python_version", "paddle_version",
    "paddleocr_version", "libreoffice_version", "termbase_identity", "termbase_version", "termbase_hash", "model_policy",
    "schema_versions", "retention_days", "tenant_isolation", "network_egress", "corpus_identity", "constraints_sha256",
    "behavior_configuration",
)
_OPTIONAL_PROVIDER_METADATA = frozenset({"provider_backend", "model_revision", "quantization_or_dtype"})

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
    "retention_days",
    "tenant_isolation",
    "network_egress",
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


def _normalize_candidate_mapping(value: dict[str, Any], *, strict: bool = False) -> dict[str, Any]:
    source_value = dict(value.get("candidate_spec") or {}) if isinstance(value.get("candidate_spec"), dict) else {}
    source_value.update(value)
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
    if isinstance(normalized.get("model_policy"), dict):
        from .model_policy import ModelPolicy

        normalized["model_policy"] = ModelPolicy.from_mapping(normalized["model_policy"]).as_dict()
    if isinstance(normalized.get("corpus_identity"), dict):
        normalized["corpus_identity"] = canonical_corpus_identity(normalized["corpus_identity"])
    return normalized


def load_candidate_spec(path: Path, *, root: Path | None = None, require_identity: bool = False, strict: bool | None = None) -> dict[str, Any]:
    """Load one explicit public-safe candidate deployment specification."""

    path = path.expanduser().resolve()
    value = _normalize_candidate_mapping(_load_candidate_mapping(path), strict=require_identity if strict is None else strict)
    value.setdefault("schema_version", CANDIDATE_SPEC_SCHEMA_VERSION)
    declared_version = str(value.get("candidate_spec_version") or value.get("schema_version") or "")
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
    return value is None or (isinstance(value, str) and value.strip().upper() == UNSET_VALUE)


def _resolved_value(value: Any, *, field: str, allow_not_exposed: bool = False, _nested: bool = False) -> bool:
    if _is_unset(value):
        return False
    if isinstance(value, str):
        if value in {NOT_EXPOSED_VALUE, NOT_APPLICABLE_VALUE}:
            return allow_not_exposed and field in _OPTIONAL_PROVIDER_METADATA
        return bool(value.strip())
    if isinstance(value, dict):
        if not value:
            return _nested
        status = str(value.get("status") or "")
        if status in {NOT_EXPOSED_VALUE, NOT_APPLICABLE_VALUE}:
            return allow_not_exposed and field in _OPTIONAL_PROVIDER_METADATA
        if field == "generation_settings" and value.get("source") == PROVIDER_DEFAULTS_FROZEN:
            return value.get("resolved") is not False
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
    current = _nested_hash(result.get(field))
    if current is not None and current.lower() != actual.lower():
        raise EvidenceValidationError(f"candidate {field} disagrees with deterministic repository input")
    if current is None:
        nested = dict(result.get(field) or {})
        nested["hash"] = actual
        result[field] = nested


def resolve_candidate_spec(candidate_spec: dict[str, Any], *, root: Path, subject_git_sha: str | None = None, model_policy: Any | None = None, corpus: dict[str, Any] | None = None, require_sources: bool = False) -> dict[str, Any]:
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
    constraints = root / "constraints-production.txt"
    if constraints.is_file() and not constraints.is_symlink():
        _bind_value(result, "constraints_sha256", sha256_file(constraints))
    elif require_sources and not _is_unset(result.get("constraints_sha256")):
        raise EvidenceValidationError("candidate constraints-production.txt is unavailable for verification")
    prompt_hash = _tree_hash(root / "prompts")
    if require_sources and prompt_hash is None and (not _is_unset(result.get("prompt_hash")) or _nested_hash(result.get("prompt_identity")) is not None):
        raise EvidenceValidationError("candidate prompt tree is unavailable for verification")
    _bind_nested_hash(result, "prompt_identity", prompt_hash)
    if prompt_hash is not None:
        _bind_value(result, "prompt_hash", prompt_hash)
    termbase_hash = _tree_hash(root / "termbase")
    if require_sources and termbase_hash is None and (not _is_unset(result.get("termbase_hash")) or _nested_hash(result.get("termbase_identity")) is not None):
        raise EvidenceValidationError("candidate termbase is unavailable for verification")
    _bind_nested_hash(result, "termbase_identity", termbase_hash)
    if termbase_hash is not None:
        _bind_value(result, "termbase_hash", termbase_hash)
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
    if corpus is not None:
        actual_corpus = canonical_corpus_identity(corpus)
        current_corpus = result.get("corpus_identity")
        if _is_unset(current_corpus) or current_corpus == {} or current_corpus == canonical_corpus_identity(None):
            result["corpus_identity"] = actual_corpus
        elif canonical_corpus_identity(current_corpus) != actual_corpus:
            raise EvidenceValidationError("candidate corpus identity disagrees with frozen corpus")
    raw_manifest = result.get("ocr_asset_manifest")
    if not _is_unset(raw_manifest):
        manifest = _resolve_candidate_path(root, str(raw_manifest))
        if manifest.is_file() and not manifest.is_symlink():
            _bind_value(result, "ocr_asset_manifest_sha256", sha256_file(manifest))
        elif require_sources:
            raise EvidenceValidationError("candidate OCR asset manifest is unavailable for verification")
    behavior = dict(result.get("behavior_configuration") or {})
    for field, actual in (("prompt_hash", prompt_hash), ("termbase_hash", termbase_hash)):
        if actual is not None and field in behavior:
            if _is_unset(behavior[field]):
                behavior[field] = actual
            elif behavior[field] != actual:
                raise EvidenceValidationError(f"candidate behavior {field} disagrees with deterministic repository input")
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


def candidate_completeness(candidate_spec: dict[str, Any], state: str) -> list[str]:
    """Return unresolved candidate inputs for a requested release state."""

    if state in {"DEVELOPMENT", "CERTIFICATION_STALE"}:
        return []
    fields = _CANDIDATE_COMPLETENESS_FIELDS.get(state, _PRODUCTION_COMPLETENESS_FIELDS)
    missing: list[str] = []
    for field in fields:
        allow_not_exposed = field in _OPTIONAL_PROVIDER_METADATA
        if field == "subject_git_sha":
            raw_subject = str(candidate_spec.get(field) or "")
            valid = len(raw_subject) == 40 and not (set(raw_subject.lower()) - set("0123456789abcdef"))
        elif field == "prompt_identity":
            identity = candidate_spec.get(field)
            identity_version = identity.get("version") if isinstance(identity, dict) else None
            valid = _hash_field_resolved(candidate_spec, field, nested_field="hash") and (
                _resolved_value(identity_version, field=field) or _resolved_value(candidate_spec.get("prompt_version"), field=field)
            )
        elif field == "ocr_asset_manifest_sha256" or field == "constraints_sha256" or field == "termbase_hash":
            valid = _hash_field_resolved(candidate_spec, field)
        elif field == "termbase_identity":
            valid = _hash_field_resolved(candidate_spec, field, nested_field="hash")
        else:
            valid = _resolved_value(candidate_spec.get(field), field=field, allow_not_exposed=allow_not_exposed)
        if not valid:
            missing.append(field)
    if state in {"GEMMA_EVAL_READY", "SYNTHETIC_PRODUCTION_CANDIDATE"} and candidate_spec.get("ocr_provider") == "paddle":
        for field in ("ocr_asset_manifest", "ocr_asset_manifest_sha256"):
            if field not in missing and not _resolved_value(candidate_spec.get(field), field=field):
                missing.append(field)
    if state == "PRODUCTION_CERTIFIED" and candidate_spec.get("ocr_provider") != "paddle":
        missing.append("ocr_provider")
    if state == "PRODUCTION_CERTIFIED":
        retention = candidate_spec.get("retention_days")
        if isinstance(retention, bool) or not isinstance(retention, int) or retention <= 0:
            missing.append("retention_days")
        if candidate_spec.get("tenant_isolation") != "workspace_per_session":
            missing.append("tenant_isolation")
        if candidate_spec.get("network_egress") != "approved_inference_only":
            missing.append("network_egress")
    return sorted(set(missing))


def _resolve_candidate_path(root: Path, raw: str) -> Path:
    path = Path(raw).expanduser()
    return path if path.is_absolute() else root.expanduser().resolve() / path


def canonical_candidate_factors(candidate_spec: dict[str, Any]) -> dict[str, Any]:
    """Return the explicit, path/timestamp-free candidate identity factors."""

    normalized = _normalize_candidate_mapping(dict(candidate_spec), strict=True)
    factors = {key: normalized.get(key) for key in CANDIDATE_INPUT_FIELDS if key in normalized and key not in {"ocr_asset_manifest", "ocr_asset_manifest_sha256"}}
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
        "heavy_runtime": ("heavy_pass", "networkless_pass", "representative_engine_pass", "full_engine_pass", "unexpected_capability_blocks"),
        "model_validation": ("split", "requested_model", "effective_model", "target_model_approved", "quality_metrics_authoritative", "critical_failure_count", "repetitions", "configuration_hash", "behavior_configuration_hash", "experiment_plan_hash", "scenario_ids", "formats", "required_media_compliance", "vision_input_proven", "locked_terminology_recall", "unexpected_unresolved_rate"),
        "model_high_risk_stability": ("requested_model", "effective_model", "target_model_approved", "critical_failure_count", "worst_critical_frequency", "repetitions", "configuration_hash", "behavior_configuration_hash", "experiment_plan_hash", "scenario_ids", "formats", "required_group_coverage", "group_critical_frequency", "category_coverage", "vision_input_proven"),
        "model_held_out": ("split", "requested_model", "effective_model", "target_model_approved", "quality_metrics_authoritative", "critical_failure_count", "configuration_hash", "behavior_configuration_hash", "experiment_plan_hash", "scenario_ids", "formats", "corpus_fingerprint", "held_out_fingerprint", "required_media_compliance", "vision_input_proven", "locked_terminology_recall", "unexpected_unresolved_rate"),
        "internal_bilingual": ("attestation_id", "artifact_count", "work_unit_count", "critical_business_meaning_errors", "critical_numeric_date_unit_errors", "critical_modality_escalations", "critical_table_mapping_errors", "critical_trend_reversals", "unsupported_critical_executive_claims", "overall_noncritical_semantic_fidelity", "locked_terminology"),
        "zero_korean_comprehension": ("attestation_id", "users", "answers", "critical_question_accuracy", "overall_comprehension", "critical_misunderstanding"),
        "security": ("dependency_audit_pass", "secret_scan_pass", "static_scan_pass", "unresolved_high_findings", "unresolved_critical_findings", "secret_findings", "audited_dependency_set_sha256", "candidate_constraints_sha256", "pip_audit_version", "semgrep_version", "semgrep_ruleset_identity", "semgrep_ruleset_sha256"),
        "reliability": ("timeout_recovery_pass", "resume_pass", "fifty_slide_pass", "concurrency_pass", "slo_pass", "concurrent_runs"),
        "model_data_policy": ("attestation_id", "approved_for_internal_artifacts"),
        "pilot_canary": ("attestation_id", "users", "artifacts", "critical_confirmed_errors", "cross_user_exposure", "security_incidents", "silent_incomplete_output"),
        "governance": ("codeowners_pass", "branch_protection_pass", "required_ci_pass", "review_required"),
    }
    missing = [key for key in requirements.get(evidence_type, ()) if key not in payload]
    if missing:
        raise EvidenceValidationError(f"{evidence_type} evidence is missing payload fields: {', '.join(missing)}")
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
        if float(payload["locked_terminology_recall"]) + 1e-12 < 0.995 or float(payload["unexpected_unresolved_rate"]) != 0:
            raise EvidenceValidationError("validation evidence fails terminology or unexpected-unresolved gates")
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
        if not _is_true(payload["target_model_approved"]) or not _is_true(payload["vision_input_proven"]) or payload["critical_failure_count"] != 0 or payload["worst_critical_frequency"] != 0 or not _positive_int(payload["repetitions"], 5):
            raise EvidenceValidationError("high-risk stability evidence fails target, critical-frequency, or repetition gates")
    elif evidence_type == "model_held_out":
        if payload["split"] != "held_out" or not _is_true(payload["target_model_approved"]) or not _is_true(payload["quality_metrics_authoritative"]):
            raise EvidenceValidationError("held-out evidence is not authoritative target-model evidence")
        if payload["critical_failure_count"] != 0:
            raise EvidenceValidationError("held-out evidence fails critical gate")
        if not _is_true(payload["required_media_compliance"]) or not _is_true(payload["vision_input_proven"]) or float(payload["locked_terminology_recall"]) + 1e-12 < 0.995 or float(payload["unexpected_unresolved_rate"]) != 0:
            raise EvidenceValidationError("held-out evidence fails media, vision, terminology, or unexpected-unresolved gates")
    elif evidence_type == "internal_bilingual":
        if not str(payload["attestation_id"]) or payload["attestation_id"] == "UNSET" or not _positive_int(payload["artifact_count"], 50) or not _positive_int(payload["work_unit_count"], 200):
            raise EvidenceValidationError("internal bilingual sample/attestation is insufficient")
        critical = ("critical_business_meaning_errors", "critical_numeric_date_unit_errors", "critical_modality_escalations", "critical_table_mapping_errors", "critical_trend_reversals", "unsupported_critical_executive_claims")
        if any(payload[key] != 0 for key in critical) or float(payload["overall_noncritical_semantic_fidelity"]) < 0.98 or float(payload["locked_terminology"]) < 0.995:
            raise EvidenceValidationError("internal bilingual quality gates failed")
    elif evidence_type == "zero_korean_comprehension":
        if not str(payload["attestation_id"]) or payload["attestation_id"] == "UNSET" or not _positive_int(payload["users"], 10) or not _positive_int(payload["answers"], 100):
            raise EvidenceValidationError("zero-Korean study sample/attestation is insufficient")
        if float(payload["critical_question_accuracy"]) != 1.0 or float(payload["overall_comprehension"]) < 0.95 or payload["critical_misunderstanding"] != 0:
            raise EvidenceValidationError("zero-Korean comprehension gates failed")
    elif evidence_type == "security":
        if not all(_is_true(payload[key]) for key in ("dependency_audit_pass", "secret_scan_pass", "static_scan_pass")) or any(payload[key] != 0 for key in ("unresolved_high_findings", "unresolved_critical_findings", "secret_findings")):
            raise EvidenceValidationError("security evidence has failed or unresolved findings")
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
    elif evidence_type == "governance" and not all(_is_true(payload[key]) for key in ("codeowners_pass", "branch_protection_pass", "required_ci_pass", "review_required")):
        raise EvidenceValidationError("repository governance evidence is incomplete")


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
            raise EvidenceValidationError(str(exc)) from exc
        if payload != verified["payload"]:
            raise EvidenceValidationError("machine evidence payload is not the adapter-derived payload")
        validate_evidence_payload(str(evidence_type), payload)
        identity = evidence_identity(value, sources=verified["sources"])
        return {**value, "path": str(path), "sha256": sha256_file(path), "envelope_sha256": sha256_file(path), "evidence_identity": identity}
    validate_evidence_payload(str(evidence_type), payload)
    physical = sha256_file(path)
    return {**value, "path": str(path), "sha256": physical, "envelope_sha256": physical, "evidence_identity": evidence_identity(value)}


def write_evidence(path: Path, *, evidence_type: str, subject_git_sha: str, deployment_fingerprint: str, payload: dict[str, Any], generated_at: str, attestation_id: str | None = None, candidate_spec: dict[str, Any] | None = None) -> Path:
    """Write a source-free envelope after validating its substantive payload."""

    if evidence_type not in EVIDENCE_TYPES:
        raise EvidenceValidationError("unknown evidence type")
    if evidence_type in MACHINE_EVIDENCE_TYPES:
        raise EvidenceValidationError("machine evidence must be derived from source results by evidence_adapters")
    validate_evidence_payload(evidence_type, payload)
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
    """Return the one compact corpus identity used by every caller."""

    value = corpus or {}
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
        source.setdefault("prompt_identity", {"tree_sha256": _tree_hash(root / "prompts")})
        source.setdefault("termbase_identity", {"tree_sha256": _tree_hash(root / "termbase")})
        source.setdefault("schema_versions", {"evidence_ir": "1.0", "translation_patch": "1.0", "slide_ir": "1.0"})
        constraints = root / "constraints-production.txt"
        source.setdefault("constraints_sha256", sha256_file(constraints) if constraints.is_file() else None)
        if source.get("ocr_asset_manifest_sha256") is None:
            source["ocr_asset_manifest_sha256"] = _manifest_hash(source, root)
    return canonical_candidate_factors(source)


def deployment_fingerprint(factors: dict[str, Any]) -> str:
    return sha256_bytes(canonical_bytes(factors))


def certification_fingerprint(*, deployment: str, evidence_hashes: dict[str, str], release_state: str, champion_hash: str | None = None) -> str:
    return sha256_bytes(canonical_bytes({"deployment_fingerprint": deployment, "evidence_hashes": dict(sorted(evidence_hashes.items())), "release_state": release_state, "champion_hash": champion_hash}))


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
