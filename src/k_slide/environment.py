"""Canonical, source-free identity for one K-Slide execution environment."""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from typing import Any, Mapping

from . import (
    EVIDENCE_IR_SCHEMA_VERSION,
    EXECUTION_CONTRACT_VERSION,
    RUN_ENVIRONMENT_IDENTITY_VERSION,
    RUN_STORE_SCHEMA_VERSION,
    SLIDE_IR_SCHEMA_VERSION,
)
from .errors import ErrorCode, KSlideError
from .evidence_ir import stable_revision
from .translation_contract import TRANSLATION_PATCH_SCHEMA_VERSION
from .classification_policy import (
    InferenceDataUsePolicy,
    REFERENCE_POLICY_VERSION,
    REFERENCE_ROUTE_IDENTITY,
)

_REFERENCE_POLICY = InferenceDataUsePolicy.reference()


_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_IMAGE = re.compile(r"^sha256:[0-9a-f]{64}$")
_VERSION = re.compile(r"^[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[-+][A-Za-z0-9.-]+)?$")
_IDENTITY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}$")
_FORBIDDEN = ("access", "secret", "token", "password", "credential", "source_text", "prompt", "translation", "content")


def _invalid(message: str, *, code: ErrorCode = ErrorCode.EXECUTION_INVALID) -> KSlideError:
    return KSlideError(code, message)


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or not _IDENTITY.fullmatch(value) or any(word in value.lower() for word in _FORBIDDEN):
        raise _invalid(f"Run environment {label} is invalid.")
    return value


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _HEX64.fullmatch(value):
        raise _invalid(f"Run environment {label} must be a SHA-256 identity.")
    return value


def _version(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _VERSION.fullmatch(value):
        raise _invalid(f"Run environment {label} must be an exact version.")
    return value


def _hash(value: Any) -> str:
    return stable_revision({"environment_component": value})


@dataclass(frozen=True)
class RunEnvironmentIdentity:
    """The immutable environment contract bound to a run at creation.

    Every member is a source-free identity or an exact version.  Runtime
    labels are deliberately not represented as proof of compatibility; the
    runtime artifact, image, build, candidate, and configuration identities
    are the authoritative subjects.
    """

    kslide_source_revision: str
    candidate_identity: str
    candidate_version: str
    kslide_version: str
    runtime_artifact_identity: str
    runtime_image_identity: str
    runtime_build_identity: str
    runtime_manifest_sha256: str
    runtime_sbom_sha256: str
    target_model_identity: str
    effective_model_identity: str
    model_config_identity: str
    semantic_config_identity: str
    ocr_asset_identity: str
    ocr_config_identity: str
    ocr_provider: str
    termbase_identity: str
    termbase_version: str
    inference_route_identity: str = REFERENCE_ROUTE_IDENTITY
    inference_data_policy_version: str = REFERENCE_POLICY_VERSION
    inference_data_policy_hash: str = _REFERENCE_POLICY.policy_hash
    inference_data_policy_identity: str = _REFERENCE_POLICY.policy_identity
    execution_contract_version: str = EXECUTION_CONTRACT_VERSION
    run_store_schema_version: str = RUN_STORE_SCHEMA_VERSION
    evidence_ir_schema_version: str = EVIDENCE_IR_SCHEMA_VERSION
    translation_patch_schema_version: str = TRANSLATION_PATCH_SCHEMA_VERSION
    slide_ir_schema_version: str = SLIDE_IR_SCHEMA_VERSION
    identity_version: str = RUN_ENVIRONMENT_IDENTITY_VERSION

    def __post_init__(self) -> None:
        if self.identity_version != RUN_ENVIRONMENT_IDENTITY_VERSION:
            raise _invalid("Unsupported run environment identity version.", code=ErrorCode.EXECUTION_UNSUPPORTED_VERSION)
        if not isinstance(self.kslide_source_revision, str) or not _SHA40.fullmatch(self.kslide_source_revision):
            raise _invalid("Run environment K-Slide source revision is invalid.")
        for value, label in (
            (self.candidate_identity, "candidate identity"),
            (self.runtime_artifact_identity, "runtime artifact identity"),
            (self.runtime_build_identity, "runtime build identity"),
            (self.runtime_manifest_sha256, "runtime manifest identity"),
            (self.runtime_sbom_sha256, "runtime SBOM identity"),
            (self.model_config_identity, "model configuration identity"),
            (self.semantic_config_identity, "semantic configuration identity"),
            (self.ocr_asset_identity, "OCR asset identity"),
            (self.ocr_config_identity, "OCR configuration identity"),
            (self.termbase_identity, "termbase identity"),
        ):
            _sha(value, label)
        if not isinstance(self.runtime_image_identity, str) or not _IMAGE.fullmatch(self.runtime_image_identity):
            raise _invalid("Run environment runtime image identity is invalid.")
        for value, label in (
            (self.candidate_version, "candidate version"),
            (self.kslide_version, "K-Slide version"),
            (self.termbase_version, "termbase version"),
        ):
            _version(value, label)
        for value, label in (
            (self.target_model_identity, "target model identity"),
            (self.effective_model_identity, "effective model identity"),
            (self.ocr_provider, "OCR provider identity"),
            (self.inference_route_identity, "inference route identity"),
            (self.inference_data_policy_version, "inference data-use policy version"),
        ):
            _text(value, label)
        for value, label in (
            (self.inference_data_policy_hash, "inference data-use policy hash"),
            (self.inference_data_policy_identity, "inference data-use policy identity"),
        ):
            _sha(value, label)
        for value, label in (
            (self.execution_contract_version, "execution contract version"),
            (self.run_store_schema_version, "run-store schema version"),
            (self.evidence_ir_schema_version, "EvidenceIR schema version"),
            (self.translation_patch_schema_version, "TranslationPatch schema version"),
            (self.slide_ir_schema_version, "SlideIR schema version"),
        ):
            _version(value, label)

    def as_dict(self) -> dict[str, str]:
        return {
            "identity_version": self.identity_version,
            # Keep the persisted operational record source-free by using the
            # neutral subject name; this is the exact K-Slide source revision
            # identity, never source content.
            "kslide_revision": self.kslide_source_revision,
            "candidate_identity": self.candidate_identity,
            "candidate_version": self.candidate_version,
            "kslide_version": self.kslide_version,
            "runtime_artifact_identity": self.runtime_artifact_identity,
            "runtime_image_identity": self.runtime_image_identity,
            "runtime_build_identity": self.runtime_build_identity,
            "runtime_manifest_sha256": self.runtime_manifest_sha256,
            "runtime_sbom_sha256": self.runtime_sbom_sha256,
            "target_model_identity": self.target_model_identity,
            "effective_model_identity": self.effective_model_identity,
            "model_config_identity": self.model_config_identity,
            "semantic_config_identity": self.semantic_config_identity,
            "ocr_asset_identity": self.ocr_asset_identity,
            "ocr_config_identity": self.ocr_config_identity,
            "ocr_provider": self.ocr_provider,
            "termbase_identity": self.termbase_identity,
            "termbase_version": self.termbase_version,
            "inference_route_identity": self.inference_route_identity,
            "inference_data_policy_version": self.inference_data_policy_version,
            "inference_data_policy_hash": self.inference_data_policy_hash,
            "inference_data_policy_identity": self.inference_data_policy_identity,
            "execution_contract_version": self.execution_contract_version,
            "run_store_schema_version": self.run_store_schema_version,
            "evidence_ir_schema_version": self.evidence_ir_schema_version,
            "translation_patch_schema_version": self.translation_patch_schema_version,
            "slide_ir_schema_version": self.slide_ir_schema_version,
        }

    @property
    def identity_sha256(self) -> str:
        return stable_revision(self.as_dict())

    # Compatibility spellings for deployment adapters that use the existing
    # runtime/candidate vocabulary. They do not create alternate identities.
    @property
    def source_revision(self) -> str:
        return self.kslide_source_revision

    @property
    def model_identity(self) -> str:
        return self.effective_model_identity

    @property
    def ocr_asset_manifest_sha256(self) -> str:
        return self.ocr_asset_identity

    @property
    def ocr_config_sha256(self) -> str:
        return self.ocr_config_identity

    @property
    def runtime_image_digest(self) -> str:
        return self.runtime_image_identity

    @classmethod
    def from_dict(cls, value: Any) -> "RunEnvironmentIdentity":
        fields = {
            "identity_version", "kslide_revision", "candidate_identity", "candidate_version", "kslide_version",
            "runtime_artifact_identity", "runtime_image_identity", "runtime_build_identity", "runtime_manifest_sha256",
            "runtime_sbom_sha256", "target_model_identity", "effective_model_identity", "model_config_identity",
            "semantic_config_identity", "ocr_asset_identity", "ocr_config_identity", "ocr_provider", "termbase_identity",
            "termbase_version", "inference_route_identity", "inference_data_policy_version", "inference_data_policy_hash",
            "inference_data_policy_identity", "execution_contract_version", "run_store_schema_version", "evidence_ir_schema_version",
            "translation_patch_schema_version", "slide_ir_schema_version",
        }
        if not isinstance(value, Mapping) or set(value) not in (fields, fields - {"inference_route_identity", "inference_data_policy_version", "inference_data_policy_hash", "inference_data_policy_identity"}):
            raise _invalid("Run environment identity is incomplete.", code=ErrorCode.STATE_CORRUPT)
        try:
            raw = dict(value)
            raw["kslide_source_revision"] = raw.pop("kslide_revision")
            if "inference_route_identity" not in raw:
                reference = InferenceDataUsePolicy.reference()
                raw.update(
                    {
                        "inference_route_identity": reference.inference_route_identity,
                        "inference_data_policy_version": reference.policy_version,
                        "inference_data_policy_hash": reference.policy_hash,
                        "inference_data_policy_identity": reference.policy_identity,
                    }
                )
            return cls(**raw)
        except (TypeError, ValueError) as exc:
            if isinstance(exc, KSlideError):
                raise
            raise _invalid("Run environment identity is invalid.", code=ErrorCode.STATE_CORRUPT) from exc

    @classmethod
    def legacy_reference(cls, *, runtime_ref: str, model_identity: str, ocr_identity: str, termbase_identity: str, engine_contract_version: str = EXECUTION_CONTRACT_VERSION, source_revision: str | None = None) -> "RunEnvironmentIdentity":
        """Build a deterministic reference identity for pre-KSA-10 adapters.

        The reference adapter remains usable by the KSA-06/08 regression
        suite. Production callers should provide the explicit KSA-07-backed
        identity instead of treating an opaque deployment label as proof.
        """

        base = {
            "runtime_ref": runtime_ref,
            "model_identity": model_identity,
            "ocr_identity": ocr_identity,
            "termbase_identity": termbase_identity,
            "engine_contract_version": engine_contract_version,
        }
        seed = _hash(base)
        return cls(
            kslide_source_revision=source_revision if isinstance(source_revision, str) and _SHA40.fullmatch(source_revision) else seed[:40],
            candidate_identity=_hash({"candidate": base}),
            candidate_version="1.0",
            kslide_version="0.0.0",
            runtime_artifact_identity=_hash({"artifact": base}),
            runtime_image_identity=f"sha256:{_hash({'image': base})}",
            runtime_build_identity=_hash({"build": base}),
            runtime_manifest_sha256=_hash({"manifest": base}),
            runtime_sbom_sha256=_hash({"sbom": base}),
            target_model_identity=model_identity,
            effective_model_identity=model_identity,
            model_config_identity=_hash({"model": model_identity}),
            semantic_config_identity=_hash({"contract": engine_contract_version}),
            ocr_asset_identity=_hash({"ocr-assets": ocr_identity}),
            ocr_config_identity=_hash({"ocr-config": ocr_identity}),
            ocr_provider="reference",
            termbase_identity=_hash({"termbase": termbase_identity}),
            termbase_version="1.0",
            inference_route_identity=InferenceDataUsePolicy.reference().inference_route_identity,
            inference_data_policy_version=InferenceDataUsePolicy.reference().policy_version,
            inference_data_policy_hash=InferenceDataUsePolicy.reference().policy_hash,
            inference_data_policy_identity=InferenceDataUsePolicy.reference().policy_identity,
            execution_contract_version=engine_contract_version,
        )

    @classmethod
    def from_candidate_spec(cls, candidate_spec: Mapping[str, Any], *, runtime_manifest: Mapping[str, Any] | None = None) -> "RunEnvironmentIdentity":
        """Project existing candidate/runtime manifest subjects into this contract."""

        candidate = dict(candidate_spec)
        try:
            from .certification import candidate_deployment_fingerprint

            fingerprint_candidate = dict(candidate)
            declared_candidate_identity = fingerprint_candidate.pop("deployment_fingerprint", None)
            candidate_identity = candidate_deployment_fingerprint(fingerprint_candidate)
            if declared_candidate_identity not in (None, "", "UNSET") and declared_candidate_identity != candidate_identity:
                raise _invalid("Run environment candidate identity cannot be rederived.")
        except Exception as exc:
            raise _invalid("Run environment candidate identity is unavailable.") from exc
        runtime = dict(runtime_manifest or {})
        raw_policy = candidate.get("inference_data_use_policy")
        if raw_policy is None:
            raw_policy = candidate.get("inference_data_policy")
        route = candidate.get("inference_route_identity")
        if not isinstance(route, str) or not route or not isinstance(raw_policy, Mapping):
            raise _invalid("Run environment inference route/data-use policy identity is incomplete.")
        policy = InferenceDataUsePolicy.from_mapping(raw_policy)
        if policy.inference_route_identity != route:
            raise _invalid("Run environment inference route/data-use policy identity is inconsistent.")
        candidate_source = candidate.get("subject_git_sha")
        runtime_source = runtime.get("source_revision")
        if runtime_source not in (None, "") and runtime_source != candidate_source:
            raise _invalid("Run environment runtime source identity cannot be rederived.")
        candidate_kslide_version = candidate.get("kslide_version")
        runtime_kslide_version = runtime.get("kslide_version")
        if runtime_kslide_version not in (None, "") and runtime_kslide_version != candidate_kslide_version:
            raise _invalid("Run environment runtime K-Slide version cannot be rederived.")
        artifact = candidate.get("runtime_artifact_identity")
        if isinstance(artifact, Mapping):
            artifact = artifact.get("sha256")
        runtime_artifact = runtime.get("artifact_identity")
        if isinstance(runtime_artifact, Mapping):
            runtime_artifact = runtime_artifact.get("sha256")
        if runtime_artifact not in (None, "") and artifact not in (None, "") and runtime_artifact != artifact:
            raise _invalid("Run environment runtime artifact identity cannot be rederived.")
        artifact = artifact or runtime_artifact
        runtime_build = runtime.get("build_inputs_sha256")
        candidate_build = candidate.get("runtime_build_identity")
        if runtime_build not in (None, "") and candidate_build not in (None, "") and runtime_build != candidate_build:
            raise _invalid("Run environment runtime build identity cannot be rederived.")
        runtime_image = (runtime.get("image_identity") or {}).get("value") if isinstance(runtime.get("image_identity"), Mapping) else None
        candidate_image = candidate.get("runtime_image_identity")
        if runtime_image not in (None, "") and candidate_image not in (None, "") and runtime_image != candidate_image:
            raise _invalid("Run environment runtime image identity cannot be rederived.")
        ocr = runtime.get("ocr_asset_manifest") if isinstance(runtime.get("ocr_asset_manifest"), Mapping) else {}
        runtime_ocr_config = ocr.get("paddlex_config_sha256")
        candidate_ocr_config = candidate.get("ocr_config_identity")
        if runtime_ocr_config not in (None, "") and candidate_ocr_config not in (None, "") and runtime_ocr_config != candidate_ocr_config:
            raise _invalid("Run environment OCR configuration identity cannot be rederived.")
        schema = candidate.get("schema_versions")
        if not isinstance(schema, Mapping):
            schema = {}
        model = candidate.get("effective_model")
        model_config = candidate.get("model_config_identity") or _hash({key: candidate.get(key) for key in ("requested_model", "effective_model", "provider", "provider_backend", "model_revision", "quantization_or_dtype")})
        semantic_config = candidate.get("semantic_config_identity") or _hash({key: candidate.get(key) for key in ("prompt_identity", "generation_settings", "vision_settings", "context_configuration", "image_preprocessing_settings", "normalization_behavior", "repair_policy", "behavior_configuration")})
        termbase = candidate.get("termbase_identity")
        if isinstance(termbase, Mapping):
            termbase = termbase.get("hash") or termbase.get("sha256")
        values = {
            "kslide_source_revision": candidate.get("subject_git_sha"),
            "candidate_identity": candidate_identity,
            "candidate_version": candidate.get("candidate_spec_version") or candidate.get("schema_version"),
            "kslide_version": candidate.get("kslide_version"),
            "runtime_artifact_identity": artifact,
            "runtime_image_identity": runtime_image or candidate_image,
            "runtime_build_identity": runtime_build or candidate_build or artifact,
            "runtime_manifest_sha256": candidate.get("runtime_artifact_manifest_sha256") or runtime.get("runtime_manifest_sha256") or runtime.get("manifest_sha256"),
            "runtime_sbom_sha256": candidate.get("runtime_sbom_sha256") or (runtime.get("sbom") or {}).get("sha256"),
            "target_model_identity": candidate.get("requested_model") or candidate.get("effective_model"),
            "effective_model_identity": model,
            "model_config_identity": model_config,
            "semantic_config_identity": semantic_config,
            "ocr_asset_identity": candidate.get("ocr_asset_manifest_sha256") or ocr.get("sha256"),
            "ocr_config_identity": candidate.get("ocr_config_identity") or ocr.get("paddlex_config_sha256"),
            "ocr_provider": candidate.get("ocr_provider"),
            "termbase_identity": candidate.get("termbase_hash") or termbase,
            "termbase_version": candidate.get("termbase_version") or (termbase or {}).get("version") if isinstance(termbase, Mapping) else candidate.get("termbase_version"),
            "inference_route_identity": route,
            "inference_data_policy_version": policy.policy_version,
            "inference_data_policy_hash": policy.policy_hash,
            "inference_data_policy_identity": policy.policy_identity,
            "execution_contract_version": candidate.get("execution_contract_version", EXECUTION_CONTRACT_VERSION),
            "run_store_schema_version": candidate.get("run_store_schema_version", RUN_STORE_SCHEMA_VERSION),
            "evidence_ir_schema_version": schema.get("evidence_ir"),
            "translation_patch_schema_version": schema.get("translation_patch"),
            "slide_ir_schema_version": schema.get("slide_ir"),
        }
        runtime_sbom = (runtime.get("sbom") or {}).get("sha256") if isinstance(runtime.get("sbom"), Mapping) else None
        if runtime_sbom not in (None, "") and values["runtime_sbom_sha256"] != runtime_sbom:
            raise _invalid("Run environment runtime SBOM identity cannot be rederived.")
        if ocr.get("sha256") not in (None, "") and values["ocr_asset_identity"] != ocr.get("sha256"):
            raise _invalid("Run environment OCR asset identity cannot be rederived.")
        if any(value in (None, "", "UNSET", {}) for value in values.values()):
            raise _invalid("Run environment candidate/runtime identity is incomplete.")
        try:
            return cls(**values)
        except KSlideError:
            raise
        except (TypeError, ValueError) as exc:
            raise _invalid("Run environment candidate/runtime identity is invalid.") from exc


EnvironmentIdentity = RunEnvironmentIdentity
ExecutionEnvironmentIdentity = RunEnvironmentIdentity


def environment_mismatch_fields(expected: RunEnvironmentIdentity | None, actual: RunEnvironmentIdentity | None) -> tuple[str, ...]:
    if expected is None and actual is None:
        return ()
    if expected is None:
        return ("run_environment_identity",)
    if actual is None:
        return ("current_environment_identity",)
    expected_values = expected.as_dict()
    actual_values = actual.as_dict()
    return tuple(key for key in expected_values if expected_values.get(key) != actual_values.get(key))


def raise_environment_mismatch(expected: RunEnvironmentIdentity | None, actual: RunEnvironmentIdentity | None) -> None:
    fields = environment_mismatch_fields(expected, actual)
    if fields:
        raise KSlideError(
            ErrorCode.EXECUTION_ENVIRONMENT_MISMATCH,
            "Run environment is incompatible; resume was refused.",
            {"mismatch_code": "KSLIDE_RUN_ENVIRONMENT_MISMATCH", "mismatch_fields": list(fields)},
        )


def ensure_configured_policy_matches_environment(root: "Path", environment: RunEnvironmentIdentity) -> None:
    """Re-check deployment policy drift before a resumable workspace mutation."""

    from .classification_policy import REFERENCE_ROUTE_IDENTITY, load_inference_data_use_policy

    if environment.inference_route_identity == REFERENCE_ROUTE_IDENTITY:
        return
    try:
        configured = load_inference_data_use_policy(root, route_identity=environment.inference_route_identity)
    except KSlideError as exc:
        raise KSlideError(
            ErrorCode.EXECUTION_ENVIRONMENT_MISMATCH,
            "Run environment is incompatible; resume was refused.",
            {"mismatch_code": "KSLIDE_RUN_ENVIRONMENT_MISMATCH", "mismatch_fields": ["inference_data_policy"]},
        ) from exc
    fields = []
    if configured.policy_version != environment.inference_data_policy_version:
        fields.append("inference_data_policy_version")
    if configured.policy_hash != environment.inference_data_policy_hash:
        fields.append("inference_data_policy_hash")
    if configured.policy_identity != environment.inference_data_policy_identity:
        fields.append("inference_data_policy_identity")
    if fields:
        raise KSlideError(
            ErrorCode.EXECUTION_ENVIRONMENT_MISMATCH,
            "Run environment is incompatible; resume was refused.",
            {"mismatch_code": "KSLIDE_RUN_ENVIRONMENT_MISMATCH", "mismatch_fields": fields},
        )


def _repository_revision(root: "Path") -> str | None:
    try:
        revision = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=5,
            check=True,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None
    return revision if _SHA40.fullmatch(revision) else None


def _read_runtime_manifest(path: "Path") -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise _invalid("Approved runtime manifest is unavailable or malformed.") from exc
    if not isinstance(value, dict):
        raise _invalid("Approved runtime manifest is not an object.")
    try:
        from .runtime_artifact import validate_runtime_manifest

        manifest = validate_runtime_manifest(value)
    except Exception as exc:
        raise _invalid("Approved runtime manifest is incomplete or cannot be rederived.") from exc
    if manifest.get("artifact_status") != "CANDIDATE" or "image_identity" not in manifest:
        raise _invalid("Approved runtime manifest is not a complete executable runtime subject.")
    return manifest


def _environment_source(root: "Path") -> tuple["Path", "Path"]:
    candidate_paths = (
        root / ".k-slide-config" / "resolved-candidate.json",
        root / ".k-slide-config" / "production-candidate.json",
        root / "resolved-candidate.json",
        root / "production-candidate.json",
        root / "evals" / "production-candidate.yaml",
    )
    runtime_paths = (
        root / ".k-slide-config" / "runtime-manifest.json",
        root / ".k-slide-config" / "runtime" / "runtime-manifest.json",
        root / "runtime" / "runtime-manifest.json",
        root / "runtime-manifest.json",
    )
    candidate = next((path for path in candidate_paths if path.is_file() and not path.is_symlink()), None)
    runtime = next((path for path in runtime_paths if path.is_file() and not path.is_symlink()), None)
    if candidate is None:
        raise _invalid("Approved KSA-10 environment identity is unavailable; no candidate subject was found.")
    if runtime is None:
        raise _invalid("Approved KSA-10 environment identity is unavailable; no runtime manifest subject was found.")
    return candidate, runtime


def resolve_effective_environment(root: "Path", *, environment_identity: RunEnvironmentIdentity | None = None) -> RunEnvironmentIdentity:
    """Resolve the current product environment without manufacturing proof.

    An explicit identity is an approved deployment binding.  Otherwise the
    product path must reopen the immutable candidate and runtime subjects and
    project them through the existing KSA-07 authorities.
    """

    if environment_identity is not None:
        if not isinstance(environment_identity, RunEnvironmentIdentity):
            raise _invalid("Current KSA-10 environment identity is invalid.")
        return environment_identity

    root = root.expanduser().resolve()
    candidate_path, runtime_path = _environment_source(root)
    try:
        from .certification import EvidenceValidationError, load_candidate_spec, resolve_candidate_spec
        from .security import sha256_file

        candidate = load_candidate_spec(candidate_path, root=root, require_identity=True, strict=True)
        candidate = resolve_candidate_spec(
            candidate,
            root=root,
            subject_git_sha=candidate.get("subject_git_sha"),
            require_sources=True,
        )
        runtime = _read_runtime_manifest(runtime_path)
        runtime_manifest_sha = sha256_file(runtime_path)
        declared_manifest_sha = candidate.get("runtime_artifact_manifest_sha256")
        if declared_manifest_sha not in (None, "", "UNSET") and declared_manifest_sha != runtime_manifest_sha:
            raise _invalid("Approved candidate and runtime manifest identities disagree.")
        runtime["runtime_manifest_sha256"] = runtime_manifest_sha
        source_revision = _repository_revision(root)
        if source_revision is not None and runtime.get("source_revision") != source_revision:
            raise _invalid("Approved runtime manifest is not bound to the current K-Slide revision.")
        identity = RunEnvironmentIdentity.from_candidate_spec(candidate, runtime_manifest=runtime)
        from .classification_policy import load_inference_data_use_policy

        configured_policy = load_inference_data_use_policy(root, route_identity=identity.inference_route_identity)
        if (
            configured_policy.policy_version != identity.inference_data_policy_version
            or configured_policy.policy_hash != identity.inference_data_policy_hash
            or configured_policy.policy_identity != identity.inference_data_policy_identity
        ):
            raise KSlideError(
                ErrorCode.EXECUTION_ENVIRONMENT_MISMATCH,
                "Run environment is incompatible; resume was refused.",
                {
                    "mismatch_code": "KSLIDE_RUN_ENVIRONMENT_MISMATCH",
                    "mismatch_fields": ["inference_data_policy"],
                },
            )
    except KSlideError:
        raise
    except EvidenceValidationError as exc:
        raise _invalid("Approved KSA-10 candidate/runtime identity is incomplete, unresolved, or inconsistent.") from exc
    except Exception as exc:
        raise _invalid("Approved KSA-10 candidate/runtime identity cannot be rederived.") from exc
    return identity
