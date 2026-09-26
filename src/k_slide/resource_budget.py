"""Versioned resource limits shared by intake, normalization, and execution."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .errors import ErrorCode, KSlideError


RESOURCE_BUDGET_SCHEMA_VERSION = "1.0"
RESOURCE_BUDGET_PROFILE = ".k-slide-config/production-profile.json"
_MODEL_BUDGET_RESPONSE_OVERHEAD_BYTES = 512

# These are implementation safety ceilings, not company-approved production
# budgets. Production profiles must supply every limit explicitly.
_TECHNICAL_CEILINGS = {
    "max_file_bytes": 512 * 1024 * 1024,
    "max_total_file_bytes_per_run": 2_000_000_000,
    "max_documents_per_run": 32,
    "max_pdf_pages_per_document": 200,
    "max_pptx_slides_per_deck": 200,
    "max_work_units_per_run": 500,
    "max_pixels_per_image": 120_000_000,
    "max_total_decoded_pixels_per_run": 500_000_000,
    "max_normalized_bytes_per_run": 2_000_000_000,
    "max_image_dimension": 20_000,
    "max_media_items_per_work_unit": 256,
    "model_media_token_reserve_per_item": 1_024,
    "max_model_input_tokens_per_work_unit": 2_000_000,
    "max_model_output_tokens_per_work_unit": 2_000_000,
    "max_model_tokens_per_run": 100_000_000,
    "max_concurrent_runs_per_scope": 1,
    "max_queued_runs_per_scope": 100_000,
    "max_concurrent_work_units_per_run": 1,
}

_REFERENCE_VALUES = {
    "max_file_bytes": 512 * 1024 * 1024,
    "max_total_file_bytes_per_run": 2_000_000_000,
    "max_documents_per_run": 32,
    "max_pdf_pages_per_document": 200,
    "max_pptx_slides_per_deck": 200,
    "max_work_units_per_run": 500,
    "max_pixels_per_image": 120_000_000,
    "max_total_decoded_pixels_per_run": 500_000_000,
    "max_normalized_bytes_per_run": 2_000_000_000,
    "max_image_dimension": 20_000,
    "max_media_items_per_work_unit": 256,
    "model_media_token_reserve_per_item": 1_024,
    "max_model_input_tokens_per_work_unit": 2_000_000,
    "max_model_output_tokens_per_work_unit": 2_000_000,
    "max_model_tokens_per_run": 100_000_000,
    "max_concurrent_runs_per_scope": 1,
    "max_queued_runs_per_scope": 16,
    "max_concurrent_work_units_per_run": 1,
    "max_media_duration_seconds": None,
}

_NUMERIC_FIELDS = tuple(_TECHNICAL_CEILINGS)
_FIELDS = frozenset((*_NUMERIC_FIELDS, "max_media_duration_seconds"))


def _invalid(message: str, *, code: ErrorCode = ErrorCode.RESOURCE_BUDGET_INVALID) -> KSlideError:
    return KSlideError(code, message)


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


@dataclass(frozen=True)
class ResourceBudget:
    """One closed budget contract, snapshotted into every admitted run."""

    values: tuple[tuple[str, int | None], ...]
    environment: str
    schema_version: str = RESOURCE_BUDGET_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != RESOURCE_BUDGET_SCHEMA_VERSION:
            raise _invalid("Resource budget schema version is unsupported.")
        if not isinstance(self.environment, str) or self.environment not in {"production", "reference_non_production"}:
            raise _invalid("Resource budget environment is unsupported.")
        mapping = dict(self.values)
        if set(mapping) != _FIELDS:
            raise _invalid("Resource budget fields are incomplete or unsupported.")
        for field, ceiling in _TECHNICAL_CEILINGS.items():
            value = mapping[field]
            if isinstance(value, bool) or not isinstance(value, int) or value < 1 or value > ceiling:
                raise _invalid(f"Resource budget {field} is outside the supported range.")
        duration = mapping["max_media_duration_seconds"]
        if duration is not None:
            raise _invalid("Duration-bearing media is unsupported by the current static-image and slide pipeline.")
        if mapping["max_concurrent_runs_per_scope"] != 1 or mapping["max_concurrent_work_units_per_run"] != 1:
            raise _invalid("The current K-Slide admission and single-agent owners support one active run and work unit per scope.")

    @classmethod
    def reference(cls) -> "ResourceBudget":
        """Non-production defaults retained for deterministic reference use."""

        return cls(tuple(sorted(_REFERENCE_VALUES.items())), "reference_non_production")

    @classmethod
    def from_mapping(cls, value: Any, *, environment: str = "production") -> "ResourceBudget":
        if not isinstance(value, Mapping) or set(value) != _FIELDS:
            raise _invalid("Resource budget must contain exactly the versioned limit fields.")
        return cls(tuple(sorted(value.items())), environment)

    @classmethod
    def from_dict(cls, value: Any) -> "ResourceBudget":
        if not isinstance(value, Mapping) or set(value) != {"schema_version", "environment", "limits"}:
            raise _invalid("Persisted resource budget is malformed.", code=ErrorCode.STATE_CORRUPT)
        result = cls.from_mapping(value.get("limits"), environment=value.get("environment"))
        if value.get("schema_version") != RESOURCE_BUDGET_SCHEMA_VERSION:
            raise _invalid("Persisted resource budget schema version is unsupported.", code=ErrorCode.STATE_CORRUPT)
        return result

    @classmethod
    def load_for_workspace(cls, root: Path, *, production_required: bool = False) -> "ResourceBudget":
        path = root.expanduser().resolve() / RESOURCE_BUDGET_PROFILE
        if not path.is_file():
            if production_required:
                raise _invalid("Production resource budget is missing.", code=ErrorCode.RESOURCE_BUDGET_UNAVAILABLE)
            return cls.reference()
        try:
            value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_strict_json_object)
        except (OSError, UnicodeError, ValueError) as exc:
            raise _invalid("Production resource budget is unreadable or malformed.") from exc
        if not isinstance(value, Mapping):
            raise _invalid("Production profile is malformed while resolving its resource budget.")
        raw_budget = value.get("resource_budget")
        if raw_budget is None:
            if production_required:
                raise _invalid("Production resource budget is missing.", code=ErrorCode.RESOURCE_BUDGET_UNAVAILABLE)
            return cls.reference()
        result = cls.from_dict(raw_budget)
        if result.environment != "production" and production_required:
            raise _invalid("Production requires an explicitly production-classified resource budget.")
        return result

    @staticmethod
    def production_required_for_workspace(root: Path) -> bool:
        """Require production limits once a workspace profile leaves development.

        Candidate and fixture runs may use the explicitly non-production
        reference budget. Any materialized readiness/release profile must bind
        a production-classified budget before it can admit production work.
        Malformed profile state fails closed in ``load_for_workspace``.
        """

        path = root.expanduser().resolve() / RESOURCE_BUDGET_PROFILE
        if not path.is_file():
            return False
        try:
            value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_strict_json_object)
        except (OSError, UnicodeError, ValueError):
            return True
        if not isinstance(value, Mapping):
            return True
        release_state = value.get("release_state")
        return isinstance(release_state, str) and release_state != "DEVELOPMENT"

    @classmethod
    def from_run_manifest(cls, root: Path, manifest: Mapping[str, Any], *, production_required: bool = False) -> "ResourceBudget":
        value = manifest.get("resource_budget")
        if value is None:
            # Existing runs created before this contract remain readable under
            # the explicitly non-production reference ceiling.
            if production_required:
                raise _invalid("Managed run has no immutable production resource budget snapshot.", code=ErrorCode.RESOURCE_BUDGET_UNAVAILABLE)
            return cls.reference()
        result = cls.from_dict(value)
        expected = manifest.get("resource_budget_sha256")
        if expected is not None and expected != result.sha256:
            raise _invalid("Persisted resource budget identity does not match its run manifest.", code=ErrorCode.STATE_CORRUPT)
        return result

    def limit(self, name: str) -> int | None:
        if name not in _FIELDS:
            raise KeyError(name)
        return dict(self.values)[name]

    def enforce(self, name: str, observed: int, *, message: str | None = None) -> None:
        limit = self.limit(name)
        if isinstance(observed, bool) or not isinstance(observed, int) or observed < 0:
            raise _invalid(f"Observed resource amount for {name} is invalid.", code=ErrorCode.STATE_CORRUPT)
        if limit is None:
            if observed:
                raise KSlideError(ErrorCode.RESOURCE_LIMIT, message or f"Resource {name} is unsupported by this pipeline.", {"resource": name, "observed": observed})
            return
        if observed > limit:
            raise KSlideError(ErrorCode.RESOURCE_LIMIT, message or f"Resource {name} exceeds the configured budget.", {"resource": name, "observed": observed, "limit": limit})

    def as_dict(self) -> dict[str, Any]:
        return {"schema_version": self.schema_version, "environment": self.environment, "limits": dict(self.values)}

    @property
    def sha256(self) -> str:
        encoded = json.dumps(self.as_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


def production_budget_status(value: Any) -> tuple[bool, str]:
    """Readiness helper: absent production budgets must fail closed."""

    try:
        budget = ResourceBudget.from_mapping(value, environment="production")
    except KSlideError as exc:
        return False, exc.message
    return True, budget.sha256


def estimate_model_input_tokens(packet: Mapping[str, Any], prompt: str, media_count: int, budget: ResourceBudget) -> int:
    """Conservative text-byte upper bound plus response metadata and media reserves.

    This is a K-Slide packet budget, not provider-reported tokenizer usage.
    Production qualification still requires the managed provider to expose
    and enforce its own actual token accounting.
    """

    if isinstance(media_count, bool) or not isinstance(media_count, int) or media_count < 0:
        raise _invalid("Model media count is invalid.")
    encoded = json.dumps(dict(packet), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return (
        len(encoded)
        + len(prompt.encode("utf-8"))
        + media_count * int(budget.limit("model_media_token_reserve_per_item"))
        + _MODEL_BUDGET_RESPONSE_OVERHEAD_BYTES
    )


def estimate_model_output_tokens(value: Mapping[str, Any]) -> int:
    """Upper bound a returned TranslationPatch by its UTF-8 byte length."""

    return len(json.dumps(dict(value), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8"))
