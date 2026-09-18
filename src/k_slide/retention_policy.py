"""Canonical, source-free retention policy contract."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any


RETENTION_POLICY_SCHEMA_VERSION = "1.0"
RETENTION_POLICY_FIELD = "retention_policy"
CONTENT_RETENTION_FIELD = "content_retention_days"
OPERATIONAL_METADATA_RETENTION_FIELD = "operational_metadata_retention_days"
RETENTION_POLICY_FIELDS = (
    "schema_version",
    CONTENT_RETENTION_FIELD,
    OPERATIONAL_METADATA_RETENTION_FIELD,
)
RETENTION_UNRESOLVED_MARKERS = frozenset({"UNSET", "NOT_YET_CONFIGURED"})


@dataclass(frozen=True)
class RetentionPolicy:
    """The centrally supplied retention values used by K-Slide.

    Unresolved markers are representable for public/development templates, but
    callers that perform production readiness or deletion must request a
    resolved policy explicitly.
    """

    schema_version: str
    content_retention_days: int | str
    operational_metadata_retention_days: int | str

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any], *, require_resolved: bool = False) -> "RetentionPolicy":
        if not isinstance(value, Mapping):
            raise ValueError("retention_policy must be an object")
        if "retention_days" in value:
            raise ValueError(
                "legacy retention_days is unsupported; explicitly supply "
                "retention_policy.content_retention_days and "
                "retention_policy.operational_metadata_retention_days"
            )
        missing = [field for field in RETENTION_POLICY_FIELDS if field not in value]
        if missing:
            raise ValueError("retention_policy is missing required fields: " + ", ".join(missing))
        unexpected = sorted(str(key) for key in value if key not in RETENTION_POLICY_FIELDS)
        if unexpected:
            raise ValueError("retention_policy contains unsupported fields: " + ", ".join(unexpected))
        schema_version = str(value["schema_version"])
        if schema_version != RETENTION_POLICY_SCHEMA_VERSION:
            raise ValueError(f"unsupported retention policy schema: {schema_version}")
        parsed: dict[str, int | str] = {}
        for field in (CONTENT_RETENTION_FIELD, OPERATIONAL_METADATA_RETENTION_FIELD):
            raw = value[field]
            if isinstance(raw, str) and raw.strip().upper() in RETENTION_UNRESOLVED_MARKERS:
                if require_resolved:
                    raise ValueError(f"retention_policy.{field} is unresolved; central policy is required")
                parsed[field] = raw.strip().upper()
                continue
            if isinstance(raw, bool) or not isinstance(raw, int) or raw <= 0:
                raise ValueError(f"retention_policy.{field} must be a positive integer or an explicit unresolved marker")
            parsed[field] = raw
        policy = cls(
            schema_version=schema_version,
            content_retention_days=parsed[CONTENT_RETENTION_FIELD],
            operational_metadata_retention_days=parsed[OPERATIONAL_METADATA_RETENTION_FIELD],
        )
        if require_resolved:
            policy.require_resolved()
        return policy

    @property
    def resolved(self) -> bool:
        return isinstance(self.content_retention_days, int) and isinstance(self.operational_metadata_retention_days, int)

    def require_resolved(self) -> "RetentionPolicy":
        for field, value in (
            (CONTENT_RETENTION_FIELD, self.content_retention_days),
            (OPERATIONAL_METADATA_RETENTION_FIELD, self.operational_metadata_retention_days),
        ):
            if not isinstance(value, int):
                raise ValueError(f"retention_policy.{field} is unresolved; central policy is required")
        return self

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            CONTENT_RETENTION_FIELD: self.content_retention_days,
            OPERATIONAL_METADATA_RETENTION_FIELD: self.operational_metadata_retention_days,
        }
