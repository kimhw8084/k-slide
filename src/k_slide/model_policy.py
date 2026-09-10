"""Authoritative production model policy.

The policy is deliberately small and dependency-free so the runtime doctor and
the evaluation tooling consult the same approval logic.  Private deployments
may add aliases through the ignored local policy overlay; the public defaults
remain exact and never accept a string-prefix convention as proof of approval.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ModelPolicy:
    target_family: str = "Gemma 4"
    target_size: str = "31B"
    target_variant: str = "instruction_tuned"
    approved_model_ids: tuple[str, ...] = ("google/gemma-4-31b-it",)
    approved_aliases: tuple[str, ...] = ()

    @classmethod
    def from_mapping(cls, value: dict[str, Any] | None) -> "ModelPolicy":
        value = value or {}

        def values(key: str, default: tuple[str, ...]) -> tuple[str, ...]:
            raw = value.get(key, default)
            if isinstance(raw, str):
                return (raw,)
            if isinstance(raw, (list, tuple)):
                return tuple(str(item) for item in raw)
            return default

        return cls(
            target_family=str(value.get("target_family", cls.target_family)),
            target_size=str(value.get("target_size", cls.target_size)),
            target_variant=str(value.get("target_variant", cls.target_variant)),
            approved_model_ids=values("approved_model_ids", cls.approved_model_ids),
            approved_aliases=values("approved_aliases", ()),
        )

    def approved(self, *, requested: str | None, effective: str | None) -> bool:
        if not requested or not effective:
            return False
        approved = set(self.approved_model_ids) | set(self.approved_aliases)
        return requested in approved and effective in approved

    def as_dict(self) -> dict[str, Any]:
        return {
            "target_family": self.target_family,
            "target_size": self.target_size,
            "target_variant": self.target_variant,
            "approved_model_ids": list(self.approved_model_ids),
            "approved_aliases": list(self.approved_aliases),
        }


def load_model_policy(root: Path | None = None) -> ModelPolicy:
    """Load public policy plus an optional ignored local alias overlay."""

    root = (root or Path.cwd()).expanduser().resolve()
    local = root / ".k-slide-config" / "model-policy.local.yaml"
    if not local.is_file():
        local = root / ".k-slide-config" / "model-policy.local.json"
    if not local.is_file():
        return ModelPolicy()
    try:
        text = local.read_text(encoding="utf-8")
        if local.suffix == ".json":
            value = json.loads(text)
            if not isinstance(value, dict):
                raise ValueError("model policy overlay must be an object")
            return ModelPolicy.from_mapping(value)
        mapping: dict[str, Any] = {}
        current_list: str | None = None
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].rstrip()
            if not line.strip():
                continue
            if line.startswith("  - ") and current_list:
                mapping.setdefault(current_list, []).append(line[4:].strip().strip("'\""))
                continue
            if ":" not in line:
                raise ValueError("invalid model policy line")
            key, raw_value = (item.strip() for item in line.split(":", 1))
            if not raw_value:
                current_list = key
                mapping[key] = []
            else:
                current_list = None
                mapping[key] = raw_value.strip().strip("'\"")
        return ModelPolicy.from_mapping(mapping)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError, TypeError):
        # A malformed private overlay must never silently certify a model.
        return ModelPolicy(approved_model_ids=(), approved_aliases=())
