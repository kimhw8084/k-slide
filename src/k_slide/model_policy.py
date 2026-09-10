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
    approved_alias_targets: tuple[tuple[str, tuple[str, ...]], ...] = ()

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

        raw_targets = value.get("approved_alias_targets", {})
        targets: list[tuple[str, tuple[str, ...]]] = []
        if isinstance(raw_targets, dict):
            for alias, raw_values in sorted(raw_targets.items()):
                if isinstance(raw_values, str):
                    raw_values = [raw_values]
                if isinstance(raw_values, (list, tuple)):
                    targets.append((str(alias), tuple(str(item) for item in raw_values)))

        return cls(
            target_family=str(value.get("target_family", cls.target_family)),
            target_size=str(value.get("target_size", cls.target_size)),
            target_variant=str(value.get("target_variant", cls.target_variant)),
            approved_model_ids=values("approved_model_ids", cls.approved_model_ids),
            approved_aliases=values("approved_aliases", ()),
            approved_alias_targets=tuple(targets),
        )

    def approved(self, *, requested: str | None, effective: str | None) -> bool:
        if not requested or not effective:
            return False
        if requested in self.approved_model_ids:
            # Separately approved canonical IDs are not interchangeable.  A
            # direct request must resolve to that exact deployment unless an
            # explicit alias mapping says otherwise.
            return effective == requested
        if requested not in self.approved_aliases:
            return False
        targets = dict(self.approved_alias_targets).get(requested, ())
        return effective in targets

    def canonical_effective(self, *, requested: str | None, effective: str | None) -> str | None:
        """Return the policy's canonical effective ID for one approved pair."""

        if not self.approved(requested=requested, effective=effective):
            return None
        if effective in self.approved_model_ids:
            return effective
        targets = dict(self.approved_alias_targets).get(str(requested), ())
        return effective if effective in targets else None

    def as_dict(self) -> dict[str, Any]:
        return {
            "target_family": self.target_family,
            "target_size": self.target_size,
            "target_variant": self.target_variant,
            "approved_model_ids": list(self.approved_model_ids),
            "approved_aliases": list(self.approved_aliases),
            "approved_alias_targets": {alias: list(targets) for alias, targets in self.approved_alias_targets},
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
        current_map: str | None = None
        current_alias: str | None = None
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].rstrip()
            if not line.strip():
                continue
            indent = len(line) - len(line.lstrip())
            content = line.strip()
            if current_map == "approved_alias_targets" and current_alias and indent >= 4 and content.startswith("- "):
                mapping["approved_alias_targets"][current_alias].append(content[2:].strip().strip("'\""))
                continue
            if current_map == "approved_alias_targets" and indent == 2 and ":" in content:
                alias, raw_target = (item.strip() for item in content.split(":", 1))
                if raw_target:
                    mapping["approved_alias_targets"][alias] = [raw_target.strip("'\"")]
                else:
                    mapping["approved_alias_targets"][alias] = []
                current_alias = alias
                current_list = None
                continue
            if line.startswith("  - ") and current_list:
                mapping.setdefault(current_list, []).append(line[4:].strip().strip("'\""))
                continue
            if ":" not in line:
                raise ValueError("invalid model policy line")
            key, raw_value = (item.strip() for item in line.split(":", 1))
            if not raw_value:
                current_map = key if key == "approved_alias_targets" else None
                current_alias = None
                current_list = None if current_map else key
                mapping[key] = {} if current_map else []
            else:
                current_map = None
                current_alias = None
                current_list = None
                mapping[key] = raw_value.strip().strip("'\"")
        return ModelPolicy.from_mapping(mapping)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError, TypeError):
        # A malformed private overlay must never silently certify a model.
        return ModelPolicy(approved_model_ids=(), approved_aliases=())
