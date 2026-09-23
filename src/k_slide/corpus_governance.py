"""Source-free, fail-closed governance for evaluation corpus identities.

Private manifests may be held outside the repository.  This module validates
their canonical metadata and fingerprints without loading source or gold bytes.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Iterable


CORPUS_GOVERNANCE_SCHEMA_VERSION = "1.0"
CORPUS_ROLES = (
    "public_synthetic_regression",
    "private_representative",
    "frozen_high_risk",
    "sealed_held_out",
)
EVALUATION_PURPOSES = ("development", "regression", "private_evaluation", "comparison", "promotion")
ACCESS_CLASS_BY_ROLE = {
    "public_synthetic_regression": "public_development",
    "private_representative": "approved_private_evaluation",
    "frozen_high_risk": "frozen_comparison",
    "sealed_held_out": "sealed_promotion",
}
ALLOWED_PURPOSES_BY_ROLE = {
    "public_synthetic_regression": frozenset({"development", "regression"}),
    "private_representative": frozenset({"private_evaluation"}),
    "frozen_high_risk": frozenset({"comparison"}),
    "sealed_held_out": frozenset({"promotion"}),
}
_STATES_BY_ROLE = {
    "public_synthetic_regression": frozenset({"active", "retired"}),
    "private_representative": frozenset({"active", "retired"}),
    "frozen_high_risk": frozenset({"frozen", "retired"}),
    "sealed_held_out": frozenset({"sealed", "contaminated", "retired"}),
}
_AUTHORITIES_BY_ROLE = {
    "public_synthetic_regression": "repository_generator",
    "private_representative": "approved_private_evaluation",
    "frozen_high_risk": "evaluation_governance",
    "sealed_held_out": "evaluation_governance",
}
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_OPAQUE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_IDENTITY_FIELDS = {
    "schema_version", "set_id", "role", "version", "state", "manifest_fingerprint",
    "item_count", "active_item_count", "provenance", "access_class", "predecessor",
}
_MANIFEST_FIELDS = {
    "schema_version", "set_id", "role", "version", "state", "items", "provenance",
    "access_class", "predecessor", "manifest_fingerprint",
}
_ITEM_FIELDS = {"item_id", "source_sha256", "gold_sha256", "state", "replacement_of"}
_PREDECESSOR_FIELDS = {"set_id", "version", "manifest_fingerprint"}
_REPLACEMENT_FIELDS = {"set_id", "version", "item_id"}
_CONTAMINATION_CONTEXTS = frozenset({
    "development", "regression", "training", "private_evaluation", "comparison",
    "prompt_selection", "rule_tuning", "threshold_tuning",
})
_HISTORY_ENTRY_FIELDS = {"manifest", "exposure_contexts"}


class CorpusGovernanceError(ValueError):
    """A governed corpus contract is malformed, inconsistent, or ineligible."""


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _require_hash(value: Any, label: str) -> str:
    if not isinstance(value, str) or _HEX64.fullmatch(value) is None:
        raise CorpusGovernanceError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _require_opaque(value: Any, label: str) -> str:
    if not isinstance(value, str) or _OPAQUE_ID.fullmatch(value) is None:
        raise CorpusGovernanceError(f"{label} must be a bounded opaque identifier")
    return value


def _require_version(value: Any) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 64 or value != value.strip():
        raise CorpusGovernanceError("corpus version must be a non-empty stable string")
    return value


def _canonical_provenance(value: Any, role: str) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != {"authority", "record_sha256"}:
        raise CorpusGovernanceError("corpus provenance must contain only authority and record_sha256")
    if value.get("authority") != _AUTHORITIES_BY_ROLE[role]:
        raise CorpusGovernanceError("corpus provenance authority does not match its role")
    return {"authority": value["authority"], "record_sha256": _require_hash(value.get("record_sha256"), "provenance record_sha256")}


def _canonical_predecessor(value: Any) -> dict[str, str] | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != _PREDECESSOR_FIELDS:
        raise CorpusGovernanceError("corpus predecessor identity is malformed")
    return {
        "set_id": _require_opaque(value.get("set_id"), "predecessor set_id"),
        "version": _require_version(value.get("version")),
        "manifest_fingerprint": _require_hash(value.get("manifest_fingerprint"), "predecessor manifest_fingerprint"),
    }


def _canonical_replacement(value: Any) -> dict[str, str] | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != _REPLACEMENT_FIELDS:
        raise CorpusGovernanceError("replacement lineage is malformed")
    return {
        "set_id": _require_opaque(value.get("set_id"), "replacement set_id"),
        "version": _require_version(value.get("version")),
        "item_id": _require_opaque(value.get("item_id"), "replacement item_id"),
    }


def item_fingerprint(source_sha256: str, gold_sha256: str) -> str:
    """Hash the source/gold pair without disclosing either underlying value."""

    source = _require_hash(source_sha256, "source_sha256")
    gold = _require_hash(gold_sha256, "gold_sha256")
    return sha256_bytes(canonical_bytes({"source_sha256": source, "gold_sha256": gold}))


def _canonical_items(value: Any, *, role: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise CorpusGovernanceError("governed corpus items must be a non-empty list")
    allowed_item_states = {"active", "retired", "contaminated"}
    result: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    source_gold: dict[str, str] = {}
    pair_fingerprints: set[str] = set()
    for raw in value:
        if not isinstance(raw, dict) or set(raw) - _ITEM_FIELDS or not {"item_id", "source_sha256", "gold_sha256", "state"} <= set(raw):
            raise CorpusGovernanceError("governed corpus item has an unsupported shape")
        item_id = _require_opaque(raw["item_id"], "item_id")
        source_hash = _require_hash(raw["source_sha256"], "source_sha256")
        gold_hash = _require_hash(raw["gold_sha256"], "gold_sha256")
        state = raw["state"]
        if item_id in seen_ids:
            raise CorpusGovernanceError("governed corpus contains a duplicate item ID")
        if state not in allowed_item_states or (state == "contaminated" and role != "sealed_held_out"):
            raise CorpusGovernanceError("governed corpus item lifecycle is invalid for its role")
        if state == "contaminated" and role == "sealed_held_out":
            pass
        if source_hash in source_gold and source_gold[source_hash] != gold_hash:
            raise CorpusGovernanceError("governed corpus contains contradictory gold for one source identity")
        pair = item_fingerprint(source_hash, gold_hash)
        if pair in pair_fingerprints:
            raise CorpusGovernanceError("governed corpus contains duplicate item membership")
        replacement = _canonical_replacement(raw.get("replacement_of"))
        if replacement is not None and role != "sealed_held_out":
            raise CorpusGovernanceError("replacement lineage is supported only for sealed held-out items")
        item = {"item_id": item_id, "source_sha256": source_hash, "gold_sha256": gold_hash, "state": state}
        if replacement is not None:
            item["replacement_of"] = replacement
        result.append(item)
        seen_ids.add(item_id)
        source_gold[source_hash] = gold_hash
        pair_fingerprints.add(pair)
    result.sort(key=lambda item: item["item_id"])
    return result


def canonical_manifest(value: Any) -> dict[str, Any]:
    """Validate and canonicalize a source-free governed set manifest."""

    if not isinstance(value, dict) or set(value) - _MANIFEST_FIELDS:
        raise CorpusGovernanceError("governed corpus manifest has unsupported fields")
    required = _MANIFEST_FIELDS - {"predecessor"}
    if not required <= set(value):
        raise CorpusGovernanceError("governed corpus manifest is incomplete")
    if value.get("schema_version") != CORPUS_GOVERNANCE_SCHEMA_VERSION:
        raise CorpusGovernanceError("unsupported corpus governance schema version")
    role = value.get("role")
    if role not in CORPUS_ROLES:
        raise CorpusGovernanceError("unknown governed corpus role")
    state = value.get("state")
    if state not in _STATES_BY_ROLE[role]:
        raise CorpusGovernanceError("corpus lifecycle state is invalid for its role")
    access_class = value.get("access_class")
    if access_class != ACCESS_CLASS_BY_ROLE[role]:
        raise CorpusGovernanceError("corpus access class does not match its role")
    provenance = _canonical_provenance(value.get("provenance"), role)
    items = _canonical_items(value.get("items"), role=role)
    if state == "retired" and any(item["state"] == "active" for item in items):
        raise CorpusGovernanceError("retired corpus cannot contain active items")
    active_count = sum(item["state"] == "active" for item in items)
    if state in {"active", "frozen", "sealed"} and active_count == 0:
        raise CorpusGovernanceError("eligible corpus lifecycle state requires active membership")
    if role == "sealed_held_out" and state == "contaminated" and not any(item["state"] == "contaminated" for item in items):
        raise CorpusGovernanceError("contaminated corpus must preserve a contaminated item record")
    canonical = {
        "schema_version": CORPUS_GOVERNANCE_SCHEMA_VERSION,
        "set_id": _require_opaque(value.get("set_id"), "set_id"),
        "role": role,
        "version": _require_version(value.get("version")),
        "state": state,
        "items": items,
        "provenance": provenance,
        "access_class": access_class,
    }
    predecessor = _canonical_predecessor(value.get("predecessor"))
    if predecessor is not None:
        canonical["predecessor"] = predecessor
    expected = sha256_bytes(canonical_bytes(canonical))
    supplied = _require_hash(value.get("manifest_fingerprint"), "manifest_fingerprint")
    if supplied != expected:
        raise CorpusGovernanceError("governed corpus manifest fingerprint does not match canonical content")
    canonical["manifest_fingerprint"] = expected
    return canonical


def build_manifest(*, set_id: str, role: str, version: str, state: str, items: list[dict[str, Any]], provenance: dict[str, str], predecessor: dict[str, str] | None = None) -> dict[str, Any]:
    """Build a manifest with its deterministic fingerprint filled in."""

    value: dict[str, Any] = {
        "schema_version": CORPUS_GOVERNANCE_SCHEMA_VERSION,
        "set_id": set_id,
        "role": role,
        "version": version,
        "state": state,
        "items": items,
        "provenance": provenance,
        "access_class": ACCESS_CLASS_BY_ROLE.get(role),
    }
    if predecessor is not None:
        value["predecessor"] = predecessor
    # Validate the shape before calculating the public fingerprint.
    role_items = _canonical_items(items, role=role) if role in CORPUS_ROLES else []
    payload = dict(value)
    payload["items"] = role_items
    fingerprint = sha256_bytes(canonical_bytes(payload))
    value["manifest_fingerprint"] = fingerprint
    return canonical_manifest(value)


def manifest_identity(manifest: Any) -> dict[str, Any]:
    value = canonical_manifest(manifest)
    identity = {
        "schema_version": value["schema_version"],
        "set_id": value["set_id"],
        "role": value["role"],
        "version": value["version"],
        "state": value["state"],
        "manifest_fingerprint": value["manifest_fingerprint"],
        "item_count": len(value["items"]),
        "active_item_count": sum(item["state"] == "active" for item in value["items"]),
        "provenance": value["provenance"],
        "access_class": value["access_class"],
    }
    if "predecessor" in value:
        identity["predecessor"] = value["predecessor"]
    return identity


def canonical_set_identity(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) - _IDENTITY_FIELDS:
        raise CorpusGovernanceError("governed set identity has unsupported fields")
    required = _IDENTITY_FIELDS - {"predecessor"}
    if not required <= set(value):
        raise CorpusGovernanceError("governed set identity is incomplete")
    if value.get("schema_version") != CORPUS_GOVERNANCE_SCHEMA_VERSION:
        raise CorpusGovernanceError("unsupported corpus governance schema version")
    role = value.get("role")
    if role not in CORPUS_ROLES:
        raise CorpusGovernanceError("unknown governed corpus role")
    state = value.get("state")
    if state not in _STATES_BY_ROLE[role]:
        raise CorpusGovernanceError("corpus lifecycle state is invalid for its role")
    count = value.get("item_count")
    if not isinstance(count, int) or isinstance(count, bool) or count < 1:
        raise CorpusGovernanceError("corpus item_count must be a positive integer")
    active_count = value.get("active_item_count")
    if not isinstance(active_count, int) or isinstance(active_count, bool) or not 0 <= active_count <= count:
        raise CorpusGovernanceError("corpus active_item_count must be a bounded non-negative integer")
    if state in {"active", "frozen", "sealed"} and active_count == 0:
        raise CorpusGovernanceError("eligible corpus identity requires active membership")
    if state == "retired" and active_count != 0:
        raise CorpusGovernanceError("retired corpus identity cannot have active membership")
    if value.get("access_class") != ACCESS_CLASS_BY_ROLE[role]:
        raise CorpusGovernanceError("corpus access class does not match its role")
    result = {
        "schema_version": CORPUS_GOVERNANCE_SCHEMA_VERSION,
        "set_id": _require_opaque(value.get("set_id"), "set_id"),
        "role": role,
        "version": _require_version(value.get("version")),
        "state": state,
        "manifest_fingerprint": _require_hash(value.get("manifest_fingerprint"), "manifest_fingerprint"),
        "item_count": count,
        "active_item_count": active_count,
        "provenance": _canonical_provenance(value.get("provenance"), role),
        "access_class": value["access_class"],
    }
    predecessor = _canonical_predecessor(value.get("predecessor"))
    if predecessor is not None:
        result["predecessor"] = predecessor
    return result


def canonical_corpus_identity(value: Any, *, require_complete: bool = False) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) - {"schema_version", "sets"}:
        raise CorpusGovernanceError("governed corpus identity has unsupported fields")
    if value.get("schema_version") != CORPUS_GOVERNANCE_SCHEMA_VERSION or not isinstance(value.get("sets"), list):
        raise CorpusGovernanceError("governed corpus identity is malformed")
    sets = [canonical_set_identity(item) for item in value["sets"]]
    roles = [item["role"] for item in sets]
    if len(roles) != len(set(roles)):
        raise CorpusGovernanceError("governed corpus identity has duplicate roles")
    set_ids = [item["set_id"] for item in sets]
    if len(set_ids) != len(set(set_ids)):
        raise CorpusGovernanceError("governed corpus identity has conflicting set IDs")
    sets.sort(key=lambda item: CORPUS_ROLES.index(item["role"]))
    result = {"schema_version": CORPUS_GOVERNANCE_SCHEMA_VERSION, "sets": sets}
    if require_complete and set(roles) != set(CORPUS_ROLES):
        raise CorpusGovernanceError("candidate corpus identity must bind all four governed roles")
    return result


def corpus_identity_fingerprint(value: Any, *, require_complete: bool = False) -> str:
    return sha256_bytes(canonical_bytes(canonical_corpus_identity(value, require_complete=require_complete)))


def is_complete_corpus_identity(value: Any) -> bool:
    try:
        canonical_corpus_identity(value, require_complete=True)
    except CorpusGovernanceError:
        return False
    return True


def is_certification_corpus_ready(value: Any) -> bool:
    expected = {
        "public_synthetic_regression": "regression",
        "private_representative": "private_evaluation",
        "frozen_high_risk": "comparison",
        "sealed_held_out": "promotion",
    }
    try:
        identity = canonical_corpus_identity(value, require_complete=True)
        for item in identity["sets"]:
            require_set_purpose(item, expected[item["role"]])
    except (CorpusGovernanceError, KeyError):
        return False
    return True


def set_identity_for_role(corpus_identity: Any, role: str) -> dict[str, Any]:
    identity = canonical_corpus_identity(corpus_identity)
    return next(item for item in identity["sets"] if item["role"] == role)


def require_set_purpose(set_identity: Any, purpose: str, *, contamination_report: Any | None = None) -> dict[str, Any]:
    identity = canonical_set_identity(set_identity)
    if purpose not in EVALUATION_PURPOSES:
        raise CorpusGovernanceError("unknown evaluation purpose")
    if purpose not in ALLOWED_PURPOSES_BY_ROLE[identity["role"]]:
        raise CorpusGovernanceError("evaluation purpose is not allowed for this corpus role")
    expected_state = {
        "public_synthetic_regression": "active",
        "private_representative": "active",
        "frozen_high_risk": "frozen",
        "sealed_held_out": "sealed",
    }[identity["role"]]
    if identity["state"] != expected_state:
        raise CorpusGovernanceError("corpus lifecycle state is not eligible for evaluation")
    if identity["role"] == "sealed_held_out" and contamination_report is not None:
        if validate_contamination_report(contamination_report, set_identity=identity):
            raise CorpusGovernanceError("sealed held-out corpus is contaminated")
    return identity


def _manifest_predecessor(manifest: dict[str, Any]) -> dict[str, str]:
    return {"set_id": manifest["set_id"], "version": manifest["version"], "manifest_fingerprint": manifest["manifest_fingerprint"]}


def validate_transition(previous_manifest: Any, next_manifest: Any, *, history: Iterable[Any] = ()) -> dict[str, Any]:
    """Validate immutable versioning, retirement history, and replacements."""

    previous = canonical_manifest(previous_manifest)
    current = canonical_manifest(next_manifest)
    all_history = [canonical_manifest(item) for item in history]
    versions: dict[tuple[str, str], tuple[str, str]] = {}
    for manifest in [previous, *all_history, current]:
        key = (manifest["set_id"], manifest["version"])
        value = (manifest["manifest_fingerprint"], manifest["role"])
        if key in versions and versions[key] != value:
            raise CorpusGovernanceError("corpus history contains an ambiguous set version")
        versions[key] = value
    if previous["role"] != current["role"]:
        raise CorpusGovernanceError("corpus transition cannot change role")
    if previous["state"] == "retired" and current["state"] != "retired":
        raise CorpusGovernanceError("retired corpus cannot be reactivated")
    same_version = previous["set_id"] == current["set_id"] and previous["version"] == current["version"]
    if same_version and previous["manifest_fingerprint"] != current["manifest_fingerprint"]:
        raise CorpusGovernanceError("frozen or sealed corpus changed without a new version")
    if not same_version:
        if current.get("predecessor") != _manifest_predecessor(previous):
            raise CorpusGovernanceError("new corpus version must link its exact predecessor")
    old_items = {item["item_id"]: item for item in previous["items"]}
    new_items = {item["item_id"]: item for item in current["items"]}
    for item_id, old in old_items.items():
        updated = new_items.get(item_id)
        if updated is None:
            raise CorpusGovernanceError("retired corpus item history cannot be deleted")
        if any(updated[key] != old[key] for key in ("source_sha256", "gold_sha256")):
            raise CorpusGovernanceError("corpus item content changed in place")
        if old["state"] in {"retired", "contaminated"} and updated["state"] == "active":
            raise CorpusGovernanceError("retired or contaminated item cannot be reactivated")
        if old["state"] != updated["state"] and not (old["state"] == "active" and updated["state"] in {"retired", "contaminated"}):
            raise CorpusGovernanceError("corpus item lifecycle transition is invalid")
    known = [previous, *all_history]
    prior_item_records = {
        (manifest["set_id"], manifest["version"], item["item_id"]): item
        for manifest in known for item in manifest["items"]
    }
    historical_hashes = {
        item_fingerprint(item["source_sha256"], item["gold_sha256"])
        for manifest in known for item in manifest["items"]
        if item["state"] in {"retired", "contaminated"}
    }
    has_contaminated_sealed_history = current["role"] == "sealed_held_out" and any(
        item["state"] == "contaminated" for manifest in known for item in manifest["items"]
    )
    for item_id, item in new_items.items():
        if item_id in old_items:
            continue
        replacement = item.get("replacement_of")
        if has_contaminated_sealed_history and item["state"] == "active" and replacement is None:
            raise CorpusGovernanceError("active held-out replacement must identify its contaminated predecessor")
        if replacement is not None:
            target = prior_item_records.get((replacement["set_id"], replacement["version"], replacement["item_id"]))
            if target is None or target["state"] not in {"retired", "contaminated"}:
                raise CorpusGovernanceError("replacement lineage must reference a retired historical item")
            if item_fingerprint(item["source_sha256"], item["gold_sha256"]) == item_fingerprint(target["source_sha256"], target["gold_sha256"]):
                raise CorpusGovernanceError("replacement cannot reuse contaminated source and gold bytes")
            if item["source_sha256"] == target["source_sha256"] or item["gold_sha256"] == target["gold_sha256"]:
                raise CorpusGovernanceError("replacement must use distinct source and gold identities")
        elif item_fingerprint(item["source_sha256"], item["gold_sha256"]) in historical_hashes:
            raise CorpusGovernanceError("retired corpus bytes cannot be resurrected under a new item ID")
    return current


def _canonical_history_entry(value: Any) -> tuple[dict[str, Any], dict[str, str]]:
    """Load a historical manifest and optional item-scoped prior-exposure contexts."""

    if isinstance(value, dict) and set(value) == _HISTORY_ENTRY_FIELDS:
        manifest = canonical_manifest(value.get("manifest"))
        contexts = value.get("exposure_contexts")
        if not isinstance(contexts, list):
            raise CorpusGovernanceError("history exposure_contexts must be a list")
        result: dict[str, str] = {}
        for record in contexts:
            if not isinstance(record, dict) or set(record) != {"item_id", "context"}:
                raise CorpusGovernanceError("history exposure context has an unsupported shape")
            item_id = _require_opaque(record.get("item_id"), "history exposure item_id")
            context = record.get("context")
            if context not in _CONTAMINATION_CONTEXTS or item_id in result:
                raise CorpusGovernanceError("history exposure context is invalid or duplicated")
            result[item_id] = context
        member_ids = {item["item_id"] for item in manifest["items"]}
        if not set(result) <= member_ids:
            raise CorpusGovernanceError("history exposure context references a missing manifest item")
        canonical_contexts = [{"item_id": key, "context": result[key]} for key in sorted(result)]
        if contexts != canonical_contexts:
            raise CorpusGovernanceError("history exposure contexts must be canonically ordered")
        return manifest, result
    return canonical_manifest(value), {}


def cross_set_overlaps(manifests: Iterable[Any], *, history: Iterable[Any] = ()) -> list[dict[str, str]]:
    """Reject current role overlap and active sealed reuse of prior exposure.

    Public synthetic membership is permanently exposure-relevant, including
    retired records. Historical active membership and explicitly recorded
    private exposure contexts remain relevant after retirement. Other retired
    records stay auditable without making unrelated bytes globally ineligible.
    """

    current = [(canonical_manifest(item), {}, False) for item in manifests]
    prior = [(*_canonical_history_entry(item), True) for item in history]
    records = [
        (manifest, item, contexts.get(item["item_id"], ""), historical)
        for manifest, contexts, historical in [*current, *prior]
        for item in manifest["items"]
    ]
    overlaps: list[dict[str, str]] = []
    for index, (left_manifest, left, left_context, left_historical) in enumerate(records):
        for right_manifest, right, right_context, right_historical in records[index + 1:]:
            same_manifest = (
                left_manifest["set_id"], left_manifest["version"], left_manifest["manifest_fingerprint"]
            ) == (
                right_manifest["set_id"], right_manifest["version"], right_manifest["manifest_fingerprint"]
            )
            both_active = (
                left_manifest["role"] != right_manifest["role"]
                and left["state"] == right["state"] == "active"
                and not left_historical and not right_historical
            )
            left_sealed_active = left_manifest["role"] == "sealed_held_out" and left["state"] == "active" and not left_historical
            right_sealed_active = right_manifest["role"] == "sealed_held_out" and right["state"] == "active" and not right_historical
            left_exposed = (
                left_manifest["role"] == "public_synthetic_regression"
                or (left_historical and left_manifest["role"] != "sealed_held_out" and left["state"] == "active")
                or left["state"] == "contaminated"
                or bool(left_context)
            )
            right_exposed = (
                right_manifest["role"] == "public_synthetic_regression"
                or (right_historical and right_manifest["role"] != "sealed_held_out" and right["state"] == "active")
                or right["state"] == "contaminated"
                or bool(right_context)
            )
            if same_manifest and not (left_sealed_active and right_exposed) and not (right_sealed_active and left_exposed):
                continue
            if not both_active and not (left_sealed_active and right_exposed) and not (right_sealed_active and left_exposed):
                continue
            left_ref = (left_manifest["role"], left_manifest["set_id"], left_manifest["version"], left["item_id"])
            right_ref = (right_manifest["role"], right_manifest["set_id"], right_manifest["version"], right["item_id"])
            for kind, left_digest, right_digest in (
                ("source_sha256", left["source_sha256"], right["source_sha256"]),
                ("gold_sha256", left["gold_sha256"], right["gold_sha256"]),
                ("item_fingerprint", item_fingerprint(left["source_sha256"], left["gold_sha256"]), item_fingerprint(right["source_sha256"], right["gold_sha256"])),
            ):
                if left_digest != right_digest:
                    continue
                overlaps.append({
                    "identity_kind": kind,
                    "identity_sha256": left_digest,
                    "first_role": left_ref[0],
                    "first_set_id": left_ref[1],
                    "first_version": left_ref[2],
                    "first_item_id": left_ref[3],
                    "overlap_role": right_ref[0],
                    "overlap_set_id": right_ref[1],
                    "overlap_version": right_ref[2],
                    "overlap_item_id": right_ref[3],
                })
    deduplicated = {tuple(sorted(item.items())): item for item in overlaps}
    return sorted(deduplicated.values(), key=lambda item: (item["identity_kind"], item["identity_sha256"], item["first_role"], item["overlap_role"]))


def validate_corpus_bundle(value: Any, *, history: Any = None, require_complete: bool = True) -> list[dict[str, Any]]:
    """Validate the private hash-only manifests that substantiate candidate identities."""

    if not isinstance(value, list):
        raise CorpusGovernanceError("governed corpus manifest bundle must be a list")
    manifests = [canonical_manifest(item) for item in value]
    roles = [item["role"] for item in manifests]
    if len(roles) != len(set(roles)):
        raise CorpusGovernanceError("governed corpus manifest bundle has duplicate roles")
    if require_complete and set(roles) != set(CORPUS_ROLES):
        raise CorpusGovernanceError("governed corpus manifest bundle must contain all four roles")
    raw_history = [] if history is None else history
    if not isinstance(raw_history, list):
        raise CorpusGovernanceError("governed corpus history must be a list")
    prior_entries = [_canonical_history_entry(item) for item in raw_history]
    prior_manifests = [item[0] for item in prior_entries]
    overlaps = cross_set_overlaps(manifests, history=raw_history)
    if overlaps:
        raise CorpusGovernanceError("active corpus items overlap governed prior exposure")
    nodes: dict[tuple[str, str, str], dict[str, Any]] = {}
    versions: dict[tuple[str, str], tuple[str, str]] = {}
    for manifest in [*prior_manifests, *manifests]:
        key = (manifest["set_id"], manifest["version"], manifest["manifest_fingerprint"])
        if key in nodes:
            raise CorpusGovernanceError("governed corpus history contains duplicate manifest identities")
        version_key = (manifest["set_id"], manifest["version"])
        version_value = (manifest["manifest_fingerprint"], manifest["role"])
        if version_key in versions and versions[version_key] != version_value:
            raise CorpusGovernanceError("governed corpus history contains an ambiguous set version")
        versions[version_key] = version_value
        nodes[key] = manifest
    for current in manifests:
        node = current
        seen: set[tuple[str, str, str]] = set()
        while "predecessor" in node:
            predecessor = node["predecessor"]
            key = (predecessor["set_id"], predecessor["version"], predecessor["manifest_fingerprint"])
            if key in seen:
                raise CorpusGovernanceError("governed corpus history contains a transition cycle")
            seen.add(key)
            previous = nodes.get(key)
            if previous is None:
                raise CorpusGovernanceError("governed corpus predecessor history is missing")
            validate_transition(previous, node, history=prior_manifests)
            node = previous
    manifests.sort(key=lambda item: CORPUS_ROLES.index(item["role"]))
    return manifests


def validate_contamination_report(report: Any, *, set_identity: Any | None = None, manifest: Any | None = None) -> list[str]:
    if not isinstance(report, dict) or set(report) != {"schema_version", "set_id", "version", "items"}:
        raise CorpusGovernanceError("contamination report has an unsupported shape")
    if report.get("schema_version") != CORPUS_GOVERNANCE_SCHEMA_VERSION:
        raise CorpusGovernanceError("unsupported contamination report schema version")
    set_id = _require_opaque(report.get("set_id"), "contamination report set_id")
    version = _require_version(report.get("version"))
    if set_identity is not None:
        identity = canonical_set_identity(set_identity)
        if identity["role"] != "sealed_held_out" or (identity["set_id"], identity["version"]) != (set_id, version):
            raise CorpusGovernanceError("contamination report does not match sealed held-out identity")
    values = report.get("items")
    if not isinstance(values, list):
        raise CorpusGovernanceError("contamination report items must be a list")
    seen: set[str] = set()
    ids: list[str] = []
    for item in values:
        if not isinstance(item, dict) or set(item) != {"item_id", "source_sha256", "gold_sha256", "context"}:
            raise CorpusGovernanceError("contamination report item has an unsupported shape")
        item_id = _require_opaque(item.get("item_id"), "contamination item_id")
        if item_id in seen or item.get("context") not in _CONTAMINATION_CONTEXTS:
            raise CorpusGovernanceError("contamination report contains duplicate items or unknown context")
        _require_hash(item.get("source_sha256"), "contamination source_sha256")
        _require_hash(item.get("gold_sha256"), "contamination gold_sha256")
        seen.add(item_id)
        ids.append(item_id)
    if ids != sorted(ids):
        raise CorpusGovernanceError("contamination report items are not canonically ordered")
    if manifest is not None:
        governed = canonical_manifest(manifest)
        if governed["role"] != "sealed_held_out" or (governed["set_id"], governed["version"]) != (set_id, version):
            raise CorpusGovernanceError("contamination report does not match its manifest")
        members = {item["item_id"]: item for item in governed["items"]}
        for finding in values:
            member = members.get(finding["item_id"])
            if member is None or member["state"] != "active" or (member["source_sha256"], member["gold_sha256"]) != (finding["source_sha256"], finding["gold_sha256"]):
                raise CorpusGovernanceError("contamination report does not match active held-out membership")
    return ids


def apply_contamination_report(manifest: Any, report: Any, *, new_version: str) -> dict[str, Any]:
    previous = canonical_manifest(manifest)
    if previous["role"] != "sealed_held_out" or previous["state"] != "sealed":
        raise CorpusGovernanceError("only an active sealed held-out manifest can receive contamination")
    report_ids = validate_contamination_report(report, set_identity=manifest_identity(previous))
    reported = {item["item_id"]: item for item in report["items"]}
    current_items = {item["item_id"]: item for item in previous["items"]}
    if any(item_id not in current_items for item_id in report_ids):
        raise CorpusGovernanceError("contamination report references an unknown held-out item")
    next_items = []
    for item in previous["items"]:
        updated = dict(item)
        finding = reported.get(item["item_id"])
        if finding is not None:
            if (finding["source_sha256"], finding["gold_sha256"]) != (item["source_sha256"], item["gold_sha256"]):
                raise CorpusGovernanceError("contamination report hashes do not match held-out membership")
            if item["state"] != "active":
                raise CorpusGovernanceError("contamination report cannot reactivate or rewrite historical membership")
            updated["state"] = "contaminated"
        next_items.append(updated)
    transition = build_manifest(
        set_id=previous["set_id"], role=previous["role"], version=new_version, state="contaminated",
        items=next_items, provenance=previous["provenance"], predecessor=_manifest_predecessor(previous),
    )
    return validate_transition(previous, transition)


def load_manifest(path: Path) -> dict[str, Any]:
    """Load canonical JSON while rejecting symlink and traversal ambiguity."""

    raw_path = Path(path).expanduser()
    if ".." in raw_path.parts:
        raise CorpusGovernanceError("governed corpus manifest path cannot contain traversal")
    absolute = raw_path.absolute()
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        if current.is_symlink():
            raise CorpusGovernanceError("governed corpus manifest path contains a symlink")
    if not absolute.is_file():
        raise CorpusGovernanceError("governed corpus manifest is missing")
    try:
        raw = absolute.read_bytes()
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CorpusGovernanceError("governed corpus manifest is unreadable or malformed") from exc
    canonical = canonical_manifest(value)
    if raw != canonical_bytes(canonical) + b"\n":
        raise CorpusGovernanceError("governed corpus manifest serialization is not canonical")
    return canonical


def validate_role_purpose(role: str, purpose: str) -> None:
    if role not in CORPUS_ROLES:
        raise CorpusGovernanceError("unknown governed corpus role")
    if purpose not in EVALUATION_PURPOSES or purpose not in ALLOWED_PURPOSES_BY_ROLE[role]:
        raise CorpusGovernanceError("evaluation purpose is not allowed for this corpus role")
