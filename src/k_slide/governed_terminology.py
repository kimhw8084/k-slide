"""Platform-neutral governed termbase authority contract and resolver."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol

from .errors import ErrorCode, KSlideError
from .terminology import TermRecord, Termbase, load_termbase, merge_termbases


GOVERNED_TERMBASE_SCHEMA_VERSION = "1.0"
TERMBASE_IDENTITY_SCHEMA_VERSION = "2.0"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IDENTITY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@+-]{0,255}$")
_FORBIDDEN = ("access", "secret", "token", "password", "credential", "source_text", "translation", "content")


def _invalid(message: str, details: dict[str, Any] | None = None) -> KSlideError:
    return KSlideError(ErrorCode.SCHEMA_INVALID, message, details or {})


def _identity(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _IDENTITY.fullmatch(value) or any(word in value.lower() for word in _FORBIDDEN):
        raise _invalid(f"Termbase {label} is invalid.")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value.lower()):
        raise _invalid(f"Termbase {label} must be a SHA-256 digest.")
    return value.lower()


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise _invalid("Governed termbase source is missing or symlinked.", {"path": path.name})
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
    except (OSError, UnicodeError) as exc:
        raise _invalid("Governed termbase source could not be read.", {"path": path.name}) from exc
    return digest.hexdigest()


def _safe_source(root: Path, raw: str, *, package_core: Path | None = None) -> Path:
    relative = Path(raw).expanduser()
    if relative.is_absolute() and package_core is not None and relative.resolve() == package_core.resolve():
        return relative.resolve()
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise _invalid("Termbase authority source path must be relative and stay inside the project.")
    if relative == Path(".k-slide-config/termbase.local.json"):
        raise _invalid("Generic local termbase overrides cannot be governed production sources.")
    allowed_prefixes = (Path("termbase"), Path(".k-slide-engine/termbase"))
    if not any(relative == prefix or prefix in relative.parents for prefix in allowed_prefixes):
        raise _invalid("Governed termbase sources must be inside a termbase directory.")
    current = root
    for component in relative.parts:
        current = current / component
        if current.is_symlink():
            raise _invalid("Termbase authority source path must not traverse symlinks.")
    resolved = current.resolve()
    if package_core is not None and resolved == package_core.resolve():
        return resolved
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise _invalid("Termbase authority source path escapes the project.") from exc
    return resolved


@dataclass(frozen=True)
class GovernedTermbaseSource:
    """Authority-declared content-addressed source; path is only a lookup hint."""

    identity: str
    version: str
    sha256: str
    path: str
    scope: str = "core"
    scope_ref: str = "core"
    parent_scope_ref: str | None = None
    authorization_identity: str | None = None

    @property
    def rank(self) -> int:
        return {"core": 0, "bu": 1, "team": 2}[self.scope]

    def as_identity(self, *, order: int | None = None) -> dict[str, Any]:
        result: dict[str, Any] = {
            "identity": self.identity,
            "version": self.version,
            "sha256": self.sha256,
            "scope": self.scope,
            "scope_ref": self.scope_ref,
            "parent_scope_ref": self.parent_scope_ref,
        }
        if self.authorization_identity is not None:
            result["authorization_identity"] = self.authorization_identity
        if order is not None:
            result["order"] = order
        return result


@dataclass(frozen=True)
class TermbaseGovernance:
    """Explicit deployment/workspace authority contract, not an IAM system."""

    governance_identity: str
    policy_identity: str
    authorization_identity: str
    core: GovernedTermbaseSource
    overlays: tuple[GovernedTermbaseSource, ...] = ()
    overlay_order: tuple[str, ...] = ()
    order_identity: str = "single"
    schema_version: str = GOVERNED_TERMBASE_SCHEMA_VERSION

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "TermbaseGovernance":
        if not isinstance(value, Mapping):
            raise _invalid("Termbase governance authority must be an object.")
        schema = str(value.get("schema_version", GOVERNED_TERMBASE_SCHEMA_VERSION))
        if schema != GOVERNED_TERMBASE_SCHEMA_VERSION:
            raise _invalid("Unsupported termbase governance schema.")
        core_value = value.get("core")
        overlay_values = value.get("overlays", [])
        if not isinstance(core_value, Mapping) or not isinstance(overlay_values, list):
            raise _invalid("Termbase governance must declare one core and an overlay array.")
        overlays = tuple(_source_from_mapping(item, label=f"overlay-{index}", default_scope=None, authorized=True) for index, item in enumerate(overlay_values))
        order = value.get("overlay_order", [item.identity for item in overlays])
        if not isinstance(order, list) or any(not isinstance(item, str) for item in order):
            raise _invalid("Termbase overlay order must be an array of identities.")
        order_identity = value.get("order_identity", "single" if len(overlays) < 2 else None)
        if len(overlays) >= 2 and not order_identity:
            raise _invalid("Multiple termbase overlays require an authorized order identity.")
        return cls(
            governance_identity=_identity(value.get("governance_identity", value.get("identity")), "governance identity"),
            policy_identity=_identity(value.get("policy_identity"), "policy identity"),
            authorization_identity=_identity(value.get("authorization_identity", value.get("authorization_ref")), "authorization identity"),
            core=_source_from_mapping(core_value, label="core", default_scope="core", authorized=False),
            overlays=overlays,
            overlay_order=tuple(order),
            order_identity=_identity(order_identity, "order identity"),
            schema_version=schema,
        )

    def as_mapping(self) -> dict[str, Any]:
        def source(item: GovernedTermbaseSource) -> dict[str, Any]:
            value = item.as_identity()
            value["path"] = item.path
            return value

        return {
            "schema_version": self.schema_version,
            "governance_identity": self.governance_identity,
            "policy_identity": self.policy_identity,
            "authorization_identity": self.authorization_identity,
            "core": source(self.core),
            "overlays": [source(item) for item in self.overlays],
            "overlay_order": list(self.overlay_order),
            "order_identity": self.order_identity,
        }


class TermbaseGovernanceAdapter(Protocol):
    """Deployment-owned resolver; authentication remains outside K-Slide."""

    def resolve_termbase_governance(self, project_root: Path) -> TermbaseGovernance | Mapping[str, Any]: ...


def _source_from_mapping(value: Mapping[str, Any], *, label: str, default_scope: str | None, authorized: bool) -> GovernedTermbaseSource:
    if not isinstance(value, Mapping):
        raise _invalid(f"Termbase {label} descriptor must be an object.")
    scope = str(value.get("scope", default_scope or "")).strip().lower().replace("business_unit", "bu").replace("business-unit", "bu")
    if scope not in {"core", "bu", "team"} or (default_scope is not None and scope != default_scope):
        raise _invalid(f"Termbase {label} scope metadata is invalid.")
    scope_ref = value.get("scope_ref", value.get("scope_id", "core" if scope == "core" else None))
    if not isinstance(scope_ref, str) or not _IDENTITY.fullmatch(scope_ref) or "/" in scope_ref:
        raise _invalid(f"Termbase {label} scope reference is invalid.")
    parent = value.get("parent_scope_ref", value.get("parent_scope_id"))
    if scope == "team" and (not isinstance(parent, str) or not _IDENTITY.fullmatch(parent)):
        raise _invalid(f"Termbase {label} team overlay must declare its BU parent.")
    if scope != "team" and parent is not None:
        raise _invalid(f"Termbase {label} has unexpected parent scope metadata.")
    authorization = value.get("authorization_identity", value.get("authorization_ref"))
    if authorized:
        authorization = _identity(authorization, f"{label} authorization identity")
    elif authorization is not None:
        authorization = _identity(authorization, f"{label} authorization identity")
    path = value.get("path")
    if not isinstance(path, str) or not path.strip():
        raise _invalid(f"Termbase {label} source path is missing.")
    return GovernedTermbaseSource(
        identity=_identity(value.get("identity", value.get("source_id")), f"{label} identity"),
        version=_identity(value.get("version"), f"{label} version"),
        sha256=_digest(value.get("sha256", value.get("hash")), f"{label} source"),
        path=path,
        scope=scope,
        scope_ref=scope_ref,
        parent_scope_ref=parent,
        authorization_identity=authorization,
    )


def _default_core(root: Path) -> tuple[Path, GovernedTermbaseSource]:
    package_core = Path(__file__).resolve().parents[2] / "termbase" / "core.json"
    for path in (root / "termbase" / "core.json", root / ".k-slide-engine" / "termbase" / "core.json", package_core):
        if path.is_symlink():
            raise _invalid("Termbase core must not be symlinked.")
        if path != package_core:
            try:
                _safe_source(root, str(path.relative_to(root)), package_core=package_core)
            except ValueError:
                raise _invalid("Termbase core path is outside the project.")
        if path.is_file():
            parsed = load_termbase(path)
            digest = _sha256_file(path)
            source_path = str(path.relative_to(root)) if path != package_core else str(path)
            return path, GovernedTermbaseSource("core-" + digest[:16], parsed.version, digest, source_path, "core", "core")
    raise _invalid("Centrally governed core termbase is unavailable.")


def _coerce_authority(root: Path, authority: TermbaseGovernance | Mapping[str, Any] | TermbaseGovernanceAdapter) -> TermbaseGovernance:
    if isinstance(authority, TermbaseGovernance):
        return TermbaseGovernance.from_mapping(authority.as_mapping())
    if isinstance(authority, Mapping):
        return TermbaseGovernance.from_mapping(authority)
    resolver = getattr(authority, "resolve_termbase_governance", None) or getattr(authority, "resolve", None)
    if not callable(resolver):
        raise _invalid("Termbase governance adapter is not callable.")
    resolved = resolver(root)
    return resolved if isinstance(resolved, TermbaseGovernance) else TermbaseGovernance.from_mapping(resolved)


def _default_governance(root: Path) -> tuple[TermbaseGovernance, Path]:
    path, core = _default_core(root)
    return TermbaseGovernance("repository-core-v1", "repository-core-policy-v1", "repository-core-authority-v1", core), path


def _check_unexpected_material(root: Path, expected: set[Path]) -> None:
    paths: list[Path] = [root / ".k-slide-config" / "termbase.local.json"]
    if (root / ".k-slide-config").is_symlink():
        raise _invalid("Termbase configuration directory must not be symlinked.")
    for directory in (
        root / "termbase" / "overlays",
        root / ".k-slide-engine" / "termbase" / "overlays",
        root / ".k-slide-config" / "termbase-overlays",
    ):
        if directory.is_symlink():
            raise _invalid("Termbase overlay directory must not be symlinked.")
        if directory.is_dir():
            paths.extend(path for path in directory.rglob("*") if path.is_file() or path.is_symlink())
    for path in paths:
        if path.exists() or path.is_symlink():
            if path.is_symlink() or path.resolve() not in expected:
                raise _invalid("Unexpected or unauthorized termbase overlay material is present.")


def _load_sources(root: Path, governance: TermbaseGovernance) -> tuple[tuple[GovernedTermbaseSource, Termbase], tuple[tuple[GovernedTermbaseSource, Termbase], ...]]:
    if governance.core.scope != "core" or governance.core.scope_ref != "core":
        raise _invalid("Governed termbase core scope metadata is invalid.")
    if len({item.identity for item in governance.overlays}) != len(governance.overlays):
        raise _invalid("Governed termbase overlay identities must be unique.")
    if len({(item.identity, item.version, item.sha256) for item in governance.overlays}) != len(governance.overlays):
        raise _invalid("Governed termbase overlay identity/version/hash tuples must be unique.")
    scopes: dict[str, tuple[str, str | None]] = {}
    for item in governance.overlays:
        metadata = (item.scope, item.parent_scope_ref)
        if item.scope_ref in scopes and scopes[item.scope_ref] != metadata:
            raise _invalid("Governed termbase scope metadata conflicts.")
        scopes[item.scope_ref] = metadata
    bus = {item.scope_ref for item in governance.overlays if item.scope == "bu"}
    for item in governance.overlays:
        if item.scope == "team" and item.parent_scope_ref not in bus:
            raise _invalid("Governed team overlay has an unresolved BU parent.")
    identities = {item.identity for item in governance.overlays}
    if set(governance.overlay_order) != identities or len(governance.overlay_order) != len(identities):
        raise _invalid("Governed termbase overlay order is incomplete or ambiguous.")
    by_identity = {item.identity: item for item in governance.overlays}
    if any(by_identity[governance.overlay_order[index]].rank > by_identity[governance.overlay_order[index + 1]].rank for index in range(len(governance.overlay_order) - 1)):
        raise _invalid("Governed termbase overlay order violates core/BU/team hierarchy.")
    order_positions = {item: index for index, item in enumerate(governance.overlay_order)}
    for item in governance.overlays:
        if item.scope == "team" and any(parent.scope == "bu" and parent.scope_ref == item.parent_scope_ref and order_positions[item.identity] <= order_positions[parent.identity] for parent in governance.overlays):
            raise _invalid("Governed team overlay is ordered before its BU parent.")
    package_core = Path(__file__).resolve().parents[2] / "termbase" / "core.json"
    expected_paths: set[Path] = set()
    loaded: list[tuple[GovernedTermbaseSource, Termbase]] = []
    for source in (governance.core, *governance.overlays):
        path = _safe_source(root, source.path, package_core=package_core)
        expected_paths.add(path.resolve())
        if _sha256_file(path) != source.sha256:
            raise _invalid("Governed termbase source content hash does not match authority.")
        parsed = load_termbase(path)
        if parsed.version != source.version:
            raise _invalid("Governed termbase source version does not match authority.")
        loaded.append((source, parsed))
    _check_unexpected_material(root, expected_paths)
    return (loaded[0],), tuple(loaded[1:])


def _record_identity(record: TermRecord) -> dict[str, Any]:
    return {
        "source": record.source,
        "preferred": {key: record.preferred[key] for key in sorted(record.preferred)},
        "status": record.status,
        "scope": sorted(record.scope),
        "avoid": sorted(record.avoid),
        "term_id": record.term_id,
    }


def _merge(core: tuple[GovernedTermbaseSource, Termbase], overlays: tuple[tuple[GovernedTermbaseSource, Termbase], ...], governance: TermbaseGovernance) -> Termbase:
    ordered = [core, *sorted(overlays, key=lambda item: governance.overlay_order.index(item[0].identity))]
    merged: dict[str, tuple[TermRecord, int, str]] = {}
    term_ids: set[str] = set()
    for source, termbase in ordered:
        for record in termbase.records:
            if record.term_id is not None:
                if record.term_id in term_ids:
                    raise _invalid("Governed termbase term_id is duplicated across sources.")
                term_ids.add(record.term_id)
            existing = merged.get(record.source)
            if existing is None:
                merged[record.source] = (record, source.rank, source.identity)
                continue
            prior, prior_rank, prior_source = existing
            if prior_rank == source.rank:
                raise _invalid("Same-precedence governed termbase records are ambiguous.")
            if prior_rank > source.rank:
                if prior.status == "LOCKED" and prior.as_dict() != record.as_dict():
                    raise _invalid("A lower-authority termbase cannot override a higher-authority LOCKED term.")
                raise _invalid("Governed termbase hierarchy is not monotonic.")
            if prior.status == "LOCKED":
                raise _invalid("A higher-authority overlay cannot override a LOCKED term.", {"locked_source": prior_source})
            merged[record.source] = (record, source.rank, source.identity)
    effective = tuple(value[0] for value in merged.values())
    authority = {
        "governance_identity": governance.governance_identity,
        "policy_identity": governance.policy_identity,
        "authorization_identity": governance.authorization_identity,
        "order_identity": governance.order_identity,
    }
    overlay_identity = [source.as_identity(order=index) for index, identity in enumerate(governance.overlay_order) for source, _ in overlays if source.identity == identity]
    effective_hash = _sha256_bytes(_canonical(sorted((_record_identity(record) for record in effective), key=lambda item: (item["source"], item["term_id"] or ""))))
    identity_payload = {
        "schema_version": TERMBASE_IDENTITY_SCHEMA_VERSION,
        "authority": authority,
        "core": core[0].as_identity(),
        "overlays": overlay_identity,
        "overlay_order": list(governance.overlay_order),
        "effective_hash": effective_hash,
    }
    identity = {
        "schema_version": TERMBASE_IDENTITY_SCHEMA_VERSION,
        **authority,
        "version": core[1].version,
        "hash": _sha256_bytes(_canonical(identity_payload)),
        "core": core[0].as_identity(),
        "core_identity": core[0].identity,
        "overlays": overlay_identity,
        "overlay_order": list(governance.overlay_order),
        "effective_hash": effective_hash,
    }
    return Termbase(core[1].version, effective, "governed", identity)


def resolve_governed_termbase(root: Path, *, authority: TermbaseGovernance | Mapping[str, Any] | TermbaseGovernanceAdapter | None = None) -> Termbase:
    """Resolve core plus explicitly authorized overlays, failing closed."""

    root = root.expanduser().resolve()
    if authority is None:
        governance, _ = _default_governance(root)
        if (root / ".k-slide-config" / "termbase.local.json").exists():
            raise _invalid("Generic local termbase overrides are non-authoritative and cannot enter production resolution.")
    else:
        governance = _coerce_authority(root, authority)
    core, overlays = _load_sources(root, governance)
    return _merge(core[0], overlays, governance)


def load_reference_termbase(root: Path, *, run_override: Path) -> Termbase:
    """Explicit non-authoritative fixture path for development/reference use."""

    root = root.expanduser().resolve()
    core_path, _ = _default_core(root)
    overlay = run_override.expanduser()
    if overlay.is_symlink() or not overlay.is_file():
        raise _invalid("Reference termbase overlay is missing or symlinked.")
    return merge_termbases(load_termbase(core_path), load_termbase(overlay))


def materialize_governed_termbase(
    source_root: Path,
    target_root: Path,
    authority: TermbaseGovernance | Mapping[str, Any] | TermbaseGovernanceAdapter,
) -> tuple[Path, ...]:
    """Copy only authority-declared sources into an isolated workspace.

    The target is expected to be disposable. Existing files are accepted only
    when their content hash is exactly the authority-declared hash.
    """

    source_root = source_root.expanduser().resolve()
    target_root = target_root.expanduser().resolve()
    governance = _coerce_authority(source_root, authority)
    package_core = Path(__file__).resolve().parents[2] / "termbase" / "core.json"
    materialized: list[Path] = []
    for source in (governance.core, *governance.overlays):
        source_path = _safe_source(source_root, source.path, package_core=package_core)
        if _sha256_file(source_path) != source.sha256:
            raise _invalid("Governed termbase source content drifted before materialization.")
        relative = Path(source.path)
        if relative.is_absolute():
            try:
                relative = source_path.relative_to(source_root)
            except ValueError:
                raise _invalid("Governed termbase source cannot be materialized outside the target project.")
        destination = target_root / relative
        current = target_root
        for component in relative.parts:
            current = current / component
            if current.is_symlink():
                raise _invalid("Governed termbase destination must not traverse symlinks.")
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        created = False
        if destination.exists() or destination.is_symlink():
            if destination.is_symlink() or _sha256_file(destination) != source.sha256:
                raise _invalid("Isolated workspace contains unexpected termbase material.")
        else:
            try:
                destination.write_bytes(source_path.read_bytes())
                destination.chmod(0o600)
                created = True
            except (OSError, UnicodeError) as exc:
                raise _invalid("Governed termbase could not be materialized.") from exc
        if created:
            materialized.append(destination)
    return tuple(materialized)
