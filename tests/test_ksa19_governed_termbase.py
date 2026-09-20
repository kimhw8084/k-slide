from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from k_slide.certification import EvidenceValidationError, effective_termbase_identity, resolve_candidate_spec
from k_slide.errors import KSlideError
from k_slide.governed_terminology import TermbaseGovernance, resolve_governed_termbase
from k_slide.evidence_ir import EvidenceIR
from k_slide.model import build_work_packet
from k_slide.terminology import load_effective_termbase


def _write(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class GovernedTermbaseTests(unittest.TestCase):
    def _root(self) -> tuple[tempfile.TemporaryDirectory[str], Path, Path]:
        holder = tempfile.TemporaryDirectory()
        root = Path(holder.name)
        core = root / "termbase" / "core.json"
        _write(core, {"version": "1.0", "records": [{"term_id": "core-1", "source": "용어", "preferred": {"default": "core"}, "status": "PREFERRED"}]})
        return holder, root, core

    def _governance(self, root: Path, core: Path, overlays: list[dict]) -> dict:
        descriptors = []
        for item in overlays:
            path = root / item["path"]
            descriptors.append({**item, "sha256": _sha(path), "authorization_identity": item.get("authorization_identity", f"auth-{item['identity']}")})
        return {
            "governance_identity": "company-governance-v1",
            "policy_identity": "company-termbase-policy-v1",
            "authorization_identity": "workspace-authority-v1",
            "core": {"identity": "company-core-v1", "version": "1.0", "sha256": _sha(core), "path": "termbase/core.json"},
            "overlays": descriptors,
            "overlay_order": [item["identity"] for item in descriptors],
            "order_identity": "authorized-order-v1" if len(descriptors) > 1 else "single",
        }

    def test_core_only_is_governed_and_relocation_is_identity_stable(self) -> None:
        holder, root, core = self._root()
        try:
            first = effective_termbase_identity(root)
            self.assertEqual(first["governance_identity"], "repository-core-v1")
            self.assertEqual(first["core"]["sha256"], _sha(core))
            self.assertNotIn("path", first)
            moved = Path(tempfile.mkdtemp())
            (moved / "termbase").mkdir()
            (moved / "termbase" / "core.json").write_bytes(core.read_bytes())
            self.assertEqual(first, effective_termbase_identity(moved))
        finally:
            holder.cleanup()

    def test_authorized_bu_and_team_overlays_follow_hierarchy(self) -> None:
        holder, root, core = self._root()
        try:
            bu = root / "termbase" / "overlays" / "sales.json"
            team = root / "termbase" / "overlays" / "sales-team.json"
            _write(bu, {"version": "2.0", "records": [{"term_id": "bu-1", "source": "용어", "preferred": {"default": "business"}, "status": "PREFERRED"}]})
            _write(team, {"version": "3.0", "records": [{"term_id": "team-1", "source": "용어", "preferred": {"default": "team"}, "status": "PREFERRED"}]})
            authority = self._governance(root, core, [
                {"identity": "bu-sales-v2", "version": "2.0", "path": "termbase/overlays/sales.json", "scope": "BU", "scope_ref": "sales"},
                {"identity": "team-sales-v3", "version": "3.0", "path": "termbase/overlays/sales-team.json", "scope": "team", "scope_ref": "sales-team", "parent_scope_ref": "sales"},
            ])
            resolved = resolve_governed_termbase(root, authority=authority)
            self.assertEqual(resolved.resolve("용어").default, "team")
            self.assertEqual([item["identity"] for item in resolved.binding_identity["overlays"]], ["bu-sales-v2", "team-sales-v3"])
        finally:
            holder.cleanup()

    def test_lower_scope_refinement_is_allowed_but_locked_higher_scope_is_not(self) -> None:
        holder, root, core = self._root()
        try:
            bu = root / "termbase" / "overlays" / "sales.json"
            _write(bu, {"version": "2.0", "records": [{"term_id": "bu-1", "source": "용어", "preferred": {"default": "business"}, "status": "PREFERRED"}]})
            authority = self._governance(root, core, [{"identity": "bu-sales-v2", "version": "2.0", "path": "termbase/overlays/sales.json", "scope": "BU", "scope_ref": "sales"}])
            self.assertEqual(resolve_governed_termbase(root, authority=authority).resolve("용어").default, "business")
            _write(core, {"version": "1.0", "records": [{"term_id": "core-1", "source": "용어", "preferred": {"default": "core"}, "status": "LOCKED"}]})
            with self.assertRaises(KSlideError):
                resolve_governed_termbase(root, authority=authority)
        finally:
            holder.cleanup()

    def test_same_precedence_duplicate_identity_scope_and_order_fail_closed(self) -> None:
        holder, root, core = self._root()
        try:
            first = root / "termbase" / "overlays" / "one.json"
            second = root / "termbase" / "overlays" / "two.json"
            _write(first, {"version": "1.0", "records": [{"term_id": "one", "source": "하나", "preferred": {"default": "one"}}]})
            _write(second, {"version": "1.0", "records": [{"term_id": "two", "source": "하나", "preferred": {"default": "two"}}]})
            descriptors = [
                {"identity": "bu-one", "version": "1.0", "path": "termbase/overlays/one.json", "scope": "BU", "scope_ref": "sales"},
                {"identity": "bu-two", "version": "1.0", "path": "termbase/overlays/two.json", "scope": "BU", "scope_ref": "marketing"},
            ]
            with self.assertRaises(KSlideError):
                resolve_governed_termbase(root, authority=self._governance(root, core, descriptors))
            duplicate = self._governance(root, core, [descriptors[0], {**descriptors[1], "identity": "bu-one"}])
            with self.assertRaises(KSlideError):
                resolve_governed_termbase(root, authority=duplicate)
            conflict = self._governance(root, core, [{**descriptors[0], "scope_ref": "same"}, {**descriptors[1], "scope": "team", "scope_ref": "same", "parent_scope_ref": "sales"}])
            with self.assertRaises(KSlideError):
                resolve_governed_termbase(root, authority=conflict)
        finally:
            holder.cleanup()

    def test_missing_authorization_symlink_traversal_and_unexpected_extra_overlay_fail(self) -> None:
        holder, root, core = self._root()
        try:
            overlay = root / "termbase" / "overlays" / "sales.json"
            extra = root / "termbase" / "overlays" / "extra.json"
            _write(overlay, {"version": "1.0", "records": [{"term_id": "bu", "source": "사업", "preferred": {"default": "business"}}]})
            _write(extra, {"version": "1.0", "records": []})
            raw = self._governance(root, core, [{"identity": "bu-sales", "version": "1.0", "path": "termbase/overlays/sales.json", "scope": "BU", "scope_ref": "sales"}])
            raw["overlays"][0].pop("authorization_identity")
            with self.assertRaises(KSlideError):
                resolve_governed_termbase(root, authority=raw)
            valid = self._governance(root, core, [{"identity": "bu-sales", "version": "1.0", "path": "termbase/overlays/sales.json", "scope": "BU", "scope_ref": "sales"}])
            with self.assertRaises(KSlideError):
                resolve_governed_termbase(root, authority=valid)
            extra.unlink()
            valid["overlays"][0]["path"] = "../outside.json"
            with self.assertRaises(KSlideError):
                resolve_governed_termbase(root, authority=valid)
        finally:
            holder.cleanup()

    def test_generic_local_overlay_is_not_authority_but_explicit_reference_fixture_is_available(self) -> None:
        holder, root, core = self._root()
        try:
            local = root / ".k-slide-config" / "termbase.local.json"
            _write(local, {"version": "1.0", "records": [{"source": "비공개", "preferred": {"default": "private"}}]})
            with self.assertRaises(EvidenceValidationError):
                effective_termbase_identity(root)
            fixture = load_effective_termbase(root, run_override=local, authoritative=False)
            self.assertIsNone(fixture.binding_identity)
            self.assertEqual(fixture.resolve("비공개").default, "private")
        finally:
            holder.cleanup()

    def test_candidate_binding_rejects_content_drift_and_plain_hash_is_not_complete_provenance(self) -> None:
        holder, root, core = self._root()
        try:
            before = effective_termbase_identity(root)
            candidate = {"candidate_spec_version": "1.1", "termbase_identity": before, "termbase_hash": before["hash"], "termbase_version": before["version"]}
            resolved = resolve_candidate_spec(candidate, root=root)
            self.assertEqual(resolved["termbase_identity"], before)
            _write(core, {"version": "1.0", "records": [{"term_id": "core-1", "source": "용어", "preferred": {"default": "drift"}, "status": "PREFERRED"}]})
            with self.assertRaises(EvidenceValidationError):
                resolve_candidate_spec(candidate, root=root, require_sources=True)
        finally:
            holder.cleanup()

    def test_termbase_governance_mapping_has_no_paths_in_identity(self) -> None:
        holder, root, core = self._root()
        try:
            overlay = root / "termbase" / "overlays" / "sales.json"
            _write(overlay, {"version": "2.0", "records": [{"term_id": "bu", "source": "사업", "preferred": {"default": "business"}}]})
            authority = self._governance(root, core, [{"identity": "bu-sales", "version": "2.0", "path": "termbase/overlays/sales.json", "scope": "BU", "scope_ref": "sales"}])
            identity = effective_termbase_identity(root, termbase_authority=TermbaseGovernance.from_mapping(authority))
            self.assertNotIn("path", json.dumps(identity))
            self.assertNotIn("사업", json.dumps(identity, ensure_ascii=False))
            self.assertIn("effective_hash", identity)
            self.assertEqual(identity["overlays"][0]["authorization_identity"], "auth-bu-sales")
        finally:
            holder.cleanup()

    def test_model_packet_carries_the_same_bound_identity_as_terminology(self) -> None:
        holder, root, _ = self._root()
        try:
            termbase = resolve_governed_termbase(root)
            packet = build_work_packet(EvidenceIR("doc-1", "unit-1", {}), termbase=termbase)
            self.assertEqual(packet["termbase_identity"], termbase.binding_identity)
            self.assertEqual(packet["terminology"], [record.as_dict() for record in termbase.records])
        finally:
            holder.cleanup()

    def test_certification_bundle_reproduces_governed_lookup_paths_and_identity(self) -> None:
        from evals.build_certification_bundle import build
        from evals.materialize_certification_bundle import materialize

        holder, root, core = self._root()
        try:
            overlay = root / "termbase" / "overlays" / "sales.json"
            _write(overlay, {"version": "2.0", "records": [{"term_id": "bu-1", "source": "사업", "preferred": {"default": "business"}, "status": "PREFERRED"}]})
            authority = self._governance(root, core, [{"identity": "bu-sales-v2", "version": "2.0", "path": "termbase/overlays/sales.json", "scope": "BU", "scope_ref": "sales"}])
            identity = effective_termbase_identity(root, termbase_authority=authority)
            subject = "a" * 40
            candidate_path = root / "candidate.json"
            _write(candidate_path, {"candidate_spec_version": "1.1", "subject_git_sha": subject, "requested_model": "google/gemma-4-31b-it", "termbase_identity": identity, "termbase_governance": authority})
            lock = root / "production.lock"
            lock.write_text("Pillow==1.0\n", encoding="utf-8")
            bundle = root / "bundle"
            build(output=bundle, target_subject_git_sha=subject, candidate_profile=candidate_path, production_dependency_lock=lock, termbase_core=core, termbase_overlays=(overlay,))
            target = root / "checkout"
            materialize(bundle_root=bundle, manifest_path=bundle / "certification-bundle.json", output_root=target, subject_git_sha=subject)
            self.assertEqual(effective_termbase_identity(target, termbase_authority=authority), identity)
        finally:
            holder.cleanup()


if __name__ == "__main__":
    unittest.main()
