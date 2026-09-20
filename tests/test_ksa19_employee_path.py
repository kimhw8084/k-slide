from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from dataclasses import replace
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from k_slide.cli import _evidence, _next, _submit, main
from k_slide.certification import effective_termbase_identity
from k_slide.environment import RunEnvironmentIdentity
from k_slide.errors import KSlideError
from k_slide.execution import WorkspaceRunStore
from k_slide.evidence_ir import EvidenceIR, EvidenceRegion, save_evidence
from k_slide.ingest import prepare_run
from k_slide.queue import WorkUnitStatus, load_queue, save_queue
from k_slide.state import RunPhase, load_state, save_state
from k_slide.verify import verify_run
from tests.reference_fixtures import reference_environment


def _write(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class EmployeeGovernedTermbasePathTests(unittest.TestCase):
    def _fixture(self, *, with_team: bool = True) -> tuple[tempfile.TemporaryDirectory[str], Path, Path, dict, dict, RunEnvironmentIdentity]:
        holder = tempfile.TemporaryDirectory()
        root = Path(holder.name)
        core = root / "termbase" / "core.json"
        bu = root / "termbase" / "overlays" / "sales.json"
        team = root / "termbase" / "overlays" / "sales-team.json"
        _write(core, {"version": "1.0", "records": [{"term_id": "core-locked", "source": "고정", "preferred": {"default": "LockedTerm"}, "status": "LOCKED"}]})
        _write(bu, {"version": "2.0", "records": [{"term_id": "bu-sales", "source": "사업", "preferred": {"default": "Business"}, "status": "PREFERRED"}]})
        overlays = [{"identity": "bu-sales-v2", "version": "2.0", "path": "termbase/overlays/sales.json", "scope": "BU", "scope_ref": "sales"}]
        if with_team:
            _write(team, {"version": "3.0", "records": [{"term_id": "team-sales", "source": "팀", "preferred": {"default": "Team"}, "status": "PREFERRED"}]})
            overlays.append({"identity": "team-sales-v3", "version": "3.0", "path": "termbase/overlays/sales-team.json", "scope": "team", "scope_ref": "sales-team", "parent_scope_ref": "sales"})
        authority = {
            "governance_identity": "company-governance-v1",
            "policy_identity": "company-termbase-policy-v1",
            "authorization_identity": "workspace-authority-v1",
            "core": {"identity": "company-core-v1", "version": "1.0", "sha256": _sha(core), "path": "termbase/core.json"},
            "overlays": [{**item, "sha256": _sha(root / item["path"]), "authorization_identity": f"auth-{item['identity']}"} for item in overlays],
            "overlay_order": [item["identity"] for item in overlays],
            "order_identity": "authorized-order-v1" if len(overlays) > 1 else "single",
        }
        identity = effective_termbase_identity(root, termbase_authority=authority)
        candidate = {
            "candidate_spec_version": "1.1",
            "subject_git_sha": "a" * 40,
            "requested_model": "google/gemma-4-31b-it",
            "termbase_identity": identity,
            "termbase_hash": identity["hash"],
            "termbase_version": identity["version"],
            "termbase_governance": authority,
        }
        _write(root / ".k-slide-config" / "production-candidate.json", candidate)
        environment = replace(reference_environment(), ocr_provider="approved-ocr", termbase_identity=identity["hash"], termbase_version=identity["version"])
        source = root / "slide.png"
        source.write_bytes(b"\x89PNG\r\n\x1a\nfixture")
        run = prepare_run(root, explicit_paths=[str(source)], environment_identity=environment)
        queue = load_queue(run)
        unit = queue.work_units[0]
        region_id = f"{unit.work_unit_id}-r001"
        evidence = EvidenceIR(
            "doc-employee",
            unit.work_unit_id,
            {"input_id": unit.source_input_id, "width_px": 100, "height_px": 100, "context_image_path": "normalized/context.png"},
            (EvidenceRegion(region_id, (0, 0, 100, 100), (0, 0, 1, 1), selected_literal_candidate="고정", literal_confidence=1.0),),
            required_source_ids=(region_id,),
        ).with_revision()
        save_evidence(run, evidence)
        unit.status = WorkUnitStatus.READY
        unit.evidence_revision = evidence.evidence_revision
        save_queue(run, queue)
        state = load_state(run)
        state.transition(RunPhase.NORMALIZED)
        state.transition(RunPhase.EXTRACTED)
        save_state(run, state)
        return holder, root, run, candidate, authority, environment

    def _translate(self, root: Path, run: Path, environment: RunEnvironmentIdentity, *, english: str) -> dict:
        next_value = _next(root, run.name, None, environment)
        self.assertEqual(next_value["status"], "READY")
        evidence = json.loads((run / "evidence" / f"{next_value['work_unit_id']}.json").read_text(encoding="utf-8"))
        payload = {
            "schema_version": "1.0",
            "work_unit_id": next_value["work_unit_id"],
            "evidence_revision": evidence["evidence_revision"],
            "regions": [{"region_id": next_value["work_unit_id"] + "-r001", "english": english, "term_ids": [], "unresolved": False}],
            "tables": [],
            "visual_interpretations": [],
            "executive_claims": [],
        }
        return _submit(root, run.name, json.dumps(payload), None, environment)

    def test_cli_evidence_packet_uses_exact_bu_and_team_authority(self) -> None:
        holder, root, run, _candidate, _authority, environment = self._fixture(with_team=True)
        try:
            packet = _evidence(root, run.name, None, environment)
            self.assertEqual(packet["status"], "NOT_READY")
            self.assertEqual(_next(root, run.name, None, environment)["status"], "READY")
            packet = _evidence(root, run.name, None, environment)
            self.assertEqual(packet["status"], "EVIDENCE_READY")
            self.assertEqual(packet["termbase_identity"], effective_termbase_identity(root, termbase_authority=_authority))
            self.assertEqual({item["source"] for item in packet["terminology"]}, {"고정", "사업", "팀"})
            self.assertEqual(packet["model_media_plan"]["context_image"]["path"].split("/")[0], ".k-slide-runs")
            serialized = json.dumps(packet, ensure_ascii=False)
            self.assertNotIn("termbase/overlays", serialized)
            self.assertNotIn("production-candidate", serialized)
            self.assertNotIn("termbase.local", serialized)
            self.assertNotIn("AccessKey", serialized)
            output = StringIO()
            job = WorkspaceRunStore(run).load(f"job-{run.name}")
            with patch("k_slide.cli.ensure_workspace_environment_compatible", return_value=(job, environment)), redirect_stdout(output):
                self.assertEqual(main(["evidence", "--root", str(root), "--run", run.name, "--json"]), 0)
            self.assertEqual(json.loads(output.getvalue())["termbase_identity"], packet["termbase_identity"])
        finally:
            holder.cleanup()

    def test_real_verify_and_finalize_reuse_bound_authority_and_locked_term(self) -> None:
        holder, root, run, _candidate, _authority, environment = self._fixture(with_team=True)
        try:
            accepted = self._translate(root, run, environment, english="LockedTerm")
            self.assertEqual(accepted["status"], "ACCEPTED")
            for name, content in {"05_executive_brief.md": "# brief\n", "05_final_report.md": "# report\n", "07_unresolved_items.md": "No unresolved items.\n"}.items():
                (run / name).write_text(content, encoding="utf-8")
            job = WorkspaceRunStore(run).load(f"job-{run.name}")
            verify_output = StringIO()
            with patch("k_slide.execution.ensure_workspace_environment_compatible", return_value=(job, environment)), redirect_stdout(verify_output):
                self.assertEqual(main(["verify", "--root", str(root), "--run", run.name, "--json"]), 0)
            self.assertEqual(json.loads(verify_output.getvalue())["status"], "PASS")
            finalize_output = StringIO()
            with patch("k_slide.execution.ensure_workspace_environment_compatible", return_value=(job, environment)), redirect_stdout(finalize_output):
                self.assertEqual(main(["finalize", "--root", str(root), "--run", run.name, "--json"]), 0)
            self.assertEqual(json.loads(finalize_output.getvalue())["status"], "PASS")
            self.assertTrue((run / "RUN_COMPLETE.md").is_file())
        finally:
            holder.cleanup()

    def test_bound_authority_rejects_locked_mismatch_and_material_drift(self) -> None:
        holder, root, run, candidate, authority, environment = self._fixture(with_team=False)
        try:
            self._translate(root, run, environment, english="WrongTerm")
            for name, content in {"05_executive_brief.md": "# brief\n", "05_final_report.md": "# report\n", "07_unresolved_items.md": "No unresolved items.\n"}.items():
                (run / name).write_text(content, encoding="utf-8")
            result = verify_run(run, environment_identity=environment)
            self.assertFalse(result.passed)
            self.assertIn("KSLIDE_LOCKED_TERM_MISMATCH", {issue.code for issue in result.issues})

            cases = {
                "core": lambda: (root / "termbase" / "core.json").write_text(json.dumps({"version": "1.0", "records": [{"term_id": "core-locked", "source": "고정", "preferred": {"default": "Changed"}, "status": "LOCKED"}]}), encoding="utf-8"),
                "overlay": lambda: (root / "termbase" / "overlays" / "sales.json").write_text(json.dumps({"version": "2.0", "records": [{"term_id": "bu-sales", "source": "사업", "preferred": {"default": "Changed"}, "status": "PREFERRED"}]}), encoding="utf-8"),
                "local": lambda: _write(root / ".k-slide-config" / "termbase.local.json", {"version": "1.0", "records": [{"source": "비공개", "preferred": {"default": "Private"}}]}),
                "extra": lambda: _write(root / "termbase" / "overlays" / "unexpected.json", {"version": "1.0", "records": []}),
            }
            for name, mutate in cases.items():
                with self.subTest(material=name):
                    mutate()
                    with self.assertRaises(KSlideError):
                        _evidence(root, run.name, None, environment)
                    # Restore the authoritative fixture for the next case.
                    _write(root / "termbase" / "core.json", {"version": "1.0", "records": [{"term_id": "core-locked", "source": "고정", "preferred": {"default": "LockedTerm"}, "status": "LOCKED"}]})
                    _write(root / "termbase" / "overlays" / "sales.json", {"version": "2.0", "records": [{"term_id": "bu-sales", "source": "사업", "preferred": {"default": "Business"}, "status": "PREFERRED"}]})
                    (root / ".k-slide-config" / "termbase.local.json").unlink(missing_ok=True)
                    (root / "termbase" / "overlays" / "unexpected.json").unlink(missing_ok=True)
            self.assertEqual(candidate["termbase_identity"], effective_termbase_identity(root, termbase_authority=authority))
        finally:
            holder.cleanup()


if __name__ == "__main__":
    unittest.main()
