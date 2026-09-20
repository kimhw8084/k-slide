from __future__ import annotations

import io
import json
import tempfile
import unittest
import zipfile
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from k_slide.cli import main
from k_slide.content_support import (
    ControlledSupportRequest,
    ReferenceSupportAuthorizationProvider,
    SupportAccessAuditWriter,
    SupportApprovalEvidence,
    SupportApprovalStatus,
    SupportArtifactClass,
    SupportAuthorizationDecision,
    SupportContentSelection,
    SupportDecisionStatus,
    SupportPurpose,
    cleanup_expired_support_content,
    materialize_controlled_support_bundle,
    read_controlled_support_bundle,
)
from k_slide.deletion import DeletionOutcome, LegalHoldStatus, ReferenceLegalHoldProvider, cleanup_operational_metadata, delete_workspace_run
from k_slide.errors import ErrorCode, KSlideError
from k_slide.paas import AuthorizedScopeContext, PaaSController, PaaSJobRequest, ReferencePaaSJobService
from k_slide.retention import cleanup_expired_runs
from k_slide.retention_policy import RetentionPolicy
from k_slide.storage import StorageArtifact, StorageLayout, StoragePlane
from k_slide.support import build_support_bundle
from tests.reference_fixtures import reference_runtime


NOW = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)


def _ts(hour: int) -> str:
    return f"2026-01-01T{hour:02d}:00:00Z"


class KSA20ControlledContentSupportTests(unittest.TestCase):
    def _setup(self) -> tuple[Path, Path, Path, StorageLayout, AuthorizedScopeContext, SupportAccessAuditWriter]:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        operational = root.parent / f"{root.name}-operational"
        operational.mkdir(mode=0o700)
        run = root / ".k-slide-runs" / "run-ksa20"
        run.mkdir(parents=True, mode=0o700)
        layout = StorageLayout.for_workspace(run, central_telemetry_root=operational)
        context = AuthorizedScopeContext("user-ksa20", "workspace-ksa20", "workspace")
        writer = SupportAccessAuditWriter(service_root=operational)
        return root, operational, run, layout, context, writer

    def _request(self, layout: StorageLayout, context: AuthorizedScopeContext, *, expires: str = _ts(23), status: SupportDecisionStatus = SupportDecisionStatus.APPROVED, approval_status: SupportApprovalStatus = SupportApprovalStatus.APPROVED, artifact_class: SupportArtifactClass = SupportArtifactClass.REPORT, relative_path: str = "05_final_report.md") -> tuple[ControlledSupportRequest, ReferenceSupportAuthorizationProvider]:
        decision = SupportAuthorizationDecision(
            access_request_ref="request-ksa20",
            scope_context=context,
            run_ref="run-ksa20",
            support_subject_ref="subject-owner",
            support_role_ref="role-support",
            support_capability_ref="capability-diagnostic",
            purpose=SupportPurpose.INCIDENT_DIAGNOSTIC,
            authority_ref="authority-company-support",
            decision_ref="decision-ksa20",
            approvals=(SupportApprovalEvidence("approval-owner", approval_status),),
            allowed_artifact_classes=(artifact_class,),
            allowed_references=(),
            issued_at=_ts(0),
            not_before_at=_ts(0),
            expires_at=expires,
            status=status,
        )
        request = ControlledSupportRequest(
            decision,
            (SupportContentSelection(artifact_class, layout.reference(StorageArtifact(artifact_class.value), relative_path)),),
        )
        provider = ReferenceSupportAuthorizationProvider()
        provider.add(decision)
        return request, provider

    def test_standard_support_bundle_remains_source_free_and_secret_safe(self) -> None:
        root, _operational, run, _layout, _context, _writer = self._setup()
        (run / "RUN_STATE.json").write_text(json.dumps({"phase": "COMPLETE", "run_id": run.name}), encoding="utf-8")
        (run / "RUN_MANIFEST.json").write_text(json.dumps({"run_id": run.name, "input_count": 1}), encoding="utf-8")
        (run / "WORK_QUEUE.json").write_text(json.dumps({"queue_revision": "q1", "work_units": []}), encoding="utf-8")
        (run / "05_final_report.md").write_text("SOURCE-CANARY Korean 검토 AccessKey=secret prompt", encoding="utf-8")
        output = root / "support.zip"
        result = build_support_bundle(root, output)
        self.assertFalse(result["source_content_included"])
        with zipfile.ZipFile(output) as archive:
            content = archive.read("support-metadata.json").decode("utf-8")
        self.assertNotIn("SOURCE-CANARY", content)
        self.assertNotIn("검토", content)
        self.assertNotIn("AccessKey", content)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)

    def test_authorized_request_materializes_only_explicit_classes_and_redacts_secret_labels(self) -> None:
        _root, _operational, _run, layout, context, writer = self._setup()
        layout.write_text(StorageArtifact.REPORT, "05_final_report.md", "REPORT-CANARY Korean 검토 AccessKey=secret")
        layout.write_text(StorageArtifact.TRANSLATION_PATCH, "translations/unit.json", "TRANSLATION-CANARY")
        request, provider = self._request(layout, context)
        artifact = materialize_controlled_support_bundle(layout, request, authority=provider, audit_writer=writer, now=NOW)
        bundle = read_controlled_support_bundle(layout, request, artifact, authority=provider, audit_writer=writer, now=NOW)
        with zipfile.ZipFile(io.BytesIO(bundle)) as archive:
            self.assertEqual(archive.namelist(), ["support-manifest.json", "items/0001-report"])
            self.assertIn("REPORT-CANARY", archive.read("items/0001-report").decode("utf-8"))
            self.assertNotIn(b"AccessKey", archive.read("items/0001-report"))
        self.assertTrue(artifact.reference.relative_path.startswith("support-content/support-artifact-"))
        self.assertEqual(artifact.reference.plane, StoragePlane.DURABLE_USER_WORKSPACE_RUN_DATA)

    def test_scope_run_and_reference_isolation_fail_closed(self) -> None:
        _root, _operational, run, layout, context, writer = self._setup()
        layout.write_text(StorageArtifact.REPORT, "05_final_report.md", "authorized")
        sibling = run.parent / "run-sibling"
        sibling.mkdir(mode=0o700)
        sibling_layout = StorageLayout.for_workspace(sibling, central_telemetry_root=writer.layout.telemetry_root)
        sibling_layout.write_text(StorageArtifact.REPORT, "05_final_report.md", "SIBLING-CANARY")
        request, provider = self._request(layout, context)
        sibling_selection = SupportContentSelection(SupportArtifactClass.REPORT, sibling_layout.reference(StorageArtifact.REPORT, "05_final_report.md"))
        with self.assertRaises(KSlideError) as mismatch:
            ControlledSupportRequest(request.decision, (sibling_selection,))
        self.assertEqual(mismatch.exception.code, ErrorCode.EXECUTION_CONFLICT)
        with self.assertRaises(KSlideError):
            materialize_controlled_support_bundle(sibling_layout, request, authority=provider, audit_writer=writer, now=NOW)

    def test_scoped_durable_layout_uses_the_same_exact_run_and_scope_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            service_root = Path(directory)
            service = ReferencePaaSJobService(service_root)
            context = AuthorizedScopeContext("user-scoped", "workspace-scoped", "scope-scoped")
            receipt = PaaSController(service, scope_context=context).submit(
                PaaSJobRequest("run-scoped", "scope-scoped", "store-scoped", reference_runtime(), total_work_units=1)
            )
            layout = service.content_layout(receipt.identity, scope_context=context)
            layout.write_text(StorageArtifact.SOURCE_SNAPSHOT, "inputs/source.txt", "SCOPED-CANARY")
            decision = SupportAuthorizationDecision(
                "request-scoped", context, receipt.identity.run_id, "owner-scoped", "role-support", "capability-diagnostic",
                SupportPurpose.DATA_OWNER_REVIEW, "authority-company-support", "decision-scoped",
                (SupportApprovalEvidence("approval-scoped", SupportApprovalStatus.APPROVED),),
                (SupportArtifactClass.SOURCE_SNAPSHOT,), (), _ts(0), _ts(0), _ts(23),
            )
            request = ControlledSupportRequest(
                decision,
                (SupportContentSelection(SupportArtifactClass.SOURCE_SNAPSHOT, layout.reference(StorageArtifact.SOURCE_SNAPSHOT, "inputs/source.txt")),),
            )
            provider = ReferenceSupportAuthorizationProvider()
            provider.add(decision)
            writer = SupportAccessAuditWriter(service_root=service_root)
            artifact = materialize_controlled_support_bundle(layout, request, authority=provider, audit_writer=writer, now=NOW)
            with zipfile.ZipFile(io.BytesIO(read_controlled_support_bundle(layout, request, artifact, authority=provider, audit_writer=writer, now=NOW))) as archive:
                self.assertEqual(archive.read("items/0001-source_snapshot"), b"SCOPED-CANARY")
            other = AuthorizedScopeContext("other-user", "other-workspace", "other-scope")
            with self.assertRaises(KSlideError):
                service.content_layout(receipt.identity, scope_context=other)

    def test_run_id_or_path_possession_without_decision_is_rejected(self) -> None:
        _root, _operational, _run, layout, context, writer = self._setup()
        layout.write_text(StorageArtifact.REPORT, "05_final_report.md", "CANARY")
        reference = layout.reference(StorageArtifact.REPORT, "05_final_report.md")
        with self.assertRaises(KSlideError):
            # A typed selection is not itself authority; the request must carry
            # a complete externally supplied decision.
            ControlledSupportRequest(None, (SupportContentSelection(SupportArtifactClass.REPORT, reference),))  # type: ignore[arg-type]

    def test_missing_role_approval_purpose_expiry_and_reference_are_rejected(self) -> None:
        _root, _operational, _run, layout, context, writer = self._setup()
        layout.write_text(StorageArtifact.REPORT, "05_final_report.md", "CANARY")
        with self.assertRaises(KSlideError):
            SupportAuthorizationDecision("request", context, "run-ksa20", "subject", "", "capability", SupportPurpose.INCIDENT_DIAGNOSTIC, "authority", "decision", (SupportApprovalEvidence("approval", SupportApprovalStatus.APPROVED),), (SupportArtifactClass.REPORT,), (), _ts(0), _ts(0), _ts(23))
        pending = SupportAuthorizationDecision("request", context, "run-ksa20", "subject", "role", "capability", SupportPurpose.INCIDENT_DIAGNOSTIC, "authority", "decision", (SupportApprovalEvidence("approval", SupportApprovalStatus.PENDING),), (SupportArtifactClass.REPORT,), (), _ts(0), _ts(0), _ts(23))
        pending_request = ControlledSupportRequest(pending, (SupportContentSelection(SupportArtifactClass.REPORT, layout.reference(StorageArtifact.REPORT, "05_final_report.md")),))
        pending_provider = ReferenceSupportAuthorizationProvider()
        pending_provider.add(pending)
        with self.assertRaises(KSlideError):
            materialize_controlled_support_bundle(layout, pending_request, authority=pending_provider, audit_writer=writer, now=NOW)
        with self.assertRaises(KSlideError):
            SupportAuthorizationDecision("request", context, "run-ksa20", "subject", "role", "capability", SupportPurpose.INCIDENT_DIAGNOSTIC, "authority", "decision", (SupportApprovalEvidence("approval", SupportApprovalStatus.APPROVED),), (), (), _ts(0), _ts(0), _ts(23))
        with self.assertRaises(KSlideError):
            SupportAuthorizationDecision("request", context, "run-ksa20", "subject", "role", "capability", SupportPurpose.INCIDENT_DIAGNOSTIC, "authority", "decision", (SupportApprovalEvidence("approval", SupportApprovalStatus.APPROVED),), (SupportArtifactClass.REPORT,), (), _ts(0), _ts(0), "")

    def test_denied_revoked_not_yet_valid_expired_and_authority_unavailable_are_visible(self) -> None:
        _root, _operational, _run, layout, context, writer = self._setup()
        layout.write_text(StorageArtifact.REPORT, "05_final_report.md", "CANARY")
        for status, check_time, expected in (
            (SupportDecisionStatus.DENIED, NOW, ErrorCode.SUPPORT_AUTHORIZATION_DENIED),
            (SupportDecisionStatus.REVOKED, NOW, ErrorCode.SUPPORT_AUTHORIZATION_REVOKED),
        ):
            request, provider = self._request(layout, context, status=status)
            with self.assertRaises(KSlideError) as raised:
                materialize_controlled_support_bundle(layout, request, authority=provider, audit_writer=writer, now=check_time)
            self.assertEqual(raised.exception.code, expected)
        future_request, future_provider = self._request(layout, context)
        with self.assertRaises(KSlideError) as future:
            materialize_controlled_support_bundle(layout, future_request, authority=future_provider, audit_writer=writer, now=datetime(2025, 12, 31, 23, tzinfo=timezone.utc))
        self.assertEqual(future.exception.code, ErrorCode.SUPPORT_AUTHORIZATION_DENIED)
        expired_request, expired_provider = self._request(layout, context, expires=_ts(11))
        with self.assertRaises(KSlideError) as expired:
            materialize_controlled_support_bundle(layout, expired_request, authority=expired_provider, audit_writer=writer, now=NOW)
        self.assertEqual(expired.exception.code, ErrorCode.SUPPORT_AUTHORIZATION_EXPIRED)
        missing_provider = ReferenceSupportAuthorizationProvider()
        with self.assertRaises(KSlideError) as unavailable:
            materialize_controlled_support_bundle(layout, future_request, authority=missing_provider, audit_writer=writer, now=NOW)
        self.assertEqual(unavailable.exception.code, ErrorCode.SUPPORT_AUTHORITY_UNAVAILABLE)
        lifecycles = [item.lifecycle.value for item in writer.records()]
        self.assertIn("REVOKED", lifecycles)
        self.assertIn("EXPIRED", lifecycles)

    def test_authority_is_rechecked_on_read_and_reference_provider_is_not_production_authority(self) -> None:
        _root, _operational, _run, layout, context, writer = self._setup()
        layout.write_text(StorageArtifact.REPORT, "05_final_report.md", "CANARY")
        request, provider = self._request(layout, context)
        artifact = materialize_controlled_support_bundle(layout, request, authority=provider, audit_writer=writer, now=NOW)
        provider.revoke(request.decision.decision_ref)
        with self.assertRaises(KSlideError) as revoked:
            read_controlled_support_bundle(layout, request, artifact, authority=provider, audit_writer=writer, now=NOW)
        self.assertEqual(revoked.exception.code, ErrorCode.SUPPORT_AUTHORIZATION_REVOKED)
        with self.assertRaises(KSlideError) as production:
            materialize_controlled_support_bundle(layout, request, authority=provider, audit_writer=writer, now=NOW, production=True)
        self.assertEqual(production.exception.code, ErrorCode.SUPPORT_AUTHORITY_UNAVAILABLE)

    def test_path_traversal_symlink_and_whole_run_expansion_are_rejected(self) -> None:
        _root, _operational, run, layout, context, writer = self._setup()
        layout.write_text(StorageArtifact.REPORT, "05_final_report.md", "REPORT")
        layout.write_text(StorageArtifact.TRANSLATION_PATCH, "translations/unit.json", "UNRELATED")
        request, provider = self._request(layout, context)
        with self.assertRaises(KSlideError):
            StorageLayout.for_workspace(run).reference(StorageArtifact.REPORT, "../outside")
        outside = run.parent / "outside.txt"
        outside.write_text("OUTSIDE")
        (run / "05_link_report.md").symlink_to(outside)
        symlink_request = replace(request, selections=(SupportContentSelection(SupportArtifactClass.REPORT, layout.reference(StorageArtifact.REPORT, "05_link_report.md")),))
        with self.assertRaises(KSlideError):
            materialize_controlled_support_bundle(layout, symlink_request, authority=provider, audit_writer=writer, now=NOW)
        artifact = materialize_controlled_support_bundle(layout, request, authority=provider, audit_writer=writer, now=NOW)
        with zipfile.ZipFile(io.BytesIO(read_controlled_support_bundle(layout, request, artifact, authority=provider, audit_writer=writer, now=NOW))) as archive:
            self.assertNotIn("UNRELATED", archive.read("support-manifest.json").decode("utf-8"))
            self.assertEqual(len([name for name in archive.namelist() if name.startswith("items/")]), 1)

    def test_expired_read_is_denied_even_when_legal_hold_preserves_bytes_then_cleanup_is_idempotent(self) -> None:
        _root, operational, run, layout, context, writer = self._setup()
        layout.write_text(StorageArtifact.REPORT, "05_final_report.md", "CANARY")
        request, provider = self._request(layout, context, expires=_ts(11))
        artifact = materialize_controlled_support_bundle(layout, request, authority=provider, audit_writer=writer, now=datetime(2026, 1, 1, 10, tzinfo=timezone.utc))
        with self.assertRaises(KSlideError) as expired:
            read_controlled_support_bundle(layout, request, artifact, authority=provider, audit_writer=writer, now=NOW)
        self.assertEqual(expired.exception.code, ErrorCode.SUPPORT_AUTHORIZATION_EXPIRED)
        holds = ReferenceLegalHoldProvider()
        holds.set_hold(scope_ref="workspace", run_ref=run.name)
        retained = cleanup_expired_support_content(Path(run).parents[1], scope_context=context, hold_provider=holds, operational_root=operational, now=NOW)
        self.assertEqual(retained["removed"], [])
        self.assertTrue(layout.resolve(artifact.reference).is_file())
        holds.set_release(scope_ref="workspace", run_ref=run.name)
        removed = cleanup_expired_support_content(Path(run).parents[1], scope_context=context, hold_provider=holds, operational_root=operational, now=NOW)
        self.assertEqual(removed["removed"], [artifact.artifact_ref])
        again = cleanup_expired_support_content(Path(run).parents[1], scope_context=context, hold_provider=holds, operational_root=operational, now=NOW)
        self.assertEqual(again["removed"], [])

    def test_content_retention_covers_support_copies_without_changing_metadata_ttl(self) -> None:
        root, operational, run, layout, context, writer = self._setup()
        layout.write_text(StorageArtifact.REPORT, "05_final_report.md", "CANARY")
        request, provider = self._request(layout, context, expires=_ts(11))
        artifact = materialize_controlled_support_bundle(layout, request, authority=provider, audit_writer=writer, now=datetime(2026, 1, 1, 10, tzinfo=timezone.utc))
        (run / "RUN_STATE.json").write_text(json.dumps({"run_id": run.name, "phase": "COMPLETE", "updated_at": _ts(12)}), encoding="utf-8")
        holds = ReferenceLegalHoldProvider()
        holds.set_release(scope_ref="workspace", run_ref=run.name)
        result = cleanup_expired_runs(root, RetentionPolicy("1.0", 100, 100), now=NOW, scope_context=context, hold_provider=holds, operational_root=operational)
        self.assertEqual(result["controlled_support"]["removed"], [artifact.artifact_ref])
        self.assertTrue(run.exists())
        self.assertTrue((operational / "telemetry" / "support-access-audit.jsonl").is_file())

    def test_support_access_audit_uses_operational_metadata_retention(self) -> None:
        root, operational, run, layout, context, writer = self._setup()
        layout.write_text(StorageArtifact.REPORT, "05_final_report.md", "CANARY")
        request, provider = self._request(layout, context)
        materialize_controlled_support_bundle(layout, request, authority=provider, audit_writer=writer, now=NOW)
        holds = ReferenceLegalHoldProvider()
        holds.set_release(scope_ref="workspace", run_ref=run.name)
        cleanup_operational_metadata(
            root, RetentionPolicy("1.0", 100, 1), scope_context=context, hold_provider=holds,
            operational_root=operational, now=datetime(2026, 1, 3, tzinfo=timezone.utc),
        )
        self.assertEqual(writer.records(), ())

    def test_explicit_ksa13_deletion_removes_support_copy_and_keeps_audits_source_free(self) -> None:
        root, operational, run, layout, context, writer = self._setup()
        layout.write_text(StorageArtifact.REPORT, "05_final_report.md", "Korean 검토 AccessKey=secret")
        request, provider = self._request(layout, context)
        artifact = materialize_controlled_support_bundle(layout, request, authority=provider, audit_writer=writer, now=NOW)
        holds = ReferenceLegalHoldProvider()
        holds.set_release(scope_ref="workspace", run_ref=run.name)
        result = delete_workspace_run(root, run_ref=run.name, deletion_id="delete-ksa20", scope_context=context, hold_provider=holds, operational_root=operational)
        self.assertEqual(result.outcome, DeletionOutcome.COMPLETE)
        self.assertFalse(run.exists())
        audit = (operational / "_deletions" / "workspace" / run.name / "delete-ksa20.json").read_text(encoding="utf-8")
        self.assertIn(StorageArtifact.SUPPORT_CONTENT.value, audit)
        self.assertNotIn("Korean", audit)
        self.assertNotIn("AccessKey", audit)
        self.assertNotIn("05_final_report", audit)
        support_audit = writer.audit_path.read_text(encoding="utf-8")
        self.assertIn('"lifecycle":"DELETED"', support_audit)
        self.assertNotIn("Korean", support_audit)
        self.assertNotIn("AccessKey", support_audit)
        self.assertNotIn("05_final_report", support_audit)
        self.assertFalse(Path(artifact.reference.relative_path).is_absolute())

    def test_cli_support_bundle_has_no_content_bearing_escape_hatch(self) -> None:
        parser = __import__("k_slide.cli", fromlist=["build_parser"]).build_parser()
        self.assertNotIn("controlled-support", parser._subparsers._group_actions[0].choices)
        self.assertIn("support-bundle", parser._subparsers._group_actions[0].choices)


if __name__ == "__main__":
    unittest.main()
