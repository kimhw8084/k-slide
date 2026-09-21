from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
import zipfile
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from k_slide.cli import main
from k_slide.content_support import (
    ControlledSupportRequest,
    ReferenceSupportAuthorizationProvider,
    SupportAccessAuditWriter,
    SupportAccessLifecycle,
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
from k_slide.deletion import DeletionOutcome, DeletionState, LegalHoldStatus, ReferenceLegalHoldProvider, WorkspaceDeletionBackend, cleanup_operational_metadata, delete_scoped_run, delete_workspace_run
from k_slide.errors import ErrorCode, KSlideError
from k_slide.paas import AuthorizedScopeContext, PaaSController, PaaSJobRequest, PaaSWorker, ReferencePaaSJobService, ReferenceWorkerEngine
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
        self.assertFalse(any(item.lifecycle is SupportAccessLifecycle.DELETED for item in writer.records()))
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

    def test_workspace_support_deletion_defers_audit_until_retry_and_replay_is_idempotent(self) -> None:
        root, operational, run, layout, context, writer = self._setup()
        layout.write_text(StorageArtifact.REPORT, "05_final_report.md", "Korean 검토 OCR translation AccessKey=secret")
        request, provider = self._request(layout, context)
        artifact = materialize_controlled_support_bundle(layout, request, authority=provider, audit_writer=writer, now=NOW)
        bundle_path = layout.resolve(artifact.reference)
        metadata_path = run / "support-content" / f"{artifact.artifact_ref}.json"
        holds = ReferenceLegalHoldProvider()
        holds.set_release(scope_ref="workspace", run_ref=run.name)
        original_unlink = Path.unlink
        injected = False

        def fail_bundle_once(path: Path, missing_ok: bool = False) -> None:
            nonlocal injected
            if path == bundle_path and not injected:
                injected = True
                raise OSError("injected support-content unlink failure")
            original_unlink(path, missing_ok=missing_ok)

        with patch.object(Path, "unlink", new=fail_bundle_once):
            partial = delete_workspace_run(
                root, run_ref=run.name, deletion_id="delete-support-partial", scope_context=context,
                hold_provider=holds, operational_root=operational,
            )
        self.assertEqual(partial.state, DeletionState.PARTIAL)
        self.assertEqual(partial.error_code, "TARGET_DELETE_FAILED")
        self.assertTrue(bundle_path.is_file())
        self.assertTrue(metadata_path.is_file())
        self.assertFalse(any(item.lifecycle is SupportAccessLifecycle.DELETED for item in writer.records()))

        complete = delete_workspace_run(
            root, run_ref=run.name, deletion_id="delete-support-partial", scope_context=context,
            hold_provider=holds, operational_root=operational,
        )
        self.assertEqual(complete.outcome, DeletionOutcome.COMPLETE)
        self.assertFalse(run.exists())
        deleted = [item for item in writer.records() if item.lifecycle is SupportAccessLifecycle.DELETED]
        self.assertEqual([item.support_artifact_ref for item in deleted], [artifact.artifact_ref])
        audit_before_replay = writer.audit_path.read_bytes()
        replay = delete_workspace_run(
            root, run_ref=run.name, deletion_id="delete-support-partial", scope_context=context,
            hold_provider=holds, operational_root=operational,
        )
        self.assertEqual(replay.outcome, DeletionOutcome.COMPLETE)
        self.assertEqual(audit_before_replay, writer.audit_path.read_bytes())
        support_audit = writer.audit_path.read_text(encoding="utf-8")
        for canary in ("Korean", "OCR", "translation", "AccessKey", "secret", "05_final_report", str(root), "support-content"):
            self.assertNotIn(canary, support_audit)

    def test_scoped_support_deletion_defers_audit_until_retry_and_replay_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            context = AuthorizedScopeContext("user-support-delete", "workspace-support-delete", "scope-support-delete")
            service = ReferencePaaSJobService(root)
            receipt = PaaSController(service, scope_context=context).submit(
                PaaSJobRequest("run-support-delete", "scope-support-delete", "store-support-delete", reference_runtime(), total_work_units=1)
            )
            PaaSWorker(
                service, worker_id="worker-support-delete", runtime_identity=reference_runtime(),
                engine=ReferenceWorkerEngine(), scope_context=context,
            ).run_until_terminal(receipt.identity)
            layout = service.content_layout(receipt.identity, scope_context=context)
            layout.write_text(StorageArtifact.SOURCE_SNAPSHOT, "inputs/source.txt", "Korean OCR translation AccessKey=secret")
            decision = SupportAuthorizationDecision(
                "request-support-delete", context, receipt.identity.run_id, "subject-owner", "role-support", "capability-diagnostic",
                SupportPurpose.DATA_OWNER_REVIEW, "authority-company-support", "decision-support-delete",
                (SupportApprovalEvidence("approval-support-delete", SupportApprovalStatus.APPROVED),),
                (SupportArtifactClass.SOURCE_SNAPSHOT,), (), _ts(0), _ts(0), _ts(23),
            )
            request = ControlledSupportRequest(
                decision,
                (SupportContentSelection(SupportArtifactClass.SOURCE_SNAPSHOT, layout.reference(StorageArtifact.SOURCE_SNAPSHOT, "inputs/source.txt")),),
            )
            provider = ReferenceSupportAuthorizationProvider()
            provider.add(decision)
            writer = SupportAccessAuditWriter(service_root=root)
            artifact = materialize_controlled_support_bundle(layout, request, authority=provider, audit_writer=writer, now=NOW)
            bundle_path = layout.resolve(artifact.reference)
            metadata_path = bundle_path.with_suffix(".json")
            holds = ReferenceLegalHoldProvider()
            holds.set_release(scope_ref=context.scope_ref, run_ref=receipt.identity.run_id)
            original_unlink = Path.unlink
            injected = False

            def fail_bundle_once(path: Path, missing_ok: bool = False) -> None:
                nonlocal injected
                if path == bundle_path and not injected:
                    injected = True
                    raise OSError("injected scoped support-content unlink failure")
                original_unlink(path, missing_ok=missing_ok)

            with patch.object(Path, "unlink", new=fail_bundle_once):
                partial = delete_scoped_run(
                    service, identity=receipt.identity, scope_context=context, deletion_id="delete-scoped-support-partial",
                    hold_provider=holds,
                )
            self.assertEqual(partial.state, DeletionState.PARTIAL)
            self.assertEqual(partial.error_code, "TARGET_DELETE_FAILED")
            self.assertTrue(bundle_path.is_file())
            self.assertTrue(metadata_path.is_file())
            self.assertFalse(any(item.lifecycle is SupportAccessLifecycle.DELETED for item in writer.records()))

            complete = delete_scoped_run(
                service, identity=receipt.identity, scope_context=context, deletion_id="delete-scoped-support-partial",
                hold_provider=holds,
            )
            self.assertEqual(complete.outcome, DeletionOutcome.COMPLETE, complete.as_dict())
            self.assertFalse(layout.durable_root.exists())
            deleted = [item for item in writer.records() if item.lifecycle is SupportAccessLifecycle.DELETED]
            self.assertEqual([item.support_artifact_ref for item in deleted], [artifact.artifact_ref])
            audit_before_replay = writer.audit_path.read_bytes()
            replay = delete_scoped_run(
                service, identity=receipt.identity, scope_context=context, deletion_id="delete-scoped-support-partial",
                hold_provider=holds,
            )
            self.assertEqual(replay.outcome, DeletionOutcome.COMPLETE)
            self.assertEqual(audit_before_replay, writer.audit_path.read_bytes())
            support_audit = writer.audit_path.read_text(encoding="utf-8")
            for canary in ("Korean", "OCR", "translation", "AccessKey", "secret", "inputs/source.txt", str(root), "support-content"):
                self.assertNotIn(canary, support_audit)

    def test_workspace_support_audit_outage_after_unlink_keeps_durable_recovery(self) -> None:
        root, operational, run, layout, context, writer = self._setup()
        layout.write_text(StorageArtifact.REPORT, "05_final_report.md", "Korean OCR translation AccessKey=secret")
        request, provider = self._request(layout, context)
        artifact = materialize_controlled_support_bundle(layout, request, authority=provider, audit_writer=writer, now=NOW)
        bundle_path = layout.resolve(artifact.reference)
        metadata_path = bundle_path.with_suffix(".json")
        holds = ReferenceLegalHoldProvider()
        holds.set_release(scope_ref="workspace", run_ref=run.name)

        with patch.object(SupportAccessAuditWriter, "write", side_effect=OSError("persistent central audit outage")):
            partial = delete_workspace_run(
                root, run_ref=run.name, deletion_id="delete-support-audit-outage", scope_context=context,
                hold_provider=holds, operational_root=operational,
            )
        self.assertEqual(partial.state, DeletionState.PARTIAL)
        self.assertFalse(bundle_path.exists())
        self.assertFalse(metadata_path.exists())
        deletion_audit_path = operational / "_deletions" / "workspace" / run.name / "delete-support-audit-outage.json"
        deletion_audit = deletion_audit_path.read_text(encoding="utf-8")
        self.assertIn("support_recovery", deletion_audit)
        for canary in ("Korean", "OCR", "translation", "AccessKey", "secret", "05_final_report.md", str(root), "support-content"):
            self.assertNotIn(canary, deletion_audit)
        self.assertFalse(any(item.lifecycle is SupportAccessLifecycle.DELETED for item in writer.records()))

        complete = delete_workspace_run(
            root, run_ref=run.name, deletion_id="delete-support-audit-outage", scope_context=context,
            hold_provider=holds, operational_root=operational,
        )
        self.assertEqual(complete.outcome, DeletionOutcome.COMPLETE)
        deleted = [item for item in writer.records() if item.lifecycle is SupportAccessLifecycle.DELETED]
        self.assertEqual([item.support_artifact_ref for item in deleted], [artifact.artifact_ref])

    def test_scoped_support_audit_outage_after_unlink_keeps_durable_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            context = AuthorizedScopeContext("user-scoped-outage", "workspace-scoped-outage", "scope-scoped-outage")
            service = ReferencePaaSJobService(root)
            receipt = PaaSController(service, scope_context=context).submit(
                PaaSJobRequest("run-scoped-outage", "scope-scoped-outage", "store-scoped-outage", reference_runtime(), total_work_units=1)
            )
            PaaSWorker(service, worker_id="worker-scoped-outage", runtime_identity=reference_runtime(), engine=ReferenceWorkerEngine(), scope_context=context).run_until_terminal(receipt.identity)
            layout = service.content_layout(receipt.identity, scope_context=context)
            layout.write_text(StorageArtifact.SOURCE_SNAPSHOT, "inputs/source.txt", "Korean OCR translation AccessKey=secret")
            decision = SupportAuthorizationDecision(
                "request-scoped-outage", context, receipt.identity.run_id, "subject-owner", "role-support", "capability-diagnostic",
                SupportPurpose.DATA_OWNER_REVIEW, "authority-company-support", "decision-scoped-outage",
                (SupportApprovalEvidence("approval-scoped-outage", SupportApprovalStatus.APPROVED),),
                (SupportArtifactClass.SOURCE_SNAPSHOT,), (), _ts(0), _ts(0), _ts(23),
            )
            request = ControlledSupportRequest(
                decision,
                (SupportContentSelection(SupportArtifactClass.SOURCE_SNAPSHOT, layout.reference(StorageArtifact.SOURCE_SNAPSHOT, "inputs/source.txt")),),
            )
            provider = ReferenceSupportAuthorizationProvider()
            provider.add(decision)
            writer = SupportAccessAuditWriter(service_root=root)
            artifact = materialize_controlled_support_bundle(layout, request, authority=provider, audit_writer=writer, now=NOW)
            bundle_path = layout.resolve(artifact.reference)
            metadata_path = bundle_path.with_suffix(".json")
            holds = ReferenceLegalHoldProvider()
            holds.set_release(scope_ref=context.scope_ref, run_ref=receipt.identity.run_id)

            with patch.object(SupportAccessAuditWriter, "write", side_effect=OSError("persistent central audit outage")):
                partial = delete_scoped_run(
                    service, identity=receipt.identity, scope_context=context, deletion_id="delete-scoped-audit-outage",
                    hold_provider=holds,
                )
            self.assertEqual(partial.state, DeletionState.PARTIAL)
            self.assertFalse(bundle_path.exists())
            self.assertFalse(metadata_path.exists())
            audit_path = service._central_operational_root() / "_deletions" / service._scope_key(context) / receipt.identity.run_id / receipt.identity.job_id / "delete-scoped-audit-outage.json"
            deletion_audit = audit_path.read_text(encoding="utf-8")
            self.assertIn("support_recovery", deletion_audit)
            for canary in ("Korean", "OCR", "translation", "AccessKey", "secret", "inputs/source.txt", str(root), "support-content"):
                self.assertNotIn(canary, deletion_audit)

            complete = delete_scoped_run(
                service, identity=receipt.identity, scope_context=context, deletion_id="delete-scoped-audit-outage",
                hold_provider=holds,
            )
            self.assertEqual(complete.outcome, DeletionOutcome.COMPLETE)
            deleted = [item for item in writer.records() if item.lifecycle is SupportAccessLifecycle.DELETED]
            self.assertEqual([item.support_artifact_ref for item in deleted], [artifact.artifact_ref])

    def test_workspace_ambiguous_support_audit_commit_is_exactly_once(self) -> None:
        root, operational, run, layout, context, writer = self._setup()
        layout.write_text(StorageArtifact.REPORT, "05_final_report.md", "Korean OCR translation AccessKey=secret")
        request, provider = self._request(layout, context)
        artifact = materialize_controlled_support_bundle(layout, request, authority=provider, audit_writer=writer, now=NOW)
        holds = ReferenceLegalHoldProvider()
        holds.set_release(scope_ref="workspace", run_ref=run.name)

        original_chmod = os.chmod

        def fail_support_audit_chmod(path: object, mode: int) -> None:
            if Path(path) == writer.audit_path:
                raise OSError("ambiguous chmod failure")
            original_chmod(path, mode)  # type: ignore[arg-type]

        with patch("k_slide.content_support.os.chmod", new=fail_support_audit_chmod):
            partial = delete_workspace_run(
                root, run_ref=run.name, deletion_id="delete-support-ambiguous", scope_context=context,
                hold_provider=holds, operational_root=operational,
            )
        self.assertEqual(partial.state, DeletionState.PARTIAL)
        self.assertEqual(len([item for item in writer.records() if item.lifecycle is SupportAccessLifecycle.DELETED]), 1)
        support_audit_before = writer.audit_path.read_bytes()
        complete = delete_workspace_run(
            root, run_ref=run.name, deletion_id="delete-support-ambiguous", scope_context=context,
            hold_provider=holds, operational_root=operational,
        )
        self.assertEqual(complete.outcome, DeletionOutcome.COMPLETE)
        self.assertEqual(support_audit_before, writer.audit_path.read_bytes())
        self.assertEqual(len([item for item in writer.records() if item.lifecycle is SupportAccessLifecycle.DELETED]), 1)

    def test_scoped_ambiguous_support_audit_commit_is_exactly_once(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            context = AuthorizedScopeContext("user-scoped-ambiguous", "workspace-scoped-ambiguous", "scope-scoped-ambiguous")
            service = ReferencePaaSJobService(root)
            receipt = PaaSController(service, scope_context=context).submit(
                PaaSJobRequest("run-scoped-ambiguous", "scope-scoped-ambiguous", "store-scoped-ambiguous", reference_runtime(), total_work_units=1)
            )
            PaaSWorker(service, worker_id="worker-scoped-ambiguous", runtime_identity=reference_runtime(), engine=ReferenceWorkerEngine(), scope_context=context).run_until_terminal(receipt.identity)
            layout = service.content_layout(receipt.identity, scope_context=context)
            layout.write_text(StorageArtifact.SOURCE_SNAPSHOT, "inputs/source.txt", "Korean OCR translation AccessKey=secret")
            decision = SupportAuthorizationDecision(
                "request-scoped-ambiguous", context, receipt.identity.run_id, "subject-owner", "role-support", "capability-diagnostic",
                SupportPurpose.DATA_OWNER_REVIEW, "authority-company-support", "decision-scoped-ambiguous",
                (SupportApprovalEvidence("approval-scoped-ambiguous", SupportApprovalStatus.APPROVED),),
                (SupportArtifactClass.SOURCE_SNAPSHOT,), (), _ts(0), _ts(0), _ts(23),
            )
            request = ControlledSupportRequest(
                decision,
                (SupportContentSelection(SupportArtifactClass.SOURCE_SNAPSHOT, layout.reference(StorageArtifact.SOURCE_SNAPSHOT, "inputs/source.txt")),),
            )
            provider = ReferenceSupportAuthorizationProvider()
            provider.add(decision)
            writer = SupportAccessAuditWriter(service_root=root)
            materialize_controlled_support_bundle(layout, request, authority=provider, audit_writer=writer, now=NOW)
            holds = ReferenceLegalHoldProvider()
            holds.set_release(scope_ref=context.scope_ref, run_ref=receipt.identity.run_id)

            original_chmod = os.chmod

            def fail_support_audit_chmod(path: object, mode: int) -> None:
                if Path(path) == writer.audit_path:
                    raise OSError("ambiguous chmod failure")
                original_chmod(path, mode)  # type: ignore[arg-type]

            with patch("k_slide.content_support.os.chmod", new=fail_support_audit_chmod):
                partial = delete_scoped_run(
                    service, identity=receipt.identity, scope_context=context, deletion_id="delete-scoped-ambiguous",
                    hold_provider=holds,
                )
            self.assertEqual(partial.state, DeletionState.PARTIAL)
            self.assertEqual(len([item for item in writer.records() if item.lifecycle is SupportAccessLifecycle.DELETED]), 1)
            support_audit_before = writer.audit_path.read_bytes()
            complete = delete_scoped_run(
                service, identity=receipt.identity, scope_context=context, deletion_id="delete-scoped-ambiguous",
                hold_provider=holds,
            )
            self.assertEqual(complete.outcome, DeletionOutcome.COMPLETE)
            self.assertEqual(support_audit_before, writer.audit_path.read_bytes())
            self.assertEqual(len([item for item in writer.records() if item.lifecycle is SupportAccessLifecycle.DELETED]), 1)

    def test_multiple_support_artifacts_retry_each_deletion_event_independently(self) -> None:
        root, operational, run, layout, context, writer = self._setup()
        layout.write_text(StorageArtifact.REPORT, "05_final_report.md", "REPORT Korean")
        layout.write_text(StorageArtifact.SOURCE_SNAPSHOT, "inputs/source.txt", "SOURCE Korean")
        report_request, report_provider = self._request(layout, context, artifact_class=SupportArtifactClass.REPORT, relative_path="05_final_report.md")
        source_request, source_provider = self._request(layout, context, artifact_class=SupportArtifactClass.SOURCE_SNAPSHOT, relative_path="inputs/source.txt")
        report_artifact = materialize_controlled_support_bundle(layout, report_request, authority=report_provider, audit_writer=writer, now=NOW)
        source_artifact = materialize_controlled_support_bundle(layout, source_request, authority=source_provider, audit_writer=writer, now=NOW)
        failing_ref = max(report_artifact.artifact_ref, source_artifact.artifact_ref)
        original_write = SupportAccessAuditWriter.write

        def fail_one(writer_instance: SupportAccessAuditWriter, record: object) -> None:
            if getattr(record, "lifecycle", None) is SupportAccessLifecycle.DELETED and getattr(record, "support_artifact_ref", None) == failing_ref:
                raise OSError("one support audit event failed")
            original_write(writer_instance, record)  # type: ignore[arg-type]

        holds = ReferenceLegalHoldProvider()
        holds.set_release(scope_ref="workspace", run_ref=run.name)
        with patch.object(SupportAccessAuditWriter, "write", new=fail_one):
            partial = delete_workspace_run(
                root, run_ref=run.name, deletion_id="delete-support-multiple", scope_context=context,
                hold_provider=holds, operational_root=operational,
            )
        self.assertEqual(partial.state, DeletionState.PARTIAL)
        deleted_after_failure = {item.support_artifact_ref for item in writer.records() if item.lifecycle is SupportAccessLifecycle.DELETED}
        self.assertEqual(deleted_after_failure, {min(report_artifact.artifact_ref, source_artifact.artifact_ref)})

        complete = delete_workspace_run(
            root, run_ref=run.name, deletion_id="delete-support-multiple", scope_context=context,
            hold_provider=holds, operational_root=operational,
        )
        self.assertEqual(complete.outcome, DeletionOutcome.COMPLETE)
        deleted = [item for item in writer.records() if item.lifecycle is SupportAccessLifecycle.DELETED]
        self.assertEqual({item.support_artifact_ref for item in deleted}, {report_artifact.artifact_ref, source_artifact.artifact_ref})
        self.assertEqual(len(deleted), 2)

    def test_support_audit_success_before_final_deletion_state_failure_replays_without_duplicate(self) -> None:
        root, operational, run, layout, context, writer = self._setup()
        layout.write_text(StorageArtifact.REPORT, "05_final_report.md", "Korean OCR translation AccessKey=secret")
        request, provider = self._request(layout, context)
        artifact = materialize_controlled_support_bundle(layout, request, authority=provider, audit_writer=writer, now=NOW)
        holds = ReferenceLegalHoldProvider()
        holds.set_release(scope_ref="workspace", run_ref=run.name)
        original_save = WorkspaceDeletionBackend.save_audit
        failed = False

        def fail_complete(backend: WorkspaceDeletionBackend, audit: object) -> None:
            nonlocal failed
            if getattr(audit, "state", None) is DeletionState.COMPLETE and not failed:
                failed = True
                raise OSError("injected final deletion-state persistence failure")
            original_save(backend, audit)  # type: ignore[arg-type]

        with patch.object(WorkspaceDeletionBackend, "save_audit", new=fail_complete):
            with self.assertRaises(OSError):
                delete_workspace_run(
                    root, run_ref=run.name, deletion_id="delete-support-final-state-failure", scope_context=context,
                    hold_provider=holds, operational_root=operational,
                )
        self.assertEqual(len([item for item in writer.records() if item.lifecycle is SupportAccessLifecycle.DELETED]), 1)
        support_audit_before = writer.audit_path.read_bytes()
        complete = delete_workspace_run(
            root, run_ref=run.name, deletion_id="delete-support-final-state-failure", scope_context=context,
            hold_provider=holds, operational_root=operational,
        )
        self.assertEqual(complete.outcome, DeletionOutcome.COMPLETE)
        self.assertEqual(support_audit_before, writer.audit_path.read_bytes())
        self.assertEqual([item.support_artifact_ref for item in writer.records() if item.lifecycle is SupportAccessLifecycle.DELETED], [artifact.artifact_ref])

    def test_cli_support_bundle_has_no_content_bearing_escape_hatch(self) -> None:
        parser = __import__("k_slide.cli", fromlist=["build_parser"]).build_parser()
        self.assertNotIn("controlled-support", parser._subparsers._group_actions[0].choices)
        self.assertIn("support-bundle", parser._subparsers._group_actions[0].choices)


if __name__ == "__main__":
    unittest.main()
