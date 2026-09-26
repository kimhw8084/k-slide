from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from jsonschema import Draft202012Validator

from k_slide import cli
from k_slide.deletion import LegalHoldStatus, ReferenceLegalHoldProvider, cleanup_operational_metadata
from k_slide.errors import ErrorCode, KSlideError
from k_slide.evidence_ir import EvidenceIR, EvidenceRegion, save_evidence
from k_slide.execution import sync_workspace_execution
from k_slide.ingest import prepare_run
from k_slide.paas import AuthorizedScopeContext
from k_slide.queue import WorkUnitStatus, load_queue, save_queue
from k_slide.retention_policy import RetentionPolicy
from k_slide.state import RunPhase, load_state, save_state
from k_slide.telemetry import (
    TelemetryArtifactClass,
    TelemetryEvent,
    TelemetryEventType,
    TelemetryHost,
    TelemetryIssueCategory,
    TelemetryLifecycle,
    TelemetryMachineId,
    TelemetryReference,
    TelemetryReferenceKind,
    TelemetryReviewCategory,
    TelemetrySemanticOutcome,
    TelemetryStage,
    TelemetryWriteStatus,
    TelemetryWriter,
)
from k_slide.verify import finalize_run, verify_run
from tests.reference_fixtures import reference_environment


PNG = b"\x89PNG\r\n\x1a\nminimal-ksa35-fixture"
SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas" / "operational-telemetry-event.schema.json"


def reference(kind: TelemetryReferenceKind) -> TelemetryReference:
    return TelemetryReference.from_internal(kind, TelemetryMachineId.new(kind))


def base_event(*, event_id: TelemetryReference | None = None) -> TelemetryEvent:
    return TelemetryEvent(
        TelemetryEventType.LIFECYCLE,
        event_id or reference(TelemetryReferenceKind.EVENT),
        "2026-01-01T00:00:00Z",
        run_ref=reference(TelemetryReferenceKind.RUN),
        lifecycle=TelemetryLifecycle.RUNNING,
    )


def output_for(argv: list[str]) -> tuple[int, dict[str, object]]:
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        exit_code = cli.main(argv)
    return exit_code, json.loads(buffer.getvalue())


def artifact_snapshot(run: Path) -> dict[str, str]:
    return {
        item.relative_to(run).as_posix(): hashlib.sha256(item.read_bytes()).hexdigest()
        for item in sorted(run.rglob("*"))
        if item.is_file()
    }


def prepare_bound_run(root: Path, session_id: str, seed: str = "ksa35") -> tuple[Path, object]:
    source = root / f"{seed}.png"
    source.write_bytes(PNG)
    environment = reference_environment(seed)
    run = prepare_run(root, explicit_paths=[str(source)], session_id=session_id, environment_identity=environment)
    return run, environment


def prepare_done_run(root: Path, session_id: str) -> tuple[Path, object]:
    from k_slide.cli import _conflict_assess, _next, _submit

    run, environment = prepare_bound_run(root, session_id, "ksa35-done")
    queue = load_queue(run)
    work_unit_id = queue.work_units[0].work_unit_id
    region_id = f"{work_unit_id}-r001"
    evidence = EvidenceIR(
        "doc-001",
        work_unit_id,
        {"input_id": "source-001", "width_px": 100, "height_px": 100},
        (EvidenceRegion(region_id, (0, 0, 100, 100), (0, 0, 1, 1), selected_literal_candidate="원문", literal_confidence=1.0),),
        required_source_ids=(region_id,),
    ).with_revision()
    save_evidence(run, evidence)
    queue.work_units[0].status = WorkUnitStatus.READY
    queue.work_units[0].evidence_revision = evidence.evidence_revision
    save_queue(run, queue)
    state = load_state(run)
    state.transition(RunPhase.NORMALIZED)
    state.transition(RunPhase.EXTRACTED)
    save_state(run, state)
    payload = {
        "schema_version": "1.0",
        "work_unit_id": work_unit_id,
        "evidence_revision": evidence.evidence_revision,
        "regions": [{"region_id": region_id, "english": "A faithful reconstruction.", "term_ids": [], "unresolved": False}],
        "tables": [],
        "visual_interpretations": [],
        "executive_claims": [],
    }
    if _next(root, run.name, session_id, environment)["status"] != "READY":
        raise AssertionError("engine did not reserve the prepared work unit")
    accepted = _submit(root, run.name, json.dumps(payload), session_id, environment)
    if accepted["status"] != "ACCEPTED":
        raise AssertionError("engine did not accept the fixture TranslationPatch")
    _conflict_assess(root, run.name, '{"schema_version":"1.0","candidate_groups":[]}', session_id, environment)
    (run / "05_executive_brief.md").write_text("# Executive brief\n", encoding="utf-8")
    (run / "05_final_report.md").write_text("# Source-faithful reconstruction\n", encoding="utf-8")
    (run / "07_unresolved_items.md").write_text("No unresolved items.\n", encoding="utf-8")
    verified = verify_run(run, environment_identity=environment)
    if not verified.passed:
        raise AssertionError(f"engine fixture did not verify: {verified.as_dict()}")
    finalize_run(run, environment_identity=environment)
    sync_workspace_execution(run, environment_identity=environment)
    return run, environment


class KSA35TelemetrySchemaTests(unittest.TestCase):
    def test_schema_accepts_bounded_issue_allegation_and_rejects_content_shapes(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema)
        self.assertEqual(set(schema["properties"]["error_code"]["enum"]), {item.value for item in ErrorCode})
        valid = TelemetryEvent(
            TelemetryEventType.ISSUE_REPORT,
            reference(TelemetryReferenceKind.EVENT),
            "2026-01-01T00:00:00Z",
            run_ref=reference(TelemetryReferenceKind.RUN),
            host=TelemetryHost.CLOUD_VSCODE,
            semantic_outcome=TelemetrySemanticOutcome.PENDING,
            review_category=TelemetryReviewCategory.NONE,
            issue_category=TelemetryIssueCategory.OMISSION,
            issue_report_status="ALLEGATION",
        ).as_dict()
        validator.validate(valid)
        for unsafe in (
            {**valid, "source_text": "source-owned evidence"},
            {**valid, "diagnostic": {"nested": "content"}},
            {**valid, "screenshot": "opaque-value"},
            {**valid, "host": "AccessKey=rotated-canary"},
            {**valid, "semantic_outcome": "DONE", "review_category": "SOURCE_EVIDENCE"},
            {**valid, "issue_report_status": "VERIFIED_FINDING"},
        ):
            with self.subTest(keys=tuple(unsafe)):
                self.assertTrue(list(validator.iter_errors(unsafe)))

    def test_unknown_nested_content_credentials_and_rotations_fail_before_write(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            writer = TelemetryWriter(Path(directory))
            base = base_event().as_dict()
            hostile_fields = [
                {**base, "prompt": "translate confidential source"},
                {**base, "payload": {"text": "Korean source"}},
                {**base, "file_path": "/workspace/private.pptx"},
                {**base, "ocr": ["source text"]},
                {**base, "credentials": {"AccessKey": "canary"}},
                {**base, "host": "x"},
            ]
            credential_values = ("x", "password", "common-secret", "짧은키-회전-2", "rotated-token-3f8c")
            for secret in credential_values:
                hostile_fields.append({**base, "review_category": secret})
                hostile_fields.append({**base, "unknown": secret})
            for value in hostile_fields:
                with self.subTest(value_keys=tuple(value)):
                    with self.assertRaises(KSlideError):
                        writer.record(value)
            self.assertFalse(writer.event_path.exists())
            for malformed in ("event:short", "kslide-ref-v1.event.bad", "kslide-ref-v1.run." + "g" * 64):
                with self.subTest(reference=malformed), self.assertRaises(KSlideError):
                    TelemetryReference.from_canonical(malformed)

    def test_writer_is_idempotent_bounded_concurrent_and_restart_safe(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            event = base_event()
            with ThreadPoolExecutor(max_workers=12) as pool:
                statuses = list(pool.map(lambda _index: TelemetryWriter(root).record(event), range(24)))
            self.assertEqual(statuses.count(TelemetryWriteStatus.RECORDED), 1)
            self.assertEqual(statuses.count(TelemetryWriteStatus.IDEMPOTENT), 23)
            restarted = TelemetryWriter(root)
            self.assertEqual(len(restarted.records()), 1)
            self.assertEqual(restarted.record(event), TelemetryWriteStatus.IDEMPOTENT)
            changed = TelemetryEvent(
                event.event_type,
                event.event_id,
                "2026-01-02T00:00:00Z",
                run_ref=event.run_ref,
                lifecycle=TelemetryLifecycle.RETRYING,
            )
            self.assertEqual(restarted.record(changed), TelemetryWriteStatus.CONFLICT)

    def test_transition_references_are_stable_per_host_and_separate_across_host_paths(self) -> None:
        run_ref = reference(TelemetryReferenceKind.RUN)
        cloud_id = TelemetryReference.for_transition(run_ref, 7, TelemetryEventType.LIFECYCLE, host="cloud_vscode")
        self.assertEqual(cloud_id, TelemetryReference.for_transition(run_ref, 7, TelemetryEventType.LIFECYCLE, host="cloud_vscode"))
        self.assertNotEqual(cloud_id, TelemetryReference.for_transition(run_ref, 7, TelemetryEventType.LIFECYCLE, host="opencode"))

    def test_writer_rejects_symlink_streams_and_record_bound_exhaustion(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as external_directory:
            root = Path(directory)
            external = Path(external_directory) / "external.jsonl"
            external.write_text("external content must remain untouched\n", encoding="utf-8")
            writer = TelemetryWriter(root)
            event_path = writer.event_path
            event_path.symlink_to(external)
            self.assertEqual(writer.record(base_event()), TelemetryWriteStatus.UNAVAILABLE)
            self.assertEqual(external.read_text(encoding="utf-8"), "external content must remain untouched\n")
            event_path.unlink()
            with patch("k_slide.telemetry.MAX_TELEMETRY_RECORDS", 0):
                self.assertEqual(writer.record(base_event()), TelemetryWriteStatus.CAPACITY_LIMIT)

    def test_partial_atomic_write_and_optional_sink_failure_are_truthful(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as workspace_directory:
            root = Path(directory)
            writer = TelemetryWriter(root)
            first_event = base_event()
            self.assertEqual(writer.record(first_event), TelemetryWriteStatus.RECORDED)
            prior_stream = writer.event_path.read_bytes()
            retry_event = base_event()
            with patch("k_slide.telemetry.atomic_write_text", side_effect=OSError("injected partial-write failure")):
                self.assertEqual(writer.record(retry_event), TelemetryWriteStatus.UNAVAILABLE)
            self.assertEqual(writer.event_path.read_bytes(), prior_stream)
            workspace = Path(workspace_directory)
            session_id = "sink-failure-session"
            run, _environment = prepare_bound_run(workspace, session_id, "ksa35-sink")
            with patch.dict(os.environ, {"KSLIDE_OPERATIONAL_SERVICE_ROOT": str(root)}):
                with patch.object(TelemetryWriter, "record", return_value=TelemetryWriteStatus.UNAVAILABLE):
                    value = cli._issue_report(
                        workspace,
                        run.name,
                        session_id,
                        category="omission",
                        submission_id=str(uuid4()),
                        host="opencode",
                    )
            self.assertEqual(value["status"], "NOT_DELIVERED")
            self.assertIn("next_action", value)

            before = artifact_snapshot(run)
            with patch.dict(os.environ, {"KSLIDE_OPERATIONAL_SERVICE_ROOT": str(root)}):
                with patch.object(TelemetryWriter, "record", side_effect=OSError("optional telemetry unavailable")):
                    code, _status = output_for(["status", "--root", str(workspace), "--run", run.name, "--session-id", session_id, "--json"])
            self.assertEqual(code, 0)
            self.assertEqual(artifact_snapshot(run), before)

    def test_engine_failure_code_and_lifecycle_are_derived_from_run_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as service_directory:
            root = Path(directory)
            session_id = "engine-failure-session"
            source = root / "bad.png"
            source.write_bytes(b"not-a-png")
            run = prepare_run(root, explicit_paths=[str(source)], session_id=session_id, environment_identity=reference_environment("ksa35-failure"))
            state = load_state(run)
            self.assertEqual(state.phase, RunPhase.FAILED_INPUT)
            self.assertIsNotNone(state.error_code)
            service = Path(service_directory)
            with patch.dict(os.environ, {"KSLIDE_OPERATIONAL_SERVICE_ROOT": str(service)}):
                code, _value = output_for([
                    "status", "--root", str(root), "--run", run.name, "--session-id", session_id,
                    "--host-adapter", "cloud_vscode", "--json",
                ])
            self.assertEqual(code, 0)
            events = TelemetryWriter(service).records()
            failure = next(event for event in events if event.event_type is TelemetryEventType.ERROR)
            lifecycle = next(event for event in events if event.event_type is TelemetryEventType.LIFECYCLE)
            self.assertEqual(failure.error_code, state.error_code)
            self.assertEqual(lifecycle.lifecycle, TelemetryLifecycle.PROCESSING_FAILED.value)


class KSA35IssueFlowTests(unittest.TestCase):
    def test_cloud_vscode_report_and_confirmation_use_verified_done_state_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as service_directory:
            root = Path(directory)
            session_id = "cloud-vscode-ksa35-session"
            run, environment = prepare_done_run(root, session_id)
            service = Path(service_directory)
            with patch.dict(os.environ, {"KSLIDE_OPERATIONAL_SERVICE_ROOT": str(service)}):
                real_verify = cli.verify_run
                with patch.object(cli, "verify_run", side_effect=lambda selected: real_verify(selected, environment_identity=environment)):
                    verify_code, verify_value = output_for([
                        "verify", "--root", str(root), "--run", run.name, "--session-id", session_id,
                        "--host-adapter", "cloud_vscode", "--json",
                    ])
                self.assertEqual(verify_code, 0, verify_value)
                real_finalize = cli.finalize_run
                with patch.object(cli, "finalize_run", side_effect=lambda selected: real_finalize(selected, environment_identity=environment)):
                    finalize_code, finalize_value = output_for([
                        "finalize", "--root", str(root), "--run", run.name, "--session-id", session_id,
                        "--host-adapter", "cloud_vscode", "--json",
                    ])
                self.assertEqual(finalize_code, 0, finalize_value)
                before = artifact_snapshot(run)
                status_code, status = output_for([
                    "status", "--root", str(root), "--run", run.name, "--session-id", session_id,
                    "--host-adapter", "cloud_vscode", "--json",
                ])
                self.assertEqual(status_code, 0, status)
                writer = TelemetryWriter(service)
                all_events = writer.records()
                lifecycle = [event for event in all_events if event.event_type is TelemetryEventType.LIFECYCLE]
                self.assertTrue(any(event.semantic_outcome == "DONE" and event.review_category == "NONE" for event in lifecycle))
                stages = [event for event in all_events if event.event_type is TelemetryEventType.STAGE_TIMING]
                self.assertTrue(any(event.stage == TelemetryStage.VERIFYING.value and event.duration_ms is not None for event in stages))
                self.assertTrue(any(event.stage == TelemetryStage.FINALIZING.value and event.duration_ms is not None for event in stages))
                done_event = next(event for event in lifecycle if event.semantic_outcome == "DONE")
                self.assertEqual(done_event.artifact_class, TelemetryArtifactClass.IMAGE.value)
                self.assertEqual(done_event.candidate_ref, TelemetryReference.from_identity(TelemetryReferenceKind.CANDIDATE, environment).canonical)
                self.assertEqual(done_event.runtime_ref, TelemetryReference.from_identity(TelemetryReferenceKind.RUNTIME, environment).canonical)

                submission_id = str(uuid4())
                report_code, report = output_for([
                    "report-issue", "--root", str(root), "--run", run.name, "--session-id", session_id,
                    "--host-adapter", "cloud_vscode", "--category", "false_done", "--submission-id", submission_id, "--json",
                ])
                self.assertEqual(report_code, 0, report)
                self.assertEqual(report["status"], "RECORDED")
                self.assertEqual(report["report_status"], "ALLEGATION")
                self.assertEqual(report["semantic_outcome"], "DONE")
                self.assertNotIn("source_text", report)
                lookup_code, lookup = output_for([
                    "issue-status", "--root", str(root), "--run", run.name, "--session-id", session_id,
                    "--report-id", str(report["report_id"]), "--json",
                ])
                self.assertEqual(lookup_code, 0, lookup)
                self.assertEqual(lookup["report_status"], "ALLEGATION")
                self.assertEqual(artifact_snapshot(run), before)
                events = writer.records()
                self.assertTrue(any(event.event_type is TelemetryEventType.ISSUE_REPORT and event.host == "cloud_vscode" and event.semantic_outcome == "DONE" for event in events))
                self.assertNotIn(str(root), writer.event_path.read_text(encoding="utf-8"))

    def test_opencode_report_replay_and_confirmation_use_current_session_binding(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as service_directory:
            root = Path(directory)
            session_id = "opencode-ksa35-session"
            run, _environment = prepare_bound_run(root, session_id, "ksa35-opencode")
            service = Path(service_directory)
            submission_id = str(uuid4())
            with patch.dict(os.environ, {"KSLIDE_OPERATIONAL_SERVICE_ROOT": str(service)}):
                report_args = [
                    "report-issue", "--root", str(root), "--run", run.name, "--session-id", session_id,
                    "--host-adapter", "opencode", "--category", "number_error", "--submission-id", submission_id, "--json",
                ]
                first_code, first = output_for(report_args)
                second_code, second = output_for(report_args)
                self.assertEqual(first_code, 0, first)
                self.assertEqual(second_code, 0, second)
                self.assertEqual(first["status"], "RECORDED")
                self.assertEqual(first["report_id"], second["report_id"])
                self.assertTrue(second["already_recorded"])
                self.assertEqual(len([event for event in TelemetryWriter(service).records() if event.event_type is TelemetryEventType.ISSUE_REPORT]), 1)
                lookup_code, lookup = output_for([
                    "issue-status", "--root", str(root), "--run", run.name, "--session-id", session_id,
                    "--report-id", str(first["report_id"]), "--json",
                ])
                self.assertEqual(lookup_code, 0, lookup)
                self.assertEqual(lookup["issue_category"], "number_error")
                self.assertEqual(TelemetryWriter(service).find(str(first["report_id"]), run_ref=TelemetryWriter(service).records()[0].run_ref).host, "opencode")

    def test_concurrent_duplicate_issue_submissions_persist_one_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as service_directory:
            root = Path(directory)
            session_id = "concurrent-ksa35-session"
            run, _environment = prepare_bound_run(root, session_id, "ksa35-concurrent")
            service = Path(service_directory)
            submission_id = str(uuid4())
            with patch.dict(os.environ, {"KSLIDE_OPERATIONAL_SERVICE_ROOT": str(service)}):
                with ThreadPoolExecutor(max_workers=8) as pool:
                    outcomes = list(pool.map(
                        lambda _index: cli._issue_report(
                            root, run.name, session_id, category="omission", submission_id=submission_id, host="opencode"
                        ),
                        range(16),
                    ))
            self.assertTrue(all(item["status"] == "RECORDED" for item in outcomes))
            self.assertEqual(sum(not item["already_recorded"] for item in outcomes), 1)
            reports = [event for event in TelemetryWriter(service).records() if event.event_type is TelemetryEventType.ISSUE_REPORT]
            self.assertEqual(len(reports), 1)

    def test_session_and_run_authorization_block_cross_tenant_submission_and_lookup(self) -> None:
        with tempfile.TemporaryDirectory() as first_root, tempfile.TemporaryDirectory() as second_root, tempfile.TemporaryDirectory() as service_directory:
            root_a = Path(first_root)
            root_b = Path(second_root)
            session_a = "tenant-a-session"
            session_b = "tenant-b-session"
            run_a, _ = prepare_bound_run(root_a, session_a, "tenant-a")
            run_b, _ = prepare_bound_run(root_b, session_b, "tenant-b")
            service = Path(service_directory)
            with patch.dict(os.environ, {"KSLIDE_OPERATIONAL_SERVICE_ROOT": str(service)}):
                code_b, report_b = output_for([
                    "report-issue", "--root", str(root_b), "--run", run_b.name, "--session-id", session_b,
                    "--host-adapter", "opencode", "--category", "meaning_error", "--submission-id", str(uuid4()), "--json",
                ])
                self.assertEqual(code_b, 0, report_b)
                denied_code, denied = output_for([
                    "report-issue", "--root", str(root_a), "--run", run_b.name, "--session-id", session_a,
                    "--host-adapter", "opencode", "--category", "meaning_error", "--submission-id", str(uuid4()), "--json",
                ])
                self.assertEqual(denied_code, 1)
                self.assertEqual(denied["status"], "FAILED")
                not_found = cli._issue_status(root_a, run_a.name, session_a, str(report_b["report_id"]))
                self.assertEqual(not_found["status"], "NOT_FOUND")
                with self.assertRaises(KSlideError):
                    cli._issue_report(root_a, run_a.name, "unbound-session", category="omission", submission_id=str(uuid4()), host="opencode")

    def test_forged_semantic_status_is_not_an_issue_report_argument(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            cli.build_parser().parse_args([
                "report-issue", "--run", "run-1", "--session-id", "session-1", "--category", "omission",
                "--submission-id", str(uuid4()), "--semantic-outcome", "DONE",
            ])

    def test_legal_hold_unknown_retains_telemetry_until_explicit_release(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as service_directory:
            workspace = Path(directory)
            service = Path(service_directory)
            scope_ref = reference(TelemetryReferenceKind.SCOPE)
            run_ref = reference(TelemetryReferenceKind.RUN)
            event = TelemetryEvent(
                TelemetryEventType.LIFECYCLE,
                reference(TelemetryReferenceKind.EVENT),
                "2020-01-01T00:00:00Z",
                scope_ref=scope_ref,
                run_ref=run_ref,
                lifecycle=TelemetryLifecycle.COMPLETED,
            )
            writer = TelemetryWriter(service)
            self.assertEqual(writer.record(event), TelemetryWriteStatus.RECORDED)
            provider = ReferenceLegalHoldProvider(default_status=LegalHoldStatus.UNKNOWN)
            policy = RetentionPolicy("1.0", 100, 1)
            args = dict(
                scope_context=AuthorizedScopeContext("admin-ref", "workspace-ref", "workspace"),
                hold_provider=provider,
                operational_root=service / "telemetry",
                now=datetime(2026, 1, 3, tzinfo=timezone.utc),
            )
            retained = cleanup_operational_metadata(workspace, policy, **args)
            self.assertEqual(retained["retained_telemetry"], [event.event_id])
            provider.set_release(scope_ref=scope_ref.canonical, run_ref=run_ref.canonical)
            expired = cleanup_operational_metadata(workspace, policy, **args)
            self.assertEqual(expired["expired_telemetry"], [event.event_id])
            self.assertEqual(TelemetryWriter(service).records(), ())


if __name__ == "__main__":
    unittest.main()
