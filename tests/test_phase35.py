from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from evals.opencode_diagnostics import run_diagnostic_ladder
from evals.process_control import terminate_process_group
from evals.release import build_release_manifest, build_sbom
from evals.run_deck_eval import deck_completion_contract
from evals.heavy.doctor import _libreoffice_roundtrip, main as heavy_doctor_main
from k_slide.errors import ErrorCode, KSlideError
from k_slide.ocr.policy import OCRProviderPolicy, create_ocr_provider, load_ocr_policy
from k_slide.doctor import diagnose
from k_slide.production import production_checks
from k_slide.redaction import redact_text, redact_value
from k_slide.retention import cleanup_expired_runs
from k_slide.support import build_support_bundle
from k_slide.translation_contract import (
    CLAIM_KIND_VALUES,
    COMMITMENT_VALUES,
    CONTRACT_FIELDS,
    DIRECTION_VALUES,
    RELATION_TYPE_VALUES,
    SPEECH_ACT_VALUES,
    TRANSLATION_PATCH_SCHEMA_VERSION,
    UNCERTAINTY_VALUES,
)


ROOT = Path(__file__).resolve().parents[1]


class Phase35Tests(unittest.TestCase):
    def test_full_translation_contract_matches_schema_and_typescript(self):
        schema = json.loads((ROOT / "schemas" / "translation-patch.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(schema["properties"]["schema_version"]["const"], TRANSLATION_PATCH_SCHEMA_VERSION)
        self.assertEqual(set(schema["required"]), CONTRACT_FIELDS["root"][0])
        for name, (required, optional) in CONTRACT_FIELDS.items():
            if name == "root":
                continue
            definition = schema["$defs"][name]
            self.assertEqual(set(definition.get("required", [])), required)
            self.assertEqual(set(definition["properties"]) - required, optional)
        self.assertEqual(tuple(schema["$defs"]["relation"]["properties"]["relation_type"]["enum"]), RELATION_TYPE_VALUES)
        self.assertEqual(tuple(schema["$defs"]["relation"]["properties"]["direction"]["enum"]), DIRECTION_VALUES)
        self.assertNotIn(None, schema["$defs"]["relation"]["properties"]["direction"]["enum"])
        typescript = (ROOT / ".opencode" / "tools" / "kslide.ts").read_text(encoding="utf-8")
        self.assertIn('schema_version: tool.schema.enum(["1.0"])', typescript)
        for field in ("hangul_retention", "source_element_ids", "relation_type", "direction"):
            self.assertIn(field, typescript)
        for value in (*COMMITMENT_VALUES, *SPEECH_ACT_VALUES, *RELATION_TYPE_VALUES, *DIRECTION_VALUES, *CLAIM_KIND_VALUES, *UNCERTAINTY_VALUES):
            self.assertIn(value, typescript)

    def test_ocr_missing_config_uses_managed_default(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(load_ocr_policy(Path(directory)), OCRProviderPolicy.AUTO)

    def test_ocr_malformed_config_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / ".k-slide-config"
            config.mkdir()
            (config / "ocr.local.json").write_text('{"ocr_provider":', encoding="utf-8")
            with self.assertRaises(KSlideError) as raised:
                load_ocr_policy(root)
            self.assertEqual(raised.exception.code, ErrorCode.CONFIG_INVALID)
            (config / "ocr.local.json").unlink()
            (config / "ocr.local.yaml").write_text("ocr_provider:\n", encoding="utf-8")
            with self.assertRaises(KSlideError) as raised:
                load_ocr_policy(root)
            self.assertEqual(raised.exception.code, ErrorCode.CONFIG_INVALID)

    def test_unknown_ocr_provider_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / ".k-slide-config"
            config.mkdir()
            (config / "ocr.local.json").write_text('{"ocr_provider":"imaginary"}', encoding="utf-8")
            with self.assertRaises(KSlideError) as raised:
                load_ocr_policy(Path(directory))
            self.assertEqual(raised.exception.code, ErrorCode.CONFIG_INVALID)

    def test_auto_fallback_records_original_reason(self):
        with patch("k_slide.ocr.policy._paddle_available", return_value=False):
            selection = create_ocr_provider(OCRProviderPolicy.AUTO)
        self.assertTrue(selection.fallback)
        self.assertEqual(selection.fallback_code, ErrorCode.OCR_PROVIDER_UNAVAILABLE.value)
        self.assertEqual(selection.as_dict()["ocr_fallback_code"], ErrorCode.OCR_PROVIDER_UNAVAILABLE.value)

    def test_timeout_terminates_process_group_and_reaps(self):
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "stubborn.py"
            script.write_text("import signal, subprocess, sys, time\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)\nchild = subprocess.Popen([sys.executable, '-c', 'import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(30)'])\nprint(child.pid, flush=True)\ntime.sleep(30)\n", encoding="utf-8")
            process = subprocess.Popen([sys.executable, str(script)], stdout=subprocess.PIPE, text=True, start_new_session=True)
            child_pid = int(process.stdout.readline().strip())
            result = terminate_process_group(process, grace_seconds=0.1)
            process.wait(timeout=2)
            process.stdout.close()
            self.assertTrue(result["reaped"])
            self.assertTrue(result["sigkill_sent"])
            self.assertIsNotNone(process.returncode)
            # A group member may briefly appear as a zombie while the platform
            # reaps it.  Check that it is no longer running rather than using
            # kill(pid, 0), which reports zombies as existing on macOS/Linux.
            child_is_running = True
            for _ in range(20):
                probe = subprocess.run(["ps", "-o", "stat=", "-p", str(child_pid)], capture_output=True, text=True, check=False)
                state = probe.stdout.strip()
                if not state or state.startswith("Z"):
                    child_is_running = False
                    break
                time.sleep(0.05)
            self.assertFalse(child_is_running)

    def test_diagnostic_levels_use_isolated_workspaces(self):
        with tempfile.TemporaryDirectory() as directory:
            fake = Path(directory) / "fake-opencode.py"
            fake.write_text("#!/usr/bin/env python3\nimport json,sys\na=sys.argv[1:]\nif '--version' in a: print('1.3.9'); raise SystemExit\nif a[:2] == ['debug','config']: print('{}'); raise SystemExit\nif a[:1] == ['models']: print('ollama/qwen3:14b'); raise SystemExit\nif a[:1] == ['--help']: print('run models'); raise SystemExit\nif 'run' in a: print(json.dumps({'type':'text','text':'OK'})); raise SystemExit\n", encoding="utf-8")
            fake.chmod(0o755)
            result = run_diagnostic_ladder(model="ollama/qwen3:14b", output=Path(directory) / "out", opencode=str(fake), cold_timeout=5, warm_timeout=5)
        self.assertEqual(result["workspace_assertions"]["clean_has_project_opencode"], False)
        self.assertEqual(result["workspace_assertions"]["clean_has_engine"], False)
        self.assertEqual(result["workspace_assertions"]["clean_has_k_slide_config"], False)
        self.assertEqual(result["workspace_assertions"]["kslide_has_project_opencode"], True)
        level1_command = next(item for item in result["levels"] if item["level"] == "level1_plain_opencode")["command"]
        self.assertIn("--dir", level1_command)
        self.assertTrue(any("workspace-clean" in item for item in level1_command))
        self.assertTrue(any(item["level"] == "level3_k_slide_agent" for item in result["levels"]))

    def test_level1_runtime_failure_is_not_classified_as_k_slide(self):
        with tempfile.TemporaryDirectory() as directory:
            fake = Path(directory) / "fake-opencode.py"
            fake.write_text("#!/usr/bin/env python3\nimport sys,time\na=sys.argv[1:]\nif '--version' in a: print('1.3.9'); raise SystemExit\nif a[:2] == ['debug','config']: print('{}'); raise SystemExit\nif a[:1] == ['--help']: print('run models'); raise SystemExit\nif a[:1] == ['models']: print('model'); raise SystemExit\nif 'run' in a: time.sleep(30)\n", encoding="utf-8")
            fake.chmod(0o755)
            result = run_diagnostic_ladder(model="test/model", output=Path(directory) / "out", opencode=str(fake), cold_timeout=1, warm_timeout=1)
        self.assertEqual(result["first_failed_level"], "level1_plain_opencode")
        self.assertEqual(result["conclusion"], "OPENCODE_PROVIDER_RUNTIME_BLOCKED")
        self.assertEqual(result["install"]["status"], "SKIPPED_UPSTREAM_BLOCKED")

    def test_deck_pass_requires_complete_artifacts_and_media(self):
        result = SimpleNamespace(status="PROTOCOL_SMOKE_ONLY", kslide_complete=True, media_compliance={"work_units": {"u1": {"media_sequence_valid": True}}})
        self.assertTrue(deck_completion_contract(result, expected_units=1, artifact_units=1)["pass"])
        incomplete = deck_completion_contract(result, expected_units=3, artifact_units=2)
        self.assertFalse(incomplete["pass"])
        self.assertIn("DECK_INCOMPLETE", incomplete["failures"])

    def test_heavy_workflow_persists_host_output_and_requires_capabilities(self):
        workflow = (ROOT.parent / ".github" / "workflows" / "k-slide-phase32.yml").read_text(encoding="utf-8")
        self.assertIn("--network none", workflow)
        self.assertIn("${RUNNER_TEMP}/k-slide-heavy-engine-subset:/out", workflow)
        self.assertIn("--fail-on-critical", workflow)
        for scenario_id in ("scenario-0002", "scenario-0017", "scenario-0031", "scenario-0051", "scenario-0066"):
            self.assertIn(scenario_id, workflow)
        self.assertIn("if: always()", workflow)
        dockerfile = (ROOT / "evals" / "heavy" / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("prefetch_ocr_models", dockerfile)
        self.assertIn("KSLIDE_PADDLE_REQUIRE_LOCAL_ASSETS=1", dockerfile)
        self.assertIn("PRODUCTION_LOCK", dockerfile)
        self.assertIn("installed_dependency_inventory", dockerfile)
        self.assertNotIn("Pillow>=10,<13", dockerfile)
        self.assertNotIn("paddlepaddle==${PADDLEPADDLE_VERSION}", dockerfile)
        self.assertIn("freeze_production_dependencies", workflow)
        self.assertIn("Freeze exact production dependency subject", workflow)
        self.assertIn("Verify heavy image dependency identity", workflow)
        self.assertIn("certification_bundle_run_id", workflow)
        self.assertIn("materialize_certification_bundle", workflow)
        self.assertIn("built-image-inventory.json", workflow)
        self.assertIn("dependency-context.json", workflow)
        self.assertIn("heavy_runtime.evidence.json", workflow)
        self.assertIn("set -o pipefail", workflow)
        self.assertNotIn("production_dependency_lock:", workflow)

    def test_heavy_doctor_distinguishes_local_blocked_from_required_failure(self):
        with patch("evals.heavy.doctor._command_version", return_value=None):
            self.assertEqual(_libreoffice_roundtrip(required=False)["status"], "BLOCKED")
            self.assertEqual(_libreoffice_roundtrip(required=True)["status"], "FAIL")

    def test_normal_doctor_allows_capability_blocks(self):
        with patch("evals.heavy.doctor._command_version", return_value=None), patch("evals.heavy.doctor.importlib.util.find_spec", return_value=None), patch("evals.heavy.doctor._font_check", return_value={"status": "PASS"}), patch("builtins.print"):
            self.assertEqual(heavy_doctor_main(required=False), 0)

    def test_agent_denies_headless_interactive_and_dangerous_permissions(self):
        agent = (ROOT / ".opencode" / "agents" / "k-slide.md").read_text(encoding="utf-8")
        for permission in ("question: deny", "external_directory: deny", "doom_loop: deny", "bash: deny", "edit: deny", "write: deny", "task: deny", "webfetch: deny", "websearch: deny"):
            self.assertIn(permission, agent)

    def test_redaction_removes_secrets_content_and_home_paths(self):
        text = f"Authorization: Bearer abc123 password=secret file={Path.home()}/private"
        safe = redact_text(text)
        self.assertNotIn("abc123", safe)
        self.assertNotIn("secret", safe)
        self.assertNotIn(str(Path.home()), safe)
        self.assertEqual(redact_value({"text": "검토", "api_key": "secret"}), {"text": "[REDACTED_CONTENT]", "api_key": "[REDACTED_SECRET]"})

    def test_retention_removes_only_expired_terminal_runs(self):
        from datetime import datetime, timedelta, timezone

        now = datetime(2026, 9, 9, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_root = root / ".k-slide-runs"
            run_root.mkdir(mode=0o700)
            for run_id, phase, updated in (("active", "TRANSLATING", now - timedelta(days=100)), ("recent", "COMPLETE", now - timedelta(days=1)), ("expired", "COMPLETE", now - timedelta(days=100)), ("failed", "FAILED_RUNTIME", now - timedelta(days=100))):
                run = run_root / run_id
                run.mkdir(mode=0o700)
                (run / "RUN_STATE.json").write_text(json.dumps({"phase": phase, "updated_at": updated.isoformat()}), encoding="utf-8")
            result = cleanup_expired_runs(root, 30, now=now)
            self.assertEqual({item["run_id"] for item in result["removed"]}, {"expired", "failed"})
            self.assertTrue((run_root / "active").is_dir())
            self.assertTrue((run_root / "recent").is_dir())

    def test_retention_symlink_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            run_root = root / ".k-slide-runs"
            run_root.mkdir(mode=0o700)
            (run_root / "link").symlink_to(Path(outside), target_is_directory=True)
            with self.assertRaises(KSlideError) as raised:
                cleanup_expired_runs(root, 1)
            self.assertEqual(raised.exception.code, ErrorCode.RETENTION_REFUSED)
            self.assertTrue(Path(outside).is_dir())

    def test_production_checks_fail_closed_without_profile(self):
        runtime = SimpleNamespace(opencode_version="1.3.9", reported_model_id="ollama/qwen3:14b", vision_support=None)
        with tempfile.TemporaryDirectory() as directory:
            checks = production_checks(Path(directory), runtime)
        self.assertTrue(any(item["status"] == "FAIL" for item in checks))

    def test_production_doctor_redacts_local_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            result = diagnose(Path(directory), production=True)
        serialized = json.dumps(result, ensure_ascii=False)
        self.assertNotIn(str(Path.home()), serialized)

    def test_support_bundle_excludes_source_content(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = root / ".k-slide-runs" / "run-001"
            run.mkdir(parents=True, mode=0o700)
            (run / "RUN_STATE.json").write_text(json.dumps({"phase": "COMPLETE", "run_id": "run-001"}), encoding="utf-8")
            (run / "RUN_MANIFEST.json").write_text(json.dumps({"run_id": "run-001", "input_count": 1}), encoding="utf-8")
            (run / "WORK_QUEUE.json").write_text(json.dumps({"queue_revision": "q1", "work_units": [{"status": "VERIFIED", "translation_attempts": 1}]}), encoding="utf-8")
            (run / "05_final_report.md").write_text("confidential Korean 검토 text", encoding="utf-8")
            output = root / "support.zip"
            result = build_support_bundle(root, output)
            self.assertFalse(result["source_content_included"])
            with zipfile.ZipFile(output) as archive:
                content = archive.read("support-metadata.json").decode("utf-8")
            self.assertNotIn("검토", content)
            self.assertNotIn("05_final_report", content)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)

    def test_release_metadata_is_explicitly_development_without_attestations(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = build_release_manifest(root)
            self.assertEqual(manifest["release_state"], "DEVELOPMENT")
            self.assertEqual(len(manifest["deployment_fingerprint"]), 64)
            self.assertEqual(manifest["certification_fingerprint"], "UNSET")
            self.assertIn("subject_git_sha", manifest)
            self.assertEqual(manifest["attestations"]["internal_bilingual"], "UNSET")
            self.assertEqual(manifest["attestations"]["zero_korean_comprehension"], "UNSET")
            sbom = build_sbom(root)
            self.assertEqual(sbom["bomFormat"], "CycloneDX")
            self.assertIn({"name": "k-slide:completeness", "value": "development"}, sbom["metadata"]["component"]["properties"])

    def test_release_workflow_is_manual_and_certification_gated(self):
        workflow = (ROOT.parent / ".github" / "workflows" / "k-slide-release.yml").read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch", workflow)
        self.assertNotIn("on:\n  push:", workflow)
        self.assertIn("--require-certified", workflow)
        self.assertIn("--requested-state", workflow)
        self.assertIn("SBOM.json", workflow)


if __name__ == "__main__":
    unittest.main()
