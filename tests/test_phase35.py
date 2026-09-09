from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from evals.opencode_diagnostics import run_diagnostic_ladder
from evals.process_control import terminate_process_group
from evals.run_deck_eval import deck_completion_contract
from evals.heavy.doctor import _libreoffice_roundtrip, main as heavy_doctor_main
from k_slide.errors import ErrorCode, KSlideError
from k_slide.ocr.policy import OCRProviderPolicy, create_ocr_provider, load_ocr_policy
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

    def test_heavy_doctor_distinguishes_local_blocked_from_required_failure(self):
        with patch("evals.heavy.doctor._command_version", return_value=None):
            self.assertEqual(_libreoffice_roundtrip(required=False)["status"], "BLOCKED")
            self.assertEqual(_libreoffice_roundtrip(required=True)["status"], "FAIL")

    def test_normal_doctor_allows_capability_blocks(self):
        with patch("evals.heavy.doctor._command_version", return_value=None), patch("evals.heavy.doctor.importlib.util.find_spec", return_value=None), patch("evals.heavy.doctor._font_check", return_value={"status": "PASS"}), patch("builtins.print"):
            self.assertEqual(heavy_doctor_main(required=False), 0)


if __name__ == "__main__":
    unittest.main()
