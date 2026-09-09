from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def run_cli(*arguments: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    return subprocess.run([sys.executable, "-m", "k_slide.cli", *arguments], cwd=cwd, env=env, capture_output=True, text=True, check=False)


class CliBlackBoxTests(unittest.TestCase):
    def test_no_input_prepare_returns_stable_failure_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = run_cli("prepare", "--root", directory, "--json", cwd=ROOT)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("Traceback", result.stdout + result.stderr)
            self.assertEqual(json.loads(result.stdout)["status"], "FAILED_INPUT")

    def test_runtime_and_status_are_json_contracts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runtime = run_cli("runtime", "--json", cwd=ROOT)
            self.assertEqual(runtime.returncode, 0)
            self.assertIn("kslide_version", json.loads(runtime.stdout))
            status = run_cli("status", "--root", directory, "--json", cwd=ROOT)
            self.assertEqual(status.returncode, 0)
            self.assertEqual(json.loads(status.stdout)["status"], "NO_RUN")

    def test_install_and_verify_install_text_contracts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target"
            installed = run_cli("install", "--source-root", str(ROOT), "--target", str(target), "--scope", "project", cwd=ROOT)
            verified = run_cli("verify-install", "--target", str(target), "--scope", "project", cwd=ROOT)
            self.assertEqual(installed.returncode, 0, installed.stderr)
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertIn("[PASS]", verified.stdout)
            self.assertNotIn("Traceback", verified.stdout + verified.stderr)


if __name__ == "__main__":
    unittest.main()
