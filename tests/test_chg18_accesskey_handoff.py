from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from k_slide.access_key_handoff import AccessKeyBoundaryError, AccessKeyHandoff, ACCESS_KEY_HANDOFF_FD
from k_slide.opencode_bootstrap import APPROVED_CREDENTIAL_ENV, COMPANY_ACCESS_KEY_ENV, main
from tests.test_chg18_opencode_bootstrap import _write_bootstrap


def _descriptor_is_open(descriptor: int) -> bool:
    try:
        os.fstat(descriptor)
    except OSError:
        return False
    return True


class AccessKeyHandoffTests(unittest.TestCase):
    CANARY = "KSA18-FIX07-OPAQUE-CANARY::🧪::no-format-assumptions"

    def test_missing_key_is_absent_without_reserving_descriptor(self) -> None:
        was_open = _descriptor_is_open(ACCESS_KEY_HANDOFF_FD)
        handoff = AccessKeyHandoff(None)
        try:
            self.assertEqual(handoff.pass_fds, ())
            handoff.send()
        finally:
            handoff.close()
        self.assertEqual(_descriptor_is_open(ACCESS_KEY_HANDOFF_FD), was_open)

    def test_reserved_descriptor_fails_closed_without_secret_text(self) -> None:
        backup: int | None = None
        try:
            if _descriptor_is_open(ACCESS_KEY_HANDOFF_FD):
                backup = os.dup(ACCESS_KEY_HANDOFF_FD)
            else:
                read_fd, write_fd = os.pipe()
                os.close(read_fd)
                os.dup2(write_fd, ACCESS_KEY_HANDOFF_FD, inheritable=False)
                os.close(write_fd)
            with self.assertRaisesRegex(AccessKeyBoundaryError, "^AccessKey handoff descriptor is already occupied\\.$") as raised:
                AccessKeyHandoff(self.CANARY)
            self.assertNotIn(self.CANARY, str(raised.exception))
        finally:
            if backup is not None:
                os.dup2(backup, ACCESS_KEY_HANDOFF_FD, inheritable=False)
                os.close(backup)
            else:
                os.close(ACCESS_KEY_HANDOFF_FD)

    def test_setup_and_write_failures_are_fixed_and_clear_buffers(self) -> None:
        with patch("k_slide.access_key_handoff.os.pipe", side_effect=OSError("synthetic setup detail")):
            with self.assertRaisesRegex(AccessKeyBoundaryError, "^AccessKey handoff could not be established safely\\.$") as raised:
                AccessKeyHandoff(self.CANARY)
            self.assertNotIn(self.CANARY, str(raised.exception))

        handoff = AccessKeyHandoff(self.CANARY)
        try:
            with patch("k_slide.access_key_handoff.os.write", side_effect=OSError("synthetic write detail")):
                with self.assertRaisesRegex(AccessKeyBoundaryError, "^AccessKey handoff was not consumed by the trusted host boundary\\.$") as raised:
                    handoff.send()
                self.assertNotIn(self.CANARY, str(raised.exception))
            self.assertIsNone(handoff._write_fd)
            self.assertEqual(handoff._access_key, bytearray())
        finally:
            handoff.close()

    def test_one_shot_send_closes_parent_write_and_child_read_receives_exact_bytes(self) -> None:
        handoff = AccessKeyHandoff(self.CANARY)
        child = None
        try:
            child = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    "import os, sys; chunks=[]\nwhile True:\n chunk=os.read(198, 65536)\n if not chunk: break\n chunks.append(chunk)\nos.close(198)\nsys.stdout.buffer.write(b''.join(chunks))",
                ],
                env={"PATH": os.environ.get("PATH", os.defpath)},
                pass_fds=handoff.pass_fds,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
            handoff.send()
            handoff.send()
            stdout, stderr = child.communicate(timeout=5)
            self.assertEqual(child.returncode, 0, stderr.decode())
            self.assertEqual(stdout.decode("utf-8"), self.CANARY)
            self.assertEqual(stderr, b"")
            self.assertIsNone(handoff._write_fd)
            self.assertEqual(handoff._access_key, bytearray())
        finally:
            handoff.close()
            if child is not None and child.poll() is None:
                child.kill()
                child.wait()
        self.assertFalse(_descriptor_is_open(ACCESS_KEY_HANDOFF_FD))

    def test_large_opaque_value_does_not_require_prefilling_before_child_reads(self) -> None:
        value = "KSA18-LARGE-" + ("opaque-" * 40000)
        handoff = AccessKeyHandoff(value)
        child = None
        try:
            child = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    "import hashlib, os, sys; chunks=[]\nwhile True:\n chunk=os.read(198, 65536)\n if not chunk: break\n chunks.append(chunk)\nos.close(198)\npayload=b''.join(chunks)\nprint(len(payload))\nprint(hashlib.sha256(payload).hexdigest())",
                ],
                env={"PATH": os.environ.get("PATH", os.defpath)},
                pass_fds=handoff.pass_fds,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
            handoff.send()
            stdout, stderr = child.communicate(timeout=5)
            self.assertEqual(child.returncode, 0, stderr)
            self.assertEqual(stdout.splitlines(), [str(len(value.encode("utf-8"))), hashlib.sha256(value.encode("utf-8")).hexdigest()])
        finally:
            handoff.close()
            if child is not None and child.poll() is None:
                child.kill()
                child.wait()

    def test_managed_launcher_preserves_exact_key_only_for_trusted_core(self) -> None:
        host = textwrap.dedent(
            f"""
            import json, os, subprocess, sys, textwrap

            CANARY = {self.CANARY!r}
            HANDOFF_FD = 198
            chunks = []
            try:
                while True:
                    chunk = os.read(HANDOFF_FD, 65536)
                    if not chunk:
                        break
                    chunks.append(chunk)
            finally:
                try:
                    os.close(HANDOFF_FD)
                except OSError:
                    pass
            received = b"".join(chunks).decode("utf-8")
            generic_environment = os.environ.copy()
            provider = subprocess.run(
                [sys.executable, "-c", "import json, os; value=os.environ.get('AccessKey', ''); print(json.dumps({{'has_access_key': bool(value), 'has_canary': {self.CANARY!r} in value}}))"],
                env=generic_environment,
                capture_output=True,
                text=True,
                check=False,
            )
            core_environment = generic_environment.copy()
            core_environment["AccessKey"] = received
            core_code = textwrap.dedent('''
                import json, os
                from k_slide.authentication import CompanyServiceRequest, reference_company_service_call

                observed = {{}}
                class Transport:
                    def call(self, request, *, access_key):
                        observed["exact_dedicated_argument"] = access_key == os.environ.get("AccessKey")
                        observed["dedicated_argument_matches_core_env"] = access_key == os.environ.get("AccessKey")
                        observed["request_has_credential_field"] = "accesskey" in json.dumps(request.as_dict()).lower()
                        return {{"status": "ok"}}

                response = reference_company_service_call(Transport(), CompanyServiceRequest("approved.lookup", {{"ordinary": "business"}}))
                print(json.dumps({{"response_ok": response == {{"status": "ok"}}, **observed}}))
            ''')
            core = subprocess.run([sys.executable, "-c", core_code], env=core_environment, capture_output=True, text=True, check=False)
            provider_observed = json.loads(provider.stdout)
            core_observed = json.loads(core.stdout)
            print(json.dumps({{
                "received_exact": received == CANARY,
                "descriptor_closed": not os.path.exists(f"/proc/self/fd/{{HANDOFF_FD}}"),
                "generic_environment_has_access_key": "AccessKey" in generic_environment,
                "provider": provider_observed,
                "provider_output_has_canary": CANARY in provider.stdout or CANARY in provider.stderr,
                "core": core_observed,
                "core_output_has_canary": CANARY in core.stdout or CANARY in core.stderr,
            }}))
            """
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = _write_bootstrap(root)
            script = root / "synthetic-opencode-host.py"
            script.write_text(host, encoding="utf-8")
            environment = {
                "PATH": os.environ.get("PATH", os.defpath),
                "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src"),
                APPROVED_CREDENTIAL_ENV: "google-provider-key",
                COMPANY_ACCESS_KEY_ENV: self.CANARY,
            }
            result = subprocess.run(
                [sys.executable, "-m", "k_slide.opencode_bootstrap", "--manifest", str(manifest), "--", sys.executable, str(script)],
                cwd=str(root),
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            observed = json.loads(result.stdout)
            self.assertEqual(
                observed,
                {
                    "received_exact": True,
                    "descriptor_closed": True,
                    "generic_environment_has_access_key": False,
                    "provider": {"has_access_key": False, "has_canary": False},
                    "provider_output_has_canary": False,
                    "core": {
                        "response_ok": True,
                        "exact_dedicated_argument": True,
                        "dedicated_argument_matches_core_env": True,
                        "request_has_credential_field": False,
                    },
                    "core_output_has_canary": False,
                },
            )
            self.assertNotIn(self.CANARY, result.stdout)
            self.assertNotIn(self.CANARY, result.stderr)

    def test_managed_launcher_missing_key_has_no_descriptor_and_child_exit_is_preserved(self) -> None:
        host = "import json, os, sys; print(json.dumps({'access_key_env': 'AccessKey' in os.environ, 'handoff_fd_open': os.path.exists('/proc/self/fd/198')})); raise SystemExit(23)"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = _write_bootstrap(root)
            script = root / "synthetic-opencode-no-key.py"
            script.write_text(host, encoding="utf-8")
            environment = {
                "PATH": os.environ.get("PATH", os.defpath),
                "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src"),
                APPROVED_CREDENTIAL_ENV: "google-provider-key",
            }
            result = subprocess.run(
                [sys.executable, "-m", "k_slide.opencode_bootstrap", "--manifest", str(manifest), "--", sys.executable, str(script)],
                cwd=str(root),
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 23)
            self.assertEqual(json.loads(result.stdout), {"access_key_env": False, "handoff_fd_open": False})
            self.assertEqual(result.stderr, "")

    def test_managed_launcher_setup_failure_is_source_free(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = _write_bootstrap(root)
            environment = {
                "PATH": os.environ.get("PATH", os.defpath),
                "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src"),
                APPROVED_CREDENTIAL_ENV: "google-provider-key",
                COMPANY_ACCESS_KEY_ENV: self.CANARY,
            }
            stderr = StringIO()
            with patch.dict(os.environ, environment, clear=True), patch("k_slide.access_key_handoff.os.pipe", side_effect=OSError("secret setup detail")), redirect_stderr(stderr):
                result = main(["--manifest", str(manifest), "--", sys.executable, "-c", "raise SystemExit(99)"])
            self.assertEqual(result, 78)
            self.assertEqual(stderr.getvalue(), "KSLIDE_OPENCODE_BOOTSTRAP_HANDOFF_FAILED: AccessKey handoff could not be established safely.\n")
            self.assertNotIn(self.CANARY, stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
