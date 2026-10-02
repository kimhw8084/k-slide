from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from k_slide.errors import KSlideError
from k_slide.installer import install, verify_install


ROOT = Path(__file__).resolve().parents[1]


class InstallIntegrityTests(unittest.TestCase):
    def test_late_engine_collision_cannot_partially_install_host(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            collision = root / ".k-slide-engine" / "termbase" / "core.json"
            collision.parent.mkdir(parents=True)
            collision.write_text("host-owned content")
            with self.assertRaises(KSlideError):
                install(ROOT, root)
            self.assertFalse((root / ".opencode").exists())
            self.assertFalse((root / ".k-slide-install.json").exists())
            self.assertEqual(collision.read_text(), "host-owned content")

    def test_host_and_engine_symlinks_cannot_write_outside_target(self):
        for component in (".opencode", ".k-slide-engine"):
            with self.subTest(component=component), tempfile.TemporaryDirectory() as directory:
                root = Path(directory) / "workspace"
                outside = Path(directory) / "outside"
                root.mkdir()
                outside.mkdir()
                (root / component).symlink_to(outside, target_is_directory=True)
                with self.assertRaises(KSlideError):
                    install(ROOT, root)
                self.assertEqual(list(outside.iterdir()), [])
                self.assertFalse((root / ".k-slide-install.json").exists())

    def test_verify_detects_modified_removed_and_redirected_owned_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            install(ROOT, root)
            owned = root / ".opencode" / "tools" / "kslide.ts"
            original = owned.read_bytes()
            for replacement in (b"local change", None, "symlink"):
                with self.subTest(replacement=replacement):
                    owned.unlink()
                    if isinstance(replacement, bytes):
                        owned.write_bytes(replacement)
                    elif replacement == "symlink":
                        outside = root / "other.ts"
                        outside.write_bytes(original)
                        owned.symlink_to(outside)
                    self.assertFalse(all(ok for _, ok in verify_install(root)))
                    owned.unlink(missing_ok=True)
                    owned.write_bytes(original)
            self.assertTrue(all(ok for _, ok in verify_install(root)))
            (root / ".k-slide-install.json").unlink()
            self.assertFalse(all(ok for _, ok in verify_install(root)))

    def test_reinstall_preserves_modified_files_and_has_complete_build_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = install(ROOT, root)
            before = manifest.read_bytes()
            engine = root / ".k-slide-engine"
            for name in ("README.md", "setup.py", "MANIFEST.in", "security/release-security-policy.json"):
                self.assertTrue((engine / name).is_file(), name)
            self.assertFalse(any(engine.rglob("*.pyc")))
            owned = engine / "src" / "k_slide" / "cli.py"
            owned.write_text("modified by administrator")
            with self.assertRaises(KSlideError):
                install(ROOT, root)
            self.assertEqual(owned.read_text(), "modified by administrator")
            self.assertEqual(manifest.read_bytes(), before)
