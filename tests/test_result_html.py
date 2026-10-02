from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from k_slide.decision_view import read_presentation
from k_slide.rendering.decision_html import _media, decision_html
from k_slide.rendering.reports import render_run
from tests import test_decision_view as fixture


class ResultHTMLTests(unittest.TestCase):
    def test_untrusted_text_is_escaped_and_html_is_bound_to_presentation(self):
        with tempfile.TemporaryDirectory() as directory:
            run, _ = fixture.DecisionViewTests()._run(Path(directory))
            render_run(run)
            descriptor = read_presentation(run)
            self.assertEqual(descriptor["actions"][0]["html_path"], "05_decision_view.html")
            view = json.loads((run / "05_decision_view.json").read_text())
            view["sections"]["key_takeaway"]["items"][0]["text"] = '<script>alert("source")</script><img src="https://evil.invalid">'
            html = decision_html(run, view)
            self.assertNotIn("<script>", html)
            self.assertIn("&lt;script&gt;", html)
            self.assertNotIn('<img src="https://', html)
            self.assertIn("Content-Security-Policy", html)
            self.assertIn('lang="en"', html)
            self.assertIn("@media print", html)
            self.assertIn("Review status before relying", html)
            (run / "05_decision_view.html").write_text("tampered")
            with self.assertRaises(ValueError):
                read_presentation(run)

    def test_media_paths_cannot_escape_run_or_load_active_content(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = root / "run"
            run.mkdir()
            (root / "private.png").write_bytes(b"private")
            (run / "symlink.png").symlink_to(root / "private.png")
            (run / "active.svg").write_text('<svg onload="alert(1)"/>')
            for value in ("../private.png", "symlink.png", "active.svg", "https://evil.invalid/a.png", str(root / "private.png")):
                with self.subTest(value=value):
                    self.assertIsNone(_media(run, value))


if __name__ == "__main__":
    unittest.main()
