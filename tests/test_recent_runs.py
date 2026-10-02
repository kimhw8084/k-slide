from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from k_slide.io import atomic_write_json
from k_slide.queue import create_queue, save_queue
from k_slide.session import bind_session, recent_runs, resolve_run
from k_slide.state import RunState, save_state


class RecentRunTests(unittest.TestCase):
    def _run(self, root, name):
        run = root / ".k-slide-runs" / name
        run.mkdir(parents=True)
        state = RunState(name, "private source title")
        state.error_message = "source content that must never be listed"
        save_state(run, state)
        save_queue(run, create_queue(name, input_count=1, now=state.created_at))
        return run

    def test_interruption_before_queue_commit_remains_discoverable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = self._run(root, "k-slide-interrupted")
            (run / "WORK_QUEUE.json").unlink()
            visible = recent_runs(run.parent)
            self.assertEqual(visible[0]["run_id"], run.name)
            self.assertFalse(visible[0]["progress_available"])
            self.assertEqual(visible[0]["verified_units"], 0)

    def test_session_discovery_cannot_enumerate_another_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = self._run(root, "k-slide-one")
            second = self._run(root, "k-slide-two")
            bind_session(first.parent, "first-session", first.name)
            bind_session(first.parent, "second-session", second.name)
            self.assertEqual(recent_runs(first.parent, session_id="unknown"), [])
            self.assertEqual([row["run_id"] for row in recent_runs(first.parent, session_id="first-session")], [first.name])
            visible = recent_runs(first.parent)
            self.assertEqual(len(visible), 2)
            self.assertNotIn("private source", json.dumps(visible))
            self.assertNotIn("source content", json.dumps(visible))
            self.assertNotIn("session", json.dumps(visible))
            self.assertNotIn("DONE", json.dumps(visible))
            self.assertEqual(len(recent_runs(first.parent, limit=1)), 1)

    def test_symlink_deleted_corrupt_and_identity_mismatched_runs_are_hidden(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            good = self._run(root, "k-slide-good")
            hidden = self._run(root, "k-slide-deleting")
            state = RunState(hidden.name, "standard", deletion_fence="IN_PROGRESS")
            atomic_write_json(hidden / "RUN_STATE.json", state.as_dict())
            corrupt = self._run(root, "k-slide-corrupt")
            (corrupt / "RUN_STATE.json").write_text("{broken")
            mismatch = self._run(root, "k-slide-mismatch")
            save_state(mismatch, RunState("k-slide-other-id", "standard"))
            (good.parent / "k-slide-link").symlink_to(good, target_is_directory=True)
            self.assertEqual([row["run_id"] for row in recent_runs(good.parent)], [good.name])
            alias = root / "aliased-runs"
            alias.symlink_to(good.parent, target_is_directory=True)
            self.assertEqual(recent_runs(alias), [])
            self.assertIsNone(resolve_run(alias))
