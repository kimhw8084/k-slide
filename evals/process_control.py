"""Bounded process-group cleanup for evaluation subprocesses."""

from __future__ import annotations

import os
import signal
import subprocess
from typing import Any


def terminate_process_group(process: Any, *, grace_seconds: float = 5.0) -> dict[str, Any]:
    """Terminate and reap a process tree started in its own session.

    The helper is intentionally tolerant of already-exited processes so timeout
    paths can use it safely from exception handlers.
    """

    pid = getattr(process, "pid", None)
    if not pid:
        return {"sigterm_sent": False, "sigkill_sent": False, "reaped": True}
    sigterm_sent = False
    sigkill_sent = False
    try:
        os.killpg(pid, signal.SIGTERM)
        sigterm_sent = True
    except ProcessLookupError:
        pass
    except OSError:
        try:
            process.terminate()
            sigterm_sent = True
        except OSError:
            pass
    try:
        process.wait(timeout=grace_seconds)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(pid, signal.SIGKILL)
            sigkill_sent = True
        except ProcessLookupError:
            pass
        except OSError:
            try:
                process.kill()
                sigkill_sent = True
            except OSError:
                pass
        try:
            process.wait(timeout=grace_seconds)
        except subprocess.TimeoutExpired:
            return {"sigterm_sent": sigterm_sent, "sigkill_sent": sigkill_sent, "reaped": False}
    return {"sigterm_sent": sigterm_sent, "sigkill_sent": sigkill_sent, "reaped": True}
