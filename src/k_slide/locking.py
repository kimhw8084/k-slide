"""Short-lived run locks for state, queue, submit, verify, and finalize mutations."""

from __future__ import annotations

import os
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

try:
    import fcntl
except ImportError:  # pragma: no cover - the managed target is POSIX
    fcntl = None


@contextmanager
def run_lock(run_dir: Path) -> Iterator[None]:
    """Serialize one run's mutable operations without holding a Python global lock."""

    lock_path = run_dir / ".run.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+") as handle:
        os.chmod(lock_path, 0o600)
        if fcntl is not None:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            if fcntl is not None:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
