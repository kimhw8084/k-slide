"""Filesystem locks for state, queue, submit, verify, and finalize mutations."""

from __future__ import annotations

import os
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from .errors import ErrorCode, KSlideError

try:
    fcntl: Any
    import fcntl
except ImportError:  # pragma: no cover - the managed target is POSIX
    fcntl = None


@contextmanager
def filesystem_lock(
    lock_path: Path,
    *,
    require_shared: bool = False,
    reject_symlink: bool = False,
) -> Iterator[None]:
    """Hold an advisory lock on a persistent filesystem inode."""

    if require_shared and fcntl is None:
        raise KSlideError(ErrorCode.INTERNAL, "Durable execution filesystem locking is unavailable.")

    lock_path = Path(lock_path)
    parent = lock_path.parent
    try:
        if reject_symlink and parent.is_symlink():
            raise KSlideError(ErrorCode.INTERNAL, "Durable execution filesystem mutation lock is invalid.")
        parent.mkdir(parents=True, exist_ok=True)
        if reject_symlink and parent.is_symlink():
            raise KSlideError(ErrorCode.INTERNAL, "Durable execution filesystem mutation lock is invalid.")
        if reject_symlink:
            os.chmod(parent, 0o700)
        if reject_symlink and lock_path.is_symlink():
            raise KSlideError(ErrorCode.INTERNAL, "Durable execution filesystem mutation lock is invalid.")
        flags = os.O_RDWR | os.O_CREAT
        if reject_symlink and hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(lock_path, flags, 0o600)
    except KSlideError:
        raise
    except OSError as exc:
        if require_shared:
            raise KSlideError(ErrorCode.INTERNAL, "Durable execution filesystem locking is unavailable.") from exc
        raise

    locked = False
    try:
        if reject_symlink and lock_path.is_symlink():
            raise KSlideError(ErrorCode.INTERNAL, "Durable execution filesystem mutation lock is invalid.")
        try:
            os.fchmod(descriptor, 0o600)
            if fcntl is not None:
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                locked = True
        except OSError as exc:
            if require_shared:
                raise KSlideError(ErrorCode.INTERNAL, "Durable execution filesystem locking is unavailable.") from exc
            raise
        yield
    finally:
        try:
            if locked and fcntl is not None:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


@contextmanager
def run_lock(run_dir: Path, *, bypass_deletion_fence: bool = False) -> Iterator[None]:
    """Serialize one run's mutable operations without holding a Python global lock."""

    # The lock is recreateable coordination state, not durable run data.
    from .storage import StorageArtifact, StorageLayout

    lock_path = StorageLayout.for_workspace(run_dir, bypass_deletion_fence=bypass_deletion_fence).path(StorageArtifact.COORDINATION_LOCK, ".run.lock", create_parent=True)
    with filesystem_lock(lock_path):
        yield
