"""Private one-shot AccessKey handoff for the trusted K-Slide host boundary."""

from __future__ import annotations

import os


ACCESS_KEY_HANDOFF_FD = 198


class AccessKeyBoundaryError(RuntimeError):
    """Raised when the trusted AccessKey handoff cannot be established."""


class AccessKeyHandoff:
    """Send one opaque AccessKey value through an inherited anonymous pipe."""

    def __init__(self, access_key: str | None):
        self._write_fd: int | None = None
        self._child_fd: int | None = None
        self._access_key = bytearray()
        if access_key is None or access_key == "":
            return
        if not isinstance(access_key, str):
            raise AccessKeyBoundaryError("AccessKey handoff could not be established safely.")
        try:
            os.fstat(ACCESS_KEY_HANDOFF_FD)
        except OSError:
            pass
        else:
            raise AccessKeyBoundaryError("AccessKey handoff descriptor is already occupied.")

        read_fd: int | None = None
        write_fd: int | None = None
        try:
            read_fd, write_fd = os.pipe()
            # os.pipe() can return the reserved number as either endpoint when
            # lower descriptors are occupied. Preserve the write endpoint
            # before replacing the reserved descriptor with the read end.
            if write_fd == ACCESS_KEY_HANDOFF_FD:
                replacement = os.dup(write_fd)
                os.close(write_fd)
                write_fd = replacement
            if read_fd == ACCESS_KEY_HANDOFF_FD:
                os.set_inheritable(ACCESS_KEY_HANDOFF_FD, True)
                self._child_fd = ACCESS_KEY_HANDOFF_FD
            else:
                os.dup2(read_fd, ACCESS_KEY_HANDOFF_FD, inheritable=True)
                self._child_fd = ACCESS_KEY_HANDOFF_FD
                os.close(read_fd)
            read_fd = None
            self._write_fd = write_fd
            write_fd = None
            self._access_key = bytearray(access_key.encode("utf-8"))
        except (OSError, UnicodeError) as exc:
            if read_fd is not None:
                self._close_fd(read_fd)
            if write_fd is not None:
                self._close_fd(write_fd)
            self.close()
            raise AccessKeyBoundaryError("AccessKey handoff could not be established safely.") from exc

    @property
    def pass_fds(self) -> tuple[int, ...]:
        return (self._child_fd,) if self._child_fd is not None else ()

    def send(self) -> None:
        if self._write_fd is None:
            return
        try:
            remaining = memoryview(self._access_key)
            try:
                while remaining:
                    written = os.write(self._write_fd, remaining)
                    if written <= 0:
                        raise OSError("AccessKey handoff made no progress")
                    remaining = remaining[written:]
            finally:
                remaining.release()
        except OSError as exc:
            raise AccessKeyBoundaryError("AccessKey handoff was not consumed by the trusted host boundary.") from exc
        finally:
            self._clear_access_key()
            self._close_write_fd()

    def close(self) -> None:
        self._close_write_fd()
        if self._child_fd is not None:
            self._close_fd(self._child_fd)
            self._child_fd = None
        self._clear_access_key()

    def _close_write_fd(self) -> None:
        if self._write_fd is not None:
            self._close_fd(self._write_fd)
            self._write_fd = None

    def _clear_access_key(self) -> None:
        if self._access_key:
            self._access_key[:] = b"\x00" * len(self._access_key)
            self._access_key.clear()

    @staticmethod
    def _close_fd(descriptor: int) -> None:
        try:
            os.close(descriptor)
        except OSError:
            pass
