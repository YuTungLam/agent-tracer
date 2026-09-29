"""Small cross-platform advisory file-lock helpers."""

from __future__ import annotations

import os
from typing import IO, Any

if os.name == "nt":  # pragma: win32 cover
    import msvcrt
else:  # pragma: posix cover
    import fcntl


def acquire_exclusive_nonblocking(stream: IO[Any]) -> None:
    """Acquire a one-writer advisory lock or raise BlockingIOError."""
    if os.name == "nt":  # pragma: win32 cover
        stream.flush()
        descriptor = stream.fileno()
        if os.fstat(descriptor).st_size == 0:
            os.write(descriptor, b"\0")
        os.lseek(descriptor, 0, os.SEEK_SET)
        try:
            msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
        except OSError as exc:
            raise BlockingIOError("file is already locked") from exc
        return
    fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)


def release(stream: IO[Any]) -> None:
    """Release a lock acquired by acquire_exclusive_nonblocking."""
    if os.name == "nt":  # pragma: win32 cover
        stream.flush()
        descriptor = stream.fileno()
        os.lseek(descriptor, 0, os.SEEK_SET)
        msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        return
    fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
