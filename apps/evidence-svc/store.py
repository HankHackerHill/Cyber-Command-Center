"""Streaming, immutable SHA-256 storage in a private POSIX filesystem directory."""

import asyncio
import hashlib
import os
import re
import stat
import tempfile
from collections.abc import AsyncIterable, Callable
from contextlib import ExitStack
from pathlib import Path
from typing import IO, ParamSpec, TypeVar

_P = ParamSpec("_P")
_T = TypeVar("_T")
_SHA256 = re.compile(r"[0-9a-f]{64}")


async def _disk(operation: Callable[_P, _T], *args: _P.args, **kwargs: _P.kwargs) -> _T:
    """Let an in-flight file operation finish before cancellation closes its file."""
    worker = asyncio.create_task(asyncio.to_thread(operation, *args, **kwargs))
    try:
        return await asyncio.shield(worker)
    except asyncio.CancelledError:
        while not worker.done():
            try:
                await asyncio.shield(worker)
            except asyncio.CancelledError:
                continue
        worker.result()
        raise


def _sync_directory(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _require_directory(directory: Path) -> None:
    if not stat.S_ISDIR(directory.lstat().st_mode):
        raise NotADirectoryError(f"unsafe storage directory: {directory}")


class ArtifactStore:
    def __init__(self, root: Path) -> None:
        self.root = Path(os.path.abspath(root))
        self.objects = self.root / "objects"
        # Check every existing component without following symlinks. The service
        # controls this tree and never renames or replaces an object once linked.
        for directory in (*reversed(self.objects.parents), self.objects):
            try:
                _require_directory(directory)
            except FileNotFoundError:
                directory.mkdir(mode=0o700, exist_ok=True)
                _require_directory(directory)
                _sync_directory(directory.parent)
        for directory, forbidden_bits in ((self.root, 0o022), (self.objects, 0o077)):
            metadata = directory.lstat()
            if metadata.st_uid != os.geteuid() or metadata.st_mode & forbidden_bits:
                raise PermissionError(f"unsafe storage directory ownership or permissions: {directory}")

    def path_for(self, sha256: str) -> Path:
        if not _SHA256.fullmatch(sha256):
            raise ValueError("expected a lowercase SHA-256 digest")
        _require_directory(self.root)
        _require_directory(self.objects)
        path = self.objects / sha256
        try:
            mode = path.lstat().st_mode
        except FileNotFoundError:
            return path
        if not stat.S_ISREG(mode):
            raise OSError("unsafe artifact file type")
        return path

    def exists(self, sha256: str) -> bool:
        path = self.path_for(sha256)
        try:
            return stat.S_ISREG(path.lstat().st_mode)
        except FileNotFoundError:
            return False

    def verified(self, sha256: str) -> bool:
        """Check the bytes before using this artifact as promotion evidence."""
        path = self.path_for(sha256)
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            return False
        with os.fdopen(fd, "rb") as stored:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise OSError("unsafe artifact file type")
            return hashlib.file_digest(stored, "sha256").hexdigest() == sha256

    async def put(self, chunks: AsyncIterable[bytes]) -> tuple[str, bool]:
        digest = hashlib.sha256()
        resources = ExitStack()

        def stage() -> tuple[Path, IO[bytes]]:
            _require_directory(self.root)
            _require_directory(self.objects)
            fd, name = tempfile.mkstemp(dir=self.objects, prefix=".upload-")
            path = Path(name)
            resources.callback(path.unlink, missing_ok=True)
            return path, resources.enter_context(os.fdopen(fd, "wb"))

        try:
            path, file = await _disk(stage)

            def append(chunk: bytes) -> None:
                file.write(chunk)
                digest.update(chunk)

            async for chunk in chunks:
                if chunk:
                    await _disk(append, chunk)

            def finish() -> tuple[str, bool]:
                key = digest.hexdigest()
                target = self.path_for(key)
                file.flush()
                os.fsync(file.fileno())
                try:
                    os.link(path, target, follow_symlinks=False)
                    created = True
                except FileExistsError:
                    if not self.verified(key):
                        raise OSError("existing artifact failed SHA-256 verification") from None
                    created = False
                resources.close()  # Remove the staging name before syncing the directory.
                _sync_directory(self.objects)
                return key, created

            return await _disk(finish)
        finally:
            await _disk(resources.close)
