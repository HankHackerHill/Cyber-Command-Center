import asyncio
import hashlib
import os
from collections.abc import AsyncIterator
from pathlib import Path
from threading import Event

import pytest

from store import ArtifactStore


async def chunks(*parts: bytes) -> AsyncIterator[bytes]:
    for part in parts:
        yield part


HAR = Path(__file__).resolve().parents[3] / "tests/fixtures/har_sample.har"


@pytest.mark.parametrize("data", [b"", bytes(range(256)), HAR.read_bytes()])
def test_exact_bytes_and_idempotent_put(tmp_path: Path, data: bytes) -> None:
    store = ArtifactStore(tmp_path / "store")
    expected = hashlib.sha256(data).hexdigest()
    assert not store.exists(expected) and not store.verified(expected)
    assert asyncio.run(store.put(chunks(data[:3], b"", data[3:]))) == (expected, True)
    path = store.path_for(expected)
    inode = path.stat().st_ino
    assert store.exists(expected) and store.verified(expected)
    assert path.read_bytes() == data
    assert asyncio.run(store.put(chunks(data))) == (expected, False)
    assert path.stat().st_ino == inode
    assert list(store.objects.iterdir()) == [path]


def test_store_instances_race_to_publish(tmp_path: Path) -> None:
    stores = [ArtifactStore(tmp_path) for _ in range(12)]
    body = b"shared artifact" * 1024

    async def uploads() -> list[tuple[str, bool]]:
        return await asyncio.gather(*(store.put(chunks(body)) for store in stores))

    results = asyncio.run(uploads())
    expected = hashlib.sha256(body).hexdigest()
    assert set(digest for digest, _ in results) == {expected}
    assert sum(created for _, created in results) == 1
    assert list(stores[0].objects.iterdir()) == [stores[0].path_for(expected)]


def test_partial_and_cancelled_uploads_leave_no_object(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path)

    async def disconnected() -> AsyncIterator[bytes]:
        yield b"incomplete"
        raise ConnectionResetError

    with pytest.raises(ConnectionResetError):
        asyncio.run(store.put(disconnected()))
    assert list(store.objects.iterdir()) == []

    async def cancel() -> None:
        partial = asyncio.Event()

        async def slow() -> AsyncIterator[bytes]:
            yield b"partial"
            partial.set()
            await asyncio.Event().wait()

        worker = asyncio.create_task(store.put(slow()))
        await asyncio.wait_for(partial.wait(), timeout=5)
        worker.cancel()
        with pytest.raises(asyncio.CancelledError):
            await worker

    asyncio.run(cancel())
    assert list(store.objects.iterdir()) == []


def test_cancellation_during_file_creation_cleans_stage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import tempfile

    store = ArtifactStore(tmp_path)
    started, release = Event(), Event()
    mkstemp = tempfile.mkstemp

    def paused(*, dir: Path, prefix: str) -> tuple[int, str]:
        started.set()
        assert release.wait(timeout=5)
        return mkstemp(dir=dir, prefix=prefix)

    monkeypatch.setattr(tempfile, "mkstemp", paused)

    async def cancel() -> None:
        worker = asyncio.create_task(store.put(chunks(b"data")))
        try:
            assert await asyncio.to_thread(started.wait, 5)
            worker.cancel()
        finally:
            release.set()
        with pytest.raises(asyncio.CancelledError):
            await worker

    asyncio.run(cancel())
    assert list(store.objects.iterdir()) == []


def test_failed_file_sync_cannot_publish(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = ArtifactStore(tmp_path)

    def failed(fd: int) -> None:
        raise OSError("simulated failed sync")

    monkeypatch.setattr(os, "fsync", failed)
    with pytest.raises(OSError, match="failed sync"):
        asyncio.run(store.put(chunks(b"payload")))
    assert list(store.objects.iterdir()) == []


def test_corrupted_existing_artifact_is_detected_without_clobber(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path)
    content = b"original"
    key, _ = asyncio.run(store.put(chunks(content)))
    store.path_for(key).write_bytes(b"damaged")
    assert not store.verified(key)
    with pytest.raises(OSError, match="failed SHA-256"):
        asyncio.run(store.put(chunks(content)))
    assert store.path_for(key).read_bytes() == b"damaged"
    assert list(store.objects.iterdir()) == [store.path_for(key)]


def test_key_and_symlink_boundaries(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path / "store")
    for bad in ["", "a" * 63, "Z" * 64, "../" + "a" * 61, "a" * 64 + "\n", "/tmp/target"]:
        with pytest.raises(ValueError):
            store.path_for(bad)
    hidden = tmp_path / "outside"
    hidden.write_bytes(b"unrelated")
    digest = hashlib.sha256(b"test").hexdigest()
    store.path_for(digest).symlink_to(hidden)
    with pytest.raises(OSError):
        store.verified(digest)
    with pytest.raises(OSError):
        store.path_for(digest)
    with pytest.raises(OSError):
        asyncio.run(store.put(chunks(b"test")))
    assert hidden.read_bytes() == b"unrelated"
    symlink_root = tmp_path / "redirect"
    symlink_root.symlink_to(store.root, target_is_directory=True)
    with pytest.raises(NotADirectoryError):
        ArtifactStore(symlink_root)


def test_publicly_traversable_mount_requires_private_object_directory(tmp_path: Path) -> None:
    tmp_path.chmod(0o755)
    objects = tmp_path / "objects"
    objects.mkdir(mode=0o700)
    objects.chmod(0o755)
    with pytest.raises(PermissionError):
        ArtifactStore(tmp_path)
    objects.chmod(0o700)
    assert ArtifactStore(tmp_path).objects == objects
