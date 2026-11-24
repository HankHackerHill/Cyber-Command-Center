import asyncio
import hashlib
import json
import os
import stat
from collections.abc import AsyncIterator, Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID, uuid4

import psycopg
import pytest
from psycopg import sql
from psycopg.conninfo import make_conninfo

from ledger_link import AmbiguousFinding, LinkIndex, MissingEvidence
from store import ArtifactStore


@pytest.fixture
def migrated_database() -> Iterator[str]:
    url = os.getenv("EVIDENCE_TEST_DATABASE_URL")
    if not url:
        pytest.skip("EVIDENCE_TEST_DATABASE_URL selects a disposable PostgreSQL database")
    schema = "evidence_test_" + uuid4().hex
    with psycopg.connect(url, autocommit=True) as admin:
        name = sql.Identifier(schema)
        admin.execute(sql.SQL("CREATE SCHEMA {}").format(name))
        try:
            isolated = make_conninfo(url, options=f"-c search_path={schema}")
            with psycopg.connect(isolated, autocommit=True) as conn:
                assert conn.execute("SELECT current_schema()").fetchone() == (schema,)
                for migration in sorted((Path(__file__).resolve().parents[3] / "db/migrations").glob("*.sql")):
                    with conn.transaction():
                        conn.execute(migration.read_text())
            yield isolated
        finally:
            admin.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(name))


@dataclass(frozen=True)
class Seed:
    engagement_id: UUID
    finding_id: str
    transition_hash: str
    audit_hash: str


def seed_ledger(database_url: str, finding_id: str = "F-1") -> Seed:
    engagement = uuid4()
    common = {"event_id": str(uuid4()), "engagement_id": str(engagement), "occurred_at": "2026-01-01T00:00:00Z"}
    transition = {
        **common, "from_state": "EVIDENCE_VERIFICATION", "to_state": "REMEDIATION_SYNTHESIS",
        "actor_type": "HUMAN_OPERATOR", "actor_id": "reviewer", "hitl_signature": None,
    }
    audit = {
        **common, "event_id": str(uuid4()), "actor_kind": "SYSTEM", "actor_id": "scoped-proxy",
        "event_type": "policy.denied", "payload": {"reason": "SCOPE_DENIED"},
    }
    digests: list[str] = []
    with psycopg.connect(database_url) as conn:
        conn.execute("INSERT INTO engagements (id, current_state) VALUES (%s, 'REMEDIATION_SYNTHESIS')", (engagement,))
        conn.execute(
            "INSERT INTO findings (engagement_id, id, title, confidence_score) VALUES (%s, %s, 'Example', 0.5)",
            (engagement, finding_id),
        )
        previous = "0" * 64
        for event in (transition, audit):
            payload = json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            digest = hashlib.sha256(bytes.fromhex(previous) + payload.encode()).hexdigest()
            conn.execute(
                "INSERT INTO immutable_audit_log (payload, prev_record_hash, record_hash) VALUES (%s::jsonb, %s, %s)",
                (payload, previous, digest),
            )
            digests.append(digest)
            previous = digest
    return Seed(engagement, finding_id, *digests)


def upload(store: ArtifactStore, data: bytes) -> str:
    async def chunks() -> AsyncIterator[bytes]:
        yield data

    digest, _ = asyncio.run(store.put(chunks()))
    return digest


def test_metadata_is_private_on_a_traversable_root(tmp_path: Path) -> None:
    tmp_path.chmod(0o755)
    prior_umask = os.umask(0o022)
    try:
        store = ArtifactStore(tmp_path)
        LinkIndex(tmp_path, "unused", store)
    finally:
        os.umask(prior_umask)
    index = tmp_path / "evidence-links.sqlite3"
    assert stat.S_IMODE(index.stat().st_mode) == 0o600
    index.chmod(0o644)
    with pytest.raises(PermissionError):
        LinkIndex(tmp_path, "unused", store)


@pytest.mark.parametrize("suffix", ["", "-journal", "-wal", "-shm"])
def test_metadata_symlinks_are_refused(tmp_path: Path, suffix: str) -> None:
    root = tmp_path / "cas"
    store = ArtifactStore(root)
    outside = tmp_path / "outside"
    outside.write_bytes(b"preserve")
    (root / ("evidence-links.sqlite3" + suffix)).symlink_to(outside)
    with pytest.raises(PermissionError):
        LinkIndex(root, "unused", store)
    assert outside.read_bytes() == b"preserve"


def test_retries_persist_deduplicated_links_to_both_ledger_shapes(migrated_database: str, tmp_path: Path) -> None:
    seed = seed_ledger(migrated_database)
    store = ArtifactStore(tmp_path)
    index = LinkIndex(tmp_path, migrated_database, store)
    alpha, beta = upload(store, b"alpha"), upload(store, b"beta")
    with ThreadPoolExecutor(4) as pool:
        attempts = [pool.submit(index.link, seed.finding_id, alpha, seed.transition_hash) for _ in range(6)]
        for attempt in attempts:
            attempt.result()
    index.link(seed.finding_id, alpha, seed.audit_hash, seed.engagement_id)
    index.link(seed.finding_id, beta, seed.audit_hash)
    restarted = LinkIndex(tmp_path, migrated_database, ArtifactStore(tmp_path))
    assert restarted.artifacts(seed.finding_id) == sorted([alpha, beta])
    assert restarted.has_linked_evidence(seed.finding_id)
    with psycopg.connect(migrated_database) as conn:
        assert conn.execute("SELECT status FROM findings WHERE id = %s", (seed.finding_id,)).fetchone() == ("HYPOTHESIS",)


def test_shared_finding_id_requires_owner_on_lookup(migrated_database: str, tmp_path: Path) -> None:
    left = seed_ledger(migrated_database)
    right = seed_ledger(migrated_database)
    store = ArtifactStore(tmp_path)
    digest = upload(store, b"left")
    index = LinkIndex(tmp_path, migrated_database, store)
    index.link(left.finding_id, digest, left.audit_hash)
    with pytest.raises(MissingEvidence):
        index.link(left.finding_id, digest, left.audit_hash, right.engagement_id)
    with pytest.raises(AmbiguousFinding):
        index.artifacts(left.finding_id)
    with pytest.raises(AmbiguousFinding):
        index.has_linked_evidence(left.finding_id)
    assert index.artifacts(left.finding_id, left.engagement_id) == [digest]
    assert not index.has_linked_evidence(right.finding_id, right.engagement_id)


def test_revalidates_blob_finding_and_ledger(migrated_database: str, tmp_path: Path) -> None:
    seed = seed_ledger(migrated_database)
    other = seed_ledger(migrated_database, "other")
    store = ArtifactStore(tmp_path)
    digest = upload(store, b"valid evidence")
    index = LinkIndex(tmp_path, migrated_database, store)
    for name, artifact, record in [
        (seed.finding_id, "f"*64, seed.audit_hash), (seed.finding_id, digest, "f"*64),
        (seed.finding_id, digest, other.audit_hash), ("missing", digest, seed.audit_hash),
    ]:
        with pytest.raises(MissingEvidence):
            index.link(name, artifact, record)
    index.link(seed.finding_id, digest, seed.transition_hash)
    blob = store.path_for(digest)
    blob.write_bytes(b"wrong content")
    assert not index.has_linked_evidence(seed.finding_id)
    with pytest.raises(MissingEvidence):
        index.link(seed.finding_id, digest, seed.audit_hash)
    blob.unlink()
    assert index.artifacts(seed.finding_id) == []
    assert upload(store, b"valid evidence") == digest
    assert index.artifacts(seed.finding_id) == [digest]
    # A restart against a restored database may leave an older local index.
    # Delete only the synthetic finding; ledger rows are protected by MS0.
    with psycopg.connect(migrated_database) as conn:
        conn.execute("DELETE FROM findings WHERE engagement_id = %s", (seed.engagement_id,))
    assert index.artifacts(seed.finding_id) == []
    assert not index.has_linked_evidence(seed.finding_id)


def test_hash_collision_in_ledger_is_ambiguous(migrated_database: str, tmp_path: Path) -> None:
    seed = seed_ledger(migrated_database)
    store = ArtifactStore(tmp_path)
    digest = upload(store, b"sample")
    index = LinkIndex(tmp_path, migrated_database, store)
    index.link(seed.finding_id, digest, seed.audit_hash)
    # MS0 allows duplicate hashes; inject duplicate rows only in this test schema.
    with psycopg.connect(migrated_database) as conn:
        conn.execute(
            """INSERT INTO immutable_audit_log (payload, prev_record_hash, record_hash)
               SELECT payload, prev_record_hash, record_hash FROM immutable_audit_log WHERE record_hash = %s""",
            (seed.audit_hash,),
        )
    with pytest.raises(MissingEvidence):
        index.link(seed.finding_id, digest, seed.audit_hash)
    assert not index.has_linked_evidence(seed.finding_id)
