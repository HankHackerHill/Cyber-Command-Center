"""ADR-0017 durable acceptance, replay, isolation, and ledger continuity."""

import os
import sqlite3
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from threading import Barrier
from time import monotonic, sleep
from uuid import UUID, uuid4
from typing import cast

import psycopg
import pytest
from contracts.events import ActorType, AuditEvent, Ed25519Signature, EngagementState, TransitionEvent
from contracts.ledger import LedgerRecord
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from fastapi.testclient import TestClient

import audit_delivery
import main
from audit_delivery import AuditDelivery, AuditOutbox, QueuedAudit, canonical_event
from ledger import AuditReplayConflict, GENESIS_HASH, hash_record
from main import create_app

TOKEN = {"Authorization": "Bearer test-m4"}


def event(**payload: object) -> AuditEvent:
    return AuditEvent.model_validate({"actor_kind": "SYSTEM", "actor_id": "scoped-proxy",
                                     "event_type": "TEST_DURABLE", "payload": payload})


def headers(key: UUID, *, asynchronous: bool = True) -> dict[str, str]:
    return {**TOKEN, "Idempotency-Key": str(key), **({"Prefer": "respond-async"} if asynchronous else {})}


@pytest.fixture
def urls() -> tuple[str, str]:
    database = os.getenv("ORCHESTRATOR_TEST_DATABASE_URL")
    redis = os.getenv("ORCHESTRATOR_TEST_REDIS_URL")
    if not database or not redis:
        pytest.skip("Set ORCHESTRATOR_TEST_DATABASE_URL and ORCHESTRATOR_TEST_REDIS_URL")
    return database, redis


def engagement(database: str) -> UUID:
    eid = uuid4()
    with psycopg.connect(database) as conn:
        conn.execute("INSERT INTO engagements (id) VALUES (%s)", (eid,))
    return eid


@pytest.fixture
def stalled(urls: tuple[str, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    monkeypatch.setattr(AuditDelivery, "start", lambda self: None)
    monkeypatch.setattr(AuditDelivery, "stop", lambda self: None)
    with TestClient(create_app(database_url=urls[0], redis_url=urls[1],
                              m4_audit_token="test-m4", audit_outbox_path=str(tmp_path / "outbox.sqlite3"))) as client:
        yield client


def test_sqlite_acceptance_is_durable_and_normalized(tmp_path: Path) -> None:
    path = tmp_path / "queue.sqlite3"
    eid, key = uuid4(), uuid4()
    box = AuditOutbox(path)
    original = event(value=1.0, flag=True, obj={"b": 1, "a": 2}, tiny=1e-100)
    box.enqueue(eid, key, original)
    reopened = AuditOutbox(path)
    pending = reopened.pending()
    assert pending is not None and pending[:3] == (eid, key, original)
    assert reopened.lookup(eid, key) == QueuedAudit(engagement_id=eid, event_id=key)
    assert canonical_event(original) == canonical_event(event(value=1, flag=True, obj={"a": 2, "b": 1}, tiny=1e-100))
    reopened.enqueue(eid, key, original)
    with pytest.raises(AuditReplayConflict):
        reopened.enqueue(eid, key, event(value=1, flag=1, obj={"a": 2, "b": 1}, tiny=1e-100))
    assert reopened.lookup(uuid4(), key) is None
    assert path.stat().st_mode & 0o077 == 0
    with reopened.connect() as conn:
        assert conn.execute("PRAGMA journal_mode").fetchone() == ("wal",)
        assert conn.execute("PRAGMA synchronous").fetchone() == (2,)
        assert conn.execute("SELECT count(*) FROM audit_jobs").fetchone() == (1,)


def test_async_disabled_creates_no_file(urls: tuple[str, str], tmp_path: Path,
                                        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ORCHESTRATOR_AUDIT_OUTBOX", raising=False)
    monkeypatch.chdir(tmp_path)
    eid, key = engagement(urls[0]), uuid4()
    with TestClient(create_app(database_url=urls[0], redis_url=urls[1], m4_audit_token="test-m4")) as client:
        response = client.post(f"/engagements/{eid}/audit-events", json=event().model_dump(mode="json"), headers=headers(key))
        assert response.status_code == 503
        assert client.post(f"/engagements/{eid}/audit-events", json=event().model_dump(mode="json"),
                           headers=headers(key, asynchronous=False)).status_code == 201
    assert list(tmp_path.iterdir()) == []


def test_202_is_durable_before_worker_and_duplicate_identity(stalled: TestClient, urls: tuple[str, str]) -> None:
    eid, key = engagement(urls[0]), uuid4()
    path = f"/engagements/{eid}/audit-events"
    body = event(value=1.0, flag=True).model_dump(mode="json")
    queued = {"status": "queued", "event_id": str(key), "engagement_id": str(eid)}
    for _ in range(2):
        response = stalled.post(path, json=body, headers=headers(key))
        assert response.status_code == 202 and response.json() == queued
    assert stalled.get(f"/engagements/{eid}/ledger").json() == []
    outbox: AuditOutbox = cast(FastAPI, stalled.app).state.audit_outbox
    assert outbox.pending() is not None
    poll = stalled.get(f"{path}/{key}", headers=TOKEN)
    assert poll.status_code == 202 and poll.json() == queued
    normalized = event(value=1, flag=True).model_dump(mode="json")
    assert stalled.post(path, json=normalized, headers=headers(key)).status_code == 202
    conflict = event(value=1, flag=1).model_dump(mode="json")
    for asynchronous in (False, True):
        assert stalled.post(path, json=conflict, headers=headers(key, asynchronous=asynchronous)).status_code == 409
    assert stalled.get(f"{path}/{key}").status_code == 401
    assert stalled.get(f"/engagements/{uuid4()}/audit-events/{key}", headers=TOKEN).status_code == 404
    assert stalled.get(f"{path}/{uuid4()}", headers=TOKEN).status_code == 404


def test_async_guards_and_unknown_have_no_acceptance(stalled: TestClient, urls: tuple[str, str]) -> None:
    eid, key = engagement(urls[0]), uuid4()
    path = f"/engagements/{eid}/audit-events"
    body = event().model_dump(mode="json")
    assert stalled.post(path, json=body, headers={**TOKEN, "Prefer": "respond-async"}).status_code == 422
    assert stalled.post(path, json=body, headers={"Prefer": "respond-async", "Idempotency-Key": str(key)}).status_code == 401
    assert stalled.post(path, json={**body, "actor_id": "forged"}, headers=headers(key)).status_code == 403
    assert stalled.post(path, json={**body, "from_state": "ROE_LOCKED"}, headers=headers(key)).status_code == 422
    assert stalled.post(path, content='{"actor_kind":"SYSTEM","actor_id":"scoped-proxy","event_type":"T","payload":{"x":1,"x":2}}',
                        headers={**headers(key), "Content-Type": "application/json"}).status_code == 422
    assert stalled.post(f"/engagements/{uuid4()}/audit-events", json=body, headers=headers(key)).status_code == 404
    box: AuditOutbox = cast(FastAPI, stalled.app).state.audit_outbox
    assert box.pending() is None


def test_sync_async_race_and_engagement_scope(stalled: TestClient, urls: tuple[str, str]) -> None:
    eid, other, key = engagement(urls[0]), engagement(urls[0]), uuid4()
    path = f"/engagements/{eid}/audit-events"
    barrier = Barrier(8)

    def submit(index: int) -> int:
        barrier.wait(timeout=5)
        return int(stalled.post(path, json=event(n=index % 2).model_dump(mode="json"),
                                headers=headers(key, asynchronous=index % 2 == 0)).status_code)

    with ThreadPoolExecutor(max_workers=8) as pool:
        codes = list(pool.map(submit, range(8)))
    assert codes.count(409) == 4
    assert all(code in (200, 201, 202, 409) for code in codes)
    delivery: AuditDelivery = cast(FastAPI, stalled.app).state.audit_delivery
    delivery.deliver_one()
    rows = stalled.get(f"/engagements/{eid}/ledger").json()
    assert len(rows) == 1
    replay = stalled.post(path, json={key: value for key, value in rows[0]["event"].items()
                                     if key not in {"event_id", "engagement_id", "occurred_at"}}, headers=headers(key))
    assert replay.status_code == 200 and replay.json() == rows[0]
    assert stalled.post(f"/engagements/{other}/audit-events", json=event(n=9).model_dump(mode="json"),
                        headers=headers(key)).status_code == 202


def test_outage_does_not_ack_or_fabricate_rows(stalled: TestClient, urls: tuple[str, str],
                                             monkeypatch: pytest.MonkeyPatch) -> None:
    eid, key = engagement(urls[0]), uuid4()
    path = f"/engagements/{eid}/audit-events"
    assert stalled.post(path, json=event().model_dump(mode="json"), headers=headers(key)).status_code == 202
    delivery: AuditDelivery = cast(FastAPI, stalled.app).state.audit_delivery

    def unavailable(*args: object, **kwargs: object) -> tuple[LedgerRecord, bool]:
        raise psycopg.OperationalError("simulated PostgreSQL outage")

    with monkeypatch.context() as patch:
        patch.setattr(audit_delivery, "record_audit_event", unavailable)
        assert delivery.deliver_one()
    assert stalled.get(f"/engagements/{eid}/ledger").json() == []
    assert isinstance(delivery.outbox.lookup(eid, key), QueuedAudit)
    with delivery.outbox.connect() as conn:
        row = conn.execute("SELECT attempts,receipt,last_error FROM audit_jobs").fetchone()
        assert row == (1, None, "OperationalError")
        conn.execute("UPDATE audit_jobs SET next_attempt=0")
    assert delivery.deliver_one()
    assert stalled.get(f"{path}/{key}", headers=TOKEN).status_code == 200


def test_crash_after_append_before_ack_replays_original(stalled: TestClient, urls: tuple[str, str],
                                                       monkeypatch: pytest.MonkeyPatch) -> None:
    eid, key = engagement(urls[0]), uuid4()
    path = f"/engagements/{eid}/audit-events"
    assert stalled.post(path, json=event().model_dump(mode="json"), headers=headers(key)).status_code == 202
    delivery: AuditDelivery = cast(FastAPI, stalled.app).state.audit_delivery

    def lost_ack(*args: object, **kwargs: object) -> None:
        raise OSError("crash boundary after PostgreSQL commit")

    with monkeypatch.context() as patch:
        patch.setattr(delivery.outbox, "acknowledge", lost_ack)
        assert delivery.deliver_one()
    rows = stalled.get(f"/engagements/{eid}/ledger").json()
    assert len(rows) == 1 and isinstance(delivery.outbox.lookup(eid, key), QueuedAudit)
    with delivery.outbox.connect() as conn:
        conn.execute("UPDATE audit_jobs SET next_attempt=0")
    recovered = AuditDelivery(AuditOutbox(delivery.outbox.path), delivery.database)
    assert recovered.deliver_one()
    assert stalled.get(f"/engagements/{eid}/ledger").json() == rows
    poll = stalled.get(f"{path}/{key}", headers=TOKEN)
    assert poll.status_code == 200 and poll.json() == rows[0]


def test_restart_drains_durable_queue_and_preserves_signed_chain(urls: tuple[str, str], tmp_path: Path,
                                                               monkeypatch: pytest.MonkeyPatch) -> None:
    eid, key = engagement(urls[0]), uuid4()
    operator = Ed25519PrivateKey.generate()
    path = tmp_path / "restart.sqlite3"
    with monkeypatch.context() as patch:
        patch.setattr(AuditDelivery, "start", lambda self: None)
        patch.setattr(AuditDelivery, "stop", lambda self: None)
        with TestClient(create_app(database_url=urls[0], redis_url=urls[1], m4_audit_token="test-m4", audit_outbox_path=str(path), trusted_public_keys={"operator": operator.public_key()})) as first:
            accepted = first.post(f"/engagements/{eid}/audit-events", json=event().model_dump(mode="json"), headers=headers(key))
            assert accepted.status_code == 202
            transition = TransitionEvent(
                event_id=str(uuid4()), engagement_id=str(eid), actor_id="operator", actor_type=ActorType.HUMAN_OPERATOR,
                from_state=EngagementState.INIT_SCOPING, to_state=EngagementState.ROE_LOCKED,
                occurred_at=datetime.now(timezone.utc),
            )
            transition = transition.model_copy(update={"hitl_signature": Ed25519Signature(
                signer_id="operator", signature=operator.sign(transition.canonical_envelope()).hex(),
            )})
            applied = first.post(f"/engagements/{eid}/transition", json=transition.model_dump(mode="json"))
            assert applied.status_code == 200
            assert len(first.get(f"/engagements/{eid}/ledger").json()) == 1
    with TestClient(create_app(database_url=urls[0], redis_url=urls[1], m4_audit_token="test-m4", audit_outbox_path=str(path))) as restarted:
        deadline = monotonic() + 5
        while True:
            poll = restarted.get(f"/engagements/{eid}/audit-events/{key}", headers=TOKEN)
            if poll.status_code == 200:
                break
            assert monotonic() < deadline
            sleep(0.01)
        rows = [LedgerRecord.model_validate(row) for row in restarted.get(f"/engagements/{eid}/ledger").json()]
        assert len(rows) == 2 and rows[0].event == transition
        previous = GENESIS_HASH
        for row in rows:
            assert row.prev_record_hash == previous and row.record_hash == hash_record(previous, row.event)
            previous = row.record_hash
        assert restarted.get(f"/engagements/{eid}/state").json() == {"state": "ROE_LOCKED"}


def test_outbox_persist_failure_returns_no_202(stalled: TestClient, urls: tuple[str, str],
                                              monkeypatch: pytest.MonkeyPatch) -> None:
    eid, key = engagement(urls[0]), uuid4()
    box: AuditOutbox = cast(FastAPI, stalled.app).state.audit_outbox

    def disk_full(*args: object, **kwargs: object) -> None:
        raise sqlite3.OperationalError("database or disk is full")

    with monkeypatch.context() as patch:
        patch.setattr(box, "enqueue", disk_full)
        response = stalled.post(f"/engagements/{eid}/audit-events", json=event().model_dump(mode="json"), headers=headers(key))
    assert response.status_code == 503
    assert box.lookup(eid, key) is None
    assert stalled.get(f"/engagements/{eid}/ledger").json() == []


def test_poll_known_pending_survives_database_outage(stalled: TestClient, urls: tuple[str, str],
                                                    monkeypatch: pytest.MonkeyPatch) -> None:
    eid, key = engagement(urls[0]), uuid4()
    path = f"/engagements/{eid}/audit-events"
    queued = stalled.post(path, json=event().model_dump(mode="json"), headers=headers(key))
    assert queued.status_code == 202

    def unavailable(*args: object, **kwargs: object) -> LedgerRecord | None:
        raise psycopg.OperationalError("simulated PostgreSQL outage")

    with monkeypatch.context() as patch:
        patch.setattr(main, "audit_receipt", unavailable)
        response = stalled.get(f"{path}/{key}", headers=TOKEN)
        assert response.status_code == 202 and response.json() == queued.json()
        assert stalled.get(f"{path}/{uuid4()}", headers=TOKEN).status_code == 503


def test_wal_anchor_avoids_per_operation_checkpoint_and_closes_cleanly(tmp_path: Path) -> None:
    path = tmp_path / "anchored.sqlite3"
    box = AuditOutbox(path)
    eid, key = uuid4(), uuid4()
    box.enqueue(eid, key, event(n=1))
    wal = Path(f"{path}-wal")
    assert wal.exists() and wal.stat().st_size > 0
    # Each operation closes its private connection. The idle anchor retains WAL
    # until explicit shutdown; synchronous=FULL still protects every enqueue.
    assert isinstance(box.lookup(eid, key), QueuedAudit)
    assert wal.exists() and wal.stat().st_size > 0
    box.close()
    box.close()
    assert not wal.exists()
    reopened = AuditOutbox(path)
    try:
        assert isinstance(reopened.lookup(eid, key), QueuedAudit)
        with reopened.connect() as conn:
            assert conn.execute("PRAGMA synchronous").fetchone() == (2,)
    finally:
        reopened.close()


def test_lifespan_releases_wal_anchor(urls: tuple[str, str], tmp_path: Path,
                                    monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(AuditDelivery, "start", lambda self: None)
    monkeypatch.setattr(AuditDelivery, "stop", lambda self: None)
    path = tmp_path / "lifespan.sqlite3"
    app = create_app(database_url=urls[0], redis_url=urls[1], m4_audit_token="test-m4", audit_outbox_path=str(path))
    with TestClient(app):
        box: AuditOutbox = app.state.audit_outbox
        box.enqueue(uuid4(), uuid4(), event())
        assert Path(f"{path}-wal").exists()
    assert not Path(f"{path}-wal").exists()
