"""Local PostgreSQL and Redis integration tests for the emergency-stop API."""

import json
import os
from pathlib import Path
from subprocess import Popen
import sys
from collections.abc import Iterator, Sequence
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
from math import ceil
from statistics import median
from threading import Barrier
from time import monotonic, perf_counter, sleep
from uuid import UUID, uuid4

import httpx
import psycopg
import pytest
from contracts.events import ActorType, EngagementState, TransitionEvent
from contracts.ledger import LedgerRecord
from fastapi.testclient import TestClient
from hypothesis import given, settings
from hypothesis import strategies as st
from redis import Redis
from redis.exceptions import ConnectionError as RedisConnectionError

from main import create_app
from ledger import GENESIS_HASH, hash_record


AUDIT_HEADERS = {"Authorization": "Bearer test-m4-service"}


@pytest.fixture(scope="module")
def service_urls() -> tuple[str, str]:
    database = os.environ.get("ORCHESTRATOR_TEST_DATABASE_URL")
    redis = os.environ.get("ORCHESTRATOR_TEST_REDIS_URL")
    if not database or not redis:
        pytest.skip("Set ORCHESTRATOR_TEST_DATABASE_URL and ORCHESTRATOR_TEST_REDIS_URL")
    return database, redis


@pytest.fixture(scope="module")
def client(service_urls: tuple[str, str]) -> Iterator[TestClient]:
    database, redis = service_urls
    with TestClient(create_app(database_url=database, redis_url=redis, m4_audit_token="test-m4-service")) as http:
        yield http


def engagements(database: str, states: Sequence[EngagementState]) -> list[UUID]:
    ids = [uuid4() for _ in states]
    with psycopg.connect(database) as connection, connection.cursor() as cursor:
        cursor.executemany(
            "INSERT INTO engagements (id, current_state) VALUES (%s, %s)",
            zip(ids, states, strict=True),
        )
    return ids


def stop_hash(client: TestClient, engagement_id: UUID) -> str:
    response = client.post(f"/engagements/{engagement_id}/killswitch")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "halted"
    assert body["next_state"] == EngagementState.HALTED_KILLSWITCH
    digest = body["ledger_hash"]
    assert isinstance(digest, str)
    return digest


def ledger(client: TestClient, engagement_id: UUID, since: int = 0) -> list[LedgerRecord]:
    response = client.get(f"/engagements/{engagement_id}/ledger", params={"since": since})
    assert response.status_code == 200, response.text
    return [LedgerRecord.model_validate(row) for row in response.json()]


def test_unknown_engagement(client: TestClient) -> None:
    path = f"/engagements/{uuid4()}"
    assert client.get(f"{path}/state").status_code == 404
    assert client.get(f"{path}/ledger").status_code == 404
    assert client.post(f"{path}/killswitch").status_code == 404


def test_state_ledger_and_exclusive_cursor(client: TestClient, service_urls: tuple[str, str]) -> None:
    first, other = engagements(service_urls[0], [EngagementState.INIT_SCOPING] * 2)
    state_path = f"/engagements/{first}/state"
    assert client.get(state_path).json()["state"] == "INIT_SCOPING"
    assert ledger(client, first) == []
    digest = stop_hash(client, first)
    stop_hash(client, other)
    assert client.get(state_path).json()["state"] == "HALTED_KILLSWITCH"
    record, = ledger(client, first)
    assert isinstance(record.event, TransitionEvent)
    assert record.event.engagement_id == str(first)
    assert record.event.from_state == EngagementState.INIT_SCOPING
    assert record.event.to_state == EngagementState.HALTED_KILLSWITCH
    assert record.record_hash == digest
    assert ledger(client, first, record.seq_id - 1) == [record]
    assert ledger(client, first, record.seq_id) == []


def test_redis_delivers_halt(client: TestClient, service_urls: tuple[str, str]) -> None:
    engagement_id, = engagements(service_urls[0], [EngagementState.EVIDENCE_VERIFICATION])
    with Redis.from_url(service_urls[1]) as redis, redis.pubsub() as subscriber:
        subscriber.subscribe("redops:killswitch")
        acknowledgment = subscriber.get_message(timeout=2)
        assert acknowledgment and acknowledgment["type"] == "subscribe"
        stop_hash(client, engagement_id)
        deadline = monotonic() + 2
        while monotonic() < deadline:
            message = subscriber.get_message(timeout=max(0.0, deadline - monotonic()))
            if message and message["type"] == "message":
                payload = json.loads(message["data"])
                if payload["engagement_id"] == str(engagement_id):
                    assert payload["state"] == EngagementState.HALTED_KILLSWITCH
                    return
    pytest.fail("Redis subscriber did not receive this engagement's emergency stop")


def test_every_running_state_can_be_halted(client: TestClient, service_urls: tuple[str, str]) -> None:
    states = [state for state in EngagementState if state != EngagementState.HALTED_KILLSWITCH]
    ids = engagements(service_urls[0], states)
    for engagement_id, state in zip(ids, states, strict=True):
        digest = stop_hash(client, engagement_id)
        record, = ledger(client, engagement_id)
        assert isinstance(record.event, TransitionEvent)
        assert record.event.from_state == state
        assert record.record_hash == digest


def test_concurrent_and_repeated_stops_append_once(
    client: TestClient, service_urls: tuple[str, str],
) -> None:
    engagement_id, = engagements(service_urls[0], [EngagementState.ROE_LOCKED])
    workers = 8
    barrier = Barrier(workers, timeout=10)

    def concurrent_stop() -> str:
        barrier.wait()
        return stop_hash(client, engagement_id)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(concurrent_stop) for _ in range(workers)]
        digests = [future.result() for future in futures]
    digest = stop_hash(client, engagement_id)
    assert digests == [digest] * workers
    record, = ledger(client, engagement_id)
    assert record.record_hash == digest


def test_stop_latency(service_urls: tuple[str, str], tmp_path: Path) -> None:
    """Collect four Uvicorn p99s including commit and publish; score the last three."""
    workers, samples = 4, 200
    database, redis = service_urls
    batches = [
        engagements(database, [EngagementState.INIT_SCOPING] * (workers + samples))
        for _ in range(4)
    ]
    measured_p99s = []
    socket = str(tmp_path / "http.sock")
    command = [sys.executable, "-m", "uvicorn", "main:app", "--uds", socket, "--no-access-log"]
    environment = {**os.environ, "DATABASE_URL": database, "REDIS_URL": redis}
    with Popen(command, cwd=Path(__file__).resolve().parents[1], env=environment) as server:
        try:
            with httpx.Client(transport=httpx.HTTPTransport(uds=socket), base_url="http://local") as http:
                deadline = monotonic() + 10
                while not os.path.exists(socket):
                    assert server.poll() is None and monotonic() < deadline, "Uvicorn startup failed"
                    sleep(0.01)

                def timed_stop(engagement_id: UUID) -> float:
                    start = perf_counter()
                    response = http.post(f"/engagements/{engagement_id}/killswitch")
                    assert response.status_code == 200, response.text
                    assert response.json()["notification_published"]
                    return (perf_counter() - start) * 1000

                with ThreadPoolExecutor(max_workers=workers) as pool:
                    for index, ids in enumerate(batches):
                        list(pool.map(timed_stop, ids[:workers]))
                        timings = sorted(pool.map(timed_stop, ids[workers:]))
                        p99 = timings[ceil(0.99 * samples) - 1]
                        label = f"measured run {index}" if index else "discarded warm-up"
                        print(f"Emergency stop {label} p99 {p99:.2f} ms "
                              f"({samples} fresh engagements, {workers} callers)")
                        if index:
                            measured_p99s.append(p99)
        finally:
            server.terminate()
    measured_median = median(measured_p99s)
    print(f"Median measured emergency stop p99 {measured_median:.2f} ms")
    assert measured_median < 50, f"Median measured emergency stop p99 was {measured_median:.2f} ms"


def test_stop_persists_during_notification_outage(
    client: TestClient, service_urls: tuple[str, str], monkeypatch: pytest.MonkeyPatch,
) -> None:
    engagement_id, = engagements(service_urls[0], [EngagementState.INIT_SCOPING])
    path = f"/engagements/{engagement_id}/killswitch"

    def unavailable(*args: object, **kwargs: object) -> None:
        raise RedisConnectionError("test outage")

    with monkeypatch.context() as patch:
        patch.setattr(Redis, "publish", unavailable)
        response = client.post(path, content=b"malformed", headers={"Content-Type": "application/json"})
    assert response.status_code == 200
    assert response.json()["notification_published"] is False
    retry = client.post(path)
    assert retry.status_code == 200
    assert retry.json()["notification_published"] is True
    record, = ledger(client, engagement_id)
    assert record.record_hash == response.json()["ledger_hash"] == retry.json()["ledger_hash"]


@settings(deadline=None)
@given(
    source=st.sampled_from(list(EngagementState)),
    candidate=st.sampled_from([
        EngagementState.INIT_SCOPING, EngagementState.EVIDENCE_VERIFICATION,
        EngagementState.REMEDIATION_SYNTHESIS, EngagementState.RETEST_VERIFICATION,
    ]),
)
def test_illegal_transition_is_denied_without_writes(
    client: TestClient, service_urls: tuple[str, str], source: EngagementState, candidate: EngagementState,
) -> None:
    # Every re-entry to INIT_SCOPING is illegal. Archived and halted engagements
    # also reject all four candidate destinations, as do these non-halt self-loops.
    terminal = (EngagementState.HALTED_KILLSWITCH, EngagementState.COMPLETED_ARCHIVED)
    target = candidate if source in terminal or candidate == source else EngagementState.INIT_SCOPING
    database = service_urls[0]
    initial = EngagementState.INIT_SCOPING if source == EngagementState.HALTED_KILLSWITCH else source
    engagement_id, = engagements(database, [initial])
    if source == EngagementState.HALTED_KILLSWITCH:
        stop_hash(client, engagement_id)  # Exercise denial with an existing journal entry.

    def snapshot() -> tuple[str, list[tuple[object, ...]]]:
        with psycopg.connect(database) as db:
            state = db.execute("SELECT current_state FROM engagements WHERE id=%s", (engagement_id,)).fetchone()
            assert state is not None
            rows = db.execute(
                """SELECT seq_id, payload, prev_record_hash, record_hash FROM immutable_audit_log
                   WHERE engagement_id=%s ORDER BY seq_id""", (engagement_id,),
            ).fetchall()
            return state[0], rows

    before = snapshot()
    assert before[0] == source
    event = TransitionEvent(
        engagement_id=str(engagement_id), event_id=str(uuid4()), actor_id="acceptance-test",
        actor_type=ActorType.HUMAN_OPERATOR, from_state=source, to_state=target,
        occurred_at=datetime.now(timezone.utc),
    )
    response = client.post(f"/engagements/{engagement_id}/transition", json=event.model_dump(mode="json"))
    assert snapshot() == before
    assert response.status_code in (400, 403, 409, 422), response.text
    assert response.json()["reason"] == "ILLEGAL_TRANSITION", response.text


def test_transition_to_stop_ignores_stale_source_and_retries_once(
    client: TestClient, service_urls: tuple[str, str],
) -> None:
    engagement_id, = engagements(service_urls[0], [EngagementState.INIT_SCOPING])
    path = f"/engagements/{engagement_id}/transition"
    event = TransitionEvent(
        engagement_id=str(engagement_id), event_id=str(uuid4()), actor_id="stop-test",
        actor_type=ActorType.SYSTEM, from_state=EngagementState.COMPLETED_ARCHIVED,
        to_state=EngagementState.HALTED_KILLSWITCH, occurred_at=datetime.now(timezone.utc),
    )
    for _ in range(2):
        response = client.post(path, json=event.model_dump(mode="json"))
        assert response.status_code == 200
        assert response.json()["notification_published"]
    stop, = ledger(client, engagement_id)
    assert isinstance(stop.event, TransitionEvent)
    assert stop.event.from_state == EngagementState.INIT_SCOPING
    assert stop.event.to_state == EngagementState.HALTED_KILLSWITCH
    assert stop.record_hash == response.json()["ledger_hash"]


def test_transition_malformed_event_returns_reason(client: TestClient) -> None:
    response = client.post(f"/engagements/{uuid4()}/transition", json={})
    assert response.status_code == 422
    assert response.json()["reason"] == "INVALID_EVENT"


def audit_body(**payload: object) -> dict[str, object]:
    return {"actor_kind": "SYSTEM", "actor_id": "scoped-proxy",
            "event_type": "TUNNEL_REJECTED", "payload": payload}


def test_audit_receipt_replay_and_append_only(client: TestClient, service_urls: tuple[str, str]) -> None:
    eid, other = engagements(service_urls[0], [EngagementState.INIT_SCOPING] * 2)
    path = f"/engagements/{eid}/audit-events"
    key = str(uuid4())
    headers = {**AUDIT_HEADERS, "Idempotency-Key": key}
    body = audit_body(reason="OPAQUE_TUNNEL_NOT_ALLOWED", prefix_hex="00ff", bit=True,
                      numbers=[1e20, -0.0, 1.25e-105, 2**80 + 3], note="測試")
    first = client.post(path, json=body, headers=headers)
    assert first.status_code == 201, first.text
    record = first.json()
    assert set(record) == {"seq_id", "event", "prev_record_hash", "record_hash"}
    assert record["prev_record_hash"] == GENESIS_HASH
    assert record["event"]["event_id"] == key
    assert record["event"]["engagement_id"] == str(eid)
    assert datetime.fromisoformat(record["event"]["occurred_at"]).utcoffset() == timezone.utc.utcoffset(None)
    assert record["event"]["payload"] == body["payload"]
    assert "from_state" not in record["event"] and "to_state" not in record["event"]
    replay = client.post(path, json=body, headers=headers)
    assert replay.status_code == 200 and replay.json() == record
    # JSON booleans and numbers are distinct even though True == 1 in Python.
    conflicting = {**body, "payload": {**record["event"]["payload"], "bit": 1}}
    assert client.post(path, json=conflicting, headers=headers).status_code == 409
    assert client.get(f"/engagements/{eid}/state").json() == {"state": "INIT_SCOPING"}
    assert client.get(f"/engagements/{eid}/ledger").json() == [record]
    stored, = ledger(client, eid)
    assert hash_record(GENESIS_HASH, stored.event) == stored.record_hash
    assert client.post(f"/engagements/{other}/audit-events", json=body, headers=headers).status_code == 201
    fresh = client.post(path, json=body, headers=AUDIT_HEADERS)
    assert fresh.status_code == 201 and fresh.json()["event"]["event_id"] != key
    with psycopg.connect(service_urls[0], autocommit=True) as conn:
        assert conn.execute(
            "SELECT payload->>'from_state', payload->>'to_state' FROM immutable_audit_log WHERE seq_id=%s",
            (stored.seq_id,),
        ).fetchone() == (None, None)
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="append-only"):
            conn.execute("DELETE FROM immutable_audit_log WHERE seq_id=%s", (stored.seq_id,))


def test_audit_rejects_bad_credentials_identity_and_wire(client: TestClient, service_urls: tuple[str, str]) -> None:
    eid, = engagements(service_urls[0], [EngagementState.ROE_LOCKED])
    path = f"/engagements/{eid}/audit-events"
    body = audit_body(reason="POLICY_DENIED")
    assert client.post(path, json=body).status_code == 401
    assert client.post(path, json=body, headers={"Authorization": "Bearer wrong"}).status_code == 401
    repeated_auth = [("Authorization", AUDIT_HEADERS["Authorization"])] * 2
    assert client.post(path, json=body, headers=repeated_auth).status_code == 401
    with TestClient(create_app(database_url=service_urls[0], redis_url=service_urls[1], m4_audit_token="")) as unconfigured:
        assert unconfigured.post(path, json=body, headers=AUDIT_HEADERS).status_code == 401
    for forged in ({"actor_kind": "HUMAN_OPERATOR"}, {"actor_id": "orchestrator:killswitch"}):
        assert client.post(path, json={**body, **forged}, headers=AUDIT_HEADERS).status_code == 403
    assert client.post(path, json={**body, "from_state": "ROE_LOCKED"}, headers=AUDIT_HEADERS).status_code == 422
    duplicated = [*AUDIT_HEADERS.items(), ("Idempotency-Key", str(uuid4())), ("Idempotency-Key", str(uuid4()))]
    assert client.post(path, json=body, headers=duplicated).status_code == 422
    for field in ['"n":1e-400', '"n":NaN', '"n":Infinity', '"v":1,"v":2', '"v":"\\u0000"']:
        wire = json.dumps(audit_body()).replace('"payload": {}', '"payload": {' + field + '}')
        response = client.post(path, content=wire, headers={**AUDIT_HEADERS, "Content-Type": "application/json"})
        assert response.status_code == 422, (wire, response.text)
    assert client.post(f"/engagements/{uuid4()}/audit-events", json=body, headers=AUDIT_HEADERS).status_code == 404
    assert ledger(client, eid) == []


def test_interleaved_audit_and_transition_appends(client: TestClient, service_urls: tuple[str, str]) -> None:
    eid, = engagements(service_urls[0], [EngagementState.EVIDENCE_VERIFICATION])
    path = f"/engagements/{eid}/audit-events"
    body = audit_body(reason="SCOPE_DENIED")
    headers = {**AUDIT_HEADERS, "Idempotency-Key": str(uuid4())}
    event = TransitionEvent(
        engagement_id=str(eid), event_id=str(uuid4()), actor_id="reviewer", actor_type=ActorType.SYSTEM,
        from_state=EngagementState.EVIDENCE_VERIFICATION, to_state=EngagementState.REMEDIATION_SYNTHESIS,
        occurred_at=datetime.now(timezone.utc),
    )
    workers = 8
    barrier = Barrier(workers, timeout=10)

    def append(worker: int) -> int:
        barrier.wait()
        if worker == 0:
            result = client.post(f"/engagements/{eid}/transition", json=event.model_dump(mode="json"))
        else:
            result = client.post(path, json=body, headers=headers)
        return int(result.status_code)

    with ThreadPoolExecutor(max_workers=workers) as executor:
        codes = list(executor.map(append, range(workers)))
    assert codes[0] == 200
    assert sorted(codes[1:]) == [200] * (workers - 2) + [201]
    assert client.get(f"/engagements/{eid}/state").json() == {"state": "REMEDIATION_SYNTHESIS"}
    stopped = stop_hash(client, eid)
    assert client.post(path, json=body, headers=AUDIT_HEADERS).status_code == 201
    assert stop_hash(client, eid) == stopped
    records = ledger(client, eid)
    assert len(records) == 4
    previous = GENESIS_HASH
    for entry in records:
        assert entry.prev_record_hash == previous
        assert hash_record(previous, entry.event) == entry.record_hash
        previous = entry.record_hash
