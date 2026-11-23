"""Local PostgreSQL and Redis integration tests for the emergency-stop API."""

import json
import os
from pathlib import Path
from subprocess import Popen
import sys
from collections.abc import Iterator, Sequence
from concurrent.futures import ThreadPoolExecutor
from math import ceil
from threading import Barrier
from time import monotonic, perf_counter, sleep
from uuid import UUID, uuid4

import httpx
import psycopg
import pytest
from contracts.events import EngagementState
from contracts.ledger import LedgerRecord
from fastapi.testclient import TestClient
from redis import Redis
from redis.exceptions import ConnectionError as RedisConnectionError

from main import create_app


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
    with TestClient(create_app(database_url=database, redis_url=redis)) as http:
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
    """Measure the Uvicorn HTTP path, including durable commit and Redis publish."""
    workers, samples = 4, 200
    database, redis = service_urls
    ids = engagements(database, [EngagementState.INIT_SCOPING] * (workers + samples))
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
                    list(pool.map(timed_stop, ids[:workers]))
                    timings = sorted(pool.map(timed_stop, ids[workers:]))
        finally:
            server.terminate()
    p99 = timings[ceil(0.99 * samples) - 1]
    print(f"Emergency stop p99 {p99:.2f} ms ({samples} fresh engagements, {workers} callers)")
    assert p99 < 50, f"Emergency stop p99 was {p99:.2f} ms"


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
