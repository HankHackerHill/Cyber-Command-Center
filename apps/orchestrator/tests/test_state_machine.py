"""Live database tests for archival, evidence review, and remediation handoffs."""

import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from threading import Barrier
from uuid import UUID, uuid4

import httpx
import psycopg
import pytest
from contracts.events import ActorType, Ed25519Signature, EngagementState, TransitionEvent
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from ledger import GENESIS_HASH, get_state, hash_record, read_ledger
from main import create_app


@pytest.fixture(scope="module")
def urls() -> tuple[str, str]:
    database = os.environ.get("ORCHESTRATOR_TEST_DATABASE_URL")
    redis = os.environ.get("ORCHESTRATOR_TEST_REDIS_URL")
    if not database or not redis:
        pytest.skip("Set ORCHESTRATOR_TEST_DATABASE_URL and ORCHESTRATOR_TEST_REDIS_URL")
    return database, redis


def archive_request(
    engagement: UUID, source: EngagementState, actor: str, key: Ed25519PrivateKey,
) -> TransitionEvent:
    event = TransitionEvent(
        event_id=str(uuid4()), engagement_id=str(engagement),
        from_state=source, to_state=EngagementState.COMPLETED_ARCHIVED,
        actor_type=ActorType.HUMAN_OPERATOR, actor_id=actor,
        occurred_at=datetime.now(timezone.utc),
    )
    signature = Ed25519Signature(
        signer_id=actor, signature=key.sign(event.canonical_envelope()).hex(),
    )
    return event.model_copy(update={"hitl_signature": signature})


def test_competing_signed_archives_commit_one_winner(urls: tuple[str, str]) -> None:
    database, redis = urls
    engagement = uuid4()
    source = EngagementState.REMEDIATION_SYNTHESIS
    history = TransitionEvent(
        engagement_id=str(engagement), event_id=str(uuid4()), from_state=EngagementState.EVIDENCE_VERIFICATION,
        to_state=source, actor_id="historical-operator", actor_type=ActorType.HUMAN_OPERATOR,
        occurred_at=datetime.now(timezone.utc),
    )
    previous_hash = hash_record(GENESIS_HASH, history)
    with psycopg.connect(database) as connection:
        connection.execute("INSERT INTO engagements (id, current_state) VALUES (%s, %s)", (engagement, source))
        connection.execute(
            """INSERT INTO immutable_audit_log (payload, prev_record_hash, record_hash)
               VALUES (%s::jsonb, %s, %s)""", (history.model_dump_json(), GENESIS_HASH, previous_hash),
        )

    keys = {actor: Ed25519PrivateKey.generate() for actor in ("human-A", "human-B")}
    events = [archive_request(engagement, source, actor, key) for actor, key in keys.items()]
    app = create_app(
        database_url=database, redis_url=redis,
        trusted_public_keys={actor: key.public_key() for actor, key in keys.items()},
    )
    with TestClient(app) as client:
        ready = Barrier(2, timeout=10)

        def post(event: TransitionEvent) -> httpx.Response:
            ready.wait()
            response = client.post(f"/engagements/{engagement}/transition", json=event.model_dump(mode="json"))
            assert isinstance(response, httpx.Response)
            return response

        with ThreadPoolExecutor(max_workers=2) as pool:
            responses = list(pool.map(post, events))

    assert sorted(r.status_code for r in responses) == [200, 409], [r.text for r in responses]
    ordered = sorted(zip(events, responses, strict=True), key=lambda pair: pair[1].status_code)
    (winner, applied), (_, rejected) = ordered
    assert applied.json()["status"] == "applied"
    assert rejected.json()["reason"] == "STATE_MISMATCH"
    with psycopg.connect(database) as reader:
        assert get_state(reader, engagement) == EngagementState.COMPLETED_ARCHIVED
        prior, final = read_ledger(reader, engagement, 0)
    assert prior.event == history
    assert final.seq_id > prior.seq_id
    assert prior.record_hash == final.prev_record_hash == previous_hash
    assert final.event == winner
    assert final.record_hash == hash_record(previous_hash, winner) == applied.json()["ledger_hash"]


def test_signed_archival_is_bound_to_its_engagement(urls: tuple[str, str]) -> None:
    database, redis = urls
    engagement, other = uuid4(), uuid4()
    source = EngagementState.RETEST_VERIFICATION
    with psycopg.connect(database) as connection, connection.cursor() as cursor:
        cursor.executemany("INSERT INTO engagements (id, current_state) VALUES (%s, %s)",
                           [(engagement, source), (other, source)])
    key = Ed25519PrivateKey.generate()
    event = archive_request(engagement, source, "archivist", key)
    app = create_app(database_url=database, redis_url=redis,
                     trusted_public_keys={event.actor_id: key.public_key()})
    with TestClient(app) as client:
        payload = event.model_dump(mode="json")
        mismatch = client.post(f"/engagements/{other}/transition", json=payload)
        assert 400 <= mismatch.status_code < 500, mismatch.text
        assert mismatch.json()["reason"] == "ENGAGEMENT_ID_MISMATCH"
        with psycopg.connect(database) as reader:
            for engagement_id in (engagement, other):
                assert get_state(reader, engagement_id) == source
                assert read_ledger(reader, engagement_id, 0) == []
        accepted = client.post(f"/engagements/{engagement}/transition", json=payload)
        assert accepted.status_code == 200, accepted.text
        assert accepted.json()["status"] == "applied"
    with psycopg.connect(database) as reader:
        assert get_state(reader, engagement) == EngagementState.COMPLETED_ARCHIVED
        final, = read_ledger(reader, engagement, 0)
    assert final.event == event
    assert final.prev_record_hash == GENESIS_HASH
    assert final.record_hash == hash_record(GENESIS_HASH, event) == accepted.json()["ledger_hash"]


def test_archive_denial_is_atomic_for_each_invalid_signature(urls: tuple[str, str]) -> None:
    database, redis = urls
    engagement = uuid4()
    source = EngagementState.REMEDIATION_SYNTHESIS
    with psycopg.connect(database) as connection:
        connection.execute("INSERT INTO engagements (id, current_state) VALUES (%s, %s)", (engagement, source))

    key = Ed25519PrivateKey.generate()
    event = archive_request(engagement, source, "archivist", key)
    assert event.hitl_signature is not None
    wrong_signer = event.hitl_signature.model_copy(update={"signer_id": "another-operator"})
    app = create_app(database_url=database, redis_url=redis,
                     trusted_public_keys={event.actor_id: key.public_key()})
    with TestClient(app) as client, psycopg.connect(database, autocommit=True) as reader:
        for modified in (
            event.model_copy(update={"event_id": str(uuid4())}),
            event.model_copy(update={"hitl_signature": None}),
            event.model_copy(update={"hitl_signature": wrong_signer}),
        ):
            response = client.post(f"/engagements/{engagement}/transition", json=modified.model_dump(mode="json"))
            assert response.status_code == 403, response.text
            assert response.json()["reason"] == "HUMAN_SIGNATURE_REQUIRED"
            assert get_state(reader, engagement) == source
            assert read_ledger(reader, engagement, 0) == []


@pytest.mark.parametrize(
    ("source", "destination"),
    [
        (EngagementState.CONTROLLED_VALIDATION, EngagementState.EVIDENCE_VERIFICATION),
        (EngagementState.DISCOVERY_PASSIVE, EngagementState.REMEDIATION_SYNTHESIS),
        (EngagementState.ANALYTICAL_TRIAGE, EngagementState.REMEDIATION_SYNTHESIS),
        (EngagementState.EVIDENCE_VERIFICATION, EngagementState.REMEDIATION_SYNTHESIS),
        (EngagementState.RETEST_VERIFICATION, EngagementState.REMEDIATION_SYNTHESIS),
    ],
)
def test_evidence_and_remediation_handoffs(
    urls: tuple[str, str], source: EngagementState, destination: EngagementState,
) -> None:
    database, redis = urls
    engagement = uuid4()
    event = TransitionEvent(
        engagement_id=str(engagement), event_id=str(uuid4()), from_state=source, to_state=destination,
        actor_type=ActorType.HUMAN_OPERATOR, actor_id="report-reviewer", occurred_at=datetime.now(timezone.utc),
    )
    previous = GENESIS_HASH
    with psycopg.connect(database) as connection:
        connection.execute("INSERT INTO engagements (id, current_state) VALUES (%s, %s)", (engagement, source))
        if source == EngagementState.EVIDENCE_VERIFICATION:
            history = event.model_copy(update={
                "event_id": str(uuid4()), "from_state": EngagementState.CONTROLLED_VALIDATION, "to_state": source,
            })
            previous = hash_record(GENESIS_HASH, history)
            connection.execute(
                """INSERT INTO immutable_audit_log (payload, prev_record_hash, record_hash)
                   VALUES (%s::jsonb, %s, %s)""", (history.model_dump_json(), GENESIS_HASH, previous),
            )

    app = create_app(database_url=database, redis_url=redis, trusted_public_keys={})
    with TestClient(app) as client:
        path = f"/engagements/{engagement}/transition"
        payload = event.model_dump(mode="json", exclude_none=True)
        applied = client.post(path, json=payload)
        assert applied.status_code == 200, applied.text
        digest = hash_record(previous, event)
        assert applied.json() == {"status": "applied", "next_state": destination.value, "ledger_hash": digest}

        with psycopg.connect(database) as reader:
            assert get_state(reader, engagement) == destination
            records = read_ledger(reader, engagement, 0)
        assert [r.record_hash for r in records] == ([previous, digest] if previous != GENESIS_HASH else [digest])
        latest = records[-1]
        assert latest.prev_record_hash == previous
        assert latest.event == event

        stale = client.post(path, json={**payload, "event_id": str(uuid4())})
        assert stale.status_code == 409, stale.text
        assert stale.json()["reason"] == "STATE_MISMATCH"
        with psycopg.connect(database) as reader:
            assert get_state(reader, engagement) == destination
            assert read_ledger(reader, engagement, 0) == records


def test_remediation_preserves_and_checks_optional_signature(urls: tuple[str, str]) -> None:
    database, redis = urls
    engagement = uuid4()
    source = EngagementState.EVIDENCE_VERIFICATION
    with psycopg.connect(database) as db:
        db.execute("INSERT INTO engagements (id, current_state) VALUES (%s, %s)", (engagement, source))

    key = Ed25519PrivateKey.generate()
    event = TransitionEvent(
        event_id=str(uuid4()), engagement_id=str(engagement), from_state=source,
        to_state=EngagementState.REMEDIATION_SYNTHESIS, actor_type=ActorType.HUMAN_OPERATOR,
        actor_id="reviewer", occurred_at=datetime.now(timezone.utc),
    )
    signed = event.model_copy(update={"hitl_signature": Ed25519Signature(
        signer_id=event.actor_id, signature=key.sign(event.canonical_envelope()).hex(),
    )})
    app = create_app(database_url=database, redis_url=redis, trusted_public_keys={event.actor_id: key.public_key()})
    with TestClient(app) as client, psycopg.connect(database, autocommit=True) as reader:
        payload = signed.model_dump(mode="json")
        path = f"/engagements/{engagement}/transition"
        denied = client.post(path, json={**payload, "event_id": str(uuid4())})
        assert denied.status_code == 403 and denied.json()["reason"] == "INVALID_SIGNATURE"
        assert get_state(reader, engagement) == source and not read_ledger(reader, engagement, 0)
        assert client.post(path, json=payload).status_code == 200
        record, = read_ledger(reader, engagement, 0)
        assert record.event == signed
