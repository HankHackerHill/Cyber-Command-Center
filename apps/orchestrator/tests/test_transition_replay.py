"""Applied transition approvals are consumed once, including across state cycles."""

import os
from datetime import datetime, timezone
from uuid import UUID, uuid4

import psycopg
import pytest
from contracts.events import ActorType, Ed25519Signature, EngagementState, TransitionEvent
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from ledger import GENESIS_HASH, get_state, hash_record, read_ledger, record_review_transition
from main import create_app


@pytest.fixture(scope="module")
def urls() -> tuple[str, str]:
    database = os.environ.get("ORCHESTRATOR_TEST_DATABASE_URL")
    redis = os.environ.get("ORCHESTRATOR_TEST_REDIS_URL")
    if not database or not redis:
        pytest.skip("Set ORCHESTRATOR_TEST_DATABASE_URL and ORCHESTRATOR_TEST_REDIS_URL")
    return database, redis


def signed_lock(
    engagement: UUID, source: EngagementState, key: Ed25519PrivateKey, event_id: str | None = None,
) -> TransitionEvent:
    event = TransitionEvent(
        event_id=event_id or str(uuid4()), engagement_id=str(engagement), from_state=source,
        to_state=EngagementState.ROE_LOCKED, actor_type=ActorType.HUMAN_OPERATOR,
        actor_id="reset-operator", occurred_at=datetime.now(timezone.utc),
    )
    return event.model_copy(update={"hitl_signature": Ed25519Signature(
        signer_id=event.actor_id, signature=key.sign(event.canonical_envelope()).hex(),
    )})


def test_signed_reset_replay_after_another_halt_has_no_writes(urls: tuple[str, str]) -> None:
    database, redis = urls
    engagement = uuid4()
    key = Ed25519PrivateKey.generate()
    with psycopg.connect(database) as conn:
        conn.execute("INSERT INTO engagements (id) VALUES (%s)", (engagement,))
    app = create_app(database_url=database, redis_url=redis,
                     trusted_public_keys={"reset-operator": key.public_key()})
    with TestClient(app) as client, psycopg.connect(database, autocommit=True) as reader:
        path = f"/engagements/{engagement}"
        assert client.post(f"{path}/killswitch").status_code == 200
        event = signed_lock(engagement, EngagementState.HALTED_KILLSWITCH, key)
        assert client.post(f"{path}/transition", json=event.model_dump(mode="json")).status_code == 200
        assert client.post(f"{path}/killswitch").status_code == 200
        before = read_ledger(reader, engagement, 0)
        assert len(before) == 3
        assert get_state(reader, engagement) == EngagementState.HALTED_KILLSWITCH

        rejected = client.post(f"{path}/transition", json=event.model_dump(mode="json"))
        assert rejected.status_code == 409, rejected.text
        assert rejected.json()["reason"] == "EVENT_REPLAY"
        assert get_state(reader, engagement) == EngagementState.HALTED_KILLSWITCH
        assert read_ledger(reader, engagement, 0) == before

        fresh = signed_lock(engagement, EngagementState.HALTED_KILLSWITCH, key)
        accepted = client.post(f"{path}/transition", json=fresh.model_dump(mode="json"))
        assert accepted.status_code == 200, accepted.text
        assert get_state(reader, engagement) == EngagementState.ROE_LOCKED
        records = read_ledger(reader, engagement, 0)
        assert records[:-1] == before
        assert records[-1].event == fresh
        assert records[-1].prev_record_hash == before[-1].record_hash
        assert records[-1].record_hash == hash_record(before[-1].record_hash, fresh)


def test_transition_ids_are_engagement_scoped_and_separate_from_audit_ids(urls: tuple[str, str]) -> None:
    database, redis = urls
    engagements = [uuid4(), uuid4()]
    event_id = uuid4()
    key = Ed25519PrivateKey.generate()
    with psycopg.connect(database) as conn, conn.cursor() as cursor:
        cursor.executemany("INSERT INTO engagements (id) VALUES (%s)", [(eid,) for eid in engagements])
    app = create_app(database_url=database, redis_url=redis,
                     trusted_public_keys={"reset-operator": key.public_key()}, m4_audit_token="test-m4")
    with TestClient(app) as client:
        audit = client.post(
            f"/engagements/{engagements[0]}/audit-events",
            json={"actor_kind": "SYSTEM", "actor_id": "scoped-proxy", "event_type": "TEST", "payload": {}},
            headers={"Authorization": "Bearer test-m4", "Idempotency-Key": str(event_id)},
        )
        assert audit.status_code == 201, audit.text
        for engagement in engagements:
            event = signed_lock(engagement, EngagementState.INIT_SCOPING, key, str(event_id))
            result = client.post(f"/engagements/{engagement}/transition", json=event.model_dump(mode="json"))
            assert result.status_code == 200, result.text
    with psycopg.connect(database) as reader:
        for engagement, expected_rows in zip(engagements, (2, 1), strict=True):
            assert get_state(reader, engagement) == EngagementState.ROE_LOCKED
            assert len(read_ledger(reader, engagement, 0)) == expected_rows


def test_failed_journal_append_does_not_consume_transition_id(urls: tuple[str, str]) -> None:
    database, _ = urls
    engagement = uuid4()
    key = Ed25519PrivateKey.generate()
    event = signed_lock(engagement, EngagementState.INIT_SCOPING, key)
    trusted = {event.actor_id: key.public_key()}
    with psycopg.connect(database, autocommit=True) as conn:
        conn.execute("INSERT INTO engagements (id) VALUES (%s)", (engagement,))
        # Shadow the journal only in this session and force the atomic CTE to fail.
        conn.execute(
            """CREATE TEMP TABLE immutable_audit_log (
                   LIKE public.immutable_audit_log INCLUDING ALL, CHECK (false)
               )"""
        )
        with pytest.raises(psycopg.errors.CheckViolation):
            record_review_transition(conn, engagement, event, trusted)
        assert get_state(conn, engagement) == EngagementState.INIT_SCOPING
        assert read_ledger(conn, engagement, 0) == []
        conn.execute("DROP TABLE pg_temp.immutable_audit_log")
        assert read_ledger(conn, engagement, 0) == []
        digest = record_review_transition(conn, engagement, event, trusted)
        assert get_state(conn, engagement) == EngagementState.ROE_LOCKED
        record, = read_ledger(conn, engagement, 0)
        assert record.event == event
        assert record.prev_record_hash == GENESIS_HASH
        assert record.record_hash == digest == hash_record(GENESIS_HASH, event)
