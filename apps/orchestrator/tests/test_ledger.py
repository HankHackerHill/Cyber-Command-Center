import hashlib
import json
import os
from collections.abc import Iterator
from datetime import datetime, timezone
from uuid import UUID, uuid4

import psycopg
import pytest
from contracts.events import ActorType, EngagementState, TransitionEvent
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from hypothesis import given
from hypothesis import strategies as st

from ledger import GENESIS_HASH, get_state, halt_engagement, hash_record, read_ledger
from signatures import verify_human_signature


def historical_event(engagement_id: UUID) -> TransitionEvent:
    return TransitionEvent(
        event_id="remediation-1", engagement_id=str(engagement_id),
        from_state=EngagementState.EVIDENCE_VERIFICATION,
        to_state=EngagementState.REMEDIATION_SYNTHESIS, actor_id="auditor",
        actor_type=ActorType.HUMAN_OPERATOR, occurred_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )


@pytest.fixture
def connection() -> Iterator[psycopg.Connection]:
    url = os.getenv("ORCHESTRATOR_TEST_DATABASE_URL")
    if not url:
        pytest.skip("Set ORCHESTRATOR_TEST_DATABASE_URL to a disposable MS0 database")
    with psycopg.connect(url, autocommit=True) as conn:
        yield conn


@given(st.binary(min_size=32, max_size=32), st.uuids())
def test_digest_binds_event_and_previous_hash(previous: bytes, engagement_id: UUID) -> None:
    event = historical_event(engagement_id)
    body = json.dumps(event.model_dump(mode="json"), sort_keys=True,
                      separators=(",", ":"), ensure_ascii=False).encode()
    digest = hash_record(previous.hex(), event)
    assert digest == hashlib.sha256(previous + body).hexdigest()
    tampered = event.model_copy(update={"actor_id": "different"})
    assert hash_record(previous.hex(), tampered) != digest
    changed = bytes([previous[0] ^ 1]) + previous[1:]
    assert hash_record(changed.hex(), event) != digest


def test_pre_0019_ledger_chain_and_signed_approval_replay(connection: psycopg.Connection) -> None:
    # Frozen from dc84464 using a disposable test signer. Insert the historical JSON
    # directly so today's serializer cannot silently change the fixture or its digests.
    engagement_id = UUID("4a374228-e60c-4fad-a153-5411ed8ecd94")
    queued = (
        '{"event_id":"queued","engagement_id":"4a374228-e60c-4fad-a153-5411ed8ecd94",'
        '"from_state":"ANALYTICAL_TRIAGE","to_state":"AWAITING_HITL_GATE",'
        '"actor_type":"SYSTEM","actor_id":"reviewer","occurred_at":"2026-01-12T12:34:55Z",'
        '"hitl_signature":null}'
    )
    approved = (
        '{"event_id":"approved","engagement_id":"4a374228-e60c-4fad-a153-5411ed8ecd94",'
        '"from_state":"AWAITING_HITL_GATE","to_state":"CONTROLLED_VALIDATION",'
        '"actor_type":"HUMAN_OPERATOR","actor_id":"operator-é","occurred_at":"2026-01-12T12:34:56Z",'
        '"hitl_signature":{"signer_id":"operator-é","signature":"'
        '42e3ab23ee1f034968c78c9889f920d5113b873ebfd9ca160c94a2cba086f352'
        '8d5db664d33601a715b528e1ccc908c001e338491cb6d31360c327b1f0c04701"}}'
    )
    queued_hash = "240a379e91315c1398e0186ac066471213ec34aa92a5da0ff94731fe08666cb0"
    approved_hash = "e62de87c4e6bf264a81a80ad0764fd966f1075a489827c5be420a6a506ef9233"
    rows = ((queued, GENESIS_HASH, queued_hash), (approved, queued_hash, approved_hash))
    with connection.transaction(force_rollback=True):
        connection.execute(
            "INSERT INTO engagements (id, current_state) VALUES (%s, 'CONTROLLED_VALIDATION')",
            (engagement_id,),
        )
        for row in rows:
            connection.execute(
                """INSERT INTO immutable_audit_log (payload, prev_record_hash, record_hash)
                   VALUES (%s::jsonb, %s, %s)""", row,
            )
        records = read_ledger(connection, engagement_id, 0)
    for record, (payload, previous, digest) in zip(records, rows, strict=True):
        assert record.model_dump(mode="json")["event"] == json.loads(payload)
        assert record.prev_record_hash == previous
        assert hash_record(previous, record.event) == record.record_hash == digest
    key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(
        "9818b0f47d5443761e9605c73e5a0b207192e353ba9ce8cdc8616dab8df17e77"
    ))
    approval = records[1].event
    assert isinstance(approval, TransitionEvent)
    assert verify_human_signature(approval, {"operator-é": key})


def test_stop_extends_existing_tail(connection: psycopg.Connection) -> None:
    engagement_id = uuid4()
    history = historical_event(engagement_id)
    previous = hash_record(GENESIS_HASH, history)
    connection.execute(
        "INSERT INTO engagements (id, current_state) VALUES (%s, 'REMEDIATION_SYNTHESIS')",
        (engagement_id,),
    )
    connection.execute(
        """INSERT INTO immutable_audit_log (payload, prev_record_hash, record_hash)
           VALUES (%s::jsonb, %s, %s)""", (history.model_dump_json(), GENESIS_HASH, previous),
    )
    digest = halt_engagement(connection, engagement_id)
    prior, stop = read_ledger(connection, engagement_id, 0)
    assert prior.record_hash == previous == stop.prev_record_hash
    assert stop.record_hash == digest == hash_record(previous, stop.event)
    assert isinstance(stop.event, TransitionEvent)
    assert stop.event.from_state == EngagementState.REMEDIATION_SYNTHESIS


def test_journal_failure_rolls_back_stop(connection: psycopg.Connection) -> None:
    engagement_id = uuid4()
    connection.execute("INSERT INTO engagements (id) VALUES (%s)", (engagement_id,))
    # A session-local journal with a failing check exercises a real PostgreSQL rollback.
    connection.execute(
        """CREATE TEMP TABLE immutable_audit_log (
               LIKE public.immutable_audit_log INCLUDING ALL, CHECK (false)
           )"""
    )
    with pytest.raises(psycopg.errors.CheckViolation):
        halt_engagement(connection, engagement_id)
    assert get_state(connection, engagement_id) == EngagementState.INIT_SCOPING
    assert read_ledger(connection, engagement_id, 0) == []
