import hashlib
import json
import os
from collections.abc import Iterator
from datetime import datetime, timezone
from uuid import UUID, uuid4

import psycopg
import pytest
from contracts.events import ActorType, EngagementState, TransitionEvent
from hypothesis import given
from hypothesis import strategies as st

from ledger import GENESIS_HASH, get_state, halt_engagement, hash_record, read_ledger


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
