"""Check the live MS0 schema against frozen contracts and ADR-0010."""

import os
from collections.abc import Iterator
from datetime import datetime, timezone
from enum import StrEnum
from uuid import uuid4

import psycopg
import pytest
from contracts.events import ActorType, EngagementState, TransitionEvent
from contracts.findings import EdgeKind, FindingStatus
from contracts.ledger import LedgerRecord
from contracts.plans import BlastRadius
from contracts.tasks import TaskMode, TaskStatus

from ledger import GENESIS_HASH, hash_record


@pytest.fixture
def connection() -> Iterator[psycopg.Connection]:
    url = os.getenv("ORCHESTRATOR_TEST_DATABASE_URL")
    if not url:
        pytest.skip("Set ORCHESTRATOR_TEST_DATABASE_URL to a disposable MS0 database")
    with psycopg.connect(url) as conn:
        try:
            yield conn
        finally:
            # The ledger is append-only: discard fixtures by rolling back, not deleting.
            conn.rollback()


@pytest.mark.parametrize(
    ("database_type", "contract_type"),
    [
        ("engagement_state", EngagementState),
        ("actor_type", ActorType),
        ("task_mode", TaskMode),
        ("task_status", TaskStatus),
        ("finding_status", FindingStatus),
        ("edge_kind", EdgeKind),
        ("blast_radius", BlastRadius),
    ],
)
def test_database_enum_matches_frozen_contract(
    connection: psycopg.Connection, database_type: str, contract_type: type[StrEnum],
) -> None:
    rows = connection.execute(
        """SELECT e.enumlabel
           FROM pg_catalog.pg_enum AS e
           JOIN pg_catalog.pg_type AS t ON t.oid = e.enumtypid
           JOIN pg_catalog.pg_namespace AS n ON n.oid = t.typnamespace
           WHERE n.nspname = 'public' AND t.typname = %s
           ORDER BY e.enumsortorder""",
        (database_type,),
    ).fetchall()
    assert [row[0] for row in rows] == [member.value for member in contract_type]


def test_ledger_projection_matches_contract_and_derived_key(
    connection: psycopg.Connection,
) -> None:
    rows = connection.execute(
        """SELECT attname, pg_catalog.format_type(atttypid, atttypmod),
                  attnotnull, attgenerated
           FROM pg_catalog.pg_attribute
           WHERE attrelid = 'public.immutable_audit_log'::regclass
             AND attnum > 0 AND NOT attisdropped""",
    ).fetchall()
    columns = {name: (sql_type, not_null, generated) for name, sql_type, not_null, generated in rows}
    projected_fields = {
        field.serialization_alias or name for name, field in LedgerRecord.model_fields.items()
    }
    assert LedgerRecord.model_fields["event"].serialization_alias == "payload"
    assert set(columns) == projected_fields | {"engagement_id"}
    assert columns == {
        "seq_id": ("bigint", True, ""),
        "payload": ("jsonb", True, ""),
        "prev_record_hash": ("character(64)", True, ""),
        "record_hash": ("character(64)", True, ""),
        "engagement_id": ("uuid", True, "s"),
    }
    foreign_keys = connection.execute(
        """SELECT source.attname, target.attname
           FROM pg_catalog.pg_constraint AS c
           JOIN pg_catalog.pg_attribute AS source
             ON source.attrelid = c.conrelid AND c.conkey = ARRAY[source.attnum]
           JOIN pg_catalog.pg_attribute AS target
             ON target.attrelid = c.confrelid AND c.confkey = ARRAY[target.attnum]
           WHERE c.contype = 'f'
             AND c.conrelid = 'public.immutable_audit_log'::regclass
             AND c.confrelid = 'public.engagements'::regclass""",
    ).fetchall()
    assert foreign_keys == [("engagement_id", "id")]


def test_ledger_engagement_key_is_sourced_only_from_payload(
    connection: psycopg.Connection,
) -> None:
    engagement_id = uuid4()
    event = TransitionEvent(
        event_id=str(uuid4()), engagement_id=str(engagement_id),
        from_state=EngagementState.INIT_SCOPING,
        to_state=EngagementState.HALTED_KILLSWITCH,
        actor_type=ActorType.SYSTEM, actor_id="parity-test",
        occurred_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    connection.execute("INSERT INTO public.engagements (id) VALUES (%s)", (engagement_id,))
    values = (event.model_dump_json(), GENESIS_HASH, hash_record(GENESIS_HASH, event))
    row = connection.execute(
        """INSERT INTO public.immutable_audit_log (payload, prev_record_hash, record_hash)
           VALUES (%s::jsonb, %s, %s) RETURNING engagement_id""",
        values,
    ).fetchone()
    assert row == (engagement_id,)
    # A second source for the key must be rejected even when it matches the event.
    with pytest.raises(psycopg.errors.GeneratedAlways):
        with connection.transaction():
            connection.execute(
                """INSERT INTO public.immutable_audit_log
                       (payload, prev_record_hash, record_hash, engagement_id)
                   VALUES (%s::jsonb, %s, %s, %s)""",
                (*values, engagement_id),
            )
