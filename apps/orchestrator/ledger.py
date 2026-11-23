"""Read the engagement journal and record stops and signed closures."""

import hashlib
import json
from collections.abc import Mapping
from datetime import datetime, timezone
from uuid import UUID, uuid4

from contracts.events import ActorType, EngagementState, TransitionEvent
from contracts.ledger import LedgerRecord
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from psycopg import Connection

from state_machine import Reason, TransitionDenied, require_engagement_id, require_signed_archive

GENESIS_HASH = "0" * 64


class EngagementNotFound(LookupError):
    pass


def get_state(conn: Connection, engagement_id: UUID) -> EngagementState:
    row = conn.execute(
        "SELECT current_state FROM engagements WHERE id = %s", (engagement_id,)
    ).fetchone()
    if row is None:
        raise EngagementNotFound(engagement_id)
    return EngagementState(row[0])


def read_ledger(conn: Connection, engagement_id: UUID, since: int) -> list[LedgerRecord]:
    get_state(conn, engagement_id)
    rows = conn.execute(
        """SELECT seq_id, payload, prev_record_hash, record_hash
           FROM immutable_audit_log WHERE engagement_id = %s AND seq_id > %s
           ORDER BY seq_id""",
        (engagement_id, since),
    )
    return [
        LedgerRecord.model_validate({
            "seq_id": seq, "payload": payload, "prev_record_hash": previous, "record_hash": digest,
        })
        for seq, payload, previous, digest in rows
    ]


def hash_record(previous_hash: str, event: TransitionEvent) -> str:
    """Hash the 32-byte predecessor digest followed by the complete canonical event JSON."""
    payload = json.dumps(event.model_dump(mode="json"), sort_keys=True,
                         ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(bytes.fromhex(previous_hash) + payload.encode("utf-8")).hexdigest()


def _lock_engagement(conn: Connection, engagement_id: UUID) -> EngagementState:
    row = conn.execute(
        "SELECT current_state FROM engagements WHERE id = %s FOR UPDATE", (engagement_id,),
    ).fetchone()
    if row is None:
        raise EngagementNotFound(engagement_id)
    return EngagementState(row[0])


def _tail_hash(conn: Connection, engagement_id: UUID) -> str | None:
    row = conn.execute(
        """SELECT record_hash FROM immutable_audit_log
           WHERE engagement_id = %s ORDER BY seq_id DESC LIMIT 1""",
        (engagement_id,),
    ).fetchone()
    return str(row[0]) if row else None


def archive_engagement(
    conn: Connection, engagement_id: UUID, event: TransitionEvent,
    trusted_keys: Mapping[str, Ed25519PublicKey],
) -> str:
    require_engagement_id(engagement_id, event)
    require_signed_archive(event, trusted_keys)
    with conn.transaction():
        if _lock_engagement(conn, engagement_id) != event.from_state:
            raise TransitionDenied(Reason.STATE_MISMATCH, 409)
        previous = _tail_hash(conn, engagement_id) or GENESIS_HASH
        digest = hash_record(previous, event)
        conn.execute(
            """WITH archived AS (
                   UPDATE engagements SET current_state = 'COMPLETED_ARCHIVED'
                   WHERE id = %s RETURNING id
               )
               INSERT INTO immutable_audit_log (payload, prev_record_hash, record_hash)
               SELECT %s::jsonb, %s, %s FROM archived""",
            (engagement_id, event.model_dump_json(), previous, digest),
        )
        return digest


def halt_engagement(conn: Connection, engagement_id: UUID) -> str | None:
    """Stop under the engagement lock. An already halted, unjournaled row has no hash."""
    with conn.transaction():
        state = _lock_engagement(conn, engagement_id)
        last_hash = _tail_hash(conn, engagement_id)
        if state == EngagementState.HALTED_KILLSWITCH:
            return last_hash

        stop = TransitionEvent(
            event_id=str(uuid4()), engagement_id=str(engagement_id), from_state=state,
            to_state=EngagementState.HALTED_KILLSWITCH, actor_type=ActorType.SYSTEM,
            actor_id="orchestrator:killswitch", occurred_at=datetime.now(timezone.utc),
        )
        previous = last_hash or GENESIS_HASH
        digest = hash_record(previous, stop)
        conn.execute(
            """WITH halted AS (
                   UPDATE engagements SET current_state = 'HALTED_KILLSWITCH'
                   WHERE id = %s RETURNING id
               )
               INSERT INTO immutable_audit_log (payload, prev_record_hash, record_hash)
               SELECT %s::jsonb, %s, %s FROM halted""",
            (engagement_id, stop.model_dump_json(), previous, digest),
        )
        return digest
