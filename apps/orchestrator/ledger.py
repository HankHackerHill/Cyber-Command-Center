"""Read the engagement journal and atomically record an emergency stop."""

import hashlib
import json
from datetime import datetime, timezone
from uuid import UUID, uuid4

from contracts.events import ActorType, EngagementState, TransitionEvent
from contracts.ledger import LedgerRecord
from psycopg import Connection

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


def halt_engagement(conn: Connection, engagement_id: UUID) -> str | None:
    """Stop under the engagement lock. An already halted, unjournaled row has no hash."""
    with conn.transaction():
        row = conn.execute(
            "SELECT current_state FROM engagements WHERE id = %s FOR UPDATE",
            (engagement_id,),
        ).fetchone()
        if row is None:
            raise EngagementNotFound(engagement_id)
        state = EngagementState(row[0])
        tail = conn.execute(
            """SELECT record_hash FROM immutable_audit_log
               WHERE engagement_id = %s ORDER BY seq_id DESC LIMIT 1""",
            (engagement_id,),
        ).fetchone()
        last_hash = str(tail[0]) if tail else None
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
