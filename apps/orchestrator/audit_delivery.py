"""Durable local delivery of non-transition audit events (ADR-0017).

The SQLite file must live on persistent local storage shared by every process
serving this orchestrator instance. PostgreSQL remains the ledger authority.
No SQLite transaction is held while acquiring a PostgreSQL engagement lock.
"""

import json
import logging
import os
import sqlite3
from contextlib import contextmanager
from collections.abc import Iterator
from pathlib import Path
from threading import Event, Thread
from time import time
from typing import Literal
from uuid import UUID

from contracts.events import AuditEvent
from contracts.ledger import LedgerRecord
from psycopg import Connection
from psycopg_pool import ConnectionPool
from pydantic import BaseModel, ConfigDict

from ledger import AuditReplayConflict, EngagementNotFound, record_audit_event

logger = logging.getLogger(__name__)


class QueuedAudit(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    status: Literal["queued"] = "queued"
    event_id: UUID
    engagement_id: UUID


def canonical_event(event: AuditEvent) -> str:
    """Compare validated/normalized JSON, preserving boolean versus number identity."""
    return json.dumps(event.model_dump(mode="json"), sort_keys=True,
                      ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def lock_engagement(conn: Connection, engagement_id: UUID) -> None:
    if conn.execute("SELECT id FROM engagements WHERE id = %s FOR UPDATE", (engagement_id,)).fetchone() is None:
        raise EngagementNotFound(engagement_id)


def audit_receipt(conn: Connection, engagement_id: UUID, key: UUID,
                  event: AuditEvent | None = None) -> LedgerRecord | None:
    row = conn.execute(
        """SELECT seq_id, payload, prev_record_hash, record_hash,
                  (payload - ARRAY['event_id', 'engagement_id', 'occurred_at']) = %s::jsonb
           FROM immutable_audit_log
           WHERE engagement_id = %s AND payload ? 'actor_kind' AND payload->>'event_id' = %s""",
        (event.model_dump_json() if event is not None else "null", engagement_id, str(key)),
    ).fetchone()
    if row is None:
        return None
    seq, body, previous, digest, matches = row
    if event is not None and not matches:
        raise AuditReplayConflict(key)
    return LedgerRecord.model_validate({
        "seq_id": seq, "payload": body, "prev_record_hash": previous, "record_hash": digest,
    })


class AuditOutbox:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        if str(path) == ":memory:":
            raise ValueError("Audit delivery requires a persistent SQLite file")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.close(descriptor)
        with self.connect() as conn:
            mode = conn.execute("PRAGMA journal_mode=WAL").fetchone()
            if mode != ("wal",):
                raise RuntimeError("Audit outbox requires SQLite WAL")
            conn.execute("""CREATE TABLE IF NOT EXISTS audit_jobs (
                engagement_id TEXT NOT NULL, event_id TEXT NOT NULL, body TEXT NOT NULL,
                receipt TEXT, attempts INTEGER NOT NULL DEFAULT 0,
                next_attempt REAL NOT NULL DEFAULT 0, last_error TEXT,
                PRIMARY KEY (engagement_id, event_id))""")
            conn.execute("CREATE INDEX IF NOT EXISTS audit_jobs_pending ON audit_jobs(next_attempt) WHERE receipt IS NULL")

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=0.25)
        try:
            conn.execute("PRAGMA synchronous=FULL")
            with conn:
                yield conn
        finally:
            conn.close()

    def check(self, engagement_id: UUID, key: UUID, event: AuditEvent) -> None:
        with self.connect() as conn:
            row = conn.execute("SELECT body FROM audit_jobs WHERE engagement_id=? AND event_id=?",
                               (str(engagement_id), str(key))).fetchone()
        if row is not None and row[0] != canonical_event(event):
            raise AuditReplayConflict(key)

    def enqueue(self, engagement_id: UUID, key: UUID, event: AuditEvent) -> None:
        body = canonical_event(event)
        with self.connect() as conn:
            conn.execute("INSERT OR IGNORE INTO audit_jobs (engagement_id,event_id,body) VALUES (?,?,?)",
                         (str(engagement_id), str(key), body))
            row = conn.execute("SELECT body FROM audit_jobs WHERE engagement_id=? AND event_id=?",
                               (str(engagement_id), str(key))).fetchone()
            if row is None or row[0] != body:
                raise AuditReplayConflict(key)
        # Context exit commits with synchronous=FULL before the caller may return 202.

    def lookup(self, engagement_id: UUID, key: UUID) -> QueuedAudit | LedgerRecord | None:
        with self.connect() as conn:
            row = conn.execute("SELECT receipt FROM audit_jobs WHERE engagement_id=? AND event_id=?",
                               (str(engagement_id), str(key))).fetchone()
        if row is None:
            return None
        return (LedgerRecord.model_validate_json(row[0]) if row[0] is not None
                else QueuedAudit(engagement_id=engagement_id, event_id=key))

    def pending(self) -> tuple[UUID, UUID, AuditEvent, int] | None:
        with self.connect() as conn:
            row = conn.execute("""SELECT engagement_id,event_id,body,attempts FROM audit_jobs
                WHERE receipt IS NULL AND next_attempt<=? ORDER BY next_attempt,rowid LIMIT 1""", (time(),)).fetchone()
        if row is None:
            return None
        return UUID(row[0]), UUID(row[1]), AuditEvent.model_validate_json(row[2]), int(row[3])

    def acknowledge(self, engagement_id: UUID, key: UUID, receipt: LedgerRecord) -> None:
        with self.connect() as conn:
            conn.execute("UPDATE audit_jobs SET receipt=?,last_error=NULL WHERE engagement_id=? AND event_id=?",
                         (receipt.model_dump_json(by_alias=False), str(engagement_id), str(key)))

    def retry(self, engagement_id: UUID, key: UUID, attempts: int, exc: Exception) -> None:
        delay = min(5.0, 0.05 * 2 ** min(attempts, 7))
        with self.connect() as conn:
            conn.execute("""UPDATE audit_jobs SET attempts=attempts+1,next_attempt=?,last_error=?
                WHERE engagement_id=? AND event_id=? AND receipt IS NULL""",
                         (time() + delay, type(exc).__name__, str(engagement_id), str(key)))


class AuditDelivery:
    def __init__(self, outbox: AuditOutbox, database: ConnectionPool) -> None:
        self.outbox, self.database = outbox, database
        self.stopping = Event()
        self.thread = Thread(target=self.run, name="audit-delivery", daemon=True)

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.stopping.set()
        self.thread.join(timeout=2)

    def deliver_one(self) -> bool:
        job = self.outbox.pending()
        if job is None:
            return False
        engagement_id, key, event, attempts = job
        try:
            with self.database.connection(timeout=0.25) as conn:
                with conn.transaction():
                    conn.execute("SET LOCAL statement_timeout = '1000ms'")
                    conn.execute("SET LOCAL lock_timeout = '500ms'")
                    receipt, _ = record_audit_event(conn, engagement_id, event, key)
            # Both transaction and pool context have exited: the append committed.
            self.outbox.acknowledge(engagement_id, key, receipt)
        except Exception as exc:
            self.outbox.retry(engagement_id, key, attempts, exc)
            if isinstance(exc, AuditReplayConflict):
                logger.error("Audit delivery conflict for engagement %s event %s; check shared outbox configuration",
                             engagement_id, key)
            else:
                logger.warning("Audit delivery deferred: %s", type(exc).__name__)
        return True

    def run(self) -> None:
        while not self.stopping.is_set():
            try:
                worked = self.deliver_one()
            except Exception:
                logger.exception("Audit outbox unavailable; durable jobs retained")
                worked = False
            if not worked:
                self.stopping.wait(0.05)
