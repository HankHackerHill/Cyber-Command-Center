# Orchestrator audit delivery

State transitions and their ledger appends remain synchronous, signed where
required, and atomic under the existing engagement row lock. The default audit
API also retains its synchronous 201/200 ledger-receipt behavior.

ADR-0017 asynchronous non-transition audit delivery is opt-in. Configure
`ORCHESTRATOR_AUDIT_OUTBOX` to a persistent local SQLite file. All participating
orchestrator processes for an engagement must share that same outbox domain.
Separate host-local files cannot coordinate conflicting queued idempotency keys
before PostgreSQL append; this configuration is not a multi-host queue protocol.
Keep the outbox file and its WAL on persistent storage with a private parent
directory. Leaving the variable unset creates no queue or background worker.

Authenticated M4 callers send `Prefer: respond-async` and one UUID
`Idempotency-Key` to `POST /engagements/{id}/audit-events`. A 202 response means
SQLite WAL/FULL has durably accepted the validated event, not that PostgreSQL
has appended it. Duplicate keys with identical normalized payloads are stable;
conflicting payloads receive 409. Actor authentication, wire validation and
engagement checks remain required.

`GET /engagements/{id}/audit-events/{event_id}` uses the same M4 authentication
and returns 202 while queued, 200 with the committed ledger record, or 404 for an
unknown event. A worker retries accepted jobs using the existing idempotent
ledger writer. It acknowledges the queue only after PostgreSQL commits. A crash
between append and acknowledgment replays the same key and returns the original
record, continuing the hash chain once. No queue transaction is held while
waiting for a PostgreSQL engagement lock. Shutdown is bounded; unacknowledged
jobs remain on disk for restart.

Back up and restore the outbox consistently with the ledger, and retain pending
jobs during outages. An unavailable/full outbox fails acceptance instead of
returning a false 202. Evidence promotion still requires the actual durable
artifact and ledger link through the existing evidence verification gate.

Run the full suite with disposable `ORCHESTRATOR_TEST_DATABASE_URL` and
`ORCHESTRATOR_TEST_REDIS_URL`, followed by `mypy --strict` using this service's
configuration. New delivery tests cover durable acceptance, restart and lost
acknowledgment replay, synchronous/asynchronous conflicts, signature-preserving
transition interleaving, and storage failures.
