# ADR-0013 — Append audit events without advancing engagement state

**Status: Accepted.**

The orchestrator owns all writes to `immutable_audit_log`. M4 may record
tunnel rejections and policy denials through
`POST /engagements/{id}/audit-events`. The request is a frozen
`AuditEvent` with `actor_kind`, `actor_id`, `event_type`, and a JSON
object `payload`. It has no transition fields. The first service principal
is M4 (`SYSTEM`, `scoped-proxy`). The route authenticates that principal
and verifies the supplied actor identity before appending.

The orchestrator binds the stored event to the engagement in the URL and
adds an event ID and UTC timestamp. M4 uses a stable UUID in the
`Idempotency-Key` header on retries. The same key and body return the
original ledger record. Conflicting reuse returns 409. A caller that omits
the header requests a new event. Unknown engagements return 404.

Appending takes the existing engagement row lock, reads the latest hash,
and inserts the next hash-linked ledger row in the same transaction. The
engagement retains its current state. The existing schema stores both kinds
of event in JSONB and derives the engagement foreign key from that JSON.
Previous and next states for an audit event are SQL NULL when projected from
the payload. There are no physical state columns to migrate. Existing
transition hashes, signatures, and ledger read shapes remain valid.

This decision authorizes the M4 lane to update the Python contracts, regenerate
their TypeScript representation, and implement and test the orchestrator
endpoint. The database schema and the M3 service stay in their existing lanes.
