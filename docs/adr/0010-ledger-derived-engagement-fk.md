# ADR-0010 — Derive the ledger engagement key from the transition event

**Status: Accepted**

The JSONB `payload` holds the transition event. PostgreSQL derives
`immutable_audit_log.engagement_id` as a stored generated UUID column
from `payload->>'engagement_id'`. The payload supplies the sole value,
so the indexed key and the event cannot drift. A foreign key references
`engagements(id)`. A B-tree index on the generated column supports
per-engagement ledger reads, including `GET /engagements/{id}/ledger?since=`.

An upgrade preserves signed event payloads and ledger hashes. Existing
engagement identifiers must cast to distinct UUIDs for the migration to
succeed. An incompatible identifier rolls back the migration.
