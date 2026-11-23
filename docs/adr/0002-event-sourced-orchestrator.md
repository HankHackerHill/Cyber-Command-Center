# ADR-0002: Event-Sourced Orchestrator on Postgres, Not Temporal
**Status:** Accepted — Single-writer state machine with hash-chained
append-only ledger in Postgres. Replayable, auditable, fewer moving parts
than Temporal for v1. LangGraph reserved for agent-internal graphs only.
Rationale: compliance clients demand provable action logs.
