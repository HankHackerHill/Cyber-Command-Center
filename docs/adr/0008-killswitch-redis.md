# ADR-0008: Killswitch via Redis Pub/Sub + Proxy Deny-All
**Status:** Accepted — Global stop publishes on a Redis channel; proxy
flips to deny-all within 100ms. Transition is always legal and idempotent.
