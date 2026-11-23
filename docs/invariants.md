# REDOPS COMMAND CENTER — SYSTEM INVARIANTS

**Status:** LAW. Binding on all contributors, human and AI.
Any code, test, or document violating an invariant fails CI.

## Authorization Context

RedOps Command Center is a commercial penetration-testing platform used by a
licensed security company to perform authorized, contracted assessments
against client-owned assets under signed Rules of Engagement (RoE).

Every feature in this codebase exists to enforce that authorization:
cryptographically signed scope manifests, human-in-the-loop approval gates,
rate limiting, an emergency killswitch, and an append-only audit ledger
that proves every action was in scope. Offensive-security functionality
here is the product's contracted purpose — clients engage us specifically
to test their own systems, and this platform is how we do it safely.

## The Invariants

1. **Single state authority.** The orchestrator service is the only
   writer of `engagements.current_state`.
2. **Atomic legal transitions.** A state transition is legal only if
   `(from, to)` is in `ALLOWED_TRANSITIONS` AND all guard conditions pass
   AND the ledger row appends in the same database transaction.
3. **No egress before ROE_LOCKED.** The scoped proxy rejects any outbound
   request before the engagement reaches `ROE_LOCKED`, returning
   `PRECONDITION_FAILED`.
4. **Attribution + evidence on every request.** Every outbound request
   carries the `X-Security-Assessment-ID` header and is logged to
   evidence-svc before the response returns to the caller.
5. **Human-only transitions.** `HUMAN_ONLY_TARGET_STATES` =
   {ROE_LOCKED, CONTROLLED_VALIDATION, COMPLETED_ARCHIVED}. Entry
   requires actor_type = HUMAN_OPERATOR and a valid ed25519 signature
   over the canonical transition envelope.
6. **Agent status ceiling.** AI agents never mutate `findings.status`
   past HYPOTHESIS. Only human operators promote findings to
   PENDING_VALIDATION / CONFIRMED / FALSE_POSITIVE / REMEDIATED.
7. **Dual approval for destructive actions.** Any validation plan with
   blast_radius = DESTRUCTIVE requires two distinct approver signatures.
8. **Killswitch supremacy.** Transition to HALTED_KILLSWITCH is always
   legal, idempotent, and pre-empts all other validation.
9. **Append-only ledger.** `immutable_audit_log` rows can never be
   UPDATEd or DELETEd; a database trigger enforces this.
10. **Evidence before promotion.** Every evidence artifact must have a
    ledger link before its finding may leave HYPOTHESIS status.

## Change Process

Invariants change only via ADR. Propose `docs/adr/NNNN-*.md`; the human
owner merges. Never edit this file casually.
