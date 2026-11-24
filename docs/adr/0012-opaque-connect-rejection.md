# ADR-0012 — Require per-request visibility for CONNECT

**Status: Accepted.** ADR-0013 extends the ledger contract for rejection events.

## Decision

Plain HTTP explicit proxy requests use absolute-form request targets. Every
allowed origin request must pass the engagement-state and policy checks, carry
the canonical `X-Security-Assessment-ID`, and produce a request/response
evidence artifact before the response returns. The proxy must settle the M3
reservation using the final origin status.

HTTPS requires TLS inspection under the engagement's own workspace CA. Both
legs of the connection belong to the same verified engagement. The origin
connection requires normal certificate and name verification. Each decrypted
HTTP request is subject to the same admission, attribution, evidence and
accounting requirements as plain HTTP. Test clients trust only a generated
test CA for their engagement.

Reject opaque CONNECT with reason `OPAQUE_TUNNEL_NOT_ALLOWED`. An opaque
tunnel hides the origin requests and responses needed for invariant 4 and
the 5xx breaker. A successful CONNECT handshake is never an origin response
for accounting.

### Wire behavior

For an opaque-tunnel rejection made before the CONNECT response, return
HTTP 403 with reason `OPAQUE_TUNNEL_NOT_ALLOWED`. State and killswitch
checks still pre-empt the tunnel decision.

Standard clients wait for a successful CONNECT response before sending a
TLS ClientHello. After 200, peek at the first bytes with a short, bounded
timeout. The TLS handshake record prefix (`16 03` in hex) identifies a
candidate ClientHello for the inspection path. The TLS handshake must
validate it before any origin connection can be admitted.

If the bytes cannot be inspected, flush and cleanly close the tunnel with
a FIN. Record `OPAQUE_TUNNEL_NOT_ALLOWED` in both the evidence artifact and
the audit log, with up to the first 16 received bytes encoded as hex. Use
the same reason for pre-200 rejections. If no bytes arrive before the
deadline, close and record `TUNNEL_IDLE_TIMEOUT` with an empty prefix. Do
not send a second HTTP status line on an established tunnel.

ADR-0013 specifies the durable audit route. A rejection event binds the
engagement and diagnostic ID to its reason, prefix, and evidence digest.
An acknowledgement from the evidence service alone does not confirm a
ledger append.

See [RFC 9110 §9.3.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6).

## Redis completion accounting

M3 returns a UUID in `X-Policy-Reservation` on an allowed evaluation.
Its trusted observer consumes the receipt directly in the Redis hash
`redops:policy:v1:<canonical-engagement-id>`. This is the mechanism
implemented by `AccountStore.complete` in `apps/policy-svc/main.py`.
M3 defines no completion Pub/Sub channel, subscriber, or message envelope.
The separate `redops:killswitch` channel carries stop notifications.

The observer accepts only a final origin status from 200 through 599. In one
compare-and-swap, it verifies the outstanding receipt, deletes it, decrements
`active_workers`, and increments cumulative `errors_5xx` for a 5xx response.
The rate debit remains in force. Elapsed time replenishes rate credit. A
missing receipt or ambiguous write acknowledgement does not prove a fresh
completion. A missing final origin status leaves the receipt outstanding
for reconciliation. A CONNECT handshake cannot settle it.

M4 also tracks consecutive confirmed final statuses per engagement in its
own process. An intervening non-5xx resets this streak. Reaching the
threshold latches denial and invokes the orchestrator's durable killswitch.
The M3 counter is cumulative across observers. Multiple proxy replicas
would require shared ordering for an engagement-wide consecutive streak.

## Checkpoint behavior

The checkpoint returned `503 POLICY_COMPLETION_UNAVAILABLE` from the
listener after the state check and before calling M3. That branch never
acquired a reservation. An eligible request on a listener without an origin
transport receives `501 FORWARDING_UNAVAILABLE` before admission.
