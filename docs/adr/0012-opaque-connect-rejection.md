# ADR-0012 — Require per-request visibility for CONNECT

**Status.** Owner decision for M4. The M3 completion service contract below is
a proposal. M2 and M3 remain frozen for this milestone.

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

The branch exposes ledger reads and state-transition writes. It has no M4
append operation for a rejected tunnel. A successful evidence PUT alone
cannot verify both records. The frozen `LedgerRecord` also requires a
`TransitionEvent` payload. A tunnel rejection does not change engagement
state. The proposed ledger extension is a distinct rejection event with an
engagement ID, reason, captured prefix, and evidence digest, appended idempotently by the
ledger owner. The running M4 listener denies CONNECT before 200 while
inspection and durable rejection recording are unavailable.

See [RFC 9110 §9.3.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6).

## Proposed M3 completion service contract

M3 currently issues a reservation on `POST /evaluate`. Its trusted Python
observer calls `AccountStore.complete`. Rust M4 needs a service interface.
This proposal reserves the following interface for the M3 owner.

| Field | Proposed contract |
| --- | --- |
| Operation | `POST /engagements/{id}/completions` on the configured policy service origin |
| Caller | Authenticated M4 service identity |
| Correlation | Exactly one `X-Policy-Reservation` request header containing the UUID issued by M3 |
| JSON request | Exactly one of `{"status_code":503}` for a final origin status in the range 200–599 or `{"outcome":"no_origin_response"}` when no final status was observed |
| JSON success | HTTP 200 with `{"breaker_tripped":false}` or `{"breaker_tripped":true}` |
| Errors | 404 for an unknown or wrong-engagement receipt, 409 for conflicting replay, 422 for invalid input, 503 for unavailable accounting |

M3 must bind the receipt to its engagement and admitting manifest. A first
completion releases one worker and records the outcome atomically. For a
connection failure without a final origin response, release the worker and
preserve the count of consecutive observed 5xx responses. In both cases
the original rate debit stands. Replaying the same receipt and outcome
returns the recorded result. A stop prevents new reservations while
permitting settlement of outstanding work. M4 uses the result to request
the durable halt through M2, which publishes the Redis notification after
commit.

The requested breaker counts consecutive origin 5xx responses in engagement-wide
completion order and resets the streak on another final status. M3 currently
enforces a cumulative counter. For example, at threshold two the current
policy denies after 503, 429, 500. The requested streak at that point is one.
The existing cumulative cap continues to apply to admission. The proposed
consecutive count controls publication of the killswitch. Process-local M4
streaks cannot supply cross-replica ordering. M3 implementation and a real
reservation-release test are prerequisites for enabling target egress.
