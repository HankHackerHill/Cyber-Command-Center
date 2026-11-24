# ADR-0014 — Deferred forwarding paths

**Status: Accepted (tracked debt).** M4 is closed as partial with tracked debt.

At commit `5e6a92ba2aa4c5c3d204ffdccbdf0858b2280084`, the M4 listener
returns HTTP 501 with `{"reason":"FORWARDING_UNAVAILABLE"}` for an otherwise
eligible plain HTTP request. It fails closed before reserving a policy worker
or opening an origin connection. CONNECT remains subject to its separate
rejection rules. [ADR-0012 documents the listener API.](0012-opaque-connect-rejection.md)

**Deferred scope.** The origin transport for allowed traffic remains
unimplemented. This includes successful plain HTTP forwarding and TLS
interception for HTTPS under ADR-0012.

**Resolution requirement.** Before MS1 integration sign-off, demonstrate a
signed engagement reaching `CONTROLLED_VALIDATION` and successfully forwarding
a request through the governed proxy. At that resolution, run the forwarding
benchmark after warm-up. The median of the three measured p99 overheads must
be below 15 ms. Resolve the debt in a fresh session or through a lane-exception
ADR.

**Rationale.** The human owner accepted the verified governance controls,
completion accounting, and durable audit append and directed the build to
continue. The origin transport is the remaining M4 work.
