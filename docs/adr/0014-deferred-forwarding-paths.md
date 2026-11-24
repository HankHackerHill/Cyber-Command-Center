# ADR-0014 — Deferred forwarding paths

**Status:** Functionally resolved — signed progression, HTTP and intercepted HTTPS forwarding, attribution, evidence, pre-ROE 412, excluded-path 403, hash-chain verified under load. Latency gate re-scoped per ADR-0017; performance work pending.

**Functional resolving commit:** `e7bca0099a161756958abad095198d6ea7cf2802`.
The human owner directed this green functional checkpoint to be committed and
pushed. Full performance resolution follows ADR-0017; MS1 sign-off remains with
the human owner.

At commit `5e6a92ba2aa4c5c3d204ffdccbdf0858b2280084`, the M4 listener
returns HTTP 501 with `{"reason":"FORWARDING_UNAVAILABLE"}` for an otherwise
eligible plain HTTP request. It fails closed before reserving a policy worker
or opening an origin connection. CONNECT remains subject to its separate
rejection rules. [ADR-0012 documents the listener API.](0012-opaque-connect-rejection.md)

**Original deferred scope.** The origin transport for allowed traffic was
unimplemented. This included successful plain HTTP forwarding and TLS
interception for HTTPS under ADR-0012.

**Original resolution requirement (latency definition superseded by ADR-0017).** Before MS1 integration sign-off, demonstrate a
signed engagement reaching `CONTROLLED_VALIDATION` and successfully forwarding
a request through the governed proxy. At that resolution, run the forwarding
benchmark after warm-up. The median of the three measured p99 overheads must
be below 15 ms. Resolve the debt in a fresh session or through a lane-exception
ADR.

**Historical rationale.** The human owner accepted the verified governance controls,
completion accounting, and durable audit append and directed the build to
continue. The origin transport was the remaining M4 work at that checkpoint.

## Implementation and verification evidence

The functional checkpoint transport resolves one destination IP, evaluates that IP with
M3, injects canonical attribution, uses an owned HTTP/1 connection or verified
origin TLS connection, captures bounded request/response evidence, confirms the
M2 evidence audit, and settles the actual reservation through the existing Redis
mechanism. CONNECT uses the per-engagement CA and binds the inner request to its
engagement and authority. Existing opaque classification, closure, timeout and
16-byte-prefix code and tests remain unchanged. Failed attempts without a final
origin status retain their receipt and record incomplete evidence. Killswitch
notifications cancel origin sockets and upgraded sessions; independent
finalization survives caller disconnects. Header-value octets are preserved in
hexadecimal alongside readable metadata.

The first real-stack benchmark stopped in warm-up with M3 `ACCOUNTING_BUSY`;
the durable denial event confirmed exhaustion of M3's existing CAS retries.
Replica-local serialization of policy evaluation and completion as separate
metadata phases removed that self-induced contention without retries or policy
bypasses. Body capture and evidence remain concurrent, and reservations remain
held until origin work and evidence processing finish. Socket TCP_NODELAY and
bounded phase profiling were added while investigating latency. Neither the
benchmark protocol nor its threshold was weakened.

Checks used Rust/Cargo 1.100.0, Python 3.12.14, disposable PostgreSQL 17, Redis 7,
OPA 1.0.0 and the existing service APIs. All traffic was synthetic loopback work.
The environment was loaded with `source /workspace/work/adr0014/test.env`.
From `apps/scoped-proxy`:

```sh
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
```

All four commands passed on the final code. `cargo test` passed **46 tests**;
the explicitly provisioned load test is the single ignored test in that default
run and was subsequently invoked separately. From the repository root:

```sh
/workspace/work/adr0011/venv/bin/python -m pytest -p no:cacheprovider -q --capture=tee-sys apps/orchestrator
/workspace/work/adr0011/venv/bin/python -m pytest -p no:cacheprovider -q packages/contracts-py
read -r M4_FINAL_DATABASE < /workspace/work/adr0014/final-database.txt
/workspace/work/adr0011/venv/bin/python apps/scoped-proxy/tests/ms1_capstone.py --proxy-binary "$CARGO_TARGET_DIR/release/scoped-proxy" --database-url "$M4_FINAL_DATABASE" --redis-url "$ORCHESTRATOR_TEST_REDIS_URL" --opa-url "$OPA_URL" --work-dir /workspace/work/adr0014/ms1-final --benchmark
```

The orchestrator suite passed **70 tests** with its unchanged killswitch median
p99 at **15.95 ms**. The contracts suite passed **72 tests**. One upstream
Starlette/httpx deprecation warning remains in the Python service tests.

The capstone's functional assertions passed against the release binary and a
fresh database containing only the unchanged MS0 schema. It verified five signed
transitions through CONTROLLED_VALIDATION, HTTP and inspected HTTPS round-trips,
canonical attribution, exact binary request/response evidence, M7 retrieval,
pre-ROE HTTP 412 and excluded-path HTTP 403 with no origin hits, and a nine-row
durable hash chain. The benchmark then invoked:

```sh
cargo test --release --test load -- --ignored --nocapture
```

Four closed-loop workers, 64 warm-up pairs and three runs of 1,000 paired samples
produced these exact overhead measurements:

| Run | p99 overhead (ms) |
| --- | ---: |
| Warm-up (excluded from gate) | 58.433591 |
| Measured 1 | 77.354264 |
| Measured 2 | 116.827454 |
| Measured 3 | 62.911920 |
| Median of measured runs | **77.354264** |

The load test and combined capstone-plus-benchmark command returned **exit 1**
because the strict `<15 ms` gate failed. Every benchmark request nevertheless
completed its functional assertions. A subsequent read-only check verified all
**3,073** ledger rows and their full hash chain: five transitions, 3,066 completed
request audits, and two policy denials, with **zero outstanding reservations**.

The final run's logs and result are retained under
`/workspace/work/adr0014/ms1-final/run-495dfef9-79dd-4df9-8898-bf913754d1b8/`.
A separate four-worker, 64-request diagnostic's bounded phase samples recorded
roughly 0.65 ms median origin transport, versus 6.6 ms policy evaluation, 3.0 ms
evidence persistence, 5.6 ms audit append, 1.6 ms settlement, 5.6 ms admission-lock
wait and 7.9 ms settlement-lock wait. The trace limit includes functional setup
requests and produced 59 complete phase samples.
These constituent medians identify optimization targets; their sum is not a
formal percentile bound. The precise cause of all full-run tail spikes remains
unverified. A post-run M2 idempotency-query EXPLAIN took 1.562 ms on the earlier
3,073-row engagement, which alone does not explain the larger tail measurements.

## Gate clarification and authorized performance follow-up

Technical and adversarial reviews found no remaining functional/security
blocker in the tested transport scope. The historical end-to-end measurements
above were compared to the original proxy-overhead threshold. The human owner
has clarified that gate in ADR-0017: proxy-internal processing p99 must remain
below 15 ms, and the median of the three measured end-to-end governed-path p99s
must be below 50 ms, separately for plain HTTP and intercepted HTTPS.
Frozen contracts/schema, other services, existing governance modules and CI
workflows were not modified by the functional checkpoint. CI remains deferred.

ADR-0017 authorizes narrow performance work in M2 non-transition audit delivery
and M3 policy caching/accounting settlement, preserving all guards, signatures,
invariants and frozen paths. The human owner additionally authorized durable
asynchronous M4 evidence delivery, with promotion still blocked until its
durable evidence link exists. The functional checkpoint is green and is being
pushed before that work begins. New measurements will report all four p99s for
each protocol and the proxy-internal p99; performance work remains pending.
Human MS1 sign-off has not been requested or assumed.
