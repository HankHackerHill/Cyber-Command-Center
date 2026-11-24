# ADR-0014 — Deferred forwarding paths

**Status:** Resolved. Signed progression, HTTP and intercepted HTTPS forwarding,
attribution, durable asynchronous evidence/audit delivery, completion accounting,
pre-ROE 412, excluded-path 403, and the hash chain pass the MS1 capstone under
load. Both protocol latency gates clarified by ADR-0017 pass.

**Final resolving implementation commit:** `b5382123852f13af316702624cb4641873b9ab9c`.
**Historical functional resolving commit:** `e7bca0099a161756958abad095198d6ea7cf2802`.
The human owner directed the functional checkpoint and each subsequent green
checkpoint to be pushed before continuing. Final verification is recorded below;
MS1 sign-off remains with the human owner.

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

## Historical functional checkpoint evidence

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
pushed before that work began. The completed follow-up and all four p99s for
each protocol are recorded below. Human MS1 sign-off has not been assumed.

## Final ADR-0017 implementation

M4 durably accepts an intent before origin egress and the finalized exchange
before returning an origin response. Eight independent workers deliver stable
artifact digests and event IDs to M7 and M2 without delaying that response for
remote persistence. Full storage denies before reservation or egress; failed
final writes withhold the response and retain the result. Recovery never repeats
target traffic. An incomplete attempt retains its receipt for reconciliation.
Local acceptance uses fsync and atomic rename; it does not assert that M7 or
PostgreSQL has already committed when the caller receives its response.
Promotion still requires the existing actual evidence/ledger verification gate.

M2's opt-in non-transition outbox returns 202 acceptance after SQLite WAL/FULL
commit. Its delivery worker marks a queue job complete only after PostgreSQL
commit through the existing idempotent ledger writer. Lost worker
acknowledgments replay the same event exactly once. Its persistent WAL anchor
avoids last-connection checkpoint churn. Audit work has four PostgreSQL
connections, at most eight waiters and a 250 ms acquisition timeout; overload
returns 503 while the caller retains its job. A 40-request saturation regression
proves state and killswitch progress with audit capacity held. State transitions,
their signatures, guards, row locks and atomic ledger appends remain unchanged.

M3 caches validated manifests and exact-key scope denials conservatively; it
does not cache allows or engagement state. Every allowed admission reads and hashes the
current registry bytes and obtains fresh accounting, M2 state and full OPA
evaluation. Snapshot and Redis time are read atomically. Fresh M2 state and OPA
work overlap after clock validation, with eight bounded, fully drained jobs.
No reservation commits before both allow. Every CAS retry renews both checks.
After joining M2, uncertain time progression, UTC-date changes and the window-end
boundary trigger full fresh OPA evaluation using the original nanosecond strings.
The local check only triggers evaluation; OPA retains boundary authority.

Settlement batches atomically consume receipts, release workers, count every
actual 5xx once, and retain durable status fingerprints. M4 observes its local
breaker immediately and blocks later evaluations on pending 5xx until M3 commit
is confirmed. Confirmed settlement is remembered in memory without rewriting
evidence files. A restart conservatively re-proves the same receipt/status before
admission or deletion; tests cover committed-but-unacknowledged recovery without
origin replay or duplicate counting. Deletion still requires durable M7 storage,
authenticated M2 durable handoff, settlement proof and directory fsync.

The asynchronous configuration requires persistent M4 storage, persistent Redis
accounting and a shared persistent M2 outbox domain. Legacy synchronous behavior
remains available. POSIX fsync/rename semantics are an operational prerequisite;
process restart was tested, physical power loss was not simulated. Deployment
details and recovery procedures are in the three service READMEs.

## Final commands and results

All commands used the unchanged synthetic fixture, disposable PostgreSQL 17,
Redis 7, OPA 1.0.0, Python 3.12.14 and Rust/Cargo 1.100.0. No live client traffic.
Load the task's toolchain and disposable service URLs:

```sh
source /workspace/work/adr0017/test.env
```

From `apps/scoped-proxy`, all four returned exit 0 on the final source:

```sh
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
```

`cargo test`: **64 passed, 1 ignored**. The provisioned load test was subsequently
run explicitly by the capstone. Its nearest-rank percentile test is included in
the default suite. From the repository root, all commands below returned exit 0:

```sh
/workspace/work/adr0011/venv/bin/python -m pytest -p no:cacheprovider -q --capture=tee-sys apps/orchestrator
/workspace/work/adr0011/venv/bin/python -m pytest -p no:cacheprovider -q packages/contracts-py
/workspace/work/adr0011/venv/bin/python -m pytest -p no:cacheprovider -q apps/policy-svc
/workspace/work/adr0011/venv/bin/python -m mypy --strict --config-file apps/orchestrator/pyproject.toml --cache-dir /workspace/work/adr0017/mypy-orchestrator apps/orchestrator
/workspace/work/adr0011/venv/bin/python -m mypy --strict --config-file apps/policy-svc/pyproject.toml --cache-dir /workspace/work/adr0017/mypy-policy apps/policy-svc
"$OPA_BIN" test packages/policy-bundles apps/policy-svc/tests/parameterized_assertions.rego --coverage > /workspace/work/adr0017/final-rego-coverage.json
```

Results: **84 orchestrator tests**, including contract/database parity, illegal
transitions, signed graph progression, competing transitions, and append-only
ledger tests; **72 contracts tests**; **77 policy tests**. Strict mypy: clean in
13 M2 files and 4 M3 files. The existing stop benchmark recorded warm-up p99
12.88 ms and measured p99s 12.90, 9.84 and 14.34 ms, median **12.90 ms**.
The only Python warnings are the upstream Starlette/httpx deprecation warning.
The explicit Rego assertion wrapper executes the existing parameterized cases
under OPA 1.0; coverage is **221 executable lines, zero uncovered, 100%**.
Policy bundle sources were not modified.

The final capstone command returned exit 0:

```sh
/workspace/work/adr0011/venv/bin/python apps/scoped-proxy/tests/ms1_capstone.py --proxy-binary "$CARGO_TARGET_DIR/release/scoped-proxy" --database-url "$ORCHESTRATOR_TEST_DATABASE_URL" --redis-url "$ORCHESTRATOR_TEST_REDIS_URL" --opa-url "$OPA_URL" --work-dir /workspace/work/adr0017/ms1-performance-overlap --benchmark
```

It invokes `cargo test --release --test load -- --ignored --nocapture` against
real M2/M3/M4/M7 services. Each protocol separately uses four closed-loop workers,
64 warm-up requests and three measured runs of 1,000 requests. End-to-end timing
is absolute client-send through full response body, without subtracting a direct
origin baseline. All values below are milliseconds.

| Phase | HTTP end-to-end p99 | HTTP internal p99 | HTTPS end-to-end p99 | HTTPS internal p99 |
| --- | ---: | ---: | ---: | ---: |
| Warm-up (excluded from gate) | 36.470785 | 6.556927 | 38.918449 | 10.463291 |
| Measured 1 | 42.274076 | 10.773203 | 42.135594 | 8.720987 |
| Measured 2 | 50.932994 | 6.367162 | 45.964014 | 9.423833 |
| Measured 3 | 42.876214 | 6.324406 | 45.970415 | 11.284686 |

HTTP median measured end-to-end p99: **42.876214 ms**, passing `<50 ms`.
HTTPS median: **45.964014 ms**, passing `<50 ms`. Every measured internal p99
passes `<15 ms`; maxima are **10.773203 ms** and **11.284686 ms**, respectively.
The HTTP second run exceeds 50 ms; the agreed end-to-end gate is the median of
the three measured p99s. Internal timing covers the durable request handler,
including local persistence and active polling work while excluding suspended
external waits. CONNECT setup is charged to the first decrypted request.
Hyper connection/codec work outside the handler and background delivery are
outside that internal boundary; their effects remain in the end-to-end timings.
This is the documented asynchronous configuration, not a whole-process CPU metric.

The combined capstone verified signed progression to CONTROLLED_VALIDATION,
tampered-signature rejection, HTTP and intercepted HTTPS attribution and exact
binary evidence, pre-ROE 412 and excluded-path 403 without egress. It then
verified every one of the **6,128 benchmark requests** against its unique fixture
proof, artifact digest, event ID and reservation. All **6,137 ledger rows** had a
valid hash-chain continuation; M7 artifacts were retrieved, receipts settled,
and both delivery queues drained. Final ledger tail:
`2bd02cd026a46f439ea70fc1c975b56b1a0ab57852b5081ab733849f1ce6de3c`.

Result, benchmark log, timing samples and artifact proofs remain under
`/workspace/work/adr0017/ms1-performance-overlap/run-e7655603-9011-4d42-bfac-9218542059de/`.
The fixture explicitly provisions a bounded 256-record, 4 GiB outbox budget;
it changes neither service defaults nor the signed worker cap.

Technical, adversarial and acceptance reviews covered persistence boundaries,
crash recovery, concurrent settlement, 5xx barriers, pool saturation and UTC
join freshness. Findings were corrected and regression-tested before the final
run. Frozen MS0 contracts/schema, transition writer/guards, opaque CONNECT
classification/prefix/timeout tests and policy bundle sources are unchanged by
ADR-0017. CI workflows remain deferred. ADR-0014 is technically resolved; human
MS1 sign-off remains separate.

## Investigation measurements retained

Earlier source iterations failed the clarified gates and were not accepted as
performance resolution. Each tuple below is warm-up, measured 1, measured 2,
measured 3, in milliseconds. These are distinct implementation checkpoints, not
repeated trials selected from the final source.

| Iteration / run prefix | Protocol | End-to-end p99 tuple | Internal p99 tuple |
| --- | --- | --- | --- |
| Initial async / `3229eddb` | HTTP | 68.367844, 61.847635, 72.697582, 57.430731 | 8.886590, 8.425714, 9.784329, 10.556570 |
| Initial async / `3229eddb` | HTTPS | 60.554956, 59.571079, 59.883488, 60.543314 | 9.718772, 9.708593, 17.904735, 10.691458 |
| Independent workers / `b812718b` | HTTP | 142.778096, 88.303751, 68.669627, 54.004534 | 16.527576, 8.551554, 9.662780, 11.051764 |
| Independent workers / `b812718b` | HTTPS | 49.852884, 58.278863, 45.575511, 46.071393 | 11.726934, 12.291141, 11.554283, 13.495407 |
| WAL anchor / `08baafc8` | HTTP | 46.359255, 209.747165, 183.855972, 191.939962 | 7.935153, 171.841833, 157.784920, 173.866331 |
| WAL anchor / `08baafc8` | HTTPS | 48.912794, 136.960669, 386.142321, 290.570340 | 10.943273, 117.218360, 364.639896, 265.214665 |
| Settlement proof / `46dfcc6e` | HTTP | 73.372370, 77.388840, 62.566533, 49.985181 | 21.864199, 20.189277, 7.342768, 7.677474 |
| Settlement proof / `46dfcc6e` | HTTPS | 46.119777, 69.534040, 48.855897, 44.944778 | 8.440686, 9.338602, 8.165814, 7.383690 |

The last three failed performance runs nevertheless completed the post-run
6,137-row and exact-artifact proof. The initial async harness stopped on the
latency assertion before that complete post-run proof. An earlier capacity
calibration stopped during warm-up with a fail-closed full-outbox 503 and has
no valid four-run latency result. These records are retained under the task's
`ms1-performance`, `ms1-performance-wal` and `ms1-performance-confirmed`
directories alongside the final passing run.

## Changed files

This request's functional checkpoint plus ADR-0017 follow-up changed only:

| Directory | Files |
| --- | --- |
| `apps/orchestrator/` | `README.md`, `audit_delivery.py`, `main.py`, `pyproject.toml`, `tests/test_audit_delivery.py` |
| `apps/policy-svc/` | `README.md`, `main.py`, `pyproject.toml`, `settlements.py`, `tests/parameterized_assertions.rego`, `tests/test_cache_settlements.py` |
| `apps/scoped-proxy/` | `Cargo.lock`, `Cargo.toml`, `README.md`, `src/breaker.rs`, `src/delivery.rs`, `src/inspection.rs`, `src/main.rs`, `src/policy_client.rs`, `src/transport.rs`, `tests/delivery.rs`, `tests/forwarding.rs`, `tests/gateway.rs`, `tests/load.rs`, `tests/ms1_capstone.py`, `tests/support/delivery.rs` |
| `docs/adr/` | `0014-deferred-forwarding-paths.md`, `0017-performance-scope-governed-path-latency.md` |
