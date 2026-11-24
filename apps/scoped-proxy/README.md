# Scoped proxy origin transport

Run the proxy on the trusted service network. Its operator-provisioned inputs are
`ORCHESTRATOR_URL`, `POLICY_URL`, `EVIDENCE_URL`, `REDIS_URL`, `M4_AUDIT_TOKEN`,
and `SCOPED_PROXY_WORKSPACE_DIR`. `SCOPED_PROXY_LISTEN` defaults to
`127.0.0.1:8080`. Admission stays closed until the Redis killswitch subscription
is acknowledged. Each plaintext request and CONNECT supplies exactly one
`X-Security-Assessment-ID`. Decrypted requests inherit the CONNECT engagement;
conflicting or duplicate inner IDs are rejected.

Provision a directory named with the canonical engagement UUID under
`SCOPED_PROXY_WORKSPACE_DIR`:

- `manifest.json`: the exact approved RoE bytes provisioned to M3.
- `manifest.sha256`: the lowercase SHA-256 of those bytes. M3's trusted manifest
  registry must contain the same bytes as `<digest>.json`.
- `ca.pem` and `ca-key.pem`: that engagement's workspace CA certificate and
  matching private key, for CONNECT inspection. Provision a currently valid CA
  authorized to sign certificates; protect its private key with operator-only
  filesystem permissions. Assessment clients trust their engagement's CA.
- Optional `origin-ca.pem`: additional origin trust anchors for that engagement,
  including a disposable fixture CA. `SCOPED_PROXY_ORIGIN_CA_FILE` can provision
  additional operator-controlled trust anchors across engagements. Public roots
  remain available; origin certificate and hostname verification are required.

The registry owner verifies RoE authorization before provisioning, following
M3's existing registry contract. Provision M3 accounting once through
`AccountStore.initialize`. The proxy loads manifests and origin roots at startup;
restart it after changing those files. M3 still checks its current registry and
engagement state on every admission. A missing or invalid workspace fails closed.

Plain HTTP uses absolute-form request targets. CONNECT requires an explicit
host and port; decrypted requests stay bound to that authority and engagement.
Each origin connection uses the exact IP evaluated by M3. Automatic redirects,
retries, and HTTP upgrades are disabled. Request and response bodies are bounded
to 1 MiB each; oversized or incomplete exchanges produce an error instead of an
unchecked response. Existing opaque-tunnel classification and closure rules
remain in `src/tls.rs`.

In synchronous compatibility mode, before returning an origin response the proxy uploads its forwarded request
and response metadata and exact entity-body bytes as a JSON artifact with
hexadecimal bodies, then obtains an M2 audit receipt binding the artifact's
SHA-256. This captures the forwarded request and observed origin response,
rather than original wire framing; response headers are recorded before
outbound hop-header filtering. `headers_hex` preserves every captured header-value
octet alongside the readable header representation. `PROXY_REQUEST_COMPLETED` records
the observed final status. `PROXY_REQUEST_INCOMPLETE` records an attempt without
a confirmed final status. Confirmed statuses settle the actual M3 reservation
and feed the consecutive-error breaker. Attempts without a final status retain
their receipt for operator reconciliation; a proxy-generated error does not
count as an origin completion. The reservation remains held through bounded
response capture and durable evidence processing. Client disconnects do not
cancel finalization.
Killswitch notifications cancel origin work and upgraded TLS sessions. A local
stop latch requires restarting the proxy after an authorized manual M2 reset.

Within one proxy process, a shared per-engagement mutex serializes policy
evaluation and Redis completion as separate metadata operations. This avoids
self-induced contention with M3's snapshot compare-and-swap while origin and
evidence work remain concurrent. Admission waits are bounded and preempted by
the killswitch; confirmed completions continue after a stop. Other replicas
and trusted accounting callers still use M3's existing fail-closed CAS rules.

## Durable asynchronous delivery

ADR-0017 enables this mode with `SCOPED_PROXY_OUTBOX_DIR` on persistent local
storage. The proxy owns that private directory exclusively. Before opening an
origin socket it fsyncs a request intent; before returning an origin response it
atomically writes and fsyncs the finalized exchange. This is durable local
acceptance for delivery, not a claim that M7 or PostgreSQL has already committed
the artifact or audit row. It does not wait for remote evidence persistence.
M7 delivery and M2's authenticated, idempotent asynchronous audit acceptance run
in the background, with stable event IDs and artifact digests across retries.
Promotion still waits for actual evidence and ledger linkage.

Startup validates existing records and replays delivery without repeating any
target request. An unfinished intent becomes incomplete evidence; its reservation
is retained and the engagement stays blocked for operator reconciliation.
Confirmed but unsettled recovered records also block that engagement until M3
confirms settlement. Keep these records during recovery and outages. The file
system must honor fsync and atomic rename; power-loss behavior was not simulated
by the process-restart tests.

`SCOPED_PROXY_OUTBOX_MAX_BYTES` defaults to 256 MiB and
`SCOPED_PROXY_OUTBOX_MAX_RECORDS` to 128. Capacity reserves twice the 8 MiB maximum
record size for atomic replacement, so the default effective limit is 16 records.
Full capacity denies before policy reservation or target egress. Local final-write
failure withholds the origin response and denies new admission while retaining
the captured result for retry. After repairing storage, restart only after
retained records have been verified; the local unhealthy latch does not silently
resume admission.

Successful final statuses are batched through M3's authenticated settlement API;
workers are released only on confirmed, idempotent commit. A newly observed 5xx
immediately blocks later evaluations until its shared cumulative count commits.
Evaluations that already started under the fair accounting gate may finish with
their existing reservation; this preserves the original in-flight ordering and
worker cap. The local consecutive breaker remains prompt and independent of
delivery retries. This is not a new cross-replica ordering guarantee.

Enable `ORCHESTRATOR_AUDIT_OUTBOX` in M2 and the same trusted M4 observer credential
in M3. Both delivery queues must use persistent storage; M2's participating
processes share one outbox domain. Legacy synchronous mode remains available
when the M4 outbox variable is unset.

## Verification

From this directory:

```sh
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
```

The standalone MS1 capstone uses a disposable schema-initialized PostgreSQL,
Redis, and OPA v1 loaded with `packages/policy-bundles`. Its Python environment
needs the existing orchestrator, policy, evidence, and contracts dependencies.
It starts real services, provisions generated test-only keys, exercises signed
progression and both forwarding protocols against loopback origins, checks
denials without origin traffic, retrieves evidence, verifies the durable ledger
chain, and checks reservation settlement. Run from the repository root:

```sh
python apps/scoped-proxy/tests/ms1_capstone.py \
  --proxy-binary "$CARGO_TARGET_DIR/release/scoped-proxy" \
  --database-url "$ORCHESTRATOR_TEST_DATABASE_URL" \
  --redis-url "$ORCHESTRATOR_TEST_REDIS_URL" \
  --opa-url "$OPA_URL" --work-dir work/ms1 --benchmark
```

`--benchmark` runs `cargo test --release --test load -- --ignored --nocapture`
against that provisioned asynchronous stack. HTTP and intercepted HTTPS each
use four workers, 64 warm-up requests and three measured runs of 1,000 requests.
It reports all four absolute end-to-end p99s and all four proxy-internal p99s
per protocol. The median measured end-to-end p99 must be below 50 ms, and every
measured internal p99 must be below 15 ms. Trusted timing samples are matched to
unique origin proofs; post-run checks drain delivery and verify every artifact
and ledger entry.

The optional, private `SCOPED_PROXY_TIMING_PATH` is benchmark instrumentation,
not a caller-supplied response header. Internal timing includes proxy processing
and local durable acceptance, subtracts suspended external-service and origin
waits, and adds back their active polling work. CONNECT preparation and TLS
processing are charged to the first decrypted request on a connection. It is
the durable request-handler phase, not whole-process CPU time or the full
governed-path duration. Hyper codec/connection-driver work outside handler
invocation and independent background delivery are outside this internal
boundary; the absolute client-to-full-body gate includes their latency effects.
These internal measurements apply to the asynchronous benchmark configuration,
not the legacy synchronous compatibility path.
Logs, synthetic keys, artifacts, and `result.json` remain in a fresh run directory;
service processes are stopped on exit. No live client system is contacted.

For a separate diagnostic run, use `--profile --profile-count 64` instead of
`--benchmark`. It sends governed requests with four workers and verifies the
resulting ledger and accounting. `SCOPED_PROXY_TRACE_TIMING=1` enables bounded
phase-duration logs without request identifiers, headers or bodies; the harness
sets it only for this diagnostic mode. Profiles do not replace the acceptance
benchmark or its latency gate.
