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

Before returning an origin response, the proxy uploads its forwarded request
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
against that provisioned stack. It reports the warm-up p99 and all three
measured p99 overheads from paired direct/proxied loopback requests. Only the
median of the three measured runs is compared with the strict 15 ms gate.
Logs, synthetic keys, artifacts, and `result.json` remain in a fresh run directory;
service processes are stopped on exit. No live client system is contacted.

For a separate diagnostic run, use `--profile --profile-count 64` instead of
`--benchmark`. It sends governed requests with four workers and verifies the
resulting ledger and accounting. `SCOPED_PROXY_TRACE_TIMING=1` enables bounded
phase-duration logs without request identifiers, headers or bodies; the harness
sets it only for this diagnostic mode. Profiles do not replace the acceptance
benchmark or its latency gate.
