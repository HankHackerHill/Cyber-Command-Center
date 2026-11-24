# Policy admission and settlement

Admission still reads and SHA-256 verifies the active manifest file on every
request, then checks fresh Redis state/time and M2 state. Admission obtains
the bucket, receipt count and Redis `TIME` in one atomic Lua snapshot, saving
one Redis round trip compared with separate snapshot and clock commands.
Bucket arithmetic stays in Python, and each CAS retry takes a new snapshot.
The legacy `_read` and `_now_us` interfaces and injected test clocks remain
available. A missing or modified registry file immediately denies, including
after a cache hit. The bounded
128-entry manifest cache only avoids repeated JSON/Pydantic parsing; original
manifest timestamp strings are retained for OPA's nanosecond comparison.

Each admission attempt, including every CAS retry, first validates the Redis
snapshot and clock, then starts a new M2 state GET while evaluating OPA. Both
results must allow before the reservation CAS. State denial or failure takes
precedence over the policy result, as before. An OPA query may therefore run
during an eventual M2 denial;
it accesses only the configured policy service and cannot authorize egress.
Backwards accounting time and invalid accounting retain their earlier priority.
There is no cached state or cached allow.

After M2 joins an initial OPA allow, admission samples UTC again. It requests a
full fresh OPA evaluation if the clock is naive, moved backwards, crossed a UTC
date, or reached the parsed manifest end minus one microsecond. Subtracting one
microsecond only triggers an extra evaluation; OPA still applies the original
nanosecond timestamp strings, so this introduces no boundary over-denial.
Otherwise the original allow proves the start was reached, forward time is
still before the exact end, and the UTC weekday is unchanged. This proves that
the original window truth still holds without locally granting a window. The
fresh evaluation uses the same accounting snapshot, which the subsequent CAS
must still match; retries repeat the entire procedure.

The app bounds state-check execution to eight workers and eight submitted jobs.
Every return or error drains its own state-check future; no operation is left
running after that request finishes. Authority task failures deny admission,
and lifespan shutdown drains the executor before closing its HTTP clients.
This overlaps independent I/O; it does not make M2 state and Redis reservation
one distributed transaction or strengthen their existing in-flight ordering.

The decision cache contains **only `SCOPE_DENIED`**, keyed by the exact manifest
hash, method, host, IP, path and timestamp. It holds at most 2,048 entries for one
second, under a process-local mutex. A changed manifest hash has a different key;
file revocation or hash mismatch removes that manifest's entries. Cache hits
still read Redis accounting, Redis time, M2 state, and the service clock. Denials
cannot reserve capacity. State errors, dependency errors, window, rate, worker
and breaker decisions are never cached.

There are **no cached allows**. Every allow runs all existing OPA rules against
fresh server UTC time and accounting runtime, including each reservation CAS
retry. This preserves the original window precision and immediately observes
OPA policy reloads on the allow path. The manifest's signed policy hash alone
is not proof of OPA's currently loaded modules. A scope denial may conservatively
outlive a policy reload by up to one second, producing temporary over-denial.
Exact request timestamps reduce denial-cache hits for newly generated traffic;
the optimization primarily saves manifest parsing and repeated denied requests.
It does not claim to remove the OPA round trip for allowed traffic.

## Trusted settlement batching

`POST /settlements` requires `Authorization: Bearer <M4_AUDIT_TOKEN>`. An absent
server token disables the route with 503. The frozen, strict local Pydantic
protocol rejects extra fields, duplicate receipt IDs, invalid UUIDs, non-integer
statuses, and statuses outside 200–599. A batch has 1–256 completions:

```json
{"engagement_id":"engagement-id","completions":[{"reservation_id":"00000000-0000-0000-0000-000000000001","status_code":503}]}
```

A successful response binds the engagement and returns every canonical receipt
with `status: "committed"` or `status: "missing"`. Missing is **not** proof of
completion. HTTP 409 rejects a retry that conflicts with a previously committed
status. HTTP 503 means accounting was not acknowledged and callers retain their
durable delivery record.

`AccountStore.complete_many` snapshots the accounting bucket, requested receipts
and durable completion fingerprints, then compares that exact snapshot in one
atomic Redis Lua CAS. Python performs all integer arithmetic; Lua never rounds
counters through floating point. It consumes each outstanding receipt once,
releases only the corresponding worker slots, increments the cumulative breaker
for **every** final 5xx, and persists receipt/status fingerprints in the same
script. An entire conflicting or invalid batch consumes nothing. Unknown
receipts release nothing. Rate debit and refill timestamp are unchanged.

Matching retries return `committed` from the retained fingerprint, so an HTTP
acknowledgement lost after Redis commit does not cause a second release or
increment. Fingerprints live in `redops:policy:v1:<canonical-engagement>:settled`
without expiry, separately from the outstanding-receipt hash. Both keys must be
backed up, restored and archived together; durable Redis configuration remains
an operational prerequisite. The legacy `complete` interface retains its
existing duplicate-false behavior.

On observing a final 5xx, M4 immediately raises its admission barrier and
records the local consecutive breaker once. It durably captures the final
result before submitting settlement, and blocks initiation of later evaluations
until the shared cumulative count commits. Evaluations already started under
its fair accounting gate retain their original in-flight ordering and worker
reservation. Final 5xx settlement does not wait for successful-response batches;
delivery retries do not increment the local breaker again. Until settlement
commits, worker slots remain held. Batching is not a new cross-replica ordering
guarantee for M4's consecutive breaker.

## Verification

From this directory, run `python -m pytest -q` with `POLICY_TEST_REDIS_URL`
pointing to a disposable Redis database and `OPA_BIN` set to OPA v1; then run
`python -m mypy --strict main.py settlements.py tests`.

From the repository root, run:

```sh
opa test packages/policy-bundles apps/policy-svc/tests/parameterized_assertions.rego --coverage
```

OPA 1.0 does not automatically execute the existing parameterized partial-object
test rules. The local assertion wrappers require every expected leaf to be
true (including exact case counts), so all 110 parameterized cases run
without editing the policy bundle or weakening their cases. Together with the
seven existing scope test groups, this produces 20 passing test groups and
100% executable-line coverage; line coverage is not a formal proof of all
possible policy inputs.
