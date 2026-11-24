# Policy admission and settlement

Admission still reads and SHA-256 verifies the active manifest file on every
request, then checks fresh Redis state/time and M2 state. A missing or modified
registry file immediately denies, including after a cache hit. The bounded
128-entry manifest cache only avoids repeated JSON/Pydantic parsing; original
manifest timestamp strings are retained for OPA's nanosecond comparison.

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

M4 must submit final 5xx statuses immediately and block initiation of later
evaluations until their shared count commits; evaluations already started under
its fair accounting gate retain their original in-flight ordering and worker
reservation. It must not defer 5xx counting with successful-response batches. Its local consecutive
breaker records each actual origin result once, independently of delivery
retries. Until settlement commits, worker slots remain held. Batching is not a
new cross-replica ordering guarantee for M4's consecutive breaker.

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
