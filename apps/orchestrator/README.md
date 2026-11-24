# Orchestrator API

## Engagement drafts and listings

`POST /engagements` accepts a complete `RoeManifest`, including its
`signatures` object. Its `engagement_id` supplies the engagement UUID. A new
draft starts in `INIT_SCOPING` and returns HTTP 201 with `engagement_id` and
`manifest_hash`. A duplicate ID returns 409. `PUT /engagements/{id}/roe`
replaces the draft and returns the same receipt with HTTP 200. If a transition
has already moved the engagement out of scoping, replacement returns 409
`STATE_MISMATCH`. Draft replacement clears any prior `roe_signature_hash`.

The manifest digest is lowercase SHA-256 of the UTF-8 bytes of
`RoeManifest.model_dump_json()`, the serialization used by the existing manifest
registry. Draft persistence, registry provisioning, and the signed transition
to `ROE_LOCKED` are separate operations.

`GET /engagements/{id}/tasks`, `/findings`, and `/plans` return arrays of
`WorkflowTask`, `Finding`, and `ValidationPlan` for the engagement, ordered by
text ID with PostgreSQL's `C` collation. An empty collection returns `[]`.
An unknown engagement returns 404.

## Signing a validation transition

For `AWAITING_HITL_GATE → CONTROLLED_VALIDATION`, select the plan from the
engagement's plan listing. Compute its digest from the full returned object,
including nulls and both stored approval records. A Python client can hash
the decoded plan object with the following expression.

```python
canonical = json.dumps(plan, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
approved_plan_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
```

Set `approved_plan_id` to the plan UUID and `approved_plan_hash` to this
digest **before** signing `TransitionEvent.canonical_envelope()`. M2 checks the
signature, resolves the ID within the same engagement, and holds a shared lock
on the plan through the state update and ledger commit. A valid signature
with an incomplete binding receives 422 `PLAN_BINDING_REQUIRED`. A missing
plan receives 404 `PLAN_NOT_FOUND`. A stale digest receives 409
`PLAN_HASH_MISMATCH`. A rejected event leaves the state and ledger intact.

The frozen database uses a text plan key. ADR-0019 references the canonical
lowercase, hyphenated UUID spelling of that key. Legacy text IDs remain
listable. The signed row covers `engagement_id`, `id`, `blast_radius`,
`approver_sig`, and `second_approver_sig`. Request text and expected response
deltas in cockpit snapshots are outside the stored row. Ledger verification
uses the historical event payload and needs no live plan lookup.

## Audit delivery

State transitions and their ledger appends remain synchronous, signed where
required, and atomic under the existing engagement row lock. The default audit
API also retains its synchronous 201/200 ledger-receipt behavior.

ADR-0017 asynchronous non-transition audit delivery is opt-in. Configure
`ORCHESTRATOR_AUDIT_OUTBOX` to a persistent local SQLite file. All participating
orchestrator processes for an engagement must share that same outbox domain.
Separate host-local files cannot coordinate conflicting queued idempotency keys
before PostgreSQL append; this configuration is not a multi-host queue protocol.
Keep the outbox file and its WAL on persistent storage with a private parent
directory. Leaving the variable unset creates no queue or background worker.

Authenticated M4 callers send `Prefer: respond-async` and one UUID
`Idempotency-Key` to `POST /engagements/{id}/audit-events`. A 202 response means
SQLite WAL/FULL has durably accepted the validated event, not that PostgreSQL
has appended it. Duplicate keys with identical normalized payloads are stable;
conflicting payloads receive 409. Actor authentication, wire validation and
engagement checks remain required.

`GET /engagements/{id}/audit-events/{event_id}` uses the same M4 authentication
and returns 202 while queued, 200 with the committed ledger record, or 404 for an
unknown event. A worker retries accepted jobs using the existing idempotent
ledger writer. It acknowledges the queue only after PostgreSQL commits. A crash
between append and acknowledgment replays the same key and returns the original
record, continuing the hash chain once. No queue transaction is held while
waiting for a PostgreSQL engagement lock. Shutdown is bounded; unacknowledged
jobs remain on disk for restart.

Outbox mode keeps one idle SQLite WAL connection open while every writer still
commits with FULL durability. Non-transition audit requests and delivery use a
separate PostgreSQL pool with four connections, at most eight waiters, and a
250 ms acquisition timeout. Overload returns 503 before acceptance; the caller
retains its durable job for retry. State, transitions, and killswitch keep the
original pool. This also bounds audit requests waiting in shared HTTP workers;
it does not promise isolation from arbitrary traffic to other endpoints.

Back up and restore the outbox consistently with the ledger, and retain pending
jobs during outages. An unavailable/full outbox fails acceptance instead of
returning a false 202. Evidence promotion still requires the actual durable
artifact and ledger link through the existing evidence verification gate.

Run the full suite with disposable `ORCHESTRATOR_TEST_DATABASE_URL` and
`ORCHESTRATOR_TEST_REDIS_URL`, followed by `mypy --strict` using this service's
configuration. New delivery tests cover durable acceptance, restart and lost
acknowledgment replay, synchronous/asynchronous conflicts, signature-preserving
transition interleaving, and storage failures.

## ADR-0018 and ADR-0019 verification

Local verification used Python 3.12.14, Pydantic 2.14.4, PostgreSQL 17.12
with the frozen `db/schema.sql`, and Redis 7.4.12. From the repository root,
the following commands used a disposable database and Redis instance.
`test.env` activated the scratch virtual environment, set
`ORCHESTRATOR_TEST_DATABASE_URL` and `ORCHESTRATOR_TEST_REDIS_URL`, and put
`packages/contracts-py` on `PYTHONPATH`.

```sh
source /workspace/work/test.env
set -o pipefail
python -m pytest -q --capture=tee-sys apps/orchestrator | tee /workspace/work/orchestrator-verification.log
python -m pytest -q packages/contracts-py
python -m pytest -q apps/orchestrator/tests/test_contract_database_parity.py
python -m mypy --strict --config-file apps/orchestrator/pyproject.toml --cache-dir /workspace/work/checks-mypy-orchestrator apps/orchestrator
python -m mypy --strict --config-file packages/contracts-py/pyproject.toml --cache-dir /workspace/work/checks-mypy-contracts packages/contracts-py
```

The orchestrator passed 92 tests, contracts passed 77, and the separate live
parity run passed all 9 tests. No tests skipped. The sole orchestrator warning
was the upstream Starlette/httpx deprecation. The killswitch measured p99s
were 13.91, 14.72, and 14.82 ms, giving a median of 14.72 ms against the
50 ms gate. Strict mypy 2.4.1 passed on 15 orchestrator files and 11 contracts
files. The historical two-row ledger fixture reproduced both original digests
and the pre-ADR human signature.

TypeScript was regenerated with the schema command in
`packages/contracts-py/pyproject.toml` and `json-schema-to-typescript@15.0.4`.
A second generation compared byte-for-byte equal with `cmp`. The generator
emitted Node deprecation DEP0187. The field-level serializer requires Pydantic
2.12 or later. All 77 contracts tests also passed at the 2.12.0 floor, with
two upstream union-serialization warnings.
