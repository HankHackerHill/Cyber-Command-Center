# ADR-0011: Deferred Transition Paths (M2 Resolution)

**Status:** Resolved (M2 implementation scope) at `8dab48204538cc7ec98872985d232831fc5ae758` under [ADR-0016](0016-lane-exception-sol-resolution.md). The shared MS1 integration acceptance gate remains pending; [ADR-0014](0014-deferred-forwarding-paths.md) remains unresolved.

**Resolution:** `POST /engagements/{id}/transition` now accepts all 16 progression/reset edges in the authoritative state machine. All states retain the dedicated idempotent killswitch path. Human-only target states still require a trusted HUMAN_OPERATOR Ed25519 signature over the canonical transition envelope. Engagement binding, optional-signature verification, source-state validation under `SELECT ... FOR UPDATE`, and atomic state update plus hash-chain append remain enforced. The chain continues from the current engagement tail, including audit-only records. An engagement-scoped check under the same lock rejects reuse of previously applied transition event IDs with HTTP 409 `EVENT_REPLAY`; failed transactions do not consume an ID. This does not impose an expiry on never-applied signed approvals.

**Verification:** Python 3.12.14, disposable PostgreSQL 17 and Redis 7, synthetic data and generated test-only signing keys. Commands ran from the repository root after `source /workspace/work/adr0011/test.env`, which exports the disposable service URLs, frozen contracts on `PYTHONPATH`, `PYTHONDONTWRITEBYTECODE=1`, and scratch paths for test artifacts.

```sh
/workspace/work/adr0011/venv/bin/python -m pytest -p no:cacheprovider -q --capture=tee-sys apps/orchestrator
/workspace/work/adr0011/venv/bin/python -m pytest -p no:cacheprovider -q packages/contracts-py
/workspace/work/adr0011/venv/bin/python -m mypy --strict --config-file apps/orchestrator/pyproject.toml --cache-dir /workspace/work/adr0011/mypy-cache apps/orchestrator
```

The full orchestrator suite passed **70 tests, zero skips**, including **9 live contract/database parity checks**. The contracts suite passed **72 tests**. Strict mypy found **no issues in 11 source files**. The orchestrator suite emitted one upstream Starlette/httpx deprecation warning. The unchanged killswitch benchmark measured p99s of **11.93, 9.08, and 14.82 ms**, with a **11.93 ms median**, below 50 ms.

Coverage includes the complete signed assessment progression and graph loops; every legal progression/reset edge; competing different-target transitions with exactly one winner; the unchanged illegal-transition/no-write property test; human-signature denials; real halt/manual reset; ledger continuation and independent hash/envelope verification at every hop; transaction rollback; and consumed-approval replay rejection. The live parity checks compare all seven database enums to frozen contracts, ledger serialization columns and foreign key, and the payload-derived generated engagement key. Technical, adversarial and acceptance reviews found no unresolved defect in this implementation scope. Frozen MS0 paths, existing signature checks, other services and CI workflows were not changed. No live client traffic was generated.

**Outstanding MS1 acceptance:** ADR-0016 requires a signed engagement reaching CONTROLLED_VALIDATION through the governed proxy with a successfully forwarded request and an evidence ledger row. This cross-service acceptance test has not been performed. It depends on ADR-0014 origin transport/TLS work, which is explicitly outside this resolution task. M2 local verification does not close that shared gate or grant MS1 sign-off. CI workflows remain deferred.

**History:** The fail-closed placeholder at `34fcdf7` returned HTTP 403 `TRANSITION_UNAVAILABLE` for deferred progression while preserving engagement state and ledger. The human owner accepted that tracked debt so the build could continue, then authorized its implementation through ADR-0016.
