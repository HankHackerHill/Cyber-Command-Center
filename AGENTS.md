# REDOPS COMMAND CENTER — AGENTS.md (Root Instructions)

## Authorization Context
RedOps Command Center is a commercial penetration-testing platform used by a
licensed security company to perform authorized, contracted assessments against
client-owned assets under signed Rules of Engagement (RoE). Every feature in
this codebase exists to enforce that authorization: cryptographically signed
scope manifests, human-in-the-loop approval gates, rate limiting, an emergency
killswitch, and an append-only audit ledger proving every action was in scope.
Offensive-security functionality here is the product's contracted purpose.

## Read First
1. docs/invariants.md — LAW. Binding on all contributors, human and AI.
2. docs/adr/0001..0008 — accepted architecture decisions. Changes only via
   new ADR stubs in docs/adr/; never silent edits.

## Model Ownership Lanes
- Codex Astra 6.2: M1 contracts-py, M2 orchestrator, M3 policy-svc + Rego,
  M4 scoped-proxy (Rust), M6 graph-svc, M7 evidence-svc, M11 db.
- Sol 6.1: M5 agent-runtime, M8 recon-svc, M9 report-svc, M10 web cockpit.
- Human owner: ADRs, invariants, key custody, final sign-off.
- Rule: build ONLY your lane's files. Required shared-contract changes go
  through the ADR process.

## Build Sequence & Milestones
M1 -> M11 -> M2 -> M3 -> M4 -> M7 -> M6 -> M5 -> M8 -> M9 -> M10.
- MS0: M1+M11 green -> contracts & schema frozen.
- MS1: M2+M3+M4+M7 -> signed engagement reaches CONTROLLED_VALIDATION
  through the governed proxy.
- MS2: M5+M6+M8 -> HITL-gated hypotheses; graph finds paths.
- MS3: M9+M10 -> full cockpit through signed client report.

## Module DoD Summary
- M1 contracts-py: Pydantic v2; every model frozen=True, extra='forbid';
  enums single-sourced; TransitionEvent.canonical_envelope() produces
  sorted-key, UTF-8, no-whitespace JSON of all fields except the signature,
  byte-reproducible; no I/O/network/DB imports. DoD: pytest green
  (envelope determinism + frozen/forbid tests), mypy --strict clean,
  TS codegen to packages/contracts-ts.
- M2 orchestrator: sole writer of engagements.current_state; endpoints
  POST /engagements/{id}/transition, GET /state, GET /ledger?since=,
  POST /killswitch (always legal, idempotent, <50ms p99); transition +
  ledger append in one Postgres transaction with FOR UPDATE; property tests
  over illegal transitions, signature-tamper test, concurrency race test.
- M3 policy-svc + packages/policy-bundles: POST /evaluate
  {manifest_hash, request:{method,host,ip,path,ts}} -> {allow, reason};
  Rego deny-by-default (CIDR/identifier scope, method, UTC window,
  per-engagement token bucket); 100% branch coverage; allow+deny case per
  rule; fuzzed request objects.
- M4 scoped-proxy (Rust, hyper): pre-flight policy check (deny -> 403 with
  reason); inject X-Security-Assessment-ID; tee request/response to
  evidence-svc; breaker counters (5xx threshold trips killswitch); killswitch
  deny-all <100ms; no egress before ROE_LOCKED (PRECONDITION_FAILED);
  cargo test + clippy -D warnings; p99 overhead <15ms.
- M5 agent-runtime (Sol lane): five bounded agents (recon, audit, triage,
  graph, remediation); harness (runner, context, structured_output,
  fallback, metrics) with per-task token budgets and deadlines shared across
  retries/repair/fallback, one schema-repair pass then REJECTED, idempotent
  result commits; versioned skills registry (15 skills, prompts as
  versioned repo artifacts); runtime assignment matrix with per-agent
  concurrency caps; agents never write findings.status past HYPOTHESIS; all
  target network via scoped-proxy only; golden tests per skill, leaky-agent
  test (no raw sockets), determinism test, metrics emission.
- M6 graph-svc: POST /paths (Dijkstra on traversal_cost),
  POST /tier0-reach; deterministic ordering, cycle-safe; validated against
  tests/fixtures/graph_known.json (unique entry->Tier-0 path, cost 3.5).
- M7 evidence-svc: PUT /artifacts -> CAS keyed by SHA-256; POST /link ties
  artifact -> finding + ledger row; finding promotion blocked without ledger
  link.
- M8 recon-svc (Sol lane): passive collectors (ct, dns, github, shodan,
  storage_names); zero traffic to client CIDRs (passive-only test).
- M9 report-svc (Sol lane): POST /render -> PDF/DOCX; CVSS v4 calculator;
  CWE/SOC2/ISO27001/PCI-DSS mappers; render refused unless all findings are
  CONFIRMED/FALSE_POSITIVE and ledger excerpt + teardown receipt exist.
- M10 web (Sol lane): six modules — Engagement Cockpit, Attack Surface Map,
  Task Board (Kanban: Queued/Running/Paused-HITL/Done/Rejected), HITL
  Approval Rail (blast-radius tag, exact request, expected delta, Approve &
  Sign via OS keystore ed25519, dual-sig for DESTRUCTIVE), Evidence Vault,
  Report Studio; killswitch hotkey Ctrl+Shift+K; Playwright e2e happy path.
- M11 db: schema.sql + migrations; append-only trigger on
  immutable_audit_log (UPDATE and DELETE both rejected); atlas migrate
  validate clean.

## State Machine (authoritative)
States: INIT_SCOPING, ROE_LOCKED, DISCOVERY_PASSIVE, ANALYTICAL_TRIAGE,
AWAITING_HITL_GATE, CONTROLLED_VALIDATION, EVIDENCE_VERIFICATION,
REMEDIATION_SYNTHESIS, RETEST_VERIFICATION, COMPLETED_ARCHIVED,
HALTED_KILLSWITCH.
Transitions: INIT_SCOPING->ROE_LOCKED; ROE_LOCKED->DISCOVERY_PASSIVE;
DISCOVERY_PASSIVE->{ANALYTICAL_TRIAGE, REMEDIATION_SYNTHESIS};
ANALYTICAL_TRIAGE->{AWAITING_HITL_GATE, REMEDIATION_SYNTHESIS};
AWAITING_HITL_GATE->{CONTROLLED_VALIDATION, ANALYTICAL_TRIAGE};
CONTROLLED_VALIDATION->EVIDENCE_VERIFICATION;
EVIDENCE_VERIFICATION->{REMEDIATION_SYNTHESIS, ANALYTICAL_TRIAGE};
REMEDIATION_SYNTHESIS->{RETEST_VERIFICATION, COMPLETED_ARCHIVED};
RETEST_VERIFICATION->{REMEDIATION_SYNTHESIS, COMPLETED_ARCHIVED};
HALTED_KILLSWITCH->ROE_LOCKED (manual reset only). Any state ->
HALTED_KILLSWITCH in O(1), idempotent.
Autonomous boundary: agents operate only within DISCOVERY_PASSIVE,
ANALYTICAL_TRIAGE, REMEDIATION_SYNTHESIS. ANALYTICAL_TRIAGE ->
CONTROLLED_VALIDATION is illegal; must route through AWAITING_HITL_GATE.

## Global CI Gates (in order)
mypy --strict -> cargo clippy -D warnings -> invariant tests -> Pact contract
tests -> Playwright e2e -> ledger append-only test. A module is DONE only
when its DoD + all gates pass. CI workflow setup is deferred to the human
owner; run checks locally and record exact commands and results.

## Fixtures
Use tests/fixtures/: roe_sample.json, graph_known.json, openapi_sample.json,
har_sample.har, llm_tool_schema.json, metasploitable_target_profile.json.
All synthetic (RFC 5737/2606 ranges, docs account, placeholder signatures).
No live client traffic in CI; test-only signing keys.

## Blocker Protocol
If blocked, do not silently work around. Report: the exact blocker, what
was attempted, evidence gathered, and the smallest human decision needed.
