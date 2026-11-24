# Cockpit browser acceptance

Install the web dependencies with `npm ci` in `apps/web`. Use a Python
environment with the orchestrator, graph, and evidence services' existing
dependencies. The fixture runner needs Docker with `postgres:17-alpine` and
`redis:7-alpine` already present. It uses system Chromium when available.
Use `M10_CHROMIUM_EXECUTABLE` to select a different executable, or install
Playwright Chromium with `npx playwright install chromium` from `apps/web`.

From the repository root:

```sh
PYTHONDONTWRITEBYTECODE=1 python apps/web/e2e/run.py
```

Set `M10_ARTIFACTS` to retain service logs and Playwright output under a
particular directory. Extra arguments go to Playwright, including `-g` for
test selection. The runner creates disposable Postgres and Redis containers
bound to loopback, applies the frozen MS0 schema, and starts the real
orchestrator, graph, and evidence services behind the web development server.
It uses one ephemeral Ed25519 key restricted to the fixture harness. The
browser receives only the resulting detached signature and the test data.
The local proxy exposes the cockpit's known methods and endpoints to the
browser. Production ingress needs its own authentication, engagement
authorization, and fixed same-origin service routing.

The positive checks exercise RoE draft export, authoritative rejection of an
invalid signature, the externally signed lock transition, the emergency stop
shortcut and its ledger entry, the operator-selected topology comparison, and
digest-verified evidence retrieval. The negative integrity check changes one
byte in a browser-intercepted fixture response. The approval rail is checked
with axe and keyboard navigation, including the blocked destructive approval.

The fixture provisions engagements before starting the browser because this
branch lacks engagement creation and RoE provisioning endpoints. Inventory,
tasks, proposals and findings arrive as a scoped review snapshot. The frozen
transition envelope covers engagement state and carries no plan, request, or
response delta. The checkout also lacks a native signer bridge and `apps/report-svc`.
The browser tests cover the displayed blocked states and use synthetic records
throughout.
