# Cockpit browser acceptance

Install the web dependencies with `npm ci` in `apps/web`. Use a Python
environment with the orchestrator, graph, evidence, and report service
dependencies. The report renderer needs Pango, fontconfig, and DejaVu fonts.
The fixture runner needs Docker with `postgres:17-alpine` and
`redis:7-alpine` already present. It uses system Chromium when available.
Use `M10_CHROMIUM_EXECUTABLE` to select a different executable, or install
Playwright Chromium with `npx playwright install chromium` from `apps/web`.

Run the browser suite from the repository root.

```sh
PYTHONDONTWRITEBYTECODE=1 python apps/web/e2e/run.py
```

Run the report Pact gate with `pact-python==3.4.1` installed in the fixture
Python environment and Node 22.7 or later available.

```sh
PYTHONDONTWRITEBYTECODE=1 python apps/web/e2e/run.py --pact
```

Set `M10_ARTIFACTS` to retain service logs and Playwright output under a
particular directory. Extra arguments go to Playwright, including `-g` for
test selection. The runner creates disposable Postgres and Redis containers
bound to loopback, applies the frozen MS0 schema, and starts the real
orchestrator, graph, evidence, and report services behind the web development
server. The report service uses a fixture-only finalization directory and a
database role with read access to recorded chains, nodes, and edges.
It uses one ephemeral Ed25519 key restricted to the fixture harness. The
browser receives only the resulting detached signature and the test data.
The local proxy exposes the cockpit's known methods and endpoints to the
browser. For local development outside the fixture runner, set
`REDOPS_REPORT_URL` to the report service's loopback HTTP origin with an
explicit port, such as `http://127.0.0.1:8010`.

Production ingress must authenticate the operator and authorize access to the
engagement before routing each request on the cockpit's origin.

| Cockpit request | Internal request |
| --- | --- |
| `POST /api/report/render` | Report service `POST /render` |
| `GET /api/orchestrator/engagements/{id}/findings` | Orchestrator `GET /engagements/{id}/findings` |

For the report route, authorize the engagement identified by `engagement_id`
in the request body.

The positive checks exercise RoE draft export, authoritative rejection of an
invalid signature, the externally signed lock transition, the emergency stop
shortcut and its ledger entry, the operator-selected topology comparison, and
digest-verified evidence retrieval. The approval rail is checked with axe and
keyboard navigation, including the blocked destructive approval. Report Studio
downloads both verified formats from the real `POST /render`. The test checks
the recorded chain, finding, and evidence digest in the DOCX and compares the
downloaded document digests with the service response. The suite also covers
the service's refusal to render a non-final finding and the browser's refusal
to release either report when a response contains altered document bytes. The
suite tests cancellation when the operator leaves Studio to attach a different
engagement and checks the provenance display with axe.

The runner provisions the synthetic engagements before starting the browser.
Inventory, tasks, and proposals in the checkpoint flows arrive as a scoped
review snapshot. Report Studio fetches live finding identities and statuses
from the orchestrator. The current cockpit uses detached signatures for the
RoE lock and displays validation proposals without submitting approvals.
