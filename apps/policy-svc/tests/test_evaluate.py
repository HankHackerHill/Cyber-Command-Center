"""Policy decisions against real Rego and Redis, with an isolated orchestrator response."""

import hashlib
import json
import os
import shutil
import socket
import subprocess
import time
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from threading import Barrier
from uuid import UUID, uuid4

import httpx
import pytest
from fastapi.testclient import TestClient
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from redis import Redis

from main import AccountStore, create_app

ROOT = Path(__file__).resolve().parents[3]
ROE = ROOT / "tests/fixtures/roe_sample.json"
NOW = datetime(2026, 12, 1, 12, tzinfo=timezone.utc)
TS = "2026-12-01T12:00:00Z"
HEADER = "X-Policy-Reservation"


@pytest.fixture(scope="module")
def opa_url(tmp_path_factory: pytest.TempPathFactory) -> Iterator[str]:
    executable = os.environ.get("OPA_BIN") or shutil.which("opa")
    if not executable:
        pytest.fail("Install OPA v1 on PATH or set OPA_BIN to its executable")
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    url = f"http://127.0.0.1:{port}"
    directory = ROOT / "packages/policy-bundles"
    policies = sorted(directory.glob("*.rego"))
    log = tmp_path_factory.mktemp("opa") / "server.log"
    with log.open("wb") as output, subprocess.Popen(
        [executable, "run", "--server", "--skip-version-check", "--addr", f"127.0.0.1:{port}", *map(str, policies)],
        stdout=output, stderr=subprocess.STDOUT,
    ) as server, httpx.Client(base_url=url, trust_env=False, timeout=1) as http:
        try:
            deadline = time.monotonic() + 10
            while True:
                if server.poll() is not None or time.monotonic() > deadline:
                    pytest.fail(f"OPA startup failed; see {log}")
                try:
                    if http.get("/health").is_success:
                        break
                except httpx.ConnectError:
                    pass
                time.sleep(0.02)
            yield url
        finally:
            server.terminate()


def envelope(digest: str, **overrides: object) -> dict[str, object]:
    return {
        "manifest_hash": digest,
        "request": {
            "method": "GET", "host": "api.staging.example.com", "ip": "198.51.100.7",
            "path": "/v1/report", "ts": TS, **overrides,
        },
    }


def decision(response: httpx.Response, expected: bool) -> None:
    assert response.status_code == 200, response.text
    body = response.json()
    assert set(body) == {"allow", "reason"}
    assert body["allow"] is expected, body
    assert isinstance(body["reason"], str) and body["reason"]
    assert bool(response.headers.get(HEADER)) is expected


def ready(request: httpx.Request) -> httpx.Response:
    assert request.method == "GET" and request.url.path.endswith("/state")
    return httpx.Response(200, json={"state": "CONTROLLED_VALIDATION"})


@dataclass
class Sandbox:
    directory: Path
    redis_url: str
    opa: str
    store: AccountStore
    created_keys: set[str] = field(default_factory=set)

    def provision(
        self, *, exact: bool = False, initialize: bool = True, mode: str = "HYBRID",
        engagement_id: str | None = None, not_before: str | None = None, **limits: int,
    ) -> tuple[str, str]:
        raw = ROE.read_bytes()
        manifest = json.loads(raw)
        if not exact:
            manifest["engagement_id"] = engagement_id or str(uuid4())
            manifest["execution_mode"] = mode
            if not_before:
                manifest["valid_window"]["not_before"] = not_before
            manifest["traffic_constraints"].update(limits)
            manifest["traffic_constraints"]["required_attribution_header"] = (
                "X-Security-Assessment-ID: " + manifest["engagement_id"]
            )
            raw = json.dumps(manifest).encode()
        engagement: str = manifest["engagement_id"]
        digest = hashlib.sha256(raw).hexdigest()
        (self.directory / f"{digest}.json").write_bytes(raw)
        if initialize:
            key = self.store._key(engagement)
            if key not in self.created_keys:
                assert not self.store.redis.exists(key), f"Expected a disposable Redis database; test key exists: {key}"
                self.created_keys.add(key)
            self.store.initialize(engagement)
        return engagement, digest

    @contextmanager
    def service(
        self, *, state: Callable[[httpx.Request], httpx.Response] = ready,
        now: datetime = NOW, time_us: Callable[[], int] | None = None,
        opa: str | None = None, redis_url: str | None = None,
    ) -> Iterator[TestClient]:
        app = create_app(
            manifest_dir=self.directory, orchestrator_url="http://orchestrator.invalid",
            opa_url=opa if opa is not None else self.opa,
            redis_url=redis_url if redis_url is not None else self.redis_url,
            clock=lambda: now, time_us=time_us, transport=httpx.MockTransport(state),
        )
        with TestClient(app) as client:
            yield client


@pytest.fixture
def sandbox(opa_url: str, tmp_path: Path) -> Iterator[Sandbox]:
    url = os.environ.get("POLICY_TEST_REDIS_URL") or os.environ.get("ORCHESTRATOR_TEST_REDIS_URL")
    if not url:
        pytest.fail("Set POLICY_TEST_REDIS_URL to a disposable Redis database")
    with Redis.from_url(url, decode_responses=True) as redis:
        assert redis.ping()
        sandbox = Sandbox(tmp_path, url, opa_url, AccountStore(redis))
        try:
            yield sandbox
        finally:
            if sandbox.created_keys:
                redis.delete(*sandbox.created_keys)


def test_exact_fixture_allow_and_deny(sandbox: Sandbox) -> None:
    engagement, digest = sandbox.provision(exact=True)
    assert digest == hashlib.sha256(ROE.read_bytes()).hexdigest()

    def fixture_state(request: httpx.Request) -> httpx.Response:
        assert request.url.path == f"/engagements/{engagement}/state"
        return ready(request)

    with sandbox.service(state=fixture_state) as client:
        for overrides in (
            {"path": "/v1/billing/charge"}, {"path": "/admin/reset-tenant"},
            {"path": "/admin/reset-tenant/subpath"}, {"method": "PATCH"},
            {"host": "outside.example.com"}, {"ip": "203.0.113.1"},
            {"ts": "2026-12-04T23:00:00-05:00"},  # Saturday in UTC.
            {"ts": "2026-12-13T12:00:00Z"},
        ):
            decision(client.post("/evaluate", json=envelope(digest, **overrides)), False)
        for host in ("api.staging.example.com", "web-app.staging.example.internal"):
            accepted = client.post("/evaluate", json=envelope(digest, host=host))
            decision(accepted, True)
            assert sandbox.store.complete(engagement, accepted.headers[HEADER], 200)


def test_client_cannot_backdate_service_window(sandbox: Sandbox) -> None:
    _, digest = sandbox.provision()
    with sandbox.service(now=datetime(2027, 1, 1, tzinfo=timezone.utc)) as client:
        decision(client.post("/evaluate", json=envelope(digest)), False)


def test_manifest_start_preserves_nanoseconds(sandbox: Sandbox) -> None:
    start = "2026-12-01T08:00:00.000000500Z"
    engagement, digest = sandbox.provision(not_before=start)
    with sandbox.service() as client:
        too_early = client.post("/evaluate", json=envelope(digest, ts="2026-12-01T08:00:00Z"))
        decision(too_early, False)
        at_start = client.post("/evaluate", json=envelope(digest, ts=start))
        decision(at_start, True)
        assert sandbox.store.complete(engagement, at_start.headers[HEADER], 200)


def test_passive_manifest_denies_client_target_requests(sandbox: Sandbox) -> None:
    _, digest = sandbox.provision(mode="AUTONOMOUS_PASSIVE")
    with sandbox.service() as client:
        decision(client.post("/evaluate", json=envelope(digest)), False)


def test_unknown_or_tampered_manifest(sandbox: Sandbox) -> None:
    _, digest = sandbox.provision()
    with sandbox.service() as client:
        decision(client.post("/evaluate", json=envelope("0" * 64)), False)
        manifest = sandbox.directory / f"{digest}.json"
        manifest.write_bytes(manifest.read_bytes() + b" ")
        decision(client.post("/evaluate", json=envelope(digest)), False)
        invalid = b'{"unexpected":true}'
        invalid_hash = hashlib.sha256(invalid).hexdigest()
        (sandbox.directory / f"{invalid_hash}.json").write_bytes(invalid)
        decision(client.post("/evaluate", json=envelope(invalid_hash)), False)


def test_strict_request_shape(sandbox: Sandbox) -> None:
    _, digest = sandbox.provision()
    payload = envelope(digest)
    req = payload["request"]
    assert isinstance(req, dict)
    with sandbox.service() as client:
        for invalid in (
            {}, {"request": req}, {"manifest_hash": digest}, {**payload, "unexpected": 1},
            {**payload, "request": {**req, "unexpected": True}},
            *({**payload, "request": {k: v for k, v in req.items() if k != field}} for field in req),
        ):
            decision(client.post("/evaluate", json=invalid), False)
        decision(client.post("/evaluate", content=b'{"broken"', headers={"content-type": "application/json"}), False)
        encoded = json.dumps(payload).replace('"method": "GET"', '"method": "GET", "method": "GET"')
        decision(client.post("/evaluate", content=encoded, headers={"content-type": "application/json"}), False)
        wire = json.dumps(payload).encode()
        for bad_host in (b"\xff", rb"\ud800"):
            corrupted = wire.replace(b"api.staging.example.com", bad_host)
            decision(client.post("/evaluate", content=corrupted, headers={"content-type": "application/json"}), False)


json_values = st.recursive(
    st.one_of(st.none(), st.integers(), st.booleans(), st.text(max_size=12)),
    lambda leaf: st.one_of(st.lists(leaf, max_size=3), st.dictionaries(st.text(max_size=8), leaf, max_size=3)),
    max_leaves=7,
)


@pytest.fixture
def fuzz_client(sandbox: Sandbox) -> Iterator[tuple[TestClient, str]]:
    _, digest = sandbox.provision()
    with sandbox.service() as client:
        yield client, digest


@settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(field=st.sampled_from(["method", "host", "ip", "path", "ts", "extra"]), value=json_values)
def test_fuzz_invalid_fields(fuzz_client: tuple[TestClient, str], field: str, value: object) -> None:
    # Retain a valid hash and all other fields so a bad field alone must cause denial.
    client, digest = fuzz_client
    if isinstance(value, str) and field != "extra":
        value = "\x00" + value
    decision(client.post("/evaluate", json=envelope(digest, **{field: value})), False)


@pytest.mark.parametrize("state", ["INIT_SCOPING", "DISCOVERY_PASSIVE", "AWAITING_HITL_GATE", "UNKNOWN"])
def test_orchestrator_denial(sandbox: Sandbox, state: str) -> None:
    _, digest = sandbox.provision()
    with sandbox.service(state=lambda _: httpx.Response(200, json={"state": state})) as client:
        decision(client.post("/evaluate", json=envelope(digest)), False)


def test_halt_revokes_previously_allowed_scope(sandbox: Sandbox) -> None:
    engagement, digest = sandbox.provision()
    state = "CONTROLLED_VALIDATION"
    with sandbox.service(state=lambda _: httpx.Response(200, json={"state": state})) as client:
        admitted = client.post("/evaluate", json=envelope(digest))
        decision(admitted, True)
        assert sandbox.store.complete(engagement, admitted.headers[HEADER], 200)
        state = "HALTED_KILLSWITCH"
        decision(client.post("/evaluate", json=envelope(digest)), False)


def test_unavailable_dependencies_deny(sandbox: Sandbox) -> None:
    _, digest = sandbox.provision()

    def offline(_: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("test-only orchestrator outage")

    for handler in (offline, lambda _: httpx.Response(404), lambda _: httpx.Response(200, json={})):
        with sandbox.service(state=handler) as client:
            decision(client.post("/evaluate", json=envelope(digest)), False)
    with sandbox.service(opa="http://127.0.0.1:1") as client:
        decision(client.post("/evaluate", json=envelope(digest)), False)
    with sandbox.service(redis_url="redis://127.0.0.1:1") as client:
        decision(client.post("/evaluate", json=envelope(digest)), False)
    _, uninitialized = sandbox.provision(initialize=False)
    with sandbox.service() as client:
        decision(client.post("/evaluate", json=envelope(uninitialized)), False)


@pytest.mark.parametrize("corrupted", [
    b"\xff", b"{}", b"null",
    b'{"credit":1000001,"at_us":1,"rate":1,"errors_5xx":0,"active_workers":0}',
    b'{"credit":0,"at_us":0,"rate":0,"errors_5xx":1,"active_workers":0}',
])
def test_corrupt_redis_account_denies(sandbox: Sandbox, corrupted: bytes) -> None:
    engagement, digest = sandbox.provision()
    sandbox.store.redis.hset(sandbox.store._key(engagement), mapping={"state": corrupted})
    with sandbox.service() as client:
        decision(client.post("/evaluate", json=envelope(digest)), False)


def test_resigned_manifests_and_uuid_aliases_share_accounting(sandbox: Sandbox) -> None:
    engagement, digest = sandbox.provision(max_requests_per_second=1)
    alternate_id = UUID(engagement).hex.upper()
    with sandbox.service(time_us=lambda: 1_900_000_000_000_000) as client:
        accepted = client.post("/evaluate", json=envelope(digest))
        decision(accepted, True)
        _, another_digest = sandbox.provision(engagement_id=alternate_id, max_requests_per_second=1)
        assert another_digest != digest
        assert sandbox.store.complete(alternate_id, accepted.headers[HEADER], 200)
        decision(client.post("/evaluate", json=envelope(another_digest)), False)


def test_token_refill_uses_server_clock_per_engagement(sandbox: Sandbox) -> None:
    instant = 1_900_000_000_000_000
    engagement, digest = sandbox.provision(max_requests_per_second=2)
    other, other_hash = sandbox.provision(max_requests_per_second=2)
    with sandbox.service(time_us=lambda: instant) as client:
        for _ in range(2):
            accepted = client.post("/evaluate", json=envelope(digest))
            decision(accepted, True)
            assert sandbox.store.complete(engagement, accepted.headers[HEADER], 200)
        decision(client.post("/evaluate", json=envelope(digest, ts="2026-12-03T12:00:00Z")), False)
        independent = client.post("/evaluate", json=envelope(other_hash))
        decision(independent, True)
        assert sandbox.store.complete(other, independent.headers[HEADER], 200)
        instant += 499_999
        decision(client.post("/evaluate", json=envelope(digest)), False)
        instant += 1
        next_token = client.post("/evaluate", json=envelope(digest))
        decision(next_token, True)
        assert sandbox.store.complete(engagement, next_token.headers[HEADER], 200)


def test_worker_claims_are_atomic_and_released(sandbox: Sandbox) -> None:
    engagement, digest = sandbox.provision(max_requests_per_second=100, max_concurrent_workers=2)
    with sandbox.service() as client:
        callers = 8
        start = Barrier(callers, timeout=10)

        def concurrent(_: int) -> httpx.Response:
            start.wait()
            response: httpx.Response = client.post("/evaluate", json=envelope(digest))
            return response

        with ThreadPoolExecutor(max_workers=callers) as threads:
            attempts = list(threads.map(concurrent, range(callers)))
        grants = [r for r in attempts if r.json()["allow"]]
        assert len(grants) == 2
        assert len({r.headers[HEADER] for r in grants}) == 2
        for attempt in attempts:
            decision(attempt, attempt in grants)
        assert sandbox.store.complete(engagement, grants[0].headers[HEADER], 200)
        resumed = client.post("/evaluate", json=envelope(digest))
        decision(resumed, True)
        for last in (resumed, grants[1]):
            assert sandbox.store.complete(engagement, last.headers[HEADER], 200)


def test_breaker_counts_each_observed_5xx_once(sandbox: Sandbox) -> None:
    engagement, digest = sandbox.provision(circuit_breaker_5xx_threshold=2)
    other, other_hash = sandbox.provision(circuit_breaker_5xx_threshold=2)
    with sandbox.service() as client:
        first = client.post("/evaluate", json=envelope(digest))
        decision(first, True)
        receipt = first.headers[HEADER]
        assert not sandbox.store.complete(engagement, receipt, 103)
        assert not sandbox.store.complete(other, receipt, 503)
        start = Barrier(8, timeout=10)

        def finish(_: int) -> bool:
            start.wait()
            return sandbox.store.complete(engagement, receipt, 503)

        with ThreadPoolExecutor(max_workers=8) as threads:
            assert list(threads.map(finish, range(8))).count(True) == 1
        assert not sandbox.store.complete(engagement, receipt, 503)
        ignore_4xx = client.post("/evaluate", json=envelope(digest))
        decision(ignore_4xx, True)
        assert sandbox.store.complete(engagement, ignore_4xx.headers[HEADER], 429)
        another = client.post("/evaluate", json=envelope(digest))
        decision(another, True)
        assert sandbox.store.complete(engagement, another.headers[HEADER], 500)
        decision(client.post("/evaluate", json=envelope(digest)), False)
        fresh = client.post("/evaluate", json=envelope(other_hash))
        decision(fresh, True)
        assert sandbox.store.complete(other, fresh.headers[HEADER], 200)
