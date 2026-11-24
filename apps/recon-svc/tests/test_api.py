"""Exercise every collector through the in-process API using synthetic imports."""

import asyncio
import json
import socket
from collections.abc import AsyncIterator
from dataclasses import dataclass
from ipaddress import IPv4Network, ip_address
from pathlib import Path
from typing import NoReturn, TypedDict, cast

import httpx
import pytest
from contracts.events import ActorType
from contracts.findings import AssetNode
from fastapi.testclient import TestClient
from pydantic import JsonValue, TypeAdapter

from main import create_app


class ScopeBoundaries(TypedDict):
    allowed_cidrs: list[str]
    allowed_identifiers: list[str]


class ScopeFixture(TypedDict):
    engagement_id: str
    scope_boundaries: ScopeBoundaries


@dataclass(frozen=True)
class ImportCase:
    source: str
    record: dict[str, JsonValue]
    category: str
    identifier: str
    metadata: dict[str, JsonValue]


@dataclass
class ManualClock:
    now: float = 0.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def scope() -> ScopeFixture:
    repo = Path(__file__).resolve().parents[3]
    return cast(ScopeFixture, json.loads((repo / "tests/fixtures/roe_sample.json").read_bytes()))


@pytest.fixture
def cases(scope: ScopeFixture) -> tuple[ImportCase, ...]:
    boundaries = scope["scope_boundaries"]
    hostname = boundaries["allowed_identifiers"][0]
    cidr = IPv4Network(boundaries["allowed_cidrs"][0])
    address = str(cidr.network_address + 7)
    fingerprint = "ab" * 32
    return (
        ImportCase("ct", {"hostname": f"{hostname.upper()}.", "certificate_sha256": fingerprint},
                   "dns_name", hostname, {"source": "ct", "certificate_sha256": [fingerprint]}),
        ImportCase("dns", {"hostname": hostname, "record_type": "A", "value": address},
                   "dns_name", hostname, {"source": "dns", "records": [{"record_type": "A", "value": address}]}),
        ImportCase("github", {"repository": "Fixture-Org/Fixture-App", "indicator": "credential_exposure"},
                   "repository", "fixture-org/fixture-app",
                   {"source": "github", "redacted_indicators": ["credential_exposure"]}),
        ImportCase("shodan", {"asset_ref": "inventory-one", "severity": "medium", "observation_count": 2},
                   "exposure_review", "inventory-one",
                   {"source": "shodan", "severity": "medium", "observation_count": 2}),
        ImportCase("storage_names", {"asset_ref": "inventory-two", "provider": "aws", "naming_pattern": "team"},
                   "storage_review", "inventory-two",
                   {"source": "storage_names", "observations": [{"provider": "aws", "naming_pattern": "team"}]}),
    )


def payload(engagement_id: str, case: ImportCase) -> dict[str, JsonValue]:
    return {"engagement_id": engagement_id, "records": [case.record]}


def test_all_collectors_round_trip_without_network(
    scope: ScopeFixture, cases: tuple[ImportCase, ...], monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = IPv4Network(scope["scope_boundaries"]["allowed_cidrs"][0])
    assert target == IPv4Network("198.51.100.0/24")
    address = cases[1].record["value"]
    assert isinstance(address, str) and ip_address(address) in target

    attempts: list[tuple[object, ...]] = []

    def deny(*args: object, **kwargs: object) -> NoReturn:
        attempts.append((*args, kwargs))
        raise AssertionError("The passive import attempted outbound network I/O")

    adapter = TypeAdapter(list[AssetNode])
    with TestClient(create_app()) as client, monkeypatch.context() as guard:
        # In-process ASGI requests need no network. Guard connections and DNS
        # lookups regardless of destination, including the synthetic client CIDR.
        for name in ("connect", "connect_ex", "sendto"):
            guard.setattr(socket.socket, name, deny)
        for name in ("getaddrinfo", "gethostbyname", "gethostbyname_ex", "gethostbyaddr"):
            guard.setattr(socket, name, deny)

        for case in cases:
            wire = payload(scope["engagement_id"], case)
            response = client.post(f"/collect/{case.source}", json=wire)
            assert response.status_code == 200
            node, = adapter.validate_json(response.content)
            assert node.engagement_id == scope["engagement_id"]
            assert node.discovered_by is ActorType.SYSTEM
            assert node.asset_category == case.category
            assert node.canonical_identifier == case.identifier
            assert node.metadata == case.metadata

            repeat = client.post(f"/collect/{case.source}", json=wire)
            assert repeat.status_code == 200
            assert repeat.json() == response.json()

    assert attempts == []


def test_per_collector_budget_and_clock_refill(scope: ScopeFixture, cases: tuple[ImportCase, ...]) -> None:
    clock = ManualClock()
    ct, *others = cases
    wire = payload(scope["engagement_id"], ct)
    with TestClient(create_app(requests_per_minute=1, clock=clock)) as client:
        assert client.post("/collect/ct", json=wire).status_code == 200
        exhausted = client.post("/collect/ct", json=wire)
        assert exhausted.status_code == 429
        assert int(exhausted.headers["retry-after"]) == 60

        for case in others:
            route = f"/collect/{case.source}"
            assert client.post(route, json=payload(scope["engagement_id"], case)).status_code == 200

        clock.now = 59.0
        assert client.post("/collect/ct", json=wire).status_code == 429
        clock.now = 60.0
        assert client.post("/collect/ct", json=wire).status_code == 200
        assert client.post("/collect/ct", json=wire).status_code == 429


def test_upload_slots_are_isolated_and_released(scope: ScopeFixture, cases: tuple[ImportCase, ...]) -> None:
    async def check() -> None:
        ct, dns, *_ = cases
        wire = payload(scope["engagement_id"], ct)
        wire_bytes = json.dumps(wire).encode()
        release = asyncio.Event()
        started = [asyncio.Event() for _ in range(4)]

        async def slow_body(accepted: asyncio.Event) -> AsyncIterator[bytes]:
            # ASGITransport starts consuming the request body after admission.
            accepted.set()
            await release.wait()
            yield wire_bytes

        transport = httpx.ASGITransport(app=create_app())
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            uploads = [asyncio.create_task(client.post("/collect/ct", content=slow_body(event)))
                       for event in started]
            try:
                async with asyncio.timeout(5):
                    await asyncio.gather(*(event.wait() for event in started))
                    denied = await client.post("/collect/ct", json=wire)
                    assert denied.status_code == 429
                    assert denied.headers["retry-after"] == "1"
                    other = await client.post("/collect/dns", json=payload(scope["engagement_id"], dns))
                    assert other.status_code == 200
            finally:
                release.set()
                completed = await asyncio.gather(*uploads)
            assert [response.status_code for response in completed] == [200] * 4
            assert (await client.post("/collect/ct", json=wire)).status_code == 200

    asyncio.run(check())


def test_unknown_source_is_not_dispatched(scope: ScopeFixture, cases: tuple[ImportCase, ...]) -> None:
    with TestClient(create_app()) as client:
        response = client.post("/collect/unknown", json=payload(scope["engagement_id"], cases[0]))
    assert response.status_code == 404


def test_invalid_bodies_return_sanitized_errors(scope: ScopeFixture, cases: tuple[ImportCase, ...]) -> None:
    engagement_id = scope["engagement_id"]
    marker = "synthetic-input-must-not-be-echoed"
    ct, _, github, shodan, storage = cases
    invalid: tuple[tuple[str, dict[str, JsonValue]], ...] = (
        ("ct", {"engagement_id": 2, "records": [ct.record]}),
        ("ct", {**payload(engagement_id, ct), "url": marker}),
        ("github", {"engagement_id": engagement_id, "records": [{**github.record, "content": marker}]}),
        ("shodan", {"engagement_id": engagement_id, "records": [{**shodan.record, "observation_count": True}]}),
        ("storage_names", {"engagement_id": engagement_id, "records": [{**storage.record, "bucket": marker}]}),
    )
    with TestClient(create_app()) as client:
        for source, wire in invalid:
            response = client.post(f"/collect/{source}", json=wire)
            assert response.status_code == 422
            assert marker not in response.text
        malformed = client.post(
            "/collect/ct", content=f'{{"engagement_id":"{marker}",', headers={"Content-Type": "application/json"},
        )
        assert malformed.status_code == 422
        assert marker not in malformed.text


def test_oversized_body_refused_with_and_without_content_length(
    scope: ScopeFixture, cases: tuple[ImportCase, ...],
) -> None:
    wire = json.dumps(payload(scope["engagement_id"], cases[0])).encode()
    padding = b" " * (128 * 1024 + 1 - len(wire))
    headers = {"Content-Type": "application/json"}
    with TestClient(create_app()) as client:
        assert client.post("/collect/ct", content=wire + padding, headers=headers).status_code == 413
        assert client.post("/collect/ct", content=iter((wire, padding)), headers=headers).status_code == 413
