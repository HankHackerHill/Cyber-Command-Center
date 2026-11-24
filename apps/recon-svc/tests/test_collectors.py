"""Defensive inventory import tests with synthetic, already collected records."""

import json
import socket
from collections.abc import Sequence
from pathlib import Path

import pytest
from contracts.events import ActorType
from contracts.findings import AssetNode
from contracts.roe import RoeManifest
from pydantic import JsonValue

from collectors import Source, import_records

FIXTURE = Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "roe_sample.json"
Record = dict[str, JsonValue]


@pytest.fixture(scope="module")
def roe() -> RoeManifest:
    return RoeManifest.model_validate_json(FIXTURE.read_bytes())


def collect(source: Source, records: Sequence[Record], engagement: str) -> list[AssetNode]:
    return import_records(source, json.dumps({"engagement_id": engagement, "records": records}).encode("utf-8"))


def test_ct_normalizes_names_and_deduplicates_certificate_digests(roe: RoeManifest) -> None:
    host = roe.scope_boundaries.allowed_identifiers[0]
    other = roe.scope_boundaries.allowed_identifiers[1]
    records: list[Record] = [
        {"hostname": other, "certificate_sha256": "c" * 64},
        {"hostname": host.upper() + ".", "certificate_sha256": "B" * 64},
        {"hostname": host, "certificate_sha256": "a" * 64},
        {"hostname": host, "certificate_sha256": "b" * 64},
    ]
    nodes = collect(Source.CT, records, roe.engagement_id)
    assert [node.canonical_identifier for node in nodes] == [host, other]
    assert all(node.asset_category == "dns_name" for node in nodes)
    assert nodes[0].metadata == {"source": "ct", "certificate_sha256": ["a" * 64, "b" * 64]}
    assert nodes[1].metadata == {"source": "ct", "certificate_sha256": ["c" * 64]}
    assert collect(Source.CT, list(reversed(records)), roe.engagement_id) == nodes
    assert collect(Source.CT, records[1:2], roe.engagement_id)[0].id == nodes[0].id


def test_dns_imports_supplied_answers_and_shares_ct_asset_identity(roe: RoeManifest) -> None:
    host, alias = roe.scope_boundaries.allowed_identifiers[:2]
    address = str(next(roe.scope_boundaries.allowed_cidrs[0].hosts()))
    records: list[Record] = [
        {"hostname": host.upper() + ".", "record_type": "AAAA", "value": "2001:DB8:0:0::1"},
        {"hostname": host, "record_type": "A", "value": address},
        {"hostname": host, "record_type": "A", "value": address},
        {"hostname": alias, "record_type": "CNAME", "value": host.upper() + "."},
    ]
    nodes = collect(Source.DNS, records, roe.engagement_id)
    assert [node.canonical_identifier for node in nodes] == [host, alias]
    assert all(node.asset_category == "dns_name" for node in nodes)
    assert nodes[0].metadata == {
        "source": "dns",
        "records": [
            {"record_type": "A", "value": address},
            {"record_type": "AAAA", "value": "2001:db8::1"},
        ],
    }
    assert nodes[1].metadata == {"source": "dns", "records": [{"record_type": "CNAME", "value": host}]}
    ct = collect(Source.CT, [{"hostname": host, "certificate_sha256": "a" * 64}], roe.engagement_id)
    assert ct[0].id == nodes[0].id
    assert collect(Source.DNS, list(reversed(records)), roe.engagement_id) == nodes


def test_github_accepts_reviewed_indicator_labels(roe: RoeManifest) -> None:
    records: list[Record] = [
        {"repository": "Synthetic-Org/Example-App", "indicator": "secret_in_history"},
        {"repository": "synthetic-org/example-app", "indicator": "credential_exposure"},
        {"repository": "synthetic-org/EXAMPLE-APP", "indicator": "secret_in_history"},
    ]
    node, = collect(Source.GITHUB, records, roe.engagement_id)
    assert node.asset_category == "repository"
    assert node.canonical_identifier == "synthetic-org/example-app"
    assert node.metadata == {
        "source": "github",
        "redacted_indicators": ["credential_exposure", "secret_in_history"],
    }
    assert collect(Source.GITHUB, list(reversed(records)), roe.engagement_id) == [node]


def test_shodan_orders_review_priorities_and_keeps_max_count_at_reported_severity(roe: RoeManifest) -> None:
    records: list[Record] = [
        {"asset_ref": "review-low", "severity": "low", "observation_count": 10},
        {"asset_ref": "review-b", "severity": "high", "observation_count": 1},
        {"asset_ref": "review-a", "severity": "medium", "observation_count": 9},
        {"asset_ref": "review-a", "severity": "high", "observation_count": 2},
        {"asset_ref": "review-a", "severity": "high", "observation_count": 3},
        {"asset_ref": "review-a", "severity": "high", "observation_count": 3},
    ]
    nodes = collect(Source.SHODAN, records, roe.engagement_id)
    assert [node.canonical_identifier for node in nodes] == ["review-a", "review-b", "review-low"]
    assert all(node.asset_category == "exposure_review" for node in nodes)
    assert nodes[0].metadata == {"source": "shodan", "severity": "high", "observation_count": 3}
    assert nodes[1].metadata == {"source": "shodan", "severity": "high", "observation_count": 1}
    assert nodes[2].metadata == {"source": "shodan", "severity": "low", "observation_count": 10}
    assert collect(Source.SHODAN, list(reversed(records)), roe.engagement_id) == nodes


def test_storage_imports_classified_naming_patterns(roe: RoeManifest) -> None:
    records: list[Record] = [
        {"asset_ref": "inventory-b", "provider": "gcp", "naming_pattern": "team"},
        {"asset_ref": "inventory-a", "provider": "azure", "naming_pattern": "service"},
        {"asset_ref": "inventory-a", "provider": "aws", "naming_pattern": "environment"},
        {"asset_ref": "inventory-a", "provider": "azure", "naming_pattern": "service"},
    ]
    nodes = collect(Source.STORAGE_NAMES, records, roe.engagement_id)
    assert [node.canonical_identifier for node in nodes] == ["inventory-a", "inventory-b"]
    assert all(node.asset_category == "storage_review" for node in nodes)
    assert nodes[0].metadata == {
        "source": "storage_names",
        "observations": [
            {"provider": "aws", "naming_pattern": "environment"},
            {"provider": "azure", "naming_pattern": "service"},
        ],
    }
    assert nodes[1].metadata == {
        "source": "storage_names", "observations": [{"provider": "gcp", "naming_pattern": "team"}],
    }
    assert collect(Source.STORAGE_NAMES, list(reversed(records)), roe.engagement_id) == nodes


def test_each_collector_stays_offline_and_scopes_node_ids(
    roe: RoeManifest, monkeypatch: pytest.MonkeyPatch,
) -> None:
    host = roe.scope_boundaries.allowed_identifiers[0]
    network = roe.scope_boundaries.allowed_cidrs[0]
    assert str(network) == "198.51.100.0/24"
    records: dict[Source, Record] = {
        Source.CT: {"hostname": host, "certificate_sha256": "a" * 64},
        Source.DNS: {"hostname": host, "record_type": "A", "value": str(next(network.hosts()))},
        Source.GITHUB: {"repository": "synthetic-org/example-app", "indicator": "credential_exposure"},
        Source.SHODAN: {"asset_ref": "review-a", "severity": "high", "observation_count": 1},
        Source.STORAGE_NAMES: {"asset_ref": "inventory-a", "provider": "aws", "naming_pattern": "environment"},
    }
    attempts: list[tuple[object, ...]] = []

    def forbidden_network(*args: object, **kwargs: object) -> None:
        attempts.append(args)
        raise AssertionError(f"Collector attempted network access with fixture range {network}")

    # Prohibit all socket creation and name resolution rather than relying on
    # destination filters that could miss a DNS, UDP or alternate-host attempt.
    with monkeypatch.context() as network_guard:
        network_guard.setattr(socket, "socket", forbidden_network)
        network_guard.setattr(socket, "getaddrinfo", forbidden_network)
        network_guard.setattr(socket, "gethostbyname", forbidden_network)
        network_guard.setattr(socket, "gethostbyname_ex", forbidden_network)
        assert set(records) == set(Source)
        for source, record in records.items():
            node, = collect(source, [record], roe.engagement_id)
            foreign, = collect(source, [record], "eng_other_fixture")
            assert node.engagement_id == roe.engagement_id
            assert foreign.engagement_id == "eng_other_fixture"
            assert node.id.version == 5 and node.id != foreign.id
            assert node.metadata == foreign.metadata
            assert node.canonical_identifier == foreign.canonical_identifier
            assert node.discovered_by is ActorType.SYSTEM
    assert attempts == []


@pytest.mark.parametrize(
    ("source", "record"),
    [
        (Source.CT, {"hostname": "*.example.com", "certificate_sha256": "a" * 64}),
        (Source.CT, {"hostname": "https://api.example.com", "certificate_sha256": "a" * 64}),
        (Source.CT, {"hostname": "api.example.com", "certificate_sha256": "not-a-digest"}),
        (Source.DNS, {"hostname": "api.example.com", "record_type": "AAAA", "value": "198.51.100.1"}),
        (Source.DNS, {"hostname": "api.example.com", "record_type": "AAAA", "value": "2001:db8::1%eth0"}),
        (Source.GITHUB, {"repository": "synthetic-org/example-app", "indicator": "credential_exposure",
                         "snippet": "synthetic secret-like text"}),
        (Source.GITHUB, {"repository": "https://example.com/owner/repo", "indicator": "credential_exposure"}),
        (Source.SHODAN, {"asset_ref": "review-a", "severity": "high", "observation_count": 1,
                         "banner": "synthetic service banner"}),
        (Source.SHODAN, {"asset_ref": "198.51.100.1", "severity": "high", "observation_count": 1}),
        (Source.SHODAN, {"asset_ref": "review-a", "severity": "high", "observation_count": True}),
        (Source.STORAGE_NAMES, {"asset_ref": "inventory-a", "provider": "aws", "naming_pattern": "team",
                                "bucket_name": "synthetic-fixture-name"}),
        (Source.STORAGE_NAMES, {"asset_ref": "inventory-a", "provider": "aws",
                                "naming_pattern": "generated-candidate"}),
    ],
)
def test_collectors_reject_invalid_and_non_review_fields(
    source: Source, record: Record, roe: RoeManifest,
) -> None:
    with pytest.raises(ValueError):
        collect(source, [record], roe.engagement_id)


def test_import_rejects_oversized_or_record_scoped_batch(roe: RoeManifest) -> None:
    record: Record = {"asset_ref": "review-a", "severity": "high", "observation_count": 1}
    with pytest.raises(ValueError):
        collect(Source.SHODAN, [record] * 257, roe.engagement_id)
    with pytest.raises(ValueError):
        collect(Source.SHODAN, [{**record, "engagement_id": "eng_other_fixture"}], roe.engagement_id)
