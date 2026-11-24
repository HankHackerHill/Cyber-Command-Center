import hashlib
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from uuid import UUID

import psycopg
import pytest
from fastapi.testclient import TestClient

from main import create_app
from test_ledger_link import migrated_database, seed_ledger


HAR = Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "har_sample.har"
OCTETS = {"Content-Type": "application/octet-stream"}


@pytest.fixture
def client(tmp_path: Path, migrated_database: str) -> Iterator[TestClient]:
    with TestClient(create_app(root=tmp_path, database_url=migrated_database)) as service:
        yield service


def artifact_reference(data: bytes) -> dict[str, str]:
    digest = hashlib.sha256(data).hexdigest()
    return {"sha256": digest, "url": f"/artifacts/{digest}"}


def status(database: str, engagement_id: UUID, finding_id: str) -> str:
    with psycopg.connect(database) as conn:
        result = conn.execute(
            "SELECT status::text FROM findings WHERE engagement_id = %s AND id = %s",
            (engagement_id, finding_id),
        ).fetchone()
        assert result is not None
        return str(result[0])


def test_rust_consumer_put_and_stable_har_url(client: TestClient) -> None:
    raw = HAR.read_bytes()
    reference = artifact_reference(raw)
    # EvidenceClient sends raw bytes, with Content-Type as its only application header.
    for expected_status in (201, 200):
        upload = client.put("/artifacts", content=raw, headers=OCTETS, follow_redirects=False)
        assert upload.status_code == expected_status, upload.text
        assert upload.json() == reference
        download = client.get(reference["url"], follow_redirects=False)
        assert download.status_code == 200
        assert download.content == raw
    missing = artifact_reference(b"never uploaded")
    assert client.get(missing["url"]).status_code == 404


def test_concurrent_duplicate_puts_publish_one_new_object(client: TestClient) -> None:
    raw = b"\xff\x00\r\nopaque fixture bytes"
    reference = artifact_reference(raw)

    def upload(_: int) -> int:
        response = client.put("/artifacts", content=raw, headers=OCTETS)
        assert response.json() == reference
        return int(response.status_code)

    with ThreadPoolExecutor(max_workers=4) as workers:
        statuses = sorted(workers.map(upload, range(8)))
    assert statuses == [200] * 7 + [201]
    assert client.get(reference["url"]).content == raw


def test_invalid_link_values_return_422_without_echoing_input(client: TestClient) -> None:
    for finding_json in (br'"private-marker-\ud800"', b"NaN"):
        body = (b'{"finding_id":' + finding_json + b',"sha256":"' + b"1" * 64
                + b'","record_hash":"' + b"2" * 64 + b'"}')
        response = client.post("/link", content=body, headers={"Content-Type": "application/json"})
        assert response.status_code == 422
        assert response.json() == {"detail": "Invalid evidence request"}


def test_link_and_verify_never_promote_finding(
    client: TestClient, migrated_database: str, tmp_path: Path
) -> None:
    seed = seed_ledger(migrated_database)
    finding_url = f"/findings/{seed.finding_id}"
    original = status(migrated_database, seed.engagement_id, seed.finding_id)
    assert original == "HYPOTHESIS"
    listing = client.get(f"{finding_url}/evidence")
    assert listing.status_code == 200 and listing.json() == []
    before = client.post(f"{finding_url}/verify-evidence")
    assert before.status_code == 200 and before.json() == {"ok": False}
    assert status(migrated_database, seed.engagement_id, seed.finding_id) == original

    raw = HAR.read_bytes()
    reference = artifact_reference(raw)
    assert client.put("/artifacts", content=raw, headers=OCTETS).status_code == 201
    link = {"finding_id": seed.finding_id, "sha256": reference["sha256"],
            "record_hash": seed.transition_hash}
    for _ in range(2):
        response = client.post("/link", json=link)
        assert response.status_code == 200, response.text
        assert status(migrated_database, seed.engagement_id, seed.finding_id) == original

    # A fresh application using the same storage must see the committed evidence.
    with TestClient(create_app(root=tmp_path, database_url=migrated_database)) as reopened:
        listing = reopened.get(f"{finding_url}/evidence")
        assert listing.status_code == 200 and listing.json() == [reference]
        assert reopened.get(reference["url"]).content == raw
        verified = reopened.post(f"{finding_url}/verify-evidence")
        assert verified.status_code == 200 and verified.json() == {"ok": True}
    assert status(migrated_database, seed.engagement_id, seed.finding_id) == original


def test_unknown_and_cross_engagement_references_create_no_link(
    client: TestClient, migrated_database: str,
) -> None:
    seed = seed_ledger(migrated_database, "F-local")
    foreign = seed_ledger(migrated_database, "F-other")
    raw = HAR.read_bytes()
    digest = artifact_reference(raw)["sha256"]
    assert client.put("/artifacts", content=raw, headers=OCTETS).status_code == 201
    valid = {"finding_id": seed.finding_id, "engagement_id": str(seed.engagement_id),
             "sha256": digest, "record_hash": seed.audit_hash}
    for change in (
        {"finding_id": "unknown"}, {"sha256": "0" * 64}, {"record_hash": "f" * 64},
        {"record_hash": foreign.audit_hash}, {"engagement_id": str(foreign.engagement_id)},
    ):
        response = client.post("/link", json=valid | change)
        assert response.status_code == 404, (change, response.text)
    for item in (seed, foreign):
        url = f"/findings/{item.finding_id}"
        assert client.get(f"{url}/evidence").json() == []
        assert client.post(f"{url}/verify-evidence").json() == {"ok": False}
        assert status(migrated_database, item.engagement_id, item.finding_id) == "HYPOTHESIS"


def test_record_hash_scopes_link_and_ambiguous_finding_reads_require_scope(
    client: TestClient, migrated_database: str,
) -> None:
    first = seed_ledger(migrated_database, "F-shared")
    second = seed_ledger(migrated_database, "F-shared")
    raw = HAR.read_bytes()
    reference = artifact_reference(raw)
    assert client.put("/artifacts", content=raw, headers=OCTETS).status_code == 201
    link = {"finding_id": first.finding_id, "sha256": reference["sha256"],
            "record_hash": first.audit_hash}
    url = f"/findings/{first.finding_id}"
    assert client.get(f"{url}/evidence").status_code == 409
    assert client.post(f"{url}/verify-evidence").status_code == 409
    inferred = client.post("/link", json=link)
    assert inferred.status_code == 200, inferred.text
    accepted = client.post("/link", json=link | {"engagement_id": str(first.engagement_id)})
    assert accepted.status_code == 200, accepted.text
    for seed, expected in ((first, [reference]), (second, [])):
        scope = {"engagement_id": str(seed.engagement_id)}
        listing = client.get(f"{url}/evidence", params=scope)
        assert listing.status_code == 200 and listing.json() == expected
        verification = client.post(f"{url}/verify-evidence", params=scope)
        assert verification.status_code == 200 and verification.json() == {"ok": bool(expected)}
        assert status(migrated_database, seed.engagement_id, seed.finding_id) == "HYPOTHESIS"
