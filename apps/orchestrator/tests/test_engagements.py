"""Live PostgreSQL coverage of draft ownership, state guards, and operator listings."""

import json
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
from pathlib import Path
from time import monotonic, sleep
from uuid import uuid4

import psycopg
from contracts.roe import RoeManifest
from fastapi.testclient import TestClient
from psycopg.types.json import Jsonb

from test_api import client as client, service_urls as service_urls

FIXTURE = Path(__file__).resolve().parents[3] / "tests/fixtures/roe_sample.json"


def manifest_for(owner: str) -> RoeManifest:
    draft = json.loads(FIXTURE.read_bytes())
    draft["engagement_id"] = owner
    draft["traffic_constraints"]["required_attribution_header"] = f"X-Security-Assessment-ID: {owner}"
    return RoeManifest.model_validate(draft)


def test_create_and_replace_manifest(client: TestClient, service_urls: tuple[str, str]) -> None:
    eid = uuid4()
    # Existing signed spellings survive normalization of the database key.
    draft = manifest_for("{" + str(eid).upper() + "}")
    path = f"/engagements/{eid}"
    document = draft.model_dump(mode="json")
    first = client.post("/engagements", json=document)
    assert first.status_code == 201, first.text
    assert first.json() == {
        "engagement_id": str(eid), "manifest_hash": sha256(draft.model_dump_json().encode()).hexdigest(),
    }
    assert client.get(f"{path}/state").json() == {"state": "INIT_SCOPING"}
    for kind in ("tasks", "findings", "plans", "ledger"):
        assert client.get(f"{path}/{kind}").json() == []
    changed = RoeManifest.model_validate({**document, "execution_mode": "MANUAL"})
    with psycopg.connect(service_urls[0]) as db:
        assert db.execute("SELECT roe_manifest, roe_signature_hash FROM engagements WHERE id=%s", (eid,)).fetchone() == (
            document, None,
        )
        # A duplicate POST must preserve the existing draft.
        assert client.post("/engagements", json=changed.model_dump(mode="json")).status_code == 409
        assert db.execute("SELECT roe_manifest FROM engagements WHERE id=%s", (eid,)).fetchone() == (document,)
        db.execute("UPDATE engagements SET roe_signature_hash=%s WHERE id=%s", ("0" * 64, eid))
    updated = client.put(f"{path}/roe", json=changed.model_dump(mode="json"))
    assert updated.status_code == 200, updated.text
    assert updated.json() == {
        "engagement_id": str(eid), "manifest_hash": sha256(changed.model_dump_json().encode()).hexdigest(),
    }
    assert client.put(f"{path}/roe", json=changed.model_dump(mode="json")).json() == updated.json()
    with psycopg.connect(service_urls[0]) as db:
        assert db.execute("SELECT roe_manifest, roe_signature_hash FROM engagements WHERE id=%s", (eid,)).fetchone() == (
            changed.model_dump(mode="json"), None,
        )
    assert client.get(f"{path}/ledger").json() == []


def test_invalid_drafts_and_unknown_engagement(client: TestClient) -> None:
    eid = uuid4()
    path = f"/engagements/{eid}"
    doc = manifest_for(str(eid)).model_dump(mode="json")
    for invalid in (
        {key: value for key, value in doc.items() if key != "signatures"},
        {**doc, "engagement_id": eid.urn},
        {**doc, "current_state": "ROE_LOCKED"},
        {**doc, "scope_boundaries": {**doc["scope_boundaries"], "allowed_identifiers": ["bad\x00name"]}},
    ):
        assert client.post("/engagements", json=invalid).status_code == 422
    assert client.put(f"{path}/roe", json=doc).status_code == 404
    for kind in ("state", "tasks", "findings", "plans"):
        assert client.get(f"{path}/{kind}").status_code == 404
    assert client.post("/engagements", json=doc).status_code == 201
    mismatch = client.put(f"{path}/roe", json={**doc, "engagement_id": str(uuid4())})
    assert mismatch.status_code == 422 and mismatch.json()["reason"] == "ENGAGEMENT_ID_MISMATCH"


def test_unencodable_draft_rejections_preserve_state(client: TestClient, service_urls: tuple[str, str]) -> None:
    eid = uuid4()
    initial = manifest_for(str(eid)).model_dump(mode="json")
    # One surrogate reaches model serialization, the other schema validation.
    # Both requests are valid JSON syntax with escaped ASCII wire bytes.
    invalid_documents = [
        {**initial, "scope_boundaries": {**initial["scope_boundaries"], "allowed_identifiers": ["\ud800"]}},
        {**initial, "extra_field": "\ud800"},
    ]
    path = f"/engagements/{eid}"
    headers = {"Content-Type": "application/json"}
    for method, endpoint in (("POST", "/engagements"), ("PUT", f"{path}/roe")):
        for invalid in invalid_documents:
            response = client.request(method, endpoint, headers=headers, content=json.dumps(invalid).encode("ascii"))
            assert response.status_code == 422 and response.json() == {"reason": "INVALID_MANIFEST"}
        if method == "POST":
            assert client.get(f"{path}/state").status_code == 404
            assert client.post("/engagements", json=initial).status_code == 201
    with psycopg.connect(service_urls[0]) as db:
        assert db.execute(
            "SELECT current_state, roe_manifest, roe_signature_hash FROM engagements WHERE id=%s", (eid,),
        ).fetchone() == ("INIT_SCOPING", initial, None)
    assert client.get(f"{path}/ledger").json() == []


def test_draft_update_cannot_race_past_state_lock(client: TestClient, service_urls: tuple[str, str]) -> None:
    eid = uuid4()
    initial = manifest_for(str(eid)).model_dump(mode="json")
    assert client.post("/engagements", json=initial).status_code == 201
    updated = {**initial, "execution_mode": "MANUAL"}
    with ThreadPoolExecutor(max_workers=1) as executor, psycopg.connect(service_urls[0]) as db:
        # Stand in for the transaction holding the engagement row while locking the RoE.
        db.execute("SELECT id FROM engagements WHERE id=%s FOR UPDATE", (eid,))
        request = executor.submit(client.put, f"/engagements/{eid}/roe", json=updated)
        deadline = monotonic() + 5
        while monotonic() < deadline:
            if db.execute("""
                SELECT EXISTS (SELECT FROM pg_locks WHERE NOT granted
                               AND pg_backend_pid() = ANY(pg_blocking_pids(pid)))
            """).fetchone() == (True,):
                break
            sleep(0.01)
        else:
            raise AssertionError("draft update did not wait for the engagement lock")
        db.execute("UPDATE engagements SET current_state='ROE_LOCKED' WHERE id=%s", (eid,))
        db.commit()
        denied = request.result(timeout=5)
        assert denied.status_code == 409 and denied.json()["reason"] == "STATE_MISMATCH"
        assert db.execute("SELECT roe_manifest FROM engagements WHERE id=%s", (eid,)).fetchone() == (initial,)
    assert client.get(f"/engagements/{eid}/ledger").json() == []


def test_listings_return_only_owned_rows_in_stable_id_order(client: TestClient, service_urls: tuple[str, str]) -> None:
    eid, other = uuid4(), uuid4()
    first_sig = {"signer_id": "one", "signature": "1" * 128}
    second_sig = {"signer_id": "two", "signature": "2" * 128}
    with psycopg.connect(service_urls[0]) as db:
        for owner in (eid, other):
            db.execute("INSERT INTO engagements(id) VALUES (%s)", (owner,))
            for item in ("second", "First"):
                db.execute("INSERT INTO workflow_tasks (engagement_id,id,mode,status) VALUES (%s,%s,%s,%s)",
                           (owner, item, "MANUAL_ONLY", "QUEUED"))
                db.execute("INSERT INTO findings (engagement_id,id,title,confidence_score,cvss_score) "
                           "VALUES (%s,%s,%s,0.89,%s)", (owner, item, item, 7.1 if item == "First" else None))
                # Pre-ADR-0019 textual plan identifiers remain listable.
                db.execute("INSERT INTO validation_plans (engagement_id,id,blast_radius,approver_sig,second_approver_sig) "
                           "VALUES (%s,%s,%s,%s,%s)", (
                               owner, item, "DESTRUCTIVE" if item == "First" else "READ_ONLY",
                               Jsonb(first_sig) if item == "First" else None,
                               Jsonb(second_sig) if item == "First" else None,
                           ))
    expected = {
        "tasks": [
            {"id": i, "engagement_id": str(eid), "mode": "MANUAL_ONLY", "status": "QUEUED"}
            for i in ("First", "second")
        ],
        "findings": [
            {"id": i, "engagement_id": str(eid), "title": i, "confidence_score": 0.89,
             "cvss_score": score, "status": "HYPOTHESIS"}
            for i, score in (("First", 7.1), ("second", None))
        ],
        "plans": [
            {"id": "First", "engagement_id": str(eid), "blast_radius": "DESTRUCTIVE",
             "approver_sig": first_sig, "second_approver_sig": second_sig},
            {"id": "second", "engagement_id": str(eid), "blast_radius": "READ_ONLY",
             "approver_sig": None, "second_approver_sig": None},
        ],
    }
    for endpoint, rows in expected.items():
        for _ in range(2):
            response = client.get(f"/engagements/{eid}/{endpoint}")
            assert response.status_code == 200, response.text
            assert response.json() == rows
    assert client.get(f"/engagements/{eid}/ledger").json() == []
