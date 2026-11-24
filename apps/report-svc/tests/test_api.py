"""HTTP boundary tests with the frozen M2/M7 responses and real document generation."""

import base64
import hashlib
import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from io import BytesIO
from pathlib import Path
from uuid import UUID
from zipfile import ZipFile

import httpx
import pytest
from contracts.roe import RoeManifest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from pypdf import PdfReader

from main import create_app

OWNER = UUID("1cabb07a-a07f-438e-b1e6-1d770aa51bae")
OTHER = UUID("edf5d99e-9eee-4291-b1cc-fa79522ca8fe")
FINDING = "review-27"
DIGEST = hashlib.sha256(b"stored synthetic evidence").hexdigest()
FINDINGS_PATH = f"/engagements/{OWNER}/findings"
LEDGER_PATH = f"/engagements/{OWNER}/ledger"
EVIDENCE_PATH = f"/findings/{FINDING}/evidence"
SAMPLE = Path(__file__).resolve().parents[3] / "tests/fixtures/roe_sample.json"
SECTIONS = [
    "cover", "executive_summary", "methodology", "findings",
    "finding_details", "attack_narratives", "remediation", "appendix",
]


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def ledger_rows(key: Ed25519PrivateKey) -> list[dict[str, object]]:
    # Genuine pre-ADR-0019 wire shape. Sequence numbers are global, so gaps are legal.
    lock: dict[str, object] = {
        "event_id": "archived-lock", "engagement_id": str(OWNER), "from_state": "INIT_SCOPING",
        "to_state": "ROE_LOCKED", "actor_type": "HUMAN_OPERATOR", "actor_id": "lead-op",
        "occurred_at": "2026-03-02T09:00:00Z",
    }
    lock["hitl_signature"] = {"signer_id": "lead-op", "signature": key.sign(canonical(lock)).hex()}
    audit: dict[str, object] = {
        "event_id": "02ee1587-fa9b-4d93-b6fe-b6521390e570", "engagement_id": str(OWNER),
        "actor_kind": "SYSTEM", "actor_id": "scoped-proxy", "event_type": "EVIDENCE_LINK_REVIEW",
        "occurred_at": "2026-03-02T09:01:00Z", "payload": {"label": "Reviewed café evidence"},
    }
    previous = "0" * 64
    rows: list[dict[str, object]] = []
    for sequence, event in ((4, lock), (9, audit)):
        digest = hashlib.sha256(bytes.fromhex(previous) + canonical(event)).hexdigest()
        rows.append({"seq_id": sequence, "event": event, "prev_record_hash": previous, "record_hash": digest})
        previous = digest
    return rows


@dataclass
class SourceFixture:
    workspace: Path
    key: Ed25519PrivateKey
    manifest: RoeManifest
    findings: list[dict[str, object]]
    ledger: list[dict[str, object]]
    evidence: list[dict[str, str]]
    next_findings: list[dict[str, object]] | None = None
    overrides: dict[str, httpx.Response] = field(default_factory=dict)
    requests: list[httpx.Request] = field(default_factory=list)

    def upstream(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        assert request.method == "GET"
        if request.url.path in self.overrides:
            return self.overrides[request.url.path]
        if request.url.host == "m2.test" and request.url.path == FINDINGS_PATH:
            response = httpx.Response(200, json=self.findings)
            if self.next_findings is not None:
                self.findings = self.next_findings
                self.next_findings = None
            return response
        if request.url.host == "m2.test" and request.url.path == LEDGER_PATH:
            assert request.url.params.get("since", "0") == "0"
            return httpx.Response(200, json=self.ledger)
        if request.url.host == "m7.test" and request.url.path == EVIDENCE_PATH:
            assert request.url.params.get("engagement_id") == str(OWNER)
            return httpx.Response(200, json=self.evidence)
        pytest.fail(f"Unexpected service request {request.method} {request.url}")

    def client(self) -> TestClient:
        return TestClient(create_app(
            workspace_root=self.workspace.parent, orchestrator_url="http://m2.test",
            evidence_url="http://m7.test", public_keys={"lead-op": self.key.public_key()},
            transport=httpx.MockTransport(self.upstream),
        ))


@pytest.fixture
def source(tmp_path: Path) -> SourceFixture:
    directory = tmp_path / str(OWNER)
    directory.mkdir()
    key = Ed25519PrivateKey.generate()
    data = json.loads(SAMPLE.read_bytes())
    data["engagement_id"] = str(OWNER)
    data["traffic_constraints"]["required_attribution_header"] = f"X-Security-Assessment-ID: {OWNER}"
    data["signatures"]["lead_operator_sig"] = "ed25519:" + "0" * 128
    draft = RoeManifest.model_validate_json(json.dumps(data), strict=True)
    signature = key.sign(canonical(draft.model_dump(mode="json", exclude={"signatures"})))
    data["signatures"]["lead_operator_sig"] = f"ed25519:{signature.hex()}"
    manifest = RoeManifest.model_validate_json(json.dumps(data), strict=True)
    (directory / "manifest.json").write_text(manifest.model_dump_json(), encoding="utf-8")
    (directory / "teardown.json").write_bytes(canonical({
        "engagement_id": str(OWNER), "status": "completed",
        "completed_at": "2026-03-02T12:00:00Z", "workspace_id": "review-workspace-12",
    }))
    (directory / "report.json").write_bytes(canonical({
        "engagement_id": str(OWNER), "findings": {
            FINDING: {"cwe": "CWE-79",
                      "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                      "reproduction_steps": ["Review the timestamped evidence screenshot."],
                      "remediation": "Apply the approved output encoding change."},
        }, "attack_narratives": ["The reviewed evidence connects the two recorded observations."],
    }))
    return SourceFixture(
        directory, key, manifest,
        [{"id": FINDING, "engagement_id": str(OWNER), "title": "Recorded review finding",
          "confidence_score": 0.92, "cvss_score": None, "status": "CONFIRMED"}],
        ledger_rows(key), [{"sha256": DIGEST, "url": f"/artifacts/{DIGEST}"}],
    )


@pytest.fixture
def client(source: SourceFixture) -> Iterator[TestClient]:
    with source.client() as connected:
        yield connected


def render(client: TestClient, sections: list[str] | None = None) -> httpx.Response:
    response = client.post("/render", json={"engagement_id": str(OWNER), "sections": SECTIONS if sections is None else sections})
    assert isinstance(response, httpx.Response)
    return response


def assert_refused(response: httpx.Response, status: int) -> None:
    assert response.status_code == status, response.text[:2048]
    payload = response.json()
    assert "pdf" not in payload and "docx" not in payload
    assert "content_base64" not in response.text


def test_http_render_provenance_and_real_documents(source: SourceFixture, client: TestClient) -> None:
    response = render(client)
    assert response.status_code == 200, response.text[:2048]
    result = response.json()
    assert result["engagement_id"] == str(OWNER)
    assert result["manifest_hash"] == hashlib.sha256(source.manifest.model_dump_json().encode()).hexdigest()
    signature = bytes.fromhex(source.manifest.signatures.lead_operator_sig.removeprefix("ed25519:"))
    assert result["roe_signature_hash"] == hashlib.sha256(signature).hexdigest()
    assert [record["record_hash"] for record in result["ledger_excerpt"]] == [row["record_hash"] for row in source.ledger]
    assert result["teardown_receipt"]["workspace_id"] == "review-workspace-12"
    expected_media = {"pdf": "application/pdf",
                      "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document"}
    for extension, media_type in expected_media.items():
        document = result[extension]
        assert document["media_type"] == media_type
        assert document["filename"].endswith("." + extension)
        contents = base64.b64decode(document["content_base64"], validate=True)
        assert hashlib.sha256(contents).hexdigest() == document["sha256"]
        if extension == "pdf":
            pdf_text = " ".join(page.extract_text() for page in PdfReader(BytesIO(contents)).pages)
            assert "Recorded review finding" in " ".join(pdf_text.split())
        else:
            with ZipFile(BytesIO(contents)) as archive:
                assert b"Recorded review finding" in archive.read("word/document.xml")
    assert {request.url.path for request in source.requests} == {FINDINGS_PATH, LEDGER_PATH, EVIDENCE_PATH}


@pytest.mark.parametrize("status", ["HYPOTHESIS", "PENDING_VALIDATION", "REMEDIATED"])
def test_any_ineligible_finding_blocks_every_section(source: SourceFixture, client: TestClient, status: str) -> None:
    source.findings.append({**source.findings[0], "id": "second-finding", "status": status})
    assert_refused(render(client, ["cover"]), 409)


def test_false_positive_is_eligible(source: SourceFixture, client: TestClient) -> None:
    source.findings[0]["status"] = "FALSE_POSITIVE"
    response = render(client, ["appendix"])
    assert response.status_code == 200, response.text[:2048]


def test_late_hypothesis_during_render_prevents_release(source: SourceFixture, client: TestClient) -> None:
    source.next_findings = [*source.findings, {**source.findings[0], "id": "new-observation", "status": "HYPOTHESIS"}]
    assert_refused(render(client, ["appendix"]), 409)
    assert sum(request.url.path == FINDINGS_PATH for request in source.requests) >= 2


def test_clean_assessment_without_findings_or_review_notes(source: SourceFixture, client: TestClient) -> None:
    source.findings.clear()
    (source.workspace / "report.json").unlink()
    response = render(client, ["executive_summary"])
    assert response.status_code == 200, response.text[:2048]
    assert all(request.url.host != "m7.test" for request in source.requests)


@pytest.mark.parametrize("missing", ["ledger_excerpt", "teardown"])
def test_mandatory_evidence_cannot_be_omitted_by_section_selection(
    source: SourceFixture, client: TestClient, missing: str,
) -> None:
    if missing == "ledger_excerpt":
        source.ledger.clear()
    else:
        (source.workspace / "teardown.json").unlink()
    assert_refused(render(client, ["findings"]), 409)


def test_request_cannot_supply_report_provenance_or_status(client: TestClient) -> None:
    body = {"engagement_id": str(OWNER), "sections": ["cover"], "findings": [],
            "teardown_receipt": {"status": "completed"}, "ledger_excerpt": []}
    assert_refused(client.post("/render", json=body), 422)


def test_unknown_section_rejected(client: TestClient) -> None:
    assert_refused(render(client, ["not-a-section"]), 422)


@pytest.mark.parametrize("mismatch", ["finding_owner", "ledger_digest", "chain_link", "seq_order", "evidence_url"])
def test_corrupt_or_cross_engagement_sources_fail_closed(
    source: SourceFixture, client: TestClient, mismatch: str,
) -> None:
    if mismatch == "finding_owner":
        source.findings[0]["engagement_id"] = str(OTHER)
    elif mismatch == "ledger_digest":
        source.ledger[0]["record_hash"] = "a" * 64
    elif mismatch == "chain_link":
        source.ledger[1]["prev_record_hash"] = "0" * 64
    elif mismatch == "seq_order":
        source.ledger[1]["seq_id"] = 3
    else:
        source.evidence[0]["url"] = "https://untrusted.invalid/artifacts/" + DIGEST
    assert_refused(render(client), 502)


def test_tampered_manifest_refuses_output(source: SourceFixture, client: TestClient) -> None:
    data = json.loads((source.workspace / "manifest.json").read_bytes())
    data["traffic_constraints"]["max_requests_per_second"] += 1
    (source.workspace / "manifest.json").write_bytes(canonical(data))
    response = render(client)
    assert 400 <= response.status_code < 500
    assert "content_base64" not in response.text


def test_missing_manifest_trust_store_fails_closed(source: SourceFixture) -> None:
    app = create_app(workspace_root=source.workspace.parent, orchestrator_url="http://m2.test",
                     evidence_url="http://m7.test", public_keys={}, transport=httpx.MockTransport(source.upstream))
    with TestClient(app) as connected:
        assert_refused(render(connected), 503)


def test_duplicate_operator_key_rejects_the_entire_trust_store(
    source: SourceFixture, monkeypatch: pytest.MonkeyPatch,
) -> None:
    valid = source.key.public_key().public_bytes_raw().hex()
    other = Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
    # A permissive last-key-wins decoder would verify the signed fixture here.
    monkeypatch.setenv("ORCHESTRATOR_OPERATOR_PUBLIC_KEYS", f'{{"lead-op":"{other}","lead-op":"{valid}"}}')
    app = create_app(workspace_root=source.workspace.parent, orchestrator_url="http://m2.test",
                     evidence_url="http://m7.test", transport=httpx.MockTransport(source.upstream))
    with TestClient(app) as connected:
        assert_refused(render(connected), 503)


def test_foreign_teardown_refuses_output(source: SourceFixture, client: TestClient) -> None:
    receipt = source.workspace / "teardown.json"
    data = json.loads(receipt.read_bytes())
    data["engagement_id"] = str(OTHER)
    receipt.write_bytes(canonical(data))
    response = render(client)
    assert 400 <= response.status_code < 500
    assert "content_base64" not in response.text


def test_teardown_in_progress_is_not_a_completion_receipt(source: SourceFixture, client: TestClient) -> None:
    receipt = source.workspace / "teardown.json"
    data = json.loads(receipt.read_bytes())
    data["status"] = "in_progress"
    receipt.write_bytes(canonical(data))
    assert_refused(render(client), 409)


def test_upstream_redirect_blocks_release(source: SourceFixture, client: TestClient) -> None:
    source.overrides[EVIDENCE_PATH] = httpx.Response(307, headers={"Location": "https://untrusted.invalid/receipt"})
    assert_refused(render(client), 502)
    assert all(request.url.host in {"m2.test", "m7.test"} for request in source.requests)


def test_failed_dependency_never_emits_a_report(source: SourceFixture, client: TestClient) -> None:
    source.overrides[LEDGER_PATH] = httpx.Response(200, content=b"{", headers={"Content-Type": "application/json"})
    assert_refused(render(client), 502)


def test_orchestrator_unknown_engagement(source: SourceFixture, client: TestClient) -> None:
    source.overrides[FINDINGS_PATH] = httpx.Response(404, json={"reason": "ENGAGEMENT_NOT_FOUND"})
    assert_refused(render(client), 404)
