"""Read-only reporting API for the internal service network.

Run uvicorn main:app with ORCHESTRATOR_URL, EVIDENCE_URL, REPORT_WORKSPACE_ROOT
and ORCHESTRATOR_OPERATOR_PUBLIC_KEYS (operator ID to raw Ed25519 public-key hex).
Mount a trusted, read-only finalization directory at REPORT_WORKSPACE_ROOT/<UUID>.
Publish the finalized workspace as an immutable directory. manifest.json holds the signed frozen
RoeManifest. teardown.json is the workspace operator's attestation with engagement_id,
status "completed", completed_at (timezone required), and optional workspace_id.
Optional report.json carries engagement_id, a findings map keyed by actual finding
ID (cvss_vector, cwe, reproduction_steps, remediation), and attack_narratives.
The workspace publisher selects the final signed manifest and supplies the
reviewed notes and teardown attestation. M2 supplies finding identities/statuses
and the ledger. Its lock event carries no manifest digest. M7 supplies verified
evidence links. The API only accepts an engagement ID and section names.
"""

import base64
import json
import os
from collections.abc import Mapping, Sequence
from hashlib import sha256
from pathlib import Path
from typing import Literal, TypeVar
from urllib.parse import quote
from uuid import UUID

import httpx
from contracts.events import TransitionEvent
from contracts.findings import Finding, FindingStatus
from contracts.ledger import LedgerRecord
from contracts.roe import RoeManifest, Sha256Hex
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import FastAPI, HTTPException, Response
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, TypeAdapter, ValidationError

from mappers.cvss4 import score_vector
from mappers.cwe import lookup_cwe
from mappers.frameworks import map_frameworks
from render import ReportData, ReportFinding, Section, render_report

# M2's ledger is a single ordered response. Bound reads before parsing them.
MAX_SOURCE_BYTES = 64 * 1024 * 1024
EXCERPT_LENGTH = 25
FINAL_STATUSES = {FindingStatus.CONFIRMED, FindingStatus.FALSE_POSITIVE}
T = TypeVar("T", bound=BaseModel)


class Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class RenderRequest(Model):
    engagement_id: UUID
    sections: tuple[Section, ...] = Field(default=tuple(Section), min_length=1)


class TeardownReceipt(Model):
    engagement_id: UUID
    completed_at: AwareDatetime
    status: Literal["completed"]
    workspace_id: str | None = Field(default=None, min_length=1)


class ReviewedFinding(Model):
    cvss_vector: str | None = None
    cwe: str | None = Field(default=None, pattern=r"^CWE-[1-9][0-9]*$")
    reproduction_steps: tuple[str, ...] = ()
    remediation: str | None = None


class Review(Model):
    engagement_id: UUID
    findings: dict[str, ReviewedFinding] = Field(default_factory=dict)
    attack_narratives: tuple[str, ...] = ()


class EvidenceLink(Model):
    sha256: Sha256Hex
    url: str


class Document(Model):
    filename: str
    media_type: str
    sha256: Sha256Hex
    content_base64: str


class ReportResponse(Model):
    engagement_id: UUID
    manifest_hash: Sha256Hex
    roe_signature_hash: Sha256Hex
    ledger_excerpt: tuple[LedgerRecord, ...]
    teardown_receipt: TeardownReceipt
    pdf: Document
    docx: Document


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def read_workspace(path: Path, model: type[T]) -> T:
    try:
        with path.open("rb") as file:
            content = file.read(MAX_SOURCE_BYTES + 1)
        if len(content) > MAX_SOURCE_BYTES:
            raise ValueError("oversized workspace input")
        return model.model_validate_json(content)
    except FileNotFoundError:
        raise
    except OSError:
        raise HTTPException(503, "Report workspace unavailable") from None
    except ValueError:
        raise HTTPException(409, f"Invalid report input: {path.name}") from None


def configured_keys() -> tuple[Ed25519PublicKey, ...]:
    # Match M2's all-or-nothing parsing of the shared operator trust store.
    def decode(entries: list[tuple[str, object]]) -> dict[str, Ed25519PublicKey]:
        keys: dict[str, Ed25519PublicKey] = {}
        for signer, value in entries:
            if not signer.strip() or signer in keys or not isinstance(value, str) or len(value) != 64:
                raise ValueError
            keys[signer] = Ed25519PublicKey.from_public_bytes(bytes.fromhex(value))
        return keys

    try:
        entries: object = json.loads(os.environ.get("ORCHESTRATOR_OPERATOR_PUBLIC_KEYS", "{}"), object_pairs_hook=decode)
        if not isinstance(entries, dict):
            raise ValueError
        return tuple(entries.values())
    except (ValueError, RecursionError):
        raise HTTPException(503, "Invalid operator key configuration") from None


def verify_manifest(manifest: RoeManifest, owner: UUID, keys: Sequence[Ed25519PublicKey]) -> tuple[str, str]:
    try:
        matches = UUID(manifest.engagement_id) == owner
    except ValueError:
        matches = False
    if not matches:
        raise HTTPException(409, "Scope manifest belongs to a different engagement")
    if not keys:
        raise HTTPException(503, "Operator trust store unavailable")
    unsigned = canonical(manifest.model_dump(mode="json", exclude={"signatures"}))
    signature = bytes.fromhex(manifest.signatures.lead_operator_sig.removeprefix("ed25519:"))
    for key in keys:
        try:
            key.verify(signature, unsigned)
        except InvalidSignature:
            continue
        return sha256(manifest.model_dump_json().encode()).hexdigest(), sha256(signature).hexdigest()
    raise HTTPException(409, "Scope manifest signature verification failed")


def verified_excerpt(records: Sequence[LedgerRecord], owner: UUID) -> tuple[LedgerRecord, ...]:
    if not records:
        raise HTTPException(409, "A ledger excerpt is required")
    previous, sequence = "0" * 64, 0
    for record in records:
        event = record.event
        try:
            event_owner = UUID(event.engagement_id) if isinstance(event, TransitionEvent) else event.engagement_id
        except ValueError:
            event_owner = None
        digest = sha256(bytes.fromhex(previous) + canonical(event.model_dump(mode="json"))).hexdigest()
        if (event_owner != owner or record.seq_id <= sequence or record.prev_record_hash != previous
                or record.record_hash != digest):
            raise HTTPException(502, "Orchestrator ledger integrity check failed")
        previous, sequence = digest, record.seq_id
    return tuple(records[-EXCERPT_LENGTH:])


def get_rows(client: httpx.Client, url: str, model: type[T], *, engagement_lookup: bool = False) -> list[T]:
    try:
        with client.stream("GET", url, headers={"Accept": "application/json"}) as response:
            if engagement_lookup and response.status_code == 404:
                raise HTTPException(404, "Engagement not found")
            if response.status_code != 200:
                raise HTTPException(502, "Reporting source returned an unsuccessful response")
            raw = bytearray()
            for chunk in response.iter_bytes():
                if len(raw) + len(chunk) > MAX_SOURCE_BYTES:
                    raise HTTPException(502, "Reporting source exceeded the supported response size")
                raw.extend(chunk)
        entries = TypeAdapter(list[object]).validate_json(bytes(raw))
        return [model.model_validate(entry) for entry in entries]
    except (httpx.HTTPError, httpx.InvalidURL):
        raise HTTPException(502, "Reporting source unavailable") from None
    except ValidationError:
        raise HTTPException(502, "Invalid reporting source data") from None


def report_finding(finding: Finding, notes: ReviewedFinding, evidence: str, client: httpx.Client) -> ReportFinding:
    if finding.id in ("", ".", ".."):
        raise HTTPException(502, "Finding ID cannot be represented by the evidence endpoint")
    encoded = quote(finding.id, safe="")
    url = f"{evidence}/findings/{encoded}/evidence?engagement_id={finding.engagement_id}"
    links = get_rows(client, url, EvidenceLink)
    if any(link.url != f"/artifacts/{link.sha256}" for link in links):
        raise HTTPException(502, "Invalid evidence artifact reference")
    try:
        score = score_vector(notes.cvss_vector) if notes.cvss_vector is not None else None
    except ValueError:
        raise HTTPException(409, "Invalid reviewed CVSS v4 vector") from None
    name = lookup_cwe(notes.cwe) if notes.cwe else None
    return ReportFinding(
        id=finding.id, title=finding.title, status=finding.status.value, cvss_vector=notes.cvss_vector,
        cvss_score=score, cwe=f"{notes.cwe} — {name}" if name else notes.cwe,
        framework_mappings=map_frameworks(notes.cwe) if notes.cwe else (),
        evidence_links=tuple(sorted({link.url for link in links})),
        reproduction_steps=notes.reproduction_steps, remediation=notes.remediation,
    )


def document(owner: UUID, extension: str, media_type: str, data: bytes) -> Document:
    return Document(filename=f"{owner}.{extension}", media_type=media_type, sha256=sha256(data).hexdigest(),
                    content_base64=base64.b64encode(data).decode("ascii"))


def create_app(
    *, workspace_root: Path | None = None, orchestrator_url: str | None = None, evidence_url: str | None = None,
    public_keys: Mapping[str, Ed25519PublicKey] | None = None, transport: httpx.BaseTransport | None = None,
) -> FastAPI:
    app = FastAPI(title="RedOps report service")
    root = workspace_root or os.getenv("REPORT_WORKSPACE_ROOT")
    orchestrator = (orchestrator_url or os.getenv("ORCHESTRATOR_URL") or "").rstrip("/")
    evidence = (evidence_url or os.getenv("EVIDENCE_URL") or "").rstrip("/")

    @app.post("/render", response_model_by_alias=False)
    def render(body: RenderRequest, response: Response) -> ReportResponse:
        """Return both artifacts as Base64 with content digests and their report provenance."""
        if not root or not orchestrator or not evidence:
            raise HTTPException(503, "Report sources are not configured")
        owner = body.engagement_id
        directory = Path(root) / str(owner)
        with httpx.Client(transport=transport, timeout=10, follow_redirects=False, trust_env=False) as client:
            findings_url = f"{orchestrator}/engagements/{owner}/findings"
            findings = get_rows(client, findings_url, Finding, engagement_lookup=True)
            ids = {finding.id for finding in findings}
            if len(ids) != len(findings) or any(f.engagement_id != str(owner) for f in findings):
                raise HTTPException(502, "Invalid finding identity in orchestrator response")
            if any(f.status not in FINAL_STATUSES for f in findings):
                raise HTTPException(409, "All findings must be CONFIRMED or FALSE_POSITIVE")
            records = get_rows(client, f"{orchestrator}/engagements/{owner}/ledger?since=0", LedgerRecord)
            excerpt = verified_excerpt(records, owner)
            try:
                manifest = read_workspace(directory / "manifest.json", RoeManifest)
                teardown = read_workspace(directory / "teardown.json", TeardownReceipt)
            except FileNotFoundError as exc:
                raise HTTPException(409, f"Required report input missing: {Path(str(exc.filename)).name}") from None
            if teardown.engagement_id != owner:
                raise HTTPException(409, "Teardown receipt belongs to a different engagement")
            keys = configured_keys() if public_keys is None else tuple(public_keys.values())
            manifest_hash, signature_hash = verify_manifest(manifest, owner, keys)
            try:
                review = read_workspace(directory / "report.json", Review)
            except FileNotFoundError:
                review = Review(engagement_id=owner)
            if review.engagement_id != owner or not review.findings.keys() <= ids:
                raise HTTPException(409, "Review refers to another engagement or an unknown finding")
            rows = tuple(report_finding(f, review.findings.get(f.id, ReviewedFinding()), evidence, client)
                         for f in sorted(findings, key=lambda record: record.id))
            data = ReportData(
                engagement_id=str(owner), manifest_hash=manifest_hash, roe_signature_hash=signature_hash,
                manifest_json=canonical(manifest.model_dump(mode="json")).decode(),
                ledger_excerpt_json=canonical([r.model_dump(mode="json") for r in excerpt]).decode(),
                teardown_receipt_json=canonical(teardown.model_dump(mode="json")).decode(),
                findings=rows, attack_narratives=review.attack_narratives,
            )
            artifacts = render_report(data, body.sections)
            # M2 and M7 provide independent reads. Refuse to release a report if
            # the authoritative finding set changed while gathering or rendering it.
            latest = get_rows(client, findings_url, Finding, engagement_lookup=True)
            if latest != findings:
                raise HTTPException(409, "Findings changed during rendering. Review and retry.")
        response.headers["Cache-Control"] = "no-store"
        return ReportResponse(
            engagement_id=owner, manifest_hash=manifest_hash, roe_signature_hash=signature_hash,
            ledger_excerpt=excerpt, teardown_receipt=teardown,
            pdf=document(owner, "pdf", "application/pdf", artifacts.pdf),
            docx=document(owner, "docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                          artifacts.docx),
        )

    return app


app = create_app()
