"""Check Report Studio's M9 contract against a disposable M10 fixture."""

import base64
from hashlib import sha256
import os
from pathlib import Path
import subprocess
from urllib.parse import urlsplit
from uuid import UUID

from pact import Pact, Verifier, match

WEB = Path(__file__).resolve().parents[1]
PROVIDER = "report-service"
PDF = "application/pdf"
DOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
DETAIL = "All findings must be CONFIRMED or FALSE_POSITIVE"
DIGEST = r"^[a-f0-9]{64}$"
TIMESTAMP = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$"

CONSUMER = """
import assert from 'node:assert/strict';
import { renderReport } from './src/api/client.ts';

const [mock, ready, pending] = process.argv.slice(1);
const fetchFromNode = globalThis.fetch;
globalThis.fetch = (path, options) => {
  assert.equal(path, '/api/report/render');
  // Mirror the same-origin Vite rewrite at the service boundary.
  return fetchFromNode(new URL(path.slice('/api/report'.length), mock), options);
};

const report = await renderReport(ready);
assert.equal(report.pdf.filename, `${ready}.pdf`);
assert.equal(report.docx.filename, `${ready}.docx`);
assert.equal(report.ledgerExcerpt.length, 1);
await assert.rejects(renderReport(pending), { status: 409, reason: 'REPORT_FINDINGS_NOT_FINAL' });
"""


def document(owner: str, extension: str, media_type: str, data: bytes) -> dict[str, object]:
    return {
        "filename": f"{owner}.{extension}",
        "media_type": media_type,
        "sha256": match.regex(sha256(data).hexdigest(), regex=DIGEST),
        "content_base64": match.regex(base64.b64encode(data).decode("ascii"), regex=r"^[A-Za-z0-9+/]+={0,2}$"),
    }


def receipt(owner: str) -> dict[str, object]:
    timestamp = "2026-01-01T12:00:00Z"
    return {
        "engagement_id": owner,
        "manifest_hash": match.regex("a" * 64, regex=DIGEST),
        "roe_signature_hash": match.regex("b" * 64, regex=DIGEST),
        "ledger_excerpt": [{
            "seq_id": match.integer(1),
            "prev_record_hash": match.regex("0" * 64, regex=DIGEST),
            "record_hash": match.regex("c" * 64, regex=DIGEST),
            "event": {
                "event_id": match.string("fixture-event"),
                "engagement_id": owner,
                "actor_kind": "SYSTEM",
                "actor_id": "scoped-proxy",
                "event_type": "EVIDENCE_FIXTURE",
                "occurred_at": match.regex(timestamp, regex=TIMESTAMP),
                "payload": {"synthetic": True},
            },
        }],
        "teardown_receipt": {
            "engagement_id": owner,
            "completed_at": match.regex(timestamp, regex=TIMESTAMP),
            "status": "completed",
        },
        "pdf": document(owner, "pdf", PDF, b"%PDF-1.7\n"),
        "docx": document(owner, "docx", DOCX, b"PK\x03\x04"),
    }


def main() -> None:
    origin = os.environ["M10_REPORT_URL"]
    url = urlsplit(origin)
    if url.scheme != "http" or url.netloc != f"127.0.0.1:{url.port}" or url.path or url.query or url.fragment:
        raise ValueError("M10_REPORT_URL must be the disposable report service's loopback origin")
    ready = str(UUID(os.environ["M10_REPORT_ID"]))
    pending = str(UUID(os.environ["M10_REVIEW_ID"]))
    output = Path(os.environ["M10_PACT_OUTPUT"])
    output.mkdir(parents=True, exist_ok=True)

    pact = Pact("report-studio", PROVIDER).with_specification("V4")
    outcomes: list[tuple[str, str, int, dict[str, object]]] = [
        ("render a finalized engagement", ready, 200, receipt(ready)),
        ("reject an engagement with non-final findings", pending, 409, {"detail": DETAIL}),
    ]
    for description, engagement, status, body in outcomes:
        interaction = (pact.upon_receiving(description)
                       .with_request("POST", "/render")
                       .with_header("Accept", "application/json")
                       .with_body({"engagement_id": engagement}, content_type="application/json")
                       .will_respond_with(status)
                       .with_body(body, content_type="application/json"))
        if status == 200:
            interaction.with_header("Cache-Control", "no-store")

    with pact.serve(addr="127.0.0.1") as server:
        subprocess.run(["node", "--experimental-transform-types", "--input-type=module", "--eval", CONSUMER,
                        "--", str(server.url), ready, pending], cwd=WEB, check=True, timeout=90)
    pact.write_file(output, overwrite=True)

    (Verifier(PROVIDER, host="127.0.0.1")
     .add_transport(url=origin)
     .add_source(output / f"report-studio-{PROVIDER}.json")
     .set_error_on_empty_pact()
     .set_request_timeout(60_000)
     .verify())


if __name__ == "__main__":
    main()
