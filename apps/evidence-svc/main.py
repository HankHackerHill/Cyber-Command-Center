"""Internal artifact storage and the read-only evidence-before-promotion gate."""

import os
import sqlite3
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, cast
from uuid import UUID

import psycopg
from contracts.roe import Sha256Hex
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from pydantic import AfterValidator, BaseModel, ConfigDict, Field

from ledger_link import AmbiguousFinding, LinkIndex, MissingEvidence
from store import ArtifactStore


def valid_finding_id(value: str) -> str:
    if "\x00" in value:
        raise ValueError("finding_id must contain valid PostgreSQL text")
    value.encode("utf-8")
    return value


FindingId = Annotated[str, Field(strict=True), AfterValidator(valid_finding_id)]


class Artifact(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    sha256: Sha256Hex
    url: str


class Link(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    finding_id: FindingId
    sha256: Sha256Hex
    record_hash: Sha256Hex
    engagement_id: UUID | None = None


class EvidenceCheck(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    ok: bool


@dataclass(frozen=True)
class Services:
    store: ArtifactStore
    links: LinkIndex


async def services(request: Request) -> Services:
    return cast(Services, request.app.state.services)


Resources = Annotated[Services, Depends(services)]


def artifact(digest: str) -> Artifact:
    return Artifact(sha256=digest, url=f"/artifacts/{digest}")


def create_app(*, root: Path | None = None, database_url: str | None = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        directory = root if root is not None else Path(os.environ["EVIDENCE_ROOT"])
        store = ArtifactStore(directory)
        links = LinkIndex(directory, database_url or os.environ["DATABASE_URL"], store)
        app.state.services = Services(store, links)
        yield

    app = FastAPI(title="RedOps evidence service", lifespan=lifespan)

    @app.exception_handler(RequestValidationError)
    async def invalid(request: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": "Invalid evidence request"})

    @app.exception_handler(MissingEvidence)
    async def missing(request: Request, exc: MissingEvidence) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @app.exception_handler(AmbiguousFinding)
    async def ambiguous(request: Request, exc: AmbiguousFinding) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(OSError)
    @app.exception_handler(sqlite3.Error)
    @app.exception_handler(psycopg.Error)
    async def unavailable(request: Request, exc: Exception) -> JSONResponse:
        return JSONResponse(status_code=503, content={"detail": "Evidence storage unavailable"})

    @app.put(
        "/artifacts", status_code=201, responses={200: {"model": Artifact, "description": "Already stored"}},
        openapi_extra={"requestBody": {"content": {"application/octet-stream": {
            "schema": {"type": "string", "format": "binary"},
        }}}},
    )
    async def upload(request: Request, response: Response, resources: Resources) -> Artifact:
        """Store the exact request bytes. Return the same URL on a duplicate PUT."""
        digest, created = await resources.store.put(request.stream())
        response.status_code = 201 if created else 200
        return artifact(digest)

    @app.get("/artifacts/{sha256}", response_class=FileResponse)
    def download(sha256: Sha256Hex, resources: Resources) -> FileResponse:
        if not resources.store.exists(sha256):
            raise HTTPException(404, "Artifact not found")
        if not resources.store.verified(sha256):
            raise HTTPException(503, "Stored artifact failed integrity verification")
        return FileResponse(
            resources.store.path_for(sha256), media_type="application/octet-stream",
            filename=sha256, headers={"X-Content-Type-Options": "nosniff"},
        )

    @app.post("/link")
    def link(body: Link, resources: Resources) -> Artifact:
        """Link an artifact to a ledger record and a finding in that record's engagement."""
        resources.links.link(body.finding_id, body.sha256, body.record_hash, body.engagement_id)
        return artifact(body.sha256)

    @app.get("/findings/{id:path}/evidence")
    def finding_evidence(id: FindingId, resources: Resources, engagement_id: UUID | None = None) -> list[Artifact]:
        """Supply engagement_id when different engagements use the same finding ID."""
        return [artifact(digest) for digest in resources.links.artifacts(id, engagement_id)]

    @app.post("/findings/{id:path}/verify-evidence")
    def verify_evidence(id: FindingId, resources: Resources, engagement_id: UUID | None = None) -> EvidenceCheck:
        """Check the evidence prerequisite without changing the finding's status."""
        return EvidenceCheck(ok=resources.links.has_linked_evidence(id, engagement_id))

    return app


app = create_app()
