"""Engagement audit, signed closure, and emergency stop API."""

import json
import os
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from typing import Annotated, Literal
from uuid import UUID

from contracts.events import EngagementState, TransitionEvent
from contracts.ledger import LedgerRecord
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import Depends, FastAPI, Query, Request
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from psycopg_pool import ConnectionPool
from pydantic import BaseModel
from redis import Redis
from redis.exceptions import RedisError

from deps import Services, services
from ledger import EngagementNotFound, archive_engagement, get_state, halt_engagement, read_ledger
from signatures import load_operator_public_keys
from state_machine import Reason, TransitionDenied, require_engagement_id

Resources = Annotated[Services, Depends(services)]


class StateResponse(BaseModel):
    state: EngagementState


class ArchiveResponse(BaseModel):
    status: Literal["applied"] = "applied"
    next_state: Literal[EngagementState.COMPLETED_ARCHIVED] = EngagementState.COMPLETED_ARCHIVED
    ledger_hash: str


class StopResponse(BaseModel):
    status: Literal["halted"] = "halted"
    next_state: Literal[EngagementState.HALTED_KILLSWITCH] = EngagementState.HALTED_KILLSWITCH
    ledger_hash: str | None
    notification_published: bool


def create_app(
    *, database_url: str | None = None, redis_url: str | None = None,
    trusted_public_keys: Mapping[str, Ed25519PublicKey] | None = None,
) -> FastAPI:
    keys = dict(trusted_public_keys) if trusted_public_keys is not None else load_operator_public_keys()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        with (
            ConnectionPool(
                database_url or os.environ["DATABASE_URL"],
                open=False, min_size=1, max_size=16, kwargs={"autocommit": True},
            ) as pool,
            Redis.from_url(redis_url or os.environ["REDIS_URL"],
                           socket_connect_timeout=0.25, socket_timeout=0.25) as publisher,
        ):
            app.state.services = Services(pool, publisher)
            yield

    app = FastAPI(lifespan=lifespan)

    @app.exception_handler(EngagementNotFound)
    async def missing_engagement(request: Request, exc: EngagementNotFound) -> JSONResponse:
        return JSONResponse(status_code=404, content={"reason": Reason.ENGAGEMENT_NOT_FOUND})

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request: Request, exc: RequestValidationError) -> JSONResponse:
        if getattr(request.scope.get("route"), "name", None) == "transition":
            return JSONResponse(status_code=422, content={"reason": Reason.INVALID_EVENT})
        return await request_validation_exception_handler(request, exc)

    @app.exception_handler(TransitionDenied)
    async def denied_transition(request: Request, exc: TransitionDenied) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content={"reason": exc.reason})

    @app.get("/engagements/{id}/state")
    def state(id: UUID, resources: Resources) -> StateResponse:
        with resources.database.connection() as conn:
            return StateResponse(state=get_state(conn, id))

    @app.get("/engagements/{id}/ledger", response_model_by_alias=False)
    def ledger(id: UUID, resources: Resources,
               since: Annotated[int, Query(ge=0, le=2**63 - 1)] = 0) -> list[LedgerRecord]:
        with resources.database.connection() as conn:
            return read_ledger(conn, id, since)

    @app.post("/engagements/{id}/killswitch")
    def killswitch(id: UUID, resources: Resources) -> StopResponse:
        with resources.database.connection() as conn:
            digest = halt_engagement(conn, id)
        # Publish after commit. A retry publishes again without duplicating the journal row.
        try:
            resources.notifications.publish("redops:killswitch", json.dumps({
                "engagement_id": str(id), "state": EngagementState.HALTED_KILLSWITCH,
            }))
        except RedisError:
            return StopResponse(ledger_hash=digest, notification_published=False)
        return StopResponse(ledger_hash=digest, notification_published=True)

    @app.post("/engagements/{id}/transition")
    def transition(id: UUID, event: TransitionEvent, resources: Resources) -> ArchiveResponse | StopResponse:
        """Record signed closure or an emergency stop."""
        if event.to_state == EngagementState.HALTED_KILLSWITCH:
            require_engagement_id(id, event)
            return killswitch(id, resources)
        with resources.database.connection() as conn:
            digest = archive_engagement(conn, id, event, keys)
        return ArchiveResponse(ledger_hash=digest)

    return app


app = create_app()
