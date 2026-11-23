"""Engagement state inspection, ledger reads, and the emergency stop API."""

import json
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated, Literal
from uuid import UUID

from contracts.events import EngagementState
from contracts.ledger import LedgerRecord
from fastapi import Depends, FastAPI, Query, Request
from fastapi.responses import JSONResponse
from psycopg_pool import ConnectionPool
from pydantic import BaseModel
from redis import Redis
from redis.exceptions import RedisError

from deps import Services, services
from ledger import EngagementNotFound, get_state, halt_engagement, read_ledger

Resources = Annotated[Services, Depends(services)]


class StateResponse(BaseModel):
    state: EngagementState


class StopResponse(BaseModel):
    status: Literal["halted"] = "halted"
    next_state: Literal[EngagementState.HALTED_KILLSWITCH] = EngagementState.HALTED_KILLSWITCH
    ledger_hash: str | None
    notification_published: bool


def create_app(*, database_url: str | None = None, redis_url: str | None = None) -> FastAPI:
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
        return JSONResponse(status_code=404, content={"reason": "ENGAGEMENT_NOT_FOUND"})

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

    return app


app = create_app()
