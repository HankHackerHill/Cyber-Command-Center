"""Engagement audit, remediation, signed closure, and emergency stop API."""

import json
import os
import secrets
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from decimal import Decimal, InvalidOperation
from typing import Annotated, Literal
from uuid import UUID

from contracts.events import ActorType, AuditEvent, EngagementState, TransitionEvent
from contracts.ledger import LedgerRecord
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from psycopg_pool import ConnectionPool
from pydantic import BaseModel
from redis import Redis
from redis.exceptions import RedisError

from deps import Services, services
from ledger import (
    AuditReplayConflict, EngagementNotFound, get_state, halt_engagement, read_ledger,
    record_audit_event, record_review_transition,
)
from signatures import load_operator_public_keys
from state_machine import Reason, TransitionDenied, require_engagement_id

Resources = Annotated[Services, Depends(services)]


class StateResponse(BaseModel):
    state: EngagementState


class TransitionError(BaseModel):
    reason: Reason


class ReviewResponse(BaseModel):
    status: Literal["applied"] = "applied"
    next_state: EngagementState
    ledger_hash: str


class StopResponse(BaseModel):
    status: Literal["halted"] = "halted"
    next_state: Literal[EngagementState.HALTED_KILLSWITCH] = EngagementState.HALTED_KILLSWITCH
    ledger_hash: str | None
    notification_published: bool


async def validate_audit_wire(request: Request) -> None:
    """Keep loss of numeric precision or duplicate fields out of the immutable journal."""
    def distinct_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result = dict(pairs)
        if len(pairs) != len(result):
            raise ValueError("duplicate JSON field")
        return result

    def check_number(token: str) -> None:
        original = Decimal(token)
        if not original.is_finite() or original != Decimal(str(float(token))):
            raise ValueError("numeric value exceeds the JSON model's precision")

    try:
        json.loads(await request.body(), object_pairs_hook=distinct_pairs,
                   parse_float=check_number, parse_constant=check_number)
    except (ValueError, InvalidOperation, RecursionError) as exc:
        raise HTTPException(422, "Invalid audit JSON") from exc


def create_app(
    *, database_url: str | None = None, redis_url: str | None = None,
    trusted_public_keys: Mapping[str, Ed25519PublicKey] | None = None,
    m4_audit_token: str | None = None,
) -> FastAPI:
    keys = dict(trusted_public_keys) if trusted_public_keys is not None else load_operator_public_keys()
    audit_token = m4_audit_token if m4_audit_token is not None else os.getenv("M4_AUDIT_TOKEN")

    async def authenticate_m4(
        request: Request,
        bearer: Annotated[HTTPAuthorizationCredentials | None, Depends(HTTPBearer(auto_error=False))],
    ) -> None:
        if (
            not audit_token or bearer is None or len(request.headers.getlist("authorization")) != 1
            or not secrets.compare_digest(bearer.credentials.encode(), audit_token.encode())
        ):
            raise HTTPException(401, "Unauthorized", headers={"WWW-Authenticate": "Bearer"})

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
        if getattr(request.scope.get("route"), "name", None) in ("transition", "append_audit"):
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

    @app.post(
        "/engagements/{id}/audit-events", status_code=201, response_model_by_alias=False,
        dependencies=[Depends(authenticate_m4), Depends(validate_audit_wire)],
        responses={
            200: {"model": LedgerRecord, "description": "Idempotent replay"},
            401: {"description": "Invalid service credential"},
            403: {"description": "Actor does not match the authenticated service"},
            404: {"description": "Unknown engagement"},
            409: {"description": "Conflicting use of an Idempotency-Key"},
        },
    )
    def append_audit(
        id: UUID, event: AuditEvent, resources: Resources, response: Response,
        idempotency_keys: Annotated[list[UUID] | None, Header(alias="Idempotency-Key")] = None,
    ) -> LedgerRecord:
        if event.actor_kind != ActorType.SYSTEM or event.actor_id != "scoped-proxy":
            raise HTTPException(403, "Actor identity does not match the authenticated service")
        if idempotency_keys is not None and len(idempotency_keys) != 1:
            raise HTTPException(422, "Expected a single Idempotency-Key")
        with resources.database.connection() as conn:
            try:
                key = idempotency_keys[0] if idempotency_keys else None
                receipt, created = record_audit_event(conn, id, event, key)
            except AuditReplayConflict as exc:
                raise HTTPException(409, "Idempotency-Key was used for a different event") from exc
        response.status_code = 201 if created else 200
        return receipt

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

    @app.post(
        "/engagements/{id}/transition",
        responses={
            403: {
                "model": TransitionError,
                "description": "Signature check failed or the requested transition is deferred.",
            },
            404: {"model": TransitionError, "description": "Engagement not found."},
            409: {"model": TransitionError, "description": "Illegal transition or stale source state."},
            422: {"model": TransitionError, "description": "Invalid event or mismatched engagement ID."},
        },
    )
    def transition(id: UUID, event: TransitionEvent, resources: Resources) -> ReviewResponse | StopResponse:
        """Record evidence review, remediation, signed closure, or an emergency stop.

        An otherwise valid request for a deferred transition returns HTTP 403 with
        reason `TRANSITION_UNAVAILABLE`. The engagement state and audit ledger stay intact.
        """
        if event.to_state == EngagementState.HALTED_KILLSWITCH:
            require_engagement_id(id, event)
            return killswitch(id, resources)
        with resources.database.connection() as conn:
            digest = record_review_transition(conn, id, event, keys)
        return ReviewResponse(next_state=event.to_state, ledger_hash=digest)

    return app


app = create_app()
