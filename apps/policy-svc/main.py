"""Admission decisions for HTTP requests under an active, operator-provisioned RoE.

Only trusted service configuration supplies manifests, the orchestrator/OPA
origins, and Redis accounting. Request identifiers never select a network origin.
"""

import hashlib
import json
import os
import re
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import TypedDict
from uuid import UUID, uuid4

import httpx
from contracts.events import EngagementState
from contracts.roe import ExecutionMode, RoeManifest
from fastapi import Depends, FastAPI, Request, Response
from fastapi.exception_handlers import http_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from redis import Redis
from redis.exceptions import RedisError
from starlette.exceptions import HTTPException as StarletteHTTPException


class HttpRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    method: str
    host: str
    ip: str
    path: str
    ts: str


class Evaluation(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    manifest_hash: str = Field(pattern=r"^[0-9a-f]{64}$", min_length=64, max_length=64)
    request: HttpRequest


class Decision(BaseModel):
    allow: bool = False
    reason: str


class Runtime(TypedDict):
    tokens: int
    active_workers: int
    errors_5xx: int


class InvalidInput(ValueError):
    pass


class Bucket(BaseModel):
    """Redis state. Credit is stored in millionths of a request."""

    model_config = ConfigDict(extra="forbid", strict=True)
    credit: int = Field(ge=0)
    at_us: int = Field(ge=0)
    rate: int = Field(ge=0)
    active_workers: int = Field(ge=0)
    errors_5xx: int = Field(ge=0)


class AccountStore:
    """Per-engagement limits shared by all policy-service processes.

    Trusted provisioning and response observers use initialize and complete.
    A receipt only correlates accounting. It is never accepted by /evaluate.
    Dropping a completion holds its worker slot until it can be reconciled.
    """

    def __init__(self, redis: Redis, time_us: Callable[[], int] | None = None) -> None:
        self.redis = redis
        self.time_us = time_us

    @staticmethod
    def _key(engagement_id: str) -> str:
        try:
            engagement_id = str(UUID(engagement_id))
        except ValueError:
            pass  # The frozen contract also supports opaque engagement identifiers.
        return "redops:policy:v1:" + engagement_id

    def initialize(self, engagement_id: str) -> None:
        """Provision once without resetting live limits or outstanding work."""
        empty = Bucket(credit=0, at_us=0, rate=0, active_workers=0, errors_5xx=0)
        self.redis.eval(
            "if redis.call('EXISTS', KEYS[1]) == 0 then "
            "return redis.call('HSET', KEYS[1], 'state', ARGV[1]) end return 0",
            1, self._key(engagement_id), empty.model_dump_json(),
        )

    def _read(self, key: str) -> tuple[str, Bucket]:
        # Read metadata and count outstanding receipts in one snapshot. Broken
        # or partial accounting must never make more worker slots available.
        snapshot: object = self.redis.eval(
            "return {redis.call('HGET', KEYS[1], 'state'), redis.call('HLEN', KEYS[1]) - 1}",
            1, key,
        )
        if not isinstance(snapshot, list) or len(snapshot) != 2:
            raise InvalidInput("invalid accounting response")
        raw, receipts = snapshot
        if not isinstance(raw, (str, bytes)):
            raise InvalidInput("missing accounting")
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        strict_json(raw.encode("utf-8"))
        bucket = Bucket.model_validate_json(raw)
        if type(receipts) is not int or bucket.active_workers != receipts:
            raise InvalidInput("inconsistent worker count")
        if bucket.credit > bucket.rate * 1_000_000:
            raise InvalidInput("invalid bucket credit")
        if bucket.rate == 0 and (bucket.at_us or bucket.active_workers or bucket.errors_5xx):
            raise InvalidInput("invalid initial bucket")
        return raw, bucket

    def _now_us(self) -> int:
        if self.time_us is not None:
            return self.time_us()
        instant = self.redis.time()
        if not isinstance(instant, tuple) or len(instant) != 2:
            raise InvalidInput("invalid accounting clock")
        seconds, micros = instant
        if not isinstance(seconds, int) or not isinstance(micros, int) or not 0 <= micros < 1_000_000:
            raise InvalidInput("invalid accounting clock")
        return seconds * 1_000_000 + micros

    def _update(self, script: str, key: str, *arguments: str) -> str:
        result: object = self.redis.eval(script, 1, key, *arguments)
        if isinstance(result, bytes):
            return result.decode("ascii")
        if isinstance(result, str):
            return result
        raise InvalidInput("invalid accounting response")

    def reserve(
        self, engagement_id: str, capacity: int, judge: Callable[[Runtime], Decision],
    ) -> tuple[Decision, str | None]:
        key = self._key(engagement_id)
        for _ in range(12):
            raw, bucket = self._read(key)
            now = self._now_us()
            if now < bucket.at_us:
                return Decision(reason="CLOCK_UNAVAILABLE"), None
            # At a rate change, refill elapsed time at the more restrictive rate.
            credit = capacity * 1_000_000
            if bucket.rate:
                earned = (now - bucket.at_us) * min(capacity, bucket.rate)
                credit = min(credit, bucket.credit + earned)
            decision = judge(Runtime(tokens=credit // 1_000_000, active_workers=bucket.active_workers,
                                     errors_5xx=bucket.errors_5xx))
            if not decision.allow:
                return decision, None
            if credit < 1_000_000:
                return Decision(reason="RATE_DENIED"), None
            updated = Bucket(credit=credit - 1_000_000, at_us=now, rate=capacity,
                             active_workers=bucket.active_workers + 1, errors_5xx=bucket.errors_5xx)
            receipt = str(uuid4())
            # Compare the exact snapshot evaluated by Rego. A competing change
            # requires a new decision before any counters are written.
            stored = self._update(
                "if redis.call('HGET', KEYS[1], 'state') ~= ARGV[1] then return 'retry' end "
                "if redis.call('HEXISTS', KEYS[1], ARGV[3]) == 1 then return 'retry' end "
                "redis.call('HSET', KEYS[1], 'state', ARGV[2], ARGV[3], '1') return 'ok'",
                key, raw, updated.model_dump_json(), receipt,
            )
            if stored == "ok":
                return decision, receipt
        return Decision(reason="ACCOUNTING_BUSY"), None

    def complete(self, engagement_id: str, reservation_id: str, status_code: int) -> bool:
        """Record a final observed HTTP status once. Duplicate completions return false."""
        if type(status_code) is not int or not 200 <= status_code <= 599:
            return False
        key = self._key(engagement_id)
        try:
            receipt = str(UUID(reservation_id))
            for _ in range(12):
                raw, bucket = self._read(key)
                if bucket.active_workers == 0:
                    return False
                updated = bucket.model_copy(update={
                    "active_workers": bucket.active_workers - 1,
                    "errors_5xx": bucket.errors_5xx + int(status_code >= 500),
                })
                outcome = self._update(
                    "if redis.call('HGET', KEYS[1], ARGV[3]) ~= '1' then return 'missing' end "
                    "if redis.call('HGET', KEYS[1], 'state') ~= ARGV[1] then return 'retry' end "
                    "redis.call('HSET', KEYS[1], 'state', ARGV[2]) "
                    "redis.call('HDEL', KEYS[1], ARGV[3]) return 'ok'",
                    key, raw, updated.model_dump_json(), receipt,
                )
                if outcome != "retry":
                    return outcome == "ok"
        except (RedisError, ValueError):
            return False
        return False


def unique_fields(pairs: list[tuple[str, object]]) -> dict[str, object]:
    fields = dict(pairs)
    if len(fields) != len(pairs):
        raise InvalidInput("duplicate field")
    return fields


def strict_json(raw: bytes) -> object:
    def invalid_number(_: str) -> None:
        raise InvalidInput("invalid JSON number")

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=unique_fields, parse_constant=invalid_number)
    except (ValueError, RecursionError) as exc:
        raise InvalidInput("invalid JSON") from exc


async def validate_wire(request: Request) -> None:
    strict_json(await request.body())


def read_manifest(directory: Path, digest: str) -> tuple[RoeManifest, dict[str, object]]:
    raw = (directory / f"{digest}.json").read_bytes()
    if hashlib.sha256(raw).hexdigest() != digest:
        raise InvalidInput("manifest content hash mismatch")
    document = strict_json(raw)
    if not isinstance(document, dict):
        raise InvalidInput("invalid manifest")
    # The contract validates the document. OPA uses its original timestamp
    # strings so a nanosecond boundary cannot be widened by Python datetime.
    return RoeManifest.model_validate_json(raw, strict=True), document


def check_rules(opa: httpx.Client, manifest: dict[str, object], request: HttpRequest,
                now: datetime, runtime: Runtime) -> Decision:
    if now.utcoffset() is None:
        return Decision(reason="CLOCK_UNAVAILABLE")
    payload = {"manifest": manifest, "request": request.model_dump(),
               "now": now.astimezone(timezone.utc).isoformat(), "runtime": runtime}
    try:
        answer = opa.post("/v1/data/redops", json={"input": payload})
        answer.raise_for_status()
        body = strict_json(answer.content)
    except (httpx.HTTPError, ValueError):
        return Decision(reason="POLICY_UNAVAILABLE")
    result = body.get("result") if isinstance(body, dict) else None
    if not isinstance(result, dict):
        return Decision(reason="POLICY_UNAVAILABLE")
    for name in ("scope", "window", "breaker", "rate"):
        rule = result.get(name)
        if not isinstance(rule, dict) or type(rule.get("allow")) is not bool:
            return Decision(reason="POLICY_UNAVAILABLE")
        if not rule["allow"]:
            return Decision(reason=f"{name.upper()}_DENIED")
    return Decision(allow=True, reason="ALLOWED")


def check_state(orchestrator: httpx.Client, engagement_id: str) -> Decision | None:
    if not re.fullmatch(r"[A-Za-z0-9_-]+", engagement_id):
        return Decision(reason="INVALID_ENGAGEMENT_ID")
    try:
        answer = orchestrator.get(f"/engagements/{engagement_id}/state")
        answer.raise_for_status()
        state = strict_json(answer.content)
    except (httpx.HTTPError, ValueError):
        return Decision(reason="STATE_UNAVAILABLE")
    # This API evaluates client-target traffic. Active validation requires
    # human approval in M2. A missing or unrecognized state denies admission.
    if state != {"state": EngagementState.CONTROLLED_VALIDATION}:
        return Decision(reason="STATE_DENIED")
    return None


def create_app(
    *, manifest_dir: Path | None = None, orchestrator_url: str | None = None,
    opa_url: str | None = None, redis_url: str | None = None,
    clock: Callable[[], datetime] | None = None,
    transport: httpx.BaseTransport | None = None,
    time_us: Callable[[], int] | None = None,
) -> FastAPI:
    utc_now = clock or (lambda: datetime.now(timezone.utc))

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        directory = manifest_dir or Path(os.environ["POLICY_MANIFEST_DIR"])
        with (
            httpx.Client(base_url=orchestrator_url or os.environ["ORCHESTRATOR_URL"],
                         transport=transport, trust_env=False, timeout=2) as orchestrator,
            httpx.Client(base_url=opa_url or os.environ["OPA_URL"], trust_env=False, timeout=2) as opa,
            Redis.from_url(redis_url or os.environ["REDIS_URL"], decode_responses=True,
                           socket_connect_timeout=2, socket_timeout=2) as redis,
        ):
            app.state.directory = directory
            app.state.orchestrator = orchestrator
            app.state.opa = opa
            app.state.accounting = AccountStore(redis, time_us=time_us)
            yield

    app = FastAPI(lifespan=lifespan)

    @app.exception_handler(StarletteHTTPException)
    async def bad_body(request: Request, exc: StarletteHTTPException) -> Response:
        if exc.status_code == 400 and request.url.path == "/evaluate":
            return JSONResponse(content=Decision(reason="INVALID_REQUEST").model_dump())
        return await http_exception_handler(request, exc)

    @app.exception_handler(RequestValidationError)
    @app.exception_handler(InvalidInput)
    async def invalid(request: Request, exc: Exception) -> JSONResponse:
        return JSONResponse(content=Decision(reason="INVALID_REQUEST").model_dump())

    @app.post(
        "/evaluate",
        dependencies=[Depends(validate_wire)],
        responses={200: {"headers": {"X-Policy-Reservation": {
            "description": "Accounting receipt returned for an allowed evaluation.",
            "schema": {"type": "string", "format": "uuid"},
        }}}},
    )
    def evaluate(evaluation: Evaluation, request: Request, response: Response) -> Decision:
        """Evaluate one request and reserve capacity on allow.

        X-Policy-Reservation identifies the admission for trusted completion accounting.
        """
        services = request.app.state
        try:
            manifest, document = read_manifest(services.directory, evaluation.manifest_hash)
        except FileNotFoundError:
            return Decision(reason="UNKNOWN_MANIFEST")
        except (OSError, InvalidInput, ValidationError):
            return Decision(reason="INVALID_MANIFEST")
        if manifest.execution_mode == ExecutionMode.AUTONOMOUS_PASSIVE:
            return Decision(reason="PASSIVE_ONLY")

        def judge(runtime: Runtime) -> Decision:
            denied = check_state(services.orchestrator, manifest.engagement_id)
            if denied is not None:
                return denied
            return check_rules(services.opa, document, evaluation.request, utc_now(), runtime)

        store: AccountStore = services.accounting
        try:
            decision, reservation = store.reserve(
                manifest.engagement_id, manifest.traffic_constraints.max_requests_per_second, judge,
            )
        except (RedisError, ValueError):
            return Decision(reason="ACCOUNTING_UNAVAILABLE")
        if reservation is not None:
            response.headers["X-Policy-Reservation"] = reservation
        return decision

    return app


app = create_app()
