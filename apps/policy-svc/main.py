"""Admission decisions for HTTP requests under an active, operator-provisioned RoE.

Only trusted service configuration supplies manifests, the orchestrator/OPA
origins, and Redis accounting. Request identifiers never select a network origin.
"""

import hashlib
import json
import os
import re
import secrets
import time
from collections import OrderedDict
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import TypedDict
from uuid import UUID, uuid4

import httpx
from contracts.events import EngagementState
from contracts.roe import ExecutionMode, RoeManifest
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.exception_handlers import http_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from redis import Redis
from redis.exceptions import RedisError
from starlette.exceptions import HTTPException as StarletteHTTPException

from settlements import (
    Completion, ConflictingCompletion, SettlementAcknowledgement, SettlementBatch, SettlementResponse,
)


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

    def complete_many(self, engagement_id: str, completions: list[Completion]) -> list[SettlementAcknowledgement]:
        """Atomically consume distinct receipts and retain durable retry proofs.

        No worker is released before the entire CAS commits. A matching retry is
        acknowledged only by its persisted original status; missing receipts are
        never evidence of completion. Retain the :settled hash with the live
        accounting hash, including in backup/restore and engagement archival.
        """
        batch = SettlementBatch(engagement_id=engagement_id, completions=completions)
        key = self._key(batch.engagement_id)
        receipt_ids = [item.reservation_id for item in batch.completions]
        for _ in range(12):
            # A single snapshot covers bucket integrity, outstanding receipts,
            # and durable completion fingerprints. Neither hash has an expiry.
            snapshot: object = self.redis.eval(
                "local a = redis.call('HMGET', KEYS[1], unpack(ARGV)) "
                "local b = redis.call('HMGET', KEYS[2], unpack(ARGV)) "
                "return {redis.call('HGET', KEYS[1], 'state'), "
                "redis.call('HLEN', KEYS[1])-1, a, b}",
                2, key, key + ":settled", *receipt_ids,
            )
            if not isinstance(snapshot, list) or len(snapshot) != 4:
                raise InvalidInput("invalid settlement snapshot")
            raw, count, outstanding, settled = snapshot
            if not isinstance(raw, (str, bytes)) or not isinstance(outstanding, list) or not isinstance(settled, list):
                raise InvalidInput("invalid settlement snapshot")
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8")
            strict_json(raw.encode("utf-8"))
            bucket = Bucket.model_validate_json(raw)
            if (type(count) is not int or count != bucket.active_workers
                    or bucket.credit > bucket.rate * 1_000_000
                    or (bucket.rate == 0 and (bucket.at_us or bucket.active_workers or bucket.errors_5xx))
                    or len(outstanding) != len(receipt_ids) or len(settled) != len(receipt_ids)):
                raise InvalidInput("invalid settlement accounting")
            consumed = 0
            errors = 0
            acknowledgements: list[SettlementAcknowledgement] = []
            arguments: list[str] = []
            for item, pending, prior in zip(batch.completions, outstanding, settled, strict=True):
                if isinstance(pending, bytes):
                    pending = pending.decode("ascii")
                if isinstance(prior, bytes):
                    prior = prior.decode("ascii")
                if pending not in (None, "1") or (prior is not None and (not isinstance(prior, str) or not re.fullmatch(r"[2-5][0-9]{2}", prior))):
                    raise InvalidInput("invalid settlement receipt")
                if pending is not None and prior is not None:
                    raise InvalidInput("receipt outstanding and settled")
                if prior is not None and prior != str(item.status_code):
                    raise ConflictingCompletion("receipt status conflict")
                if pending is not None:
                    consumed += 1
                    errors += int(item.status_code >= 500)
                acknowledgements.append(SettlementAcknowledgement(
                    reservation_id=item.reservation_id,
                    status="committed" if pending is not None or prior is not None else "missing",
                ))
                arguments.extend([item.reservation_id, str(item.status_code), pending or "", prior or ""])
            if consumed > bucket.active_workers:
                raise InvalidInput("invalid settlement workers")
            updated = bucket.model_copy(update={
                "active_workers": bucket.active_workers - consumed,
                "errors_5xx": bucket.errors_5xx + errors,
            })
            outcome: object = self.redis.eval(
                "if redis.call('HGET', KEYS[1], 'state') ~= ARGV[1] then return 'retry' end "
                "for i=3,#ARGV,4 do "
                "if (redis.call('HGET', KEYS[1], ARGV[i]) or '') ~= ARGV[i+2] "
                "or (redis.call('HGET', KEYS[2], ARGV[i]) or '') ~= ARGV[i+3] then return 'retry' end end "
                "for i=3,#ARGV,4 do if ARGV[i+2] == '1' then "
                "redis.call('HDEL', KEYS[1], ARGV[i]) "
                "redis.call('HSET', KEYS[2], ARGV[i], ARGV[i+1]) end end "
                "redis.call('HSET', KEYS[1], 'state', ARGV[2]) return 'ok'",
                2, key, key + ":settled", raw, updated.model_dump_json(), *arguments,
            )
            if outcome in ("ok", b"ok"):
                return acknowledgements
            if outcome not in ("retry", b"retry"):
                raise InvalidInput("invalid settlement response")
        raise InvalidInput("settlement accounting busy")


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


class DecisionCache:
    """Bounded manifest-validation and scope-denial cache, never allow authority.

    Scope denials expire after one second: a policy hot reload can temporarily
    over-deny, but cannot grant traffic. There is no cached allow, UTC window,
    state, runtime snapshot, dependency error or reservation.
    """

    def __init__(self) -> None:
        self.lock = Lock()
        self.manifests: OrderedDict[str, tuple[RoeManifest, dict[str, object]]] = OrderedDict()
        self.denials: OrderedDict[tuple[str, str, str, str, str, str], float] = OrderedDict()

    def invalidate(self, digest: str) -> None:
        with self.lock:
            self.manifests.pop(digest, None)
            for key in list(self.denials):
                if key[0] == digest:
                    del self.denials[key]

    def read_manifest(self, directory: Path, digest: str) -> tuple[RoeManifest, dict[str, object]]:
        # A stat/mtime cache cannot detect same-size replacement or revocation.
        # Always read and SHA256 the actual registry bytes, even on a hit.
        try:
            raw = (directory / f"{digest}.json").read_bytes()
            if hashlib.sha256(raw).hexdigest() != digest:
                raise InvalidInput("manifest content hash mismatch")
        except (OSError, InvalidInput):
            self.invalidate(digest)
            raise
        with self.lock:
            cached = self.manifests.get(digest)
            if cached is not None:
                self.manifests.move_to_end(digest)
                return cached
        value = parse_manifest(raw)
        with self.lock:
            self.manifests[digest] = value
            self.manifests.move_to_end(digest)
            while len(self.manifests) > 128:
                self.manifests.popitem(last=False)
        return value

    @staticmethod
    def key(digest: str, request: HttpRequest) -> tuple[str, str, str, str, str, str]:
        return digest, request.method, request.host, request.ip, request.path, request.ts

    def scope_denied(self, digest: str, request: HttpRequest) -> bool:
        key = self.key(digest, request)
        with self.lock:
            expiry = self.denials.get(key)
            if expiry is None:
                return False
            if time.monotonic() >= expiry:
                del self.denials[key]
                return False
            self.denials.move_to_end(key)
            return True

    def remember(self, digest: str, request: HttpRequest, decision: Decision) -> None:
        if decision.allow or decision.reason != "SCOPE_DENIED":
            return
        with self.lock:
            self.denials[self.key(digest, request)] = time.monotonic() + 1.0
            self.denials.move_to_end(self.key(digest, request))
            while len(self.denials) > 2048:
                self.denials.popitem(last=False)


def parse_manifest(raw: bytes) -> tuple[RoeManifest, dict[str, object]]:
    document = strict_json(raw)
    if not isinstance(document, dict):
        raise InvalidInput("invalid manifest")
    # Keep original timestamp strings: Python datetime truncates nanoseconds.
    return RoeManifest.model_validate_json(raw, strict=True), document


def read_manifest(directory: Path, digest: str) -> tuple[RoeManifest, dict[str, object]]:
    raw = (directory / f"{digest}.json").read_bytes()
    if hashlib.sha256(raw).hexdigest() != digest:
        raise InvalidInput("manifest content hash mismatch")
    return parse_manifest(raw)


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
            app.state.decision_cache = DecisionCache()
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
        if request.url.path == "/settlements":
            return JSONResponse(status_code=422, content={"detail": "INVALID_SETTLEMENT"})
        return JSONResponse(content=Decision(reason="INVALID_REQUEST").model_dump())

    def authenticate_observer(request: Request) -> None:
        token = os.environ.get("M4_AUDIT_TOKEN")
        if not token:
            raise HTTPException(status_code=503, detail="SETTLEMENT_AUTH_UNAVAILABLE")
        supplied = request.headers.getlist("authorization")
        if len(supplied) != 1 or not secrets.compare_digest(
            supplied[0].encode("utf-8"), ("Bearer " + token).encode("utf-8"),
        ):
            raise HTTPException(status_code=401, detail="UNAUTHORIZED")

    @app.post("/settlements", dependencies=[Depends(authenticate_observer), Depends(validate_wire)])
    def settle(batch: SettlementBatch, request: Request) -> SettlementResponse:
        store: AccountStore = request.app.state.accounting
        try:
            results = store.complete_many(batch.engagement_id, batch.completions)
        except ConflictingCompletion as exc:
            raise HTTPException(status_code=409, detail="COMPLETION_CONFLICT") from exc
        except (RedisError, ValueError) as exc:
            raise HTTPException(status_code=503, detail="ACCOUNTING_UNAVAILABLE") from exc
        return SettlementResponse(engagement_id=batch.engagement_id, completions=results)

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
            cache: DecisionCache = services.decision_cache
            manifest, document = cache.read_manifest(services.directory, evaluation.manifest_hash)
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
            now = utc_now()
            if now.utcoffset() is None:
                return Decision(reason="CLOCK_UNAVAILABLE")
            if cache.scope_denied(evaluation.manifest_hash, evaluation.request):
                return Decision(reason="SCOPE_DENIED")
            decision = check_rules(services.opa, document, evaluation.request, now, runtime)
            cache.remember(evaluation.manifest_hash, evaluation.request, decision)
            return decision

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
