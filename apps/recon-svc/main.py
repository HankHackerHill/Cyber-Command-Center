"""Import reviewed public observations into engagement-scoped AssetNode records.

On the internal service network, POST a JSON object with engagement_id and
records to /collect/{source}. Source selection determines the accepted record
schema. The service processes observations supplied by its caller and returns
contract records for downstream review. It opens no outbound connection and
stores no observations. Apply deployment ingress authentication separately.

Each process independently limits requests and uploads in flight by source.
"""

import asyncio
from collections.abc import Callable
from math import ceil
from threading import Lock
from time import monotonic

from contracts.findings import AssetNode
from fastapi import FastAPI, HTTPException, Request
from starlette.requests import ClientDisconnect

from collectors import MAX_BODY_BYTES, Source, import_records

UPLOAD_TIMEOUT_SECONDS = 10
MAX_UPLOADS_PER_SOURCE = 4


class SourceBudget:
    """Token bucket with bounded in-flight uploads for one source."""

    def __init__(self, requests_per_minute: int, clock: Callable[[], float]) -> None:
        self._capacity = requests_per_minute
        self._rate = requests_per_minute / 60
        self._tokens = float(requests_per_minute)
        self._clock = clock
        self._updated = clock()
        self._uploads = 0
        self._lock = Lock()

    def begin(self) -> int | None:
        """Reserve admission or return the recommended retry delay in seconds."""
        with self._lock:
            now = max(self._updated, self._clock())
            self._tokens = min(self._capacity, self._tokens + (now - self._updated) * self._rate)
            self._updated = now
            if self._tokens < 1:
                return max(1, ceil((1 - self._tokens) / self._rate))
            if self._uploads >= MAX_UPLOADS_PER_SOURCE:
                return 1
            self._tokens -= 1
            self._uploads += 1
            return None

    def finish(self) -> None:
        with self._lock:
            self._uploads -= 1


async def _read_body(request: Request) -> bytes:
    body = bytearray()
    try:
        async with asyncio.timeout(UPLOAD_TIMEOUT_SECONDS):
            async for chunk in request.stream():
                if len(chunk) > MAX_BODY_BYTES - len(body):
                    raise HTTPException(413, "Import body exceeds byte limit")
                body.extend(chunk)
    except TimeoutError:
        raise HTTPException(408, "Import upload timed out") from None
    except ClientDisconnect:
        raise HTTPException(400, "Import upload disconnected") from None
    return bytes(body)


def create_app(*, requests_per_minute: int = 60, clock: Callable[[], float] = monotonic) -> FastAPI:
    if type(requests_per_minute) is not int or not 1 <= requests_per_minute <= 3_600:
        raise ValueError("requests_per_minute must be in [1, 3600]")
    budgets = {source: SourceBudget(requests_per_minute, clock) for source in Source}
    app = FastAPI(title="RedOps public observation import")

    @app.post("/collect/{source}", response_model=list[AssetNode])
    async def collect(source: str, request: Request) -> list[AssetNode]:
        """Normalize one bounded batch of supplied observations for the selected source."""
        try:
            collector = Source(source)
        except ValueError:
            raise HTTPException(404, "Unknown collector") from None
        budget = budgets[collector]
        retry_after = budget.begin()
        if retry_after is not None:
            raise HTTPException(429, "Collector rate limit reached", headers={"Retry-After": str(retry_after)})
        try:
            body = await _read_body(request)
            # The request is read explicitly so buffering cannot exceed the
            # intake limit. Invalid source data never appears in the response.
            return import_records(collector, body)
        except (ValueError, OverflowError, RecursionError):
            raise HTTPException(422, "Invalid collector import") from None
        finally:
            budget.finish()

    return app


app = create_app()
