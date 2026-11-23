"""Process-scoped database pool and emergency-stop publisher."""

from dataclasses import dataclass

from fastapi import Request
from psycopg_pool import ConnectionPool
from redis import Redis


@dataclass(frozen=True)
class Services:
    database: ConnectionPool
    notifications: Redis


async def services(request: Request) -> Services:
    resources: Services = request.app.state.services
    return resources
