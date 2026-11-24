"""Read-only graph queries on the internal service network."""

import os
from typing import Annotated, Protocol
from uuid import UUID

import psycopg
from contracts.findings import AssetEdge, AssetNode
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from psycopg.rows import dict_row
from pydantic import AfterValidator, BaseModel, ConfigDict, Field

from paths import Graph, nodes_reaching_tier0, shortest_path


def valid_engagement_id(value: str) -> str:
    if "\x00" in value:
        raise ValueError("engagement_id must contain valid PostgreSQL text")
    value.encode("utf-8")
    try:
        return str(UUID(value))
    except ValueError:
        # MS0 contracts and synthetic fixtures also permit opaque string IDs.
        return value


EngagementId = Annotated[
    str, Field(strict=True, min_length=1), AfterValidator(valid_engagement_id),
]


class ReachRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    engagement_id: EngagementId


class PathRequest(ReachRequest):
    src: UUID
    dst: UUID


class GraphRepository(Protocol):
    def load(self, engagement_id: str) -> Graph | None:
        """Load one engagement snapshot; None means the engagement is absent."""
        ...


class PostgresGraphRepository:
    def __init__(self, database_url: str) -> None:
        self._database_url = database_url

    def load(self, engagement_id: str) -> Graph | None:
        try:
            database_id = UUID(engagement_id)
        except ValueError:
            return None
        with psycopg.connect(
            self._database_url, row_factory=dict_row, connect_timeout=5,
        ) as connection:
            connection.isolation_level = psycopg.IsolationLevel.REPEATABLE_READ
            connection.read_only = True
            with connection.cursor() as cursor:
                # Bound parameters and the same engagement key on every read
                # preserve MS0's composite-key isolation. No graph writes.
                cursor.execute("SELECT id FROM engagements WHERE id = %s", (database_id,))
                if cursor.fetchone() is None:
                    return None
                cursor.execute(
                    "SELECT id, asset_category, canonical_identifier, metadata, discovered_by "
                    "FROM asset_nodes WHERE engagement_id = %s ORDER BY id", (database_id,),
                )
                nodes = [AssetNode.model_validate(dict(row, engagement_id=engagement_id))
                         for row in cursor.fetchall()]
                cursor.execute(
                    "SELECT id, src_node, dst_node, edge_kind, traversal_cost, proven_by_finding "
                    "FROM asset_edges WHERE engagement_id = %s ORDER BY id", (database_id,),
                )
                edges = [AssetEdge.model_validate(dict(row, engagement_id=engagement_id))
                         for row in cursor.fetchall()]
        return Graph(engagement_id, nodes, edges)


def create_app(
    *, repository: GraphRepository | None = None, database_url: str | None = None,
) -> FastAPI:
    app = FastAPI(title="RedOps graph service")
    # Resolve configuration without opening a connection at import time. Tests
    # inject a repository and never depend on DATABASE_URL or target services.
    configured_url = database_url if database_url is not None else os.environ.get("DATABASE_URL")
    source = repository
    if source is None and configured_url:
        source = PostgresGraphRepository(configured_url)

    def graph_for(engagement_id: str) -> Graph:
        if source is None:
            raise HTTPException(503, "Graph storage unavailable")
        try:
            graph = source.load(engagement_id)
            if graph is not None and graph.engagement_id != engagement_id:
                raise ValueError("Repository returned another engagement")
        except (psycopg.Error, ValueError):
            raise HTTPException(503, "Graph storage unavailable") from None
        if graph is None:
            raise HTTPException(404, "Engagement not found")
        return graph

    @app.exception_handler(RequestValidationError)
    async def invalid(request: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": "Invalid graph request"})

    @app.post("/paths")
    def paths(body: PathRequest) -> list[AssetEdge]:
        """Shortest directed path; [] for no path or the identity path."""
        graph = graph_for(body.engagement_id)
        try:
            return shortest_path(graph, body.src, body.dst)
        except KeyError:
            raise HTTPException(404, "Asset node not found") from None

    @app.post("/tier0-reach")
    def tier0_reach(body: ReachRequest) -> list[AssetNode]:
        """Nodes with a directed path to Tier-0, in node ID order, including Tier-0."""
        return nodes_reaching_tier0(graph_for(body.engagement_id))

    return app


app = create_app()
