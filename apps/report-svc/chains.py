"""Read recorded attack chains and retrieve optional graph context for those paths."""

import math
from dataclasses import dataclass
from itertools import groupby, pairwise
from time import monotonic
from typing import Protocol
from uuid import UUID

import httpx
import psycopg
from contracts.findings import AssetEdge
from fastapi import HTTPException
from psycopg.rows import class_row
from pydantic import TypeAdapter, ValidationError


MAX_CHAIN_NODES = 50_000
MAX_GRAPH_BYTES = 4 * 1024 * 1024
GRAPH_TIMEOUT_SECONDS = 1.0
GRAPH_EDGES = TypeAdapter(list[AssetEdge])


@dataclass(frozen=True)
class ChainHop:
    finding_id: str
    edge_ids: tuple[str, ...]


@dataclass(frozen=True)
class ChainPath:
    id: str
    node_ids: tuple[UUID, ...]
    hops: tuple[ChainHop, ...]
    tier0_reached: bool


class ChainRepository(Protocol):
    def load(self, engagement_id: UUID) -> tuple[ChainPath, ...]: ...


@dataclass(frozen=True)
class _ChainNode:
    chain_id: str
    position: int
    node_id: UUID
    node_exists: bool
    tier0: bool
    proof_count: int
    finding_id: str | None
    edge_ids: list[str] | None


_CHAIN_QUERY = """
    WITH chain_steps AS (
        SELECT chain.engagement_id, chain.id, step.node_id, step.position,
               lag(step.node_id) OVER (PARTITION BY chain.id ORDER BY step.position) AS previous_node
        FROM attack_chains AS chain
        CROSS JOIN LATERAL unnest(chain.path_node_ids) WITH ORDINALITY AS step(node_id, position)
        WHERE chain.engagement_id = %s
    )
    SELECT step.id AS chain_id, step.position, step.node_id, node.id IS NOT NULL AS node_exists,
           COALESCE(node.metadata -> 'tier0' = 'true'::jsonb, false) AS tier0,
           proof.proof_count, proof.finding_id, proof.edge_ids
    FROM chain_steps AS step
    LEFT JOIN asset_nodes AS node ON node.engagement_id = step.engagement_id AND node.id = step.node_id
    LEFT JOIN LATERAL (
        SELECT count(DISTINCT edge.proven_by_finding) AS proof_count,
               min(edge.proven_by_finding) AS finding_id, array_agg(edge.id ORDER BY edge.id) AS edge_ids
        FROM asset_edges AS edge
        WHERE edge.engagement_id = step.engagement_id AND edge.src_node = step.previous_node
          AND edge.dst_node = step.node_id AND edge.proven_by_finding IS NOT NULL
    ) AS proof ON true
    ORDER BY step.id, step.position
    LIMIT %s
"""


def _recorded_path(chain_id: str, nodes: tuple[_ChainNode, ...]) -> ChainPath:
    if len(nodes) < 2:
        raise HTTPException(409, f"Attack chain {chain_id!r} has no evidence-bearing hop after node 1")
    hops: list[ChainHop] = []
    for node in nodes:
        if not node.node_exists:
            raise HTTPException(409, f"Attack chain {chain_id!r} node {node.position} ({node.node_id}) is missing")
        if node.position == 1:
            continue
        if node.proof_count > 1:
            raise HTTPException(409, f"Attack chain {chain_id!r} hop {node.position - 1} has ambiguous finding proof")
        if not node.finding_id or not node.edge_ids:
            raise HTTPException(409, f"Attack chain {chain_id!r} hop {node.position - 1} has no finding proof")
        hops.append(ChainHop(node.finding_id, tuple(node.edge_ids)))
    return ChainPath(chain_id, tuple(node.node_id for node in nodes), tuple(hops), any(node.tier0 for node in nodes))


class PostgresChainRepository:
    def __init__(self, database_url: str) -> None:
        self._database_url = database_url

    def load(self, engagement_id: UUID) -> tuple[ChainPath, ...]:
        try:
            with psycopg.connect(self._database_url, row_factory=class_row(_ChainNode), connect_timeout=5) as connection:
                connection.isolation_level = psycopg.IsolationLevel.REPEATABLE_READ
                connection.read_only = True
                connection.execute("SET LOCAL statement_timeout = '5s'")
                rows = connection.execute(_CHAIN_QUERY, (engagement_id, MAX_CHAIN_NODES + 1)).fetchall()
        except (psycopg.Error, ValueError):
            raise HTTPException(503, "Attack chain storage unavailable") from None
        if len(rows) > MAX_CHAIN_NODES:
            raise HTTPException(503, "Attack chain storage exceeded the supported response size")
        return tuple(_recorded_path(chain_id, tuple(nodes)) for chain_id, nodes in groupby(rows, lambda row: row.chain_id))


def graph_path_cost(
    client: httpx.Client, graph_url: str, owner: UUID, chain: ChainPath, *, deadline: float,
) -> float | None:
    """Use graph-svc only when its path describes the exact recorded proof sequence."""
    timeout = min(GRAPH_TIMEOUT_SECONDS, deadline - monotonic())
    if timeout <= 0 or not chain.hops:
        return None
    deadline = monotonic() + timeout
    try:
        with client.stream(
            "POST", f"{graph_url.rstrip('/')}/paths",
            json={"engagement_id": str(owner), "src": str(chain.node_ids[0]), "dst": str(chain.node_ids[-1])},
            timeout=timeout, follow_redirects=False,
        ) as response:
            if response.status_code != 200:
                return None
            raw = bytearray()
            for chunk in response.iter_bytes():
                if monotonic() > deadline or len(raw) + len(chunk) > MAX_GRAPH_BYTES:
                    return None
                raw.extend(chunk)
        edges = GRAPH_EDGES.validate_json(bytes(raw))
    except (httpx.HTTPError, httpx.InvalidURL, ValidationError):
        return None
    node_pairs = tuple(pairwise(chain.node_ids))
    if len(edges) != len(chain.hops) or len(edges) != len(node_pairs):
        return None
    for edge, hop, (src, dst) in zip(edges, chain.hops, node_pairs, strict=True):
        if (edge.engagement_id != str(owner) or edge.src_node != src or edge.dst_node != dst
                or edge.proven_by_finding != hop.finding_id or edge.id not in hop.edge_ids):
            return None
    cost = sum((edge.traversal_cost for edge in edges), 0.0)
    return cost if math.isfinite(cost) else None
