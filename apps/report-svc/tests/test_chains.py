"""Exercise the report's chain reads against the unchanged MS0 schema."""

import json
import os
from collections.abc import Iterator
from pathlib import Path
from uuid import UUID, uuid4

import psycopg
import pytest
from contracts.findings import AssetEdge, AssetNode
from fastapi import HTTPException
from psycopg import sql
from psycopg.conninfo import make_conninfo
from psycopg.types.json import Jsonb

from chains import ChainHop, ChainPath, PostgresChainRepository

ROOT = Path(__file__).resolve().parents[3]
CHAIN_ID = "known-assessment-chain"


@pytest.fixture
def chain_database() -> Iterator[str]:
    url = os.getenv("REPORT_TEST_DATABASE_URL")
    if not url:
        pytest.skip("Set REPORT_TEST_DATABASE_URL to a disposable PostgreSQL database")
    schema = "report_chain_test_" + uuid4().hex
    with psycopg.connect(url, autocommit=True) as admin:
        identifier = sql.Identifier(schema)
        admin.execute(sql.SQL("CREATE SCHEMA {}").format(identifier))
        try:
            scoped_url = make_conninfo(url, options=f"-c search_path={schema}")
            with psycopg.connect(scoped_url) as conn:
                assert conn.execute("SELECT current_schema()").fetchone() == (schema,)
                conn.execute((ROOT / "db/schema.sql").read_text(encoding="utf-8"))
            yield scoped_url
        finally:
            admin.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(identifier))


def seed_graph(conn: psycopg.Connection, owner: UUID, finding_prefix: str = "") -> list[UUID]:
    raw = json.loads((ROOT / "tests/fixtures/graph_known.json").read_bytes())
    path = [UUID(identifier) for identifier in raw["expected"]["shortest_path_entry_to_tier0"]["path_node_ids"]]
    conn.execute("INSERT INTO engagements (id) VALUES (%s)", (owner,))
    for record in raw["nodes"]:
        node = AssetNode.model_validate(dict(record, engagement_id=str(owner)))
        conn.execute(
            """INSERT INTO asset_nodes
               (engagement_id, id, asset_category, canonical_identifier, metadata, discovered_by)
               VALUES (%s, %s, %s, %s, %s, %s)""",
            (owner, node.id, node.asset_category, node.canonical_identifier, Jsonb(node.metadata), node.discovered_by),
        )
    for record in raw["edges"]:
        edge = AssetEdge.model_validate(dict(record, engagement_id=str(owner)))
        assert edge.proven_by_finding is not None
        finding_id = finding_prefix + edge.proven_by_finding
        conn.execute(
            """INSERT INTO findings (engagement_id, id, title, confidence_score, status)
               VALUES (%s, %s, %s, 1.0, 'CONFIRMED') ON CONFLICT DO NOTHING""",
            (owner, finding_id, f"Recorded finding {finding_id}"),
        )
        conn.execute(
            """INSERT INTO asset_edges
               (engagement_id, id, src_node, dst_node, edge_kind, traversal_cost, proven_by_finding)
               VALUES (%s, %s, %s, %s, %s, %s, %s)""",
            (owner, edge.id, edge.src_node, edge.dst_node, edge.edge_kind, edge.traversal_cost, finding_id),
        )
    conn.execute(
        "INSERT INTO attack_chains (engagement_id, id, path_node_ids) VALUES (%s, %s, %s)",
        (owner, CHAIN_ID, path),
    )
    return path


def test_loads_fixture_chain_in_path_order_for_its_engagement(chain_database: str) -> None:
    owner, other, empty = uuid4(), uuid4(), uuid4()
    with psycopg.connect(chain_database) as conn:
        path = seed_graph(conn, owner)
        seed_graph(conn, other, "other-")
        conn.execute("INSERT INTO engagements (id) VALUES (%s)", (empty,))
    repository = PostgresChainRepository(chain_database)
    for engagement, prefix in ((owner, ""), (other, "other-")):
        hops = tuple(ChainHop(f"{prefix}fnd-{index:04}", (f"edge-{index:04}",)) for index in range(1, 4))
        assert repository.load(engagement) == (ChainPath(CHAIN_ID, tuple(path), hops, True),)
    assert repository.load(empty) == ()


def test_missing_hop_proof_cannot_use_another_engagements_edge(chain_database: str) -> None:
    owner, other = uuid4(), uuid4()
    with psycopg.connect(chain_database) as conn:
        seed_graph(conn, owner)
        seed_graph(conn, other)
        conn.execute("DELETE FROM asset_edges WHERE engagement_id = %s AND id = 'edge-0002'", (owner,))
    with pytest.raises(HTTPException) as refusal:
        PostgresChainRepository(chain_database).load(owner)
    assert refusal.value.status_code == 409
    assert CHAIN_ID in refusal.value.detail
    assert "hop 2" in refusal.value.detail.lower()


def test_parallel_edges_with_conflicting_proofs_refuse_the_chain(chain_database: str) -> None:
    owner = uuid4()
    with psycopg.connect(chain_database) as conn:
        seed_graph(conn, owner)
        conn.execute(
            """INSERT INTO asset_edges
               (engagement_id, id, src_node, dst_node, edge_kind, traversal_cost, proven_by_finding)
               SELECT engagement_id, 'another-edge', src_node, dst_node, edge_kind, traversal_cost, 'fnd-0004'
               FROM asset_edges WHERE engagement_id = %s AND id = 'edge-0002'""",
            (owner,),
        )
    with pytest.raises(HTTPException) as refusal:
        PostgresChainRepository(chain_database).load(owner)
    assert refusal.value.status_code == 409
    assert CHAIN_ID in refusal.value.detail
    assert "hop 2" in refusal.value.detail.lower()
