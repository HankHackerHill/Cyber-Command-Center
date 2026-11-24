"""In-process API checks against synthetic graphs; no client network traffic."""

import json
from pathlib import Path
from types import TracebackType
from typing import TypedDict, cast
from uuid import UUID

import psycopg
import pytest
from contracts.findings import AssetEdge, AssetNode
from fastapi.testclient import TestClient

from main import PostgresGraphRepository, create_app
from paths import Graph


class ExpectedPath(TypedDict):
    path_node_ids: list[str]
    total_traversal_cost: float


class ExpectedGraph(TypedDict):
    shortest_path_entry_to_tier0: ExpectedPath
    nodes_with_no_path_to_tier0: list[str]


class FixtureData(TypedDict):
    engagement_id: str
    entry_node_id: str
    tier0_node_ids: list[str]
    nodes: list[dict[str, object]]
    edges: list[dict[str, object]]
    expected: ExpectedGraph


class MemoryRepository:
    def __init__(self, *graphs: Graph) -> None:
        self.graphs = {graph.engagement_id: graph for graph in graphs}
        self.calls: list[str] = []

    def load(self, engagement_id: str) -> Graph | None:
        self.calls.append(engagement_id)
        return self.graphs.get(engagement_id)


@pytest.fixture
def known() -> tuple[Graph, FixtureData]:
    path = Path(__file__).resolve().parents[3] / "tests/fixtures/graph_known.json"
    raw = cast(FixtureData, json.loads(path.read_bytes()))
    engagement_id = raw["engagement_id"]
    graph = Graph(
        engagement_id,
        [AssetNode.model_validate(dict(node, engagement_id=engagement_id)) for node in raw["nodes"]],
        [AssetEdge.model_validate(dict(edge, engagement_id=engagement_id)) for edge in raw["edges"]],
    )
    return graph, raw


def test_fixture_path_api_round_trip(known: tuple[Graph, FixtureData]) -> None:
    graph, raw = known
    expected = raw["expected"]["shortest_path_entry_to_tier0"]
    with TestClient(create_app(repository=MemoryRepository(graph))) as client:
        response = client.post("/paths", json={
            "engagement_id": graph.engagement_id,
            "src": raw["entry_node_id"],
            "dst": raw["tier0_node_ids"][0],
        })
    assert response.status_code == 200
    edges = [AssetEdge.model_validate(edge) for edge in response.json()]
    assert [edge.id for edge in edges] == ["edge-0001", "edge-0002", "edge-0003"]
    assert edges == list(graph.edges[:3])
    assert [str(edges[0].src_node), *(str(edge.dst_node) for edge in edges)] == expected["path_node_ids"]
    assert sum(edge.traversal_cost for edge in edges) == expected["total_traversal_cost"] == 3.5
    assert all(edge.engagement_id == graph.engagement_id for edge in edges)


def test_fixture_reach_api_returns_exact_chain(known: tuple[Graph, FixtureData]) -> None:
    graph, raw = known
    with TestClient(create_app(repository=MemoryRepository(graph))) as client:
        response = client.post("/tier0-reach", json={"engagement_id": graph.engagement_id})
    assert response.status_code == 200
    nodes = [AssetNode.model_validate(node) for node in response.json()]
    expected_ids = raw["expected"]["shortest_path_entry_to_tier0"]["path_node_ids"]
    assert [str(node.id) for node in nodes] == expected_ids
    assert nodes == [node for node in graph.nodes if str(node.id) in expected_ids]
    assert {str(node.id) for node in graph.nodes} - {str(node.id) for node in nodes} == set(
        raw["expected"]["nodes_with_no_path_to_tier0"]
    )


def test_unreachable_reverse_and_identity_paths(known: tuple[Graph, FixtureData]) -> None:
    graph, raw = known
    with TestClient(create_app(repository=MemoryRepository(graph))) as client:
        for src, dst in [
            (raw["expected"]["nodes_with_no_path_to_tier0"][0], raw["tier0_node_ids"][0]),
            (raw["tier0_node_ids"][0], raw["entry_node_id"]),
            (raw["entry_node_id"], raw["entry_node_id"]),
        ]:
            response = client.post("/paths", json={"engagement_id": graph.engagement_id, "src": src, "dst": dst})
            assert response.status_code == 200
            assert response.json() == []


def test_unknown_engagement_and_nodes_return_404(known: tuple[Graph, FixtureData]) -> None:
    graph, raw = known
    with TestClient(create_app(repository=MemoryRepository(graph))) as client:
        assert client.post("/tier0-reach", json={"engagement_id": "missing"}).status_code == 404
        for engagement_id, src, dst in [
            ("missing", raw["entry_node_id"], raw["tier0_node_ids"][0]),
            (graph.engagement_id, str(UUID(int=1)), raw["tier0_node_ids"][0]),
            (graph.engagement_id, raw["entry_node_id"], str(UUID(int=1))),
            (graph.engagement_id, str(UUID(int=1)), str(UUID(int=1))),
        ]:
            response = client.post("/paths", json={"engagement_id": engagement_id, "src": src, "dst": dst})
            assert response.status_code == 404


def test_engagements_cannot_combine_edges_with_shared_asset_ids(known: tuple[Graph, FixtureData]) -> None:
    graph, raw = known
    first = Graph(graph.engagement_id, graph.nodes, graph.edges[:1])
    other_id = "eng_other"
    second = Graph(
        other_id,
        [node.model_copy(update={"engagement_id": other_id}) for node in graph.nodes],
        [edge.model_copy(update={"engagement_id": other_id}) for edge in graph.edges[1:3]],
    )
    repository = MemoryRepository(first, second)
    with TestClient(create_app(repository=repository)) as client:
        for engagement_id in [first.engagement_id, second.engagement_id]:
            response = client.post("/paths", json={
                "engagement_id": engagement_id, "src": raw["entry_node_id"], "dst": raw["tier0_node_ids"][0],
            })
            assert response.status_code == 200
            assert response.json() == []
        reachable = client.post("/tier0-reach", json={"engagement_id": first.engagement_id})
        assert [node["id"] for node in reachable.json()] == raw["tier0_node_ids"]
        reachable = client.post("/tier0-reach", json={"engagement_id": second.engagement_id})
        assert [node["id"] for node in reachable.json()] == [str(node.id) for node in second.nodes[1:4]]
        response = client.post("/paths", json={
            "engagement_id": other_id, "src": str(second.nodes[1].id), "dst": raw["tier0_node_ids"][0],
        })
        assert response.status_code == 200
        assert [edge["engagement_id"] for edge in response.json()] == [other_id, other_id]


@pytest.mark.parametrize("route,payload", [
    ("/tier0-reach", {}),
    ("/tier0-reach", {"engagement_id": ""}),
    ("/tier0-reach", {"engagement_id": 123}),
    ("/tier0-reach", {"engagement_id": None}),
    ("/tier0-reach", {"engagement_id": "eng\x00bad"}),
    ("/tier0-reach", {"engagement_id": "eng\ud800bad"}),
    ("/tier0-reach", {"engagement_id": "eng", "src": str(UUID(int=1))}),
    ("/paths", {"engagement_id": "eng", "src": "not-a-uuid", "dst": str(UUID(int=1))}),
    ("/paths", {"engagement_id": "eng", "src": str(UUID(int=1))}),
    ("/paths", {"engagement_id": "eng", "src": str(UUID(int=1)), "dst": str(UUID(int=2)), "extra": True}),
])
def test_invalid_requests_rejected_before_repository_access(route: str, payload: dict[str, object]) -> None:
    repository = MemoryRepository()
    with TestClient(create_app(repository=repository)) as client:
        response = client.post(route, content=json.dumps(payload), headers={"Content-Type": "application/json"})
    assert response.status_code == 422
    assert repository.calls == []


@pytest.mark.parametrize("failure", [
    psycopg.OperationalError("postgresql://user:secret@private-db/internal"),
    ValueError("corrupt stored client graph: secret"),
])
@pytest.mark.parametrize("route", ["/paths", "/tier0-reach"])
def test_storage_failures_are_unavailable_without_leaking_details(route: str, failure: Exception) -> None:
    class BrokenRepository:
        def load(self, engagement_id: str) -> Graph | None:
            raise failure

    payload: dict[str, object] = {"engagement_id": "eng"}
    if route == "/paths":
        payload.update(src=str(UUID(int=1)), dst=str(UUID(int=2)))
    with TestClient(create_app(repository=BrokenRepository())) as client:
        response = client.post(route, json=payload)
    assert response.status_code == 503
    assert "secret" not in response.text
    assert "private-db" not in response.text


def test_empty_known_engagement_has_no_reachable_nodes() -> None:
    with TestClient(create_app(repository=MemoryRepository(Graph("empty", [], [])))) as client:
        response = client.post("/tier0-reach", json={"engagement_id": "empty"})
    assert response.status_code == 200
    assert response.json() == []


@pytest.mark.parametrize("route", ["/paths", "/tier0-reach"])
def test_wrong_engagement_from_repository_is_never_disclosed(route: str, known: tuple[Graph, FixtureData]) -> None:
    graph, raw = known

    class WrongRepository:
        def load(self, engagement_id: str) -> Graph | None:
            return graph

    payload: dict[str, object] = {"engagement_id": "another-engagement"}
    if route == "/paths":
        payload.update(src=raw["entry_node_id"], dst=raw["tier0_node_ids"][0])
    with TestClient(create_app(repository=WrongRepository())) as client:
        response = client.post(route, json=payload)
    assert response.status_code == 503
    assert graph.nodes[0].canonical_identifier not in response.text
    assert graph.engagement_id not in response.text


def test_uuid_engagement_spellings_resolve_to_one_repository_key() -> None:
    engagement_id = "a1111111-b111-4111-8111-c11111111111"
    repository = MemoryRepository(Graph(engagement_id, [], []))
    with TestClient(create_app(repository=repository)) as client:
        for spelling in [engagement_id.upper(), UUID(engagement_id).hex, "{" + engagement_id + "}"]:
            response = client.post("/tier0-reach", json={"engagement_id": spelling})
            assert response.status_code == 200
            assert response.json() == []
    assert repository.calls == [engagement_id] * 3


class DatabaseDouble:
    """Assert transaction and bound-key properties without any database I/O."""

    def __init__(self, graph: Graph, exists: bool = True) -> None:
        self.graph = graph
        self.exists = exists
        self.queries: list[tuple[str, tuple[UUID, ...]]] = []
        self.connections: list[ConnectionDouble] = []

    def connect(self, database_url: str, *, row_factory: object, connect_timeout: int) -> "ConnectionDouble":
        assert database_url == "postgresql://synthetic-test-only"
        assert row_factory is psycopg.rows.dict_row
        assert connect_timeout > 0
        connection = ConnectionDouble(self)
        self.connections.append(connection)
        return connection


class ConnectionDouble:
    def __init__(self, database: DatabaseDouble) -> None:
        self.database = database
        self.isolation_level: psycopg.IsolationLevel | None = None
        self.read_only = False
        self.closed = False

    def __enter__(self) -> "ConnectionDouble":
        return self

    def __exit__(self, kind: type[BaseException] | None, error: BaseException | None, tb: TracebackType | None) -> None:
        self.closed = True

    def cursor(self) -> "CursorDouble":
        return CursorDouble(self)


class CursorDouble:
    def __init__(self, connection: ConnectionDouble) -> None:
        self.connection = connection
        self.query = ""

    def __enter__(self) -> "CursorDouble":
        return self

    def __exit__(self, kind: type[BaseException] | None, error: BaseException | None, tb: TracebackType | None) -> None:
        return None

    def execute(self, query: str, parameters: tuple[UUID, ...]) -> None:
        assert self.connection.read_only
        assert self.connection.isolation_level == psycopg.IsolationLevel.REPEATABLE_READ
        assert query.lstrip().upper().startswith("SELECT ")
        assert parameters == (UUID(self.connection.database.graph.engagement_id),)
        assert "WHERE id = %s" in query or "WHERE engagement_id = %s" in query
        self.query = query
        self.connection.database.queries.append((query, parameters))

    def fetchone(self) -> dict[str, object] | None:
        assert "FROM engagements" in self.query
        if self.connection.database.exists:
            return {"id": UUID(self.connection.database.graph.engagement_id)}
        return None

    def fetchall(self) -> list[dict[str, object]]:
        graph = self.connection.database.graph
        if "FROM asset_nodes" in self.query:
            return [node.model_dump(exclude={"engagement_id"}) for node in graph.nodes]
        assert "FROM asset_edges" in self.query
        return [edge.model_dump(exclude={"engagement_id"}) for edge in graph.edges]


@pytest.mark.parametrize("shape", ["known", "empty", "unknown"])
def test_postgres_loader_uses_one_read_only_scoped_snapshot(
    shape: str, known: tuple[Graph, FixtureData], monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture_graph, _ = known
    engagement_id = "a1111111-b111-4111-8111-c11111111111"
    graph = Graph(
        engagement_id,
        [node.model_copy(update={"engagement_id": engagement_id}) for node in fixture_graph.nodes]
        if shape == "known" else [],
        [edge.model_copy(update={"engagement_id": engagement_id}) for edge in fixture_graph.edges]
        if shape == "known" else [],
    )
    database = DatabaseDouble(graph, exists=shape != "unknown")
    monkeypatch.setattr("main.psycopg.connect", database.connect)
    loaded = PostgresGraphRepository("postgresql://synthetic-test-only").load(engagement_id)
    assert loaded == (None if shape == "unknown" else graph)
    assert len(database.connections) == 1
    assert database.connections[0].closed
    if shape == "unknown":
        assert len(database.queries) == 1
        assert "FROM engagements" in database.queries[0][0]
    else:
        assert len(database.queries) == 3
        assert "FROM engagements" in database.queries[0][0]
        assert "FROM asset_nodes" in database.queries[1][0]
        assert "FROM asset_edges" in database.queries[2][0]


def test_postgres_loader_rejects_opaque_fixture_id_without_connecting(monkeypatch: pytest.MonkeyPatch) -> None:
    def unexpected_connect(*args: object, **kwargs: object) -> None:
        pytest.fail("Opaque fixture IDs must not be sent to a UUID database column")

    monkeypatch.setattr("main.psycopg.connect", unexpected_connect)
    assert PostgresGraphRepository("postgresql://synthetic-test-only").load("eng_9f82a1c4") is None
