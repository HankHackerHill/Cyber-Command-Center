"""Fixture acceptance and adversarial cases for directed graph analysis."""

import json
import os
import random
import subprocess
import sys
from pathlib import Path
from typing import TypedDict, cast
from uuid import UUID

import pytest
from contracts.events import ActorType
from contracts.findings import AssetEdge, AssetNode, EdgeKind

from paths import Graph, nodes_reaching_tier0, nodes_with_no_path_to_tier0, shortest_path

FIXTURE = Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "graph_known.json"
SERVICE = Path(__file__).resolve().parents[1]
ENGAGEMENT = "synthetic-engagement"


class ExpectedPath(TypedDict):
    path_node_ids: list[str]
    total_traversal_cost: float


class ExpectedGraph(TypedDict):
    shortest_path_entry_to_tier0: ExpectedPath
    nodes_with_no_path_to_tier0: list[str]
    cycle_present_between: list[str]
    dijkstra_must_terminate: bool


class KnownFixture(TypedDict):
    engagement_id: str
    entry_node_id: str
    tier0_node_ids: list[str]
    nodes: list[dict[str, object]]
    edges: list[dict[str, object]]
    expected: ExpectedGraph


def load_fixture() -> tuple[KnownFixture, Graph]:
    fixture = cast(KnownFixture, json.loads(FIXTURE.read_text()))
    engagement_id = fixture["engagement_id"]
    nodes = [AssetNode.model_validate(dict(node, engagement_id=engagement_id))
             for node in fixture["nodes"]]
    edges = [AssetEdge.model_validate(dict(edge, engagement_id=engagement_id))
             for edge in fixture["edges"]]
    return fixture, Graph(engagement_id, nodes, edges)


def node(number: int, *, tier0: bool = False, engagement_id: str = ENGAGEMENT) -> AssetNode:
    return AssetNode(
        id=UUID(int=number), engagement_id=engagement_id, asset_category="IAM_ROLE",
        canonical_identifier=f"synthetic-role-{number}", metadata={"tier0": tier0},
        discovered_by=ActorType.AI_AGENT,
    )


def edge(identifier: str, src: AssetNode, dst: AssetNode, cost: float = 1.0) -> AssetEdge:
    return AssetEdge(
        id=identifier, engagement_id=src.engagement_id, src_node=src.id, dst_node=dst.id,
        edge_kind=EdgeKind.IAM_ASSUME, traversal_cost=cost,
    )


def test_fixture_exact_path_and_cost() -> None:
    fixture, graph = load_fixture()
    expected = fixture["expected"]["shortest_path_entry_to_tier0"]
    path = shortest_path(graph, UUID(fixture["entry_node_id"]), UUID(fixture["tier0_node_ids"][0]))

    assert [str(path[0].src_node), *(str(item.dst_node) for item in path)] == expected["path_node_ids"]
    assert [item.id for item in path] == ["edge-0001", "edge-0002", "edge-0003"]
    assert path == [AssetEdge.model_validate(dict(item, engagement_id=fixture["engagement_id"]))
                    for item in fixture["edges"][:3]]
    assert sum(item.traversal_cost for item in path) == expected["total_traversal_cost"] == 3.5


def test_fixture_exactly_four_nodes_without_tier0_path() -> None:
    fixture, graph = load_fixture()
    unreachable = nodes_with_no_path_to_tier0(graph)
    assert [str(item.id) for item in unreachable] == fixture["expected"]["nodes_with_no_path_to_tier0"]
    reachable = nodes_reaching_tier0(graph)
    assert [str(item.id) for item in reachable] == fixture["expected"]["shortest_path_entry_to_tier0"]["path_node_ids"]
    assert {item.id for item in unreachable}.isdisjoint(item.id for item in reachable)
    assert {item.id for item in unreachable + reachable} == {item.id for item in graph.nodes}


def test_fixture_pod_cycle_terminates_with_deadline() -> None:
    # A broken traversal fails this test within five seconds instead of hanging pytest.
    script = """
import json
import sys
from uuid import UUID
from contracts.findings import AssetNode, AssetEdge
from paths import Graph, shortest_path, nodes_reaching_tier0
fixture = json.loads(open(sys.argv[1]).read())
engagement = fixture['engagement_id']
nodes = [AssetNode.model_validate(dict(item, engagement_id=engagement)) for item in fixture['nodes']]
edges = [AssetEdge.model_validate(dict(item, engagement_id=engagement)) for item in fixture['edges']]
graph = Graph(engagement, nodes, edges)
a, b = map(UUID, fixture['expected']['cycle_present_between'])
target = UUID(fixture['tier0_node_ids'][0])
assert [edge.id for edge in shortest_path(graph, a, b)] == ['edge-0006']
assert [edge.id for edge in shortest_path(graph, b, a)] == ['edge-0007']
assert shortest_path(graph, a, target) == []
assert shortest_path(graph, b, target) == []
assert len(nodes_reaching_tier0(graph)) == 4
"""
    subprocess.run(
        [sys.executable, "-c", script, str(FIXTURE)], cwd=SERVICE,
        env={**os.environ, "PYTHONPATH": os.pathsep.join(sys.path)},
        check=True, capture_output=True, text=True, timeout=5,
    )


def test_fixture_is_deterministic_under_shuffled_input() -> None:
    fixture, graph = load_fixture()
    src, dst = UUID(fixture["entry_node_id"]), UUID(fixture["tier0_node_ids"][0])
    expected_path = shortest_path(graph, src, dst)
    expected_reach = nodes_reaching_tier0(graph)
    expected_no_path = nodes_with_no_path_to_tier0(graph)
    for seed in range(32):
        nodes, edges = list(graph.nodes), list(graph.edges)
        rng = random.Random(seed)
        rng.shuffle(nodes)
        rng.shuffle(edges)
        shuffled = Graph(graph.engagement_id, nodes, edges)
        assert shortest_path(shuffled, src, dst) == expected_path
        assert nodes_reaching_tier0(shuffled) == expected_reach
        assert nodes_with_no_path_to_tier0(shuffled) == expected_no_path


def test_equal_cost_ties_use_node_id_then_edge_id() -> None:
    src, low, high, dst = node(100), node(2), node(3), node(200, tier0=True)
    nodes = [src, high, dst, low]
    edges = [
        edge("z-parallel", src, low), edge("a-parallel", src, low),
        edge("0-high", src, high), edge("z-low-to-target", low, dst),
        edge("a-high-to-target", high, dst),
    ]
    for seed in range(32):
        rng = random.Random(seed)
        rng.shuffle(nodes)
        rng.shuffle(edges)
        graph = Graph(ENGAGEMENT, nodes, edges)
        assert [item.id for item in shortest_path(graph, src.id, dst.id)] == [
            "a-parallel", "z-low-to-target",
        ]


def test_dijkstra_uses_cost_instead_of_hop_count_and_discards_stale_entries() -> None:
    src, middle, improved, dst = node(1), node(2), node(3), node(4)
    edges = [edge("direct", src, dst, 10), edge("old", src, improved, 8),
             edge("first", src, middle, 1), edge("improve", middle, improved, 1),
             edge("last", improved, dst, 1)]
    graph = Graph(ENGAGEMENT, [src, middle, improved, dst], edges)
    assert [item.id for item in shortest_path(graph, src.id, dst.id)] == ["first", "improve", "last"]


def test_finite_edge_costs_can_have_path_sums_above_float_range() -> None:
    src, cheaper, expensive, dst = node(1), node(3), node(2), node(4)
    graph = Graph(ENGAGEMENT, [src, cheaper, expensive, dst], [
        edge("cheap-first", src, cheaper, 1e308),
        edge("cheap-last", cheaper, dst, 1e308),
        edge("expensive-first", src, expensive, 1.1e308),
        edge("expensive-last", expensive, dst, 1.1e308),
    ])
    # Both accumulated costs overflow binary64. The path must remain reachable,
    # and its selection must still compare the actual sums of the finite costs.
    assert [item.id for item in shortest_path(graph, src.id, dst.id)] == ["cheap-first", "cheap-last"]


def test_zero_cost_cycle_and_self_loop_do_not_change_shortest_path() -> None:
    src, middle, dst = node(1), node(2), node(3, tier0=True)
    graph = Graph(ENGAGEMENT, [src, middle, dst], [
        edge("self", src, src, 0), edge("first", src, middle, 0),
        edge("cycle", middle, src, 0), edge("last", middle, dst, 1),
    ])
    assert [item.id for item in shortest_path(graph, src.id, dst.id)] == ["first", "last"]
    assert nodes_reaching_tier0(graph) == [src, middle, dst]
    assert nodes_with_no_path_to_tier0(graph) == []


def test_paths_are_directed_and_identity_path_is_empty() -> None:
    src, dst = node(1), node(2)
    graph = Graph(ENGAGEMENT, [src, dst], [edge("forward", src, dst)])
    assert shortest_path(graph, dst.id, src.id) == []
    assert shortest_path(graph, src.id, src.id) == []
    assert shortest_path(graph, dst.id, dst.id) == []
    with pytest.raises(KeyError):
        shortest_path(graph, UUID(int=99), dst.id)
    with pytest.raises(KeyError):
        shortest_path(graph, src.id, UUID(int=99))
    with pytest.raises(KeyError):
        shortest_path(graph, UUID(int=99), UUID(int=99))


def test_multiple_tier0_nodes_and_isolated_tier0() -> None:
    src, first, second, isolated, dead = node(1), node(2, tier0=True), node(3, tier0=True), node(4, tier0=True), node(5)
    graph = Graph(ENGAGEMENT, [dead, isolated, second, first, src], [
        edge("to-first", src, first), edge("to-second", src, second),
        edge("outward-only", first, dead),
    ])
    assert nodes_reaching_tier0(graph) == [src, first, second, isolated]
    assert nodes_with_no_path_to_tier0(graph) == [dead]


def test_no_tier0_and_empty_graph() -> None:
    first, second = node(1), node(2)
    graph = Graph(ENGAGEMENT, [first, second], [edge("one", first, second)])
    assert nodes_reaching_tier0(graph) == []
    assert nodes_with_no_path_to_tier0(graph) == [first, second]
    empty = Graph(ENGAGEMENT, [], [])
    assert nodes_reaching_tier0(empty) == []
    assert nodes_with_no_path_to_tier0(empty) == []


@pytest.mark.parametrize("marker", ["true", 1, [True], {"value": True}])
def test_tier0_marker_requires_json_boolean_true(marker: object) -> None:
    marked = node(1).model_copy(update={"metadata": {"tier0": marker}})
    graph = Graph(ENGAGEMENT, [marked], [])
    assert nodes_reaching_tier0(graph) == []


def test_graph_rejects_cross_engagement_records() -> None:
    first, second = node(1), node(2)
    foreign_node = node(3, engagement_id="other-engagement")
    with pytest.raises(ValueError):
        Graph(ENGAGEMENT, [first, foreign_node], [])
    foreign_edge = edge("foreign", first, second).model_copy(update={"engagement_id": "other-engagement"})
    with pytest.raises(ValueError):
        Graph(ENGAGEMENT, [first, second], [foreign_edge])


def test_graph_rejects_duplicate_ids_and_dangling_edges() -> None:
    first, second = node(1), node(2)
    one_edge = edge("duplicate", first, second)
    with pytest.raises(ValueError):
        Graph(ENGAGEMENT, [first, first], [])
    with pytest.raises(ValueError):
        Graph(ENGAGEMENT, [first, second], [one_edge, one_edge])
    with pytest.raises(ValueError):
        Graph(ENGAGEMENT, [first], [one_edge])
    with pytest.raises(ValueError):
        Graph(ENGAGEMENT, [second], [one_edge])


def test_graph_does_not_reorder_callers_lists() -> None:
    first, second, third = node(1), node(2), node(3)
    nodes = [third, second, first]
    edges = [edge("z", second, third), edge("a", first, second)]
    graph = Graph(ENGAGEMENT, nodes, edges)
    assert nodes == [third, second, first]
    assert [item.id for item in edges] == ["z", "a"]
    assert graph.nodes == (first, second, third)
    assert [item.id for item in graph.edges] == ["a", "z"]
