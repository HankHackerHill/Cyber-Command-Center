"""Pure, directed graph analysis using the frozen MS0 asset contracts."""

import heapq
import math
from collections.abc import Iterable
from dataclasses import dataclass
from fractions import Fraction
from uuid import UUID

from contracts.findings import AssetEdge, AssetNode


@dataclass(frozen=True, init=False)
class Graph:
    """A validated snapshot of one engagement, independent of input ordering."""

    engagement_id: str
    nodes: tuple[AssetNode, ...]
    edges: tuple[AssetEdge, ...]

    def __init__(
        self, engagement_id: str, nodes: Iterable[AssetNode], edges: Iterable[AssetEdge],
    ) -> None:
        ordered_nodes = tuple(sorted(nodes, key=lambda node: node.id))
        ordered_edges = tuple(sorted(edges, key=lambda edge: edge.id))
        node_ids = {node.id for node in ordered_nodes}
        if len(node_ids) != len(ordered_nodes):
            raise ValueError("Duplicate node ID")
        if len({edge.id for edge in ordered_edges}) != len(ordered_edges):
            raise ValueError("Duplicate edge ID")
        if any(node.engagement_id != engagement_id for node in ordered_nodes):
            raise ValueError("Node belongs to another engagement")
        for edge in ordered_edges:
            if edge.engagement_id != engagement_id:
                raise ValueError("Edge belongs to another engagement")
            if edge.src_node not in node_ids or edge.dst_node not in node_ids:
                raise ValueError("Edge endpoint missing from engagement")
            if not math.isfinite(edge.traversal_cost) or edge.traversal_cost < 0:
                raise ValueError("Traversal cost must be finite and nonnegative")
        object.__setattr__(self, "engagement_id", engagement_id)
        # MS0 models are frozen but their metadata dictionaries are shallowly
        # mutable. Detach the snapshot from the repository's input records.
        object.__setattr__(self, "nodes", tuple(node.model_copy(deep=True) for node in ordered_nodes))
        object.__setattr__(self, "edges", ordered_edges)


def shortest_path(graph: Graph, src: UUID, dst: UUID) -> list[AssetEdge]:
    """Return directed edges in traversal order, or [] if no path exists.

    Missing endpoints raise KeyError; src == dst has the empty path. Dijkstra
    settles its frontier by (total cost, node ID, incoming edge ID), visiting
    outgoing edges by (destination node ID, edge ID). The first equal-cost
    predecessor is retained. This defines deterministic frontier tie-breaking,
    including parallel edges, rather than lexicographic complete-path ranking.
    Exact internal sums of the stored binary floats avoid overflow and rounding
    changing path selection. Returned contracts retain their original costs.
    """
    adjacency: dict[UUID, list[AssetEdge]] = {node.id: [] for node in graph.nodes}
    for node_id in (src, dst):
        if node_id not in adjacency:
            raise KeyError(str(node_id))
    for edge in graph.edges:
        adjacency[edge.src_node].append(edge)
    for outgoing in adjacency.values():
        outgoing.sort(key=lambda edge: (edge.dst_node, edge.id))

    distances = {src: Fraction(0)}
    frontier: list[tuple[Fraction, UUID, str]] = [(Fraction(0), src, "")]
    predecessors: dict[UUID, AssetEdge] = {}
    settled: set[UUID] = set()
    while frontier:
        distance, node_id, _ = heapq.heappop(frontier)
        if node_id in settled or distance != distances[node_id]:
            continue
        settled.add(node_id)
        if node_id == dst:
            result: list[AssetEdge] = []
            while node_id != src:
                edge = predecessors[node_id]
                result.append(edge)
                node_id = edge.src_node
            result.reverse()
            return result
        for edge in adjacency[node_id]:
            if edge.dst_node in settled:
                continue
            candidate = distance + Fraction.from_float(edge.traversal_cost)
            previous = distances.get(edge.dst_node)
            if previous is None or candidate < previous:
                distances[edge.dst_node] = candidate
                predecessors[edge.dst_node] = edge
                heapq.heappush(frontier, (candidate, edge.dst_node, edge.id))
    return []


def nodes_reaching_tier0(graph: Graph) -> list[AssetNode]:
    """Return all ancestors of explicitly marked Tier-0 nodes, including self.

    Tier-0 membership requires the JSON boolean true in metadata.tier0. The
    entry node's chain in graph_known.json leads to just such a marked node;
    no inference from node names, categories or unreachable sink nodes is used.
    """
    reverse: dict[UUID, list[UUID]] = {node.id: [] for node in graph.nodes}
    for edge in graph.edges:
        reverse[edge.dst_node].append(edge.src_node)
    reached = {node.id for node in graph.nodes if node.metadata.get("tier0") is True}
    pending = list(sorted(reached, reverse=True))
    while pending:
        for predecessor in reverse[pending.pop()]:
            if predecessor not in reached:
                reached.add(predecessor)
                pending.append(predecessor)
    return [node for node in graph.nodes if node.id in reached]


def nodes_with_no_path_to_tier0(graph: Graph) -> list[AssetNode]:
    """Return exactly the complement of Tier-0 reachability in node ID order."""
    reached = {node.id for node in nodes_reaching_tier0(graph)}
    return [node for node in graph.nodes if node.id not in reached]
