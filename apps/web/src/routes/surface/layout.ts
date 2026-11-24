import type { AssetEdge, AssetNode } from "../../api/client";

export const GRAPH_WIDTH = 720;
export const GRAPH_HEIGHT = 405;
export const VISIBLE_NODE_LIMIT = 72;
export const VISIBLE_EDGE_LIMIT = 288;

type Point = { x: number; y: number };

function compareText(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

export function topologyView(nodes: AssetNode[], edges: AssetEdge[], path: AssetEdge[]) {
  const selectedEdges = new Set(path.map((edge) => edge.id));
  const selectedNodes = new Set(path.flatMap((edge) => [edge.src_node, edge.dst_node]));
  const relevantFirst = (a: string, b: string, selection: Set<string>) =>
    Number(selection.has(b)) - Number(selection.has(a)) || compareText(a, b);
  const visibleNodes = [...nodes].sort((a, b) => relevantFirst(a.id, b.id, selectedNodes)).slice(0, VISIBLE_NODE_LIMIT);
  const visibleIds = new Set(visibleNodes.map((node) => node.id));
  const visibleEdges = edges.filter((edge) => visibleIds.has(edge.src_node) && visibleIds.has(edge.dst_node))
    .sort((a, b) => relevantFirst(a.id, b.id, selectedEdges)).slice(0, VISIBLE_EDGE_LIMIT);
  return { visibleNodes, visibleEdges };
}

/** Finite, deterministic force simulation. No animation, plugins, or network access. */
export function layoutTopology(nodes: AssetNode[], edges: AssetEdge[]): Map<string, Point> {
  const cx = GRAPH_WIDTH / 2;
  const cy = GRAPH_HEIGHT / 2;
  const points = nodes.map((node, index) => {
    const angle = index * Math.PI * (3 - Math.sqrt(5));
    const radius = 20 + 140 * Math.sqrt(index / Math.max(1, nodes.length - 1));
    return { id: node.id, x: cx + Math.cos(angle) * radius, y: cy + Math.sin(angle) * radius * 0.8 };
  });
  const indexes = new Map(points.map((point, index) => [point.id, index]));
  const links = edges.map((edge) => [indexes.get(edge.src_node), indexes.get(edge.dst_node)] as const)
    .filter(([a, b]) => a !== undefined && b !== undefined && a !== b);
  for (let step = 0; step < 100; step += 1) {
    const forces = points.map((point) => ({ x: (cx - point.x) * 0.018, y: (cy - point.y) * 0.018 }));
    for (let a = 0; a < points.length; a += 1) {
      for (let b = a + 1; b < points.length; b += 1) {
        const dx = points[a].x - points[b].x;
        const dy = points[a].y - points[b].y;
        const d2 = dx * dx + dy * dy + 1;
        const scale = 2200 / (d2 * Math.sqrt(d2));
        forces[a].x += dx * scale;
        forces[a].y += dy * scale;
        forces[b].x -= dx * scale;
        forces[b].y -= dy * scale;
      }
    }
    for (const [a, b] of links) {
      if (a === undefined || b === undefined) continue;
      const dx = points[b].x - points[a].x;
      const dy = points[b].y - points[a].y;
      const distance = Math.hypot(dx, dy) || 1;
      const scale = (distance - 88) * 0.035 / distance;
      forces[a].x += dx * scale;
      forces[a].y += dy * scale;
      forces[b].x -= dx * scale;
      forces[b].y -= dy * scale;
    }
    const maxMove = 13 - step * 0.12;
    for (let index = 0; index < points.length; index += 1) {
      const point = points[index];
      const force = forces[index];
      point.x = Math.min(GRAPH_WIDTH - 52, Math.max(52, point.x + Math.min(maxMove, Math.max(-maxMove, force.x))));
      point.y = Math.min(GRAPH_HEIGHT - 44, Math.max(44, point.y + Math.min(maxMove, Math.max(-maxMove, force.y))));
    }
  }
  return new Map(points.map((point) => [point.id, point]));
}

export function pathMatchesSnapshot(
  path: AssetEdge[], inventory: AssetEdge[], source: string, destination: string,
): boolean {
  const known = new Map(inventory.map((edge) => [edge.id, edge]));
  const seen = new Set([source]);
  let next = source;
  for (const edge of path) {
    const previous = known.get(edge.id);
    if (!previous || previous.src_node !== next || edge.src_node !== next ||
        previous.dst_node !== edge.dst_node || previous.edge_kind !== edge.edge_kind ||
        seen.has(edge.dst_node)) return false;
    seen.add(edge.dst_node);
    next = edge.dst_node;
  }
  return path.length === 0 || next === destination;
}
