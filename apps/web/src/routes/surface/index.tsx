import { useQuery } from "@tanstack/react-query";
import { useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { getPath, isEngagementId, type AssetEdge, type AssetNode } from "../../api/client";
import { useWorkspace } from "../../workspace";
import { GRAPH_HEIGHT, GRAPH_WIDTH, layoutTopology, pathMatchesSnapshot, topologyView } from "./layout";
import "./surface.css";

const EMPTY_NODES: AssetNode[] = [];
const EMPTY_EDGES: AssetEdge[] = [];

type Selection = { from: string; to: string };

function graphLabel(identifier: string): string {
  return identifier.length <= 23 ? identifier : `${identifier.slice(0, 20)}…`;
}

function GraphCanvas({ nodes, edges, path }: { nodes: AssetNode[]; edges: AssetEdge[]; path: AssetEdge[] }) {
  const canvas = useRef<HTMLCanvasElement>(null);
  const { visibleNodes, visibleEdges } = useMemo(() => topologyView(nodes, edges, path), [nodes, edges, path]);
  const positions = useMemo(() => layoutTopology(visibleNodes, visibleEdges), [visibleNodes, visibleEdges]);
  useEffect(() => {
    const element = canvas.current;
    if (!element) return;
    const context = element.getContext("2d");
    if (!context) return;
    const scale = Math.min(window.devicePixelRatio || 1, 2);
    element.width = Math.round(GRAPH_WIDTH * scale);
    element.height = Math.round(GRAPH_HEIGHT * scale);
    context.setTransform(scale, 0, 0, scale, 0, 0);
    const marks = new Set(path.map((edge) => edge.id));
    const linked = new Set(path.flatMap((edge) => [edge.src_node, edge.dst_node]));
    for (const mark of [false, true]) {
      for (const edge of visibleEdges) {
        if (marks.has(edge.id) !== mark) continue;
        const src = positions.get(edge.src_node);
        const dst = positions.get(edge.dst_node);
        if (!src || !dst) continue;
        const angle = Math.atan2(dst.y - src.y, dst.x - src.x);
        const targetX = dst.x - Math.cos(angle) * 13;
        const targetY = dst.y - Math.sin(angle) * 13;
        context.strokeStyle = mark ? "#faba76" : "#4f6178";
        context.fillStyle = context.strokeStyle;
        context.lineWidth = mark ? 2.8 : 1.3;
        context.beginPath();
        context.moveTo(src.x, src.y);
        context.lineTo(targetX, targetY);
        context.stroke();
        context.beginPath();
        context.moveTo(targetX, targetY);
        context.lineTo(targetX - 7 * Math.cos(angle - 0.42), targetY - 7 * Math.sin(angle - 0.42));
        context.lineTo(targetX - 7 * Math.cos(angle + 0.42), targetY - 7 * Math.sin(angle + 0.42));
        context.closePath();
        context.fill();
      }
    }
    context.font = "11px ui-monospace, monospace";
    context.textAlign = "center";
    for (const node of visibleNodes) {
      const position = positions.get(node.id);
      if (!position) continue;
      const critical = node.metadata.tier0 === true;
      const selected = linked.has(node.id);
      context.strokeStyle = selected ? "#faba76" : critical ? "#ffc582" : "#8cdad9";
      context.fillStyle = selected ? "#5b3528" : critical ? "#3d2820" : "#17333b";
      context.lineWidth = selected ? 2.5 : 1.6;
      context.beginPath();
      if (critical) {
        context.moveTo(position.x, position.y - 11);
        context.lineTo(position.x + 11, position.y);
        context.lineTo(position.x, position.y + 11);
        context.lineTo(position.x - 11, position.y);
        context.closePath();
      } else {
        context.arc(position.x, position.y, 9, 0, Math.PI * 2);
      }
      context.fill();
      context.stroke();
      if (visibleNodes.length <= 14 || selected) {
        const text = graphLabel(node.canonical_identifier);
        context.fillStyle = "#111923";
        const width = context.measureText(text).width + 8;
        const labelX = Math.max(width / 2 + 3, Math.min(GRAPH_WIDTH - width / 2 - 3, position.x));
        context.fillRect(labelX - width / 2, position.y + 15, width, 15);
        context.fillStyle = "#d9e5f1";
        context.fillText(text, labelX, position.y + 26);
      }
    }
  }, [visibleNodes, visibleEdges, positions, path]);
  return (
    <figure className="topology-figure">
      <div className="topology-canvas">
        <canvas ref={canvas} width={GRAPH_WIDTH} height={GRAPH_HEIGHT} aria-hidden="true" />
      </div>
      <figcaption className="topology-caption">
        <span><i className="topology-legend topology-legend--asset" /> Asset</span>
        <span><i className="topology-legend topology-legend--critical" /> Tier 0</span>
        {path.length > 0 && <span><i className="topology-legend topology-legend--path" /> Selected path</span>}
        <span className="muted">{visibleNodes.length} of {nodes.length} assets · {visibleEdges.length} of {edges.length} relationships</span>
      </figcaption>
    </figure>
  );
}

function Inventory({ nodes, edges, path }: { nodes: AssetNode[]; edges: AssetEdge[]; path: AssetEdge[] }) {
  const names = new Map(nodes.map((node) => [node.id, node.canonical_identifier]));
  return (
    <section className="panel" aria-labelledby="asset-inventory">
      <div className="panel-head"><h2 id="asset-inventory">Asset inventory</h2><span className="muted">{nodes.length} assets</span></div>
      <div className="topology-table">
        <table aria-label="Asset inventory">
          <thead><tr><th scope="col">Identifier</th><th scope="col">Category</th><th scope="col">Origin</th><th scope="col">Tier</th></tr></thead>
          <tbody>
            {nodes.map((node) => <tr key={node.id}>
              <th scope="row" className="mono">{node.canonical_identifier}</th>
              <td>{node.asset_category}</td><td>{titleCase(node.discovered_by)}</td>
              <td>{node.metadata.tier0 === true ? "Tier 0" : "—"}</td>
            </tr>)}
          </tbody>
        </table>
      </div>
      {edges.length > 0 && <details className="topology-relationships">
        <summary>Relationship details ({edges.length})</summary>
        <div className="topology-table">
          <table aria-label="Asset relationships">
            <thead><tr><th scope="col">From</th><th scope="col">To</th><th scope="col">Relationship</th></tr></thead>
            <tbody>{edges.map((edge) => <tr key={edge.id}>
              <th scope="row" className="mono">{names.get(edge.src_node)}</th>
              <td className="mono">{names.get(edge.dst_node)}</td><td>{titleCase(edge.edge_kind)}</td>
            </tr>)}</tbody>
          </table>
        </div>
      </details>}
      {path.length > 0 && <details className="topology-relationships">
        <summary>Path overlay steps ({path.length})</summary>
        <ol>{path.map((edge) => <li key={edge.id}>{names.get(edge.src_node)} → {names.get(edge.dst_node)}</li>)}</ol>
      </details>}
    </section>
  );
}

function titleCase(value: string): string {
  return value.toLowerCase().replaceAll("_", " ").replace(/^./, (first) => first.toUpperCase());
}

function SurfaceContents({ engagementId, live, nodes, edges }: {
  engagementId: string; live: boolean; nodes: AssetNode[]; edges: AssetEdge[];
}) {
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [selection, setSelection] = useState<Selection | null>(null);
  const knownNodes = useMemo(() => new Set(nodes.map((node) => node.id)), [nodes]);
  const canRequest = live && isEngagementId(engagementId) && knownNodes.has(from) && knownNodes.has(to) && from !== to;
  const pathQuery = useQuery({
    queryKey: ["graph-path", engagementId, selection?.from, selection?.to],
    queryFn: ({ signal }) => {
      if (!selection || !live) throw new Error("No selected inventory path");
      return getPath(engagementId, selection.from, selection.to, signal);
    },
    enabled: canRequest && selection !== null,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
    retry: false,
  });
  const returnedPath = canRequest && !pathQuery.isError && !pathQuery.isFetching ? pathQuery.data : undefined;
  const matches = !!selection && !!returnedPath && pathMatchesSnapshot(returnedPath, edges, selection.from, selection.to);
  const overlay = matches && returnedPath ? returnedPath : EMPTY_EDGES;

  function compare(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!canRequest) return;
    if (selection?.from === from && selection.to === to) void pathQuery.refetch();
    else setSelection({ from, to });
  }

  if (nodes.length === 0) return <section className="panel topology-empty">
    <h2>No assets in this snapshot</h2>
    <p className="muted">Import an engagement review snapshot to inspect its recorded topology.</p>
  </section>;

  return <>
    <div className="topology-columns">
      <section className="panel" aria-labelledby="topology-title">
        <div className="panel-head"><h2 id="topology-title">Recorded topology</h2><span className="pill">Snapshot</span></div>
        <GraphCanvas nodes={nodes} edges={edges} path={overlay} />
      </section>
      <section className="panel topology-controls" aria-labelledby="overlay-title">
        <div className="panel-head"><h2 id="overlay-title">Path overlay</h2></div>
        <p className="muted">Compare two assets against the existing graph.</p>
        <form onSubmit={compare}>
          <label className="field">From asset
            <select value={from} onChange={(event) => { setFrom(event.currentTarget.value); setSelection(null); }}>
              <option value="">Select an asset</option>
              {nodes.map((node) => <option key={node.id} value={node.id}>{node.canonical_identifier}</option>)}
            </select>
          </label>
          <label className="field">To asset
            <select value={to} onChange={(event) => { setTo(event.currentTarget.value); setSelection(null); }}>
              <option value="">Select an asset</option>
              {nodes.map((node) => <option key={node.id} value={node.id}>{node.canonical_identifier}</option>)}
            </select>
          </label>
          <button className="button button--primary" type="submit" disabled={!canRequest || pathQuery.isFetching}>
            {pathQuery.isFetching ? "Checking graph…" : "Show path overlay"}
          </button>
        </form>
        {!live && <p className="muted topology-note">Attach a live engagement to compare assets with graph-svc.</p>}
        {pathQuery.isError && <p className="notice" role="alert">The graph service could not return this path.</p>}
        {!!returnedPath && !matches && <p className="notice" role="alert">The graph result differs from the imported snapshot.</p>}
        {matches && <p className="notice topology-note" role="status">{overlay.length > 0
          ? `Path overlay ready · ${overlay.length} ${overlay.length === 1 ? "relationship" : "relationships"}`
          : "No path returned for the selected assets."}</p>}
      </section>
    </div>
    <Inventory nodes={nodes} edges={edges} path={overlay} />
  </>;
}

export function SurfaceRoute() {
  const { mode, engagementId, snapshot } = useWorkspace();
  const nodes = snapshot?.nodes ?? EMPTY_NODES;
  const edges = snapshot?.edges ?? EMPTY_EDGES;
  // Reset local path selection when the engagement or imported graph changes.
  const graphKey = JSON.stringify([mode, engagementId, nodes.map((node) => node.id), edges.map((edge) => edge.id)]);
  return <div className="page">
    <header className="page-heading"><h1>Attack surface</h1>
      <p className="lede">Inspect assets and relationships from your engagement inventory.</p>
    </header>
    <SurfaceContents key={graphKey} live={mode === "live"} engagementId={engagementId} nodes={nodes} edges={edges} />
  </div>;
}
