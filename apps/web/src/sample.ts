import type { AssetNode } from '@contracts'
import type { WorkspaceSnapshot } from './review'

export const SAMPLE_ID = '2d092ccd-59fb-4b7a-8c3f-fbdcd3be9731'

const inventory = [
  ['External gateway', 'gateway'], ['Customer API', 'service'], ['Identity broker', 'identity'],
  ['Service account', 'identity'], ['Data store', 'storage'], ['Admin console', 'service'],
] as const
const nodes: AssetNode[] = inventory.map(([name, category], index) => ({
  id: `00000000-0000-4000-8000-00000000000${index + 1}`, engagement_id: SAMPLE_ID,
  asset_category: category, canonical_identifier: name,
  metadata: index === 2 ? { tier0: true } : {}, discovered_by: 'SYSTEM',
}))

export const sampleSnapshot: WorkspaceSnapshot = {
  engagementId: SAMPLE_ID,
  nodes,
  edges: [[0, 1], [1, 2], [2, 3], [1, 4], [2, 5]].map(([src, dst], index) => ({
    id: `edge-${index + 1}`, engagement_id: SAMPLE_ID, src_node: nodes[src].id, dst_node: nodes[dst].id,
    edge_kind: 'NET_REACH', traversal_cost: 1,
  })),
  findings: [
    { id: 'F-104', engagement_id: SAMPLE_ID, title: 'Authorization documentation gap', status: 'HYPOTHESIS', confidence_score: 0.91 },
    { id: 'F-105', engagement_id: SAMPLE_ID, title: 'Broad identity scope', status: 'HYPOTHESIS', confidence_score: 0.78 },
    { id: 'F-091', engagement_id: SAMPLE_ID, title: 'Missing artifact retention control', status: 'CONFIRMED', confidence_score: 0.97, cvss_score: 4.3 },
  ],
  tasks: [
    { task: { id: 'T-021', engagement_id: SAMPLE_ID, mode: 'MANUAL_ONLY', status: 'QUEUED' }, title: 'Review retention settings' },
    { task: { id: 'T-022', engagement_id: SAMPLE_ID, mode: 'AI_AUTONOMOUS_PASSIVE', status: 'RUNNING' },
      title: 'Correlate supplied asset inventory', confidence: 0.82, reasoning_trace: ['Loaded reviewed inventory', 'Matched supplied records'] },
    { task: { id: 'T-018', engagement_id: SAMPLE_ID, mode: 'AI_PROPOSED_HITL_GATED', status: 'PAUSED_HITL' },
      title: 'Review API authorization evidence', confidence: 0.91,
      reasoning_trace: ['Read the supplied OpenAPI snapshot', 'Recorded a documentation gap'], proposal_id: 'P-015' },
    { task: { id: 'T-016', engagement_id: SAMPLE_ID, mode: 'MANUAL_ONLY', status: 'DONE' }, title: 'Verify evidence digest' },
    { task: { id: 'T-013', engagement_id: SAMPLE_ID, mode: 'AI_AUTONOMOUS_PASSIVE', status: 'REJECTED' }, title: 'Evaluate incomplete review data' },
  ],
  proposals: [
    { plan: { id: 'P-015', engagement_id: SAMPLE_ID, blast_radius: 'READ_ONLY' }, finding_id: 'F-104',
      title: 'Review API authorization evidence', score: 0.91, request: 'Review the signed OpenAPI snapshot for documented authorization controls.',
      expected_delta: 'An operator annotation recording which operations have documented authorization.' },
    { plan: { id: 'P-016', engagement_id: SAMPLE_ID, blast_radius: 'DESTRUCTIVE' }, finding_id: 'F-105',
      title: 'Review a proposed identity change', score: 0.68, request: 'Review the isolation and rollback requirements in the supplied change record.',
      expected_delta: 'A written disposition from two distinct operators.' },
  ],
}
