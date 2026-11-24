import { z } from 'zod'
import type { AssetEdge, AssetNode, Finding, ValidationPlan, WorkflowTask } from '@contracts'

export interface TaskReview {
  task: WorkflowTask
  title?: string
  confidence?: number
  reasoning_trace?: string[]
  proposal_id?: string
}

export interface PlanReview {
  plan: Pick<ValidationPlan, 'id' | 'engagement_id' | 'blast_radius' | 'approver_sig' | 'second_approver_sig'>
  finding_id?: string
  title: string
  score: number
  request: string
  expected_delta: string
}

export interface WorkspaceSnapshot {
  engagementId: string
  nodes: AssetNode[]
  edges: AssetEdge[]
  findings: Finding[]
  tasks: TaskReview[]
  proposals: PlanReview[]
}

const uuid = z.string().regex(/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i).transform((id) => id.toLowerCase())
const id = z.string().min(1).max(256).refine((value) => !/[\x00-\x1f\x7f]/.test(value))
const label = z.string().min(1).max(256)
const confidence = z.number().min(0).max(1)
const signature = z.strictObject({ signer_id: id, signature: z.string().regex(/^[0-9a-f]{128}$/) })

const asset = z.strictObject({
  id: uuid, engagement_id: uuid, asset_category: label, canonical_identifier: label,
  metadata: z.record(z.string(), z.unknown()), discovered_by: z.enum(['HUMAN_OPERATOR', 'AI_AGENT', 'SYSTEM']),
})
const edge = z.strictObject({
  id, engagement_id: uuid, src_node: uuid, dst_node: uuid,
  edge_kind: z.enum(['SECRET_REUSE', 'IAM_ASSUME', 'NET_REACH', 'K8S_RBAC']),
  traversal_cost: z.number().nonnegative().finite(), proven_by_finding: id.nullish(),
})
const finding = z.strictObject({
  id, engagement_id: uuid, title: label, confidence_score: confidence,
  cvss_score: z.number().min(0).max(10).nullish(),
  status: z.enum(['HYPOTHESIS', 'PENDING_VALIDATION', 'CONFIRMED', 'FALSE_POSITIVE', 'REMEDIATED']).optional(),
})
const task = z.strictObject({
  task: z.strictObject({
    id, engagement_id: uuid, mode: z.enum(['MANUAL_ONLY', 'AI_AUTONOMOUS_PASSIVE', 'AI_PROPOSED_HITL_GATED']),
    status: z.enum(['QUEUED', 'RUNNING', 'PAUSED_HITL', 'DONE', 'REJECTED']).optional(),
  }),
  title: label.optional(), confidence: confidence.optional(),
  reasoning_trace: z.array(z.string().max(1024)).max(32).optional(), proposal_id: id.optional(),
})
const proposal = z.strictObject({
  plan: z.strictObject({
    id, engagement_id: uuid, blast_radius: z.enum(['READ_ONLY', 'REVERSIBLE', 'DESTRUCTIVE']),
    approver_sig: signature.nullish(), second_approver_sig: signature.nullish(),
  }),
  finding_id: id.optional(), title: label, score: z.number().min(0).max(3),
  request: z.string().min(1).max(8192), expected_delta: z.string().min(1).max(8192),
})
const snapshot = z.strictObject({
  engagementId: uuid, nodes: z.array(asset).max(150), edges: z.array(edge).max(512),
  findings: z.array(finding).max(256), tasks: z.array(task).max(256), proposals: z.array(proposal).max(128),
})

export const MAX_REVIEW_BYTES = 1024 * 1024

export function parseSnapshot(text: string, expectedId: string): WorkspaceSnapshot {
  if (new TextEncoder().encode(text).byteLength > MAX_REVIEW_BYTES) throw new Error('Snapshot exceeds 1 MiB.')
  let value: WorkspaceSnapshot
  try { value = snapshot.parse(JSON.parse(text)) } catch { throw new Error('Snapshot fields do not match the review format.') }
  const records = [...value.nodes, ...value.edges, ...value.findings, ...value.tasks.map((item) => item.task),
    ...value.proposals.map((item) => item.plan)]
  if (value.engagementId !== expectedId || records.some((record) => record.engagement_id !== expectedId)) {
    throw new Error('Snapshot must belong to the attached engagement.')
  }
  const separateLists = [value.nodes, value.edges, value.findings, value.tasks.map((item) => item.task),
    value.proposals.map((item) => item.plan)]
  if (separateLists.some((items) => new Set(items.map((item) => item.id)).size !== items.length)) {
    throw new Error('Snapshot contains duplicate IDs.')
  }
  const nodes = new Set(value.nodes.map((item) => item.id))
  const findings = new Set(value.findings.map((item) => item.id))
  const proposals = new Set(value.proposals.map((item) => item.plan.id))
  if (value.edges.some((item) => !nodes.has(item.src_node) || !nodes.has(item.dst_node))
    || value.proposals.some((item) => item.finding_id && !findings.has(item.finding_id))
    || value.tasks.some((item) => item.proposal_id && !proposals.has(item.proposal_id))) {
    throw new Error('Snapshot refers to records outside the import.')
  }
  return value
}
