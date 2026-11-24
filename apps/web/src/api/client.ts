import type {
  AssetEdge,
  AssetNode,
  Ed25519Signature,
  EngagementState,
  LedgerRecord,
  RecordedAuditEvent,
  TransitionEvent,
} from '../../../../packages/contracts-ts/index'

export type {
  AssetEdge,
  AssetNode,
  AttackChain,
  BlastRadius,
  Ed25519Signature,
  Engagement,
  EngagementState,
  Finding,
  LedgerRecord,
  RoeManifest,
  TransitionEvent,
  ValidationPlan,
  WorkflowTask,
} from '../../../../packages/contracts-ts/index'

// Service-specific response shapes from the existing endpoints. Contract
// entities are imported above from the frozen generated types.
export interface StopResult {
  status: 'halted'
  next_state: 'HALTED_KILLSWITCH'
  ledger_hash: string | null
  notification_published: boolean
}

export interface ReviewResult {
  status: 'applied'
  next_state: EngagementState
  ledger_hash: string
}

export type TransitionResult = ReviewResult | StopResult

export interface ArtifactRef {
  sha256: string
  url: string
}

const messages: Record<string, string> = {
  ENGAGEMENT_NOT_FOUND: 'The orchestrator could not find this engagement.',
  ENGAGEMENT_ID_MISMATCH: 'The event belongs to another engagement.',
  EVENT_REPLAY: 'This event was already applied. Refresh the engagement state.',
  HUMAN_SIGNATURE_REQUIRED: 'The orchestrator requires a valid signature from a trusted operator.',
  ILLEGAL_TRANSITION: 'The orchestrator rejected this transition.',
  INVALID_SIGNATURE: 'The orchestrator rejected the signature.',
  INVALID_EVENT: 'The orchestrator rejected the event.',
  STATE_MISMATCH: 'The engagement state changed. Refresh it and prepare a new event.',
  TRANSITION_UNAVAILABLE: 'This transition is unavailable on the orchestrator.',
  INVALID_RESPONSE: 'The service returned an invalid or unexpected response.',
  RESPONSE_TOO_LARGE: 'The service response exceeds the cockpit download limit.',
  REQUEST_FAILED: 'The request failed. Refresh the engagement to check the result.',
  ARTIFACT_INTEGRITY: 'The downloaded bytes do not match the recorded SHA-256 digest.',
}

export class ApiError extends Error {
  constructor(public readonly status: number, public readonly reason: string) {
    super(Object.hasOwn(messages, reason) ? messages[reason] : `Service request failed (HTTP ${status}).`)
    this.name = 'ApiError'
  }
}

export const ENGAGEMENT_STATES = [
  'INIT_SCOPING', 'ROE_LOCKED', 'DISCOVERY_PASSIVE', 'ANALYTICAL_TRIAGE',
  'AWAITING_HITL_GATE', 'CONTROLLED_VALIDATION', 'EVIDENCE_VERIFICATION',
  'REMEDIATION_SYNTHESIS', 'RETEST_VERIFICATION', 'COMPLETED_ARCHIVED', 'HALTED_KILLSWITCH',
] as const satisfies readonly EngagementState[]

const states = new Set<unknown>(ENGAGEMENT_STATES)
const actorTypes = new Set<unknown>(['HUMAN_OPERATOR', 'SYSTEM', 'AI_AGENT'])
const edgeKinds = new Set<unknown>(['SECRET_REUSE', 'IAM_ASSUME', 'NET_REACH', 'K8S_RBAC'])
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i
const digest = /^[a-f0-9]{64}$/
const maxJsonBytes = 4 * 1024 * 1024
const maxArtifactBytes = 32 * 1024 * 1024

export function isEngagementId(value: unknown): value is string {
  return typeof value === 'string' && uuid.test(value)
}

export function isEngagementState(value: unknown): value is EngagementState {
  return states.has(value)
}

export function normalizeEngagementId(value: string): string {
  if (!isEngagementId(value)) throw new Error('Enter a valid engagement UUID.')
  return value.toLowerCase()
}

function isDigest(value: unknown): value is string {
  return typeof value === 'string' && digest.test(value)
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function isSignature(value: unknown): value is Ed25519Signature {
  return isObject(value) && typeof value.signer_id === 'string' && value.signer_id.length > 0
    && typeof value.signature === 'string' && /^[a-f0-9]{128}$/.test(value.signature)
}

function sameEngagement(value: unknown, id: string): boolean {
  // M2 preserves an externally signed event's exact engagement spelling,
  // including the alternative UUID spellings PostgreSQL accepts.
  if (typeof value !== 'string') return false
  const unbraced = value.startsWith('{') && value.endsWith('}') ? value.slice(1, -1) : value
  return /^(?:[a-f0-9]{4}-?){7}[a-f0-9]{4}$/i.test(unbraced)
    && unbraced.replaceAll('-', '').toLowerCase() === id.replaceAll('-', '')
}

function isLedgerEvent(value: unknown, id: string): value is TransitionEvent | RecordedAuditEvent {
  if (!isObject(value) || !sameEngagement(value.engagement_id, id) || typeof value.event_id !== 'string'
      || !value.event_id || typeof value.actor_id !== 'string' || typeof value.occurred_at !== 'string') return false
  if ('from_state' in value) {
    return isEngagementState(value.from_state) && isEngagementState(value.to_state) && actorTypes.has(value.actor_type)
      && (value.hitl_signature === null || value.hitl_signature === undefined || isSignature(value.hitl_signature))
  }
  return actorTypes.has(value.actor_kind) && typeof value.event_type === 'string' && isObject(value.payload)
}

function isLedgerRecord(value: unknown, id: string): value is LedgerRecord {
  return isObject(value) && typeof value.seq_id === 'number' && Number.isSafeInteger(value.seq_id) && value.seq_id > 0
    && isLedgerEvent(value.event, id) && isDigest(value.prev_record_hash) && isDigest(value.record_hash)
}

function isEdge(value: unknown, id: string): value is AssetEdge {
  return isObject(value) && sameEngagement(value.engagement_id, id) && typeof value.id === 'string'
    && isEngagementId(value.src_node) && isEngagementId(value.dst_node) && edgeKinds.has(value.edge_kind)
    && typeof value.traversal_cost === 'number' && Number.isFinite(value.traversal_cost) && value.traversal_cost >= 0
    && (value.proven_by_finding == null || typeof value.proven_by_finding === 'string')
}

function isNode(value: unknown, id: string): value is AssetNode {
  return isObject(value) && sameEngagement(value.engagement_id, id) && isEngagementId(value.id)
    && typeof value.asset_category === 'string' && typeof value.canonical_identifier === 'string'
    && actorTypes.has(value.discovered_by) && isObject(value.metadata)
}

function isStop(value: unknown): value is StopResult {
  return isObject(value) && value.status === 'halted' && value.next_state === 'HALTED_KILLSWITCH'
    && (value.ledger_hash === null || isDigest(value.ledger_hash)) && typeof value.notification_published === 'boolean'
}

function invalidResponse(): never {
  throw new ApiError(502, 'INVALID_RESPONSE')
}

type Service = 'orchestrator' | 'graph' | 'evidence'

async function readBytes(response: Response, limit: number): Promise<Uint8Array<ArrayBuffer>> {
  const length = response.headers.get('content-length')
  if (length !== null && (!/^\d+$/.test(length) || Number(length) > limit)) {
    await response.body?.cancel()
    throw new ApiError(502, 'RESPONSE_TOO_LARGE')
  }
  if (!response.body) invalidResponse()
  const reader = response.body.getReader()
  const chunks: Uint8Array[] = []
  let size = 0
  try {
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      size += value.byteLength
      if (size > limit) {
        await reader.cancel()
        throw new ApiError(502, 'RESPONSE_TOO_LARGE')
      }
      chunks.push(value)
    }
  } finally {
    reader.releaseLock()
  }
  const bytes = new Uint8Array(size)
  let offset = 0
  for (const chunk of chunks) {
    bytes.set(chunk, offset)
    offset += chunk.byteLength
  }
  return bytes
}

function parseJson(bytes: Uint8Array): unknown {
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as unknown
  } catch {
    return invalidResponse()
  }
}

async function request(service: Service, path: string, options: {
  method?: 'GET' | 'POST'
  body?: object
  signal?: AbortSignal
  artifact?: boolean
} = {}): Promise<Uint8Array<ArrayBuffer>> {
  const deadline = AbortSignal.timeout(options.artifact ? 30_000 : 10_000)
  const signal = options.signal ? AbortSignal.any([options.signal, deadline]) : deadline
  const headers = new Headers({ Accept: options.artifact ? 'application/octet-stream' : 'application/json' })
  if (options.body) headers.set('Content-Type', 'application/json')
  try {
    const response = await fetch(`/api/${service}${path}`, {
      method: options.method ?? 'GET',
      headers,
      body: options.body ? JSON.stringify(options.body) : null,
      signal,
      cache: 'no-store',
      credentials: 'same-origin',
      mode: 'same-origin',
      redirect: 'error',
    })
    if (!response.ok) {
      let reason = `HTTP_${response.status}`
      if (response.headers.get('content-type')?.split(';')[0] === 'application/json') {
        try {
          const body = parseJson(await readBytes(response, 4096))
          if (isObject(body) && typeof body.reason === 'string' && Object.hasOwn(messages, body.reason)) {
            reason = body.reason
          }
        } catch {
          // Preserve the HTTP failure. Never echo untrusted error payloads.
        }
      } else {
        await response.body?.cancel()
      }
      throw new ApiError(response.status, reason)
    }
    if (response.status !== 200 || response.headers.get('content-type')?.split(';')[0] !== headers.get('Accept')) {
      await response.body?.cancel()
      invalidResponse()
    }
    return await readBytes(response, options.artifact ? maxArtifactBytes : maxJsonBytes)
  } catch (error) {
    if (options.signal?.aborted || error instanceof ApiError) throw error
    throw new ApiError(0, 'REQUEST_FAILED')
  }
}

export async function getState(engagementId: string, signal?: AbortSignal): Promise<EngagementState> {
  const id = normalizeEngagementId(engagementId)
  const result = parseJson(await request('orchestrator', `/engagements/${id}/state`, { signal }))
  if (!isObject(result) || !isEngagementState(result.state)) invalidResponse()
  return result.state
}

export async function getLedger(engagementId: string, since = 0, signal?: AbortSignal): Promise<LedgerRecord[]> {
  const id = normalizeEngagementId(engagementId)
  if (!Number.isSafeInteger(since) || since < 0) throw new Error('Invalid ledger offset.')
  const result = parseJson(await request('orchestrator', `/engagements/${id}/ledger?since=${since}`, { signal }))
  if (!Array.isArray(result) || !result.every((record) => isLedgerRecord(record, id))) invalidResponse()
  let prior = since
  for (const record of result) {
    if (record.seq_id <= prior) invalidResponse()
    prior = record.seq_id
  }
  return result
}

export async function transition(event: TransitionEvent, signal?: AbortSignal): Promise<TransitionResult> {
  const id = normalizeEngagementId(event.engagement_id)
  const result = parseJson(await request('orchestrator', `/engagements/${id}/transition`, {
    method: 'POST', body: event, signal,
  }))
  if (event.to_state === 'HALTED_KILLSWITCH' && isStop(result)) return result
  if (!isObject(result) || result.status !== 'applied' || result.next_state !== event.to_state
      || !isEngagementState(result.next_state) || !isDigest(result.ledger_hash)) invalidResponse()
  return { status: result.status, next_state: result.next_state, ledger_hash: result.ledger_hash }
}

export async function killswitch(engagementId: string, signal?: AbortSignal): Promise<StopResult> {
  const id = normalizeEngagementId(engagementId)
  const result = parseJson(await request('orchestrator', `/engagements/${id}/killswitch`, { method: 'POST', signal }))
  if (!isStop(result)) invalidResponse()
  return result
}

export async function getPath(engagementId: string, src: string, dst: string, signal?: AbortSignal): Promise<AssetEdge[]> {
  const id = normalizeEngagementId(engagementId)
  if (!isEngagementId(src) || !isEngagementId(dst)) throw new Error('Select two valid assets.')
  const result = parseJson(await request('graph', '/paths', {
    method: 'POST', body: { engagement_id: id, src, dst }, signal,
  }))
  if (!Array.isArray(result) || !result.every((edge) => isEdge(edge, id))) invalidResponse()
  let cursor = src.toLowerCase()
  for (const edge of result) {
    if (edge.src_node.toLowerCase() !== cursor) invalidResponse()
    cursor = edge.dst_node.toLowerCase()
  }
  if (result.length && cursor !== dst.toLowerCase()) invalidResponse()
  return result
}

export async function getTier0Reach(engagementId: string, signal?: AbortSignal): Promise<AssetNode[]> {
  const id = normalizeEngagementId(engagementId)
  const result = parseJson(await request('graph', '/tier0-reach', {
    method: 'POST', body: { engagement_id: id }, signal,
  }))
  if (!Array.isArray(result) || !result.every((node) => isNode(node, id))) invalidResponse()
  return result
}

export async function getFindingEvidence(engagementId: string, findingId: string, signal?: AbortSignal): Promise<ArtifactRef[]> {
  const id = normalizeEngagementId(engagementId)
  if (!findingId.trim() || findingId === '.' || findingId === '..' || findingId.length > 512 || /[\u0000-\u001f\u007f]/.test(findingId)) {
    throw new Error('Enter a valid finding ID.')
  }
  const result = parseJson(await request('evidence', `/findings/${encodeURIComponent(findingId)}/evidence?engagement_id=${id}`, { signal }))
  if (!Array.isArray(result)) invalidResponse()
  return result.map((item: unknown) => {
    if (!isObject(item) || !isDigest(item.sha256) || item.url !== `/artifacts/${item.sha256}`) invalidResponse()
    return { sha256: item.sha256, url: item.url }
  })
}

export async function downloadVerifiedArtifact(sha256: string, signal?: AbortSignal): Promise<Blob> {
  if (!isDigest(sha256)) throw new Error('Invalid artifact SHA-256 digest.')
  if (!globalThis.crypto?.subtle) throw new Error('Evidence verification requires a secure browser context.')
  const bytes = await request('evidence', `/artifacts/${sha256}`, { artifact: true, signal })
  const actual = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))
  signal?.throwIfAborted()
  const actualHex = Array.from(actual, (byte) => byte.toString(16).padStart(2, '0')).join('')
  if (actualHex !== sha256) throw new ApiError(502, 'ARTIFACT_INTEGRITY')
  return new Blob([bytes], { type: 'application/octet-stream' })
}
