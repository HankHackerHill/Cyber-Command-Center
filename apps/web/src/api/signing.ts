import { isEngagementState, normalizeEngagementId } from './client'
import type { Ed25519Signature, EngagementState, TransitionEvent } from './client'

export type UnsignedTransition = Omit<TransitionEvent, 'hitl_signature'>

function safeText(value: unknown): value is string {
  // TextEncoder replaces an unpaired surrogate. Reject it before export so
  // the bytes shown to the signer are the bytes the server will verify.
  return typeof value === 'string' && Boolean(value.trim()) && !/[\u0000\uD800-\uDFFF]/u.test(value)
}

function canonicalTimestamp(value: string): string {
  const match = /^(\d{4}-\d{2}-\d{2})[Tt](\d{2}:\d{2}:\d{2})(?:\.(\d{1,6}))?([Zz]|[+-]\d{2}:\d{2})$/.exec(value)
  if (!match) throw new Error('Provide an RFC 3339 timestamp with a timezone.')
  const [, day, time, fraction, offset] = match
  const base = `${day}T${time}`
  const parsed = new Date(`${base}Z`)
  if (!day || day.startsWith('0000-') || Number.isNaN(parsed.getTime()) || parsed.toISOString().slice(0, 19) !== base) {
    throw new Error('Invalid transition timestamp.')
  }
  if (!offset || (/^[+-]/.test(offset) && (Number(offset.slice(1, 3)) > 23 || Number(offset.slice(4)) > 59))) {
    throw new Error('Invalid transition timezone.')
  }
  // Frozen Pydantic serialization emits six fractional digits for a nonzero
  // microsecond value, omits zero fractional seconds, and writes UTC as Z.
  const microseconds = fraction?.padEnd(6, '0') ?? '000000'
  const zone = ['Z', 'z', '+00:00', '-00:00'].includes(offset) ? 'Z' : offset
  return `${base}${microseconds === '000000' ? '' : `.${microseconds}`}${zone}`
}

function envelope(event: UnsignedTransition): UnsignedTransition {
  // Keep keys in ascending order to reproduce canonical_envelope() exactly.
  // The signed fields are strings; none require a cross-language numeric codec.
  if (!safeText(event.actor_id) || !safeText(event.event_id) || !safeText(event.engagement_id)
      || !['HUMAN_OPERATOR', 'AI_AGENT', 'SYSTEM'].includes(event.actor_type)
      || !isEngagementState(event.from_state) || !isEngagementState(event.to_state)) {
    throw new Error('Invalid transition envelope.')
  }
  return {
    actor_id: event.actor_id,
    actor_type: event.actor_type,
    engagement_id: event.engagement_id,
    event_id: event.event_id,
    from_state: event.from_state,
    occurred_at: canonicalTimestamp(event.occurred_at),
    to_state: event.to_state,
  }
}

export function makeTransition(input: {
  engagementId: string
  fromState: EngagementState
  toState: EngagementState
  actorId: string
}): UnsignedTransition {
  if (!globalThis.crypto?.randomUUID) throw new Error('Creating a signing envelope requires a secure browser context.')
  const actorId = input.actorId.trim()
  if (!safeText(actorId) || actorId.length > 256) throw new Error('Enter a valid operator ID.')
  return envelope({
    event_id: crypto.randomUUID(),
    engagement_id: normalizeEngagementId(input.engagementId),
    from_state: input.fromState,
    to_state: input.toState,
    actor_type: 'HUMAN_OPERATOR',
    actor_id: actorId,
    occurred_at: new Date().toISOString(),
  })
}

export function canonicalTransition(event: UnsignedTransition): string {
  return JSON.stringify(envelope(event))
}

export function parseDetachedSignature(text: string, actorId: string): Ed25519Signature {
  if (text.length > 2048) throw new Error('Signature document is too large.')
  let data: unknown
  try {
    data = JSON.parse(text) as unknown
  } catch {
    throw new Error('Enter a JSON signature document produced by the operator signer.')
  }
  if (data === null || typeof data !== 'object' || Array.isArray(data)) {
    throw new Error('Invalid signature document.')
  }
  const fields = data as Record<string, unknown>
  if (Object.keys(fields).length !== 2 || fields.signer_id !== actorId || !safeText(actorId)
      || typeof fields.signature !== 'string' || !/^[a-f0-9]{128}$/.test(fields.signature)) {
    throw new Error('Use the matching operator ID and a lowercase Ed25519 signature in hexadecimal.')
  }
  return { signer_id: actorId, signature: fields.signature }
}

export function attachSignature(event: UnsignedTransition, signature: Ed25519Signature): TransitionEvent {
  if (event.actor_type !== 'HUMAN_OPERATOR' || signature.signer_id !== event.actor_id
      || !/^[a-f0-9]{128}$/.test(signature.signature)) {
    throw new Error('This signature does not match the prepared operator envelope.')
  }
  return { ...envelope(event), hitl_signature: signature }
}
