import type { RoeManifest } from '../../api/client'

export type RoeDraft = Omit<RoeManifest, 'signatures'>

export const weekdays = ['MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT', 'SUN'] as const
const assessmentTypes = ['WEB_API', 'CLOUD_CONFIG'] as const
const modes = ['MANUAL', 'AUTONOMOUS_PASSIVE', 'HYBRID'] as const

function input(data: FormData, name: string): string {
  const value = data.get(name)
  return typeof value === 'string' ? value.trim() : ''
}

function lines(data: FormData, name: string): string[] {
  const values = input(data, name).split(/\r?\n/).map((item) => item.trim()).filter(Boolean)
  if (values.length > 200 || values.some((value) => value.length > 512 || /[\u0000-\u001f\u007f]/u.test(value))) {
    throw new Error('Keep each scope list to at most 200 lines and each entry to 512 printable characters.')
  }
  return [...new Set(values)]
}

function number(data: FormData, name: string, label: string, min: number): number {
  const value = input(data, name)
  const parsed = Number(value)
  if (!/^\d{1,9}$/u.test(value) || !Number.isSafeInteger(parsed) || parsed < min) {
    throw new Error(`${label} must be a whole number of at least ${min}.`)
  }
  return parsed
}

function timestamp(data: FormData, name: string, label: string): string {
  const value = input(data, name)
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/u.test(value)) {
    throw new Error(`${label} must be a UTC timestamp ending in Z, with seconds.`)
  }
  const parsed = new Date(value)
  if (!Number.isFinite(parsed.valueOf()) || parsed.toISOString().replace('.000Z', 'Z') !== value || value.startsWith('0000-')) {
    throw new Error(`${label} must be a valid UTC date and time.`)
  }
  return value
}

function ipv4Address(value: string): bigint | undefined {
  const parts = value.split('.')
  if (parts.length !== 4 || parts.some((part) => !/^(0|[1-9]\d{0,2})$/u.test(part) || Number(part) > 255)) {
    return undefined
  }
  return parts.reduce((address, part) => (address << 8n) | BigInt(part), 0n)
}

function ipv6Address(value: string): bigint | undefined {
  if (!/^[a-f0-9:.]+$/iu.test(value)) return undefined
  try {
    // URL parsing canonicalizes IPv6 literals locally. It performs no lookup.
    const host = new URL(`http://[${value}]/`).hostname.slice(1, -1)
    const [head, tail] = host.split('::')
    const left = head ? head.split(':') : []
    const right = tail ? tail.split(':') : []
    const padding = tail === undefined ? 0 : 8 - left.length - right.length
    const groups = [...left, ...Array<string>(padding).fill('0'), ...right]
    if (groups.length !== 8) return undefined
    return groups.reduce((address, part) => (address << 16n) | BigInt(`0x${part}`), 0n)
  } catch {
    return undefined
  }
}

function isNetwork(value: string): boolean {
  const parts = value.split('/')
  if (parts.length !== 2) return false
  const [address = '', prefix = ''] = parts
  if (!/^(0|[1-9]\d{0,2})$/u.test(prefix)) return false
  const version6 = address.includes(':')
  const bits = version6 ? 128 : 32
  const prefixSize = Number(prefix)
  const parsed = version6 ? ipv6Address(address) : ipv4Address(address)
  if (prefixSize > bits || parsed === undefined) return false
  return parsed % (1n << BigInt(bits - prefixSize)) === 0n
}

export function prepareRoeDraft(data: FormData, engagementId: string): RoeDraft {
  const types = assessmentTypes.filter((type) => data.getAll('assessment_types').includes(type))
  const [assessment, ...others] = types
  if (!assessment) throw new Error('Choose at least one assessment type.')
  const mode = modes.find((entry) => entry === input(data, 'execution_mode'))
  if (!mode) throw new Error('Choose an execution mode.')

  const notBefore = timestamp(data, 'not_before', 'Window start')
  const notAfter = timestamp(data, 'not_after', 'Window end')
  if (notBefore >= notAfter) throw new Error('Window end must follow window start.')
  const days = weekdays.filter((day) => data.getAll('weekdays').includes(day))

  const cidrs = lines(data, 'allowed_cidrs')
  if (cidrs.some((cidr) => !isNetwork(cidr))) throw new Error('Use CIDR network addresses with host bits set to zero.')
  const identifiers = lines(data, 'allowed_identifiers')
  const excluded = lines(data, 'excluded_paths')
  if (excluded.some((path) => !path.startsWith('/') || path.startsWith('//') || /[?#\\\s]/u.test(path))) {
    throw new Error('Excluded paths must begin with a single slash and contain no query or fragment.')
  }
  const methods = [...new Set(input(data, 'allowed_methods').split(/[\s,]+/u).filter(Boolean).map((method) => method.toUpperCase()))]
  if (methods.some((method) => !/^[A-Z][A-Z0-9-]*$/u.test(method))) {
    throw new Error('Enter HTTP method names separated by spaces or commas.')
  }

  return {
    manifest_urn: 'urn:secops:roe:v1',
    engagement_id: engagementId,
    assessment_types: [assessment, ...others],
    execution_mode: mode,
    valid_window: { not_before: notBefore, not_after: notAfter, allowed_days_utc: days },
    scope_boundaries: {
      allowed_cidrs: cidrs,
      allowed_identifiers: identifiers,
      excluded_paths: excluded,
      allowed_http_methods: methods,
    },
    traffic_constraints: {
      max_requests_per_second: number(data, 'request_rate', 'Requests per second', 0),
      max_concurrent_workers: number(data, 'workers', 'Concurrent workers', 0),
      required_attribution_header: `X-Security-Assessment-ID: ${engagementId}`,
      circuit_breaker_5xx_threshold: number(data, 'breaker_threshold', '5xx breaker threshold', 1),
    },
  }
}
