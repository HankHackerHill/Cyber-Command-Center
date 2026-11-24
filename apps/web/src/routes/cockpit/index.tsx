import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useRef, useState, type FormEvent } from 'react'
import { isEngagementId, transition, type LedgerRecord, type TransitionEvent } from '../../api/client'
import { attachSignature, canonicalTransition, makeTransition, parseDetachedSignature, type UnsignedTransition } from '../../api/signing'
import { ledgerKey, stateKey, useWorkspace } from '../../workspace'
import { prepareRoeDraft, weekdays, type RoeDraft } from './draft'
import './cockpit.css'

function downloadJson(filename: string, json: string) {
  const url = URL.createObjectURL(new Blob([json], { type: 'application/json' }))
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  document.body.append(anchor)
  anchor.click()
  anchor.remove()
  window.setTimeout(() => URL.revokeObjectURL(url), 10_000)
}

function describeError(error: unknown): string {
  return error instanceof Error ? error.message : 'The operation could not be completed.'
}

function AttachmentPanel() {
  const { attach, mode, showSample, stop } = useWorkspace()
  const [value, setValue] = useState('')
  const [error, setError] = useState<string | null>(null)

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (stop.isPending) return
    const id = value.trim().toLowerCase()
    if (!isEngagementId(id)) {
      setError('Enter the UUID of an existing engagement.')
      return
    }
    setError(null)
    attach(id)
  }

  return (
    <section className="panel" aria-labelledby="attach-title">
      <div className="panel-head">
        <h2 id="attach-title">Attach an engagement</h2>
      </div>
      <form className="cockpit-stack" onSubmit={submit}>
        <label className="field" htmlFor="engagement-id">
          <span>Engagement ID</span>
          <input id="engagement-id" className="mono" autoComplete="off" spellCheck={false} maxLength={36}
            placeholder="Enter the engagement UUID" required value={value} aria-invalid={error !== null}
            aria-describedby={error ? 'attach-error' : undefined}
            onChange={(event) => { setValue(event.target.value); setError(null) }} />
        </label>
        {error && <p id="attach-error" className="notice cockpit-error" role="alert">{error}</p>}
        <div className="cockpit-actions">
          <button className="button button--primary" type="submit" disabled={stop.isPending}>Attach engagement</button>
          {mode === 'live' && <button className="button button--secondary" type="button" onClick={showSample}
            disabled={stop.isPending}>Open sample</button>}
        </div>
      </form>
      <div className="cockpit-create">
        <button className="button button--secondary" type="button" disabled aria-describedby="create-blocker">Create engagement</button>
        <p id="create-blocker" className="muted">Engagement creation requires an orchestrator endpoint.</p>
      </div>
    </section>
  )
}

function StatePanel() {
  const { state, engagementId, mode, stop } = useWorkspace()
  const observedState = state.data
  const halted = observedState === 'HALTED_KILLSWITCH'
  return (
    <section className="panel cockpit-state" aria-labelledby="engagement-state-title">
      <div className="panel-head">
        <h2 id="engagement-state-title">{mode === 'live' ? 'Live engagement state' : 'Sample engagement state'}</h2>
        <span className={mode === 'live' && !state.isError && !state.isPending ? 'pill pill--accent' : 'pill'}>
          {mode === 'sample' ? 'Sample' : state.isError ? 'Unavailable' : state.isPending ? 'Connecting' : 'Live'}
        </span>
      </div>
      <div className="cockpit-state-value" role="status" aria-live="polite">
        <span className={`cockpit-indicator${halted ? ' cockpit-indicator--halted' : ''}`} aria-hidden="true" />
        <strong>{observedState ?? (state.isError ? 'State unavailable' : 'Waiting for state')}</strong>
      </div>
      <p className="mono muted cockpit-engagement-id">{engagementId}</p>
      {state.isError && <p className="notice cockpit-error" role="alert">{state.data
        ? 'State refresh failed. The value shown is the last observed state.'
        : 'The orchestrator could not return this engagement. Check the connection and the engagement ID.'}</p>}
      <div className="cockpit-actions">
        <button className="button button--secondary" type="button" onClick={() => { void state.refetch() }}
          disabled={mode === 'sample' || state.isFetching}>Refresh state</button>
        <button className="button button--danger" type="button" onClick={stop.activate}
          disabled={mode !== 'live' || stop.isPending}>{stop.isPending ? 'Requesting stop…' : 'Activate killswitch'}</button>
      </div>
      <p className="muted cockpit-kbd">Keyboard shortcut <kbd>Ctrl</kbd> + <kbd>Shift</kbd> + <kbd>K</kbd></p>
    </section>
  )
}

function formatTimestamp(value: string): string {
  const parsed = new Date(value)
  if (!Number.isFinite(parsed.valueOf())) return 'Timestamp unavailable'
  return `${parsed.toISOString().slice(0, 16).replace('T', ' ')} UTC`
}

function LedgerPanel() {
  const { mode, ledger } = useWorkspace()
  const records = [...(ledger.data ?? [])].sort((left, right) => right.seq_id - left.seq_id).slice(0, 5)
  return (
    <section className="panel" aria-labelledby="ledger-heading">
      <div className="panel-head">
        <h2 id="ledger-heading">Recent ledger activity</h2>
        <span className="pill">{mode === 'sample' ? 'Sample' : 'Orchestrator'}</span>
      </div>
      {ledger.isError && <p className="notice cockpit-error" role="alert">Ledger refresh failed.</p>}
      {records.length ? <ol className="cockpit-ledger" aria-label="Ledger records">
        {records.map((record) => <LedgerEntry key={record.seq_id} record={record} />)}
      </ol> : <p className="muted">{ledger.isPending ? 'Loading ledger records…' : 'No ledger records to display.'}</p>}
    </section>
  )
}

function LedgerEntry({ record }: { record: LedgerRecord }) {
  const entry = record.event
  const label = 'to_state' in entry ? `${entry.from_state} → ${entry.to_state}` : entry.event_type
  return (
    <li className="cockpit-ledger-entry">
      <div><strong>{label}</strong><p className="muted">{entry.actor_id} · {formatTimestamp(entry.occurred_at)}</p></div>
      <span className="mono muted" title={record.record_hash}>{record.record_hash.slice(0, 12)}</span>
    </li>
  )
}

function DraftPanel({ engagementId }: { engagementId: string }) {
  const [draft, setDraft] = useState<RoeDraft | null>(null)
  const [error, setError] = useState<string | null>(null)

  function prepare(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    try {
      setDraft(prepareRoeDraft(new FormData(event.currentTarget), engagementId))
      setError(null)
    } catch (cause) {
      setDraft(null)
      setError(describeError(cause))
    }
  }
  const json = draft ? `${JSON.stringify(draft, null, 2)}\n` : ''

  return (
    <section className="panel" aria-labelledby="draft-heading">
      <div className="panel-head">
        <h2 id="draft-heading">Rules of engagement</h2><span className="pill">Local draft</span>
      </div>
      <p className="muted">Draft the scope, time window, and traffic limits for external signing and provisioning.</p>
      <details className="cockpit-details">
        <summary>Draft scope and limits</summary>
        <form className="cockpit-stack cockpit-draft-form" onSubmit={prepare} onChange={() => { setDraft(null); setError(null) }}>
          <div className="form-grid cockpit-form-grid">
            <fieldset className="cockpit-fieldset">
              <legend>Assessment types</legend>
              <label className="cockpit-check"><input type="checkbox" name="assessment_types" value="WEB_API" defaultChecked /> Web API</label>
              <label className="cockpit-check"><input type="checkbox" name="assessment_types" value="CLOUD_CONFIG" /> Cloud configuration</label>
            </fieldset>
            <label className="field">Execution mode
              <select name="execution_mode">
                <option value="MANUAL">Manual</option>
                <option value="AUTONOMOUS_PASSIVE">Autonomous passive</option>
                <option value="HYBRID">Hybrid</option>
              </select>
            </label>
            <label className="field">Window start (UTC)
              <input name="not_before" placeholder="2026-12-01T08:00:00Z" maxLength={20} required />
            </label>
            <label className="field">Window end (UTC)
              <input name="not_after" placeholder="2026-12-12T22:00:00Z" maxLength={20} required />
            </label>
          </div>
          <fieldset className="cockpit-fieldset">
            <legend>Allowed UTC days</legend>
            <div className="cockpit-actions">
              {weekdays.map((day, index) => <label key={day} className="cockpit-check">
                <input type="checkbox" name="weekdays" value={day} defaultChecked={index < 5} /> {day}
              </label>)}
            </div>
          </fieldset>
          <div className="form-grid cockpit-form-grid">
            <label className="field">Allowed CIDRs (one per line)
              <textarea name="allowed_cidrs" className="mono" rows={3} maxLength={24_000} placeholder="198.51.100.0/24" />
            </label>
            <label className="field">Allowed asset identifiers (one per line)
              <textarea name="allowed_identifiers" className="mono" rows={3} maxLength={24_000} placeholder="api.staging.example.com" />
            </label>
            <label className="field">Excluded paths (one per line)
              <textarea name="excluded_paths" className="mono" rows={3} maxLength={24_000} />
            </label>
            <label className="field">Allowed HTTP methods
              <input name="allowed_methods" defaultValue="GET HEAD OPTIONS" maxLength={90} />
            </label>
            <label className="field">Requests per second
              <input type="number" name="request_rate" min={0} max={999_999_999} step={1} defaultValue={1} required />
            </label>
            <label className="field">Concurrent workers
              <input type="number" name="workers" min={0} max={999_999_999} step={1} defaultValue={1} required />
            </label>
            <label className="field">5xx breaker threshold
              <input type="number" name="breaker_threshold" min={1} max={999_999_999} step={1} defaultValue={5} required />
            </label>
          </div>
          {error && <p className="notice cockpit-error" role="alert">{error}</p>}
          <div className="cockpit-actions"><button className="button button--secondary" type="submit">Preview unsigned draft</button></div>
        </form>
        {draft && <div className="cockpit-stack cockpit-draft-preview">
          <label className="field">Unsigned RoE draft JSON
            <textarea className="mono" rows={9} readOnly value={json} />
          </label>
          <div className="cockpit-actions"><button className="button button--secondary" type="button"
            onClick={() => downloadJson(`roe-draft-${engagementId}.json`, json)}>Download unsigned draft</button></div>
        </div>}
      </details>
    </section>
  )
}

function LockPanel() {
  const { mode, state, engagementId, stop } = useWorkspace()
  const queryClient = useQueryClient()
  const writeLock = useRef(false)
  const [actorId, setActorId] = useState('')
  const [provisioned, setProvisioned] = useState(false)
  const [prepared, setPrepared] = useState<UnsignedTransition | null>(null)
  const [detached, setDetached] = useState('')
  const [error, setError] = useState<string | null>(null)

  const applied = useMutation({
    mutationFn: (event: TransitionEvent) => transition(event),
    onSuccess: async (_receipt, event) => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: stateKey(event.engagement_id), exact: true }),
        queryClient.invalidateQueries({ queryKey: ledgerKey(event.engagement_id), exact: true }),
      ])
    },
    onSettled: () => { writeLock.current = false },
    retry: false,
  })
  const ready = mode === 'live' && !state.isError && !stop.isPending && state.data === 'INIT_SCOPING'
  const canonical = prepared ? canonicalTransition(prepared) : null

  function prepareEnvelope(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!ready || !provisioned) return
    try {
      const candidate = makeTransition({ engagementId, fromState: 'INIT_SCOPING', toState: 'ROE_LOCKED', actorId: actorId.trim() })
      setPrepared(candidate)
      setDetached('')
      setError(null)
      applied.reset()
    } catch (cause) {
      setPrepared(null)
      setError(describeError(cause))
    }
  }

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!ready || !prepared || !provisioned || writeLock.current || applied.isPending || applied.isSuccess) return
    try {
      const signature = parseDetachedSignature(detached, prepared.actor_id)
      const signed = attachSignature(prepared, signature)
      setError(null)
      writeLock.current = true
      applied.mutate(signed)
    } catch (cause) {
      setError(describeError(cause))
    }
  }

  function clearEnvelope() {
    setPrepared(null)
    setDetached('')
    setError(null)
    applied.reset()
  }

  return (
    <section className="panel" aria-labelledby="lock-heading">
      <div className="panel-head">
        <h2 id="lock-heading">Lock rules of engagement</h2><span className="pill">Human signature</span>
      </div>
      <p className="muted">Provision the signed RoE through your existing operator workflow. Then sign the state transition with your Ed25519 key in the OS keystore.</p>
      {mode === 'sample' && <p className="notice">Attach an existing engagement to submit a signed state transition.</p>}
      {mode === 'live' && !ready && !applied.isSuccess && <p className="notice">The orchestrator must report INIT_SCOPING to prepare and submit a lock envelope.</p>}
      {mode === 'live' && <form className="cockpit-stack" onSubmit={prepareEnvelope}>
        <fieldset className="cockpit-fieldset cockpit-stack" disabled={!ready || applied.isPending || applied.isSuccess}>
          <label className="field">Operator ID
            <input value={actorId} onChange={(event) => { setActorId(event.target.value); clearEnvelope() }}
              autoComplete="off" spellCheck={false} maxLength={128} required />
          </label>
          <label className="cockpit-check">
            <input type="checkbox" checked={provisioned} required onChange={(event) => { setProvisioned(event.target.checked); clearEnvelope() }} />
            The signed RoE has been provisioned for this engagement.
          </label>
          <div className="cockpit-actions"><button className="button button--secondary" type="submit"
            disabled={!actorId.trim() || !provisioned}>Prepare lock envelope</button></div>
        </fieldset>
      </form>}
      {canonical && !applied.isSuccess && <form className="cockpit-stack cockpit-signature-form" onSubmit={submit}>
        <label className="field">Canonical transition envelope
          <textarea className="mono" rows={4} readOnly value={canonical} />
        </label>
        <div className="cockpit-actions"><button className="button button--secondary" type="button"
          onClick={() => downloadJson('roe-lock-envelope.json', canonical)}>Download lock envelope</button></div>
        <label className="field">Detached signature JSON
          <textarea className="mono" rows={3} placeholder='{"signer_id":"…","signature":"…"}' required maxLength={2_048}
            value={detached} disabled={!ready || applied.isPending}
            onChange={(event) => { setDetached(event.target.value); setError(null) }} />
        </label>
        <div className="cockpit-actions"><button className="button button--primary" type="submit"
          disabled={!ready || applied.isPending || !detached.trim()}>
          {applied.isPending ? 'Submitting signed transition…' : 'Submit signed transition'}</button></div>
      </form>}
      {error && <p className="notice cockpit-error" role="alert">{error}</p>}
      {applied.isError && <p className="notice cockpit-error" role="alert">{describeError(applied.error)}</p>}
      {applied.isSuccess && <p className="notice" role="status">The orchestrator recorded ROE_LOCKED.</p>}
    </section>
  )
}

export function CockpitRoute() {
  const { engagementId, mode } = useWorkspace()
  return (
    <div className="page cockpit-page">
      <header className="page-heading">
        <p className="eyebrow">Engagement operations</p>
        <h1>Engagement Cockpit</h1>
        <p className="lede">Monitor engagement state, review the audit trail, and prepare the rules of engagement.</p>
      </header>
      <div className="cockpit-grid">
        <StatePanel />
        <AttachmentPanel />
      </div>
      <LedgerPanel />
      <DraftPanel key={`${mode}:${engagementId}:draft`} engagementId={engagementId} />
      <LockPanel key={`${mode}:${engagementId}:lock`} />
    </div>
  )
}
