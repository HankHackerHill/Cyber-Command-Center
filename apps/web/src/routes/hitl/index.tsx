import { useId, useState } from 'react'
import type { BlastRadius, Ed25519Signature, Finding } from '@contracts'
import { useWorkspace, type PlanReview } from '../../workspace'
import './hitl.css'

const blastRadii: Record<BlastRadius, { label: string; tone: string }> = {
  READ_ONLY: { label: 'Read-only', tone: 'readonly' },
  REVERSIBLE: { label: 'State-changing', tone: 'reversible' },
  DESTRUCTIVE: { label: 'Destructive', tone: 'destructive' },
}

function rankProposals(left: PlanReview, right: PlanReview) {
  const severity = Number(right.plan.blast_radius === 'DESTRUCTIVE')
    - Number(left.plan.blast_radius === 'DESTRUCTIVE')
  if (severity !== 0) return severity
  if (left.score !== right.score) return right.score - left.score
  return left.plan.id < right.plan.id ? -1 : left.plan.id > right.plan.id ? 1 : 0
}

function BlastRadiusTag({ blastRadius }: { blastRadius: BlastRadius }) {
  const { label, tone } = blastRadii[blastRadius]
  return <span className={`approval-risk approval-risk--${tone}`}>{label}</span>
}

function isSignatureRecord(value: Ed25519Signature | null | undefined): value is Ed25519Signature {
  return Boolean(value && value.signer_id.trim() && /^[a-f0-9]{128}$/.test(value.signature))
}

function reportedSignerIds({ approver_sig, second_approver_sig }: PlanReview['plan']): string[] {
  const records = [approver_sig, second_approver_sig].filter(isSignatureRecord)
  const signerIds = new Set<string>()
  const signatureValues = new Set<string>()
  for (const record of records) {
    const signer = record.signer_id.trim()
    if (!signerIds.has(signer) && !signatureValues.has(record.signature)) {
      signerIds.add(signer)
      signatureValues.add(record.signature)
    }
  }
  return [...signerIds]
}

function ReviewText({ heading, content }: { heading: string; content: string }) {
  const headingId = useId()
  return (
    <div className="proposal-content">
      <h3 id={headingId}>{heading}</h3>
      {content ? (
        <div className="approval-text" role="region" aria-labelledby={headingId} tabIndex={0}>
          <pre>{content}</pre>
        </div>
      ) : <p className="muted">This snapshot does not include a value.</p>}
    </div>
  )
}

function ProposalDetails({ proposal, finding, regionId }: {
  proposal: PlanReview
  finding: Finding | undefined
  regionId: string
}) {
  const detailId = useId()
  const blockerId = useId()
  const destructive = proposal.plan.blast_radius === 'DESTRUCTIVE'
  const signerIds = reportedSignerIds(proposal.plan)

  return (
    <article className="panel approval-detail" id={regionId} aria-labelledby={detailId}>
      <header className="approval-detail-heading">
        <div>
          <p className="eyebrow">Validation proposal</p>
          <h2 id={detailId}>{proposal.title}</h2>
          <p className="mono muted approval-plan-id">{proposal.plan.id}</p>
        </div>
        <BlastRadiusTag blastRadius={proposal.plan.blast_radius} />
      </header>
      {proposal.finding_id && (
        <dl className="approval-finding">
          <dt>Linked finding</dt>
          <dd>{finding?.title ?? proposal.finding_id}</dd>
        </dl>
      )}
      <ReviewText heading="Exact request" content={proposal.request} />
      <ReviewText heading="Expected response delta" content={proposal.expected_delta} />
      <div className="proposal-content approval-requirements">
        <h3>Approval requirements</h3>
        <p>{destructive ? 'Two distinct operator signatures required.' : 'Operator signature required.'}</p>
        <p className="muted">
          {signerIds.length === 0 ? 'No structurally valid signature records supplied.' : (
            <>{signerIds.length} structurally distinct signer {signerIds.length === 1 ? 'record' : 'records'} supplied. Signature validity is unverified.</>
          )}
        </p>
        {signerIds.length > 0 && <ul>{signerIds.map((signer) => <li key={signer}>{signer}</li>)}</ul>}
      </div>
      <footer className="approval-actions">
        <div className="notice" id={blockerId}>
          <strong>Plan approval unavailable</strong>
          <p>This branch exposes engagement transition signing. A plan approval endpoint and an OS-keystore signing bridge are required to bind approval to this request.</p>
        </div>
        <button className="button button--primary" type="button" disabled aria-describedby={blockerId}>Approve &amp; Sign</button>
      </footer>
    </article>
  )
}

export function HitlRoute() {
  const { mode, engagementId, snapshot } = useWorkspace()
  const regionId = useId()
  const proposals = (snapshot?.proposals ?? []).slice().sort(rankProposals)
  const [selection, setSelection] = useState<{ engagementId: string; planId: string }>()
  const selected = (selection?.engagementId === engagementId
    ? proposals.find((proposal) => proposal.plan.id === selection.planId)
    : undefined) ?? proposals[0]
  const finding = snapshot?.findings.find((item) => selected?.finding_id === item.id)

  return (
    <section className="page approval-page" aria-labelledby="approval-rail-heading">
      <header className="page-heading">
        <div>
          <p className="eyebrow">Human oversight</p>
          <h1 id="approval-rail-heading">HITL Approval Rail</h1>
          <p className="lede">Review the request, expected response delta and approval requirements for each proposal.</p>
        </div>
        {snapshot && <span className="pill">{mode === 'sample' ? 'Sample workspace' : 'Imported snapshot'}</span>}
      </header>
      {selected ? (
        <div className="approval-grid">
          <section className="panel approval-queue" aria-labelledby="ranked-proposal-heading">
            <div className="approval-queue-heading">
              <h2 id="ranked-proposal-heading">Ranked proposals</h2>
              <span className="pill">{proposals.length}</span>
            </div>
            <p className="muted approval-list-note">Destructive proposals appear first. Other proposals follow their supplied score.</p>
            <ol className="approval-list" aria-label="Ranked proposals">
              {proposals.map((proposal, index) => (
                <li key={proposal.plan.id}>
                  <button
                    type="button"
                    aria-controls={regionId}
                    aria-pressed={selected.plan.id === proposal.plan.id}
                    className="approval-queue-item"
                    onClick={() => setSelection({ engagementId, planId: proposal.plan.id })}
                  >
                    <span className="approval-rank" aria-hidden="true">{index + 1}</span>
                    <span className="approval-queue-copy">
                      <strong>{proposal.title}</strong>
                      <span className="approval-queue-meta">
                        <BlastRadiusTag blastRadius={proposal.plan.blast_radius} />
                        <span className="muted">Score {proposal.score.toFixed(2)}</span>
                      </span>
                    </span>
                  </button>
                </li>
              ))}
            </ol>
          </section>
          <ProposalDetails proposal={selected} finding={finding} regionId={regionId} />
        </div>
      ) : (
        <section className="panel approval-empty" aria-labelledby="empty-approval-heading">
          <h2 id="empty-approval-heading">No proposals to review</h2>
          <p className="muted">{snapshot ? 'The current snapshot contains no validation proposals.' : 'Import a workspace snapshot to review validation proposals.'}</p>
        </section>
      )}
    </section>
  )
}
