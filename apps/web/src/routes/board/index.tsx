import { Link } from '@tanstack/react-router'
import type { TaskMode, TaskStatus } from '@contracts'
import { useWorkspace, type PlanReview, type TaskReview } from '../../workspace'
import './board.css'

const lanes: ReadonlyArray<{ status: TaskStatus; name: string; tone: string }> = [
  { status: 'QUEUED', name: 'Queued', tone: 'queued' },
  { status: 'RUNNING', name: 'Running', tone: 'running' },
  { status: 'PAUSED_HITL', name: 'Paused-HITL', tone: 'paused' },
  { status: 'DONE', name: 'Done', tone: 'done' },
  { status: 'REJECTED', name: 'Rejected', tone: 'rejected' },
]

const modes: Record<TaskMode, string> = {
  MANUAL_ONLY: 'Human task',
  AI_AUTONOMOUS_PASSIVE: 'Agent · Passive',
  AI_PROPOSED_HITL_GATED: 'Agent · HITL gated',
}

function TaskCard({ review, proposal }: { review: TaskReview; proposal: PlanReview | undefined }) {
  const { task, confidence, reasoning_trace: trace, proposal_id: proposalId } = review
  const hasDetails = Boolean(trace?.length || proposalId)

  return (
    <article className="task-card">
      <p className="task-mode">{modes[task.mode]}</p>
      <h3>{review.title || task.id}</h3>
      {review.title && <p className="mono muted task-identifier">{task.id}</p>}
      {typeof confidence === 'number' && (
        <p className="task-confidence">
          <span>Confidence</span>
          <strong>{Math.round(confidence * 100)}%</strong>
        </p>
      )}
      {hasDetails && (
        <details className="task-details">
          <summary>Review details</summary>
          {Boolean(trace?.length) && <>
            <h4>Reasoning trace</h4>
            <ol>{trace?.map((item, index) => <li key={index}>{item}</li>)}</ol>
          </>}
          {proposalId && <>
            <h4>Proposed validation plan</h4>
            {proposal ? <>
              <p>{proposal.title}</p>
              <Link to="/hitl" className="task-review-link">Open approval rail</Link>
            </> : <p className="muted">Proposal {proposalId} is absent from this snapshot.</p>}
          </>}
        </details>
      )}
    </article>
  )
}

export function BoardRoute() {
  const { mode, snapshot } = useWorkspace()
  const tasks = snapshot?.tasks ?? []
  const proposals = new Map<string, PlanReview>(snapshot?.proposals.map((proposal) => [proposal.plan.id, proposal]))

  return (
    <section className="page task-board" aria-labelledby="task-board-heading">
      <header className="page-heading">
        <div>
          <p className="eyebrow">Engagement workflow</p>
          <h1 id="task-board-heading">Task Board</h1>
          <p className="lede">Follow human and agent work through the review queue.</p>
        </div>
        {snapshot && <span className="pill">{mode === 'sample' ? 'Sample workspace' : 'Imported snapshot'}</span>}
      </header>
      {!snapshot && <p className="notice">Import a workspace snapshot to review tasks and their supporting details.</p>}
      <div className="task-board-lanes">
        {lanes.map(({ status, name, tone }) => {
          const cards = tasks.filter(({ task }) => (task.status ?? 'QUEUED') === status)
          return (
            <section className="panel task-lane" key={status} aria-labelledby={`task-lane-${status}`}>
              <header className="task-lane-header">
                <span className={`task-status-dot task-status-dot--${tone}`} aria-hidden="true" />
                <h2 id={`task-lane-${status}`}>{name}</h2>
                <span className="task-count">{cards.length}</span>
              </header>
              {cards.length ? (
                <ul className="task-lane-items">
                  {cards.map((review) => (
                    <li key={review.task.id}>
                      <TaskCard review={review} proposal={proposals.get(review.proposal_id ?? '')} />
                    </li>
                  ))}
                </ul>
              ) : <p className="task-lane-empty muted">No tasks</p>}
            </section>
          )
        })}
      </div>
    </section>
  )
}
