import { ClipboardCheck, FileText } from 'lucide-react'
import { useState } from 'react'
import { EmptyState, PageHeading, Pill } from '@ui'
import { useWorkspace } from '../../workspace'

const finalStatuses = new Set(['CONFIRMED', 'FALSE_POSITIVE'])

export function StudioRoute() {
  const { snapshot, mode } = useWorkspace()
  const [format, setFormat] = useState('PDF')
  const findings = snapshot?.findings ?? []
  const eligible = findings.filter((item) => item.status && finalStatuses.has(item.status)).length
  return <section className="page">
    <PageHeading title="Report Studio" category="Deliverables" description="Review the supplied findings against the reporting prerequisites." />
    <div className="split studio-grid">
      <section className="panel" aria-labelledby="report-findings">
        <div className="panel-head"><div><h2 id="report-findings">Findings register</h2><p>{mode === 'sample' ? 'Sample review records' : 'Imported review records'}</p></div><Pill>{findings.length} findings</Pill></div>
        {findings.length === 0 ? <EmptyState title="No findings available">Import a review snapshot for this engagement to populate the register.</EmptyState> :
          <div className="table-wrap"><table><thead><tr><th scope="col">Finding</th><th scope="col">Status</th><th scope="col">Confidence</th></tr></thead><tbody>
            {findings.map((item) => <tr key={item.id}>
              <td><span className="mono record-id">{item.id}</span><div>{item.title}</div></td>
              <td><Pill tone={item.status && finalStatuses.has(item.status) ? 'success' : 'warning'}>{(item.status ?? 'HYPOTHESIS').replaceAll('_', ' ')}</Pill></td>
              <td>{Math.round(item.confidence_score * 100)}%</td>
            </tr>)}
          </tbody></table></div>}
      </section>
      <section className="panel" aria-labelledby="render-options">
        <div className="panel-head"><div className="panel-title"><ClipboardCheck size={20} aria-hidden="true" /><h2 id="render-options">Render readiness</h2></div></div>
        <ul className="prerequisites">
          <li><span>Eligible finding status</span><Pill tone={eligible > 0 && eligible === findings.length ? 'success' : 'warning'}>{eligible} of {findings.length}</Pill></li>
          <li><span>Ledger excerpt</span><Pill>Verification unavailable</Pill></li>
          <li><span>Teardown receipt</span><Pill>Verification unavailable</Pill></li>
        </ul>
        <div className="field"><label htmlFor="render-format">Output format</label><select id="render-format" value={format} onChange={(event) => setFormat(event.target.value)}><option>PDF</option><option>DOCX</option></select></div>
        <button className="button button--primary" disabled aria-describedby="render-blocker"><FileText size={16} aria-hidden="true" /> Render report</button>
        <p className="notice" id="render-blocker">Report rendering is unavailable. This checkout has no report service.</p>
      </section>
    </div>
  </section>
}
