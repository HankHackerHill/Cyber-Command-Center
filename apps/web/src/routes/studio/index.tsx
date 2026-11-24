import { useQuery } from '@tanstack/react-query'
import { ClipboardCheck, FileText } from 'lucide-react'
import { useLayoutEffect, useRef, useState } from 'react'
import { EmptyState, PageHeading, Pill } from '@ui'
import { getFindings, renderReport, type Finding, type RenderedReport } from '../../api/client'
import { useWorkspace } from '../../workspace'

const finalStatuses = new Set(['CONFIRMED', 'FALSE_POSITIVE'])

interface Download {
  filename: string
  url: string
}

type RenderStatus =
  | { kind: 'pending' }
  | { kind: 'error'; message: string }
  | { kind: 'ready'; report: RenderedReport; pdf: Download; docx: Download }

function StudioContents({ engagementId, live, sampleFindings }: {
  engagementId: string
  live: boolean
  sampleFindings: Finding[]
}) {
  const register = useQuery({
    queryKey: ['engagement', engagementId, 'findings'],
    queryFn: ({ signal }) => getFindings(engagementId, signal),
    enabled: live,
  })
  const [render, setRender] = useState<RenderStatus | null>(null)
  const inFlight = useRef<AbortController | null>(null)
  const objectUrls = useRef<string[]>([])
  const findings = live ? register.data ?? [] : sampleFindings
  const eligible = findings.filter((item) => item.status && finalStatuses.has(item.status)).length
  const report = render?.kind === 'ready' ? render.report : null

  function clearDownloads() {
    objectUrls.current.forEach((url) => URL.revokeObjectURL(url))
    objectUrls.current = []
  }

  useLayoutEffect(() => () => {
    inFlight.current?.abort()
    clearDownloads()
  }, [])

  async function requestReport() {
    if (!live || inFlight.current) return
    clearDownloads()
    const controller = new AbortController()
    inFlight.current = controller
    setRender({ kind: 'pending' })
    try {
      const result = await renderReport(engagementId, controller.signal)
      if (controller.signal.aborted) return
      const pdfUrl = URL.createObjectURL(result.pdf.blob)
      objectUrls.current.push(pdfUrl)
      const docxUrl = URL.createObjectURL(result.docx.blob)
      objectUrls.current.push(docxUrl)
      setRender({
        kind: 'ready', report: result,
        pdf: { filename: result.pdf.filename, url: pdfUrl },
        docx: { filename: result.docx.filename, url: docxUrl },
      })
    } catch (error) {
      if (controller.signal.aborted) return
      clearDownloads()
      setRender({ kind: 'error', message: error instanceof Error ? error.message : 'Report rendering failed.' })
    } finally {
      if (inFlight.current === controller) inFlight.current = null
    }
  }

  return <div className="split">
    <section className="panel" aria-labelledby="report-findings">
      <div className="panel-head"><div><h2 id="report-findings">Findings register</h2><p>{live ? 'Live engagement records' : 'Sample review records'}</p></div>
        {(!live || register.data) && <Pill>{findings.length} {findings.length === 1 ? 'finding' : 'findings'}</Pill>}
      </div>
      {live && register.isPending ? <p role="status" className="muted">Loading findings…</p> :
        live && register.isError ? <div className="notice notice--danger" role="alert">
          Could not load the findings register. <button type="button" className="button button--secondary" onClick={() => void register.refetch()}>Retry findings lookup</button>
        </div> : findings.length === 0 ? <EmptyState title="No findings recorded">The register contains no findings for this engagement.</EmptyState> :
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
        <li><span>Finalized findings</span>{(!live || register.isSuccess) ?
          <Pill tone={eligible === findings.length ? 'success' : 'warning'}>{eligible} of {findings.length}</Pill> :
          <Pill>{register.isError ? 'Unavailable' : 'Loading'}</Pill>}</li>
        <li><span>Signed scope manifest</span><Pill tone={report ? 'success' : undefined}>{report ? 'Verified by M9' : 'Checked at render'}</Pill></li>
        <li><span>Ledger excerpt</span><Pill tone={report ? 'success' : undefined}>{report ? `${report.ledgerExcerpt.length} verified` : 'Checked at render'}</Pill></li>
        <li><span>Teardown receipt</span><Pill tone={report ? 'success' : undefined}>{report ? 'Completed' : 'Checked at render'}</Pill></li>
      </ul>
      <button type="button" className="button button--primary" disabled={!live || render?.kind === 'pending'}
        aria-describedby={live ? undefined : 'render-blocker'} onClick={() => void requestReport()}>
        <FileText size={16} aria-hidden="true" /> {render?.kind === 'pending' ? 'Rendering…' : 'Render report'}
      </button>
      {!live && <p className="notice" id="render-blocker">Attach a live engagement to render a report.</p>}
      {render?.kind === 'pending' && <p role="status" className="muted">Checking report sources and rendering both formats…</p>}
      {render?.kind === 'error' && <p role="alert" className="notice notice--danger">{render.message}</p>}
      {render?.kind === 'ready' && <>
        <p role="status" className="notice notice--success">Report ready. PDF and DOCX checksums verified.</p>
        <div className="studio-downloads">
          <a className="button button--secondary" href={render.pdf.url} download={render.pdf.filename}>Download PDF</a>
          <a className="button button--secondary" href={render.docx.url} download={render.docx.filename}>Download DOCX</a>
        </div>
        <details className="studio-provenance">
          <summary>Report provenance</summary>
          <dl>
            <dt>Scope manifest SHA-256</dt><dd><code>{render.report.manifestHash}</code></dd>
            <dt>RoE signature SHA-256</dt><dd><code>{render.report.roeSignatureHash}</code></dd>
            <dt>Last record in report excerpt</dt><dd><code>{render.report.ledgerExcerpt.at(-1)?.record_hash}</code></dd>
            <dt>Teardown completed</dt><dd><time dateTime={render.report.teardownCompletedAt}>{render.report.teardownCompletedAt}</time></dd>
          </dl>
        </details>
      </>}
    </section>
  </div>
}

export function StudioRoute() {
  const { engagementId, mode, snapshot } = useWorkspace()
  return <section className="page">
    <PageHeading title="Report Studio" category="Deliverables" description="Review findings and render the assessment report as PDF and DOCX." />
    <StudioContents key={`${mode}:${engagementId}`} engagementId={engagementId} live={mode === 'live'} sampleFindings={snapshot?.findings ?? []} />
  </section>
}
