import { useState, type ChangeEvent } from 'react'
import { createRoot } from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { createRootRoute, createRoute, createRouter, Link, Outlet, RouterProvider } from '@tanstack/react-router'
import { Bot, FileCheck2, Fingerprint, GitFork, LayoutDashboard, Network, ShieldCheck, ShieldOff, Upload } from 'lucide-react'
import { Pill } from '@ui'
import { CockpitRoute } from './routes/cockpit'
import { SurfaceRoute } from './routes/surface'
import { BoardRoute } from './routes/board'
import { HitlRoute } from './routes/hitl'
import { VaultRoute } from './routes/vault'
import { StudioRoute } from './routes/studio'
import { useWorkspace, WorkspaceProvider } from './workspace'
import './styles.css'

const sections = [
  { to: '/', label: 'Cockpit', icon: LayoutDashboard },
  { to: '/surface', label: 'Attack surface', icon: Network },
  { to: '/board', label: 'Task board', icon: Bot },
  { to: '/hitl', label: 'Approval rail', icon: ShieldCheck },
  { to: '/vault', label: 'Evidence vault', icon: Fingerprint },
  { to: '/studio', label: 'Report studio', icon: FileCheck2 },
] as const

function Shell() {
  const { engagementId, importSnapshot, mode, snapshot, state, stop } = useWorkspace()
  const [upload, setUpload] = useState<{ id: string; message: string; error: boolean } | null>(null)
  const [importing, setImporting] = useState(false)
  const live = mode === 'live'
  const stopped = live && state.data === 'HALTED_KILLSWITCH'
  const healthyRead = live && state.isSuccess && !stopped

  async function onFile(event: ChangeEvent<HTMLInputElement>): Promise<void> {
    const file = event.currentTarget.files?.item(0)
    event.currentTarget.value = ''
    if (!file) return
    setImporting(true)
    setUpload(null)
    try {
      await importSnapshot(file)
      setUpload({ id: engagementId, message: 'Review snapshot imported for this session.', error: false })
    } catch (error) {
      setUpload({ id: engagementId, message: error instanceof Error ? error.message : 'Snapshot could not be imported.', error: true })
    } finally {
      setImporting(false)
    }
  }

  return <div className="shell">
    <a className="skip-link" href="#content">Skip to content</a>
    <aside className="sidebar" aria-label="Workspace sidebar">
      <div className="brand"><span className="brand-mark"><GitFork size={22} aria-hidden="true" /></span><span><strong>RedOps</strong><small>COMMAND CENTER</small></span></div>
      <div className="nav-label">WORKSPACE</div>
      <nav aria-label="Workspace modules">
        {sections.map(({ to, label, icon: Icon }) => <Link key={to} to={to} activeOptions={{ exact: true }} className="nav-link" activeProps={{ 'aria-current': 'page' }}><Icon size={18} aria-hidden="true" /><span>{label}</span></Link>)}
      </nav>
      <div className="sidebar-bottom"><div className="workspace-card"><span className="workspace-icon">{live ? 'L' : 'S'}</span><div><strong>{live ? 'Attached engagement' : 'Sample workspace'}</strong><small>{live ? engagementId.slice(0, 8) : 'Synthetic review data'}</small></div></div></div>
    </aside>
    <div className="application">
      <header className="topbar">
        <div className="workspace-status"><span className={`signal${stopped ? ' signal--halted' : healthyRead ? ' signal--live' : ''}`} aria-hidden="true" />
          <div><strong>{live ? 'Live workspace' : 'Sample workspace'}</strong><small>{live ? (state.isError ? 'State unavailable' : state.data?.replaceAll('_', ' ') ?? 'Connecting') : 'Review only'}</small></div>
        </div>
        <div className="top-actions">
          {live && <label className="button button--secondary upload-control"><Upload size={16} aria-hidden="true" /><span>{importing ? 'Importing…' : 'Import snapshot'}</span><input type="file" accept="application/json,.json" aria-label="Import review snapshot" disabled={importing} onChange={(event) => { void onFile(event) }} /></label>}
          <button type="button" className="button button--danger" onClick={stop.activate} disabled={!live || stop.isPending} aria-keyshortcuts="Control+Shift+K" aria-describedby="stop-explanation">
            <ShieldOff size={17} aria-hidden="true" /><span>{stop.isPending ? 'Stopping…' : 'Emergency stop'}</span><kbd aria-hidden="true">Ctrl ⇧ K</kbd>
          </button>
          <span id="stop-explanation" className="sr-only">{live ? 'Halt the attached engagement. Shortcut Control Shift K.' : 'Attach a live engagement to use emergency stop.'}</span>
        </div>
      </header>
      <main id="content" className="content" tabIndex={-1}>
        <div className="workspace-feedback">
          {stop.receipt && <p role="status" className={stop.receipt.notification_published ? 'notice notice--success' : 'notice notice--warning'}>
            {stop.receipt.notification_published ? 'Engagement halted. Stop notification published.' : 'Engagement halted. Stop notification could not be published. Retry emergency stop.'}
          </p>}
          {stop.error && <p role="alert" className="notice notice--danger">{stop.error}</p>}
          {upload?.id === engagementId && live && <p role={upload.error ? 'alert' : 'status'} className="notice">{upload.message}</p>}
        </div>
        <Outlet />
        <footer className="workspace-footer">
          <Pill>{live ? (snapshot ? 'Imported review snapshot' : 'Attached engagement') : 'Sample data'}</Pill>
        </footer>
      </main>
    </div>
  </div>
}

const root = createRootRoute({ component: Shell, notFoundComponent: () => <main className="page"><h1>Module unavailable</h1><Link to="/">Return to cockpit</Link></main> })
const tree = root.addChildren([
  createRoute({ getParentRoute: () => root, path: '/', component: CockpitRoute }),
  createRoute({ getParentRoute: () => root, path: '/surface', component: SurfaceRoute }),
  createRoute({ getParentRoute: () => root, path: '/board', component: BoardRoute }),
  createRoute({ getParentRoute: () => root, path: '/hitl', component: HitlRoute }),
  createRoute({ getParentRoute: () => root, path: '/vault', component: VaultRoute }),
  createRoute({ getParentRoute: () => root, path: '/studio', component: StudioRoute }),
])
const router = createRouter({ routeTree: tree })
declare module '@tanstack/react-router' { interface Register { router: typeof router } }

const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
const element = document.getElementById('root')
if (!element) throw new Error('Application root is missing.')
createRoot(element).render(<QueryClientProvider client={client}><WorkspaceProvider><RouterProvider router={router} /></WorkspaceProvider></QueryClientProvider>)
