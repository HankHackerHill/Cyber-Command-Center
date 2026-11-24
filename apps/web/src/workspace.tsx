import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { createContext, useContext, useLayoutEffect, useRef, useState, type ReactNode } from 'react'
import type { EngagementState, LedgerRecord } from '@contracts'
import { getLedger, getState, isEngagementId, killswitch, type StopResult } from './api/client'
import { MAX_REVIEW_BYTES, parseSnapshot, type WorkspaceSnapshot } from './review'
import { SAMPLE_ID, sampleSnapshot } from './sample'

export type { WorkspaceSnapshot, PlanReview, TaskReview } from './review'
export const stateKey = (id: string) => ['engagement', id, 'state'] as const
export const ledgerKey = (id: string) => ['engagement', id, 'ledger'] as const

function useWorkspaceState() {
  const [selection, setSelection] = useState<{ mode: 'sample' | 'live'; engagementId: string }>({ mode: 'sample', engagementId: SAMPLE_ID })
  const [imported, setImported] = useState<WorkspaceSnapshot | null>(null)
  const selectionVersion = useRef(0)
  const { mode, engagementId } = selection
  const queryClient = useQueryClient()
  const state = useQuery<EngagementState>({
    queryKey: mode === 'live' ? stateKey(engagementId) : ['sample', 'state'],
    enabled: mode === 'live', queryFn: ({ signal }) => getState(engagementId, signal),
    initialData: mode === 'sample' ? 'AWAITING_HITL_GATE' : undefined,
    refetchInterval: 4000, retry: false,
  })
  const ledger = useQuery<LedgerRecord[]>({
    queryKey: mode === 'live' ? ledgerKey(engagementId) : ['sample', 'ledger'],
    enabled: mode === 'live', queryFn: ({ signal }) => getLedger(engagementId, 0, signal),
    initialData: mode === 'sample' ? [] : undefined, retry: false,
  })
  const stopLock = useRef(false)
  const mutation = useMutation({
    mutationFn: (id: string) => killswitch(id),
    onSuccess: async (_receipt, id) => {
      await queryClient.cancelQueries({ queryKey: stateKey(id) })
      queryClient.setQueryData(stateKey(id), 'HALTED_KILLSWITCH' satisfies EngagementState)
      void queryClient.invalidateQueries({ queryKey: stateKey(id) })
      void queryClient.invalidateQueries({ queryKey: ledgerKey(id) })
    },
    onSettled: () => { stopLock.current = false },
  })

  function attach(raw: string): void {
    if (stopLock.current) return
    const id = raw.trim().toLowerCase()
    if (!isEngagementId(id)) throw new Error('Enter a canonical engagement UUID.')
    if (id !== engagementId || mode === 'sample') {
      selectionVersion.current += 1
      setImported(null)
    }
    setSelection({ mode: 'live', engagementId: id })
  }

  function showSample(): void {
    if (stopLock.current) return
    selectionVersion.current += 1
    setSelection({ mode: 'sample', engagementId: SAMPLE_ID })
    setImported(null)
  }

  async function importSnapshot(file: File): Promise<void> {
    if (mode !== 'live') throw new Error('Attach an engagement first.')
    if (file.size > MAX_REVIEW_BYTES) throw new Error('Snapshot exceeds 1 MiB.')
    const version = selectionVersion.current
    const parsed = parseSnapshot(await file.text(), engagementId)
    if (version !== selectionVersion.current) throw new Error('The engagement changed during import.')
    setImported(parsed)
  }

  function activate(): void {
    if (mode !== 'live' || stopLock.current) return
    stopLock.current = true
    mutation.mutate(engagementId)
  }

  useLayoutEffect(() => {
    function handleKey(event: KeyboardEvent): void {
      if (event.ctrlKey && event.shiftKey && !event.altKey && !event.metaKey && event.code === 'KeyK' && mode === 'live') {
        event.preventDefault()
        if (!event.repeat) activate()
      }
    }
    window.addEventListener('keydown', handleKey)
    return () => window.removeEventListener('keydown', handleKey)
  })

  const currentStop = mode === 'live' && mutation.variables === engagementId
  const receipt: StopResult | null = currentStop ? mutation.data ?? null : null
  return {
    engagementId, mode, state, ledger, attach, showSample, importSnapshot,
    snapshot: mode === 'sample' ? sampleSnapshot : imported?.engagementId === engagementId ? imported : null,
    stop: {
      activate, isPending: mutation.isPending, receipt,
      error: currentStop && mutation.isError ? 'Emergency stop could not be confirmed. Check the live state and retry.' : null,
    },
  }
}

const WorkspaceContext = createContext<ReturnType<typeof useWorkspaceState> | null>(null)

export function WorkspaceProvider({ children }: { children: ReactNode }) {
  const workspace = useWorkspaceState()
  return <WorkspaceContext.Provider value={workspace}>{children}</WorkspaceContext.Provider>
}

export function useWorkspace() {
  const value = useContext(WorkspaceContext)
  if (value === null) throw new Error('Workspace provider is missing.')
  return value
}
