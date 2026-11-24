import { fileURLToPath } from 'node:url'
import react from '@vitejs/plugin-react'
import { defineConfig, loadEnv, type ProxyOptions } from 'vite'

const localServices = {
  orchestrator: 'REDOPS_ORCHESTRATOR_URL',
  graph: 'REDOPS_GRAPH_URL',
  evidence: 'REDOPS_EVIDENCE_URL',
} as const

const exposedRoutes = {
  orchestrator: /^(?:GET \/engagements\/[0-9a-f-]{36}\/(?:state|ledger)|POST \/engagements\/[0-9a-f-]{36}\/(?:transition|killswitch))$/,
  graph: /^POST \/(?:paths|tier0-reach)$/,
  evidence: /^GET \/(?:findings\/[^/?#]+\/evidence|artifacts\/[0-9a-f]{64})$/,
}

export default defineConfig(({ mode }) => {
  // This proxy is for local integration. Production ingress owns identity,
  // engagement authorization, and the fixed same-origin API routing.
  const env = { ...loadEnv(mode, process.cwd(), 'REDOPS_'), ...process.env }
  const proxy: Record<string, ProxyOptions> = {}
  for (const service of Object.keys(localServices) as (keyof typeof localServices)[]) {
    const variable = localServices[service]
    const configured = env[variable]
    if (!configured) continue
    const url = new URL(configured)
    if (url.protocol !== 'http:' || !['127.0.0.1', '[::1]'].includes(url.hostname)
      || !url.port || url.pathname !== '/' || url.search || url.hash || url.username || url.password) {
      throw new Error(`${variable} must be a loopback HTTP origin with an explicit port`)
    }
    const prefix = `/api/${service}`
    proxy[`^${prefix}/`] = {
      target: url.origin,
      changeOrigin: true,
      rewrite: (path) => path.slice(prefix.length),
      bypass: (request) => {
        const path = request.url?.slice(prefix.length).split('?', 1)[0]
        if (!exposedRoutes[service].test(`${request.method} ${path}`)) return false
        if (request.method === 'POST' && (request.headers['sec-fetch-site'] === 'cross-site'
          || (request.headers.origin && request.headers.origin !== `http://${request.headers.host}`))) return false
      },
    }
  }
  return {
    plugins: [react()],
    resolve: {
      alias: {
        '@ui': fileURLToPath(new URL('../../packages/ui/index.tsx', import.meta.url)),
        '@contracts': fileURLToPath(new URL('../../packages/contracts-ts/index.ts', import.meta.url)),
      },
      dedupe: ['react', 'react-dom'],
    },
    server: {
      host: '127.0.0.1',
      proxy,
      fs: { allow: [fileURLToPath(new URL('.', import.meta.url)), fileURLToPath(new URL('../../packages/', import.meta.url))] },
    },
  }
})
