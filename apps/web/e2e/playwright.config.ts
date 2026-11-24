import { defineConfig } from '@playwright/test'

const baseURL = process.env.M10_WEB_URL
if (!baseURL || !/^http:\/\/127\.0\.0\.1:\d+$/.test(baseURL)) {
  throw new Error('Start the disposable fixture services with e2e/run.py before running Playwright.')
}

export default defineConfig({
  testDir: '.',
  testMatch: 'cockpit.spec.ts',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 30_000,
  expect: { timeout: 10_000 },
  outputDir: process.env.M10_PLAYWRIGHT_OUTPUT,
  reporter: 'line',
  use: {
    baseURL,
    browserName: 'chromium',
    viewport: { width: 1440, height: 960 },
    serviceWorkers: 'block',
    trace: 'retain-on-failure',
    launchOptions: {
      executablePath: process.env.M10_CHROMIUM_EXECUTABLE,
      args: ['--no-sandbox', '--disable-dev-shm-usage', '--disable-background-networking', '--no-proxy-server'],
    },
  },
})
