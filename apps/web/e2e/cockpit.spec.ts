import AxeBuilder from '@axe-core/playwright'
import { expect, test, type Page } from '@playwright/test'
import { createHash, sign } from 'node:crypto'
import { readFile } from 'node:fs/promises'

function required(name: string): string {
  const value = process.env[name]
  if (!value) throw new Error(`Missing ${name}. Run e2e/run.py to start the fixture environment.`)
  return value
}

const origin = required('M10_WEB_URL')
const lockId = required('M10_LOCK_ID')
const stopId = required('M10_STOP_ID')
const reviewId = required('M10_REVIEW_ID')
const operator = required('M10_OPERATOR')
const fixtureBytes = Buffer.from('RedOps synthetic evidence. No client data.\n')
const artifactSha256 = createHash('sha256').update(fixtureBytes).digest('hex')

function endpoint(engagementId: string, suffix: string): string {
  return `/api/orchestrator/engagements/${engagementId}/${suffix}`
}

async function attach(page: Page, engagementId: string): Promise<void> {
  await page.goto('/')
  await page.getByRole('textbox', { name: 'Engagement ID', exact: true }).fill(engagementId)
  await page.getByRole('button', { name: 'Attach engagement', exact: true }).click()
  await expect(page.getByRole('region', { name: 'Live engagement state' }).getByText('INIT_SCOPING', { exact: true })).toBeVisible()
}

async function open(page: Page, name: string): Promise<void> {
  await page.getByRole('link', { name, exact: true }).click()
}

const outbound = new WeakMap<Page, string[]>()
test.beforeEach(async ({ page, context }) => {
  const attempts: string[] = []
  outbound.set(page, attempts)
  await context.route('**/*', async route => {
    if (new URL(route.request().url()).origin === origin) {
      await route.continue()
    } else {
      attempts.push(route.request().url())
      await route.abort('blockedbyclient')
    }
  })
})

test.afterEach(({ page }) => {
  expect(outbound.get(page), 'Browser traffic stays within the fixture origin').toEqual([])
})

test('records an externally signed RoE lock with the real orchestrator', async ({ page, request }) => {
  await attach(page, lockId)
  await expect(page.getByRole('button', { name: 'Create engagement', exact: true })).toBeDisabled()
  await page.getByText('Draft scope and limits', { exact: true }).click()
  await page.getByLabel('Window start (UTC)', { exact: true }).fill('2026-12-01T08:00:00Z')
  await page.getByLabel('Window end (UTC)', { exact: true }).fill('2026-12-12T22:00:00Z')
  await page.getByLabel('Allowed CIDRs (one per line)', { exact: true }).fill('198.51.100.0/24')
  await page.getByRole('button', { name: 'Preview unsigned draft', exact: true }).click()
  const [draft] = await Promise.all([
    page.waitForEvent('download'),
    page.getByRole('button', { name: 'Download unsigned draft', exact: true }).click(),
  ])
  const draftValue: unknown = JSON.parse(await readFile(await draft.path(), 'utf8'))
  expect(draftValue).toMatchObject({
    engagement_id: lockId,
    scope_boundaries: { allowed_cidrs: ['198.51.100.0/24'] },
  })
  expect(draftValue).not.toHaveProperty('signatures')
  await page.getByRole('textbox', { name: 'Operator ID', exact: true }).fill(operator)
  await page.getByRole('checkbox', { name: 'The signed RoE has been provisioned for this engagement.', exact: true }).check()
  await page.getByRole('button', { name: 'Prepare lock envelope', exact: true }).click()
  const [download] = await Promise.all([
    page.waitForEvent('download'),
    page.getByRole('button', { name: 'Download lock envelope', exact: true }).click(),
  ])
  const canonical = await readFile(await download.path())
  const text = canonical.toString('utf8')
  await expect(page.getByRole('textbox', { name: 'Canonical transition envelope', exact: true })).toHaveValue(text)
  const unsigned = JSON.parse(text) as Record<string, string>
  expect(unsigned).toMatchObject({
    engagement_id: lockId,
    from_state: 'INIT_SCOPING',
    to_state: 'ROE_LOCKED',
    actor_type: 'HUMAN_OPERATOR',
    actor_id: operator,
  })
  expect(unsigned).not.toHaveProperty('hitl_signature')
  expect(Object.keys(unsigned)).toEqual(Object.keys(unsigned).sort())

  const signatureField = page.getByRole('textbox', { name: 'Detached signature JSON', exact: true })
  const submit = page.getByRole('button', { name: 'Submit signed transition', exact: true })
  await signatureField.fill(JSON.stringify({ signer_id: operator, signature: '0'.repeat(128) }))
  const [rejected] = await Promise.all([
    page.waitForResponse(response => response.url() === `${origin}${endpoint(lockId, 'transition')}` && response.request().method() === 'POST'),
    submit.click(),
  ])
  expect(rejected.status()).toBe(403)
  expect(await rejected.json()).toEqual({ reason: 'HUMAN_SIGNATURE_REQUIRED' })
  const rejectedLedger = await request.get(endpoint(lockId, 'ledger'))
  expect(rejectedLedger.ok()).toBeTruthy()
  expect(await rejectedLedger.json()).toEqual([])

  const key = await readFile(required('M10_SIGNER_PATH'))
  const sig = sign(null, canonical, key).toString('hex')
  await signatureField.fill(JSON.stringify({
    signer_id: operator, signature: sig,
  }))
  const [transition] = await Promise.all([
    page.waitForResponse(response => response.url() === `${origin}${endpoint(lockId, 'transition')}` && response.request().method() === 'POST'),
    submit.click(),
  ])
  expect(transition.status()).toBe(200)
  await expect(page.getByRole('region', { name: 'Live engagement state' }).getByText('ROE_LOCKED', { exact: true })).toBeVisible()
  const ledger = await request.get(endpoint(lockId, 'ledger'))
  expect(ledger.ok()).toBeTruthy()
  expect(await ledger.json()).toEqual([expect.objectContaining({
    event: { ...unsigned, hitl_signature: { signer_id: operator, signature: sig } },
    prev_record_hash: '0'.repeat(64),
    record_hash: expect.stringMatching(/^[0-9a-f]{64}$/),
  })])
})

test('stops the attached engagement from another module with Ctrl+Shift+K', async ({ page, request }) => {
  await attach(page, stopId)
  const foreign = await request.post(endpoint(stopId, 'killswitch'), { headers: { Origin: 'https://foreign.invalid' } })
  expect(foreign.status()).toBe(404)
  expect(await (await request.get(endpoint(stopId, 'state'))).json()).toEqual({ state: 'INIT_SCOPING' })
  await open(page, 'Task board')
  const [stop] = await Promise.all([
    page.waitForResponse(response => response.url() === `${origin}${endpoint(stopId, 'killswitch')}` && response.request().method() === 'POST'),
    page.keyboard.press('Control+Shift+K'),
  ])
  expect(stop.status()).toBe(200)
  expect(await stop.json()).toMatchObject({ next_state: 'HALTED_KILLSWITCH', notification_published: true })
  const state = await request.get(endpoint(stopId, 'state'))
  expect(state.ok()).toBeTruthy()
  expect(await state.json()).toEqual({ state: 'HALTED_KILLSWITCH' })
  const ledger = await request.get(endpoint(stopId, 'ledger'))
  expect(ledger.ok()).toBeTruthy()
  expect(await ledger.json()).toEqual([expect.objectContaining({
    event: expect.objectContaining({ engagement_id: stopId, to_state: 'HALTED_KILLSWITCH' }),
  })])
})

test('compares graph evidence and downloads a digest-verified linked artifact', async ({ page }) => {
  await attach(page, reviewId)
  await page.getByLabel('Import review snapshot', { exact: true }).setInputFiles(required('M10_SNAPSHOT_PATH'))
  await open(page, 'Attack surface')
  await expect(page.getByRole('table', { name: 'Asset inventory' })).toContainText('gateway.example.test')
  await page.getByRole('combobox', { name: 'From asset', exact: true }).selectOption('11111111-1111-4111-8111-111111111111')
  await page.getByRole('combobox', { name: 'To asset', exact: true }).selectOption('22222222-2222-4222-8222-222222222222')
  const [route] = await Promise.all([
    page.waitForResponse(response => response.url() === `${origin}/api/graph/paths` && response.request().method() === 'POST'),
    page.getByRole('button', { name: 'Show path overlay', exact: true }).click(),
  ])
  expect(route.status()).toBe(200)
  expect(await route.json()).toEqual([expect.objectContaining({ id: 'm10-fixture-edge', engagement_id: reviewId })])
  await expect(page.getByText('Path overlay ready', { exact: false })).toBeVisible()

  await open(page, 'Evidence vault')
  await page.getByRole('textbox', { name: 'Finding ID', exact: true }).fill('m10-finding')
  const [linked] = await Promise.all([
    page.waitForResponse(response => response.url() === `${origin}/api/evidence/findings/m10-finding/evidence?engagement_id=${reviewId}`),
    page.getByRole('button', { name: 'Find evidence', exact: true }).click(),
  ])
  expect(linked.status()).toBe(200)
  await expect(page.getByText(artifactSha256, { exact: true })).toBeVisible()
  await expect(page.getByRole('link', { name: 'Download verified artifact' })).toHaveCount(0)
  await page.getByRole('button', { name: 'Verify SHA-256', exact: true }).click()
  const link = page.getByRole('link', { name: 'Download verified artifact' })
  await expect(link).toBeVisible()
  const [download] = await Promise.all([page.waitForEvent('download'), link.click()])
  expect(await readFile(await download.path())).toEqual(fixtureBytes)
})

test('withholds the evidence download if the returned bytes fail SHA-256 verification', async ({ page }) => {
  await attach(page, reviewId)
  await open(page, 'Evidence vault')
  await page.getByRole('textbox', { name: 'Finding ID', exact: true }).fill('m10-finding')
  await page.getByRole('button', { name: 'Find evidence', exact: true }).click()
  await expect(page.getByText(artifactSha256, { exact: true })).toBeVisible()
  await page.route(`${origin}/api/evidence/artifacts/${artifactSha256}`, async route => {
    const response = await route.fetch({ maxRedirects: 0 })
    const altered = await response.body()
    altered.writeUInt8(altered.readUInt8(0) ^ 1, 0)
    await route.fulfill({ response, body: altered })
  })
  await page.getByRole('button', { name: 'Verify SHA-256', exact: true }).click()
  await expect(page.getByText('Artifact verification failed. Download is blocked.', { exact: true })).toBeVisible()
  await expect(page.getByRole('link', { name: 'Download verified artifact' })).toHaveCount(0)
})

test('shows supplied review work with unsupported approval and report actions blocked', async ({ page }) => {
  await attach(page, reviewId)
  await page.getByLabel('Import review snapshot', { exact: true }).setInputFiles(required('M10_SNAPSHOT_PATH'))
  await open(page, 'Task board')
  for (const column of ['Queued', 'Running', 'Paused-HITL', 'Done', 'Rejected']) {
    await expect(page.getByRole('heading', { name: column, exact: true })).toBeVisible()
  }
  await expect(page.getByText('Review fixture exposure', { exact: true })).toBeVisible()
  await page.getByText('Review details', { exact: true }).click()
  await expect(page.getByText('Review imported evidence and note data provenance.', { exact: true })).toBeVisible()

  await open(page, 'Approval rail')
  await expect(page.getByRole('heading', { name: 'HITL Approval Rail', exact: true })).toBeVisible()
  const ranked = page.getByRole('list', { name: 'Ranked proposals', exact: true }).getByRole('button')
  await expect(ranked.nth(0)).toHaveAccessibleName(/^Review archive deletion proposal/)
  await expect(ranked.nth(1)).toHaveAccessibleName(/^Review status response/)
  await expect(page.getByText('Two distinct operator signatures required.', { exact: true })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Approve & Sign', exact: true })).toBeDisabled()
  const accessibility = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']).analyze()
  expect(accessibility.violations.map(violation => ({ id: violation.id, nodes: violation.nodes.map(node => node.target) }))).toEqual([])
  await ranked.nth(0).focus()
  await page.keyboard.press('Tab')
  await expect(ranked.nth(1)).toBeFocused()
  await page.keyboard.press('Enter')
  await expect(page.getByText('GET /fixture/status HTTP/1.1', { exact: true })).toBeVisible()
  await expect(page.getByText('Read existing status only.', { exact: true })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Approve & Sign', exact: true })).toBeDisabled()

  await open(page, 'Report studio')
  await expect(page.getByRole('heading', { name: 'Report Studio', exact: true })).toBeVisible()
  await expect(page.getByText('Review maintenance access', { exact: true })).toBeVisible()
  await expect(page.getByRole('button', { name: /render report/i })).toBeDisabled()
})
