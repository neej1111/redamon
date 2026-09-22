/**
 * The scan queue.
 *
 * The failures guarded here are all ones the existing browser paths have:
 *
 *  - `enqueueJob` checks no ownership and does not dedupe. It is an
 *    unconditional create against a table with no uniqueness constraint, so an
 *    agent retry loop mints duplicate jobs for the same scan.
 *  - the cancel route's `updateMany` IGNORES its count, so a job that flipped
 *    to running in the race window still answers ok with nothing cancelled -
 *    and the caller believes it stopped a scan that is in fact running.
 *  - a queued job that parks in `needs_review` waits for a person, and an agent
 *    that is not told waits forever.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  findProject: vi.fn(),
  findManyJobs: vi.fn(),
  findJob: vi.fn(),
  updateManyJobs: vi.fn(),
  enqueue: vi.fn(),
}))

vi.mock('@/lib/prisma', () => ({
  default: {
    project: { findUnique: (...a: unknown[]) => h.findProject(...a) },
    jobQueue: {
      findMany: (...a: unknown[]) => h.findManyJobs(...a),
      findUnique: (...a: unknown[]) => h.findJob(...a),
      updateMany: (...a: unknown[]) => h.updateManyJobs(...a),
    },
  },
}))
vi.mock('@/lib/enqueueJob', () => ({ enqueueJob: (...a: unknown[]) => h.enqueue(...a) }))

import { McpScopeError, McpAccessDenied, __resetRateLimiter } from '@/lib/mcpAuth'
import { McpToolError } from './errors'
import { cancelQueuedScan, queueRecon } from './queueTools'
import type { McpContext } from './tools'

const ctx = (scopes: string[] = ['recon:queue']): McpContext => ({
  token: {
    tokenId: 't1', userId: 'owner', tokenPrefix: 'rdmn_mcp_aaaaaaaa',
    name: 'agent', scopes: scopes as never,
  },
})

const jobRow = (over: Record<string, unknown> = {}) => ({
  id: 'j1', projectId: 'p1', kind: 'full_recon', status: 'queued', priority: 10,
  blockedCode: '', blockedReason: '', runId: '',
  enqueuedAt: new Date('2026-09-14T10:00:00Z'),
  envelopeBytes: BigInt(2147483648),
  ...over,
})

beforeEach(() => {
  vi.clearAllMocks()
  __resetRateLimiter()
  h.findProject.mockResolvedValue({ id: 'p1', userId: 'owner' })
  h.findManyJobs.mockResolvedValue([])
  h.enqueue.mockResolvedValue({ ok: true, status: 201, id: 'j-new' })
  h.findJob.mockResolvedValue(jobRow({ id: 'j-new' }))
  h.updateManyJobs.mockResolvedValue({ count: 1 })
})

describe('queue_recon permissions', () => {
  test('it needs recon:queue, and recon:scan is not enough', async () => {
    // Queued work dispatches LATER and outlives the credential that created
    // it, which is a materially different grant from starting a scan now.
    await expect(queueRecon(ctx(['recon:scan']), 'p1')).rejects.toBeInstanceOf(McpScopeError)
  })

  test('ownership is checked before anything is created', async () => {
    // enqueueJob does NOT check ownership: its own header says callers own it.
    h.findProject.mockResolvedValue({ id: 'p1', userId: 'someone-else' })
    await expect(queueRecon(ctx(), 'p1')).rejects.toBeInstanceOf(McpAccessDenied)
    expect(h.enqueue).not.toHaveBeenCalled()
  })

  // REGRESSION: the start bucket is keyed PER PROJECT and therefore shared
  // across every token in the deployment. Consuming it before proving ownership
  // let anyone who knew a project id burn that project's one-start-per-five-
  // minutes window, and the owner's own start_recon was then refused with
  // "Rate limit reached for this token" - blaming their own credential.
  // start_recon itself checks ownership first; these two did not.
  test('REGRESSION: a foreign project does not consume the per-project budget', async () => {
    vi.stubEnv('MCP_RATE_START_PER_WINDOW', '1')
    h.findProject.mockResolvedValue({ id: 'p1', userId: 'someone-else' })
    await expect(queueRecon(ctx(), 'p1')).rejects.toBeInstanceOf(McpAccessDenied)

    // The owner's window must still be intact.
    h.findProject.mockResolvedValue({ id: 'p1', userId: 'owner' })
    await expect(queueRecon(ctx(), 'p1')).resolves.toBeTruthy()
    vi.unstubAllEnvs()
  })

  test('it uses the per-project start window, not the ordinary write budget', async () => {
    // An enqueue reaches the same dispatcher a start reaches, so metering it as
    // a write would be an unmetered path to the same version-retention churn.
    vi.stubEnv('MCP_RATE_START_PER_WINDOW', '1')
    await queueRecon(ctx(), 'p1')
    await expect(queueRecon(ctx(), 'p1')).rejects.toThrow(/rate limit/i)
    vi.unstubAllEnvs()
  })
})

describe('queue_recon does not create duplicates', () => {
  test('an existing queued full recon refuses, naming the job', async () => {
    h.findManyJobs.mockResolvedValue([jobRow({ id: 'j-existing' })])
    const err = await queueRecon(ctx(), 'p1').catch((e: McpToolError) => e)
    expect(err).toMatchObject({ code: 'already_queued' })
    expect((err as McpToolError).message).toMatch(/j-existing/)
    expect(h.enqueue).not.toHaveBeenCalled()
  })

  test('a dispatching job counts as existing too', async () => {
    h.findManyJobs.mockResolvedValue([jobRow({ status: 'dispatching' })])
    await expect(queueRecon(ctx(), 'p1')).rejects.toMatchObject({ code: 'already_queued' })
  })

  test('a parked job says a PERSON must release it', async () => {
    // Nothing on this surface can re-confirm a needs_review job, so an agent
    // that is not told this waits forever.
    h.findManyJobs.mockResolvedValue([jobRow({ status: 'needs_review' })])
    await expect(queueRecon(ctx(), 'p1')).rejects.toThrow(/parked awaiting a person/)
  })

  test('the per-project ceiling refuses a flood of other kinds', async () => {
    // The memory governor holds ONE process-global ledger across all projects
    // and all tenants, and the dispatcher breaks head-of-line rather than
    // skipping, so a few fat jobs from one caller stall every other tenant.
    h.findManyJobs.mockResolvedValue([
      jobRow({ id: 'a', kind: 'gvm' }),
      jobRow({ id: 'b', kind: 'trufflehog' }),
      jobRow({ id: 'c', kind: 'supply_chain' }),
    ])
    await expect(queueRecon(ctx(), 'p1')).rejects.toMatchObject({ code: 'busy' })
  })
})

describe('queue_recon result', () => {
  test('it queues a full recon and describes the job', async () => {
    const r = await queueRecon(ctx(), 'p1')
    expect(h.enqueue).toHaveBeenCalledWith({ projectId: 'p1', userId: 'owner', kind: 'full_recon' })
    expect(r.job).toMatchObject({ jobId: 'j-new', kind: 'full_recon', status: 'queued' })
  })

  test('the BigInt envelope is serialisable', async () => {
    // JSON.stringify throws on a BigInt, so an unconverted one would fail the
    // whole tool call at the point of rendering the result.
    const r = await queueRecon(ctx(), 'p1')
    expect(() => JSON.stringify(r)).not.toThrow()
    expect(r.job).toMatchObject({ envelopeBytes: 2147483648 })
  })

  test('it says plainly that the job outlives the token', async () => {
    const notes = (await queueRecon(ctx(), 'p1')).notes.join(' ')
    expect(notes).toMatch(/OUTLIVES the token/)
    expect(notes).toMatch(/needs_review/)
  })

  test('an enqueue refusal is reported, never reported as queued', async () => {
    h.enqueue.mockResolvedValue({ ok: false, status: 400, error: 'Unknown scan kind: x' })
    await expect(queueRecon(ctx(), 'p1')).rejects.toBeInstanceOf(McpToolError)
  })
})

describe('cancel_queued_scan', () => {
  test('it needs recon:queue and ownership of the job', async () => {
    await expect(cancelQueuedScan(ctx([]), 'p1', 'j1')).rejects.toBeInstanceOf(McpScopeError)
    h.findJob.mockResolvedValue(jobRow({ projectId: 'someone-elses' }))
    await expect(cancelQueuedScan(ctx(), 'p1', 'j1'))
      .rejects.toMatchObject({ code: 'not_found' })
    expect(h.updateManyJobs).not.toHaveBeenCalled()
  })

  test('it cancels a queued job and reports what it was', async () => {
    const r = await cancelQueuedScan(ctx(), 'p1', 'j1')
    expect(r).toMatchObject({ jobId: 'j1', cancelled: true, priorStatus: 'queued' })
  })

  test('the update stays GUARDED, so a cancel cannot resurrect a dispatch', async () => {
    // Every dispatch state write is guarded on the prior status precisely so a
    // cancel landing mid-dispatch is not undone. An unguarded update here would
    // remove that protection.
    await cancelQueuedScan(ctx(), 'p1', 'j1')
    const where = h.updateManyJobs.mock.calls[0][0].where
    expect(where.id).toBe('j1')
    expect(where.status.in).toEqual(['queued', 'dispatching', 'needs_review'])
  })

  // REGRESSION: the browser cancel route ignores its own updateMany count, so a
  // job that flipped to `running` in the race window still returns {ok: true}
  // with nothing cancelled. Copying that here would tell an unattended agent it
  // had stopped a scan that is in fact still running against a live target.
  test('REGRESSION: a lost race reports failure, never success', async () => {
    h.updateManyJobs.mockResolvedValue({ count: 0 })
    const err = await cancelQueuedScan(ctx(), 'p1', 'j1').catch((e: McpToolError) => e)
    expect(err).toMatchObject({ code: 'lost_race' })
    expect((err as McpToolError).message).toMatch(/already started or finished/)
  })

  test('a running job says to use stop_recon instead', async () => {
    h.findJob.mockResolvedValue(jobRow({ status: 'running' }))
    await expect(cancelQueuedScan(ctx(), 'p1', 'j1')).rejects.toThrow(/stop_recon/)
    expect(h.updateManyJobs).not.toHaveBeenCalled()
  })

  test('an already finished job is refused by name', async () => {
    h.findJob.mockResolvedValue(jobRow({ status: 'done' }))
    await expect(cancelQueuedScan(ctx(), 'p1', 'j1')).rejects.toMatchObject({ code: 'not_cancellable' })
  })

  test('a parked job CAN be cancelled, since nothing here can release it', async () => {
    h.findJob.mockResolvedValue(jobRow({ status: 'needs_review' }))
    const r = await cancelQueuedScan(ctx(), 'p1', 'j1')
    expect(r.cancelled).toBe(true)
    expect(r.priorStatus).toBe('needs_review')
  })
})
