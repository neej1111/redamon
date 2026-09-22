/**
 * Scan Queue C-7 - deleting a project must stop in-flight work FIRST, so a
 * mid-write scan cannot resurrect the deleted project's graph as orphan nodes and
 * a dispatched job cannot scan a deleted project with DEFAULT settings.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  projectDelete: vi.fn(),
  jobQueueUpdateMany: vi.fn(),
  capturedFindMany: vi.fn(),
  orchestratorFetch: vi.fn(),
  effectiveUser: vi.fn(),
  countAuthorizations: vi.fn(),
  archiveTransaction: vi.fn(),
}))

vi.mock('@/lib/prisma', () => ({
  default: {
    project: { delete: (...a: unknown[]) => h.projectDelete(...a) },
    jobQueue: { updateMany: (...a: unknown[]) => h.jobQueueUpdateMany(...a) },
    capturedHttpTransaction: { findMany: (...a: unknown[]) => h.capturedFindMany(...a) },
    // The authorization records do NOT cascade: they are archived first, so
    // deleting a project cannot destroy the record of what authorized it.
    engagementAuthorization: { count: (...a: unknown[]) => h.countAuthorizations(...a) },
    $transaction: (fn: (tx: unknown) => unknown) => h.archiveTransaction(fn),
  },
}))
vi.mock('@/app/api/graph/neo4j', () => ({ getGraphSession: () => ({ run: vi.fn(), close: vi.fn() }) }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: (...a: unknown[]) => h.orchestratorFetch(...a) }))
vi.mock('@/lib/access', async () => {
  const actual = await vi.importActual<typeof import('@/lib/access')>('@/lib/access')
  return { ...actual, requireEffectiveUser: () => h.effectiveUser(), requireProjectAccess: () => null }
})

import { DELETE } from './route'

const del = () => new NextRequest('http://x/api/projects/p1', { method: 'DELETE' })
const params = (id: string) => ({ params: Promise.resolve({ id }) })

beforeEach(() => {
  vi.clearAllMocks()
  h.effectiveUser.mockResolvedValue({ userId: 'u1' })
  h.projectDelete.mockResolvedValue({ id: 'p1', userId: 'u1' })
  h.jobQueueUpdateMany.mockResolvedValue({ count: 2 })
  h.capturedFindMany.mockResolvedValue([])
  h.orchestratorFetch.mockResolvedValue({ ok: true, json: async () => ({ deleted: [] }) })
  h.countAuthorizations.mockResolvedValue(0)
  h.archiveTransaction.mockImplementation(async (fn: (tx: unknown) => unknown) =>
    fn({ $executeRawUnsafe: async () => 1 })
  )
})

describe('the record of what authorized an engagement outlives the engagement', () => {
  // Every OTHER Project child cascades. These do not, because deleting a
  // project is exactly when the record of what authorized it stops being
  // recoverable, and that is the thing an incident review needs most.
  test('a project with no records deletes without touching the archive', async () => {
    h.countAuthorizations.mockResolvedValue(0)
    expect((await DELETE(del(), params('p1'))).status).toBe(200)
    expect(h.archiveTransaction).not.toHaveBeenCalled()
  })

  test('a project WITH records archives them first', async () => {
    h.countAuthorizations.mockResolvedValue(2)
    expect((await DELETE(del(), params('p1'))).status).toBe(200)
    expect(h.archiveTransaction).toHaveBeenCalled()
    // Archived BEFORE the delete: the foreign key is Restrict, so the other
    // order would simply fail.
    expect(h.archiveTransaction.mock.invocationCallOrder[0])
      .toBeLessThan(h.projectDelete.mock.invocationCallOrder[0])
  })

  test('a failed archive refuses the delete rather than losing the records', async () => {
    h.countAuthorizations.mockResolvedValue(2)
    h.archiveTransaction.mockRejectedValue(new Error('archive table missing'))
    const res = await DELETE(del(), params('p1'))
    expect(res.status).toBe(500)
    expect((await res.json()).error).toMatch(/must outlive/)
    expect(h.projectDelete).not.toHaveBeenCalled()
  })
})

test('cancels non-terminal queue rows before deleting the project (C-7)', async () => {
  const res = await DELETE(del(), params('p1'))
  expect(res.status).toBe(200)
  expect(h.jobQueueUpdateMany).toHaveBeenCalledWith(expect.objectContaining({
    where: expect.objectContaining({ projectId: 'p1', status: { in: ['queued', 'dispatching', 'running', 'needs_review'] } }),
    data: expect.objectContaining({ status: 'canceled' }),
  }))
  expect(h.projectDelete).toHaveBeenCalled()
})

test('calls the orchestrator stop endpoints for the running scan types', async () => {
  await DELETE(del(), params('p1'))
  const stopCalls = h.orchestratorFetch.mock.calls
    .map(c => String(c[0]))
    .filter(u => u.endsWith('/stop'))
  expect(stopCalls.some(u => u.includes('/recon/p1/stop'))).toBe(true)
  expect(stopCalls.some(u => u.includes('/gvm/p1/stop'))).toBe(true)
  expect(stopCalls.some(u => u.includes('/supply-chain/p1/stop'))).toBe(true)
})

test('a failed cancel does not abort the delete (best-effort)', async () => {
  h.jobQueueUpdateMany.mockRejectedValue(new Error('db down'))
  const res = await DELETE(del(), params('p1'))
  expect(res.status).toBe(200)
  expect(h.projectDelete).toHaveBeenCalled()
})
