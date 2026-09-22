/**
 * Pruning long-dead MCP tokens. Internal-key only, driven by the orchestrator's
 * maintenance loop because the webapp has no scheduler of its own.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({ isInternal: vi.fn(), deleteMany: vi.fn() }))

vi.mock('@/lib/prisma', () => ({
  default: { mcpAccessToken: { deleteMany: (...a: unknown[]) => h.deleteMany(...a) } },
}))
vi.mock('@/lib/session', () => ({ isInternalRequest: (...a: unknown[]) => h.isInternal(...a) }))

import { POST, retentionDays } from './route'

const req = () => ({}) as never

beforeEach(() => {
  vi.clearAllMocks()
  vi.unstubAllEnvs()
  h.isInternal.mockReturnValue(true)
  h.deleteMany.mockResolvedValue({ count: 2 })
})

describe('auth', () => {
  test('a non-internal caller is refused and deletes nothing', async () => {
    h.isInternal.mockReturnValue(false)
    const res = await POST(req())
    expect(res.status).toBe(401)
    expect(h.deleteMany).not.toHaveBeenCalled()
  })

  test('the internal key is accepted', async () => {
    expect((await POST(req())).status).toBe(200)
  })
})

describe('what it deletes', () => {
  test('only rows dead for longer than the retention window', async () => {
    const res = await POST(req())
    const where = h.deleteMany.mock.calls[0][0].where
    const cutoff = new Date((await res.json()).cutoff)

    expect(where.OR).toEqual([
      { revokedAt: { lt: cutoff } },
      { expiresAt: { lt: cutoff } },
    ])
  })

  test('a LIVE token is never matched', async () => {
    await POST(req())
    const where = h.deleteMany.mock.calls[0][0].where
    // Both arms require a non-null timestamp older than the cutoff, so a live
    // token (both null) matches neither.
    for (const arm of where.OR) {
      expect(Object.values(arm)[0]).toHaveProperty('lt')
    }
  })

  test('it reports the count', async () => {
    expect((await POST(req())).status).toBe(200)
    expect(await (await POST(req())).json()).toMatchObject({ pruned: 2 })
  })

  test('a database failure is a 500, not a silent success', async () => {
    h.deleteMany.mockRejectedValue(new Error('db down'))
    expect((await POST(req())).status).toBe(500)
  })
})

describe('retentionDays', () => {
  test('defaults to 90', () => {
    expect(retentionDays()).toBe(90)
  })

  test('honours a valid override', () => {
    vi.stubEnv('MCP_TOKEN_RETENTION_DAYS', '30')
    expect(retentionDays()).toBe(30)
  })

  test('garbage and non-positive values fall back to the default', () => {
    for (const bad of ['', 'abc', '0', '-7']) {
      vi.stubEnv('MCP_TOKEN_RETENTION_DAYS', bad)
      expect(retentionDays()).toBe(90)
    }
  })
})
