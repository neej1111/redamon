/**
 * Regressions found reviewing the engagement surface, one describe per bug.
 *
 * Each of these was green on every existing test. They share a shape worth
 * naming: a control that reads one value while a different value is the one
 * that takes effect. The guard checked the argument while the column took the
 * override; the direction check read a `before` that could not contain the
 * field; the idempotency key was checked before the write that enforces it.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  createProject: vi.fn(),
  findProject: vi.fn(),
  updateProject: vi.fn(),
  updateManyProject: vi.fn(),
  createAuthorization: vi.fn(),
  findFirstAuthorization: vi.fn(),
  findUniqueAuthorization: vi.fn(),
  findManyAuthorization: vi.fn(),
  countAuthorization: vi.fn(),
  findFirstScanJob: vi.fn(),
  transaction: vi.fn(),
  busy: vi.fn(),
  audit: vi.fn(),
}))

vi.mock('@/lib/prisma', () => {
  const client = {
    project: {
      create: (...a: unknown[]) => h.createProject(...a),
      findUnique: (...a: unknown[]) => h.findProject(...a),
      update: (...a: unknown[]) => h.updateProject(...a),
      updateMany: (...a: unknown[]) => h.updateManyProject(...a),
    },
    engagementAuthorization: {
      create: (...a: unknown[]) => h.createAuthorization(...a),
      findFirst: (...a: unknown[]) => h.findFirstAuthorization(...a),
      findUnique: (...a: unknown[]) => h.findUniqueAuthorization(...a),
      findMany: (...a: unknown[]) => h.findManyAuthorization(...a),
      count: (...a: unknown[]) => h.countAuthorization(...a),
    },
    scanJob: { findFirst: (...a: unknown[]) => h.findFirstScanJob(...a) },
    $transaction: (fn: (tx: unknown) => unknown) => h.transaction(fn, client),
  }
  return { default: client }
})
vi.mock('@/lib/graphWriters', () => ({ describeScanWriters: (...a: unknown[]) => h.busy(...a) }))
vi.mock('@/lib/audit', () => ({ writeAudit: (...a: unknown[]) => h.audit(...a) }))

import { __resetRateLimiter } from '@/lib/mcpAuth'
import { field, fieldsWhere } from '@/lib/reconSettings/registry'
import { createProject } from './engagementTools'
import { updateReconSettings } from './writeTools'
import type { McpContext } from './tools'

const ctx = (): McpContext => ({
  token: {
    tokenId: 't1', userId: 'owner', tokenPrefix: 'rdmn_mcp_aaaaaaaa',
    name: 'agent',
    scopes: ['recon:read', 'project:create', 'engagement:authorize', 'recon:settings'] as never,
  },
})

const AUTH = {
  documentSha256: 'a'.repeat(64),
  documentKind: 'hackerone_program',
  programHandle: 'nba-public',
  issuedAt: '2026-01-01T00:00:00.000Z',
}

const projectRow = (over: Record<string, unknown> = {}) => ({
  id: 'p1',
  userId: 'owner',
  updatedAt: new Date('2026-01-01T00:00:00.000Z'),
  engagementKind: 'internal',
  roeGlobalMaxRps: 3,
  roeExcludedHosts: ['a.tld'],
  roeNotes: 'the original note',
  targetDomain: 'example.com',
  ffufWordlist: '/usr/share/seclists/Discovery/Web-Content/common.txt',
  ...over,
})

beforeEach(() => {
  vi.clearAllMocks()
  __resetRateLimiter()
  h.busy.mockResolvedValue(null)
  h.findProject.mockResolvedValue(projectRow())
  h.createProject.mockResolvedValue({ id: 'p1', name: 'test' })
  h.createAuthorization.mockResolvedValue({ id: 'auth1', recordedAt: new Date() })
  h.findFirstAuthorization.mockResolvedValue(null)
  h.findUniqueAuthorization.mockResolvedValue(null)
  h.findManyAuthorization.mockResolvedValue([])
  h.countAuthorization.mockResolvedValue(0)
  h.findFirstScanJob.mockResolvedValue(null)
  h.updateProject.mockResolvedValue({})
  h.updateManyProject.mockResolvedValue({ count: 1 })
  h.transaction.mockImplementation((fn, client) => fn(client))
  h.audit.mockResolvedValue(undefined)
})

/** The `data` object the tool handed Prisma. */
const createdData = () => h.createProject.mock.calls[0][0].data as Record<string, unknown>

describe("create_project's settings block may not override the engagement guard", () => {
  // `settings` is filtered in CREATE mode, which accepts create-only fields, and
  // it was applied AFTER the targeting and engagement columns. The third_party
  // guard read args.engagementKind while the row stored settings.engagementKind,
  // so a caller could pass the guard as a third party and be stored as internal.
  const TIGHT_THIRD_PARTY = {
    name: 'test',
    engagementKind: 'third_party',
    targetDomain: 'example.com',
    settings: { roeGlobalMaxRps: 3 },
    authorization: AUTH,
  }

  test('a third_party engagement cannot be stored as internal', async () => {
    await expect(
      createProject(ctx(), { ...TIGHT_THIRD_PARTY, settings: { engagementKind: 'internal' } })
    ).rejects.toThrow(/engagementKind.*may not be set through `settings`/s)
    expect(h.createProject).not.toHaveBeenCalled()
  })

  test('the ceiling the guard checks IS the one `settings` wrote', async () => {
    // The limits arrive through `settings` now, so there is no second block that
    // could disagree with the one the guard read. The guard runs after the
    // settings are merged into `data`, which is what makes that true rather
    // than merely likely.
    await expect(
      createProject(ctx(), { ...TIGHT_THIRD_PARTY, settings: { roeGlobalMaxRps: 0 } })
    ).rejects.toThrow(/must declare a request-rate ceiling/)
    expect(h.createProject).not.toHaveBeenCalled()
  })

  test('the targeting mode cannot be changed after it was derived', async () => {
    await expect(
      createProject(ctx(), {
        name: 'test',
        engagementKind: 'internal',
        targetDomain: 'example.com',
        settings: { targetDomain: 'somebody-else.tld' },
      })
    ).rejects.toThrow(/targetDomain.*may not be set through `settings`/s)
  })

  test('ordinary tuning still goes through settings', async () => {
    await createProject(ctx(), {
      name: 'test',
      engagementKind: 'internal',
      targetDomain: 'example.com',
      settings: { naabuRateLimit: 25, nucleiEnabled: false },
    })
    expect(createdData().naabuRateLimit).toBe(25)
    expect(createdData().nucleiEnabled).toBe(false)
  })

  test('the guard reads the value being stored, not the one requested', async () => {
    // Defence in depth behind the refusal above: whatever assembles `data`, the
    // third_party rules are checked against what the column will hold.
    await expect(
      createProject(ctx(), {
        name: 'test', engagementKind: 'third_party', targetDomain: 'example.com',
      })
    ).rejects.toThrow(/must declare a request-rate ceiling/)
  })

  test('the audit records the engagement that was stored', async () => {
    await createProject(ctx(), { ...TIGHT_THIRD_PARTY })
    const after = h.audit.mock.calls[0][0].after as Record<string, unknown>
    expect(after.engagementKind).toBe('third_party')
    expect(after.engagementLimits).toEqual({ roeGlobalMaxRps: 3 })
  })
})

describe('a field the surface cannot read back is not writable either', () => {
  // The old shape was write-without-read with a blinded audit: these columns
  // carry the client's identity and the agreement text, so they are withheld
  // from every MCP read, which meant the audit row recorded the prior value as
  // absent and the overwrite was unrecoverable.
  //
  // It is closed differently now. They are the engagement RECORD, refused
  // outright rather than refused by a special case inside one tool - so there is
  // no path left that could write them blind.
  const BLIND = fieldsWhere((f, key) => f.readable === false && key.startsWith('roe')).map(f => f.key)

  test('there is at least one such field, or this test proves nothing', () => {
    expect(BLIND.length).toBeGreaterThan(0)
  })

  test.each(BLIND)('%s is refused by the ordinary settings path', async key => {
    await expect(updateReconSettings(ctx(), 'p1', { [key]: 'overwritten' }))
      .rejects.toThrow(new RegExp(key))
    expect(h.updateProject).not.toHaveBeenCalled()
    expect(h.updateManyProject).not.toHaveBeenCalled()
  })

  test('every unreadable engagement column is closed to writes too', () => {
    // The read boundary and the write boundary agree here, which is the
    // property that makes a blinded audit impossible rather than merely
    // guarded against.
    for (const key of BLIND) {
      expect(field(key)!.mcp, key).toBe('never')
    }
  })

  test('a readable engagement LIMIT is still writable', async () => {
    await updateReconSettings(ctx(), 'p1', { roeGlobalMaxRps: 1 })
    expect(h.updateProject.mock.calls[0][0].data).toEqual({ roeGlobalMaxRps: 1 })
  })

  test('the audit for a limit change carries the real prior value', async () => {
    await updateReconSettings(ctx(), 'p1', { roeGlobalMaxRps: 1 })
    expect(h.audit.mock.calls[0][0].before).toEqual({ roeGlobalMaxRps: 3 })
  })
})

describe('a concurrent create_project with the same idempotency key returns the first project', () => {
  // The pre-check is a read and the constraint is on the write, so two retries
  // of the same loop tick race. The loser used to get a raw P2002, and an
  // unattended caller's answer to an opaque error is another retry with a fresh
  // key: the second project the key exists to prevent.
  const ARGS = {
    name: 'test',
    engagementKind: 'internal',
    targetDomain: 'example.com',
    authorization: AUTH,
    idempotencyKey: 'h1-nba-public',
  }

  test('the loser of the race gets the winner\'s project, not an error', async () => {
    h.transaction.mockRejectedValueOnce(Object.assign(new Error('unique'), { code: 'P2002' }))
    h.findUniqueAuthorization
      .mockResolvedValueOnce(null) // the pre-check, before the winner committed
      .mockResolvedValueOnce({ projectId: 'p-winner', project: { userId: 'owner', name: 'test' } })

    const r = await createProject(ctx(), ARGS)
    expect(r).toMatchObject({ projectId: 'p-winner', created: false })
  })

  test('a unique violation on some other column is not swallowed', async () => {
    h.transaction.mockRejectedValueOnce(Object.assign(new Error('unique'), { code: 'P2002' }))
    h.findUniqueAuthorization.mockResolvedValue(null)
    await expect(createProject(ctx(), ARGS)).rejects.toThrow('unique')
  })

  test('a call with no idempotency key still surfaces the error', async () => {
    h.transaction.mockRejectedValueOnce(Object.assign(new Error('unique'), { code: 'P2002' }))
    const { idempotencyKey: _k, ...noKey } = ARGS
    await expect(createProject(ctx(), noKey)).rejects.toThrow('unique')
  })

  test('the winner of the race is not returned to another account', async () => {
    h.transaction.mockRejectedValueOnce(Object.assign(new Error('unique'), { code: 'P2002' }))
    h.findUniqueAuthorization
      .mockResolvedValueOnce(null)
      .mockResolvedValueOnce({ projectId: 'p-other', project: { userId: 'someone-else', name: 'x' } })
    await expect(createProject(ctx(), ARGS)).rejects.toThrow(/another account/)
  })
})
