/**
 * A password change must revoke every MCP personal access token.
 *
 * An admin can reset another user's password without knowing the current one,
 * so a reset that left live programmatic credentials behind would not actually
 * lock the account: a stolen token would keep working. The revoke shares the
 * password write's transaction, because a half-applied reset (new password, old
 * tokens still live) is worse than either outcome on its own.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  getSession: vi.fn(),
  hashPassword: vi.fn(),
  verifyPassword: vi.fn(),
  audit: vi.fn(),
  findUser: vi.fn(),
  updateUser: vi.fn(),
  updateManyTokens: vi.fn(),
  transaction: vi.fn(),
}))

vi.mock('@/lib/prisma', () => ({
  default: {
    user: {
      findUnique: (...a: unknown[]) => h.findUser(...a),
      update: (...a: unknown[]) => h.updateUser(...a),
    },
    mcpAccessToken: { updateMany: (...a: unknown[]) => h.updateManyTokens(...a) },
    $transaction: (...a: unknown[]) => h.transaction(...a),
  },
}))
vi.mock('@/lib/session', () => ({ getSession: (...a: unknown[]) => h.getSession(...a) }))
vi.mock('@/lib/auth', () => ({
  hashPassword: (...a: unknown[]) => h.hashPassword(...a),
  verifyPassword: (...a: unknown[]) => h.verifyPassword(...a),
}))
vi.mock('@/lib/audit', () => ({ writeAudit: (...a: unknown[]) => h.audit(...a) }))

import { PUT } from './route'

const params = (id = 'owner') => ({ params: Promise.resolve({ id }) })
const req = (body: unknown) => ({ json: async () => body }) as never

beforeEach(() => {
  vi.clearAllMocks()
  h.getSession.mockResolvedValue({ userId: 'owner', role: 'standard' })
  h.hashPassword.mockResolvedValue('new-hash')
  h.verifyPassword.mockResolvedValue(true)
  h.findUser.mockResolvedValue({ password: 'old-hash' })
  h.updateUser.mockReturnValue('USER_UPDATE_OP')
  h.updateManyTokens.mockReturnValue('TOKEN_REVOKE_OP')
  // The route awaits prisma.$transaction([...]) and destructures the results.
  h.transaction.mockImplementation(async () => [{}, { count: 3 }])
  h.audit.mockResolvedValue(undefined)
})

describe('a self-service password change revokes the user tokens', () => {
  test('it revokes every live token in the same transaction', async () => {
    const res = await PUT(req({ newPassword: 'brand-new', currentPassword: 'old' }), params('owner'))

    expect(res.status).toBe(200)
    expect(h.updateManyTokens).toHaveBeenCalledWith({
      where: { userId: 'owner', revokedAt: null },
      data: { revokedAt: expect.any(Date) },
    })
    // Both operations go into ONE $transaction call.
    expect(h.transaction).toHaveBeenCalledWith(['USER_UPDATE_OP', 'TOKEN_REVOKE_OP'])
  })

  test('it reports how many tokens were revoked', async () => {
    const res = await PUT(req({ newPassword: 'brand-new', currentPassword: 'old' }), params('owner'))
    expect(await res.json()).toMatchObject({ success: true, revokedMcpTokens: 3 })
  })

  test('already-revoked tokens are not re-stamped', async () => {
    await PUT(req({ newPassword: 'brand-new', currentPassword: 'old' }), params('owner'))
    expect(h.updateManyTokens.mock.calls[0][0].where.revokedAt).toBeNull()
  })

  test('the revocation is audited', async () => {
    await PUT(req({ newPassword: 'brand-new', currentPassword: 'old' }), params('owner'))
    expect(h.audit).toHaveBeenCalledWith(expect.objectContaining({
      action: 'mcp-token.revoke-all',
      targetId: 'owner',
    }))
  })

  test('no audit noise when the user had no tokens', async () => {
    h.transaction.mockResolvedValue([{}, { count: 0 }])
    await PUT(req({ newPassword: 'brand-new', currentPassword: 'old' }), params('owner'))
    expect(h.audit).not.toHaveBeenCalled()
  })
})

describe("an admin reset also revokes the target user's tokens", () => {
  test('the reset does not leave live programmatic credentials behind', async () => {
    h.getSession.mockResolvedValue({ userId: 'admin1', role: 'admin' })
    const res = await PUT(req({ newPassword: 'reset-by-admin' }), params('victim'))

    expect(res.status).toBe(200)
    expect(h.updateManyTokens).toHaveBeenCalledWith(
      expect.objectContaining({ where: { userId: 'victim', revokedAt: null } })
    )
  })

  test('the audit records that it was an admin action', async () => {
    h.getSession.mockResolvedValue({ userId: 'admin1', role: 'admin' })
    await PUT(req({ newPassword: 'reset-by-admin' }), params('victim'))
    expect(h.audit).toHaveBeenCalledWith(expect.objectContaining({
      actorId: 'admin1',
      after: expect.objectContaining({ byAdmin: true }),
    }))
  })
})

describe('a refused password change revokes nothing', () => {
  test('a wrong current password leaves the tokens alone', async () => {
    h.verifyPassword.mockResolvedValue(false)
    const res = await PUT(req({ newPassword: 'brand-new', currentPassword: 'wrong' }), params('owner'))

    expect(res.status).toBe(401)
    expect(h.transaction).not.toHaveBeenCalled()
    expect(h.updateManyTokens).not.toHaveBeenCalled()
  })

  test('a non-admin changing someone else changes nothing', async () => {
    h.getSession.mockResolvedValue({ userId: 'mallory', role: 'standard' })
    const res = await PUT(req({ newPassword: 'brand-new' }), params('victim'))

    expect(res.status).toBe(403)
    expect(h.transaction).not.toHaveBeenCalled()
  })

  test('a too-short password changes nothing', async () => {
    const res = await PUT(req({ newPassword: 'ab', currentPassword: 'old' }), params('owner'))
    expect(res.status).toBe(400)
    expect(h.transaction).not.toHaveBeenCalled()
  })
})
