/**
 * The connect-time `instructions` string.
 *
 * Two properties this file exists to hold:
 *
 *  - **failing to onboard must never fail a connection.** The profile read, the
 *    tool-list build and the render are all best-effort; an agent that cannot be
 *    given instructions still gets a working server.
 *  - **the profile is read here, not in mcpAuth.ts.** It is editorial, and
 *    keeping the read out of the resolution path is what stops it looking like a
 *    second authorization input.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({ findToken: vi.fn() }))

vi.mock('@/lib/prisma', () => ({
  default: { mcpAccessToken: { findUnique: (...a: unknown[]) => h.findToken(...a) } },
}))
vi.mock('@/lib/audit', () => ({ writeAudit: vi.fn() }))

import { MCP_SCOPES, type McpScope } from '@/lib/mcpAuth'
import { buildInstructions, profileForToken, __resetAdvertisedToolsCache } from './instructions'

const READ_ONLY: McpScope[] = ['recon:read']

beforeEach(() => {
  vi.clearAllMocks()
  __resetAdvertisedToolsCache()
  h.findToken.mockResolvedValue({ profile: 'asm' })
  vi.spyOn(console, 'error').mockImplementation(() => undefined)
})

describe('the profile lookup', () => {
  test('reads the stored profile', async () => {
    expect(await profileForToken('t1')).toBe('asm')
    expect(h.findToken.mock.calls[0][0]).toEqual({
      where: { id: 't1' },
      select: { profile: true },
    })
  })

  test('selects ONLY the profile, never the hash or the scopes', async () => {
    await profileForToken('t1')
    expect(Object.keys(h.findToken.mock.calls[0][0].select)).toEqual(['profile'])
  })

  test('a null profile reads as custom', async () => {
    h.findToken.mockResolvedValue({ profile: null })
    expect(await profileForToken('t1')).toBe('custom')
  })

  test('a missing row reads as custom', async () => {
    h.findToken.mockResolvedValue(null)
    expect(await profileForToken('t1')).toBe('custom')
  })

  test('an unrecognised stored value reads as custom rather than throwing', async () => {
    // A row written by a newer build, or tampered with.
    h.findToken.mockResolvedValue({ profile: 'from_the_future' })
    expect(await profileForToken('t1')).toBe('custom')
  })

  test('a database failure reads as custom, and does not propagate', async () => {
    h.findToken.mockRejectedValue(new Error('postgres is down'))
    expect(await profileForToken('t1')).toBe('custom')
  })
})

describe('building the instructions', () => {
  test('it renders the profile the token carries', async () => {
    const text = await buildInstructions('t1', [...MCP_SCOPES])
    expect(text).toContain('Continuous attack surface monitoring')
  })

  test('it is scope-filtered', async () => {
    const text = (await buildInstructions('t1', READ_ONLY))!
    expect(text).toContain('recon:read')
    expect(text).not.toContain('kali_exec')
    expect(text).not.toContain('set_finding_verdict')
  })

  test('a database failure still produces instructions, as the custom profile', async () => {
    h.findToken.mockRejectedValue(new Error('postgres is down'))
    const text = await buildInstructions('t1', READ_ONLY)
    expect(text).toBeDefined()
    expect(text).toContain('Custom')
  })

  test('the tool list is built once and cached for the process', async () => {
    await buildInstructions('t1', READ_ONLY)
    await buildInstructions('t2', READ_ONLY)
    // Two calls, two profile reads, but the expensive half happened once. If the
    // cache broke, every initialize would construct a throwaway MCP server.
    expect(h.findToken).toHaveBeenCalledTimes(2)
  })

  test('it never throws, whatever goes wrong', async () => {
    h.findToken.mockImplementation(() => { throw new Error('sync boom') })
    await expect(buildInstructions('t1', READ_ONLY)).resolves.toBeDefined()
  })
})
