/**
 * set_finding_verdict: the only write to a finding on this surface.
 *
 * Four things must hold, and three of them are failures that look like success:
 *
 *  - the verdict is stamped `human`, NOT a third provenance value. A third
 *    value makes the finding prune-eligible (a re-scan deletes it), lets a
 *    later AI run overwrite it, stops `likely_noise` meaning false-positive,
 *    and renders as "Not reviewed".
 *  - `updated: false` is never reported as success. The op answers HTTP 200 in
 *    two different failure shapes, both carrying it.
 *  - it refuses while a triage run is live, because that run's measurement step
 *    is unconditional and would silently re-file the finding afterwards.
 *  - it is audited, because a verdict is durable, suppresses future AI review,
 *    and had no actor record anywhere before this.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  findProject: vi.fn(),
  liveTriageRun: vi.fn(),
  writeAudit: vi.fn(),
  fetch: vi.fn(),
}))

vi.mock('@/lib/prisma', () => ({
  default: { project: { findUnique: (...a: unknown[]) => h.findProject(...a) } },
}))
vi.mock('@/lib/triageRun', () => ({ findLiveTriageRun: (...a: unknown[]) => h.liveTriageRun(...a) }))
vi.mock('@/lib/audit', () => ({ writeAudit: (...a: unknown[]) => h.writeAudit(...a) }))

import { McpScopeError, McpAccessDenied, __resetRateLimiter } from '@/lib/mcpAuth'
import { McpToolError } from './errors'
import { setFindingVerdict } from './verdictTools'
import type { McpContext } from './tools'

const ctx = (scopes: string[] = ['triage:write']): McpContext => ({
  token: {
    tokenId: 't1', userId: 'owner', tokenPrefix: 'rdmn_mcp_aaaaaaaa',
    name: 'agent', scopes: scopes as never,
  },
})

const agentReturns = (body: unknown) =>
  h.fetch.mockResolvedValue({ ok: true, json: async () => body })

const sentBody = () => JSON.parse(h.fetch.mock.calls[0][1].body)

beforeEach(() => {
  vi.clearAllMocks()
  __resetRateLimiter()
  vi.stubGlobal('fetch', h.fetch)
  h.findProject.mockResolvedValue({ id: 'p1', userId: 'owner' })
  h.liveTriageRun.mockResolvedValue(null)
  agentReturns({ updated: true, label: 'Vulnerability' })
})

describe('permissions and arguments', () => {
  test('it needs triage:write; triage:read is not enough', async () => {
    await expect(setFindingVerdict(ctx(['triage:read']), 'p1', 'v1', 'confirmed'))
      .rejects.toBeInstanceOf(McpScopeError)
  })

  test('ownership is checked before the agent is called', async () => {
    h.findProject.mockResolvedValue({ id: 'p1', userId: 'someone-else' })
    await expect(setFindingVerdict(ctx(), 'p1', 'v1', 'confirmed'))
      .rejects.toBeInstanceOf(McpAccessDenied)
    expect(h.fetch).not.toHaveBeenCalled()
  })

  test('an unknown verdict is refused by name, listing the valid ones', async () => {
    await expect(setFindingVerdict(ctx(), 'p1', 'v1', 'looks_bad'))
      .rejects.toThrow(/One of: confirmed, likely_noise, unreviewed/)
    expect(h.fetch).not.toHaveBeenCalled()
  })

  test('the three real verdicts are accepted', async () => {
    for (const status of ['confirmed', 'likely_noise', 'unreviewed']) {
      __resetRateLimiter()
      await expect(setFindingVerdict(ctx(), 'p1', 'v1', status)).resolves.toBeTruthy()
    }
  })
})

// REGRESSION: the obvious design - a third triage_source value so an agent's
// verdict is not laundered as a human's - breaks four behaviours that branch on
// that field being a closed two-value set. Most severely, the ingest-then-prune
// keep predicate is `(n:Muted OR coalesce(n.triage_source,'') = 'human')`, so a
// third value falls on the DELETE side and a re-scan removes the finding
// entirely rather than stamping stale_since.
describe('REGRESSION: provenance is a separate property, never a third source value', () => {
  test('the channel travels as `source`, which the mixin records separately', async () => {
    await setFindingVerdict(ctx(), 'p1', 'v1', 'confirmed')
    const body = sentBody()
    expect(body.op).toBe('human_verdict')
    expect(body.source).toBe('mcp')
    // The verdict VALUE is never sent: the mixin hardcodes 'human'.
    expect(body.triage_source).toBeUndefined()
  })

  test('the actor is sent, so a verdict records who and not only who it was not', async () => {
    await setFindingVerdict(ctx(), 'p1', 'v1', 'confirmed')
    expect(sentBody().verdict_by).toBe('owner')
  })

  test('the answer says the verdict is recorded as the operator\'s own', async () => {
    const notes = (await setFindingVerdict(ctx(), 'p1', 'v1', 'confirmed')).notes.join(' ')
    expect(notes).toMatch(/recorded as a human verdict/)
    expect(notes).toMatch(/arrived over MCP/)
  })
})

describe('a failed write is never reported as success', () => {
  test('updated:false is an error, whatever else the body says', async () => {
    // The op answers 200 with {updated:false} for a wrong id, another tenant's
    // id, and a non-muteable label - deliberately indistinguishable.
    agentReturns({ updated: false, label: null })
    await expect(setFindingVerdict(ctx(), 'p1', 'gone', 'confirmed'))
      .rejects.toMatchObject({ code: 'not_updated' })
  })

  test('the message covers the real ambiguity and says what to do', async () => {
    agentReturns({ updated: false, label: null })
    const err = await setFindingVerdict(ctx(), 'p1', 'gone', 'confirmed')
      .then(() => null, (e: Error) => e)
    expect(err?.message).toMatch(/no longer exists, was never in this project, or is not a type/)
    expect(err?.message).toMatch(/re-read list_findings/)
  })

  test('the second failure shape, an invalid status, is reported too', async () => {
    agentReturns({ updated: false, reason: "invalid status 'x'" })
    await expect(setFindingVerdict(ctx(), 'p1', 'v1', 'confirmed'))
      .rejects.toThrow(/invalid status/)
  })

  test('an unreachable agent is an error, not a silent no-op', async () => {
    h.fetch.mockRejectedValue(new Error('ECONNREFUSED'))
    await expect(setFindingVerdict(ctx(), 'p1', 'v1', 'confirmed'))
      .rejects.toBeInstanceOf(McpToolError)
  })

  test('nothing is audited when nothing was written', async () => {
    agentReturns({ updated: false, label: null })
    await setFindingVerdict(ctx(), 'p1', 'v1', 'confirmed').catch(() => {})
    expect(h.writeAudit).not.toHaveBeenCalled()
  })
})

// REGRESSION (plan 14.2): a triage run reads at step A and publishes minutes
// later, and while its verdict-writing steps protect a human verdict, its
// MEASUREMENT step is unconditional and rewrites triage_state - which drives the
// board section. A verdict does not touch updated_at, so the publish-time
// "unchanged" guard still matches and the row is written. A verdict set at
// T+3min saying "confirmed" gets filed under False Positive at T+8min.
describe('REGRESSION: it refuses while a triage run could re-file the finding', () => {
  test('a running triage run refuses the write', async () => {
    h.liveTriageRun.mockResolvedValue({ id: 'r1', status: 'running' })
    await expect(setFindingVerdict(ctx(), 'p1', 'v1', 'confirmed'))
      .rejects.toMatchObject({ code: 'busy' })
    expect(h.fetch).not.toHaveBeenCalled()
  })

  test('a publishing run refuses too, and says to retry', async () => {
    h.liveTriageRun.mockResolvedValue({ id: 'r1', status: 'publishing' })
    await expect(setFindingVerdict(ctx(), 'p1', 'v1', 'confirmed'))
      .rejects.toThrow(/Retry once it has finished/)
  })

  test('an unreadable run state FAILS CLOSED', async () => {
    // Writing blind here means the verdict may be silently undone, which is
    // worse than not writing it.
    h.liveTriageRun.mockRejectedValue(new Error('db down'))
    await expect(setFindingVerdict(ctx(), 'p1', 'v1', 'confirmed'))
      .rejects.toMatchObject({ code: 'busy' })
    expect(h.fetch).not.toHaveBeenCalled()
  })
})

describe('the verdict is audited', () => {
  test('a successful write records the finding, the status and the token', async () => {
    // Before this, a verdict was audited NOWHERE: the webapp route wrote no
    // audit row and the agent logged only mute and unmute. A durable decision
    // that suppresses future AI review was invisible to reconstruction.
    await setFindingVerdict(ctx(), 'p1', 'v1', 'likely_noise', 'duplicate of CVE-1')
    expect(h.writeAudit).toHaveBeenCalledWith(expect.objectContaining({
      actorId: 'owner',
      action: 'mcp.set_finding_verdict',
      targetType: 'finding',
      targetId: 'v1',
      source: 'mcp',
    }))
    expect(h.writeAudit.mock.calls[0][0].after).toMatchObject({
      projectId: 'p1', status: 'likely_noise', channel: 'mcp', tokenPrefix: 'rdmn_mcp_aaaaaaaa',
    })
  })

  test('the reason is bounded before it is sent', async () => {
    await setFindingVerdict(ctx(), 'p1', 'v1', 'confirmed', 'x'.repeat(5000))
    expect(sentBody().reason.length).toBe(500)
  })
})
