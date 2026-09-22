/**
 * Ownership for the child rows MCP tools address by id.
 *
 * `assertMcpProjectAccess` proves the PARENT only. Every child id here is a
 * bare cuid that `findUnique` resolves across tenants without complaint, and a
 * `ScanVersion` is a gzipped dump of an entire attack-surface graph - so one
 * missing predicate is a cross-tenant read of another tenant's whole graph.
 *
 * Every helper must be indistinguishable between "no such row" and "someone
 * else's row", or the id space becomes enumerable.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  findProject: vi.fn(),
  queryRaw: vi.fn(),
  findJob: vi.fn(),
  findView: vi.fn(),
  findRemediation: vi.fn(),
}))

vi.mock('@/lib/prisma', () => ({
  default: {
    project: { findUnique: (...a: unknown[]) => h.findProject(...a) },
    $queryRaw: (...a: unknown[]) => h.queryRaw(...a),
    jobQueue: { findUnique: (...a: unknown[]) => h.findJob(...a) },
    graphView: { findUnique: (...a: unknown[]) => h.findView(...a) },
    remediation: { findUnique: (...a: unknown[]) => h.findRemediation(...a) },
  },
}))

import { McpAccessDenied } from '@/lib/mcpAuth'
import { McpToolError } from './errors'
import {
  assertJobInProject,
  assertRemediationInProject,
  assertVersionInProject,
  assertViewInProject,
} from './childAccess'

beforeEach(() => {
  vi.clearAllMocks()
  h.findProject.mockResolvedValue({ id: 'p1', userId: 'owner' })
})

describe('the parent is proved first, whatever the child id', () => {
  test.each([
    ['version', () => assertVersionInProject('owner', 'p1', 'v1')],
    ['job', () => assertJobInProject('owner', 'p1', 'j1')],
    ['view', () => assertViewInProject('owner', 'p1', 'g1')],
    ['remediation', () => assertRemediationInProject('owner', 'p1', 'r1')],
  ])("a foreign project stops the %s lookup before it happens", async (_kind, call) => {
    h.findProject.mockResolvedValue({ id: 'p1', userId: 'someone-else' })
    await expect(call()).rejects.toBeInstanceOf(McpAccessDenied)
    expect(h.queryRaw).not.toHaveBeenCalled()
    expect(h.findJob).not.toHaveBeenCalled()
    expect(h.findView).not.toHaveBeenCalled()
    expect(h.findRemediation).not.toHaveBeenCalled()
  })
})

describe('a child belonging to another project is refused', () => {
  test('a version whose projectId does not match', async () => {
    // The attack: a valid id from a project the token does not own. Without the
    // row-side predicate this returns another tenant's whole graph dump.
    h.queryRaw.mockResolvedValue([{
      id: 'v1', project_id: 'someone-elses-project', seq: 1, label: 'Scan 1',
      is_current: false, pinned: false, node_count: 1, link_count: 0,
      created_at: new Date(), snapshot_bytes: 4096,
    }])
    await expect(assertVersionInProject('owner', 'p1', 'v1'))
      .rejects.toMatchObject({ code: 'not_found' })
  })

  test('a job, a view and a remediation', async () => {
    h.findJob.mockResolvedValue({ id: 'j1', projectId: 'other' })
    h.findView.mockResolvedValue({ id: 'g1', projectId: 'other', cypherQuery: 'MATCH (n) RETURN n' })
    h.findRemediation.mockResolvedValue({ id: 'r1', projectId: 'other' })

    await expect(assertJobInProject('owner', 'p1', 'j1'))
      .rejects.toMatchObject({ code: 'not_found' })
    await expect(assertViewInProject('owner', 'p1', 'g1'))
      .rejects.toMatchObject({ code: 'not_found' })
    await expect(assertRemediationInProject('owner', 'p1', 'r1'))
      .rejects.toMatchObject({ code: 'not_found' })
  })
})

describe('a missing child is the same answer as a foreign one', () => {
  test('so the id space cannot be enumerated', async () => {
    h.queryRaw.mockResolvedValue([])
    h.findJob.mockResolvedValue(null)
    h.findView.mockResolvedValue(null)
    h.findRemediation.mockResolvedValue(null)

    const errors = await Promise.all([
      assertVersionInProject('owner', 'p1', 'nope').catch(e => e),
      assertJobInProject('owner', 'p1', 'nope').catch(e => e),
      assertViewInProject('owner', 'p1', 'nope').catch(e => e),
      assertRemediationInProject('owner', 'p1', 'nope').catch(e => e),
    ])
    // REGRESSION (e2e finding): these used to answer "Project not found" for a
    // bad CHILD id, on a project the caller had just proved it owns - sending an
    // agent off to retry with a different projectId over a bad viewId.
    for (const e of errors) {
      expect(e).toBeInstanceOf(McpToolError)
      expect(e.code).toBe('not_found')
      expect(e.message).not.toBe('Project not found')
      expect(e.message).toMatch(/in this project/)
    }
  })

  test('a foreign child and a missing child give the SAME message', async () => {
    // The one distinction that must never leak. Naming the child kind is safe
    // precisely because both branches produce this identical string.
    h.findView.mockResolvedValue(null)
    const missing = await assertViewInProject('owner', 'p1', 'nope').catch(e => e)
    h.findView.mockResolvedValue({ id: 'g1', projectId: 'someone-else' })
    const foreign = await assertViewInProject('owner', 'p1', 'g1').catch(e => e)

    expect(missing.message).toBe(foreign.message)
    expect(missing.code).toBe(foreign.code)
  })

  test('a foreign PROJECT still fails earlier, with the flat message', async () => {
    // The project boundary is untouched: it is enforced before any child is
    // read, and still cannot be told apart from a project that does not exist.
    h.findProject.mockResolvedValue({ id: 'p1', userId: 'someone-else' })
    const e = await assertViewInProject('owner', 'p1', 'g1').catch(err => err)
    expect(e).toBeInstanceOf(McpAccessDenied)
    expect(e.message).toBe('Project not found')
    expect(h.findView).not.toHaveBeenCalled()
  })
})

describe('an owned child resolves', () => {
  test('a version reports hasSnapshot without loading the bytes', async () => {
    h.queryRaw.mockResolvedValue([{
      id: 'v1', project_id: 'p1', seq: 4, label: 'Scan 4', is_current: false,
      pinned: true, node_count: 120, link_count: 300,
      created_at: new Date('2026-09-01T00:00:00Z'), snapshot_bytes: 8192,
    }])
    const v = await assertVersionInProject('owner', 'p1', 'v1')
    expect(v).toMatchObject({ seq: 4, pinned: true, hasSnapshot: true, snapshotBytes: 8192 })

    const sql = (h.queryRaw.mock.calls[0][0] as unknown as string[]).join(' ')
    expect(sql).toContain('octet_length(snapshot)')
  })

  test('a version with no bytes reports hasSnapshot false, not an error', async () => {
    h.queryRaw.mockResolvedValue([{
      id: 'v1', project_id: 'p1', seq: 5, label: 'Scan 5', is_current: true,
      pinned: false, node_count: null, link_count: null,
      created_at: new Date(), snapshot_bytes: null,
    }])
    const v = await assertVersionInProject('owner', 'p1', 'v1')
    expect(v.hasSnapshot).toBe(false)
    expect(v.isCurrent).toBe(true)
  })

  test('a view carries its query for the caller to run, and nothing else does', async () => {
    h.findView.mockResolvedValue({
      id: 'g1', projectId: 'p1', name: 'Admin panels', description: 'd',
      cypherQuery: 'MATCH (s:Subdomain) RETURN s',
    })
    const v = await assertViewInProject('owner', 'p1', 'g1')
    expect(v.cypherQuery).toBe('MATCH (s:Subdomain) RETURN s')
    expect(v.name).toBe('Admin panels')
  })

  test('a job and a remediation resolve to their projected fields', async () => {
    h.findJob.mockResolvedValue({
      id: 'j1', projectId: 'p1', kind: 'full_recon', status: 'queued',
      runId: '', enqueuedAt: new Date(),
    })
    h.findRemediation.mockResolvedValue({
      id: 'r1', projectId: 'p1', title: 'Patch nginx', status: 'pending',
    })
    expect(await assertJobInProject('owner', 'p1', 'j1')).toMatchObject({ kind: 'full_recon' })
    expect(await assertRemediationInProject('owner', 'p1', 'r1')).toMatchObject({ title: 'Patch nginx' })
  })
})
