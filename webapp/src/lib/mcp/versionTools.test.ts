/**
 * list_scan_versions and compare_scan_versions.
 *
 * Three failures dominate here, and none of them looks like an error:
 *
 *  - a read-only tool that WRITES. The browser versions route calls
 *    `ensureCurrentVersion`, which backfills and promotes rows. A tool
 *    annotated readOnlyHint doing that is a lie to every client.
 *  - a delta returned raw. Its identity keys embed secret VALUES
 *    (`Secret: [value, file]`, `JsReconFinding: [url, type, value]`) and its
 *    node bags are unbounded.
 *  - a delta computed ACROSS a state change. Activation clears the graph and
 *    then restores it as two separate steps, so mid-restore the project is
 *    observably empty and the comparison succeeds while reporting every node as
 *    removed.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  findProject: vi.fn(),
  queryRaw: vi.fn(),
  countVersions: vi.fn(),
  activity: vi.fn(),
  capture: vi.fn(),
  loadSnapshot: vi.fn(),
  trySlot: vi.fn(),
  ensureCurrentVersion: vi.fn(),
}))

vi.mock('@/lib/prisma', () => ({
  default: {
    project: { findUnique: (...a: unknown[]) => h.findProject(...a) },
    scanVersion: { count: (...a: unknown[]) => h.countVersions(...a) },
    $queryRaw: (...a: unknown[]) => h.queryRaw(...a),
  },
}))
vi.mock('@/lib/mcp/activity', () => ({
  readProjectActivity: (...a: unknown[]) => h.activity(...a),
}))
vi.mock('@/lib/scanSnapshot', () => ({
  captureGraphSnapshot: (...a: unknown[]) => h.capture(...a),
  loadSnapshot: (...a: unknown[]) => h.loadSnapshot(...a),
  // Identity: the tests hand it the payload shape computeReconDelta wants.
  snapshotToGraphPayload: (p: unknown) => p,
  tryWithSnapshotSlot: (fn: () => Promise<unknown>) => h.trySlot(fn),
  ensureCurrentVersion: (...a: unknown[]) => h.ensureCurrentVersion(...a),
}))

import { McpScopeError, McpAccessDenied, __resetRateLimiter } from '@/lib/mcpAuth'
import { compareScanVersions, listScanVersions } from './versionTools'
import type { McpContext } from './tools'

const ctx = (scopes: string[] = ['recon:read']): McpContext => ({
  token: {
    tokenId: 't1', userId: 'owner', tokenPrefix: 'rdmn_mcp_aaaaaaaa',
    name: 'agent', scopes: scopes as never,
  },
})

const idle = () => ({
  scans: [], agentSession: false, triageRun: false, activating: false, unknown: false,
})

/** A scan_versions row as the raw SQL returns it (snake_case, plus the size). */
const vrow = (over: Record<string, unknown> = {}) => ({
  id: 'v2', project_id: 'p1', seq: 2, label: 'Scan 2', is_current: false,
  pinned: false, node_count: 10, link_count: 5,
  created_at: new Date('2026-09-01T00:00:00Z'), snapshot_bytes: 4096,
  ...over,
})

/** A graph payload in the shape computeReconDelta consumes. */
const graph = (nodes: { type: string; name: string; props?: Record<string, unknown> }[]) => ({
  nodes: nodes.map((n, i) => ({
    id: `n${i}`, type: n.type, name: n.name, properties: n.props ?? { name: n.name },
  })),
  links: [],
})

beforeEach(() => {
  vi.clearAllMocks()
  __resetRateLimiter()
  h.findProject.mockResolvedValue({ id: 'p1', userId: 'owner' })
  h.countVersions.mockResolvedValue(1)
  h.activity.mockResolvedValue(idle())
  h.trySlot.mockImplementation(async (fn: () => Promise<unknown>) => ({
    acquired: true, value: await fn(),
  }))
})

describe('list_scan_versions', () => {
  test('needs recon:read and project ownership', async () => {
    await expect(listScanVersions(ctx([]), 'p1')).rejects.toBeInstanceOf(McpScopeError)
    h.findProject.mockResolvedValue({ id: 'p1', userId: 'someone-else' })
    await expect(listScanVersions(ctx(), 'p1')).rejects.toBeInstanceOf(McpAccessDenied)
  })

  test('REGRESSION: it never calls ensureCurrentVersion, which WRITES', async () => {
    // The browser route calls it, and it creates a backfill v1 row for a
    // pre-timeline project and promotes an orphan row to current.
    h.queryRaw.mockResolvedValue([vrow()])
    await listScanVersions(ctx(), 'p1')
    expect(h.ensureCurrentVersion).not.toHaveBeenCalled()
  })

  test('a project with no versions is an honest empty list', async () => {
    h.queryRaw.mockResolvedValue([])
    h.countVersions.mockResolvedValue(0)
    const r = await listScanVersions(ctx(), 'p1')
    expect(r.versions).toEqual([])
    expect(r.total).toBe(0)
  })

  test('it never selects the snapshot bytes, only their length', async () => {
    h.queryRaw.mockResolvedValue([vrow()])
    await listScanVersions(ctx(), 'p1')
    // The tagged template's literal strings are the first argument.
    const sql = (h.queryRaw.mock.calls[0][0] as unknown as string[]).join(' ')
    expect(sql).toContain('octet_length(snapshot)')
    expect(sql).not.toMatch(/SELECT[^;]*\bsnapshot\b\s*(,|FROM)/)
  })

  test('pinned and hasSnapshot are surfaced: they decide whether it survives', async () => {
    h.queryRaw.mockResolvedValue([
      vrow({ id: 'v2', pinned: true, snapshot_bytes: 4096 }),
      vrow({ id: 'v1', seq: 1, pinned: false, snapshot_bytes: null }),
    ])
    h.countVersions.mockResolvedValue(2)
    const r = await listScanVersions(ctx(), 'p1')
    expect(r.versions[0]).toMatchObject({ versionId: 'v2', pinned: true, hasSnapshot: true })
    expect(r.versions[1]).toMatchObject({ versionId: 'v1', pinned: false, hasSnapshot: false })
  })

  test('it says plainly that an unpinned version can vanish', async () => {
    h.queryRaw.mockResolvedValue([vrow()])
    const notes = (await listScanVersions(ctx(), 'p1')).notes.join(' ')
    expect(notes).toMatch(/UNPINNED/)
    expect(notes).toMatch(/Pinning is the only way to keep one/)
  })

  test('truncation is visible', async () => {
    h.queryRaw.mockResolvedValue([vrow()])
    h.countVersions.mockResolvedValue(40)
    const r = await listScanVersions(ctx(), 'p1')
    expect(r.truncated).toBe(true)
    expect(r.total).toBe(40)
  })
})

describe('compare_scan_versions defaults', () => {
  beforeEach(() => {
    // resolveSide's default `from` lookup, then assertVersionInProject's row read.
    h.queryRaw.mockResolvedValue([vrow()])
    h.loadSnapshot.mockResolvedValue(graph([{ type: 'Port', name: '443' }]))
    h.capture.mockResolvedValue(graph([
      { type: 'Port', name: '443' }, { type: 'Port', name: '8080' },
    ]))
  })

  test('a projectId-only call works, comparing the newest stored version to current', async () => {
    // Load-bearing beyond convenience: the generated API reference calls every
    // tool with only its schema-required arguments and asserts it reaches the
    // backend, so a tool that threw bad_args here would fail that test.
    const r = await compareScanVersions(ctx(), 'p1')
    expect(r.from.versionId).toBe('v2')
    expect(r.to.versionId).toBe('current')
    expect(r.lenses.newlyExposedPorts).toBe(1)
  })

  // REGRESSION: `from: "current"` is accepted by the schema and documented in
  // the tool description, and was then silently discarded: the guard fell
  // through to the default lookup and compared two STORED versions instead.
  // A caller asking "what would reverting to v2 cost me" got a comparison it
  // never requested, with no error.
  test('REGRESSION: from "current" captures the live graph, it is not substituted', async () => {
    const r = await compareScanVersions(ctx(), 'p1', { from: 'current', to: 'v2' })
    expect(r.from.versionId).toBe('current')
    expect(r.to.versionId).toBe('v2')
    expect(h.capture).toHaveBeenCalledOnce()
  })

  test('comparing the live graph with itself is refused, not captured twice', async () => {
    // Two captures of the same graph is a guaranteed no-op answer bought with
    // two snapshot slots the UI also needs.
    await expect(compareScanVersions(ctx(), 'p1', { from: 'current', to: 'current' }))
      .rejects.toThrow(/with itself/i)
    expect(h.capture).not.toHaveBeenCalled()
  })

  test('a project with no comparable version says so rather than failing obscurely', async () => {
    h.queryRaw.mockResolvedValue([])
    await expect(compareScanVersions(ctx(), 'p1')).rejects.toThrow(/no earlier saved version/i)
  })
})

describe('compare_scan_versions never returns the raw delta', () => {
  beforeEach(() => {
    h.queryRaw.mockResolvedValue([vrow()])
    // A Secret whose identity key embeds the value itself.
    h.loadSnapshot.mockResolvedValue(graph([]))
    h.capture.mockResolvedValue(graph([
      { type: 'Secret', name: 'aws-key', props: { value: 'AKIAIOSFODNN7EXAMPLE', file: 'app.js' } },
      { type: 'Port', name: '8080', props: { number: 8080, ip_address: '10.0.0.1' } },
    ]))
  })

  test('a secret VALUE never appears, not even inside an identity key', async () => {
    // `identityKey` builds a Secret's key from [value, file], so `key`,
    // `sourceKey` and `targetKey` literally embed secret material.
    const s = JSON.stringify(await compareScanVersions(ctx(), 'p1'))
    expect(s).not.toContain('AKIAIOSFODNN7EXAMPLE')
    expect(s).not.toContain('Secret::')
  })

  test('node property bags never appear', async () => {
    const s = JSON.stringify(await compareScanVersions(ctx(), 'p1'))
    expect(s).not.toContain('"properties"')
    expect(s).not.toContain('previousProperties')
    expect(s).not.toContain('ip_address')
  })

  test('the raw node arrays and the overlay never appear', async () => {
    // `overlay` re-serialises the union of both graphs; the lens arrays hold the
    // same object references as addedNodes, so they serialise twice.
    const r = await compareScanVersions(ctx(), 'p1') as Record<string, unknown>
    expect(r.addedNodes).toBeUndefined()
    expect(r.removedNodes).toBeUndefined()
    expect(r.changedNodes).toBeUndefined()
    expect(r.overlay).toBeUndefined()
  })

  test('what it DOES return is counts, scores and capped {type,name} samples', async () => {
    const r = await compareScanVersions(ctx(), 'p1')
    expect(r.totals.added).toBe(2)
    expect(r.lenses.newlyExposedPorts).toBe(1)
    expect(r.samples.newlyExposedPorts).toEqual([{ type: 'Port', name: '8080' }])
    expect(r.scorecard.some(s => s.type === 'Secret')).toBe(true)
  })
})

describe('compare_scan_versions refuses rather than lying about the live graph', () => {
  beforeEach(() => {
    h.queryRaw.mockResolvedValue([vrow()])
    h.loadSnapshot.mockResolvedValue(graph([{ type: 'Port', name: '443' }]))
    h.capture.mockResolvedValue(graph([]))
  })

  test('an activation in flight refuses', async () => {
    h.activity.mockResolvedValue({ ...idle(), activating: true })
    await expect(compareScanVersions(ctx(), 'p1')).rejects.toMatchObject({ code: 'busy' })
  })

  test('a running scan refuses', async () => {
    h.activity.mockResolvedValue({ ...idle(), scans: [{ kind: 'gvm' }] })
    await expect(compareScanVersions(ctx(), 'p1')).rejects.toMatchObject({ code: 'busy' })
  })

  test('an unknown activity state refuses, rather than assuming it is safe', async () => {
    h.activity.mockResolvedValue({ ...idle(), unknown: true })
    await expect(compareScanVersions(ctx(), 'p1')).rejects.toMatchObject({ code: 'busy' })
  })

  // REGRESSION (plan 14.1): the busy check is point-in-time and is NOT held
  // across the capture. Activation clears the graph and restores it as two
  // separate steps, so an activation starting one millisecond after the check
  // passes deletes the graph mid-stream. The result is not an error: it is a
  // SUCCESSFUL delta reporting every node in the project as removed, which an
  // agent acts on as "the attack surface was torn down".
  test('REGRESSION: a state change DURING the capture is refused, not reported', async () => {
    let checks = 0
    h.activity.mockImplementation(async () => {
      checks += 1
      return checks === 1 ? idle() : { ...idle(), activating: true }
    })
    await expect(compareScanVersions(ctx(), 'p1')).rejects.toMatchObject({ code: 'busy' })
    expect(checks).toBe(2)
  })

  test('the recheck happens AFTER the capture, not instead of it', async () => {
    const order: string[] = []
    h.activity.mockImplementation(async () => { order.push('check'); return idle() })
    h.capture.mockImplementation(async () => { order.push('capture'); return graph([]) })
    await compareScanVersions(ctx(), 'p1')
    expect(order).toEqual(['check', 'capture', 'check'])
  })

  test('a busy snapshot slot refuses instead of queueing behind it', async () => {
    // Queueing would leave an abandoned waiter that runs a full graph capture
    // nobody is awaiting, holding a slot the UI also needs.
    h.trySlot.mockResolvedValue({ acquired: false })
    await expect(compareScanVersions(ctx(), 'p1')).rejects.toMatchObject({ code: 'busy' })
    expect(h.capture).not.toHaveBeenCalled()
  })
})

describe('compare_scan_versions explains the two confusing failures', () => {
  test('passing the CURRENT version id says to use "current"', async () => {
    // Its snapshot is null by design, so "empty snapshot" would send the caller
    // hunting for a data problem that does not exist.
    h.queryRaw.mockResolvedValue([vrow({ id: 'v9', seq: 9, is_current: true, snapshot_bytes: null })])
    await expect(compareScanVersions(ctx(), 'p1', { from: 'v9' }))
      .rejects.toThrow(/Pass "current" for that side instead/)
  })

  test('a trimmed version names retention, not a bare not-found', async () => {
    h.queryRaw.mockResolvedValue([vrow({ id: 'v2' })])
    h.loadSnapshot.mockResolvedValue(null)
    await expect(compareScanVersions(ctx(), 'p1', { from: 'v2', to: 'current' }))
      .rejects.toThrow(/trimmed by retention/i)
  })

  test("another project's version id is refused, indistinguishably from a missing one",
    async () => {
      h.queryRaw.mockResolvedValue([vrow({ project_id: 'someone-elses' })])
      const foreign = await compareScanVersions(ctx(), 'p1', { from: 'vX' }).catch(e => e)
      h.queryRaw.mockResolvedValue([])
      const missing = await compareScanVersions(ctx(), 'p1', { from: 'vNope' }).catch(e => e)

      expect(foreign.code).toBe('not_found')
      expect(missing.message).toBe(foreign.message)
      expect(foreign.message).toMatch(/scan version/)
    })
})

describe('compare_scan_versions rate limiting', () => {
  // REGRESSION: same shape as queue_recon. The compare bucket is shared across
  // tokens for a given project, so consuming it before the ownership check let
  // a stranger exhaust a project's comparison budget.
  test('REGRESSION: a foreign project does not consume the per-project budget', async () => {
    h.queryRaw.mockResolvedValue([vrow()])
    h.loadSnapshot.mockResolvedValue(graph([]))
    h.capture.mockResolvedValue(graph([]))
    vi.stubEnv('MCP_RATE_COMPARE_PER_WINDOW', '1')

    h.findProject.mockResolvedValue({ id: 'p1', userId: 'someone-else' })
    await expect(compareScanVersions(ctx(), 'p1')).rejects.toBeInstanceOf(McpAccessDenied)

    h.findProject.mockResolvedValue({ id: 'p1', userId: 'owner' })
    await expect(compareScanVersions(ctx(), 'p1')).resolves.toBeTruthy()
    vi.unstubAllEnvs()
  })

  test('it uses its own per-project bucket, not the query one', async () => {
    h.queryRaw.mockResolvedValue([vrow()])
    h.loadSnapshot.mockResolvedValue(graph([]))
    h.capture.mockResolvedValue(graph([]))
    vi.stubEnv('MCP_RATE_COMPARE_PER_WINDOW', '1')

    await compareScanVersions(ctx(), 'p1')
    await expect(compareScanVersions(ctx(), 'p1')).rejects.toThrow(/rate limit/i)
    vi.unstubAllEnvs()
  })
})
