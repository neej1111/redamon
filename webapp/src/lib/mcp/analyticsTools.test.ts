/**
 * The three precomputed graph views.
 *
 * These are hand-written Cypher on a surface whose justification is that it
 * does not lie, and they project SCALARS - which the outbound tenant
 * post-validation explicitly cannot check. So `scope_query` on the agent side
 * is their sole isolation boundary, and the things that can go wrong are
 * properties of the query TEXT rather than of the code around it:
 *
 *  - an inline tenant property or a `$pid`, neither of which the exec endpoint
 *    can bind, and which injection turns into a duplicated map key;
 *  - a bare re-reference to a global node, which loses its exemption, gets
 *    tenant props injected, and then matches NOTHING - silently emptying the
 *    KEV signal that two of these views sort by;
 *  - a missing `stale_since` filter, which `scope_query` never adds, so counts
 *    would include findings a later scan stopped reporting and disagree with
 *    graph_summary;
 *  - naming the `Muted` label, which `scope_query` refuses outright.
 *
 * None of those produce an error at runtime. The first is a generic failure,
 * and the rest return HTTP 200 with a quietly wrong answer, which is why they
 * are asserted here against the query text itself.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  findProject: vi.fn(),
  execCypher: vi.fn(),
}))

vi.mock('@/lib/prisma', () => ({
  default: { project: { findUnique: (...a: unknown[]) => h.findProject(...a) } },
}))
vi.mock('@/lib/mcp/graphClient', () => ({
  execCypher: (...a: unknown[]) => h.execCypher(...a),
}))

import { McpScopeError, McpAccessDenied, __resetRateLimiter } from '@/lib/mcpAuth'
import { McpToolError } from './errors'
import {
  BLAST_RADIUS_CYPHER,
  EXPLOIT_PATHS_CYPHER,
  attackSurfaceCypher,
  getAttackSurfaceOverview,
  getBlastRadius,
  listExploitPaths,
} from './analyticsTools'
import type { McpContext } from './tools'

const ctx = (scopes: string[] = ['recon:read']): McpContext => ({
  token: {
    tokenId: 't1', userId: 'owner', tokenPrefix: 'rdmn_mcp_aaaaaaaa',
    name: 'agent', scopes: scopes as never,
  },
})

const ALL_QUERIES = () => ({
  attack_surface: attackSurfaceCypher(),
  exploit_paths: EXPLOIT_PATHS_CYPHER,
  blast_radius: BLAST_RADIUS_CYPHER,
})

beforeEach(() => {
  vi.clearAllMocks()
  __resetRateLimiter()
  h.findProject.mockResolvedValue({ id: 'p1', userId: 'owner' })
  h.execCypher.mockResolvedValue({ records: [{ subdomains: 3 }] })
})

describe('the Cypher is compatible with the endpoint that runs it', () => {
  test('no query binds a parameter, because the exec endpoint binds only the tenant', () => {
    // GraphExecRequest has no params field at all: the cypher branch binds
    // exactly tenant_user_id and tenant_project_id. A carried-over `$pid` dies
    // on ParameterMissing and surfaces as a generic "graph query failed".
    for (const [name, q] of Object.entries(ALL_QUERIES())) {
      const params = q.match(/\$[A-Za-z_][A-Za-z0-9_]*/g) ?? []
      expect(params, `${name} binds a parameter`).toEqual([])
    }
  })

  test('no query carries an inline tenant property', () => {
    // Injection would turn `{project_id: $pid}` into a DUPLICATED key in one
    // map literal. Scoping is the injector's job, not the query's.
    for (const [name, q] of Object.entries(ALL_QUERIES())) {
      expect(q, `${name}`).not.toMatch(/project_id\s*:/)
      expect(q, `${name}`).not.toMatch(/user_id\s*:/)
    }
  })

  test('no query names the Muted label, which scope_query refuses outright', () => {
    // This is also why notMuted() from @/lib/graphMute cannot be used here: its
    // text contains 'Muted', so it would turn every one of these into a hard
    // refusal. The exclusion still happens, server-side, after this text.
    for (const [name, q] of Object.entries(ALL_QUERIES())) {
      expect(q, `${name}`).not.toMatch(/Muted/)
    }
  })

  test('every query has at least one labelled node pattern', () => {
    // A query with none is hard-rejected: it cannot be proven scoped.
    for (const [name, q] of Object.entries(ALL_QUERIES())) {
      expect(q, `${name}`).toMatch(/\([a-z0-9]+:[A-Z]/)
    }
  })

  test('no query returns a whole node or a property bag', () => {
    // The graph stores raw secrets: Secret.matched_text is the full match, and
    // redaction happens in React at render time, not in the store.
    for (const [name, q] of Object.entries(ALL_QUERIES())) {
      expect(q, `${name}`).not.toMatch(/properties\s*\(/)
      expect(q, `${name}`).not.toMatch(/matched_text/)
      // No node VARIABLE is returned, only aliased scalars. Returning `c` or
      // `t` would ship the node's whole property bag.
      const returned = (q.match(/^RETURN ([\s\S]*?)(?:\nORDER BY|\nLIMIT|$)/m) ?? [])[1] ?? ''
      for (const v of ['t', 'c', 'm', 'cap', 'ex', 'bu', 'svc', 'p']) {
        expect(returned, `${name} returns the node ${v}`).not.toMatch(new RegExp(`(^|[\\s,])${v}([\\s,]|$)`))
      }
    }
  })

  test('every query is bounded', () => {
    // The exec path caps at 1000 rows against the UI routes' 200,000, so a
    // group-by with no LIMIT truncates or 413s on a large project.
    expect(EXPLOIT_PATHS_CYPHER).toMatch(/LIMIT \d+/)
    expect(BLAST_RADIUS_CYPHER).toMatch(/LIMIT \d+/)
    // The overview is a chained aggregation: it yields exactly one row by
    // construction, so a LIMIT would be noise.
    expect(attackSurfaceCypher()).toMatch(/^RETURN /m)
  })
})

// REGRESSION (plan A.9, measured against the live views): a bare re-reference
// to a CVE or MitreData node loses its global-reference exemption, gets tenant
// props injected, and matches nothing - because those nodes carry no tenant
// props by design. The UI's kill-chain view reports cisaKev false for every row
// and the blast-radius view sorts by a kevCount that is permanently 0. HTTP
// 200, no error, view renders, ranking silently gone.
describe('REGRESSION: global-reference labels are spelled out on every re-reference', () => {
  test('no GLOBAL-reference node is ever re-referenced bare', () => {
    // Only the global labels matter here. A bare `(t)` is fine and in fact
    // correct: Technology IS tenant-scoped, so injection adding tenant props to
    // it is the intended behaviour. CVE, MitreData and Capec carry no tenant
    // props at all, so the same injection empties the match.
    for (const [name, q] of Object.entries(ALL_QUERIES())) {
      const bare = q.match(/\((c|m|cap)\)/g) ?? []
      expect(bare, `${name} re-references a global node without its label`).toEqual([])
    }
  })

  test('the KEV join names CVE on BOTH sides', () => {
    // This exact pattern is the one that empties the KEV signal.
    expect(EXPLOIT_PATHS_CYPHER).toContain('(ex:ExploitGvm)-[:EXPLOITED_CVE]->(c:CVE)')
    expect(BLAST_RADIUS_CYPHER).toContain('(ex:ExploitGvm)-[:EXPLOITED_CVE]->(c:CVE)')
  })

  test('the CWE join names both global labels', () => {
    expect(EXPLOIT_PATHS_CYPHER).toContain('(c:CVE)-[:HAS_CWE]->(m:MitreData)')
  })
})

describe('the stale half is written by hand', () => {
  test('every muteable label in these queries carries a stale_since filter', () => {
    // scope_query injects `!Muted` but NEVER `stale_since IS NULL`, so without
    // this these tools would count findings a later scan stopped reporting and
    // disagree with graph_summary.
    expect(EXPLOIT_PATHS_CYPHER).toMatch(/ex\.stale_since IS NULL/)
    expect(BLAST_RADIUS_CYPHER).toMatch(/ex\.stale_since IS NULL/)
    const overview = attackSurfaceCypher()
    for (const v of ['b0', 'b1', 'b2', 'b3', 'b4', 'b5', 'b6', 'b7']) {
      expect(overview, `${v} has no stale filter`).toMatch(new RegExp(`${v}\\.stale_since IS NULL`))
    }
  })

  // REGRESSION: PLACEMENT, not presence. `WITH ... WHERE ex.stale_since IS NULL`
  // DROPS the row, and the row carries the CVE - so a CVE whose only exploit
  // record is stale disappears from the ranking, taking its CVSS out of
  // maxCvss and its technology possibly out of the result entirely. Attached to
  // the OPTIONAL MATCH instead, a stale exploit simply does not match, `ex` is
  // null, and the CVE is still counted with knownExploitCount 0.
  //
  // The original test asserted the predicate was PRESENT, which it was, and
  // passed while the query was wrong.
  test('REGRESSION: every stale filter sits on its OPTIONAL MATCH, not on a WITH', () => {
    for (const [name, q] of Object.entries(ALL_QUERIES())) {
      for (const line of q.split('\n')) {
        if (!/stale_since/.test(line)) continue
        expect(line.trimStart(), `${name}: "${line.trim()}" filters rows instead of the match`)
          .toMatch(/^OPTIONAL MATCH /)
      }
    }
  })

  test('REGRESSION: no query drops rows on a null-or-fresh test', () => {
    // The specific shape of the bug, pinned so it cannot come back in another
    // form: `ex IS NULL OR ex.stale_since IS NULL` is only ever needed when the
    // filter has been moved off the match it belongs to.
    for (const [name, q] of Object.entries(ALL_QUERIES())) {
      expect(q, `${name}`).not.toMatch(/IS NULL OR \w+\.stale_since IS NULL/)
    }
  })

  test('asset labels are NOT stale-filtered, because assets are not findings', () => {
    const overview = attackSurfaceCypher()
    expect(overview).toMatch(/OPTIONAL MATCH \(a0:Subdomain\)\nWITH/)
  })
})

describe('the overview census', () => {
  test('it uses OPTIONAL MATCH, so one empty label does not empty the answer', () => {
    // A plain MATCH that finds nothing yields zero rows, which takes the whole
    // chained aggregation to zero rows: a project whose first label happens to
    // be empty would get no answer at all.
    const overview = attackSurfaceCypher()
    expect(overview).not.toMatch(/^MATCH /m)
    expect((overview.match(/OPTIONAL MATCH/g) ?? []).length).toBeGreaterThan(15)
  })

  test('it separates findings by severity, which is what makes it actionable', () => {
    const q = attackSurfaceCypher()
    for (const k of ['criticalVulnerabilities', 'highVulnerabilities', 'mediumVulnerabilities']) {
      expect(q).toContain(k)
    }
  })

  test('it returns the single aggregated row', async () => {
    h.execCypher.mockResolvedValue({ records: [{ subdomains: 12, criticalVulnerabilities: 2 }] })
    const r = await getAttackSurfaceOverview(ctx(), 'p1')
    expect(r.surface).toMatchObject({ subdomains: 12, criticalVulnerabilities: 2 })
  })

  test('no row at all is an error, not an empty surface', async () => {
    // The chained aggregation always produces exactly one row, including on an
    // empty project. None means the query did not run as written.
    h.execCypher.mockResolvedValue({ records: [] })
    await expect(getAttackSurfaceOverview(ctx(), 'p1')).rejects.toBeInstanceOf(McpToolError)
  })
})

describe('scope, ownership and dependency failures', () => {
  const calls: [string, (c: McpContext) => Promise<unknown>][] = [
    ['get_attack_surface_overview', c => getAttackSurfaceOverview(c, 'p1')],
    ['list_exploit_paths', c => listExploitPaths(c, 'p1')],
    ['get_blast_radius', c => getBlastRadius(c, 'p1')],
  ]

  test.each(calls)('%s needs recon:read', async (_n, call) => {
    await expect(call(ctx([]))).rejects.toBeInstanceOf(McpScopeError)
  })

  test.each(calls)('%s checks ownership before the graph', async (_n, call) => {
    h.findProject.mockResolvedValue({ id: 'p1', userId: 'someone-else' })
    await expect(call(ctx())).rejects.toBeInstanceOf(McpAccessDenied)
    expect(h.execCypher).not.toHaveBeenCalled()
  })

  test.each(calls)('%s reports a graph failure, never an empty answer', async (_n, call) => {
    h.execCypher.mockRejectedValue(new McpToolError('The graph service is unavailable.', 'agent_unreachable'))
    await expect(call(ctx())).rejects.toBeInstanceOf(McpToolError)
  })

  test.each(calls)('%s sends the resolved identity, never one from arguments', async (_n, call) => {
    await call(ctx())
    expect(h.execCypher).toHaveBeenCalledWith('owner', 'p1', expect.any(String))
  })
})

describe('the list views report their cap', () => {
  test('a full page is marked truncated', async () => {
    h.execCypher.mockResolvedValue({ records: Array.from({ length: 50 }, () => ({ cve: 'CVE-1' })) })
    const r = await listExploitPaths(ctx(), 'p1')
    expect(r.truncated).toBe(true)
    expect(r.limit).toBe(50)
  })

  test('a short page is not', async () => {
    h.execCypher.mockResolvedValue({ records: [{ cve: 'CVE-1' }] })
    expect((await getBlastRadius(ctx(), 'p1')).truncated).toBeUndefined()
  })

  test('the description of cisaKev does not overclaim', async () => {
    h.execCypher.mockResolvedValue({ records: [] })
    const notes = (await listExploitPaths(ctx(), 'p1')).notes.join(' ')
    expect(notes).toMatch(/not\s+that the CVE is on a public exploited list/)
  })
})

// REGRESSION (e2e finding: an empty ranking read as "nothing is exploitable").
// Both views start from (:Technology)-[:HAS_KNOWN_CVE]->(:CVE), so a project
// whose CVE lookup never ran answers zero rows however much it holds. Observed
// live on a project with 19 technologies and 215 vulnerabilities: both tools
// returned `returned: 0` and not one of their notes said why.
describe('an empty analytics answer explains itself', () => {
  test('list_exploit_paths says an empty result is not "nothing exploitable"', async () => {
    h.execCypher.mockResolvedValue({ records: [] })
    const r = await listExploitPaths(ctx(), 'p1')
    expect(r.returned).toBe(0)
    expect(r.notes.join(' ')).toMatch(/not the same as "nothing is exploitable"/)
    expect(r.notes.join(' ')).toMatch(/cveLookupEnabled/)
  })

  test('get_blast_radius says the same', async () => {
    h.execCypher.mockResolvedValue({ records: [] })
    const r = await getBlastRadius(ctx(), 'p1')
    expect(r.returned).toBe(0)
    expect(r.notes.join(' ')).toMatch(/not the same as "nothing is exploitable"/)
  })

  test('a populated answer does NOT carry the explanation', async () => {
    // It is an explanation of emptiness; on a real ranking it is noise.
    h.execCypher.mockResolvedValue({
      records: [{ technology: 'nginx', cveCount: 3, maxCvss: 9.8 }],
    })
    const r = await getBlastRadius(ctx(), 'p1')
    expect(r.notes.join(' ')).not.toMatch(/not the same as/)
  })
})
