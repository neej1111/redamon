/**
 * Saved graph views: a query a human already wrote and vetted.
 *
 * Running one by name costs no LLM call, spends nothing from the per-token
 * daily budget, avoids the retry variance of the natural-language path, and is
 * deterministic. "Every night, run my exposed-admin-panels view" becomes one
 * call.
 *
 * `POST /api/graph-views/execute` is NOT reused, and the reason matters: it
 * takes RAW CYPHER and never reads `prisma.graphView` at all - "execute a saved
 * view" is a client-side convention. Reusing it would ship an arbitrary-Cypher
 * endpoint wearing a saved-view label, and it authenticates by cookie, injects
 * `project_id` without `user_id`, exempts more label patterns from scoping than
 * the agent path does, goes straight to the webapp's own Neo4j pool with no row
 * cap and no concurrency ceiling, and checks for writes with a keyword scan
 * that leaves string literals in. So: reuse the GUARD STACK, never the route.
 *
 * The stored query is unvalidated at rest - the creating route persists
 * `cypherQuery` with no write-keyword check, no length bound and no scoping
 * proof, because every guard lives on the reader. Routing through `execCypher`
 * is therefore not merely preferable, it is the only thing standing between a
 * stored string and Neo4j.
 */
import prisma from '@/lib/prisma'
import { assertMcpProjectAccess, requireScope } from '@/lib/mcpAuth'
import { McpToolError } from '@/lib/mcp/errors'
import { assertViewInProject } from '@/lib/mcp/childAccess'
import { execCypher } from '@/lib/mcp/graphClient'
import { enforceRate, guardGraphResult, type McpContext } from '@/lib/mcp/tools'

export const VIEWS_MAX = 100

/**
 * The saved views, by name.
 *
 * `cypherQuery` is NEVER returned. The browser route does return it, because it
 * has no `select` and a person editing a view needs to see it; handing it to an
 * external model instead leaks the graph schema and gives the caller an
 * injection carrier for free. Its whole value here is that the caller does not
 * have to know the query.
 */
export async function listGraphViews(ctx: McpContext, projectId: string) {
  requireScope(ctx.token, 'recon:read')
  enforceRate(ctx, 'read')
  await assertMcpProjectAccess(ctx.token.userId, projectId)

  const views = await prisma.graphView.findMany({
    where: { projectId },
    select: { id: true, name: true, description: true, createdAt: true },
    orderBy: { name: 'asc' },
    take: VIEWS_MAX,
  })

  return {
    projectId,
    views: views.map(v => ({
      viewId: v.id,
      name: v.name,
      description: v.description,
      createdAt: v.createdAt.toISOString(),
    })),
    returned: views.length,
    notes: [
      'The query text is deliberately not shown. Run one with run_graph_view.',
      'A view saved in the app can still be refused here: this surface proves a query is ' +
        'tenant-scoped and read-only by stricter rules than the app applies, so a view that ' +
        'works in the UI is not guaranteed to run over MCP.',
    ],
  }
}

/**
 * Run one saved view.
 *
 * `graph:cypher`, and that is not a judgement call. `recon:read` is the DEFAULT
 * scope on every minted token, so declaring this tool `recon:read` would hand
 * arbitrary stored-Cypher execution to the default credential - the exact
 * capability `graph:cypher` is sold to the operator as withholding. The caller
 * does not author the query, but it chooses which stored query runs, and that
 * is enough.
 */
export async function runGraphView(ctx: McpContext, projectId: string, viewId: string) {
  requireScope(ctx.token, 'recon:read')
  requireScope(ctx.token, 'graph:cypher')
  enforceRate(ctx, 'query')

  // Scoped by projectId in the lookup rather than by trusting `view.projectId`
  // afterwards, so a foreign id is the same flat answer as a missing one.
  const view = await assertViewInProject(ctx.token.userId, projectId, viewId)

  const cypher = (view.cypherQuery ?? '').trim()
  if (!cypher) {
    throw new McpToolError(
      `The saved view "${view.name}" has no query stored on it.`,
      'bad_args'
    )
  }

  let result
  try {
    result = await execCypher(ctx.token.userId, projectId, cypher)
  } catch (err) {
    // A refusal here is usually not a broken tool, and saying so is the
    // difference between the operator fixing the view and concluding MCP is
    // broken. The two paths apply different guards to the same stored string:
    // this one additionally refuses CALL outside the read-only schema
    // procedures, matches write words on raw text including inside string
    // literals, and rejects any query with no labelled node pattern or any
    // pattern it cannot prove scoped after injection.
    if (err instanceof McpToolError && err.code !== 'agent_unreachable') {
      throw new McpToolError(
        `The saved view "${view.name}" cannot be run over MCP: ${err.message} ` +
        `This surface proves a query is tenant-scoped and read-only by stricter rules than the ` +
        `app applies, so a view that works in the UI can still be refused here. The view itself ` +
        `is unchanged.`,
        'view_not_runnable'
      )
    }
    throw err
  }

  const guarded = guardGraphResult(result, ctx, projectId, 'run_graph_view')
  return {
    projectId,
    view: { viewId: view.id, name: view.name },
    records: guarded.records,
    ...(guarded.truncated ? { truncated: true } : {}),
  }
}
