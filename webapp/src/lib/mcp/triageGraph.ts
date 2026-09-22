/**
 * The MCP server's triage calls into the agent.
 *
 * Deliberately NOT `callGraphTriage` from `@/lib/triageClient`: that returns a
 * `NextResponse` rather than data, so every caller would re-parse an HTTP
 * envelope it never wanted, and it inherits `agentFetch`'s 30s default instead
 * of setting its own bound. Same shape as `graphClient.ts` instead: a direct
 * fetch with the internal key, an explicit timeout, and either parsed data or
 * an `McpToolError`.
 *
 * Every call sets `source: 'mcp'`. That is not decoration: it is what opts the
 * request into the agent's MCP concurrency ceiling. Without it these tools run
 * unthrottled against the same Neo4j the operator's own Priority Board reads
 * through this very endpoint.
 */
import { agentBaseUrl } from '@/lib/agentFetch'
import { internalKeyHeaders } from '@/lib/agentAuth'
import { McpToolError } from '@/lib/mcp/errors'

/** Generous enough for an untriaged project's full table, bounded all the same. */
const TRIAGE_TIMEOUT_MS = 60_000

export type McpTriageOp = 'list_findings' | 'list_muted' | 'human_verdict'

export interface TriageFinding {
  id: string
  label: string
  name: string
  severity: string
  source: string
  [key: string]: unknown
}

export interface TriageFindingsResult {
  findings: TriageFinding[]
  total?: number
}

/**
 * One `/graph/triage` op, as data.
 *
 * The tenant is the RESOLVED identity, never anything from the caller's
 * arguments: the mixin scopes `node_id` by it, so a guessed id from another
 * project matches nothing rather than acting on it.
 */
export async function callTriage(
  op: McpTriageOp,
  userId: string,
  projectId: string,
  extra: Record<string, unknown> = {}
): Promise<Record<string, unknown>> {
  let resp: Response
  try {
    resp = await fetch(`${agentBaseUrl()}/graph/triage`, {
      method: 'POST',
      headers: internalKeyHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({
        op,
        user_id: userId,
        project_id: projectId,
        source: 'mcp',
        ...extra,
      }),
      signal: AbortSignal.timeout(TRIAGE_TIMEOUT_MS),
    })
  } catch (err) {
    console.error(`[mcp] triage ${op} transport error:`, err)
    // NEVER an empty findings list. "The scan found nothing" and "the findings
    // service could not be reached" must not look the same to an agent writing
    // a security report.
    throw new McpToolError('The findings service is unavailable.', 'agent_unreachable')
  }
  if (!resp.ok) {
    console.error(`[mcp] triage ${op} failed (${resp.status})`)
    throw new McpToolError('The findings could not be read.', 'agent_failed')
  }
  const body = (await resp.json().catch(() => null)) as Record<string, unknown> | null
  if (!body || typeof body !== 'object') {
    throw new McpToolError('The findings could not be read.', 'agent_failed')
  }
  warnIfAgentIsOlder(body)
  return body
}

/** Once per process: a hundred identical lines would bury the one that matters. */
let staleAgentWarned = false

/**
 * Say so when the agent on the other end predates this code.
 *
 * The agent's Python is baked into its own image; a deploy that rebuilds only
 * the webapp leaves an older one running. Pydantic ignores unknown fields, so
 * that agent accepts `source`, `limit` and `verdict_by`, silently discards all
 * three, and answers 200. The MCP concurrency ceiling then does not apply to
 * these calls, and every verdict is recorded with no channel and no actor -
 * with nothing anywhere to indicate it.
 */
function warnIfAgentIsOlder(body: Record<string, unknown>): void {
  if (body.mcp_gated === true || staleAgentWarned) return
  staleAgentWarned = true
  console.error(
    '[mcp] the agent did not acknowledge the MCP triage gate. It predates this webapp build, ' +
    'so findings calls are NOT taking the graph concurrency ceiling and verdicts are being ' +
    'written without a channel or an actor. Rebuild the agent image: ' +
    '`docker compose build agent && docker compose up -d agent`.'
  )
}

/** Test seam: the warning is once-per-process by design. */
export function __resetAgentVersionWarning(): void {
  staleAgentWarned = false
}

/** `list_findings`, with the row cap pushed down to the agent. */
export async function listTriageFindings(
  userId: string,
  projectId: string,
  limit: number
): Promise<TriageFindingsResult> {
  const body = await callTriage('list_findings', userId, projectId, { limit })
  const findings = Array.isArray(body.findings) ? (body.findings as TriageFinding[]) : null
  if (!findings) throw new McpToolError('The findings could not be read.', 'agent_failed')
  return {
    findings,
    total: typeof body.total === 'number' ? body.total : undefined,
  }
}

/**
 * `list_muted`. Note the asymmetry with the above: this op returns NO `total`,
 * so a count is `findings.length`. The mixin applies no limit unless one is
 * asked for, so the cap has to travel WITH the request - capping only the rows
 * this side returns still pulls the whole suppressed set across the wire.
 */
export async function listMutedFindings(
  userId: string,
  projectId: string,
  limit: number
): Promise<TriageFinding[]> {
  const body = await callTriage('list_muted', userId, projectId, { limit })
  const findings = Array.isArray(body.findings) ? (body.findings as TriageFinding[]) : null
  if (!findings) throw new McpToolError('The muted findings could not be read.', 'agent_failed')
  return findings
}
