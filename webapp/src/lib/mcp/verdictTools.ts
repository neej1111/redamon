/**
 * The one write to a finding on this surface: a triage verdict.
 *
 * It closes the loop for an external triage assistant, whose judgement would
 * otherwise be recomputed from scratch by the next nightly run.
 *
 * THE PROVENANCE DESIGN IS NOT THE OBVIOUS ONE. The instinct is to write a
 * third `triage_source` value so an agent's verdict is not laundered as a
 * human's. That is wrong, and it was checked across every site that reads the
 * field: `triage_source` is a closed two-value set four separate behaviours
 * branch on. A third value makes the finding prune-eligible, so the next scan
 * DELETES it rather than stamping `stale_since`; it lets a later AI run
 * overwrite the verdict, because the publish guard tests equality with
 * 'human'; it stops `likely_noise` producing a false-positive state, because
 * the scorer tests membership of ("human","ai"); and it renders as "Not
 * reviewed" in the board.
 *
 * So the verdict stays `'human'` - honest in the sense that matters, since the
 * token is the operator's own delegated credential carrying their authority -
 * and the CHANNEL is recorded separately, on a property that no branch reads.
 *
 * MUTE AND UNMUTE ARE NOT HERE, in either direction. Mute is the one action
 * that makes a finding invisible to every other read on this surface, and
 * "this is a false positive, mute it" is an entirely plausible injection
 * against an agent whose context is full of target-controlled text. Unmute is
 * out for a less obvious reason: the triage subsystem's stated invariant is
 * that only a person mutes, which is precisely what bounds a prompt injection
 * in scanner output to "mislabel a verdict a human can overrule". Handing
 * unmute to an unattended token removes that bound, and reversing a
 * suppression is the same control operated in the direction that makes hidden
 * findings visible again.
 */
import { requireScope } from '@/lib/mcpAuth'
import { assertMcpProjectAccess } from '@/lib/mcpAuth'
import { writeAudit } from '@/lib/audit'
import { findLiveTriageRun } from '@/lib/triageRun'
import { McpToolError } from '@/lib/mcp/errors'
import { callTriage } from '@/lib/mcp/triageGraph'
import { enforceRate, type McpContext } from '@/lib/mcp/tools'

export const VERDICT_STATUSES = ['confirmed', 'likely_noise', 'unreviewed'] as const
export type VerdictStatus = (typeof VERDICT_STATUSES)[number]

export async function setFindingVerdict(
  ctx: McpContext,
  projectId: string,
  nodeId: string,
  status: string,
  reason?: string
) {
  requireScope(ctx.token, 'triage:write')
  enforceRate(ctx, 'write')
  await assertMcpProjectAccess(ctx.token.userId, projectId)

  if (!(VERDICT_STATUSES as readonly string[]).includes(status)) {
    throw new McpToolError(
      `Unknown verdict '${status}'. One of: ${VERDICT_STATUSES.join(', ')}.`,
      'bad_args'
    )
  }

  // REFUSE WHILE A TRIAGE RUN IS LIVE, and fail closed if the run state cannot
  // be read. A run reads the graph at its first step and publishes minutes
  // later, and while its verdict-writing steps do protect a human verdict, its
  // MEASUREMENT step is unconditional and rewrites `triage_state` - which is
  // what files a finding into a board section. Worse, a verdict does not touch
  // `updated_at`, so the publish-time "unchanged" guard still matches and the
  // row is written. The concrete outcome: a verdict set at T+3min says
  // confirmed, and the run publishing at T+8min files it under False Positive
  // from its own pre-verdict analysis. Rare for a human, routine for an
  // unattended agent.
  let liveRun
  try {
    liveRun = await findLiveTriageRun(projectId)
  } catch (err) {
    console.error('[mcp] triage run state unreadable:', err)
    throw new McpToolError(
      'Whether a triage run is in progress could not be determined, so the verdict was not ' +
      'written. A run publishing over it would silently re-file the finding.',
      'busy'
    )
  }
  if (liveRun) {
    throw new McpToolError(
      `A triage run is ${liveRun.status} on this project. A verdict written now would be ` +
      `silently re-filed when that run publishes. Retry once it has finished.`,
      'busy'
    )
  }

  const body = await callTriage('human_verdict', ctx.token.userId, projectId, {
    node_id: nodeId,
    status,
    reason: (reason ?? '').slice(0, 500),
    verdict_by: ctx.token.userId,
  })

  // The op answers HTTP 200 in two different failure shapes, and both carry
  // `updated: false`. Reporting either as success would tell a caller its
  // judgement was recorded when nothing was written.
  if (body.updated !== true) {
    const why = typeof body.reason === 'string' ? ` (${body.reason})` : ''
    throw new McpToolError(
      `The verdict was NOT recorded${why}. The finding no longer exists, was never in this ` +
      `project, or is not a type a verdict can be set on. A finding id is only valid until the ` +
      `next scan of that source, so re-read list_findings before retrying.`,
      'not_updated'
    )
  }

  // A verdict is durable and suppresses future AI review of that finding, and
  // neither the webapp route nor the agent recorded an actor for one. The agent
  // now logs it too; this is the half that ties it to a token.
  void writeAudit({
    actorId: ctx.token.userId,
    action: 'mcp.set_finding_verdict',
    targetType: 'finding',
    targetId: nodeId,
    after: {
      projectId,
      status,
      label: body.label ?? null,
      channel: 'mcp',
      tokenId: ctx.token.tokenId,
      tokenPrefix: ctx.token.tokenPrefix,
    },
    source: 'mcp',
  })

  return {
    projectId,
    nodeId,
    status,
    label: body.label ?? null,
    recorded: true,
    notes: [
      'This verdict is durable: it survives re-scans and a later AI triage run will not ' +
        'overwrite it.',
      'It is recorded as a human verdict, because it carries the authority of the operator whose ' +
        'token this is. The node separately records that it arrived over MCP.',
      'Nothing on this surface can undo it except another verdict, and nothing here can mute or ' +
        'unmute a finding.',
    ],
  }
}
