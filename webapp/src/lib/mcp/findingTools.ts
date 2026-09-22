/**
 * What the scans actually found.
 *
 * The single biggest gap in the shipped surface. The only route to a finding
 * was `query_graph`, which forces an external agent to already know that "a
 * finding" means one of eight unrelated labels, and then to invent its own
 * ranking. The product computes a ranking and the surface threw it away.
 *
 * Two things here are not obvious and are both load-bearing:
 *
 *  - a project that has never been triaged has NO ranking, and that is the
 *    common case. Saying "ranked by priority" over a list of nulls would make a
 *    caller either trust an order that carries no signal or read unscored as
 *    unimportant, so `triageState` says which of the two worlds it is in.
 *  - muted findings are excluded here, from `graph_summary`, and from Cypher
 *    (the tenant filter refuses any query naming the label). So "zero findings"
 *    can mean "a human suppressed thirty criticals", which is why
 *    `list_muted_findings` exists at all.
 */
import prisma from '@/lib/prisma'
import { requireScope } from '@/lib/mcpAuth'
import { assertMcpProjectAccess } from '@/lib/mcpAuth'
import { McpToolError } from '@/lib/mcp/errors'
import { listMutedFindings, listTriageFindings, type TriageFinding } from '@/lib/mcp/triageGraph'
import { enforceRate, type McpContext } from '@/lib/mcp/tools'

export const FINDINGS_DEFAULT_LIMIT = 25
export const FINDINGS_MAX_LIMIT = 100

/** The agent-side mixin's own ceiling; asking past it buys nothing. */
const TRIAGE_FETCH_CEILING = 2000

/**
 * How many individual muted rows this tool will RETURN. Past this it reports
 * the cap rather than growing the payload.
 */
export const MUTED_MAX_ROWS = 200

/**
 * The cap that travels WITH the request.
 *
 * `MUTED_MAX_ROWS` bounds what this tool returns; it does nothing about what
 * crosses the wire. Without this the agent serialised, and the webapp parsed
 * and grouped, every suppressed finding in the project on every call - the
 * unbounded-dependency cost this surface refuses everywhere else.
 */
const MUTED_FETCH_CEILING = 2000

/**
 * The fields a finding is projected down to.
 *
 * The mixin returns 32. `triage_proof`, `triage_factors` and
 * `triage_ai_corrections` are raw JSON blobs sized for a UI, not for a model's
 * context, and `triage_ai_quote` is literally quoted target output - it is
 * behind an explicit argument and never travels without the untrusted-data
 * note. No property outside this list reaches a caller, which is also what
 * keeps `Secret.matched_text` and its kind off this surface by construction.
 */
const FINDING_FIELDS = [
  'id', 'label', 'name', 'severity', 'source', 'location', 'host', 'section',
  'triage_state', 'triage_status', 'triage_priority_score', 'triage_tier',
  'triage_ai_verdict', 'triage_group_key', 'triage_run_id', 'triaged_at',
] as const

const SECTION_NAMES: Record<number, string> = {
  0: 'ranked',
  1: 'not_triaged',
  2: 'likely_false_positive',
  3: 'resolved',
}

export const FINDING_SECTIONS = Object.values(SECTION_NAMES)

function projectFinding(raw: TriageFinding, includeQuote: boolean): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const key of FINDING_FIELDS) {
    if (raw[key] !== undefined && raw[key] !== null && raw[key] !== '') out[key] = raw[key]
  }
  const section = typeof raw.section === 'number' ? raw.section : null
  if (section !== null) out.sectionName = SECTION_NAMES[section] ?? 'unknown'
  if (includeQuote && raw.triage_ai_quote) out.triage_ai_quote = raw.triage_ai_quote
  return out
}

export type TriageState = 'never_run' | 'partial' | 'current'

/**
 * Which of the three triage worlds this project is in.
 *
 * Read from the `TriageRun` table rather than inferred from the returned page:
 * a page is at most 100 rows out of potentially thousands, so "every row I can
 * see carries a run id" is not evidence about the project. A database failure
 * degrades to `never_run`, which is the conservative direction - it claims less
 * ranking than there may be, rather than more.
 */
async function resolveTriageState(projectId: string): Promise<TriageState> {
  try {
    const runs = await prisma.triageRun.findMany({
      where: { projectId },
      select: { status: true, finishedAt: true },
      orderBy: { startedAt: 'desc' },
      take: 5,
    })
    if (runs.length === 0) return 'never_run'
    if (runs.some(r => r.status === 'completed')) return 'current'
    return 'partial'
  } catch (err) {
    console.error('[mcp] triage run state unreadable:', err)
    return 'never_run'
  }
}

const TRIAGE_STATE_NOTE: Record<TriageState, string> = {
  never_run: 'No triage run has ever completed on this project, so NOTHING here is ranked: ' +
    'triage_priority_score is absent on every finding and the order is scanner severity alone. ' +
    'Do not read an unscored finding as an unimportant one.',
  partial: 'A triage run exists but none has completed, so the ranking is partial: some findings ' +
    'carry a priority score and others have never been scored. Order is severity where a score ' +
    'is absent.',
  current: 'A triage run has completed, so findings are ordered by the computed priority score ' +
    'first and scanner severity second.',
}

export interface ListFindingsArgs {
  limit?: number
  offset?: number
  severity?: string
  section?: string
  includeQuotes?: boolean
}

function clampLimit(raw: number | undefined): number {
  if (typeof raw !== 'number' || !Number.isFinite(raw)) return FINDINGS_DEFAULT_LIMIT
  return Math.max(1, Math.min(Math.trunc(raw), FINDINGS_MAX_LIMIT))
}

export async function listFindings(
  ctx: McpContext,
  projectId: string,
  args: ListFindingsArgs = {}
) {
  requireScope(ctx.token, 'recon:read')
  enforceRate(ctx, 'read')
  await assertMcpProjectAccess(ctx.token.userId, projectId)

  const limit = clampLimit(args.limit)
  const offset = Math.max(0, Math.trunc(args.offset ?? 0))
  // Paging stops at the window, and says so. Slicing past it returned an empty
  // page while still reporting `truncated`, so an agent walking a large project
  // got empty answers and a "there is more" flag, forever.
  if (offset >= TRIAGE_FETCH_CEILING) {
    throw new McpToolError(
      `This tool can page through the first ${TRIAGE_FETCH_CEILING} findings, and offset ` +
      `${offset} is past that. Narrow with severity or section rather than paging further.`,
      'bad_args'
    )
  }
  const section = args.section?.trim().toLowerCase()
  if (section && !FINDING_SECTIONS.includes(section)) {
    throw new McpToolError(
      `Unknown section '${args.section}'. One of: ${FINDING_SECTIONS.join(', ')}.`,
      'bad_args'
    )
  }
  const severity = args.severity?.trim().toLowerCase()

  // `/graph/triage` has no offset, so the page is sliced here. The cap sent to
  // the agent covers the window the caller asked for, which keeps the internal
  // transfer bounded for the common offset-0 call instead of shipping the
  // mixin's full 2000 every time. A filter widens the window, because filtering
  // happens on this side.
  const filtering = Boolean(section || severity)
  const want = filtering ? TRIAGE_FETCH_CEILING : Math.min(offset + limit, TRIAGE_FETCH_CEILING)

  const [{ findings: raw, total }, triageState] = await Promise.all([
    listTriageFindings(ctx.token.userId, projectId, want),
    resolveTriageState(projectId),
  ])

  let rows = raw
  if (severity) rows = rows.filter(f => String(f.severity ?? '').toLowerCase() === severity)
  if (section) {
    rows = rows.filter(f => SECTION_NAMES[Number(f.section)] === section)
  }

  const matched = filtering ? rows.length : (total ?? rows.length)
  const page = rows.slice(offset, offset + limit)

  // A filter is applied HERE, over a window the agent caps. When that window
  // came back full there may be further matches beyond it, so the filtered
  // count is a floor rather than a total and must not be reported as one: a
  // caller told "4 critical findings" when there are forty has been given the
  // false negative this whole surface exists to prevent.
  //
  // The same applies when the agent returns no `total` at all. It always does
  // today, so that is drift - and a drifted answer must degrade to "at least
  // this many" rather than to the WINDOW SIZE, which would report 25 findings
  // for a project with six thousand.
  const partialTotal =
    (filtering && raw.length >= TRIAGE_FETCH_CEILING) || total === undefined

  return {
    projectId,
    triageState,
    triageStateNote: TRIAGE_STATE_NOTE[triageState],
    findings: page.map(f => projectFinding(f, args.includeQuotes === true)),
    returned: page.length,
    offset,
    // From the UNCAPPED count when unfiltered, so a page can never pass for the
    // whole set. With a filter it is the number that matched in the window.
    total: matched,
    ...(partialTotal
      ? {
          totalIsPartial: true,
          scannedWindow: TRIAGE_FETCH_CEILING,
          totalNote:
            `This project has more than ${TRIAGE_FETCH_CEILING} findings and the filter was ` +
            `applied to the highest-ranked ${TRIAGE_FETCH_CEILING}. "total" is therefore AT ` +
            `LEAST this many, not exactly this many. Do not report it as a complete count.`,
        }
      : {}),
    ...(offset + page.length < matched || partialTotal ? { truncated: true } : {}),
  }
}

// --- the suppressed half --------------------------------------------------------

interface MutedGroup {
  label: string
  severity: string
  count: number
  /** Distinct human reasons, capped: the point is why, not who said it how often. */
  reasons: string[]
}

/**
 * The findings a human decided to suppress.
 *
 * This is the one data class no token could reach by ANY route before: muted
 * findings are excluded from the census, excluded from `list_findings`, and
 * unreachable by Cypher because the tenant filter refuses any query that so
 * much as names the label. That is why it sits behind its own permission
 * rather than widening the read scope every existing token already holds.
 *
 * It is not a breach of the no-Muted boundary. That boundary is that
 * AGENT-AUTHORED Cypher must never name the label, enforced at the tenant
 * filter, because arbitrary queries are what would let suppressed findings leak
 * back into agent reasoning. This goes through the sanctioned fixed op, the
 * same one the Muted table in the UI uses, and adds no query surface.
 */
export async function listMuted(
  ctx: McpContext,
  projectId: string,
  args: { detail?: boolean } = {}
) {
  requireScope(ctx.token, 'triage:read')
  enforceRate(ctx, 'read')
  await assertMcpProjectAccess(ctx.token.userId, projectId)

  const all = await listMutedFindings(ctx.token.userId, projectId, MUTED_FETCH_CEILING)
  // A full window means there may be more suppressed findings than this. Saying
  // "42 muted" when there are 4000 is the same false negative as reporting a
  // clean project, one level in.
  const partialTotal = all.length >= MUTED_FETCH_CEILING

  const groups = new Map<string, MutedGroup>()
  for (const f of all) {
    const label = String(f.label ?? 'unknown')
    const severity = String(f.severity ?? 'unknown')
    const key = `${label}|${severity}`
    const g = groups.get(key) ?? { label, severity, count: 0, reasons: [] }
    g.count += 1
    const reason = String(f.muted_reason ?? '').trim()
    if (reason && !g.reasons.includes(reason) && g.reasons.length < 5) g.reasons.push(reason)
    groups.set(key, g)
  }

  return {
    projectId,
    total: all.length,
    ...(partialTotal
      ? {
          totalIsPartial: true,
          scannedWindow: MUTED_FETCH_CEILING,
          totalNote:
            `This project has at least ${MUTED_FETCH_CEILING} suppressed findings and only the ` +
            `most recently muted ${MUTED_FETCH_CEILING} were read. "total" is AT LEAST this ` +
            `many, not exactly this many.`,
        }
      : {}),
    groups: [...groups.values()].sort((a, b) => b.count - a.count),
    // Rows only on request, and capped whatever happens: `list_muted` applies
    // no limit of its own, so an unbounded project would otherwise ship every
    // suppressed finding in full on every call.
    ...(args.detail === true
      ? {
          findings: all.slice(0, MUTED_MAX_ROWS).map(f => ({
            id: f.id,
            label: f.label,
            name: f.name,
            severity: f.severity,
            source: f.source,
            muted_at: f.muted_at,
            muted_by: f.muted_by,
            muted_reason: f.muted_reason,
          })),
          returned: Math.min(all.length, MUTED_MAX_ROWS),
          ...(all.length > MUTED_MAX_ROWS ? { truncated: true } : {}),
        }
      : {}),
  }
}
