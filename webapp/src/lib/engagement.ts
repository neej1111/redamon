/**
 * What has to be true before a scan may reach somebody else's estate.
 *
 * Two defects this closes, and they compound.
 *
 * The first: the engagement limits used to hang off a writable master switch.
 * `roeEnabled` defaulted false and gated the capper, so a project with a 3 rps
 * ceiling written and the switch off ran unlimited, and one write of false
 * disabled the ceiling, the exclusions and the window at once while every field
 * still showed its configured value. It is DERIVED now - see
 * `deriveRoeEnabled` - so limits apply when there is a limit to apply and
 * nothing can turn them off without removing them.
 *
 * The second: a project carried no link to the document that permitted it. With
 * an agent able to create projects and reach every pipeline parameter, "who said
 * you could scan this" needs an answer that survives the token that made the
 * claim.
 *
 * `engagementKind` is what ties them together. An `internal` project is our own
 * estate and nothing changes for it. A `third_party` project must carry a
 * non-zero ceiling AND an authorization record, and `start_recon` refuses it
 * otherwise - refuses, rather than silently downgrading, because a scan that
 * quietly ran without its ceiling is the exact failure this exists to prevent.
 *
 * Every project that predates the column reads as `internal`, which keeps the
 * estate working and means the defect is closed for NEW projects only. The
 * existing ones are FLAGGED instead: `describeEngagement` reports the absence of
 * a ceiling prominently so an operator converts deliberately rather than
 * discovering it during an incident.
 */
import { createHash } from 'crypto'

import prisma from '@/lib/prisma'

export type EngagementKind = 'internal' | 'third_party'

export const ENGAGEMENT_KINDS: readonly EngagementKind[] = ['internal', 'third_party']

export const DOCUMENT_KINDS = [
  'hackerone_program',
  'bugcrowd_program',
  'roe_document',
  'internal_ticket',
  'other',
] as const
export type DocumentKind = (typeof DOCUMENT_KINDS)[number]

export function isEngagementKind(value: unknown): value is EngagementKind {
  return typeof value === 'string' && (ENGAGEMENT_KINDS as readonly string[]).includes(value)
}

export function isDocumentKind(value: unknown): value is DocumentKind {
  return typeof value === 'string' && (DOCUMENT_KINDS as readonly string[]).includes(value)
}

const SHA256_RE = /^[0-9a-f]{64}$/

export function isSha256(value: unknown): value is string {
  return typeof value === 'string' && SHA256_RE.test(value)
}

/** The digest of a scope document, for a caller that has the text rather than the hash. */
export function digestScopeDocument(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex')
}

export interface EngagementProjectRow {
  id: string
  engagementKind: string
  roeGlobalMaxRps: number
  roeExcludedHosts?: string[]
  roeTimeWindowEnabled?: boolean
  targetDomain?: string
  engagementIdentityHeader?: string
}

export interface EngagementStatus {
  kind: EngagementKind
  /** The effective request-rate ceiling, or null when there is none. */
  ceilingRps: number | null
  /** True when a ceiling is configured. */
  ceilingEffective: boolean
  /** The derived answer to "are this project's engagement limits live". */
  limitsActive: boolean
  /** Which of the three limits make them live, for the status line in the form. */
  activeLimits: string[]
  hasAuthorization: boolean
  /** Empty when the engagement is startable. Otherwise, why it is not. */
  blockers: string[]
  /** Not blocking, but an operator should see it. */
  warnings: string[]
}

/**
 * Are this project's engagement limits live?
 *
 * The TypeScript half of one rule. `recon_settings/engagement.py` holds the
 * other, for recon, the agent and the orchestrator; the webapp cannot import
 * Python, so the copy is unavoidable and `engagement.derivation.test.ts` pins
 * the two to a shared fixture table instead.
 *
 * Limits apply when there is a limit to apply. Never read `project.roeEnabled`:
 * the column is kept only so old rows and old exports still load, and nothing
 * writes it.
 */
export function deriveRoeEnabled(project: {
  roeGlobalMaxRps?: number | null
  roeExcludedHosts?: string[] | null
  roeTimeWindowEnabled?: boolean | null
} | null | undefined): boolean {
  // Never throws. It runs on the path that decides whether a rate ceiling
  // applies and on the queued-job fingerprint, and both take rows assembled
  // elsewhere - a partial select, an older export bundle, a test fixture. A
  // throw here would be a scan that starts without a ceiling.
  if (!project || typeof project !== 'object') return false
  const ceiling = Number(project.roeGlobalMaxRps ?? 0)
  if (Number.isFinite(ceiling) && ceiling > 0) return true
  const excluded = project.roeExcludedHosts
  if (Array.isArray(excluded) && excluded.some(h => String(h).trim() !== '')) return true
  return Boolean(project.roeTimeWindowEnabled)
}

/**
 * The effective request-rate ceiling, or null when there is none.
 *
 * ZERO MEANS NO CEILING rather than a slow one, which is the trap this function
 * exists to keep out of every caller.
 */
export function effectiveCeiling(project: EngagementProjectRow): number | null {
  return project.roeGlobalMaxRps > 0 ? project.roeGlobalMaxRps : null
}

export function describeEngagement(
  project: EngagementProjectRow,
  authorizationCount: number
): EngagementStatus {
  const kind: EngagementKind = isEngagementKind(project.engagementKind)
    ? project.engagementKind
    : 'internal'
  const ceiling = effectiveCeiling(project)
  const blockers: string[] = []
  const warnings: string[] = []

  if (kind === 'third_party') {
    if (!(project.roeGlobalMaxRps > 0)) {
      blockers.push(
        'roeGlobalMaxRps is 0, which means NO ceiling rather than a slow one. A third-party ' +
        'engagement must declare a request-rate ceiling.'
      )
    }
    if (authorizationCount === 0) {
      blockers.push(
        'No authorization record. A third-party engagement must record the scope document ' +
        'that permits it before a scan starts; use attach_engagement_authorization.'
      )
    }
  } else if (ceiling === null) {
    // The whole existing estate lands here after the backfill. Loud, and not
    // blocking: turning it into a blocker would break every project at once.
    warnings.push(
      'This project has NO request-rate ceiling: every tool runs at whatever rate its own ' +
      'setting says. That is the default for a project created before engagement kinds ' +
      'existed. If the target is not your own estate, set engagementKind to third_party on a ' +
      'new project, or set roeGlobalMaxRps to a non-zero value.'
    )
  }

  if (kind === 'third_party' && !project.engagementIdentityHeader) {
    warnings.push(
      'No engagement identity header is set, so the target\'s operators cannot attribute this ' +
      'traffic to you. Many programs require one.'
    )
  }

  const activeLimits: string[] = []
  if (project.roeGlobalMaxRps > 0) activeLimits.push('a request-rate ceiling')
  if ((project.roeExcludedHosts ?? []).some(h => String(h).trim() !== '')) {
    activeLimits.push('an excluded-host list')
  }
  if (project.roeTimeWindowEnabled) activeLimits.push('a scanning time window')

  return {
    kind,
    ceilingRps: ceiling,
    ceilingEffective: ceiling !== null,
    limitsActive: deriveRoeEnabled(project),
    activeLimits,
    hasAuthorization: authorizationCount > 0,
    blockers,
    warnings,
  }
}

const ENGAGEMENT_SELECT = {
  id: true,
  engagementKind: true,
  engagementIdentityHeader: true,
  roeGlobalMaxRps: true,
  roeExcludedHosts: true,
  roeTimeWindowEnabled: true,
  targetDomain: true,
} as const

/**
 * Load a project's engagement status.
 *
 * FAILS CLOSED for a third_party project: an unreadable project or an
 * uncountable authorization set is reported as blocking, never as fine. This
 * runs on the path that decides whether a scan reaches somebody else's estate,
 * and "we could not check" is not the same as "it is allowed".
 */
export async function loadEngagement(projectId: string): Promise<EngagementStatus> {
  const project = await prisma.project.findUnique({
    where: { id: projectId },
    select: ENGAGEMENT_SELECT,
  })
  if (!project) {
    return {
      kind: 'third_party',
      ceilingRps: null,
      ceilingEffective: false,
      limitsActive: false,
      activeLimits: [],
      hasAuthorization: false,
      blockers: ['Project not found.'],
      warnings: [],
    }
  }
  let count = 0
  try {
    count = await prisma.engagementAuthorization.count({ where: { projectId } })
  } catch (err) {
    // An unreadable authorization set is treated as ABSENT, which blocks a
    // third-party engagement and merely omits a note on an internal one. That
    // is the fail-closed direction: "we could not check" is not "it is fine".
    console.error(`[engagement] could not count authorizations for ${projectId}:`, err)
    count = 0
  }
  return describeEngagement(project as EngagementProjectRow, count)
}

/**
 * The project's current authorization, or null.
 *
 * The most recent record, because the model is append-only: when a program
 * re-issues its scope a new row records that the engagement continued under a
 * new authority from that moment, and the latest one is what a run today is
 * covered by.
 */
export async function currentAuthorization(projectId: string) {
  return prisma.engagementAuthorization.findFirst({
    where: { projectId },
    orderBy: { recordedAt: 'desc' },
    select: {
      id: true,
      documentSha256: true,
      documentKind: true,
      sourceUrl: true,
      programHandle: true,
      issuedAt: true,
      recordedAt: true,
      recordedVia: true,
      summary: true,
    },
  })
}
