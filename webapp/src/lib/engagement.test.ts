/**
 * The engagement gate: what has to be true before a scan reaches somebody
 * else's estate.
 *
 * The rule these tests pin is narrow and load-bearing. `roeGlobalMaxRps`
 * defaults 0, so a project has NO rate ceiling unless someone deliberately set
 * one. That was survivable while three of fifteen rate fields were reachable
 * over MCP; with every rate reachable, the engagement limits are the main
 * control for all of them.
 *
 * The failure the assertions below exist to prevent is that a ceiling of 0 is NO
 * ceiling rather than a slow one, and is also the shipped default.
 *
 * The other one they used to guard - a ceiling written with a master switch off,
 * which capped nothing - cannot happen any more: the switch is DERIVED from
 * whether a limit is set, so a written ceiling is always a live one.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'

import {
  DOCUMENT_KINDS,
  describeEngagement,
  deriveRoeEnabled,
  digestScopeDocument,
  effectiveCeiling,
  isDocumentKind,
  isEngagementKind,
  isSha256,
  type EngagementProjectRow,
} from './engagement'

const project = (over: Partial<EngagementProjectRow> = {}): EngagementProjectRow => ({
  id: 'p1',
  engagementKind: 'internal',
  roeGlobalMaxRps: 0,
  ...over,
})

describe('zero is not a slow ceiling, it is no ceiling', () => {
  test('a written ceiling is a live ceiling', () => {
    expect(effectiveCeiling(project({ roeGlobalMaxRps: 3 }))).toBe(3)
  })

  test('0 is not a ceiling', () => {
    expect(effectiveCeiling(project({ roeGlobalMaxRps: 0 }))).toBeNull()
  })
})

describe('the engagement limits are live when there is a limit to apply', () => {
  test('a rate ceiling makes them live', () => {
    expect(deriveRoeEnabled({ roeGlobalMaxRps: 3 })).toBe(true)
  })

  test('an excluded host makes them live', () => {
    expect(deriveRoeEnabled({ roeExcludedHosts: ['pay.target.test'] })).toBe(true)
  })

  test('a time window makes them live', () => {
    expect(deriveRoeEnabled({ roeTimeWindowEnabled: true })).toBe(true)
  })

  test('none of the three leaves them inert', () => {
    expect(deriveRoeEnabled({
      roeGlobalMaxRps: 0, roeExcludedHosts: [], roeTimeWindowEnabled: false,
    })).toBe(false)
  })

  test('a blank exclusion entry is not an exclusion', () => {
    // An empty row left behind by the paired editor is not a limit, and reading
    // it as one would tell an operator their limits are live when nothing is.
    expect(deriveRoeEnabled({ roeExcludedHosts: ['', '  '] })).toBe(false)
  })

  test('a missing project is not enabled rather than throwing', () => {
    expect(deriveRoeEnabled(null)).toBe(false)
    expect(deriveRoeEnabled(undefined)).toBe(false)
  })

  test('describeEngagement reports WHICH limits are live', () => {
    // So the form can say "limits are active because a rate ceiling is set"
    // rather than showing a checkbox nobody may tick.
    const status = describeEngagement(
      project({ roeGlobalMaxRps: 3, roeTimeWindowEnabled: true }), 0
    )
    expect(status.limitsActive).toBe(true)
    expect(status.activeLimits).toEqual(['a request-rate ceiling', 'a scanning time window'])
  })
})

describe('a third-party engagement is blocked until both exist', () => {
  const third = (over: Partial<EngagementProjectRow> = {}) =>
    project({ engagementKind: 'third_party', roeGlobalMaxRps: 3, ...over })

  test('a ceiling and a record together make it startable', () => {
    const status = describeEngagement(third(), 1)
    expect(status.blockers).toEqual([])
    expect(status.ceilingRps).toBe(3)
    expect(status.hasAuthorization).toBe(true)
  })

  test('no authorization blocks it, naming the tool that fixes it', () => {
    const status = describeEngagement(third(), 0)
    expect(status.blockers).toHaveLength(1)
    expect(status.blockers[0]).toMatch(/attach_engagement_authorization/)
  })

  test('a zero ceiling blocks it, saying what zero means', () => {
    const status = describeEngagement(third({ roeGlobalMaxRps: 0 }), 1)
    expect(status.blockers[0]).toMatch(/NO ceiling/)
  })

  test('two missing things produce two blockers, not one', () => {
    // An operator who fixes the first and retries should not discover the
    // second one call later.
    const status = describeEngagement(third({ roeGlobalMaxRps: 0 }), 0)
    expect(status.blockers).toHaveLength(2)
  })

  test('a missing identity header warns without blocking', () => {
    // Many programs require one, and none of them are enforced by us.
    const status = describeEngagement(third(), 1)
    expect(status.blockers).toEqual([])
    expect(status.warnings.join(' ')).toMatch(/identity header/)
  })
})

describe('the existing estate is flagged, not broken', () => {
  test('an internal project with no ceiling still starts, loudly', () => {
    // Every project created before engagement kinds existed reads as internal
    // with no ceiling. Blocking them would turn the whole estate red at once,
    // which is not a fix.
    const status = describeEngagement(project(), 0)
    expect(status.blockers).toEqual([])
    expect(status.warnings.join(' ')).toMatch(/NO request-rate ceiling/)
  })

  test('an internal project WITH a ceiling gets no warning', () => {
    const status = describeEngagement(project({ roeGlobalMaxRps: 10 }), 0)
    expect(status.warnings).toEqual([])
  })

  test('an unrecognised engagementKind reads as internal rather than throwing', () => {
    // A value written before the enum was constrained, or by a future version.
    // Reading it as internal keeps the project working; reading it as
    // third_party would block a project nobody converted.
    const status = describeEngagement(project({ engagementKind: 'something_else' }), 0)
    expect(status.kind).toBe('internal')
  })
})

describe('the authorization record is a digest, never the document', () => {
  test('the digest of a document is its sha256', () => {
    const digest = digestScopeDocument('in scope: *.example.com\nout: admin.example.com\n')
    expect(digest).toMatch(/^[0-9a-f]{64}$/)
    expect(digestScopeDocument('different')).not.toBe(digest)
  })

  test('the same document always digests the same', () => {
    const text = 'a scope document'
    expect(digestScopeDocument(text)).toBe(digestScopeDocument(text))
  })

  test('only 64 lower-case hex is a digest', () => {
    expect(isSha256('a'.repeat(64))).toBe(true)
    expect(isSha256('A'.repeat(64))).toBe(false)
    expect(isSha256('a'.repeat(63))).toBe(false)
    expect(isSha256('')).toBe(false)
    expect(isSha256(null)).toBe(false)
  })

  test('the document kinds cover the formats a scope actually arrives in', () => {
    // The point of storing only a digest is that the model works the same for
    // any of them and parses none of them.
    for (const kind of ['hackerone_program', 'bugcrowd_program', 'roe_document', 'internal_ticket']) {
      expect(isDocumentKind(kind), kind).toBe(true)
    }
    expect(isDocumentKind('made_up')).toBe(false)
    expect(DOCUMENT_KINDS).toContain('other')
  })

  test('only the two engagement kinds are engagement kinds', () => {
    expect(isEngagementKind('internal')).toBe(true)
    expect(isEngagementKind('third_party')).toBe(true)
    expect(isEngagementKind('thirdparty')).toBe(false)
    expect(isEngagementKind(undefined)).toBe(false)
  })
})
