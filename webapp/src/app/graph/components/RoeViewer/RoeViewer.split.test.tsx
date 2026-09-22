/**
 * G5: the read-only engagement panel shows every LIMIT, split from the record.
 *
 * The panel exists to answer "what constrains this engagement". It used to
 * render 35 `roe*` fields as one undifferentiated list, which is what made the
 * two concepts easy to confuse in the first place: a checkbox that disabled the
 * rate ceiling sat next to the client's phone number, looking like the same kind
 * of thing.
 *
 * The assertion that earns its place is the first one. `roeForbiddenTools`
 * refuses a tool BEFORE it runs, and the panel did not show it at all - a live
 * constraint invisible on the one screen built to display constraints. Nothing
 * failed, because nothing checked.
 *
 * @vitest-environment jsdom
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'

import { RoeViewer } from './RoeViewer'
import { fieldsWhere } from '@/lib/reconSettings/registry'

vi.mock('./AuthorizationHistory', () => ({ AuthorizationHistory: () => null }))

afterEach(cleanup)

/** A project with every limit set, so each one has something to render. */
const LIMITED = {
  engagementKind: 'third_party',
  engagementIdentityHeader: 'X-Bug-Bounty: me',
  targetDomain: 'example.com',
  roeGlobalMaxRps: 3,
  roeExcludedHosts: ['pay.example.com'],
  roeExcludedHostReasons: ['third-party processor'],
  roeTimeWindowEnabled: true,
  roeTimeWindowDays: ['monday'],
  roeTimeWindowStartTime: '09:00',
  roeTimeWindowEndTime: '17:00',
  roeTimeWindowTimezone: 'Europe/Rome',
  roeForbiddenTools: ['execute_hydra'],
  roeForbiddenCategories: ['brute_force'],
  roeAllowDos: false,
  roeAllowAccountLockout: false,
  roeAllowSocialEngineering: false,
  roeMaxSeverityPhase: 'exploitation',
  roeClientName: 'Acme Ltd',
}

function panel(over: Record<string, unknown> = {}) {
  const { container } = render(
    <RoeViewer projectId="p1" project={{ ...LIMITED, ...over } as never} />
  )
  return container.textContent ?? ''
}

describe('every enforced limit is visible', () => {
  test('the registry names 14 writable limits, or this test drifted', () => {
    const limits = fieldsWhere(f => f.group === 'engagement_limits' && f.mcp === 'settable')
    expect(limits).toHaveLength(14)
  })

  test('a forbidden TOOL is shown, not only a forbidden category', () => {
    const text = panel()
    expect(text).toMatch(/Forbidden tools/i)
    expect(text).toMatch(/execute_hydra/)
  })

  test('the three agent flags that are enforced are shown', () => {
    const text = panel()
    for (const label of [/Availability testing/i, /Account lockout/i, /Social engineering/i]) {
      expect(text, String(label)).toMatch(label)
    }
  })

  test('the rate ceiling, the exclusions and the window are shown', () => {
    const text = panel()
    expect(text).toMatch(/3 rps/)
    expect(text).toMatch(/pay\.example\.com/)
    expect(text).toMatch(/third-party processor/)
    expect(text).toMatch(/Europe\/Rome/)
  })
})

describe('the two groups are labelled differently', () => {
  test('limits say they are limits', () => {
    const text = panel()
    expect(text).toMatch(/Engagement limit: excluded hosts/i)
    expect(text).toMatch(/Engagement limit: time window/i)
    expect(text).toMatch(/Engagement limits: agent/i)
  })

  test('the record says it is the record, and that nothing enforces it', () => {
    const text = panel()
    expect(text).toMatch(/Engagement record/i)
    expect(text).toMatch(/Recorded permissions/i)
    expect(text).toMatch(/No code refuses anything on these/i)
  })

  test('a recorded permission is not listed among the enforced ones', () => {
    // Production testing is a statement about the estate that no scanner can
    // verify. Showing it beside the DoS gate implies a symmetry that is not
    // there.
    const text = panel()
    const enforced = text.slice(text.indexOf('Engagement limits: agent'), text.indexOf('Recorded permissions'))
    expect(enforced).not.toMatch(/Production/i)
  })
})

describe('the empty state says the thing worth saying', () => {
  test('no limits and no record reports the absent ceiling, not an absent document', () => {
    const text = panel({
      roeGlobalMaxRps: 0, roeExcludedHosts: [], roeTimeWindowEnabled: false,
      roeClientName: '', roeDocumentName: '', roeNotes: '',
      roeEngagementStartDate: '', roeClientContactName: '',
    })
    expect(text).toMatch(/no request-rate ceiling/i)
    expect(text).toMatch(/No engagement limits/i)
  })

  test('a record with no limits still renders the record', () => {
    // The derived flag is false here. Gating the whole panel on it would hide
    // the contract from every project that recorded one without setting a limit.
    const text = panel({
      roeGlobalMaxRps: 0, roeExcludedHosts: [], roeTimeWindowEnabled: false,
    })
    expect(text).toMatch(/Acme Ltd/)
    expect(text).toMatch(/No limits are active/i)
  })
})
