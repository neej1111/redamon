/**
 * G4 and C1: the engagement-limits block, and the value that must stay out of it.
 *
 * `roeEnabled` is DERIVED. Two things follow, and only the first is obvious:
 *
 *  1. It must not sit in `formData`, or `useDirtyState` sees a value the user
 *     never edited and the unsaved-changes guard fires on every navigation.
 *  2. The form SUBMITS `formData` wholesale, so a derived value that got in
 *     would be written straight back to the column - leaving a stored value
 *     that disagrees with the derivation, which is exactly the
 *     two-sources-of-truth state the derivation exists to end.
 *
 * The status line is what replaces the checkbox. It has to say WHICH limit makes
 * the limits live, because "active" with no reason is the same opaque state the
 * master switch had.
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent } from '@testing-library/react'

import { TargetSection } from './TargetSection'

vi.mock('@/components/shared/ModelPicker', () => ({ ModelPicker: () => null }))
vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ userId: 'u1' }) }))

afterEach(cleanup)

type Data = Record<string, unknown>

const BASE: Data = {
  name: '', description: '', targetDomain: 'example.com', subdomainList: [],
  ipMode: false, targetIps: [], domainBatchMode: false, domainBatchHosts: [],
  subdomainDiscoveryEnabled: true, aiInPipeline: false, verifyDomainOwnership: false,
  ownershipToken: '', ownershipTxtPrefix: '', aiPipelineModel: '',
  stealthMode: false, targetGuardrailEnabled: true,
  roeGlobalMaxRps: 0, roeExcludedHosts: [], roeExcludedHostReasons: [],
  roeTimeWindowEnabled: false, roeTimeWindowDays: [], roeTimeWindowTimezone: 'UTC',
  roeTimeWindowStartTime: '09:00', roeTimeWindowEndTime: '18:00',
}

function renderWith(over: Data = {}) {
  const writes: Record<string, unknown> = {}
  const data = { ...BASE, ...over }
  const updateField = (k: string, v: unknown) => { writes[k] = v }
  render(<TargetSection data={data as never} updateField={updateField as never} mode="edit" />)
  return writes
}

describe('the status line replaces the master switch', () => {
  test('with no limit set it says so, and names what to do', () => {
    renderWith()
    expect(screen.getByText(/No limits are active/i)).toBeTruthy()
  })

  test('a rate ceiling makes them active, and the line says which limit did it', () => {
    renderWith({ roeGlobalMaxRps: 3 })
    expect(screen.getByText(/Limits are ACTIVE because a rate ceiling is set/i)).toBeTruthy()
  })

  test('an excluded host alone makes them active', () => {
    renderWith({ roeExcludedHosts: ['pay.test'], roeExcludedHostReasons: ['processor'] })
    expect(screen.getByText(/ACTIVE because an excluded-host list/i)).toBeTruthy()
  })

  test('a time window alone makes them active', () => {
    renderWith({ roeTimeWindowEnabled: true })
    expect(screen.getByText(/ACTIVE because a scanning time window/i)).toBeTruthy()
  })

  test('two limits are both named, not just the first', () => {
    renderWith({ roeGlobalMaxRps: 3, roeTimeWindowEnabled: true })
    expect(
      screen.getByText(/a rate ceiling and a scanning time window are set/i)
    ).toBeTruthy()
  })

  test('a third-party project is told its scans will be REFUSED, not just unconstrained', () => {
    // Part F. "No limits are active" is true and understates it by exactly the
    // amount that matters: for a third-party engagement the scan does not run
    // slowly, it does not run.
    renderWith({ engagementKind: 'third_party', roeGlobalMaxRps: 0 })
    expect(screen.getByText(/will be REFUSED until a request-rate ceiling is set/i)).toBeTruthy()
  })

  test('an internal project is not told that', () => {
    renderWith({ engagementKind: 'internal', roeGlobalMaxRps: 0 })
    expect(screen.queryByText(/will be REFUSED/i)).toBeNull()
  })

  test('a third-party project WITH a ceiling is not warned', () => {
    renderWith({ engagementKind: 'third_party', roeGlobalMaxRps: 3 })
    expect(screen.queryByText(/will be REFUSED/i)).toBeNull()
  })

  test('there is no checkbox for it anywhere in the block', () => {
    // A switch whose only job is to disable other safety fields is a bypass, not
    // a setting. Rendering one read-only would still invite "why is it greyed
    // out"; there simply is not one.
    const { container } = render(
      <TargetSection data={BASE as never} updateField={(() => {}) as never} mode="edit" />
    )
    const labels = [...container.querySelectorAll('label')].map(l => l.textContent ?? '')
    expect(labels.filter(l => /enable rules of engagement/i.test(l))).toEqual([])
  })
})

describe('G4: the derived flag is never written', () => {
  test('rendering writes nothing at all', () => {
    expect(renderWith()).toEqual({})
  })

  test('editing a limit writes only that limit', () => {
    const writes = renderWith()
    const rps = screen.getByLabelText(/Global max requests\/sec/i)
    fireEvent.change(rps, { target: { value: '3' } })
    expect(writes).toEqual({ roeGlobalMaxRps: 3 })
    expect(writes).not.toHaveProperty('roeEnabled')
  })

  test('adding an excluded host writes the host AND its reason together', () => {
    // The two arrays are positional. Writing one without the other silently
    // re-pairs every reason below it with the wrong host.
    const writes = renderWith()
    fireEvent.click(screen.getByText(/Add excluded host/i))
    expect(Object.keys(writes).sort()).toEqual(['roeExcludedHostReasons', 'roeExcludedHosts'])
    expect(writes.roeExcludedHosts).toEqual([''])
    expect(writes.roeExcludedHostReasons).toEqual([''])
  })
})

describe('C1: TargetSection holds the general limits and not the agent ones', () => {
  test('the eight that configure no single module are here', () => {
    renderWith({ roeTimeWindowEnabled: true })
    for (const label of [
      /Global max requests\/sec/i, /Never-touch hosts/i,
      /Restrict scanning to a time window/i, /Timezone/i,
      /Start time/i, /End time/i, /Allowed days/i,
    ]) {
      expect(screen.getAllByText(label).length, String(label)).toBeGreaterThan(0)
    }
  })

  test("the agent's own limits are NOT here", () => {
    // They belong beside the thing that enforces them. A field filed by its
    // prefix instead of by its job is how the form becomes a list of columns.
    const { container } = render(
      <TargetSection data={BASE as never} updateField={(() => {}) as never} mode="edit" />
    )
    const text = container.textContent ?? ''
    expect(text).not.toMatch(/Forbidden tools/i)
    expect(text).not.toMatch(/Max allowed phase/i)
    expect(text).not.toMatch(/Allow availability testing/i)
  })
})
