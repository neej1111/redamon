/**
 * Two guards that only real documents made visible.
 *
 * 1. A PROPOSAL SIZE BOUND. Per-field validation cannot catch a parse that has
 *    gone wrong in shape rather than in any single value. One 15,000-character
 *    disclosure policy came back with 631 of the 658 fields in the prompt,
 *    almost all zeroes and falses, and every one of them individually legal, so
 *    nothing rejected any of it. Across sixty documents every other proposal was
 *    between 2 and 14 fields.
 *
 * 2. A CLOSED SET THE REGISTRY CALLED FREE TEXT. That same 631-field proposal
 *    included `supplyChainInputMode`, which the project PUT refuses with
 *    "must be one of: upload, github, org" - a vocabulary declared in
 *    webapp/src/lib/validation/supplyChainInput.ts and nowhere else. The parse
 *    modal tells the operator every proposed value is "already checked against
 *    the same bounds the API enforces", and for this field that was false.
 *
 * @vitest-environment node
 */
import { readFileSync } from 'fs'
import { fileURLToPath } from 'url'

import { describe, test, expect } from 'vitest'

import { MAX_PROPOSED_CHANGES, proposalIsImplausible } from './roeParse'
import { field } from './registry'

describe('a document cannot rewrite the whole pipeline', () => {
  test('an ordinary proposal is accepted', () => {
    // The largest legitimate proposal observed over sixty documents was 14.
    for (const n of [0, 1, 2, 14, 30, MAX_PROPOSED_CHANGES]) {
      expect(proposalIsImplausible(n), `${n} changes`).toBe(false)
    }
  })

  test('the observed failure is refused', () => {
    expect(proposalIsImplausible(631)).toBe(true)
    expect(proposalIsImplausible(MAX_PROPOSED_CHANGES + 1)).toBe(true)
  })

  test('the bound leaves real headroom over what documents actually do', () => {
    // Close to the observed maximum and this rejects real policies; close to the
    // failure and it never fires. The gap between 14 and 631 is where it lives.
    expect(MAX_PROPOSED_CHANGES).toBeGreaterThan(14 * 2)
    expect(MAX_PROPOSED_CHANGES).toBeLessThan(631 / 4)
  })

  test('the route refuses rather than presenting the diff', () => {
    const route = readFileSync(
      fileURLToPath(new URL('../../app/api/roe/parse/route.ts', import.meta.url)),
      'utf8'
    )
    expect(route).toContain('proposalIsImplausible')
    // Refused, and explicitly nothing written.
    const block = route.slice(route.indexOf('proposalIsImplausible'))
    expect(block).toMatch(/status:\s*422/)
    expect(block).toMatch(/Nothing has been changed/)
  })
})

describe('the parse validates against what the save enforces', () => {
  test('supplyChainInputMode is a closed set in the registry', () => {
    // The field that proved the two could disagree: accepted by the proposal,
    // refused by the PUT, so the operator saw a value "validated" and a save
    // that failed.
    expect(field('supplyChainInputMode')?.values).toEqual(['upload', 'github', 'org'])
  })

  test('the registry agrees with the validator that actually refuses it', () => {
    const src = readFileSync(
      fileURLToPath(new URL('../validation/supplyChainInput.ts', import.meta.url)),
      'utf8'
    )
    const m = /SUPPLY_CHAIN_INPUT_MODES = \[([^\]]+)\]/.exec(src)
    expect(m, 'the guarding constant moved or was renamed').not.toBeNull()
    const enforced = [...m![1].matchAll(/'([^']+)'/g)].map(x => x[1])
    expect(field('supplyChainInputMode')?.values).toEqual(enforced)
  })
})
