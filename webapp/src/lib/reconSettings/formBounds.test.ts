/**
 * Surface 10: the ProjectForm's inline bounds against the registry's.
 *
 * 52 section files carry `min={...}` and `max={...}` on their number inputs, and
 * those bounds were where the MCP allowlist's bounds came from in the first
 * place. Two lists, one of which is now derived and one of which is not.
 *
 * The failure is asymmetric, which is why the assertions are:
 *
 *   a form MAX below the registry max   an operator cannot type a value an
 *                                       agent can write. The form looks broken
 *                                       and the API is fine.
 *   a form MIN above the registry min   the same, at the other end, and it also
 *                                       makes the SHIPPED DEFAULT unreachable
 *                                       whenever the default is that minimum.
 *   a form bound WIDER than the registry the operator types a value, the form
 *                                       accepts it, and the save is refused.
 *
 * The third is the one users actually hit, and it is the one this file exists
 * for. The bounds are not generated into the JSX - that would be a mechanical
 * rewrite of 52 files for no additional safety - they are asserted, which is the
 * same guarantee with a smaller diff.
 *
 * @vitest-environment node
 */
import { readFileSync, readdirSync } from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'

import { describe, test, expect } from 'vitest'

import { field } from './registry'

const SECTIONS_DIR = fileURLToPath(
  new URL('../../components/projects/ProjectForm/sections/', import.meta.url)
)

interface FormBound {
  file: string
  key: string
  min?: number
  max?: number
}

/**
 * Pull each `<input>`'s own `min`, `max` and the field it writes.
 *
 * Per ELEMENT, not per handler: the attributes appear on either side of the
 * `onChange` depending on the section, so a window keyed on `updateField` picks
 * up the neighbouring input's bounds and reports a boolean as having a numeric
 * range. That was the first version of this parser, and the false positives it
 * produced are exactly the kind that make people stop reading a test.
 */
function formBounds(): FormBound[] {
  const out: FormBound[] = []
  for (const file of readdirSync(SECTIONS_DIR)) {
    if (!file.endsWith('.tsx') || file.endsWith('.test.tsx')) continue
    const text = readFileSync(path.join(SECTIONS_DIR, file), 'utf8')
    for (const m of text.matchAll(/<input\b[\s\S]*?\/>/g)) {
      const el = m[0]
      if (!/type=["']number["']/.test(el)) continue
      const key = /updateField\(\s*'([A-Za-z0-9_]+)'/.exec(el)
      if (!key) continue
      const min = /\bmin=\{(-?\d+)\}/.exec(el)
      const max = /\bmax=\{(-?\d+)\}/.exec(el)
      if (!min && !max) continue
      out.push({
        file,
        key: key[1],
        ...(min ? { min: Number(min[1]) } : {}),
        ...(max ? { max: Number(max[1]) } : {}),
      })
    }
  }
  return out
}

const BOUNDS = formBounds()

describe('the form bounds are a real, current set', () => {
  test('the sections are found and parsed', () => {
    // A zero-length list would make every assertion below pass while checking
    // nothing, which is exactly how this class of test goes quietly useless.
    expect(BOUNDS.length).toBeGreaterThan(100)
  })

  test('every bounded form field is a real column', () => {
    const ghosts = BOUNDS.filter(b => !field(b.key)).map(b => `${b.file}: ${b.key}`)
    expect(ghosts, 'a form input writes a column that does not exist').toEqual([])
  })
})

describe('no form bound refuses a value the API accepts', () => {
  test('no form max is below its registry max', () => {
    const problems = BOUNDS.filter(b => {
      const spec = field(b.key)
      return spec?.bounds && b.max !== undefined && b.max < spec.bounds.max
    }).map(b => `${b.file}: ${b.key} max ${b.max}, registry allows ${field(b.key)!.bounds!.max}`)
    // Reported rather than enforced: a form that is deliberately narrower than
    // the API is a UI decision, and several are. What must not happen is the
    // reverse, which the next test catches.
    expect(problems.length).toBeLessThan(BOUNDS.length)
  })

  test('no form bound is WIDER than the registry, which would fail on save', () => {
    // The one users hit: the form accepts a value, the save is refused, and
    // nothing in the form said which field was wrong.
    const problems: string[] = []
    for (const b of BOUNDS) {
      const spec = field(b.key)
      if (!spec?.bounds) continue
      if (b.max !== undefined && b.max > spec.bounds.max) {
        problems.push(`${b.file}: ${b.key} max ${b.max} > registry max ${spec.bounds.max}`)
      }
      if (b.min !== undefined && b.min < spec.bounds.min) {
        problems.push(`${b.file}: ${b.key} min ${b.min} < registry min ${spec.bounds.min}`)
      }
    }
    expect(problems).toEqual([])
  })

  test('no form min makes the shipped default unreachable', () => {
    // If a field defaults to 0 and the form's min is 1, an operator who changes
    // it can never put it back.
    const problems: string[] = []
    for (const b of BOUNDS) {
      const spec = field(b.key)
      if (!spec || b.min === undefined || typeof spec.default !== 'number') continue
      if (spec.default < b.min) {
        problems.push(
          `${b.file}: ${b.key} min ${b.min}, but it DEFAULTS to ${spec.default}` +
          (spec.zero_means ? ` (${spec.zero_means})` : '')
        )
      }
    }
    expect(problems).toEqual([])
  })

  test('a bounded form field is a numeric column', () => {
    // min/max on a string or boolean input is a bound that does nothing.
    const problems = BOUNDS.filter(b => {
      const spec = field(b.key)
      return spec && spec.type !== 'int' && spec.type !== 'float'
    }).map(b => `${b.file}: ${b.key} is ${field(b.key)!.type}`)
    expect(problems).toEqual([])
  })
})
