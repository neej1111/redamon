/**
 * P6: a bound is a bound, and a closed list is closed.
 *
 * Twenty-four fields declared `0..10000000`, which is not a bound. Since the
 * form input and the MCP validator are both generated from the registry, a fake
 * bound is a fake control on BOTH doors at once: `tlsxRetries` at ten million
 * against a scope-locked host is a denial of service while a 3 rps ceiling is
 * still nominally honoured, and a rate ceiling whose own maximum is ten million
 * is not a ceiling.
 *
 * The image fields were the same failure wearing different clothes. All 17
 * accepted any string and had it silently replaced at scan start by
 * `sanitize_image_settings()`. The DANGER was contained; the DISHONESTY was not,
 * because `get_recon_settings` echoed the value the caller wrote while the scan
 * ran a different one. That is exactly the failure the allowlist's own "nothing
 * is silently stripped" rule exists to prevent, so the set is closed and an
 * out-of-set value is refused AT THE WRITE.
 *
 * @vitest-environment node
 */
import { readFileSync, readdirSync } from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'

import { describe, test, expect } from 'vitest'

import { filterReconSettings } from './filter'
import { field, fieldsWhere } from './registry'

/**
 * Fields allowed above the plan's flat ceiling, and why.
 *
 * One, and it is a fact about the tool rather than a judgement: `katanaMaxUrls`
 * SHIPS at 300000, so a maximum of 100000 would put the shipped default outside
 * its own bound - the form would render an out-of-range value and an API write
 * of the default would be refused. Lowering the default is a scan-behaviour
 * change nobody asked for.
 *
 * Named rather than derived from a formula, because a formula ("at most 20x the
 * default") would quietly re-admit every field whose default somebody later
 * raises. This costs one look, once.
 */
const ABOVE_THE_FLAT_CEILING: Record<string, number> = {
  katanaMaxUrls: 1_000_000,
}

const FLAT_CEILING = 100_000

describe('P6: no counting or concurrency field declares a fake maximum', () => {
  const counting = () => fieldsWhere(f => (f.unit === 'count' || f.unit === 'threads') && !!f.bounds)

  test('there are plenty of them, or this proves nothing', () => {
    expect(counting().length).toBeGreaterThan(80)
  })

  test('no count or threads field declares a maximum above 100000', () => {
    const problems = counting()
      .filter(f => f.bounds!.max > FLAT_CEILING && !(f.key in ABOVE_THE_FLAT_CEILING))
      .map(f => `${f.key}: max ${f.bounds!.max}, default ${String(f.default)}`)
    expect(problems).toEqual([])
  })

  test('each exception is one the shipped default forces, and no wider', () => {
    // The excuse has to be earned. A field listed here whose default fits under
    // the flat ceiling is a field somebody widened for convenience.
    const problems: string[] = []
    for (const [key, allowed] of Object.entries(ABOVE_THE_FLAT_CEILING)) {
      const f = fieldsWhere((_s, k) => k === key)[0]
      if (!f) { problems.push(`${key}: not a field any more; drop the exception`); continue }
      if (typeof f.default !== 'number' || f.default <= FLAT_CEILING) {
        problems.push(`${key}: ships at ${String(f.default)}, which fits under ${FLAT_CEILING}`)
      }
      if (f.bounds!.max !== allowed) {
        problems.push(`${key}: max ${f.bounds!.max}, exception allows ${allowed}`)
      }
    }
    expect(problems).toEqual([])
  })

  test('every shipped default is inside its own bound', () => {
    // The failure the exception above exists to avoid, asserted for every field
    // rather than only for the one that hit it.
    const problems = fieldsWhere(f => !!f.bounds && typeof f.default === 'number')
      .filter(f => (f.default as number) < f.bounds!.min || (f.default as number) > f.bounds!.max)
      .map(f => `${f.key}: default ${String(f.default)} outside ${f.bounds!.min}..${f.bounds!.max}`)
    expect(problems).toEqual([])
  })

  test('the ten-million bound is gone entirely', () => {
    const problems = fieldsWhere(f => !!f.bounds && f.bounds.max >= 10_000_000)
      .map(f => `${f.key}: ${f.bounds!.max}`)
    expect(problems).toEqual([])
  })

  test('the rate ceiling has a ceiling of its own', () => {
    const ceiling = fieldsWhere((_f, key) => key === 'roeGlobalMaxRps')[0]
    expect(ceiling.bounds!.max).toBeLessThanOrEqual(10000)
  })

  test('every declared bound is actually enforced at both ends', () => {
    // A bound nothing checks is the same fake control in a different place.
    const problems: string[] = []
    for (const f of fieldsWhere(s => s.mcp === 'settable' && !!s.bounds)) {
      if (filterReconSettings({ [f.key]: f.bounds!.max + 1 }).ok) {
        problems.push(`${f.key}: max + 1 accepted`)
      }
      if (f.bounds!.min > 0 && filterReconSettings({ [f.key]: f.bounds!.min - 1 }).ok) {
        problems.push(`${f.key}: min - 1 accepted`)
      }
    }
    expect(problems).toEqual([])
  })
})

describe('P6: a container image is a closed list, never free text', () => {
  const images = () => fieldsWhere((_f, key) => key.endsWith('DockerImage'))

  test('all seventeen are covered, not only the eight with no input', () => {
    expect(images()).toHaveLength(17)
  })

  test('every one declares a non-empty closed value set', () => {
    const problems = images()
      .filter(f => !f.values || f.values.length === 0)
      .map(f => `${f.key}: no values list`)
    expect(problems).toEqual([])
  })

  test('the shipped default is inside its own set', () => {
    // Otherwise the field ships unsettable-to-its-own-value, which the form
    // would render as a select with the current value missing.
    const problems = images()
      .filter(f => typeof f.default === 'string' && f.default && !f.values!.includes(f.default))
      .map(f => `${f.key}: default ${String(f.default)} is not in its own set`)
    expect(problems).toEqual([])
  })

  test('an out-of-set image is REFUSED, not accepted and reverted', () => {
    const problems: string[] = []
    for (const f of images()) {
      const r = filterReconSettings({ [f.key]: 'attacker/evil:latest' })
      if (r.ok) problems.push(`${f.key}: accepted a non-shipped image`)
      else if (!r.error.includes('must be one of')) {
        problems.push(`${f.key}: refused without naming the permitted set`)
      }
    }
    expect(problems).toEqual([])
  })

  test('an operator-approved mirror is accepted, and only from the server env', () => {
    // An air-gapped or private-registry deployment mirrors the shipped images.
    // The operator names the mirrors in an env var the SERVER controls, which
    // is not attacker-influenceable the way a project setting is - so it widens
    // the closed list without re-opening the hole the list exists to close.
    const before = process.env.RECON_EXTRA_ALLOWED_IMAGES
    try {
      expect(filterReconSettings({ nucleiDockerImage: 'myregistry.local/nuclei:v3' }).ok)
        .toBe(false)
      process.env.RECON_EXTRA_ALLOWED_IMAGES = 'myregistry.local/nuclei:v3'
      expect(filterReconSettings({ nucleiDockerImage: 'myregistry.local/nuclei:v3' }).ok)
        .toBe(true)
      // Still not anything at all.
      expect(filterReconSettings({ nucleiDockerImage: 'attacker/evil:latest' }).ok)
        .toBe(false)
    } finally {
      if (before === undefined) delete process.env.RECON_EXTRA_ALLOWED_IMAGES
      else process.env.RECON_EXTRA_ALLOWED_IMAGES = before
    }
  })

  test('a shipped image is accepted', () => {
    const problems = images()
      .filter(f => typeof f.default === 'string' && f.default)
      .filter(f => !filterReconSettings({ [f.key]: f.default as string }).ok)
      .map(f => `${f.key}: refused its own default`)
    expect(problems).toEqual([])
  })
})


// --- the form half of the closed list ---------------------------------------------

const SECTIONS_DIR = fileURLToPath(
  new URL('../../components/projects/ProjectForm/sections/', import.meta.url)
)
const FORM_DIR = fileURLToPath(
  new URL('../../components/projects/ProjectForm/', import.meta.url)
)

/**
 * The JSX element that writes a field, found by looking BACKWARDS from the write.
 *
 * Not by matching the element forwards, which is the obvious way and is wrong:
 * an arrow function in `onChange={(e) => ...}` contains a `>`, so a non-greedy
 * element match ends before it reaches the `updateField` call and the field is
 * never seen. That false negative is how a free-text control over a closed value
 * set sat here unnoticed while a scan reported every image field as a select.
 */
function controlFor(text: string, index: number): string | null {
  const before = text.slice(0, index)
  let best: { tag: string; at: number } | null = null
  for (const tag of ['input', 'select', 'textarea', 'Toggle']) {
    const at = before.lastIndexOf(`<${tag}`)
    if (at >= 0 && (!best || at > best.at)) best = { tag, at }
  }
  return best ? best.tag : null
}

function formFiles(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, name.name)
    if (name.isDirectory()) { formFiles(full, out); continue }
    if (!name.name.endsWith('.tsx') || name.name.includes('.test.')) continue
    out.push(full)
  }
  return out
}

describe('P6: the form cannot offer a value the write will refuse', () => {
  test('every bespoke control over a closed value set is a select', () => {
    // The other half of A4.3. Closing the value set at the API and leaving a
    // text box in the form is worse than leaving both open: the operator types
    // something the form accepts and the save rejects, which reads as a bug in
    // saving rather than as a refused value.
    const problems: string[] = []
    for (const full of formFiles(FORM_DIR)) {
      const text = readFileSync(full, 'utf8')
      for (const m of text.matchAll(/updateField\(\s*'([A-Za-z0-9_]+)'/g)) {
        const spec = field(m[1])
        if (!spec?.values || spec.type !== 'string') continue
        const tag = controlFor(text, m.index!)
        if (tag !== 'select') {
          problems.push(`${path.basename(full)}: ${m[1]} is a <${tag}>, not a <select>`)
        }
      }
    }
    expect(problems).toEqual([])
  })

  test('a closed string-list is never driven by a free-text box', () => {
    // The list half of the same rule. `roeForbiddenTools` was a comma-separated
    // text input over a set the gate matches exactly, so every value it produced
    // was plausible and unenforceable - including the one its own placeholder
    // suggested. A closed list belongs on checkboxes, like nucleiSeverity.
    const problems: string[] = []
    for (const full of formFiles(FORM_DIR)) {
      const text = readFileSync(full, 'utf8')
      for (const m of text.matchAll(/updateField\(\s*'([A-Za-z0-9_]+)'/g)) {
        const spec = field(m[1])
        if (!spec?.values || spec.type !== 'string-list') continue
        const before = text.slice(0, m.index!)
        const at = before.lastIndexOf('<input')
        if (at < 0) continue
        const tag = before.slice(at, at + 200)
        if (/type="text"/.test(tag)) {
          problems.push(`${path.basename(full)}: ${m[1]} is written from a text input`)
        }
      }
    }
    expect(problems).toEqual([])
  })

  test('the backwards parser really finds a control', () => {
    // A parser that found nothing would make the assertion above vacuous, which
    // is exactly the failure it was written to replace.
    const text = readFileSync(path.join(SECTIONS_DIR, 'GraphqlScanSection.tsx'), 'utf8')
    const m = /updateField\(\s*'graphqlCopDockerImage'/.exec(text)
    expect(m).not.toBeNull()
    expect(controlFor(text, m!.index)).toBe('select')
  })
})
