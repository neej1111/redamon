/**
 * P1: the UI and MCP reach the same things.
 *
 * "Identical capabilities" was false in BOTH directions before this. MCP could
 * write 65 columns the form had no input for, which is the direction nobody
 * notices because the missing half is the one a person would have complained
 * about. And the engagement's limits were reachable only through a dedicated
 * MCP tool with its own direction rules, which is the direction that made the
 * form look safer than it was.
 *
 * Two assertions, and they are deliberately opposite:
 *
 *   every WRITABLE field has an input      MCP cannot reach what the form cannot
 *   every INPUT is a writable field        the form cannot reach what MCP cannot,
 *                                          except the engagement RECORD, which is
 *                                          UI-only on purpose and named as such
 *
 * This is what stops the gap reopening the next time a tool ships with MCP
 * support and no UI, which is exactly how the sixteen TruffleHog options
 * happened: the per-source targets moved to their own model, the shared ones
 * stayed on Project, and nothing noticed for a year.
 *
 * @vitest-environment node
 */
import { readFileSync, readdirSync, statSync } from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'

import { describe, test, expect } from 'vitest'

import { field, fieldsWhere, type NamedField } from './registry'

const FORM_DIR = fileURLToPath(
  new URL('../../components/projects/ProjectForm/', import.meta.url)
)
const SECTIONS_DIR = path.join(FORM_DIR, 'sections')

/**
 * Which columns each file writes.
 *
 * Four shapes, because four exist in the tree and a parser that knew only the
 * first would report a false gap for every section using the `setField` helper.
 * `RegistryFields` declares its columns as a literal array, which is what makes
 * a generated input visible here at all - a list built at run time would satisfy
 * nothing.
 */
const WRITE_PATTERNS: RegExp[] = [
  /updateField\(\s*'([A-Za-z0-9_]+)'/g,
  /setField\(\s*[A-Za-z0-9_.]+\s*,\s*'([A-Za-z0-9_]+)'/g,
  /\bupdate\(\s*'([A-Za-z0-9_]+)'/g,
  /onChange=\{[^}]*'([A-Za-z0-9_]+)'/g,
]

function formFiles(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const full = path.join(dir, name)
    if (statSync(full).isDirectory()) {
      formFiles(full, out)
      continue
    }
    if (!/\.(ts|tsx)$/.test(name) || name.includes('.test.')) continue
    out.push(full)
  }
  return out
}

/** column -> the section files that write it. */
function formInputs(): Map<string, Set<string>> {
  const out = new Map<string, Set<string>>()
  const add = (key: string, file: string) => {
    if (!field(key)) return
    const set = out.get(key) ?? new Set<string>()
    set.add(file)
    out.set(key, set)
  }
  for (const full of formFiles(FORM_DIR)) {
    const file = path.basename(full).replace(/\.tsx?$/, '')
    const text = readFileSync(full, 'utf8')
    for (const pattern of WRITE_PATTERNS) {
      for (const m of text.matchAll(pattern)) add(m[1], file)
    }
    for (const m of text.matchAll(/updateMultipleFields\(\{([^}]*)\}/g)) {
      for (const k of m[1].matchAll(/([A-Za-z0-9_]+)\s*:/g)) add(k[1], file)
    }
    // `<RegistryFields keys={[...]} />` declares its columns literally.
    for (const m of text.matchAll(/keys=\{\[([^\]]*)\]\}/g)) {
      for (const k of m[1].matchAll(/'([A-Za-z0-9_]+)'/g)) add(k[1], file)
    }
  }
  return out
}

const INPUTS = formInputs()
const SECTION_FILES = new Set(
  readdirSync(SECTIONS_DIR)
    .filter(f => f.endsWith('.tsx') && !f.includes('.test.'))
    .map(f => f.replace(/\.tsx$/, ''))
)

const writable = (): NamedField[] =>
  fieldsWhere(f => f.mcp === 'settable' || f.mcp === 'create_only')

describe('P1a: MCP cannot reach a field the form cannot', () => {
  test('every writable field names a section that exists', () => {
    const problems = writable()
      .filter(f => !f.form_section || !SECTION_FILES.has(f.form_section))
      .map(f => `${f.key}: form_section ${JSON.stringify(f.form_section)}`)
    expect(problems).toEqual([])
  })

  test('every writable field has an input somewhere in the form', () => {
    const problems = writable()
      .filter(f => !INPUTS.has(f.key))
      .map(f => `${f.key} (${f.form_section}) is writable over MCP and has no input`)
    expect(problems).toEqual([])
  })

  test("the input is in the section the registry names", () => {
    // Otherwise the registry answers "where do I change this" with a section
    // that does not contain it, which is worse than not answering.
    const problems = writable()
      .filter(f => INPUTS.has(f.key) && f.form_section)
      .filter(f => !INPUTS.get(f.key)!.has(f.form_section!))
      .map(f => `${f.key}: registry says ${f.form_section}, input is in ${[...INPUTS.get(f.key)!].join(', ')}`)
    expect(problems).toEqual([])
  })
})

/**
 * Columns the FORM may write that the MCP surface refuses, each for a stated
 * reason rather than by omission.
 *
 * `engagement-record` is the big one and the deliberate one: the contract is a
 * person's to write, it carries third-party personal data, and no code enforces
 * it. `secret` and `escalation` are the same shape - an operator supplies a
 * stored token and decides whether the agent may run shell commands, and neither
 * is something a token should be able to grant itself. `upload-managed` is the
 * filename of a file the same request just placed on disk, so the writer and the
 * uploader have to be the same endpoint.
 */
const UI_ONLY_REASONS = new Set([
  'engagement-record', 'secret', 'escalation', 'upload-managed',
])

describe('P1b: the form cannot reach a field MCP cannot, except by classification', () => {
  test('every form input is writable, or UI-only for a named reason', () => {
    const problems: string[] = []
    for (const [key, files] of INPUTS) {
      const spec = field(key)!
      if (spec.mcp !== 'never') continue
      if (spec.deny_reason && UI_ONLY_REASONS.has(spec.deny_reason)) continue
      problems.push(
        `${key} is refused by MCP (${spec.deny_reason ?? 'no reason'}) but written by ` +
        `${[...files].join(', ')}`
      )
    }
    expect(problems).toEqual([])
  })

  test('the derived engagement flag has no input anywhere', () => {
    // P5. A master switch whose only function is to disable other safety fields
    // is a bypass shipped as a checkbox: one write and the ceiling, the
    // exclusions and the window all stop applying while every field still shows
    // its configured value.
    expect(INPUTS.has('roeEnabled')).toBe(false)
    expect(field('roeEnabled')!.form_section).toBeNull()
    expect(field('roeEnabled')!.mcp).toBe('never')
    expect(field('roeEnabled')!.deny_reason).toBe('derived')
  })

  test('updateGraphDb has no input and is refused by MCP', () => {
    // A4.2. Off, the scan still runs and still reaches the target and stores
    // nothing, so every later read reports "nothing found" where the truth is
    // "nothing was written".
    expect(INPUTS.has('updateGraphDb')).toBe(false)
    expect(field('updateGraphDb')!.mcp).toBe('never')
    expect(field('updateGraphDb')!.deny_reason).toBe('not-tuning')
  })
})

describe('P1 is measuring something', () => {
  test('the form writes a substantial number of columns', () => {
    // A parser that matched nothing would make every assertion above vacuous in
    // one direction and impossible in the other; this is the tripwire.
    expect(INPUTS.size).toBeGreaterThan(400)
  })

  test('the engagement limits are reachable from both doors', () => {
    for (const f of fieldsWhere(s => s.group === 'engagement_limits')) {
      if (f.key === 'roeEnabled') continue
      expect(f.mcp, `${f.key} must be settable over MCP`).toBe('settable')
      expect(INPUTS.has(f.key), `${f.key} must have a form input`).toBe(true)
    }
  })

  test('the engagement record is reachable from neither MCP door', () => {
    for (const f of fieldsWhere(s => s.deny_reason === 'engagement-record')) {
      expect(f.mcp, `${f.key} must be closed to MCP`).toBe('never')
    }
  })
})
