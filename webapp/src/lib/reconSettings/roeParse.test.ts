/**
 * P3, P12, P14: the parse path is a proposal, validated, with no field list.
 *
 * The document is a third party's text. Before this, the blast radius of a
 * malicious "scope document" was six rate fields copied by a hand-written map;
 * the map is gone and the parser reaches the whole pipeline, so the containment
 * has to be in code rather than in prompt wording.
 *
 * P3 is the one that matters most and is easiest to skip: it is the COMPOSITION
 * check. Both halves look correct in isolation - the MCP validator rejects bad
 * values, and the parse path validates - and what it asserts is that they reject
 * the SAME values, field by field, driven by iterating the registry. Without it
 * the form quietly becomes a way around the validators.
 *
 * @vitest-environment node
 */
import { readFileSync } from 'fs'
import { fileURLToPath } from 'url'

import { describe, test, expect } from 'vitest'

import { filterReconSettings } from './filter'
import { field, fieldsWhere, type NamedField } from './registry'
import { buildParseProposal, currentValuesForDiff, isParseWritable } from './roeParse'

// --- what a document may propose --------------------------------------------------

describe('a parsed document configures the project, it does not re-point it', () => {
  test('every targeting column is refused', () => {
    // Derived rather than listed: the scope columns are `create_only`, so a new
    // targeting column is refused the day it is classified.
    const scope = fieldsWhere(f => f.mcp === 'create_only')
    expect(scope.length).toBeGreaterThan(0)
    for (const f of scope) {
      expect(isParseWritable(f), `${f.key} must not be parse-writable`).toBe(false)
    }
  })

  test('naming a target in the document changes nothing', () => {
    const proposal = buildParseProposal({
      targetDomain: 'attacker-controlled.test',
      targetIps: ['10.0.0.0/8'],
      subdomainList: ['admin'],
      naabuRateLimit: 50,
    })
    expect(proposal.changes.map(c => c.key)).toEqual(['naabuRateLimit'])
    expect(proposal.ignored).toEqual(['subdomainList', 'targetDomain', 'targetIps'])
  })

  test('every engagement LIMIT is proposable', () => {
    for (const f of fieldsWhere(s => s.group === 'engagement_limits')) {
      if (f.key === 'roeEnabled') continue // derived; nothing writes it
      expect(isParseWritable(f), f.key).toBe(true)
    }
  })

  test('every engagement RECORD column is proposable, although MCP refuses it', () => {
    // The document IS the contract, and filling the record from it is the whole
    // point of the upload. The MCP surface is a different door.
    for (const f of fieldsWhere(s => s.deny_reason === 'engagement-record')) {
      expect(isParseWritable(f), f.key).toBe(true)
      expect(f.mcp, f.key).toBe('never')
    }
  })

  test('a credential is never proposable', () => {
    expect(isParseWritable(field('cypherfixGithubToken')!)).toBe(false)
  })

  test('the derived engagement flag is never proposable', () => {
    expect(isParseWritable(field('roeEnabled')!)).toBe(false)
  })
})

// --- P3: the same values, rejected the same way ------------------------------------

/** A value the field's own shape makes illegal. */
function illegalValue(f: NamedField): unknown | undefined {
  if (f.values) return '__not-a-permitted-value__'
  if (f.type === 'int' || f.type === 'float') {
    return f.bounds ? f.bounds.max + 1 : undefined
  }
  if (f.type === 'boolean') return 'not-a-boolean'
  if (f.type === 'string-list' || f.type === 'number-list') return 'not-an-array'
  if (f.type === 'string' && f.validator === 'project_file') return '/etc/shadow'
  if (f.type === 'string' && f.validator === 'http_header') return 'Host: victim.test'
  return undefined
}

describe('P3: a value the MCP validator rejects is rejected by the parse path too', () => {
  const settable = fieldsWhere(f => f.mcp === 'settable')

  test('there is a substantial set to check, or this proves nothing', () => {
    expect(settable.filter(f => illegalValue(f) !== undefined).length).toBeGreaterThan(300)
  })

  test('field by field, driven by the registry rather than by a fixture list', () => {
    const problems: string[] = []
    for (const f of settable) {
      const bad = illegalValue(f)
      if (bad === undefined) continue

      const mcpAccepted = filterReconSettings({ [f.key]: bad }).ok
      const parseAccepted = buildParseProposal({ [f.key]: bad }).changes.length > 0

      if (mcpAccepted !== parseAccepted) {
        problems.push(
          `${f.key}: MCP ${mcpAccepted ? 'accepted' : 'rejected'}, ` +
          `parse ${parseAccepted ? 'accepted' : 'rejected'}`
        )
      }
      if (parseAccepted) problems.push(`${f.key}: the parse path accepted an illegal value`)
    }
    expect(problems).toEqual([])
  })

  test('a rejected value is REPORTED, never dropped', () => {
    // Dropping it silently is how somebody believes a document applied when part
    // of it did not.
    const proposal = buildParseProposal({ naabuRateLimit: 999_999_999, nucleiEnabled: true })
    expect(proposal.changes.map(c => c.key)).toEqual(['nucleiEnabled'])
    expect(proposal.rejected).toHaveLength(1)
    expect(proposal.rejected[0].key).toBe('naabuRateLimit')
    expect(proposal.rejected[0].why).toMatch(/between/)
  })

  test('a legal value at each bound is accepted by both', () => {
    for (const f of fieldsWhere(s => s.mcp === 'settable' && Boolean(s.bounds))) {
      for (const v of [f.bounds!.min, f.bounds!.max]) {
        expect(filterReconSettings({ [f.key]: v }).ok, `${f.key}=${v} over MCP`).toBe(true)
        expect(
          buildParseProposal({ [f.key]: v }).rejected,
          `${f.key}=${v} through the parse path`
        ).toEqual([])
      }
    }
  })
})

describe('only what the diff needs is sent as "what it is now"', () => {
  test('a stored credential is not part of it', () => {
    const narrowed = currentValuesForDiff({
      naabuRateLimit: 50,
      cypherfixGithubToken: 'ghp_secret',
      roeClientName: 'Acme',
    })
    expect(narrowed).toEqual({ naabuRateLimit: 50, roeClientName: 'Acme' })
  })

  test('a scope column is not part of it either', () => {
    // It could not be proposed, so it could never be a change; including it
    // would only widen the request.
    expect(currentValuesForDiff({ targetDomain: 'example.com' })).toEqual({})
  })

  test('a key that is not a column is dropped', () => {
    expect(currentValuesForDiff({ notAColumn: 1 })).toEqual({})
  })

  test('it is a registry query, so it covers every proposable field', () => {
    const everyProposable = Object.fromEntries(
      fieldsWhere(f => isParseWritable(f)).map(f => [f.key, 'x'])
    )
    expect(Object.keys(currentValuesForDiff(everyProposable)).length)
      .toBe(Object.keys(everyProposable).length)
  })
})

// --- the result is a diff, not a write -----------------------------------------------

describe('the parse result is a proposal a person confirms', () => {
  test('a value equal to what is stored is not a change', () => {
    const proposal = buildParseProposal({ naabuRateLimit: 50 }, { naabuRateLimit: 50 })
    expect(proposal.changes).toEqual([])
  })

  test('a change carries the before, the after and where to look', () => {
    const proposal = buildParseProposal({ naabuRateLimit: 5 }, { naabuRateLimit: 50 })
    expect(proposal.changes).toHaveLength(1)
    const change = proposal.changes[0]
    expect(change.before).toBe(50)
    expect(change.after).toBe(5)
    expect(change.section).toBe(field('naabuRateLimit')!.form_section)
    expect(change.meaning.length).toBeGreaterThan(0)
  })

  test('an unchanged list is not reported as a change', () => {
    const proposal = buildParseProposal(
      { scanModules: ['port_scan', 'http_probe'] },
      { scanModules: ['port_scan', 'http_probe'] }
    )
    expect(proposal.changes).toEqual([])
  })

  test('a null or absent value proposes nothing', () => {
    expect(buildParseProposal({ naabuRateLimit: null }).changes).toEqual([])
    expect(buildParseProposal({ naabuRateLimit: undefined }).changes).toEqual([])
  })
})

// --- P12: no hand-written field list survives anywhere in the path ---------------------

/**
 * The parse path, narrowed to the code that MOVES parsed values.
 *
 * `RoeSection.tsx` is scoped to its two handlers rather than taken whole,
 * because the same file is also the FORM for the engagement record: it names
 * `roeClientName` and two dozen siblings as inputs, which is what a form does.
 * What must contain no field names is the code that carries a parsed value from
 * the response into the form, which is where the 49-key `fieldMap` lived.
 */
function handlersOf(text: string): string {
  const out: string[] = []
  for (const name of ['handleFileUpload', 'applyProposal']) {
    const start = text.indexOf(`const ${name} =`)
    if (start < 0) continue
    // To the next top-level `const ` at the same indentation.
    const rest = text.slice(start + 1)
    const end = rest.search(/\n  const [a-zA-Z]/)
    out.push(end < 0 ? rest : rest.slice(0, end))
  }
  return out.join('\n')
}

const ROE_SECTION = readFileSync(
  fileURLToPath(
    new URL('../../components/projects/ProjectForm/sections/RoeSection.tsx', import.meta.url)
  ),
  'utf8'
)

const PARSE_PATH = [
  { rel: 'RoeSection.tsx (its parse handlers)', text: handlersOf(ROE_SECTION) },
  ...['../../app/api/roe/parse/route.ts', './roeParse.ts'].map(rel => ({
    rel,
    text: readFileSync(fileURLToPath(new URL(rel, import.meta.url)), 'utf8'),
  })),
]

describe('P12: field names appear in the parse path in exactly one place', () => {
  test('the handlers were found, or this test reads an empty string', () => {
    expect(PARSE_PATH[0].text.length).toBeGreaterThan(200)
  })

  test('no file in the path names three or more registry columns', () => {
    // Two is the tolerance, not zero: a file may legitimately mention one or two
    // columns in prose. THREE is a list, and a list is the thing that goes stale
    // - the map this replaced held 49 of them, kept in step with a prompt by
    // hand. With no hand-written list there is nothing left to forget.
    const problems: string[] = []
    for (const { rel, text } of PARSE_PATH) {
      const named = new Set<string>()
      for (const m of text.matchAll(/['"]([a-zA-Z][a-zA-Z0-9]{5,})['"]/g)) {
        if (field(m[1])) named.add(m[1])
      }
      if (named.size >= 3) problems.push(`${rel}: names ${[...named].sort().join(', ')}`)
    }
    expect(problems).toEqual([])
  })

  test('the component does not map parsed keys onto form keys', () => {
    expect(ROE_SECTION).not.toMatch(/fieldMap/)
    // It copies whatever the handler returns, key for key.
    expect(ROE_SECTION).toMatch(/for \(const change of proposal\.changes\)/)
  })
})

// --- P14: the handler writes only what the registry permits ----------------------------

describe('P14: the handler is driven by the registry, not by a fixture list', () => {
  test('every settable field is proposable, without being named anywhere', () => {
    const notProposable = fieldsWhere(f => f.mcp === 'settable')
      .filter(f => !isParseWritable(f))
      .map(f => f.key)
    expect(notProposable).toEqual([])
  })

  test('a key that is not a column at all is ignored, and said to be', () => {
    const proposal = buildParseProposal({ definitelyNotAColumn: 1, naabuRateLimit: 5 })
    expect(proposal.ignored).toEqual(['definitelyNotAColumn'])
    expect(proposal.changes.map(c => c.key)).toEqual(['naabuRateLimit'])
  })
})
