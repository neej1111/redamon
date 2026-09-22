/**
 * What a parsed Rules of Engagement document may propose, and how it is checked.
 *
 * The document is UNTRUSTED input. A target can hand you a "scope document", and
 * an LLM reading it is not a sanitiser. Before this, the blast radius was six
 * rate fields copied by a hand-written map; the map is gone and the parser can
 * reach the whole pipeline, so the containment has to be in code rather than in
 * prompt wording.
 *
 * Three rules, and all three are enforced here:
 *
 *   1. SCOPE IS NEVER WRITABLE. `targetDomain`, `targetIps`, `domainBatchHosts`
 *      and `subdomainList` are all `create_only`, and the check below is a
 *      registry query rather than a list of those four names, so a new targeting
 *      column is refused the day it is classified. A parsed document may
 *      configure the platform; it may not re-point it.
 *   2. EVERY VALUE IS VALIDATED, against the same registry bounds and validators
 *      an MCP write goes through. A rejected value is REPORTED rather than
 *      dropped: silently discarding it is how a person believes a document
 *      applied when part of it did not.
 *   3. THE RESULT IS A PROPOSAL. Nothing here writes. It returns a diff for a
 *      person to confirm.
 *
 * There is no literal field-name list in this file, and there must never be one.
 * Field names appear in the parse path in exactly one place: the registry.
 */
import { field, type RegistryField } from './registry'
import { validateValue } from './validators'

export interface ParseChange {
  key: string
  /** What the project holds now, when the caller supplied it. */
  before?: unknown
  after: unknown
  /** The registry's one-line description, so the confirmation diff can explain itself. */
  meaning: string
  /** Which form section the change lands in, so the reviewer knows where to look. */
  section: string | null
}

export interface ParseRejection {
  key: string
  value: unknown
  why: string
}

export interface ParseProposal {
  changes: ParseChange[]
  /** Values the document proposed that the validators refused. Shown, never dropped. */
  rejected: ParseRejection[]
  /** Keys the parser returned that no writable column matches. */
  ignored: string[]
}

/**
 * May a parsed document propose a value for this column?
 *
 * Mirrors `is_parse_writable` in `recon_settings/roe_prompt.py`, and the two are
 * pinned together by the field list the generated prompt carries: P14 iterates
 * the registry rather than a fixture, so a disagreement fails rather than
 * quietly narrowing what a document can do.
 */
export function isParseWritable(spec: RegistryField): boolean {
  if (spec.deny_reason === 'engagement-record') return true
  return spec.mcp === 'settable'
}

/**
 * The subset of the form worth sending as "what it is now".
 *
 * The diff only needs the fields a document could propose, so sending the whole
 * form is both a bigger request and a wider exposure than the job requires: the
 * form's data carries stored credentials like `cypherfixGithubToken`. They never
 * left the browser for the model - the agent receives the document text and
 * nothing else - but a value that does not need to travel should not travel.
 *
 * Derived from the registry, so it needs no list of field names and cannot go
 * stale against one.
 */
export function currentValuesForDiff(
  form: Record<string, unknown>
): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(form)) {
    const spec = field(key)
    if (spec && isParseWritable(spec)) out[key] = value
  }
  return out
}

/**
 * Turn what the parser returned into a proposal.
 *
 * `current` is the project's present values, when the caller has them; it is
 * what makes the result a DIFF rather than a list of assignments, and a value
 * equal to what is already stored is not a change at all.
 */
export function buildParseProposal(
  parsed: Record<string, unknown>,
  current: Record<string, unknown> = {}
): ParseProposal {
  const changes: ParseChange[] = []
  const rejected: ParseRejection[] = []
  const ignored: string[] = []

  for (const key of Object.keys(parsed).sort()) {
    const value = parsed[key]
    if (value === null || value === undefined) continue

    const spec = field(key)
    if (!spec || !isParseWritable(spec)) {
      ignored.push(key)
      continue
    }

    const problem = validateValue(key, spec, value, undefined)
    if (problem) {
      rejected.push({ key, value, why: problem })
      continue
    }

    const before = Object.prototype.hasOwnProperty.call(current, key) ? current[key] : undefined
    if (before !== undefined && sameValue(before, value)) continue

    changes.push({
      key,
      ...(before !== undefined ? { before } : {}),
      after: value,
      meaning: spec.meaning,
      section: spec.form_section,
    })
  }

  return { changes, rejected, ignored }
}

/** Structural equality, so an unchanged list is not reported as a change. */
function sameValue(a: unknown, b: unknown): boolean {
  if (a === b) return true
  if (Array.isArray(a) && Array.isArray(b)) {
    return a.length === b.length && a.every((v, i) => sameValue(v, b[i]))
  }
  if (a && b && typeof a === 'object' && typeof b === 'object') {
    return JSON.stringify(a) === JSON.stringify(b)
  }
  return false
}

/**
 * The most settings one document may change before the parse is disbelieved.
 *
 * A Rules of Engagement document constrains an engagement. It does not
 * reconfigure a scan pipeline. Across forty real disclosure policies and twenty
 * synthetic ones, the proposal sizes were 2 to 14 fields - and then one 15,000
 * character policy came back with 631 of the 658 fields in the prompt, almost
 * all of them zeroes and falses, none of them rejected by per-field validation
 * because each value was individually legal.
 *
 * That is a model failure rather than a document, and per-field validation
 * cannot see it: the signal is the SHAPE of the answer, not any one value. Left
 * alone it either buries a real diff in a 631-row table for a human to approve,
 * or on a non-interactive path rewrites the project wholesale.
 *
 * 60 is roughly four times the largest legitimate proposal observed and an order
 * of magnitude below the failure.
 */
export const MAX_PROPOSED_CHANGES = 60

/** Is this proposal so large it is evidence the parse went wrong? */
export function proposalIsImplausible(changeCount: number): boolean {
  return changeCount > MAX_PROPOSED_CHANGES
}
