/**
 * What a project preset may and may not carry.
 *
 * A preset is a reusable recon CONFIGURATION. Two classes of column are not
 * that, and letting either ride along is how a preset saved from project A
 * quietly re-scopes project B:
 *
 *   target identity   the domain, the address list, the batch, the project's
 *                     own name. Listed by name below, because they have no
 *                     single registry classification. The UPLOADED FILES are
 *                     queried instead: a preset that named one would point a
 *                     second project at a file only the first one uploaded.
 *   the engagement    its LIMITS (the rate ceiling, the excluded hosts, the
 *                     scanning window, the agent's denylists) and its RECORD
 *                     (the client name, the contacts, the dates, the document
 *                     text). Queried from the registry, never matched on a name
 *                     prefix.
 *
 * The prefix distinction is the one worth stating. These columns are still
 * called `roe*` and will stay called that - renaming fifteen columns buys
 * nothing and costs a migration - but they are no longer "the RoE block": the
 * limits are ordinary settings now and the record is the contract. A guard
 * written as `key.startsWith('roe')` survives that reclassification by accident,
 * so the next person to rename a column or reclassify a field silently removes a
 * live control. Asking the registry means the guard follows the classification.
 */
import {
  engagementLimitFields,
  engagementRecordFields,
  fieldsWhere,
} from '@/lib/reconSettings/registry'

/** Target identity, binary blobs and per-project files. */
const TARGET_IDENTITY_FIELDS = [
  // Target-specific (user-requested exclusions)
  'targetDomain',
  'subdomainList',
  'ipMode',
  'targetIps',
  // Domain batch is target identity too: without these a preset saved from a
  // batch project carries that project's hostname list, and applying it silently
  // flips another project into batch mode pointed at scope its owner never
  // entered there.
  'domainBatchMode',
  'domainBatchHosts',
  'domainBatchGroups',
  // Project identity
  'name',
  'description',
  // Per-project custom wordlists (text content tied to the project, not reusable across targets)
  'vhostSniCustomWordlist',
]

/**
 * Every column a preset must never capture or apply.
 *
 * The engagement half is a registry QUERY rather than a list, so reclassifying a
 * field updates this set with it. `project-preset-utils.test.ts` asserts the two
 * are equal, which is what stops the query being replaced by a snapshot of its
 * answer.
 */
export const PRESET_EXCLUDED_FIELDS: ReadonlySet<string> = new Set([
  ...TARGET_IDENTITY_FIELDS,
  ...engagementLimitFields().map(f => f.key),
  ...engagementRecordFields().map(f => f.key),
  // Every file reference, including the RoE document's own bytes. These name a
  // file that one project uploaded, so carrying one into another project points
  // it at content its owner never supplied.
  ...fieldsWhere(f => f.deny_reason === 'upload-managed').map(f => f.key),
])

/**
 * Extract preset-safe settings from form data by stripping excluded fields.
 */
export function extractPresetSettings(
  formData: Record<string, unknown>
): Record<string, unknown> {
  const settings: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(formData)) {
    if (!PRESET_EXCLUDED_FIELDS.has(key)) {
      settings[key] = value
    }
  }
  return settings
}

/**
 * Strip the excluded columns from a preset being APPLIED, not just captured.
 *
 * Both halves are needed and neither is sufficient. Excluding at capture stops
 * NEW presets carrying the engagement; excluding at apply neutralises every
 * preset saved before this shipped, which already contains 37 of these columns
 * including the rate ceiling and the client's phone number.
 */
export function stripExcludedOnApply(
  settings: Record<string, unknown>
): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(settings)) {
    if (!PRESET_EXCLUDED_FIELDS.has(key)) out[key] = value
  }
  return out
}
