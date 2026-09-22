/**
 * The two tools that explain the recon pipeline rather than reading a project.
 *
 * `update_recon_settings` was a 126-field API whose only reference manual was
 * `get_recon_settings`, which returns key names and current values: no meaning,
 * no type, no bounds, no enum domains, no grouping. An agent learned a bound by
 * being refused, one field at a time, and because one bad key refuses the WHOLE
 * call, a batch of guesses applied nothing at all.
 *
 * Both tools follow the `graph_schema` shape: no projectId, no database, no
 * tenant data. They are derived from constants in this build, so they still
 * answer when Neo4j and Postgres are down.
 *
 * Both are now served from `recon_settings/registry.yaml`, which carries the
 * unit, the phase, the traffic class, the engagement-cap flag, the bounds or
 * the validator, and a meaning for every one of the 712 Project columns. The
 * reference manual and the thing it describes are therefore the same file, so
 * an agent that trusts `describe_recon_settings` cannot be surprised by
 * `update_recon_settings`.
 */
import { DENY_REASON_DOC, permittedKeys, settableFieldCount } from '@/lib/reconSettings/filter'
import {
  field,
  fieldsWhere,
  loadRegistry,
  settableFields,
  type RegistryField,
} from '@/lib/reconSettings/registry'
import { SCAN_MODULE_VALUES, SEVERITY_VALUES } from '@/lib/reconSettings/validators'
import { RECON_PRESETS, getPresetById, type ReconPreset } from '@/lib/recon-presets'
import { requireScope } from '@/lib/mcpAuth'
import { McpToolError } from '@/lib/mcp/errors'
import { enforceRate, type McpContext } from '@/lib/mcp/tools'

// --- the settings reference -----------------------------------------------------

export interface SettingDoc {
  key: string
  /** The value shape, joined from Prisma at registry build time. */
  kind: string
  min?: number
  max?: number
  /** The closed set of values a list or enum field accepts, when it has one. */
  values?: readonly string[]
  /** The named validator a free-form value is checked against. */
  validator?: string
  unit: string
  phase: string
  /** none | passive | active: whether writing this sends traffic at the target. */
  traffic: string
  /** True when the engagement rate ceiling rewrites this value at scan start. */
  roeCapped?: boolean
  /** 'unlimited' when 0 is the FASTEST value, not the slowest. */
  zeroMeans?: string
  meaning: string
}

export interface SettingGroup {
  group: string
  settings: SettingDoc[]
}

let cachedGroups: SettingGroup[] | null = null

/** One tool's title, for the group heading. */
function groupName(tool: string): string {
  return loadRegistry().tools[tool]?.title ?? tool
}

function toDoc(key: string, spec: RegistryField): SettingDoc {
  return {
    key,
    kind: spec.type,
    ...(spec.bounds ? { min: spec.bounds.min, max: spec.bounds.max } : {}),
    ...(spec.values ? { values: spec.values } : {}),
    ...(spec.validator ? { validator: spec.validator } : {}),
    unit: spec.unit,
    phase: spec.phase,
    traffic: spec.traffic,
    ...(spec.roe_capped ? { roeCapped: true } : {}),
    ...(spec.zero_means ? { zeroMeans: spec.zero_means } : {}),
    meaning: spec.meaning,
  }
}

/**
 * Every settable field, grouped by the tool it configures.
 *
 * Driven by the REGISTRY, which is also what `update_recon_settings` validates
 * against, so the two cannot disagree. Grouping by tool rather than by an
 * arbitrary documentation section means the group an agent reads is the thing
 * it is configuring.
 */
export function settingGroups(): SettingGroup[] {
  if (cachedGroups) return cachedGroups
  const byTool = new Map<string, SettingDoc[]>()
  for (const f of settableFields()) {
    const list = byTool.get(f.tool)
    const doc = toDoc(f.key, f)
    if (list) list.push(doc)
    else byTool.set(f.tool, [doc])
  }
  cachedGroups = [...byTool.entries()]
    .map(([tool, settings]) => ({ group: groupName(tool), settings }))
    .sort((a, b) => a.group.localeCompare(b.group))
  return cachedGroups
}

/** Test seam: the grouping is cached because the registry is constant per build. */
export function __resetCatalogCache(): void {
  cachedGroups = null
}

const PHASE_NOTES: Record<string, string> = {
  domain_discovery: 'Subdomain enumeration and DNS. The phase every later one draws its hosts from.',
  port_scan: 'Port scanning (Naabu, Masscan) and service/banner identification.',
  http_probe: 'HTTP probing and technology fingerprinting of the hosts found so far.',
  resource_enum: 'Crawling, directory fuzzing, parameter and API discovery.',
  vuln_scan: 'Nuclei templates, takeover checks and the CVE / MITRE enrichment that hangs off them.',
  js_recon: 'JavaScript retrieval and analysis, including source maps and secret extraction.',
}

const NOTES = [
  'Configuration is TWO levels, and this is the mistake to avoid. `scanModules` decides which ' +
    'pipeline PHASES run at all; the per-tool `*Enabled` flags decide which tools run inside a ' +
    'phase. Setting one without the other is a silent no-op.',
  'Concretely: with "port_scan" in scanModules but naabuEnabled and masscanEnabled both false, ' +
    'the pipeline logs "skipping port scan phase" and continues. The scan runs, nothing is port ' +
    'scanned, and no result field says why. Enable the phase AND at least one tool in it.',
  'A phase that is not in scanModules does not run whatever its tools are set to.',
  'Sections listed as standalone scanners are not pipeline phases and are not gated by ' +
    'scanModules at all; they are separate jobs.',
  'These are the fields THIS surface may write. A key absent from them is refused BY NAME, ' +
    'never silently ignored, and one bad key refuses the whole call - so read the bounds ' +
    'rather than probing for them.',
  'One more field set exists and is not listed here: the engagement scope is fixed at ' +
    'creation and is set through create_project. Writing it through update_recon_settings is ' +
    'refused with a pointer to the right tool.',
  'The engagement LIMITS - roeGlobalMaxRps, roeExcludedHosts, the time window, ' +
    'roeForbiddenTools, roeForbiddenCategories, the allow flags and roeMaxSeverityPhase - ARE ' +
    'listed and ARE settable here, in either direction. What keeps them honest is not a ' +
    'write-time direction rule but that every one of them is enforced at scan start whatever ' +
    'the setting says: a ceiling still rewrites all 17 rate fields, an excluded host is still ' +
    'dropped in three places. Read preflight_scope_check to see the resolved configuration.',
  'The engagement RECORD - the client name, the contacts, the dates, the document - is not ' +
    'here and is not writable by any tool on this surface. It is the contract, a person ' +
    'writes it, and it carries third-party personal data.',
  'A value is VALIDATED and then CAPPED, not blocked. A rate above the engagement ceiling is ' +
    'rewritten to the ceiling at scan start, and a container image outside the shipped ' +
    'allowlist is pinned back to the default. get_recon_settings echoes what you wrote; ' +
    'preflight_scope_check reports what will actually run.',
  'Where zeroMeans is "unlimited", 0 is the FASTEST value the field accepts and not the ' +
    'safest. Under an engagement ceiling a 0 there is rewritten to the ceiling.',
  'Settings apply to the NEXT scan. A scan already running read its settings when it started.',
]

/**
 * The shape of the recon configuration, with no values in it.
 *
 * Deliberately no current values: `get_recon_settings` answers that, and
 * duplicating it means two tools disagree the moment one is cached. This one
 * describes the shape, that one reports the state.
 */
export async function describeReconSettings(ctx: McpContext, args: { group?: string } = {}) {
  requireScope(ctx.token, 'recon:read')
  enforceRate(ctx, 'read')

  const all = settingGroups()
  const wanted = args.group?.trim().toLowerCase()
  const groups = wanted
    ? all.filter(g => g.group.toLowerCase().includes(wanted))
    : all

  if (wanted && groups.length === 0) {
    throw new McpToolError(
      `No settings group matches '${args.group}'. Call this tool with no arguments to see the ` +
      `group names.`,
      'bad_args'
    )
  }

  return {
    phases: SCAN_MODULE_VALUES.map(module => ({ module, what: PHASE_NOTES[module] ?? '' })),
    enums: { scanModules: SCAN_MODULE_VALUES, severity: SEVERITY_VALUES },
    groups,
    settableFieldCount: settableFieldCount(),
    dispositions: {
      settable: 'write any time through update_recon_settings',
      create_only: 'the engagement scope: set once by create_project, immutable after',
      never: 'not a pipeline parameter; refused with its class',
    },
    notes: NOTES,
  }
}

// --- the preset catalogue ---------------------------------------------------------

export interface PresetApplicability {
  /** Keys the preset sets that this surface could actually write. */
  appliedCount: number
  deniedCount: number
  deniedByReason: Record<string, number>
  /**
   * True when the denied set includes a field that makes the scan QUIETER.
   * Applying such a preset over MCP would be louder than the preset asked for,
   * while reporting success.
   */
  stealthCritical: boolean
  stealthCriticalFields: string[]
}

/**
 * How much of a preset this surface could actually apply.
 *
 * Far more than it used to. A preset sets fields across the whole project form,
 * and while 126 of 712 columns were settable, between a third and 60% of every
 * preset was refused; for the stealth presets the refused part WAS the stealth,
 * because the rate limits and the passive-mode switches were all in the denied
 * classes.
 *
 * What is still refused is the engagement scope and the engagement record, and
 * those are refused because a preset has no business setting them, not because
 * they are dangerous to tune. The engagement LIMITS are settable but a preset
 * never carries them either: they are a property of one engagement, not of a
 * reusable configuration, so `extractPresetSettings` drops them at capture.
 */
const SETTABLE = new Set(permittedKeys('update'))

export function presetApplicability(preset: ReconPreset): PresetApplicability {
  const keys = Object.keys(preset.parameters ?? {})
  let applied = 0
  const deniedByReason: Record<string, number> = {}
  const stealthCriticalFields: string[] = []

  for (const key of keys) {
    if (SETTABLE.has(key)) {
      applied += 1
      continue
    }
    const spec = field(key)
    const reason = spec ? spec.mcp : 'not-a-column'
    deniedByReason[reason] = (deniedByReason[reason] ?? 0) + 1
    // A refusal only changes the ENGAGEMENT RISK when the refused field is one
    // that would have made the scan quieter. With the scope and the RoE the
    // only refusals left, a half-applied preset can no longer be louder than
    // the preset asked for; it can only be pointed somewhere else, which
    // create_project owns.
    if (spec?.traffic === 'active' && spec.mcp !== 'settable') {
      stealthCriticalFields.push(key)
    }
  }

  return {
    appliedCount: applied,
    deniedCount: keys.length - applied,
    deniedByReason,
    stealthCritical: stealthCriticalFields.length > 0,
    stealthCriticalFields: stealthCriticalFields.sort().slice(0, 20),
  }
}

function presetRow(p: ReconPreset) {
  return {
    id: p.id,
    name: p.name,
    shortDescription: p.shortDescription,
    targetProfile: p.targetProfile,
    environment: p.environment,
    applicability: presetApplicability(p),
  }
}

/**
 * The 26 curated engagement presets, and how much of each this surface could
 * actually apply.
 *
 * `applicability` is the field that earns its place. A preset's `parameters` is
 * a partial over the WHOLE project form, so between a third and 60% of every
 * preset is denied by class here - and for the stealth presets the denied part
 * IS the stealth: the rate limits, the passive-mode switches, the brute-force
 * toggles. An intersection write would leave the caller louder than the preset
 * it asked for while reporting success, which is why this tool reads and does
 * not write.
 */
export async function listReconPresets(ctx: McpContext, args: { presetId?: string } = {}) {
  requireScope(ctx.token, 'recon:read')
  enforceRate(ctx, 'read')

  const id = args.presetId?.trim()
  if (id) {
    const preset = getPresetById(id)
    if (!preset) {
      throw new McpToolError(
        `No preset with id '${id}'. Call this tool with no arguments to list them.`,
        'not_found'
      )
    }
    // The full description only for a named preset: they run to forty-plus
    // lines each, and twenty-six of them at once would dominate the caller's
    // context for no gain.
    return { preset: { ...presetRow(preset), fullDescription: preset.fullDescription } }
  }

  return {
    presets: RECON_PRESETS.map(presetRow),
    deniedReasons: DENY_REASON_DOC,
    notes: [
      'These are read-only here: this tool describes presets, it does not apply them. Write ' +
        'the fields you want with update_recon_settings, which validates each one.',
      'appliedCount is how much of a preset this surface could write. It is most of every ' +
        'preset now that the tuning surface is the whole pipeline; what stays refused is the ' +
        'engagement scope (create_project) and the engagement record, which a preset has no ' +
        'business setting. No preset carries an engagement LIMIT either, by construction.',
      'stealthCritical means the refused part of a preset includes something that sends ' +
        'traffic, so writing the rest would not reproduce the preset\'s posture. It is false ' +
        'for every shipped preset today; treat a true as a reason to hand the preset to an ' +
        'operator rather than half-applying it.',
      'A preset is a starting point, not a scope decision. Read describe_recon_settings for ' +
        'what each field it names actually does before writing it.',
    ],
  }
}
