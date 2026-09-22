/**
 * Result post-validation: defence in depth against a tenant-filter regression.
 *
 * `scope_query` was designed for the Kali sandbox, which is semi-trusted and
 * loopback-only. Handing the same primitive to an internet-reachable caller
 * widens it, and the tenant filter HAS failed once already: an unlabelled
 * `MATCH (n)` used to bypass `inject_tenant_filter` entirely and return another
 * project's data. A future regression there would become a REMOTE cross-tenant
 * breach rather than a sandbox-local one.
 *
 * So every node and relationship that comes back is checked again here, on the
 * way out, against the tenant the caller actually proved. A violation drops the
 * WHOLE response - not the offending row - because a partial answer would be
 * indistinguishable from a complete one and would be acted on as if it were.
 *
 * Accepted, documented residual: a scalar projection (`RETURN i.address`) has
 * no tenant keys to check. Those are bounded by `scope_query` alone.
 */

/**
 * Untenanted global reference nodes. They deliberately carry no user_id or
 * project_id because they are shared vulnerability/technique reference data,
 * not anyone's findings.
 */
export const GLOBAL_REFERENCE_LABELS: ReadonlySet<string> = new Set([
  'CVE',
  'MitreData',
  'Capec',
])

export class TenantViolation extends Error {
  constructor(
    public detail: {
      kind: 'node' | 'relationship'
      labels: string[]
      sawUserId: unknown
      sawProjectId: unknown
    }
  ) {
    super('graph result failed tenant post-validation')
    this.name = 'TenantViolation'
  }
}

interface CoercedNode {
  _kind?: string
  labels?: unknown
  properties?: Record<string, unknown>
}

function isGlobalReference(labels: string[]): boolean {
  // A node qualifies only if EVERY label is a global reference label: a
  // dual-labelled node carrying one tenanted label is still tenant data.
  return labels.length > 0 && labels.every(l => GLOBAL_REFERENCE_LABELS.has(l))
}

/**
 * Does this map carry tenant-key-shaped fields? If so it is tenant data
 * whatever it claims to be, and it is checked.
 *
 * `RETURN properties(n)` yields a plain map with `user_id` / `project_id` and
 * NO `_kind`, so keying the check on `_kind` alone missed it entirely.
 */
function carriesTenantKeys(obj: Record<string, unknown>): boolean {
  return 'user_id' in obj || 'project_id' in obj
}

function tenantMismatch(
  sawUserId: unknown,
  sawProjectId: unknown,
  userId: string,
  projectId: string
): boolean {
  return sawUserId !== userId || sawProjectId !== projectId
}

function checkEntity(value: CoercedNode, userId: string, projectId: string): void {
  const kind = value._kind === 'relationship' ? 'relationship' : 'node'
  const labels = Array.isArray(value.labels) ? value.labels.map(String) : []
  if (kind === 'node' && isGlobalReference(labels)) return

  const props = value.properties ?? {}
  const sawUserId = props.user_id
  const sawProjectId = props.project_id

  // A relationship between two tenanted nodes may legitimately carry no keys
  // of its own; only a MISMATCH is a violation there. A node with no keys at
  // all is not: every entity node is written with the tenant key, so a missing
  // one means the filter did not apply.
  if (kind === 'relationship' && sawUserId === undefined && sawProjectId === undefined) return

  if (tenantMismatch(sawUserId, sawProjectId, userId, projectId)) {
    throw new TenantViolation({ kind, labels, sawUserId, sawProjectId })
  }
}

/**
 * Walk EVERY value. Nothing here short-circuits on `_kind`.
 *
 * `_kind` and `labels` are produced by the agent's coercion, but a caller can
 * author a map with those exact keys - `RETURN {_kind:"node", labels:["CVE"],
 * loot: n}` is legal Cypher - and the coercion passes any map through verbatim.
 * Treating `_kind` as a trusted discriminator therefore let the attacker this
 * guard exists to stop declare their own payload exempt and, worse, stop the
 * walk before the smuggled node underneath was ever looked at.
 *
 * So: a map that looks like an entity is CHECKED, a map that carries tenant
 * keys is CHECKED, and either way the walk continues into its values.
 */
function walk(value: unknown, userId: string, projectId: string): void {
  if (value === null || typeof value !== 'object') return
  if (Array.isArray(value)) {
    for (const v of value) walk(v, userId, projectId)
    return
  }
  const obj = value as CoercedNode & Record<string, unknown>

  if (obj._kind === 'node' || obj._kind === 'relationship') {
    checkEntity(obj, userId, projectId)
  } else if (carriesTenantKeys(obj)) {
    // A bare property map (properties(n), or a hand-built map). It claims no
    // kind, so no global-reference exemption applies to it.
    if (tenantMismatch(obj.user_id, obj.project_id, userId, projectId)) {
      throw new TenantViolation({
        kind: 'node',
        labels: [],
        sawUserId: obj.user_id,
        sawProjectId: obj.project_id,
      })
    }
  }

  // ALWAYS descend, including into a map that just passed as an entity: a
  // smuggled node can be nested under any key of a caller-authored map.
  for (const v of Object.values(obj)) walk(v, userId, projectId)
}

/**
 * Throws `TenantViolation` if any returned entity belongs to another tenant.
 * Call it on the records BEFORE they reach the caller.
 */
export function assertTenantScoped(
  records: unknown,
  userId: string,
  projectId: string
): void {
  walk(records, userId, projectId)
}
