/**
 * Which `Project` columns an MCP tool may RETURN.
 *
 * The write side has been a positive, frozen, fully-classified set since the
 * surface shipped. The read side had nothing: `get_recon_settings` returns the
 * WRITE allowlist, which quietly conflated "what you may change" with "what you
 * may see". That worked while the settings subset was the only project read.
 *
 * It stops working now, because the surface reads project-adjacent data in
 * several more places, and the 700-column problem is about to repeat in the
 * other direction: someone adds a column holding client information and a read
 * tool with a generous `select` starts returning it.
 *
 * The Rules of Engagement fields make that concrete rather than theoretical.
 * They are all denied for WRITE with the reason "the encoded engagement
 * agreement", and among them are `roeClientContactName`,
 * `roeClientContactEmail`, `roeClientContactPhone` and `roeEmergencyContact` -
 * third-party personal data - plus `roeDocumentData`, a binary blob, and
 * `roeRawText`. A read tool that selected "the RoE" without an explicit field
 * list would hand an external agent a client's phone number.
 *
 * The list is now a REGISTRY QUERY rather than a second classification table.
 * `readable: false` is explicit per column in `recon_settings/registry.yaml`
 * and everything else is readable, which inverts the old default deliberately:
 * a column nobody classified is far more likely to be ordinary recon tuning
 * than a credential, and the credentials and the personal data are named. The
 * registry's own tests are what stop the named set shrinking by accident.
 */
import {
  mcpReadableFields,
  readDeniedFields,
} from '@/lib/reconSettings/registry'

/**
 * Columns withheld from every MCP read, with the reason, for the docs and the
 * error message. Derived: this is a view of the registry, not a second copy.
 */
export const MCP_UNREADABLE_PROJECT_FIELDS: Readonly<Record<string, string>> = Object.freeze(
  Object.fromEntries(
    readDeniedFields().map(f => [f.key, f.read_deny_reason ?? 'withheld'])
  )
)

/** Every `Project` column an MCP tool may return. */
export const MCP_READABLE_PROJECT_FIELDS: ReadonlySet<string> = Object.freeze(
  new Set<string>(mcpReadableFields().map(f => f.key))
)

export function isReadableProjectField(key: string): boolean {
  return MCP_READABLE_PROJECT_FIELDS.has(key)
}

/**
 * Narrow a Prisma `select` to the readable set, naming anything refused.
 *
 * A tool builds its own `select`; this is the assertion that it did not reach
 * past the boundary, so the check lives beside the field list rather than in
 * each caller's head.
 */
export function assertReadableSelect(select: Record<string, unknown>, tool: string): void {
  const forbidden = Object.keys(select).filter(k => !isReadableProjectField(k))
  if (forbidden.length > 0) {
    throw new Error(
      `[mcp] ${tool} selects Project column(s) that are not MCP-readable: ` +
      `${forbidden.join(', ')}. Each is withheld from every read on this surface ` +
      `(credential, third-party personal data, or the engagement document itself); ` +
      `see readable: false in recon_settings/registry.yaml.`
    )
  }
}
