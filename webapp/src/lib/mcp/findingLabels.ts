/**
 * The labels that count as "a finding", for the inbound MCP surface.
 *
 * A finding is not one node type: it is eight unrelated labels written by eight
 * different scanners. Any tool that reports on findings has to know all eight,
 * and a tool that knows seven produces a false negative rather than an error.
 *
 * Keep in sync with `MUTEABLE_LABELS` in
 * `graph_db/mixins/recon/triage_mixin.py` and with `MUTEABLE` in
 * `webapp/src/lib/muteEnforcement.test.ts`.
 */
export const MUTEABLE_FINDING_LABELS = Object.freeze([
  'Vulnerability',
  'JsReconFinding',
  'Secret',
  'MultiscannerFinding',
  'GithubSecret',
  'GithubSensitiveFile',
  'MalPackageFinding',
  'ExploitGvm',
])

/**
 * Count the findings a later scan stopped reporting, per the census's own rules.
 *
 * `_GRAPH_SUMMARY_NODES_CYPHER` excludes both suppressed (`:Muted`) and
 * superseded (`stale_since`) findings from the counts and says nothing about
 * it, while raw Cypher includes stale ones by default. An agent cross-checking
 * a `graph_summary` count against a `query_graph` count therefore got two
 * different numbers with no way to learn why. This is the missing half of that
 * explanation.
 *
 * Two things about the shape are load-bearing, both verified against
 * `graph_db/tenant_filter.py`:
 *
 *  - the query must NOT name the `Muted` label. `scope_query` refuses any query
 *    that so much as mentions it, and injects `!Muted` into every pattern
 *    itself, so the count is already "stale but not suppressed".
 *  - every pattern carries a LABEL. A census is the one shape
 *    `has_labelled_node_pattern` hard-rejects, and an unlabelled `(n)` would be
 *    refused outright.
 *
 * `OPTIONAL MATCH` rather than `MATCH`: a plain MATCH that finds nothing yields
 * zero rows, which would take the whole chained aggregation to zero rows and
 * return no answer at all for a project whose first label happens to be clean.
 */
export function staleFindingsCypher(): string {
  const lines: string[] = []
  const carried: string[] = []
  MUTEABLE_FINDING_LABELS.forEach((label, i) => {
    const v = `f${i}`
    const prefix = carried.length ? `${carried.join(', ')}, ` : ''
    lines.push(`OPTIONAL MATCH (${v}:${label}) WHERE ${v}.stale_since IS NOT NULL`)
    lines.push(`WITH ${prefix}count(${v}) AS c${i}`)
    carried.push(`c${i}`)
  })
  lines.push(`RETURN ${carried.join(' + ')} AS stale`)
  return lines.join('\n')
}
