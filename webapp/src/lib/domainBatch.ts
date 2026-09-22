/**
 * Domain batch: turn a flat hostname list into ordered domain groups.
 *
 * This is the ONLY implementation of the grouping rule. The form renders its
 * preview from it and the project routes re-derive `domainBatchGroups` from it
 * server-side, so what the operator approved is literally what the pipeline runs
 * and a crafted `domainBatchGroups` in a request body is never trusted.
 *
 * The rule is deliberately "the last two labels are the domain", NOT a public
 * suffix list: it is the same thing an operator does by hand when filling the
 * single-domain form (target = the domain, everything else = subdomain prefixes),
 * so a batch and a hand-built project scan identically. `foo.example.co.uk`
 * therefore groups under `co.uk`. That is a known, tested consequence, not an
 * oversight - see the tests. A WILDCARD entry is the one exception: it consults
 * PUBLIC_SUFFIXES, because "scan the host you listed" survives that quirk and
 * "enumerate everything under co.uk" does not.
 *
 * Group order is first-appearance order, and it is the RUN order: the operator
 * approves a list in the preview and the pipeline walks it top to bottom.
 */

/** Prefixes are stored with a trailing dot, and "." means the root domain itself,
 *  matching toStoredPrefixes() in ProjectForm/sections/TargetSection.tsx. */
export const ROOT_DOMAIN_PREFIX = '.'

/** The second sentinel: "enumerate this domain", i.e. run the same full subdomain
 *  discovery a Single Domain project runs. Written by a `*.domain.com` entry and
 *  read by parse_target() in recon/main.py. Never a hostname. */
export const WILDCARD_PREFIX = '*'

/**
 * Multi-label public suffixes, for wildcard entries ONLY.
 *
 * rootOf() is deliberately last-two-labels (see the header), so `acme.co.uk`
 * reduces to `co.uk`. For a literal entry that is a harmless, tested quirk: the
 * group still scans exactly the host that was listed. For a WILDCARD it is not
 * harmless - `*.co.uk` would mean "enumerate every subdomain of co.uk", i.e. a
 * whole public suffix the operator never authorized.
 *
 * Mirror of `_MULTI_LABEL_SUFFIXES` in recon/main_recon_modules/origin_discovery.py,
 * which exists for the same reason - keep the two in sync. Curated subset of the
 * Public Suffix List; it covers the common cases, not every entry.
 */
const PUBLIC_SUFFIXES: ReadonlySet<string> = new Set([
  'co.uk', 'org.uk', 'me.uk', 'ltd.uk', 'plc.uk', 'net.uk', 'sch.uk', 'ac.uk', 'gov.uk', 'nhs.uk',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'asn.au', 'id.au',
  'co.nz', 'net.nz', 'org.nz', 'govt.nz', 'ac.nz', 'school.nz', 'geek.nz',
  'co.za', 'org.za', 'net.za', 'gov.za', 'ac.za', 'web.za',
  'co.jp', 'or.jp', 'ne.jp', 'ac.jp', 'go.jp', 'ad.jp', 'ed.jp', 'gr.jp', 'lg.jp',
  'com.br', 'net.br', 'org.br', 'gov.br', 'edu.br',
  'co.in', 'net.in', 'org.in', 'gen.in', 'firm.in', 'ind.in', 'gov.in', 'ac.in', 'edu.in', 'res.in',
  'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn', 'ac.cn',
  'co.kr', 'or.kr', 'ne.kr', 're.kr', 'pe.kr', 'go.kr', 'ac.kr',
  'com.ru', 'net.ru', 'org.ru', 'msk.ru', 'spb.ru',
  'com.tr', 'net.tr', 'org.tr', 'gov.tr', 'edu.tr', 'bel.tr',
  'com.mx', 'net.mx', 'org.mx', 'gob.mx', 'edu.mx',
  'com.ar', 'net.ar', 'org.ar', 'gob.ar', 'edu.ar',
  'com.sg', 'net.sg', 'org.sg', 'gov.sg', 'edu.sg',
  'com.hk', 'net.hk', 'org.hk', 'gov.hk', 'edu.hk', 'idv.hk',
  'co.il', 'org.il', 'net.il', 'ac.il', 'gov.il', 'muni.il', 'k12.il',
  'co.id', 'or.id', 'net.id', 'web.id', 'ac.id', 'go.id', 'sch.id', 'my.id',
  'co.th', 'or.th', 'net.th', 'in.th', 'ac.th', 'go.th',
  'com.tw', 'net.tw', 'org.tw', 'gov.tw', 'edu.tw', 'idv.tw',
  'com.ua', 'net.ua', 'org.ua', 'in.ua', 'kiev.ua',
  'com.pl', 'net.pl', 'org.pl', 'edu.pl', 'gov.pl',
  'com.gr', 'net.gr', 'org.gr', 'edu.gr', 'gov.gr',
  'com.pk', 'net.pk', 'org.pk', 'gov.pk', 'edu.pk',
  'com.eg', 'net.eg', 'org.eg', 'gov.eg', 'edu.eg',
  'com.sa', 'net.sa', 'org.sa', 'gov.sa', 'edu.sa',
  'com.ph', 'net.ph', 'org.ph', 'gov.ph', 'edu.ph',
  'com.my', 'net.my', 'org.my', 'gov.my', 'edu.my',
  'com.ng', 'net.ng', 'org.ng', 'gov.ng', 'edu.ng',
])

export interface DomainGroup {
  /** The registrable domain, e.g. "domain3.com". */
  rootDomain: string
  /** Stored-form prefixes, e.g. ["sub3.", "suba.sub3."], ["."] for the bare root,
   *  or ["*"] for "enumerate this domain". */
  prefixes: string[]
  /** The normalized hostnames that produced this group, in input order. A
   *  wildcard entry contributes its canonical token `*.<root>`. */
  hosts: string[]
  /** True when any entry asked for full enumeration of this domain. Derived, for
   *  rendering only: the Python side re-derives it from `'*' in prefixes` and
   *  never trusts this field (see _parse_domain_batch_groups). */
  wildcard: boolean
}

export interface GroupingResult {
  groups: DomainGroup[]
  /** Entries rejected verbatim as the operator typed them, for the UI to show. */
  invalid: string[]
}

/**
 * Caps on one batch. MAX_BATCH_GROUPS mirrors supplyChainOrgMaxRepos (the org
 * batch's own fan-out cap): without one, a pasted list becomes a single run that
 * holds the project's one scan slot for weeks with no visible end.
 *
 * These bound the TYPED list, not the run. A wildcard group discovers hosts the
 * list never named, so neither cap bounds run length any more; that is carried
 * by the preview badge and the cost warning in TargetSection instead.
 */
export const MAX_BATCH_HOSTS = 500
export const MAX_BATCH_GROUPS = 50

/**
 * Everything a hostname may contain once normalized. This is the choke point for
 * untrusted input: a host reaches a Cypher MERGE, a scan target and (via its
 * group slug) a filename, so anything outside this set is REJECTED rather than
 * sanitized - silently stripping characters would scan a different host than the
 * operator read in the preview.
 */
const HOSTNAME_CHARSET = /^[a-z0-9.-]+$/

/** Strip the things people paste around a hostname: scheme, credentials, path,
 *  query, port, surrounding whitespace and a trailing root dot. */
function normalizeHost(raw: string): string {
  let h = raw.trim().toLowerCase()
  if (!h) return ''
  h = h.replace(/^[a-z][a-z0-9+.-]*:\/\//, '')  // scheme
  h = h.split('/')[0].split('?')[0].split('#')[0]  // path / query / fragment
  const at = h.lastIndexOf('@')
  if (at !== -1) h = h.slice(at + 1)  // credentials
  h = h.split(':')[0]  // port
  h = h.replace(/\.+$/, '')  // trailing root dot
  return h
}

/** The last two labels. "suba.sub3.domain3.com" -> "domain3.com". */
function rootOf(host: string): string {
  const labels = host.split('.')
  return labels.slice(-2).join('.')
}

/**
 * Split a leading wildcard marker off an entry, before any charset test.
 *
 * `*` is recognized in exactly ONE place - here - so HOSTNAME_CHARSET stays free
 * of metacharacters and every other gate keeps rejecting a stray star. Both
 * spellings an operator might paste are accepted and mean the same thing:
 * `*.example.com` (bug-bounty scope notation) and `*example.com`.
 *
 * Only ONE marker is stripped, so `**.example.com` keeps a `*` and is then
 * rejected by the charset test like any other malformed entry.
 */
export function splitWildcard(host: string): { wildcard: boolean; rest: string } {
  if (host.startsWith('*.')) return { wildcard: true, rest: host.slice(2) }
  if (host.startsWith('*')) return { wildcard: true, rest: host.slice(1) }
  return { wildcard: false, rest: host }
}

/**
 * A wildcard may only name a domain we can actually enumerate: the registrable
 * domain itself, and not a public suffix. `*.sub.example.com` is REJECTED rather
 * than widened to `*.example.com` - silently scanning more than the operator
 * wrote is the one repair this module refuses to make.
 */
function isUsableWildcardRoot(host: string): boolean {
  return rootOf(host) === host && !PUBLIC_SUFFIXES.has(host)
}

function isUsableHost(host: string): boolean {
  if (!host || !HOSTNAME_CHARSET.test(host)) return false
  const labels = host.split('.')
  // A single label is not a scannable target and has no derivable domain.
  if (labels.length < 2) return false
  // No empty labels ("a..b"), no label starting or ending with a hyphen, and a
  // TLD of at least two letters - the same shape REGEX_DOMAIN enforces.
  if (labels.some(l => l.length === 0 || l.length > 63)) return false
  if (labels.some(l => l.startsWith('-') || l.endsWith('-'))) return false
  if (!/^[a-z]{2,}$/.test(labels[labels.length - 1])) return false
  return true
}

/**
 * Group hostnames by their registrable domain, preserving first-appearance order.
 * Duplicates are dropped. Entries that cannot be grouped are returned in
 * `invalid` as the operator typed them, so the UI can point at the offending line.
 */
export function groupHostsByRootDomain(hosts: readonly string[]): GroupingResult {
  const groups: DomainGroup[] = []
  const byRoot = new Map<string, DomainGroup>()
  const invalid: string[] = []
  const seen = new Set<string>()

  for (const raw of hosts) {
    if (typeof raw !== 'string' || !raw.trim()) continue
    const { wildcard, rest } = splitWildcard(normalizeHost(raw))
    const host = rest
    if (!isUsableHost(host) || (wildcard && !isUsableWildcardRoot(host))) {
      if (!invalid.includes(raw.trim())) invalid.push(raw.trim())
      continue
    }
    // Keyed on the PAIR, not the host: `*.example.com` and `example.com` reduce
    // to the same host but mean different things, and deduping on the host alone
    // would silently drop whichever came second - turning a wildcard into a
    // literal scan, or making the "include root" toggle a no-op.
    const seenKey = wildcard ? `*${host}` : host
    if (seen.has(seenKey)) continue
    seen.add(seenKey)

    const rootDomain = rootOf(host)
    let group = byRoot.get(rootDomain)
    if (!group) {
      group = { rootDomain, prefixes: [], hosts: [], wildcard: false }
      byRoot.set(rootDomain, group)
      groups.push(group)
    }
    group.hosts.push(wildcard ? `*.${host}` : host)

    // A wildcard contributes "*"; the bare root contributes "."; anything deeper
    // contributes its prefix with a trailing dot, which is what parse_target()
    // in recon/main.py expects.
    const prefix = wildcard
      ? WILDCARD_PREFIX
      : host === rootDomain
        ? ROOT_DOMAIN_PREFIX
        : `${host.slice(0, host.length - rootDomain.length - 1)}.`
    if (!group.prefixes.includes(prefix)) group.prefixes.push(prefix)
    if (wildcard) group.wildcard = true
  }

  return { groups, invalid }
}

/**
 * Filesystem-safe identifier for a group's per-run output file. The root domain
 * is already charset-filtered by isUsableHost, so this cannot emit a separator or
 * a traversal sequence; the extra guard keeps that true if the caller ever passes
 * an unvalidated string.
 */
export function groupSlug(rootDomain: string): string {
  const slug = rootDomain.toLowerCase()
    .replace(/[^a-z0-9.-]/g, '_')
    .replace(/\.\.+/g, '_')
    .replace(/^[.\-_]+/, '')
    .replace(/[.\-_]+$/, '')
  // A slug of only separators names nothing and would collide across groups.
  return /[a-z0-9]/.test(slug) ? slug : 'group'
}

export interface BatchValidation {
  ok: boolean
  errors: string[]
  groups: DomainGroup[]
  invalid: string[]
}

/**
 * The shared gate for a batch host list: grouping plus the caps. Used by the form
 * before submit and by the project routes before persisting, so the UI and the
 * server can never disagree about what is acceptable.
 */
export function validateDomainBatch(hosts: readonly string[]): BatchValidation {
  const { groups, invalid } = groupHostsByRootDomain(hosts)
  const errors: string[] = []

  const supplied = hosts.filter(h => typeof h === 'string' && h.trim()).length
  if (supplied > MAX_BATCH_HOSTS) {
    errors.push(`Too many hostnames: ${supplied}. The limit is ${MAX_BATCH_HOSTS}.`)
  }
  if (groups.length > MAX_BATCH_GROUPS) {
    errors.push(`Too many domains: ${groups.length}. The limit is ${MAX_BATCH_GROUPS}.`)
  }
  if (invalid.length > 0) {
    errors.push(`Not valid hostnames: ${invalid.slice(0, 5).join(', ')}`
      + (invalid.length > 5 ? ` (+${invalid.length - 5} more)` : ''))
  }
  if (groups.length === 0 && errors.length === 0) {
    errors.push('Domain batch mode needs at least one hostname.')
  }

  return { ok: errors.length === 0, errors, groups, invalid }
}
