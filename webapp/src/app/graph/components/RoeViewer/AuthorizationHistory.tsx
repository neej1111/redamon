'use client'

/**
 * What authorized this engagement, and when.
 *
 * Append-only: a later record does not replace an earlier one, it says the
 * engagement continued under a new authority from that moment. So the list is
 * the history, the newest entry is the authority a run today is covered by, and
 * nothing here can edit or remove one.
 *
 * Four states, all of which happen:
 *
 *   loading   the fetch is in flight
 *   error     the fetch failed, which is NOT the same as "no record"
 *   empty     an internal engagement legitimately has none; a third-party one
 *             with none cannot start, and that is worth saying loudly
 *   listed    one or more records
 *
 * The distinction between `error` and `empty` is the one that matters. Rendering
 * a failed fetch as "no records" would tell an operator their third-party
 * engagement is unauthorized when the truth is that nobody asked.
 */
import { useEffect, useState } from 'react'
import { FileCheck } from 'lucide-react'

import { ExternalLink } from '@/components/ui'
import styles from './RoeViewer.module.css'

export interface AuthorizationRecord {
  id: string
  documentSha256: string
  documentKind: string
  sourceUrl: string
  programHandle: string | null
  issuedAt: string
  recordedAt: string
  recordedVia: string
  recordedByTokenId: string | null
  summary: string
}

const KIND_LABELS: Record<string, string> = {
  hackerone_program: 'HackerOne program',
  bugcrowd_program: 'Bugcrowd program',
  roe_document: 'Rules of Engagement document',
  internal_ticket: 'Internal ticket',
  other: 'Other',
}

const VIA_LABELS: Record<string, string> = {
  mcp: 'recorded by an agent over MCP',
  ui: 'recorded in the app',
  import: 'copied in with an imported project',
}

function formatWhen(iso: string): string {
  try {
    return new Date(iso).toLocaleString()
  } catch {
    return iso
  }
}

export function AuthorizationHistory({
  projectId,
  engagementKind,
}: {
  projectId: string
  engagementKind?: string
}) {
  const [state, setState] = useState<'loading' | 'error' | 'ready'>('loading')
  const [records, setRecords] = useState<AuthorizationRecord[]>([])

  useEffect(() => {
    if (!projectId) return
    let cancelled = false
    setState('loading')
    fetch(`/api/projects/${projectId}/authorizations`)
      .then(async r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`)
        return r.json()
      })
      .then(body => {
        if (cancelled) return
        setRecords(Array.isArray(body.authorizations) ? body.authorizations : [])
        setState('ready')
      })
      .catch(() => {
        if (!cancelled) setState('error')
      })
    return () => { cancelled = true }
  }, [projectId])

  if (state === 'loading') {
    return <p className={styles.authState}>Loading authorization records&hellip;</p>
  }

  if (state === 'error') {
    return (
      <p className={styles.authWarn}>
        Could not read the authorization records. This is not the same as there being none:
        retry before concluding anything about whether this engagement is authorized.
      </p>
    )
  }

  if (records.length === 0) {
    return engagementKind === 'third_party' ? (
      <p className={styles.authWarn}>
        No record of what authorized this engagement. A third-party engagement cannot start a
        scan without one; it is recorded over MCP with
        {' '}<code>attach_engagement_authorization</code>.
      </p>
    ) : (
      <p className={styles.authState}>
        No authorization records. An internal engagement scans your own estate and does not
        need one.
      </p>
    )
  }

  return (
    <div className={styles.authList}>
      {records.map((record, index) => (
        <div
          key={record.id}
          className={`${styles.authItem} ${index === 0 ? styles.authCurrent : styles.authSuperseded}`}
        >
          <div className={styles.authHead}>
            <span className={styles.authProgram}>
              {record.programHandle || KIND_LABELS[record.documentKind] || record.documentKind}
              {index === 0 ? ' · current' : ''}
            </span>
            <span className={styles.authWhen}>
              issued {formatWhen(record.issuedAt)} · recorded {formatWhen(record.recordedAt)}
            </span>
          </div>
          {record.summary && <span className={styles.authMeta}>{record.summary}</span>}
          <span className={styles.authDigest}>sha256:{record.documentSha256}</span>
          <span className={styles.authMeta}>
            {KIND_LABELS[record.documentKind] || record.documentKind}
            {' · '}
            {VIA_LABELS[record.recordedVia] || record.recordedVia}
            {record.recordedByTokenId ? ` · token ${record.recordedByTokenId}` : ''}
          </span>
          {record.sourceUrl && (
            <span className={styles.authMeta}>
              {/* An agent holding engagement:authorize supplies this string and
                  nothing constrains its scheme, so it reaches here as untrusted
                  input. ExternalLink renders a non-http(s) value as plain text
                  rather than a link the operator can click. */}
              <ExternalLink href={record.sourceUrl}>{record.sourceUrl}</ExternalLink>
            </span>
          )}
        </div>
      ))}
    </div>
  )
}

export function AuthorizationSectionIcon() {
  return <FileCheck size={15} />
}
