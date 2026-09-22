'use client'

import { useState, useRef } from 'react'
import { ChevronDown, Shield, Upload, Loader2, AlertTriangle, CheckCircle } from 'lucide-react'
import { WikiInfoButton } from '@/components/ui'
import { Modal } from '@/components/ui/Modal/Modal'
import type { Project } from '@prisma/client'
import { currentValuesForDiff, type ParseProposal } from '@/lib/reconSettings/roeParse'
import styles from '../ProjectForm.module.css'

type ProjectFormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface RoeSectionProps {
  data: ProjectFormData
  updateField: <K extends keyof ProjectFormData>(field: K, value: ProjectFormData[K]) => void
  updateMultipleFields: (fields: Partial<ProjectFormData>) => void
  mode: 'create' | 'edit'
  onFileSelected: (file: File | null) => void
}

const ENGAGEMENT_TYPES = [
  { value: 'external', label: 'External Penetration Test' },
  { value: 'internal', label: 'Internal Penetration Test' },
  { value: 'web_app', label: 'Web Application Test' },
  { value: 'api', label: 'API Security Test' },
  { value: 'mobile', label: 'Mobile Application Test' },
  { value: 'physical', label: 'Physical Security Test' },
  { value: 'social_engineering', label: 'Social Engineering' },
  { value: 'red_team', label: 'Red Team Engagement' },
]

const DATA_HANDLING_OPTIONS = [
  { value: 'no_access', label: 'No access to sensitive data' },
  { value: 'prove_access_only', label: 'Prove access only (no collection)' },
  { value: 'limited_collection', label: 'Limited collection' },
  { value: 'full_access', label: 'Full access' },
]

const COMPLIANCE_OPTIONS = ['PCI-DSS', 'HIPAA', 'SOC2', 'GDPR', 'ISO27001']

/** One proposed value, short enough to read in a diff row. */
function preview(value: unknown): string {
  if (value === null || value === undefined) return '—'
  if (Array.isArray(value)) return value.length === 0 ? '(empty)' : value.join(', ').slice(0, 160)
  if (typeof value === 'object') return JSON.stringify(value).slice(0, 160)
  const text = String(value)
  return text === '' ? '(empty)' : text.slice(0, 160)
}

/**
 * The engagement RECORD: who the client is, who to call, what the document said.
 *
 * Not the engagement's LIMITS. Those used to live here too, under the same `roe`
 * prefix and the same heading, and conflating them is what made a master switch
 * that disabled the rate ceiling look like an ordinary checkbox. The limits are
 * ordinary settings now: the rate ceiling, the excluded hosts and the scanning
 * window sit in Target & Modules, and the agent's denylists sit with the agent's
 * other behaviour.
 *
 * What is left here is the contract. A person writes it, a model reads it, and
 * nothing in the pipeline enforces it - which is exactly why the MCP surface
 * never touches it and why it carries third-party personal data.
 */
export function RoeSection({ data, updateField, updateMultipleFields, mode, onFileSelected }: RoeSectionProps) {
  const [isOpen, setIsOpen] = useState(true)
  const [isParsing, setIsParsing] = useState(false)
  const [parseError, setParseError] = useState<string | null>(null)
  const [proposal, setProposal] = useState<(ParseProposal & { roeRawText?: string }) | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const readOnly = mode === 'edit'

  const handleFileUpload = async (file: File) => {
    setIsParsing(true)
    setParseError(null)
    onFileSelected(file)

    try {
      const formData = new FormData()
      formData.append('file', file)
      // Pass the currently selected LLM model so the agent uses it for parsing
      if (data.agentOpenaiModel) {
        formData.append('model', data.agentOpenaiModel as string)
      }
      // The present values, so what comes back is a DIFF rather than a list of
      // assignments: a parsed value equal to what is already set is not a
      // change. Narrowed to the fields a document could propose - the form's
      // data also holds stored credentials, and a value that does not need to
      // travel should not travel.
      formData.append('current', JSON.stringify(currentValuesForDiff(data as never)))

      const response = await fetch('/api/roe/parse', {
        method: 'POST',
        body: formData,
      })

      if (!response.ok) {
        const err = await response.json().catch(() => ({}))
        throw new Error(err.error || `Parse failed (${response.status})`)
      }

      // A PROPOSAL, not a write. There is no field map here and there must never
      // be one again: the route writes whatever the registry marks writable and
      // validates every value through the same bounds an MCP write goes through,
      // so field names live in exactly one place. This component copies what it
      // is handed and shows it to a person first.
      setProposal(await response.json())
    } catch (err) {
      setParseError(err instanceof Error ? err.message : 'Failed to parse document')
    } finally {
      setIsParsing(false)
    }
  }

  const applyProposal = () => {
    if (!proposal) return
    const updates: Record<string, unknown> = {}
    for (const change of proposal.changes) updates[change.key] = change.after
    if (proposal.roeRawText) updates.roeRawText = proposal.roeRawText
    // What the document actually produced, kept on the record so the report can
    // say which settings came from it rather than from a person. Stored as the
    // CONFIRMED set, not the raw model output: a value somebody declined is not
    // something the document configured.
    updates.roeParsedJson = {
      applied: Object.fromEntries(proposal.changes.map(c => [c.key, c.after])),
      rejected: proposal.rejected,
      ignored: proposal.ignored,
    }
    updateMultipleFields(updates as Partial<ProjectFormData>)
    setProposal(null)
  }

  const toggleCompliance = (fw: string) => {
    const current = data.roeComplianceFrameworks || []
    if (current.includes(fw)) {
      updateField('roeComplianceFrameworks', current.filter(c => c !== fw))
    } else {
      updateField('roeComplianceFrameworks', [...current, fw])
    }
  }

  return (
    <>
    <div className={styles.section}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <Shield size={16} />
          Engagement Record
          <WikiInfoButton target="Roe" />
        </h2>
        <ChevronDown
          size={16}
          className={`${styles.sectionIcon} ${isOpen ? styles.sectionIconOpen : ''}`}
        />
      </div>

      {isOpen && (
        <div className={styles.sectionContent}>
          {/* Document Upload (create mode only) */}
          {mode === 'create' && (
            <div className={styles.subSection}>
              <h3 className={styles.subSectionTitle}>Upload RoE Document</h3>
              <p className={styles.sectionDescription}>
                Upload a Rules of Engagement document (.pdf, .txt, .md, .docx). It is read and
                turned into a <strong>proposed</strong> set of changes across the whole form:
                this record, the engagement&apos;s limits in Target &amp; Modules, and any tool
                the document constrains. Nothing is applied until you review the diff.
              </p>
              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept=".pdf,.txt,.md,.docx"
                    style={{ display: 'none' }}
                    onChange={(e) => {
                      const file = e.target.files?.[0]
                      if (file) handleFileUpload(file)
                    }}
                  />
                  <button
                    type="button"
                    className="secondaryButton"
                    onClick={() => fileInputRef.current?.click()}
                    disabled={isParsing}
                    style={{ width: 'fit-content' }}
                  >
                    {isParsing ? (
                      <>
                        <Loader2 size={14} className={styles.spinner} />
                        Parsing RoE document...
                      </>
                    ) : (
                      <>
                        <Upload size={14} />
                        Upload &amp; Parse Document
                      </>
                    )}
                  </button>
                  {parseError && (
                    <span style={{ color: 'var(--color-error)', fontSize: '0.8rem', marginTop: 4 }}>
                      {parseError}
                    </span>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* Engagement kind: who the target belongs to, and therefore what has
              to be true before a scan may start. Create-time only, for the same
              reason the target is: converting a project afterwards would either
              claim an authority nobody granted or drop a ceiling a person set. */}
          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>Engagement</h3>
            <div className={styles.fieldRow}>
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Whose estate is the target?</label>
                <select
                  className="select"
                  value={(data.engagementKind as string) || 'internal'}
                  disabled={readOnly}
                  onChange={(e) => updateField('engagementKind', e.target.value)}
                >
                  <option value="internal">Internal - our own estate</option>
                  <option value="third_party">Third party - somebody else&apos;s</option>
                </select>
                <span className={styles.fieldHint}>
                  Fixed at creation. A third-party engagement cannot start without a non-zero
                  request-rate ceiling AND a record of what authorized it.
                </span>
              </div>
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Identity Header</label>
                <input
                  className="textInput"
                  value={(data.engagementIdentityHeader as string) || ''}
                  placeholder="X-Bug-Bounty: your-handle"
                  onChange={(e) => updateField('engagementIdentityHeader', e.target.value)}
                />
                <span className={styles.fieldHint}>
                  Sent with every request so the target&apos;s operators can attribute the traffic
                  to you. Many programs require one. Leave empty to send none.
                </span>
              </div>
            </div>
            {data.engagementKind === 'third_party' && !(data.roeGlobalMaxRps > 0) && (
              <span className={styles.fieldHint} style={{ color: 'var(--color-danger, #d33)' }}>
                A third-party engagement needs a request-rate ceiling, or its scans will be
                refused. Set it in Target &amp; Modules &rarr; Engagement limits.
              </span>
            )}
            <span className={styles.fieldHint}>
              This record is the CONTRACT: who the client is, who to call, what the document said.
              Nothing here constrains a scan. The limits that do - the rate ceiling, the excluded
              hosts, the scanning window and the agent&apos;s denylists - are ordinary settings,
              editable at any time, in Target &amp; Modules and Agent Behaviour.
            </span>
          </div>

          {/* Client & Engagement */}
          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>Client &amp; Engagement</h3>
            <div className={styles.fieldRow}>
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Client Name</label>
                <input className="textInput" value={data.roeClientName} readOnly={readOnly}
                  onChange={(e) => updateField('roeClientName', e.target.value)} />
              </div>
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Engagement Type</label>
                <select className="select" value={data.roeEngagementType} disabled={readOnly}
                  onChange={(e) => updateField('roeEngagementType', e.target.value)}>
                  {ENGAGEMENT_TYPES.map(t => (
                    <option key={t.value} value={t.value}>{t.label}</option>
                  ))}
                </select>
              </div>
            </div>
            <div className={styles.fieldRow}>
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Contact Name</label>
                <input className="textInput" value={data.roeClientContactName} readOnly={readOnly}
                  onChange={(e) => updateField('roeClientContactName', e.target.value)} />
              </div>
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Contact Email</label>
                <input className="textInput" type="email" value={data.roeClientContactEmail} readOnly={readOnly}
                  onChange={(e) => updateField('roeClientContactEmail', e.target.value)} />
              </div>
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Contact Phone</label>
                <input className="textInput" value={data.roeClientContactPhone} readOnly={readOnly}
                  onChange={(e) => updateField('roeClientContactPhone', e.target.value)} />
              </div>
            </div>
            <div className={styles.fieldRow}>
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Emergency Contact</label>
                <input className="textInput" value={data.roeEmergencyContact} readOnly={readOnly}
                  onChange={(e) => updateField('roeEmergencyContact', e.target.value)} />
              </div>
            </div>
            <div className={styles.fieldRow}>
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Start Date</label>
                <input className="textInput" type="date" value={data.roeEngagementStartDate} readOnly={readOnly}
                  onChange={(e) => updateField('roeEngagementStartDate', e.target.value)} />
              </div>
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>End Date</label>
                <input className="textInput" type="date" value={data.roeEngagementEndDate} readOnly={readOnly}
                  onChange={(e) => updateField('roeEngagementEndDate', e.target.value)} />
              </div>
            </div>
          </div>

          {/* Recorded permissions. These three are RECORD rather than limit: the
              pipeline has no physical capability, production is a statement about
              the estate that no scanner can verify, and exfiltration reaches the
              agent as prompt text. The three that ARE enforced in code live with
              the agent's other behaviour. */}
          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>Recorded Permissions</h3>
            <p className={styles.sectionDescription}>
              Read by the agent as prompt context and printed in the report. The permissions
              enforced in code - availability testing, social engineering, account lockout,
              forbidden tools and categories, the severity cap - are in Agent Behaviour.
            </p>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Allow Physical Access</label>
                <input type="checkbox" checked={data.roeAllowPhysicalAccess} disabled={readOnly}
                  onChange={(e) => updateField('roeAllowPhysicalAccess', e.target.checked)} />
              </div>
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Allow Data Exfiltration</label>
                <input type="checkbox" checked={data.roeAllowDataExfiltration} disabled={readOnly}
                  onChange={(e) => updateField('roeAllowDataExfiltration', e.target.checked)} />
              </div>
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Allow Production Testing</label>
                <input type="checkbox" checked={data.roeAllowProductionTesting} disabled={readOnly}
                  onChange={(e) => updateField('roeAllowProductionTesting', e.target.checked)} />
              </div>
            </div>
          </div>

          {/* Data Handling */}
          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>Data Handling</h3>
            <div className={styles.fieldRow}>
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Sensitive Data Policy</label>
                <select className="select" value={data.roeSensitiveDataHandling} disabled={readOnly}
                  onChange={(e) => updateField('roeSensitiveDataHandling', e.target.value)}>
                  {DATA_HANDLING_OPTIONS.map(opt => (
                    <option key={opt.value} value={opt.value}>{opt.label}</option>
                  ))}
                </select>
              </div>
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Data Retention (days)</label>
                <input className="textInput" type="number" min={0} max={3650}
                  value={data.roeDataRetentionDays} readOnly={readOnly}
                  onChange={(e) => updateField('roeDataRetentionDays', parseInt(e.target.value) || 90)} />
              </div>
            </div>
            <div className={styles.fieldRow}>
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Require data encryption</label>
                <input type="checkbox" checked={data.roeRequireDataEncryption} disabled={readOnly}
                  onChange={(e) => updateField('roeRequireDataEncryption', e.target.checked)} />
              </div>
            </div>
          </div>

          {/* Communication */}
          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>Communication</h3>
            <div className={styles.fieldRow}>
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Status Update Frequency</label>
                <select className="select" value={data.roeStatusUpdateFrequency} disabled={readOnly}
                  onChange={(e) => updateField('roeStatusUpdateFrequency', e.target.value)}>
                  <option value="daily">Daily</option>
                  <option value="weekly">Weekly</option>
                  <option value="on_finding">On each finding</option>
                  <option value="none">None</option>
                </select>
              </div>
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Notify client on critical findings</label>
                <input type="checkbox" checked={data.roeCriticalFindingNotify} disabled={readOnly}
                  onChange={(e) => updateField('roeCriticalFindingNotify', e.target.checked)} />
              </div>
            </div>
            <div className={styles.fieldRow}>
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Incident Procedure</label>
                <textarea className="textInput" rows={3} value={data.roeIncidentProcedure} readOnly={readOnly}
                  onChange={(e) => updateField('roeIncidentProcedure', e.target.value)}
                  placeholder="What to do if testing causes an incident..." />
              </div>
            </div>
          </div>

          {/* Compliance */}
          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>Compliance &amp; Authorization</h3>
            <div className={styles.fieldRow}>
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Compliance Frameworks</label>
                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                  {COMPLIANCE_OPTIONS.map(fw => (
                    <label key={fw} style={{ display: 'flex', alignItems: 'center', gap: 4, cursor: readOnly ? 'default' : 'pointer' }}>
                      <input type="checkbox" checked={(data.roeComplianceFrameworks || []).includes(fw)}
                        disabled={readOnly} onChange={() => toggleCompliance(fw)} />
                      {fw}
                    </label>
                  ))}
                </div>
              </div>
            </div>
          </div>

          {/* Third-Party Providers */}
          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>Third-Party Providers</h3>
            <div className={styles.fieldRow}>
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Cloud/hosting providers with separate authorization</label>
                <input className="textInput" type="text" readOnly={readOnly}
                  value={(data.roeThirdPartyProviders || []).join(', ')}
                  onChange={(e) => updateField('roeThirdPartyProviders', e.target.value.split(',').map((s: string) => s.trim()).filter(Boolean))}
                  placeholder="e.g. AWS, Hetzner, Cloudflare" />
              </div>
            </div>
          </div>

          {/* Notes */}
          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>Notes</h3>
            <div className={styles.fieldRow}>
              <div className={styles.fieldGroup}>
                <textarea className="textInput" rows={4} value={data.roeNotes} readOnly={readOnly}
                  onChange={(e) => updateField('roeNotes', e.target.value)}
                  placeholder="Additional rules not captured by fields above..." />
              </div>
            </div>
          </div>

          {/* Raw RoE Text (always read-only) */}
          {data.roeRawText && (
            <div className={styles.subSection}>
              <h3 className={styles.subSectionTitle}>Extracted Document Text</h3>
              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <textarea className="textInput" rows={8} value={data.roeRawText} readOnly
                    style={{ fontFamily: 'monospace', fontSize: '0.8rem' }} />
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>

    {/* The parse result is a PROPOSAL. A document is a third party's text and an
        LLM reading it is not a sanitiser, so what it produces is a diff a person
        confirms rather than a write. Values the validators refused are shown
        here rather than dropped: silently discarding one is how somebody
        believes a document applied when part of it did not. */}
    <Modal
      isOpen={proposal !== null}
      onClose={() => setProposal(null)}
      title="Review what this document would change"
      size="large"
      footer={
        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
          <button type="button" className="secondaryButton" onClick={() => setProposal(null)}>
            Discard
          </button>
          <button
            type="button"
            onClick={applyProposal}
            disabled={!proposal || proposal.changes.length === 0}
            style={{
              padding: '8px 24px',
              background: 'var(--color-accent, #3b82f6)',
              color: '#fff',
              border: 'none',
              borderRadius: '6px',
              cursor: 'pointer',
              fontSize: '0.9rem',
              fontWeight: 500,
            }}
          >
            Apply {proposal?.changes.length ?? 0} change{proposal?.changes.length === 1 ? '' : 's'}
          </button>
        </div>
      }
    >
      <div style={{ display: 'flex', flexDirection: 'column', gap: 16, fontSize: '0.85rem', lineHeight: 1.5 }}>
        <p style={{ margin: 0 }}>
          Nothing has been applied yet. These are the values the document proposes, each one
          already checked against the same bounds the API enforces. Applying them fills the form;
          you still have to save.
        </p>

        {proposal && proposal.changes.length === 0 && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <CheckCircle size={18} />
            <span>The document proposes nothing this project does not already have set.</span>
          </div>
        )}

        {proposal && proposal.changes.length > 0 && (
          <div style={{ maxHeight: 360, overflowY: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8rem' }}>
              <thead>
                <tr style={{ textAlign: 'left' }}>
                  <th style={{ padding: '4px 8px' }}>Setting</th>
                  <th style={{ padding: '4px 8px' }}>Now</th>
                  <th style={{ padding: '4px 8px' }}>Would become</th>
                  <th style={{ padding: '4px 8px' }}>Where</th>
                </tr>
              </thead>
              <tbody>
                {proposal.changes.map(c => (
                  <tr key={c.key} style={{ borderTop: '1px solid var(--color-border, #333)' }}>
                    <td style={{ padding: '4px 8px', fontFamily: 'monospace' }} title={c.meaning}>{c.key}</td>
                    <td style={{ padding: '4px 8px', opacity: 0.7 }}>{preview(c.before)}</td>
                    <td style={{ padding: '4px 8px', fontWeight: 600 }}>{preview(c.after)}</td>
                    <td style={{ padding: '4px 8px', opacity: 0.7 }}>{c.section ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {proposal && proposal.rejected.length > 0 && (
          <div style={{ padding: '10px 12px', background: 'var(--color-surface-alt, rgba(234,179,8,0.08))', borderRadius: 6, borderLeft: '3px solid var(--color-warning, #eab308)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
              <AlertTriangle size={16} />
              <strong>{proposal.rejected.length} value{proposal.rejected.length === 1 ? '' : 's'} refused</strong>
            </div>
            <ul style={{ margin: 0, paddingLeft: 20 }}>
              {proposal.rejected.map(r => (
                <li key={r.key}>
                  <code>{r.key}</code> = {preview(r.value)} &mdash; {r.why}
                </li>
              ))}
            </ul>
          </div>
        )}

        {proposal && proposal.ignored.length > 0 && (
          <p style={{ margin: 0, opacity: 0.75 }}>
            Ignored, because no setting a document may write matches them:{' '}
            <code>{proposal.ignored.join(', ')}</code>. The engagement&apos;s TARGET is among
            these by design: a scope document configures this project, it does not re-point it.
          </p>
        )}
      </div>
    </Modal>
    </>
  )
}
