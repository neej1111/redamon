'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import Link from 'next/link'
import {
  Building2, ChevronDown, FileText, Github, Loader2, PackageSearch, Trash2, Upload,
} from 'lucide-react'
import { WikiInfoButton } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'
import { SETTINGS_KEYS_HREF } from '@/lib/settingsLinks'
import { CredentialShortcut } from '@/components/settings/CredentialShortcut'
import { useCredentialKeys } from '@/hooks/useCredentialKeys'
import { isValidGitRef, parseGithubRepo } from '@/lib/validation/supplyChainInput'
import { GITHUB_DOT_COM, hostHint, parseOwnerTarget } from '@/lib/github/ownerTarget'
import { RegistryFields } from '../RegistryFields'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface SupplyChainScanSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
  /** Uploads are written against a project row, so they need a saved project.
   *  In create mode the section explains that instead of offering a dead button. */
  projectId?: string | null
  mode?: 'create' | 'edit'
  /** Update Settings / Start to Scan for this scan, rendered in the header. */
  actions?: React.ReactNode
}

interface UploadedFile {
  name: string
  size: number
  uploaded_at: string
}

const get = (data: FormData, key: string) => (data as unknown as Record<string, unknown>)[key]
const setField = (
  updateField: SupplyChainScanSectionProps['updateField'],
  key: string,
  value: unknown,
) => updateField(key as keyof FormData, value as FormData[keyof FormData])

/**
 * Client-side shape check only: a bare owner name, or a URL that resolves to
 * host + owner. Which HOSTS are actually reachable is the server's call (it owns
 * the operator's allowlist), so a well-formed value for an unregistered host
 * gets a specific error back from the API rather than being guessed at here.
 */
function orgTargetShapeOk(value: string): boolean {
  return parseOwnerTarget(value, [GITHUB_DOT_COM]) !== null
    || (hostHint(value) !== null && parseOwnerTarget(value, [hostHint(value) as string]) !== null)
}

/** The same shape-only check for a single `owner/repo` coordinate. */
function repoShapeOk(value: string): boolean {
  return parseGithubRepo(value, [GITHUB_DOT_COM]) !== null
    || (hostHint(value) !== null && parseGithubRepo(value, [hostHint(value) as string]) !== null)
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`
}

/**
 * L1 - Supply Chain Scanner: WHAT the standalone scan reads. It is launched from
 * the Other Scans card, which owns only the run controls; everything that has to
 * be configured before it can run lives here, exactly like the Secret
 * Multiscanner section above it.
 *
 * The scan consumes exactly ONE input, so the three sources are mutually
 * exclusive and the selected one is persisted as the project's input mode. Each
 * new upload REPLACES the previous file rather than accumulating.
 *
 * 'org' is the odd one out: it does not run this project's single scan, it
 * queues one scan per repository in an account. It is still a persisted mode,
 * because the card has to know which action to offer - a Start that can never be
 * enabled is the failure this replaced.
 */
export function SupplyChainScanSection({
  data, updateField, projectId, mode = 'edit', actions,
}: SupplyChainScanSectionProps) {
  const [isOpen, setIsOpen] = useState(true)
  const [file, setFile] = useState<UploadedFile | null>(null)
  const [busy, setBusy] = useState(false)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)
  const keys = useCredentialKeys()

  const canUpload = mode === 'edit' && Boolean(projectId)

  const source = String(get(data, 'supplyChainInputMode') ?? 'upload')
  const repoUrl = String(get(data, 'supplyChainRepoUrl') ?? '')
  const repoRef = String(get(data, 'supplyChainRepoRef') ?? '')
  const org = String(get(data, 'supplyChainOrgName') ?? '')

  // The uploaded file lives on a shared volume, not on the project row, so the
  // name saved as the scan input is confirmed against what is actually there.
  const loadFiles = useCallback(async () => {
    if (!canUpload) { setLoading(false); return }
    setLoading(true)
    try {
      const res = await fetch(`/api/supply-chain/${projectId}/upload`)
      if (res.ok) {
        const body = await res.json()
        setFile((body.files || [])[0] || null)
      }
    } catch {
      setError('Could not list the uploaded file')
    } finally {
      setLoading(false)
    }
  }, [canUpload, projectId])

  useEffect(() => { void loadFiles() }, [loadFiles])

  const onFilePicked = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const picked = e.target.files?.[0]
    // Always clear the input: picking the SAME file twice must still fire a
    // change event, otherwise a re-upload after a delete silently does nothing.
    e.target.value = ''
    if (!picked || !projectId) return

    setBusy(true)
    setError(null)
    try {
      const form = new FormData()
      form.append('file', picked)
      const res = await fetch(`/api/supply-chain/${projectId}/upload`, { method: 'POST', body: form })
      const body = await res.json().catch(() => ({}))
      if (!res.ok) {
        setError(body.error || 'Upload failed')
        return
      }
      // The upload route already recorded this as the scan input. Mirroring it
      // into the form is not cosmetic: saving the form afterwards would write
      // back the stale name it was loaded with and un-point the scan.
      setField(updateField, 'supplyChainSbomFile', body.filename ?? '')
      await loadFiles()
    } catch {
      setError('Upload failed')
    } finally {
      setBusy(false)
    }
  }

  const removeFile = async () => {
    if (!file || !projectId) return
    setBusy(true)
    try {
      await fetch(
        `/api/supply-chain/${projectId}/upload?filename=${encodeURIComponent(file.name)}`,
        { method: 'DELETE' })
      setField(updateField, 'supplyChainSbomFile', '')
      await loadFiles()
    } catch {
      setError('Could not remove the file')
    } finally {
      setBusy(false)
    }
  }

  const repoInvalid = repoUrl.trim() !== '' && !repoShapeOk(repoUrl)
  const refInvalid = !isValidGitRef(repoRef)
  const orgInvalid = org.trim() !== '' && !orgTargetShapeOk(org.trim())

  return (
    // id: scroll target for the Other Scans card's settings link. Keep it in
    // sync with PROJECT_SECTION_ANCHORS in lib/projectSettingsLinks.ts.
    <div className={styles.section} id="supply-chain-scanner">
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <PackageSearch size={16} />
          Supply Chain Scanner
          <WikiInfoButton target="SupplyChainScan" />
          {/* The OSV verdict is offline, but reaching a repo or enumerating an
              org talks to GitHub, so only the upload path is truly passive. */}
          <span className={source === 'upload' ? styles.badgePassive : styles.badgeActive}>
            {source === 'upload' ? 'Passive' : 'Active'}
          </span>
        </h2>
        {actions}
        <ChevronDown size={16} className={`${styles.sectionIcon} ${isOpen ? styles.sectionIconOpen : ''}`} />
      </div>

      {isOpen && (
        <div className={styles.sectionContent}>
          <p className={styles.sectionDescription}>
            Audit an SBOM / lockfile, or a GitHub repository, against the offline OSV database for
            known-malicious (MAL) and known-vulnerable packages. The OSV verdict is fully offline.
            The scan itself is started from Other Scans; the input it reads is set here.
          </p>

          <h3 className={styles.subSectionTitle}>Scan input</h3>
          <div className={styles.inputSourceToggle} role="radiogroup" aria-label="Supply-chain scan input source">
            <button
              type="button"
              role="radio"
              aria-checked={source === 'upload'}
              onClick={() => setField(updateField, 'supplyChainInputMode', 'upload')}
              className={`${styles.inputSourceOption} ${source === 'upload' ? styles.inputSourceOptionActive : ''}`}
            >
              <FileText size={13} />
              <span>Uploaded SBOM / lockfile</span>
            </button>
            <button
              type="button"
              role="radio"
              aria-checked={source === 'github'}
              onClick={() => setField(updateField, 'supplyChainInputMode', 'github')}
              className={`${styles.inputSourceOption} ${source === 'github' ? styles.inputSourceOptionActive : ''}`}
            >
              <Github size={13} />
              <span>GitHub repository</span>
            </button>
            <button
              type="button"
              role="radio"
              aria-checked={source === 'org'}
              onClick={() => setField(updateField, 'supplyChainInputMode', 'org')}
              className={`${styles.inputSourceOption} ${source === 'org' ? styles.inputSourceOptionActive : ''}`}
            >
              <Building2 size={13} />
              <span>GitHub organization</span>
            </button>
          </div>

          <div className={styles.inputPanel}>
            {source === 'upload' ? (
              !canUpload ? (
                <p className={styles.sectionRequirement}>
                  Save the project first, then upload the SBOM / lockfile to scan here.
                </p>
              ) : (
                <>
                  <div className={styles.inputRow}>
                    <input
                      ref={fileInputRef}
                      type="file"
                      accept=".json,.xml,.txt,.lock,.toml,.mod,.sum,.yaml,.yml"
                      onChange={onFilePicked}
                      disabled={busy}
                      style={{ display: 'none' }}
                      aria-label="Upload SBOM or lockfile"
                    />
                    <button
                      type="button"
                      className={styles.inputSourceOption}
                      style={{ flex: '0 0 auto' }}
                      disabled={busy}
                      onClick={() => fileInputRef.current?.click()}
                    >
                      {busy ? <Loader2 size={13} className={styles.spinner} /> : <Upload size={13} />}
                      <span>{file ? 'Replace file' : 'Upload file'}</span>
                    </button>

                    {loading ? (
                      <span className={styles.fieldHint}>Loading current input...</span>
                    ) : file ? (
                      <div className={styles.activeFile}>
                        <FileText size={13} />
                        <span className={styles.activeFileName} title={file.name}>{file.name}</span>
                        <span>({formatSize(file.size)})</span>
                        <button
                          type="button"
                          className={styles.inputSourceOption}
                          style={{ flex: '0 0 auto', padding: '4px 8px' }}
                          disabled={busy}
                          onClick={() => void removeFile()}
                          aria-label={`Remove ${file.name}`}
                          title="Remove"
                        >
                          <Trash2 size={12} />
                        </button>
                      </div>
                    ) : (
                      <span className={styles.fieldHint}>No file uploaded yet.</span>
                    )}
                  </div>
                  <p className={styles.fieldHint}>
                    CycloneDX / SPDX SBOMs and lockfiles (package-lock.json, yarn.lock, poetry.lock,
                    go.sum, Gemfile.lock, ...). Max 10 MB. Uploading is immediate and a new upload
                    replaces the current file. No API key is needed for an upload; keys and tokens
                    live in{' '}
                    <Link href={SETTINGS_KEYS_HREF} style={{ color: 'var(--accent-primary)', fontWeight: 500 }}>
                      Global Settings
                    </Link>.
                  </p>
                </>
              )
            ) : source === 'org' ? (
              <>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel} htmlFor="sc-org">Organization or user</label>
                  <input
                    id="sc-org"
                    type="text"
                    className="textInput"
                    placeholder="acme-corp or https://ghe.example.com/orgs/acme-corp"
                    value={org}
                    onChange={(e) => setField(updateField, 'supplyChainOrgName', e.target.value)}
                  />
                  {orgInvalid && (
                    <span className={styles.fieldHintWarning}>
                      An organization or user name (letters, digits and dashes, 39 characters max),
                      or its URL - github.com, or a GitHub Enterprise host you configured in Global
                      Settings.
                    </span>
                  )}
                  <p className={styles.fieldHint}>
                    Enumerates the account&apos;s repos and queues one supply-chain scan per repo,
                    which run as capacity frees up (follow them in Scans &rarr; Scan queue). Queue
                    the batch from the Supply Chain Scanner card in Other Scans. Works for a user or
                    an org you belong to; you only ever see your own repos, never another
                    user&apos;s private ones.
                  </p>
                </div>
                <p className={styles.fieldHint}>
                  What you type decides which credential is used, both set in{' '}
                  <Link href={SETTINGS_KEYS_HREF} style={{ color: 'var(--accent-primary)', fontWeight: 500 }}>
                    Global Settings
                  </Link>:
                </p>
                <ul className={styles.inputHintList}>
                  <li>
                    An org name or a github.com URL uses the GitHub Access Token. Public repos
                    don&apos;t need it; private repos do, and it lifts the anonymous rate limit.
                  </li>
                  <li>
                    A GitHub Enterprise URL (e.g. https://ghe.example.com/orgs/acme-corp) uses the
                    GitHub Enterprise Token. That host must first be registered as the GitHub
                    Enterprise Host (the allowlist).
                  </li>
                  <li>
                    Any other host is refused before anything runs; no token is sent and no
                    connection is made.
                  </li>
                </ul>
                <p className={styles.fieldHint}>
                  The two tokens are never swapped. If the matching one is missing, the scan runs
                  anonymously (public repos only).
                </p>
              </>
            ) : (
              <>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel} htmlFor="sc-repo-url">Repository</label>
                  <input
                    id="sc-repo-url"
                    type="text"
                    className="textInput"
                    placeholder="owner/repo or https://github.com/owner/repo"
                    value={repoUrl}
                    onChange={(e) => setField(updateField, 'supplyChainRepoUrl', e.target.value)}
                  />
                  {repoInvalid && (
                    <span className={styles.fieldHintWarning}>
                      Must be a repository as owner/repo, or its https URL on github.com or a GitHub
                      Enterprise host you configured in Global Settings.
                    </span>
                  )}
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel} htmlFor="sc-repo-ref">Branch / tag</label>
                  <input
                    id="sc-repo-ref"
                    type="text"
                    className="textInput"
                    placeholder="default branch"
                    value={repoRef}
                    onChange={(e) => setField(updateField, 'supplyChainRepoRef', e.target.value)}
                  />
                  {refInvalid && (
                    <span className={styles.fieldHintWarning}>
                      Branch/tag contains characters git does not allow.
                    </span>
                  )}
                </div>
                <p className={styles.fieldHint}>
                  The repository is cloned shallowly inside the scan sandbox and its lockfiles are
                  audited. Public repos clone anonymously; private ones use the GitHub Access Token
                  from{' '}
                  <Link href={SETTINGS_KEYS_HREF} style={{ color: 'var(--accent-primary)', fontWeight: 500 }}>
                    Global Settings
                  </Link>.
                </p>
              </>
            )}

            {error && <span className={styles.fieldHintWarning}>{error}</span>}
          </div>

          {/* An upload needs no credential; an org or repo target may. Optional
              throughout: a public repo clones anonymously, and the GHE pair only
              matters when the target names that host. */}
          {source !== 'upload' && (
            <>
              <div className={styles.groupHeader}>
                <h3 className={styles.subSectionTitle}>Credentials</h3>
                <p className={styles.fieldHint}>
                  Only needed to reach a private repository or to lift the anonymous rate limit.
                </p>
              </div>
              <div className={styles.credentialStack}>
                <CredentialShortcut settingsKey="supplyChainGithubToken" keys={keys} optional />
                <CredentialShortcut settingsKey="githubEnterpriseHost" keys={keys} optional />
                <CredentialShortcut settingsKey="githubEnterpriseToken" keys={keys} optional />
              </div>
            </>
          )}

          <RegistryFields
            keys={['supplyChainDeepAnalysisEnabled', 'supplyChainEcosystems', 'supplyChainOrgDeepAnalysisEnabled', 'supplyChainOrgIncludeArchived', 'supplyChainOrgIncludeForks', 'supplyChainOrgMaxRepos', 'supplyChainOrgRef', 'supplyChainRepoScope']}
            data={data}
            updateField={updateField}
            title="Advanced"
            description="Settings this tool accepts that have no dedicated control. Bounds, options and descriptions come from the settings registry, so they are the same ones the API enforces."
          />
        </div>
      )}
    </div>
  )
}
