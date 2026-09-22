/**
 * One dispatch entry point that routes a JobQueue `kind` to the SAME start path
 * the user's button uses (Scan Queue plan, R2). The queue dispatcher never spawns
 * a container: it asks the webapp, and the webapp re-runs the identical start path,
 * so RoE, guardrails, the activation lock, target validation, the version freeze
 * and admission all re-run at dispatch, hours after enqueue.
 *
 * full_recon goes through lib/startFullScan.ts (the shared full-scan path with the
 * version freeze). Every other kind forwards to its orchestrator start endpoint,
 * mirroring its /api/.../start route body exactly.
 */
import prisma from '@/lib/prisma'
import { loadEngagement } from '@/lib/engagement'
import { resolveTrufflehogStart } from '@/lib/trufflehogStart'
import { orchestratorFetch } from '@/lib/orchestrator'
import { normalizeOrchestratorStartError } from '@/lib/orchestratorError'
import { startFullScan } from '@/lib/startFullScan'
import { parseScanMode, type ScanTrigger } from '@/lib/scanTimeline'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'
const WEBAPP_URL = process.env.WEBAPP_URL || 'http://localhost:3000'

export interface DispatchStartResult {
  ok: boolean
  status: number
  error?: string
  limit?: Record<string, unknown>
  activationInProgress?: boolean
  busy?: string
  state?: unknown
  scanJobId?: string | null
  runId?: string
}

export type StartScanPayload = Record<string, unknown>

/** Kinds whose orchestrator start body is just {project_id, user_id, webapp_api_url}. */
const SIMPLE_KIND_ENDPOINT: Record<string, { path: (p: string) => string; fallback: string }> = {
  gvm: { path: p => `/gvm/${p}/start`, fallback: 'Failed to start GVM scan' },
  github_hunt: { path: p => `/github-hunt/${p}/start`, fallback: 'Failed to start GitHub Secret Hunt' },
  supply_chain: { path: p => `/supply-chain/${p}/start`, fallback: 'Failed to start Supply-Chain scan' },
  // A per-repo batch item runs the supply-chain container; its repo config is
  // applied by the env-override layer in scanners/supply_chain_scan/project_settings.py.
  supply_chain_repo: { path: p => `/supply-chain/${p}/start`, fallback: 'Failed to start Supply-Chain scan' },
}

function runId(state: unknown): string {
  if (state && typeof state === 'object') {
    const s = state as Record<string, unknown>
    const v = s.run_id ?? s.runId
    if (typeof v === 'string') return v
  }
  return ''
}

/** Orchestrator stop endpoint per kind. Run-based kinds need the run id. */
const STOP_ENDPOINT: Record<string, (p: string, r: string) => string | null> = {
  full_recon: p => `/recon/${p}/stop`,
  gvm: p => `/gvm/${p}/stop`,
  github_hunt: p => `/github-hunt/${p}/stop`,
  // Run-keyed: the run id is the source. A project-level stop would kill
  // whichever source the orchestrator happened to pick, or nothing at all.
  trufflehog: (p, r) => (r ? `/trufflehog/${p}/${encodeURIComponent(r)}/stop` : null),
  supply_chain: p => `/supply-chain/${p}/stop`,
  supply_chain_repo: p => `/supply-chain/${p}/stop`,
  ai_attack: (p, r) => (r ? `/ai-attack-surface/${p}/${r}/stop` : null),
  partial_recon: (p, r) => (r ? `/recon/${p}/partial/${r}/stop` : null),
}

/**
 * Best-effort stop of a scan that was just started. Used when a job is canceled in
 * the narrow window between dispatch claiming it and marking it running (Finding 1):
 * the scan already began, so we tell the orchestrator to stop it. Never throws.
 */
export async function stopScan(kind: string, projectId: string, runId = ''): Promise<void> {
  const build = STOP_ENDPOINT[kind]
  const path = build ? build(projectId, runId) : null
  if (!path) return
  try {
    await orchestratorFetch(`${RECON_ORCHESTRATOR_URL}${path}`, { method: 'POST' })
  } catch (e) {
    console.warn(`[jobQueue] best-effort stop of ${kind} for ${projectId} failed:`, e)
  }
}

export async function dispatchStart(
  kind: string,
  projectId: string,
  opts: { actorUserId?: string | null; payload?: StartScanPayload } = {},
): Promise<DispatchStartResult> {
  const payload = opts.payload ?? {}

  // full_recon: the shared full-scan path (version freeze + ScanJob history).
  if (kind === 'full_recon') {
    const mode = parseScanMode(payload.mode) ?? 'new'
    const trigger: ScanTrigger = 'scheduled'
    const r = await startFullScan({ projectId, mode, trigger, actorUserId: opts.actorUserId ?? null })
    if (r.ok) {
      return { ok: true, status: 200, state: r.state, scanJobId: r.scanJobId ?? null, runId: runId(r.state) }
    }
    return {
      ok: false,
      status: r.status,
      error: r.error,
      limit: r.limit,
      activationInProgress: r.activationInProgress,
      busy: r.busy,
      scanJobId: r.scanJobId ?? null,
    }
  }

  const project = await prisma.project.findUnique({
    where: { id: projectId },
    select: { id: true, userId: true, supplyChainInputMode: true },
  })
  if (!project) return { ok: false, status: 404, error: 'Project not found' }

  // The engagement rule applies to the OTHER scanners too, and it has to be
  // checked here rather than only in startFullScan: GVM sweeps ports, the
  // GitHub hunt reads an organization's repositories, and the supply-chain scan
  // clones one. All three reach somebody else's estate.
  //
  // The queue dispatcher and the scheduler both arrive through this function
  // with nobody watching, which is exactly why the check is server-side: an
  // agent-facing rule that only applies when an agent is present is not a
  // control.
  const engagement = await loadEngagement(projectId)
  if (engagement.blockers.length > 0) {
    return {
      ok: false,
      status: 409,
      error:
        'This is a third-party engagement and it is not startable: ' +
        engagement.blockers.join(' '),
    }
  }

  // 'org' is not an input this scan can read: it means "enumerate the account
  // and queue one scan per repo", which is a different kind (supply_chain_repo).
  // Dispatching it anyway would spawn a container that dies looking for an SBOM.
  if (kind === 'supply_chain' && project.supplyChainInputMode === 'org') {
    return {
      ok: false,
      status: 400,
      error: 'This project scans a GitHub organization. Queue the org batch from Other Scans '
        + 'instead, or set an SBOM/repository input in project settings.',
    }
  }

  let path: string
  let body: Record<string, unknown>
  let fallback: string

  const simple = SIMPLE_KIND_ENDPOINT[kind]
  if (simple) {
    path = simple.path(projectId)
    fallback = simple.fallback
    body = { project_id: projectId, user_id: project.userId, webapp_api_url: WEBAPP_URL }
    // A supply_chain_repo (org-batch) item carries its target repo in the payload;
    // forward it as a per-repo override so the container scans THIS repo, not the
    // project's default supply-chain config (Phase 6).
    if (kind === 'supply_chain_repo') {
      body.repo_override_url = typeof payload.repo_url === 'string' ? payload.repo_url : ''
      // Empty = github.com. Set for a GitHub Enterprise batch so the container
      // clones from that host and asks for the matching credential.
      body.repo_override_host = typeof payload.host === 'string' ? payload.host : ''
      body.repo_override_ref = typeof payload.ref === 'string' ? payload.ref : ''
      body.repo_override_scope = typeof payload.scope === 'string' ? payload.scope : ''
      body.repo_override_deep = !!payload.deep_analysis
    }
  } else if (kind === 'trufflehog') {
    // A dedicated branch, not the simple one: a queued TruffleHog job carries
    // its source (and the profile that defines the target) in the payload, and
    // the simple branch forwards no payload at all — the job would dispatch with
    // no source and run the wrong config.
    const resolved = await resolveTrufflehogStart(projectId, {
      profileId: typeof payload.profile_id === 'string' ? payload.profile_id : undefined,
      source: typeof payload.source === 'string' ? payload.source : undefined,
      webappUrl: WEBAPP_URL,
    })
    if (!resolved.ok) return { ok: false, status: resolved.status, error: resolved.error }
    path = `/trufflehog/${projectId}/start`
    fallback = 'Failed to start Secret Multiscanner scan'
    body = resolved.body as unknown as Record<string, unknown>
  } else if (kind === 'ai_attack') {
    path = `/ai-attack-surface/${projectId}/start`
    fallback = 'Failed to start AI Attack Surface scan'
    body = {
      project_id: projectId,
      user_id: project.userId,
      webapp_api_url: WEBAPP_URL,
      tool: payload.tool ?? 'garak',
      targets: payload.targets ?? [],
      bounds: payload.bounds ?? {},
      roe_confirmed: payload.roe_confirmed ?? false,
      dry_run: payload.dry_run ?? false,
      probes: payload.probes ?? [],
      strategies: payload.strategies ?? [],
      objective: payload.objective ?? '',
      target_model: payload.target_model ?? '',
      target_purpose: payload.target_purpose ?? '',
      // The GitHub token / api_key is never carried in a queue payload (see the
      // enqueue guard: ai_attack with a non-empty api_key is not queueable).
      api_key: payload.api_key ?? '',
      auth_header: payload.auth_header ?? '',
      auth_scheme: payload.auth_scheme ?? '',
    }
  } else if (kind === 'partial_recon') {
    path = `/recon/${projectId}/partial`
    fallback = 'Failed to start partial recon'
    body = {
      project_id: projectId,
      user_id: project.userId,
      webapp_api_url: WEBAPP_URL,
      tool_id: payload.tool_id,
      graph_inputs: payload.graph_inputs,
      user_inputs: payload.user_inputs ?? [],
      user_targets: payload.user_targets ?? null,
      include_graph_targets: payload.include_graph_targets ?? true,
      settings_overrides: payload.settings_overrides ?? {},
    }
  } else {
    return { ok: false, status: 400, error: `Unknown scan kind: ${kind}` }
  }

  const response = await orchestratorFetch(`${RECON_ORCHESTRATOR_URL}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}))
    const { error, limit } = normalizeOrchestratorStartError(errorData, fallback)
    return {
      ok: false,
      status: response.status,
      error,
      ...(limit ? { limit: limit as Record<string, unknown> } : {}),
    }
  }

  const state = await response.json().catch(() => ({}))
  return { ok: true, status: 200, state, runId: runId(state) }
}
