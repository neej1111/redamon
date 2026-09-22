/**
 * Scan Queue - re-confirm a needs_review job (plan Phase 5, C-4).
 *
 * A job moves to needs_review when its scan settings changed between enqueue and
 * dispatch. Re-confirming accepts the CURRENT configuration: recompute the
 * fingerprint from the live project and requeue. Object-level authz as in cancel:
 * projectId is re-resolved from the row and guardProject-ed (404 on non-ownership).
 */
import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { guardProject } from '@/lib/access'
import { settingsFingerprint } from '@/lib/jobQueue'
import { resolveTrufflehogFingerprintExtra } from '@/lib/trufflehogStart'
import { authProfileFingerprintExtra } from '@/lib/authProfileFingerprint'

export const runtime = 'nodejs'

interface RouteParams {
  params: Promise<{ id: string }>
}

export async function POST(_request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const row = await prisma.jobQueue.findUnique({ where: { id } })
    if (!row) return NextResponse.json({ error: 'Not found' }, { status: 404 })
    const denied = await guardProject(row.projectId)
    if (denied) return denied

    if (row.status !== 'needs_review') {
      return NextResponse.json(
        { error: `Only a job awaiting review can be re-confirmed (state '${row.status}').`, status: row.status },
        { status: 409 },
      )
    }

    const project = await prisma.project.findUnique({ where: { id: row.projectId } })
    if (!project) {
      // The project is gone; there is nothing to run. Fail the row.
      await prisma.jobQueue.update({
        where: { id },
        data: { status: 'failed', error: 'project no longer exists', finishedAt: new Date() },
      })
      return NextResponse.json({ error: 'Project not found' }, { status: 404 })
    }

    // Both contributions, exactly as enqueue and dispatch compute them. Folding
    // in only the TruffleHog half stored a hash the dispatcher could not
    // reproduce for a full_recon or partial_recon job, whose auth profile is a
    // relation the Project-row fingerprint cannot see: the job was re-confirmed,
    // dispatched, failed the comparison and went straight back to needs_review,
    // with no way out for anyone.
    const settingsHash = settingsFingerprint(
      row.kind, project as unknown as Record<string, unknown>,
      {
        ...(await resolveTrufflehogFingerprintExtra(
          row.kind, row.projectId, (row.payload ?? {}) as Record<string, unknown>,
        )),
        ...(await authProfileFingerprintExtra(row.kind, row.projectId)),
      },
    )
    await prisma.jobQueue.update({
      where: { id },
      data: {
        status: 'queued',
        settingsHash, // accept the CURRENT configuration
        blockedCode: '',
        blockedReason: '',
        notBefore: null,
      },
    })
    return NextResponse.json({ ok: true })
  } catch (error) {
    console.error('[jobQueue] reconfirm failed:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Internal server error' },
      { status: 500 },
    )
  }
}
