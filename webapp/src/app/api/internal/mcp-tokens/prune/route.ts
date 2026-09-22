/**
 * Prune long-dead MCP access tokens.
 *
 * Revoked and expired rows are kept and shown, because "why did my agent stop
 * working" is the common support question. They are not kept forever: after a
 * retention window they are deleted outright.
 *
 * Called from the orchestrator's existing maintenance loop. The webapp has no
 * scheduler of its own - no instrumentation.ts, no setInterval - so this is
 * driven from outside rather than by inventing one here.
 */
import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { isInternalRequest } from '@/lib/session'

export const runtime = 'nodejs'

const DEFAULT_RETENTION_DAYS = 90
const DAY_MS = 86_400_000

export function retentionDays(): number {
  const raw = parseInt(process.env.MCP_TOKEN_RETENTION_DAYS || '', 10)
  // 0 / negative / unset / garbage -> the documented default. A huge value
  // effectively disables pruning.
  return Number.isFinite(raw) && raw > 0 ? raw : DEFAULT_RETENTION_DAYS
}

export async function POST(request: NextRequest) {
  if (!isInternalRequest(request)) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }
  try {
    const cutoff = new Date(Date.now() - retentionDays() * DAY_MS)
    const { count } = await prisma.mcpAccessToken.deleteMany({
      where: {
        OR: [
          { revokedAt: { lt: cutoff } },
          { expiresAt: { lt: cutoff } },
        ],
      },
    })
    if (count > 0) console.info(`[mcp-tokens] pruned ${count} dead token(s)`)
    return NextResponse.json({ pruned: count, cutoff: cutoff.toISOString() })
  } catch (error) {
    console.error('[mcp-tokens] prune failed:', error)
    return NextResponse.json({ error: 'Prune failed' }, { status: 500 })
  }
}
