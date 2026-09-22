/**
 * NL -> Cypher for the graph views.
 *
 * This route used to forward `user_id` and `project_id` straight from the
 * client body with no ownership check and no internal key. The agent endpoint
 * behind it spends the BODY-NAMED user's LLM provider key, so any logged-in
 * user could generate Cypher against any project and bill any other user's
 * key. The identity now comes from the session and the body's is ignored
 * (mcp_plan.md P0-3).
 */
import { NextRequest, NextResponse } from 'next/server'
import { requireEffectiveUser, requireProjectAccess } from '@/lib/access'
import { internalKeyHeaders } from '@/lib/agentAuth'

const AGENT_API_URL = process.env.AGENT_API_URL || process.env.NEXT_PUBLIC_AGENT_API_URL || 'http://localhost:8080'

export async function POST(request: NextRequest) {
  const eff = await requireEffectiveUser()
  if (eff instanceof NextResponse) return eff

  let body: Record<string, unknown>
  try {
    body = await request.json()
  } catch {
    return NextResponse.json({ error: 'Invalid JSON body' }, { status: 400 })
  }

  const projectId = typeof body.project_id === 'string' ? body.project_id : ''
  const access = await requireProjectAccess(eff, projectId)
  if (access instanceof NextResponse) return access

  try {
    const resp = await fetch(`${AGENT_API_URL}/text-to-cypher`, {
      method: 'POST',
      headers: internalKeyHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({
        ...body,
        // The session decides whose projects and whose LLM key are used, never
        // the caller's body.
        user_id: eff.userId,
        project_id: access.project.id,
      }),
    })

    if (!resp.ok) {
      // The upstream body can carry a model name, a Cypher fragment or a
      // provider error; keep it in the server log and return a stable string.
      const detail = await resp.text().catch(() => '')
      console.error(`[text-to-cypher] agent returned ${resp.status}: ${detail}`)
      return NextResponse.json(
        { error: 'Could not generate a query for that question.' },
        { status: resp.status }
      )
    }
    return NextResponse.json(await resp.json())
  } catch (error) {
    console.error('Text-to-cypher proxy error:', error)
    return NextResponse.json({ error: 'Could not reach the query generator.' }, { status: 502 })
  }
}
