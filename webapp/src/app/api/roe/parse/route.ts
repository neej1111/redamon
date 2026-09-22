import { NextRequest, NextResponse } from 'next/server'
import { internalKeyHeaders } from '@/lib/agentAuth'
import { getEffectiveUser } from '@/lib/session'
import { buildParseProposal, proposalIsImplausible, MAX_PROPOSED_CHANGES } from '@/lib/reconSettings/roeParse'

const AGENT_API_URL = process.env.AGENT_API_URL || process.env.NEXT_PUBLIC_AGENT_API_URL || 'http://localhost:8080'
const MAX_FILE_SIZE = 20 * 1024 * 1024 // 20 MB
const MAX_PDF_PAGES = 200
const AGENT_TIMEOUT_MS = 120_000 // 2 minutes for LLM parsing

/**
 * The form's present values, so the proposal is a diff rather than a list.
 *
 * Optional: without it every parsed field reads as a change, which is correct
 * for a new project and merely noisier for an existing one.
 */
function readCurrentValues(formData: FormData): Record<string, unknown> {
  const raw = formData.get('current')
  if (typeof raw !== 'string' || raw.trim() === '') return {}
  try {
    const parsed = JSON.parse(raw)
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {}
  } catch {
    return {}
  }
}

// POST /api/roe/parse - Upload RoE document, extract text, forward to agent for LLM parsing
export async function POST(request: NextRequest) {
  try {
    const formData = await request.formData()
    const file = formData.get('file') as File | null

    if (!file) {
      return NextResponse.json({ error: 'No file provided' }, { status: 400 })
    }

    // File size guard
    if (file.size > MAX_FILE_SIZE) {
      return NextResponse.json(
        { error: `File too large (${(file.size / 1024 / 1024).toFixed(1)} MB). Maximum is ${MAX_FILE_SIZE / 1024 / 1024} MB.` },
        { status: 400 }
      )
    }

    // Extract text based on file type
    const mimeType = file.type || ''
    const fileName = file.name.toLowerCase()
    let text = ''

    if (mimeType === 'text/plain' || fileName.endsWith('.txt') || fileName.endsWith('.md')) {
      text = await file.text()
    } else if (mimeType === 'application/pdf' || fileName.endsWith('.pdf')) {
      // Use pdfjs-dist directly - pdf-parse v2 triggers DOMMatrix errors in Node.js
      // pdfjs-dist is in serverExternalPackages so it's loaded from node_modules at runtime
      const pdfjs = await import('pdfjs-dist/legacy/build/pdf.mjs')
      const path = await import('path')
      pdfjs.GlobalWorkerOptions.workerSrc = path.resolve(
        process.cwd(), 'node_modules/pdfjs-dist/legacy/build/pdf.worker.mjs'
      )
      const data = new Uint8Array(await file.arrayBuffer())
      const doc = await pdfjs.getDocument({ data, useSystemFonts: true }).promise
      try {
        if (doc.numPages > MAX_PDF_PAGES) {
          await doc.destroy()
          return NextResponse.json(
            { error: `PDF has ${doc.numPages} pages (max ${MAX_PDF_PAGES}). Please use a shorter document.` },
            { status: 400 }
          )
        }
        const pages: string[] = []
        for (let i = 1; i <= doc.numPages; i++) {
          const page = await doc.getPage(i)
          const content = await page.getTextContent()
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          pages.push(content.items.map((item: any) => item.str || '').join(' '))
        }
        text = pages.join('\n')
      } finally {
        await doc.destroy()
      }
    } else if (
      mimeType === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' ||
      fileName.endsWith('.docx')
    ) {
      const mammoth = await import('mammoth')
      const buffer = Buffer.from(await file.arrayBuffer())
      const result = await mammoth.extractRawText({ buffer })
      text = result.value
    } else {
      return NextResponse.json(
        { error: `Unsupported file type: ${mimeType || fileName}. Use .pdf, .txt, .md, or .docx` },
        { status: 400 }
      )
    }

    if (!text.trim()) {
      return NextResponse.json({ error: 'Could not extract text from document' }, { status: 422 })
    }

    // Forward extracted text to agent for LLM parsing (with timeout)
    const model = formData.get('model') as string | null
    const userId = (await getEffectiveUser())?.userId ?? null
    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), AGENT_TIMEOUT_MS)

    let agentResponse: Response
    try {
      agentResponse = await fetch(`${AGENT_API_URL}/roe/parse`, {
        method: 'POST',
        headers: internalKeyHeaders({ 'Content-Type': 'application/json' }),
        // The caller's id travels with the request so the agent can resolve THIS
        // user's LLM providers. Without it the agent falls back to whatever
        // project settings happen to be cached in its orchestrator, and on a
        // freshly started agent - or when the document is uploaded while
        // CREATING a project, which is the only place this feature is offered -
        // there is no project loaded and no provider key, so every parse failed
        // with "LLM not available" whatever model was asked for.
        body: JSON.stringify({ text, ...(model && { model }), ...(userId && { user_id: userId }) }),
        signal: controller.signal,
      })
    } catch (fetchError) {
      if (fetchError instanceof DOMException && fetchError.name === 'AbortError') {
        return NextResponse.json({ error: 'RoE parsing timed out. Try a shorter document or different model.' }, { status: 504 })
      }
      throw fetchError
    } finally {
      clearTimeout(timeout)
    }

    if (!agentResponse.ok) {
      const errorData = await agentResponse.json().catch(() => ({}))
      return NextResponse.json(
        { error: errorData.error || 'Agent parsing failed' },
        { status: agentResponse.status }
      )
    }

    const parsed = await agentResponse.json()

    // The agent returns what the MODEL said. This turns it into a PROPOSAL: every
    // value re-validated against the same registry bounds an MCP write goes
    // through, a scope column refused rather than applied, and a rejected value
    // reported rather than dropped. Nothing here writes; the form shows the diff
    // and a person confirms it.
    //
    // Re-validating is not belt and braces. The document is a third party's text,
    // an LLM reading it is not a sanitiser, and after the parser gained the whole
    // pipeline the difference between "validated" and "trusted" is the difference
    // between a configuration change and a configuration attack.
    const fields = (parsed?.fields ?? {}) as Record<string, unknown>
    const current = readCurrentValues(formData)
    const proposal = buildParseProposal(fields, current)

    // A document that would change more settings than any real one ever has is
    // a failed parse, not a demanding policy. Refusing beats asking somebody to
    // review hundreds of rows they did not ask for.
    if (proposalIsImplausible(proposal.changes.length)) {
      return NextResponse.json(
        {
          error:
            `The model proposed ${proposal.changes.length} setting changes from this document, ` +
            `which is more than any Rules of Engagement document should make (limit ${MAX_PROPOSED_CHANGES}). ` +
            `Nothing has been changed. This is almost always the model answering with its whole field ` +
            `list rather than reading the document; try again, or try a different model.`,
          proposedCount: proposal.changes.length,
          limit: MAX_PROPOSED_CHANGES,
        },
        { status: 422 }
      )
    }

    return NextResponse.json({
      ...proposal,
      // Kept separate from the proposal: it is the document, not a setting a
      // person reviews, and the form stores it alongside whatever it confirms.
      roeRawText: text,
      unknownKeys: parsed?.unknownKeys ?? [],
      registryDigest: parsed?.registryDigest ?? null,
    })
  } catch (error) {
    console.error('RoE parse error:', error)
    return NextResponse.json(
      { error: `Failed to parse RoE document: ${error instanceof Error ? error.message : String(error)}` },
      { status: 500 }
    )
  }
}
