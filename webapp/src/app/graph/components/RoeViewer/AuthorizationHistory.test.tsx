/**
 * The authorization panel: strategy row 10, plus one regression.
 *
 * Row 10's claim is that a failed fetch is not "no records". Telling an
 * operator their third-party engagement has no authorization when the truth is
 * that nobody could ask is the one reading of this panel that leads somewhere
 * bad, and the two states are one `catch` apart.
 *
 * The regression below is a different failure of the same panel: everything it
 * renders arrives from an agent holding engagement:authorize, so it is
 * untrusted input rendered into the operator's own session.
 *
 * Run: npx vitest run --no-file-parallelism \
 *   src/app/graph/components/RoeViewer/AuthorizationHistory.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, waitFor } from '@testing-library/react'

vi.mock('./RoeViewer.module.css', () => ({ default: new Proxy({}, { get: (_t, k) => String(k) }) }))

import { AuthorizationHistory, type AuthorizationRecord } from './AuthorizationHistory'

const record = (over: Partial<AuthorizationRecord> = {}): AuthorizationRecord => ({
  id: 'a1',
  documentSha256: 'a'.repeat(64),
  documentKind: 'hackerone_program',
  sourceUrl: 'https://hackerone.com/example',
  programHandle: 'example',
  issuedAt: '2026-01-01T00:00:00.000Z',
  recordedAt: '2026-01-02T00:00:00.000Z',
  recordedVia: 'mcp',
  recordedByTokenId: 't1',
  summary: '428 in scope',
  ...over,
})

function respond(body: unknown, ok = true, status = 200) {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
    ok, status, json: async () => body,
  }))
}

beforeEach(() => vi.clearAllMocks())
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

describe('row 10: a failed fetch is not "no records"', () => {
  test('a non-2xx shows the retry copy and never the empty-state copy', async () => {
    respond({}, false, 500)
    render(<AuthorizationHistory projectId="p1" engagementKind="third_party" />)
    await waitFor(() => {
      expect(screen.getByText(/Could not read the authorization records/)).toBeTruthy()
    })
    expect(screen.queryByText(/No record of what authorized/)).toBeNull()
  })

  test('a rejected fetch shows the same retry copy', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('offline')))
    render(<AuthorizationHistory projectId="p1" engagementKind="third_party" />)
    await waitFor(() => {
      expect(screen.getByText(/Could not read the authorization records/)).toBeTruthy()
    })
  })

  test('a genuinely empty third-party engagement says so, and warns', async () => {
    respond({ authorizations: [] })
    render(<AuthorizationHistory projectId="p1" engagementKind="third_party" />)
    await waitFor(() => {
      expect(screen.getByText(/No record of what authorized/)).toBeTruthy()
    })
    expect(screen.queryByText(/Could not read/)).toBeNull()
  })

  test('an empty internal engagement is not a warning', async () => {
    respond({ authorizations: [] })
    render(<AuthorizationHistory projectId="p1" engagementKind="internal" />)
    await waitFor(() => {
      expect(screen.getByText(/does not\s+need one/)).toBeTruthy()
    })
  })

  test('records render', async () => {
    respond({ authorizations: [record()] })
    render(<AuthorizationHistory projectId="p1" engagementKind="third_party" />)
    await waitFor(() => expect(screen.getByText(/HackerOne program/)).toBeTruthy())
  })
})

describe('a stored sourceUrl is never rendered as a clickable non-http link', () => {
  // sourceUrl is `z.string().max(2000)` on the MCP tool and only trimmed before
  // storage, so an agent holding engagement:authorize chooses this string. It
  // used to reach a bare `<a href>`, which makes a javascript: or data: URL one
  // operator click away from running in the app's own origin.
  test.each([
    'javascript:alert(document.cookie)',
    'JaVaScRiPt:alert(1)',
    'data:text/html,<script>alert(1)</script>',
    'vbscript:msgbox(1)',
    ' javascript:alert(1)',
  ])('%s is shown as text, not as a link', async raw => {
    respond({ authorizations: [record({ sourceUrl: raw })] })
    const { container } = render(<AuthorizationHistory projectId="p1" />)
    await waitFor(() => expect(screen.getByText(raw.trim())).toBeTruthy())
    expect(container.querySelector('a')).toBeNull()
  })

  test('an ordinary https source is still a link that opens safely', async () => {
    respond({ authorizations: [record({ sourceUrl: 'https://hackerone.com/example' })] })
    const { container } = render(<AuthorizationHistory projectId="p1" />)
    await waitFor(() => expect(container.querySelector('a')).toBeTruthy())
    const a = container.querySelector('a')!
    expect(a.getAttribute('href')).toBe('https://hackerone.com/example')
    expect(a.getAttribute('rel')).toBe('noopener noreferrer')
  })
})
