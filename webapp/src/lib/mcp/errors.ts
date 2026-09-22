/**
 * Error normalisation for the inbound MCP surface.
 *
 * A stable, safe message leaves the process; the full detail goes to the server
 * log. The project already has the counter-pattern in
 * `normalizeOrchestratorStartError` ("never render the raw object"), and this
 * applies the same rule to every MCP response: no stack traces, no file paths,
 * no Cypher or schema fragments, no upstream body passed through.
 *
 * Why it matters more here than in the UI: the caller is an external agent that
 * will put whatever it receives into a model's context. An upstream error
 * carrying a hostname, a provider message or a Cypher fragment becomes training
 * data for the next prompt, and a leaked internal path becomes reconnaissance.
 */

/** An error whose message was WRITTEN to be shown to the caller. */
export class McpToolError extends Error {
  constructor(message: string, public code?: string) {
    super(message)
    this.name = 'McpToolError'
  }
}

/**
 * Turn anything thrown into a safe string.
 *
 * `McpToolError` passes through because its message was authored for the
 * caller. Everything else is replaced with a generic line and logged, because
 * an unplanned error's message was authored for a developer.
 */
export function safeMessage(err: unknown, fallback: string, context: string): string {
  if (err instanceof McpToolError) return err.message
  console.error(`[mcp] ${context}:`, err)
  return fallback
}

/** The MCP tool-result shape for a failure. */
export function toolError(message: string) {
  return {
    isError: true,
    content: [{ type: 'text' as const, text: message }],
  }
}

/** The MCP tool-result shape for a success, carrying JSON the model can read. */
export function toolJson(payload: unknown) {
  return {
    content: [{ type: 'text' as const, text: JSON.stringify(payload, null, 2) }],
  }
}
