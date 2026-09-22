/**
 * Deep links into Global Settings.
 *
 * /settings renders a tab bar and reads the initial tab from `?tab=`. A bare
 * href="/settings" therefore always lands on LLM Providers, so a link that
 * said "configure your API key here" dropped the user on an unrelated screen
 * and left them to find the right tab themselves.
 *
 * The ids below MUST stay in sync with `validTabs` in
 * webapp/src/app/settings/page.tsx - an unknown id silently falls back to
 * 'providers', which is exactly the broken behaviour these links exist to fix.
 * settingsLinks.test.ts reads that array out of the page source and fails if
 * the two ever drift.
 */

export const SETTINGS_TABS = {
  providers: 'providers',
  skills: 'skills',
  chatSkills: 'chat-skills',
  tradecraft: 'tradecraft',
  keys: 'keys',
  mcp: 'mcp',
  mcpTokens: 'mcp-tokens',
  system: 'system',
} as const

export type SettingsTab = (typeof SETTINGS_TABS)[keyof typeof SETTINGS_TABS]

/** Href for a specific Global Settings tab. */
export function settingsHref(tab: SettingsTab): string {
  return `/settings?tab=${tab}`
}

/** API Keys & Tunneling - where every tool token and API key lives. */
export const SETTINGS_KEYS_HREF = settingsHref(SETTINGS_TABS.keys)

/** Agent Skills - where user-uploaded .md skill files live. */
export const SETTINGS_SKILLS_HREF = settingsHref(SETTINGS_TABS.skills)

/** MCP Server - the INBOUND credentials other agents connect in with. */
export const SETTINGS_MCP_TOKENS_HREF = settingsHref(SETTINGS_TABS.mcpTokens)
