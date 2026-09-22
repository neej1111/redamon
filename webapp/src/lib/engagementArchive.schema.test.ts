/**
 * The archive table must be in the Prisma schema, or `db push` deletes it.
 *
 * Found by opening 20 engagements over MCP and then trying to clean them up.
 * Nine would not delete:
 *
 *   500 "Could not archive this project's engagement authorization records, so
 *        it was not deleted."
 *   relation "engagement_authorization_archive" does not exist
 *
 * The table was created by raw SQL from the webapp entrypoint, deliberately
 * outside the schema. `prisma db push --accept-data-loss` drops what the schema
 * does not declare, so every push removed it and only the next webapp boot put
 * it back. In between, the `Restrict` foreign key made every project holding an
 * authorization record permanently undeletable. `db push` is how this repo
 * applies schema changes, so that window was normal working practice, not an
 * edge case.
 *
 * `engagementArchive.integration.test.ts` covers the archive behaviour against
 * real SQL but skips unless DATABASE_URL is set, and it assumes the table is
 * already there - which it always was, in an environment that had just booted.
 * This one always runs, and asserts the one property that stops the table
 * disappearing again.
 *
 * @vitest-environment node
 */
import { readFileSync } from 'fs'
import { fileURLToPath } from 'url'

import { describe, test, expect } from 'vitest'

const SCHEMA = readFileSync(
  fileURLToPath(new URL('../../prisma/schema.prisma', import.meta.url)),
  'utf8'
)
const SOURCE = readFileSync(
  fileURLToPath(new URL('./engagementArchive.ts', import.meta.url)),
  'utf8'
)

function modelBlock(name: string): string {
  const start = SCHEMA.indexOf(`model ${name} {`)
  expect(start, `model ${name} is not in schema.prisma`).toBeGreaterThan(-1)
  return SCHEMA.slice(start, SCHEMA.indexOf('\n}', start))
}

describe('the archive survives db push', () => {
  test('it is a declared model, not raw SQL the push will drop', () => {
    const block = modelBlock('EngagementAuthorizationArchive')
    expect(block).toContain('@@map("engagement_authorization_archive")')
  })

  test('it holds no relation to Project, because it outlives one', () => {
    // A foreign key to Project would defeat the entire purpose: the row exists
    // precisely because that project has been deleted.
    const block = modelBlock('EngagementAuthorizationArchive')
    expect(block).not.toMatch(/@relation/)
  })

  test('every column the archive writes is declared', () => {
    // The INSERT is raw SQL, so nothing else checks these agree. A column added
    // to the statement and not to the model fails at run time, during a delete,
    // which is the worst moment to find out.
    const insert = /INSERT INTO engagement_authorization_archive \(([\s\S]*?)\)/.exec(SOURCE)
    expect(insert, 'the archive INSERT was not found').not.toBeNull()

    const columns = insert![1]
      .split(',')
      .map(c => c.trim())
      .filter(Boolean)
    expect(columns.length).toBeGreaterThan(5)

    const block = modelBlock('EngagementAuthorizationArchive')
    const missing = columns.filter(col => {
      // A column appears either as an @map target or as the field name itself.
      const camel = col.replace(/_([a-z])/g, (_, c: string) => c.toUpperCase())
      return !block.includes(`@map("${col}")`) && !new RegExp(`\\b${camel}\\b`).test(block)
    })
    expect(missing, `columns written but not declared: ${missing.join(', ')}`).toEqual([])
  })

  test('the live table keeps its append-only trigger applied on every boot', () => {
    // The table is now Prisma's, but the TRIGGER still is not: Prisma has no
    // primitive for one, so the boot script remains the only thing that puts it
    // back after a push. Deleting that script would silently end the
    // append-only guarantee while every test here still passed.
    const script = readFileSync(
      fileURLToPath(new URL('../../scripts/apply-engagement-immutability.mjs', import.meta.url)),
      'utf8'
    )
    expect(script).toContain('CREATE OR REPLACE FUNCTION')
    expect(script).toMatch(/append_only/)
  })
})
