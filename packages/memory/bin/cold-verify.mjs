// SPDX-License-Identifier: AGPL-3.0-or-later
import { readFileSync } from 'node:fs'
import { parseOriginal } from '../src/codecs.mjs'
import { inspectSnapshot } from '../src/snapshot.mjs'

try {
  const [file, owner, headsFile] = process.argv.slice(2)
  if (!file || !owner) throw new Error('usage: cold-verify.mjs SNAPSHOT OWNER [RETAINED_HEADS_JSON]')
  const snapshot = parseOriginal(readFileSync(file))
  const checked = inspectSnapshot(snapshot, owner, { expectedHeads: headsFile ? parseOriginal(readFileSync(headsFile)) : undefined })
  process.stdout.write(JSON.stringify({ verdict: 'VERIFIED', verified_scope: 'snapshot-integrity', records: checked.records.length,
    citations: checked.records.map(r => ({ record_id: r.meta.id, revision: r.file.revision,
      tombstoned: checked.tombstones.some(t => t.id === r.meta.id), ...r.citation })),
    heads: snapshot.heads, independent_trust_anchor_supplied: Boolean(headsFile),
    grants_authority: false, ceiling: 'Integrity and provenance only; no truth, authority, or human-presence claim.' }) + '\n')
} catch (error) {
  process.stderr.write(JSON.stringify({ verdict: 'REFUSED', reason: error.code ?? error.message }) + '\n')
  process.exitCode = 1
}
