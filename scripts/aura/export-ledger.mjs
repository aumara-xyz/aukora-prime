#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
// Export a verified read-only gate snapshot and its observed head without loading a signing key.
import { readFileSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { parseArgs } from 'node:util'
import { gatePublicKeySha256, readGateSnapshot } from './gate-snapshot.mjs'

export function exportGateLedger({ dbPath, publicKeyPath, outPath, keySha256 } = {}) {
  let publicKeyPem, expectedKeySha256
  try {
    publicKeyPem = readFileSync(publicKeyPath, 'utf8')
    expectedKeySha256 = keySha256 ?? gatePublicKeySha256(publicKeyPem)
  } catch { return { ok: false, reason: 'aura-export:public-key-unavailable' } }
  const snapshot = readGateSnapshot({ dbPath, sourceId: 'gate-ledger', publicKeyPem, expectedKeySha256 })
  if (!snapshot.ok) return snapshot
  if (snapshot.records.length === 0) return { ok: false, reason: 'aura-export:empty-ledger' }
  const entries = snapshot.records.map(record => record.entry)
  const head = { seq: snapshot.selected_head.position, head: snapshot.selected_head.hash,
    gate_fp: snapshot.source.key_sha256.slice(0, 16), entry_at: entries.at(-1)?.at ?? null,
    anchored_at: new Date().toISOString() }
  const bundle = { kind: 'aukora-gate-export/v1', public_key_pem: publicKeyPem,
    gate_pubkey_sha256: snapshot.source.key_sha256, entries, head }
  const bytes = JSON.stringify(bundle) + '\n'
  if (Buffer.byteLength(bytes, 'utf8') > 8 * 1024 * 1024)
    return { ok: false, reason: 'aura-export:byte-bound-exceeded' }
  try {
    writeFileSync(outPath, bytes, { flag: 'wx', mode: 0o600 })
  } catch { return { ok: false, reason: 'aura-export:output-unavailable' } }
  return { ok: true, reason: 'aura-export:observed-head', entries: entries.length, head }
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  let result
  try {
    const { values } = parseArgs({ options: { db: { type: 'string' }, 'public-key': { type: 'string' },
      out: { type: 'string' }, 'key-sha256': { type: 'string' }, help: { type: 'boolean' } }, strict: true })
    if (values.help) {
      console.log('Usage: node scripts/aura/export-ledger.mjs --db FILE --public-key PUBLIC.pem --out NEW.json [--key-sha256 HEX]')
      console.log('Run as a node admin able to read the gate DB and public key. No signing key is loaded.')
      console.log('Reads one verified SQLite snapshot including WAL; writes a new mode-0600 export (8 MiB limit).')
      console.log('The carried head is a local observation, not an independently retained anchor. Share ledger contents deliberately.')
      console.log('Verify offline: node scripts/aura/verify-export.mjs NEW.json [--anchor PREVIOUSLY_RETAINED.json]')
      process.exit(0)
    }
    if (!values.db || !values['public-key'] || !values.out) throw Error('usage')
    result = exportGateLedger({ dbPath: values.db, publicKeyPath: values['public-key'], outPath: values.out,
      keySha256: values['key-sha256'] })
  } catch { result = { ok: false, reason: 'aura-export:usage' } }
  console.log(result.ok ? `EXPORTED ${result.reason} entries=${result.entries} seq=${result.head.seq}`
    : `NOT EXPORTED ${result.reason}`)
  process.exitCode = result.ok ? 0 : 1
}
