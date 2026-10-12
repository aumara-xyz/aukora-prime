#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
// Verify gate export bytes and supplied heads through the existing cold verifier.
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { gateEntryBody, gatePublicKeySha256 } from './gate-snapshot.mjs'
import { parseUniqueJson, verifyGateSnapshot } from './verify-collected.mjs'

const refuse = name => { throw new Error(`aura-export:${name}`) }
const json = text => parseUniqueJson(text, { maxBytes: 8 * 1024 * 1024 })

function verifyHeads(heads, snapshot) {
  let previous = 0
  for (const head of heads) {
    if (!head || !Number.isSafeInteger(head.seq) || head.seq <= previous) refuse('anchor-sequence')
    if (head.gate_fp !== snapshot.source.key_sha256.slice(0, 16)) refuse('anchor-key-mismatch')
    if (head.seq > snapshot.selected_head.position) refuse('anchor-beyond-export')
    if (head.head !== snapshot.records[head.seq - 1].hash) refuse('anchor-head-mismatch')
    previous = head.seq
  }
}

export function verifyExport(document, { publicKeyPem, anchors } = {}) {
  const bundled = !Array.isArray(document)
  if (bundled && (!document || document.kind !== 'aukora-gate-export/v1')) refuse('export-shape')
  const entries = bundled ? document.entries : document
  if (!Array.isArray(entries) || entries.length === 0) refuse('empty-or-invalid-entries')
  const key = publicKeyPem ?? (bundled ? document.public_key_pem : undefined)
  let keySha256
  try { keySha256 = gatePublicKeySha256(key) } catch { refuse('public-key-required-or-invalid') }
  if (bundled && (document.gate_pubkey_sha256 !== keySha256
    || gatePublicKeySha256(document.public_key_pem) !== keySha256)) refuse('bundle-key-mismatch')
  const source = { journal_id: 'gate-export', key_sha256: keySha256 }
  const last = entries.at(-1)
  const snapshot = { ok: true, status: 'complete', source,
    selected_head: { position: entries.length, hash: last?.hash },
    records: entries.map(entry => ({ position: entry?.seq, hash: entry?.hash,
      action_id: entry?.proposal ?? null, entry, entry_body: entry && gateEntryBody(entry) })) }
  verifyGateSnapshot(snapshot, source, key)
  if (bundled) {
    if (document.head?.seq !== entries.length) refuse('bundle-head-mismatch')
    verifyHeads([document.head], snapshot)
  }
  if (anchors !== undefined) {
    if (!Array.isArray(anchors) || anchors.length === 0) refuse('anchor-required')
    verifyHeads(anchors, snapshot)
  }
  const anchored = anchors?.at(-1)?.seq ?? 0
  return { entries: entries.length, head: last.hash, key_sha256: keySha256,
    reason: anchored ? 'gate-chain-and-supplied-anchor' : 'gate-chain-only',
    anchored_through: anchored, unanchored_entries: entries.length - anchored,
    key_source: publicKeyPem ? 'supplied-public-key' : 'carried-public-key-only' }
}

function readAnchors(file) {
  const text = readFileSync(file, 'utf8').trim()
  if (!text) refuse('anchor-required')
  // Whole JSON admits pretty-printed heads/bundles; JSONL admits publisher history.
  let value
  try { JSON.parse(text); value = json(text) }
  catch (error) {
    if (!(error instanceof SyntaxError)) throw error
    value = text.split('\n').filter(line => line.trim()).map(json)
  }
  if (value?.kind === 'aukora-gate-export/v1') value = value.head
  return Array.isArray(value) ? value : [value]
}

export function main(argv = process.argv.slice(2)) {
  if (argv.length === 1 && argv[0] === '--help') {
    console.log('Usage: node scripts/aura/verify-export.mjs EXPORT.json [--public-key PUBLIC.pem] [--anchor HEAD.json|HEADS.jsonl]')
    console.log('Accepts a raw gate entry array with --public-key, or an export-ledger.mjs bundle carrying its public key.')
    console.log('A supplied anchor is a retained {seq,head,gate_fp}, publisher history, or earlier export bundle.')
    console.log('Retain the anchor and public key independently; a head carried with this export is only an observation.')
    console.log('Exit 0 VERIFIED: signed gate chain and supplied head agree. Exit 1 NOT VERIFIED: named refusal.')
    console.log('Without an anchor, valid tail removal is undetectable. An earlier anchor protects only its prefix.')
    console.log('Only anchor seq/head/gate_fp are checked; timestamps, provenance and latestness are not verified.')
    console.log('Membrane minimal needs Merkle heads plus proofFromPrevious, which gate exports do not contain.')
    return 0
  }
  try {
    const [file, ...args] = argv
    const options = {}
    if (!file || file.startsWith('--') || args.length % 2) refuse('usage')
    for (let index = 0; index < args.length; index += 2) {
      const flag = args[index]
      if (!['--public-key', '--anchor'].includes(flag) || Object.hasOwn(options, flag)
        || !args[index + 1] || args[index + 1].startsWith('--')) refuse('usage')
      options[flag] = args[index + 1]
    }
    const result = verifyExport(json(readFileSync(file, 'utf8')), {
      publicKeyPem: options['--public-key'] ? readFileSync(options['--public-key'], 'utf8') : undefined,
      anchors: options['--anchor'] ? readAnchors(options['--anchor']) : undefined })
    console.log(`VERIFIED ${result.reason} entries=${result.entries} anchored_through=${result.anchored_through} unanchored_entries=${result.unanchored_entries}`)
    console.log(`KEY ${result.key_source} sha256=${result.key_sha256}`)
    console.log('SCOPE supplied data only; anchor provenance, latestness, event truth and completeness not established')
    console.log('TAIL omission beyond the supplied anchor is undetectable; bundled heads are not independent anchors')
    console.log('MINIMAL NOT RUN gate-export-is-not-a-merkle-proof')
    return 0
  } catch (error) {
    const code = /^(?:aura-export|aura-collected):[a-z-]+$/u.test(error?.message)
      ? error.message : 'aura-export:input-unavailable-or-invalid'
    console.log(`NOT VERIFIED ${code}`)
    return 1
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href)
  process.exitCode = main()
