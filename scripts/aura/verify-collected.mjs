// SPDX-License-Identifier: AGPL-3.0-or-later
// Cold verification of join-1 gate observations. An observation grants no authority.
// Nostr cryptography/owner binding belong to the injected frozen records codec.
import { parseStrictJson } from '../../packages/contracts/src/json.mjs'
import { gatePublicKeySha256, readGateSnapshot, verifyGateRecord } from './gate-snapshot.mjs'
import { spawnSync } from 'node:child_process'
import { isAbsolute } from 'node:path'
import { pathToFileURL } from 'node:url'

const HEX64 = /^[0-9a-f]{64}$/u
const HEX16 = /^[0-9a-f]{16}$/u
const JOURNAL_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u
const ZERO_ID = '0'.repeat(64)
const MAX_ROWS = 50000
const MAX_JSON_BYTES = 128 * 1024
const MAX_LOG_BYTES = 32 * 1024 * 1024
const VERIFIED_PREFIXES = new WeakMap()
const ANCHOR_SCOPE = 'provided-data-consistency-only; retrieval, provenance and witness independence unperformed'
const SOURCE_FIELDS = ['journal_id', 'key_sha256']
const REFERENCE_FIELDS = ['journal_id', 'position', 'hash']
const PAYLOAD_FIELDS = ['schema', 'classification', 'grants_authority', 'source', 'action_id', 'entry', 'entry_body']
const VERIFIED_FIELDS = ['version', 'type', 'id', 'pubkey', 'created_at', 'sequence', 'previous_id', 'source',
  'action_id', 'owner_pubkey_hex', 'encryption', 'references', 'binding_digest', 'grants_authority', 'plaintext']
const EVENT_FIELDS = ['id', 'pubkey', 'created_at', 'kind', 'tags', 'content', 'sig']
const RECORD_FIELDS = ['position', 'hash', 'action_id', 'entry', 'entry_body']
const ENTRY_FIELDS = ['seq', 'at', 'event', 'proposal', 'target', 'base_sha', 'new_sha', 'detail', 'prev', 'hash', 'sig']
const SNAPSHOT_FIELDS = ['ok', 'status', 'source', 'selected_head', 'records']
const ANCHOR_FIELDS = ['seq', 'head', 'gate_fp', 'entry_at', 'anchored_at']
const GATE_REASONS = new Set(['source-id-invalid', 'source-path-invalid', 'public-key-invalid', 'key-pin-required',
  'bounds-invalid', 'key-pin-mismatch', 'selected-head-invalid', 'row-count-invalid', 'row-bound-exceeded',
  'record-bound-exceeded', 'record-shape', 'record-types', 'record-hash-shape', 'signature-shape', 'hash-mismatch',
  'signature-invalid', 'record-verification-failed', 'sequence-gap', 'chain-mismatch', 'byte-bound-exceeded',
  'selected-head-mismatch', 'snapshot-unavailable'].map((name) => `gate-source:${name}`))

export class AuraCollectedError extends TypeError {
  constructor(name) {
    super(`aura-collected:${name}`)
    this.name = 'AuraCollectedError'
    this.code = this.message
  }
}
const refuse = (name) => { throw new AuraCollectedError(name) }

/** Reject duplicate decoded keys before plaintext/header JSON loses that evidence. */
export function parseUniqueJson(text, options = {}) {
  try { return parseStrictJson(text, { maxBytes: MAX_JSON_BYTES, ...options }) }
  catch (error) {
    const names = { JSON_DUPLICATE_KEY: 'json-duplicate-key', JSON_DEPTH: 'json-depth', JSON_SIZE: 'json-size',
      JSON_LONE_SURROGATE: 'json-unicode', JSON_UNSAFE_NUMBER: 'json-number', JSON_NEGATIVE_ZERO: 'json-number' }
    refuse(names[error?.reason] ?? 'json-invalid')
  }
}

function closed(value, fields) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false
  const proto = Object.getPrototypeOf(value)
  if (proto !== Object.prototype && proto !== null) return false
  const keys = Reflect.ownKeys(value)
  return keys.length === fields.length && fields.every((key) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, key)
    return descriptor?.enumerable === true && Object.hasOwn(descriptor, 'value')
  })
}
function array(value) {
  if (!Array.isArray(value) || value.length > MAX_ROWS || Object.getPrototypeOf(value) !== Array.prototype) return false
  const keys = Reflect.ownKeys(value)
  return keys.length === value.length + 1 && Array.from({ length: value.length }, (_, index) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index))
    return descriptor?.enumerable === true && Object.hasOwn(descriptor, 'value')
  }).every(Boolean)
}
function sourceOf(value) {
  if (!closed(value, SOURCE_FIELDS) || typeof value.journal_id !== 'string' || !JOURNAL_ID.test(value.journal_id)
    || typeof value.key_sha256 !== 'string' || !HEX64.test(value.key_sha256)) refuse('source-shape')
  return { journal_id: value.journal_id, key_sha256: value.key_sha256 }
}
const sameSource = (left, right) => left.journal_id === right.journal_id && left.key_sha256 === right.key_sha256
function headOf(value) {
  if (!closed(value, ['position', 'hash']) || !Number.isSafeInteger(value.position) || value.position < 0
    || typeof value.hash !== 'string' || (value.position === 0 ? value.hash !== 'GENESIS' : !HEX64.test(value.hash)))
    refuse('source-head-shape')
  return { position: value.position, hash: value.hash }
}
function trustedKeySha256(gatePublicKey) {
  try { return gatePublicKeySha256(gatePublicKey) } catch { refuse('gate-public-key-invalid') }
}
function safeReason(error) {
  return error instanceof AuraCollectedError ? error.code : 'aura-collected:verification-failed'
}
const initial = () => ({ source: null, aura_head: { sequence: 0, id: ZERO_ID }, coverage: { position: 0, hash: 'GENESIS' } })
function incomplete(context, reason, extra = {}) {
  return { ok: false, status: 'incomplete', reason, source: context.source,
    aura_head: { ...context.aura_head }, coverage: { ...context.coverage }, grants_authority: false, ...extra }
}

function validateMetadata(metadata, event, sequence, previousId, source) {
  if (!closed(metadata, VERIFIED_FIELDS) || metadata.version !== 1 || metadata.type !== 'aura'
    || metadata.grants_authority !== false || metadata.encryption !== 'nip44-v2'
    || typeof metadata.id !== 'string' || !HEX64.test(metadata.id) || metadata.id !== event.id
    || typeof metadata.pubkey !== 'string' || !HEX64.test(metadata.pubkey) || metadata.pubkey !== event.pubkey
    || !Number.isSafeInteger(metadata.created_at) || metadata.created_at < 0 || metadata.created_at !== event.created_at
    || typeof metadata.owner_pubkey_hex !== 'string' || !HEX64.test(metadata.owner_pubkey_hex)
    || typeof metadata.binding_digest !== 'string' || !HEX64.test(metadata.binding_digest)
    || !array(metadata.references) || typeof metadata.plaintext !== 'string') refuse('record-metadata-shape')
  if (metadata.sequence !== sequence) refuse('aura-sequence-gap')
  if (metadata.previous_id !== previousId) refuse('aura-chain-mismatch')
  if (!closed(metadata.source, REFERENCE_FIELDS) || metadata.source.journal_id !== source.journal_id
    || metadata.source.position !== sequence || typeof metadata.source.hash !== 'string' || !HEX64.test(metadata.source.hash))
    refuse('source-reference-mismatch')
  if (metadata.action_id !== null && typeof metadata.action_id !== 'string') refuse('action-reference-shape')
}

/**
 * Verify only the retained signed stream, before opening a live source snapshot.
 * codec.verify must verify B's exact Nostr profile, trusted service-owner binding and NIP-44 MAC,
 * and return B's full metadata plus the exact decrypted JSON string in plaintext.
 * verified_records is PRIVATE internal coverage data; callers must not print or publish it.
 */
export async function verifyAuraStream(events, { codec, source, gatePublicKey, verifiedPrefix } = {}) {
  const context = initial()
  try {
    context.source = sourceOf(source)
    if (trustedKeySha256(gatePublicKey) !== context.source.key_sha256) refuse('gate-key-pin-mismatch')
    if (!codec || typeof codec.verify !== 'function') refuse('codec-required')
    if (!array(events)) refuse('events-shape')
    let verified_records = [], offset = 0
    if (verifiedPrefix !== undefined) {
      if (!VERIFIED_PREFIXES.has(verifiedPrefix) || VERIFIED_PREFIXES.get(verifiedPrefix) !== codec
        || !sameSource(verifiedPrefix.source, context.source)) refuse('verified-prefix-invalid')
      context.aura_head = { ...verifiedPrefix.aura_head }
      context.coverage = { ...verifiedPrefix.coverage }
      verified_records = [...verifiedPrefix.verified_records]
      offset = verified_records.length
    }
    if (offset + events.length > MAX_ROWS) refuse('events-shape')
    for (let index = 0; index < events.length; index++) {
      const event = events[index]
      if (!closed(event, EVENT_FIELDS) || typeof event.id !== 'string' || !HEX64.test(event.id)) refuse('event-shape')
      let metadata
      try { metadata = await codec.verify(event) } catch { refuse('nostr-verification-failed') }
      validateMetadata(metadata, event, offset + index + 1, context.aura_head.id, context.source)
      const payload = parseUniqueJson(metadata.plaintext)
      if (!closed(payload, PAYLOAD_FIELDS) || payload.schema !== 'aukora:aura:gate-observation:v1'
        || payload.classification !== 'gate-ledger-observation' || payload.grants_authority !== false
        || !closed(payload.source, [...REFERENCE_FIELDS, 'key_sha256'])
        || payload.source.journal_id !== context.source.journal_id || payload.source.key_sha256 !== context.source.key_sha256
        || payload.source.position !== metadata.source.position || payload.source.hash !== metadata.source.hash)
        refuse('observation-payload-shape')
      if (!closed(payload.entry, ENTRY_FIELDS)) refuse('entry-shape')
      const checked = verifyGateRecord(payload.entry, gatePublicKey)
      if (!checked.ok) refuse('gate-record-invalid')
      if (payload.entry.seq !== metadata.source.position || payload.entry.hash !== metadata.source.hash
        || payload.entry.prev !== context.coverage.hash) refuse('gate-chain-mismatch')
      if (typeof payload.entry_body !== 'string' || payload.entry_body !== checked.entry_body) refuse('entry-body-mismatch')
      const action_id = payload.entry.proposal ?? null
      if (payload.action_id !== action_id || metadata.action_id !== action_id) refuse('action-reference-mismatch')
      verified_records.push(Object.freeze({ position: payload.entry.seq, hash: payload.entry.hash, action_id,
        entry: Object.freeze(payload.entry), entry_body: payload.entry_body }))
      context.aura_head = { sequence: offset + index + 1, id: event.id }
      context.coverage = { position: payload.entry.seq, hash: payload.entry.hash }
    }
    const result = Object.freeze({ ok: true, status: 'complete', grants_authority: false,
      source: Object.freeze(context.source), aura_head: Object.freeze(context.aura_head),
      coverage: Object.freeze(context.coverage), verified_records: Object.freeze(verified_records) })
    VERIFIED_PREFIXES.set(result, codec)
    return result
  } catch (error) { return incomplete(context, safeReason(error)) }
}

/** Revalidate adapter/injected snapshots before append; never treats ok:true as a proof. */
export function verifyGateSnapshot(snapshot, source, gatePublicKey) {
  source = sourceOf(source)
  if (trustedKeySha256(gatePublicKey) !== source.key_sha256) refuse('gate-key-pin-mismatch')
  if (!closed(snapshot, SNAPSHOT_FIELDS) || snapshot.ok !== true || snapshot.status !== 'complete')
    refuse('source-snapshot-shape')
  if (!sameSource(sourceOf(snapshot.source), source)) refuse('source-identity-mismatch')
  const selected_head = headOf(snapshot.selected_head)
  if (!array(snapshot.records) || snapshot.records.length > MAX_ROWS || snapshot.records.length !== selected_head.position)
    refuse('source-sequence-gap')
  let previous = 'GENESIS'
  for (let index = 0; index < snapshot.records.length; index++) {
    const record = snapshot.records[index]
    if (!closed(record, RECORD_FIELDS) || !closed(record.entry, ENTRY_FIELDS)) refuse('source-record-shape')
    const checked = verifyGateRecord(record.entry, gatePublicKey)
    if (!checked.ok) refuse('gate-record-invalid')
    if (record.position !== index + 1 || record.position !== record.entry.seq || record.hash !== record.entry.hash
      || record.entry.prev !== previous) refuse('source-sequence-gap')
    if (record.entry_body !== checked.entry_body || record.action_id !== (record.entry.proposal ?? null))
      refuse('source-record-mismatch')
    previous = record.hash
  }
  if (previous !== selected_head.hash) refuse('selected-head-mismatch')
  return selected_head
}

function verifyAnchors(anchors, snapshot, source) {
  if (anchors === undefined || (array(anchors) && anchors.length === 0)) return { anchor_status: 'unperformed', anchors_checked: 0 }
  if (!array(anchors) || anchors.length > MAX_ROWS) refuse('anchors-shape')
  let prior = 0
  for (const anchor of anchors) {
    if (!closed(anchor, ANCHOR_FIELDS) || !Number.isSafeInteger(anchor.seq) || anchor.seq < 1
      || typeof anchor.head !== 'string' || !HEX64.test(anchor.head)
      || typeof anchor.gate_fp !== 'string' || !HEX16.test(anchor.gate_fp)
      || typeof anchor.entry_at !== 'string' || anchor.entry_at.length === 0
      || typeof anchor.anchored_at !== 'string' || anchor.anchored_at.length === 0 || anchor.anchored_at.length > 128)
      refuse('anchor-shape')
    if (anchor.seq <= prior) refuse('anchor-sequence-gap')
    if (anchor.seq > snapshot.selected_head.position) refuse('anchor-beyond-selected-head')
    if (anchor.gate_fp !== source.key_sha256.slice(0, 16)) refuse('anchor-key-mismatch')
    const record = snapshot.records[anchor.seq - 1]
    if (record.hash !== anchor.head || record.entry.at !== anchor.entry_at) refuse('anchor-source-mismatch')
    prior = anchor.seq
  }
  const last = anchors[anchors.length - 1]
  return { anchor_status: 'verified', anchors_checked: anchors.length, anchored_head: { position: last.seq, hash: last.head } }
}

/**
 * Cold-check complete source coverage through this selected snapshot head and supplied old anchors.
 * This checks the supplied anchor rows' consistency; it neither fetches nor publishes a witness.
 * Returns PUBLIC metadata only: no decrypted entries, signed bodies, events, paths or raw errors.
 */
export async function verifyCollected({ events, snapshot, codec, gatePublicKey, expectedSource, anchors } = {}) {
  let context = initial()
  let selected_head = null
  try {
    const source = sourceOf(expectedSource ?? snapshot?.source)
    context.source = source
    if (snapshot?.selected_head !== undefined && snapshot.selected_head !== null) selected_head = headOf(snapshot.selected_head)
    const retained = await verifyAuraStream(events, { codec, source, gatePublicKey })
    context = { source: retained.source, aura_head: retained.aura_head, coverage: retained.coverage }
    if (!retained.ok) return incomplete(context, retained.reason,
      { selected_head, anchor_status: 'unperformed', anchors_checked: 0, anchor_scope: ANCHOR_SCOPE })
    if (snapshot?.ok === false) {
      const reason = GATE_REASONS.has(snapshot.reason) ? snapshot.reason : 'aura-collected:source-snapshot-incomplete'
      return incomplete(context, reason, { selected_head, anchor_status: 'unperformed', anchors_checked: 0, anchor_scope: ANCHOR_SCOPE })
    }
    selected_head = verifyGateSnapshot(snapshot, source, gatePublicKey)
    if (retained.coverage.position > selected_head.position) refuse('source-truncated')
    for (let index = 0; index < retained.verified_records.length; index++) {
      const covered = retained.verified_records[index], current = snapshot.records[index]
      if (covered.hash !== current.hash || covered.entry_body !== current.entry_body
        || ENTRY_FIELDS.some((field) => covered.entry[field] !== current.entry[field])) refuse('source-prefix-altered')
    }
    if (retained.coverage.position !== selected_head.position || retained.coverage.hash !== selected_head.hash)
      refuse('coverage-incomplete')
    const anchorResult = verifyAnchors(anchors, snapshot, source)
    if (anchorResult.anchor_status === 'unperformed')
      return incomplete(context, 'aura-collected:anchor-unperformed', { selected_head, anchor_scope: ANCHOR_SCOPE, ...anchorResult })
    return { ok: true, status: 'complete', ...context, grants_authority: false, selected_head, anchor_scope: ANCHOR_SCOPE, ...anchorResult }
  } catch (error) {
    return incomplete(context, safeReason(error), { selected_head, anchor_status: 'unperformed', anchors_checked: 0, anchor_scope: ANCHOR_SCOPE })
  }
}

// Read-only openat keeps the checked directory inode pinned. No lock, mkdir, repair or writes.
const READ_STORE = String.raw`
import os,sys,json,stat
limit=32*1024*1024
try:
    directory=os.open(sys.argv[1],os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        info=os.fstat(directory)
        if not stat.S_ISDIR(info.st_mode) or info.st_mode&0o077 or info.st_uid!=os.getuid(): raise ValueError()
        log=os.open('gate-observations.nostr.jsonl',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
        try:
            info=os.fstat(log)
            if not stat.S_ISREG(info.st_mode) or info.st_mode&0o077 or info.st_uid!=os.getuid() or info.st_size>limit: raise ValueError()
            data=b''
            while True:
                block=os.read(log,min(65536,limit+1-len(data)))
                if not block: break
                data+=block
                if len(data)>limit: raise ValueError()
            text=data.decode('utf-8','strict')
            if text and not text.endswith('\n'): raise ValueError()
        finally: os.close(log)
    finally: os.close(directory)
    sys.stdout.write(json.dumps({'text':text},ensure_ascii=False,separators=(',',':')))
except Exception:
    sys.exit(2)
`

/** Actual cold path: private bounded NOFOLLOW reads + complete read-only source snapshot. */
export async function verifyCollectorStore({ storeDir, snapshotOptions, codec, anchors, pythonExecutable = 'python3' } = {}) {
  try {
    if (typeof storeDir !== 'string' || !isAbsolute(storeDir) || /[\x00-\x1f\x7f]/u.test(storeDir)) refuse('store-path-invalid')
    const read = spawnSync(pythonExecutable, ['-I', '-c', READ_STORE, storeDir],
      { encoding: 'utf8', maxBuffer: MAX_LOG_BYTES * 2 + 65536 })
    if (read.error || read.status !== 0) refuse('store-read-unavailable')
    const response = JSON.parse(read.stdout) // Output from this closed local helper, not an event parser.
    if (!closed(response, ['text']) || typeof response.text !== 'string'
      || Buffer.byteLength(response.text, 'utf8') > MAX_LOG_BYTES) refuse('store-read-unavailable')
    const lines = response.text === '' ? [] : response.text.slice(0, -1).split('\n')
    if (lines.length > MAX_ROWS) refuse('events-shape')
    const events = lines.map((line) => parseUniqueJson(line))
    const snapshot = readGateSnapshot(snapshotOptions)
    return await verifyCollected({ events, snapshot, codec, gatePublicKey: snapshotOptions?.publicKeyPem,
      expectedSource: { journal_id: snapshotOptions?.sourceId, key_sha256: snapshotOptions?.expectedKeySha256 }, anchors })
  } catch (error) {
    return incomplete(initial(), safeReason(error), { selected_head: null, anchor_status: 'unperformed',
      anchors_checked: 0, anchor_scope: ANCHOR_SCOPE })
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const file = process.argv[2]
    if (process.argv.length !== 3 || !file || !isAbsolute(file)) refuse('trusted-context-required')
    const { collectorContext } = await import(pathToFileURL(file).href)
    const context = typeof collectorContext === 'function' ? await collectorContext() : collectorContext
    const result = await verifyCollectorStore(context)
    process.stdout.write(`${JSON.stringify(result)}\n`)
    process.exitCode = result.ok ? 0 : 2
  } catch (error) {
    const reason = error instanceof AuraCollectedError ? error.code : 'aura-collected:trusted-context-unavailable'
    process.stderr.write(`${reason}\n`)
    process.exitCode = 2
  }
}
